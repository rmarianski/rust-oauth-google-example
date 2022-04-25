use anyhow::{anyhow, bail, Context};
use clap::Parser;
use rand::{thread_rng, Rng};
use reqwest::Client;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::str::from_utf8;
use url::Url;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    google_client_id: String,
    #[clap(long)]
    google_client_secret: String,
    #[clap(long, default_value = "https://accounts.google.com/o/oauth2/v2/auth")]
    auth_url: String,
    #[clap(long, default_value = "https://www.googleapis.com/oauth2/v4/token")]
    token_url: String,
    #[clap(long, default_value = "http://localhost:8080")]
    redirect_url: Url,
    #[clap(long, default_value = "20")]
    num_state_bytes: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // NOTE: generate google redirect url
    let state = new_state(args.num_state_bytes);
    let redirect_uri = args
        .redirect_url
        .as_str()
        .strip_suffix('/')
        .unwrap_or_else(|| args.redirect_url.as_str());
    let query_string = new_query_string(&args.google_client_id, redirect_uri, &state);
    let auth_redirect_url = format!("{}?{}", args.auth_url, query_string);
    println!("Google auth redirect: {}", auth_redirect_url);

    // NOTE: listen for requests from google
    let bind_addr = format!("127.0.0.1:{}", args.redirect_url.port().unwrap_or(8080));
    let google_redirect_state = recv_redirect_request(&bind_addr).context("recv redirect state")?;

    // sanity check the state received matches
    if google_redirect_state.state != state {
        bail!(
            "state mismatch: {} != {}",
            google_redirect_state.state,
            state
        );
    }

    // NOTE: exchange the code for an access token
    // TODO: add pkce verifier
    let http_client = Client::new();
    let token_request_body = new_token_request_body(
        &args.google_client_id,
        &args.google_client_secret,
        &google_redirect_state.code,
        redirect_uri,
    );
    println!("posting token request body:\n{}", token_request_body);
    let token_response = http_client
        .post(&args.token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(token_request_body)
        .send()
        .await
        .context("post token")?;
    let status_code = token_response.status();
    let bs = token_response.bytes().await.context("read bytes")?;
    let bytes_str = from_utf8(&bs).context("bytes -> string")?;
    println!(
        "received response: status={} body={}",
        status_code, bytes_str
    );
    let token_response: TokenResponse = serde_json::from_str(bytes_str).context("parse json")?;
    println!("token response: {:?}", token_response);
    // TODO: validate the token properly
    let email = parse_email_from_jwt(&token_response.id_token).context("parse email")?;
    println!("Successfully validated: {}", email);
    Ok(())
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    // access_token: String,
    // expires_in: u32,
    // scope: String,
    // token_type: String,
    id_token: String,
}

fn parse_email_from_jwt(token: &str) -> anyhow::Result<String> {
    let fields: Vec<_> = token.splitn(3, '.').collect();
    if fields.len() != 3 {
        bail!("invalid number of fields: {}", fields.len());
    }
    let decoded = base64::decode(fields[1].as_bytes()).context("base64 decode")?;
    let jwt_data: JwtData = serde_json::from_slice(&decoded).context("json deserialize")?;
    if jwt_data.email.is_empty() {
        bail!("empty");
    }
    Ok(jwt_data.email)
}

#[derive(Debug, Deserialize)]
struct JwtData {
    email: String,
}

fn new_state(num_bytes: u32) -> String {
    let random_bytes: Vec<u8> = (0..num_bytes).map(|_| thread_rng().gen::<u8>()).collect();
    base64::encode_config(&random_bytes, base64::URL_SAFE_NO_PAD)
}

fn new_query_string(client_id: &str, redirect_uri: &str, state: &str) -> String {
    format!(
        "response_type=code&scope=openid%20email&client_id={}&redirect_uri={}&state={}",
        query_encode(client_id),
        query_encode(redirect_uri),
        query_encode(state)
    )
}

fn query_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

struct GoogleRedirectState {
    code: String,
    state: String,
}

fn recv_redirect_request(addr: &str) -> anyhow::Result<GoogleRedirectState> {
    let listener = TcpListener::bind(addr).with_context(|| format!("bind: {}", addr))?;
    let (mut stream, _socket_addr) = listener.accept().context("accept")?;
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("read request line")?;
    if !request_line.starts_with("GET ") {
        bail!("bad redirect request line: {}", request_line);
    }
    let redirect_path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("redirect path: {}", request_line))?;
    let url = Url::parse(&(format!("http://localhost{}", redirect_path)))
        .with_context(|| format!("parse path {}", redirect_path))?;
    let mut code = String::new();
    let mut state = String::new();
    for pair in url.query_pairs() {
        match pair.0.as_ref() {
            "code" => code = pair.1.into(),
            "state" => state = pair.1.into(),
            _ => {}
        }
    }
    if code.is_empty() {
        bail!("missing code: {}", request_line);
    }
    if state.is_empty() {
        bail!("missing state: {}", request_line);
    }
    let message = "Go back to your terminal :)";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        message.len(),
        message
    );
    stream.write_all(response.as_bytes()).context("write")?;
    Ok(GoogleRedirectState { state, code })
}

fn new_token_request_body(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> String {
    format!(
        "client_id={}&client_secret={}&code={}&grant_type=authorization_code&redirect_uri={}",
        query_encode(client_id),
        query_encode(client_secret),
        query_encode(code),
        query_encode(redirect_uri)
    )
}
