//! The authorization code flow with PKCE (S256) and a loopback redirect.

use std::{
    io::{IsTerminal, Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};

use oauth2::{
    basic::BasicClient, url::Url, AuthType, AuthUrl, AuthorizationCode, CsrfToken,
    PkceCodeChallenge, RedirectUrl, Scope,
};

use crate::vault::{
    auth::token::{client_id, describe, http_client, token_url, TokenSet},
    config::OAuth,
    Error, Result,
};

/// How long to wait for the browser to come back.
pub const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Runs the flow: prints the authorization URL, waits for the redirect on a random loopback
/// port, checks `state`, and exchanges the code with the PKCE verifier.
pub fn login(profile: &str, oauth: &OAuth) -> Result<TokenSet> {
    let endpoint = oauth
        .authorization_endpoint
        .clone()
        .ok_or_else(|| Error::Auth("the profile has no authorization_endpoint".into()))?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| Error::io("cannot listen for the browser redirect", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::io("cannot listen for the browser redirect", e))?
        .port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let http = http_client()?;
    let client = BasicClient::new(client_id(oauth))
        .set_auth_uri(
            AuthUrl::new(endpoint)
                .map_err(|_| Error::Auth("the authorization endpoint is not a URL".into()))?,
        )
        .set_token_uri(token_url(oauth)?)
        .set_redirect_uri(
            RedirectUrl::new(redirect).map_err(|_| Error::Auth("bad redirect URL".into()))?,
        )
        .set_auth_type(AuthType::RequestBody);

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(challenge);
    for scope in &oauth.scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    let (url, state) = request.url();

    eprintln!("To log in to {profile}, open this URL in a browser:\n{url}");
    if std::io::stdin().is_terminal() {
        let _ = webbrowser::open(url.as_str());
    }
    eprintln!("Waiting for authorization...");

    let code = wait_for_callback(&listener, state.secret(), CALLBACK_TIMEOUT)?;
    let response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(verifier)
        .request(&http)
        .map_err(|e| Error::Auth(describe(e, &[])))?;
    Ok(TokenSet::from_response(&response))
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes());
}

/// Waits for the redirect with `code` and `state`, up to `timeout`.
pub fn wait_for_callback(
    listener: &TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> Result<String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::io("cannot listen for the browser redirect", e))?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buffer = [0u8; 8192];
                let read = stream.read(&mut buffer).unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let target = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
                    respond(&mut stream, "400 Bad Request", "bad request");
                    continue;
                };
                if url.path() != "/callback" {
                    respond(&mut stream, "404 Not Found", "not found");
                    continue;
                }
                let query = |key: &str| {
                    url.query_pairs()
                        .find(|(k, _)| k == key)
                        .map(|(_, v)| v.into_owned())
                };
                if let Some(error) = query("error") {
                    respond(
                        &mut stream,
                        "200 OK",
                        "Login failed. You can close this window.",
                    );
                    let error: String = error
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .take(60)
                        .collect();
                    return Err(Error::Auth(format!(
                        "the provider returned the error {error}"
                    )));
                }
                if query("state").as_deref() != Some(expected_state) {
                    respond(&mut stream, "400 Bad Request", "state mismatch");
                    return Err(Error::Auth(
                        "the redirect did not carry the expected state; login aborted".into(),
                    ));
                }
                let Some(code) = query("code") else {
                    respond(&mut stream, "400 Bad Request", "missing code");
                    return Err(Error::Auth(
                        "the redirect carried no authorization code".into(),
                    ));
                };
                respond(
                    &mut stream,
                    "200 OK",
                    "Logged in. You can close this window.",
                );
                return Ok(code);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(Error::Auth(
                        "timed out waiting for the browser; run login again".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(Error::io("cannot accept the browser redirect", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gives_up_after_the_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let started = Instant::now();
        let error = wait_for_callback(&listener, "state", Duration::from_millis(200)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    fn callback(listener: &TcpListener, query: &str) -> std::thread::JoinHandle<()> {
        let port = listener.local_addr().unwrap().port();
        let query = query.to_string();
        std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(stream, "GET /callback?{query} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut sink = String::new();
            let _ = stream.read_to_string(&mut sink);
        })
    }

    #[test]
    fn accepts_the_matching_state_and_rejects_others() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let handle = callback(&listener, "code=abc&state=good");
        assert_eq!(
            wait_for_callback(&listener, "good", Duration::from_secs(5)).unwrap(),
            "abc"
        );
        handle.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let handle = callback(&listener, "code=abc&state=evil");
        assert!(wait_for_callback(&listener, "good", Duration::from_secs(5)).is_err());
        handle.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let handle = callback(&listener, "error=access_denied&state=good");
        let error = wait_for_callback(&listener, "good", Duration::from_secs(5)).unwrap_err();
        assert!(error.to_string().contains("access_denied"));
        handle.join().unwrap();
    }
}
