//! `login` for oauth2 profiles: device flow and authorization code with PKCE, against a mock
//! provider.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    process::Stdio,
};

use predicates::prelude::*;
use sha2::{Digest, Sha256};

use crate::helpers::{
    oauth::{base64url, error_json, field, oauth_config, token_json, MockProvider},
    *,
};

fn device_provider(
    token_script: impl Fn(usize) -> (u16, String) + Send + Sync + 'static,
) -> MockProvider {
    MockProvider::start(move |request, nth| match request.path.as_str() {
        "/device" => {
            let base = request.body.clone();
            let _ = base;
            (
                200,
                "{\"device_code\":\"DEVICE_CODE_1\",\"user_code\":\"ABCD-1234\",\
                  \"verification_uri\":\"https://verify.example.com/activate\",\
                  \"expires_in\":600,\"interval\":1}"
                    .to_string(),
            )
        }
        "/token" => token_script(nth),
        _ => (404, "{}".into()),
    })
}

fn stored_json(ws: &Workspace) -> serde_json::Value {
    serde_json::from_str(&ws.stored("company").expect("stored credential")).unwrap()
}

#[test]
fn device_flow_stores_tokens_and_expiry() {
    let provider = device_provider(|nth| {
        if nth == 0 {
            (400, error_json("authorization_pending"))
        } else {
            (
                200,
                token_json("FAKE_ACCESS_1", Some("FAKE_REFRESH_1"), Some(3600)),
            )
        }
    });
    let ws = Workspace::new(&oauth_config(&provider.base(), "device"));
    let output = ws
        .cmd()
        .args(["login", "-p", "company"])
        .assert()
        .success()
        .get_output()
        .clone();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // The verification URL and user code are shown; no token is
    assert!(text.contains("https://verify.example.com/activate"));
    assert!(text.contains("ABCD-1234"));
    assert_no_secrets(&text, &["FAKE_ACCESS_1", "FAKE_REFRESH_1", "DEVICE_CODE_1"]);

    let stored = stored_json(&ws);
    assert_eq!(stored["identity"], oauth::company_identity());
    assert_eq!(stored["oauth2"]["access_token"], "FAKE_ACCESS_1");
    assert_eq!(stored["oauth2"]["refresh_token"], "FAKE_REFRESH_1");
    assert!(stored["oauth2"]["expires_at"]
        .as_str()
        .unwrap()
        .contains('T'));
    assert_eq!(stored["oauth2"]["scope"], "read_api");

    // The device request carried the client id and scope
    let device = provider.requests_to("/device");
    assert_eq!(
        field(&device[0].body, "client_id").as_deref(),
        Some("public-client-id")
    );
    assert_eq!(field(&device[0].body, "scope").as_deref(), Some("read_api"));
    assert_eq!(provider.requests_to("/token").len(), 2);
}

#[test]
fn denied_and_expired_authorizations_keep_previous_credentials() {
    for error in ["access_denied", "expired_token"] {
        let provider = device_provider(move |_| (400, error_json(error)));
        let ws = Workspace::new(&oauth_config(&provider.base(), "device"));
        ws.seed_oauth(
            "company",
            &oauth::company_identity(),
            "OLD_ACCESS",
            None,
            None,
        );
        ws.cmd()
            .args(["login", "-p", "company", "--force"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("authentication failed"));
        assert_eq!(
            stored_json(&ws)["oauth2"]["access_token"],
            "OLD_ACCESS",
            "{error}"
        );
    }
}

#[test]
fn slow_down_is_honored() {
    let started = std::time::Instant::now();
    let provider = device_provider(|nth| match nth {
        0 => (400, error_json("slow_down")),
        _ => (200, token_json("FAKE_ACCESS_2", None, None)),
    });
    let ws = Workspace::new(&oauth_config(&provider.base(), "device"));
    ws.cmd().args(["login", "-p", "company"]).assert().success();
    // The polling interval grows after slow_down (interval 1 s -> at least 5 s more)
    assert!(started.elapsed().as_secs() >= 5, "{:?}", started.elapsed());
    assert_eq!(stored_json(&ws)["oauth2"]["access_token"], "FAKE_ACCESS_2");
}

#[test]
fn usable_credentials_are_reused_unless_forced() {
    let provider = device_provider(|_| (200, token_json("NEW_ACCESS", None, Some(3600))));
    let ws = Workspace::new(&oauth_config(&provider.base(), "device"));
    ws.seed_oauth(
        "company",
        &oauth::company_identity(),
        "OLD_ACCESS",
        None,
        Some("2999-01-01T00:00:00Z"),
    );
    ws.cmd()
        .args(["login", "-p", "company"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already has usable credentials"));
    assert!(provider.requests_to("/device").is_empty());
    ws.cmd()
        .args(["login", "-p", "company", "--force"])
        .assert()
        .success();
    assert_eq!(stored_json(&ws)["oauth2"]["access_token"], "NEW_ACCESS");
}

// ---- authorization code with PKCE ----

fn code_provider() -> MockProvider {
    MockProvider::start(|request, _| match request.path.as_str() {
        "/token" => {
            let ok = field(&request.body, "grant_type").as_deref() == Some("authorization_code")
                && field(&request.body, "code").as_deref() == Some("AUTH_CODE_1")
                && field(&request.body, "code_verifier").is_some();
            if ok {
                (
                    200,
                    token_json("FAKE_ACCESS_3", Some("FAKE_REFRESH_3"), Some(3600)),
                )
            } else {
                (400, error_json("invalid_grant"))
            }
        }
        _ => (404, "{}".into()),
    })
}

/// Starts `login` and returns the child with the authorization URL it printed.
fn start_code_login(
    ws: &Workspace,
) -> (
    std::process::Child,
    String,
    BufReader<std::process::ChildStderr>,
) {
    let mut child = ws
        .std_cmd()
        .args(["login", "-p", "company"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "no URL was printed"
        );
        if line.starts_with("http://") {
            break;
        }
    }
    (child, line.trim().to_string(), stderr)
}

fn visit(url: &str) {
    let rest = url.strip_prefix("http://").unwrap();
    let (host, path) = rest.split_once('/').unwrap();
    let mut stream = TcpStream::connect(host).unwrap();
    write!(
        stream,
        "GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut sink = String::new();
    let _ = stream.read_to_string(&mut sink);
}

#[test]
fn authorization_code_flow_uses_pkce_and_stores_the_tokens() {
    let provider = code_provider();
    let ws = Workspace::new(&oauth_config(&provider.base(), "authorization_code"));
    let (mut child, url, _stderr) = start_code_login(&ws);

    let query = url.split_once('?').unwrap().1;
    assert_eq!(
        field(query, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert_eq!(field(query, "response_type").as_deref(), Some("code"));
    assert_eq!(
        field(query, "client_id").as_deref(),
        Some("public-client-id")
    );
    assert_eq!(field(query, "scope").as_deref(), Some("read_api"));
    let redirect = field(query, "redirect_uri").unwrap();
    assert!(redirect.starts_with("http://127.0.0.1:"));
    let state = field(query, "state").unwrap();
    let challenge = field(query, "code_challenge").unwrap();

    visit(&format!("{redirect}?code=AUTH_CODE_1&state={state}"));
    assert!(child.wait().unwrap().success());

    // The verifier presented at exchange matches the challenge sent earlier
    let token = provider.requests_to("/token");
    assert_eq!(token.len(), 1);
    let verifier = field(&token[0].body, "code_verifier").unwrap();
    assert_eq!(base64url(&Sha256::digest(verifier.as_bytes())), challenge);
    assert_eq!(stored_json(&ws)["oauth2"]["access_token"], "FAKE_ACCESS_3");
}

#[test]
fn a_wrong_state_is_rejected_and_nothing_is_stored() {
    let provider = code_provider();
    let ws = Workspace::new(&oauth_config(&provider.base(), "authorization_code"));
    let (mut child, url, _stderr) = start_code_login(&ws);
    let query = url.split_once('?').unwrap().1;
    let redirect = field(query, "redirect_uri").unwrap();
    visit(&format!("{redirect}?code=AUTH_CODE_1&state=not-the-state"));
    assert_eq!(child.wait().unwrap().code(), Some(1));
    assert!(ws.stored("company").is_none());
    assert!(provider.requests_to("/token").is_empty());
}

#[test]
fn a_provider_error_callback_stores_nothing() {
    let provider = code_provider();
    let ws = Workspace::new(&oauth_config(&provider.base(), "authorization_code"));
    let (mut child, url, _stderr) = start_code_login(&ws);
    let query = url.split_once('?').unwrap().1;
    let redirect = field(query, "redirect_uri").unwrap();
    visit(&format!("{redirect}?error=access_denied"));
    assert_eq!(child.wait().unwrap().code(), Some(1));
    assert!(ws.stored("company").is_none());
}
