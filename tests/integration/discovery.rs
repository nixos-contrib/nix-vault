//! Endpoint discovery: an oauth2 profile with an `issuer` finds its endpoints in the provider's
//! metadata, and the endpoints written in the profile win.

use std::sync::{Arc, Mutex};

use predicates::prelude::*;

use crate::helpers::{
    oauth::{token_json, MockProvider},
    *,
};

/// A provider that serves metadata at `metadata_path`, claiming to be `issuer_suffix` under its
/// own base address, and a device flow that succeeds at once.
fn provider(
    metadata_path: &'static str,
    issuer: impl Fn(&str) -> String + Send + Sync + 'static,
) -> MockProvider {
    let base = Arc::new(Mutex::new(String::new()));
    let seen = base.clone();
    let provider = MockProvider::start(move |request, _| {
        let base = seen.lock().unwrap().clone();
        match request.path.as_str() {
            p if p == metadata_path => (
                200,
                format!(
                    "{{\"issuer\":\"{}\",\"token_endpoint\":\"{base}/token\",\
                      \"device_authorization_endpoint\":\"{base}/device\"}}",
                    issuer(&base)
                ),
            ),
            "/device" => (
                200,
                "{\"device_code\":\"DEVICE_CODE_1\",\"user_code\":\"ABCD-1234\",\
                  \"verification_uri\":\"https://verify.example.com/activate\",\
                  \"expires_in\":600,\"interval\":1}"
                    .to_string(),
            ),
            "/token" => (
                200,
                token_json("FAKE_ACCESS_1", Some("FAKE_REFRESH_1"), Some(3600)),
            ),
            _ => (404, "{}".into()),
        }
    });
    *base.lock().unwrap() = provider.base();
    provider
}

fn config(issuer: &str, extra: &str) -> String {
    format!(
        "[company]\nhost = \"gitlab.example.com\"\ntype = \"oauth2\"\n[company.oauth2]\n\
         client_id = \"public-client-id\"\nflow = \"device\"\nissuer = \"{issuer}\"\n{extra}\n"
    )
}

#[test]
fn endpoints_come_from_the_rfc_8414_document() {
    let provider = provider("/.well-known/oauth-authorization-server", |b| b.to_string());
    let ws = Workspace::new(&config(&provider.base(), ""));
    ws.cmd().args(["login", "-p", "company"]).assert().success();
    assert_eq!(provider.requests_to("/device").len(), 1);
    assert_eq!(provider.requests_to("/token").len(), 1);
}

#[test]
fn openid_configuration_is_the_fallback() {
    let provider = provider("/.well-known/openid-configuration", |b| format!("{b}/"));
    let ws = Workspace::new(&config(&provider.base(), ""));
    ws.cmd().args(["login", "-p", "company"]).assert().success();
    assert_eq!(provider.requests_to("/token").len(), 1);
}

#[test]
fn explicit_endpoints_override_discovered_ones() {
    let provider = provider("/.well-known/oauth-authorization-server", |b| b.to_string());
    let extra = format!(
        "token_endpoint = \"{0}/other-token\"\ndevice_authorization_endpoint = \"{0}/device\"",
        provider.base()
    );
    let ws = Workspace::new(&config(&provider.base(), &extra));
    // Everything is set, so the metadata is not even fetched; the made-up token path is hit
    ws.cmd().args(["login", "-p", "company"]).assert().failure();
    assert_eq!(
        provider
            .requests_to("/.well-known/oauth-authorization-server")
            .len(),
        0
    );
    assert_eq!(provider.requests_to("/other-token").len(), 1);
    assert_eq!(provider.requests_to("/token").len(), 0);
}

#[test]
fn a_document_for_another_issuer_is_refused() {
    let provider = provider("/.well-known/oauth-authorization-server", |_| {
        "https://evil.example.com".into()
    });
    let ws = Workspace::new(&config(&provider.base(), ""));
    ws.cmd()
        .args(["login", "-p", "company"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("different issuer"));
    assert_eq!(provider.requests_to("/token").len(), 0);
}

#[test]
fn unreachable_metadata_is_reported() {
    let provider = MockProvider::start(|_, _| (404, "{}".into()));
    let ws = Workspace::new(&config(&provider.base(), ""));
    ws.cmd()
        .args(["login", "-p", "company"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot discover the endpoints"));
}

#[test]
fn listing_does_not_touch_the_network() {
    let ws = Workspace::new(&config("http://127.0.0.1:9", ""));
    ws.cmd().arg("list").assert().success();
}
