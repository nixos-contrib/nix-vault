//! `list`: names, hosts, types, credential presence and expiry, never a secret.

use predicates::prelude::*;

use crate::helpers::*;

#[test]
fn shows_each_credential_state_without_secrets() {
    let ws = Workspace::new(&format!(
        "{CONFIG}\n[old]\nhost = \"git.example.com\"\ntype = \"basic\"\n\
         [soon]\nhost = \"soon.example.com\"\ntype = \"oauth2\"\n[soon.oauth2]\nclient_id = \"c\"\n\
         flow = \"device\"\ndevice_authorization_endpoint = \"https://soon.example.com/d\"\n\
         token_endpoint = \"https://soon.example.com/t\"\n"
    ));
    ws.seed_basic("cache", &cache_identity(), FAKE_USER, FAKE_PASSWORD);
    ws.seed_oauth(
        "company",
        &company_identity(),
        FAKE_TOKEN,
        Some(FAKE_REFRESH),
        Some("2999-01-01T00:00:00Z"),
    );
    ws.seed_basic("old", "some-other-identity", FAKE_USER, FAKE_PASSWORD);
    ws.seed_oauth(
        "soon",
        &identity("oauth2", "soon.example.com", Some("c")),
        FAKE_TOKEN,
        None,
        Some("2000-01-01T00:00:00Z"),
    );
    let output = ws.cmd().arg("list").assert().success().get_output().clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("PROFILE"));
    let row = |name: &str| {
        stdout
            .lines()
            .find(|l| l.starts_with(name))
            .unwrap()
            .to_string()
    };
    assert!(row("cache").contains("basic") && row("cache").contains("stored"));
    assert!(row("company").contains("stored (refreshable)"));
    assert!(row("company").contains("2999-01-01T00:00:00Z"));
    assert!(row("old").contains("login again (changed)"));
    assert!(row("soon").contains("expired"));
    assert_no_secrets(
        &stdout,
        &[FAKE_USER, FAKE_PASSWORD, FAKE_TOKEN, FAKE_REFRESH],
    );
}

#[test]
fn shows_no_credentials_when_nothing_is_stored() {
    let ws = Workspace::new(CONFIG);
    ws.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"cache\s+cache\.example\.com\s+basic\s+no\s+-").unwrap());
}
