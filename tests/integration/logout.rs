//! `logout`: removes stored credentials, keeps the configuration.

use predicates::prelude::*;

use crate::helpers::*;

#[test]
fn removes_credentials_and_keeps_the_config() {
    let ws = Workspace::new(CONFIG);
    ws.seed_basic("cache", &cache_identity(), FAKE_USER, FAKE_PASSWORD);
    let before = std::fs::read(ws.config_file()).unwrap();
    let output = ws
        .cmd()
        .args(["logout", "-p", "cache"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not revoked at the service"))
        .get_output()
        .clone();
    assert_no_secrets(
        &String::from_utf8_lossy(&output.stdout),
        &[FAKE_USER, FAKE_PASSWORD],
    );
    assert!(ws.stored("cache").is_none());
    assert_eq!(std::fs::read(ws.config_file()).unwrap(), before);
    // exec now refuses with the login instruction
    ws.cmd()
        .args(["exec", "-p", "cache", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "run: nix-vault login --profile cache",
        ));
}

#[test]
fn nothing_stored_is_not_an_error() {
    let ws = Workspace::new(CONFIG);
    ws.cmd()
        .args(["logout", "-p", "cache"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No stored credentials for cache"));
}

#[test]
fn unknown_profile_is_a_usage_error() {
    let ws = Workspace::new(CONFIG);
    ws.cmd().args(["logout", "-p", "nope"]).assert().code(2);
}
