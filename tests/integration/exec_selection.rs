//! Profile selection: explicit, deduplicated, conflict-checked before anything is launched.

use predicates::prelude::*;

use crate::helpers::*;

fn two_hosts_same() -> String {
    format!("{CONFIG}\n[mirror]\nhost = \"cache.example.com\"\ntype = \"basic\"\n")
}

#[test]
fn requires_an_explicit_profile() {
    let ws = Workspace::new(CONFIG);
    ws.cmd()
        .args(["exec", "--", "true"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("at least one --profile"));
}

#[test]
fn unknown_profile_is_a_usage_error() {
    let ws = Workspace::new(CONFIG);
    ws.cmd()
        .args(["exec", "-p", "nope", "--", "true"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown profile \"nope\""));
}

#[test]
fn the_same_profile_twice_is_selected_once() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let out = ws
        .cmd()
        .args([
            "exec",
            "-p",
            "cache",
            "-p",
            "cache",
            "--",
            "sh",
            "-c",
            SHOW_SESSION,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(text.matches("machine cache.example.com").count(), 1);
}

#[test]
fn profiles_on_different_hosts_are_both_delivered() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    ws.seed_oauth("company", &company_identity(), FAKE_TOKEN, None, None);
    let out = ws
        .cmd()
        .args([
            "exec",
            "-p",
            "company",
            "-p",
            "cache",
            "--",
            "sh",
            "-c",
            SHOW_SESSION,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    // oauth2 defaults to an access token (by_type prefix), basic to netrc
    assert!(text.contains("access-tokens = gitlab.example.com=OAuth2:FAKE_TOKEN_91bc"));
    assert!(text.contains(&format!(
        "machine cache.example.com login {FAKE_USER} password {FAKE_PASSWORD}"
    )));
}

#[test]
fn different_credentials_for_the_same_host_are_rejected_before_launch() {
    let ws = Workspace::new(&two_hosts_same());
    ws.seed_cache();
    ws.seed_basic(
        "mirror",
        &identity("basic", "cache.example.com", None),
        "other",
        "other-pw",
    );
    let marker = ws.path().join("ran");
    ws.cmd()
        .env("MARKER", &marker)
        .args([
            "exec",
            "-p",
            "cache",
            "-p",
            "mirror",
            "--",
            "sh",
            "-c",
            "touch \"$MARKER\"",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("\"cache\" and \"mirror\""))
        .stderr(predicate::str::contains("cache.example.com"));
    assert!(!marker.exists(), "the child must not be launched");
}

#[test]
fn identical_credentials_for_the_same_host_are_merged() {
    let ws = Workspace::new(&two_hosts_same());
    ws.seed_cache();
    ws.seed_basic(
        "mirror",
        &identity("basic", "cache.example.com", None),
        FAKE_USER,
        FAKE_PASSWORD,
    );
    let out = ws
        .cmd()
        .args([
            "exec",
            "-p",
            "cache",
            "-p",
            "mirror",
            "--",
            "sh",
            "-c",
            SHOW_SESSION,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8(out)
            .unwrap()
            .matches("machine cache.example.com")
            .count(),
        1
    );
}

#[test]
fn different_credentials_conflict_even_across_mechanisms() {
    let config = format!(
        "{CONFIG}\n[mirror]\nhost = \"cache.example.com\"\ntype = \"basic\"\n[mirror.nix]\nuse = [\"access-token\"]\n"
    );
    let ws = Workspace::new(&config);
    ws.seed_cache();
    ws.seed_basic(
        "mirror",
        &identity("basic", "cache.example.com", None),
        "other",
        "other-pw",
    );
    ws.cmd()
        .args(["exec", "-p", "cache", "-p", "mirror", "--", "true"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "different credentials for cache.example.com",
        ));
}

#[test]
fn missing_credentials_refuse_with_the_login_instruction() {
    let ws = Workspace::new(CONFIG);
    let marker = ws.path().join("ran");
    ws.cmd()
        .env("MARKER", &marker)
        .args([
            "exec",
            "-p",
            "cache",
            "-p",
            "company",
            "--",
            "sh",
            "-c",
            "touch \"$MARKER\"",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "profile \"cache\" has no usable credentials; run: nix-vault login --profile cache",
        ))
        .stderr(predicate::str::contains(
            "profile \"company\" has no usable credentials; run: nix-vault login --profile company",
        ));
    assert!(!marker.exists());
}

#[test]
fn credentials_persist_across_exec_runs() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let before = ws.stored("cache").unwrap();
    for _ in 0..2 {
        ws.cmd()
            .args(["exec", "-p", "cache", "--", "true"])
            .assert()
            .success();
    }
    assert_eq!(ws.stored("cache").unwrap(), before);
}
