//! `login` for basic profiles. The prompts need a terminal, so these run in a pty.

use expectrl::{session::OsSession, Eof, Expect, Session};
use predicates::prelude::*;

use crate::helpers::*;

fn start(ws: &Workspace, args: &[&str]) -> OsSession {
    let mut cmd = ws.std_cmd();
    cmd.arg("login").args(args);
    Session::spawn(cmd).unwrap()
}

fn finish(mut session: OsSession) -> String {
    let captured = session.expect(Eof).unwrap();
    String::from_utf8_lossy(captured.as_bytes()).into_owned()
}

fn stored_pair(ws: &Workspace, profile: &str) -> (String, String) {
    let value: serde_json::Value = serde_json::from_str(&ws.stored(profile).unwrap()).unwrap();
    (
        value["basic"]["username"].as_str().unwrap().to_string(),
        value["basic"]["password"].as_str().unwrap().to_string(),
    )
}

#[test]
fn stores_username_and_hidden_password_without_claiming_validation() {
    let ws = Workspace::new(CONFIG);
    let mut session = start(&ws, &["-p", "cache"]);
    session.expect("Username: ").unwrap();
    session.send_line(FAKE_USER).unwrap();
    let before_password = session.expect("Password or token: ").unwrap();
    let mut transcript = String::from_utf8_lossy(before_password.before()).into_owned();
    session.send_line(FAKE_PASSWORD).unwrap();
    transcript.push_str(&finish(session));
    let output = transcript;
    assert!(
        output.contains("Stored credentials for cache (cache.example.com)."),
        "{output}"
    );
    assert!(output.contains("not checked with the service"));
    assert!(
        !output.to_lowercase().contains("validated") && !output.to_lowercase().contains("verified")
    );
    // The password must never be echoed by the terminal
    assert!(
        !output.contains(FAKE_PASSWORD),
        "the password was echoed: {output}"
    );
    assert_eq!(
        stored_pair(&ws, "cache"),
        (FAKE_USER.into(), FAKE_PASSWORD.into())
    );
    // The identity of the profile is stored with it
    assert!(ws.stored("cache").unwrap().contains(&cache_identity()));
}

#[test]
fn a_personal_access_token_works_as_the_password() {
    let ws = Workspace::new(CONFIG);
    let mut session = start(&ws, &["-p", "cache"]);
    session.expect("Username: ").unwrap();
    session.send_line("token-owner").unwrap();
    session.expect("Password or token: ").unwrap();
    session.send_line("glpat-FAKE-PAT").unwrap();
    finish(session);
    assert_eq!(stored_pair(&ws, "cache").1, "glpat-FAKE-PAT");
}

#[test]
fn usable_credentials_are_reused_without_prompting() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let session = start(&ws, &["-p", "cache"]);
    let output = finish(session);
    assert!(
        output.contains("already has usable credentials"),
        "{output}"
    );
    assert!(!output.contains("Username"));
    assert_eq!(
        stored_pair(&ws, "cache"),
        (FAKE_USER.into(), FAKE_PASSWORD.into())
    );
}

#[test]
fn force_prompts_again_and_replaces_only_on_success() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let mut session = start(&ws, &["-p", "cache", "--force"]);
    session.expect("Username: ").unwrap();
    session.send_line("new-user").unwrap();
    session.expect("Password or token: ").unwrap();
    session.send_line("new-password").unwrap();
    finish(session);
    assert_eq!(
        stored_pair(&ws, "cache"),
        ("new-user".into(), "new-password".into())
    );
}

#[test]
fn cancelling_at_the_prompt_keeps_the_previous_credentials() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let mut session = start(&ws, &["-p", "cache", "--force"]);
    session.expect("Username: ").unwrap();
    session.send_line("half-typed").unwrap();
    session.expect("Password or token: ").unwrap();
    // Ctrl-C at the hidden prompt
    session.send(expectrl::ControlCode::EndOfText).unwrap();
    finish(session);
    assert_eq!(
        stored_pair(&ws, "cache"),
        (FAKE_USER.into(), FAKE_PASSWORD.into())
    );
}

#[test]
fn bad_selections_store_nothing() {
    let ws = Workspace::new(CONFIG);
    ws.cmd().args(["login", "-p", "nope"]).assert().code(2);
    ws.cmd().args(["login"]).assert().code(2);
    ws.cmd()
        .args(["login", "-p", "cache", "-p", "company"])
        .assert()
        .code(2);
    assert!(ws.stored("cache").is_none() && ws.stored("nope").is_none());
}

#[test]
fn without_a_terminal_credentials_cannot_be_asked_for() {
    let ws = Workspace::new(CONFIG);
    ws.cmd()
        .args(["login", "-p", "cache"])
        .write_stdin(format!("{FAKE_USER}\n{FAKE_PASSWORD}\n"))
        .assert()
        .code(1)
        .stderr(predicate::str::contains("interactive terminal"));
    assert!(ws.stored("cache").is_none());
}

#[test]
fn an_unavailable_store_fails_clearly_and_writes_nothing() {
    let ws = Workspace::new(CONFIG);
    ws.cmd()
        .env("NIX_VAULT_FILE_STORE_FAIL", "1")
        .args(["login", "-p", "cache"])
        .write_stdin("x\ny\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("credential store unavailable"));
    assert!(ws.stored("cache").is_none());
    assert_no_secrets(&ws.all_text_outside_store(), &[FAKE_PASSWORD, "y\n"]);
}
