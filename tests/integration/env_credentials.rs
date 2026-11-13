//! `[<profile>.basic]`: a basic profile reads its credentials from environment variables.
//! Nothing is stored, and the keychain (or the file store) is never opened.

use predicates::prelude::*;

use crate::helpers::*;

const CI_USER: &str = "oauth2";
const CI_TOKEN: &str = "FAKE_CI_TOKEN_6b8e";

const CONFIG: &str = r#"
[ci]
host = "cache.example.com"
type = "basic"

[ci.basic]
username_env = "CI_USER"
password_env = "CI_TOKEN"
"#;

#[test]
fn the_credentials_reach_nix_through_the_session_netrc_and_nothing_is_stored() {
    let ws = Workspace::new(CONFIG);
    let output = ws
        .cmd()
        .env("CI_USER", CI_USER)
        .env("CI_TOKEN", CI_TOKEN)
        .args(["exec", "-p", "ci", "--", "sh", "-c", SHOW_SESSION])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains(&format!(
        "machine cache.example.com login {CI_USER} password {CI_TOKEN}"
    )));
    assert_no_secrets(&stderr, &[CI_TOKEN]);
    // Nothing was written: no store entry, and the session is gone
    assert!(!ws.store_dir().join("credentials.age").exists());
    assert!(ws.leftover_sessions().is_empty());
}

#[test]
fn the_store_is_never_opened_for_these_profiles() {
    // An unusable store: any command that opened it would fail with a configuration error
    let ws = Workspace::new(CONFIG);
    let cmd = |args: &[&str]| {
        let mut cmd = ws.cmd();
        cmd.env("NIX_VAULT_STORE", "no-such-store")
            .env("CI_USER", CI_USER)
            .env("CI_TOKEN", CI_TOKEN)
            .args(args);
        cmd
    };
    cmd(&["exec", "-p", "ci", "--", "true"]).assert().success();
    cmd(&["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("environment"));
    cmd(&["login", "-p", "ci"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "reads its credentials from the environment",
        ));
    cmd(&["logout", "-p", "ci"])
        .assert()
        .success()
        .stdout(predicate::str::contains("reads them from the environment"));
}

#[test]
fn a_missing_or_empty_variable_stops_exec_before_launch_and_is_named() {
    for (user, token, named, what) in [
        (Some("u"), None, "CI_TOKEN", "is not set"),
        (None, Some(CI_TOKEN), "CI_USER", "is not set"),
        (Some(""), Some(CI_TOKEN), "CI_USER", "is empty"),
        (Some("u"), Some(""), "CI_TOKEN", "is empty"),
    ] {
        let ws = Workspace::new(CONFIG);
        let marker = ws.path().join("launched");
        let mut cmd = ws.cmd();
        if let Some(user) = user {
            cmd.env("CI_USER", user);
        }
        if let Some(token) = token {
            cmd.env("CI_TOKEN", token);
        }
        let output = cmd
            .args(["exec", "-p", "ci", "--", "touch"])
            .arg(&marker)
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "the variable {named} {what}"
            )))
            .get_output()
            .clone();
        assert!(!marker.exists(), "the command must not be launched");
        assert_no_secrets(&String::from_utf8(output.stderr).unwrap(), &[CI_TOKEN]);
    }
}

#[test]
fn two_profiles_can_take_different_variables() {
    let ws = Workspace::new(&format!(
        "{CONFIG}\n[other]\nhost = \"other.example.com\"\ntype = \"basic\"\n\
         [other.basic]\nusername_env = \"OTHER_USER\"\npassword_env = \"OTHER_TOKEN\"\n"
    ));
    let output = ws
        .cmd()
        .env("CI_USER", CI_USER)
        .env("CI_TOKEN", CI_TOKEN)
        .env("OTHER_USER", "second")
        .env("OTHER_TOKEN", "FAKE_OTHER_TOKEN_2c")
        .args([
            "exec",
            "-p",
            "ci",
            "-p",
            "other",
            "--",
            "sh",
            "-c",
            SHOW_SESSION,
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!(
        "machine cache.example.com login {CI_USER} password {CI_TOKEN}"
    )));
    assert!(stdout.contains("machine other.example.com login second password FAKE_OTHER_TOKEN_2c"));
}

#[test]
fn the_variables_are_left_in_the_commands_environment() {
    // Decided and documented: they were put there by the CI job, and removing them would
    // surprise a command that needs them too
    let ws = Workspace::new(CONFIG);
    ws.cmd()
        .env("CI_USER", CI_USER)
        .env("CI_TOKEN", CI_TOKEN)
        .args([
            "exec",
            "-p",
            "ci",
            "--",
            "sh",
            "-c",
            "echo ${CI_TOKEN:+inherited}",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("inherited"));
}

#[test]
fn the_credentials_can_be_delivered_through_the_proxy() {
    let ws = Workspace::new(
        r#"
[ci]
host = "proxy.invalid"
type = "basic"

[ci.basic]
username_env = "CI_USER"
password_env = "CI_TOKEN"

[ci.nix]
use = ["proxy"]

[ci.proxy]
headers = { CF-Access-Client-Id = "{username}", CF-Access-Client-Secret = "{password}" }
"#,
    );
    let output = ws
        .cmd()
        .env("CI_USER", "fake-client-id.access")
        .env("CI_TOKEN", CI_TOKEN)
        .args([
            "exec",
            "-p",
            "ci",
            "--",
            "sh",
            "-c",
            "cat \"${NIX_CONFIG##*!include }\"",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("substituters = http://127.0.0.1:"));
    assert!(!stdout.contains(CI_TOKEN) && !stdout.contains("netrc-file"));
}

#[test]
fn the_table_is_validated() {
    let check = |config: &str, expect: &str| {
        Workspace::new(config)
            .cmd()
            .arg("list")
            .assert()
            .failure()
            .stderr(predicate::str::contains(expect.to_string()));
    };
    let head = "[a]\nhost = \"h.example\"\ntype = \"basic\"\n";
    check(
        &format!("{head}[a.basic]\nusername_env = \"U\"\npassword = \"literal-secret\"\n"),
        "\"password\" must not be stored",
    );
    check(
        &format!("{head}[a.basic]\nusername_env = \"U\"\n"),
        "missing required key \"password_env\"",
    );
    check(
        &format!("{head}[a.basic]\nusername_env = \"1BAD\"\npassword_env = \"T\"\n"),
        "\"username_env\" must be the name of an environment variable",
    );
    check(
        &format!("{head}[a.basic]\nusername_env = \"SAME\"\npassword_env = \"SAME\"\n"),
        "must be different variables",
    );
    check(
        &format!("{head}username_env = \"U\"\n"),
        "\"username_env\" belongs in [a.basic]",
    );
    check(
        "[a]\nhost = \"h.example\"\ntype = \"oauth2\"\n[a.oauth2]\nclient_id = \"c\"\nflow = \"device\"\n\
         device_authorization_endpoint = \"https://h.example/d\"\ntoken_endpoint = \"https://h.example/t\"\n\
         [a.basic]\nusername_env = \"U\"\npassword_env = \"T\"\n",
        "[basic] is only valid for basic profiles",
    );
}
