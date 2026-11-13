//! `type = "process"`: a helper command prints the credential; nothing is stored.

use std::os::unix::fs::PermissionsExt;

use predicates::prelude::*;

use crate::helpers::*;

// Fake JWT-shaped tokens: {"exp":4102444800} (year 2100) and {"exp":1000000000} (year 2001)
const FUTURE_JWT: &str = "aGVhZGVy.eyJleHAiOjQxMDI0NDQ4MDB9.FAKE_SIGNATURE_5e2";
const PAST_JWT: &str = "aGVhZGVy.eyJleHAiOjEwMDAwMDAwMDB9.FAKE_SIGNATURE_5e2";

/// A process profile whose command is the script `helper`, in the workspace.
fn config(ws_dir: &std::path::Path, format: &str) -> String {
    format!(
        "[svc]\nhost = \"proxy.invalid\"\ntype = \"process\"\n[svc.process]\n\
         command = [\"{}/helper\"]\ncommand_output_format = \"{format}\"\n\
         [svc.proxy]\nheaders = {{ cf-access-token = \"{{access_token}}\" }}\n",
        ws_dir.display()
    )
}

/// A workspace whose helper runs `script` (a shell script body).
fn workspace(format: &str, script: &str) -> Workspace {
    let ws = Workspace::new("");
    let helper = ws.path().join("helper");
    std::fs::write(&helper, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    ws.set_config(&config(ws.path(), format));
    ws
}

const PROBE: &str = r#"
conf=${NIX_CONFIG##*!include }
cat "$conf"
echo '--- with the prefix'
curl -s -o /dev/null -w '%{http_code}\n' "$NIX_VAULT_PROXY_SVC/nix-cache-info"
"#;

#[test]
fn the_helpers_token_is_served_through_the_proxy_and_stored_nowhere() {
    // The token is assembled when the script runs, so its text is in no file of the workspace
    let ws = workspace(
        "text",
        "printf '%s.%s.%s%s\\n' aGVhZGVy eyJleHAiOjQxMDI0NDQ4MDB9 FAKE_SIGNATURE_ 5e2",
    );
    let output = ws
        .cmd()
        .args(["exec", "-p", "svc", "--", "sh", "-c", PROBE])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("substituters = http://127.0.0.1:"));
    // 502: the proxy is up and its upstream does not resolve
    assert!(stdout
        .split("--- with the prefix\n")
        .nth(1)
        .unwrap()
        .starts_with("502"));
    assert!(!stdout.contains(FUTURE_JWT));
    assert_no_secrets(&stderr, &[FUTURE_JWT, "FAKE_SIGNATURE_5e2"]);
    // Nothing was stored, and the session is gone
    assert!(!ws.all_text().contains("FAKE_SIGNATURE_5e2"));
    assert!(ws.leftover_sessions().is_empty());
}

#[test]
fn a_json_helper_works_too() {
    let ws = workspace(
        "json",
        "echo '{\"access_token\":\"fake-json-token-7a1\",\"expires_at\":\"2100-01-01T00:00:00Z\"}'",
    );
    ws.cmd()
        .args(["exec", "-p", "svc", "--", "sh", "-c", PROBE])
        .assert()
        .success()
        .stdout(predicate::str::contains("substituters = http://127.0.0.1:"))
        .stdout(predicate::str::contains("fake-json-token-7a1").not());
}

#[test]
fn a_failing_helper_stops_exec_before_launch_and_its_messages_are_shown() {
    let ws = workspace("text", "echo 'run: fake-tool login' >&2; exit 3");
    let marker = ws.path().join("launched");
    ws.cmd()
        .args(["exec", "-p", "svc", "--", "touch"])
        .arg(&marker)
        .assert()
        .failure()
        .stderr(predicate::str::contains("run: fake-tool login"))
        .stderr(predicate::str::contains(
            "the command of profile \"svc\" failed with",
        ));
    assert!(!marker.exists(), "the command must not be launched");
}

#[test]
fn bad_output_is_refused_without_quoting_it() {
    for (format, script, expect) in [
        ("text", "echo", "printed nothing"),
        (
            "text",
            "echo 'secret-looking part one'",
            "more than one line or word",
        ),
        (
            "text",
            "printf 'first\\nSECOND_LINE_SECRET\\n'",
            "more than one line or word",
        ),
        ("json", "echo 'not json SECRET_JSON_9'", "not valid JSON"),
        ("json", "echo '{\"username\":\"u\"}'", "JSON without"),
        ("text", &format!("echo {PAST_JWT}"), "already expired"),
    ] {
        let ws = workspace(format, script);
        let output = ws
            .cmd()
            .args(["exec", "-p", "svc", "--", "true"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(expect))
            .get_output()
            .clone();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_no_secrets(
            &stderr,
            &[
                "SECOND_LINE_SECRET",
                "SECRET_JSON_9",
                "secret-looking",
                "FAKE_SIGNATURE_5e2",
            ],
        );
    }
}

#[test]
fn a_missing_program_is_reported_by_profile() {
    let ws = Workspace::new(
        "[svc]\nhost = \"proxy.invalid\"\ntype = \"process\"\n[svc.process]\n\
         command = [\"no-such-helper-program\"]\n[svc.proxy]\n\
         headers = { X = \"{access_token}\" }\n",
    );
    ws.cmd()
        .args(["exec", "-p", "svc", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "the command of profile \"svc\" cannot be run",
        ));
}

#[test]
fn login_logout_and_list_do_not_run_the_helper() {
    let ws = workspace("text", "touch \"$(dirname \"$0\")/ran\"; echo tok");
    ws.cmd()
        .args(["login", "-p", "svc"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "gets its credential from a command",
        ));
    ws.cmd()
        .args(["logout", "-p", "svc"])
        .assert()
        .success()
        .stdout(predicate::str::contains("stores no credentials"));
    ws.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("process"))
        .stdout(predicate::str::contains("from a command"));
    assert!(!ws.path().join("ran").exists());
}

#[test]
fn a_config_file_others_can_write_is_refused_when_it_has_process_profiles() {
    let ws = workspace("text", "echo tok");
    std::fs::set_permissions(ws.config_file(), std::fs::Permissions::from_mode(0o666)).unwrap();
    ws.cmd()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("can be written by other users"))
        .stderr(predicate::str::contains("chmod go-w"));
    // Without process profiles the mode is not checked
    ws.set_config("[a]\nhost = \"h.example\"\ntype = \"basic\"\n");
    std::fs::set_permissions(ws.config_file(), std::fs::Permissions::from_mode(0o666)).unwrap();
    ws.cmd().arg("list").assert().success();
}

#[test]
fn process_profiles_are_validated() {
    let check = |config: &str, expect: &str| {
        Workspace::new(config)
            .cmd()
            .arg("list")
            .assert()
            .failure()
            .stderr(predicate::str::contains(expect.to_string()));
    };
    let head = "[a]\nhost = \"h.example\"\ntype = \"process\"\n";
    let proxy = "[a.proxy]\nheaders = { X = \"{access_token}\" }\n";
    check(
        &format!("{head}[a.process]\ncommand = [\"cloudflared access token\"]\n{proxy}"),
        "an array of the program and its arguments",
    );
    check(
        &format!("{head}[a.process]\ncommand = []\n{proxy}"),
        "non-empty array",
    );
    check(
        &format!("{head}{proxy}"),
        "missing required table [a.process]",
    );
    check(
        &format!("{head}[a.process]\ncommand = [\"x\"]\ncommand_output_format = \"xml\"\n{proxy}"),
        "must be \"text\" or \"json\"",
    );
    check(
        &format!("{head}[a.process]\ncommand = [\"x\"]\n[a.nix]\nuse = [\"netrc\"]\n{proxy}"),
        "delivered through the proxy only",
    );
    check(
        &format!("{head}[a.process]\ncommand = [\"x\"]\n"),
        "needs a [a.proxy] table",
    );
    check(
        &format!("{head}[a.process]\ncommand = [\"x\"]\n[a.proxy]\nheaders = {{ X = \"{{password}}\" }}\n"),
        "this profile type does not have",
    );
    check(
        "[a]\nhost = \"h.example\"\ntype = \"basic\"\n[a.process]\ncommand = [\"x\"]\n",
        "[process] is only valid for process profiles",
    );
    check(
        "[a]\nhost = \"h.example\"\ntype = \"basic\"\ncommand = [\"x\"]\n",
        "\"command\" belongs in [a.process]",
    );
}
