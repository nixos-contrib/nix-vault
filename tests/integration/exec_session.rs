//! The temporary session: permissions, isolation, cleanup and what the child sees.

use std::{os::unix::fs::PermissionsExt, time::Instant};

use predicates::prelude::*;

use crate::helpers::*;

#[test]
fn session_files_are_owner_only_and_removed_afterwards() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let script = r#"
conf=${NIX_CONFIG##*!include }
dir=$(dirname "$conf")
ls -ld "$dir" "$(dirname "$dir")" "$conf" "$dir/netrc"
"#;
    let out = ws
        .cmd()
        .args(["exec", "-p", "cache", "--", "sh", "-c", script])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    let modes: Vec<&str> = text
        .lines()
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(
        modes,
        ["drwx------", "drwx------", "-rw-------", "-rw-------"]
    );
    assert!(
        ws.leftover_sessions().is_empty(),
        "{:?}",
        ws.leftover_sessions()
    );
}

#[test]
fn sessions_are_removed_after_failure_and_spawn_errors() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    ws.cmd()
        .args(["exec", "-p", "cache", "--", "false"])
        .assert()
        .code(1);
    assert!(ws.leftover_sessions().is_empty());
    ws.cmd()
        .args(["exec", "-p", "cache", "--", "definitely-not-a-command-xyz"])
        .assert()
        .code(127);
    assert!(ws.leftover_sessions().is_empty());
}

#[test]
fn concurrent_runs_use_different_directories() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let script = "conf=${NIX_CONFIG##*!include }; dirname \"$conf\" > \"$OUT\"; sleep 1";
    let mut children = Vec::new();
    for n in 0..2 {
        let mut cmd = ws.std_cmd();
        cmd.env("OUT", ws.path().join(format!("dir{n}")))
            .args(["exec", "-p", "cache", "--", "sh", "-c", script]);
        children.push(cmd.spawn().unwrap());
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    let a = std::fs::read_to_string(ws.path().join("dir0")).unwrap();
    let b = std::fs::read_to_string(ws.path().join("dir1")).unwrap();
    assert_ne!(a, b);
    assert!(ws.leftover_sessions().is_empty());
}

#[test]
fn nix_config_is_extended_not_replaced() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let out = ws
        .cmd()
        .env("NIX_CONFIG", "max-jobs = 3")
        .args([
            "exec",
            "-p",
            "cache",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$NIX_CONFIG\"",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.starts_with("max-jobs = 3\n!include "), "{text}");
    assert_eq!(text.matches("!include").count(), 1);
}

#[test]
fn secrets_are_not_in_the_childs_environment_or_arguments() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let out = ws
        .cmd()
        .args([
            "exec",
            "-p",
            "cache",
            "--",
            "sh",
            "-c",
            "env; echo \"$0 $*\"",
            "arg1",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_no_secrets(
        &String::from_utf8(out).unwrap(),
        &[FAKE_USER, FAKE_PASSWORD],
    );
}

#[test]
fn a_wrongly_protected_user_directory_is_refused() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let uid = std::fs::metadata(ws.tmp_dir()).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&uid);
    let dir = ws.tmp_dir().join(format!("nix-vault-{uid}"));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let marker = ws.path().join("ran");
    ws.cmd()
        .env("MARKER", &marker)
        .args(["exec", "-p", "cache", "--", "sh", "-c", "touch \"$MARKER\""])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("refusing to use it"));
    assert!(!marker.exists());
}

#[test]
fn exec_adds_little_overhead_when_credentials_are_usable() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let started = Instant::now();
    ws.cmd()
        .args(["exec", "-p", "cache", "--", "true"])
        .assert()
        .success();
    assert!(
        started.elapsed().as_secs_f64() < 1.0,
        "took {:?}",
        started.elapsed()
    );
}
