//! Process behavior: exit status, signals, arguments, stdin and no re-run.

use std::{
    io::Write,
    os::unix::process::ExitStatusExt,
    process::Stdio,
    time::{Duration, Instant},
};

use predicates::prelude::*;

use crate::helpers::*;

fn ws() -> Workspace {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    ws
}

#[test]
fn the_childs_exit_status_is_mirrored() {
    let ws = ws();
    for code in [0, 1, 42] {
        ws.cmd()
            .args([
                "exec",
                "-p",
                "cache",
                "--",
                "sh",
                "-c",
                &format!("exit {code}"),
            ])
            .assert()
            .code(code);
    }
}

#[test]
fn death_by_signal_is_reproduced() {
    let ws = ws();
    let status = ws
        .std_cmd()
        .args(["exec", "-p", "cache", "--", "sh", "-c", "kill -TERM $$"])
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(15), "status: {status:?}");
    assert!(ws.leftover_sessions().is_empty());
}

#[test]
fn argument_boundaries_are_preserved() {
    let ws = ws();
    ws.cmd()
        .args([
            "exec",
            "-p",
            "cache",
            "--",
            "sh",
            "-c",
            "printf '%s|' \"$@\"",
            "sh",
            "a b",
            "c'd",
            "",
            "--",
            "e\"f",
        ])
        .assert()
        .success()
        .stdout("a b|c'd||--|e\"f|");
}

#[test]
fn stdin_is_passed_through() {
    let ws = ws();
    ws.cmd()
        .args(["exec", "-p", "cache", "--", "cat"])
        .write_stdin("hello from stdin")
        .assert()
        .success()
        .stdout("hello from stdin");
}

#[test]
fn missing_and_non_executable_commands_have_distinct_statuses() {
    let ws = ws();
    ws.cmd()
        .args(["exec", "-p", "cache", "--", "definitely-not-a-command-xyz"])
        .assert()
        .code(127)
        .stderr(predicate::str::contains("command not found"));
    let file = ws.path().join("not-executable");
    std::fs::write(&file, "#!/bin/sh\n").unwrap();
    ws.cmd()
        .args(["exec", "-p", "cache", "--", file.to_str().unwrap()])
        .assert()
        .code(126);
    assert!(ws.leftover_sessions().is_empty());
}

#[test]
fn a_failing_command_is_never_run_again() {
    let ws = ws();
    let counter = ws.path().join("count");
    ws.cmd()
        .env("COUNTER", &counter)
        .args([
            "exec",
            "-p",
            "cache",
            "--",
            "sh",
            "-c",
            "echo run >> \"$COUNTER\"; exit 1",
        ])
        .assert()
        .code(1);
    assert_eq!(
        std::fs::read_to_string(&counter).unwrap().lines().count(),
        1
    );
}

#[test]
fn sigterm_is_forwarded_and_the_session_is_removed() {
    let ws = ws();
    let ready = ws.path().join("ready");
    let got = ws.path().join("got");
    let script = "trap 'echo term > \"$GOT\"; exit 7' TERM; echo ready > \"$READY\"; \
                  while :; do sleep 0.1; done";
    let mut cmd = ws.std_cmd();
    cmd.env("READY", &ready)
        .env("GOT", &got)
        .args(["exec", "-p", "cache", "--", "sh", "-c", script]);
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "child never became ready");
        std::thread::sleep(Duration::from_millis(20));
    }
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(7), "status: {status:?}");
    assert_eq!(std::fs::read_to_string(&got).unwrap().trim(), "term");
    assert!(ws.leftover_sessions().is_empty());
}

#[test]
fn interactive_input_reaches_the_child() {
    let ws = ws();
    let mut child = ws
        .std_cmd()
        .args(["exec", "-p", "cache", "--", "sh"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"echo hi$((1+1))\nexit 3\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stdout).contains("hi2"));
}
