//! What Nix is given: merged netrc, merged access tokens, and the user's files left alone.

use std::os::unix::fs::PermissionsExt;

use predicates::prelude::*;
use sha2::{Digest, Sha256};

use crate::helpers::*;

const SAMPLE: &str = include_str!("../fixtures/netrc/sample");

fn hash(path: &std::path::Path) -> Option<String> {
    std::fs::read(path).ok().map(|b| {
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect()
    })
}

fn run(ws: &Workspace, profiles: &[&str]) -> (String, String) {
    let mut cmd = ws.cmd();
    cmd.arg("exec");
    for p in profiles {
        cmd.args(["-p", p]);
    }
    cmd.args(["--", "sh", "-c", SHOW_SESSION]);
    let output = cmd.assert().success().get_output().clone();
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn the_users_netrc_is_copied_verbatim_except_overridden_hosts() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let user_netrc = ws.path().join("user-netrc");
    std::fs::write(&user_netrc, SAMPLE).unwrap();
    ws.nix.set(&[], Some(&user_netrc));
    let (stdout, stderr) = run(&ws, &["cache"]);
    let netrc = stdout.split("--- netrc\n").nth(1).unwrap();

    // Kept byte for byte: comments, quoted entries, the macro body and the default entry
    assert!(netrc.contains("# Logins for the team (fake values only)"));
    assert!(netrc.contains("machine keep.example.com login keepuser password KEEP_SECRET_1"));
    assert!(
        netrc.contains("machine \"quoted.example.com\" login \"user name\" password \"pass word\"")
    );
    assert!(netrc.contains("macdef init\nmachine inside-macro.example.com login macrouser"));
    assert!(netrc.contains("default login anonymous password anon@example.com"));
    // The overridden host's old entry is gone and the selected one is present, before `default`
    assert!(!netrc.contains("OLD_SECRET_2"));
    let new_at = netrc
        .find(&format!(
            "machine cache.example.com login {FAKE_USER} password {FAKE_PASSWORD}"
        ))
        .expect("selected entry");
    assert!(new_at < netrc.find("default login").unwrap());
    // The clash is announced by host only
    assert!(
        stderr.contains("profile \"cache\" replaces existing credentials for cache.example.com")
    );
    assert_no_secrets(
        &stderr,
        &[FAKE_USER, FAKE_PASSWORD, "OLD_SECRET_2", "KEEP_SECRET_1"],
    );
    // And the user's file is untouched
    assert_eq!(std::fs::read_to_string(&user_netrc).unwrap(), SAMPLE);
}

#[test]
fn a_missing_user_netrc_starts_empty() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let (stdout, stderr) = run(&ws, &["cache"]);
    assert!(stdout.contains("machine cache.example.com"));
    assert!(!stderr.contains("warning"));
}

#[test]
fn an_unreadable_user_netrc_is_skipped_with_a_warning_naming_the_file() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let user_netrc = ws.path().join("root-only-netrc");
    std::fs::write(&user_netrc, SAMPLE).unwrap();
    std::fs::set_permissions(&user_netrc, std::fs::Permissions::from_mode(0o000)).unwrap();
    ws.nix.set(&[], Some(&user_netrc));
    let (stdout, stderr) = run(&ws, &["cache"]);
    std::fs::set_permissions(&user_netrc, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(stderr.contains("warning: cannot read netrc-file"));
    assert!(stderr.contains("root-only-netrc"));
    assert_no_secrets(&stderr, &["KEEP_SECRET_1", "OLD_SECRET_2"]);
    assert!(stdout.contains("machine cache.example.com"));
    assert!(!stdout.contains("KEEP_SECRET_1"));
}

#[test]
fn access_tokens_are_merged_with_the_selected_profile_winning() {
    let config = format!(
        "{CONFIG}\n[hub]\nhost = \"github.com\"\ntype = \"basic\"\n[hub.nix]\nuse = [\"access-token\"]\n\
         [lab]\nhost = \"gitlab.example.com\"\ntype = \"basic\"\n[lab.nix]\nuse = [\"access-token\"]\n"
    );
    let ws = Workspace::new(&config);
    ws.seed_basic(
        "hub",
        &identity("basic", "github.com", None),
        "u",
        "ghp_FAKE",
    );
    ws.seed_basic(
        "lab",
        &identity("basic", "gitlab.example.com", None),
        "u",
        "glpat_FAKE",
    );
    ws.nix.set(
        &[
            ("old.example.com", "OLD_TOKEN"),
            ("gitlab.example.com", "USER_OWN_TOKEN"),
        ],
        None,
    );
    let (stdout, stderr) = run(&ws, &["hub", "lab"]);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("access-tokens ="))
        .unwrap();
    assert!(line.contains("old.example.com=OLD_TOKEN"), "{line}");
    assert!(
        line.contains("github.com=ghp_FAKE"),
        "github.com is bare: {line}"
    );
    assert!(line.contains("gitlab.example.com=PAT:glpat_FAKE"), "{line}");
    assert!(!line.contains("USER_OWN_TOKEN"), "{line}");
    assert!(stderr.contains("replaces existing credentials for gitlab.example.com"));
    assert_no_secrets(
        &stderr,
        &["USER_OWN_TOKEN", "OLD_TOKEN", "ghp_FAKE", "glpat_FAKE"],
    );
    // No netrc was requested, so no netrc-file line
    assert!(!stdout.contains("netrc-file"));
}

#[test]
fn style_can_be_set_and_both_mechanisms_can_be_used_together() {
    let config = "[both]\nhost = \"git.example.com\"\ntype = \"basic\"\n\
                  [both.nix]\nuse = [\"access-token\", \"netrc\"]\naccess_token_style = \"plain\"\n";
    let ws = Workspace::new(config);
    ws.seed_basic(
        "both",
        &identity("basic", "git.example.com", None),
        "bob",
        "pw1",
    );
    let (stdout, _) = run(&ws, &["both"]);
    assert!(stdout.contains("access-tokens = git.example.com=pw1"));
    assert!(stdout.contains("netrc-file = "));
    assert!(stdout.contains("machine git.example.com login bob password pw1"));
}

#[test]
fn oauth_netrc_uses_the_fixed_oauth2_username() {
    let ws = Workspace::new(&format!("{CONFIG}\n[company.nix]\nuse = [\"netrc\"]\n"));
    ws.seed_oauth("company", &company_identity(), FAKE_TOKEN, None, None);
    let (stdout, _) = run(&ws, &["company"]);
    assert!(
        stdout.contains(&format!(
            "machine gitlab.example.com login oauth2 password {FAKE_TOKEN}"
        )),
        "{stdout}"
    );
    // Only the netrc sub-table exists, so there is no access token
    assert!(!stdout.contains("access-tokens"));
}

#[test]
fn the_users_own_files_are_unchanged_by_login_free_commands() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let nix_conf = ws.path().join(".config/nix/nix.conf");
    std::fs::create_dir_all(nix_conf.parent().unwrap()).unwrap();
    std::fs::write(&nix_conf, "max-jobs = 2\n").unwrap();
    let user_netrc = ws.path().join(".netrc");
    std::fs::write(&user_netrc, SAMPLE).unwrap();
    ws.nix.set(&[], Some(&user_netrc));
    let before = (hash(&nix_conf), hash(&user_netrc), hash(&ws.config_file()));
    run(&ws, &["cache"]);
    ws.cmd().arg("list").assert().success();
    ws.cmd().args(["logout", "-p", "cache"]).assert().success();
    assert_eq!(
        before,
        (hash(&nix_conf), hash(&user_netrc), hash(&ws.config_file()))
    );
}

#[test]
fn a_nix_that_cannot_be_run_prevents_launch() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    let marker = ws.path().join("ran");
    ws.cmd()
        .env("PATH", ws.path().join("no-such-dir"))
        .env("MARKER", &marker)
        .args(["exec", "-p", "cache", "--", "sh", "-c", "touch \"$MARKER\""])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "cannot read the Nix configuration",
        ));
    assert!(!marker.exists());
}
