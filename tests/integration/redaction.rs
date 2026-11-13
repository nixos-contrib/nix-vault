//! Distinctive fake secrets must never reach output, backtraces or leftover files.

use crate::helpers::*;

const SAMPLE: &str = include_str!("../fixtures/netrc/sample");
const ALL: [&str; 6] = [
    FAKE_USER,
    FAKE_PASSWORD,
    FAKE_TOKEN,
    "KEEP_SECRET_1",
    "OLD_SECRET_2",
    "USER_OWN_TOKEN",
];

fn setup() -> Workspace {
    let ws = Workspace::new(&format!(
        "{CONFIG}\n[mirror]\nhost = \"cache.example.com\"\ntype = \"basic\"\n"
    ));
    ws.seed_cache();
    ws.seed_oauth("company", &company_identity(), FAKE_TOKEN, None, None);
    let user_netrc = ws.path().join("user-netrc");
    std::fs::write(&user_netrc, SAMPLE).unwrap();
    ws.nix.set(
        &[("gitlab.example.com", "USER_OWN_TOKEN")],
        Some(&user_netrc),
    );
    ws
}

fn all_output(ws: &Workspace, args: &[&str]) -> String {
    let output = ws
        .cmd()
        .env("RUST_BACKTRACE", "1")
        .args(args)
        .output()
        .unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn commands_never_print_secrets() {
    let ws = setup();
    let variants: [&[&str]; 9] = [
        &["exec", "-p", "cache", "-p", "company", "--", "true"],
        &["exec", "-p", "cache", "--", "false"],
        &["exec", "-p", "cache", "--", "definitely-not-a-command-xyz"],
        &["exec", "-p", "nope", "--", "true"],
        &["exec", "-p", "mirror", "--", "true"],
        &["list"],
        &["logout", "-p", "mirror"],
        &["login", "-p", "nope"],
        &["login", "-p", "cache", "-p", "company"],
    ];
    for args in variants {
        let text = all_output(&ws, args);
        assert_no_secrets(&text, &ALL);
    }
}

#[test]
fn a_conflict_between_profiles_does_not_leak_either_secret() {
    let ws = setup();
    ws.seed_basic(
        "mirror",
        &identity("basic", "cache.example.com", None),
        "other",
        "OTHER_PW_55",
    );
    let text = all_output(&ws, &["exec", "-p", "cache", "-p", "mirror", "--", "true"]);
    assert_no_secrets(&text, &[FAKE_PASSWORD, "OTHER_PW_55", FAKE_USER]);
}

#[test]
fn nothing_secret_is_left_behind_in_the_workspace() {
    let ws = setup();
    ws.cmd()
        .args([
            "exec",
            "-p",
            "cache",
            "-p",
            "company",
            "--",
            "sh",
            "-c",
            SHOW_SESSION,
        ])
        .assert()
        .success();
    ws.cmd().arg("list").assert().success();
    // No file, the encrypted store included, may hold them in the clear
    let text = ws.all_text();
    for secret in [FAKE_USER, FAKE_PASSWORD, FAKE_TOKEN] {
        assert!(!text.contains(secret), "{secret} found in a leftover file");
    }
}
