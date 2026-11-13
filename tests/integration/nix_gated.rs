//! Tests against the real `nix`. They are skipped when `nix` is not installed.

use std::process::Command;

use crate::helpers::{
    oauth::{base64url, MockProvider},
    *,
};

fn real_nix() -> Option<std::path::PathBuf> {
    let output = Command::new("sh")
        .args(["-c", "command -v nix"])
        .output()
        .ok()?;
    let path = String::from_utf8(output.stdout).ok()?;
    let path = path.trim();
    (!path.is_empty()).then(|| path.into())
}

fn workspace(config: &str) -> Workspace {
    let ws = Workspace::new(config);
    // The real nix keeps its caches inside the workspace
    std::fs::create_dir_all(ws.path().join("cache")).unwrap();
    ws
}

#[test]
fn real_nix_sees_the_merged_access_tokens_through_the_include() {
    let Some(nix) = real_nix() else {
        eprintln!("skipped: nix is not installed");
        return;
    };
    let ws = workspace("[hub]\nhost = \"github.com\"\ntype = \"basic\"\n[hub.access-token]\n");
    ws.seed_basic(
        "hub",
        &identity("basic", "github.com", None),
        "u",
        "ghp_FAKE_TOKEN",
    );
    let out = ws
        .cmd()
        .env("NIX_VAULT_NIX", &nix)
        .env("XDG_CACHE_HOME", ws.path().join("cache"))
        .env("NIX_CONFIG", "max-jobs = 3")
        .args(["exec", "-p", "hub", "--", "nix", "config", "show", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        json["access-tokens"]["value"]["github.com"],
        "ghp_FAKE_TOKEN"
    );
    // The user's own NIX_CONFIG is still in effect
    assert_eq!(json["max-jobs"]["value"], 3);
}

#[test]
fn real_nix_sends_the_netrc_login_to_a_cache_and_not_without_exec() {
    let Some(nix) = real_nix() else {
        eprintln!("skipped: nix is not installed");
        return;
    };
    let provider = MockProvider::start(|_, _| (404, "{}".into()));
    let config = "[cache]\nhost = \"127.0.0.1\"\ntype = \"basic\"\n";
    let ws = workspace(config);
    ws.seed_basic(
        "cache",
        &identity("basic", "127.0.0.1", None),
        "cacheuser",
        "cachepass",
    );
    let store = format!("http://127.0.0.1:{}", provider.port);
    let probe = [
        "nix",
        "path-info",
        "--store",
        &store,
        "/nix/store/00000000000000000000000000000000-fake",
    ];

    let mut with_exec = ws.cmd();
    with_exec
        .env("NIX_VAULT_NIX", &nix)
        .env("XDG_CACHE_HOME", ws.path().join("cache"))
        .args(["exec", "-p", "cache", "--"])
        .args(probe);
    // The probe fails (the mock is not a binary cache); only the request matters
    let _ = with_exec.output().unwrap();
    let authorized = provider.requests_to("/nix-cache-info");
    assert!(!authorized.is_empty(), "nix never contacted the mock cache");
    let expected = format!("Basic {}", base64std(b"cacheuser:cachepass"));
    assert_eq!(
        authorized[0].authorization.as_deref(),
        Some(expected.as_str())
    );

    // Baseline: without nix-vault the same request carries no login
    let before = provider.requests_to("/nix-cache-info").len();
    let mut plain = Command::new(&nix);
    plain
        .env("HOME", ws.path())
        .env("XDG_CACHE_HOME", ws.path().join("cache"))
        .args(&probe[1..]);
    let _ = plain.output().unwrap();
    let all = provider.requests_to("/nix-cache-info");
    assert!(all.len() > before);
    assert!(all[before].authorization.is_none());
}

fn base64std(data: &[u8]) -> String {
    let mut out = base64url(data).replace('-', "+").replace('_', "/");
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}
