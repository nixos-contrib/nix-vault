//! Refresh before launch: rotating tokens, failures and concurrent runs.

use predicates::prelude::*;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::helpers::{
    oauth::{company_identity, error_json, field, oauth_config, token_json, MockProvider},
    *,
};

fn provider(response: impl Fn(usize) -> (u16, String) + Send + Sync + 'static) -> MockProvider {
    MockProvider::start(move |request, nth| match request.path.as_str() {
        "/token" => {
            assert_eq!(
                field(&request.body, "grant_type").as_deref(),
                Some("refresh_token")
            );
            response(nth)
        }
        _ => (404, "{}".into()),
    })
}

fn workspace(provider: &MockProvider) -> Workspace {
    Workspace::new(&oauth_config(&provider.base(), "device"))
}

fn soon() -> String {
    (OffsetDateTime::now_utc() + Duration::seconds(60))
        .format(&Rfc3339)
        .unwrap()
}

const SHOW_STORE: &str = r#"
conf=${NIX_CONFIG##*!include }
cat "$conf"
# Snapshot the encrypted store as it is when the child starts
cp "$STORE/credentials.age" "$SNAPSHOT"
"#;

fn exec_show(ws: &Workspace) -> assert_cmd::assert::Assert {
    ws.cmd()
        .env("STORE", ws.store_dir())
        .env("SNAPSHOT", ws.path().join("snapshot.age"))
        .args(["exec", "-p", "company", "--", "sh", "-c", SHOW_STORE])
        .assert()
}

#[test]
fn an_expiring_token_is_refreshed_and_the_rotated_refresh_token_is_saved_before_launch() {
    let provider = provider(|_| {
        (
            200,
            token_json("NEW_ACCESS", Some("NEW_REFRESH"), Some(3600)),
        )
    });
    let ws = workspace(&provider);
    ws.seed_oauth(
        "company",
        &company_identity(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        Some(&soon()),
    );
    let out = exec_show(&ws).success().get_output().stdout.clone();
    let text = String::from_utf8(out).unwrap();
    // The child gets the new token ...
    assert!(
        text.contains("access-tokens = gitlab.example.com=OAuth2:NEW_ACCESS"),
        "{text}"
    );
    // ... and the rotated refresh token was already stored when the child ran
    let snapshot = vault::read_file(&ws.path().join("snapshot.age")).unwrap();
    let store = &snapshot["company"];
    assert!(store.contains("NEW_REFRESH") && store.contains("NEW_ACCESS"));
    assert!(!store.contains("OLD_REFRESH") && !store.contains("OLD_ACCESS"));
    // The refresh request carried the old refresh token and the client id
    let request = &provider.requests_to("/token")[0];
    assert_eq!(
        field(&request.body, "refresh_token").as_deref(),
        Some("OLD_REFRESH")
    );
    assert_eq!(
        field(&request.body, "client_id").as_deref(),
        Some("public-client-id")
    );
}

#[test]
fn the_old_refresh_token_is_kept_when_the_provider_sends_none() {
    let provider = provider(|_| (200, token_json("NEW_ACCESS", None, Some(3600))));
    let ws = workspace(&provider);
    ws.seed_oauth(
        "company",
        &company_identity(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        Some(&soon()),
    );
    exec_show(&ws).success();
    let stored = ws.stored("company").unwrap();
    assert!(stored.contains("NEW_ACCESS") && stored.contains("OLD_REFRESH"));
}

#[test]
fn an_unknown_expiry_is_usable_without_contacting_the_provider() {
    let provider = provider(|_| (500, "{}".into()));
    let ws = workspace(&provider);
    ws.seed_oauth(
        "company",
        &company_identity(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        None,
    );
    exec_show(&ws).success();
    assert!(provider.requests_to("/token").is_empty());
}

#[test]
fn refresh_failures_prevent_launch_with_the_login_instruction() {
    let rejected = provider(|_| (400, error_json("invalid_grant")));
    let down = provider(|_| (500, "boom".into()));
    for (provider, expected) in [(&rejected, "invalid_grant"), (&down, "unexpected response")] {
        let ws = workspace(provider);
        ws.seed_oauth(
            "company",
            &company_identity(),
            "OLD_ACCESS",
            Some("OLD_REFRESH"),
            Some(&soon()),
        );
        let marker = ws.path().join("ran");
        let output = ws
            .cmd()
            .env("MARKER", &marker)
            .args([
                "exec",
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
                "run: nix-vault login --profile company",
            ))
            .stderr(predicate::str::contains(expected))
            .get_output()
            .clone();
        assert!(!marker.exists(), "the child must not be launched");
        assert_no_secrets(
            &String::from_utf8_lossy(&output.stderr),
            &["OLD_REFRESH", "OLD_ACCESS"],
        );
    }
}

#[test]
fn an_unreachable_provider_prevents_launch() {
    let ws = Workspace::new(&oauth_config("http://127.0.0.1:1", "device"));
    ws.seed_oauth(
        "company",
        &company_identity(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        Some(&soon()),
    );
    ws.cmd()
        .args(["exec", "-p", "company", "--", "true"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "could not reach the token endpoint",
        ));
}

#[test]
fn an_expired_token_without_a_refresh_token_cannot_launch() {
    let provider = provider(|_| (200, token_json("X", None, None)));
    let ws = workspace(&provider);
    ws.seed_oauth(
        "company",
        &company_identity(),
        "OLD_ACCESS",
        None,
        Some("2000-01-01T00:00:00Z"),
    );
    ws.cmd()
        .args(["exec", "-p", "company", "--", "true"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("expired and cannot be refreshed"));
    assert!(provider.requests_to("/token").is_empty());
}

#[test]
fn a_failure_to_save_the_refreshed_tokens_fails_loudly_without_printing_them() {
    let provider = provider(|_| {
        (
            200,
            token_json("NEW_ACCESS", Some("NEW_REFRESH"), Some(3600)),
        )
    });
    let ws = workspace(&provider);
    ws.seed_oauth(
        "company",
        &company_identity(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        Some(&soon()),
    );
    // Reading the store works but its lock cannot be taken (a directory sits where the lock
    // file belongs), so writing the refreshed credentials fails
    std::fs::create_dir(ws.store_dir().join(".lock")).unwrap();
    let output = ws
        .cmd()
        .args(["exec", "-p", "company", "--", "true"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("could not be saved"))
        .get_output()
        .clone();
    assert_no_secrets(
        &String::from_utf8_lossy(&output.stderr),
        &["NEW_ACCESS", "NEW_REFRESH", "OLD_REFRESH"],
    );
}

#[test]
fn concurrent_runs_refresh_only_once() {
    // A slow provider keeps the first refresh in flight while the second run waits for the lock
    let provider = provider(|_| {
        std::thread::sleep(std::time::Duration::from_millis(700));
        (
            200,
            token_json("NEW_ACCESS", Some("NEW_REFRESH"), Some(3600)),
        )
    });
    let ws = workspace(&provider);
    ws.seed_oauth(
        "company",
        &company_identity(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        Some(&soon()),
    );
    let mut children = Vec::new();
    for _ in 0..2 {
        let mut cmd = ws.std_cmd();
        cmd.args([
            "exec",
            "-p",
            "company",
            "--",
            "sh",
            "-c",
            "grep -q NEW_ACCESS \"${NIX_CONFIG##*!include }\"",
        ]);
        children.push(cmd.spawn().unwrap());
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(provider.requests_to("/token").len(), 1);
}

#[test]
fn login_refreshes_expiring_credentials_instead_of_prompting() {
    let provider = provider(|_| {
        (
            200,
            token_json("NEW_ACCESS", Some("NEW_REFRESH"), Some(3600)),
        )
    });
    let ws = workspace(&provider);
    ws.seed_oauth(
        "company",
        &company_identity(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        Some(&soon()),
    );
    ws.cmd()
        .args(["login", "-p", "company"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Refreshed the credentials for company",
        ));
    assert!(ws.stored("company").unwrap().contains("NEW_REFRESH"));
}
