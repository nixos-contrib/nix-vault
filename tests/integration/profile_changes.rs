//! Credentials are bound to the profile's host and OAuth client.

use predicates::prelude::*;

use crate::helpers::*;

#[test]
fn changing_the_host_or_client_invalidates_stored_credentials() {
    let ws = Workspace::new(CONFIG);
    ws.seed_cache();
    ws.seed_oauth("company", &company_identity(), FAKE_TOKEN, None, None);
    ws.cmd()
        .args(["exec", "-p", "cache", "-p", "company", "--", "true"])
        .assert()
        .success();

    ws.set_config(&CONFIG.replace("cache.example.com", "other-cache.example.com"));
    ws.cmd().arg("list").assert().success().stdout(
        predicate::str::is_match(
            r"cache\s+other-cache\.example\.com\s+basic\s+login again \(changed\)",
        )
        .unwrap(),
    );
    ws.cmd()
        .args(["exec", "-p", "cache", "--", "true"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "run: nix-vault login --profile cache",
        ));

    ws.set_config(&CONFIG.replace("public-client-id", "another-client"));
    ws.cmd()
        .args(["exec", "-p", "company", "--", "true"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "run: nix-vault login --profile company",
        ));
    // The stale entries are not deleted automatically
    assert!(ws.stored("cache").is_some() && ws.stored("company").is_some());
}

#[test]
fn changing_unrelated_settings_keeps_the_credentials() {
    let ws = Workspace::new(CONFIG);
    ws.seed_oauth("company", &company_identity(), FAKE_TOKEN, None, None);
    for changed in [
        CONFIG.replace("oauth/token", "oauth/token2"),
        CONFIG.replace("[\"read_api\"]", "[\"read_api\", \"read_user\"]"),
        format!("{CONFIG}\n[company.access-token]\nstyle = \"github\"\n"),
        format!("{CONFIG}\n[company.netrc]\nusername = \"someone\"\n"),
    ] {
        ws.set_config(&changed);
        ws.cmd()
            .args(["exec", "-p", "company", "--", "true"])
            .assert()
            .success();
    }
}

#[test]
fn two_profiles_on_one_host_keep_separate_accounts() {
    let config = "[alice]\nhost = \"cache.example.com\"\ntype = \"basic\"\n\
                  [bob]\nhost = \"cache.example.com\"\ntype = \"basic\"\n";
    let ws = Workspace::new(config);
    let id = identity("basic", "cache.example.com", None);
    ws.seed_basic("alice", &id, "alice", "alice-pw");
    ws.seed_basic("bob", &id, "bob", "bob-pw");
    for (profile, user, password) in [("alice", "alice", "alice-pw"), ("bob", "bob", "bob-pw")] {
        let out = ws
            .cmd()
            .args(["exec", "-p", profile, "--", "sh", "-c", SHOW_SESSION])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&format!(
            "machine cache.example.com login {user} password {password}"
        )));
        assert_eq!(text.matches("machine cache.example.com").count(), 1);
    }
}
