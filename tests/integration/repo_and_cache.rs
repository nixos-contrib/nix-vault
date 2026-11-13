//! SC-007: a build needing a private repository and a separately authenticated binary cache.

use crate::helpers::*;

#[test]
fn one_exec_serves_a_forge_token_and_a_cache_login() {
    let config = "[forge]\nhost = \"gitlab.example.com\"\ntype = \"oauth2\"\nclient_id = \"c\"\n\
                  flow = \"device\"\ndevice_authorization_endpoint = \"https://gitlab.example.com/d\"\n\
                  token_endpoint = \"https://gitlab.example.com/t\"\n[forge.access-token]\n\
                  style = \"typed\"\n\
                  [cache]\nhost = \"cache.example.com\"\ntype = \"basic\"\n";
    let ws = Workspace::new(config);
    ws.seed_oauth(
        "forge",
        &identity("oauth2", "gitlab.example.com", Some("c")),
        FAKE_TOKEN,
        None,
        None,
    );
    ws.seed_cache();
    // The user's other logins and tokens must survive
    let user_netrc = ws.path().join("user-netrc");
    std::fs::write(
        &user_netrc,
        "machine other.example.com login o password OTHER_PW\n",
    )
    .unwrap();
    ws.nix
        .set(&[("old.example.com", "OLD_TOKEN")], Some(&user_netrc));

    let out = ws
        .cmd()
        .args([
            "exec",
            "-p",
            "forge",
            "-p",
            "cache",
            "--",
            "sh",
            "-c",
            SHOW_SESSION,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("old.example.com=OLD_TOKEN"));
    assert!(text.contains(&format!("gitlab.example.com=OAuth2:{FAKE_TOKEN}")));
    assert!(text.contains(&format!(
        "machine cache.example.com login {FAKE_USER} password {FAKE_PASSWORD}"
    )));
    assert!(text.contains("machine other.example.com login o password OTHER_PW"));
    assert!(ws.leftover_sessions().is_empty());
}

#[test]
fn the_same_host_through_both_mechanisms_with_different_accounts_is_rejected() {
    let config = "[forge]\nhost = \"git.example.com\"\ntype = \"basic\"\n[forge.access-token]\n\
                  [mirror]\nhost = \"git.example.com\"\ntype = \"basic\"\n";
    let ws = Workspace::new(config);
    let id = identity("basic", "git.example.com", None);
    ws.seed_basic("forge", &id, "a", "pw-a");
    ws.seed_basic("mirror", &id, "b", "pw-b");
    let marker = ws.path().join("ran");
    ws.cmd()
        .env("MARKER", &marker)
        .args([
            "exec",
            "-p",
            "forge",
            "-p",
            "mirror",
            "--",
            "sh",
            "-c",
            "touch \"$MARKER\"",
        ])
        .assert()
        .code(2);
    assert!(!marker.exists());
}
