//! Configuration validation: every error names the profile and key, and exits with status 2.

use predicates::prelude::*;

use crate::helpers::{Workspace, CONFIG};

fn fails_with(config: &str, message: &str) {
    let ws = Workspace::new(config);
    ws.cmd()
        .arg("list")
        .assert()
        .code(2)
        .stderr(predicate::str::contains(message));
}

const BASIC: &str = "[a]\nhost = \"h.example\"\ntype = \"basic\"\n";

#[test]
fn valid_file_with_every_profile_shape_lists() {
    let config = format!(
        "{CONFIG}\n[work]\nhost = \"github.com\"\ntype = \"oauth2\"\nclient_id = \"c\"\n\
         flow = \"authorization_code\"\nauthorization_endpoint = \"https://github.com/a\"\n\
         token_endpoint = \"https://github.com/t\"\n[work.access-token]\n[work.netrc]\n"
    );
    let ws = Workspace::new(&config);
    ws.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("cache.example.com"))
        .stdout(predicate::str::contains("github.com"));
}

#[test]
fn rejects_secret_bearing_keys() {
    for key in [
        "password",
        "token",
        "access_token",
        "refresh_token",
        "client_secret",
        "username",
    ] {
        fails_with(
            &format!("{BASIC}{key} = \"x\"\n"),
            &format!("\"{key}\" must not be stored in the configuration file; use nix-vault login"),
        );
    }
}

#[test]
fn rejects_unsupported_constructs() {
    for key in ["extends", "groups", "sources", "targets"] {
        fails_with(
            &format!("{BASIC}{key} = \"x\"\n"),
            &format!("unknown key \"{key}\""),
        );
    }
}

#[test]
fn rejects_bad_hosts_endpoints_and_style() {
    fails_with(
        "[a]\nhost = \"https://h.example\"\ntype = \"basic\"\n",
        "host must be a bare hostname",
    );
    fails_with(
        &CONFIG.replace(
            "https://gitlab.example.com/oauth/token",
            "http://example.com/token",
        ),
        "\"token_endpoint\" must use https",
    );
    fails_with(
        &format!("{BASIC}[a.access-token]\nstyle = \"bitbucket\"\n"),
        "\"style\" must be \"plain\" or \"typed\" in [a.access-token]",
    );
    fails_with(
        &format!("{BASIC}style = \"plain\"\n"),
        "in [a.access-token]",
    );
}

#[test]
fn rejects_netrc_keys_and_oauth_keys_on_basic() {
    for profile in [
        format!("{BASIC}[a.netrc]\nusername = \"u\"\n"),
        format!("{BASIC}[a.netrc]\nlogin = \"u\"\n"),
    ] {
        let key = if profile.contains("username") {
            "username"
        } else {
            "login"
        };
        fails_with(&profile, &format!("profile \"a\": unknown key \"{key}\""));
    }
    fails_with(
        &format!("{BASIC}client_id = \"c\"\n"),
        "\"client_id\" is only valid for oauth2 profiles",
    );
}

#[test]
fn rejects_missing_keys_bad_names_and_invalid_toml() {
    fails_with(
        &CONFIG.replace("client_id = \"public-client-id\"\n", ""),
        "profile \"company\": missing required key \"client_id\"",
    );
    fails_with(
        "[\"bad name\"]\nhost = \"h\"\ntype = \"basic\"\n",
        "may only contain letters",
    );
    fails_with("[a\nhost = ", "invalid configuration file");
}

#[test]
fn missing_file_explains_how_to_create_one() {
    let ws = Workspace::new(CONFIG);
    std::fs::remove_file(ws.config_file()).unwrap();
    ws.cmd()
        .arg("list")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("config.example.toml"));
}

#[test]
fn every_command_shows_examples_in_help() {
    let ws = Workspace::new(CONFIG);
    for command in ["login", "exec", "logout", "list"] {
        ws.cmd()
            .args([command, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Examples:"));
    }
}

#[test]
fn the_example_configuration_is_valid() {
    let example = include_str!("../../config.example.toml");
    let ws = Workspace::new(example);
    ws.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("mono"))
        .stdout(predicate::str::contains("git.example.com"));
}
