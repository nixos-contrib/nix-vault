//! `use = ["proxy"]`: Nix is pointed at a local proxy for the session, and the credentials stay
//! out of every file Nix reads.

use predicates::prelude::*;

use crate::helpers::*;

const SERVICE_ID: &str = "fake-client-id-3d9.access";
const SERVICE_SECRET: &str = "FAKE_SERVICE_SECRET_3d9";

// `.invalid` never resolves, so the proxy's upstream is unreachable and answers 502
const CONFIG: &str = r#"
[svc]
host = "proxy.invalid"
type = "basic"

[svc.nix]
use = ["proxy"]

[svc.proxy]
headers = { CF-Access-Client-Id = "{username}", CF-Access-Client-Secret = "{password}" }
"#;

fn seeded(config: &str) -> Workspace {
    let ws = Workspace::new(config);
    ws.seed_basic(
        "svc",
        &identity("basic", "proxy.invalid", None),
        SERVICE_ID,
        SERVICE_SECRET,
    );
    ws
}

fn set_substituters(ws: &Workspace, list: &[&str]) {
    let list: Vec<String> = list.iter().map(|s| format!("\"{s}\"")).collect();
    let netrc = ws.path().join("no-such-netrc");
    std::fs::write(
        ws.nix.json_path(),
        format!(
            "{{\"access-tokens\":{{\"value\":{{}}}},\"netrc-file\":{{\"value\":\"{}\"}},\
             \"substituters\":{{\"value\":[{}]}}}}",
            netrc.display(),
            list.join(",")
        ),
    )
    .unwrap();
}

/// Prints the session `nix.conf`, then what the proxy answers to a request with and without its
/// secret path prefix.
const PROBE: &str = r#"
conf=${NIX_CONFIG##*!include }
cat "$conf"
echo '--- with the prefix'
curl -s -o /dev/null -w '%{http_code}\n' "$NIX_VAULT_PROXY_SVC/nix-cache-info"
echo '--- without the prefix'
curl -s -o /dev/null -w '%{http_code}\n' "${NIX_VAULT_PROXY_SVC%/*}/nix-cache-info"
echo "--- url"
echo "$NIX_VAULT_PROXY_SVC"
"#;

#[test]
fn nix_is_pointed_at_the_proxy_and_no_credential_is_written() {
    let ws = seeded(CONFIG);
    set_substituters(
        &ws,
        &[
            "https://cache.nixos.org",
            "https://proxy.invalid/team?priority=10",
        ],
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

    // The proxied host's entry now names the proxy, with its path and query; others are kept
    let line = stdout
        .lines()
        .find(|l| l.starts_with("substituters = "))
        .expect("a substituters line");
    assert!(line.starts_with("substituters = https://cache.nixos.org http://127.0.0.1:"));
    assert!(line.ends_with("/team?priority=10"), "{line}");
    assert!(!stdout.contains("access-tokens") && !stdout.contains("netrc-file"));

    // The proxy answers (502: its upstream does not resolve) only under its secret prefix
    let with = stdout.split("--- with the prefix\n").nth(1).unwrap();
    assert!(with.starts_with("502"), "{with}");
    let without = stdout.split("--- without the prefix\n").nth(1).unwrap();
    assert!(without.starts_with("404"), "{without}");
    assert!(stdout.contains("--- url\nhttp://127.0.0.1:"));

    // The service token is in no file and no message, and the session is gone
    assert_no_secrets(&stderr, &[SERVICE_ID, SERVICE_SECRET]);
    assert!(!stdout.contains(SERVICE_SECRET));
    assert!(stderr.contains("proxy.invalid is served through a local proxy"));
    assert!(ws.leftover_sessions().is_empty());
}

#[test]
fn a_host_nix_does_not_list_is_added_as_a_substituter() {
    let ws = seeded(CONFIG);
    set_substituters(&ws, &["https://cache.nixos.org"]);
    ws.cmd()
        .args(["exec", "-p", "svc", "--", "sh", "-c", PROBE])
        .assert()
        .success()
        .stdout(
            predicate::str::is_match(
                "substituters = https://cache.nixos.org http://127.0.0.1:\\d+/[0-9a-f]{32}\n",
            )
            .unwrap(),
        );
}

#[test]
fn the_proxy_is_closed_when_the_command_ends() {
    let ws = seeded(CONFIG);
    let output = ws
        .cmd()
        .args([
            "exec",
            "-p",
            "svc",
            "--",
            "sh",
            "-c",
            "echo \"$NIX_VAULT_PROXY_SVC\"",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let url = String::from_utf8(output.stdout).unwrap();
    let addr = url
        .trim()
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_string();
    assert!(std::net::TcpStream::connect(addr).is_err());
}

#[test]
fn a_profile_without_proxy_leaves_substituters_alone() {
    let ws = seeded("[svc]\nhost = \"proxy.invalid\"\ntype = \"basic\"\n");
    set_substituters(&ws, &["https://cache.nixos.org"]);
    ws.cmd()
        .args(["exec", "-p", "svc", "--", "sh", "-c", SHOW_SESSION])
        .assert()
        .success()
        .stdout(predicate::str::contains("substituters").not())
        .stdout(predicate::str::contains("netrc-file = "));
}

#[test]
fn an_oauth2_profile_is_served_through_the_proxy_with_its_access_token() {
    let config = "[svc]\nhost = \"proxy.invalid\"\ntype = \"oauth2\"\n[svc.oauth2]\nclient_id = \"public-client-id\"\n\
                  flow = \"authorization_code\"\nauthorization_endpoint = \"https://idp.example/a\"\n\
                  token_endpoint = \"https://idp.example/t\"\nredirect_port = 8251\n\
                  [svc.nix]\nuse = [\"proxy\"]\n[svc.proxy]\nheaders = { Authorization = \"Bearer {access_token}\" }\n";
    let ws = Workspace::new(config);
    ws.seed_oauth(
        "svc",
        &identity("oauth2", "proxy.invalid", Some("public-client-id")),
        "FAKE_ACCESS_TOKEN_5c1",
        None,
        Some("2999-01-01T00:00:00Z"),
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
    // The proxy is in place, and the token is in no file and no message
    assert!(stdout.contains("substituters = http://127.0.0.1:"));
    assert!(stdout
        .split("--- with the prefix\n")
        .nth(1)
        .unwrap()
        .starts_with("502"));
    assert!(!stdout.contains("FAKE_ACCESS_TOKEN_5c1"));
    assert_no_secrets(&stderr, &["FAKE_ACCESS_TOKEN_5c1"]);
    assert!(!stdout.contains("netrc-file") && !stdout.contains("access-tokens"));
}

#[test]
fn proxy_placeholders_must_fit_the_profile_type_and_mechanisms_do_not_combine() {
    let wrong = "[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.nix]\nuse=[\"proxy\"]\n\
                 [a.proxy]\nheaders = { X = \"{access_token}\" }\n";
    Workspace::new(wrong)
        .cmd()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("this profile type does not have"));
    let ws = Workspace::new(
        "[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.nix]\nuse=[\"proxy\",\"netrc\"]\n\
         [a.proxy]\nheaders = { X = \"{password}\" }\n",
    );
    ws.cmd()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("\"proxy\" cannot be combined"));
}

// ---- renewal while the command runs ----

use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::helpers::oauth::{error_json, field, token_json, MockProvider};

fn refresh_provider(
    response: impl Fn(usize) -> (u16, String) + Send + Sync + 'static,
) -> MockProvider {
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

/// An oauth2 profile `svc` behind the proxy whose token endpoint is `base`.
fn renewing_workspace(base: &str, seconds_left: i64) -> Workspace {
    let config = format!(
        "[svc]\nhost = \"proxy.invalid\"\ntype = \"oauth2\"\n[svc.oauth2]\n\
         client_id = \"public-client-id\"\nflow = \"authorization_code\"\n\
         authorization_endpoint = \"{base}/authorize\"\ntoken_endpoint = \"{base}/token\"\n\
         [svc.nix]\nuse = [\"proxy\"]\n[svc.proxy]\n\
         headers = {{ Authorization = \"Bearer {{access_token}}\" }}\n"
    );
    let ws = Workspace::new(&config);
    // Usable when `exec` starts (the refresh margin is 120 seconds), expiring a few seconds later
    let expires = (OffsetDateTime::now_utc() + Duration::seconds(seconds_left))
        .format(&Rfc3339)
        .unwrap();
    ws.seed_oauth(
        "svc",
        &identity("oauth2", "proxy.invalid", Some("public-client-id")),
        "FAKE_OLD_ACCESS_77",
        Some("FAKE_OLD_REFRESH_77"),
        Some(&expires),
    );
    ws
}

/// Waits for the token to cross the refresh margin, then makes one request through the proxy.
const WAIT_THEN_REQUEST: &str = r#"
sleep 5
curl -s -w '%{http_code}\n' "$NIX_VAULT_PROXY_SVC/nix-cache-info"
"#;

#[test]
fn a_token_that_expires_during_the_command_is_renewed_by_the_proxy() {
    let provider = refresh_provider(|_| {
        (
            200,
            token_json(
                "FAKE_NEW_ACCESS_77",
                Some("FAKE_NEW_REFRESH_77"),
                Some(3600),
            ),
        )
    });
    let ws = renewing_workspace(&provider.base(), 123);
    let output = ws
        .cmd()
        .args(["exec", "-p", "svc", "--", "sh", "-c", WAIT_THEN_REQUEST])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    // Not launched with a renewal (the token was usable), renewed once by the request, and the
    // request was forwarded (502: the upstream does not resolve) instead of refused
    assert_eq!(provider.requests_to("/token").len(), 1);
    assert!(stdout.trim_end().ends_with("502"), "{stdout}");
    // The rotated tokens were saved
    let stored = ws.stored("svc").unwrap();
    assert!(stored.contains("FAKE_NEW_ACCESS_77") && stored.contains("FAKE_NEW_REFRESH_77"));
    assert!(!stdout.contains("FAKE_NEW_ACCESS_77"));
}

#[test]
fn a_renewal_that_fails_answers_401_with_the_login_instruction() {
    let provider = refresh_provider(|_| (400, error_json("invalid_grant")));
    let ws = renewing_workspace(&provider.base(), 123);
    let output = ws
        .cmd()
        .args(["exec", "-p", "svc", "--", "sh", "-c", WAIT_THEN_REQUEST])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("nix-vault: "), "{stdout}");
    assert!(
        stdout.contains("\"svc\"") && stdout.trim_end().ends_with("401"),
        "{stdout}"
    );
    assert_no_secrets(&stdout, &["FAKE_OLD_ACCESS_77", "FAKE_OLD_REFRESH_77"]);
    assert_no_secrets(&stderr, &["FAKE_OLD_ACCESS_77", "FAKE_OLD_REFRESH_77"]);
}
