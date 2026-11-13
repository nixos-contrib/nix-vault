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
fn proxy_is_refused_for_oauth2_profiles_and_in_combinations() {
    let oauth = "[a]\nhost=\"h.example\"\ntype=\"oauth2\"\n[a.oauth2]\nclient_id=\"c\"\nflow=\"device\"\n\
                 device_authorization_endpoint=\"https://h.example/d\"\ntoken_endpoint=\"https://h.example/t\"\n\
                 [a.nix]\nuse=[\"proxy\"]\n";
    let ws = Workspace::new(oauth);
    ws.cmd()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "\"proxy\" is only available for basic profiles",
        ));
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
