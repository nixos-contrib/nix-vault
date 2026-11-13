//! Nix credential delivery: reading the effective Nix settings, rendering entries and building
//! the session.

pub mod netrc;
pub mod proxy;
pub mod render;
pub mod session;
pub mod source;

use std::{collections::BTreeMap, path::PathBuf, process::Command};

use crate::vault::{auth::redact::Secret, Error, Result};

/// The user's effective Nix settings that nix-vault must preserve.
#[derive(Debug)]
pub struct NixEffectiveConfig {
    /// `access-tokens`: host to token.
    pub access_tokens: BTreeMap<String, Secret>,
    /// `netrc-file`.
    pub netrc_file: PathBuf,
    /// `substituters` (extra ones included): the binary caches Nix queries, in order.
    pub substituters: Vec<String>,
}

fn nix_binary() -> std::ffi::OsString {
    // Always `nix` from PATH (tests put a stub first on PATH)
    "nix".into()
}

/// Reads the effective settings by running `nix config show --json` in the current environment.
/// The output holds the user's own tokens: it is parsed in memory and never printed.
pub fn effective_config() -> Result<NixEffectiveConfig> {
    let output = Command::new(nix_binary())
        .args(["config", "show", "--json"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| {
            Error::NixUnavailable(format!(
                "cannot run `nix config show --json` ({e}); is nix installed and on PATH?"
            ))
        })?;
    if !output.status.success() {
        return Err(Error::NixUnavailable(format!(
            "`nix config show --json` failed with {}",
            output.status
        )));
    }
    parse_effective_config(&output.stdout)
}

/// Parses the JSON printed by `nix config show --json`.
pub fn parse_effective_config(json: &[u8]) -> Result<NixEffectiveConfig> {
    let bad = || Error::NixUnavailable("unexpected output from `nix config show --json`".into());
    let value: serde_json::Value = serde_json::from_slice(json).map_err(|_| bad())?;
    let mut access_tokens = BTreeMap::new();
    if let Some(map) = value
        .pointer("/access-tokens/value")
        .and_then(|v| v.as_object())
    {
        for (host, token) in map {
            let token = token.as_str().ok_or_else(bad)?;
            access_tokens.insert(host.clone(), Secret::new(token));
        }
    }
    let netrc_file = value
        .pointer("/netrc-file/value")
        .and_then(|v| v.as_str())
        .ok_or_else(bad)?;
    let substituters = value
        .pointer("/substituters/value")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .map(|v| v.as_str().map(str::to_string).ok_or_else(bad))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(NixEffectiveConfig {
        access_tokens,
        netrc_file: PathBuf::from(netrc_file),
        substituters,
    })
}

/// Returns `substituters` with the entries for `host` pointed at `local` (the proxy's base URL),
/// keeping each entry's path and query. When no entry names the host, `local` is added: selecting
/// a proxied profile means using that cache.
pub fn point_at_proxy(substituters: &[String], host: &str, local: &str) -> Vec<String> {
    let mut found = false;
    let mut list: Vec<String> = substituters
        .iter()
        .map(|entry| match split_authority(entry) {
            Some((authority, rest)) if same_host(authority, host) => {
                found = true;
                format!("{local}{rest}")
            }
            _ => entry.clone(),
        })
        .collect();
    if !found {
        list.push(local.to_string());
    }
    list
}

/// Splits `https://host:port/path?query` into (`host:port`, `/path?query`).
fn split_authority(url: &str) -> Option<(&str, &str)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    Some((&rest[..end], &rest[end..]))
}

fn same_host(authority: &str, host: &str) -> bool {
    let bare = authority
        .rsplit_once('@')
        .map_or(authority, |(_, h)| h)
        .trim_end_matches(":443");
    bare.eq_ignore_ascii_case(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tokens_and_netrc_file() {
        let json = br#"{"access-tokens":{"value":{"a.example":"AAA","b.example":"BBB"}},
                        "netrc-file":{"value":"/etc/nix/netrc"},"other":{"value":1}}"#;
        let config = parse_effective_config(json).unwrap();
        assert_eq!(config.netrc_file, PathBuf::from("/etc/nix/netrc"));
        assert_eq!(config.access_tokens["a.example"].expose(), "AAA");
        assert_eq!(config.access_tokens.len(), 2);
    }

    #[test]
    fn missing_netrc_file_or_garbage_is_an_error() {
        assert!(parse_effective_config(b"{}").is_err());
        assert!(parse_effective_config(b"not json").is_err());
    }

    #[test]
    fn substituters_are_read_and_rewritten_for_a_proxied_host() {
        let json = br#"{"substituters":{"value":["https://cache.nixos.org","https://nix.example.com/team?priority=10","https://other.example"]},
                        "netrc-file":{"value":"/n"}}"#;
        let config = parse_effective_config(json).unwrap();
        assert_eq!(config.substituters.len(), 3);
        let list = point_at_proxy(
            &config.substituters,
            "nix.example.com",
            "http://127.0.0.1:9/tok",
        );
        assert_eq!(
            list,
            [
                "https://cache.nixos.org",
                "http://127.0.0.1:9/tok/team?priority=10",
                "https://other.example"
            ]
        );
        // Not listed: it is added
        let list = point_at_proxy(
            &config.substituters,
            "new.example.com",
            "http://127.0.0.1:9/tok",
        );
        assert_eq!(list.last().unwrap(), "http://127.0.0.1:9/tok");
        assert_eq!(list.len(), 4);
        // A port, a userinfo part or a different case still names the host; a prefix of it does not
        let tricky = vec![
            "https://NIX.example.com:443".to_string(),
            "https://nix.example.com.evil".to_string(),
        ];
        let list = point_at_proxy(&tricky, "nix.example.com", "http://l/t");
        assert_eq!(list, ["http://l/t", "https://nix.example.com.evil"]);
    }

    #[test]
    fn empty_access_tokens_are_fine() {
        let config = parse_effective_config(
            br#"{"access-tokens":{"value":{}},"netrc-file":{"value":"/n"}}"#,
        )
        .unwrap();
        assert!(config.access_tokens.is_empty());
    }
}
