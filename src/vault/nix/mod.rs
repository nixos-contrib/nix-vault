//! Nix credential delivery: reading the effective Nix settings, rendering entries and building
//! the session.

pub mod netrc;
pub mod render;
pub mod session;

use std::{collections::BTreeMap, path::PathBuf, process::Command};

use crate::vault::{auth::redact::Secret, Error, Result};

/// The user's effective Nix settings that nix-vault must preserve.
#[derive(Debug)]
pub struct NixEffectiveConfig {
    /// `access-tokens`: host to token.
    pub access_tokens: BTreeMap<String, Secret>,
    /// `netrc-file`.
    pub netrc_file: PathBuf,
}

fn nix_binary() -> std::ffi::OsString {
    // Release builds always use `nix` from PATH; the override exists for tests only
    #[cfg(feature = "file-store")]
    if let Some(binary) = std::env::var_os("NIX_VAULT_NIX") {
        return binary;
    }
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
    Ok(NixEffectiveConfig {
        access_tokens,
        netrc_file: PathBuf::from(netrc_file),
    })
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
    fn empty_access_tokens_are_fine() {
        let config = parse_effective_config(
            br#"{"access-tokens":{"value":{}},"netrc-file":{"value":"/n"}}"#,
        )
        .unwrap();
        assert!(config.access_tokens.is_empty());
    }
}
