//! Profile configuration: the TOML model, validation, discovery and derived values.
//!
//! The file holds no secrets. It is validated as a whole before any command acts, and every
//! error names the profile and the key concerned.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use oauth2::url::Url;
use sha2::{Digest, Sha256};

use crate::vault::{Error, Result};

/// Keys that must never be stored in the configuration file.
const SECRET_KEYS: [&str; 6] = [
    "password",
    "token",
    "access_token",
    "refresh_token",
    "client_secret",
    "username",
];
/// Keys valid for every profile.
const COMMON_KEYS: [&str; 4] = ["host", "type", "access-token", "netrc"];
/// Keys valid inside `[<name>.oauth2]`.
const OAUTH_KEYS: [&str; 6] = [
    "client_id",
    "flow",
    "device_authorization_endpoint",
    "authorization_endpoint",
    "token_endpoint",
    "scopes",
];

/// How an access token is rendered for Nix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// `<host>=<token>`
    Plain,
    /// `<host>=OAuth2:<token>` (oauth2) or `<host>=PAT:<token>` (basic)
    Typed,
}

/// The OAuth flow used to log in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Device authorization grant.
    Device,
    /// Authorization code grant with PKCE.
    AuthorizationCode,
}

impl Flow {
    fn as_str(self) -> &'static str {
        match self {
            Flow::Device => "device",
            Flow::AuthorizationCode => "authorization_code",
        }
    }
}

/// OAuth settings of an oauth2 profile. The client is public: there is no client secret.
#[derive(Clone, Debug)]
pub struct OAuth {
    /// Public client identifier.
    pub client_id: String,
    /// Flow to run at login.
    pub flow: Flow,
    /// Device authorization endpoint (flow `device`).
    pub device_authorization_endpoint: Option<String>,
    /// Authorization endpoint (flow `authorization_code`).
    pub authorization_endpoint: Option<String>,
    /// Token endpoint.
    pub token_endpoint: String,
    /// Requested scopes.
    pub scopes: Vec<String>,
}

/// The authentication type of a profile.
#[derive(Clone, Debug)]
pub enum Kind {
    /// Username and password (or personal access token).
    Basic,
    /// OAuth 2.0 tokens.
    OAuth2(OAuth),
}

/// A named profile: one host and one authentication type.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Profile name (the table key).
    pub name: String,
    /// Lowercased bare hostname.
    pub host: String,
    /// Authentication type and its settings.
    pub kind: Kind,
    /// `[<name>.access-token]` present: the optional `style`.
    pub access_token: Option<Option<Style>>,
    /// `[<name>.netrc]` present: also (or only) deliver through netrc. The table has no keys.
    pub netrc: bool,
}

/// The mechanisms through which a profile's credentials are presented to Nix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Present as a Nix access token with this style.
    pub access_token: Option<Style>,
    /// Present through netrc.
    pub netrc: bool,
}

impl Profile {
    /// Returns the authentication type name used in output.
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            Kind::Basic => "basic",
            Kind::OAuth2(_) => "oauth2",
        }
    }

    /// Returns the effective access-token style: the configured one, else `plain` for the host
    /// `github.com` and `typed` for every other host.
    pub fn style(&self) -> Style {
        match self.access_token {
            Some(Some(style)) => style,
            _ if self.host == "github.com" => Style::Plain,
            _ => Style::Typed,
        }
    }

    /// Returns the mechanisms used for this profile (see FR-026).
    pub fn delivery(&self) -> Delivery {
        if self.access_token.is_none() && !self.netrc {
            return match self.kind {
                Kind::OAuth2(_) => Delivery {
                    access_token: Some(self.style()),
                    netrc: false,
                },
                Kind::Basic => Delivery {
                    access_token: None,
                    netrc: true,
                },
            };
        }
        Delivery {
            access_token: self.access_token.map(|_| self.style()),
            netrc: self.netrc,
        }
    }

    /// Returns the identity that stored credentials are bound to: SHA-256 (hex) over the type,
    /// the lowercased host and, for oauth2, the client id. Anything else may change freely.
    pub fn identity(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"nix-vault-identity-v1\0");
        hasher.update(self.type_name().as_bytes());
        hasher.update(b"\0");
        hasher.update(self.host.as_bytes());
        if let Kind::OAuth2(oauth) = &self.kind {
            hasher.update(b"\0");
            hasher.update(oauth.client_id.as_bytes());
        }
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// The validated configuration: profiles in file order.
#[derive(Clone, Debug)]
pub struct Config {
    /// Profiles in the order they appear in the file.
    pub profiles: Vec<Profile>,
}

impl Config {
    /// Reads and validates the file at `path`.
    pub fn load(path: &Path) -> Result<Config> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::config(format!(
                    "no configuration file at {}; create one (see config.example.toml in the \
                     nix-vault repository)",
                    path.display()
                )))
            }
            Err(e) => {
                return Err(Error::config(format!(
                    "cannot read the configuration file {}: {e}",
                    path.display()
                )))
            }
        };
        Config::parse(&text)
    }

    /// Parses and validates configuration text.
    pub fn parse(text: &str) -> Result<Config> {
        let table: toml::Table = text.parse().map_err(|e: toml::de::Error| {
            // The parser's message can quote the offending line; report only the position
            let line = e
                .span()
                .map(|s| text[..s.start.min(text.len())].matches('\n').count() + 1);
            match line {
                Some(line) => Error::config(format!(
                    "invalid configuration file: {} (line {line})",
                    e.message()
                )),
                None => Error::config(format!("invalid configuration file: {}", e.message())),
            }
        })?;
        let mut profiles = Vec::new();
        let mut seen = HashSet::new();
        for (name, value) in &table {
            check_name(name)?;
            let Some(profile_table) = value.as_table() else {
                return Err(Error::config(format!(
                    "profile \"{name}\": must be a table with at least \"host\" and \"type\""
                )));
            };
            if !seen.insert(name.clone()) {
                continue;
            }
            profiles.push(parse_profile(name, profile_table)?);
        }
        Ok(Config { profiles })
    }

    /// Returns the profile called `name`.
    pub fn profile(&self, name: &str) -> Result<&Profile> {
        self.profiles
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| Error::usage(format!("unknown profile \"{name}\"; run: nix-vault list")))
    }
}

fn check_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(Error::config(format!(
            "profile name \"{name}\" may only contain letters, digits, \".\", \"_\" and \"-\""
        )))
    }
}

fn secret_error(profile: &str, key: &str) -> Error {
    Error::config(format!(
        "profile \"{profile}\": \"{key}\" must not be stored in the configuration file; \
         use nix-vault login"
    ))
}

fn unknown_key(profile: &str, key: &str) -> Error {
    Error::config(format!("profile \"{profile}\": unknown key \"{key}\""))
}

fn style_error(profile: &str) -> Error {
    Error::config(format!(
        "profile \"{profile}\": \"style\" must be \"plain\" or \"typed\" in \
         [{profile}.access-token]"
    ))
}

fn missing(profile: &str, key: &str) -> Error {
    Error::config(format!(
        "profile \"{profile}\": missing required key \"{key}\""
    ))
}

fn string_value(profile: &str, table: &toml::Table, key: &str) -> Result<Option<String>> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
        Some(_) => Err(Error::config(format!(
            "profile \"{profile}\": \"{key}\" must be a non-empty string"
        ))),
    }
}

fn required_string(profile: &str, table: &toml::Table, key: &str) -> Result<String> {
    string_value(profile, table, key)?.ok_or_else(|| missing(profile, key))
}

fn parse_host(profile: &str, host: &str) -> Result<String> {
    let valid = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if valid {
        Ok(host.to_ascii_lowercase())
    } else {
        Err(Error::config(format!(
            "profile \"{profile}\": host must be a bare hostname"
        )))
    }
}

fn check_endpoint(profile: &str, key: &str, value: &str) -> Result<()> {
    let https_error = || Error::config(format!("profile \"{profile}\": \"{key}\" must use https"));
    let url = Url::parse(value).map_err(|_| {
        Error::config(format!(
            "profile \"{profile}\": \"{key}\" must be a valid URL"
        ))
    })?;
    match url.scheme() {
        "https" => Ok(()),
        // Plain http is accepted only for loopback services, which the tests use
        "http" if matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")) => Ok(()),
        _ => Err(https_error()),
    }
}

fn parse_profile(name: &str, table: &toml::Table) -> Result<Profile> {
    for key in table.keys() {
        let key = key.as_str();
        if SECRET_KEYS.contains(&key) {
            return Err(secret_error(name, key));
        }
        if key == "style" {
            return Err(style_error(name));
        }
    }

    let kind_name = required_string(name, table, "type")?;
    let is_oauth = match kind_name.as_str() {
        "basic" => false,
        "oauth2" => true,
        _ => {
            return Err(Error::config(format!(
                "profile \"{name}\": \"type\" must be \"basic\" or \"oauth2\""
            )))
        }
    };
    for key in table.keys() {
        let key = key.as_str();
        if COMMON_KEYS.contains(&key) {
            continue;
        }
        if key == "oauth2" {
            if is_oauth {
                continue;
            }
            return Err(Error::config(format!(
                "profile \"{name}\": \"oauth2\" is only valid for oauth2 profiles"
            )));
        }
        if OAUTH_KEYS.contains(&key) {
            return Err(Error::config(format!(
                "profile \"{name}\": \"{key}\" belongs in [{name}.oauth2]"
            )));
        }
        return Err(unknown_key(name, key));
    }

    let host = parse_host(name, &required_string(name, table, "host")?)?;

    let kind = if is_oauth {
        let oauth = match table.get("oauth2") {
            Some(toml::Value::Table(oauth)) => oauth,
            Some(_) => {
                return Err(Error::config(format!(
                    "profile \"{name}\": \"oauth2\" must be a table"
                )))
            }
            None => {
                return Err(Error::config(format!(
                    "profile \"{name}\": missing required table [{name}.oauth2]"
                )))
            }
        };
        Kind::OAuth2(parse_oauth(name, oauth)?)
    } else {
        Kind::Basic
    };

    let access_token = match table.get("access-token") {
        None => None,
        Some(value) => Some(parse_access_token(name, value)?),
    };
    let netrc = match table.get("netrc") {
        None => false,
        Some(value) => {
            parse_netrc(name, value)?;
            true
        }
    };

    Ok(Profile {
        name: name.to_string(),
        host,
        kind,
        access_token,
        netrc,
    })
}

fn parse_oauth(name: &str, table: &toml::Table) -> Result<OAuth> {
    for key in table.keys() {
        let key = key.as_str();
        if SECRET_KEYS.contains(&key) {
            return Err(secret_error(name, key));
        }
        if !OAUTH_KEYS.contains(&key) {
            return Err(unknown_key(name, key));
        }
    }
    let client_id = required_string(name, table, "client_id")?;
    let flow = match required_string(name, table, "flow")?.as_str() {
        "device" => Flow::Device,
        "authorization_code" => Flow::AuthorizationCode,
        _ => {
            return Err(Error::config(format!(
                "profile \"{name}\": \"flow\" must be \"device\" or \"authorization_code\""
            )))
        }
    };
    let token_endpoint = required_string(name, table, "token_endpoint")?;
    check_endpoint(name, "token_endpoint", &token_endpoint)?;

    let device_authorization_endpoint = string_value(name, table, "device_authorization_endpoint")?;
    let authorization_endpoint = string_value(name, table, "authorization_endpoint")?;
    match flow {
        Flow::Device => {
            if authorization_endpoint.is_some() {
                return Err(Error::config(format!(
                    "profile \"{name}\": \"authorization_endpoint\" is only valid for flow \
                     \"authorization_code\""
                )));
            }
            let endpoint = device_authorization_endpoint
                .as_deref()
                .ok_or_else(|| missing(name, "device_authorization_endpoint"))?;
            check_endpoint(name, "device_authorization_endpoint", endpoint)?;
        }
        Flow::AuthorizationCode => {
            if device_authorization_endpoint.is_some() {
                return Err(Error::config(format!(
                    "profile \"{name}\": \"device_authorization_endpoint\" is only valid for \
                     flow \"device\""
                )));
            }
            let endpoint = authorization_endpoint
                .as_deref()
                .ok_or_else(|| missing(name, "authorization_endpoint"))?;
            check_endpoint(name, "authorization_endpoint", endpoint)?;
        }
    }

    let scopes = match table.get("scopes") {
        None => Vec::new(),
        Some(toml::Value::Array(items)) => {
            let mut scopes = Vec::new();
            for item in items {
                match item {
                    toml::Value::String(s)
                        if !s.is_empty() && !s.chars().any(char::is_whitespace) =>
                    {
                        scopes.push(s.clone())
                    }
                    _ => {
                        return Err(Error::config(format!(
                            "profile \"{name}\": \"scopes\" items must be non-empty strings \
                             without whitespace"
                        )))
                    }
                }
            }
            scopes
        }
        Some(_) => {
            return Err(Error::config(format!(
                "profile \"{name}\": \"scopes\" must be an array of strings"
            )))
        }
    };

    Ok(OAuth {
        client_id,
        flow,
        device_authorization_endpoint,
        authorization_endpoint,
        token_endpoint,
        scopes,
    })
}

fn parse_access_token(name: &str, value: &toml::Value) -> Result<Option<Style>> {
    let Some(table) = value.as_table() else {
        return Err(Error::config(format!(
            "profile \"{name}\": \"access-token\" must be a table"
        )));
    };
    let mut style = None;
    for (key, value) in table {
        match key.as_str() {
            "style" => {
                style = Some(match value.as_str() {
                    Some("plain") => Style::Plain,
                    Some("typed") => Style::Typed,
                    Some(old @ ("github" | "gitlab")) => {
                        let new = if old == "github" { "plain" } else { "typed" };
                        return Err(Error::config(format!(
                            "profile \"{name}\": style \"{old}\" was renamed to \"{new}\" in \
                             [{name}.access-token]"
                        )));
                    }
                    _ => return Err(style_error(name)),
                })
            }
            k if SECRET_KEYS.contains(&k) => return Err(secret_error(name, k)),
            k => return Err(unknown_key(name, k)),
        }
    }
    Ok(style)
}

fn parse_netrc(name: &str, value: &toml::Value) -> Result<()> {
    let Some(table) = value.as_table() else {
        return Err(Error::config(format!(
            "profile \"{name}\": \"netrc\" must be a table"
        )));
    };
    // The table only selects the mechanism: the login is the stored username (basic) or `oauth2`
    if let Some(key) = table.keys().next() {
        return Err(match key.as_str() {
            "style" => style_error(name),
            k if k != "username" && SECRET_KEYS.contains(&k) => secret_error(name, k),
            k => unknown_key(name, k),
        });
    }
    Ok(())
}

/// Returns the configuration file path: `explicit`, else `$XDG_CONFIG_HOME/nix-vault/config.toml`,
/// else `~/.config/nix-vault/config.toml`. (`NIX_VAULT_CONFIG_FILE` reaches `explicit` through
/// the command line parser.)
pub fn config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    base_dir("XDG_CONFIG_HOME", ".config")
        .join("nix-vault")
        .join("config.toml")
}

/// Returns the state directory (lock files only): `$NIX_VAULT_STATE_DIR`, else
/// `$XDG_STATE_HOME/nix-vault`, else `~/.local/state/nix-vault`.
pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("NIX_VAULT_STATE_DIR") {
        return PathBuf::from(dir);
    }
    base_dir("XDG_STATE_HOME", ".local/state").join("nix-vault")
}

/// Returns the directory of the encrypted file store: `$NIX_VAULT_STORE_DIR`, else
/// `$XDG_DATA_HOME/nix-vault/credentials`, else `~/.local/share/nix-vault/credentials`.
pub fn store_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("NIX_VAULT_STORE_DIR") {
        return PathBuf::from(dir);
    }
    base_dir("XDG_DATA_HOME", ".local/share")
        .join("nix-vault")
        .join("credentials")
}

fn base_dir(xdg_variable: &str, home_relative: &str) -> PathBuf {
    match std::env::var_os(xdg_variable) {
        Some(dir) if !dir.is_empty() && Path::new(&dir).is_absolute() => PathBuf::from(dir),
        _ => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(home_relative),
    }
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[cache]
host = "Cache.Example.com"
type = "basic"

[company]
host = "gitlab.example.com"
type = "oauth2"

[company.oauth2]
client_id = "public-client-id"
flow = "device"
device_authorization_endpoint = "https://gitlab.example.com/oauth/authorize_device"
token_endpoint = "https://gitlab.example.com/oauth/token"
scopes = ["read_api"]

[company.access-token]
style = "typed"

[company.netrc]
"#;

    fn error(text: &str) -> String {
        Config::parse(text).unwrap_err().to_string()
    }

    #[test]
    fn parses_the_example_shape() {
        let config = Config::parse(GOOD).unwrap();
        assert_eq!(config.profiles.len(), 2);
        assert_eq!(config.profiles[0].host, "cache.example.com");
        assert_eq!(config.profile("company").unwrap().style(), Style::Typed);
    }

    #[test]
    fn delivery_defaults_follow_the_type() {
        let config = Config::parse(GOOD).unwrap();
        let cache = config.profile("cache").unwrap().delivery();
        assert_eq!(
            cache,
            Delivery {
                access_token: None,
                netrc: true
            }
        );
        let oauth = Config::parse(
            "[a]\nhost=\"github.com\"\ntype=\"oauth2\"\n[a.oauth2]\nclient_id=\"c\"\nflow=\"device\"\n\
             device_authorization_endpoint=\"https://github.com/d\"\n\
             token_endpoint=\"https://github.com/t\"\n",
        )
        .unwrap();
        assert_eq!(
            oauth.profiles[0].delivery(),
            Delivery {
                access_token: Some(Style::Plain),
                netrc: false
            }
        );
        let both = config.profile("company").unwrap().delivery();
        assert_eq!(
            both,
            Delivery {
                access_token: Some(Style::Typed),
                netrc: true
            }
        );
    }

    #[test]
    fn identity_covers_type_host_and_client_only() {
        let base = Config::parse(GOOD).unwrap();
        let id = base.profile("company").unwrap().identity();

        let changed_host = GOOD.replace("gitlab.example.com\"\ntype", "other.example.com\"\ntype");
        let id_host = Config::parse(&changed_host)
            .unwrap()
            .profile("company")
            .unwrap()
            .identity();
        assert_ne!(id, id_host);

        let id_client = Config::parse(&GOOD.replace("public-client-id", "another"))
            .unwrap()
            .profile("company")
            .unwrap()
            .identity();
        assert_ne!(id, id_client);

        // Flow details, scopes and style do not matter
        let relaxed = GOOD
            .replace("[\"read_api\"]", "[\"read_api\", \"read_user\"]")
            .replace("\"typed\"", "\"plain\"")
            .replace("oauth/token", "oauth/token2");
        let id_relaxed = Config::parse(&relaxed)
            .unwrap()
            .profile("company")
            .unwrap()
            .identity();
        assert_eq!(id, id_relaxed);
    }

    #[test]
    fn rejects_secrets_and_unknown_keys() {
        let secret = "[a]\nhost=\"h.example\"\ntype=\"basic\"\npassword=\"x\"\n";
        assert_eq!(
            error(secret),
            "profile \"a\": \"password\" must not be stored in the configuration file; \
             use nix-vault login"
        );
        let user = "[a]\nhost=\"h.example\"\ntype=\"basic\"\nusername=\"x\"\n";
        assert!(error(user).contains("\"username\" must not be stored"));
        let unknown = "[a]\nhost=\"h.example\"\ntype=\"basic\"\nextends=\"b\"\n";
        assert_eq!(error(unknown), "profile \"a\": unknown key \"extends\"");
    }

    #[test]
    fn validates_hosts_endpoints_and_style() {
        assert!(error("[a]\nhost=\"https://h.example\"\ntype=\"basic\"\n")
            .contains("host must be a bare hostname"));
        let http = GOOD.replace(
            "https://gitlab.example.com/oauth/token",
            "http://example.com/t",
        );
        assert!(error(&http).contains("\"token_endpoint\" must use https"));
        let loopback = GOOD.replace(
            "https://gitlab.example.com/oauth/token",
            "http://127.0.0.1:9/t",
        );
        assert!(Config::parse(&loopback).is_ok());
        let style = GOOD.replace("\"typed\"", "\"bitbucket\"");
        assert!(error(&style).contains("\"style\" must be \"plain\" or \"typed\""));
        let old = GOOD.replace("\"typed\"", "\"gitlab\"");
        assert!(error(&old).contains("style \"gitlab\" was renamed to \"typed\""));
        let old = GOOD.replace("\"typed\"", "\"github\"");
        assert!(error(&old).contains("style \"github\" was renamed to \"plain\""));
        let outside = "[a]\nhost=\"h.example\"\ntype=\"basic\"\nstyle=\"plain\"\n";
        assert!(error(outside).contains("in [a.access-token]"));
    }

    #[test]
    fn the_netrc_table_takes_no_keys() {
        let user = "[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.netrc]\nusername=\"u\"\n";
        assert_eq!(error(user), "profile \"a\": unknown key \"username\"");
    }

    #[test]
    fn oauth_keys_need_an_oauth_profile_and_flow_endpoints_match() {
        let top_level = "[a]\nhost=\"h.example\"\ntype=\"basic\"\nclient_id=\"c\"\n";
        assert_eq!(
            error(top_level),
            "profile \"a\": \"client_id\" belongs in [a.oauth2]"
        );
        let basic = "[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.oauth2]\nclient_id=\"c\"\n";
        assert_eq!(
            error(basic),
            "profile \"a\": \"oauth2\" is only valid for oauth2 profiles"
        );
        let no_table = "[a]\nhost=\"h.example\"\ntype=\"oauth2\"\n";
        assert_eq!(
            error(no_table),
            "profile \"a\": missing required table [a.oauth2]"
        );
        let unknown = GOOD.replace("scopes =", "audience = \"x\"\nscopes =");
        assert_eq!(
            error(&unknown),
            "profile \"company\": unknown key \"audience\""
        );
        let missing_client = GOOD.replace("client_id = \"public-client-id\"\n", "");
        assert!(error(&missing_client).contains("missing required key \"client_id\""));
        let wrong_endpoint =
            GOOD.replace("device_authorization_endpoint", "authorization_endpoint");
        assert!(error(&wrong_endpoint).contains("only valid for flow"));
    }

    #[test]
    fn rejects_bad_names_and_invalid_toml_without_quoting_the_input() {
        assert!(error("[\"bad name\"]\nhost=\"h\"\ntype=\"basic\"\n")
            .contains("may only contain letters, digits"));
        let message = error("[a]\nhost = \"h.example\ntoken = \"SECRET-VALUE\"\n");
        assert!(message.contains("invalid configuration file"));
        assert!(!message.contains("SECRET-VALUE"));
    }
}
