//! Profile configuration: the TOML model, validation, discovery and derived values.
//!
//! The file holds no secrets. It is validated as a whole before any command acts, and every
//! error names the profile and the key concerned.

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use oauth2::url::Url;
use serde::Deserialize;
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
/// Keys valid inside `[<name>.oauth2]`.
const OAUTH_KEYS: [&str; 6] = [
    "client_id",
    "flow",
    "device_authorization_endpoint",
    "authorization_endpoint",
    "token_endpoint",
    "scopes",
];

/// The prefix put in front of an access token for Nix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum Prefix {
    /// `<host>=<token>`: no prefix.
    #[serde(rename = "none")]
    Bare,
    /// `<host>=OAuth2:<token>` (oauth2) or `<host>=PAT:<token>` (basic): the prefix depends on the
    /// profile type.
    #[serde(rename = "by_type")]
    ByType,
}

/// The OAuth flow used to log in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum Flow {
    /// Device authorization grant.
    #[serde(rename = "device")]
    Device,
    /// Authorization code grant with PKCE.
    #[serde(rename = "authorization_code")]
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
    /// Fixed loopback port for the browser redirect (flow `authorization_code`); a random free
    /// port when absent. Needed by providers that only accept pre-registered redirect URLs.
    pub redirect_port: Option<u16>,
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
    /// Access-token delivery was chosen in `[<name>.nix]`: the optional `access_token_prefix`.
    pub access_token: Option<Option<Prefix>>,
    /// Netrc delivery was chosen in `[<name>.nix]`.
    pub netrc: bool,
    /// Proxy delivery was chosen in `[<name>.nix]`: a local reverse proxy adds the credentials.
    pub proxy: bool,
    /// The headers the proxy adds, from `[<name>.proxy]`: name and value template, where
    /// `{username}` and `{password}` stand for the stored credential. Empty without `proxy`.
    pub proxy_headers: Vec<(String, String)>,
}

/// The mechanisms through which a profile's credentials are presented to Nix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Present as a Nix access token with this style.
    pub access_token: Option<Prefix>,
    /// Present through netrc.
    pub netrc: bool,
    /// Present through a local reverse proxy that Nix is pointed at.
    pub proxy: bool,
}

impl Profile {
    /// Returns the authentication type name used in output.
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            Kind::Basic => "basic",
            Kind::OAuth2(_) => "oauth2",
        }
    }

    /// Returns the effective access-token prefix: the configured one, else `none` for the host
    /// `github.com` and `by_type` for every other host.
    pub fn prefix(&self) -> Prefix {
        match self.access_token {
            Some(Some(style)) => style,
            _ if self.host == "github.com" => Prefix::Bare,
            _ => Prefix::ByType,
        }
    }

    /// Returns the mechanisms used for this profile (see FR-026).
    pub fn delivery(&self) -> Delivery {
        if self.proxy {
            return Delivery {
                access_token: None,
                netrc: false,
                proxy: true,
            };
        }
        if self.access_token.is_none() && !self.netrc {
            return match self.kind {
                Kind::OAuth2(_) => Delivery {
                    access_token: Some(self.prefix()),
                    netrc: false,
                    proxy: false,
                },
                Kind::Basic => Delivery {
                    access_token: None,
                    netrc: true,
                    proxy: false,
                },
            };
        }
        Delivery {
            access_token: self.access_token.map(|_| self.prefix()),
            netrc: self.netrc,
            proxy: false,
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

fn prefix_error(profile: &str) -> Error {
    Error::config(format!(
        "profile \"{profile}\": \"access_token_prefix\" must be \"none\" or \"by_type\" in \
         [{profile}.nix]"
    ))
}

/// The earlier spellings of the access token prefix key, which name their replacement.
const OLD_PREFIX_KEYS: [&str; 3] = ["style", "access-token-style", "access_token_style"];

fn renamed_prefix_key(profile: &str, old: &str) -> Error {
    Error::config(format!(
        "profile \"{profile}\": \"{old}\" was renamed to \"access_token_prefix\" in \
         [{profile}.nix]"
    ))
}

fn use_error(profile: &str) -> Error {
    Error::config(format!(
        "profile \"{profile}\": \"use\" must be a non-empty list without repeats of \
         \"access-token\", \"netrc\" and \"proxy\" in [{profile}.nix]"
    ))
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

/// What the TOML file may hold for a `basic` profile. Serde checks names, types, enums and
/// unknown keys; `validate` applies the rules that span fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBasic {
    host: String,
    nix: Option<RawNix>,
    proxy: Option<RawProxy>,
    // `type` was read to pick this struct
    #[serde(rename = "type")]
    _type: String,
}

/// What the TOML file may hold for an `oauth2` profile.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOAuth2Profile {
    host: String,
    oauth2: RawOAuth,
    nix: Option<RawNix>,
    proxy: Option<RawProxy>,
    #[serde(rename = "type")]
    _type: String,
}

enum RawProfile {
    Basic(RawBasic),
    OAuth2(RawOAuth2Profile),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxy {
    headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOAuth {
    client_id: String,
    flow: Flow,
    device_authorization_endpoint: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: String,
    #[serde(default)]
    scopes: Vec<String>,
    redirect_port: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNix {
    r#use: Option<Vec<Mechanism>>,
    access_token_prefix: Option<Prefix>,
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
enum Mechanism {
    #[serde(rename = "access-token")]
    AccessToken,
    #[serde(rename = "netrc")]
    Netrc,
    #[serde(rename = "proxy")]
    Proxy,
}

/// Rejects, with the messages the contract promises, the keys that must never be in the file and
/// the keys of earlier formats or in the wrong table. Runs before serde so those messages win.
fn precheck(name: &str, table: &toml::Table) -> Result<()> {
    for key in table.keys().map(String::as_str) {
        if SECRET_KEYS.contains(&key) {
            return Err(secret_error(name, key));
        }
        let moved = |what: String| Error::config(format!("profile \"{name}\": {what}"));
        match key {
            "access-token" => {
                return Err(moved(format!(
                    "[{name}.access-token] was replaced by [{name}.nix] (use = \
                     [\"access-token\"], access_token_prefix = \"none\" or \"by_type\")"
                )))
            }
            "netrc" => {
                return Err(moved(format!(
                    "[{name}.netrc] was replaced by [{name}.nix] (use = [\"netrc\"])"
                )))
            }
            k if OLD_PREFIX_KEYS.contains(&k) => return Err(renamed_prefix_key(name, k)),
            "use" | "access_token_prefix" => {
                return Err(moved(format!("\"{key}\" belongs in [{name}.nix]")))
            }
            k if OAUTH_KEYS.contains(&k) => {
                return Err(moved(format!("\"{k}\" belongs in [{name}.oauth2]")))
            }
            _ => {}
        }
    }
    for section in ["oauth2", "nix", "proxy"] {
        let Some(toml::Value::Table(inner)) = table.get(section) else {
            continue;
        };
        for key in inner.keys().map(String::as_str) {
            if SECRET_KEYS.contains(&key) {
                return Err(secret_error(name, key));
            }
            if section == "nix" && OLD_PREFIX_KEYS.contains(&key) {
                return Err(renamed_prefix_key(name, key));
            }
        }
    }
    Ok(())
}

/// Turns a serde error into the contract's message. The path says which key holds the wrong
/// value; the offending value itself is never quoted, since it could be a secret pasted into the
/// wrong place.
fn shape_error(name: &str, path: &str, message: &str, table: &toml::Table) -> Error {
    let config = |text: String| Error::config(format!("profile \"{name}\": {text}"));
    let quoted = |prefix: &str| {
        let rest = message.strip_prefix(prefix)?;
        Some(rest.split('`').next()?.to_string())
    };
    if message.starts_with("missing field `oauth2`") {
        return config(format!("missing required table [{name}.oauth2]"));
    }
    if let Some(key) = quoted("missing field `") {
        return config(format!("missing required key \"{key}\""));
    }
    if let Some(key) = quoted("unknown field `") {
        if key == "oauth2" {
            return config("\"oauth2\" is only valid for oauth2 profiles".into());
        }
        return unknown_key(name, &key);
    }
    match path {
        "oauth2.flow" => config("\"flow\" must be \"device\" or \"authorization_code\"".into()),
        "nix.access_token_prefix" => {
            let old = table
                .get("nix")
                .and_then(|n| n.get("access_token_prefix"))
                .and_then(|v| v.as_str());
            // The values of the earlier spellings name their replacement
            let renamed = |old: &str| match old {
                "plain" | "github" => Some("none"),
                "typed" | "gitlab" => Some("by_type"),
                _ => None,
            };
            match old.and_then(|o| renamed(o).map(|n| (o, n))) {
                Some((old, new)) => config(format!(
                    "value \"{old}\" was renamed to \"{new}\" in [{name}.nix]"
                )),
                None => prefix_error(name),
            }
        }
        p if p.starts_with("nix.use") => use_error(name),
        "oauth2.scopes" => config("\"scopes\" must be an array of strings".into()),
        p if p.starts_with("oauth2.scopes") => {
            config("\"scopes\" items must be non-empty strings without whitespace".into())
        }
        p => {
            let key = p.rsplit('.').next().unwrap_or(p);
            // Serde words a type mismatch as "invalid type: <value>, expected <what>"
            match message.rsplit_once(", expected ") {
                Some((_, what)) => {
                    let what = match what {
                        "a sequence" => "an array",
                        "a map" => "a table",
                        other if other.starts_with("struct ") => "a table",
                        other => other,
                    };
                    config(format!("\"{key}\" must be {what}"))
                }
                None => config(format!("\"{key}\" has an invalid value")),
            }
        }
    }
}

fn parse_profile(name: &str, table: &toml::Table) -> Result<Profile> {
    precheck(name, table)?;
    let value = || toml::Value::Table(table.clone());
    let fail = |e: serde_path_to_error::Error<toml::de::Error>| {
        shape_error(name, &e.path().to_string(), e.inner().message(), table)
    };
    // `type` picks the struct, so each type accepts exactly its own keys
    let raw = match table.get("type").and_then(|t| t.as_str()) {
        Some("basic") => {
            RawProfile::Basic(serde_path_to_error::deserialize(value()).map_err(fail)?)
        }
        Some("oauth2") => {
            RawProfile::OAuth2(serde_path_to_error::deserialize(value()).map_err(fail)?)
        }
        None => {
            return Err(Error::config(format!(
                "profile \"{name}\": missing required key \"type\""
            )))
        }
        Some(_) => {
            return Err(Error::config(format!(
                "profile \"{name}\": \"type\" must be \"basic\" or \"oauth2\""
            )))
        }
    };
    validate(name, raw)
}

fn nonempty(name: &str, key: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::config(format!(
            "profile \"{name}\": \"{key}\" must be a non-empty string"
        )));
    }
    Ok(())
}

/// The rules that span fields: the endpoints each flow needs, `use` and the style.
fn validate(name: &str, raw: RawProfile) -> Result<Profile> {
    let config = |text: String| Error::config(format!("profile \"{name}\": {text}"));
    // The type decides the default delivery: (access token, netrc)
    let is_basic = matches!(raw, RawProfile::Basic(_));
    let placeholders: &[&str] = if is_basic {
        &["{username}", "{password}"]
    } else {
        &["{access_token}"]
    };
    let (host, kind, nix, proxy_table, default) = match raw {
        RawProfile::Basic(b) => (b.host, Kind::Basic, b.nix, b.proxy, (false, true)),
        RawProfile::OAuth2(o) => (
            o.host,
            Kind::OAuth2(validate_oauth(name, o.oauth2)?),
            o.nix,
            o.proxy,
            (true, false),
        ),
    };
    let host = parse_host(name, &host)?;

    let (access_token, netrc, proxy) = match nix {
        None => (None, false, false),
        Some(nix) => {
            let mut proxy = false;
            let (token, netrc) = match &nix.r#use {
                None => default,
                Some(list) => {
                    let token = list.contains(&Mechanism::AccessToken);
                    let netrc = list.contains(&Mechanism::Netrc);
                    proxy = list.contains(&Mechanism::Proxy);
                    let repeats =
                        list.len() != usize::from(token) + usize::from(netrc) + usize::from(proxy);
                    if list.is_empty() || repeats {
                        return Err(use_error(name));
                    }
                    (token, netrc)
                }
            };
            if proxy && (token || netrc) {
                return Err(config(format!(
                    "\"proxy\" cannot be combined with other mechanisms in \"use\" in \
                     [{name}.nix]: the credentials go to the proxy, not to the host"
                )));
            }
            if nix.access_token_prefix.is_some() && !token {
                return Err(config(format!(
                    "\"access_token_prefix\" needs \"access-token\" in \"use\" in [{name}.nix]"
                )));
            }
            (token.then_some(nix.access_token_prefix), netrc, proxy)
        }
    };

    let proxy_headers = match (proxy, proxy_table) {
        (true, Some(table)) => validate_headers(name, &table.headers, placeholders)?,
        (true, None) => {
            return Err(config(format!(
                "\"proxy\" in \"use\" needs a [{name}.proxy] table with \"headers\""
            )))
        }
        (false, Some(_)) => {
            return Err(config(format!(
                "[{name}.proxy] needs \"proxy\" in \"use\" in [{name}.nix]"
            )))
        }
        (false, None) => Vec::new(),
    };

    Ok(Profile {
        name: name.to_string(),
        host,
        kind,
        access_token,
        netrc,
        proxy,
        proxy_headers,
    })
}

/// Headers a proxy must not set: the ones that frame a message, and the one Nix uses for its own
/// HTTP proxy. (`Authorization` and `Cookie` may be set: the proxy's value replaces the client's.)
const RESERVED_HEADERS: [&str; 11] = [
    "proxy-authorization",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "expect",
];

/// Checks the header table of `[<name>.proxy]`: valid names, none reserved, values made of text
/// and the profile type's placeholders (`allowed`), at least one of which is used. Values are
/// never quoted in errors.
fn validate_headers(
    name: &str,
    headers: &BTreeMap<String, String>,
    allowed: &[&str],
) -> Result<Vec<(String, String)>> {
    let config = |text: String| Error::config(format!("profile \"{name}\": {text}"));
    if headers.is_empty() {
        return Err(config("\"headers\" must not be empty".into()));
    }
    let mut uses_credential = false;
    for (header, template) in headers {
        let valid_name = !header.is_empty()
            && header
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c));
        if !valid_name {
            return Err(config(format!("\"{header}\" is not a valid header name")));
        }
        if RESERVED_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
            return Err(config(format!(
                "the header \"{header}\" cannot be set by a proxy"
            )));
        }
        if template.is_empty() || template.chars().any(char::is_control) {
            return Err(config(format!(
                "the value of header \"{header}\" must be non-empty text without control characters"
            )));
        }
        let mut rest = template.as_str();
        while let Some(at) = rest.find(['{', '}']) {
            let tail = &rest[at..];
            let placeholder = allowed.iter().find(|p| tail.starts_with(**p));
            match placeholder {
                Some(p) => {
                    uses_credential = true;
                    rest = &tail[p.len()..];
                }
                None => {
                    return Err(config(format!(
                        "the value of header \"{header}\" has a stray brace or a placeholder \
                         this profile type does not have; use {}",
                        allowed.join(" or ")
                    )))
                }
            }
        }
    }
    if !uses_credential {
        return Err(config(format!(
            "no header in [proxy] uses {}, so the stored credential would never be sent",
            allowed.join(" or ")
        )));
    }
    Ok(headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect())
}

fn validate_oauth(name: &str, o: RawOAuth) -> Result<OAuth> {
    let config = |text: String| Error::config(format!("profile \"{name}\": {text}"));
    nonempty(name, "client_id", &o.client_id)?;
    nonempty(name, "token_endpoint", &o.token_endpoint)?;
    check_endpoint(name, "token_endpoint", &o.token_endpoint)?;
    // Each flow needs its own endpoint and rejects the other's
    let (own, other, own_key, other_key, other_flow) = match o.flow {
        Flow::Device => (
            &o.device_authorization_endpoint,
            &o.authorization_endpoint,
            "device_authorization_endpoint",
            "authorization_endpoint",
            "authorization_code",
        ),
        Flow::AuthorizationCode => (
            &o.authorization_endpoint,
            &o.device_authorization_endpoint,
            "authorization_endpoint",
            "device_authorization_endpoint",
            "device",
        ),
    };
    if other.is_some() {
        return Err(config(format!(
            "\"{other_key}\" is only valid for flow \"{other_flow}\""
        )));
    }
    let endpoint = own
        .as_deref()
        .ok_or_else(|| config(format!("missing required key \"{own_key}\"")))?;
    nonempty(name, own_key, endpoint)?;
    check_endpoint(name, own_key, endpoint)?;
    if o.scopes
        .iter()
        .any(|s| s.is_empty() || s.chars().any(char::is_whitespace))
    {
        return Err(config(
            "\"scopes\" items must be non-empty strings without whitespace".into(),
        ));
    }
    if let Some(port) = o.redirect_port {
        if !matches!(o.flow, Flow::AuthorizationCode) {
            return Err(config(
                "\"redirect_port\" is only valid for flow \"authorization_code\"".into(),
            ));
        }
        if port < 1024 {
            return Err(config(
                "\"redirect_port\" must be between 1024 and 65535".into(),
            ));
        }
    }
    Ok(OAuth {
        client_id: o.client_id,
        flow: o.flow,
        device_authorization_endpoint: o.device_authorization_endpoint,
        authorization_endpoint: o.authorization_endpoint,
        token_endpoint: o.token_endpoint,
        scopes: o.scopes,
        redirect_port: o.redirect_port,
    })
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

[company.nix]
use = ["access-token", "netrc"]
access_token_prefix = "by_type"
"#;

    fn error(text: &str) -> String {
        Config::parse(text).unwrap_err().to_string()
    }

    #[test]
    fn parses_the_example_shape() {
        let config = Config::parse(GOOD).unwrap();
        assert_eq!(config.profiles.len(), 2);
        assert_eq!(config.profiles[0].host, "cache.example.com");
        assert_eq!(config.profile("company").unwrap().prefix(), Prefix::ByType);
    }

    #[test]
    fn delivery_defaults_follow_the_type() {
        let config = Config::parse(GOOD).unwrap();
        let cache = config.profile("cache").unwrap().delivery();
        assert_eq!(
            cache,
            Delivery {
                access_token: None,
                netrc: true,
                proxy: false
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
                access_token: Some(Prefix::Bare),
                netrc: false,
                proxy: false
            }
        );
        let both = config.profile("company").unwrap().delivery();
        assert_eq!(
            both,
            Delivery {
                access_token: Some(Prefix::ByType),
                netrc: true,
                proxy: false
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
            .replace("\"by_type\"", "\"none\"")
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
        let style = GOOD.replace("\"by_type\"", "\"bitbucket\"");
        assert!(error(&style)
            .contains("\"access_token_prefix\" must be \"none\" or \"by_type\" in [company.nix]"));
        let old = GOOD.replace("\"by_type\"", "\"gitlab\"");
        assert!(error(&old).contains("value \"gitlab\" was renamed to \"by_type\""));
        let old = GOOD.replace("\"by_type\"", "\"github\"");
        assert!(error(&old).contains("value \"github\" was renamed to \"none\""));
        let old = GOOD.replace("\"by_type\"", "\"typed\"");
        assert!(error(&old).contains("value \"typed\" was renamed to \"by_type\""));
        let outside = "[a]\nhost=\"h.example\"\ntype=\"basic\"\naccess_token_prefix=\"none\"\n";
        assert_eq!(
            error(outside),
            "profile \"a\": \"access_token_prefix\" belongs in [a.nix]"
        );
        let hyphen =
            "[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.nix]\naccess-token-style=\"plain\"\n";
        assert!(error(hyphen).contains("renamed to \"access_token_prefix\""));
        let renamed = "[a]\nhost=\"h.example\"\ntype=\"basic\"\nstyle=\"plain\"\n";
        assert!(error(renamed).contains("renamed to \"access_token_prefix\" in [a.nix]"));
        let previous =
            "[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.nix]\naccess_token_style=\"plain\"\n";
        assert_eq!(
            error(previous),
            "profile \"a\": \"access_token_style\" was renamed to \"access_token_prefix\" in [a.nix]"
        );
        let style_without_token = "[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.nix]\n\
                                   access_token_prefix=\"none\"\n";
        assert!(error(style_without_token).contains("needs \"access-token\" in \"use\""));
    }

    #[test]
    fn the_nix_table_validates_use_and_rejects_the_old_tables() {
        let nix =
            |body: &str| format!("[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.nix]\n{body}\n");
        for bad in [
            "use = []",
            "use = \"netrc\"",
            "use = [\"ssh\"]",
            "use = [\"netrc\", \"netrc\"]",
        ] {
            assert!(
                error(&nix(bad)).contains("\"use\" must be a non-empty list"),
                "{bad}"
            );
        }
        let user = nix("username=\"u\"");
        assert!(error(&user).contains("\"username\" must not be stored"));
        let login = nix("login=\"u\"");
        assert_eq!(error(&login), "profile \"a\": unknown key \"login\"");
        // The tables of the earlier format name their replacement
        let old = "[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.netrc]\n";
        assert!(error(old).contains("[a.netrc] was replaced by [a.nix]"));
        let old = "[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.access-token]\n";
        assert!(error(old).contains("[a.access-token] was replaced by [a.nix]"));
        // Without `use` the type decides; `use` and the style choose the mechanisms
        let delivery = |t: &str, body: &str| {
            let extra = if t == "oauth2" {
                "[a.oauth2]\nclient_id=\"c\"\nflow=\"device\"\n\
                 device_authorization_endpoint=\"https://h.example/d\"\n\
                 token_endpoint=\"https://h.example/t\"\n"
            } else {
                ""
            };
            let text = format!("[a]\nhost=\"h.example\"\ntype=\"{t}\"\n{extra}[a.nix]\n{body}\n");
            Config::parse(&text).unwrap().profiles[0].delivery()
        };
        assert!(delivery("basic", "").netrc && delivery("basic", "").access_token.is_none());
        assert!(!delivery("oauth2", "").netrc && delivery("oauth2", "").access_token.is_some());
        let both = delivery("basic", "use = [\"access-token\", \"netrc\"]");
        assert!(both.netrc && both.access_token.is_some());
        let token_only = delivery(
            "basic",
            "use = [\"access-token\"]\naccess_token_prefix = \"none\"",
        );
        assert!(!token_only.netrc && token_only.access_token == Some(Prefix::Bare));
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
    fn a_wrong_type_names_the_key_and_never_quotes_the_value() {
        let basic = |body: &str| format!("[a]\ntype=\"basic\"\nhost=\"h.example\"\n{body}\n");
        assert_eq!(
            error(&basic("nix = 3")),
            "profile \"a\": \"nix\" must be a table"
        );
        assert_eq!(
            error("[a]\ntype=\"basic\"\nhost=5\n"),
            "profile \"a\": \"host\" must be a string"
        );
        let oauth = GOOD.replace("scopes = [\"read_api\"]", "scopes = \"SECRET-VALUE\"");
        let message = error(&oauth);
        assert_eq!(
            message,
            "profile \"company\": \"scopes\" must be an array of strings"
        );
        assert!(!message.contains("SECRET-VALUE"));
        let items = GOOD.replace("[\"read_api\"]", "[\"read_api\", 7]");
        assert!(error(&items).contains("\"scopes\" items must be non-empty strings"));
    }

    #[test]
    fn rejects_bad_names_and_invalid_toml_without_quoting_the_input() {
        assert!(error("[\"bad name\"]\nhost=\"h\"\ntype=\"basic\"\n")
            .contains("may only contain letters, digits"));
        let message = error("[a]\nhost = \"h.example\ntoken = \"SECRET-VALUE\"\n");
        assert!(message.contains("invalid configuration file"));
        assert!(!message.contains("SECRET-VALUE"));
    }
    fn code_profile(extra: &str) -> String {
        format!(
            "[sts]\nhost = \"sts.example.com\"\ntype = \"oauth2\"\n[sts.oauth2]\nclient_id = \"c\"\n\
             flow = \"authorization_code\"\nauthorization_endpoint = \"https://idp.example.com/a\"\n\
             token_endpoint = \"https://idp.example.com/t\"\n{extra}\n"
        )
    }

    #[test]
    fn redirect_port_is_optional_and_kept() {
        let config = Config::parse(&code_profile("redirect_port = 8251")).unwrap();
        let Kind::OAuth2(oauth) = &config.profile("sts").unwrap().kind else {
            panic!("not oauth2")
        };
        assert_eq!(oauth.redirect_port, Some(8251));
        let config = Config::parse(&code_profile("")).unwrap();
        let Kind::OAuth2(oauth) = &config.profile("sts").unwrap().kind else {
            panic!("not oauth2")
        };
        assert_eq!(oauth.redirect_port, None);
    }

    #[test]
    fn redirect_port_is_validated() {
        assert!(error(&code_profile("redirect_port = 80"))
            .contains("\"redirect_port\" must be between 1024 and 65535"));
        assert!(Config::parse(&code_profile("redirect_port = 70000")).is_err());
        let device = GOOD.replace(
            "scopes = [\"read_api\"]",
            "scopes = [\"read_api\"]\nredirect_port = 8251",
        );
        assert!(error(&device)
            .contains("\"redirect_port\" is only valid for flow \"authorization_code\""));
    }

    const PROXY_TABLE: &str =
        "[a.proxy]\nheaders = { CF-Access-Client-Id = \"{username}\", CF-Access-Client-Secret = \"{password}\" }\n";

    fn proxied(nix: &str, table: &str) -> String {
        format!("[a]\nhost=\"h.example\"\ntype=\"basic\"\n[a.nix]\n{nix}\n{table}")
    }

    #[test]
    fn proxy_is_an_exclusive_mechanism_of_basic_profiles() {
        let config = Config::parse(&proxied("use = [\"proxy\"]", PROXY_TABLE)).unwrap();
        let profile = &config.profiles[0];
        assert!(profile.proxy);
        assert_eq!(
            profile.delivery(),
            Delivery {
                access_token: None,
                netrc: false,
                proxy: true
            }
        );
        assert_eq!(
            profile.proxy_headers,
            [
                ("CF-Access-Client-Id".to_string(), "{username}".to_string()),
                (
                    "CF-Access-Client-Secret".to_string(),
                    "{password}".to_string()
                )
            ]
        );
        for combined in [
            "use = [\"proxy\", \"netrc\"]",
            "use = [\"access-token\", \"proxy\"]",
        ] {
            assert!(
                error(&proxied(combined, PROXY_TABLE)).contains("\"proxy\" cannot be combined"),
                "{combined}"
            );
        }
        assert!(error(&proxied("use = [\"proxy\", \"proxy\"]", PROXY_TABLE))
            .contains("\"use\" must be a non-empty list"));
        // oauth2 profiles use {access_token}, and basic placeholders are not available to them
        let oauth = |headers: &str| {
            format!(
                "[a]\nhost=\"h.example\"\ntype=\"oauth2\"\n[a.oauth2]\nclient_id=\"c\"\nflow=\"device\"\n\
                 device_authorization_endpoint=\"https://h.example/d\"\ntoken_endpoint=\"https://h.example/t\"\n\
                 [a.nix]\nuse = [\"proxy\"]\n[a.proxy]\nheaders = {{ {headers} }}\n"
            )
        };
        let config = Config::parse(&oauth("Authorization = \"Bearer {access_token}\"")).unwrap();
        assert!(config.profiles[0].proxy);
        assert_eq!(
            config.profiles[0].proxy_headers,
            [(
                "Authorization".to_string(),
                "Bearer {access_token}".to_string()
            )]
        );
        assert!(error(&oauth("X = \"{password}\"")).contains("this profile type does not have"));
        assert!(error(&proxied(
            "use = [\"proxy\"]",
            "[a.proxy]\nheaders = { X = \"{access_token}\" }\n"
        ))
        .contains("this profile type does not have"));
        // Not chosen: nothing changes
        let plain = Config::parse(BASIC_ONLY).unwrap();
        assert!(!plain.profiles[0].proxy && plain.profiles[0].proxy_headers.is_empty());
    }

    #[test]
    fn the_proxy_table_and_use_go_together() {
        assert!(error(&proxied("use = [\"proxy\"]", ""))
            .contains("\"proxy\" in \"use\" needs a [a.proxy] table with \"headers\""));
        assert!(error(&proxied("use = [\"netrc\"]", PROXY_TABLE))
            .contains("[a.proxy] needs \"proxy\" in \"use\" in [a.nix]"));
        assert!(error(&proxied("use = [\"proxy\"]", "[a.proxy]\n"))
            .contains("missing required key \"headers\""));
        assert!(
            error(&proxied("use = [\"proxy\"]", "[a.proxy]\nheaders = {}\n"))
                .contains("\"headers\" must not be empty")
        );
        assert!(error(&proxied(
            "use = [\"proxy\"]",
            "[a.proxy]\nheaders = { X = \"{password}\" }\nextra = 1\n"
        ))
        .contains("unknown key"));
    }

    #[test]
    fn header_names_and_templates_are_checked_without_quoting_values() {
        let table = |header: &str| format!("[a.proxy]\nheaders = {{ {header} }}\n");
        let check = |header: &str| error(&proxied("use = [\"proxy\"]", &table(header)));
        // Names
        assert!(check("\"Bad Name\" = \"{password}\"").contains("not a valid header name"));
        for reserved in ["Proxy-Authorization", "Host", "Content-Length"] {
            assert!(
                check(&format!("{reserved} = \"{{password}}\""))
                    .contains("cannot be set by a proxy"),
                "{reserved}"
            );
        }
        // Values
        assert!(check("X = \"\"").contains("must be non-empty text"));
        assert!(check("X = \"{token}\"").contains("this profile type does not have"));
        assert!(check("X = \"a}b{password}\"").contains("stray brace"));
        assert!(check("X = \"static\"").contains("would never be sent"));
        // Authorization and Cookie may be set: the proxy's value replaces the client's
        for settable in ["Authorization", "Cookie"] {
            assert!(
                Config::parse(&proxied(
                    "use = [\"proxy\"]",
                    &table(&format!("{settable} = \"{{password}}\""))
                ))
                .is_ok(),
                "{settable}"
            );
        }
        // Literal text around placeholders is fine
        let ok = Config::parse(&proxied(
            "use = [\"proxy\"]",
            &table("X-Auth = \"Bearer {password}\", X-User = \"{username}\""),
        ));
        assert!(ok.is_ok());
        // A wrong-typed value never shows what it was
        let message = check("X = 5");
        assert!(message.contains("\"X\" must be") && !message.contains('5'));
    }

    const BASIC_ONLY: &str = "[a]\nhost=\"h.example\"\ntype=\"basic\"\n";
}
