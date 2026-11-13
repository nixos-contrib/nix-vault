//! Secure credential storage.
//!
//! Credentials live in the platform keyring, one JSON entry per profile. There is no automatic
//! fallback: when the keyring cannot be used the command fails (see [`open`]). An encrypted file
//! store exists for machines without a keychain, but only when selected explicitly with
//! `NIX_VAULT_STORE=file`.

pub mod file;
pub mod keyring;
pub mod locker;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::vault::{auth::redact::Secret, Error, Result};

/// Keyring service name under which credentials are stored; the account is the profile name.
pub const SERVICE: &str = "nix-vault";
/// Current layout version of [`Credential`].
const SCHEMA: u32 = 1;

/// A place that keeps secret values by account name.
pub trait SecretStore: Send {
    /// Returns the value stored for `account`, or `None`.
    fn get(&self, account: &str) -> Result<Option<Secret>>;
    /// Stores `value` for `account`, replacing any existing value.
    fn set(&self, account: &str, value: &Secret) -> Result<()>;
    /// Deletes the value for `account`. Returns false if there was none.
    fn delete(&self, account: &str) -> Result<bool>;
}

/// Username and password (or personal access token) of a basic profile.
#[derive(Clone, Serialize, Deserialize)]
pub struct BasicCredential {
    /// Account name.
    pub username: Secret,
    /// Password or personal access token.
    pub password: Secret,
}

/// OAuth tokens of an oauth2 profile.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthCredential {
    /// Current access token.
    pub access_token: Secret,
    /// Refresh token, when the provider issued one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Secret>,
    /// Token type, always `bearer`.
    pub token_type: String,
    /// When the access token expires; absent means unknown.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// Scopes granted, as reported by the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// What is kept in the keyring for one profile.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Layout version.
    pub schema: u32,
    /// Identity of the profile the credential was obtained for (see `Profile::identity`).
    pub identity: String,
    /// When it was saved.
    #[serde(with = "time::serde::rfc3339")]
    pub saved_at: OffsetDateTime,
    /// Present for basic profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic: Option<BasicCredential>,
    /// Present for oauth2 profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2: Option<OAuthCredential>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("identity", &self.identity)
            .field("basic", &self.basic.as_ref().map(|_| "[REDACTED]"))
            .field("oauth2", &self.oauth2.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl std::fmt::Debug for BasicCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BasicCredential([REDACTED])")
    }
}

impl std::fmt::Debug for OAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OAuthCredential([REDACTED])")
    }
}

fn check_secret(label: &str, secret: &Secret) -> Result<()> {
    let value = secret.expose();
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(Error::Auth(format!(
            "the {label} is empty or contains control characters"
        )));
    }
    Ok(())
}

impl Credential {
    /// Builds a basic credential for a profile with identity `identity`.
    pub fn basic(identity: String, username: Secret, password: Secret) -> Self {
        Credential {
            schema: SCHEMA,
            identity,
            saved_at: OffsetDateTime::now_utc(),
            basic: Some(BasicCredential { username, password }),
            oauth2: None,
        }
    }

    /// Builds an oauth2 credential for a profile with identity `identity`.
    pub fn oauth2(identity: String, credential: OAuthCredential) -> Self {
        Credential {
            schema: SCHEMA,
            identity,
            saved_at: OffsetDateTime::now_utc(),
            basic: None,
            oauth2: Some(credential),
        }
    }

    /// Checks the invariants of a stored credential.
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA {
            return Err(Error::StoreUnavailable(
                "a stored credential was written by a newer nix-vault; upgrade nix-vault".into(),
            ));
        }
        match (&self.basic, &self.oauth2) {
            (Some(basic), None) => {
                check_secret("username", &basic.username)?;
                check_secret("password", &basic.password)
            }
            (None, Some(oauth)) => {
                check_secret("access token", &oauth.access_token)?;
                if let Some(refresh) = &oauth.refresh_token {
                    check_secret("refresh token", refresh)?;
                }
                Ok(())
            }
            _ => Err(Error::StoreUnavailable(
                "a stored credential must hold exactly one of basic or oauth2 values".into(),
            )),
        }
    }
}

/// Typed access to the credentials of profiles.
pub struct CredentialStore {
    inner: Box<dyn SecretStore>,
}

impl CredentialStore {
    /// Wraps a secret store.
    pub fn new(inner: Box<dyn SecretStore>) -> Self {
        CredentialStore { inner }
    }

    /// Opens the selected store (the keyring, or the encrypted file store).
    pub fn open() -> Result<Self> {
        Ok(CredentialStore::new(open()?))
    }

    /// Returns the credential stored for `profile`, if any.
    pub fn load(&self, profile: &str) -> Result<Option<Credential>> {
        let Some(raw) = self.inner.get(profile)? else {
            return Ok(None);
        };
        let credential: Credential = serde_json::from_str(raw.expose()).map_err(|_| {
            Error::StoreUnavailable(format!(
                "the stored entry for profile \"{profile}\" is unreadable; \
                 run: nix-vault login --profile {profile} --force"
            ))
        })?;
        credential.validate()?;
        Ok(Some(credential))
    }

    /// Stores `credential` for `profile`, replacing any existing one.
    pub fn save(&self, profile: &str, credential: &Credential) -> Result<()> {
        credential.validate()?;
        let json = serde_json::to_string(credential)
            .map_err(|e| Error::StoreUnavailable(format!("cannot encode credential: {e}")))?;
        self.inner.set(profile, &Secret::new(json))
    }

    /// Removes the credential of `profile`. Returns false if there was none.
    pub fn remove(&self, profile: &str) -> Result<bool> {
        self.inner.delete(profile)
    }
}

/// Opens the secret store selected by `NIX_VAULT_STORE`: `keychain` (the default, the platform
/// keyring) or `file` (the encrypted file store). The choice is never made automatically.
pub fn open() -> Result<Box<dyn SecretStore>> {
    match std::env::var("NIX_VAULT_STORE").as_deref() {
        Ok("") | Err(_) | Ok("keychain") => Ok(Box::new(keyring::Keychain::open()?)),
        Ok("file") => Ok(Box::new(file::FileStore::open(
            crate::vault::config::store_dir(),
            file::Settings::from_env()?,
        )?)),
        Ok(other) => Err(Error::config(format!(
            "NIX_VAULT_STORE must be \"keychain\" or \"file\", not \"{other}\""
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth() -> OAuthCredential {
        OAuthCredential {
            access_token: Secret::new("at-1"),
            refresh_token: Some(Secret::new("rt-1")),
            token_type: "bearer".into(),
            expires_at: Some(OffsetDateTime::UNIX_EPOCH),
            scope: Some("read_api".into()),
        }
    }

    #[test]
    fn round_trips_through_json() {
        let credential = Credential::oauth2("id".into(), oauth());
        let json = serde_json::to_string(&credential).unwrap();
        let back: Credential = serde_json::from_str(&json).unwrap();
        back.validate().unwrap();
        assert_eq!(back.identity, "id");
        assert_eq!(
            back.oauth2.unwrap().expires_at,
            Some(OffsetDateTime::UNIX_EPOCH)
        );
    }

    #[test]
    fn debug_never_shows_secrets() {
        let credential =
            Credential::basic("id".into(), Secret::new("alice-x"), Secret::new("pw-x"));
        let text = format!("{credential:?}");
        assert!(!text.contains("alice-x") && !text.contains("pw-x"));
    }

    #[test]
    fn rejects_invalid_credentials() {
        let mut credential = Credential::basic("id".into(), Secret::new("u"), Secret::new("p"));
        credential.validate().unwrap();
        credential.basic.as_mut().unwrap().password = Secret::new("");
        assert!(credential.validate().is_err());
        credential.basic.as_mut().unwrap().password = Secret::new("a\nb");
        assert!(credential.validate().is_err());

        let mut both = Credential::basic("id".into(), Secret::new("u"), Secret::new("p"));
        both.oauth2 = Some(oauth());
        assert!(both.validate().is_err());

        let mut future = Credential::basic("id".into(), Secret::new("u"), Secret::new("p"));
        future.schema = 99;
        assert!(future
            .validate()
            .unwrap_err()
            .to_string()
            .contains("upgrade nix-vault"));
    }
}
