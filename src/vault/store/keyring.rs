//! The platform keyring: the login keychain on macOS and the Secret Service on Linux.
//!
//! There is no fallback: if the store cannot be opened the command fails.

use std::sync::OnceLock;

use crate::vault::{
    auth::redact::Secret,
    store::{SecretStore, SERVICE},
    Error, Result,
};

/// The platform keyring.
pub struct Keychain;

impl Keychain {
    /// Opens the platform store (once per process) and returns a handle to it.
    pub fn open() -> Result<Self> {
        static STORE: OnceLock<std::result::Result<(), String>> = OnceLock::new();
        STORE
            .get_or_init(|| open_store().map_err(|e| e.to_string()))
            .as_ref()
            .map(|_| Keychain)
            .map_err(|e| Error::StoreUnavailable(unavailable_hint(e)))
    }

    fn entry(account: &str) -> Result<keyring_core::Entry> {
        keyring_core::Entry::new(SERVICE, account)
            .map_err(|e| Error::StoreUnavailable(e.to_string()))
    }
}

fn unavailable_hint(reason: &str) -> String {
    if cfg!(target_os = "linux") {
        format!(
            "{reason}; nix-vault stores credentials in the Secret Service (for example \
             gnome-keyring or KeePassXC) and never falls back to plaintext files. \
             Start one in your session and try again"
        )
    } else {
        format!("{reason}; nix-vault never falls back to plaintext files")
    }
}

fn open_store() -> keyring_core::Result<()> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()?;
    #[cfg(target_os = "linux")]
    let store = zbus_secret_service_keyring_store::Store::new()?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        keyring_core::set_default_store(store);
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    Err(keyring_core::Error::NotSupportedByStore(
        "only macOS and Linux are supported".to_string(),
    ))
}

impl SecretStore for Keychain {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        match Self::entry(account)?.get_password() {
            Ok(value) => Ok(Some(Secret::new(value))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::StoreUnavailable(format!(
                "cannot read the entry for profile \"{account}\": {e}"
            ))),
        }
    }

    fn set(&self, account: &str, value: &Secret) -> Result<()> {
        Self::entry(account)?
            .set_password(value.expose())
            .map_err(|e| {
                Error::StoreUnavailable(format!(
                    "cannot write the entry for profile \"{account}\": {e}"
                ))
            })
    }

    fn delete(&self, account: &str) -> Result<bool> {
        match Self::entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(e) => Err(Error::StoreUnavailable(format!(
                "cannot delete the entry for profile \"{account}\": {e}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips a fake credential through the real platform store. Run manually on macOS and
    /// on Linux with a Secret Service: `cargo test -- --ignored keyring_smoke`.
    #[test]
    #[ignore]
    fn keyring_smoke() {
        let store = Keychain::open().expect("platform store");
        let account = "nix-vault-smoke-test";
        store.set(account, &Secret::new("fake-value")).unwrap();
        assert_eq!(store.get(account).unwrap().unwrap().expose(), "fake-value");
        assert!(store.delete(account).unwrap());
        assert!(store.get(account).unwrap().is_none());
    }
}
