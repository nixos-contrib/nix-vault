//! A file-backed store for fake credentials. Compiled only with the `file-store` feature.
//!
//! CLI tests run separate processes (login, then exec), so an in-process map cannot hold the
//! credentials between them. Release builds never contain this code.

use std::path::PathBuf;

use crate::vault::{auth::redact::Secret, store::SecretStore, Error, Result};

/// One JSON file per account under a directory.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    /// Opens the store. `NIX_VAULT_FILE_STORE_FAIL=1` makes opening fail like an unavailable
    /// keyring.
    pub fn open(dir: PathBuf) -> Result<Self> {
        if std::env::var_os("NIX_VAULT_FILE_STORE_FAIL").is_some_and(|v| v == "1") {
            return Err(Error::StoreUnavailable(
                "file store failure injected".into(),
            ));
        }
        std::fs::create_dir_all(&dir).map_err(|e| Error::io("cannot create the file store", e))?;
        Ok(FileStore { dir })
    }

    fn path(&self, account: &str) -> PathBuf {
        self.dir.join(format!("{account}.json"))
    }
}

impl SecretStore for FileStore {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        match std::fs::read_to_string(self.path(account)) {
            Ok(text) => Ok(Some(Secret::new(text))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io("cannot read the file store", e)),
        }
    }

    fn set(&self, account: &str, value: &Secret) -> Result<()> {
        // Failure injection for the "persist after refresh" tests
        if std::env::var_os("NIX_VAULT_FILE_STORE_FAIL_SET").is_some_and(|v| v == "1") {
            return Err(Error::StoreUnavailable(
                "file store write failure injected".into(),
            ));
        }
        std::fs::write(self.path(account), value.expose())
            .map_err(|e| Error::io("cannot write the file store", e))
    }

    fn delete(&self, account: &str) -> Result<bool> {
        match std::fs::remove_file(self.path(account)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::io("cannot delete from the file store", e)),
        }
    }
}
