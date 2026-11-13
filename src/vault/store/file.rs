//! An encrypted file store for machines without a usable keychain.
//!
//! Opt-in only (`NIX_VAULT_STORE=file`): it is never a fallback. All profiles live in one
//! age-encrypted file protected by a passphrase, so a command pays the key-derivation cost once.
//! The file never contains plaintext credentials; writes are atomic and serialized by a lock.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{DirBuilder, File, OpenOptions},
    io::{IsTerminal, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
};

use age::{scrypt, secrecy::SecretString};
use fd_lock::RwLock;
use serde::{Deserialize, Serialize};

use crate::vault::{auth::redact::Secret, store::SecretStore, Error, Result};

/// Name of the encrypted file inside the store directory.
const FILE_NAME: &str = "credentials.age";
/// Layout version of the decrypted document.
const SCHEMA: u32 = 1;
/// Lowest and highest scrypt work factors (log2 of N) accepted from the environment. The age
/// default (18) is used when none is given; lowering it weakens the protection and exists so
/// automated tests stay fast.
const MIN_WORK_FACTOR: u8 = 10;
const MAX_WORK_FACTOR: u8 = 22;

/// The decrypted contents: one opaque value per account.
#[derive(Default, Serialize, Deserialize)]
struct Document {
    schema: u32,
    entries: BTreeMap<String, Secret>,
}

/// Identifies one version of the file, so a cached document is dropped as soon as another
/// process replaces it (writes are renames, so the inode changes).
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileId {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
}

/// How the store is configured.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    /// The passphrase, when one is configured: the content of the file named by
    /// `NIX_VAULT_STORE_PASSPHRASE_FILE` (read here), else `NIX_VAULT_STORE_PASSPHRASE`. Without
    /// either, the store asks on a terminal.
    pub passphrase: Option<String>,
    /// `NIX_VAULT_STORE_WORK_FACTOR`: scrypt work factor override.
    pub work_factor: Option<u8>,
}

impl Settings {
    /// Reads the settings from the environment.
    pub fn from_env() -> Result<Self> {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    /// Reads the settings from `var`, a lookup of environment-style variables.
    fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let set = |name: &str| var(name).filter(|v| !v.is_empty());
        let work_factor = match set("NIX_VAULT_STORE_WORK_FACTOR") {
            Some(value) => {
                let parsed: u8 = value.parse().map_err(|_| work_factor_error())?;
                if !(MIN_WORK_FACTOR..=MAX_WORK_FACTOR).contains(&parsed) {
                    return Err(work_factor_error());
                }
                Some(parsed)
            }
            None => None,
        };
        // The passphrase file wins; naming one that cannot be read is an error, not a fallback
        let passphrase = match set("NIX_VAULT_STORE_PASSPHRASE_FILE") {
            Some(path) => {
                let text = std::fs::read_to_string(&path).map_err(|e| {
                    unavailable(&format!("cannot read the passphrase file {path}"), e)
                })?;
                let text = text.trim_end_matches(['\r', '\n']).to_string();
                if text.is_empty() {
                    return Err(Error::StoreUnavailable(format!(
                        "the passphrase file {path} is empty"
                    )));
                }
                Some(text)
            }
            None => set("NIX_VAULT_STORE_PASSPHRASE"),
        };
        Ok(Settings {
            passphrase,
            work_factor,
        })
    }
}

fn work_factor_error() -> Error {
    Error::config(format!(
        "NIX_VAULT_STORE_WORK_FACTOR must be a number from {MIN_WORK_FACTOR} to {MAX_WORK_FACTOR}"
    ))
}

/// The encrypted file store.
pub struct FileStore {
    dir: PathBuf,
    settings: Settings,
    passphrase: RefCell<Option<SecretString>>,
    cache: RefCell<Option<(Option<FileId>, Document)>>,
}

impl FileStore {
    /// Opens the store in `dir` (created with owner-only permissions). The passphrase is only
    /// requested when the first credential is read or written.
    pub fn open(dir: PathBuf, settings: Settings) -> Result<Self> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| {
                unavailable(
                    &format!("cannot create the store directory {}", dir.display()),
                    e,
                )
            })?;
        Ok(FileStore {
            dir,
            settings,
            passphrase: RefCell::new(None),
            cache: RefCell::new(None),
        })
    }

    fn file(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    /// Returns the identity of the file as it is now, or `None` when there is no file.
    fn file_id(&self) -> Option<FileId> {
        let meta = std::fs::metadata(self.file()).ok()?;
        Some(FileId {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.size(),
            modified: (meta.mtime(), meta.mtime_nsec()),
        })
    }

    /// Returns the passphrase: from the file, from the environment, or from a hidden prompt.
    /// `confirm` asks twice, for a store that does not exist yet.
    fn passphrase(&self, confirm: bool) -> Result<SecretString> {
        if let Some(cached) = self.passphrase.borrow().as_ref() {
            return Ok(cached.clone());
        }
        let value = if let Some(passphrase) = &self.settings.passphrase {
            passphrase.clone()
        } else if std::io::stdin().is_terminal() {
            let first = rpassword::prompt_password("Credential store passphrase: ")
                .map_err(|_| Error::Auth("cancelled".into()))?;
            if first.is_empty() {
                return Err(Error::StoreUnavailable("the passphrase is empty".into()));
            }
            if confirm {
                let again = rpassword::prompt_password("Confirm passphrase: ")
                    .map_err(|_| Error::Auth("cancelled".into()))?;
                if again != first {
                    return Err(Error::StoreUnavailable(
                        "the passphrases do not match".into(),
                    ));
                }
            }
            first
        } else {
            return Err(Error::StoreUnavailable(
                "the encrypted file store needs a passphrase: set \
                 NIX_VAULT_STORE_PASSPHRASE_FILE to a file holding it, or run from a terminal"
                    .into(),
            ));
        };
        let secret = SecretString::from(value);
        *self.passphrase.borrow_mut() = Some(secret.clone());
        Ok(secret)
    }

    /// Reads and decrypts the file. A missing file is an empty document and needs no passphrase.
    fn read(&self) -> Result<Document> {
        let ciphertext = match std::fs::read(self.file()) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Document::default()),
            Err(e) => return Err(unavailable("cannot read the encrypted store", e)),
        };
        let identity = scrypt::Identity::new(self.passphrase(false)?);
        let plaintext = age::decrypt(&identity, &ciphertext).map_err(|_| {
            Error::StoreUnavailable(format!(
                "cannot decrypt {}: wrong passphrase or damaged file",
                self.file().display()
            ))
        })?;
        serde_json::from_slice::<Document>(&plaintext)
            .ok()
            .filter(|d| d.schema == SCHEMA)
            .ok_or_else(|| {
                Error::StoreUnavailable(format!(
                    "{} has an unsupported layout",
                    self.file().display()
                ))
            })
    }

    /// Encrypts `document` and replaces the file atomically (temporary file, then rename).
    fn write(&self, document: &Document) -> Result<()> {
        let mut recipient = scrypt::Recipient::new(self.passphrase(!self.file().exists())?);
        if let Some(factor) = self.settings.work_factor {
            recipient.set_work_factor(factor);
        }
        let plaintext = serde_json::to_vec(document)
            .map_err(|e| unavailable("cannot encode the credentials", e))?;
        let ciphertext = age::encrypt(&recipient, &plaintext)
            .map_err(|e| unavailable("cannot encrypt the credentials", e))?;

        let mut temporary = tempfile::NamedTempFile::new_in(&self.dir)
            .map_err(|e| unavailable("cannot write the encrypted store", e))?;
        temporary
            .write_all(&ciphertext)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|e| unavailable("cannot write the encrypted store", e))?;
        temporary
            .persist(self.file())
            .map_err(|e| unavailable("cannot replace the encrypted store", e.error))?;
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Runs `change` on a freshly read document while holding the store lock, then writes it.
    fn update<T>(&self, change: impl FnOnce(&mut Document) -> T) -> Result<T> {
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.dir.join(".lock"))
            .map_err(|e| unavailable("cannot open the store lock", e))?;
        let mut lock = RwLock::new(lock_file);
        let _guard = lock
            .write()
            .map_err(|e| unavailable("cannot lock the store", e))?;
        let mut document = self.read()?;
        document.schema = SCHEMA;
        let result = change(&mut document);
        self.write(&document)?;
        *self.cache.borrow_mut() = Some((self.file_id(), document));
        Ok(result)
    }
}

fn unavailable(context: &str, source: impl std::fmt::Display) -> Error {
    Error::StoreUnavailable(format!("{context}: {source}"))
}

impl SecretStore for FileStore {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        // Reuse the decrypted document only while the file is the one it was read from
        let id = self.file_id();
        let fresh = matches!(self.cache.borrow().as_ref(), Some((cached, _)) if *cached == id);
        if !fresh {
            let document = self.read()?;
            *self.cache.borrow_mut() = Some((id, document));
        }
        Ok(self
            .cache
            .borrow()
            .as_ref()
            .and_then(|(_, d)| d.entries.get(account).cloned()))
    }

    fn set(&self, account: &str, value: &Secret) -> Result<()> {
        self.update(|d| {
            d.entries.insert(account.to_string(), value.clone());
        })
    }

    fn delete(&self, account: &str) -> Result<bool> {
        // Nothing stored yet: no passphrase is needed to learn that
        if !self.file().exists() {
            return Ok(false);
        }
        self.update(|d| d.entries.remove(account).is_some())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn store(dir: &Path, passphrase: &str) -> FileStore {
        FileStore::open(
            dir.to_path_buf(),
            Settings {
                passphrase: Some(passphrase.into()),
                work_factor: Some(10),
            },
        )
        .unwrap()
    }

    #[test]
    fn round_trips_and_never_writes_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), "pw-1");
        assert!(s.get("cache").unwrap().is_none());
        s.set("cache", &Secret::new("DISTINCTIVE_SECRET_VALUE"))
            .unwrap();
        // A second handle (another process) sees it
        let again = store(dir.path(), "pw-1");
        assert_eq!(
            again.get("cache").unwrap().unwrap().expose(),
            "DISTINCTIVE_SECRET_VALUE"
        );
        let on_disk = std::fs::read(dir.path().join(FILE_NAME)).unwrap();
        assert!(!String::from_utf8_lossy(&on_disk).contains("DISTINCTIVE_SECRET_VALUE"));
        assert!(!String::from_utf8_lossy(&on_disk).contains("cache"));
    }

    #[test]
    fn permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("credentials");
        let s = store(&inner, "pw-1");
        s.set("a", &Secret::new("v")).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&inner), 0o700);
        assert_eq!(mode(&inner.join(FILE_NAME)), 0o600);
    }

    #[test]
    fn a_wrong_passphrase_fails_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        store(dir.path(), "right")
            .set("a", &Secret::new("v"))
            .unwrap();
        let before = std::fs::read(dir.path().join(FILE_NAME)).unwrap();
        let wrong = store(dir.path(), "wrong");
        let message = format!("{}", wrong.get("a").err().unwrap());
        assert!(message.contains("wrong passphrase or damaged file"));
        assert!(wrong.set("b", &Secret::new("x")).is_err());
        assert_eq!(std::fs::read(dir.path().join(FILE_NAME)).unwrap(), before);
    }

    #[test]
    fn a_change_made_by_another_handle_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        let first = store(dir.path(), "pw");
        first.set("a", &Secret::new("1")).unwrap();
        assert_eq!(first.get("a").unwrap().unwrap().expose(), "1");
        // Another process rewrites the file; the cached document must not be served
        store(dir.path(), "pw").set("a", &Secret::new("2")).unwrap();
        assert_eq!(first.get("a").unwrap().unwrap().expose(), "2");
    }

    #[test]
    fn delete_updates_and_missing_store_needs_no_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let none = FileStore::open(dir.path().to_path_buf(), Settings::default()).unwrap();
        assert!(none.get("a").unwrap().is_none());
        assert!(!none.delete("a").unwrap());
        let s = store(dir.path(), "pw");
        s.set("a", &Secret::new("1")).unwrap();
        s.set("b", &Secret::new("2")).unwrap();
        assert!(s.delete("a").unwrap());
        assert!(!s.delete("a").unwrap());
        let again = store(dir.path(), "pw");
        assert!(again.get("a").unwrap().is_none());
        assert_eq!(again.get("b").unwrap().unwrap().expose(), "2");
    }

    #[test]
    fn a_passphrase_is_required_without_a_terminal() {
        let dir = tempfile::tempdir().unwrap();
        store(dir.path(), "pw").set("a", &Secret::new("1")).unwrap();
        let none = FileStore::open(dir.path().to_path_buf(), Settings::default()).unwrap();
        // stdin is not a terminal under `cargo test`
        let message = format!("{}", none.get("a").err().unwrap());
        assert!(message.contains("needs a passphrase"));
    }

    #[test]
    fn the_passphrase_file_wins_and_loses_its_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pass");
        std::fs::write(&file, "from-file\n").unwrap();
        let path = file.display().to_string();
        let settings = Settings::from_vars(|name| match name {
            "NIX_VAULT_STORE_PASSPHRASE_FILE" => Some(path.clone()),
            "NIX_VAULT_STORE_PASSPHRASE" => Some("ignored".into()),
            "NIX_VAULT_STORE_WORK_FACTOR" => Some("10".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(settings.passphrase.as_deref(), Some("from-file"));
        let s = FileStore::open(dir.path().join("s"), settings).unwrap();
        s.set("a", &Secret::new("1")).unwrap();
        assert_eq!(
            store(&dir.path().join("s"), "from-file")
                .get("a")
                .unwrap()
                .unwrap()
                .expose(),
            "1"
        );
    }

    #[test]
    fn a_passphrase_file_that_is_missing_or_empty_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        for path in [dir.path().join("missing"), empty] {
            let path = path.display().to_string();
            let result = Settings::from_vars(|name| {
                (name == "NIX_VAULT_STORE_PASSPHRASE_FILE").then(|| path.clone())
            });
            assert!(result.is_err(), "{path}");
        }
    }

    #[test]
    fn the_work_factor_must_be_in_range() {
        let with = |value: &'static str| {
            Settings::from_vars(move |name| {
                (name == "NIX_VAULT_STORE_WORK_FACTOR").then(|| value.to_string())
            })
        };
        for bad in ["9", "23", "abc"] {
            assert!(with(bad).is_err(), "{bad}");
        }
        assert_eq!(with("12").unwrap().work_factor, Some(12));
    }
}
