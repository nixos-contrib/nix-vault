//! The per-execution session: a private directory with the Nix configuration and netrc files
//! that carry the selected credentials, removed when the command ends.

use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::{
    app,
    vault::{
        auth::redact::Secret,
        nix::{netrc, NixEffectiveConfig},
        Error, Result,
    },
};

/// What a session has to provide to Nix.
pub struct Plan {
    /// Selected access tokens: host and rendered value.
    pub access_tokens: Vec<(String, Secret)>,
    /// Selected netrc entries.
    pub netrc: Vec<netrc::Entry>,
    /// The complete `substituters` list to set, when proxied profiles change it.
    pub substituters: Option<Vec<String>>,
}

/// A private session directory. It is removed on `cleanup()` and on drop.
pub struct Session {
    dir: Option<tempfile::TempDir>,
    path: PathBuf,
}

/// Returns the directory under which per-user session directories live: `$XDG_RUNTIME_DIR`
/// when it exists and belongs to the user (Linux), else `$TMPDIR`, else `/tmp`.
pub fn base_dir() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        if let Ok(meta) = std::fs::metadata(&dir) {
            if meta.is_dir() && meta.uid() == uid {
                return dir;
            }
        }
    }
    std::env::var_os("TMPDIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Creates (or verifies) the per-user directory `<base>/nix-vault-<uid>` with mode 0700.
fn user_dir(base: &Path) -> Result<PathBuf> {
    let uid = unsafe { libc::geteuid() };
    let dir = base.join(format!("nix-vault-{uid}"));
    match DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::io("cannot create the session directory", e)),
    }
    let meta = std::fs::symlink_metadata(&dir)
        .map_err(|e| Error::io("cannot inspect the session directory", e))?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(Error::Io(format!(
            "{} must be a directory owned by you with mode 0700; refusing to use it",
            dir.display()
        )));
    }
    Ok(dir)
}

impl Session {
    /// Creates an empty session directory under `base`.
    pub fn create_in(base: &Path) -> Result<Session> {
        let parent = user_dir(base)?;
        let dir = tempfile::Builder::new()
            .prefix("session-")
            .tempdir_in(&parent)
            .map_err(|e| Error::io("cannot create the session directory", e))?;
        let path = dir.path().to_path_buf();
        // The parent is already 0700; make the session directory itself owner-only as well
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io("cannot restrict the session directory", e))?;
        Ok(Session {
            dir: Some(dir),
            path,
        })
    }

    /// Returns the session directory.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes `contents` to a new owner-only file called `name` and returns its path.
    pub fn write_file(&self, name: &str, contents: &[u8]) -> Result<PathBuf> {
        let path = self.path.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| Error::io("cannot create a session file", e))?;
        file.write_all(contents)
            .map_err(|e| Error::io("cannot write a session file", e))?;
        Ok(path)
    }

    /// Removes the session directory, warning (with the path only) when that fails.
    pub fn cleanup(&mut self) {
        if let Some(dir) = self.dir.take() {
            let path = dir.path().to_path_buf();
            if dir.close().is_err() {
                app::warn(format!(
                    "could not remove the session directory {}; remove it manually",
                    path.display()
                ));
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Builds a session for `plan`: the user's netrc `existing_netrc` merged with the selected
/// entries, and a `nix.conf` that sets `access-tokens` (the user's tokens minus overridden
/// hosts plus the selected ones) and `netrc-file`. Returns the session and the `nix.conf` path.
pub fn build(
    base: &Path,
    plan: &Plan,
    nix: &NixEffectiveConfig,
    existing_netrc: &[u8],
) -> Result<(Session, PathBuf)> {
    let session = Session::create_in(base)?;
    let mut conf = String::new();

    if !plan.netrc.is_empty() {
        let contents = netrc::merged(existing_netrc, &plan.netrc)?;
        let path = session.write_file("netrc", &contents)?;
        conf.push_str(&format!("netrc-file = {}\n", path.display()));
    }

    if !plan.access_tokens.is_empty() {
        let overridden: Vec<&str> = plan.access_tokens.iter().map(|(h, _)| h.as_str()).collect();
        let mut entries: Vec<String> = nix
            .access_tokens
            .iter()
            .filter(|(host, _)| !overridden.contains(&host.as_str()))
            .map(|(host, token)| format!("{host}={}", token.expose()))
            .collect();
        entries.extend(
            plan.access_tokens
                .iter()
                .map(|(host, value)| format!("{host}={}", value.expose())),
        );
        conf.push_str(&format!("access-tokens = {}\n", entries.join(" ")));
    }

    if let Some(list) = &plan.substituters {
        conf.push_str(&format!("substituters = {}\n", list.join(" ")));
    }

    let conf_path = session.write_file("nix.conf", conf.as_bytes())?;
    Ok((session, conf_path))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn nix(tokens: &[(&str, &str)]) -> NixEffectiveConfig {
        NixEffectiveConfig {
            access_tokens: tokens
                .iter()
                .map(|(h, t)| (h.to_string(), Secret::new(*t)))
                .collect::<BTreeMap<_, _>>(),
            netrc_file: PathBuf::from("/none"),
            substituters: Vec::new(),
        }
    }

    #[test]
    fn directories_and_files_are_owner_only_and_removed() {
        let base = tempfile::tempdir().unwrap();
        let plan = Plan {
            access_tokens: vec![("same.example".into(), Secret::new("SESSION"))],
            netrc: vec![netrc::Entry {
                host: "cache.example".into(),
                login: "u".into(),
                password: Secret::new("p"),
            }],
            substituters: None,
        };
        let (mut session, conf) = build(
            base.path(),
            &plan,
            &nix(&[("old.example", "OLD"), ("same.example", "FILE")]),
            b"machine keep.example login a password b\n",
        )
        .unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(session.path()), 0o700);
        assert_eq!(mode(session.path().parent().unwrap()), 0o700);
        assert_eq!(mode(&conf), 0o600);
        assert_eq!(mode(&session.path().join("netrc")), 0o600);

        let text = std::fs::read_to_string(&conf).unwrap();
        assert!(text.contains("access-tokens = old.example=OLD same.example=SESSION"));
        assert!(!text.contains("FILE"));
        assert!(text.contains("netrc-file = "));
        let netrc = std::fs::read_to_string(session.path().join("netrc")).unwrap();
        assert!(netrc.contains("machine keep.example login a password b"));
        assert!(netrc.contains("machine cache.example login u password p"));

        let path = session.path().to_path_buf();
        session.cleanup();
        assert!(!path.exists());
    }

    #[test]
    fn drop_removes_the_directory() {
        let base = tempfile::tempdir().unwrap();
        let path = {
            let session = Session::create_in(base.path()).unwrap();
            session.path().to_path_buf()
        };
        assert!(!path.exists());
    }

    #[test]
    fn concurrent_sessions_use_different_directories() {
        let base = tempfile::tempdir().unwrap();
        let a = Session::create_in(base.path()).unwrap();
        let b = Session::create_in(base.path()).unwrap();
        assert_ne!(a.path(), b.path());
    }

    #[test]
    fn a_user_directory_with_wrong_mode_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        let dir = base.path().join(format!("nix-vault-{uid}"));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Session::create_in(base.path()).is_err());
    }

    #[test]
    fn no_access_tokens_means_no_access_tokens_line() {
        let base = tempfile::tempdir().unwrap();
        let plan = Plan {
            access_tokens: vec![],
            netrc: vec![netrc::Entry {
                host: "h".into(),
                login: "u".into(),
                password: Secret::new("p"),
            }],
            substituters: None,
        };
        let (_s, conf) = build(base.path(), &plan, &nix(&[("x", "y")]), b"").unwrap();
        assert!(!std::fs::read_to_string(conf)
            .unwrap()
            .contains("access-tokens"));
    }
}
