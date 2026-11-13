//! Shared helpers for the integration tests. Everything uses fake credentials and local files.

#![allow(dead_code)]

pub mod fake_nix;
pub mod oauth;

use std::{
    path::{Path, PathBuf},
    process::Command as StdCommand,
};

use assert_cmd::Command;
use sha2::{Digest, Sha256};

pub use fake_nix::FakeNix;

/// Distinctive fake secrets that must never leak.
pub const FAKE_USER: &str = "fakeuser_7f3a";
pub const FAKE_PASSWORD: &str = "FAKE_PASSWORD_7f3a";
pub const FAKE_TOKEN: &str = "FAKE_TOKEN_91bc";
pub const FAKE_REFRESH: &str = "FAKE_REFRESH_44de";

/// Path of the binary under test.
pub fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nix-vault"))
}

/// A temporary home with a configuration file, file store, state and temp directories.
pub struct Workspace {
    pub dir: tempfile::TempDir,
    pub nix: FakeNix,
}

impl Workspace {
    pub fn new(config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), config).unwrap();
        for sub in ["store", "state", "tmp"] {
            std::fs::create_dir(dir.path().join(sub)).unwrap();
        }
        let nix = FakeNix::new(dir.path());
        Workspace { dir, nix }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn config_file(&self) -> PathBuf {
        self.path().join("config.toml")
    }

    pub fn store_dir(&self) -> PathBuf {
        self.path().join("store")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.path().join("tmp")
    }

    pub fn set_config(&self, config: &str) {
        std::fs::write(self.config_file(), config).unwrap();
    }

    /// Environment shared by every invocation.
    pub fn apply_env(&self, cmd: &mut StdCommand) {
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.path())
            .env("NIX_VAULT_CONFIG_FILE", self.config_file())
            .env("NIX_VAULT_STATE_DIR", self.path().join("state"))
            .env("NIX_VAULT_FILE_STORE_DIR", self.store_dir())
            .env("TMPDIR", self.tmp_dir())
            .env("NIX_VAULT_NIX", self.nix.binary())
            .env("FAKE_NIX_JSON", self.nix.json_path())
            .env("FAKE_NIX_LOG", self.nix.log_path());
    }

    /// A command for the binary under test.
    pub fn cmd(&self) -> Command {
        let mut std_cmd = StdCommand::new(binary());
        self.apply_env(&mut std_cmd);
        Command::from_std(std_cmd)
    }

    /// A `std` command with the same environment (for pty sessions).
    pub fn std_cmd(&self) -> StdCommand {
        let mut cmd = StdCommand::new(binary());
        self.apply_env(&mut cmd);
        cmd
    }

    /// Writes a stored basic credential for `profile` as nix-vault would (see data-model.md).
    pub fn seed_basic(&self, profile: &str, identity: &str, user: &str, password: &str) {
        let json = format!(
            r#"{{"schema":1,"identity":"{identity}","saved_at":"2026-01-01T00:00:00Z",
                "basic":{{"username":"{user}","password":"{password}"}}}}"#
        );
        std::fs::write(self.store_dir().join(format!("{profile}.json")), json).unwrap();
    }

    /// Writes a stored oauth2 credential. `expires_at` is RFC 3339 or `None`.
    pub fn seed_oauth(
        &self,
        profile: &str,
        identity: &str,
        access: &str,
        refresh: Option<&str>,
        expires_at: Option<&str>,
    ) {
        let refresh = refresh
            .map(|r| format!(r#","refresh_token":"{r}""#))
            .unwrap_or_default();
        let expires = expires_at
            .map(|e| format!(r#","expires_at":"{e}""#))
            .unwrap_or_default();
        let json = format!(
            r#"{{"schema":1,"identity":"{identity}","saved_at":"2026-01-01T00:00:00Z",
                "oauth2":{{"access_token":"{access}"{refresh},"token_type":"bearer"{expires}}}}}"#
        );
        std::fs::write(self.store_dir().join(format!("{profile}.json")), json).unwrap();
    }

    pub fn stored(&self, profile: &str) -> Option<String> {
        std::fs::read_to_string(self.store_dir().join(format!("{profile}.json"))).ok()
    }

    /// Every file under the workspace (excluding the file store, which legitimately holds the
    /// fake credentials), concatenated, for leak checks.
    pub fn all_text_outside_store(&self) -> String {
        let mut out = String::new();
        let store = self.store_dir();
        let mut stack = vec![self.path().to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path == store {
                    continue;
                }
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(text) = std::fs::read_to_string(&path) {
                    out.push_str(&text);
                }
            }
        }
        out
    }
}

/// Computes a profile identity exactly like the binary does (type, host and, for oauth2, the
/// client id), so tests can seed credentials.
pub fn identity(kind: &str, host: &str, client_id: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nix-vault-identity-v1\0");
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(host.as_bytes());
    if let Some(client) = client_id {
        hasher.update(b"\0");
        hasher.update(client.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Fails when any of `secrets` appears in `text`.
pub fn assert_no_secrets(text: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(
            !text.contains(secret),
            "secret {secret:?} leaked into: {text}"
        );
    }
}

/// A basic profile named `cache` and an oauth2 profile named `company`.
pub const CONFIG: &str = r#"
[cache]
host = "cache.example.com"
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
"#;

pub fn cache_identity() -> String {
    identity("basic", "cache.example.com", None)
}

pub fn company_identity() -> String {
    identity("oauth2", "gitlab.example.com", Some("public-client-id"))
}

/// A shell snippet for a child command: prints the session `nix.conf` and netrc it was given.
pub const SHOW_SESSION: &str = r#"
conf=${NIX_CONFIG##*!include }
cat "$conf"
echo '--- netrc'
netrc=$(sed -n 's/^netrc-file = //p' "$conf")
if [ -n "$netrc" ]; then cat "$netrc"; fi
"#;

impl Workspace {
    /// Seeds the `cache` basic profile with the fake user and password.
    pub fn seed_cache(&self) {
        self.seed_basic("cache", &cache_identity(), FAKE_USER, FAKE_PASSWORD);
    }

    /// Names of the leftover session directories under the temp directory.
    pub fn leftover_sessions(&self) -> Vec<String> {
        let mut found = Vec::new();
        for user_dir in std::fs::read_dir(self.tmp_dir()).unwrap().flatten() {
            if user_dir
                .file_name()
                .to_string_lossy()
                .starts_with("nix-vault-")
            {
                for entry in std::fs::read_dir(user_dir.path()).unwrap().flatten() {
                    found.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
        found
    }
}
