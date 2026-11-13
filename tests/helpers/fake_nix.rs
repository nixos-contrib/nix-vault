//! A stub `nix` that answers `config show --json` from a JSON file.

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub struct FakeNix {
    dir: PathBuf,
}

impl FakeNix {
    pub fn new(root: &Path) -> Self {
        let dir = root.join("fakenix");
        std::fs::create_dir(&dir).unwrap();
        let script = "#!/bin/sh\n\
            echo \"$@\" >> \"$FAKE_NIX_LOG\"\n\
            if [ \"$1 $2 $3\" = \"config show --json\" ]; then cat \"$FAKE_NIX_JSON\"; exit 0; fi\n\
            echo \"unexpected arguments: $*\" >&2\nexit 1\n";
        let binary = dir.join("nix");
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let nix = FakeNix { dir };
        nix.set(&[], None);
        nix
    }

    pub fn binary(&self) -> PathBuf {
        self.dir.join("nix")
    }

    pub fn json_path(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir.join("calls.log")
    }

    /// Sets what `nix config show --json` reports: existing access tokens and the netrc path.
    pub fn set(&self, tokens: &[(&str, &str)], netrc_file: Option<&Path>) {
        let tokens: Vec<String> = tokens
            .iter()
            .map(|(h, t)| format!("\"{h}\":\"{t}\""))
            .collect();
        let netrc = netrc_file
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| self.dir.join("no-such-netrc").display().to_string());
        let json = format!(
            "{{\"access-tokens\":{{\"value\":{{{}}}}},\"netrc-file\":{{\"value\":\"{netrc}\"}}}}",
            tokens.join(",")
        );
        std::fs::write(self.json_path(), json).unwrap();
    }
}
