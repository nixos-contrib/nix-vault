# nix-vault

Authenticate Nix against private services without keeping credentials in `nix.conf` or netrc
files. nix-vault logs you in, keeps the credentials in your system keychain, and runs a command
with them available to Nix for that command only. It is inspired by
[aws-vault](https://github.com/99designs/aws-vault).

```bash
nix-vault login --profile cache                 # once
nix-vault exec -p company -p cache -- nix build # credentials exist only for this command
```

## Install

```bash
nix run github:nixos-contrib/nix-vault -- --help     # or: nix profile install github:nixos-contrib/nix-vault
cargo binstall nix-vault                        # prebuilt binary from the GitHub release
cargo install nix-vault
```

Supported: macOS and Linux (including NixOS). On Linux the credentials go to the Secret Service
(for example gnome-keyring or KeePassXC), so one must be running in your session. nix-vault never
falls back to plaintext files: without a usable keychain, `login` fails.

## Configuration

Profiles live in `~/.config/nix-vault/config.toml` (or `$XDG_CONFIG_HOME/nix-vault/config.toml`,
or the file named by `--config` / `NIX_VAULT_CONFIG_FILE`). Each top-level table is a profile with
one `host` and one `type`, `basic` or `oauth2`. See [`config.example.toml`](config.example.toml).

```toml
[cache]
host = "cache.example.com"
type = "basic"

[company]
host = "gitlab.example.com"
type = "oauth2"
client_id = "public-client-id"
flow = "device"                                   # or "authorization_code" (PKCE)
device_authorization_endpoint = "https://gitlab.example.com/oauth/authorize_device"
token_endpoint = "https://gitlab.example.com/oauth/token"
scopes = ["read_api"]
```

The file never holds usernames, passwords, access tokens or refresh tokens, and the whole file is
validated before any command runs; errors name the profile and the key. There are no profile
groups, inheritance or reusable sources.

### How credentials reach Nix

| Sub-table | Meaning |
|-----------|---------|
| none | oauth2 profiles use a Nix **access token**; basic profiles use **netrc** |
| `[<profile>.access-token]` | present the credential as an `access-tokens` entry. Optional `style`: `github` (`host=<token>`) or `gitlab` (`host=OAuth2:<token>`, or `host=PAT:<token>` for basic profiles). Default: `github` for the host `github.com`, otherwise `gitlab`. A basic profile used this way must hold a personal access token as its password. |
| `[<profile>.netrc]` | present the credential through netrc. Optional `username` (oauth2 profiles only, default `oauth2`); basic profiles use the username given at login. |

Use both sub-tables to present one profile both ways. Access tokens are used by Nix's own forge
fetchers (flake inputs and `nix flake update`); netrc covers HTTP downloads and binary caches.

## Commands

```text
nix-vault login  --profile <name> [--force]     store credentials for one profile
nix-vault exec   -p <name> [-p <name>...] -- <command> [args...]
nix-vault logout --profile <name>               remove the stored credentials
nix-vault list                                  names, hosts, types, credentials, expiry
```

* **login** asks for a username and a hidden password (a personal access token works as the
  password) for basic profiles, and runs the configured OAuth flow for oauth2 profiles. Usable
  credentials are reused and expiring OAuth credentials are refreshed; `--force` authenticates
  again and replaces them only on success. Basic credentials are stored as typed: nix-vault does
  not check them with the service.
* **exec** needs at least one `--profile` (profiles are never selected implicitly), refreshes
  expiring OAuth tokens before launch, and refuses to start the command if a profile has no usable
  credentials (it prints the exact `nix-vault login` command). Distinct profiles that would
  present different credentials for the same host are rejected. The command runs without a shell,
  with stdio attached and its exit status or signal reproduced.
* **logout** removes the local credentials and keeps the configuration. Tokens are not revoked at
  the service.
* **list** never shows a secret.

Exit statuses: `0` success; `1` operational failure; `2` usage or configuration error; `126`/`127`
command not executable / not found; otherwise the command's own status (or `128+n`, re-raising
signal `n`).

### What `exec` does to your Nix setup

`exec` never edits `nix.conf` or your netrc. It reads your effective Nix settings
(`nix config show --json`), writes a session `nix.conf` and netrc in a private directory
(`<runtime dir>/nix-vault-<uid>/session-*`, mode 0700, files 0600), and extends the command's
`NIX_CONFIG` with one `!include` line. Your existing netrc entries and `access-tokens` are carried
over (the selected profile wins for a host both define, and a note names the host). If your
`netrc-file` exists but cannot be read, the command still runs without its entries and a warning
names the file. The session directory is removed when the command ends. Secrets are never put in
arguments or the environment.

## Limitations

* **Client-side only.** Credentials reach Nix commands run by `exec`: flake input fetches,
  `nix flake update`, and downloads done in that client process. Downloads performed by the **Nix
  daemon** (multi-user installs, NixOS) use the daemon's configuration and may not see session
  credentials. On a trusted-user setup a client-supplied `netrc-file` was observed to reach daemon
  substitution on macOS (Determinate Nix), but this is not guaranteed and was not verified for
  untrusted users or on NixOS. Fetches inside **sandboxed builds** and **remote builders** are not
  covered.
* **No renewal while the command runs.** OAuth tokens are refreshed only before launch (when
  expiry is known). A long command may outlive its token.
* **Cleanup is best effort.** The session is removed after normal exit, startup failure and
  handled signals (SIGINT, SIGTERM, SIGHUP). After SIGKILL, a crash or power loss the 0700
  directory with 0600 files can remain; nix-vault does not delete directories from earlier runs.
  On macOS session files live under `$TMPDIR` on disk; on Linux under `$XDG_RUNTIME_DIR` (tmpfs).
* **Copies of your own entries.** Session files hold copies of your existing netrc entries and
  access tokens as well as the selected credentials, owner-only and removed on exit.
* **Flags win.** Settings the command itself passes (`--option`, `--extra-...`) override the
  session settings.
* **Changing a profile.** Stored credentials are bound to the profile's type, host and OAuth client
  id. Changing those asks for a new login; changing scopes or endpoints does not, so run
  `login --force` after changing `scopes`.
* Not provided: a general secrets manager, shell export/eval integration, printing secrets,
  external credential providers, a background daemon, custom encrypted storage, remote token
  revocation, `completions`.

## Development

```bash
nix develop                                   # pinned Rust toolchain
cargo fmt --check && cargo clippy --all-targets --features file-store -- -D warnings
cargo test --features file-store              # unit + CLI + integration tests
cargo test -- --ignored keyring_smoke         # real keychain round trip (manual)
```

Tests use fake credentials, a scripted mock OAuth provider on a loopback port, and a fake `nix`
(the tests that need the real `nix` skip themselves when it is absent). The `file-store` feature
adds a file-backed credential store for those tests; release builds must never enable it.

## License

MIT, see [LICENSE](LICENSE).
