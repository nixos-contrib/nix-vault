# nix-vault

[![CI](https://github.com/nixos-contrib/nix-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/nixos-contrib/nix-vault/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nixos-contrib/nix-vault)](https://github.com/nixos-contrib/nix-vault/releases/latest)
[![Rust](https://img.shields.io/badge/Rust-1.95-DEA584?logo=rust&logoColor=white)](rust-toolchain.toml)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux-lightgrey)](#install)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Authenticate Nix against private services without keeping credentials in `nix.conf` or netrc
files. nix-vault logs you in, keeps the credentials in your system keychain, and runs a command
with them available to Nix for that command only. It is inspired by
[aws-vault](https://github.com/99designs/aws-vault).

```bash
nix-vault login --profile cache                 # once
nix-vault exec -p company -p cache -- nix build # credentials exist only for this command
```

```text
 login ──► your keychain (once)
 exec  ──► session credentials ──► your command (nix build ...) ──► removed when it ends
```

## Pick your setup

| You want | Use | Read |
|----------|-----|------|
| A login to a private cache or forge, kept in your keychain | a `basic` or `oauth2` profile | [Configuration](docs/configuration.md) |
| A service behind Cloudflare Access, or one that needs custom headers | the local proxy delivery | [Cloudflare Access](docs/cloudflare-access.md) |
| A token that another tool prints (`cloudflared`, 1Password, a script) | a `process` profile | [Process profiles](docs/process-profiles.md) |
| CI, or a machine with no keychain | environment variables, or the encrypted file store | [CI](docs/ci.md) |

All the guides are in [docs/](docs/README.md).

## Install

```bash
nix run github:nixos-contrib/nix-vault -- --help     # or: nix profile install github:nixos-contrib/nix-vault
cargo binstall nix-vault                        # prebuilt binary from the GitHub release
cargo install nix-vault
```

Supported: macOS and Linux (including NixOS). On Linux the credentials go to the Secret Service
(for example gnome-keyring or KeePassXC), so one must be running in your session. nix-vault never
falls back to another store by itself: without a usable keychain, `login` fails.

A machine without a keychain, such as a headless box or a CI runner, can use environment variables
or an opt-in encrypted file store: see [CI](docs/ci.md).

## Configuration

Profiles live in `~/.config/nix-vault/config.toml` (or `$XDG_CONFIG_HOME/nix-vault/config.toml`,
or the file named by `--config` / `NIX_VAULT_CONFIG_FILE`). Each top-level table is a profile with
one `host` and one `type`: `basic`, `oauth2` or `process`.

```toml
[cache]
host = "cache.example.com"
type = "basic"

[company]
host = "gitlab.example.com"
type = "oauth2"

[company.oauth2]
client_id = "public-client-id"
flow = "device"                                   # or "authorization_code" (PKCE)
device_authorization_endpoint = "https://gitlab.example.com/oauth/authorize_device"
token_endpoint = "https://gitlab.example.com/oauth/token"
scopes = ["read_api"]
```

The file never holds usernames, passwords, access tokens or refresh tokens, and the whole file is
validated before any command runs. Every key and how credentials reach Nix are in
[Configuration](docs/configuration.md); a full example is [`config.example.toml`](config.example.toml).

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

How `exec` changes your Nix setup is in [docs/delivery.md](docs/delivery.md).

## Limitations

* **Client-side only.** Credentials reach Nix commands run by `exec`. Downloads performed by the
  **Nix daemon** (multi-user installs, NixOS), fetches inside **sandboxed builds** and **remote
  builders** are not covered in general.
* **Cleanup is best effort** after SIGKILL, a crash or power loss.

The full list is in [docs/limitations.md](docs/limitations.md).

## Development

```bash
nix develop                                   # pinned Rust toolchain
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test                                    # unit + CLI + integration tests
cargo test -- --ignored keyring_smoke         # real keychain round trip (manual)
```

Tests use fake credentials, a scripted mock OAuth provider on a loopback port, a fake `nix` put
first on `PATH` (the tests that need the real `nix` skip themselves when it is absent), and the
encrypted file store with a fake passphrase, so they exercise the same code users run.

## License

MIT, see [LICENSE](LICENSE).
