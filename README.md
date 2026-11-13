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

## Install

```bash
nix run github:nixos-contrib/nix-vault -- --help     # or: nix profile install github:nixos-contrib/nix-vault
cargo binstall nix-vault                        # prebuilt binary from the GitHub release
cargo install nix-vault
```

Supported: macOS and Linux (including NixOS). On Linux the credentials go to the Secret Service
(for example gnome-keyring or KeePassXC), so one must be running in your session. nix-vault never
falls back to another store by itself: without a usable keychain, `login` fails.

### Without a keychain: the encrypted file store

On a machine with no keychain (a headless box, a minimal container) you can opt in to an
encrypted file store. Nothing is ever written in the clear: all profiles live in one file
encrypted with a passphrase ([age](https://age-encryption.org), scrypt).

| Variable | Meaning |
|----------|---------|
| `NIX_VAULT_STORE` | `keychain` (default) or `file`. Never chosen automatically. |
| `NIX_VAULT_STORE_DIR` | where the file lives; default `$XDG_DATA_HOME/nix-vault/credentials` (`~/.local/share/nix-vault/credentials`). The directory is created with mode 0700 and the file is 0600. |
| `NIX_VAULT_STORE_PASSPHRASE_FILE` | path of a file whose content is the passphrase (preferred for scripts). |
| `NIX_VAULT_STORE_PASSPHRASE` | the passphrase itself. It protects against casual reads of the file, not against anyone who can read your process environment. |
| `NIX_VAULT_STORE_WORK_FACTOR` | scrypt work factor, 10 to 22 (default 18). Lowering it weakens the protection; the test suite uses it to stay fast. |

The passphrase is taken from the file, then the variable, then a hidden prompt when stdin is a
terminal (twice when the store is created); with none of those the command fails. A wrong
passphrase or a damaged file is an error and nothing is overwritten. The store needs the same
passphrase for every profile, and a lost passphrase cannot be recovered: log in again.

```bash
export NIX_VAULT_STORE=file
nix-vault login --profile cache     # asks for a new passphrase the first time
nix-vault exec -p cache -- nix build
```

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

[company.oauth2]
client_id = "public-client-id"
flow = "device"                                   # or "authorization_code" (PKCE)
device_authorization_endpoint = "https://gitlab.example.com/oauth/authorize_device"
token_endpoint = "https://gitlab.example.com/oauth/token"
scopes = ["read_api"]
```

The file never holds usernames, passwords, access tokens or refresh tokens, and the whole file is
validated before any command runs (a sub-table that does not match the profile's `type` is
rejected); errors name the profile and the key. There are no profile
groups, inheritance or reusable sources.

### How credentials reach Nix

| `[<profile>.nix]` | Meaning |
|-------------------|---------|
| absent | oauth2 profiles use a Nix **access token**; basic profiles use **netrc** |
| `use = [...]` | the mechanisms, a non-empty list of `"access-token"`, `"netrc"` and/or `"proxy"`. `"access-token"` presents the credential as an `access-tokens` entry (a basic profile used this way must hold a personal access token as its password). `"netrc"` presents it through netrc: basic profiles use the username given at login, oauth2 profiles use `oauth2`. `"proxy"` (not combined with the others) sends the credential through a local reverse proxy, see [Services behind Cloudflare Access](#services-behind-cloudflare-access). |
| `access_token_prefix` | only with `"access-token"`: `none` (`host=<token>`: github.com, Gitea, Forgejo) or `by_type` (`host=OAuth2:<token>`, or `host=PAT:<token>` for basic profiles: GitLab). Default: `none` for the host `github.com`, otherwise `by_type`. |

List both mechanisms to present one profile both ways. Keys use `snake_case`; values are spelled as the external system spells them (`authorization_code` as in OAuth, `access-token` and `netrc` as in Nix). Access tokens are used by Nix's own forge
fetchers (flake inputs and `nix flake update`); netrc covers HTTP downloads and binary caches.

### Services behind Cloudflare Access

Nix can only send an `Authorization` header from netrc: it cannot send the headers Cloudflare
Access wants for a service token. `use = ["proxy"]` covers that:

```toml
[cache]
host = "nix.example.com"
type = "basic"        # login stores the service token: client ID as username, secret as password

[cache.nix]
use = ["proxy"]

[cache.proxy]
headers = { CF-Access-Client-Id = "{username}", CF-Access-Client-Secret = "{password}" }
```

`exec` starts a small reverse proxy on `127.0.0.1` for the length of the command. It forwards each
request over HTTPS to the profile's host, adds the headers of `[<profile>.proxy]`, and streams the bodies, so a large upload or download is never held in memory. The session `nix.conf`
sets `substituters`: the entries for that host now point at the proxy (path and query kept), and the
host is added when you do not list it. Your other substituters are kept.

* **The headers.** `headers` is required with `use = ["proxy"]`. Names are spelled as HTTP spells
  them; values are text in which the placeholders stand for the stored credential, so nothing
  secret is written in the file: `{username}` and `{password}` for basic profiles, `{access_token}`
  for oauth2 profiles. At least one header must use one. The headers that frame a message (`Host`,
  `Content-Length`, ...) cannot be set. A header the client sends with the same name is replaced,
  so `Authorization = "Bearer {access_token}"` works even though Nix itself can only send Basic.
* **The address.** The local URL has a random path prefix, and anything outside it gets a 404, so
  another user on the machine cannot borrow the credentials. It is passed to the command in
  `NIX_VAULT_PROXY_<PROFILE>` (the profile name in capitals), for a command that names the service
  itself: `nix-vault exec -p cache -- nix copy --to "$NIX_VAULT_PROXY_CACHE" ./result`.
* **Permission.** Nix only honors a `substituters` setting from a session if you are allowed to use
  it: a trusted user (`trusted-users`), or the address permitted by `trusted-substituters`.
* **Two ways to get the credential.** A basic profile holds a service token. An oauth2 profile logs
  in through the provider (for Cloudflare, an Access SaaS OIDC application: authorization code with
  PKCE, `redirect_port` set to a registered redirect URL) and the proxy sends the access token as
  configured:

  ```toml
  [cache]
  host = "nix.example.com"
  type = "oauth2"

  [cache.oauth2]
  client_id = "<the application's client ID>"
  flow = "authorization_code"
  authorization_endpoint = "https://<team>.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<client ID>/authorization"
  token_endpoint = "https://<team>.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<client ID>/token"
  scopes = ["openid", "email", "offline_access"]   # offline_access: a refresh token, so the proxy can renew the access token
  redirect_port = 8251

  [cache.nix]
  use = ["proxy"]

  [cache.proxy]
  headers = { Authorization = "Bearer {access_token}" }
  ```
* **Renewal during the run.** The proxy asks for its headers on every request. For an oauth2
  profile it renews the access token when it is within two minutes of its end, exchanging the
  refresh token (and saving a rotated one), so a command that runs longer than the token lives
  keeps working. This needs a refresh token: with Cloudflare Access add `offline_access` to `scopes`
  (the dashboard does not list it, but the API accepts it when the application has a refresh token
  lifetime). Concurrent requests share one renewal. When the token cannot be renewed (the refresh
  token expired or was revoked, or there never was one) the proxy does not forward the request: it
  answers `401` with a message that names the profile and says to run `nix-vault login`. A
  service token (basic profile) does not expire during a run, so its headers never change. Headers
  the client sends that the proxy does not replace are passed on untouched.

### Credentials from a command

A `process` profile gets its credential from a helper command, in the manner of AWS's
`credential_process`. Nothing is stored by nix-vault: `exec` runs the command each time, so the tool
that owns the login stays in charge of it.

```toml
[team-cache]
host = "nix.example.com"
type = "process"

[team-cache.process]
command = ["cloudflared", "access", "token", "https://nix.example.com"]
command_output_format = "text"      # the default

[team-cache.proxy]
headers = { cf-access-token = "{access_token}" }
```

* **The command** is an array: the program and its arguments, run without a shell. Its stderr and
  stdin are your terminal's, so it can say what to do (`cloudflared` says to run its login) and can
  prompt. It has 60 seconds and may print up to 64 KiB.
* **`command_output_format`** is `text` (default): the output, trimmed, must be one token, which is
  `{access_token}`; if it is a JWT, its `exp` is the expiry. Or `json`: `{"access_token": "...",
  "expires_at": "..."}`, or `username` and `password`, with `expires_at` optional.
* **Delivery** is the proxy, implied for this type, so `[<profile>.proxy]` is required and
  `[<profile>.nix]` may be left out (or `use = ["proxy"]`). `{username}` and `{password}` are
  available with `json`.
* **When it fails** (a non-zero exit, a timeout, an expired token, output that is not a token),
  `exec` stops before launching the command. The helper's own messages are above the error, which
  names the profile and the command and never shows the output.
* **While the command runs.** The proxy asks for its headers on every request. When the token the
  helper printed is within two minutes of its end, the helper is run again (without a terminal
  input, so it cannot take what you type for the command). If that fails the token that is still
  good keeps being used, and the helper is tried again after ten seconds; once the token has
  expired the request is not forwarded: the proxy answers `401` with a message that names the
  profile. A token with no known expiry is kept for the whole command.
* **`login` and `logout`** have nothing to do for this type, and `list` does not run the command.
* **The config file is code.** Whoever can write it chooses what runs as you, so nix-vault refuses
  a configuration file that other users can write when it has a process profile
  (`chmod go-w <file>`).

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
names the file. The session directory is removed when the command ends. Credentials are never put in
arguments or the environment; with `proxy` the environment holds the local proxy's address, not the
credential.

## Limitations

* **Client-side only.** Credentials reach Nix commands run by `exec`: flake input fetches,
  `nix flake update`, and downloads done in that client process. Downloads performed by the **Nix
  daemon** (multi-user installs, NixOS) use the daemon's configuration and may not see session
  credentials. On a trusted-user setup a client-supplied `netrc-file` was observed to reach daemon
  substitution on macOS (Determinate Nix), but this is not guaranteed and was not verified for
  untrusted users or on NixOS. Fetches inside **sandboxed builds** and **remote builders** are not
  covered.
* **No renewal while the command runs.** OAuth tokens are refreshed only before launch (when
  expiry is known). A long command, such as a big `nix copy` or build, may outlive its token and
  then fail with the service's own authorization error; nix-vault does not rerun it. Run it again
  (the next `exec` refreshes first), or use a longer-lived token: a `basic` profile can hold a
  personal access token. Nix reads `access-tokens` once at startup, so those cannot be renewed in
  a running process. It re-reads the netrc file on every request (observed for client-side
  fetches), so renewal during a run would be possible for netrc delivery; nix-vault does not do it.
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
* `redirect_port` (authorization code flow only) fixes the loopback port of the browser redirect, for
  providers that only accept pre-registered redirect URLs; register
  `http://127.0.0.1:<port>/callback` there. By default a random free port is used.
* Not provided: a general secrets manager, shell export/eval integration, printing secrets,
  external credential providers, a background daemon, custom encrypted storage, remote token
  revocation, `completions`.

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
