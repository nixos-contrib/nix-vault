# Configuration

Profiles live in `~/.config/nix-vault/config.toml` (or `$XDG_CONFIG_HOME/nix-vault/config.toml`,
or the file named by `--config` / `NIX_VAULT_CONFIG_FILE`). Each top-level table is a profile with
one `host` and one `type`, `basic` or `oauth2`. See [`config.example.toml`](../config.example.toml).

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

## How credentials reach Nix

| `[<profile>.nix]` | Meaning |
|-------------------|---------|
| absent | oauth2 profiles use a Nix **access token**; basic profiles use **netrc** |
| `use = [...]` | the mechanisms, a non-empty list of `"access-token"`, `"netrc"` and/or `"proxy"`. `"access-token"` presents the credential as an `access-tokens` entry (a basic profile used this way must hold a personal access token as its password). `"netrc"` presents it through netrc: basic profiles use the username given at login, oauth2 profiles use `oauth2`. `"proxy"` (not combined with the others) sends the credential through a local reverse proxy, see [Cloudflare Access and the proxy](cloudflare-access.md). |
| `access_token_prefix` | only with `"access-token"`: `none` (`host=<token>`: github.com, Gitea, Forgejo) or `by_type` (`host=OAuth2:<token>`, or `host=PAT:<token>` for basic profiles: GitLab). Default: `none` for the host `github.com`, otherwise `by_type`. |

List both mechanisms to present one profile both ways. Keys use `snake_case`; values are spelled as the external system spells them (`authorization_code` as in OAuth, `access-token` and `netrc` as in Nix). Access tokens are used by Nix's own forge
fetchers (flake inputs and `nix flake update`); netrc covers HTTP downloads and binary caches.
