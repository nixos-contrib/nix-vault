# Using nix-vault in CI

A CI runner has no keychain. There are two ways to run without one.

## Credentials from the environment

A CI runner has no keychain. A basic profile can read its username and password from environment
variables instead of a stored login, so the same profile file works locally and in CI:

```toml
[gitlab-ci]
host = "cache.example.com"
type = "basic"

[gitlab-ci.basic]
username_env = "NIX_CACHE_USERNAME"
password_env = "NIX_CACHE_TOKEN"
```

```yaml
build:
  variables:
    NIX_CACHE_USERNAME: "oauth2"          # the username your cache expects
  id_tokens:
    NIX_CACHE_TOKEN:
      aud: https://cache.example.com
  script:
    - nix-vault exec --profile gitlab-ci -- nix build
```

* **Names, not values.** The variable names are not secrets, so they may be in the file; a literal
  `username` or `password` is still refused. Both variables are required, and they must be
  different.
* **Read when `exec` starts.** A variable that is not set, or is empty, stops `exec` before the
  command is launched, with a message that names the variable (never its value).
* **Nothing is stored and no store is opened.** The credentials never touch disk except the
  session netrc (mode 0600), and neither the keychain nor the encrypted file store is opened for
  these profiles, so a runner without a keychain works.
* **Delivery is as for any basic profile**: netrc by default, or `use = ["proxy"]` with
  `{username}` and `{password}` in the headers.
* **`login`, `logout` and `list`.** `login` says the credentials come from the environment and does
  nothing, `logout` has nothing to remove, and `list` shows "environment" without reading the
  variables.
* **The variables stay in the command's environment.** They were put there by the CI job, and
  removing them would surprise a command that needs them too; nix-vault does not copy them anywhere
  else. Use a job-scoped variable, and a short-lived one where the CI offers it (GitLab's ID
  tokens, for example), so a leaked value is worth little.

## The encrypted file store

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
