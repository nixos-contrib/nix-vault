# Commands

```text
nix-vault login  --profile <name> [--force]     store credentials for one profile
nix-vault exec   -p <name> [-p <name>...] -- <command> [args...]
nix-vault logout --profile <name>               remove the stored credentials
nix-vault list                                  names, hosts, types, credentials, expiry
```

## login

Asks for a username and a hidden password (a personal access token works as the password) for
`basic` profiles, and runs the configured OAuth flow for `oauth2` profiles. Usable credentials are
reused and expiring OAuth credentials are refreshed; `--force` authenticates again and replaces
them only on success. Basic credentials are stored as typed: nix-vault does not check them with
the service. An `oauth2` profile with an `issuer` reads the provider's metadata here, see
[endpoint discovery](configuration.md#endpoint-discovery).

## exec

Needs at least one `--profile`: profiles are never selected implicitly. It refreshes expiring
OAuth tokens before launch and refuses to start the command if a profile has no usable credentials
(it prints the exact `nix-vault login` command). Distinct profiles that would present different
credentials for the same host are rejected. The command runs without a shell, with stdio attached
and its exit status or signal reproduced. How it changes your Nix setup is in
[delivery.md](delivery.md).

## logout

Removes the local credentials and keeps the configuration. Tokens are not revoked at the service.

## list

Shows names, hosts, types, whether credentials are stored and when they expire. It never shows a
secret and does not touch the network.

## Exit statuses

| Status | Meaning |
|--------|---------|
| `0` | success |
| `1` | operational failure |
| `2` | usage or configuration error |
| `126` / `127` | the command is not executable / not found |
| otherwise | the command's own status, or `128+n` when it was killed by signal `n` |
