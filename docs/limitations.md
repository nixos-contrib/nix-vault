# Limitations

* **Client-side only.** Credentials reach Nix commands run by `exec`: flake input fetches,
  `nix flake update`, and downloads done in that client process. Downloads performed by the **Nix
  daemon** (multi-user installs, NixOS) use the daemon's configuration and may not see session
  credentials. On a trusted-user setup a client-supplied `netrc-file` was observed to reach daemon
  substitution on macOS (Determinate Nix), but this is not guaranteed and was not verified for
  untrusted users or on NixOS. Fetches inside **sandboxed builds** and **remote builders** are not
  covered.
* **Renewal during the run needs the proxy.** With `use = ["proxy"]` the proxy renews an oauth2
  token and re-runs a process helper while the command runs. For `access-token` and `netrc`
  delivery, OAuth tokens are refreshed only before launch (when expiry is known), so a long command,
  such as a big `nix copy` or build, may outlive its token and then fail with the service's own
  authorization error; nix-vault does not rerun it. Run it again (the next `exec` refreshes first),
  or use a longer-lived token, or the proxy. Nix reads `access-tokens` once at startup, so those
  cannot be renewed in a running process. It re-reads the netrc file on every request (observed for
  client-side fetches), so renewal during a run would be possible for netrc delivery; nix-vault does
  not do it.
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
  external credential providers other than a process profile's helper command, a background daemon, custom encrypted storage, remote token
  revocation, `completions`.
