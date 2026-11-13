# Credentials from a command

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
