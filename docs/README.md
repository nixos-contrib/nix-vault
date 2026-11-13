# nix-vault documentation

Which setup is yours?

```mermaid
flowchart TD
    A([Where does the credential come from?]) --> B{CI, with no keychain?}
    B -- yes --> C[Environment variables or the encrypted file store<br/>ci.md]
    B -- no --> D{Another tool prints it?<br/>cloudflared, 1Password, a script}
    D -- yes --> E[A process profile<br/>process-profiles.md]
    D -- no --> F{Behind Cloudflare Access,<br/>or needs custom headers?}
    F -- yes --> G[The proxy delivery<br/>cloudflare-access.md]
    F -- no --> H[A basic or oauth2 profile with netrc or access-token<br/>configuration.md]
```

| Page | What is in it |
|------|---------------|
| [configuration.md](configuration.md) | The config file, profile types and how credentials reach Nix |
| [delivery.md](delivery.md) | What `exec` does to your Nix setup |
| [cloudflare-access.md](cloudflare-access.md) | The reverse proxy: service tokens, OIDC with renewal, custom headers |
| [process-profiles.md](process-profiles.md) | A helper command prints the credential (for example `cloudflared`) |
| [ci.md](ci.md) | Environment variables and the encrypted file store, for runners without a keychain |
| [limitations.md](limitations.md) | What nix-vault does not do, and what is best effort |
