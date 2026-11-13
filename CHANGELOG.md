# Changelog

## [0.4.0](https://github.com/nixos-contrib/nix-vault/compare/v0.3.0...v0.4.0) (2026-11-13)


### Features

* add a local reverse proxy delivery for services that need custom headers ([#13](https://github.com/nixos-contrib/nix-vault/issues/13)) ([9f5af67](https://github.com/nixos-contrib/nix-vault/commit/9f5af674ec19c83949a8890bb53854a93b97092c))
* add process profiles that get a credential from a helper command ([#15](https://github.com/nixos-contrib/nix-vault/issues/15)) ([f431faf](https://github.com/nixos-contrib/nix-vault/commit/f431faf22ffeed518d9cce7b74a5cab9aa7f2c38)), closes [#14](https://github.com/nixos-contrib/nix-vault/issues/14)
* let authorization code profiles fix the redirect port ([#10](https://github.com/nixos-contrib/nix-vault/issues/10)) ([f5931e2](https://github.com/nixos-contrib/nix-vault/commit/f5931e2c371501e83ef00b88447ebf25d9219e6d))
* read a basic profile's credentials from environment variables ([#18](https://github.com/nixos-contrib/nix-vault/issues/18)) ([d40eb6d](https://github.com/nixos-contrib/nix-vault/commit/d40eb6d832bc3a16f5625070ee155a9c30ab8702)), closes [#4](https://github.com/nixos-contrib/nix-vault/issues/4)
* renew an oauth2 token while a command runs through the proxy ([#16](https://github.com/nixos-contrib/nix-vault/issues/16)) ([75c0a53](https://github.com/nixos-contrib/nix-vault/commit/75c0a5394df228600ac867e2f919d8cbadbd7eb5)), closes [#5](https://github.com/nixos-contrib/nix-vault/issues/5)
* run a process profile's command again when its token nears its end ([#17](https://github.com/nixos-contrib/nix-vault/issues/17)) ([02c80e9](https://github.com/nixos-contrib/nix-vault/commit/02c80e90026b9ebb002a8c79af30552cefe07812)), closes [#14](https://github.com/nixos-contrib/nix-vault/issues/14)

## [0.3.0](https://github.com/nixos-contrib/nix-vault/compare/v0.2.0...v0.3.0) (2026-11-13)


### Features

* name the access token prefix choice access_token_prefix ([#8](https://github.com/nixos-contrib/nix-vault/issues/8)) ([df002a7](https://github.com/nixos-contrib/nix-vault/commit/df002a7b9bec33cf91b24b932512f7bc5e77378e))

## [0.2.0](https://github.com/nixos-contrib/nix-vault/compare/v0.1.0...v0.2.0) (2026-11-13)


### Features

* choose the Nix delivery in a [profile.nix] table ([efb1081](https://github.com/nixos-contrib/nix-vault/commit/efb10819ed3e1d001d727648cc79a1f46f3df250))
* name the access token style key access_token_style ([43c7b5d](https://github.com/nixos-contrib/nix-vault/commit/43c7b5d0509d7ffd3ce9414a96597bb78dba8c0d))

## 0.1.0 (2026-11-13)


### Features

* add an opt-in encrypted file store ([24aaca0](https://github.com/nixos-contrib/nix-vault/commit/24aaca0b0c8ae6fc1c95adce0b62336d1ad52cb5))
* add nix-vault CLI for authenticating Nix against private services ([ef12a2b](https://github.com/nixos-contrib/nix-vault/commit/ef12a2b13efd6d6b12f0db6c4245a58eed61b0a4))
* drop the netrc username setting ([b48c2b4](https://github.com/nixos-contrib/nix-vault/commit/b48c2b4b61bb75232443fbdf5eb8024b4e2727db))
* rename access-token styles to plain and typed ([0e02457](https://github.com/nixos-contrib/nix-vault/commit/0e0245721fa04cd8c2cc95b14eadb6d788912d24))


### Bug Fixes

* **nix:** ad-hoc sign the binary on macOS ([fd28df8](https://github.com/nixos-contrib/nix-vault/commit/fd28df8d3658496fc7994ad114b0b5b26be4a41f))

## Changelog

All notable changes are recorded here by release-please.
