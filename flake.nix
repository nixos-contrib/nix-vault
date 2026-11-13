{
  description = "nix-vault - authenticate Nix against private services and run commands with the credentials";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
        rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rust-toolchain;
          rustc = rust-toolchain;
        };
      in
      {
        packages.default = rustPlatform.buildRustPackage {
          pname = manifest.name;
          inherit (manifest) version;
          cargoLock.lockFile = ./Cargo.lock;
          src = pkgs.lib.cleanSource ./.;
          # The tests need a writable HOME, loopback networking and the nix binary; CI runs them
          # with `cargo test --features file-store` instead.
          doCheck = false;
          meta = with pkgs.lib; {
            inherit (manifest) description;
            inherit (manifest) homepage;
            license = licenses.mit;
            mainProgram = manifest.name;
          };
        };

        devShells.default = pkgs.mkShell {
          inherit (manifest) name;
          packages = [
            rust-toolchain
            pkgs.pkg-config
            pkgs.bashInteractive
            pkgs.zsh
          ];
        };
      }
    );
}
