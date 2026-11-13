//! Command line definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::vault::config;

const PROGRAM_HELP: &str = "Get started:
  nix-vault login -p cache                # store credentials for the `cache` profile
  nix-vault exec -p cache -- nix build    # run a command with them available to Nix
  nix-vault list                          # profiles and whether credentials are stored

Profiles live in ~/.config/nix-vault/config.toml (see config.example.toml).";
const LOGIN_EXAMPLES: &str = "Examples:
  nix-vault login --profile cache          # prompt for a username and password or token
  nix-vault login -p company               # run the profile's OAuth flow
  nix-vault login -p cache --force         # authenticate again and replace the credentials";
const EXEC_EXAMPLES: &str = "Examples:
  nix-vault exec --profile company -- nix flake update
  nix-vault exec -p company -p cache -- nix build
  nix-vault exec -p cache -- sh -c 'nix build && nix run'";
const LOGOUT_EXAMPLES: &str = "Examples:
  nix-vault logout --profile company       # remove the stored credentials (not revoked remotely)";
const LIST_EXAMPLES: &str = "Examples:
  nix-vault list                           # name, host, type, credentials and expiry";

/// Program is the main entry point for the nix-vault CLI.
#[derive(Debug, Parser)]
#[command(
    name = "nix-vault",
    about = "Authenticate Nix against private services.",
    long_about = "Store credentials for the services Nix needs in the system keychain, and run \
                  commands with them available to Nix, without keeping them in nix.conf or netrc \
                  files.",
    after_help = PROGRAM_HELP,
    version
)]
pub struct Program {
    /// Command specifies the subcommand to execute.
    #[command(subcommand)]
    pub command: ProgramCommand,
}

/// ProgramArgs holds the shared flags available to every subcommand.
#[derive(Debug, Args)]
pub struct ProgramArgs {
    /// Path to the nix-vault configuration file.
    #[arg(
        help = "Config file path.",
        env = "NIX_VAULT_CONFIG_FILE",
        default_value_os_t = config::config_path(None),
        long,
        value_name = "PATH"
    )]
    pub config: PathBuf,

    /// Path to the directory holding the per-profile lock files.
    #[arg(
        help = "State directory path.",
        env = "NIX_VAULT_STATE_DIR",
        default_value_os_t = config::state_dir(),
        long,
        value_name = "PATH"
    )]
    pub state_dir: PathBuf,
}

/// Top-level subcommand dispatched by [`Program`].
#[derive(Debug, Subcommand)]
pub enum ProgramCommand {
    /// Store credentials for a profile.
    #[command(
        name = "login",
        after_help = LOGIN_EXAMPLES,
        about = "Store credentials for a profile.",
        long_about = "Ask for a username and a hidden password (or personal access token) for a \
                      basic profile, or run the profile's OAuth flow. Usable credentials are \
                      reused and expiring OAuth credentials are refreshed; --force authenticates \
                      again and replaces them only on success. Basic credentials are stored as \
                      typed: they are not checked with the service.",
        next_display_order = 1
    )]
    Login(LoginCommandArgs),

    /// Run a command with the credentials of the selected profiles available to Nix.
    #[command(
        name = "exec",
        after_help = EXEC_EXAMPLES,
        about = "Run a command with the selected profiles' credentials available to Nix.",
        long_about = "Run any command, such as a shell or a script that invokes Nix, with the \
                      credentials of one or more profiles available to Nix for that command \
                      only. Expiring OAuth tokens are refreshed first; the command is not started \
                      when a profile has no usable credentials. nix.conf and your netrc are \
                      never modified.",
        next_display_order = 2
    )]
    Exec(ExecCommandArgs),

    /// Remove the stored credentials of a profile.
    #[command(
        name = "logout",
        after_help = LOGOUT_EXAMPLES,
        about = "Remove the stored credentials of a profile.",
        long_about = "Delete the locally stored credentials of a profile and keep its \
                      configuration. Tokens are not revoked at the service.",
        next_display_order = 3
    )]
    Logout(LogoutCommandArgs),

    /// Show profiles and whether credentials are stored.
    #[command(
        name = "list",
        after_help = LIST_EXAMPLES,
        about = "Show profiles and whether credentials are stored.",
        long_about = "Show each profile's name, host, authentication type, whether credentials \
                      are stored and their expiry when known. Secrets are never shown.",
        next_display_order = 4
    )]
    List(ListCommandArgs),
}

/// Arguments of `login`.
#[derive(Debug, Args)]
pub struct LoginCommandArgs {
    /// Shared flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile to log in to
    #[arg(short = 'p', long, value_name = "NAME")]
    pub profile: String,

    /// Authenticate again and replace the stored credentials
    #[arg(long)]
    pub force: bool,
}

/// Arguments of `exec`.
#[derive(Debug, Args)]
pub struct ExecCommandArgs {
    /// Shared flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile to use (repeatable; at least one is required)
    #[arg(short = 'p', long = "profile", value_name = "NAME")]
    pub profiles: Vec<String>,

    /// Command and arguments, after `--`
    #[arg(last = true, num_args = 1.., value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// Arguments of `logout`.
#[derive(Debug, Args)]
pub struct LogoutCommandArgs {
    /// Shared flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile to log out of
    #[arg(short = 'p', long, value_name = "NAME")]
    pub profile: String,
}

/// Arguments of `list`.
#[derive(Debug, Args)]
pub struct ListCommandArgs {
    /// Shared flags.
    #[command(flatten)]
    pub parent: ProgramArgs,
}
