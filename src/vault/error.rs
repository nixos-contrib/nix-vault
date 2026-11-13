//! The error type and its mapping to process exit statuses.
//!
//! Messages name profiles, hosts and paths only; they never contain credential values.

use std::fmt;

/// Result type used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can make a command fail.
#[derive(Debug)]
pub enum Error {
    /// The configuration file is missing, unreadable or invalid.
    Config(String),
    /// The command line was used incorrectly.
    Usage(String),
    /// The platform credential store cannot be used.
    StoreUnavailable(String),
    /// A selected profile has no usable credentials.
    NoCredentials {
        /// Profile that needs a login.
        profile: String,
        /// Why the stored credentials cannot be used, when more specific than "none".
        detail: Option<String>,
    },
    /// Authentication with the service failed or was cancelled.
    Auth(String),
    /// Refreshing stored credentials failed.
    Refresh {
        /// Profile whose credentials could not be refreshed.
        profile: String,
        /// Short, secret-free reason.
        detail: String,
    },
    /// The `nix` command could not be run or understood.
    NixUnavailable(String),
    /// The child command could not be started.
    Spawn {
        /// The command as typed.
        command: String,
        /// True when the command exists but cannot be executed.
        not_executable: bool,
    },
    /// Any other input/output failure.
    Io(String),
}

impl Error {
    /// Builds a configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Error::Config(message.into())
    }

    /// Builds a usage error.
    pub fn usage(message: impl Into<String>) -> Self {
        Error::Usage(message.into())
    }

    /// Builds an input/output error.
    pub fn io(context: &str, source: impl fmt::Display) -> Self {
        Error::Io(format!("{context}: {source}"))
    }

    /// Returns the exit status documented in contracts/cli.md.
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Config(_) | Error::Usage(_) => 2,
            Error::Spawn {
                not_executable: true,
                ..
            } => 126,
            Error::Spawn { .. } => 127,
            _ => 1,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) | Error::Usage(m) | Error::Io(m) => write!(f, "{m}"),
            Error::StoreUnavailable(m) => write!(f, "credential store unavailable: {m}"),
            Error::NoCredentials { profile, detail } => {
                write!(f, "profile \"{profile}\" has no usable credentials")?;
                if let Some(detail) = detail {
                    write!(f, " ({detail})")?;
                }
                write!(f, "; run: nix-vault login --profile {profile}")
            }
            Error::Auth(m) => write!(f, "authentication failed: {m}"),
            Error::Refresh { profile, detail } => write!(
                f,
                "could not refresh credentials for profile \"{profile}\" ({detail}); \
                 run: nix-vault login --profile {profile}"
            ),
            Error::NixUnavailable(m) => write!(f, "cannot read the Nix configuration: {m}"),
            Error::Spawn {
                command,
                not_executable,
            } => {
                if *not_executable {
                    write!(f, "cannot execute \"{command}\": permission denied")
                } else {
                    write!(f, "command not found: \"{command}\"")
                }
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_the_contract() {
        assert_eq!(Error::config("x").exit_code(), 2);
        assert_eq!(Error::usage("x").exit_code(), 2);
        assert_eq!(Error::StoreUnavailable("x".into()).exit_code(), 1);
        assert_eq!(
            Error::NoCredentials {
                profile: "p".into(),
                detail: None
            }
            .exit_code(),
            1
        );
        assert_eq!(Error::Auth("x".into()).exit_code(), 1);
        assert_eq!(
            Error::Refresh {
                profile: "p".into(),
                detail: "x".into()
            }
            .exit_code(),
            1
        );
        assert_eq!(Error::NixUnavailable("x".into()).exit_code(), 1);
        assert_eq!(Error::Io("x".into()).exit_code(), 1);
        assert_eq!(
            Error::Spawn {
                command: "c".into(),
                not_executable: false
            }
            .exit_code(),
            127
        );
        assert_eq!(
            Error::Spawn {
                command: "c".into(),
                not_executable: true
            }
            .exit_code(),
            126
        );
    }

    #[test]
    fn missing_credentials_names_the_login_command() {
        let message = Error::NoCredentials {
            profile: "cache".into(),
            detail: None,
        }
        .to_string();
        assert_eq!(
            message,
            "profile \"cache\" has no usable credentials; run: nix-vault login --profile cache"
        );
    }
}
