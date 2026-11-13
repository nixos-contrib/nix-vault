mod app;
mod vault;

use std::{
    os::unix::process::ExitStatusExt,
    process::{ExitCode, ExitStatus},
};

use clap::Parser;
use time::OffsetDateTime;

use crate::{
    app::{args::*, exec::*},
    vault::{auth::basic::TerminalPrompt, config::Config, store::CredentialStore, *},
};

fn main() -> ExitCode {
    let program = Program::parse();

    // Process the correct command
    match run(program) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn run(program: Program) -> Result<ExitCode> {
    match program.command {
        ProgramCommand::Login(args) => {
            // The configuration is validated before the store is opened or anything is asked
            let config = Config::load(&args.parent.config)?;
            let store = CredentialStore::open()?;
            let mut command = LoginCommand {
                writer: Box::new(std::io::stdout()),
                config,
                store,
                prompt: Box::new(TerminalPrompt),
            };
            command.execute(&args)?
        }
        ProgramCommand::Exec(args) => {
            let config = Config::load(&args.parent.config)?;
            let store = CredentialStore::open()?;
            let store = std::sync::Arc::new(std::sync::Mutex::new(store));
            let mut command = ExecCommand { config, store };
            return Ok(exit_code(command.execute(&args)?));
        }
        ProgramCommand::Logout(args) => {
            let config = Config::load(&args.parent.config)?;
            let store = CredentialStore::open()?;
            let mut command = LogoutCommand {
                writer: Box::new(std::io::stdout()),
                config,
                store,
            };
            command.execute(&args)?
        }
        ProgramCommand::List(args) => {
            let config = Config::load(&args.parent.config)?;
            let store = CredentialStore::open()?;
            let mut command = ListCommand {
                writer: Box::new(std::io::stdout()),
                config,
                store,
                now: OffsetDateTime::now_utc(),
            };
            command.execute(&args)?
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Maps the exit status of the child process to our own, shell style. When the child died from
/// a signal, nix-vault dies from the same signal (the session was removed before this runs), so
/// the caller sees the same outcome; 128 + n is the fallback.
fn exit_code(status: ExitStatus) -> ExitCode {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitCode::from(code as u8),
        (None, Some(signal)) => {
            let _ = signal_hook::low_level::emulate_default_handler(signal);
            ExitCode::from(128 + signal as u8)
        }
        (None, None) => ExitCode::FAILURE,
    }
}
