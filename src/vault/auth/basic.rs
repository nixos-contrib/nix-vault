//! Interactive prompts for basic profiles.

use std::io::{BufRead, IsTerminal, Write};

use crate::vault::{auth::redact::Secret, Error, Result};

/// Asks the user for a username and a password or token.
pub trait Prompt {
    /// Asks for the username (echoed).
    fn username(&self) -> Result<Secret>;
    /// Asks for the password or personal access token (hidden).
    fn password(&self) -> Result<Secret>;
}

/// Prompts on the terminal.
pub struct TerminalPrompt;

fn need_terminal() -> Error {
    Error::Auth(
        "login needs an interactive terminal to ask for credentials; \
         run nix-vault login from a terminal"
            .into(),
    )
}

impl Prompt for TerminalPrompt {
    fn username(&self) -> Result<Secret> {
        if !std::io::stdin().is_terminal() {
            return Err(need_terminal());
        }
        eprint!("Username: ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line)?;
        if read == 0 {
            return Err(Error::Auth("login cancelled".into()));
        }
        Ok(Secret::new(line.trim_end_matches(['\r', '\n']).to_string()))
    }

    fn password(&self) -> Result<Secret> {
        if !std::io::stdin().is_terminal() {
            return Err(need_terminal());
        }
        let password = rpassword::prompt_password("Password or token: ")
            .map_err(|_| Error::Auth("login cancelled".into()))?;
        Ok(Secret::new(password))
    }
}
