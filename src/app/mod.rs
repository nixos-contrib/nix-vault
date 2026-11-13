//! The command line -- [`args`], what it parses -- and what it runs -- [`exec`].

pub mod args;
pub mod exec;

/// Prints a warning on stderr.
pub fn warn(message: impl std::fmt::Display) {
    eprintln!("warning: {message}");
}

/// Prints a note on stderr.
pub fn note(message: impl std::fmt::Display) {
    eprintln!("note: {message}");
}
