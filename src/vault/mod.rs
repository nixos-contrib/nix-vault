//! Domain layer: configuration, credential storage, authentication and Nix delivery.

pub mod auth;
pub mod config;
pub mod error;
pub mod nix;
pub mod store;

pub use error::{Error, Result};
