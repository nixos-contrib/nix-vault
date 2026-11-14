//! Integration tests: the real binary against fake credentials, a fake `nix` and mock services.

#[path = "helpers/mod.rs"]
mod helpers;

#[path = "integration"]
mod areas {
    pub mod config;
    pub mod discovery;
    pub mod env_credentials;
    pub mod exec_selection;
    pub mod exec_session;
    pub mod list;
    pub mod login;
    pub mod login_oauth;
    pub mod logout;
    pub mod nix_delivery;
    pub mod nix_gated;
    pub mod process;
    pub mod process_profiles;
    pub mod profile_changes;
    pub mod proxy;
    pub mod redaction;
    pub mod refresh;
    pub mod repo_and_cache;
}
