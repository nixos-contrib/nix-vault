//! Authentication: credential state, login and refresh.

pub mod basic;
pub mod code;
pub mod device;
pub mod discovery;
pub mod env;
pub mod process;
pub mod redact;
pub mod token;

use time::{Duration, OffsetDateTime};

use std::path::Path;

use crate::vault::{
    auth::redact::Secret,
    config::{Flow, Kind, Profile},
    store::{locker::with_profile_lock, Credential, CredentialStore, OAuthCredential},
    Error, Result,
};
use basic::Prompt;
use token::TokenSet;

/// Credentials that expire within this margin are refreshed before launch.
pub const REFRESH_MARGIN: Duration = Duration::seconds(120);

/// What can be done with the credentials stored for a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialState {
    /// Nothing is stored.
    Absent,
    /// Stored for different settings (host or OAuth client changed).
    StaleIdentity,
    /// Can be used as they are.
    Usable,
    /// Expiring or expired, but a refresh token exists.
    Expiring,
    /// Expired and cannot be refreshed.
    Expired,
}

/// Computes the state of `stored` for `profile` at time `now` (see data-model.md).
pub fn state(
    profile: &Profile,
    stored: Option<&Credential>,
    now: OffsetDateTime,
) -> CredentialState {
    let Some(stored) = stored else {
        return CredentialState::Absent;
    };
    if stored.identity != profile.identity() {
        return CredentialState::StaleIdentity;
    }
    match (&profile.kind, &stored.basic, &stored.oauth2) {
        (Kind::Basic, Some(_), None) => CredentialState::Usable,
        (Kind::OAuth2(_), None, Some(oauth)) => match oauth.expires_at {
            None => CredentialState::Usable,
            Some(expires_at) if expires_at > now + REFRESH_MARGIN => CredentialState::Usable,
            Some(_) if oauth.refresh_token.is_some() => CredentialState::Expiring,
            Some(_) => CredentialState::Expired,
        },
        // Stored for another type: the identity should have caught this
        _ => CredentialState::StaleIdentity,
    }
}

/// How a login ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    /// Existing usable credentials were kept.
    Reused,
    /// Expiring credentials were refreshed.
    Refreshed,
    /// New credentials were stored.
    Stored,
}

/// Logs in to a basic profile: reuses usable credentials unless `force`, otherwise asks for a
/// username and a password or token and stores them. Nothing is sent to the service.
pub fn login_basic(
    profile: &Profile,
    store: &CredentialStore,
    force: bool,
    prompt: &dyn Prompt,
) -> Result<LoginOutcome> {
    if !matches!(profile.kind, Kind::Basic) {
        return Err(Error::usage(format!(
            "profile \"{}\" is not a basic profile",
            profile.name
        )));
    }
    let stored = store.load(&profile.name)?;
    if !force
        && state(profile, stored.as_ref(), OffsetDateTime::now_utc()) == CredentialState::Usable
    {
        return Ok(LoginOutcome::Reused);
    }
    let username = prompt.username()?;
    let password = prompt.password()?;
    // The old credential is replaced only after both prompts completed
    let credential = Credential::basic(profile.identity(), username, password);
    store.save(&profile.name, &credential)?;
    Ok(LoginOutcome::Stored)
}

/// Builds the credential to store from a token set. A refresh token the provider did not
/// rotate (`previous_refresh`) is kept.
pub fn credential_from_tokens(
    profile: &Profile,
    tokens: TokenSet,
    previous_refresh: Option<Secret>,
) -> Credential {
    let expires_at = tokens
        .expires_in
        .map(|lifetime| OffsetDateTime::now_utc() + Duration::seconds(lifetime.as_secs() as i64));
    Credential::oauth2(
        profile.identity(),
        OAuthCredential {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token.or(previous_refresh),
            token_type: "bearer".into(),
            expires_at,
            scope: tokens.scope,
        },
    )
}

/// Returns usable credentials for an oauth2 profile, refreshing them first when they expire
/// within the margin. Refreshing is serialized per profile, the stored entry is re-read under
/// the lock (another process may have refreshed already), and a rotated refresh token is saved
/// before the new access token is returned.
pub fn refresh_profile(
    profile: &Profile,
    store: &CredentialStore,
    state_dir: &Path,
) -> Result<Credential> {
    let Kind::OAuth2(oauth) = &profile.kind else {
        return Err(Error::usage(format!(
            "profile \"{}\" is not an oauth2 profile",
            profile.name
        )));
    };
    with_profile_lock(state_dir, &profile.name, || {
        let stored = store.load(&profile.name)?;
        let no_credentials = |detail: Option<&str>| Error::NoCredentials {
            profile: profile.name.clone(),
            detail: detail.map(str::to_string),
        };
        match state(profile, stored.as_ref(), OffsetDateTime::now_utc()) {
            CredentialState::Usable => Ok(stored.expect("usable")),
            CredentialState::Expiring => {
                let stored = stored.expect("expiring");
                let old = stored
                    .oauth2
                    .as_ref()
                    .and_then(|o| o.refresh_token.clone())
                    .ok_or_else(|| no_credentials(Some("expired and cannot be refreshed")))?;
                let tokens = token::refresh(oauth, &old).map_err(|detail| Error::Refresh {
                    profile: profile.name.clone(),
                    detail,
                })?;
                let credential = credential_from_tokens(profile, tokens, Some(old));
                store
                    .save(&profile.name, &credential)
                    .map_err(|_| Error::Refresh {
                        profile: profile.name.clone(),
                        detail: "the refreshed tokens could not be saved".into(),
                    })?;
                Ok(credential)
            }
            CredentialState::Absent => Err(no_credentials(None)),
            CredentialState::StaleIdentity => Err(no_credentials(Some(
                "its host or OAuth client changed since the last login",
            ))),
            CredentialState::Expired => {
                Err(no_credentials(Some("expired and cannot be refreshed")))
            }
        }
    })
}

/// Logs in to an oauth2 profile: reuses usable credentials unless `force`, refreshes expiring
/// ones, and otherwise runs the configured flow and stores the resulting tokens.
pub fn login_oauth(
    profile: &Profile,
    store: &CredentialStore,
    state_dir: &Path,
    force: bool,
) -> Result<LoginOutcome> {
    let Kind::OAuth2(oauth) = &profile.kind else {
        return Err(Error::usage(format!(
            "profile \"{}\" is not an oauth2 profile",
            profile.name
        )));
    };
    if !force {
        let stored = store.load(&profile.name)?;
        match state(profile, stored.as_ref(), OffsetDateTime::now_utc()) {
            CredentialState::Usable => return Ok(LoginOutcome::Reused),
            CredentialState::Expiring => match refresh_profile(profile, store, state_dir) {
                Ok(_) => return Ok(LoginOutcome::Refreshed),
                Err(e) => crate::app::note(format!("{e}; logging in again")),
            },
            _ => {}
        }
    }
    let tokens = match oauth.flow {
        Flow::Device => device::login(&profile.name, oauth)?,
        Flow::AuthorizationCode => code::login(&profile.name, oauth)?,
    };
    let credential = credential_from_tokens(profile, tokens, None);
    // The old credential is replaced only now, after the flow succeeded
    with_profile_lock(state_dir, &profile.name, || {
        store.save(&profile.name, &credential)
    })?;
    Ok(LoginOutcome::Stored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        auth::redact::Secret,
        config::Config,
        store::{Credential, OAuthCredential},
    };

    fn profiles() -> (Profile, Profile) {
        let config = Config::parse(
            "[b]\nhost=\"h.example\"\ntype=\"basic\"\n\
             [o]\nhost=\"g.example\"\ntype=\"oauth2\"\n[o.oauth2]\nclient_id=\"c\"\nflow=\"device\"\n\
             device_authorization_endpoint=\"https://g.example/d\"\n\
             token_endpoint=\"https://g.example/t\"\n",
        )
        .unwrap();
        (config.profiles[0].clone(), config.profiles[1].clone())
    }

    fn oauth(expires_in: Option<i64>, refresh: bool) -> OAuthCredential {
        OAuthCredential {
            access_token: Secret::new("at"),
            refresh_token: refresh.then(|| Secret::new("rt")),
            token_type: "bearer".into(),
            expires_at: expires_in.map(|s| OffsetDateTime::now_utc() + Duration::seconds(s)),
            scope: None,
        }
    }

    #[test]
    fn state_table() {
        let (basic, o) = profiles();
        let now = OffsetDateTime::now_utc();
        assert_eq!(state(&basic, None, now), CredentialState::Absent);

        let stored = Credential::basic(basic.identity(), Secret::new("u"), Secret::new("p"));
        assert_eq!(state(&basic, Some(&stored), now), CredentialState::Usable);
        let stale = Credential::basic("other".into(), Secret::new("u"), Secret::new("p"));
        assert_eq!(
            state(&basic, Some(&stale), now),
            CredentialState::StaleIdentity
        );

        let make = |expires, refresh| Credential::oauth2(o.identity(), oauth(expires, refresh));
        assert_eq!(
            state(&o, Some(&make(None, false)), now),
            CredentialState::Usable
        );
        assert_eq!(
            state(&o, Some(&make(Some(3600), false)), now),
            CredentialState::Usable
        );
        assert_eq!(
            state(&o, Some(&make(Some(60), true)), now),
            CredentialState::Expiring
        );
        assert_eq!(
            state(&o, Some(&make(Some(-5), true)), now),
            CredentialState::Expiring
        );
        assert_eq!(
            state(&o, Some(&make(Some(60), false)), now),
            CredentialState::Expired
        );
        assert_eq!(
            state(&o, Some(&make(Some(-5), false)), now),
            CredentialState::Expired
        );
    }
}
