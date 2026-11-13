//! Rendering of stored credentials as Nix access tokens and netrc entries.

use crate::vault::{
    auth::redact::Secret,
    config::{Kind, Prefix, Profile},
    nix::netrc::Entry,
    store::Credential,
    Error, Result,
};

fn mismatch(profile: &Profile) -> Error {
    Error::NoCredentials {
        profile: profile.name.clone(),
        detail: Some("the stored credentials do not match the profile type".into()),
    }
}

/// Returns the secret that is presented to the service: the password or the access token.
fn secret_of<'a>(profile: &Profile, credential: &'a Credential) -> Result<&'a Secret> {
    match (&profile.kind, &credential.basic, &credential.oauth2) {
        (Kind::Basic, Some(basic), None) => Ok(&basic.password),
        (Kind::OAuth2(_), None, Some(oauth)) => Ok(&oauth.access_token),
        _ => Err(mismatch(profile)),
    }
}

/// Returns the netrc entry for `profile`: the stored username and password for basic profiles,
/// and the fixed username `oauth2` with the access token for oauth2 profiles.
pub fn netrc_entry(profile: &Profile, credential: &Credential) -> Result<Entry> {
    let login = match (&profile.kind, &credential.basic) {
        (Kind::Basic, Some(basic)) => basic.username.expose().to_string(),
        (Kind::OAuth2(_), _) => "oauth2".to_string(),
        _ => return Err(mismatch(profile)),
    };
    Ok(Entry {
        host: profile.host.clone(),
        login,
        password: secret_of(profile, credential)?.clone(),
    })
}

/// Returns the `access-tokens` entry (`host`, `value`) for `profile` using its style:
/// `none` renders the bare token, `by_type` renders `OAuth2:<token>` (oauth2) or
/// `PAT:<token>` (basic).
pub fn access_token_entry(profile: &Profile, credential: &Credential) -> Result<(String, Secret)> {
    let token = secret_of(profile, credential)?.expose();
    if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::Auth(format!(
            "the credential of profile \"{}\" contains whitespace and cannot be used as a Nix \
             access token",
            profile.name
        )));
    }
    let rendered = match (profile.prefix(), &profile.kind) {
        (Prefix::Bare, _) => token.to_string(),
        (Prefix::ByType, Kind::OAuth2(_)) => format!("OAuth2:{token}"),
        (Prefix::ByType, Kind::Basic) => format!("PAT:{token}"),
    };
    Ok((profile.host.clone(), Secret::new(rendered)))
}

/// Returns a string that identifies the account behind a credential, used to tell whether two
/// profiles on the same host would present different credentials.
pub fn account_fingerprint(credential: &Credential) -> String {
    match (&credential.basic, &credential.oauth2) {
        (Some(basic), _) => format!(
            "basic\0{}\0{}",
            basic.username.expose(),
            basic.password.expose()
        ),
        (_, Some(oauth)) => format!("oauth2\0{}", oauth.access_token.expose()),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        config::Config,
        store::{Credential, OAuthCredential},
    };

    fn config(extra_basic: &str, extra_oauth: &str, host: &str) -> Config {
        Config::parse(&format!(
            "[b]\nhost=\"{host}\"\ntype=\"basic\"\n{extra_basic}\n\
             [o]\nhost=\"{host}\"\ntype=\"oauth2\"\n[o.oauth2]\nclient_id=\"c\"\nflow=\"device\"\n\
             device_authorization_endpoint=\"https://{host}/d\"\n\
             token_endpoint=\"https://{host}/t\"\n{extra_oauth}\n"
        ))
        .unwrap()
    }

    fn basic_cred(p: &Profile) -> Credential {
        Credential::basic(p.identity(), Secret::new("alice"), Secret::new("pat-1"))
    }

    fn oauth_cred(p: &Profile) -> Credential {
        Credential::oauth2(
            p.identity(),
            OAuthCredential {
                access_token: Secret::new("tok-1"),
                refresh_token: None,
                token_type: "bearer".into(),
                expires_at: None,
                scope: None,
            },
        )
    }

    #[test]
    fn by_type_prefix_depends_on_the_profile_type() {
        let c = config("", "", "gitlab.example.com");
        let (b, o) = (&c.profiles[0], &c.profiles[1]);
        assert_eq!(
            access_token_entry(b, &basic_cred(b)).unwrap().1.expose(),
            "PAT:pat-1"
        );
        assert_eq!(
            access_token_entry(o, &oauth_cred(o)).unwrap().1.expose(),
            "OAuth2:tok-1"
        );
    }

    #[test]
    fn none_is_the_bare_token_and_the_default_for_github_com() {
        let c = config("", "", "github.com");
        let (b, o) = (&c.profiles[0], &c.profiles[1]);
        assert_eq!(
            access_token_entry(b, &basic_cred(b)).unwrap().1.expose(),
            "pat-1"
        );
        assert_eq!(
            access_token_entry(o, &oauth_cred(o)).unwrap().1.expose(),
            "tok-1"
        );
        // An explicit style wins over the host default
        let c = config(
            "[b.nix]\nuse=[\"access-token\"]\naccess_token_prefix=\"by_type\"",
            "",
            "github.com",
        );
        let b = &c.profiles[0];
        assert_eq!(
            access_token_entry(b, &basic_cred(b)).unwrap().1.expose(),
            "PAT:pat-1"
        );
        let c = config(
            "[b.nix]\nuse=[\"access-token\"]\naccess_token_prefix=\"none\"",
            "",
            "gitlab.example.com",
        );
        let b = &c.profiles[0];
        assert_eq!(
            access_token_entry(b, &basic_cred(b)).unwrap().1.expose(),
            "pat-1"
        );
    }

    #[test]
    fn netrc_entries_use_the_right_login() {
        let c = config("", "[o.nix]\nuse=[\"netrc\"]", "h.example");
        let (b, o) = (&c.profiles[0], &c.profiles[1]);
        let e = netrc_entry(b, &basic_cred(b)).unwrap();
        assert_eq!((e.login.as_str(), e.password.expose()), ("alice", "pat-1"));
        let e = netrc_entry(o, &oauth_cred(o)).unwrap();
        assert_eq!((e.login.as_str(), e.password.expose()), ("oauth2", "tok-1"));
    }

    #[test]
    fn mismatched_credentials_are_refused() {
        let c = config("", "", "h.example");
        let (b, o) = (&c.profiles[0], &c.profiles[1]);
        assert!(netrc_entry(b, &oauth_cred(o)).is_err());
        assert!(access_token_entry(o, &basic_cred(b)).is_err());
    }

    #[test]
    fn tokens_with_whitespace_cannot_be_access_tokens() {
        let c = config("", "", "h.example");
        let b = &c.profiles[0];
        let cred = Credential::basic(b.identity(), Secret::new("u"), Secret::new("a b"));
        assert!(access_token_entry(b, &cred).is_err());
    }
}
