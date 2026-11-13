//! Credentials supplied through environment variables (`[<profile>.basic]`), for CI runners that
//! have no keychain. Nothing is stored: the variables are read when `exec` starts.

use crate::vault::{auth::redact::Secret, config::Profile, store::Credential, Error, Result};

/// Reads the credential of a basic profile from its environment variables. Returns `None` for a
/// profile that does not use them. A variable that is not set, or is empty, is an error that
/// names the variable and never a value.
pub fn acquire(profile: &Profile) -> Result<Option<Credential>> {
    acquire_from(profile, |name| std::env::var_os(name))
}

fn acquire_from(
    profile: &Profile,
    get: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Option<Credential>> {
    let Some(env) = &profile.env else {
        return Ok(None);
    };
    let read = |variable: &str| -> Result<Secret> {
        let problem = |what: &str| {
            Error::Auth(format!(
                "profile \"{}\" reads its credentials from the environment, and the variable \
                 {variable} {what}",
                profile.name
            ))
        };
        match get(variable) {
            None => Err(problem("is not set")),
            Some(value) => match value.to_str() {
                Some("") => Err(problem("is empty")),
                Some(text) => Ok(Secret::new(text)),
                None => Err(problem("is not valid text")),
            },
        }
    };
    let username = read(&env.username_env)?;
    let password = read(&env.password_env)?;
    Ok(Some(Credential::basic(
        profile.identity(),
        username,
        password,
    )))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::vault::config::Config;

    fn profile(with_env: bool) -> Profile {
        let table = if with_env {
            "[a.basic]\nusername_env = \"CI_USER\"\npassword_env = \"CI_TOKEN\"\n"
        } else {
            ""
        };
        Config::parse(&format!(
            "[a]\nhost = \"h.example\"\ntype = \"basic\"\n{table}"
        ))
        .unwrap()
        .profiles
        .remove(0)
    }

    fn vars(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        move |name| map.get(name).map(|v| (*v).into())
    }

    #[test]
    fn the_values_come_from_the_named_variables() {
        let c = acquire_from(
            &profile(true),
            vars(&[("CI_USER", "oauth2"), ("CI_TOKEN", "tok-1")]),
        )
        .unwrap()
        .unwrap();
        let basic = c.basic.unwrap();
        assert_eq!(basic.username.expose(), "oauth2");
        assert_eq!(basic.password.expose(), "tok-1");
    }

    #[test]
    fn a_profile_without_the_table_is_not_served_from_the_environment() {
        assert!(acquire_from(
            &profile(false),
            vars(&[("CI_USER", "u"), ("CI_TOKEN", "t")])
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn a_missing_or_empty_variable_is_named_and_its_value_never_is() {
        let p = profile(true);
        let missing = acquire_from(&p, vars(&[("CI_USER", "u")]))
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("CI_TOKEN") && missing.contains("is not set"),
            "{missing}"
        );
        let empty = acquire_from(&p, vars(&[("CI_USER", ""), ("CI_TOKEN", "t")]))
            .unwrap_err()
            .to_string();
        assert!(
            empty.contains("CI_USER") && empty.contains("is empty"),
            "{empty}"
        );
        let secret = acquire_from(&p, vars(&[("CI_USER", "u")]))
            .unwrap_err()
            .to_string();
        assert!(!secret.contains("\"u\""));
    }
}
