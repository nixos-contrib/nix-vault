//! Endpoint discovery: reads an authorization server's metadata (RFC 8414 or OpenID Connect
//! Discovery) to fill in the endpoints a profile leaves out.
//!
//! Endpoints written in the profile always win over discovered ones. The fetch happens only when
//! a command talks to the provider, never when the configuration is read, and the result is kept
//! for the life of the process (a running proxy refreshes tokens many times).

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use oauth2::url::Url;
use serde::Deserialize;

use crate::vault::{
    auth::token::http_client,
    config::{is_secure_url, Flow, OAuth},
    Error, Result,
};

/// Largest metadata document accepted.
const MAX_BYTES: usize = 256 * 1024;

/// The fields of the metadata document that are used.
#[derive(Clone, Debug, Deserialize)]
struct Metadata {
    issuer: Option<String>,
    token_endpoint: Option<String>,
    authorization_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
}

static CACHE: OnceLock<Mutex<HashMap<String, Metadata>>> = OnceLock::new();

/// Returns `oauth` with every endpoint it needs filled in: those set in the profile are kept and
/// the rest come from the issuer's metadata. A profile without `issuer` is returned unchanged.
pub fn resolve(oauth: &OAuth) -> Result<OAuth> {
    let Some(issuer) = &oauth.issuer else {
        return Ok(oauth.clone());
    };
    let needs_flow_endpoint = match oauth.flow {
        Flow::Device => oauth.device_authorization_endpoint.is_none(),
        Flow::AuthorizationCode => oauth.authorization_endpoint.is_none(),
    };
    if oauth.token_endpoint.is_some() && !needs_flow_endpoint {
        return Ok(oauth.clone());
    }
    let metadata = metadata(issuer)?;
    let mut resolved = oauth.clone();
    if resolved.token_endpoint.is_none() {
        resolved.token_endpoint = Some(found(&metadata.token_endpoint, "token_endpoint", issuer)?);
    }
    match oauth.flow {
        Flow::Device if needs_flow_endpoint => {
            resolved.device_authorization_endpoint = Some(found(
                &metadata.device_authorization_endpoint,
                "device_authorization_endpoint",
                issuer,
            )?);
        }
        Flow::AuthorizationCode if needs_flow_endpoint => {
            resolved.authorization_endpoint = Some(found(
                &metadata.authorization_endpoint,
                "authorization_endpoint",
                issuer,
            )?);
        }
        _ => {}
    }
    Ok(resolved)
}

/// Takes one endpoint from the metadata, which must be a URL safe to send credentials to.
fn found(value: &Option<String>, key: &str, issuer: &str) -> Result<String> {
    let value = value.as_deref().ok_or_else(|| {
        Error::Auth(format!(
            "the metadata of {issuer} has no \"{key}\"; set it in the profile"
        ))
    })?;
    match Url::parse(value) {
        Ok(url) if is_secure_url(&url) => Ok(value.to_string()),
        _ => Err(Error::Auth(format!(
            "the metadata of {issuer} has a \"{key}\" that is not an https URL"
        ))),
    }
}

/// The metadata of an issuer, fetched once per process.
fn metadata(issuer: &str) -> Result<Metadata> {
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().ok().and_then(|c| c.get(issuer).cloned()) {
        return Ok(hit);
    }
    let fetched = fetch(issuer)?;
    if let Ok(mut cache) = cache.lock() {
        cache.insert(issuer.to_string(), fetched.clone());
    }
    Ok(fetched)
}

/// The places an issuer's metadata may be: RFC 8414 puts the well-known segment between the host
/// and the issuer's path, OpenID Connect appends it to the issuer.
fn candidates(issuer: &str) -> Result<Vec<String>> {
    let url = Url::parse(issuer)
        .map_err(|_| Error::Auth(format!("the issuer {issuer} is not a valid URL")))?;
    let path = url.path().trim_end_matches('/');
    let mut origin = url.clone();
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    let origin = origin.as_str().trim_end_matches('/');
    let mut list = vec![format!(
        "{origin}/.well-known/oauth-authorization-server{path}"
    )];
    list.push(format!("{origin}{path}/.well-known/openid-configuration"));
    Ok(list)
}

fn fetch(issuer: &str) -> Result<Metadata> {
    let http = http_client()?;
    let mut last = format!("no metadata found for {issuer}");
    for url in candidates(issuer)? {
        let response = match http.get(&url).header("Accept", "application/json").send() {
            Ok(r) => r,
            Err(_) => {
                last = format!("could not reach {url}");
                continue;
            }
        };
        if !response.status().is_success() {
            last = format!("{url} answered {}", response.status());
            continue;
        }
        let body = response
            .bytes()
            .map_err(|_| Error::Auth(format!("could not read the metadata from {url}")))?;
        if body.len() > MAX_BYTES {
            return Err(Error::Auth(format!("the metadata at {url} is too large")));
        }
        let metadata: Metadata = serde_json::from_slice(&body)
            .map_err(|_| Error::Auth(format!("the metadata at {url} is not valid JSON")))?;
        // A document for another issuer could point the login anywhere
        let matches = metadata
            .issuer
            .as_deref()
            .is_some_and(|i| i.trim_end_matches('/') == issuer.trim_end_matches('/'));
        if !matches {
            return Err(Error::Auth(format!(
                "the metadata at {url} is for a different issuer than {issuer}"
            )));
        }
        return Ok(metadata);
    }
    Err(Error::Auth(format!(
        "cannot discover the endpoints of {issuer}: {last}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_follow_rfc_8414_then_openid() {
        assert_eq!(
            candidates("https://idp.example.com").unwrap(),
            [
                "https://idp.example.com/.well-known/oauth-authorization-server",
                "https://idp.example.com/.well-known/openid-configuration"
            ]
        );
        assert_eq!(
            candidates("https://idp.example.com/tenant/1/").unwrap(),
            [
                "https://idp.example.com/.well-known/oauth-authorization-server/tenant/1",
                "https://idp.example.com/tenant/1/.well-known/openid-configuration"
            ]
        );
    }
}
