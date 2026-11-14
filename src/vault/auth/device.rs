//! The device authorization flow.

use std::io::IsTerminal;

use oauth2::{
    basic::BasicClient, AuthType, DeviceAuthorizationUrl, Scope,
    StandardDeviceAuthorizationResponse,
};

use crate::vault::{
    auth::{
        discovery::resolve,
        token::{client_id, describe, http_client, token_url, TokenSet},
    },
    config::OAuth,
    Error, Result,
};

/// Runs the device flow: prints the verification URL and user code, waits for the user to
/// approve in a browser, and returns the tokens. Nothing is stored here.
pub fn login(profile: &str, oauth: &OAuth) -> Result<TokenSet> {
    let oauth = &resolve(oauth)?;
    let endpoint = oauth
        .device_authorization_endpoint
        .clone()
        .ok_or_else(|| Error::Auth("the profile has no device_authorization_endpoint".into()))?;
    let http = http_client()?;
    let client =
        BasicClient::new(client_id(oauth))
            .set_token_uri(token_url(oauth)?)
            .set_device_authorization_url(DeviceAuthorizationUrl::new(endpoint).map_err(|_| {
                Error::Auth("the device authorization endpoint is not a URL".into())
            })?)
            .set_auth_type(AuthType::RequestBody);

    let mut request = client.exchange_device_code();
    for scope in &oauth.scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    let details: StandardDeviceAuthorizationResponse = request
        .request(&http)
        .map_err(|e| Error::Auth(describe(e, &[])))?;

    let uri = details.verification_uri().as_str().to_string();
    let open = details
        .verification_uri_complete()
        .map(|u| u.secret().clone())
        .unwrap_or_else(|| uri.clone());
    eprintln!(
        "To log in to {profile}, open {uri} and enter the code {}",
        details.user_code().secret()
    );
    if std::io::stdin().is_terminal() {
        let _ = webbrowser::open(&open);
    }
    eprintln!("Waiting for authorization...");

    let response = client
        .exchange_device_access_token(&details)
        .request(&http, std::thread::sleep, None)
        .map_err(|e| Error::Auth(describe(e, &[])))?;
    Ok(TokenSet::from_response(&response))
}
