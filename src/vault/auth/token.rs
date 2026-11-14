//! Talking to OAuth token endpoints: the HTTP client, token sets, refresh and error mapping.
//!
//! Redirects are disabled and every request has a timeout. Response bodies are never echoed:
//! errors carry only the OAuth error code and a description with known secrets removed.

use std::time::Duration;

use oauth2::{
    basic::BasicClient, reqwest::blocking::Client as HttpClient, AuthType, ClientId, ErrorResponse,
    RefreshToken, RequestTokenError, TokenResponse, TokenUrl,
};

use crate::vault::{
    auth::{
        discovery::resolve,
        redact::{redact, Secret},
    },
    config::OAuth,
    Error, Result,
};

/// Tokens obtained from a provider.
#[derive(Debug)]
pub struct TokenSet {
    /// Access token.
    pub access_token: Secret,
    /// Refresh token, when issued.
    pub refresh_token: Option<Secret>,
    /// Lifetime of the access token, when reported.
    pub expires_in: Option<Duration>,
    /// Granted scopes, space separated, when reported.
    pub scope: Option<String>,
}

impl TokenSet {
    /// Extracts the tokens from a provider response.
    pub fn from_response<T: TokenResponse>(response: &T) -> Self {
        TokenSet {
            access_token: Secret::new(response.access_token().secret().clone()),
            refresh_token: response
                .refresh_token()
                .map(|t| Secret::new(t.secret().clone())),
            expires_in: response.expires_in(),
            scope: response.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
        }
    }
}

/// Builds the HTTP client: no redirects (they could send credentials elsewhere) and timeouts.
pub fn http_client() -> Result<HttpClient> {
    HttpClient::builder()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| Error::Auth("cannot create the HTTP client".into()))
}

/// Returns the token URL of a profile.
pub fn token_url(oauth: &OAuth) -> Result<TokenUrl> {
    let endpoint = oauth
        .token_endpoint
        .clone()
        .ok_or_else(|| Error::Auth("the profile has no token_endpoint".into()))?;
    TokenUrl::new(endpoint).map_err(|_| Error::Auth("the token endpoint is not a valid URL".into()))
}

/// Returns a client id wrapper.
pub fn client_id(oauth: &OAuth) -> ClientId {
    ClientId::new(oauth.client_id.clone())
}

/// Turns a token request failure into a short message without response bodies or secrets.
pub fn describe<RE, T>(error: RequestTokenError<RE, T>, secrets: &[&str]) -> String
where
    RE: std::error::Error + 'static,
    T: ErrorResponse + 'static,
{
    let text = match error {
        RequestTokenError::ServerResponse(response) => {
            let message = redact(&response.to_string(), secrets);
            let message: String = message.chars().take(200).collect();
            format!("the provider answered: {message}")
        }
        RequestTokenError::Request(_) => "could not reach the token endpoint".to_string(),
        RequestTokenError::Parse(_, _) => {
            "the token endpoint returned an unexpected response".to_string()
        }
        RequestTokenError::Other(message) => redact(&message, secrets),
    };
    text
}

/// Exchanges a refresh token for a new token set. The provider may rotate the refresh token.
pub fn refresh(oauth: &OAuth, refresh_token: &Secret) -> std::result::Result<TokenSet, String> {
    let oauth = &resolve(oauth).map_err(|e| e.to_string())?;
    let http = http_client().map_err(|e| e.to_string())?;
    let url = token_url(oauth).map_err(|e| e.to_string())?;
    let client = BasicClient::new(client_id(oauth))
        .set_token_uri(url)
        .set_auth_type(AuthType::RequestBody);
    let response = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.expose().to_string()))
        .request(&http)
        .map_err(|e| describe(e, &[refresh_token.expose()]))?;
    Ok(TokenSet::from_response(&response))
}
