//! Header sources for the proxy beyond fixed headers.
//!
//! The source of an oauth2 profile keeps its credential current: when the access token is about
//! to end, the refresh token is exchanged for a new one, so a command that runs longer than the
//! token's life keeps working.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::vault::{
    auth::{self, redact::Secret, CredentialState},
    config::Profile,
    nix::{proxy::HeaderSource, render},
    store::{Credential, CredentialStore},
};

/// Renews the credential of one oauth2 profile as needed and renders its headers.
pub struct OAuthSource {
    profile: Profile,
    store: Arc<Mutex<CredentialStore>>,
    state_dir: PathBuf,
    /// The credential in use. Holding its lock while renewing means concurrent requests wait for
    /// one renewal instead of each starting their own.
    current: Mutex<Credential>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere must not stop every later request
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl OAuthSource {
    /// Starts from `credential`, which `exec` has just made usable.
    pub fn new(
        profile: Profile,
        store: Arc<Mutex<CredentialStore>>,
        state_dir: PathBuf,
        credential: Credential,
    ) -> Self {
        OAuthSource {
            profile,
            store,
            state_dir,
            current: Mutex::new(credential),
        }
    }
}

impl HeaderSource for OAuthSource {
    fn headers(&self) -> Result<Vec<(String, Secret)>, String> {
        let mut current = lock(&self.current);
        let state = auth::state(
            &self.profile,
            Some(&current),
            time::OffsetDateTime::now_utc(),
        );
        if state != CredentialState::Usable {
            // Takes the per-profile lock, re-reads the store (another nix-vault may have renewed
            // already), and saves a rotated refresh token before returning the new access token
            let fresh = {
                let store = lock(&self.store);
                auth::refresh_profile(&self.profile, &store, &self.state_dir)
            };
            // The error names the profile and what to run, never a token
            *current = fresh.map_err(|e| format!("nix-vault: {e}"))?;
        }
        render::proxy_headers(&self.profile, &current).map_err(|e| format!("nix-vault: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use time::{Duration, OffsetDateTime};
    use tiny_http::{Response, Server, StatusCode};

    use super::*;
    use crate::vault::{
        config::Config,
        store::{OAuthCredential, SecretStore},
        Result as VaultResult,
    };

    /// An in-memory store.
    #[derive(Default)]
    struct Memory(Mutex<HashMap<String, Secret>>);

    impl SecretStore for Memory {
        fn get(&self, account: &str) -> VaultResult<Option<Secret>> {
            Ok(self.0.lock().unwrap().get(account).cloned())
        }
        fn set(&self, account: &str, value: &Secret) -> VaultResult<()> {
            self.0.lock().unwrap().insert(account.into(), value.clone());
            Ok(())
        }
        fn delete(&self, account: &str) -> VaultResult<bool> {
            Ok(self.0.lock().unwrap().remove(account).is_some())
        }
    }

    /// A token endpoint that counts its requests and answers with `status` and `body`.
    struct TokenEndpoint {
        url: String,
        requests: Arc<AtomicUsize>,
        server: Arc<Server>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl TokenEndpoint {
        fn start(status: u16, body: &'static str) -> TokenEndpoint {
            let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
            let url = format!("http://{}/token", server.server_addr().to_ip().unwrap());
            let requests = Arc::new(AtomicUsize::new(0));
            let thread = {
                let (server, requests) = (Arc::clone(&server), Arc::clone(&requests));
                std::thread::spawn(move || {
                    for mut request in server.incoming_requests() {
                        let mut sink = String::new();
                        let _ = request.as_reader().read_to_string(&mut sink);
                        requests.fetch_add(1, Ordering::SeqCst);
                        // A little latency, so concurrent callers really overlap
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        let _ = request.respond(
                            Response::from_string(body)
                                .with_status_code(StatusCode(status))
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        "Content-Type",
                                        "application/json",
                                    )
                                    .unwrap(),
                                ),
                        );
                    }
                })
            };
            TokenEndpoint {
                url,
                requests,
                server,
                thread: Some(thread),
            }
        }
    }

    impl Drop for TokenEndpoint {
        fn drop(&mut self) {
            self.server.unblock();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    const REFRESHED: &str = r#"{"access_token":"new-access-9","token_type":"bearer","expires_in":3600,"refresh_token":"new-refresh-9"}"#;

    fn profile(token_url: &str) -> Profile {
        Config::parse(&format!(
            "[p]\nhost=\"h.example\"\ntype=\"oauth2\"\n[p.oauth2]\nclient_id=\"c\"\n\
             flow=\"authorization_code\"\nauthorization_endpoint=\"https://idp.example/a\"\n\
             token_endpoint=\"{token_url}\"\n[p.nix]\nuse=[\"proxy\"]\n[p.proxy]\n\
             headers = {{ Authorization = \"Bearer {{access_token}}\" }}\n"
        ))
        .unwrap()
        .profiles
        .remove(0)
    }

    fn credential(
        profile: &Profile,
        expires_in: Option<Duration>,
        refresh: Option<&str>,
    ) -> Credential {
        Credential::oauth2(
            profile.identity(),
            OAuthCredential {
                access_token: Secret::new("old-access-1"),
                refresh_token: refresh.map(Secret::new),
                token_type: "bearer".into(),
                expires_at: expires_in.map(|d| OffsetDateTime::now_utc() + d),
                scope: None,
            },
        )
    }

    /// A source over an in-memory store holding `credential`, and the state directory.
    fn source(
        profile: &Profile,
        credential: Credential,
    ) -> (OAuthSource, Arc<Mutex<CredentialStore>>, tempfile::TempDir) {
        let store = Arc::new(Mutex::new(CredentialStore::new(
            Box::new(Memory::default()),
        )));
        store
            .lock()
            .unwrap()
            .save(&profile.name, &credential)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let headers = OAuthSource::new(
            profile.clone(),
            Arc::clone(&store),
            dir.path().to_path_buf(),
            credential,
        );
        (headers, store, dir)
    }

    fn bearer(headers: Vec<(String, Secret)>) -> String {
        assert_eq!(headers[0].0, "Authorization");
        headers[0].1.expose().to_string()
    }

    #[test]
    fn a_fresh_token_is_used_without_contacting_the_provider() {
        let endpoint = TokenEndpoint::start(200, REFRESHED);
        let p = profile(&endpoint.url);
        let (source, _store, _dir) = source(
            &p,
            credential(&p, Some(Duration::hours(1)), Some("refresh-1")),
        );
        for _ in 0..3 {
            assert_eq!(bearer(source.headers().unwrap()), "Bearer old-access-1");
        }
        assert_eq!(endpoint.requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_token_near_its_end_is_renewed_once_and_the_rotated_refresh_token_is_saved() {
        let endpoint = TokenEndpoint::start(200, REFRESHED);
        let p = profile(&endpoint.url);
        let (source, store, _dir) = source(
            &p,
            credential(&p, Some(Duration::seconds(30)), Some("refresh-1")),
        );
        assert_eq!(bearer(source.headers().unwrap()), "Bearer new-access-9");
        assert_eq!(bearer(source.headers().unwrap()), "Bearer new-access-9");
        assert_eq!(endpoint.requests.load(Ordering::SeqCst), 1);
        let saved = store
            .lock()
            .unwrap()
            .load(&p.name)
            .unwrap()
            .unwrap()
            .oauth2
            .unwrap();
        assert_eq!(saved.access_token.expose(), "new-access-9");
        assert_eq!(saved.refresh_token.unwrap().expose(), "new-refresh-9");
    }

    #[test]
    fn concurrent_requests_share_one_renewal() {
        let endpoint = TokenEndpoint::start(200, REFRESHED);
        let p = profile(&endpoint.url);
        let (source, _store, _dir) = source(
            &p,
            credential(&p, Some(Duration::seconds(30)), Some("refresh-1")),
        );
        let source = Arc::new(source);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let source = Arc::clone(&source);
                std::thread::spawn(move || bearer(source.headers().unwrap()))
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), "Bearer new-access-9");
        }
        assert_eq!(endpoint.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_failed_renewal_is_a_message_that_names_the_profile_and_no_token() {
        let endpoint = TokenEndpoint::start(400, r#"{"error":"invalid_grant"}"#);
        let p = profile(&endpoint.url);
        let (source, _store, _dir) = source(
            &p,
            credential(&p, Some(Duration::seconds(30)), Some("refresh-1")),
        );
        let message = source.headers().unwrap_err();
        assert!(
            message.starts_with("nix-vault: ") && message.contains("\"p\""),
            "{message}"
        );
        assert!(!message.contains("refresh-1") && !message.contains("old-access-1"));
    }

    #[test]
    fn an_expired_token_without_a_refresh_token_says_to_log_in_again() {
        let endpoint = TokenEndpoint::start(200, REFRESHED);
        let p = profile(&endpoint.url);
        let (source, _store, _dir) = source(&p, credential(&p, Some(Duration::seconds(-5)), None));
        let message = source.headers().unwrap_err();
        assert!(message.contains("nix-vault login --profile p"), "{message}");
        assert_eq!(endpoint.requests.load(Ordering::SeqCst), 0);
    }
}
