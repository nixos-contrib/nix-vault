//! The local reverse proxy behind `use = ["proxy"]`.
//!
//! Nix cannot send custom HTTP headers, so for a service that wants them (Cloudflare Access
//! wants `CF-Access-Client-Id` and `CF-Access-Client-Secret`) the session points Nix at a proxy on
//! `127.0.0.1`. The proxy forwards each request to the real host, adds the headers, and streams
//! bodies in both directions. It lives for one `exec` and serves only that command.
//!
//! The local URL carries a random path prefix. Anything that does not start with it gets a 404,
//! so another user on the machine cannot borrow the credentials by finding the port.

use std::{
    io::{Read, Write},
    net::SocketAddr,
    sync::Arc,
    thread::JoinHandle,
};

use oauth2::reqwest::{
    blocking::{Body, Client},
    redirect::Policy,
    Method,
};
use tiny_http::{Header, Response, Server, StatusCode};

use crate::vault::{auth::redact::Secret, Error, Result};

/// Headers that describe one connection, not the message (RFC 9110 section 7.6.1), plus the ones
/// the proxy sets itself.
const NOT_FORWARDED: [&str; 11] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// Where the proxy gets the headers it adds. It is asked on every request, so a credential that
/// expires during a long command can be renewed in between.
pub trait HeaderSource: Send + Sync {
    /// Returns the headers to add now, replacing any the client sent with the same name, or a
    /// message for the client when there are none (it must not contain a secret).
    fn headers(&self) -> std::result::Result<Vec<(String, Secret)>, String>;
}

/// Headers that never change: a service token.
pub struct StaticHeaders(pub Vec<(String, Secret)>);

impl HeaderSource for StaticHeaders {
    fn headers(&self) -> std::result::Result<Vec<(String, Secret)>, String> {
        Ok(self.0.clone())
    }
}

/// What the proxy forwards to and what it adds.
pub struct Target {
    /// Where requests go, without a trailing slash: `https://cache.example.com`.
    pub base: String,
    /// Where the headers added to every request come from.
    pub source: Arc<dyn HeaderSource>,
}

/// A running proxy. It stops on `stop()` and on drop.
pub struct Proxy {
    server: Option<Arc<Server>>,
    thread: Option<JoinHandle<()>>,
    url: String,
}

impl Proxy {
    /// Starts a proxy for `target` on a random loopback port.
    pub fn start(target: Target) -> Result<Proxy> {
        let server = Server::http("127.0.0.1:0")
            .map_err(|e| Error::Io(format!("cannot start the local proxy: {e}")))?;
        let addr: SocketAddr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| Error::Io("the local proxy has no address".into()))?;
        let prefix = format!("/{}", random_token()?);
        let url = format!("http://{addr}{prefix}");

        let client = Client::builder()
            // A redirect (to a login page, say) is the client's to follow or not
            .redirect(Policy::none())
            .connect_timeout(std::time::Duration::from_secs(30))
            // No overall timeout: a NAR can take as long as it takes
            .timeout(None)
            .build()
            .map_err(|_| Error::Io("cannot create the HTTP client for the local proxy".into()))?;

        let server = Arc::new(server);
        let shared = Arc::new(Shared {
            client,
            target,
            prefix,
        });
        let thread = {
            let server = Arc::clone(&server);
            std::thread::spawn(move || {
                for request in server.incoming_requests() {
                    let shared = Arc::clone(&shared);
                    std::thread::spawn(move || handle(&shared, request));
                }
            })
        };
        Ok(Proxy {
            server: Some(server),
            thread: Some(thread),
            url,
        })
    }

    /// Returns the local base URL, including the secret path prefix, for Nix to use in place of
    /// the real one.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Stops accepting requests and closes the port.
    pub fn stop(&mut self) {
        if let Some(server) = self.server.take() {
            server.unblock();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            // The last reference: dropping it closes the listening socket
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Shared {
    client: Client,
    target: Target,
    prefix: String,
}

/// Returns 128 random bits as hex, from the operating system.
fn random_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| Error::io("cannot read random bytes for the local proxy", e))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn text_response(status: u16, text: impl Into<String>) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(text.into()).with_status_code(StatusCode(status))
}

/// Returns the part of `url` after the secret prefix, or `None` when it is not under it.
fn strip_prefix<'a>(url: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = url.strip_prefix(prefix)?;
    match rest.chars().next() {
        None | Some('/') | Some('?') => Some(rest),
        _ => None,
    }
}

fn handle(shared: &Shared, mut request: tiny_http::Request) {
    let url = request.url().to_string();
    let Some(rest) = strip_prefix(&url, &shared.prefix) else {
        let _ = request.respond(text_response(404, "not found"));
        return;
    };
    let path = if rest.starts_with('/') {
        rest.to_string()
    } else {
        format!("/{rest}")
    };
    let Ok(method) = Method::from_bytes(request.method().as_str().as_bytes()) else {
        let _ = request.respond(text_response(405, "method not allowed"));
        return;
    };

    // Asked per request. When there is nothing to send the request is not forwarded: sending it
    // without the credential, or with a stale one, would only be rejected upstream
    let headers = match shared.target.source.headers() {
        Ok(headers) => headers,
        Err(message) => {
            let _ = request.respond(text_response(401, message));
            return;
        }
    };
    let mut builder = shared
        .client
        .request(method, format!("{}{path}", shared.target.base));
    let injected: Vec<String> = headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    for header in request.headers() {
        let name = header.field.as_str().as_str().to_ascii_lowercase();
        if NOT_FORWARDED.contains(&name.as_str()) || name == "expect" || injected.contains(&name) {
            continue;
        }
        builder = builder.header(name, header.value.as_str());
    }
    for (name, value) in &headers {
        builder = builder.header(name.as_str(), value.expose());
    }

    // The request body is streamed through a pipe, so a large upload is never held in memory
    let length = request.body_length();
    let mut feeder: Option<std::io::PipeWriter> = None;
    if length != Some(0) {
        let Ok((reader, writer)) = std::io::pipe() else {
            let _ = request.respond(text_response(500, "local proxy failure"));
            return;
        };
        builder = builder.body(match length {
            Some(n) => Body::sized(reader, n as u64),
            None => Body::new(reader),
        });
        feeder = Some(writer);
    }
    let sender = std::thread::spawn(move || builder.send());
    if let Some(mut writer) = feeder {
        // An upstream that answers early stops reading: that is not an error here
        let _ = std::io::copy(request.as_reader(), &mut writer);
        let _ = writer.flush();
        drop(writer);
    }
    let response = match sender.join() {
        Ok(Ok(response)) => response,
        _ => {
            let _ = request.respond(text_response(502, "the upstream service is unreachable"));
            return;
        }
    };

    let status = response.status().as_u16();
    let length = response.content_length().map(|n| n as usize);
    let headers: Vec<Header> = response
        .headers()
        .iter()
        .filter(|(name, _)| !NOT_FORWARDED.contains(&name.as_str()))
        .filter_map(|(name, value)| {
            Header::from_bytes(name.as_str().as_bytes(), value.as_bytes()).ok()
        })
        .collect();
    let _ = request.respond(Response::new(
        StatusCode(status),
        headers,
        response,
        length,
        None,
    ));
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use super::*;

    /// A fake upstream: records what it was sent and answers by path.
    struct Upstream {
        server: Arc<Server>,
        thread: Option<JoinHandle<()>>,
        seen: Arc<Mutex<Vec<Seen>>>,
        base: String,
    }

    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        url: String,
        headers: BTreeMap<String, String>,
        body_len: usize,
    }

    impl Upstream {
        fn start() -> Upstream {
            let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
            let base = format!("http://{}", server.server_addr().to_ip().unwrap());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let thread = {
                let (server, seen) = (Arc::clone(&server), Arc::clone(&seen));
                std::thread::spawn(move || {
                    for mut request in server.incoming_requests() {
                        let mut body = Vec::new();
                        let _ = request.as_reader().read_to_end(&mut body);
                        let headers = request
                            .headers()
                            .iter()
                            .map(|h| {
                                (
                                    h.field.as_str().as_str().to_ascii_lowercase(),
                                    h.value.as_str().to_string(),
                                )
                            })
                            .collect();
                        let url = request.url().to_string();
                        seen.lock().unwrap().push(Seen {
                            method: request.method().as_str().to_string(),
                            url: url.clone(),
                            headers,
                            body_len: body.len(),
                        });
                        let response = match url.as_str() {
                            "/redirect" => Response::from_string("")
                                .with_status_code(StatusCode(302))
                                .with_header(
                                    Header::from_bytes("Location", "https://login.example/")
                                        .unwrap(),
                                ),
                            "/missing" => text_response(404, "no such narinfo"),
                            _ => Response::from_string("hello from upstream"),
                        };
                        let _ = request.respond(response);
                    }
                })
            };
            Upstream {
                server,
                thread: Some(thread),
                seen,
                base,
            }
        }

        fn requests(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Drop for Upstream {
        fn drop(&mut self) {
            self.server.unblock();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn client() -> Client {
        Client::builder().redirect(Policy::none()).build().unwrap()
    }

    fn proxy_to(upstream: &Upstream) -> Proxy {
        Proxy::start(Target {
            base: upstream.base.clone(),
            source: Arc::new(StaticHeaders(vec![
                ("CF-Access-Client-Id".into(), Secret::new("id-1.access")),
                ("CF-Access-Client-Secret".into(), Secret::new("secret-1")),
            ])),
        })
        .unwrap()
    }

    #[test]
    fn requests_get_the_headers_and_lose_the_secret_prefix() {
        let upstream = Upstream::start();
        let proxy = proxy_to(&upstream);
        let response = client()
            .get(format!("{}/nix-cache-info?x=1", proxy.url()))
            .header("Authorization", "Basic b3JpZ2luOnBhc3M=")
            // A client-sent value for an injected header must not survive
            .header("CF-Access-Client-Secret", "client-sent")
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().unwrap(), "hello from upstream");

        let seen = upstream.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].url, "/nix-cache-info?x=1");
        assert_eq!(seen[0].headers["cf-access-client-id"], "id-1.access");
        assert_eq!(seen[0].headers["cf-access-client-secret"], "secret-1");
        // The origin's own credential passes through untouched
        assert_eq!(seen[0].headers["authorization"], "Basic b3JpZ2luOnBhc3M=");
        // Host is the upstream's, not the proxy's
        assert_eq!(
            seen[0].headers["host"],
            upstream.base.trim_start_matches("http://")
        );
    }

    #[test]
    fn anything_outside_the_secret_prefix_is_a_404_and_never_reaches_the_upstream() {
        let upstream = Upstream::start();
        let proxy = proxy_to(&upstream);
        let addr = proxy.url().split('/').nth(2).unwrap().to_string();
        for path in ["/", "/nix-cache-info", "/wrong-token/nix-cache-info"] {
            let status = client()
                .get(format!("http://{addr}{path}"))
                .send()
                .unwrap()
                .status();
            assert_eq!(status, 404, "{path}");
        }
        // A path that merely starts with the token's text is not under it
        let status = client()
            .get(format!("{}x/nix-cache-info", proxy.url()))
            .send()
            .unwrap()
            .status();
        assert_eq!(status, 404);
        assert!(upstream.requests().is_empty());
    }

    #[test]
    fn uploads_are_streamed_with_their_length_and_heads_have_no_body() {
        let upstream = Upstream::start();
        let proxy = proxy_to(&upstream);
        let body = vec![7u8; 3 * 1024 * 1024];
        let response = client()
            .put(format!("{}/nar/x.nar", proxy.url()))
            .body(body.clone())
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        let head = client()
            .head(format!("{}/x.narinfo", proxy.url()))
            .send()
            .unwrap();
        assert_eq!(head.status(), 200);

        let seen = upstream.requests();
        assert_eq!(seen[0].method, "PUT");
        assert_eq!(seen[0].body_len, body.len());
        assert_eq!(seen[0].headers["content-length"], body.len().to_string());
        assert_eq!(seen[1].method, "HEAD");
    }

    #[test]
    fn upstream_statuses_and_redirects_pass_through_unchanged() {
        let upstream = Upstream::start();
        let proxy = proxy_to(&upstream);
        let missing = client()
            .get(format!("{}/missing", proxy.url()))
            .send()
            .unwrap();
        assert_eq!(missing.status(), 404);
        assert_eq!(missing.text().unwrap(), "no such narinfo");
        let redirect = client()
            .get(format!("{}/redirect", proxy.url()))
            .send()
            .unwrap();
        assert_eq!(redirect.status(), 302);
        assert_eq!(redirect.headers()["location"], "https://login.example/");
    }

    #[test]
    fn an_unreachable_upstream_is_a_502_without_details() {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", free.local_addr().unwrap());
        drop(free);
        let proxy = Proxy::start(Target {
            base,
            source: Arc::new(StaticHeaders(vec![(
                "CF-Access-Client-Secret".into(),
                Secret::new("secret-1"),
            )])),
        })
        .unwrap();
        let response = client().get(format!("{}/x", proxy.url())).send().unwrap();
        assert_eq!(response.status(), 502);
        let text = response.text().unwrap();
        assert!(!text.contains("secret-1") && !text.contains("127.0.0.1"));
    }

    #[test]
    fn a_stopped_proxy_refuses_connections() {
        let upstream = Upstream::start();
        let mut proxy = proxy_to(&upstream);
        let url = proxy.url().to_string();
        proxy.stop();
        assert!(client().get(format!("{url}/x")).send().is_err());
    }

    /// A source whose value changes on every call and that can be told to fail.
    struct Counting {
        calls: std::sync::atomic::AtomicUsize,
        fail_from: usize,
    }

    impl HeaderSource for Counting {
        fn headers(&self) -> std::result::Result<Vec<(String, Secret)>, String> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if n >= self.fail_from {
                return Err(
                    "nix-vault: the credentials cannot be renewed; run: nix-vault login -p x"
                        .into(),
                );
            }
            Ok(vec![(
                "Authorization".into(),
                Secret::new(format!("Bearer token-{n}")),
            )])
        }
    }

    #[test]
    fn the_headers_are_asked_for_on_every_request() {
        let upstream = Upstream::start();
        let proxy = Proxy::start(Target {
            base: upstream.base.clone(),
            source: Arc::new(Counting {
                calls: Default::default(),
                fail_from: usize::MAX,
            }),
        })
        .unwrap();
        for _ in 0..3 {
            client().get(format!("{}/x", proxy.url())).send().unwrap();
        }
        let seen = upstream.requests();
        let tokens: Vec<&str> = seen
            .iter()
            .map(|r| r.headers["authorization"].as_str())
            .collect();
        assert_eq!(
            tokens,
            ["Bearer token-1", "Bearer token-2", "Bearer token-3"]
        );
    }

    #[test]
    fn a_source_that_has_no_headers_answers_401_and_nothing_is_forwarded() {
        let upstream = Upstream::start();
        let proxy = Proxy::start(Target {
            base: upstream.base.clone(),
            source: Arc::new(Counting {
                calls: Default::default(),
                fail_from: 2,
            }),
        })
        .unwrap();
        assert_eq!(
            client()
                .get(format!("{}/a", proxy.url()))
                .send()
                .unwrap()
                .status(),
            200
        );
        let refused = client().get(format!("{}/b", proxy.url())).send().unwrap();
        assert_eq!(refused.status(), 401);
        assert!(refused
            .text()
            .unwrap()
            .contains("run: nix-vault login -p x"));
        assert_eq!(
            upstream.requests().len(),
            1,
            "the second request must not reach the upstream"
        );
    }
}
