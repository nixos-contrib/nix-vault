//! A tiny scripted OAuth provider on a loopback port, with fake tokens only.
//!
//! Handlers see the request and how many requests to the same path came before it, so device
//! polling states (pending, slow down, success) are easy to script.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub body: String,
    pub authorization: Option<String>,
}

type Handler = dyn Fn(&Request, usize) -> (u16, String) + Send + Sync;

pub struct MockProvider {
    pub port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut buffer).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buffer[..n]);
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..header_end]).into_owned();
    let length = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    while data.len() < header_end + length {
        let n = stream.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..n]);
    }
    let first = head.lines().next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let authorization = head.lines().find_map(|l| {
        l.to_ascii_lowercase()
            .starts_with("authorization:")
            .then(|| l.split_once(':').unwrap().1.trim().to_string())
    });
    Some(Request {
        authorization,
        method,
        path: path.to_string(),
        query: query.to_string(),
        body: String::from_utf8_lossy(&data[header_end..]).into_owned(),
    })
}

impl MockProvider {
    pub fn start(
        handler: impl Fn(&Request, usize) -> (u16, String) + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests: Arc<Mutex<Vec<Request>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        let (reqs, stopped) = (requests.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut workers = Vec::new();
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let (reqs, handler) = (reqs.clone(), handler.clone());
                        workers.push(std::thread::spawn(move || {
                            let _ = stream.set_nonblocking(false);
                            let Some(request) = read_request(&mut stream) else {
                                return;
                            };
                            let nth = {
                                let mut all = reqs.lock().unwrap();
                                let nth = all.iter().filter(|r| r.path == request.path).count();
                                all.push(request.clone());
                                nth
                            };
                            let (status, body) = handler(&request, nth);
                            let reply = format!(
                                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = stream.write_all(reply.as_bytes());
                        }));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        MockProvider {
            port,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn requests_to(&self, path: &str) -> Vec<Request> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == path)
            .cloned()
            .collect()
    }
}

impl Drop for MockProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// An oauth2 profile `company` pointing at `base` using `flow`.
pub fn oauth_config(base: &str, flow: &str) -> String {
    let endpoint = if flow == "device" {
        format!("device_authorization_endpoint = \"{base}/device\"")
    } else {
        format!("authorization_endpoint = \"{base}/authorize\"")
    };
    format!(
        "[company]\nhost = \"gitlab.example.com\"\ntype = \"oauth2\"\n[company.oauth2]\nclient_id = \"public-client-id\"\n\
         flow = \"{flow}\"\n{endpoint}\ntoken_endpoint = \"{base}/token\"\nscopes = [\"read_api\"]\n"
    )
}

/// The identity of the profile from `oauth_config` (host and client id only).
pub fn company_identity() -> String {
    super::identity("oauth2", "gitlab.example.com", Some("public-client-id"))
}

pub fn token_json(access: &str, refresh: Option<&str>, expires_in: Option<u64>) -> String {
    let refresh = refresh
        .map(|r| format!(",\"refresh_token\":\"{r}\""))
        .unwrap_or_default();
    let expires = expires_in
        .map(|e| format!(",\"expires_in\":{e}"))
        .unwrap_or_default();
    format!("{{\"access_token\":\"{access}\",\"token_type\":\"Bearer\"{refresh}{expires},\"scope\":\"read_api\"}}")
}

pub fn error_json(error: &str) -> String {
    format!("{{\"error\":\"{error}\",\"error_description\":\"fake {error}\"}}")
}

/// A form field of a URL-encoded body or query.
pub fn field(text: &str, name: &str) -> Option<String> {
    text.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| percent_decode(v))
    })
}

pub fn percent_decode(value: &str) -> String {
    let bytes = value.replace('+', " ").into_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// base64url without padding (for checking PKCE challenges).
pub fn base64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.len();
        let value = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..=n {
            out.push(ALPHABET[((value >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}
