//! A small netrc reader/editor that preserves the user's file byte for byte.
//!
//! Existing crates parse netrc into lookup structures and cannot round-trip comments, `macdef`
//! bodies or formatting. nix-vault needs to copy the user's netrc into the session file,
//! dropping only the entries of hosts it overrides, so it tokenizes the file itself.

use std::ops::Range;

use crate::vault::{auth::redact::Secret, Error, Result};

/// One entry to add: `machine <host> login <login> password <password>`.
pub struct Entry {
    /// Host (`machine`).
    pub host: String,
    /// Login name.
    pub login: String,
    /// Password or token.
    pub password: Secret,
}

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Machine(String),
    Default,
}

#[derive(Debug)]
struct Located {
    kind: Kind,
    /// Start of the line holding the entry's first token (leading indentation included).
    start: usize,
    /// End of the entry: after its last token and the rest of that line when only whitespace.
    end: usize,
}

struct Token {
    start: usize,
    end: usize,
    text: Vec<u8>,
}

struct Scanner<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn skip_blank_and_comments(&mut self) {
        loop {
            while self.pos < self.raw.len() && self.raw[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }
            if self.pos < self.raw.len() && self.raw[self.pos] == b'#' && self.at_line_start() {
                while self.pos < self.raw.len() && self.raw[self.pos] != b'\n' {
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
    }

    fn at_line_start(&self) -> bool {
        let mut i = self.pos;
        while i > 0 {
            i -= 1;
            match self.raw[i] {
                b'\n' => return true,
                b' ' | b'\t' | b'\r' => continue,
                _ => return false,
            }
        }
        true
    }

    fn next_token(&mut self) -> Option<Token> {
        self.skip_blank_and_comments();
        if self.pos >= self.raw.len() {
            return None;
        }
        let start = self.pos;
        let mut text = Vec::new();
        if self.raw[self.pos] == b'"' {
            self.pos += 1;
            while self.pos < self.raw.len() && self.raw[self.pos] != b'"' {
                if self.raw[self.pos] == b'\\' && self.pos + 1 < self.raw.len() {
                    self.pos += 1;
                }
                text.push(self.raw[self.pos]);
                self.pos += 1;
            }
            if self.pos < self.raw.len() {
                self.pos += 1;
            }
        } else {
            while self.pos < self.raw.len() && !self.raw[self.pos].is_ascii_whitespace() {
                text.push(self.raw[self.pos]);
                self.pos += 1;
            }
        }
        Some(Token {
            start,
            end: self.pos,
            text,
        })
    }

    /// Skips the body of a `macdef`: from the next line to the first empty line.
    fn skip_macdef_body(&mut self) {
        while self.pos < self.raw.len() && self.raw[self.pos] != b'\n' {
            self.pos += 1;
        }
        if self.pos < self.raw.len() {
            self.pos += 1;
        }
        while self.pos < self.raw.len() {
            let line_end = self.raw[self.pos..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(self.raw.len(), |i| self.pos + i);
            let blank = self.raw[self.pos..line_end]
                .iter()
                .all(|b| b.is_ascii_whitespace());
            self.pos = (line_end + 1).min(self.raw.len());
            if blank {
                break;
            }
        }
    }
}

/// Extends `end` over trailing spaces and one newline when nothing else follows on the line.
fn extend_to_line_end(raw: &[u8], end: usize) -> usize {
    let mut i = end;
    while i < raw.len() && matches!(raw[i], b' ' | b'\t' | b'\r') {
        i += 1;
    }
    if i < raw.len() && raw[i] == b'\n' {
        i + 1
    } else if i >= raw.len() {
        i
    } else {
        end
    }
}

fn line_start(raw: &[u8], pos: usize) -> usize {
    let mut i = pos;
    while i > 0 && matches!(raw[i - 1], b' ' | b'\t') {
        i -= 1;
    }
    i
}

fn locate(raw: &[u8]) -> Vec<Located> {
    let mut scanner = Scanner { raw, pos: 0 };
    let mut entries: Vec<Located> = Vec::new();
    while let Some(token) = scanner.next_token() {
        let word = String::from_utf8_lossy(&token.text).to_ascii_lowercase();
        match word.as_str() {
            "machine" => {
                let host = scanner.next_token();
                let (host_text, end) = match host {
                    Some(h) => (String::from_utf8_lossy(&h.text).to_ascii_lowercase(), h.end),
                    None => (String::new(), token.end),
                };
                entries.push(Located {
                    kind: Kind::Machine(host_text),
                    start: line_start(raw, token.start),
                    end,
                });
            }
            "default" => entries.push(Located {
                kind: Kind::Default,
                start: line_start(raw, token.start),
                end: token.end,
            }),
            "login" | "password" | "account" => {
                // The value is consumed so that a value such as "machine" is not an entry
                if let Some(value) = scanner.next_token() {
                    if let Some(last) = entries.last_mut() {
                        last.end = value.end;
                    }
                }
            }
            "macdef" => {
                // The macro body is kept even when its entry is removed: it is not ours to drop
                let _name = scanner.next_token();
                scanner.skip_macdef_body();
            }
            _ => {
                if let Some(last) = entries.last_mut() {
                    last.end = token.end;
                }
            }
        }
    }
    for entry in &mut entries {
        entry.end = extend_to_line_end(raw, entry.end);
    }
    entries
}

/// Returns the (lowercased) hosts of the `machine` entries in `raw`.
pub fn hosts(raw: &[u8]) -> Vec<String> {
    locate(raw)
        .into_iter()
        .filter_map(|e| match e.kind {
            Kind::Machine(host) => Some(host),
            Kind::Default => None,
        })
        .collect()
}

/// Returns `raw` without the entries of the given hosts (compared case-insensitively); every
/// other byte is kept. `default` entries are never removed.
pub fn remove_hosts(raw: &[u8], hosts: &[String]) -> Vec<u8> {
    let hosts: Vec<String> = hosts.iter().map(|h| h.to_ascii_lowercase()).collect();
    let ranges: Vec<Range<usize>> = locate(raw)
        .into_iter()
        .filter(|e| matches!(&e.kind, Kind::Machine(h) if hosts.contains(h)))
        .map(|e| e.start..e.end)
        .collect();
    let mut out = Vec::with_capacity(raw.len());
    let mut at = 0;
    for range in ranges {
        if range.start >= at {
            out.extend_from_slice(&raw[at..range.start]);
            at = range.end;
        }
    }
    out.extend_from_slice(&raw[at..]);
    out
}

fn quote(value: &str) -> Result<String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(Error::Auth(
            "a credential value is empty or contains control characters and cannot be written \
             to a netrc file"
                .into(),
        ));
    }
    if value
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '"' | '\\' | '#'))
    {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        Ok(format!("\"{escaped}\""))
    } else {
        Ok(value.to_string())
    }
}

/// Inserts `entries` before the first `default` entry, or at the end when there is none, so a
/// `default` entry cannot shadow them.
pub fn add_entries(raw: &[u8], entries: &[Entry]) -> Result<Vec<u8>> {
    let mut block = String::new();
    for entry in entries {
        block.push_str(&format!(
            "machine {} login {} password {}\n",
            quote(&entry.host)?,
            quote(&entry.login)?,
            quote(entry.password.expose())?
        ));
    }
    let default_at = locate(raw)
        .into_iter()
        .find(|e| e.kind == Kind::Default)
        .map(|e| e.start);
    let mut out = Vec::with_capacity(raw.len() + block.len() + 1);
    match default_at {
        Some(at) => {
            out.extend_from_slice(&raw[..at]);
            out.extend_from_slice(block.as_bytes());
            out.extend_from_slice(&raw[at..]);
        }
        None => {
            out.extend_from_slice(raw);
            if !raw.is_empty() && !raw.ends_with(b"\n") {
                out.push(b'\n');
            }
            out.extend_from_slice(block.as_bytes());
        }
    }
    Ok(out)
}

/// Builds the session netrc: the user's entries without the overridden hosts, then `entries`.
pub fn merged(existing: &[u8], entries: &[Entry]) -> Result<Vec<u8>> {
    let hosts: Vec<String> = entries.iter().map(|e| e.host.clone()).collect();
    add_entries(&remove_hosts(existing, &hosts), entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# my logins\nmachine keep.example login a password b\n\
machine drop.example\n  login c\n  password d\n# comment between\nmacdef init\nmachine fake.example login x password y\n\nmachine MIXED.example login e password f\ndefault login anon password anon\n";

    fn entry(host: &str) -> Entry {
        Entry {
            host: host.into(),
            login: "user".into(),
            password: Secret::new("tok en"),
        }
    }

    #[test]
    fn nothing_removed_means_identity() {
        let out = remove_hosts(SAMPLE.as_bytes(), &["absent.example".into()]);
        assert_eq!(out, SAMPLE.as_bytes());
    }

    #[test]
    fn removes_only_the_named_hosts_case_insensitively() {
        let out = String::from_utf8(remove_hosts(
            SAMPLE.as_bytes(),
            &["drop.example".into(), "mixed.example".into()],
        ))
        .unwrap();
        assert!(!out.contains("drop.example") && !out.contains("login c"));
        assert!(!out.contains("MIXED.example"));
        // Everything else stays, including comments, the macdef body and the default entry
        assert!(out.contains("# my logins"));
        assert!(out.contains("# comment between"));
        assert!(out.contains("macdef init\nmachine fake.example login x password y\n"));
        assert!(out.contains("machine keep.example login a password b"));
        assert!(out.contains("default login anon password anon"));
    }

    #[test]
    fn values_named_machine_are_not_entries() {
        let raw = "machine a.example login machine password machine\n";
        let out = remove_hosts(raw.as_bytes(), &["machine".into()]);
        assert_eq!(out, raw.as_bytes());
    }

    #[test]
    fn entries_go_before_default() {
        let out =
            String::from_utf8(add_entries(SAMPLE.as_bytes(), &[entry("new.example")]).unwrap())
                .unwrap();
        let new_at = out.find("machine new.example").unwrap();
        let default_at = out.find("default login").unwrap();
        assert!(new_at < default_at);
        assert!(out.contains("password \"tok en\""));
    }

    #[test]
    fn entries_are_appended_with_a_newline_when_there_is_no_default() {
        let out = add_entries(b"machine a login b password c", &[entry("n.example")]).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "machine a login b password c\nmachine n.example login user password \"tok en\"\n"
        );
        let empty = add_entries(b"", &[entry("n.example")]).unwrap();
        assert!(String::from_utf8(empty)
            .unwrap()
            .starts_with("machine n.example"));
    }

    #[test]
    fn merged_replaces_a_clashing_host() {
        let out = String::from_utf8(
            merged(
                b"machine n.example login old password old\nmachine k login a password b\n",
                &[entry("n.example")],
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!out.contains("old"));
        assert_eq!(out.matches("machine n.example").count(), 1);
        assert!(out.contains("machine k login a password b"));
    }

    #[test]
    fn rejects_control_characters() {
        let bad = Entry {
            host: "h".into(),
            login: "u".into(),
            password: Secret::new("a\nb"),
        };
        assert!(add_entries(b"", &[bad]).is_err());
    }

    #[test]
    fn quotes_values_with_special_characters() {
        let e = Entry {
            host: "h".into(),
            login: "u".into(),
            password: Secret::new("a\"b\\c"),
        };
        let out = String::from_utf8(add_entries(b"", &[e]).unwrap()).unwrap();
        assert!(out.contains("password \"a\\\"b\\\\c\""));
    }
}
