//! Credentials from a helper command (`type = "process"`), in the manner of AWS's
//! `credential_process`.
//!
//! The command is run directly, without a shell. Its stdout is the credential and is never
//! logged or put in an error; its stderr and stdin are the terminal's, so a helper can say what
//! to do (`cloudflared` says to run its login) and can prompt.

use std::{
    io::Read,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use serde::Deserialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::vault::{
    auth::redact::Secret,
    config::{CommandOutput, Kind, Process, Profile},
    store::{Credential, OAuthCredential},
    Error, Result,
};

/// How long the command may run (it may prompt, so this is generous).
const TIMEOUT: Duration = Duration::from_secs(60);
/// The most output that is read. A token is a few kilobytes at most.
const MAX_OUTPUT: usize = 64 * 1024;

/// Runs the profile's command and returns the credential it printed. With `interactive` the
/// command shares the terminal's input and can prompt. Without it (while another command is
/// running) its input is empty, so it cannot take what the user types for that command.
pub fn acquire(profile: &Profile, interactive: bool) -> Result<Credential> {
    let Kind::Process(process) = &profile.kind else {
        return Err(Error::usage(format!(
            "profile \"{}\" is not a process profile",
            profile.name
        )));
    };
    let output = run(profile, process, interactive)?;
    parse(
        profile,
        process.command_output,
        &output,
        OffsetDateTime::now_utc(),
    )
}

fn failure(profile: &Profile, what: &str) -> Error {
    Error::Auth(format!(
        "the command of profile \"{}\" {what}",
        profile.name
    ))
}

fn run(profile: &Profile, process: &Process, interactive: bool) -> Result<Vec<u8>> {
    let mut child = Command::new(&process.command[0])
        .args(&process.command[1..])
        .stdin(if interactive {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            failure(
                profile,
                &format!(
                    "cannot be run ({:?}); is it installed and on PATH?",
                    e.kind()
                ),
            )
        })?;
    let mut stdout = child.stdout.take().expect("piped");
    // Read on a thread so a command that never closes its output still times out
    let reader = std::thread::spawn(move || {
        let mut data = Vec::new();
        let _ = (&mut stdout)
            .take(MAX_OUTPUT as u64 + 1)
            .read_to_end(&mut data);
        data
    });

    let started = Instant::now();
    let status: ExitStatus = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() > TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(failure(
                    profile,
                    &format!("did not finish within {} seconds", TIMEOUT.as_secs()),
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return Err(failure(profile, "cannot be waited for")),
        }
    };
    let data = reader.join().unwrap_or_default();
    if !status.success() {
        // The command's own messages are already on the terminal
        return Err(failure(profile, &format!("failed with {status}")));
    }
    if data.len() > MAX_OUTPUT {
        return Err(failure(profile, "printed more than 64 KiB"));
    }
    Ok(data)
}

#[derive(Deserialize)]
struct JsonCredential {
    access_token: Option<String>,
    username: Option<String>,
    password: Option<String>,
    expires_at: Option<String>,
}

/// Turns the command's output into a credential. `now` is passed in for the expiry check.
pub fn parse(
    profile: &Profile,
    format: CommandOutput,
    output: &[u8],
    now: OffsetDateTime,
) -> Result<Credential> {
    let bad = |what: &str| failure(profile, &format!("printed {what}"));
    let identity = profile.identity();
    let (credential_of, expires_at): (Credential, Option<OffsetDateTime>) = match format {
        CommandOutput::Text => {
            let text = std::str::from_utf8(output).map_err(|_| bad("output that is not text"))?;
            let token = text.trim();
            if token.is_empty() {
                return Err(bad("nothing"));
            }
            if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(bad("more than one line or word; expected a single token"));
            }
            let expiry = jwt_expiry(token);
            (token_credential(&identity, token, expiry), expiry)
        }
        CommandOutput::Json => {
            let doc: JsonCredential =
                serde_json::from_slice(output).map_err(|_| bad("output that is not valid JSON"))?;
            let expiry = match doc.expires_at.as_deref() {
                None => None,
                Some(text) => Some(
                    OffsetDateTime::parse(text, &Rfc3339)
                        .map_err(|_| bad("an \"expires_at\" that is not an RFC 3339 time"))?,
                ),
            };
            match (doc.access_token, doc.username, doc.password) {
                (Some(token), None, None) if !token.is_empty() => {
                    (token_credential(&identity, &token, expiry), expiry)
                }
                (None, Some(user), Some(password)) if !user.is_empty() && !password.is_empty() => (
                    Credential::basic(identity, Secret::new(user), Secret::new(password)),
                    expiry,
                ),
                _ => {
                    return Err(bad(
                        "JSON without either \"access_token\" or both \"username\" and \
                         \"password\" (and not both kinds)",
                    ))
                }
            }
        }
    };
    if expires_at.is_some_and(|t| t <= now) {
        return Err(failure(
            profile,
            "returned a credential that has already expired",
        ));
    }
    Ok(credential_of)
}

fn token_credential(identity: &str, token: &str, expires_at: Option<OffsetDateTime>) -> Credential {
    Credential::oauth2(
        identity.to_string(),
        OAuthCredential {
            access_token: Secret::new(token),
            refresh_token: None,
            token_type: "bearer".into(),
            expires_at,
            scope: None,
        },
    )
}

/// Returns the `exp` of a JWT. Only the payload is read: nothing is verified, the service does
/// that. Anything that is not a JWT with a numeric `exp` has no known expiry.
pub fn jwt_expiry(token: &str) -> Option<OffsetDateTime> {
    let mut parts = token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let claims: serde_json::Value = serde_json::from_slice(&base64url_decode(payload)?).ok()?;
    let exp = claims.get("exp")?;
    let seconds = exp.as_i64().or_else(|| exp.as_f64().map(|f| f as i64))?;
    OffsetDateTime::from_unix_timestamp(seconds).ok()
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let (mut out, mut accumulator, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in input.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return None,
        } as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::config::Config;

    fn profile(format: &str) -> Profile {
        Config::parse(&format!(
            "[p]\nhost=\"h.example\"\ntype=\"process\"\n[p.process]\ncommand=[\"true\"]\n\
             command_output_format=\"{format}\"\n[p.proxy]\n\
             headers = {{ X = \"{{access_token}}\" }}\n"
        ))
        .unwrap()
        .profiles
        .remove(0)
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    /// A JWT-shaped token with the given payload JSON (the signature is not checked).
    fn jwt(payload: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in payload.as_bytes().chunks(3) {
            let n = chunk.iter().fold(0u32, |a, b| (a << 8) | *b as u32) << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        format!("aGVhZGVy.{out}.c2lnbmF0dXJl")
    }

    #[test]
    fn text_output_is_trimmed_and_a_jwt_gives_its_expiry() {
        let p = profile("text");
        let token = jwt("{\"exp\":1900000000,\"email\":\"someone@example.com\"}");
        let c = parse(
            &p,
            CommandOutput::Text,
            format!("{token}\n").as_bytes(),
            now(),
        )
        .unwrap();
        let oauth = c.oauth2.unwrap();
        assert_eq!(oauth.access_token.expose(), token);
        assert_eq!(oauth.expires_at.unwrap().unix_timestamp(), 1_900_000_000);
        // Not a JWT: no known expiry
        let c = parse(&p, CommandOutput::Text, b"opaque-token-1\n", now()).unwrap();
        assert!(c.oauth2.unwrap().expires_at.is_none());
    }

    #[test]
    fn text_output_must_be_one_token() {
        let p = profile("text");
        for bad in [
            &b""[..],
            b"\n",
            b"two words",
            b"line1\nline2\n",
            b"\xff\xfe",
        ] {
            let e = parse(&p, CommandOutput::Text, bad, now())
                .unwrap_err()
                .to_string();
            assert!(e.contains("profile \"p\""), "{e}");
        }
    }

    #[test]
    fn an_expired_credential_is_refused_without_quoting_it() {
        let p = profile("text");
        let token = jwt("{\"exp\":1700000000}");
        let e = parse(&p, CommandOutput::Text, token.as_bytes(), now())
            .unwrap_err()
            .to_string();
        assert!(e.contains("already expired") && !e.contains(&token));
    }

    #[test]
    fn json_output_holds_a_token_or_a_username_and_password() {
        let p = profile("json");
        let c = parse(
            &p,
            CommandOutput::Json,
            br#"{"access_token":"tok-1","expires_at":"2030-01-01T00:00:00Z"}"#,
            now(),
        )
        .unwrap();
        assert_eq!(c.oauth2.unwrap().access_token.expose(), "tok-1");
        let c = parse(
            &p,
            CommandOutput::Json,
            br#"{"username":"u","password":"pw"}"#,
            now(),
        )
        .unwrap();
        assert_eq!(c.basic.unwrap().password.expose(), "pw");
        for bad in [
            &br#"{}"#[..],
            br#"{"access_token":"t","username":"u","password":"p"}"#,
            br#"{"username":"u"}"#,
            br#"{"access_token":"t","expires_at":"yesterday"}"#,
            br#"{"access_token":"t","expires_at":"2020-01-01T00:00:00Z"}"#,
            b"not json",
        ] {
            let e = parse(&p, CommandOutput::Json, bad, now())
                .unwrap_err()
                .to_string();
            assert!(!e.contains("\"t\"") && !e.contains("pw"), "{e}");
        }
    }

    #[test]
    fn jwt_expiry_reads_only_the_payload() {
        assert_eq!(
            jwt_expiry(&jwt("{\"exp\":1900000000}"))
                .unwrap()
                .unix_timestamp(),
            1_900_000_000
        );
        assert!(jwt_expiry("a.b").is_none());
        assert!(jwt_expiry("a.b.c.d").is_none());
        assert!(jwt_expiry(&jwt("{\"no\":1}")).is_none());
        assert!(jwt_expiry("not-a-jwt").is_none());
    }
}
