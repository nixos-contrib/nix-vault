//! Secret wrappers and redaction helpers.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A secret value. It is zeroized on drop and never shown by `Debug`; there is no `Display`.
#[derive(Clone)]
pub struct Secret(SecretString);

impl Secret {
    /// Wraps `value`.
    pub fn new(value: impl Into<String>) -> Self {
        Secret(SecretString::from(value.into()))
    }

    /// Returns the secret text. Call sites should be few and deliberate.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Only used to write the credential store entry.
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Secret::new)
    }
}

/// Replaces every occurrence of each non-empty secret in `text` with `[REDACTED]`.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_string();
    // Longest first, so a secret that contains another one is replaced as a whole
    let mut sorted: Vec<&str> = secrets.iter().copied().filter(|s| !s.is_empty()).collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for secret in sorted {
        out = out.replace(secret, "[REDACTED]");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_value() {
        let secret = Secret::new("hunter2-distinct");
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert!(!format!("{:?}", Some(&secret)).contains("hunter2"));
    }

    #[test]
    fn redact_handles_repeated_and_overlapping_secrets() {
        let text = "a=token-abc b=token-abc c=abc";
        let out = redact(text, &["abc", "token-abc"]);
        assert_eq!(out, "a=[REDACTED] b=[REDACTED] c=[REDACTED]");
    }

    #[test]
    fn redact_ignores_empty_secrets() {
        assert_eq!(redact("text", &[""]), "text");
    }
}
