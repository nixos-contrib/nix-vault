//! Reads and writes the encrypted file store exactly as the binary does (age, passphrase mode),
//! so tests can seed credentials and inspect what was saved. Fake passphrase only.

use std::{collections::BTreeMap, path::Path};

use age::{scrypt, secrecy::SecretString};

/// The passphrase every test workspace uses.
pub const PASSPHRASE: &str = "fake-store-passphrase-3e1";
/// Name of the encrypted file inside the store directory.
pub const FILE: &str = "credentials.age";

/// Decrypts `file`; `None` when it does not exist.
pub fn read_file(file: &Path) -> Option<BTreeMap<String, String>> {
    let ciphertext = std::fs::read(file).ok()?;
    let identity = scrypt::Identity::new(SecretString::from(PASSPHRASE.to_string()));
    let plaintext = age::decrypt(&identity, &ciphertext).expect("decrypt the test store");
    let document: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    Some(
        document["entries"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect(),
    )
}

/// Returns every stored entry of the store directory `dir`.
pub fn read(dir: &Path) -> BTreeMap<String, String> {
    read_file(&dir.join(FILE)).unwrap_or_default()
}

/// Replaces the entries of the store directory `dir`.
pub fn write(dir: &Path, entries: &BTreeMap<String, String>) {
    let mut recipient = scrypt::Recipient::new(SecretString::from(PASSPHRASE.to_string()));
    recipient.set_work_factor(10);
    let document = serde_json::json!({ "schema": 1, "entries": entries });
    let ciphertext = age::encrypt(&recipient, document.to_string().as_bytes()).unwrap();
    std::fs::write(dir.join(FILE), ciphertext).unwrap();
}
