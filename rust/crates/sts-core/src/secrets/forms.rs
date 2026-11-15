// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The parts of `common/secrets.js`'s cloud key management services that
//! are not an SDK call, compiled whether or not the SDKs are: the stored
//! text of a wrapped data key under each, the names each accepts, and the
//! sentence each refuses an unusable key with. A 1.x store holds these
//! forms (rust/DESIGN.md D11), so they are Node's to the byte:
//!
//! * **aws-kms**: `$dekkms$1$aws-kms$<b64url key id>$<base64 blob>`, the
//!   AAD as the encryption context `{"sts-dek": aad}`;
//! * **gcp-kms**: `…$gcp-kms$<b64url key name>$<version>:<base64>`, the AAD
//!   as the additional authenticated data;
//! * **azure-keys**: `…$azure-keys$<b64url vault/keys/name>$<version>:…`,
//!   `<base64 iv>.<base64 tag>.<base64 ct>` under an oct key's A256GCM (the
//!   AAD as its AAD) and `<base64>` under RSA-OAEP-256, whose plaintext is
//!   the data key followed by SHA-256 of the AAD.
//!
//! node's regular expressions (`/^(\d+):(.+)$/` and the rest) are written
//! out by hand: sts-core carries no regex engine, and each is one scan.

// A build without an SDK leaves that provider's helpers unused.
#![cfg_attr(
    not(all(feature = "aws", feature = "gcp", feature = "azure")),
    allow(dead_code)
)]

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;

/// The smallest RSA key `azure-keys` wraps with (`AZURE_RSA_MIN_BITS`).
pub const AZURE_RSA_MIN_BITS: usize = 3072;

/// AWS KMS's encryption context for a data key: `{ 'sts-dek': aad }`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn aws_context(aad: &str) -> (&'static str, String) {
    ("sts-dek", aad.to_string())
}

/// node's `Buffer.from(text, 'base64')`: forgiving, as node's decoder is —
/// the url-safe alphabet too, padding optional, anything else skipped, and
/// a lone trailing character dropped.
#[tracing::instrument(level = "debug", skip_all)]
pub fn node_base64(text: &str) -> Vec<u8> {
    let mut clean = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '=' => break,
            '-' => clean.push('+'),
            '_' => clean.push('/'),
            c if c.is_ascii_alphanumeric() || c == '+' || c == '/' => {
                clean.push(c)
            }
            _ => {}
        }
    }
    if clean.len() % 4 == 1 {
        clean.pop();
    }
    STANDARD_NO_PAD.decode(clean.as_bytes()).unwrap_or_default()
}

/// node's `Buffer.toString('base64')`.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// `/^projects\/[^/]+\/locations\/[^/]+\/keyRings\/[^/]+\/cryptoKeys\/
/// [^/]+$/`, `GCP_KEY_NAME`: a CryptoKey's resource name, never a version.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_gcp_key_name(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    parts.len() == 8
        && parts[0] == "projects"
        && parts[2] == "locations"
        && parts[4] == "keyRings"
        && parts[6] == "cryptoKeys"
        && [1, 3, 5, 7].iter().all(|i| !parts[*i].is_empty())
}

/// `gcpVersionOf()`: the digits after a final `/cryptoKeyVersions/`, or
/// empty.
#[tracing::instrument(level = "debug", skip_all)]
pub fn gcp_version_of(name: &str) -> String {
    const AT: &str = "/cryptoKeyVersions/";
    let Some(i) = name.rfind(AT) else {
        return String::new();
    };
    let digits = &name[i + AT.len()..];
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        digits.to_string()
    } else {
        String::new()
    }
}

/// `/^(\d+):(.+)$/` over a gcp-kms ciphertext: its version and its base64.
/// (`.` is any character but a line terminator, as in node.)
#[tracing::instrument(level = "debug", skip_all)]
pub fn gcp_body(ciphertext: &str) -> Option<(String, String)> {
    let digits: String = ciphertext
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let rest = ciphertext[digits.len()..].strip_prefix(':')?;
    if digits.is_empty() || rest.is_empty() || rest.contains(line_end) {
        return None;
    }
    Some((digits, rest.to_string()))
}

/// `/^(\d+):/`, the version alone (`isStale()`).
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn gcp_version_prefix(ciphertext: &str) -> Option<String> {
    let digits: String = ciphertext
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() || !ciphertext[digits.len()..].starts_with(':') {
        return None;
    }
    Some(digits)
}

/// `/^[A-Za-z0-9-]+$/`: a Key Vault key's name.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_azure_key_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `/^([A-Za-z0-9]+):(.+)$/` over an azure-keys ciphertext: the key
/// version it was wrapped under, and the body.
#[tracing::instrument(level = "debug", skip_all)]
pub fn azure_body(ciphertext: &str) -> Option<(String, String)> {
    let version = azure_version_prefix(ciphertext)?;
    let rest = &ciphertext[version.len() + 1..];
    if rest.is_empty() || rest.contains(line_end) {
        return None;
    }
    Some((version, rest.to_string()))
}

/// `/^([A-Za-z0-9]+):/`, the version alone (`isStale()`).
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn azure_version_prefix(ciphertext: &str) -> Option<String> {
    let version: String = ciphertext
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    if version.is_empty() || !ciphertext[version.len()..].starts_with(':') {
        return None;
    }
    Some(version)
}

/// JavaScript's line terminators, which `.` does not match.
fn line_end(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// awsKmsProvider's refusal of a key it cannot wrap with, or `None`.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn aws_key_refusal(
    key_id: &str,
    usage: Option<&str>,
    spec: Option<&str>,
    enabled: Option<bool>,
) -> Option<String> {
    if usage == Some("ENCRYPT_DECRYPT")
        && spec == Some("SYMMETRIC_DEFAULT")
        && enabled != Some(false)
    {
        return None;
    }
    Some(format!(
        "the KMS key \"{}\" is not an enabled symmetric ENCRYPT_DECRYPT key \
         ({}, {}, {}).",
        key_id,
        usage.unwrap_or("?"),
        spec.unwrap_or("?"),
        if enabled == Some(false) {
            "disabled"
        } else {
            "enabled"
        }
    ))
}

/// gcpKmsProvider's refusal of a key it cannot wrap with, or `None`.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn gcp_key_refusal(
    name: &str,
    purpose: Option<&str>,
    algorithm: Option<&str>,
    primary_state: Option<&str>,
) -> Option<String> {
    if purpose == Some("ENCRYPT_DECRYPT")
        && algorithm == Some("GOOGLE_SYMMETRIC_ENCRYPTION")
        && primary_state == Some("ENABLED")
    {
        return None;
    }
    Some(format!(
        "the Cloud KMS key \"{}\" is not an ENCRYPT_DECRYPT key of \
         GOOGLE_SYMMETRIC_ENCRYPTION with an enabled primary version ({}, \
         {}, primary {}).",
        name,
        purpose.unwrap_or("?"),
        algorithm.unwrap_or("?"),
        primary_state.unwrap_or("none")
    ))
}

/// What an Azure key is, for wrapping: `(symmetric, rsa)` by its `kty`.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn azure_kind(kty: &str) -> (bool, bool) {
    (
        kty == "oct-HSM" || kty == "oct",
        kty == "RSA" || kty == "RSA-HSM",
    )
}

/// azureKeysProvider's refusal of a key it cannot wrap with, or `None`.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn azure_key_refusal(
    name: &str,
    vault: &str,
    kty: &str,
    enabled: Option<bool>,
    ops: &[String],
    bits: usize,
) -> Option<String> {
    let (symmetric, rsa) = azure_kind(kty);
    let needs: &[&str] = if symmetric {
        &["encrypt", "decrypt"]
    } else {
        &["wrapKey", "unwrapKey"]
    };
    let allowed = needs.iter().all(|op| ops.iter().any(|o| o == op));
    if enabled != Some(false)
        && allowed
        && (symmetric || rsa)
        && !(rsa && bits < AZURE_RSA_MIN_BITS)
    {
        return None;
    }
    Some(format!(
        "the Key Vault key \"{}\" in {} is not usable to wrap data keys: it \
         must be enabled, an oct-HSM key allowing encrypt and decrypt or an \
         RSA key of at least {} bits allowing wrapKey and unwrapKey (it is \
         {}{}, {}, operations {}).",
        name,
        vault,
        AZURE_RSA_MIN_BITS,
        if kty.is_empty() { "?" } else { kty },
        if bits > 0 {
            format!(" {}-bit", bits)
        } else {
            String::new()
        },
        if enabled == Some(false) {
            "disabled"
        } else {
            "enabled"
        },
        if ops.is_empty() {
            "none".to_string()
        } else {
            ops.join(" ")
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forms_as_node_reads_them() {
        assert_eq!(node_base64("AQID"), vec![1, 2, 3]);
        assert_eq!(node_base64("AQI="), vec![1, 2]);
        assert_eq!(node_base64("AQI"), vec![1, 2]);
        assert_eq!(node_base64("-_8"), vec![0xfb, 0xff]);
        assert_eq!(node_base64("AQ ID\n"), vec![1, 2, 3]);
        assert!(is_gcp_key_name(
            "projects/p/locations/l/keyRings/r/cryptoKeys/k"
        ));
        assert!(!is_gcp_key_name(
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
        ));
        assert!(!is_gcp_key_name(
            "projects//locations/l/keyRings/r/cryptoKeys/k"
        ));
        assert_eq!(gcp_version_of("a/cryptoKeyVersions/12"), "12");
        assert_eq!(gcp_version_of("a/cryptoKeyVersions/1x"), "");
        assert_eq!(gcp_body("3:QUJD"), Some(("3".into(), "QUJD".into())));
        assert_eq!(gcp_body("3:"), None);
        assert_eq!(gcp_body(":x"), None);
        assert_eq!(gcp_version_prefix("12:x"), Some("12".into()));
        assert!(is_azure_key_name("sts-kek-1"));
        assert!(!is_azure_key_name("sts_kek"));
        assert_eq!(
            azure_body("abc123:i.t.c"),
            Some(("abc123".into(), "i.t.c".into()))
        );
        assert_eq!(azure_body(":x"), None);
        assert_eq!(
            aws_key_refusal("k", Some("SIGN_VERIFY"), None, Some(false))
                .unwrap(),
            "the KMS key \"k\" is not an enabled symmetric ENCRYPT_DECRYPT \
             key (SIGN_VERIFY, ?, disabled)."
        );
        assert!(aws_key_refusal(
            "k",
            Some("ENCRYPT_DECRYPT"),
            Some("SYMMETRIC_DEFAULT"),
            Some(true)
        )
        .is_none());
        assert!(azure_key_refusal(
            "k",
            "https://v",
            "RSA",
            Some(true),
            &["wrapKey".into(), "unwrapKey".into()],
            2048
        )
        .unwrap()
        .contains(
            "(it is RSA 2048-bit, enabled, operations wrapKey unwrapKey)"
        ));
        assert!(azure_key_refusal(
            "k",
            "https://v",
            "oct-HSM",
            None,
            &["encrypt".into(), "decrypt".into()],
            0
        )
        .is_none());
    }
}
