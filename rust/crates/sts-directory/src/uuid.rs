// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `entryUUID` (RFC 4530): what never changes about an entry, and what a
//! person's `sub` is (`urn:uuid:<entryUUID>`). A seeded entry's, and a
//! restored row's that has none, is a name-based (version 5, RFC 9562
//! section 5.5) UUID over the realm and the store key under
//! `ENTRY_UUID_NAMESPACE`, so every process computes the same one; every
//! other entry's is random (version 4). The SHA-1 is `sts_crypto`'s, the one
//! place this service hashes.

const ENTRY_UUID_NAMESPACE: [u8; 16] = [
    0x3b, 0x2f, 0x8c, 0x4e, 0x6d, 0x1a, 0x4e, 0x9f, 0x8a, 0x7c, 0x5d, 0x2e,
    0x1f, 0x0b, 0x9a, 0x86,
];

/// `nameBasedUuid()`.
#[tracing::instrument(level = "debug")]
pub fn name_based_uuid(name: &str) -> String {
    let mut input = ENTRY_UUID_NAMESPACE.to_vec();
    input.extend_from_slice(name.as_bytes());
    let hash = sts_crypto::content_hash::sha1(&input);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// `backfilledEntryUuid()`: over the realm (the default when empty) and
/// the store key.
#[tracing::instrument(level = "debug")]
pub fn backfilled_entry_uuid(realm: &str, key: &str) -> String {
    let realm = if realm.is_empty() { "default" } else { realm };
    name_based_uuid(&format!("{realm}\n{key}"))
}

/// `UUID_SHAPED`, in either case.
// A HOT PATH: asked of every subject resolved, so no span.
pub fn uuid_shaped(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(g, n)| {
            g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

/// `DN_SHAPED`: `/^[A-Za-z][A-Za-z0-9-]*=/`.
// A HOT PATH, as `uuid_shaped()`.
pub fn dn_shaped(text: &str) -> bool {
    let mut chars = text.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    for c in chars {
        if c == '=' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    false
}

/// `DID_SHAPED`: `/^did:[a-z0-9]+:/i`.
// A HOT PATH, as `uuid_shaped()`.
pub fn did_shaped(text: &str) -> bool {
    let lower = text.to_lowercase();
    let Some(rest) = lower.strip_prefix("did:") else {
        return false;
    };
    match rest.find(':') {
        Some(at) if at > 0 => {
            rest[..at].bytes().all(|b| b.is_ascii_alphanumeric())
        }
        _ => false,
    }
}
