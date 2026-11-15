// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SAML 2.0 ARTIFACT (saml-bindings-2.0-os section 3.6.4;
//! `saml2_sso.ts`'s `mintArtifact()`, `isForeignArtifact()` and
//! `stashArtifact()`): a four-byte header — TypeCode 0x0004 and the
//! EndpointIndex — the SourceID, the SHA-1 of this realm's issuer, which is
//! an INDEX and not a hash for security, and twenty random bytes of
//! MessageHandle, the one secret in it. The 44 bytes travel as base64 in
//! `SAMLart`.
//!
//! **THE STORE IS KEYED BY `credentialDigest(artifact)`, NEVER BY THE
//! ARTIFACT (#614)**, under Node's handle `saml2_sso.artifacts` with the
//! row's `expires` (ms) as its expiry, so a row Node wrote is one Rust
//! resolves and the reverse ([`row_key`], [`StoredArtifact`]). Bounded by
//! `saml2.maxArtifacts` per realm: full refuses the next one rather than
//! forget an unresolved one (STS-SAML-0110). A single cell: the handle
//! carries no cell's tag (cells are phase 9).

use base64::Engine;
use serde_json::{json, Map, Value as Json};

/// The store's handle, Node's.
pub const STORE_HANDLE: &str = "saml2_sso.artifacts";

/// The SourceID: SHA-1 of the issuer's entityID
/// (`stsCrypto.samlArtifactSourceId()`).
#[tracing::instrument(level = "debug")]
pub fn source_id(issuer: &str) -> [u8; 20] {
    sts_crypto::content_hash::sha1(issuer.as_bytes())
}

/// `mintArtifact(idpEntityId, endpointIndex)` over a given handle.
#[tracing::instrument(level = "debug", skip_all)]
pub fn artifact_of(issuer: &str, endpoint_index: u16, handle: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(44);
    bytes.extend(0x0004u16.to_be_bytes());
    bytes.extend(endpoint_index.to_be_bytes());
    bytes.extend(source_id(issuer));
    bytes.extend(handle);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `mintArtifact(idpEntityId, endpointIndex)`: twenty fresh random bytes.
#[tracing::instrument(level = "debug")]
pub fn mint(issuer: &str, endpoint_index: u16) -> String {
    let handle = sts_crypto::random::random_bytes(20).unwrap_or_default();
    artifact_of(issuer, endpoint_index, &handle)
}

/// `isForeignArtifact(artifact)`: a 44-byte type 0x0004 artifact whose
/// SourceID names an entity other than `issuer`. Anything else names no
/// SourceID and is the unknown artifact it looks like.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_foreign(artifact: &str, issuer: &str) -> bool {
    let bytes = crate::binding::node_base64(artifact);
    if bytes.len() != 44 || bytes[0..2] != [0, 4] {
        return false;
    }
    bytes[4..24] != source_id(issuer)
}

/// The row's key: `credentialDigest(artifact)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn row_key(artifact: &str) -> String {
    sts_crypto::secrets::credential_digest(artifact).unwrap_or_default()
}

/// One stored artifact, as Node writes it: `Object.assign({ expires },
/// { xml, spEntityId, issuer, inResponseTo, createdAt })`, in that order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StoredArtifact {
    /// When it stops resolving, ms.
    pub expires: i64,
    /// The message it stands for.
    pub xml: String,
    /// The service provider it was minted for.
    pub sp_entity_id: String,
    pub issuer: String,
    pub in_response_to: String,
    pub created_at: i64,
}

impl StoredArtifact {
    /// The row's JSON, Node's shape and order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn to_json(&self) -> Json {
        let mut m = Map::new();
        m.insert("expires".into(), json!(self.expires));
        m.insert("xml".into(), json!(self.xml));
        m.insert("spEntityId".into(), json!(self.sp_entity_id));
        m.insert("issuer".into(), json!(self.issuer));
        m.insert("inResponseTo".into(), json!(self.in_response_to));
        m.insert("createdAt".into(), json!(self.created_at));
        Json::Object(m)
    }

    /// A row Node (or this) wrote.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_json(v: &Json) -> Option<StoredArtifact> {
        let o = v.as_object()?;
        let text =
            |k: &str| o.get(k).and_then(Json::as_str).unwrap_or("").to_string();
        let num = |k: &str| o.get(k).and_then(Json::as_f64).unwrap_or(0.0);
        Some(StoredArtifact {
            expires: o.get("expires")?.as_f64()? as i64,
            xml: text("xml"),
            sp_entity_id: text("spEntityId"),
            issuer: text("issuer"),
            in_response_to: text("inResponseTo"),
            created_at: num("createdAt") as i64,
        })
    }
}

/// `saml2.artifactTtlS` as `stashArtifact()` reads it: a value that is
/// not a finite number of 0 or more is 300; 0 is an artifact that expires
/// the moment it is minted, a legitimate negative test.
#[tracing::instrument(level = "debug")]
pub fn usable_ttl_s(ttl: f64) -> f64 {
    if ttl.is_finite() && ttl >= 0.0 {
        ttl
    } else {
        300.0
    }
}
