// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `GET /oauth2/jwks` (`oauth2.ts`'s `sendJwks()`): the realm's published
//! keys, built as Node builds them, member for member and in Node's order.
//!
//! The list, before any filter:
//!
//! 1. the current RSA key — `kid`, `n`, `e`, and `x5c` of the certificate
//!    the realm's hierarchy issued over it (else its self-signed one), its
//!    chain, and the service Root after the chain when the chain's top
//!    certificate verifies under it (`pki.chainThroughRoot()`, through
//!    `helpers.x5cOf()`);
//! 2. every curve key (`extraKeys`) and post-quantum key (`pqKeys`);
//! 3. the RSA key's other generations (#42): the standby `jose:RS256` rows
//!    that are live — `next` first, then the retired by `retiredAt`, newest
//!    first — each with the certificate the hierarchy issued over it, then
//!    the pinned RSA signers (`helpers.ownRsaCertificates('jose')`);
//! 4. the other standby `jose` rows that are `next`, or retired with no
//!    `retiredUntil` or one still ahead;
//! 5. the signer groups' published members and the pinned non-RSA signers;
//! 6. RFC 9278 thumbprint-URI twins of everything so far, under
//!    `keys.kidFormat=jwk-thumbprint-uri`;
//! 7. the request-object encryption keys and the configured KEM keys.
//!
//! Then the signature policy (#1368) narrows it, in Node's order: the
//! post-quantum signing keys go unless `keys.postQuantumSigning`; the EdDSA
//! ones unless `keys.eddsaSigning`; a key whose algorithm the realm's sign
//! list does not admit (or, in product mode with no list, ES256K) goes, and
//! under `keys.pqcOnly` every classical key but RSA. A key marked
//! `use: "enc"` is never a signing key and always stays.
//!
//! What this module does not hold is the key material's origin: the key
//! set's blob is the caller's, as is a realm's post-quantum keys when the
//! stored set has none yet (Node generates them at the first fetch), and
//! the certificate authority's records reach it through
//! [`CertificateSources`].

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::settings::Settings;
use sts_crypto::jws_alg::{Family, JwsAlg};
use sts_crypto::keys::JwsKey;

/// What the certificate authority holds that the JWKS reads.
pub trait CertificateSources {
    /// `pki.publishedCertificateFor(realm, useCase, slot, kid)`: the
    /// certificate PEM and chain PEMs the realm's hierarchy issued.
    fn published(
        &self,
        use_case: &str,
        slot: &str,
        kid: &str,
    ) -> Option<(String, Vec<String>)>;
    /// The service Root, PEM (`pki.serviceRoot().certificatePem`).
    fn service_root_pem(&self) -> Option<String>;
    /// `pki.pinnedSignersFor(realm)` for a use case, the retired ones past
    /// `retiredUntil` already left out.
    fn pinned_signers(&self, use_case: &str) -> Vec<PinnedSigner>;
}

/// One pinned signer (#263).
#[derive(Debug, Clone, Default)]
pub struct PinnedSigner {
    pub kid: String,
    pub kind: String,
    pub certificate_pem: String,
    pub chain_pem: Vec<String>,
    pub public_jwk: Option<Json>,
}

/// The signature policy's JWKS half (`common/signature_policy.ts`), read
/// from the ambient realm's settings and the mode.
#[derive(Debug, Clone, Default)]
pub struct JwksPolicy {
    pub post_quantum: bool,
    pub eddsa: bool,
    pub pqc_only: bool,
    /// `keys.signingAlgorithms` with RS256 added, or `None`.
    pub sign_list: Option<Vec<String>>,
    /// `mode.omitsUnapprovedSigningCurves()`.
    pub product_curves: bool,
    pub thumbprint_uri_kids: bool,
    /// `keys.encryptionKemAlgs`.
    pub kem_algs: Vec<String>,
}

fn list_of(raw: &sts_core::settings::SettingValue) -> Vec<String> {
    let text = raw.as_str().to_string();
    let items: Vec<String> = if raw.as_list().is_empty() {
        text.split(',').map(str::to_string).collect()
    } else {
        raw.as_list().to_vec()
    };
    items
        .into_iter()
        .map(|one| one.trim().to_string())
        .filter(|one| !one.is_empty())
        .collect()
}

impl JwksPolicy {
    /// The policy as the settings say it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_settings(settings: &Settings, mode: &Mode) -> JwksPolicy {
        let mut list = list_of(&settings.value_of("keys.signingAlgorithms"));
        let sign_list = if list.is_empty() {
            None
        } else {
            if !list.iter().any(|one| one == "RS256") {
                list.push("RS256".into());
            }
            Some(list)
        };
        use sts_core::settings::SettingValue;
        let pq = settings.value_of("keys.postQuantumSigning");
        JwksPolicy {
            post_quantum: !matches!(pq, SettingValue::Bool(false)),
            eddsa: settings.value_of("keys.eddsaSigning").as_bool(),
            pqc_only: settings.value_of("keys.pqcOnly").as_bool(),
            kem_algs: list_of(&settings.value_of("keys.encryptionKemAlgs")),
            sign_list,
            product_curves: mode.omits_unapproved_signing_curves(),
            thumbprint_uri_kids: settings.value_of("keys.kidFormat").as_str()
                == "jwk-thumbprint-uri",
        }
    }

    fn omits_unapproved_curves(&self) -> bool {
        self.sign_list.is_none() && self.product_curves
    }

    fn listed(&self, alg: &str) -> bool {
        match &self.sign_list {
            Some(list) => alg == "none" || list.iter().any(|one| one == alg),
            None => !(alg == "ES256K" && self.omits_unapproved_curves()),
        }
    }

    fn narrowed(&self) -> bool {
        self.sign_list.is_some() || self.omits_unapproved_curves()
    }
}

fn s<'a>(jwk: &'a Json, name: &str) -> &'a str {
    jwk.get(name).and_then(Json::as_str).unwrap_or("")
}

fn is_pq_alg(alg: &str) -> bool {
    JwsAlg::by_name(alg).is_some_and(|row| row.is_post_quantum())
}

fn is_eddsa_alg(alg: &str) -> bool {
    alg == "Ed25519"
        || alg == "Ed448"
        || JwsAlg::by_name(alg).is_some_and(|row| row.family == Family::EdDsa)
}

/// `helpers.withoutPqSigningKeys()`.
fn without_pq(keys: Vec<Json>, policy: &JwksPolicy) -> Vec<Json> {
    if policy.post_quantum {
        return keys;
    }
    keys.into_iter()
        .filter(|jwk| {
            !(is_pq_alg(s(jwk, "alg"))
                || (s(jwk, "kty") == "AKP" && s(jwk, "use") != "enc"))
        })
        .collect()
}

/// `helpers.withoutEddsaSigningKeys()`.
fn without_eddsa(keys: Vec<Json>, policy: &JwksPolicy) -> Vec<Json> {
    if policy.eddsa {
        return keys;
    }
    keys.into_iter()
        .filter(|jwk| {
            !((s(jwk, "kty") == "OKP" && s(jwk, "use") != "enc")
                || is_eddsa_alg(s(jwk, "alg")))
        })
        .collect()
}

/// `signaturePolicy.publishedUnderPqcOnly()`.
fn published_under_pqc_only(jwk: &Json, policy: &JwksPolicy) -> bool {
    !policy.pqc_only
        || s(jwk, "use") == "enc"
        || s(jwk, "kty") == "AKP"
        || s(jwk, "kty") == "RSA"
}

fn algs_of_curve(crv: &str) -> Option<&'static [&'static str]> {
    Some(match crv {
        "P-256" => &["ES256"],
        "P-384" => &["ES384"],
        "P-521" => &["ES512"],
        "secp256k1" => &["ES256K"],
        "Ed25519" => &["EdDSA", "Ed25519"],
        "Ed448" => &["EdDSA", "Ed448"],
        _ => return None,
    })
}

/// `helpers.withoutUnlistedSigningKeys()`.
fn without_unlisted(keys: Vec<Json>, policy: &JwksPolicy) -> Vec<Json> {
    if !policy.narrowed() {
        if policy.pqc_only {
            return keys
                .into_iter()
                .filter(|jwk| published_under_pqc_only(jwk, policy))
                .collect();
        }
        return keys;
    }
    keys.into_iter()
        .filter(|jwk| {
            if s(jwk, "use") == "enc" {
                return true;
            }
            if !published_under_pqc_only(jwk, policy) {
                return false;
            }
            let alg = s(jwk, "alg");
            if !alg.is_empty() {
                return policy.listed(alg);
            }
            match algs_of_curve(s(jwk, "crv")) {
                None => true,
                Some(algs) => algs.iter().any(|one| policy.listed(one)),
            }
        })
        .collect()
}

/// RFC 7638's members by `kty`, as `crypto.js`'s `THUMBPRINT_MEMBERS`.
fn thumbprint_members(kty: &str) -> Option<&'static [&'static str]> {
    Some(match kty {
        "AKP" => &["alg", "kty", "pub"],
        "EC" => &["crv", "kty", "x", "y"],
        "RSA" => &["e", "kty", "n"],
        "OKP" => &["crv", "kty", "x"],
        "oct" => &["k", "kty"],
        _ => return None,
    })
}

/// `crypto.jwkThumbprintUri()`, or `None` where the key lacks a member.
#[tracing::instrument(level = "debug", skip_all)]
pub fn thumbprint_uri(jwk: &Json) -> Option<String> {
    let members = thumbprint_members(s(jwk, "kty"))?;
    let mut parts = Vec::new();
    for m in members {
        let v = jwk.get(*m).filter(|v| {
            !v.is_null() && v.as_str().is_none_or(|t| !t.is_empty())
        })?;
        parts.push(format!("{}:{}", Json::from(*m), v));
    }
    let canonical = format!("{{{}}}", parts.join(","));
    let digest = sts_crypto::jws_alg::Hash::Sha256.digest(canonical.as_bytes());
    Some(format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
        sts_crypto::b64::encode(&digest)
    ))
}

const THUMBPRINT_URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:";

/// `joseKid.withThumbprintUriEntries()`.
fn with_thumbprint_entries(list: Vec<Json>, policy: &JwksPolicy) -> Vec<Json> {
    if !policy.thumbprint_uri_kids {
        return list;
    }
    let mut twins = Vec::new();
    for jwk in &list {
        let kid = s(jwk, "kid");
        if kid.is_empty() || kid.starts_with(THUMBPRINT_URI_PREFIX) {
            continue;
        }
        if let (Some(uri), Some(object)) =
            (thumbprint_uri(jwk), jwk.as_object())
        {
            let mut copy = object.clone();
            copy.insert("kid".into(), Json::from(uri));
            twins.push(Json::Object(copy));
        }
    }
    let mut out = list;
    out.extend(twins);
    out
}

fn strip_pem(pem: &str) -> String {
    pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .split_whitespace()
        .collect()
}

fn as_pem(text: &str) -> String {
    let value = text.trim();
    if value.is_empty() {
        return String::new();
    }
    if value.contains("-----BEGIN") {
        return text.to_string();
    }
    let flat: String = value.split_whitespace().collect();
    let lines: Vec<String> = flat
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// `helpers.x5cOf()` through `pki.chainThroughRoot()`: the leaf, its
/// chain without the leaf, and the service Root when the chain's top
/// certificate verifies under it and it is not already there.
#[tracing::instrument(level = "debug", skip_all)]
pub fn x5c_of(
    certificate: &str,
    chain: &[String],
    sources: &dyn CertificateSources,
) -> Vec<String> {
    let leaf = as_pem(certificate);
    let chain: Vec<String> = chain
        .iter()
        .map(|one| as_pem(one))
        .filter(|pem| !pem.is_empty() && *pem != leaf)
        .collect();
    let mut pems: Vec<String> = if leaf.is_empty() {
        chain.clone()
    } else {
        std::iter::once(leaf).chain(chain.iter().cloned()).collect()
    };
    if let (Some(top), Some(root)) = (chain.last(), sources.service_root_pem())
    {
        if !pems.contains(&root)
            && sts_crypto::keys::certificate_signed_by(top, &root)
        {
            pems.push(root);
        }
    }
    pems.iter().map(|pem| strip_pem(pem)).collect()
}

fn rsa_jwk(kid: &str, cert_pem: &str, x5c: Vec<String>) -> Option<Json> {
    let key = JwsKey::from_pem(cert_pem).ok()?;
    let public = key.public_jwk().ok()??;
    Some(json!({
        "kty": "RSA", "use": "sig", "kid": kid,
        "n": public.get("n")?, "e": public.get("e")?,
        "x5c": x5c,
    }))
}

fn num(v: Option<&Json>) -> f64 {
    v.map_or(0.0, crate::js::to_number)
}

/// What a JWKS is built from.
pub struct JwksInputs<'a> {
    /// The realm's key set, as `keystore.js` stores it.
    pub blob: &'a Json,
    /// The post-quantum keys, when the stored set has none yet.
    pub pq_keys: Option<Vec<Json>>,
    pub sources: &'a dyn CertificateSources,
    pub policy: &'a JwksPolicy,
    pub now_ms: f64,
}

fn current_rsa(inputs: &JwksInputs<'_>) -> Result<Json, String> {
    let blob = inputs.blob;
    let self_signed = blob
        .get("certPem")
        .and_then(Json::as_str)
        .map(str::to_string)
        .or_else(|| blob.get("certB64").and_then(Json::as_str).map(as_pem))
        .ok_or("the key set holds no certificate")?;
    let born_b64 = blob
        .get("certB64")
        .and_then(Json::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| strip_pem(&self_signed));
    let kid = sts_store::key_sets::kid_of(&born_b64);
    let (cert, chain) = inputs
        .sources
        .published("jose", "RS256", &kid)
        .unwrap_or((self_signed, Vec::new()));
    let x5c = x5c_of(&cert, &chain, inputs.sources);
    // The hierarchy files a published certificate as bare base64 (once
    // Node certified the key, which product always has): read as PEM.
    rsa_jwk(&kid, &as_pem(&cert), x5c)
        .ok_or_else(|| "the RSA certificate could not be read".to_string())
}

fn standby(blob: &Json) -> Vec<Json> {
    blob.pointer("/generations/standby")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default()
}

fn standby_live(one: &Json, now: f64) -> bool {
    s(one, "role") != "retired"
        || num(one.get("retiredUntil")) <= 0.0
        || num(one.get("retiredUntil")) > now
}

/// `ownRsaCertificates('jose')` without the current row.
fn other_rsa(inputs: &JwksInputs<'_>) -> Vec<Json> {
    let mut rows: Vec<Json> = standby(inputs.blob)
        .into_iter()
        .filter(|one| s(one, "unit") == "jose:RS256")
        .filter(|one| standby_live(one, inputs.now_ms))
        .collect();
    rows.sort_by(|a, b| {
        let next = |one: &Json| i32::from(s(one, "role") != "next");
        next(a).cmp(&next(b)).then(
            num(b.get("retiredAt"))
                .partial_cmp(&num(a.get("retiredAt")))
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    let mut out = Vec::new();
    for one in rows {
        let kid = s(&one, "kid");
        let (cert, chain) = inputs
            .sources
            .published("jose", "RS256", kid)
            .unwrap_or_else(|| (s(&one, "certPem").to_string(), Vec::new()));
        let x5c = x5c_of(&cert, &chain, inputs.sources);
        if let Some(jwk) = rsa_jwk(kid, &cert, x5c) {
            out.push(jwk);
        }
    }
    for one in inputs.sources.pinned_signers("jose") {
        if one.kind != "rsa" {
            continue;
        }
        let x5c = x5c_of(&one.certificate_pem, &one.chain_pem, inputs.sources);
        if let Some(jwk) = rsa_jwk(&one.kid, &one.certificate_pem, x5c) {
            out.push(jwk);
        }
    }
    out
}

/// `helpers.groupPublishedJwks()`: the general JOSE signer groups' members.
fn group_members(inputs: &JwksInputs<'_>) -> Vec<Json> {
    let groups = inputs
        .blob
        .get("signerGroups")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for one in groups {
        let group = s(&one, "group");
        if group == "xml" || group == "browser-devices" {
            continue;
        }
        let Some(public) = one.get("publicJwk").and_then(Json::as_object)
        else {
            continue;
        };
        let mut jwk: Map<String, Json> = public.clone();
        let paired = s(&one, "kind") == "pq"
            && one.get("pairedSlot").is_some_and(|v| {
                !v.is_null() && v != &Json::Bool(false) && v != &json!("")
            });
        if !paired {
            let kid = public.get("kid").and_then(Json::as_str).unwrap_or("");
            if let Some((cert, chain)) =
                inputs.sources.published("jose", s(&one, "slot"), kid)
            {
                jwk.insert(
                    "x5c".into(),
                    json!(x5c_of(&cert, &chain, inputs.sources)),
                );
            }
        }
        out.push(Json::Object(jwk));
    }
    out
}

/// The JWK Set's `keys`, in Node's order and narrowed by the policy.
#[tracing::instrument(level = "debug", skip_all)]
pub fn jwks_keys(inputs: &JwksInputs<'_>) -> Result<Vec<Json>, String> {
    let blob = inputs.blob;
    let mut list = vec![current_rsa(inputs)?];
    let public_of = |one: &Json| one.get("publicJwk").cloned();
    for one in blob
        .get("extraKeys")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
    {
        list.extend(public_of(one));
    }
    let pq: Vec<Json> = match blob.get("pqKeys").and_then(Json::as_array) {
        Some(held) => held.clone(),
        None => inputs.pq_keys.clone().unwrap_or_default(),
    };
    for one in &pq {
        list.extend(public_of(one));
    }
    list.extend(other_rsa(inputs));
    for one in standby(blob) {
        let next = s(&one, "role") == "next";
        let until = num(one.get("retiredUntil"));
        if s(&one, "kind") != "rsa"
            && s(&one, "useCase") == "jose"
            && (next || until <= 0.0 || until > inputs.now_ms)
        {
            list.extend(public_of(&one));
        }
    }
    list.extend(group_members(inputs));
    for one in inputs.sources.pinned_signers("jose") {
        if one.kind == "rsa" {
            continue;
        }
        if let Some(Json::Object(mut jwk)) = one.public_jwk.clone() {
            jwk.insert(
                "x5c".into(),
                json!(x5c_of(
                    &one.certificate_pem,
                    &one.chain_pem,
                    inputs.sources
                )),
            );
            list.push(Json::Object(jwk));
        }
    }
    let mut list = with_thumbprint_entries(list, inputs.policy);
    for kind in ["rsa", "ec"] {
        if let Some(jwk) = blob
            .pointer(&format!("/requestObjectEncKeys/{}/publicJwk", kind))
            .filter(|j| j.is_object())
        {
            list.push(jwk.clone());
        }
    }
    // `kemEncryptionKeysFor()`: the held keys of the configured algs,
    // through `publicJweKemJwk()` (`priv` and `d` dropped).
    for one in blob
        .get("kemEncKeys")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
    {
        if !inputs.policy.kem_algs.iter().any(|a| a == s(one, "alg")) {
            continue;
        }
        if let Some(Json::Object(jwk)) = one.get("publicJwk") {
            let mut public = jwk.clone();
            public.remove("priv");
            public.remove("d");
            list.push(Json::Object(public));
        }
    }
    let list = without_pq(list, inputs.policy);
    let list = without_eddsa(list, inputs.policy);
    Ok(without_unlisted(list, inputs.policy))
}

/// The document as Node sends it: `JSON.stringify({ keys }, null, 2)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn jwks_body(keys: Vec<Json>) -> String {
    serde_json::to_string_pretty(&json!({ "keys": keys }))
        .unwrap_or_else(|_| "{}".to_string())
}

/// The certificate authority's records as the store holds them: the
/// realm's hierarchy row and the service's (`keystore.pkiFor()`), over
/// [`sts_store::key_sets::KeySets`].
pub struct StoredSources {
    pub sets: std::sync::Arc<sts_store::key_sets::KeySets>,
    pub realm: String,
    pub now_ms: f64,
}

impl CertificateSources for StoredSources {
    fn published(
        &self,
        use_case: &str,
        slot: &str,
        kid: &str,
    ) -> Option<(String, Vec<String>)> {
        self.sets
            .published_certificate_for(&self.realm, use_case, slot, kid)
    }

    fn service_root_pem(&self) -> Option<String> {
        self.sets
            .pki_row("*service")?
            .pointer("/root/certificatePem")?
            .as_str()
            .map(str::to_string)
    }

    /// `pki.pinnedSignersFor()`: the `certs` records marked pinned, the
    /// retired ones past `retiredUntil` left out. A pinned post-quantum
    /// signer's AKP key is not read here yet (its SPKI decoding is
    /// `pqcX509.decodeSpki()`), so such a signer publishes no key.
    fn pinned_signers(&self, use_case: &str) -> Vec<PinnedSigner> {
        let Some(row) = self.sets.pki_row(&self.realm) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (_, record) in row
            .get("certs")
            .and_then(Json::as_object)
            .into_iter()
            .flatten()
        {
            let meta = &record["pinnedSigner"];
            let kid = s(record, "kid");
            if record.get("pinned") != Some(&Json::Bool(true))
                || !meta.is_object()
                || kid.is_empty()
                || s(record, "useCase") != use_case
            {
                continue;
            }
            let retired = num(meta.get("retiredAt")) > 0.0;
            if retired && num(meta.get("retiredUntil")) <= self.now_ms {
                continue;
            }
            let kind = s(meta, "kind").to_string();
            let public_jwk = if kind == "pq" {
                None
            } else {
                JwsKey::from_pem(s(record, "publicKeyPem"))
                    .ok()
                    .and_then(|k| k.public_jwk().ok().flatten())
                    .and_then(|jwk| {
                        let mut jwk = jwk.as_object()?.clone();
                        jwk.insert("kid".into(), json!(kid));
                        jwk.insert("use".into(), json!("sig"));
                        if kind != "rsa" {
                            jwk.insert("alg".into(), meta["alg"].clone());
                        }
                        Some(Json::Object(jwk))
                    })
            };
            out.push(PinnedSigner {
                kid: kid.to_string(),
                kind,
                certificate_pem: s(record, "certificatePem").to_string(),
                chain_pem: record["chainPem"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Json::as_str)
                    .map(str::to_string)
                    .collect(),
                public_jwk,
            });
        }
        out
    }
}

#[cfg(test)]
mod certified_tests {
    #![allow(clippy::unwrap_used)] // tests

    use super::*;

    /// The hierarchy's certificate as the store files it: bare base64.
    struct Certified(String);

    impl CertificateSources for Certified {
        fn published(
            &self,
            _use_case: &str,
            _slot: &str,
            _kid: &str,
        ) -> Option<(String, Vec<String>)> {
            Some((self.0.clone(), Vec::new()))
        }
        fn service_root_pem(&self) -> Option<String> {
            None
        }
        fn pinned_signers(&self, _use_case: &str) -> Vec<PinnedSigner> {
            Vec::new()
        }
    }

    #[test]
    fn a_certified_rsa_key_is_published_from_bare_base64() {
        let blob = sts_store::key_sets::generate_key_set(0).unwrap();
        let bare = blob["certB64"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| strip_pem(blob["certPem"].as_str().unwrap()));
        let sources = Certified(bare.clone());
        let settings = std::sync::Arc::new(sts_core::settings::Settings::new(
            Json::Null,
            std::collections::HashMap::new(),
        ));
        let mode = sts_core::mode::Mode::shared(settings.clone());
        let policy = JwksPolicy::from_settings(&settings, &mode);
        let keys = jwks_keys(&JwksInputs {
            blob: &blob,
            pq_keys: None,
            sources: &sources,
            policy: &policy,
            now_ms: 0.0,
        })
        .unwrap();
        assert_eq!(keys[0]["kty"], "RSA");
        assert_eq!(keys[0]["x5c"][0], json!(bare));
    }
}
