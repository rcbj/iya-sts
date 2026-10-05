// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! XML Signature: what the Node service's `common/crypto.js` section 1 and
//! 1a do over `common/vendored/xmldsig.js`, as one module on `sts-xml`.
//!
//! * [`sign_enveloped`] — `crypto.signXml()`: the ten SignatureMethods
//!   `saml.signatureAlgorithm` offers, each down the path Node sends it. RSA
//!   and the post-quantum rows take `signEnveloped()`'s fixed shape, ECDSA
//!   the general engine's — the two shapes differ (a namespace declaration
//!   on `SignedInfo`, the Reference's transforms, the digest's
//!   canonicalization) and both are reproduced, so an RSA signature, which
//!   is deterministic, is the same BYTES Node makes.
//! * [`verify_xml_signature`] — `crypto.verifyXmlSignature()`: the
//!   signature on ONE named element and on no other, every refusal under the
//!   code and in the words Node uses.
//! * [`sign_query_string`] / [`verify_query_string`] — the SAML HTTP Redirect
//!   binding's detached signature.
//!
//! **THE TABLES ARE NODE'S TWO, MERGED.** The vendored registry names what
//! is signed and each method's default digest; `crypto.js` adds what is
//! VERIFIED and names what is refused and why. [`signature_method`] answers
//! from the union, as the vendored engine does once `crypto.js` has
//! registered its rows.
//!
//! **ONE DELIBERATE DIFFERENCE, AND IT IS A FIX.** Node verifies from a
//! serialized copy — the `<ds:Signature>` on its own, and the signed element
//! with the signature removed — and xmldom's serializer declares only the
//! prefixes an element USES. So a prefix named in an exclusive
//! canonicalization's `InclusiveNamespaces PrefixList` and declared on an
//! ANCESTOR is lost, and a correct signature over it fails there (SAML
//! signers put `xs` in that list for `xsi:type="xs:string"`). This module
//! canonicalizes IN PLACE, where every in-scope declaration is visible, which
//! is what the signer did. Everything else is the same octets: removing the
//! signature first is what the enveloped transform is defined to do, and
//! `crypto.js` already refuses inclusive canonicalization on a nested
//! element and copies the ancestors' declarations for the `SignedInfo` — the
//! two cases where in place and detached could otherwise differ.
//!
//! A reference resolves within the signature first and then within the
//! signed element, as Node's does; it can only name the element itself,
//! because the reference check runs before.
//!
//! The XPath transforms are refused with Node's own message: xmldom has no
//! `document.evaluate`, so the service has never performed them.

use std::sync::LazyLock;

use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use openssl::bn::BigNum;
use openssl::dsa::DsaSig;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, PKeyRef, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use openssl::x509::X509;
use sts_core::errors::{codes, ErrorCode};
use sts_xml::c14n;
use sts_xml::dom::{Document, NodeId};

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{rsa_key_problem, KeyPolicy};
use crate::pq;

/// The namespaces and algorithm identifiers.
pub mod uri {
    pub const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
    pub const XENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
    pub const XMLDSIG_MORE: &str = "http://www.w3.org/2001/04/xmldsig-more#";
    pub const XMLDSIG_MORE_2007: &str =
        "http://www.w3.org/2007/05/xmldsig-more#";
    pub const XMLDSIG_MORE_2021: &str =
        "http://www.w3.org/2021/04/xmldsig-more#";
    /// draft-eastlake-rfc9231bis-xmlsec-uris' namespace — a DRAFT.
    pub const XMLDSIG_MORE_2026: &str =
        "http://www.w3.org/2026/08/xmldsig-more#";
    pub const XMLDSIG11: &str = "http://www.w3.org/2009/xmldsig11#";
    pub const C14N_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    pub const C14N_EXCLUSIVE_WC: &str =
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    pub const C14N_INCLUSIVE: &str =
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    pub const C14N_INCLUSIVE_WC: &str =
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    pub const TRANSFORM_ENVELOPED: &str =
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    pub const TRANSFORM_BASE64: &str =
        "http://www.w3.org/2000/09/xmldsig#base64";
    pub const TRANSFORM_XPATH: &str =
        "http://www.w3.org/TR/1999/REC-xpath-19991116";
    pub const TRANSFORM_XPATH_FILTER2: &str =
        "http://www.w3.org/2002/06/xmldsig-filter2";
    pub const RSA_SHA256: &str =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
    pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
    pub const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
}

use uri::*;

// ---------------------------------------------------------------------------
// The hashes.
// ---------------------------------------------------------------------------

/// A hash an XML signature or digest names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Ripemd160,
}

impl Hash {
    /// Node's name for it, which `crypto.js` keys its tables by.
    pub fn node_name(self) -> &'static str {
        match self {
            Hash::Sha1 => "sha1",
            Hash::Sha224 => "sha224",
            Hash::Sha256 => "sha256",
            Hash::Sha384 => "sha384",
            Hash::Sha512 => "sha512",
            Hash::Sha3_224 => "sha3-224",
            Hash::Sha3_256 => "sha3-256",
            Hash::Sha3_384 => "sha3-384",
            Hash::Sha3_512 => "sha3-512",
            Hash::Ripemd160 => "ripemd160",
        }
    }

    pub fn md(self) -> MessageDigest {
        match self {
            Hash::Sha1 => MessageDigest::sha1(),
            Hash::Sha224 => MessageDigest::sha224(),
            Hash::Sha256 => MessageDigest::sha256(),
            Hash::Sha384 => MessageDigest::sha384(),
            Hash::Sha512 => MessageDigest::sha512(),
            Hash::Sha3_224 => MessageDigest::sha3_224(),
            Hash::Sha3_256 => MessageDigest::sha3_256(),
            Hash::Sha3_384 => MessageDigest::sha3_384(),
            Hash::Sha3_512 => MessageDigest::sha3_512(),
            Hash::Ripemd160 => MessageDigest::ripemd160(),
        }
    }

    /// SHA-1 is governed by a setting; RIPEMD-160, of SHA-1's length, is
    /// recorded as weak and accepted.
    pub fn weak(self) -> bool {
        matches!(self, Hash::Sha1 | Hash::Ripemd160)
    }

    /// `hashLabel()`: `SHA3-256`; with `digest`, `SHA-256` and `RIPEMD-160`.
    fn label(self, digest: bool) -> String {
        let upper = self.node_name().to_uppercase();
        if !digest {
            return upper;
        }
        match self {
            Hash::Ripemd160 => "RIPEMD-160".to_string(),
            Hash::Sha3_224
            | Hash::Sha3_256
            | Hash::Sha3_384
            | Hash::Sha3_512 => upper,
            _ => upper.replacen("SHA", "SHA-", 1),
        }
    }

    fn digest_len(self) -> usize {
        self.md().size()
    }
}

// ---------------------------------------------------------------------------
// The SignatureMethods.
// ---------------------------------------------------------------------------

/// How a SignatureMethod is computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// RSASSA-PKCS1-v1_5.
    Rsa,
    /// RSASSA-PSS, MGF1 over the message digest.
    RsaPss,
    Ecdsa,
    EdDsa,
    Dsa,
    /// ML-DSA and SLH-DSA, pure, empty context.
    PostQuantum,
}

/// One SignatureMethod, as the merged registry knows it.
#[derive(Clone, Debug)]
pub struct SignatureMethod {
    pub uri: String,
    pub family: Family,
    pub hash: Option<Hash>,
    /// Node's `asymmetricKeyType` values a key must have.
    pub key_types: Vec<String>,
    /// `crypto.js`'s label.
    pub label: String,
    /// The vendored engine's label, which its own refusals quote.
    engine_label: String,
    /// The DigestMethod a new Reference pairs with it by default.
    pub default_digest: &'static str,
    /// The OpenSSL algorithm name of a post-quantum row.
    pub pq_alg: Option<&'static str>,
    /// Whether the vendored engine's own RSA path (no verifier injected)
    /// computes it: its `rsa` family, with PSS where its row says so.
    engine_rsa: Option<bool>,
    pub weak: bool,
    pub sha1: bool,
}

const PQ_SIGS: [(&str, &str, &str, &str); 15] = [
    (
        "ml-dsa-44",
        "ML-DSA-44",
        SHA256,
        "ML-DSA-44 (FIPS 204, category 2 — draft)",
    ),
    (
        "ml-dsa-65",
        "ML-DSA-65",
        SHA384,
        "ML-DSA-65 (FIPS 204, category 3 — draft)",
    ),
    (
        "ml-dsa-87",
        "ML-DSA-87",
        SHA512,
        "ML-DSA-87 (FIPS 204, category 5 — draft)",
    ),
    (
        "slh-dsa-sha2-128s",
        "SLH-DSA-SHA2-128s",
        SHA256,
        "SLH-DSA-SHA2-128s (FIPS 205, small — draft)",
    ),
    (
        "slh-dsa-sha2-128f",
        "SLH-DSA-SHA2-128f",
        SHA256,
        "SLH-DSA-SHA2-128f (FIPS 205, fast — draft)",
    ),
    (
        "slh-dsa-sha2-192s",
        "SLH-DSA-SHA2-192s",
        SHA384,
        "SLH-DSA-SHA2-192s (FIPS 205, small — draft)",
    ),
    (
        "slh-dsa-sha2-192f",
        "SLH-DSA-SHA2-192f",
        SHA384,
        "SLH-DSA-SHA2-192f (FIPS 205, fast — draft)",
    ),
    (
        "slh-dsa-sha2-256s",
        "SLH-DSA-SHA2-256s",
        SHA512,
        "SLH-DSA-SHA2-256s (FIPS 205, small — draft)",
    ),
    (
        "slh-dsa-sha2-256f",
        "SLH-DSA-SHA2-256f",
        SHA512,
        "SLH-DSA-SHA2-256f (FIPS 205, fast — draft)",
    ),
    (
        "slh-dsa-shake-128s",
        "SLH-DSA-SHAKE-128s",
        SHA256,
        "SLH-DSA-SHAKE-128s (FIPS 205, small — draft)",
    ),
    (
        "slh-dsa-shake-128f",
        "SLH-DSA-SHAKE-128f",
        SHA256,
        "SLH-DSA-SHAKE-128f (FIPS 205, fast — draft)",
    ),
    (
        "slh-dsa-shake-192s",
        "SLH-DSA-SHAKE-192s",
        SHA384,
        "SLH-DSA-SHAKE-192s (FIPS 205, small — draft)",
    ),
    (
        "slh-dsa-shake-192f",
        "SLH-DSA-SHAKE-192f",
        SHA384,
        "SLH-DSA-SHAKE-192f (FIPS 205, fast — draft)",
    ),
    (
        "slh-dsa-shake-256s",
        "SLH-DSA-SHAKE-256s",
        SHA512,
        "SLH-DSA-SHAKE-256s (FIPS 205, small — draft)",
    ),
    (
        "slh-dsa-shake-256f",
        "SLH-DSA-SHAKE-256f",
        SHA512,
        "SLH-DSA-SHAKE-256f (FIPS 205, fast — draft)",
    ),
];

/// The one stateful scheme: named, never verified.
pub const HSS_LMS_URI: &str = "http://www.w3.org/2026/08/xmldsig-more#hss-lms";

struct Row {
    uri: String,
    family: Family,
    hash: Option<Hash>,
    key_types: Vec<String>,
    label: String,
}

fn row(
    uri: String,
    family: Family,
    hash: Option<Hash>,
    key_types: &[&str],
    label: String,
) -> Row {
    Row {
        uri,
        family,
        hash,
        key_types: key_types.iter().map(|s| s.to_string()).collect(),
        label,
    }
}

/// `crypto.js`'s XML_SIGNATURE_METHODS, in its order.
fn verified_rows() -> Vec<Row> {
    let mut out = Vec::new();
    for (hash, uri) in [
        (Hash::Sha1, format!("{}rsa-sha1", DS_NS)),
        (Hash::Sha224, format!("{}rsa-sha224", XMLDSIG_MORE)),
        (Hash::Sha224, format!("{}rsa-sha224", XMLDSIG_MORE_2007)),
        (Hash::Sha256, format!("{}rsa-sha256", XMLDSIG_MORE)),
        (Hash::Sha384, format!("{}rsa-sha384", XMLDSIG_MORE)),
        (Hash::Sha512, format!("{}rsa-sha512", XMLDSIG_MORE)),
        (Hash::Ripemd160, format!("{}rsa-ripemd160", XMLDSIG_MORE)),
    ] {
        let label = format!("RSA-{}", hash.label(false));
        out.push(row(uri, Family::Rsa, Some(hash), &["rsa"], label));
    }
    for hash in [
        Hash::Sha1,
        Hash::Sha224,
        Hash::Sha256,
        Hash::Sha384,
        Hash::Sha512,
        Hash::Sha3_224,
        Hash::Sha3_256,
        Hash::Sha3_384,
        Hash::Sha3_512,
        Hash::Ripemd160,
    ] {
        out.push(row(
            format!("{}{}-rsa-MGF1", XMLDSIG_MORE_2007, hash.node_name()),
            Family::RsaPss,
            Some(hash),
            &["rsa", "rsa-pss"],
            format!("RSASSA-PSS {} with MGF1", hash.label(false)),
        ));
    }
    out.push(row(
        format!("{}rsa-pss", XMLDSIG_MORE_2007),
        Family::RsaPss,
        Some(Hash::Sha256),
        &["rsa", "rsa-pss"],
        "RSASSA-PSS with parameters (RFC 9231 section 2.3.9)".to_string(),
    ));
    for (hash, uri) in [
        (Hash::Sha1, format!("{}ecdsa-sha1", XMLDSIG_MORE)),
        (Hash::Sha224, format!("{}ecdsa-sha224", XMLDSIG_MORE)),
        (Hash::Sha256, format!("{}ecdsa-sha256", XMLDSIG_MORE)),
        (Hash::Sha384, format!("{}ecdsa-sha384", XMLDSIG_MORE)),
        (Hash::Sha512, format!("{}ecdsa-sha512", XMLDSIG_MORE)),
        (
            Hash::Sha3_224,
            format!("{}ecdsa-sha3-224", XMLDSIG_MORE_2021),
        ),
        (
            Hash::Sha3_256,
            format!("{}ecdsa-sha3-256", XMLDSIG_MORE_2021),
        ),
        (
            Hash::Sha3_384,
            format!("{}ecdsa-sha3-384", XMLDSIG_MORE_2021),
        ),
        (
            Hash::Sha3_512,
            format!("{}ecdsa-sha3-512", XMLDSIG_MORE_2021),
        ),
        (
            Hash::Ripemd160,
            format!("{}ecdsa-ripemd160", XMLDSIG_MORE_2007),
        ),
    ] {
        let label = format!("ECDSA-{}", hash.label(false));
        out.push(row(uri, Family::Ecdsa, Some(hash), &["ec"], label));
    }
    out.push(row(
        format!("{}eddsa-ed25519", XMLDSIG_MORE_2021),
        Family::EdDsa,
        None,
        &["ed25519"],
        "EdDSA Ed25519 (RFC 9231)".to_string(),
    ));
    out.push(row(
        format!("{}eddsa-ed448", XMLDSIG_MORE_2021),
        Family::EdDsa,
        None,
        &["ed448"],
        "EdDSA Ed448 (RFC 9231)".to_string(),
    ));
    out.push(row(
        format!("{}dsa-sha1", DS_NS),
        Family::Dsa,
        Some(Hash::Sha1),
        &["dsa"],
        "DSA-SHA1".to_string(),
    ));
    out.push(row(
        format!("{}dsa-sha256", XMLDSIG11),
        Family::Dsa,
        Some(Hash::Sha256),
        &["dsa"],
        "DSA-SHA256 (XMLDSig 1.1)".to_string(),
    ));
    for (suffix, alg, _, label) in PQ_SIGS {
        out.push(row(
            format!("{}{}", XMLDSIG_MORE_2026, suffix),
            Family::PostQuantum,
            None,
            &[alg.to_lowercase().as_str()],
            label.to_string(),
        ));
    }
    out
}

/// The vendored registry's own classical rows: `(uri, label, default
/// digest, the engine's RSA path)` — `Some(pss)` where its built-in RSA
/// computes the method.
const VENDORED: [(&str, &str, &str, Option<bool>); 15] = [
    (
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        "RSA-SHA1 (insecure)",
        SHA1,
        Some(false),
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "RSA-SHA256",
        SHA256,
        Some(false),
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        "RSA-SHA384",
        SHA384,
        Some(false),
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        "RSA-SHA512",
        SHA512,
        Some(false),
    ),
    (
        "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
        "RSASSA-PSS SHA-256 (RFC 9231)",
        SHA256,
        Some(true),
    ),
    (
        "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1",
        "RSASSA-PSS SHA-384 (RFC 9231)",
        SHA384,
        Some(true),
    ),
    (
        "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1",
        "RSASSA-PSS SHA-512 (RFC 9231)",
        SHA512,
        Some(true),
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
        "ECDSA-SHA1 (insecure)",
        SHA1,
        None,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        "ECDSA-SHA256",
        SHA256,
        None,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        "ECDSA-SHA384",
        SHA384,
        None,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        "ECDSA-SHA512",
        SHA512,
        None,
    ),
    (
        "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
        "HMAC-SHA1 (insecure)",
        SHA1,
        None,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
        "HMAC-SHA256 (a MAC, not a signature)",
        SHA256,
        None,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
        "HMAC-SHA384 (a MAC, not a signature)",
        SHA384,
        None,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
        "HMAC-SHA512 (a MAC, not a signature)",
        SHA512,
        None,
    ),
];

static METHODS: LazyLock<Vec<SignatureMethod>> = LazyLock::new(|| {
    verified_rows()
        .into_iter()
        .map(|r| {
            let vendored = VENDORED.iter().find(|v| v.0 == r.uri);
            let pq = PQ_SIGS
                .iter()
                .find(|p| format!("{}{}", XMLDSIG_MORE_2026, p.0) == r.uri);
            let (engine_label, default_digest, engine_rsa) =
                match (vendored, pq) {
                    (Some(v), _) => (v.1.to_string(), v.2, v.3),
                    (None, Some(p)) => (p.3.to_string(), p.2, None),
                    // Registered by crypto.js: its label, SHA-256 paired, and the
                    // engine's RSA path only for its plain `rsa` family.
                    (None, None) => (
                        r.label.clone(),
                        SHA256,
                        (r.family == Family::Rsa).then_some(false),
                    ),
                };
            let weak = r.hash.is_some_and(Hash::weak);
            let sha1 = r.hash == Some(Hash::Sha1);
            SignatureMethod {
                pq_alg: pq.map(|p| p.1),
                uri: r.uri,
                family: r.family,
                hash: r.hash,
                key_types: r.key_types,
                label: r.label,
                engine_label,
                default_digest,
                engine_rsa,
                weak,
                sha1,
            }
        })
        .collect()
});

/// A SignatureMethod this service verifies, or `None`.
pub fn signature_method(uri: &str) -> Option<&'static SignatureMethod> {
    METHODS.iter().find(|m| m.uri == uri)
}

/// Every verified SignatureMethod, in `crypto.js`'s order.
pub fn signature_methods() -> &'static [SignatureMethod] {
    &METHODS
}

/// Why a SignatureMethod is refused by name, or `None`.
pub fn refused_signature_method(method: &str) -> Option<&'static str> {
    let in_ns = |ns: &str, names: &[&str]| {
        names.iter().any(|n| format!("{}{}", ns, n) == method)
    };
    if in_ns(XMLDSIG_MORE, &["rsa-md5", "hmac-md5"]) {
        return Some("MD5 is broken and RFC 9231 says it MUST NOT be used");
    }
    if in_ns(XMLDSIG_MORE_2007, &["md2-rsa-MGF1", "md5-rsa-MGF1"]) {
        return Some("MD2 and MD5 are broken");
    }
    if in_ns(
        XMLDSIG_MORE_2007,
        &[
            "rsa-whirlpool",
            "ecdsa-whirlpool",
            "whirlpool-rsa-MGF1",
            "ripemd128-rsa-MGF1",
        ],
    ) {
        return Some(
            "Whirlpool and RIPEMD-128 are not in node's OpenSSL default \
             provider",
        );
    }
    if in_ns(
        XMLDSIG_MORE,
        &[
            "esign-sha1",
            "esign-sha224",
            "esign-sha256",
            "esign-sha384",
            "esign-sha512",
        ],
    ) {
        return Some("ESIGN has no implementation in OpenSSL");
    }
    if in_ns(
        XMLDSIG_MORE_2021,
        &["eddsa-ed25519ph", "eddsa-ed25519ctx", "eddsa-ed448ph"],
    ) {
        return Some(
            "node verifies pure EdDSA only, not the pre-hashed or context \
             variants",
        );
    }
    if method == HSS_LMS_URI {
        return Some(
            "HSS/LMS is a stateful hash-based scheme and OpenSSL 3.5 (node \
             24) has no verifier for it",
        );
    }
    None
}

// ---------------------------------------------------------------------------
// The DigestMethods.
// ---------------------------------------------------------------------------

/// The DigestMethods computed, `(uri, hash)`, in `crypto.js`'s order.
pub fn digest_methods() -> Vec<(String, Hash)> {
    vec![
        (format!("{}sha1", DS_NS), Hash::Sha1),
        (format!("{}sha224", XMLDSIG_MORE), Hash::Sha224),
        (format!("{}sha256", XENC_NS), Hash::Sha256),
        (format!("{}sha384", XMLDSIG_MORE), Hash::Sha384),
        (format!("{}sha512", XENC_NS), Hash::Sha512),
        (format!("{}sha3-224", XMLDSIG_MORE_2007), Hash::Sha3_224),
        (format!("{}sha3-256", XMLDSIG_MORE_2007), Hash::Sha3_256),
        (format!("{}sha3-384", XMLDSIG_MORE_2007), Hash::Sha3_384),
        (format!("{}sha3-512", XMLDSIG_MORE_2007), Hash::Sha3_512),
        (format!("{}ripemd160", XENC_NS), Hash::Ripemd160),
    ]
}

/// The hash a DigestMethod names, or `None`.
pub fn digest_method(uri: &str) -> Option<Hash> {
    digest_methods()
        .into_iter()
        .find(|(u, _)| u == uri)
        .map(|(_, h)| h)
}

fn refused_digest_method(uri: &str) -> Option<&'static str> {
    if uri == format!("{}md5", XMLDSIG_MORE) {
        return Some("MD5 is broken");
    }
    if uri == format!("{}whirlpool", XMLDSIG_MORE_2007) {
        return Some("Whirlpool is not in node's OpenSSL default provider");
    }
    None
}

// ---------------------------------------------------------------------------
// The policy, and the verdict before any cryptography.
// ---------------------------------------------------------------------------

/// What the mode and the settings decide.
#[derive(Clone, Copy, Debug, Default)]
pub struct XmlPolicy {
    /// `saml.allowSha1Signatures` as in force (always off in product).
    pub sha1_allowed: bool,
    /// `mode.usesBrokenAlgorithms()`: development keeps every ECDSA curve.
    pub broken_algorithms: bool,
}

/// `xmlAlgorithmVerdict()`.
#[derive(Clone, Debug, Default)]
pub struct AlgorithmVerdict {
    pub problem: String,
    pub code: Option<ErrorCode>,
    pub weak: bool,
    pub sha1: bool,
    pub label: String,
}

/// What a SignatureMethod and a set of DigestMethods amount to, before any
/// cryptography; `problem` is empty when they are verified here and the
/// policy allows them.
pub fn algorithm_verdict(
    signature: &str,
    digests: &[String],
    policy: &XmlPolicy,
) -> AlgorithmVerdict {
    let Some(sig) = signature_method(signature) else {
        let why = refused_signature_method(signature);
        return AlgorithmVerdict {
            problem: format!(
                "the SignatureMethod {} is not one this service verifies{}",
                if signature.is_empty() {
                    "(none)".to_string()
                } else {
                    format!("\"{}\"", signature)
                },
                why.map(|w| format!(": {}", w)).unwrap_or_default()
            ),
            code: Some(codes::STS_KEYS_0061),
            label: signature.to_string(),
            ..AlgorithmVerdict::default()
        };
    };
    let mut out = AlgorithmVerdict {
        weak: sig.weak,
        sha1: sig.sha1,
        label: sig.label.clone(),
        ..AlgorithmVerdict::default()
    };
    let mut sha1_digest = false;
    for uri in digests {
        let Some(hash) = digest_method(uri) else {
            out.problem = format!(
                "the DigestMethod \"{}\" is not one this service computes{}",
                uri,
                refused_digest_method(uri)
                    .map(|w| format!(": {}", w))
                    .unwrap_or_default()
            );
            out.code = Some(codes::STS_KEYS_0061);
            return out;
        };
        out.weak = out.weak || hash.weak();
        out.sha1 = out.sha1 || hash == Hash::Sha1;
        sha1_digest = sha1_digest || hash == Hash::Sha1;
    }
    if out.sha1 && !policy.sha1_allowed {
        out.problem = format!(
            "the signature uses SHA-1 ({}{}), which is weak and refused while \
             saml.allowSha1Signatures is off — and always in product mode",
            out.label,
            if sha1_digest {
                ", or a SHA-1 DigestMethod"
            } else {
                ""
            }
        );
        out.code = Some(codes::STS_KEYS_0062);
    }
    out
}

// ---------------------------------------------------------------------------
// Keys.
// ---------------------------------------------------------------------------

/// Node's `asymmetricKeyType` of a key, or `""`.
pub fn key_type<T>(key: &PKeyRef<T>) -> String {
    let named = match key.id() {
        Id::RSA => "rsa",
        Id::RSA_PSS => "rsa-pss",
        Id::EC => "ec",
        Id::ED25519 => "ed25519",
        Id::ED448 => "ed448",
        Id::DSA => "dsa",
        _ => "",
    };
    if !named.is_empty() {
        return named.to_string();
    }
    PQ_SIGS
        .iter()
        .find(|p| pq::is_a(key, p.1))
        .map(|p| p.1.to_lowercase())
        .unwrap_or_default()
}

/// A key to verify with, and the certificate's subject CN.
pub struct VerificationKey {
    pub key: PKey<Public>,
    pub subject: String,
}

fn first_cn(cert: &X509) -> String {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().to_string().ok())
        .unwrap_or_default()
}

/// `verificationKeyFrom()`: a certificate (PEM, or bare base64 DER) or a
/// public key PEM. Never panics; a problem is the `Err`.
pub fn verification_key_from(
    cert: Option<&str>,
    public_key_pem: Option<&str>,
) -> Result<VerificationKey, String> {
    if let Some(cert) = cert.filter(|c| !c.is_empty()) {
        let text = cert.trim();
        let parsed = if text.starts_with("-----BEGIN") {
            X509::from_pem(text.as_bytes()).map_err(|e| e.to_string())
        } else {
            let der: String =
                text.chars().filter(|c| !c.is_whitespace()).collect();
            decode_base64(&der)
                .ok_or_else(|| "not base64".to_string())
                .and_then(|d| X509::from_der(&d).map_err(|e| e.to_string()))
        };
        return parsed
            .and_then(|c| {
                let key = c.public_key().map_err(|e| e.to_string())?;
                Ok(VerificationKey {
                    key,
                    subject: first_cn(&c),
                })
            })
            .map_err(|e| format!("the certificate could not be read: {}", e));
    }
    if let Some(pem) = public_key_pem.filter(|p| !p.is_empty()) {
        return PKey::public_key_from_pem(pem.as_bytes())
            .map(|key| VerificationKey {
                key,
                subject: String::new(),
            })
            .map_err(|e| format!("the public key could not be read: {}", e));
    }
    Err("no certificate or public key was given".to_string())
}

/// The curves of at least 256 bits an XML ECDSA key may be on in product.
const XML_ECDSA_CURVES: [Nid; 8] = [
    Nid::X9_62_PRIME256V1,
    Nid::SECP384R1,
    Nid::SECP521R1,
    Nid::SECP256K1,
    Nid::BRAINPOOL_P256R1,
    Nid::BRAINPOOL_P320R1,
    Nid::BRAINPOOL_P384R1,
    Nid::BRAINPOOL_P512R1,
];

/// `xmlEcdsaCurveProblem()`: a curve weaker than P-256, refused in product.
pub fn ecdsa_curve_problem(
    key: &PKeyRef<Public>,
    policy: &XmlPolicy,
) -> Option<String> {
    let curve = key.ec_key().ok().and_then(|ec| ec.group().curve_name());
    if curve.is_some_and(|c| XML_ECDSA_CURVES.contains(&c))
        || policy.broken_algorithms
    {
        return None;
    }
    let name = curve
        .and_then(|c| c.short_name().ok())
        .unwrap_or("an unnamed curve");
    Some(format!(
        "an ECDSA key on {}, weaker than P-256, which verifies no XML \
         signature in product mode",
        name
    ))
}

/// Why a certificate's key can make no XML signature verified here, or
/// `None` — what a registration asks before trusting one.
pub fn xml_signature_key_problem(
    certificate: &str,
    policy: &XmlPolicy,
) -> Option<String> {
    let found = match verification_key_from(Some(certificate), None) {
        Ok(found) => found,
        Err(problem) => return Some(problem),
    };
    let kind = key_type(&found.key);
    if kind == "ec" {
        if let Some(weak) = ecdsa_curve_problem(&found.key, policy) {
            return Some(format!("its public key is {}", weak));
        }
    }
    let usable = METHODS.iter().any(|m| m.key_types.contains(&kind));
    if usable {
        return None;
    }
    Some(format!(
        "its public key is {}, which makes no XML signature this service \
         verifies",
        if kind.is_empty() {
            "of an unknown type"
        } else {
            &kind
        }
    ))
}

/// RFC 9231 section 2.3.9's RSAPSSParams, read: `(hash, salt length)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PssParameters {
    pub hash: Hash,
    pub salt_length: usize,
}

/// `pssParameters()` over a `rsa-pss` SignatureMethod element.
fn pss_parameters(
    doc: &Document,
    method: NodeId,
) -> Result<PssParameters, String> {
    let mut hash = Hash::Sha256;
    let mut salt: Option<usize> = None;
    if let Some(params) =
        first_descendant(doc, method, Some(XMLDSIG_MORE_2007), "RSAPSSParams")
    {
        if let Some(digest) =
            first_descendant(doc, params, Some(DS_NS), "DigestMethod")
        {
            hash = digest_method(attr(doc, digest, "Algorithm")).ok_or(
                "its RSAPSSParams names a DigestMethod this service does not \
                 compute",
            )?;
        }
        if let Some(mgf) = first_descendant(
            doc,
            params,
            Some(XMLDSIG_MORE_2007),
            "MaskGenerationFunction",
        ) {
            let mgf_hash =
                match first_descendant(doc, mgf, Some(DS_NS), "DigestMethod") {
                    Some(d) => digest_method(attr(doc, d, "Algorithm")),
                    None => Some(Hash::Sha256),
                };
            let mgf1 = format!("{}MGF1", XMLDSIG_MORE_2007);
            if attr(doc, mgf, "Algorithm") != mgf1 || mgf_hash != Some(hash) {
                return Err("its RSAPSSParams asks for a mask generation \
                            function other than MGF1 with the message \
                            digest, which node cannot verify"
                    .to_string());
            }
        }
        if let Some(s) =
            first_descendant(doc, params, Some(XMLDSIG_MORE_2007), "SaltLength")
        {
            match js_parse_int(doc.text(s).trim()) {
                Some(n) if n >= 0 => salt = Some(n as usize),
                _ => {
                    return Err("its RSAPSSParams SaltLength is not a number"
                        .to_string())
                }
            }
        }
        if let Some(t) = first_descendant(
            doc,
            params,
            Some(XMLDSIG_MORE_2007),
            "TrailerField",
        ) {
            if doc.text(t).trim() != "1" {
                return Err(
                    "its RSAPSSParams TrailerField is not 1".to_string()
                );
            }
        }
    }
    Ok(PssParameters {
        hash,
        salt_length: salt.unwrap_or_else(|| hash.digest_len()),
    })
}

/// JavaScript's `parseInt(s, 10)`: a leading integer, or `None` for NaN.
fn js_parse_int(s: &str) -> Option<i64> {
    let s = s.trim_start();
    let (sign, rest) = match s.strip_prefix('-') {
        Some(r) => (-1, r),
        None => (1, s.strip_prefix('+').unwrap_or(s)),
    };
    let digits: String =
        rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<i64>().ok().map(|n| sign * n)
}

/// An IEEE P1363 `r||s` value as DER, when it is exactly twice `width`.
fn p1363_to_der(signature: &[u8], width: usize, dsa: bool) -> Option<Vec<u8>> {
    if width == 0 || signature.len() != 2 * width {
        return None;
    }
    let r = BigNum::from_slice(&signature[..width]).ok()?;
    let s = BigNum::from_slice(&signature[width..]).ok()?;
    if dsa {
        DsaSig::from_private_components(r, s).ok()?.to_der().ok()
    } else {
        EcdsaSig::from_private_components(r, s).ok()?.to_der().ok()
    }
}

fn digest_verify(
    md: MessageDigest,
    key: &PKeyRef<Public>,
    octets: &[u8],
    signature: &[u8],
    padding: Option<(Padding, Option<usize>)>,
) -> bool {
    let attempt = || -> Result<bool, openssl::error::ErrorStack> {
        let mut verifier = Verifier::new(md, key)?;
        if let Some((pad, salt)) = padding {
            verifier.set_rsa_padding(pad)?;
            if let Some(salt) = salt {
                verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(
                    i32::try_from(salt).unwrap_or(i32::MAX),
                ))?;
                verifier.set_rsa_mgf1_md(md)?;
            }
        }
        verifier.verify_oneshot(signature, octets)
    };
    attempt().unwrap_or(false)
}

/// `verifyXmlSignatureValue()`: whether `signature` verifies over `octets`
/// under a method with a key. A key of the wrong type is `false` — another
/// registered certificate may be the right one — and never an error.
pub fn verify_signature_value(
    method: &SignatureMethod,
    key: &PKeyRef<Public>,
    octets: &[u8],
    signature: &[u8],
    pss: Option<PssParameters>,
    policy: &XmlPolicy,
) -> bool {
    let kind = key_type(key);
    if !method.key_types.contains(&kind) {
        return false;
    }
    if matches!(method.family, Family::Rsa | Family::RsaPss) {
        if let Ok(public) = PKey::public_key_from_der(
            &key.public_key_to_der().unwrap_or_default(),
        ) {
            // An exponent or a modulus that makes a forgery; no size floor,
            // XMLDSig has none and SAML partners still sign with 1024 bits.
            if rsa_key_problem(&public, 0, KeyPolicy::LENIENT).is_some() {
                return false;
            }
        }
    }
    if method.family == Family::Ecdsa {
        if let Some(problem) = ecdsa_curve_problem(key, policy) {
            tracing::info!(
                "{}an XML signature was refused: {}",
                sts_core::log::tag(codes::STS_KEYS_0077),
                problem
            );
            return false;
        }
    }
    let hash = method.hash.unwrap_or(Hash::Sha256);
    match method.family {
        Family::Rsa => digest_verify(
            hash.md(),
            key,
            octets,
            signature,
            Some((Padding::PKCS1, None)),
        ),
        Family::RsaPss => {
            let p = pss.unwrap_or(PssParameters {
                hash,
                salt_length: hash.digest_len(),
            });
            digest_verify(
                p.hash.md(),
                key,
                octets,
                signature,
                Some((Padding::PKCS1_PSS, Some(p.salt_length))),
            )
        }
        Family::Ecdsa | Family::Dsa => {
            let dsa = method.family == Family::Dsa;
            let width = if dsa {
                key.dsa()
                    .ok()
                    .map(|d| (d.q().num_bits() as usize).div_ceil(8))
            } else {
                key.ec_key()
                    .ok()
                    .map(|e| (e.group().order_bits() as usize).div_ceil(8))
            }
            .unwrap_or(0);
            let p1363 =
                p1363_to_der(signature, width, dsa).is_some_and(|der| {
                    digest_verify(hash.md(), key, octets, &der, None)
                });
            // A DER Ecdsa-Sig-Value where XMLDSig 1.1 asks for r||s.
            p1363
                || (signature.first() == Some(&0x30)
                    && digest_verify(hash.md(), key, octets, signature, None))
        }
        Family::EdDsa => Verifier::new_without_digest(key)
            .and_then(|mut v| v.verify_oneshot(signature, octets))
            .unwrap_or(false),
        Family::PostQuantum => method
            .pq_alg
            .and_then(|alg| {
                pq::verify_message(key, alg, octets, signature, None).ok()
            })
            .unwrap_or(false),
    }
}

// ---------------------------------------------------------------------------
// DOM helpers, each the Node function it is named for.
// ---------------------------------------------------------------------------

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let engine = GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    engine.decode(text).ok()
}

fn standard_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// `getAttribute()`, `""` when absent.
fn attr<'d>(doc: &'d Document, el: NodeId, name: &str) -> &'d str {
    doc.element(el).and_then(|e| e.attr(name)).unwrap_or("")
}

/// The first DESCENDANT (never the element itself) with a local name, in
/// any namespace or the one given: `getElementsByTagNameNS(ns, local)[0]`.
fn first_descendant(
    doc: &Document,
    el: NodeId,
    ns: Option<&str>,
    local: &str,
) -> Option<NodeId> {
    all_descendants(doc, el, ns, local).into_iter().next()
}

fn all_descendants(
    doc: &Document,
    el: NodeId,
    ns: Option<&str>,
    local: &str,
) -> Vec<NodeId> {
    doc.descendants(el)
        .into_iter()
        .skip(1)
        .filter(|&n| {
            doc.element(n).is_some_and(|e| {
                e.local == local
                    && ns.is_none_or(|ns| e.ns.as_deref() == Some(ns))
            })
        })
        .collect()
}

/// `directChildByLocal()`, optionally namespace-checked.
fn direct_child(
    doc: &Document,
    el: NodeId,
    local: &str,
    ns: Option<&str>,
) -> Option<NodeId> {
    doc.child_elements(el).into_iter().find(|&c| {
        doc.element(c).is_some_and(|e| {
            e.local == local && ns.is_none_or(|ns| e.ns.as_deref() == Some(ns))
        })
    })
}

/// `crypto.js`'s `idOf()`: the six spellings of an id, in its order.
pub fn id_of(doc: &Document, el: NodeId) -> String {
    for name in ["ID", "AssertionID", "ResponseID", "RequestID", "Id", "id"] {
        let v = attr(doc, el, name);
        if !v.is_empty() {
            return v.to_string();
        }
    }
    String::new()
}

/// The vendored engine's `idOf()`, which its general signer uses.
fn engine_id_of(doc: &Document, el: NodeId) -> String {
    for name in ["ID", "Id", "id", "AssertionID"] {
        let v = attr(doc, el, name);
        if !v.is_empty() {
            return v.to_string();
        }
    }
    String::new()
}

/// The vendored `findById()` over a subtree, the subtree's root included,
/// skipping what lies under `except`.
fn find_by_id(
    doc: &Document,
    root: NodeId,
    id: &str,
    except: Option<NodeId>,
) -> Option<NodeId> {
    doc.descendants(root).into_iter().find(|&n| {
        if except.is_some_and(|x| doc.is_within(n, x)) {
            return false;
        }
        doc.element(n).is_some_and(|e| {
            e.attrs.iter().any(|a| {
                matches!(
                    a.local.as_str(),
                    "Id" | "ID"
                        | "id"
                        | "AssertionID"
                        | "ResponseID"
                        | "RequestID"
                ) && a.value == id
            })
        })
    })
}

// ---------------------------------------------------------------------------
// Canonicalization and the transform chain.
// ---------------------------------------------------------------------------

/// The four canonicalization methods: `(exclusive, comments)`.
fn c14n_method(uri: &str) -> Option<(bool, bool)> {
    match uri {
        C14N_EXCLUSIVE => Some((true, false)),
        C14N_EXCLUSIVE_WC => Some((true, true)),
        C14N_INCLUSIVE => Some((false, false)),
        C14N_INCLUSIVE_WC => Some((false, true)),
        _ => None,
    }
}

/// `prefixSet()`: the PrefixList's names, or `None` when it names none.
fn prefix_set(list: &str) -> Option<Vec<String>> {
    let names: Vec<String> =
        list.split_whitespace().map(str::to_string).collect();
    (!names.is_empty()).then_some(names)
}

/// `canonicalizeBy()` as UTF-8 octets.
fn canonicalize_by(
    doc: &Document,
    node: NodeId,
    uri: &str,
    prefixes: Option<Vec<String>>,
    include: Option<&dyn Fn(NodeId) -> bool>,
) -> CryptoResult<Vec<u8>> {
    c14n::by_method(doc, node, uri, prefixes, include)
        .map(String::into_bytes)
        .ok_or_else(|| {
            CryptoError::new(format!(
                "Unsupported CanonicalizationMethod: {}",
                uri
            ))
        })
}

/// One `ds:Transform`, as `readTransforms()` reads it.
#[derive(Clone, Debug, Default)]
pub struct Transform {
    pub algorithm: String,
    pub prefix_list: Option<String>,
    pub has_xpath: bool,
}

fn read_transforms(doc: &Document, reference: NodeId) -> Vec<Transform> {
    let Some(container) = first_descendant(doc, reference, None, "Transforms")
    else {
        return Vec::new();
    };
    all_descendants(doc, container, None, "Transform")
        .into_iter()
        .map(|el| Transform {
            algorithm: attr(doc, el, "Algorithm").to_string(),
            prefix_list: first_descendant(doc, el, None, "InclusiveNamespaces")
                .map(|i| attr(doc, i, "PrefixList").to_string()),
            has_xpath: first_descendant(doc, el, None, "XPath").is_some(),
        })
        .collect()
}

const NO_XPATH: &str = "The XPath transforms need the DOM XPath engine \
     (document.evaluate), which this environment does not provide. They work \
     in the browser; they do not work under @xmldom/xmldom.";

/// `transformOctets()`. `removed` is a subtree outside the node-set from the
/// start: the signature Node takes out before it verifies.
fn transform_octets(
    doc: &Document,
    target: NodeId,
    transforms: &[Transform],
    signature: NodeId,
    removed: Option<NodeId>,
) -> CryptoResult<Vec<u8>> {
    let mut enveloped = false;
    let mut octets: Option<Vec<u8>> = None;
    for (i, t) in transforms.iter().enumerate() {
        let alg = t.algorithm.as_str();
        if octets.is_some() {
            return Err(CryptoError::new(format!(
                "Transform {} ({}) follows one that already produced \
                 octets. A canonicalization or the base64 transform ends the \
                 chain.",
                i + 1,
                alg
            )));
        }
        let exclude = |n: NodeId| {
            !(removed.is_some_and(|r| doc.is_within(n, r))
                || (enveloped && doc.is_within(n, signature)))
        };
        if alg == TRANSFORM_ENVELOPED {
            enveloped = true;
        } else if c14n_method(alg).is_some() {
            let prefixes = t.prefix_list.as_deref().and_then(prefix_set);
            octets = Some(canonicalize_by(
                doc,
                target,
                alg,
                prefixes,
                Some(&exclude),
            )?);
        } else if alg == TRANSFORM_BASE64 {
            let mut text = String::new();
            text_of_node_set(doc, target, &exclude, &mut text);
            octets = Some(decode_base64(&strip_ws(&text)).unwrap_or_default());
        } else if alg == TRANSFORM_XPATH {
            if !t.has_xpath {
                return Err(CryptoError::new(
                    "The XPath transform needs an expression.",
                ));
            }
            return Err(CryptoError::new(NO_XPATH));
        } else if alg == TRANSFORM_XPATH_FILTER2 {
            if t.has_xpath {
                return Err(CryptoError::new(NO_XPATH));
            }
        } else {
            return Err(CryptoError::new(format!(
                "Unsupported Transform: {}",
                alg
            )));
        }
    }
    match octets {
        Some(octets) => Ok(octets),
        None => {
            // XMLDSIG section 4.3.3.2: a node-set left over is serialized
            // with INCLUSIVE Canonical XML, omitting comments.
            let exclude = |n: NodeId| {
                !(removed.is_some_and(|r| doc.is_within(n, r))
                    || (enveloped && doc.is_within(n, signature)))
            };
            canonicalize_by(doc, target, C14N_INCLUSIVE, None, Some(&exclude))
        }
    }
}

fn text_of_node_set(
    doc: &Document,
    node: NodeId,
    include: &dyn Fn(NodeId) -> bool,
    out: &mut String,
) {
    match doc.kind(node) {
        sts_xml::dom::NodeKind::Text(t) | sts_xml::dom::NodeKind::CData(t) => {
            if include(node) {
                out.push_str(t);
            }
        }
        _ => {
            for &c in doc.children(node) {
                text_of_node_set(doc, c, include, out);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Signing.
// ---------------------------------------------------------------------------

/// Where an enveloped signature goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Placement {
    /// After the first child element named `Issuer`, else first.
    #[default]
    AfterIssuer,
    First,
    Last,
}

/// `crypto.signXml()`'s options.
#[derive(Clone, Debug, Default)]
pub struct EnvelopedOptions<'a> {
    /// The SignatureMethod; RSA-SHA256 when `None`.
    pub sig_alg: Option<&'a str>,
    /// The CanonicalizationMethod; exclusive C14N when `None`.
    pub c14n_alg: Option<&'a str>,
    /// The Reference URI; the root's id (`#id`) or `""` when `None`.
    pub ref_uri: Option<&'a str>,
    pub placement: Placement,
    /// Embedded as `ds:X509Data` unless `omit_key_info`.
    pub cert_pem: Option<&'a str>,
    pub omit_key_info: bool,
}

fn cert_pem_to_b64(pem: &str) -> String {
    strip_ws(
        &pem.replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", ""),
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// `signEnveloped()`'s `sigAlgSpec()`: the four RSA URIs it signs.
fn rsa_spec(uri: &str) -> Option<(Hash, &'static str)> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => {
            Some((Hash::Sha1, SHA1))
        }
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
            Some((Hash::Sha256, SHA256))
        }
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => {
            Some((Hash::Sha384, SHA384))
        }
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
            Some((Hash::Sha512, SHA512))
        }
        _ => None,
    }
}

/// `forgeMdFor()`, for the post-quantum rows' digest pairing.
fn md_for(uri: &str) -> Hash {
    match uri {
        SHA1 => Hash::Sha1,
        SHA384 => Hash::Sha384,
        SHA512 => Hash::Sha512,
        _ => Hash::Sha256,
    }
}

/// `c14nForAlg()`: exclusive or inclusive by substring, never comments,
/// exclusive when neither — `signEnveloped()`'s reading of the URI.
fn c14n_for_alg(alg: &str) -> &'static str {
    if alg.contains("exc-c14n") {
        C14N_EXCLUSIVE
    } else if alg.contains("xml-c14n") {
        C14N_INCLUSIVE
    } else {
        C14N_EXCLUSIVE
    }
}

fn digest_b64(hash: Hash, octets: &[u8]) -> CryptoResult<String> {
    Ok(standard_b64(&openssl::hash::hash(hash.md(), octets)?))
}

fn place(doc: &mut Document, root: NodeId, sig: NodeId, placement: Placement) {
    let before = match placement {
        Placement::Last => None,
        Placement::First => doc.children(root).first().copied(),
        Placement::AfterIssuer => {
            let issuer = doc
                .child_elements(root)
                .into_iter()
                .find(|&c| doc.element(c).is_some_and(|e| e.local == "Issuer"));
            match issuer {
                Some(i) => {
                    let kids = doc.children(root);
                    let at = kids.iter().position(|&k| k == i);
                    at.and_then(|p| kids.get(p + 1).copied())
                }
                None => doc.children(root).first().copied(),
            }
        }
    };
    doc.insert_before(root, sig, before);
}

fn text_into(doc: &mut Document, el: NodeId, text: &str) {
    let t = doc.create_text(text);
    doc.append(el, t);
}

/// The signer for a method: RSA PKCS#1 v1.5, ECDSA as `r||s`, or a pure
/// post-quantum signature.
fn sign_octets(
    method: &str,
    key: &PKeyRef<Private>,
    octets: &[u8],
) -> CryptoResult<Vec<u8>> {
    if let Some((hash, _)) = rsa_spec(method) {
        let mut signer = Signer::new(hash.md(), key)?;
        signer.set_rsa_padding(Padding::PKCS1)?;
        return Ok(signer.sign_oneshot_to_vec(octets)?);
    }
    let m = signature_method(method)
        .ok_or_else(|| CryptoError::new(format!("no signer for {}", method)))?;
    match m.family {
        Family::Ecdsa => {
            let hash = m.hash.unwrap_or(Hash::Sha256);
            let ec = key.ec_key()?;
            let width = (ec.group().order_bits() as usize).div_ceil(8);
            let der = {
                let mut signer = Signer::new(hash.md(), key)?;
                signer.sign_oneshot_to_vec(octets)?
            };
            let sig = EcdsaSig::from_der(&der)?;
            let mut out = sig.r().to_vec_padded(width as i32)?;
            out.extend(sig.s().to_vec_padded(width as i32)?);
            Ok(out)
        }
        Family::PostQuantum => {
            let alg =
                m.pq_alg.ok_or_else(|| CryptoError::new("no algorithm"))?;
            pq::sign_message(key, alg, octets, None)
        }
        _ => Err(CryptoError::new(format!(
            "{} is not a SignatureMethod this service signs with",
            method
        ))),
    }
}

/// The ten SignatureMethods `saml.signatureAlgorithm` offers, and every
/// other post-quantum row of the registry: what [`sign_enveloped`] signs.
pub fn signs_with(method: &str) -> bool {
    rsa_spec(method).is_some()
        || signature_method(method).is_some_and(|m| {
            m.family == Family::PostQuantum
                || (m.family == Family::Ecdsa
                    && VENDORED.iter().any(|v| v.0 == method))
        })
}

/// `crypto.signXml()`: an enveloped signature over the document's root.
pub fn sign_enveloped(
    xml: &str,
    key: &PKeyRef<Private>,
    o: &EnvelopedOptions,
) -> CryptoResult<String> {
    let sig_alg = o.sig_alg.unwrap_or(RSA_SHA256);
    if !signs_with(sig_alg) {
        return Err(CryptoError::new(format!(
            "{} is not a SignatureMethod this service signs with",
            sig_alg
        )));
    }
    let mut doc = Document::parse(xml).map_err(|e| {
        CryptoError::new(format!("malformed XML — cannot sign: {}", e))
    })?;
    let root = doc
        .document_element()
        .ok_or_else(|| CryptoError::new("malformed XML — cannot sign."))?;
    let ref_uri = match o.ref_uri {
        Some(r) => r.to_string(),
        None => {
            let id = id_of(&doc, root);
            if id.is_empty() {
                String::new()
            } else {
                format!("#{}", id)
            }
        }
    };
    let method = signature_method(sig_alg);
    if method.is_some_and(|m| m.family == Family::Ecdsa) {
        return sign_general(&mut doc, root, key, sig_alg, &ref_uri, o);
    }
    // signEnveloped(): RSA, and the post-quantum rows.
    let (hash, digest_uri) = match rsa_spec(sig_alg) {
        Some(spec) => spec,
        None => {
            let d = method.map_or(SHA256, |m| m.default_digest);
            (md_for(d), d)
        }
    };
    let c14n_alg = o.c14n_alg.unwrap_or(C14N_EXCLUSIVE);
    let c14n_fn = c14n_for_alg(c14n_alg);
    let digest =
        digest_b64(hash, &canonicalize_by(&doc, root, c14n_fn, None, None)?)?;
    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"{ds}\"><ds:CanonicalizationMethod \
         Algorithm=\"{c}\"/><ds:SignatureMethod Algorithm=\"{s}\"/>\
         <ds:Reference URI=\"{r}\"><ds:Transforms><ds:Transform \
         Algorithm=\"{env}\"/><ds:Transform Algorithm=\"{c}\"/>\
         </ds:Transforms><ds:DigestMethod Algorithm=\"{d}\"/>\
         <ds:DigestValue>{v}</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        ds = DS_NS,
        c = c14n_alg,
        s = sig_alg,
        r = ref_uri,
        env = TRANSFORM_ENVELOPED,
        d = digest_uri,
        v = digest
    );
    let key_info = match o.cert_pem {
        Some(cert) if !o.omit_key_info && !cert.is_empty() => format!(
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}\
             </ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
            cert_pem_to_b64(cert)
        ),
        _ => String::new(),
    };
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{}\">{}<ds:SignatureValue>\
         </ds:SignatureValue>{}</ds:Signature>",
        DS_NS, signed_info, key_info
    );
    let sig = import(&mut doc, &signature)?;
    place(&mut doc, root, sig, o.placement);
    let si = direct_child(&doc, sig, "SignedInfo", None)
        .ok_or_else(|| CryptoError::new("no SignedInfo"))?;
    let octets = canonicalize_by(&doc, si, c14n_fn, None, None)?;
    let value = sign_octets(sig_alg, key, &octets)?;
    let sv = direct_child(&doc, sig, "SignatureValue", None)
        .ok_or_else(|| CryptoError::new("no SignatureValue"))?;
    text_into(&mut doc, sv, &standard_b64(&value));
    Ok(doc.serialize())
}

fn import(doc: &mut Document, xml: &str) -> CryptoResult<NodeId> {
    let nodes = doc
        .parse_fragment(xml, &[])
        .map_err(|e| CryptoError::new(e.to_string()))?;
    nodes
        .into_iter()
        .find(|&n| doc.element(n).is_some())
        .ok_or_else(|| CryptoError::new("an empty fragment"))
}

/// The general engine's `signXml()` in enveloped mode — `crypto.signXml()`'s
/// ECDSA path: the one enveloped-signature transform (added, as the engine
/// adds it), so the Reference is digested over INCLUSIVE C14N of the
/// node-set, and the SignedInfo under the method's own comments flag.
fn sign_general(
    doc: &mut Document,
    root: NodeId,
    key: &PKeyRef<Private>,
    sig_alg: &str,
    ref_uri: &str,
    o: &EnvelopedOptions,
) -> CryptoResult<String> {
    let method = signature_method(sig_alg)
        .ok_or_else(|| CryptoError::new("no method"))?;
    let digest_uri = method.default_digest;
    let digest_hash = digest_method(digest_uri).unwrap_or(Hash::Sha256);
    let c14n_alg = o.c14n_alg.unwrap_or(C14N_EXCLUSIVE);
    if c14n_method(c14n_alg).is_none() {
        return Err(CryptoError::new(format!(
            "Unsupported CanonicalizationMethod: {}",
            c14n_alg
        )));
    }
    let ref_uri = if ref_uri.is_empty() {
        let id = engine_id_of(doc, root);
        if id.is_empty() {
            String::new()
        } else {
            format!("#{}", id)
        }
    } else {
        ref_uri.to_string()
    };
    let key_info = if o.omit_key_info {
        String::new()
    } else {
        let cert = o.cert_pem.filter(|c| !c.is_empty()).ok_or_else(|| {
            CryptoError::new(
                "KeyInfo was set to X509Data but no certificate was supplied.",
            )
        })?;
        format!(
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}\
             </ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
            cert_pem_to_b64(cert)
        )
    };
    let signed_info = format!(
        "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{c}\">\
         </ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"{s}\"/>\
         <ds:Reference URI=\"{r}\"><ds:Transforms><ds:Transform \
         Algorithm=\"{env}\"></ds:Transform></ds:Transforms>\
         <ds:DigestMethod Algorithm=\"{d}\"/><ds:DigestValue>\
         </ds:DigestValue></ds:Reference></ds:SignedInfo>",
        c = xml_escape(c14n_alg),
        s = xml_escape(sig_alg),
        r = xml_escape(&ref_uri),
        env = xml_escape(TRANSFORM_ENVELOPED),
        d = xml_escape(digest_uri)
    );
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{}\">{}<ds:SignatureValue>\
         </ds:SignatureValue>{}</ds:Signature>",
        DS_NS, signed_info, key_info
    );
    let sig = import(doc, &signature)?;
    place(doc, root, sig, o.placement);
    let transforms = [Transform {
        algorithm: TRANSFORM_ENVELOPED.to_string(),
        ..Transform::default()
    }];
    let octets = transform_octets(doc, root, &transforms, sig, None)?;
    let digest = digest_b64(digest_hash, &octets)?;
    let si = direct_child(doc, sig, "SignedInfo", None)
        .ok_or_else(|| CryptoError::new("no SignedInfo"))?;
    let dv = first_descendant(doc, si, None, "DigestValue")
        .ok_or_else(|| CryptoError::new("no DigestValue"))?;
    text_into(doc, dv, &digest);
    let si_octets = canonicalize_by(doc, si, c14n_alg, None, None)?;
    let value = sign_octets(sig_alg, key, &si_octets)?;
    let sv = direct_child(doc, sig, "SignatureValue", None)
        .ok_or_else(|| CryptoError::new("no SignatureValue"))?;
    text_into(doc, sv, &standard_b64(&value));
    Ok(doc.serialize())
}

/// `crypto.signQueryString()`: the base64 signature over the query string
/// exactly as given.
pub fn sign_query_string(
    query: &str,
    key: &PKeyRef<Private>,
    sig_alg: Option<&str>,
) -> CryptoResult<String> {
    let sig_alg = sig_alg.unwrap_or(RSA_SHA256);
    if !signs_with(sig_alg) {
        return Err(CryptoError::new(format!(
            "{} is not a SignatureMethod this service signs with",
            sig_alg
        )));
    }
    Ok(standard_b64(&sign_octets(sig_alg, key, query.as_bytes())?))
}

// ---------------------------------------------------------------------------
// Verification.
// ---------------------------------------------------------------------------

/// What to verify, and against what.
#[derive(Clone, Debug, Default)]
pub struct VerifyOptions<'a> {
    /// The local name of the element whose own signature is checked.
    pub element: &'a str,
    pub cert_pem: Option<&'a str>,
    pub public_key_pem: Option<&'a str>,
    pub policy: XmlPolicy,
}

/// `verifyXmlSignature()`'s answer. `present` apart from `ok`: no signature
/// and a wrong one are different facts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XmlVerdict {
    pub ok: bool,
    pub present: bool,
    pub why: String,
    pub code: Option<ErrorCode>,
    pub signature_valid: bool,
    pub references_valid: bool,
    pub signature_method: String,
    pub canonicalization: String,
    pub signer_subject: String,
    pub signer_cert_b64: String,
    pub reference_uri: String,
    pub digest_methods: Vec<String>,
    pub weak: bool,
    pub sha1: bool,
}

fn refused(present: bool, why: String, code: ErrorCode) -> XmlVerdict {
    XmlVerdict {
        present,
        why,
        code: Some(code),
        ..XmlVerdict::default()
    }
}

/// One Reference's outcome, as the engine reports it.
struct ReferenceOutcome {
    uri: String,
    ok: bool,
    reason: String,
}

/// `verifyXmlSignature()`: the signature on the first `element` carrying a
/// `ds:Signature` of its own, against the key the caller named — else the
/// certificate the signature carries. It answers rather than panics.
pub fn verify_xml_signature(xml: &str, o: &VerifyOptions) -> XmlVerdict {
    let wanted = o.element;
    let doc = match Document::parse(xml) {
        Ok(doc) => doc,
        Err(e) => {
            return refused(
                false,
                format!("the document is not well-formed XML: {}", e),
                codes::STS_KEYS_0007,
            )
        }
    };
    let elements = doc.descendants(Document::ROOT);
    let named: Vec<NodeId> = elements
        .iter()
        .copied()
        .filter(|&n| doc.element(n).is_some_and(|e| e.local == wanted))
        .collect();
    let found = named.iter().find_map(|&t| {
        direct_child(&doc, t, "Signature", Some(DS_NS)).map(|s| (t, s))
    });
    let Some((target, sig)) = found else {
        return refused(
            false,
            if named.is_empty() {
                format!("the document contains no <{}> at all", wanted)
            } else {
                format!("the <{}> carries no ds:Signature of its own", wanted)
            },
            codes::STS_KEYS_0008,
        );
    };

    // The reference must name THIS element.
    let signed_info = direct_child(&doc, sig, "SignedInfo", Some(DS_NS));
    let reference_uri = signed_info
        .and_then(|si| first_descendant(&doc, si, None, "Reference"))
        .map(|r| attr(&doc, r, "URI").to_string())
        .unwrap_or_default();
    let target_id = id_of(&doc, target);
    if !reference_uri.is_empty()
        && reference_uri.strip_prefix('#').unwrap_or(&reference_uri)
            != target_id
    {
        return refused(
            true,
            format!(
                "the signature on this <{}> references \"{}\" rather than \
                 the element it is attached to ({}), so it says nothing \
                 about this element",
                wanted,
                reference_uri,
                if target_id.is_empty() {
                    "which carries no id".to_string()
                } else {
                    format!("#{}", target_id)
                }
            ),
            codes::STS_KEYS_0009,
        );
    }

    // Inclusive canonicalization on a nested element is refused, as Node
    // refuses it (its octets depend on the ancestors').
    let c14n_alg = signed_info
        .and_then(|si| {
            first_descendant(&doc, si, None, "CanonicalizationMethod")
        })
        .map(|c| attr(&doc, c, "Algorithm").to_string())
        .unwrap_or_default();
    let nested = Some(target) != doc.document_element();
    if nested && !c14n_alg.is_empty() && !c14n_alg.contains("xml-exc-c14n") {
        return refused(
            true,
            format!(
                "this nested <{}> is signed with {}, an INCLUSIVE \
                 canonicalization whose digest depends on namespace \
                 declarations inherited from its ancestors. This service \
                 verifies a nested element from its own subtree and cannot \
                 reproduce those octets, so it refuses rather than \
                 reporting a failure it did not really test",
                wanted, c14n_alg
            ),
            codes::STS_KEYS_0010,
        );
    }

    // The algorithms, before any cryptography.
    let method_el = signed_info
        .and_then(|si| first_descendant(&doc, si, None, "SignatureMethod"));
    let signature_method_uri = method_el
        .map(|m| attr(&doc, m, "Algorithm").to_string())
        .unwrap_or_default();
    let reference_els = signed_info
        .map(|si| all_descendants(&doc, si, None, "Reference"))
        .unwrap_or_default();
    let digest_methods: Vec<String> = reference_els
        .iter()
        .map(|&r| {
            first_descendant(&doc, r, None, "DigestMethod")
                .map(|d| attr(&doc, d, "Algorithm").to_string())
                .unwrap_or_default()
        })
        .collect();
    let algorithms =
        algorithm_verdict(&signature_method_uri, &digest_methods, &o.policy);
    let with_algorithms = |mut v: XmlVerdict| {
        v.signature_method = signature_method_uri.clone();
        v.digest_methods = digest_methods.clone();
        v.weak = algorithms.weak;
        v.sha1 = algorithms.sha1;
        v
    };
    let pss = match (algorithms.problem.is_empty(), method_el) {
        (true, Some(m))
            if signature_method_uri
                == format!("{}rsa-pss", XMLDSIG_MORE_2007) =>
        {
            Some(pss_parameters(&doc, m))
        }
        _ => None,
    };
    if !algorithms.problem.is_empty() {
        return with_algorithms(refused(
            true,
            algorithms.problem.clone(),
            algorithms.code.unwrap_or(codes::STS_KEYS_0061),
        ));
    }
    if let Some(Err(problem)) = &pss {
        return with_algorithms(refused(
            true,
            format!("the RSASSA-PSS signature cannot be checked: {}", problem),
            codes::STS_KEYS_0061,
        ));
    }
    let pss = pss.and_then(Result::ok);
    let Some(method) = signature_method(&signature_method_uri) else {
        return with_algorithms(refused(
            true,
            algorithms.problem.clone(),
            codes::STS_KEYS_0061,
        ));
    };

    // The key, in the order a caller meant.
    let key_info_cert = first_descendant(&doc, sig, None, "X509Certificate")
        .map(|c| strip_ws(&doc.text(c)))
        .unwrap_or_default();
    let cert_pem = o.cert_pem.filter(|c| !c.is_empty());
    let public_key_pem = o.public_key_pem.filter(|p| !p.is_empty());
    let key = if cert_pem.is_some()
        || public_key_pem.is_some()
        || !key_info_cert.is_empty()
    {
        let cert = cert_pem.or(if public_key_pem.is_some() {
            None
        } else {
            Some(key_info_cert.as_str())
        });
        match verification_key_from(cert, public_key_pem) {
            Ok(k) => Some(k),
            Err(problem) => {
                let mut v = with_algorithms(refused(
                    true,
                    format!("the signature cannot be checked: {}", problem),
                    codes::STS_KEYS_0014,
                ));
                v.signer_cert_b64 = key_info_cert;
                return v;
            }
        }
    } else {
        None
    };

    // The engine's own checks.
    let mut verdict = with_algorithms(XmlVerdict {
        present: true,
        reference_uri: reference_uri.clone(),
        ..XmlVerdict::default()
    });
    let engine_si = direct_child(&doc, sig, "SignedInfo", None);
    let engine_sv = direct_child(&doc, sig, "SignatureValue", None);
    let (Some(si), Some(sv)) = (engine_si, engine_sv) else {
        verdict.signature_method = String::new();
        verdict.why =
            "The Signature has no SignedInfo or no SignatureValue.".to_string();
        verdict.code = Some(codes::STS_KEYS_0014);
        return verdict;
    };
    let cm = first_descendant(&doc, si, None, "CanonicalizationMethod");
    let engine_c14n = match cm {
        Some(c) => attr(&doc, c, "Algorithm").to_string(),
        None => C14N_EXCLUSIVE.to_string(),
    };
    verdict.canonicalization = engine_c14n.clone();
    if c14n_method(&engine_c14n).is_none() {
        verdict.why =
            format!("Unsupported CanonicalizationMethod: {}", engine_c14n);
        verdict.code = Some(codes::STS_KEYS_0014);
        return verdict;
    }
    let cm_prefixes = cm
        .and_then(|c| first_descendant(&doc, c, None, "InclusiveNamespaces"))
        .and_then(|i| prefix_set(attr(&doc, i, "PrefixList")));
    let si_octets = canonicalize_by(&doc, si, &engine_c14n, cm_prefixes, None)
        .unwrap_or_default();
    let signature_bytes =
        decode_base64(&strip_ws(&doc.text(sv))).unwrap_or_default();
    let (signature_valid, signature_error) = match &key {
        Some(k) => (
            verify_signature_value(
                method,
                &k.key,
                &si_octets,
                &signature_bytes,
                pss,
                &o.policy,
            ),
            None,
        ),
        None => {
            engine_rsa_verify(&doc, sig, method, &si_octets, &signature_bytes)
        }
    };

    // The references.
    let mut references = Vec::new();
    for &r in &reference_els {
        references.push(check_reference(&doc, r, sig, target));
    }
    let references_valid =
        !references.is_empty() && references.iter().all(|r| r.ok);
    verdict.ok = signature_valid && references_valid;
    verdict.signature_valid = signature_valid;
    verdict.references_valid = references_valid;
    if let Some(k) = &key {
        verdict.signer_subject = k.subject.clone();
        verdict.signer_cert_b64 = key_info_cert;
    }
    if let Some(first) = references.first() {
        verdict.reference_uri = first.uri.clone();
    }
    if !verdict.ok {
        let first = references.first();
        if !signature_valid {
            verdict.code = Some(codes::STS_KEYS_0012);
            verdict.why = format!(
                "the signature value does not verify against the expected \
                 certificate{}",
                signature_error
                    .map(|e| format!(": {}", e))
                    .unwrap_or_default()
            );
        } else if first.is_some_and(|f| !f.ok) {
            let reason = first.map(|f| f.reason.clone()).unwrap_or_default();
            verdict.code = Some(codes::STS_KEYS_0013);
            verdict.why = format!(
                "the signature value is genuine but the digest does not \
                 match, so the <{}> was altered after it was signed{}",
                wanted,
                if reason.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", reason)
                }
            );
        } else {
            verdict.code = Some(codes::STS_KEYS_0014);
            verdict.why = "the signature did not verify".to_string();
        }
    }
    verdict
}

/// One Reference: resolved within the signature first and then within the
/// signed element (whose own signature Node removes before it looks).
fn check_reference(
    doc: &Document,
    reference: NodeId,
    sig: NodeId,
    target: NodeId,
) -> ReferenceOutcome {
    let uri = attr(doc, reference, "URI").to_string();
    let fail = |reason: String| ReferenceOutcome {
        uri: uri.clone(),
        ok: false,
        reason,
    };
    let digest_uri = first_descendant(doc, reference, None, "DigestMethod")
        .map(|d| attr(doc, d, "Algorithm").to_string())
        .unwrap_or_default();
    let declared = first_descendant(doc, reference, None, "DigestValue")
        .map(|d| strip_ws(&doc.text(d)))
        .unwrap_or_default();
    let bare = uri.strip_prefix('#').unwrap_or(&uri);
    let (resolved, removed) = if uri.is_empty() {
        (Some(target), Some(sig))
    } else {
        match find_by_id(doc, sig, bare, None) {
            Some(n) => (Some(n), None),
            None => (find_by_id(doc, target, bare, Some(sig)), Some(sig)),
        }
    };
    let Some(resolved) = resolved else {
        // error-code: none — one Reference's outcome; the verdict
        // carries STS-KEYS-0013 or STS-KEYS-0014 for it.
        return fail("the referenced element was not found".to_string());
    };
    let transforms = read_transforms(doc, reference);
    let octets =
        match transform_octets(doc, resolved, &transforms, sig, removed) {
            Ok(o) => o,
            // error-code: none — one Reference's outcome; the verdict
            // carries STS-KEYS-0013 or STS-KEYS-0014 for it.
            Err(e) => return fail(e.to_string()),
        };
    let Some(hash) = digest_method(&digest_uri) else {
        // error-code: none — one Reference's outcome; the verdict
        // carries STS-KEYS-0013 or STS-KEYS-0014 for it.
        return fail(format!("Unsupported DigestMethod: {}", digest_uri));
    };
    let computed = match hash_b64(hash, &octets) {
        Some(c) => c,
        // error-code: none — one Reference's outcome; the verdict
        // carries STS-KEYS-0013 or STS-KEYS-0014 for it.
        None => return fail("the digest could not be computed".to_string()),
    };
    if computed == declared {
        ReferenceOutcome {
            uri,
            ok: true,
            reason: String::new(),
        }
    } else {
        fail("the digest does not match".to_string())
    }
}

fn hash_b64(h: Hash, octets: &[u8]) -> Option<String> {
    hash(h.md(), octets).ok().map(|d| standard_b64(&d))
}

/// The vendored engine's own RSA path, taken only when no key was named and
/// the signature carries no certificate: an `RSAKeyValue` from the document
/// itself, for the methods its built-in RSA computes. A key with no identity
/// in it — what the engine did, kept rather than widened.
fn engine_rsa_verify(
    doc: &Document,
    sig: NodeId,
    method: &SignatureMethod,
    octets: &[u8],
    signature: &[u8],
) -> (bool, Option<String>) {
    let Some(pss) = method.engine_rsa else {
        return (
            false,
            Some(format!(
                "A {} SignatureMethod needs a verifier — this module \
                 implements RSA only, on purpose. Pass opts.verifier.{}",
                method.engine_label,
                if method.family == Family::PostQuantum {
                    " The post-quantum engines are client/src/pqc.js (ML-DSA \
                     and SLH-DSA) and client/src/hbs.js (HSS/LMS); this file \
                     holds the identifiers and not the lattice."
                } else {
                    ""
                }
            )),
        );
    };
    let key = first_descendant(doc, sig, None, "RSAKeyValue").and_then(|kv| {
        let modulus = first_descendant(doc, kv, None, "Modulus")?;
        let exponent = first_descendant(doc, kv, None, "Exponent")?;
        let n =
            BigNum::from_slice(&decode_base64(&strip_ws(&doc.text(modulus)))?)
                .ok()?;
        let e =
            BigNum::from_slice(&decode_base64(&strip_ws(&doc.text(exponent)))?)
                .ok()?;
        PKey::from_rsa(Rsa::from_public_components(n, e).ok()?).ok()
    });
    let Some(key) = key else {
        return (false, Some("No RSA public key to verify with.".to_string()));
    };
    let hash = method.hash.unwrap_or(Hash::Sha256);
    let padding = if pss {
        (Padding::PKCS1_PSS, Some(hash.digest_len()))
    } else {
        (Padding::PKCS1, None)
    };
    (
        digest_verify(hash.md(), &key, octets, signature, Some(padding)),
        None,
    )
}

/// `crypto.verifyQueryString()`'s answer: `usable` apart from `ok` — "this
/// signature is wrong" and "this could not be checked" are refused under
/// different codes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryVerdict {
    pub ok: bool,
    pub usable: bool,
    pub signature_method: String,
    pub signer_subject: String,
    pub why: String,
    pub code: Option<ErrorCode>,
    pub weak: bool,
    pub sha1: bool,
}

/// `crypto.verifyQueryString()`: a service provider's HTTP Redirect binding
/// signature over the query string as it arrived.
pub fn verify_query_string(
    query: &str,
    signature: Option<&str>,
    sig_alg: &str,
    cert_pem: Option<&str>,
    policy: &XmlPolicy,
) -> QueryVerdict {
    let unusable = |why: &str, code: ErrorCode| QueryVerdict {
        signature_method: sig_alg.to_string(),
        why: why.to_string(),
        code: Some(code),
        ..QueryVerdict::default()
    };
    let Some(cert_pem) = cert_pem.filter(|c| !c.is_empty()) else {
        return unusable(
            "no certificate was given to verify the detached signature \
             against",
            codes::STS_KEYS_0060,
        );
    };
    let Some(signature) = signature.filter(|s| !s.is_empty()) else {
        return unusable(
            "there is no Signature parameter",
            codes::STS_KEYS_0060,
        );
    };
    let algorithms = algorithm_verdict(sig_alg, &[], policy);
    if !algorithms.problem.is_empty() {
        let mut v = unusable(
            &algorithms.problem,
            algorithms.code.unwrap_or(codes::STS_KEYS_0061),
        );
        v.weak = algorithms.weak;
        v.sha1 = algorithms.sha1;
        return v;
    }
    let found = match verification_key_from(Some(cert_pem), None) {
        Ok(f) => f,
        Err(problem) => return unusable(&problem, codes::STS_KEYS_0060),
    };
    let signature = strip_ws(signature);
    let base64_shape = signature
        .trim_end_matches('=')
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        && signature.len() - signature.trim_end_matches('=').len() <= 2;
    if !base64_shape {
        return unusable(
            "the Signature parameter is not base64",
            codes::STS_KEYS_0060,
        );
    }
    if signature.is_empty() {
        return unusable(
            "No Signature parameter to verify.",
            codes::STS_KEYS_0060,
        );
    }
    let Some(method) = signature_method(sig_alg) else {
        return unusable(&algorithms.problem, codes::STS_KEYS_0061);
    };
    let bytes = decode_base64(&signature).unwrap_or_default();
    if verify_signature_value(
        method,
        &found.key,
        query.as_bytes(),
        &bytes,
        None,
        policy,
    ) {
        return QueryVerdict {
            ok: true,
            usable: true,
            signature_method: sig_alg.to_string(),
            signer_subject: found.subject,
            why: String::new(),
            code: None,
            weak: algorithms.weak,
            sha1: algorithms.sha1,
        };
    }
    QueryVerdict {
        ok: false,
        usable: true,
        signature_method: sig_alg.to_string(),
        signer_subject: String::new(),
        why: "the Signature parameter does not verify against the \
              certificate over the parameters as they arrived"
            .to_string(),
        code: Some(codes::STS_KEYS_0059),
        weak: algorithms.weak,
        sha1: algorithms.sha1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_labels_are_node_s() {
        assert_eq!(Hash::Sha256.label(false), "SHA256");
        assert_eq!(Hash::Sha256.label(true), "SHA-256");
        assert_eq!(Hash::Sha3_256.label(true), "SHA3-256");
        assert_eq!(Hash::Ripemd160.label(true), "RIPEMD-160");
        assert_eq!(Hash::Ripemd160.label(false), "RIPEMD160");
    }

    #[test]
    fn the_registry() {
        assert_eq!(signature_methods().len(), 47);
        let rsa = signature_method(RSA_SHA256).unwrap();
        assert_eq!(rsa.label, "RSA-SHA256");
        assert_eq!(rsa.engine_label, "RSA-SHA256");
        let pq = signature_method(
            "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65",
        )
        .unwrap();
        assert_eq!(pq.key_types, vec!["ml-dsa-65".to_string()]);
        assert_eq!(pq.default_digest, SHA384);
        assert!(signature_method(HSS_LMS_URI).is_none());
        assert!(refused_signature_method(HSS_LMS_URI).is_some());
        assert!(signs_with(RSA_SHA256));
        assert!(!signs_with(
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
        ));
    }

    #[test]
    fn sha1_is_a_policy() {
        let off = XmlPolicy::default();
        let v = algorithm_verdict(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            &[SHA256.to_string()],
            &off,
        );
        assert_eq!(v.code, Some(codes::STS_KEYS_0062));
        let on = XmlPolicy {
            sha1_allowed: true,
            ..off
        };
        let v = algorithm_verdict(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            &[SHA1.to_string()],
            &on,
        );
        assert!(v.problem.is_empty() && v.weak && v.sha1);
    }

    #[test]
    fn parse_int_is_javascript_s() {
        assert_eq!(js_parse_int("32"), Some(32));
        assert_eq!(js_parse_int("  20abc"), Some(20));
        assert_eq!(js_parse_int("-1"), Some(-1));
        assert_eq!(js_parse_int("x"), None);
    }

    #[test]
    fn rsa_round_trip_in_every_placement() {
        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();
        let public =
            String::from_utf8(key.public_key_to_pem().unwrap()).unwrap();
        let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"><saml:Issuer>me</saml:Issuer><saml:Subject>x</saml:Subject></saml:Assertion>"#;
        for placement in
            [Placement::AfterIssuer, Placement::First, Placement::Last]
        {
            let signed = sign_enveloped(
                xml,
                &key,
                &EnvelopedOptions {
                    placement,
                    ..EnvelopedOptions::default()
                },
            )
            .unwrap();
            let v = verify_xml_signature(
                &signed,
                &VerifyOptions {
                    element: "Assertion",
                    public_key_pem: Some(&public),
                    ..VerifyOptions::default()
                },
            );
            assert!(v.ok, "{:?}: {}", placement, v.why);
            let tampered = signed.replace(">x<", ">y<");
            let v = verify_xml_signature(
                &tampered,
                &VerifyOptions {
                    element: "Assertion",
                    public_key_pem: Some(&public),
                    ..VerifyOptions::default()
                },
            );
            assert_eq!(v.code, Some(codes::STS_KEYS_0013));
        }
    }
}
