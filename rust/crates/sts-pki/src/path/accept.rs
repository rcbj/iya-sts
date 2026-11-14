// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE X.509 ACCEPT CHOKEPOINT (#1368): `SignaturePolicy.acceptX509Cause()`
//! over the X.509 rows of `common/crypto_impl/algorithm_registry.js`.
//!
//! A realm's `pki.acceptedSignatureAlgorithms` names registry ROWS, never
//! OIDs; empty, the default, accepts everything the path rules otherwise do.
//! A certificate's signature OID may mean more than one row — RSASSA-PSS's
//! OID names no hash — so every row it may mean counts, unless the
//! parameters named the hash. The rows are held to Node's
//! `algorithmRegistry.on('x509')` by `tests/x509_vectors.rs`; reading the
//! setting for the ambient realm is the caller's (the door's phase).

use sts_core::errors::{codes, ErrorCode};

/// One X.509 row of the registry: its id (what the setting names), its OID,
/// the node digest name where the OID fixes one, and `x509.js`'s id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub id: &'static str,
    pub oid: &'static str,
    pub hash: Option<&'static str>,
    pub x509: &'static str,
}

/// `algorithmRegistry.on('x509')`, in the registry's preference order.
pub const X509_ROWS: [Row; 43] = [
    Row {
        id: "ML-DSA-87",
        oid: "2.16.840.1.101.3.4.3.19",
        hash: None,
        x509: "ml-dsa-87",
    },
    Row {
        id: "ML-DSA-65",
        oid: "2.16.840.1.101.3.4.3.18",
        hash: None,
        x509: "ml-dsa-65",
    },
    Row {
        id: "ML-DSA-44",
        oid: "2.16.840.1.101.3.4.3.17",
        hash: None,
        x509: "ml-dsa-44",
    },
    Row {
        id: "SLH-DSA-SHAKE-256f",
        oid: "2.16.840.1.101.3.4.3.31",
        hash: None,
        x509: "slh-dsa-shake-256f",
    },
    Row {
        id: "SLH-DSA-SHAKE-256s",
        oid: "2.16.840.1.101.3.4.3.30",
        hash: None,
        x509: "slh-dsa-shake-256s",
    },
    Row {
        id: "SLH-DSA-SHAKE-192f",
        oid: "2.16.840.1.101.3.4.3.29",
        hash: None,
        x509: "slh-dsa-shake-192f",
    },
    Row {
        id: "SLH-DSA-SHAKE-192s",
        oid: "2.16.840.1.101.3.4.3.28",
        hash: None,
        x509: "slh-dsa-shake-192s",
    },
    Row {
        id: "SLH-DSA-SHAKE-128f",
        oid: "2.16.840.1.101.3.4.3.27",
        hash: None,
        x509: "slh-dsa-shake-128f",
    },
    Row {
        id: "SLH-DSA-SHAKE-128s",
        oid: "2.16.840.1.101.3.4.3.26",
        hash: None,
        x509: "slh-dsa-shake-128s",
    },
    Row {
        id: "SLH-DSA-SHA2-256f",
        oid: "2.16.840.1.101.3.4.3.25",
        hash: None,
        x509: "slh-dsa-sha2-256f",
    },
    Row {
        id: "SLH-DSA-SHA2-256s",
        oid: "2.16.840.1.101.3.4.3.24",
        hash: None,
        x509: "slh-dsa-sha2-256s",
    },
    Row {
        id: "SLH-DSA-SHA2-192f",
        oid: "2.16.840.1.101.3.4.3.23",
        hash: None,
        x509: "slh-dsa-sha2-192f",
    },
    Row {
        id: "SLH-DSA-SHA2-192s",
        oid: "2.16.840.1.101.3.4.3.22",
        hash: None,
        x509: "slh-dsa-sha2-192s",
    },
    Row {
        id: "SLH-DSA-SHA2-128f",
        oid: "2.16.840.1.101.3.4.3.21",
        hash: None,
        x509: "slh-dsa-sha2-128f",
    },
    Row {
        id: "SLH-DSA-SHA2-128s",
        oid: "2.16.840.1.101.3.4.3.20",
        hash: None,
        x509: "slh-dsa-sha2-128s",
    },
    Row {
        id: "ML-DSA-87-Ed448",
        oid: "1.3.6.1.5.5.7.6.51",
        hash: None,
        x509: "mldsa87-ed448-shake256",
    },
    Row {
        id: "ML-DSA-87-ES384",
        oid: "1.3.6.1.5.5.7.6.49",
        hash: None,
        x509: "mldsa87-ecdsa-p384-sha512",
    },
    Row {
        id: "ML-DSA-65-Ed25519",
        oid: "1.3.6.1.5.5.7.6.48",
        hash: None,
        x509: "mldsa65-ed25519-sha512",
    },
    Row {
        id: "ML-DSA-65-ES256",
        oid: "1.3.6.1.5.5.7.6.45",
        hash: None,
        x509: "mldsa65-ecdsa-p256-sha512",
    },
    Row {
        id: "ML-DSA-44-Ed25519",
        oid: "1.3.6.1.5.5.7.6.39",
        hash: None,
        x509: "mldsa44-ed25519-sha512",
    },
    Row {
        id: "ML-DSA-44-ES256",
        oid: "1.3.6.1.5.5.7.6.40",
        hash: None,
        x509: "mldsa44-ecdsa-p256-sha256",
    },
    Row {
        id: "ML-DSA-44-RSA2048-PSS-SHA256",
        oid: "1.3.6.1.5.5.7.6.37",
        hash: None,
        x509: "mldsa44-rsa2048-pss-sha256",
    },
    Row {
        id: "ML-DSA-44-RSA2048-PKCS15-SHA256",
        oid: "1.3.6.1.5.5.7.6.38",
        hash: None,
        x509: "mldsa44-rsa2048-pkcs15-sha256",
    },
    Row {
        id: "ML-DSA-65-RSA3072-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.41",
        hash: None,
        x509: "mldsa65-rsa3072-pss-sha512",
    },
    Row {
        id: "ML-DSA-65-RSA3072-PKCS15-SHA512",
        oid: "1.3.6.1.5.5.7.6.42",
        hash: None,
        x509: "mldsa65-rsa3072-pkcs15-sha512",
    },
    Row {
        id: "ML-DSA-65-RSA4096-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.43",
        hash: None,
        x509: "mldsa65-rsa4096-pss-sha512",
    },
    Row {
        id: "ML-DSA-65-RSA4096-PKCS15-SHA512",
        oid: "1.3.6.1.5.5.7.6.44",
        hash: None,
        x509: "mldsa65-rsa4096-pkcs15-sha512",
    },
    Row {
        id: "ML-DSA-65-ECDSA-P384-SHA512",
        oid: "1.3.6.1.5.5.7.6.46",
        hash: None,
        x509: "mldsa65-ecdsa-p384-sha512",
    },
    Row {
        id: "ML-DSA-87-RSA3072-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.52",
        hash: None,
        x509: "mldsa87-rsa3072-pss-sha512",
    },
    Row {
        id: "ML-DSA-87-RSA4096-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.53",
        hash: None,
        x509: "mldsa87-rsa4096-pss-sha512",
    },
    Row {
        id: "ML-DSA-87-ECDSA-P521-SHA512",
        oid: "1.3.6.1.5.5.7.6.54",
        hash: None,
        x509: "mldsa87-ecdsa-p521-sha512",
    },
    Row {
        id: "ES512",
        oid: "1.2.840.10045.4.3.4",
        hash: Some("sha512"),
        x509: "sha512-ecdsa",
    },
    Row {
        id: "ES384",
        oid: "1.2.840.10045.4.3.3",
        hash: Some("sha384"),
        x509: "sha384-ecdsa",
    },
    Row {
        id: "ES256",
        oid: "1.2.840.10045.4.3.2",
        hash: Some("sha256"),
        x509: "sha256-ecdsa",
    },
    Row {
        id: "Ed25519",
        oid: "1.3.101.112",
        hash: None,
        x509: "ed25519",
    },
    Row {
        id: "PS512",
        oid: "1.2.840.113549.1.1.10",
        hash: Some("sha512"),
        x509: "sha512-rsapss",
    },
    Row {
        id: "PS384",
        oid: "1.2.840.113549.1.1.10",
        hash: Some("sha384"),
        x509: "sha384-rsapss",
    },
    Row {
        id: "PS256",
        oid: "1.2.840.113549.1.1.10",
        hash: Some("sha256"),
        x509: "sha256-rsapss",
    },
    Row {
        id: "RS512",
        oid: "1.2.840.113549.1.1.13",
        hash: Some("sha512"),
        x509: "sha512-rsa",
    },
    Row {
        id: "RS384",
        oid: "1.2.840.113549.1.1.12",
        hash: Some("sha384"),
        x509: "sha384-rsa",
    },
    Row {
        id: "RS256",
        oid: "1.2.840.113549.1.1.11",
        hash: Some("sha256"),
        x509: "sha256-rsa",
    },
    Row {
        id: "RS1",
        oid: "1.2.840.113549.1.1.5",
        hash: Some("sha1"),
        x509: "sha1-rsa",
    },
    Row {
        id: "ECDSA-SHA1",
        oid: "1.2.840.10045.4.1",
        hash: Some("sha1"),
        x509: "sha1-ecdsa",
    },
];

/// The code a refusal by the accept list is recorded under (`LISTS.x509`).
pub const ACCEPT_CODE: ErrorCode = codes::STS_KEYS_0185;

/// `algorithmRegistry.byOid()`: the rows an OID may mean.
pub fn rows_by_oid(oid: &str) -> Vec<&'static Row> {
    X509_ROWS.iter().filter(|r| r.oid == oid).collect()
}

/// `SignaturePolicy.acceptX509Cause()`: why a list does not accept a
/// certificate's signature, from what the certificate says (`hash` from the
/// RSASSA-PSS parameters, where they gave one), or `None` where it may.
pub fn accept_x509_cause(
    oid: &str,
    hash: &str,
    accepted: &[String],
) -> Option<String> {
    if accepted.is_empty() {
        return None;
    }
    let meant = rows_by_oid(oid)
        .into_iter()
        .filter(|row| hash.is_empty() || row.hash.is_none_or(|h| h == hash));
    if meant
        .into_iter()
        .any(|row| accepted.iter().any(|a| a == row.id))
    {
        return None;
    }
    Some(format!(
        "its signature algorithm {} is not one pki.acceptedSignatureAlgorithms lists",
        oid
    ))
}

/// `SignaturePolicy.parsed()`: a list setting's members, trimmed, the empty
/// ones dropped.
pub fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|one| !one.is_empty())
        .map(str::to_string)
        .collect()
}
