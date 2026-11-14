// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! GUARD 3. EVERY CRYPTOGRAPHIC OPERATION IS THE CRYPTO MODULE'S (#453;
//! rcbj, 2026-10-05: "All crypto operations across all protocols and use
//! cases are to be centralized in a common module" — hashes, random values
//! and key import included).
//!
//! Mirrors `tests/crypto_centralised.js`, whose claim 1 is that no file
//! requires node's `crypto` except `common/crypto.js` and the engines under
//! it. In Rust the module is `sts-crypto`, and `sts-pki`, which DESIGN
//! section 6 builds from `openssl` halves beside it (X.509 authoring on a
//! DER writer of its own, CRL, OCSP, CMS). Two claims:
//!
//!   1. DEPENDENCIES (`cargo metadata`): no other package names a crypto
//!      library as a normal or build dependency — OpenSSL, ring, aws-lc,
//!      the RustCrypto hash, MAC, KDF, cipher and curve crates, `rand`, the
//!      JOSE and token-format libraries (Node's claim 2). A dev-dependency
//!      is the tests', which Node's guard does not walk either;
//!   2. SOURCE: outside those two, the only `openssl::` paths code names
//!      are `openssl::ssl` (and its `error`), the TLS layer — node's `tls`
//!      module, which Node's rule leaves to the socket owners, as it is not
//!      `crypto`. A package that needs `openssl` for that names it in
//!      TLS_ONLY with its reason.
//!
//! The TLS client and server crates (`tokio-openssl`, `postgres-openssl`,
//! `reqwest`'s native TLS) are not crypto libraries for this rule, for the
//! same reason.
//!
//! Both lists below may only SHRINK, as Node's `PENDING` does: an entry that
//! no longer matches fails, so a fixed site cannot leave its permission
//! behind.

use std::collections::BTreeSet;

use regex::Regex;
use sts_guards::{is_service_code, listed, ratchet, Workspace};

/// The packages that ARE the crypto module.
const THE_MODULE: &[&str] = &["sts-crypto", "sts-pki"];

/// Libraries that compute cryptography.
const CRYPTO_CRATES: &[&str] = &[
    "openssl",
    "openssl-sys",
    "foreign-types",
    "ring",
    "aws-lc-rs",
    "aws-lc-sys",
    "boring",
    "sha1",
    "sha2",
    "sha3",
    "md-5",
    "md5",
    "md4",
    "ripemd",
    "blake2",
    "blake3",
    "digest",
    "hmac",
    "hkdf",
    "pbkdf2",
    "scrypt",
    "argon2",
    "bcrypt",
    "aes",
    "aes-gcm",
    "aes-siv",
    "aes-kw",
    "chacha20poly1305",
    "cbc",
    "ctr",
    "des",
    "rc4",
    "cipher",
    "rsa",
    "dsa",
    "p256",
    "p384",
    "p521",
    "k256",
    "ecdsa",
    "elliptic-curve",
    "ed25519-dalek",
    "ed448-goldilocks",
    "x25519-dalek",
    "curve25519-dalek",
    "ml-dsa",
    "ml-kem",
    "slh-dsa",
    "signature",
    "rand",
    "rand_core",
    "getrandom",
    "subtle",
    "x509-cert",
    "x509-parser",
    "x509-ocsp",
    "cms",
    "pkcs1",
    "pkcs5",
    "pkcs8",
    "pkcs12",
    "spki",
    "jsonwebtoken",
    "josekit",
    "biscuit-auth",
    "macaroon",
    "zkryptium",
    "ssh-key",
    "sigstore",
];

/// `package|dependency` → why it is allowed: `openssl` for the TLS layer
/// only, the source claim holding the rest of it to `openssl::ssl`.
const TLS_ONLY: &[(&str, &str)] = &[
    ("sts-runtime|openssl", "the main listener's acceptor"),
    (
        "sts-store|openssl",
        "the postgres connection's TLS (and see below)",
    ),
    (
        "xacml-pep|openssl",
        "the PEP's HTTPS listener and its PDP client",
    ),
    // sts-cluster has no TLS: its `openssl` is the three uses PENDING
    // lists, and leaves with them.
    ("sts-cluster|openssl", "PENDING below"),
];

/// `file|openssl::module` outside `ssl`, each in a crate another phase-2b
/// slice is changing (listed, not edited), or in the remote PEP.
const PENDING: &[(&str, &str)] = &[
    // The cluster slice's: SHA-256 for a member's and a schedule's digest,
    // random bytes for a node id and a run id. sts-crypto has both
    // (`jws_alg::Hash::Sha256.digest()`, `random::random_bytes()`).
    ("crates/sts-cluster/src/membership.rs|hash", "cluster slice"),
    ("crates/sts-cluster/src/membership.rs|rand", "cluster slice"),
    ("crates/sts-cluster/src/schedule.rs|hash", "cluster slice"),
    ("crates/sts-cluster/src/scheduler.rs|rand", "cluster slice"),
    // The store slice's: the keystore makes and signs with key sets (a
    // port of `keystore.js`, which asked crypto.js); a random id.
    (
        "crates/sts-store/src/key_sets.rs|sha",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/key_sets.rs|bn",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/key_sets.rs|ec",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/key_sets.rs|hash",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/key_sets.rs|nid",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/key_sets.rs|pkey",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/key_sets.rs|rsa",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/key_sets.rs|x509",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/key_sets.rs|rand",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/key_sets.rs|asn1",
        "store slice: key sets",
    ),
    (
        "crates/sts-store/src/keystore.rs|hash",
        "store slice: keystore",
    ),
    (
        "crates/sts-store/src/keystore.rs|pkey",
        "store slice: keystore",
    ),
    (
        "crates/sts-store/src/keystore.rs|sign",
        "store slice: keystore",
    ),
    ("crates/sts-store/src/postgres.rs|rand", "store slice"),
    // The remote PEP: a second container, which links none of sts-crypto
    // today (Node's STANDALONE kind: a process outside the service's module
    // graph). Its listener reads its certificate, key and client CAs and
    // fingerprints the client certificate; its PDP client reads its key;
    // its AuthZEN batch ids are random. Whether it takes sts-crypto for
    // these is the owner's call, not a mechanical change to a shipped
    // binary.
    ("bins/xacml-pep/src/listener.rs|asn1", "remote PEP"),
    ("bins/xacml-pep/src/listener.rs|hash", "remote PEP"),
    ("bins/xacml-pep/src/listener.rs|pkey", "remote PEP"),
    ("bins/xacml-pep/src/listener.rs|stack", "remote PEP"),
    ("bins/xacml-pep/src/listener.rs|x509", "remote PEP"),
    ("bins/xacml-pep/src/pdp_client.rs|pkey", "remote PEP"),
    ("bins/xacml-pep/src/authzen.rs|rand", "remote PEP"),
];

#[test]
fn only_the_crypto_module_depends_on_a_crypto_library() {
    let packages = Workspace::here().packages().unwrap();
    assert!(packages.len() > 10, "cargo metadata listed the members");
    let mut found = Vec::new();
    for p in &packages {
        if THE_MODULE.contains(&p.name.as_str()) {
            continue;
        }
        let mut names = BTreeSet::new();
        for d in &p.dependencies {
            if d.kind.as_deref() != Some("dev")
                && CRYPTO_CRATES.contains(&d.name.as_str())
            {
                names.insert(d.name.clone());
            }
        }
        for name in names {
            found.push(format!("{}|{}", p.name, name));
        }
    }
    let (new, stale) = ratchet(found, TLS_ONLY.iter().map(|(k, _)| *k));
    assert!(
        new.is_empty() && stale.is_empty(),
        "every cryptographic operation is sts-crypto's (or sts-pki's): a \
         package asks it rather than depending on a crypto library itself \
         (#453, root CLAUDE.md's crypto rule).\n  dependencies not \
         allowed: {}\n  TLS_ONLY entries no longer needed (remove them): {}",
        listed(&new),
        listed(&stale)
    );
}

#[test]
fn outside_the_crypto_module_openssl_is_only_tls() {
    // `openssl::x::…` and `use openssl::{x, y::z}`; a crate name in a path.
    let path = Regex::new(
        r"\b(openssl|openssl_sys|foreign_types)::(\{[^}]*\}|[a-z0-9_]+)",
    )
    .unwrap();
    let other = Regex::new(&format!(
        r"\b({})::",
        CRYPTO_CRATES
            .iter()
            .filter(|c| !c.starts_with("openssl") && **c != "foreign-types")
            .map(|c| c.replace('-', "_"))
            .collect::<Vec<_>>()
            .join("|")
    ))
    .unwrap();
    let mut found = BTreeSet::new();
    for f in Workspace::here().sources().unwrap() {
        let dir = f.crate_dir();
        if !is_service_code(&f.rel)
            || dir == "crates/sts-crypto"
            || dir == "crates/sts-pki"
        {
            continue;
        }
        for c in path.captures_iter(&f.code) {
            let modules: Vec<String> = if c[2].starts_with('{') {
                c[2].trim_matches(|ch| ch == '{' || ch == '}')
                    .split(',')
                    .filter_map(|s| s.trim().split("::").next())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            } else {
                vec![c[2].to_string()]
            };
            for m in modules {
                if &c[1] == "openssl" && (m == "ssl" || m == "error") {
                    continue;
                }
                let m = if &c[1] == "openssl" {
                    m
                } else {
                    format!("{}::{}", &c[1], m)
                };
                found.insert(format!("{}|{}", f.rel, m));
            }
        }
        for c in other.captures_iter(&f.code) {
            found.insert(format!("{}|{}", f.rel, &c[1]));
        }
    }
    let (new, stale) = ratchet(found, PENDING.iter().map(|(k, _)| *k));
    assert!(
        new.is_empty() && stale.is_empty(),
        "outside sts-crypto and sts-pki, code asks sts-crypto for every \
         digest, signature, key, cipher and random value; `openssl::ssl` (the \
         TLS layer) is the one part of OpenSSL it names (#453).\n  uses not \
         allowed: {}\n  PENDING entries matching nothing (remove them): {}",
        listed(&new),
        listed(&stale)
    );
}
