// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! EVERY SIGNATURE ALGORITHM THIS SERVICE KNOWS, ONCE (#1368 phase 1,
//! #1374) — the Rust reading of `common/crypto_impl/algorithm_registry.js`.
//!
//! Each protocol names an algorithm its own way: `PS256` in JOSE, `-37` in
//! COSE, a URI in XML, an OID and a PKI id in X.509. The registry is the one
//! row per algorithm that every surface's spelling resolves to, so a policy
//! can say "which algorithms, in which order, for which surface" — the
//! per-realm sign and accept lists of #1368's later phases read it.
//!
//! **THE DATA IS NODE'S, EXPORTED, NEVER WRITTEN BY HAND.**
//! `tests/tools/export-rust-tables.js` writes `tables/algorithm_registry.json`
//! from the registry's rows as the module indexes them (`pki` renamed `x509`,
//! every surface present, RFC 9421 section 3.3.7's JWS aliases on
//! `httpsig`), and `tests/rust_tables.js` fails when the committed file has
//! drifted. Until the cutover the JavaScript is what is edited.
//!
//! **TWO ORDERS, WHICH MUST NOT BE CONFUSED.** [`Registry::rows`] is in
//! PREFERENCE order — post-quantum strongest first, the weak ones last —
//! which is what a console draws. [`Registry::recorded`] is what each
//! surface and consumer does TODAY, member by member, and what an empty
//! setting means. The engine tables of this crate (`jws_alg::ALGS`,
//! `webauthn::COSE_SIGNATURE_ALGS`, `dkim::DKIM_ALGORITHMS`, the PKI ids of
//! `pq_x509`) are views of the recorded order, and the tests below hold each
//! to it, as `tests/algorithm_registry.js` holds Node's.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde_json::Value as Json;
use sts_core::errors::ErrorCode;

// ---------------------------------------------------------------------------
// THE POLICY'S DOOR (#1368). Node's `signature_policy.ts` answers, for the
// ambient realm, why an algorithm may not be signed with or accepted on a
// surface — from the realm's lists (`keys.acceptedSigningAlgorithms`,
// `cose.acceptedAlgorithms`, …), `keys.postQuantumSigning`,
// `keys.eddsaSigning`, `keys.pqcOnly` and the mode — and `crypto.js` asks it
// at its chokepoints. That module reads settings and the mode, so it is
// wiring for a later phase; what lives in `crypto.js`, and so here, is the
// asking. A caller hands the chokepoint a [`SignaturePolicy`]; [`AcceptAll`]
// is what a realm with every list empty, post-quantum on and development
// mode answers.
// ---------------------------------------------------------------------------

/// Why a policy refuses: the sentence a caller may pass on, and the code it
/// records and never sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cause {
    pub code: ErrorCode,
    pub message: String,
}

/// `signature_policy.ts`'s two questions, for one realm.
pub trait SignaturePolicy: Send + Sync {
    /// `acceptCause(surface, alg)`: why a signature in this algorithm may
    /// not be accepted, asked before any key operation; `None` where it
    /// may.
    fn accept_cause(&self, surface: Surface, alg: &str) -> Option<Cause>;

    /// `signCause(surface, alg)`: why this realm may not sign with it.
    fn sign_cause(&self, surface: Surface, alg: &str) -> Option<Cause> {
        let _ = (surface, alg);
        None
    }
}

/// The policy that refuses nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAll;

impl SignaturePolicy for AcceptAll {
    fn accept_cause(&self, _surface: Surface, _alg: &str) -> Option<Cause> {
        None
    }
}

/// A surface an algorithm may have a spelling on (`SURFACES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Surface {
    Jose,
    Cose,
    Xml,
    X509,
    Cms,
    Di,
    Httpsig,
    Tls,
    Dkim,
}

impl Surface {
    /// Every surface, in the registry's order.
    pub const ALL: [Surface; 9] = [
        Surface::Jose,
        Surface::Cose,
        Surface::Xml,
        Surface::X509,
        Surface::Cms,
        Surface::Di,
        Surface::Httpsig,
        Surface::Tls,
        Surface::Dkim,
    ];

    /// The registry's name for it.
    pub fn name(self) -> &'static str {
        match self {
            Surface::Jose => "jose",
            Surface::Cose => "cose",
            Surface::Xml => "xml",
            Surface::X509 => "x509",
            Surface::Cms => "cms",
            Surface::Di => "di",
            Surface::Httpsig => "httpsig",
            Surface::Tls => "tls",
            Surface::Dkim => "dkim",
        }
    }

    pub fn from_name(name: &str) -> Option<Surface> {
        Surface::ALL.into_iter().find(|s| s.name() == name)
    }
}

/// One algorithm. The members are the registry's, as the comment at the top
/// of `algorithm_registry.js` describes them; `engine` is, per surface, the
/// row of the table that surface's own code read before the registry, kept
/// verbatim as JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// The canonical name: the JOSE `alg` where one exists.
    pub id: String,
    /// What the JWS table calls it: pq, ec, okp, rsa, hmac, dsa, bbs.
    pub family: String,
    /// The operation: ml-dsa, slh-dsa, composite, ecdsa, eddsa, rsa-pss,
    /// rsa-pkcs1, hmac, dsa, bbs.
    pub kind: String,
    /// Node's digest name, where the algorithm does not choose its own.
    pub hash: Option<String>,
    /// The key it needs: akp, ec, okp, rsa, secret, dsa, bls12-381.
    pub key_kind: String,
    /// `pqc_support.ts`'s kind: pq, composite, or none.
    pub pqc: Option<String>,
    /// Broken or short (SHA-1, RIPEMD-160): nothing admits it unasked.
    pub weak: bool,
    /// SHA-1 in particular, which has settings of its own.
    pub sha1: bool,
    pub oid: Option<String>,
    pub spec: Option<String>,
    spellings: HashMap<Surface, Json>,
    aliases: HashMap<Surface, Vec<Json>>,
    pub engine: Json,
}

impl Row {
    /// Its spelling on a surface: a string, or COSE's integer.
    pub fn spelling(&self, surface: Surface) -> Option<&Json> {
        self.spellings.get(&surface)
    }

    /// Its spelling on a surface as text, as the index keys it.
    pub fn spelled(&self, surface: Surface) -> Option<String> {
        self.spelling(surface).map(spelling_key)
    }

    /// The other spellings a surface accepts for it.
    pub fn aliases(&self, surface: Surface) -> &[Json] {
        self.aliases.get(&surface).map_or(&[], Vec::as_slice)
    }

    /// Whether it is post-quantum or composite.
    pub fn is_post_quantum(&self) -> bool {
        self.pqc.is_some()
    }

    /// The row of a surface's engine table it replaced.
    pub fn engine(&self, surface: Surface) -> Option<&Json> {
        self.engine.get(surface.name())
    }
}

/// `String(value)`, which is how Node's index keys a spelling: COSE's
/// identifiers are integers, everything else text.
fn spelling_key(value: &Json) -> String {
    match value {
        Json::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn text(value: &Json, name: &str) -> Option<String> {
    value.get(name).and_then(Json::as_str).map(str::to_string)
}

/// The registry, read once from the exported table.
pub struct Registry {
    rows: Vec<Row>,
    by_id: HashMap<String, usize>,
    by_spelling: HashMap<(Surface, String), usize>,
    by_oid: HashMap<String, Vec<usize>>,
    recorded: HashMap<String, Vec<Json>>,
    raw_signature_families: Vec<String>,
    xml_refused: Vec<(String, String)>,
    xml_digests: Vec<(String, Json)>,
    xml_digests_refused: Vec<(String, String)>,
    pki_key_algorithms: Vec<String>,
}

const TABLE: &str = include_str!("../tables/algorithm_registry.json");

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    // The table is compiled in from a file the repository's own test holds
    // equal to Node's; one that does not parse is a build that cannot have
    // passed that test, so an empty registry (which refuses every lookup)
    // is the answer rather than a panic.
    let doc: Json = serde_json::from_str(TABLE).unwrap_or(Json::Null);
    Registry::from_table(&doc)
});

fn pairs(value: Option<&Json>) -> Vec<(String, Json)> {
    value
        .and_then(Json::as_object)
        .map(|map| map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

impl Registry {
    /// The one registry.
    pub fn get() -> &'static Registry {
        &REGISTRY
    }

    /// The registry a table describes (`indexRows()` over the exported
    /// rows, which are already uniform).
    pub fn from_table(doc: &Json) -> Registry {
        let mut rows = Vec::new();
        for raw in doc["rows"].as_array().map_or(&[][..], Vec::as_slice) {
            let mut spellings = HashMap::new();
            let mut aliases = HashMap::new();
            for surface in Surface::ALL {
                match raw.get(surface.name()) {
                    None | Some(Json::Null) => {}
                    Some(value) => {
                        spellings.insert(surface, value.clone());
                    }
                }
                if let Some(list) =
                    raw["aliases"].get(surface.name()).and_then(Json::as_array)
                {
                    aliases.insert(surface, list.clone());
                }
            }
            rows.push(Row {
                id: text(raw, "id").unwrap_or_default(),
                family: text(raw, "family").unwrap_or_default(),
                kind: text(raw, "kind").unwrap_or_default(),
                hash: text(raw, "hash"),
                key_kind: text(raw, "keyKind").unwrap_or_default(),
                pqc: text(raw, "pqc"),
                weak: raw["weak"] == true,
                sha1: raw["sha1"] == true,
                oid: text(raw, "oid"),
                spec: text(raw, "spec"),
                spellings,
                aliases,
                engine: raw.get("engine").cloned().unwrap_or(Json::Null),
            });
        }
        let mut by_id = HashMap::new();
        let mut by_spelling = HashMap::new();
        let mut by_oid: HashMap<String, Vec<usize>> = HashMap::new();
        for (at, row) in rows.iter().enumerate() {
            by_id.insert(row.id.clone(), at);
            for surface in Surface::ALL {
                if let Some(value) = row.spelling(surface) {
                    by_spelling.insert((surface, spelling_key(value)), at);
                }
                for alias in row.aliases(surface) {
                    by_spelling.insert((surface, spelling_key(alias)), at);
                }
            }
            if let Some(oid) = &row.oid {
                by_oid.entry(oid.clone()).or_default().push(at);
            }
        }
        let recorded = doc["recorded"]
            .as_object()
            .map(|map| {
                map.iter()
                    .map(|(k, v)| {
                        (k.clone(), v.as_array().cloned().unwrap_or_default())
                    })
                    .collect()
            })
            .unwrap_or_default();
        let strings = |value: &Json| -> Vec<String> {
            value
                .as_array()
                .map(|list| {
                    list.iter()
                        .filter_map(Json::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        let reasons = |value: Option<&Json>| -> Vec<(String, String)> {
            pairs(value)
                .into_iter()
                .map(|(k, v)| (k, v.as_str().unwrap_or_default().to_string()))
                .collect()
        };
        Registry {
            by_id,
            by_spelling,
            by_oid,
            recorded,
            raw_signature_families: strings(&doc["rawSignatureFamilies"]),
            xml_refused: reasons(doc.get("xmlRefused")),
            xml_digests: pairs(doc.get("xmlDigests")),
            xml_digests_refused: reasons(doc.get("xmlDigestsRefused")),
            pki_key_algorithms: strings(&doc["pkiKeyAlgorithms"]),
            rows,
        }
    }

    /// Every row, in preference order (`ROWS`).
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// `byId()`: a row by its canonical name.
    pub fn by_id(&self, id: &str) -> Option<&Row> {
        self.by_id.get(id).map(|&at| &self.rows[at])
    }

    /// `bySpelling()`: a row by a surface's name for it, an alias included.
    /// A COSE identifier is given as its decimal text (`"-7"`).
    pub fn by_spelling(&self, surface: Surface, value: &str) -> Option<&Row> {
        self.by_spelling
            .get(&(surface, value.to_string()))
            .map(|&at| &self.rows[at])
    }

    /// `spelling()`: a row's spelling on a surface, by the row's id.
    pub fn spelling(&self, id: &str, surface: Surface) -> Option<&Json> {
        self.by_id(id).and_then(|row| row.spelling(surface))
    }

    /// `byOid()`: every row an OID names. RSASSA-PSS's OID names no hash, so
    /// it is several.
    pub fn by_oid(&self, oid: &str) -> Vec<&Row> {
        self.by_oid
            .get(oid)
            .map(|list| list.iter().map(|&at| &self.rows[at]).collect())
            .unwrap_or_default()
    }

    /// `on()`: the rows with a spelling on a surface, in preference order.
    pub fn on(&self, surface: Surface) -> Vec<&Row> {
        self.rows
            .iter()
            .filter(|row| row.spelling(surface).is_some())
            .collect()
    }

    /// `recorded()`: a surface's or consumer's spellings in the order it
    /// uses today — `jose`, `cose`, `cose.status`, `cose.mdoc`, `xml`,
    /// `x509`, `httpsig`, `cms`, `dkim`, `tls`, `di`. Empty for any other.
    pub fn recorded(&self, name: &str) -> Vec<Json> {
        self.recorded.get(name).cloned().unwrap_or_default()
    }

    /// `recorded()` as text, for every surface but COSE.
    pub fn recorded_names(&self, name: &str) -> Vec<String> {
        self.recorded(name).iter().map(spelling_key).collect()
    }

    /// `joseNames(keep)`: the JOSE names in today's order, narrowed.
    pub fn jose_names(&self, keep: impl Fn(&Row) -> bool) -> Vec<String> {
        self.recorded_names("jose")
            .into_iter()
            .filter(|alg| {
                self.by_spelling(Surface::Jose, alg).is_some_and(&keep)
            })
            .collect()
    }

    /// `asymmetricJoseNames()`: every JOSE name but the HMAC ones.
    pub fn asymmetric_jose_names(&self) -> Vec<String> {
        self.jose_names(|row| row.family != "hmac")
    }

    /// `postQuantumJoseNames()`.
    pub fn post_quantum_jose_names(&self) -> Vec<String> {
        self.jose_names(|row| row.family == "pq")
    }

    /// `classicalAsymmetricJoseNames()`.
    pub fn classical_asymmetric_jose_names(&self) -> Vec<String> {
        self.jose_names(|row| row.family != "hmac" && row.family != "pq")
    }

    /// `coseIds(consumer)`: one consumer's COSE identifiers, in its order —
    /// `cose` (the verifier, all twenty), `cose.status`, `cose.mdoc`.
    pub fn cose_ids(&self, consumer: &str) -> Vec<i64> {
        self.recorded(consumer)
            .iter()
            .filter_map(Json::as_i64)
            .collect()
    }

    /// `insecureCoseIds()`: the COSE identifiers marked insecure (RS1).
    pub fn insecure_cose_ids(&self) -> Vec<i64> {
        self.cose_ids("cose")
            .into_iter()
            .filter(|id| {
                self.by_spelling(Surface::Cose, &id.to_string())
                    .and_then(|row| row.engine(Surface::Cose))
                    .is_some_and(|engine| engine["insecure"] == true)
            })
            .collect()
    }

    /// `dkimAlgorithms()`.
    pub fn dkim_algorithms(&self) -> Vec<String> {
        self.recorded_names("dkim")
    }

    /// `mlDsaOids()`: the ML-DSA parameter sets' PKI ids to their OIDs.
    pub fn ml_dsa_oids(&self) -> Vec<(String, String)> {
        self.recorded_names("x509")
            .into_iter()
            .filter_map(|pki| {
                let row = self.by_spelling(Surface::X509, &pki)?;
                let oid = row.oid.clone()?;
                (row.kind == "ml-dsa").then_some((pki, oid))
            })
            .collect()
    }

    /// `pkiSignatureAlgorithms()`: `x509.js`'s `SIG_ALG_ORDER`.
    pub fn pki_signature_algorithms(&self) -> Vec<String> {
        self.recorded_names("x509")
    }

    /// `pkiKeyAlgorithms()`: the classical keys, every post-quantum
    /// signature key, then the KEMs.
    pub fn pki_key_algorithms(&self) -> &[String] {
        &self.pki_key_algorithms
    }

    /// `RAW_SIGNATURE_FAMILIES`: what `verifyRawSignature()` understands.
    pub fn raw_signature_families(&self) -> &[String] {
        &self.raw_signature_families
    }

    /// `xmlSignaturesRefused()`: the XML SignatureMethods known and
    /// refused, each with its reason.
    pub fn xml_signatures_refused(&self) -> &[(String, String)] {
        &self.xml_refused
    }

    /// `xmlDigestMethods()`: the XML DigestMethods verified, each to
    /// `{ hash, label, weak, sha1 }`.
    pub fn xml_digest_methods(&self) -> &[(String, Json)] {
        &self.xml_digests
    }

    /// `xmlDigestsRefused()`.
    pub fn xml_digests_refused(&self) -> &[(String, String)] {
        &self.xml_digests_refused
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws_alg::{Family, Hash, ALGS};

    fn registry() -> &'static Registry {
        let r = Registry::get();
        assert_eq!(r.rows().len(), 81, "the exported table loaded");
        r
    }

    #[test]
    fn lookups_answer_as_the_index_does() {
        let r = registry();
        let ps = r.by_spelling(Surface::Cose, "-37").unwrap();
        assert_eq!(ps.id, "PS256");
        assert_eq!(r.by_spelling(Surface::Jose, "PS256").unwrap().id, "PS256");
        // RFC 9421 section 3.3.7: the JWS name is an HTTP signature alias.
        assert_eq!(
            r.by_spelling(Surface::Httpsig, "ES256").unwrap().id,
            "ES256"
        );
        assert_eq!(
            r.by_spelling(Surface::Httpsig, "ecdsa-p256-sha256")
                .unwrap()
                .id,
            "ES256"
        );
        // One row for the JOSE composite and its X.509 twin.
        assert_eq!(
            r.by_spelling(Surface::X509, "mldsa44-ecdsa-p256-sha256")
                .unwrap()
                .id,
            "ML-DSA-44-ES256"
        );
        assert!(r.by_oid("1.2.840.113549.1.1.10").len() > 1, "RSASSA-PSS");
        assert!(r.by_spelling(Surface::Jose, "none").is_none());
        assert_eq!(r.insecure_cose_ids(), vec![-65535]);
        assert_eq!(r.raw_signature_families().len(), 5);
    }

    /// `jws_alg::ALGS` is the JOSE view: the recorded order, member by
    /// member, each row of the registry's family and digest.
    #[test]
    fn the_jws_table_is_the_jose_view() {
        let r = registry();
        let names: Vec<&str> = ALGS.iter().map(|a| a.name).collect();
        assert_eq!(names, r.recorded_names("jose"));
        for alg in ALGS.iter() {
            let engine = r
                .by_spelling(Surface::Jose, alg.name)
                .and_then(|row| row.engine(Surface::Jose))
                .unwrap();
            let (family, hash) = match alg.family {
                Family::Hmac(h) => ("hmac", Some(h)),
                Family::Rsa(h) | Family::RsaPss(h) => ("rsa", Some(h)),
                Family::Ec { hash, .. } => ("ec", Some(hash)),
                Family::EdDsa => ("okp", None),
                Family::MlDsa { .. }
                | Family::SlhDsa { .. }
                | Family::Composite(_) => ("pq", None),
            };
            assert_eq!(engine["family"], family, "{}", alg.name);
            let want = hash.map(Hash::name);
            assert_eq!(engine["hash"].as_str(), want, "{}", alg.name);
        }
    }

    /// WebAuthn's COSE table is the verifier's recorded list, in order,
    /// each of the registry's name, family, digest, key type, salt, curve
    /// and insecurity.
    #[test]
    fn the_cose_table_is_the_cose_view() {
        use crate::webauthn::{CoseFamily, COSE_SIGNATURE_ALGS};
        let r = registry();
        let ids: Vec<i64> = COSE_SIGNATURE_ALGS.iter().map(|a| a.id).collect();
        assert_eq!(ids, r.cose_ids("cose"));
        for alg in COSE_SIGNATURE_ALGS.iter() {
            let engine = r
                .by_spelling(Surface::Cose, &alg.id.to_string())
                .and_then(|row| row.engine(Surface::Cose))
                .unwrap();
            let family = match alg.family {
                CoseFamily::Ecdsa => "ecdsa",
                CoseFamily::EdDsa => "eddsa",
                CoseFamily::RsaPkcs1 => "rsa-pkcs1",
                CoseFamily::RsaPss => "rsa-pss",
                CoseFamily::MlDsa => "pq",
            };
            assert_eq!(engine["name"], alg.name, "{}", alg.id);
            assert_eq!(engine["family"], family, "{}", alg.id);
            assert_eq!(engine["hash"].as_str(), alg.hash, "{}", alg.id);
            assert_eq!(engine["kty"], alg.kty, "{}", alg.id);
            assert_eq!(
                engine["saltLength"].as_u64().unwrap_or(0),
                alg.salt as u64,
                "{}",
                alg.id
            );
            assert_eq!(engine["curve"].as_str(), alg.curve, "{}", alg.id);
            assert_eq!(engine["insecure"] == true, alg.insecure, "{}", alg.id);
        }
    }

    /// DKIM, the raw-signature families and the PKI ids `pq_x509` signs
    /// under are the registry's too.
    #[test]
    fn dkim_raw_and_pki_are_views() {
        let r = registry();
        assert_eq!(r.dkim_algorithms(), crate::dkim::DKIM_ALGORITHMS);
        assert_eq!(
            r.raw_signature_families(),
            ["rsa-pkcs1", "rsa-pss", "ecdsa", "eddsa", "pq"]
        );
        for pki in r.pki_signature_algorithms() {
            let row = r.by_spelling(Surface::X509, &pki).unwrap();
            if row.is_post_quantum() {
                assert!(
                    crate::pq_x509::alg(&pki).is_some(),
                    "pq_x509 signs under {}",
                    pki
                );
            }
        }
        for (pki, oid) in r.ml_dsa_oids() {
            assert_eq!(crate::pq_x509::alg(&pki).unwrap().oid, oid, "{}", pki);
        }
    }
}
