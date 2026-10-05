// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Building a path to a caller's trust anchors (`pki.js`'s
//! `verifyPathToAnchors()`, Go's `x509.Certificate.Verify()` with
//! caller-supplied roots), and the synchronous one-hop door
//! (`verifyIssuedDirectly()`).
//!
//! The builder BACKTRACKS over every issuer whose name matches and whose key
//! verifies, an anchor before an intermediate and a key-identifier match
//! before none; a candidate path that fails a rule or the clock is abandoned
//! for the next. Bounded by 12 certificates and 256 signature checks, with
//! no certificate (nor one with the same subject and key) used twice.

use super::entry::Entry;
use super::rules::{self, Problem, RuleOptions};
use crate::x509::read::{self, Certificate};

const PATH_MAX_LENGTH: usize = 12;
const PATH_MAX_SIGNATURES: usize = 256;

/// `verifyPathToAnchors()`'s options.
#[derive(Clone, Debug, Default)]
pub struct PathOptions {
    pub rules: RuleOptions,
    /// Milliseconds since the epoch.
    pub now_ms: i64,
    pub skew_ms: i64,
}

/// The verdict: the chain (leaf first, anchor last) as DER, or why not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathVerdict {
    pub ok: bool,
    pub check: String,
    pub reason: String,
    pub chain: Vec<Vec<u8>>,
    pub policies: Vec<String>,
}

impl PathVerdict {
    fn refused(check: &str, reason: String) -> PathVerdict {
        PathVerdict {
            ok: false,
            check: check.to_string(),
            reason,
            chain: Vec::new(),
            policies: Vec::new(),
        }
    }

    fn from_problem(p: &Problem) -> PathVerdict {
        PathVerdict::refused(p.check, p.why.clone())
    }
}

/// `pathSigned()`: the names match as section 7.1 compares them, and the
/// issuer's key verifies the signature.
fn path_signed(cert: &Entry, issuer: &Entry) -> bool {
    let (a, b) = (cert.facts(), issuer.facts());
    if !a.problem.is_empty()
        || !b.problem.is_empty()
        || a.issuer_rdns.join(",") != b.subject_rdns.join(",")
    {
        return false;
    }
    match (&a.cert, &b.cert) {
        (Some(c), Some(i)) => read::verify_signature(c, i).unwrap_or(false),
        _ => false,
    }
}

fn identity_of(e: &Entry) -> String {
    let f = e.facts();
    let spki = f
        .cert
        .as_ref()
        .map_or_else(|| crate::der::hex(&e.der), |c| crate::der::hex(&c.spki));
    format!("{}|{}", f.subject_rdns.join(","), spki)
}

/// `alternativeProblem()` for a foreign path (`required` false): only a
/// WRONG alternative signature is refused.
fn alternative_problem(chain: &[&Entry]) -> Option<(usize, String)> {
    let pems: Vec<&str> = chain.iter().map(|e| e.pem.as_str()).collect();
    let links = read::verify_chain(&pems).ok()?;
    links.iter().enumerate().find_map(|(i, link)| {
        let alt = &link["alternative"];
        (alt["present"] == true && alt["valid"] == false).then(|| {
            (
                i,
                alt["algorithm"]
                    .as_str()
                    .unwrap_or("post-quantum")
                    .to_string(),
            )
        })
    })
}

struct Builder<'a> {
    roots: &'a [Entry],
    intermediates: &'a [Entry],
    options: &'a PathOptions,
    first_failure: Option<Problem>,
    accepted_policies: Vec<String>,
    signatures: usize,
    exhausted: bool,
    unsigned: String,
}

impl<'a> Builder<'a> {
    fn is_anchor(&self, e: &Entry) -> bool {
        self.roots.iter().any(|r| r.der == e.der)
    }

    fn accept(&mut self, path: &[&Entry]) -> bool {
        let problem = rules::path_rule_problem(path, &self.options.rules)
            .or_else(|| {
                rules::path_validity_problem(
                    path,
                    self.options.now_ms,
                    self.options.skew_ms,
                )
            });
        if let Some(p) = problem {
            if self.first_failure.is_none() {
                self.first_failure = Some(p);
            }
            return false;
        }
        self.accepted_policies =
            rules::path_policy_outcome(path, &self.options.rules.policy)
                .user_constrained_policy_set;
        true
    }

    fn candidates_for(
        &self,
        top: &Entry,
        path: &[&'a Entry],
    ) -> Vec<(&'a Entry, bool)> {
        let facts = top.facts();
        let in_path: Vec<String> =
            path.iter().map(|e| identity_of(e)).collect();
        let mut out: Vec<(&'a Entry, bool)> = self
            .roots
            .iter()
            .map(|r| (r, true))
            .chain(
                self.intermediates
                    .iter()
                    .filter(|i| !self.is_anchor(i))
                    .map(|i| (i, false)),
            )
            .filter(|(c, _)| {
                let theirs = c.facts();
                theirs.problem.is_empty()
                    && theirs.subject_rdns.join(",")
                        == facts.issuer_rdns.join(",")
                    && !in_path.contains(&identity_of(c))
            })
            .collect();
        let rank = |(c, anchor): &(&Entry, bool)| {
            let theirs = c.facts();
            let keyed = !facts.authority_key_identifier.is_empty()
                && !theirs.key_identifier.is_empty()
                && facts.authority_key_identifier == theirs.key_identifier;
            (if *anchor { 0 } else { 2 }) + usize::from(!keyed)
        };
        // A stable sort, as Array.prototype.sort is.
        out.sort_by_key(rank);
        out
    }

    fn extend(&mut self, path: Vec<&'a Entry>) -> Option<Vec<&'a Entry>> {
        if path.len() >= PATH_MAX_LENGTH {
            self.exhausted = true;
            return None;
        }
        let top = path[path.len() - 1];
        for (candidate, anchor) in self.candidates_for(top, &path) {
            if self.signatures >= PATH_MAX_SIGNATURES {
                self.exhausted = true;
                return None;
            }
            self.signatures += 1;
            if !path_signed(top, candidate) {
                if self.unsigned.is_empty() {
                    self.unsigned = format!(
                        "the signature on \"{}\" does not verify under the key of \"{}\", the only certificate that names itself as its issuer",
                        top.subject_text(),
                        candidate.subject_text()
                    );
                }
                continue;
            }
            let mut longer = path.clone();
            longer.push(candidate);
            if anchor {
                if self.accept(&longer) {
                    return Some(longer);
                }
                continue;
            }
            if let Some(found) = self.extend(longer) {
                return Some(found);
            }
        }
        None
    }
}

/// `verifyPathToAnchors()`.
pub fn verify_path_to_anchors(
    leaf_der: &[u8],
    intermediate_ders: &[Vec<u8>],
    anchors: &[Entry],
    options: &PathOptions,
) -> PathVerdict {
    let Some(leaf) = Entry::from_der(leaf_der) else {
        return PathVerdict::refused(
            "unusable",
            "the leaf is not an X.509 certificate".to_string(),
        );
    };
    let mut intermediates = Vec::new();
    for (i, d) in intermediate_ders.iter().enumerate() {
        match Entry::from_der(d) {
            Some(e) => intermediates.push(e),
            None => {
                return PathVerdict::refused(
                    "unusable",
                    format!(
                    "intermediate certificate {} is not an X.509 certificate",
                    i
                ),
                )
            }
        }
    }
    if anchors.is_empty() {
        return PathVerdict::refused(
            "no-anchor",
            "no trust anchor is configured".to_string(),
        );
    }
    let mut b = Builder {
        roots: anchors,
        intermediates: &intermediates,
        options,
        first_failure: None,
        accepted_policies: Vec::new(),
        signatures: 0,
        exhausted: false,
        unsigned: String::new(),
    };
    if b.is_anchor(&leaf) {
        let ok = b.accept(&[&leaf]);
        return if ok {
            PathVerdict {
                ok: true,
                check: String::new(),
                reason: String::new(),
                chain: vec![leaf.der.clone()],
                policies: b.accepted_policies,
            }
        } else {
            b.first_failure.as_ref().map_or_else(
                || PathVerdict::refused("unusable", String::new()),
                PathVerdict::from_problem,
            )
        };
    }
    let chain = b.extend(vec![&leaf]);
    if let Some(chain) = chain {
        if let Some((index, algorithm)) = alternative_problem(&chain) {
            return PathVerdict::refused(
                "alternative-signature",
                format!(
                    "The certificate \"{}\" carries an alternative ({}) signature, ITU-T X.509 clause 9.8, that does NOT verify under its issuer's alternative key. A hybrid certificate whose second signature fails is not a certificate its issuer signed, whatever the first one says.",
                    chain[index].subject_text(),
                    algorithm
                ),
            );
        }
        return PathVerdict {
            ok: true,
            check: String::new(),
            reason: String::new(),
            chain: chain.iter().map(|e| e.der.clone()).collect(),
            policies: b.accepted_policies,
        };
    }
    if let Some(p) = &b.first_failure {
        return PathVerdict::from_problem(p);
    }
    let leaf_facts = leaf.facts();
    if !leaf_facts.problem.is_empty() {
        return PathVerdict::refused(
            "unusable",
            format!("\"{}\" {}", leaf.subject_text(), leaf_facts.problem),
        );
    }
    if b.exhausted {
        return PathVerdict::refused(
            "exhausted",
            format!(
                "no path to a configured trust anchor was found within {} certificates and {} signature checks",
                PATH_MAX_LENGTH, PATH_MAX_SIGNATURES
            ),
        );
    }
    if !b.unsigned.is_empty() {
        return PathVerdict::refused("signature", b.unsigned);
    }
    PathVerdict::refused(
        "no-path",
        format!(
            "no path from \"{}\" to a configured trust anchor",
            leaf.subject_text()
        ),
    )
}

/// `verifyIssuedDirectly()`: is the leaf issued, directly, by one of the
/// authorities (OpenSSL's `X509_check_issued()` and `X509_verify()`), and
/// does the two-certificate path hold the rules? `index` names which.
pub fn verify_issued_directly(
    leaf_der: &[u8],
    authority_ders: &[Vec<u8>],
    options: &PathOptions,
) -> (PathVerdict, Option<usize>) {
    let Some(leaf) = Entry::from_der(leaf_der) else {
        return (
            PathVerdict::refused(
                "unusable",
                "the certificate is not an X.509 certificate".to_string(),
            ),
            None,
        );
    };
    let mut first_failure: Option<Problem> = None;
    let mut signed_by_any = false;
    for (i, d) in authority_ders.iter().enumerate() {
        let Some(authority) = Entry::from_der(d) else {
            continue;
        };
        let issued = authority.x509.issued(&leaf.x509)
            == openssl::x509::X509VerifyResult::OK;
        let signed = issued
            && authority
                .x509
                .public_key()
                .ok()
                .and_then(|k| leaf.x509.verify(&k).ok())
                .unwrap_or(false);
        if !signed {
            continue;
        }
        signed_by_any = true;
        let path = [&leaf, &authority];
        let problem =
            rules::path_rule_problem(&path, &options.rules).or_else(|| {
                rules::path_validity_problem(
                    &path,
                    options.now_ms,
                    options.skew_ms,
                )
            });
        match problem {
            None => {
                return (
                    PathVerdict {
                        ok: true,
                        check: String::new(),
                        reason: String::new(),
                        chain: vec![leaf.der.clone(), authority.der.clone()],
                        policies: Vec::new(),
                    },
                    Some(i),
                )
            }
            Some(p) => {
                if first_failure.is_none() {
                    first_failure = Some(p);
                }
            }
        }
    }
    if let Some(p) = first_failure {
        return (PathVerdict::from_problem(&p), None);
    }
    (
        PathVerdict::refused(
            if signed_by_any { "unusable" } else { "no-path" },
            format!(
                "no authority given issued and signed \"{}\"",
                leaf.subject_text()
            ),
        ),
        None,
    )
}

/// `peerChainProblem()` over a chain OpenSSL already verified (leaf first):
/// the same rules, and `None` when it holds or cannot be read.
pub fn chain_rule_problem(chain_ders: &[Vec<u8>]) -> Option<Problem> {
    let entries: Option<Vec<Entry>> = chain_ders
        .iter()
        .take(PATH_MAX_LENGTH)
        .map(|d| Entry::from_der(d))
        .collect();
    let entries = entries?;
    if entries.is_empty() {
        return None;
    }
    let path: Vec<&Entry> = entries.iter().collect();
    rules::path_rule_problem(&path, &RuleOptions::default())
}

/// A certificate's parsed form, for callers holding only an entry.
pub fn certificate_of(e: &Entry) -> Option<&Certificate> {
    e.facts().cert.as_ref()
}
