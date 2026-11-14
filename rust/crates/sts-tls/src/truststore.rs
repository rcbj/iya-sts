// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CLIENT TRUSTSTORE: the anchors every listener in this process
//! verifies a CLIENT certificate against (`tls_server.js`'s `anchors`,
//! `addAnchors()`, `removeAnchor()`, `listAnchors()`, `loadAnchorsFile()`
//! and `secureContextOptions()`' `ca`).
//!
//! It starts EMPTY but for `tls.trustAnchorsFile`, which is read at start
//! and is FATAL when it cannot be read (`STS-TLS-0019`) or holds no
//! certificate (`STS-TLS-0020`). The runtime door
//! (`POST /admin-api/tls/trust/{add,remove}`, phase 4's) adds and removes
//! one array every listener shares. A listener's OWN anchors file (#429)
//! replaces the service's FILE anchors for it, and the service Root is
//! added where its `trustIssuedClientCertificates` says so (on by default):
//! a person's certificate from `/portal/signing-key` completes the
//! handshake, and `common/tls_client_certificates.js` decides whether it is
//! an identity (phase 5).
//!
//! **THE PIN.** In Node a request worker's copy changed nothing a handshake
//! read, so both doors are pinned to the front process
//! (`request_pool.js`'s `NEVER_DISPATCHED`). The Rust runtime is ONE
//! process: the truststore is held by the process that holds the sockets,
//! which is the guarantee the pin bought. **Not ported yet**: a runtime
//! anchor surviving a restart (`ou=trustAnchors` in the directory,
//! `reloadStoredAnchors()`) waits for the directory (phase 4), and the
//! admission rule under paranoid PKI mode (#1360, `STS-TLS-0056`/`0057`)
//! for the validation door's hierarchy half (phase 6); until then an anchor
//! is admitted when OpenSSL can read it, which is Node's rule with paranoid
//! mode off — development's default.

use std::sync::{Mutex, PoisonError};

use sts_core::errors::{codes, ErrorCode};
use sts_pki::listener::{describe_anchor, split_pem_certificates, AnchorFacts};

/// At most this many anchors (`MAX_ANCHORS`).
pub const MAX_ANCHORS: usize = 32;

/// Where an anchor came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    File,
    Runtime,
}

/// One anchor.
#[derive(Debug, Clone)]
pub struct Anchor {
    pub pem: String,
    pub facts: AnchorFacts,
    pub source: Source,
    pub added_at: String,
}

/// What an add or a remove did, or why it did nothing.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub changed: usize,
    pub duplicates: usize,
    pub total: usize,
    pub refusal: Option<(ErrorCode, String)>,
}

/// The truststore. One per process.
#[derive(Default)]
pub struct Truststore {
    anchors: Mutex<Vec<Anchor>>,
}

/// Why the anchors file stops the service.
#[derive(Debug, Clone)]
pub struct FileProblem {
    pub code: ErrorCode,
    pub message: String,
}

fn normalised(fingerprint: &str) -> String {
    fingerprint
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Every certificate of a listener's OWN anchors file, or none where it
/// cannot be read (`listenerFileAnchors()`); the startup check makes an
/// empty answer fatal (`STS-TLS-0045`).
pub fn listener_file_anchors(file: &str) -> Vec<String> {
    match std::fs::read_to_string(file) {
        Ok(text) => split_pem_certificates(&text)
            .into_iter()
            .take(MAX_ANCHORS)
            .collect(),
        Err(e) => {
            tracing::debug!("tls: {} could not be read: {}", file, e);
            Vec::new()
        }
    }
}

impl Truststore {
    fn held(&self) -> std::sync::MutexGuard<'_, Vec<Anchor>> {
        self.anchors.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `loadAnchorsFile()`: `tls.trustAnchorsFile`, read at start.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn load_file(&self, file: &str) -> Result<usize, FileProblem> {
        let file = file.trim();
        if file.is_empty() {
            return Ok(0);
        }
        let text = std::fs::read_to_string(file).map_err(|e| FileProblem {
            code: codes::STS_TLS_0019,
            message: format!(
                "tls: NOT STARTING. tls.trustAnchorsFile (STS_TLS_TRUST_ANCHORS_FILE) is \"{}\" and it could \
                 not be read: {}.",
                file,
                e.to_string().trim_end_matches('.')
            ),
        })?;
        let found = split_pem_certificates(&text);
        if found.is_empty() {
            return Err(FileProblem {
                code: codes::STS_TLS_0020,
                message: format!(
                    "tls: NOT STARTING. tls.trustAnchorsFile is \"{}\" and it holds no -----BEGIN \
                     CERTIFICATE----- block, so the client truststore would be empty while configured to \
                     be filled.",
                    file
                ),
            });
        }
        let joined = found.into_iter().take(MAX_ANCHORS).collect::<String>();
        Ok(self.add(&joined, false, Source::File).changed)
    }

    /// `addAnchors(text, { strict, source })`. Strict (the gated doors)
    /// refuses the whole bundle when one block cannot be read.
    #[tracing::instrument(level = "debug", skip(self, text))]
    pub fn add(&self, text: &str, strict: bool, source: Source) -> Outcome {
        let found = split_pem_certificates(text);
        let mut anchors = self.held();
        if found.is_empty() {
            return Outcome {
                changed: 0,
                duplicates: 0,
                total: anchors.len(),
                refusal: Some((
                    codes::STS_TLS_0012,
                    "No PEM certificate was found in the body. Send one or more -----BEGIN CERTIFICATE----- \
                     blocks, as raw text or as the `certificates` field of a form or JSON body."
                        .to_string(),
                )),
            };
        }
        let described: Vec<(String, Option<AnchorFacts>)> = found
            .into_iter()
            .map(|pem| {
                let facts = describe_anchor(&pem).ok();
                (pem, facts)
            })
            .collect();
        let unreadable = described.iter().filter(|(_, f)| f.is_none()).count();
        if strict && unreadable > 0 {
            return Outcome {
                changed: 0,
                duplicates: 0,
                total: anchors.len(),
                refusal: Some((
                    codes::STS_TLS_0013,
                    format!(
                        "{} of the {} certificate(s) sent could not be read by OpenSSL, which is what the \
                         listeners verify against — so none was added. A block OpenSSL cannot parse is not \
                         an anchor it will use, and putting one in the truststore makes the next \
                         setSecureContext() on every listener throw.",
                        unreadable,
                        described.len()
                    ),
                )),
            };
        }
        let mut added = 0;
        let mut duplicates = 0;
        for (pem, facts) in described {
            // Not strict: a block OpenSSL cannot read is not an anchor it
            // would use, so it is left out rather than poisoning the context.
            let Some(facts) = facts else {
                continue;
            };
            if anchors
                .iter()
                .any(|a| a.facts.fingerprint256 == facts.fingerprint256)
            {
                duplicates += 1;
                continue;
            }
            if anchors.len() >= MAX_ANCHORS {
                return Outcome {
                    changed: added,
                    duplicates,
                    total: anchors.len(),
                    refusal: Some((
                        codes::STS_TLS_0014,
                        format!(
                            "This truststore holds at most {} anchors; {} were added before it filled up. \
                             Remove one first — POST /admin-api/tls/trust/remove, or the row button on \
                             /admin/tls/trust.",
                            MAX_ANCHORS, added
                        ),
                    )),
                };
            }
            tracing::info!(
                "tls: trusting client certificates issued by {} ({})",
                facts.subject,
                facts.fingerprint256
            );
            anchors.push(Anchor {
                pem,
                facts,
                source,
                added_at: chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            });
            added += 1;
        }
        Outcome {
            changed: added,
            duplicates,
            total: anchors.len(),
            refusal: None,
        }
    }

    /// `removeAnchor(fingerprint)`: one anchor, by its SHA-256 fingerprint
    /// in either spelling.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn remove(&self, fingerprint: &str) -> Outcome {
        let wanted = normalised(fingerprint);
        let mut anchors = self.held();
        let total = anchors.len();
        if wanted.len() != 64 {
            return Outcome {
                changed: 0,
                duplicates: 0,
                total,
                refusal: Some((
                    codes::STS_TLS_0015,
                    "Name the anchor by its SHA-256 fingerprint in `fingerprint` — 64 hex digits, with or \
                     without the colons `openssl x509 -fingerprint -sha256` prints. Nothing was removed."
                        .to_string(),
                )),
            };
        }
        let Some(index) = anchors
            .iter()
            .position(|a| normalised(&a.facts.fingerprint256) == wanted)
        else {
            return Outcome {
                changed: 0,
                duplicates: 0,
                total,
                refusal: Some((
                    codes::STS_TLS_0016,
                    format!(
                        "This truststore holds no anchor with the SHA-256 fingerprint {}. Nothing was removed.",
                        fingerprint
                    ),
                )),
            };
        };
        let gone = anchors.remove(index);
        tracing::info!(
            "tls: no longer trusting client certificates issued by {} ({}). {} anchor(s) remain.",
            gone.facts.subject,
            gone.facts.fingerprint256,
            anchors.len()
        );
        Outcome {
            changed: 1,
            duplicates: 0,
            total: anchors.len(),
            refusal: None,
        }
    }

    /// Every anchor, for the truststore page and its API twin.
    pub fn list(&self) -> Vec<Anchor> {
        self.held().clone()
    }

    /// `secureContextOptions(policy).ca`: the runtime anchors (and the
    /// service's file anchors, unless the listener names its own file),
    /// the listener's own file, and the service Root where `trust_issued`.
    #[tracing::instrument(level = "debug", skip(self, root_pem))]
    pub fn ca_for(
        &self,
        own_file: &str,
        trust_issued: bool,
        root_pem: Option<&str>,
    ) -> Vec<String> {
        let mut out: Vec<String> = self
            .held()
            .iter()
            .filter(|a| own_file.is_empty() || a.source != Source::File)
            .map(|a| a.pem.clone())
            .collect();
        if !own_file.is_empty() {
            out.extend(listener_file_anchors(own_file));
        }
        // `issuedClientCertificateAnchor()`: read live, not added twice if
        // somebody POSTed it.
        if let (true, Some(root)) = (trust_issued, root_pem) {
            let body = |p: &str| {
                p.lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect::<String>()
            };
            if !out.iter().any(|p| body(p) == body(root)) {
                out.push(root.to_string());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use super::*;
    use sts_pki::listener::{bootstrap, ListenerIdentity};

    fn pem() -> String {
        bootstrap(
            &ListenerIdentity {
                hostnames: vec!["a.example".into()],
                ips: vec![],
                organisation: "t".into(),
                rsa_bits: 2048,
                self_signed_years: 1,
            },
            "rsa",
        )
        .unwrap()
        .cert_pem
    }

    #[test]
    fn add_list_remove() {
        let t = Truststore::default();
        let p = pem();
        assert_eq!(t.add(&p, true, Source::Runtime).changed, 1);
        assert_eq!(t.add(&p, true, Source::Runtime).duplicates, 1);
        let fp = t.list()[0].facts.fingerprint256.replace(':', "");
        assert_eq!(t.remove(&fp).changed, 1);
        assert_eq!(t.remove(&fp).refusal.unwrap().0, codes::STS_TLS_0016);
        assert_eq!(t.remove("abc").refusal.unwrap().0, codes::STS_TLS_0015);
        assert_eq!(
            t.add("nothing", true, Source::Runtime).refusal.unwrap().0,
            codes::STS_TLS_0012
        );
    }

    #[test]
    fn the_root_is_added_once_where_trusted() {
        let t = Truststore::default();
        let root = pem();
        assert_eq!(t.ca_for("", true, Some(&root)).len(), 1);
        assert!(t.ca_for("", false, Some(&root)).is_empty());
        t.add(&root, true, Source::Runtime);
        assert_eq!(t.ca_for("", true, Some(&root)).len(), 1);
    }

    #[test]
    fn an_unreadable_file_is_fatal() {
        let t = Truststore::default();
        assert_eq!(
            t.load_file("/nonexistent/anchors.pem").err().unwrap().code,
            codes::STS_TLS_0019
        );
    }
}
