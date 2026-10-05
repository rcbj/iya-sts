// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Trust realms: several logical copies of the service in one process
//! (`common/realms.js`), told apart by a segment at the front of the path.
//!
//! This is the part every crate needs before any store exists: what a
//! realm IS (an id, a name, a DNS domain fixed at creation), the AMBIENT
//! realm a request runs in (`tokio::task_local!`, rust/DESIGN.md 4.3 — the
//! default realm outside any), what a realm may be called, the base DN its
//! domain gives, its path prefix, and which realm a path names (by the
//! prefix, or in RFC 7030's EST label position). The registry's lifecycle
//! — create, update, retire, remove, overrides — and the per-realm store
//! handles come with `sts-store`.
//!
//! **The default realm is not a row.** It cannot be created, renamed,
//! re-prefixed or removed, because everything the service published before
//! realms existed is published under it. Its domain is `global.domain`,
//! read when asked.
//!
//! **A service with no realm defined behaves exactly as it did**: no prefix
//! is stripped or added and every path is the default realm's — one
//! predicate, [`RealmRegistry::active`].

use std::future::Future;
use std::sync::{Arc, PoisonError, RwLock};

use indexmap::IndexMap;

use crate::errors::{codes, ErrorCode};

/// The id of the default realm, which has an empty path prefix.
pub const DEFAULT_ID: &str = "default";

const EST_BASE: &str = "/.well-known/est/";

/// One realm's record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Realm {
    pub id: String,
    pub name: String,
    pub description: String,
    pub builtin: bool,
    /// Milliseconds since the epoch; `None` for the default realm.
    pub created_at: Option<i64>,
    /// The DNS domain, fixed at creation. Empty for the default realm,
    /// whose domain is `global.domain` ([`RealmRegistry::domain_of`]).
    pub domain: String,
}

impl Realm {
    /// The built-in default realm.
    pub fn default_realm() -> Realm {
        Realm {
            id: DEFAULT_ID.to_string(),
            name: "Default".to_string(),
            description: "The realm every path with no realm segment belongs to. It cannot be removed or \
                          re-prefixed: every URL this service published before trust realms existed is a URL \
                          in this realm."
                .to_string(),
            builtin: true,
            created_at: None,
            domain: String::new(),
        }
    }

    pub fn is_default(&self) -> bool {
        self.id == DEFAULT_ID
    }
}

tokio::task_local! {
    static AMBIENT: Arc<Realm>;
}

/// The ambient realm, or the default realm outside any.
pub fn current() -> Arc<Realm> {
    AMBIENT
        .try_with(Arc::clone)
        .unwrap_or_else(|_| Arc::new(Realm::default_realm()))
}

/// The ambient realm's id.
pub fn current_id() -> String {
    AMBIENT
        .try_with(|r| r.id.clone())
        .unwrap_or_else(|_| DEFAULT_ID.to_string())
}

/// Runs a future with a realm ambient, for it and everything it awaits.
pub async fn run<F: Future>(realm: Arc<Realm>, work: F) -> F::Output {
    AMBIENT.scope(realm, work).await
}

/// Runs a synchronous function with a realm ambient.
pub fn run_sync<R>(realm: Arc<Realm>, work: impl FnOnce() -> R) -> R {
    AMBIENT.sync_scope(realm, work)
}

/// What the realm model reads from outside itself: three settings, the
/// router's first segments and the EST labels. Handed in, so this module
/// requires no other.
pub trait RealmEnvironment: Send + Sync {
    /// `realms.enabled`.
    fn enabled(&self) -> bool;
    /// `realms.pathSegment`, as set.
    fn path_segment(&self) -> String;
    /// `global.domain`, as set.
    fn global_domain(&self) -> String;
    /// The first segment of every route the service serves.
    fn reserved(&self) -> Vec<String>;
    /// Every name EST reads as a label (`EnrollmentProfiles.EST_LABELS`).
    fn est_labels(&self) -> Vec<String>;
}

/// Refusals as sentences, the first condition's error code kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Refusals {
    pub code: Option<ErrorCode>,
    pub sentences: Vec<String>,
}

impl Refusals {
    fn push(&mut self, code: ErrorCode, sentence: String) {
        if self.code.is_none() {
            self.code = Some(code);
        }
        self.sentences.push(sentence);
    }

    pub fn is_empty(&self) -> bool {
        self.sentences.is_empty()
    }
}

/// Which realm a path names, and the path inside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathMatch {
    pub realm: Arc<Realm>,
    pub rest: String,
    /// Named in the EST label position rather than by the prefix.
    pub est_label: bool,
}

/// `realms.js`'s `/^[a-z0-9][a-z0-9-]{0,30}$/`.
fn id_shaped(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 31
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A DNS label: `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`.
fn domain_label(label: &str) -> bool {
    let b = label.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// `normalizeDomain()`: trimmed, no trailing dot, lower case, an
/// internationalised name in its A-label form.
pub fn normalize_domain(raw: &str) -> String {
    let trimmed = raw.trim();
    let text = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if text.is_empty() {
        return String::new();
    }
    let ascii = if text.is_ascii() {
        text.to_string()
    } else {
        // `url.domainToASCII()` answers '' for a name that is not one, and
        // the original is then kept for validate_domain() to refuse.
        idna::domain_to_ascii(text)
            .ok()
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| text.to_string())
    };
    ascii.to_lowercase()
}

/// RFC 2247: one `dc=` RDN per label.
pub fn base_dn_of_domain(domain: &str) -> String {
    domain
        .split('.')
        .filter(|l| !l.is_empty())
        .map(|l| format!("dc={}", l))
        .collect::<Vec<_>>()
        .join(",")
}

/// The registry of defined realms and the questions asked of it.
pub struct RealmRegistry {
    defined: RwLock<IndexMap<String, Arc<Realm>>>,
    default: Arc<Realm>,
    environment: Arc<dyn RealmEnvironment>,
}

impl RealmRegistry {
    pub fn new(environment: Arc<dyn RealmEnvironment>) -> RealmRegistry {
        RealmRegistry {
            defined: RwLock::new(IndexMap::new()),
            default: Arc::new(Realm::default_realm()),
            environment,
        }
    }

    fn defined(
        &self,
    ) -> std::sync::RwLockReadGuard<'_, IndexMap<String, Arc<Realm>>> {
        self.defined.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Holds a realm as defined. Validation is the caller's (`create()` in
    /// `sts-store`, and a store's restore, which trusts what it wrote).
    pub fn insert(&self, realm: Realm) -> Arc<Realm> {
        let held = Arc::new(realm);
        self.defined
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(held.id.clone(), held.clone());
        held
    }

    /// Forgets a defined realm; the default realm cannot be.
    pub fn forget(&self, id: &str) -> bool {
        self.defined
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .shift_remove(id)
            .is_some()
    }

    pub fn default_realm(&self) -> Arc<Realm> {
        self.default.clone()
    }

    /// `get()`: the default realm for an empty id or `default`.
    pub fn get(&self, id: &str) -> Option<Arc<Realm>> {
        if id.is_empty() || id == DEFAULT_ID {
            return Some(self.default.clone());
        }
        self.defined().get(id).cloned()
    }

    /// Every realm, the default one first.
    pub fn list(&self) -> Vec<Arc<Realm>> {
        std::iter::once(self.default.clone())
            .chain(self.defined().values().cloned())
            .collect()
    }

    /// The realms, the default one included.
    pub fn count(&self) -> usize {
        self.defined().len() + 1
    }

    /// Whether realms are switched on: one is defined and `realms.enabled`.
    pub fn active(&self) -> bool {
        !self.defined().is_empty() && self.environment.enabled()
    }

    /// A realm's domain: the default realm's is `global.domain`.
    pub fn domain_of(&self, realm: &Realm) -> String {
        if realm.is_default() {
            normalize_domain(&self.environment.global_domain())
        } else {
            realm.domain.clone()
        }
    }

    /// The base DN of a realm's directory.
    pub fn base_dn_of(&self, realm: &Realm) -> String {
        base_dn_of_domain(&self.domain_of(realm))
    }

    /// A development-mode person's invented address, in the ambient realm's
    /// domain; a name that is already an address is returned as it is.
    pub fn invented_mail_of(&self, name: &str) -> String {
        match name.find('@') {
            Some(at) if at > 0 => name.to_string(),
            _ => format!("{}@{}", name, self.domain_of(&current())),
        }
    }

    /// `realms.pathSegment` without slashes.
    pub fn path_segment(&self) -> String {
        self.environment
            .path_segment()
            .trim_matches('/')
            .to_string()
    }

    /// A realm's path prefix, `/realm/acme`; empty for the default realm or
    /// when realms are off.
    pub fn prefix_of(&self, realm: &Realm) -> String {
        if realm.is_default() || !self.active() {
            return String::new();
        }
        let segment = self.path_segment();
        if segment.is_empty() {
            format!("/{}", realm.id)
        } else {
            format!("/{}/{}", segment, realm.id)
        }
    }

    /// The ambient realm's prefix.
    pub fn current_prefix(&self) -> String {
        self.prefix_of(&current())
    }

    /// A root-relative path in the ambient realm; an absolute URL, or a
    /// path already prefixed, is returned unchanged.
    pub fn href(&self, path: &str) -> String {
        let prefix = self.current_prefix();
        if prefix.is_empty() || !path.starts_with('/') {
            return path.to_string();
        }
        if path == prefix || path.starts_with(&format!("{}/", prefix)) {
            return path.to_string();
        }
        format!("{}{}", prefix, path)
    }

    /// Whether a name is an EST label.
    pub fn is_est_label(&self, name: &str) -> bool {
        self.environment.est_labels().iter().any(|l| l == name)
    }

    fn est_label_of(path: &str) -> Option<(&str, &str)> {
        let after = path.strip_prefix(EST_BASE)?;
        match after.find('/') {
            Some(slash) if slash > 0 => {
                Some((&after[..slash], &after[slash..]))
            }
            _ => None,
        }
    }

    fn match_est_label(&self, path: &str) -> Option<PathMatch> {
        let (label, rest) = RealmRegistry::est_label_of(path)?;
        if self.is_est_label(label) {
            return None;
        }
        let realm = self.defined().get(label).cloned()?;
        Some(PathMatch {
            realm,
            rest: format!("{}{}", &EST_BASE[..EST_BASE.len() - 1], rest),
            est_label: true,
        })
    }

    /// `matchPath()`: the realm a path opens with, by its prefix or in the
    /// EST label position; `None` for no realm, or an undefined one — which
    /// falls through to the router's own 404.
    pub fn match_path(&self, path: &str) -> Option<PathMatch> {
        if !self.active() {
            return None;
        }
        let segment = self.path_segment();
        let mut head = path;
        if !segment.is_empty() {
            if !path.starts_with(&format!("/{}/", segment)) {
                return self.match_est_label(path);
            }
            head = &path[segment.len() + 1..];
        }
        let slash = head.get(1..).and_then(|h| h.find('/')).map(|i| i + 1);
        let id = match slash {
            Some(s) => &head[1..s],
            None => head.get(1..).unwrap_or(""),
        };
        let Some(realm) = self.defined().get(id).cloned() else {
            return if segment.is_empty() {
                self.match_est_label(path)
            } else {
                None
            };
        };
        let rest = match slash {
            Some(s) => &head[s..],
            None => "/",
        };
        Some(PathMatch {
            realm,
            rest: if rest.is_empty() {
                "/".to_string()
            } else {
                rest.to_string()
            },
            est_label: false,
        })
    }

    /// The label-form address of a realm's EST server, `None` for the
    /// default realm and a realm whose id is a label.
    pub fn est_label_path(&self, realm: &Realm) -> Option<String> {
        if realm.is_default() || self.is_est_label(&realm.id) {
            return None;
        }
        Some(format!("{}{}", EST_BASE, realm.id))
    }

    /// `unknownRealmPath()`: whether a path could name a realm this process
    /// has not heard of yet (one created on another node a moment ago).
    pub fn unknown_realm_path(&self, path: &str) -> bool {
        if !self.environment.enabled() {
            return false;
        }
        let defined = self.defined();
        if let Some((label, _)) = RealmRegistry::est_label_of(path) {
            if id_shaped(label)
                && !self.is_est_label(label)
                && !defined.contains_key(label)
                && label != DEFAULT_ID
            {
                return true;
            }
        }
        let segment = self.path_segment();
        let mut head = path;
        if !segment.is_empty() {
            if !path.starts_with(&format!("/{}/", segment)) {
                return false;
            }
            head = &path[segment.len() + 1..];
        }
        let rest = head.get(1..).unwrap_or("");
        let id = rest.split('/').next().unwrap_or("");
        if !id_shaped(id) || defined.contains_key(id) || id == DEFAULT_ID {
            return false;
        }
        if segment.is_empty()
            && self
                .environment
                .reserved()
                .iter()
                .any(|r| r.to_lowercase() == id)
        {
            return false;
        }
        true
    }

    /// `validateId()`: its shape, and that it names no route, EST label,
    /// defined realm or the default realm.
    pub fn validate_id(&self, id: &str) -> Refusals {
        let mut out = Refusals::default();
        if !id_shaped(id) {
            out.push(
                codes::STS_CORE_0009,
                format!(
                    "A realm id is lower-case letters, digits and hyphens, starts with a letter or a digit and is \
                     at most 31 characters. \"{}\" is not.",
                    id
                ),
            );
            return out;
        }
        if id == DEFAULT_ID {
            out.push(
                codes::STS_CORE_0010,
                format!(
                    "\"{}\" is the built-in realm and cannot be redefined.",
                    DEFAULT_ID
                ),
            );
        }
        if self.environment.reserved().iter().any(|r| r == id) {
            out.push(
                codes::STS_CORE_0011,
                format!(
                    "\"{}\" is the first segment of a path this service already serves. A realm may not be called \
                     that, whatever realms.pathSegment is set to, because clearing that setting would make the \
                     realm shadow the endpoint.",
                    id
                ),
            );
        }
        if self.is_est_label(id) {
            out.push(
                codes::STS_CORE_0107,
                format!(
                    "\"{}\" is an EST label (a certificate profile), and /.well-known/est/<realm>/ reaches a realm \
                     through the same path position as /.well-known/est/<label>/ reaches a profile. A realm may \
                     not be called by a label's name, so that one segment always means one thing.",
                    id
                ),
            );
        }
        if self.defined().contains_key(id) {
            out.push(
                codes::STS_CORE_0012,
                format!("A realm called \"{}\" is already defined.", id),
            );
        }
        out
    }

    /// `validateDomain()`: a DNS name of two labels or more, not another
    /// realm's. Nesting inside another realm's domain is allowed.
    pub fn validate_domain(&self, domain: &str, id: &str) -> Refusals {
        let mut out = Refusals::default();
        let labels: Vec<&str> = domain.split('.').collect();
        let shaped = !domain.is_empty()
            && domain.len() <= 253
            && labels.len() >= 2
            && labels.iter().all(|l| domain_label(l))
            && !labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit());
        if !shaped {
            out.push(
                codes::STS_CORE_0099,
                format!(
                    "A realm's domain is a DNS name of at least two labels — iyasec.io, dev.iyasec.io — each \
                     letters, digits and hyphens of at most 63 characters, with a top-level label that is not all \
                     digits. \"{}\" is not.",
                    domain
                ),
            );
            return out;
        }
        if let Some(holder) = self
            .list()
            .into_iter()
            .find(|r| r.id != id && self.domain_of(r) == domain)
        {
            out.push(
                codes::STS_CORE_0100,
                format!(
                    "The domain \"{}\" is already the \"{}\" realm's{}. Two realms with one domain would be two \
                     directories claiming one naming context. A domain INSIDE another realm's — dev.{} — is \
                     allowed.",
                    domain,
                    holder.id,
                    if holder.is_default() { " (global.domain)" } else { "" },
                    domain
                ),
            );
        }
        out
    }
}
