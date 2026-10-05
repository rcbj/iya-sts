// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The keystore's data keys (`common/keystore.js`, #391): what this service
//! seals with, and the one place its key-encryption key is held.
//!
//! * **Every sealed value names the data encryption key (DEK) it was sealed
//!   under**, and a DEK belongs to a scope (`service`), a realm and a data
//!   class — the caller's label, so `/admin/encryption` can count by kind.
//! * **Where the store keeps keys** (product mode, `keys.source` persisted)
//!   a DEK is random, wrapped under the key-encryption key with an AAD that
//!   binds it to its id, scope, realm and class, and stored as one JSON row
//!   per scope and realm (`dek:<scope>:<realm>` in `sts_keys`) — a union
//!   under the row's lock, so two processes that each made one keep both.
//! * **Where nothing is stored a DEK is DERIVED** from the key-encryption
//!   key, and its id (`d.` and the context in base64url) carries what it was
//!   derived for: a sibling holding the same key derives the same DEK from
//!   the id alone.
//! * **A keyed digest** is an HMAC under a key derived (HKDF, the label as
//!   its info) from the stored digest key, or from the key-encryption key
//!   where nothing is stored — a fingerprint no dictionary reads back.
//!
//! What is NOT here yet: the key management services (only the `file`
//! provider reads a key-encryption key), a previous key for a rotation,
//! the cell scope (#98), the signing keys and the certificate authority.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::mode::Mode;
use sts_core::settings::Settings;
use sts_crypto::secrets::{self, KekInput};

use crate::driver::Driver;

pub const DEK_ROW_PREFIX: &str = "dek:";
const DEK_ROW_VERSION: i64 = 1;
const DERIVED_DEK_PREFIX: &str = "d.";
/// A bound on DEKs derived from ids nobody here made.
const MAX_DERIVED_DEKS: usize = 4096;
const RELOAD_INTERVAL: Duration = Duration::from_millis(2000);
pub const DIGEST_CLASS: &str = "keyed-digest";

/// The data classes whose values are stored ON DIRECTORY ENTRIES, which
/// `keys.directoryCipher` applies to when a key of the class is made.
const DIRECTORY_CLASSES: &[&str] = &[
    "application-private-key",
    "client-secret",
    "registration-access-token",
    "federation-client-secret",
    "identity-verifications",
    "gnap-shared-key",
    "gnap-macaroon-key",
    "person-private-key",
    "federation-encryption-key",
    "kerberos-keys",
    "totp-secret",
    "recovery-codes",
    "directory",
];

/// `dekRealm()`: the default realm is `default` in a key row.
pub fn dek_realm(realm: &str) -> String {
    if realm.is_empty() {
        "default".to_string()
    } else {
        realm.to_string()
    }
}

/// `dekClass()`: lower-case letters, digits, dots and hyphens, at most 48,
/// and `general` for no label at all.
pub fn dek_class(label: &str) -> String {
    let mut out = String::new();
    let mut run = false;
    for c in label.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'
        {
            out.push(c);
            run = false;
        } else if !run {
            out.push('-');
            run = true;
        }
    }
    let trimmed: String = out.trim_matches('-').chars().take(48).collect();
    if trimmed.is_empty() {
        "general".to_string()
    } else {
        trimmed
    }
}

/// `dekRowKey()`.
pub fn dek_row_key(scope: &str, realm: &str) -> String {
    format!("{}{}:{}", DEK_ROW_PREFIX, scope, realm)
}

fn slot(scope: &str, realm: &str, cls: &str) -> String {
    format!("{}|{}|{}", scope, realm, cls)
}

fn id_ok(id: &str) -> bool {
    (8..=200).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn num(v: Option<&Json>) -> f64 {
    v.and_then(Json::as_f64).unwrap_or(0.0)
}

fn now_ms() -> f64 {
    sts_core::time::now_ms_f64().floor()
}

#[derive(Clone, Debug)]
struct Dek {
    id: String,
    scope: String,
    realm: String,
    cls: String,
    created_at: f64,
    activate_at: f64,
    wrapped_at: f64,
    destroyed: bool,
    wrapped: String,
    key: Option<Vec<u8>>,
    alg: String,
    values: f64,
    counted_at: f64,
    derived: bool,
}

impl Dek {
    /// `dekAad()`: a wrapped DEK copied onto another realm's row, or
    /// relabelled as another class, does not unwrap.
    fn aad(&self) -> String {
        format!(
            "sts dek v1|{}|{}|{}|{}",
            self.id, self.scope, self.realm, self.cls
        )
    }

    fn activation(&self) -> f64 {
        if self.activate_at != 0.0 {
            self.activate_at
        } else {
            self.created_at
        }
    }
}

/// `unionDekRows()`: the stored row and this process's, as one — every DEK
/// either holds, a destruction kept, the newer wrapping and count kept, and
/// a second digest key not added beside a stored one. `None` when the
/// stored row already says everything.
pub fn union_dek_rows(current: Option<&Json>, mine: &Json) -> Option<Json> {
    let list = |row: Option<&Json>| -> Vec<Json> {
        row.and_then(|r| r.get("deks"))
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let mut by_id: Vec<(String, Json)> = list(current)
        .into_iter()
        .map(|one| (str_of(&one, "id"), one))
        .collect();
    let mut changed = current.is_none();
    let stored_digest = by_id.iter().any(|(_, one)| {
        dek_class(&str_of(one, "cls")) == DIGEST_CLASS
            && str_of(one, "status") != "destroyed"
    });
    for one in list(Some(mine)) {
        let id = str_of(&one, "id");
        let at = by_id.iter().position(|(k, _)| *k == id);
        let Some(at) = at else {
            if stored_digest && dek_class(&str_of(&one, "cls")) == DIGEST_CLASS
            {
                continue;
            }
            by_id.push((id, one));
            changed = true;
            continue;
        };
        let theirs = &mut by_id[at].1;
        if str_of(theirs, "status") == "destroyed" {
            continue;
        }
        if str_of(&one, "status") == "destroyed" {
            theirs["status"] = json!("destroyed");
            theirs["wrapped"] = json!("");
            changed = true;
            continue;
        }
        if num(one.get("wrappedAt")) > num(theirs.get("wrappedAt")) {
            theirs["wrapped"] =
                one.get("wrapped").cloned().unwrap_or(Json::Null);
            theirs["wrappedAt"] =
                one.get("wrappedAt").cloned().unwrap_or(Json::Null);
            changed = true;
        }
        if num(one.get("countedAt")) > num(theirs.get("countedAt")) {
            theirs["values"] = json!(num(one.get("values")));
            theirs["countedAt"] =
                one.get("countedAt").cloned().unwrap_or(Json::Null);
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    let mut deks: Vec<Json> = by_id.into_iter().map(|(_, v)| v).collect();
    deks.sort_by(|a, b| {
        num(a.get("createdAt"))
            .partial_cmp(&num(b.get("createdAt")))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                if str_of(a, "id") < str_of(b, "id") {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            })
    });
    Some(json!({ "v": DEK_ROW_VERSION, "scope": mine.get("scope"),
                 "realm": mine.get("realm"), "deks": deks }))
}

fn str_of(v: &Json, key: &str) -> String {
    match v.get(key) {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn parse_dek_row(text: &str) -> Result<Json, String> {
    let row: Json = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let ok = row.get("v").and_then(Json::as_i64) == Some(DEK_ROW_VERSION)
        && row.get("deks").map(Json::is_array).unwrap_or(false)
        && row.get("scope").map(Json::is_string).unwrap_or(false)
        && row.get("realm").map(Json::is_string).unwrap_or(false);
    if ok {
        Ok(row)
    } else {
        Err("this is not a data-key row".to_string())
    }
}

#[derive(Default)]
struct State {
    deks: HashMap<String, Dek>,
    /// scope|realm|class to the current DEK and when to choose again.
    active: HashMap<String, (String, f64)>,
    /// `(scope, realm)` rows with a DEK not yet in the store.
    dirty: BTreeSet<(String, String)>,
    missed: HashSet<String>,
    reloaded_at: Option<Instant>,
}

/// The data keys of one process.
pub struct DataKeys {
    /// The key-encryption key, as its provider handed it back (text, or
    /// bytes where it was not text).
    kek: Option<Vec<u8>>,
    kek_is_text: bool,
    /// Whether DEKs are random and stored rather than derived.
    stored: bool,
    driver: Option<Arc<dyn Driver>>,
    settings: Option<Arc<Settings>>,
    state: Mutex<State>,
    writing: tokio::sync::Mutex<()>,
}

impl DataKeys {
    /// A keystore holding no key-encryption key: nothing seals.
    pub fn none() -> Arc<DataKeys> {
        Arc::new(DataKeys::bare(None, false, false, None, None))
    }

    /// `useEphemeralKek()`: a key generated per run and handed to every
    /// thread of it, with derived DEKs. Refused when it is not a usable key.
    pub fn ephemeral(kek_text: &str) -> Result<Arc<DataKeys>, String> {
        secrets::kek_bytes(KekInput::Text(kek_text))
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(DataKeys::bare(
            Some(kek_text.as_bytes().to_vec()),
            true,
            false,
            None,
            None,
        )))
    }

    /// A durable key-encryption key over a store that keeps the DEKs.
    pub fn durable(
        kek: Vec<u8>,
        kek_is_text: bool,
        driver: Arc<dyn Driver>,
        settings: Option<Arc<Settings>>,
    ) -> Result<Arc<DataKeys>, String> {
        let input = if kek_is_text {
            KekInput::Text(
                std::str::from_utf8(&kek).map_err(|e| e.to_string())?,
            )
        } else {
            KekInput::Bytes(&kek)
        };
        secrets::kek_bytes(input).map_err(|e| e.to_string())?;
        Ok(Arc::new(DataKeys::bare(
            Some(kek),
            kek_is_text,
            true,
            Some(driver),
            settings,
        )))
    }

    fn bare(
        kek: Option<Vec<u8>>,
        kek_is_text: bool,
        stored: bool,
        driver: Option<Arc<dyn Driver>>,
        settings: Option<Arc<Settings>>,
    ) -> DataKeys {
        DataKeys {
            kek,
            kek_is_text,
            stored,
            driver,
            settings,
            state: Mutex::new(State::default()),
            writing: tokio::sync::Mutex::new(()),
        }
    }

    /// `persists()`: `keys.source`, and `auto` follows the mode.
    pub fn persists(settings: &Settings, mode: &Mode) -> bool {
        match settings.value_of("keys.source").as_str() {
            "generated" => false,
            "persisted" => true,
            _ => mode.current() == "product",
        }
    }

    /// The `file` provider (`common/secrets.js`): the key read from the
    /// mounted file, as text when it trims to any, and its permissions
    /// reported rather than enforced.
    pub fn read_kek_file(path: &str) -> Result<(Vec<u8>, bool), String> {
        if path.is_empty() {
            return Err(format!(
                "{}keys.kekProvider is \"file\" and keys.kekFile names no path. Set it to a file holding the \
                 key-encryption key — `openssl rand -base64 32 > /run/secrets/sts-kek`.",
                tag(codes::STS_KEYS_0046)
            ));
        }
        let meta = std::fs::metadata(path).map_err(|e| {
            format!(
                "{}the file \"{}\" holding the key-encryption key could not be read: {}. In product mode this \
                 service will not start without it, because the alternative is generating a new signing key and \
                 silently invalidating every token it ever issued.",
                tag(codes::STS_KEYS_0047),
                path,
                e
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "{}secrets: the file \"{}\" holding the key-encryption key is readable by group or other (mode \
                     {:o}). Every signing key this service holds is protected by it. `chmod 600` it.",
                    tag(codes::STS_KEYS_0054),
                    path,
                    mode & 0o777
                );
            }
        }
        #[cfg(not(unix))]
        let _ = meta;
        let body = std::fs::read(path).map_err(|e| {
            format!(
                "{}the file \"{}\" holding the key-encryption key could not be read: {}",
                tag(codes::STS_KEYS_0047),
                path,
                e
            )
        })?;
        tracing::info!(
            "secrets: the key-encryption key was read from {}.",
            path
        );
        match std::str::from_utf8(&body) {
            Ok(text) if !text.trim().is_empty() => {
                Ok((text.trim().as_bytes().to_vec(), true))
            }
            _ => Ok((body, false)),
        }
    }

    /// `start()`: where keys persist, the key-encryption key from its
    /// provider and every stored data-key row adopted — a DEK of ours that
    /// will not unwrap stops the start — then the digest key made once.
    /// Elsewhere a keystore with no key, which seals nothing.
    pub async fn start(
        settings: Arc<Settings>,
        mode: &Mode,
        driver: Option<Arc<dyn Driver>>,
    ) -> Result<Arc<DataKeys>, String> {
        if !DataKeys::persists(&settings, mode) {
            return Ok(DataKeys::none());
        }
        let Some(driver) = driver else {
            return Err(format!(
                "{}key material is configured to persist (keys.source={}) and no persistence store is open. \
                 Product mode requires one: set persistence.mode to ldif or postgres.",
                tag(codes::STS_KEYS_0027),
                settings.value_of("keys.source").as_str()
            ));
        };
        let provider =
            settings.value_of("keys.kekProvider").as_str().to_string();
        if provider != "file" {
            return Err(format!(
                "{}keys.kekProvider is \"{}\", and this runtime reads a key-encryption key only from a file so far.",
                tag(codes::STS_KEYS_0046),
                provider
            ));
        }
        let (kek, is_text) = DataKeys::read_kek_file(
            settings.value_of("keys.kekFile").as_str(),
        )?;
        let keys = DataKeys::durable(kek, is_text, driver, Some(settings))?;
        keys.load(true).await?;
        keys.ensure_digest_key().await;
        Ok(keys)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn kek_input(&self) -> Option<KekInput<'_>> {
        let kek = self.kek.as_deref()?;
        Some(if self.kek_is_text {
            KekInput::Text(std::str::from_utf8(kek).ok()?)
        } else {
            KekInput::Bytes(kek)
        })
    }

    /// `sealed()`: whether a key-encryption key is held.
    pub fn sealed(&self) -> bool {
        self.kek.is_some()
    }

    /// `deksStored()`.
    pub fn stores_deks(&self) -> bool {
        self.stored
    }

    /// The scope a key is wrapped under: only the service's so far.
    fn wraps(&self, scope: &str) -> bool {
        scope == "service" && self.kek.is_some()
    }

    fn cipher_for(&self, cls: &str) -> &'static str {
        let siv = DIRECTORY_CLASSES.contains(&cls)
            && self
                .settings
                .as_ref()
                .map(|s| {
                    s.value_of("keys.directoryCipher").as_str() == "aes-256-siv"
                })
                .unwrap_or(false);
        if siv {
            "aes-256-siv"
        } else {
            "aes-256-gcm"
        }
    }

    /// `chooseActive()`: the usable DEK activated most recently, then the
    /// lowest id; cached until the next activation the slot waits for.
    fn current(
        &self,
        st: &mut State,
        scope: &str,
        realm: &str,
        cls: &str,
    ) -> Option<Dek> {
        let key = slot(scope, realm, cls);
        let now = now_ms();
        if let Some((id, until)) = st.active.get(&key) {
            if now < *until {
                if let Some(held) = st.deks.get(id) {
                    if held.key.is_some() && !held.destroyed {
                        return Some(held.clone());
                    }
                }
            }
        }
        let mut best: Option<&Dek> = None;
        let mut until = f64::INFINITY;
        for rec in st.deks.values() {
            if rec.scope != scope
                || rec.realm != realm
                || rec.cls != cls
                || rec.destroyed
                || rec.key.is_none()
            {
                continue;
            }
            let at = rec.activation();
            if at > now {
                until = until.min(at);
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => {
                    at > b.activation()
                        || (at == b.activation() && rec.id < b.id)
                }
            };
            if better {
                best = Some(rec);
            }
        }
        let best = best.cloned();
        match &best {
            Some(b) => {
                st.active.insert(key, (b.id.clone(), until));
            }
            None => {
                st.active.remove(&key);
            }
        }
        best
    }

    fn derive(
        &self,
        st: &mut State,
        scope: &str,
        realm: &str,
        cls: &str,
    ) -> Option<Dek> {
        let context = slot(scope, realm, cls);
        let (_, key) = secrets::derive_dek(self.kek_input()?, &context).ok()?;
        let rec = Dek {
            id: format!(
                "{}{}",
                DERIVED_DEK_PREFIX,
                URL_SAFE_NO_PAD.encode(context.as_bytes())
            ),
            scope: scope.to_string(),
            realm: realm.to_string(),
            cls: cls.to_string(),
            created_at: 0.0,
            activate_at: 0.0,
            wrapped_at: 0.0,
            destroyed: false,
            wrapped: String::new(),
            alg: secrets::dek_alg_of(&key).to_string(),
            key: Some(key),
            values: 0.0,
            counted_at: 0.0,
            derived: true,
        };
        st.deks.insert(rec.id.clone(), rec.clone());
        Some(rec)
    }

    /// `makeDek()`: a new random DEK, wrapped and marked for the store.
    fn make(
        &self,
        st: &mut State,
        scope: &str,
        realm: &str,
        cls: &str,
    ) -> Result<Dek, String> {
        let input = self.kek_input().ok_or("no key-encryption key is held")?;
        let now = now_ms();
        let key = secrets::generate_dek(self.cipher_for(cls))
            .map_err(|e| e.to_string())?;
        let mut rec = Dek {
            id: secrets::generate_dek_id().map_err(|e| e.to_string())?,
            scope: scope.to_string(),
            realm: realm.to_string(),
            cls: cls.to_string(),
            created_at: now,
            activate_at: now,
            wrapped_at: now,
            destroyed: false,
            wrapped: String::new(),
            alg: secrets::dek_alg_of(&key).to_string(),
            key: Some(key),
            values: 0.0,
            counted_at: 0.0,
            derived: false,
        };
        let key = rec.key.as_deref().unwrap_or_default();
        rec.wrapped = secrets::wrap_dek(input, key, &rec.aad())
            .map_err(|e| e.to_string())?;
        st.deks.insert(rec.id.clone(), rec.clone());
        st.dirty.insert((scope.to_string(), realm.to_string()));
        Ok(rec)
    }

    /// `activeDek()`: the DEK a value of this scope, realm and class is
    /// sealed under — the current one, or a new one.
    fn active(&self, scope: &str, realm: &str, cls: &str) -> Option<Dek> {
        let mut st = self.state();
        if let Some(held) = self.current(&mut st, scope, realm, cls) {
            return Some(held);
        }
        if !self.wraps(scope) {
            return None;
        }
        let key = slot(scope, realm, cls);
        if !self.stored {
            let derived = self.derive(&mut st, scope, realm, cls)?;
            st.active.insert(key, (derived.id.clone(), f64::INFINITY));
            return Some(derived);
        }
        match self.make(&mut st, scope, realm, cls) {
            Ok(rec) => {
                st.active.insert(key, (rec.id.clone(), f64::INFINITY));
                tracing::info!(
                    "keystore: a data encryption key was made for \"{}\" in the \"{}\" realm ({}), wrapped under the \
                     key-encryption key and queued for the store.",
                    cls,
                    realm,
                    scope
                );
                Some(rec)
            }
            Err(e) => {
                tracing::error!(
                    "{}keystore: a data encryption key could not be made: {}",
                    tag(codes::STS_KEYS_0040),
                    e
                );
                None
            }
        }
    }

    /// `dekFor()`: the DEK a sealed value names, unwrapped or derived.
    fn dek_for(&self, id: &str) -> Option<Dek> {
        let mut st = self.state();
        if let Some(rec) = st.deks.get(id) {
            if rec.key.is_some() {
                return Some(rec.clone());
            }
            if rec.wrapped.is_empty() || !self.wraps(&rec.scope) {
                return None;
            }
            let key = secrets::unwrap_dek(
                self.kek_input()?,
                &rec.wrapped,
                &rec.aad(),
            )
            .ok()?;
            let rec = st.deks.get_mut(id)?;
            rec.key = Some(key);
            return Some(rec.clone());
        }
        if self.stored || st.deks.len() >= MAX_DERIVED_DEKS {
            return None;
        }
        let encoded = id.strip_prefix(DERIVED_DEK_PREFIX)?;
        let context =
            String::from_utf8(URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()?;
        let parts: Vec<&str> = context.split('|').collect();
        if parts.len() != 3 || !self.wraps(parts[0]) {
            return None;
        }
        self.derive(&mut st, parts[0], parts[1], parts[2])
    }

    /// `seal()`: text sealed under the DEK of its realm and class, or `None`
    /// without a key-encryption key. `realm` is the realm id (`""` for the
    /// default realm).
    pub fn seal(
        &self,
        plaintext: &str,
        label: &str,
        realm: &str,
    ) -> Option<String> {
        self.kek.as_ref()?;
        let rec =
            self.active("service", &dek_realm(realm), &dek_class(label))?;
        let key = rec.key.as_deref()?;
        let tally = if label.is_empty() { None } else { Some(label) };
        match secrets::encrypt_with_dek(&rec.id, key, plaintext, tally) {
            Ok(out) => Some(out),
            Err(e) => {
                tracing::error!(
                    "{}keystore: something could not be sealed: {}",
                    tag(codes::STS_KEYS_0040),
                    e
                );
                None
            }
        }
    }

    /// `open()`: text `seal()` sealed, or `None` when it will not open. A
    /// DEK this process does not hold is said once, and the stored rows are
    /// worth reading again ([`DataKeys::needs_reload`]).
    pub fn open(&self, ciphertext: &str, label: &str) -> Option<String> {
        let id = secrets::dek_id_of(ciphertext)?;
        let Some(rec) = self.dek_for(id) else {
            self.note_miss(id, label);
            return None;
        };
        let tally = if label.is_empty() { None } else { Some(label) };
        secrets::decrypt_with_dek(rec.key.as_deref()?, ciphertext, tally).ok()
    }

    /// Whether a sealed value names a DEK this process does not hold yet.
    pub fn names_unheld(&self, ciphertext: &str) -> bool {
        secrets::dek_id_of(ciphertext)
            .map(|id| self.dek_for(id).is_none())
            .unwrap_or(false)
    }

    fn note_miss(&self, id: &str, label: &str) {
        let mut st = self.state();
        if st.missed.contains(id) {
            return;
        }
        if st.missed.len() < MAX_DERIVED_DEKS {
            st.missed.insert(id.to_string());
        }
        tracing::warn!(
            "{}keystore: a \"{}\" value names the data encryption key \"{}\", which this process does not hold; it \
             does not open. Said once per key.",
            tag(codes::STS_KEYS_0092),
            dek_class(label),
            id
        );
    }

    /// The stored digest key, oldest first (`digestKeyRec()`).
    fn digest_key(&self) -> Option<Vec<u8>> {
        let st = self.state();
        st.deks
            .values()
            .filter(|r| {
                r.cls == DIGEST_CLASS
                    && r.scope == "service"
                    && r.realm == "default"
                    && r.key.is_some()
                    && !r.derived
                    && !r.destroyed
            })
            .min_by(|a, b| {
                a.created_at
                    .partial_cmp(&b.created_at)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.id.cmp(&b.id))
            })
            .and_then(|r| r.key.clone())
    }

    /// `keyedDigest()`: an HMAC under a key derived from the stored digest
    /// key (or, where nothing is stored, the key-encryption key), base64url;
    /// `None` without one.
    pub fn keyed_digest(&self, label: &str, text: &str) -> Option<String> {
        self.kek.as_ref()?;
        let ikm = if self.stored {
            self.digest_key()?
        } else {
            secrets::kek_bytes(self.kek_input()?).ok()?
        };
        let info = format!("sts-keyed-digest:{}", label);
        let derived = hkdf_sha256(&ikm, info.as_bytes()).ok()?;
        let pkey = PKey::hmac(&derived).ok()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).ok()?;
        signer.update(text.as_bytes()).ok()?;
        Some(URL_SAFE_NO_PAD.encode(signer.sign_to_vec().ok()?))
    }

    /// `ensureDigestKey()`: made once for the service where none is stored;
    /// the union keeps whichever process wrote first.
    pub async fn ensure_digest_key(&self) {
        if !self.stored || self.digest_key().is_some() {
            return;
        }
        {
            let mut st = self.state();
            if let Err(e) =
                self.make(&mut st, "service", "default", DIGEST_CLASS)
            {
                tracing::error!(
                    "{}keystore: the digest key could not be made: {}",
                    tag(codes::STS_KEYS_0040),
                    e
                );
                return;
            }
        }
        self.settle().await;
    }

    /// `dekRowText()`: this process's DEKs of one scope and realm.
    fn row_of(&self, scope: &str, realm: &str) -> Json {
        let st = self.state();
        let mut list: Vec<&Dek> = st
            .deks
            .values()
            .filter(|r| {
                r.scope == scope
                    && r.realm == realm
                    && !r.derived
                    && (!r.wrapped.is_empty() || r.destroyed)
            })
            .collect();
        list.sort_by(|a, b| {
            a.created_at
                .partial_cmp(&b.created_at)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        });
        let deks: Vec<Json> = list
            .into_iter()
            .map(|r| {
                let mut item = json!({ "id": r.id, "cls": r.cls, "createdAt": r.created_at,
                    "alg": if r.alg.is_empty() { "aes-256-gcm" } else { &r.alg },
                    "activateAt": r.activation(), "wrappedAt": r.wrapped_at,
                    "status": if r.destroyed { "destroyed" } else { "active" },
                    "wrapped": if r.destroyed { "" } else { &r.wrapped } });
                if r.counted_at != 0.0 {
                    item["values"] = json!(r.values);
                    item["countedAt"] = json!(r.counted_at);
                }
                item
            })
            .collect();
        json!({ "v": DEK_ROW_VERSION, "scope": scope, "realm": realm, "deks": deks })
    }

    /// `settleDeks()`: every data-key row not yet in the store written, so
    /// a writer of sealed values stores nothing before the keys it was
    /// sealed under. A failed write is said (`STS-KEYS-0093`) and kept for
    /// the next settle.
    pub async fn settle(&self) {
        let _one = self.writing.lock().await;
        let Some(driver) = self.driver.clone() else {
            return;
        };
        let dirty: Vec<(String, String)> = {
            let mut st = self.state();
            std::mem::take(&mut st.dirty).into_iter().collect()
        };
        for (scope, realm) in dirty {
            let row_key = dek_row_key(&scope, &realm);
            let result =
                self.write_row(&driver, &row_key, &scope, &realm).await;
            match result {
                Ok(Some(material)) => {
                    if let Err(e) = self.adopt(&row_key, &material, false) {
                        tracing::error!("keystore: {}", e);
                    }
                    self.prune_digest_keys(&material);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(
                        "{}keystore: the \"{}\" data-key row could not be written: {}. What was sealed under its \
                         new keys will not open after a restart until it is.",
                        tag(codes::STS_KEYS_0093),
                        row_key,
                        e
                    );
                    self.state().dirty.insert((scope, realm));
                }
            }
        }
    }

    async fn write_row(
        &self,
        driver: &Arc<dyn Driver>,
        row_key: &str,
        scope: &str,
        realm: &str,
    ) -> Result<Option<String>, String> {
        let mine = self.row_of(scope, realm);
        if !driver.merges_keys() {
            let text = mine.to_string();
            driver
                .save_keys(row_key, &text)
                .await
                .map_err(|e| e.to_string())?;
            return Ok(Some(text));
        }
        // Twice at most: a row nobody had is inserted, and a process that
        // lost that race merges against the winner's.
        let mut last = String::new();
        for _ in 0..2 {
            let mine = mine.clone();
            let merge: crate::driver::KeyMerge =
                Box::new(move |current: Option<&str>| {
                    let theirs = match current {
                        Some(text) => {
                            Some(parse_dek_row(text).map_err(|e| {
                                // A row this build cannot read is NOT overwritten:
                                // replacing it would throw away DEKs other values
                                // were sealed under.
                                format!(
                                    "the stored row is not a data-key row ({})",
                                    e
                                )
                            })?)
                        }
                        None => None,
                    };
                    Ok(union_dek_rows(theirs.as_ref(), &mine)
                        .map(|row| row.to_string()))
                });
            match driver.merge_keys(row_key, merge).await {
                Ok(material) => return Ok(material),
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }

    /// `adoptDekRow()`: every DEK in a stored row this process does not
    /// hold, added and — where the scope is ours — unwrapped. One of ours
    /// that will not unwrap is the wrong key-encryption key, and `fatal`
    /// makes that stop the start.
    fn adopt(
        &self,
        row_key: &str,
        text: &str,
        fatal: bool,
    ) -> Result<usize, String> {
        let row = parse_dek_row(text).map_err(|e| {
            format!(
                "{}the \"{}\" data-key row could not be read: {}",
                tag(codes::STS_KEYS_0094),
                row_key,
                e
            )
        })?;
        let scope = str_of(&row, "scope");
        let realm = str_of(&row, "realm");
        let mut adopted = 0;
        let mut st = self.state();
        for one in row["deks"].as_array().cloned().unwrap_or_default() {
            let id = str_of(&one, "id");
            if !id_ok(&id) {
                continue;
            }
            let destroyed = str_of(&one, "status") == "destroyed";
            if let Some(held) = st.deks.get_mut(&id) {
                if destroyed && !held.destroyed {
                    held.destroyed = true;
                    held.key = None;
                    held.wrapped.clear();
                } else if !held.destroyed
                    && num(one.get("wrappedAt")) > held.wrapped_at
                {
                    held.wrapped = str_of(&one, "wrapped");
                    held.wrapped_at = num(one.get("wrappedAt"));
                }
                if num(one.get("countedAt")) > held.counted_at {
                    held.values = num(one.get("values"));
                    held.counted_at = num(one.get("countedAt"));
                }
                continue;
            }
            let created_at = num(one.get("createdAt"));
            let mut rec = Dek {
                id: id.clone(),
                scope: scope.clone(),
                realm: realm.clone(),
                cls: dek_class(&str_of(&one, "cls")),
                created_at,
                activate_at: match num(one.get("activateAt")) {
                    a if a != 0.0 => a,
                    _ => created_at,
                },
                wrapped_at: num(one.get("wrappedAt")),
                destroyed,
                wrapped: str_of(&one, "wrapped"),
                key: None,
                alg: if str_of(&one, "alg") == "aes-256-siv" {
                    "aes-256-siv".to_string()
                } else {
                    "aes-256-gcm".to_string()
                },
                values: num(one.get("values")),
                counted_at: num(one.get("countedAt")),
                derived: false,
            };
            if !rec.destroyed && self.wraps(&rec.scope) {
                let unwrapped = self
                    .kek_input()
                    .ok_or_else(|| "no key-encryption key is held".to_string())
                    .and_then(|k| {
                        secrets::unwrap_dek(k, &rec.wrapped, &rec.aad())
                            .map_err(|e| e.to_string())
                    });
                match unwrapped {
                    Ok(key) => {
                        rec.alg = secrets::dek_alg_of(&key).to_string();
                        rec.key = Some(key);
                    }
                    Err(e) => {
                        let why = format!(
                            "{}the data encryption key \"{}\" ({}, \"{}\" realm, {}) could not be unwrapped. The \
                             key-encryption key is almost certainly not the one it was wrapped under (provider: \
                             file): {}",
                            tag(codes::STS_KEYS_0091),
                            rec.id,
                            rec.cls,
                            rec.realm,
                            rec.scope,
                            e
                        );
                        if fatal {
                            return Err(format!(
                                "{}. This service will NOT start rather than make new keys, because everything \
                                 sealed under this one would stop opening.",
                                why
                            ));
                        }
                        tracing::error!("keystore: {}.", why);
                        continue;
                    }
                }
            }
            st.deks.insert(id, rec);
            adopted += 1;
        }
        if adopted > 0 {
            st.active.clear();
            st.missed.clear();
        }
        Ok(adopted)
    }

    /// `pruneDigestKeys()`: a digest key this process made that the stored
    /// row did not keep is dropped.
    fn prune_digest_keys(&self, material: &str) {
        let Ok(row) = parse_dek_row(material) else {
            return;
        };
        if str_of(&row, "scope") != "service"
            || str_of(&row, "realm") != "default"
        {
            return;
        }
        let kept: HashSet<String> = row["deks"]
            .as_array()
            .map(|list| {
                list.iter()
                    .filter(|one| {
                        dek_class(&str_of(one, "cls")) == DIGEST_CLASS
                    })
                    .map(|one| str_of(one, "id"))
                    .collect()
            })
            .unwrap_or_default();
        if kept.is_empty() {
            return;
        }
        let mut st = self.state();
        st.deks.retain(|id, rec| {
            !(rec.cls == DIGEST_CLASS
                && rec.scope == "service"
                && rec.realm == "default"
                && !kept.contains(id))
        });
    }

    /// Reads every stored data-key row and adopts what is new; `fatal` at
    /// the start. Answers how many DEKs were adopted.
    pub async fn load(&self, fatal: bool) -> Result<usize, String> {
        let Some(driver) = self.driver.clone() else {
            return Ok(0);
        };
        let rows = driver.load_keys().await.map_err(|e| {
            format!(
                "{}the stored key material could not be read: {}",
                tag(codes::STS_KEYS_0028),
                e
            )
        })?;
        self.state().reloaded_at = Some(Instant::now());
        let mut adopted = 0;
        for (row_key, material) in rows {
            if !row_key.starts_with(DEK_ROW_PREFIX) {
                continue;
            }
            match self.adopt(&row_key, &material, fatal) {
                Ok(n) => adopted += n,
                Err(e) if fatal => return Err(e),
                Err(e) => tracing::error!("keystore: {}.", e),
            }
        }
        Ok(adopted)
    }

    /// `reloadDekRows()`: the stored rows read again, at most every two
    /// seconds — for a process that met a value under a DEK it does not
    /// hold, whose ordinary cause is a DEK another process made a moment ago.
    pub async fn reload(&self) -> usize {
        if !self.stored {
            return 0;
        }
        let recent = self
            .state()
            .reloaded_at
            .map(|at| at.elapsed() < RELOAD_INTERVAL)
            .unwrap_or(false);
        if recent {
            return 0;
        }
        self.load(false).await.unwrap_or(0)
    }

    /// What `/admin/encryption` reports of the data keys.
    pub fn report(&self) -> Json {
        let st = self.state();
        let mut list: Vec<Json> = st
            .deks
            .values()
            .map(|r| {
                json!({ "id": r.id, "scope": r.scope, "realm": r.realm, "class": r.cls,
                        "alg": r.alg, "createdAt": r.created_at, "activateAt": r.activation(),
                        "status": if r.destroyed { "destroyed" } else { "active" },
                        "held": r.key.is_some(), "derived": r.derived })
            })
            .collect();
        list.sort_by_key(|a| str_of(a, "id"));
        json!({ "sealed": self.kek.is_some(), "stored": self.stored,
                "pendingRows": st.dirty.len(), "deks": list })
    }
}

/// HKDF-SHA256 with an empty salt, 32 bytes (node's `hkdfSync`).
fn hkdf_sha256(
    ikm: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let salt = [0u8; 32];
    let prk = {
        let key = PKey::hmac(&salt)?;
        let mut s = Signer::new(MessageDigest::sha256(), &key)?;
        s.update(ikm)?;
        s.sign_to_vec()?
    };
    let key = PKey::hmac(&prk)?;
    let mut s = Signer::new(MessageDigest::sha256(), &key)?;
    s.update(info)?;
    s.update(&[1u8])?;
    s.sign_to_vec()
}
