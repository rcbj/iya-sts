// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE USED-ASSERTION HISTORY (#444, phase 5, the `oauth6` slice):
//! `common/used_assertions.js` — every RFC 7523 JWT, RFC 7522 assertion and
//! RFC 9101 request object this service has accepted, so that none is
//! accepted twice, EVER, by any process on the store.
//!
//! * **ONE ROW PER DOCUMENT**, keyed by its FORMAT, ISSUER and IDENTIFIER
//!   (`keyOf()`: base64url SHA-256 over the three joined by `\n`) and NOT
//!   by what it was presented as — so a JWT that authenticated a client
//!   cannot then be a request object or a grant. The key and the table
//!   (`sts_used_assertions`) are Node's, so a row either runtime writes
//!   refuses the other's replay.
//! * **AN ATOMIC CLAIM IN THE STORE** (`claimInDatabase()`): one `INSERT …
//!   ON CONFLICT`, the primary key arbitrating; a realm holding
//!   `oauth2.assertionReplayCacheSize` live rows refuses (the cap refuses,
//!   it never forgets); a store that cannot be asked refuses (fail closed).
//! * **THE FOUR TEXT COLUMNS ARE SEALED** where the keystore persists and
//!   holds a key-encryption key (`sealedRowOf()`, label `used-assertion`,
//!   the realm's data key), and opened when read back.
//! * **RESERVED, THEN SETTLED** (`bindToResponse()`, `settle()`): a claim
//!   made for a request is `reserved`, made `spent` when the answer is a
//!   2xx (below `keepBelow`) and deleted otherwise — a document that bought
//!   nothing has not been used.
//!
//! Without a database store (memory, ldif) the history is this process's,
//! as Node's `claimInMemory()` is; ldif's file per realm is not ported.
//!
//! THE SYNCHRONOUS VERIFIERS READ A RESERVATION MADE ON ARRIVAL. The
//! client-assertion verifier (`client_auth.rs`) and the request-object
//! verifier are synchronous, and the claim is a round trip, so the door
//! claims first — from the UNVERIFIED document, as `dpop.ts`'s
//! `proofClaims()` reserves a proof's `jti` — and the verifier consults
//! that answer through [`Arrival`] ([`ARRIVAL`], a task-local); the
//! reservation is spent when the answer is a 2xx and the verifier accepted
//! the document, and released otherwise, which is Node's outcome for every
//! request: a forged document reserves nothing that outlives its refusal.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::settings::Settings;

/// `DEFAULT_CAP`.
pub const DEFAULT_CAP: i64 = 1000;
/// `MAX_SHOWN`: what a row draws of an issuer or identifier.
pub const MAX_SHOWN: usize = 512;
/// `SEALED_LABEL`.
pub const SEALED_LABEL: &str = "used-assertion";

/// `FORMATS`' keys.
pub const FORMATS: [&str; 7] = [
    "jwt",
    "openid2",
    "saml",
    "saml11",
    "saml-message",
    "attestation-challenge",
    "wss-message",
];

/// One row, as `used_assertions.js` holds it (`sts_store`'s columns).
pub type Row = sts_store::driver::UsedAssertionRow;

/// A future of the store.
pub type UsedFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The store's three statements (`claimUsedAssertion()`,
/// `settleUsedAssertion()`, `findUsedAssertion()`), or `holds() == false`
/// where it has no table.
pub trait UsedStore: Send + Sync {
    fn holds(&self) -> bool;
    fn origin(&self) -> String {
        "local".to_string()
    }
    fn claim<'a>(
        &'a self,
        row: &'a Row,
        cap: i64,
        now_ms: i64,
    ) -> UsedFuture<'a, Result<sts_store::driver::UsedClaim, String>>;
    fn settle<'a>(
        &'a self,
        realm: &'a str,
        key: &'a str,
        reservation: &'a str,
        spent: bool,
        at_ms: i64,
    ) -> UsedFuture<'a, Result<u64, String>>;
    fn find<'a>(
        &'a self,
        realm: &'a str,
        key: &'a str,
        now_ms: i64,
    ) -> UsedFuture<'a, Result<Option<Row>, String>>;
}

/// No database: the history is this process's.
pub struct NoStore;

impl UsedStore for NoStore {
    fn holds(&self) -> bool {
        false
    }
    fn claim<'a>(
        &'a self,
        _row: &'a Row,
        _cap: i64,
        _now_ms: i64,
    ) -> UsedFuture<'a, Result<sts_store::driver::UsedClaim, String>> {
        Box::pin(async { Err("no store".to_string()) })
    }
    fn settle<'a>(
        &'a self,
        _realm: &'a str,
        _key: &'a str,
        _reservation: &'a str,
        _spent: bool,
        _at_ms: i64,
    ) -> UsedFuture<'a, Result<u64, String>> {
        Box::pin(async { Ok(0) })
    }
    fn find<'a>(
        &'a self,
        _realm: &'a str,
        _key: &'a str,
        _now_ms: i64,
    ) -> UsedFuture<'a, Result<Option<Row>, String>> {
        Box::pin(async { Ok(None) })
    }
}

/// The keystore's seal and open for the four text columns.
pub trait Sealer: Send + Sync {
    /// `keystore.persists() && keystore.sealed()`.
    fn seals(&self) -> bool;
    fn seal(&self, text: &str, label: &str, realm: &str) -> Option<String>;
    fn open(&self, text: &str, label: &str) -> Option<String>;
}

/// Nothing seals.
pub struct NoSealer;

impl Sealer for NoSealer {
    fn seals(&self) -> bool {
        false
    }
    fn seal(&self, _: &str, _: &str, _: &str) -> Option<String> {
        None
    }
    fn open(&self, _: &str, _: &str) -> Option<String> {
        None
    }
}

/// What a caller asks to claim (`claim(opts)`).
#[derive(Clone, Debug, Default)]
pub struct ClaimAsk {
    pub format: String,
    /// `client-authentication`, `authorization-grant`, `request-object`, …
    pub use_: String,
    pub issuer: String,
    pub identifier: String,
    /// When the row may go, ms (the document's expiry plus the skew).
    pub expires_at: i64,
    pub client_id: String,
    pub subject: String,
    /// A claim bound to a response is RESERVED; one without is spent.
    pub reserve: bool,
}

/// What a caller holds: enough to settle this one row (`handleOf()`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handle {
    pub realm: String,
    pub key: String,
    pub reservation: String,
    pub state: String,
}

/// Why a claim was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum Refused {
    /// Held already; the row as a page draws it (`publicRow()`).
    Replay(Json),
    /// The realm holds as many live rows as it may.
    Full { live: i64, cap: i64 },
    /// It could not be asked or written.
    Store(String),
}

/// `clip(value)`.
fn clip(value: &str) -> String {
    if value.encode_utf16().count() <= MAX_SHOWN {
        return value.to_string();
    }
    let units: Vec<u16> = value.encode_utf16().take(MAX_SHOWN).collect();
    format!("{}…", String::from_utf16_lossy(&units))
}

/// `keyOf(format, issuer, identifier)`: base64url SHA-256 over the three.
#[tracing::instrument(level = "debug", skip_all)]
pub fn key_of(format: &str, issuer: &str, identifier: &str) -> String {
    sts_crypto::b64::encode(
        &sts_crypto::jws_alg::Hash::Sha256.digest(
            format!("{}\n{}\n{}", format, issuer, identifier).as_bytes(),
        ),
    )
}

/// `publicRow(row)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn public_row(row: &Row) -> Json {
    json!({ "format": row.format, "use": row.used_as, "issuer": row.issuer,
            "identifier": row.identifier, "clientId": row.client_id,
            "subject": row.subject, "state": row.state,
            "usedAt": row.used_at, "spentAt": row.spent_at,
            "expiresAt": row.expires_at, "origin": row.origin })
}

/// `usedAs(existing)`: what a replay refusal appends about the earlier use.
#[tracing::instrument(level = "debug", skip_all)]
pub fn used_as(existing: &Json) -> String {
    let field = |k: &str| crate::js::string_of(existing.get(k));
    let in_flight = if field("state") == "reserved" {
        ", by a request that has not finished yet"
    } else {
        ""
    };
    let use_ = field("use");
    match use_.as_str() {
        "request-object" => {
            format!(" — as an RFC 9101 request object{}", in_flight)
        }
        "client-attestation-pop" => format!(
            " — as a client attestation proof of possession{}",
            in_flight
        ),
        "token-exchange" => {
            format!(" — in an RFC 8693 token exchange{}", in_flight)
        }
        _ if field("format") == "saml" => format!(
            " — under RFC 7522 section {}{}",
            if use_ == "authorization-grant" {
                "2.1"
            } else {
                "2.2"
            },
            in_flight
        ),
        _ => format!(
            " — as {}{}",
            if use_ == "authorization-grant" {
                "an authorization grant"
            } else {
                "a client assertion"
            },
            in_flight
        ),
    }
}

/// The history.
pub struct UsedAssertions {
    pub settings: Arc<Settings>,
    pub store: Arc<dyn UsedStore>,
    pub sealer: Arc<dyn Sealer>,
    pub now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    memory: Mutex<HashMap<(String, String), Row>>,
}

impl UsedAssertions {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        settings: Arc<Settings>,
        store: Arc<dyn UsedStore>,
        sealer: Arc<dyn Sealer>,
        now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> UsedAssertions {
        UsedAssertions {
            settings,
            store,
            sealer,
            now_ms,
            memory: Mutex::new(HashMap::new()),
        }
    }

    /// `capOf()`.
    fn cap(&self) -> i64 {
        match self
            .settings
            .value_of("oauth2.assertionReplayCacheSize")
            .as_int()
        {
            n if n > 0 => n,
            _ => DEFAULT_CAP,
        }
    }

    fn sealed_row(&self, row: &Row) -> Row {
        if !self.sealer.seals() {
            return row.clone();
        }
        let mut out = row.clone();
        for field in [
            &mut out.issuer,
            &mut out.identifier,
            &mut out.client_id,
            &mut out.subject,
        ] {
            if !field.is_empty() {
                if let Some(sealed) =
                    self.sealer.seal(field, SEALED_LABEL, &row.realm)
                {
                    *field = sealed;
                }
            }
        }
        out
    }

    fn opened_row(&self, row: &Row) -> Row {
        let mut out = row.clone();
        for field in [
            &mut out.issuer,
            &mut out.identifier,
            &mut out.client_id,
            &mut out.subject,
        ] {
            if sts_crypto::secrets::dek_id_of(field).is_some() {
                *field = self
                    .sealer
                    .open(field, SEALED_LABEL)
                    .unwrap_or_else(|| "(unreadable)".to_string());
            }
        }
        out
    }

    /// `claim(opts)`: the document's use claimed in the ambient realm.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn claim(&self, ask: &ClaimAsk) -> Result<Handle, Refused> {
        if !FORMATS.contains(&ask.format.as_str())
            || ask.use_.is_empty()
            || ask.issuer.is_empty()
            || ask.identifier.is_empty()
        {
            return Err(Refused::Store(
                "a claim needs a format, a use, an issuer and an identifier"
                    .into(),
            ));
        }
        let now = (self.now_ms)();
        let realm = sts_core::realm::current_id();
        let reservation = sts_crypto::b64::encode(
            &sts_crypto::random::random_bytes(12).unwrap_or_default(),
        );
        let row = Row {
            realm: realm.clone(),
            key: key_of(&ask.format, &ask.issuer, &ask.identifier),
            format: ask.format.clone(),
            used_as: ask.use_.clone(),
            issuer: clip(&ask.issuer),
            identifier: clip(&ask.identifier),
            client_id: clip(&ask.client_id),
            subject: clip(&ask.subject),
            state: if ask.reserve { "reserved" } else { "spent" }.into(),
            reservation,
            origin: self.store.origin(),
            used_at: now,
            spent_at: if ask.reserve { 0 } else { now },
            expires_at: ask.expires_at.max(now),
        };
        let handle = Handle {
            realm: row.realm.clone(),
            key: row.key.clone(),
            reservation: row.reservation.clone(),
            state: row.state.clone(),
        };
        let cap = self.cap();
        if !self.store.holds() {
            return self.claim_in_memory(row, cap, now).map(|_| handle);
        }
        match self.store.claim(&self.sealed_row(&row), cap, now).await {
            Ok(a) if a.claimed => Ok(handle),
            Ok(a) => match a.existing {
                Some(existing) => Err(Refused::Replay(public_row(
                    &self.opened_row(&existing),
                ))),
                None => Err(Refused::Full { live: a.live, cap }),
            },
            Err(e) => {
                tracing::error!(
                    "{}used assertions: the store could not be asked whether \
                     an assertion from \"{}\" has been used: {}. It is \
                     refused.",
                    tag(codes::STS_STORE_0046),
                    row.issuer,
                    e
                );
                Err(Refused::Store(format!(
                    "the used-assertion history could not be consulted: {}",
                    e
                )))
            }
        }
    }

    fn claim_in_memory(
        &self,
        row: Row,
        cap: i64,
        now: i64,
    ) -> Result<(), Refused> {
        let mut held =
            self.memory.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|_, r| r.expires_at >= now);
        let at = (row.realm.clone(), row.key.clone());
        if let Some(existing) = held.get(&at) {
            return Err(Refused::Replay(public_row(existing)));
        }
        let live = held.keys().filter(|(r, _)| *r == row.realm).count() as i64;
        if live >= cap {
            return Err(Refused::Full { live, cap });
        }
        held.insert(at, row);
        Ok(())
    }

    /// `peek(opts)`: whether a live row holds this document — a look that
    /// decides nothing (`None`: the store could not say).
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn peek(
        &self,
        format: &str,
        issuer: &str,
        identifier: &str,
    ) -> Option<Json> {
        if issuer.is_empty() || identifier.is_empty() {
            return None;
        }
        let now = (self.now_ms)();
        let realm = sts_core::realm::current_id();
        let key = key_of(format, issuer, identifier);
        if !self.store.holds() {
            let held =
                self.memory.lock().unwrap_or_else(PoisonError::into_inner);
            return held
                .get(&(realm, key))
                .filter(|r| r.expires_at >= now)
                .map(public_row);
        }
        match self.store.find(&realm, &key, now).await {
            Ok(found) => found.map(|r| public_row(&self.opened_row(&r))),
            Err(e) => {
                tracing::warn!(
                    "{}used assertions: the store could not be asked whether \
                     a document from \"{}\" has been used: {}. The look is \
                     answered \"not known\"; the claim that decides fails \
                     closed.",
                    tag(codes::STS_STORE_0046),
                    clip(issuer),
                    e
                );
                None
            }
        }
    }

    /// `settle(handle, spent)`: a reservation made `spent`, or released.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn settle(&self, handle: &Handle, spent: bool) {
        let at = (self.now_ms)();
        if !self.store.holds() {
            let mut held =
                self.memory.lock().unwrap_or_else(PoisonError::into_inner);
            let at_key = (handle.realm.clone(), handle.key.clone());
            let ours = held
                .get(&at_key)
                .is_some_and(|r| r.reservation == handle.reservation);
            if !ours {
                return;
            }
            if spent {
                if let Some(r) = held.get_mut(&at_key) {
                    r.state = "spent".into();
                    r.spent_at = at;
                }
            } else {
                held.remove(&at_key);
            }
            return;
        }
        if let Err(e) = self
            .store
            .settle(&handle.realm, &handle.key, &handle.reservation, spent, at)
            .await
        {
            tracing::error!(
                "{}used assertions: {} a claim failed: {}. The row stays \
                 reserved until the assertion expires, which refuses a \
                 replay and {}",
                tag(codes::STS_STORE_0048),
                if spent { "confirming" } else { "releasing" },
                e,
                if spent {
                    "changes nothing else."
                } else {
                    "also refuses the retry this release was for."
                }
            );
        }
    }

    /// `summary().live`, of what this process holds in memory.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn live_here(&self, now_ms: i64) -> usize {
        let realm = sts_core::realm::current_id();
        self.memory
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|((r, _), row)| *r == realm && row.expires_at >= now_ms)
            .count()
    }
}

// -----------------------------------------------------------------------
// THE ARRIVAL RESERVATION the synchronous verifiers read.
// -----------------------------------------------------------------------

/// One document claimed on arrival: what it was claimed as and the answer.
#[derive(Clone, Debug)]
pub struct Reserved {
    pub issuer: String,
    pub identifier: String,
    pub answer: Result<Handle, Refused>,
    /// Set when the verifier accepted the document: the reservation is
    /// kept if the answer is a 2xx.
    pub accepted: bool,
}

/// The reservations of one request.
#[derive(Default)]
pub struct Arrival {
    pub held: Mutex<Vec<Reserved>>,
}

tokio::task_local! {
    /// The request's arrival reservations, where its door made any.
    pub static ARRIVAL: Arc<Arrival>;
}

impl Arrival {
    /// The answer for a document the verifier is about to accept, marked
    /// accepted; `None` where nothing was claimed for it on arrival.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn take(
        &self,
        issuer: &str,
        identifier: &str,
    ) -> Option<Result<Handle, Refused>> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let one = held
            .iter_mut()
            .find(|r| r.issuer == issuer && r.identifier == identifier)?;
        one.accepted = true;
        Some(one.answer.clone())
    }

    /// Another arrival's reservations, held here too.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn absorb(&self, other: &Arrival) {
        let moved: Vec<Reserved> = std::mem::take(
            &mut *other.held.lock().unwrap_or_else(PoisonError::into_inner),
        );
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(moved);
    }

    /// The answer for a document without accepting it (`lookUp()`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn look(
        &self,
        issuer: &str,
        identifier: &str,
    ) -> Option<Result<Handle, Refused>> {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.iter()
            .find(|r| r.issuer == issuer && r.identifier == identifier)
            .map(|r| r.answer.clone())
    }

    /// The reservations, settled: spent where accepted and the status a
    /// 2xx, released otherwise.
    /// `keep_below` is the status from which a reservation is released
    /// (`keepBelow`, 300 at the token endpoint; an authorization response
    /// is a redirect, so the authorization endpoint passes 400).
    #[tracing::instrument(level = "debug", skip(self, history))]
    pub async fn settle(
        &self,
        history: &UsedAssertions,
        status: u16,
        keep_below: u16,
    ) {
        let held: Vec<Reserved> = std::mem::take(
            &mut *self.held.lock().unwrap_or_else(PoisonError::into_inner),
        );
        for one in held {
            if let Ok(handle) = &one.answer {
                let spent =
                    one.accepted && status >= 200 && status < keep_below;
                history.settle(handle, spent).await;
            }
        }
    }
}

/// The ambient arrival, where the request has one.
#[tracing::instrument(level = "trace")]
pub fn arrival() -> Option<Arc<Arrival>> {
    ARRIVAL.try_with(|a| a.clone()).ok()
}

/// A compact JWT's claims, read WITHOUT verifying it.
#[tracing::instrument(level = "trace", skip_all)]
pub fn unverified_claims(jwt: &str) -> Option<Json> {
    if jwt.split('.').count() != 3 {
        return None;
    }
    crate::js::segment_json(jwt, 1).ok()
}

/// The client-assertion verifier's history over the shared one: the
/// claim made on arrival, where the door made one ([`reserve_for_token`]);
/// this process's own history otherwise.
pub struct SharedAssertionHistory {
    pub local: crate::client_auth::MemoryAssertionHistory,
}

impl crate::client_auth::AssertionHistory for SharedAssertionHistory {
    fn claim(
        &self,
        claim: &crate::client_auth::AssertionClaim,
    ) -> crate::client_auth::Spent {
        use crate::client_auth::Spent;
        let Some(found) =
            arrival().and_then(|a| a.take(&claim.issuer, &claim.identifier))
        else {
            return self.local.claim(claim);
        };
        match found {
            Ok(_) => Spent::Ok,
            Err(Refused::Replay(row)) => Spent::Replay(used_as(&row)),
            Err(Refused::Full { live, .. }) => Spent::Full(live),
            Err(Refused::Store(_)) => Spent::Failed,
        }
    }

    fn live(&self, now_ms: i64) -> usize {
        self.local.live(now_ms)
    }
}

/// THE TOKEN ENDPOINT'S AND PAR'S ARRIVAL CLAIM: a `client_assertion`'s
/// `jti`, read unverified, claimed RESERVED as `client-authentication`
/// under the client it names (`verifyAssertion()`'s `issuer: clientId`),
/// remembered until its `exp` (or `oauth2.jwtBearerMaxLifetimeS` from now)
/// plus `oauth2.clientAssertionSkewS`.
#[tracing::instrument(level = "debug", skip_all)]
pub async fn reserve_for_token(
    history: &UsedAssertions,
    body: &serde_json::Map<String, Json>,
    client_id: &str,
) -> Arc<Arrival> {
    let out = Arc::new(Arrival::default());
    let assertion = crate::js::string_of(body.get("client_assertion"));
    let Some(claims) = unverified_claims(&assertion) else {
        return out;
    };
    let jti = crate::js::string_of(claims.get("jti"));
    let named = crate::js::string_of(claims.get("sub"));
    let client = if client_id.is_empty() {
        named
    } else {
        client_id.to_string()
    };
    if jti.is_empty() || client.is_empty() {
        return out;
    }
    let now = (history.now_ms)();
    let skew = history
        .settings
        .value_of("oauth2.clientAssertionSkewS")
        .as_int();
    let remembered = match claims.get("exp") {
        Some(exp) if !exp.is_null() => {
            (crate::js::to_number(exp) * 1000.0) as i64
        }
        _ => {
            let s = history
                .settings
                .value_of("oauth2.jwtBearerMaxLifetimeS")
                .as_int();
            now + if s > 0 { s } else { 300 } * 1000
        }
    };
    let answer = history
        .claim(&ClaimAsk {
            format: "jwt".into(),
            use_: "client-authentication".into(),
            issuer: client.clone(),
            identifier: jti.clone(),
            expires_at: remembered + skew * 1000,
            client_id: client.clone(),
            subject: client.clone(),
            reserve: true,
        })
        .await;
    out.held
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Reserved {
            issuer: client,
            identifier: jti,
            answer,
            accepted: false,
        });
    out
}

/// THE AUTHORIZATION ENDPOINT'S AND PAR'S ARRIVAL CLAIM for an RFC 9101
/// request object passed by value: its `jti`, read unverified, claimed
/// RESERVED as `request-object` under its client (`iss`, else the
/// request's `client_id`) until its `exp` (ten minutes where it has none).
/// The verifier's `lookUp()` refuses a replay from it, and `spend()` keeps
/// it.
#[tracing::instrument(level = "debug", skip_all)]
pub async fn reserve_request_object(
    history: &UsedAssertions,
    query: &serde_json::Map<String, Json>,
) -> Arc<Arrival> {
    let out = Arc::new(Arrival::default());
    let object = crate::js::string_of(query.get("request"));
    let Some(claims) = unverified_claims(&object) else {
        return out;
    };
    let jti = crate::js::string_of(claims.get("jti"));
    let mut client = crate::js::string_of(query.get("client_id"));
    if client.is_empty() {
        client = crate::js::string_of(claims.get("client_id"));
    }
    if jti.is_empty() || client.is_empty() {
        return out;
    }
    let now = (history.now_ms)();
    let expires = match claims.get("exp") {
        Some(exp) if !exp.is_null() => {
            (crate::js::to_number(exp) * 1000.0) as i64
        }
        _ => now + 600_000,
    };
    let answer = history
        .claim(&ClaimAsk {
            format: "jwt".into(),
            use_: "request-object".into(),
            issuer: client.clone(),
            identifier: jti.clone(),
            expires_at: expires,
            client_id: client.clone(),
            reserve: true,
            ..ClaimAsk::default()
        })
        .await;
    out.held
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Reserved {
            issuer: client,
            identifier: jti,
            answer,
            accepted: false,
        });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history() -> UsedAssertions {
        UsedAssertions::new(
            Arc::new(Settings::new(Json::Null, HashMap::new())),
            Arc::new(NoStore),
            Arc::new(NoSealer),
            Arc::new(|| 1_000_000),
        )
    }

    fn ask() -> ClaimAsk {
        ClaimAsk {
            format: "jwt".into(),
            use_: "client-authentication".into(),
            issuer: "c".into(),
            identifier: "j".into(),
            expires_at: 2_000_000,
            client_id: "c".into(),
            reserve: true,
            ..ClaimAsk::default()
        }
    }

    #[tokio::test]
    async fn a_document_is_claimed_once_whatever_it_is_used_as() {
        let h = history();
        let held = h.claim(&ask()).await.unwrap();
        let mut again = ask();
        again.use_ = "request-object".into();
        match h.claim(&again).await {
            Err(Refused::Replay(row)) => {
                assert_eq!(
                    used_as(&row),
                    " — as a client assertion, by a request that has not \
                     finished yet"
                );
            }
            other => panic!("{:?}", other),
        }
        h.settle(&held, false).await;
        assert!(h.claim(&again).await.is_ok());
    }

    #[test]
    fn the_key_is_the_digest_of_the_three() {
        assert_eq!(key_of("jwt", "c", "j").len(), 43);
        assert_ne!(key_of("jwt", "c", "j"), key_of("saml", "c", "j"));
    }
}
