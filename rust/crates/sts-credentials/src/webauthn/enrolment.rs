// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A PASSKEY ENROLLED, AND USED: the key doors of `common/credentials.ts`
//! — `beginKeyEnrolment()` / `confirmKeyEnrolment()` (two steps, and the
//! first writes nothing but a pending challenge), `addKeyClaimed()` and
//! `addKey()` (THE ONE WRITER of a key, where the WebAuthn policy, the
//! lanes, the passkey policy's registration rules and the cap are
//! enforced, whatever door began the ceremony), `spendAssertion()` and
//! `noteKeyUsed()` (the signature counter, across the cluster, and the
//! cloned key it exposes), with every refusal, sentence and code Node's.
//!
//! **The stored credential is Node's directory shape**: one JSON value of
//! `stsWebauthnCredential` per key, its members in Node's order, so a key
//! one process wrote is read by the other (`keysOf()`), and Node verifies
//! an assertion with a key this crate stored.
//!
//! WHAT REPLACED WHAT. `Credentials`' module-level reaches —
//! `passkey_clients.offerFor()` (whose decision is ported here, over its
//! client name and learned entry), `webauthn_ceremonies.record()`,
//! `risk_datasets.mdsState()`, `ssf/account_signals` and `risk_engine` for
//! a cloned key, `attestation_revocation.noteRegistration()` — and its
//! deps `webauthnPolicy`, `passkeyPolicy`, `claims` and `counters` are the
//! traits below, handed to the constructor. The verifier and the
//! attestation are this crate's ([`super::ceremony`], [`super::trust`]).
//! Node answers a PROMISE from `confirmKeyEnrolment()` because its claim
//! is a store round trip; here every port answers in turn, so the doors are
//! synchronous and the order of their questions is Node's.
//!
//! NOT HERE: the PQC upgrade's three steps (#939), an administrator's
//! enrolment on somebody's behalf (#945) and the usernameless sign-in's
//! user-handle owner lookup (#474) — each a door of its own over the same
//! writer, which a later slice ports. `addKey()`'s `upgrade` option is
//! theirs and is not accepted here.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Retain, StoreHandles, StoreSpec,
};

use super::ceremony::{verify_registration, RegistrationInput};
use super::trust::{
    aaguid_string, recorded_algorithms, Attestation, AttestationPorts,
};
use crate::credentials::Credentials;
use crate::js;
use crate::ports::{Environment, Hook};
use crate::Verdict;

/// The claim scope a registration's credential id is claimed under.
pub const WEBAUTHN_REGISTRATION_SCOPE: &str = "authn.webauthn-registration";
/// How long a registration's credential id claim is held.
pub const WEBAUTHN_REGISTRATION_CLAIM_MS: f64 = 30.0 * 60.0 * 1000.0;
/// The claim scope a WebAuthn challenge is spent under.
pub const WEBAUTHN_CHALLENGE_SCOPE: &str = "authn.webauthn-challenge";
/// The counter scope a key's signature count is advanced under.
pub const WEBAUTHN_COUNTER_SCOPE: &str = "authn.webauthn-sign-count";
/// `Credentials.ADMIN_ENROLMENT_OFF`.
pub const ADMIN_ENROLMENT_OFF: &str = "This person's passkey policy does not \
    let an administrator enrol a passkey for them (adminEnrolment is off). \
    Turn it on under Directory → Policies → Passkeys, or have them create \
    one themselves on their account page.";

/// `authn/passkey_providers.ts`'s table: AAGUID → the name the credential
/// manager uses for itself.
const PROVIDERS: [(&str, &str); 14] = [
    (
        "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
        "Google Password Manager",
    ),
    ("adce0002-35bc-c60a-648b-0b25f1f05503", "Chrome on Mac"),
    ("fbfc3007-154e-4ecc-8c0b-6e020557d7bd", "iCloud Keychain"),
    (
        "dd4ec289-e01d-41c9-bb89-70fa845d4bf2",
        "iCloud Keychain (Managed)",
    ),
    ("08987058-cadc-4b81-b6e1-30de50dcbe96", "Windows Hello"),
    ("9ddd1817-af5a-4672-a2b9-3e3dd95000a9", "Windows Hello"),
    ("6028b017-b1d4-4c02-b4b3-afcdafc96bb2", "Windows Hello"),
    ("bada5566-a7aa-401f-bd96-45619a55120d", "1Password"),
    ("d548826e-79b4-db40-a3d8-11116f7e8349", "Bitwarden"),
    ("531126d6-e717-415c-9320-3d9aa6981239", "Dashlane"),
    ("53414d53-554e-4700-0000-000000000000", "Samsung Pass"),
    ("50726f74-6f6e-5061-7373-50726f746f6e", "Proton Pass"),
    ("fdb141b2-5d84-443e-8a35-4698c205a502", "KeePassXC"),
    ("f3809540-7f14-49c1-a8b3-8f813b225541", "Enpass"),
];

/// `FAILED_CHECK_CODES`: the code a failed ceremony check is refused with.
fn failed_check_code(check: &str) -> Option<ErrorCode> {
    Some(match check {
        "clientData.type is webauthn.create"
        | "clientData.type is webauthn.get" => codes::STS_AUTHN_0028,
        "challenge matches" => codes::STS_AUTHN_0029,
        "origin matches" => codes::STS_AUTHN_0030,
        "rpIdHash is SHA-256 of the RP ID" => codes::STS_AUTHN_0031,
        "user presence" => codes::STS_AUTHN_0032,
        "user verification" => codes::STS_AUTHN_0033,
        "attested credential data present" => codes::STS_AUTHN_0034,
        "signature counter advanced" => codes::STS_AUTHN_0035,
        "signature verifies" => codes::STS_AUTHN_0036,
        "credential algorithm was offered" => codes::STS_AUTHN_0228,
        "credential ID is at most 1023 bytes" => codes::STS_AUTHN_0229,
        "backup state only where backup eligible" => codes::STS_AUTHN_0230,
        "algorithm is allowed" => codes::STS_AUTHN_0294,
        _ => return None,
    })
}

/// `WebauthnPolicy.failureCodeFor(verdict)`: the first failed check's
/// code, else STS-AUTHN-0037.
#[tracing::instrument(level = "debug", skip_all)]
pub fn failure_code_for(verdict: &Json) -> ErrorCode {
    verdict["failed"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|f| failed_check_code(f.as_str().unwrap_or("")))
        .unwrap_or(codes::STS_AUTHN_0037)
}

/// `WebauthnPolicy.heldToOffer(now, offered)`: the list now, no wider than
/// what the ceremony's begin recorded.
#[tracing::instrument(level = "debug", skip_all)]
pub fn held_to_offer(now: &[f64], offered: &Json) -> Vec<f64> {
    let Some(asked) = offered.as_array().filter(|l| !l.is_empty()) else {
        return now.to_vec();
    };
    let asked: Vec<f64> = asked.iter().map(js::number).collect();
    now.iter()
        .copied()
        .filter(|id| asked.contains(id))
        .collect()
}

/// `Credentials.clonedKeyVerdict(verdict)`: the counter check the ONLY
/// one that failed, so the signature verified.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cloned_key_verdict(verdict: &Json) -> bool {
    let failed = verdict["failed"].as_array().cloned().unwrap_or_default();
    verdict["ok"] == json!(false)
        && failed.len() == 1
        && failed[0] == json!("signature counter advanced")
}

/// `Credentials.isUserHandle(value)`: 64 bytes this service minted,
/// base64url — exactly 86 characters.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_user_handle(value: &Json) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 86
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

/// `PasskeyProviders.nameOf(aaguid)`.
#[tracing::instrument(level = "debug")]
pub fn provider_name_of(aaguid: &str) -> String {
    let id = aaguid_string(aaguid);
    let hex = aaguid.to_lowercase().replace('-', "");
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return String::new();
    }
    let id = if id.is_empty() {
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    } else {
        id
    };
    PROVIDERS
        .iter()
        .find(|(k, _)| *k == id)
        .map_or(String::new(), |(_, n)| (*n).to_string())
}

/// `Credentials.keyGroup(key)`: `device` or `security-key`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn key_group(key: &Json) -> &'static str {
    if key.get("backupEligible") == Some(&json!(true)) {
        return "device";
    }
    match key.get("attachment").and_then(Json::as_str) {
        Some("platform") => return "device",
        Some("cross-platform") => return "security-key",
        _ => {}
    }
    let transports: Vec<String> = key["transports"]
        .as_array()
        .map(|l| l.iter().map(js::string).collect())
        .unwrap_or_default();
    if !transports.is_empty()
        && transports
            .iter()
            .all(|t| ["usb", "nfc", "ble", "smart-card"].contains(&t.as_str()))
    {
        "security-key"
    } else {
        "device"
    }
}

/// `Credentials.keyProvider(key)`: the recorded provider, else the model
/// its attestation named, else the table's.
#[tracing::instrument(level = "debug", skip_all)]
pub fn key_provider(key: &Json) -> String {
    if let Some(source) = key.get("providerSource").and_then(Json::as_str) {
        if ["mds", "table", ""].contains(&source) {
            return js::string_or_empty(key.get("provider"));
        }
    }
    let model = js::string_or_empty(key["attestation"].get("model"));
    if !model.is_empty() {
        return model;
    }
    provider_name_of(&js::string_or_empty(key.get("aaguid")))
}

/// `Credentials.defaultKeyName(key)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn default_key_name(key: &Json) -> String {
    let provider = key_provider(key);
    if !provider.is_empty() {
        provider
    } else if key_group(key) == "security-key" {
        "Security key".to_string()
    } else {
        "Passkey".to_string()
    }
}

/// `Credentials.enrolledByOf(raw)`: `{ username, sub, at }`, or none.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enrolled_by_of(raw: &Json) -> Option<Json> {
    if !raw.is_object() {
        return None;
    }
    let clean = |v: Option<&Json>| -> String {
        let t = match v {
            Some(x) if js::truthy(x) => js::string(x),
            _ => String::new(),
        };
        let t: String = js::trim(&t)
            .chars()
            .filter(|c| !((*c as u32) <= 0x1f || *c as u32 == 0x7f))
            .collect();
        let units: Vec<u16> = t.encode_utf16().take(256).collect();
        String::from_utf16_lossy(&units)
    };
    let username = clean(raw.get("username"));
    if username.is_empty() {
        return None;
    }
    let at = js::number_opt(raw.get("at"));
    Some(json!({ "username": username, "sub": clean(raw.get("sub")),
        "at": js::num(if at.is_finite() && at > 0.0 { at.floor() }
                      else { 0.0 }) }))
}

/// `Credentials.isAndroidRecheckable(key)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_android_recheckable(key: &Json) -> bool {
    let att = &key["attestation"];
    att["format"] == json!("android-key")
        && att["trusted"] == json!(true)
        && att["androidRevocation"]["chainSerials"]
            .as_array()
            .is_some_and(|l| !l.is_empty())
        && js::truthy_opt(key.get("credentialId"))
}

/// `AccountSignals.keyCredentialType(record)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn key_credential_type(record: &Json) -> &'static str {
    if record.get("attachment") == Some(&json!("platform")) {
        "fido2-platform"
    } else {
        "fido2-roaming"
    }
}

/// The WebAuthn policy's questions (`authn/webauthn_policy.ts`), each with
/// the code Node marks on a refusal.
pub trait WebauthnRules: Send + Sync {
    /// `enrolmentAllowed()`: `{ ok, why }`.
    fn enrolment_allowed(&self) -> Verdict;
    /// `enrolmentLane(asked)`.
    fn enrolment_lane(&self, asked: &str) -> String;
    /// `classicalRetryRefusal(at)`: `{ ok, why, reason }`.
    fn classical_retry_refusal(&self, at: &str) -> Verdict;
    /// `classicalRetryLane(lane)`.
    fn classical_retry_lane(&self, lane: &str) -> String;
    /// `laneRefusal(lane)`: `{ ok, why }`.
    fn lane_refusal(&self, lane: &str) -> Verdict;
    /// `settings().maxKeysPerPerson`.
    fn max_keys_per_person(&self) -> f64;
    /// `authenticatorKinds()`.
    fn authenticator_kinds(&self) -> Vec<String>;
    /// `algorithmIds(lane, classicalOnly)`.
    fn algorithm_ids(&self, lane: &str, classical_only: bool) -> Vec<f64>;
    /// `requireUserVerification()`.
    fn require_user_verification(&self) -> bool;
    /// `useAllowed(use).ok`.
    fn use_allowed(&self, key_use: &str) -> bool;
    /// `asksPostQuantum(lane)`.
    fn asks_post_quantum(&self, lane: &str) -> bool;
    /// `alongsideClassical()`.
    fn alongside_classical(&self) -> bool;
}

/// The passkey policy's questions (`common/passkey_policy.ts`) a key door
/// asks, under the person's selected profile.
pub trait PasskeyProfile: Send + Sync {
    /// `hasSelection()`.
    fn has_selection(&self) -> bool;
    /// `select(name, '')`.
    fn select(&self, name: &str);
    /// `adminEnrolmentAllowed()`.
    fn admin_enrolment_allowed(&self) -> bool;
    /// `credentialLabelFor(provider, kind)`.
    fn credential_label_for(&self, provider: &str, kind: &str) -> String;
    /// `clientRuleFor(client)`.
    fn client_rule_for(&self, client: &str) -> String;
    /// `refusalFor(at, facts)`: `{ code, why, reason }`, or none.
    fn refusal_for(&self, at: &str, facts: &Json) -> Option<Json>;
}

/// What else a key door reaches: the cluster's claims and counters, the
/// ceremony log, the metadata service's state, the signals a cloned key
/// raises, and the directory's key and user-handle writers.
pub trait KeyPorts: Send + Sync {
    /// `passkeyClients.clientOfRequest()`: the request's client name.
    fn client_name(&self) -> String;
    /// The learned entry of a client (`store.get(client)`), or null.
    fn learned_entry(&self, client: &str) -> Json;
    /// `risk_datasets.mdsState()`: a fresh BLOB is active.
    fn mds_usable(&self) -> bool;
    /// `risk_datasets.lookupAuthenticator(aaguid)`.
    fn lookup_authenticator(
        &self,
        aaguid: &str,
    ) -> Result<Option<Json>, String>;
    /// `claims.claim({ scope, value, ttlMs, realm })`: `{ ok, reason,
    /// handle, why }`.
    fn claim(&self, scope: &str, value: &str, ttl_ms: f64, realm: &str)
        -> Json;
    /// `claims.release(handle)`.
    fn release(&self, handle: &Json);
    /// `counters.advance({ scope, key, value, realm })`: `{ ok, reason,
    /// highest, advanced, why }`.
    fn advance(&self, scope: &str, key: &str, value: f64, realm: &str) -> Json;
    /// `webauthnCeremonies.record(row)`.
    fn ceremony(&self, row: &Json);
    /// `webauthnCeremonies.possiblyReplaced(facts)`.
    fn possibly_replaced(&self, facts: &Json);
    /// `accountSignals.credentialCompromised(facts)`: whether it went.
    fn credential_compromised(&self, facts: &Json) -> bool;
    /// `riskEngine.noteAuthenticatorCompromise(facts)` (the subject is the
    /// risk engine's own lookup).
    fn authenticator_compromised(&self, facts: &Json);
    /// `attestationRevocation.noteRegistration(what)`.
    fn android_registration(&self, what: &str);
    /// Whether the directory installed `writeWebauthn`.
    fn writes_keys(&self) -> bool;
    /// Whether it installed `readWebauthnUserHandle`.
    fn reads_user_handles(&self) -> bool;
    /// Whether it installed `writeWebauthnUserHandle`.
    fn writes_user_handles(&self) -> bool;
    /// Whether it installed `webauthnUserHandleOwner` (#474).
    fn reads_user_handle_owners(&self) -> bool {
        false
    }
    /// `webauthnUserHandleOwner(handle)`: the person whose entry holds the
    /// handle, in either lane, or ''.
    fn user_handle_owner(&self, _handle: &str) -> Hook<String> {
        Ok(String::new())
    }
    /// `writeWebauthn(name, value)`: one key appended.
    fn write_webauthn(&self, name: &str, value: &str) -> Hook<bool>;
    /// `readWebauthnUserHandle(name, lane)`.
    fn read_user_handle(&self, name: &str, lane: &str) -> Hook<String>;
    /// `writeWebauthnUserHandle(name, handle, lane)`.
    fn write_user_handle(
        &self,
        name: &str,
        handle: &str,
        lane: &str,
    ) -> Hook<bool>;
}

/// The pending enrolments (`credentials.pendingKeys`), declared under
/// Node's persist name so a ceremony begun on one node is finished on
/// another.
#[tracing::instrument(level = "debug", skip_all)]
pub fn declare_pending_keys(
    lifecycle: &Arc<RealmLifecycle>,
    handles: &Arc<StoreHandles>,
) -> RealmMap<Json> {
    RealmMap::new(
        lifecycle,
        handles,
        StoreSpec {
            retain: Retain::Age,
            expires_at: Some(expiry_field(Some("expires"), 1.0)),
            ..StoreSpec::persisted("credentials.pendingKeys")
        },
    )
}

/// What the key doors are built over.
#[derive(Clone)]
pub struct KeyDoorsDeps {
    pub credentials: Arc<Credentials>,
    pub env: Arc<dyn Environment>,
    pub rules: Arc<dyn WebauthnRules>,
    pub profile: Arc<dyn PasskeyProfile>,
    pub ports: Arc<dyn KeyPorts>,
    pub attestation: Arc<dyn AttestationPorts>,
    pub pending: RealmMap<Json>,
}

/// The key doors.
pub struct KeyDoors {
    d: KeyDoorsDeps,
}

fn coded(code: ErrorCode, value: Json) -> Verdict {
    Verdict::coded(code, value)
}

fn errors(code: ErrorCode, why: &str) -> Verdict {
    coded(code, json!({ "ok": false, "errors": [why] }))
}

fn reasoned(code: ErrorCode, reason: &str, why: &str) -> Verdict {
    coded(
        code,
        json!({ "ok": false, "reason": reason, "errors": [why] }),
    )
}

fn why_of(v: &Verdict) -> String {
    js::string_or_empty(v.value.get("why"))
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

impl KeyDoors {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(d: KeyDoorsDeps) -> KeyDoors {
        KeyDoors { d }
    }

    fn now(&self) -> f64 {
        self.d.env.now_ms()
    }

    fn realm(&self) -> String {
        self.d.env.realm_id()
    }

    fn select(&self, name: &str) {
        if !self.d.profile.has_selection() {
            self.d.profile.select(name);
        }
    }

    // -----------------------------------------------------------------------
    // The user handle (#474, #643).
    // -----------------------------------------------------------------------

    /// `newUserHandle()`: 64 random bytes, base64url.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn new_user_handle(&self) -> String {
        b64u(&self.d.env.random_bytes(64))
    }

    /// The attestation half of a registration (`webauthnAttestation.
    /// assess(registration)`): section 7.1 steps 21-25 over the ports the
    /// doors were built with.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn assess(
        &self,
        registration: &super::ceremony::Registration,
    ) -> Verdict {
        Attestation::new(self.d.attestation.as_ref()).assess(registration)
    }

    /// What the doors reach outside themselves for, for a door of the
    /// sign-in screen that records through the same ports.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn ports(&self) -> &Arc<dyn KeyPorts> {
        &self.d.ports
    }

    /// `ownerOfUserHandle(handle)` (#474): the person whose entry holds a
    /// handle this service minted, or ''.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn owner_of_user_handle(&self, handle: &str) -> String {
        if !is_user_handle(&json!(handle))
            || !self.d.ports.reads_user_handle_owners()
        {
            return String::new();
        }
        match self.d.ports.user_handle_owner(handle) {
            Ok(owner) => owner,
            Err(e) => {
                tracing::debug!("Caught in owner_of_user_handle(): {}", e);
                String::new()
            }
        }
    }

    /// `userHandleRefusal(username, key, presented, requireHandle)`:
    /// WebAuthn Level 3 section 7.2 step 6 — `{ ok }`, or `{ ok: false,
    /// why }` marked with its code.
    #[tracing::instrument(level = "debug", skip(self, key, presented))]
    pub fn user_handle_refusal(
        &self,
        username: &str,
        key: &Json,
        presented: &str,
        require_handle: bool,
    ) -> Verdict {
        let own = js::string_or(key.get("userHandle"), "");
        let refuse = |code: ErrorCode, why: &str| {
            coded(code, json!({ "ok": false, "why": why }))
        };
        let mismatch = "the user handle the authenticator returned is not \
                        the one the key was registered under";
        if presented.is_empty() {
            return if require_handle {
                refuse(
                    codes::STS_AUTHN_0302,
                    "the authenticator returned no user handle, so the \
                     passkey names no account",
                )
            } else {
                Verdict::of(json!({ "ok": true }))
            };
        }
        if !own.is_empty() {
            return if presented == own {
                Verdict::of(json!({ "ok": true }))
            } else {
                refuse(codes::STS_AUTHN_0303, mismatch)
            };
        }
        if require_handle {
            return refuse(
                codes::STS_AUTHN_0304,
                "this passkey was registered before passkeys could sign in \
                 without a username",
            );
        }
        if presented == legacy_user_handle(username) {
            Verdict::of(json!({ "ok": true }))
        } else {
            refuse(codes::STS_AUTHN_0303, mismatch)
        }
    }

    /// `userHandleOf(username, { mint, lane })`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn user_handle_of(
        &self,
        username: &str,
        mint: bool,
        lane: &str,
    ) -> String {
        let name = js::trim(username).to_string();
        let lane = if lane == "pqc" { "pqc" } else { "classical" };
        if !self.d.ports.reads_user_handles() {
            return String::new();
        }
        if lane == "pqc"
            && self.user_handle_of(&name, mint, "classical").is_empty()
        {
            return String::new();
        }
        let held = match self.d.ports.read_user_handle(&name, lane) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(
                    "{}credentials: reading the WebAuthn user handle of {} \
                     threw: {}",
                    tag(codes::STS_AUTHN_0065),
                    name,
                    e
                );
                return String::new();
            }
        };
        if is_user_handle(&json!(held)) {
            return held;
        }
        if !mint || !self.d.ports.writes_user_handles() {
            return String::new();
        }
        let minted = self.new_user_handle();
        let written = match self.d.ports.write_user_handle(&name, &minted, lane)
        {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(
                    "{}credentials: storing a WebAuthn user handle for {} \
                     threw: {}",
                    tag(codes::STS_AUTHN_0068),
                    name,
                    e
                );
                false
            }
        };
        if written {
            minted
        } else {
            String::new()
        }
    }

    // -----------------------------------------------------------------------
    // The client a registration offers no ML-DSA (#1112).
    // -----------------------------------------------------------------------

    /// `passkeyClients.offerFor({ at, lane })`: `{ narrowed, by, rule,
    /// notApplied, client, record }`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn offer_for(&self, at: &str, lane: &str) -> Json {
        let mut none = json!({ "narrowed": false, "by": "", "rule": "",
            "notApplied": "", "client": "", "record": "" });
        let client = self.d.ports.client_name();
        none["client"] = json!(client);
        if client.is_empty() {
            return none;
        }
        let configured = self.d.profile.client_rule_for(&client);
        let by = if !configured.is_empty() {
            "configured"
        } else if self.d.env.setting("webauthn.clientLearning") == json!(true)
            && js::truthy_opt(
                self.d.ports.learned_entry(&client).get("learnedAt"),
            )
        {
            "learned"
        } else {
            ""
        };
        if by.is_empty() {
            return none;
        }
        let rule = if configured.is_empty() {
            client.clone()
        } else {
            configured
        };
        if !self.d.rules.asks_post_quantum(lane) {
            return none;
        }
        let refusal =
            self.d.rules.classical_retry_refusal(if at == "sign-in" {
                "sign-in"
            } else {
                ""
            });
        let not_applied = if lane == "pqc" && self.d.rules.alongside_classical()
        {
            "the post-quantum lane".to_string()
        } else if refusal.value.get("ok") == Some(&json!(false)) {
            match refusal.value.get("reason") {
                Some(r) if js::truthy(r) => js::string(r),
                _ => "a classical passkey is not allowed".to_string(),
            }
        } else {
            String::new()
        };
        let record = format!(
            "{}{by}: {rule}",
            if not_applied.is_empty() {
                String::new()
            } else {
                format!("not applied ({not_applied}): ")
            }
        );
        json!({ "narrowed": not_applied.is_empty(), "by": by, "rule": rule,
            "notApplied": not_applied, "client": client, "record": record })
    }

    // -----------------------------------------------------------------------
    // Step one: a challenge, and what the ceremony will be.
    // -----------------------------------------------------------------------

    fn key_enrolment_ttl_ms(&self) -> f64 {
        let raw = self.d.env.setting("totp.enrolmentTtlMinutes");
        let minutes = if js::truthy(&raw) {
            js::number(&raw)
        } else {
            10.0
        };
        let minutes = if minutes.is_nan() {
            f64::NAN
        } else {
            minutes.max(1.0)
        };
        minutes * 60.0 * 1000.0
    }

    fn sweep_pending(&self) {
        let view = self.d.pending.in_realm(&self.realm());
        let now = self.now();
        for (key, value) in view.entries() {
            let expires = js::number_opt(value.get("expires"));
            if !js::truthy(&value) || expires < now {
                view.delete(&key);
            }
        }
    }

    /// `beginKeyEnrolment(username, { kind, lane, classicalOnly })`.
    #[tracing::instrument(level = "debug", skip(self, opts))]
    pub fn begin_key_enrolment(&self, username: &str, opts: &Json) -> Verdict {
        let name = js::trim(username).to_string();
        let allowed = self.d.rules.enrolment_allowed();
        if !allowed.ok() {
            return errors(
                allowed.code.unwrap_or(codes::STS_AUTHN_0044),
                &why_of(&allowed),
            );
        }
        self.select(&name);
        let mut lane = self
            .d
            .rules
            .enrolment_lane(&js::string_or_empty(opts.get("lane")));
        let classical_only = opts.get("classicalOnly") == Some(&json!(true));
        if classical_only {
            let retry = self.d.rules.classical_retry_refusal("");
            if !retry.ok() {
                return reasoned(
                    retry.code.unwrap_or(codes::STS_AUTHN_0420),
                    "algorithms",
                    &why_of(&retry),
                );
            }
            lane = self.d.rules.classical_retry_lane(&lane);
        }
        let mut client_rule = Json::Null;
        if !classical_only {
            let decided = self.offer_for("", &lane);
            if js::truthy_opt(decided.get("record")) {
                client_rule = json!({ "narrowed": decided["narrowed"],
                                      "record": decided["record"] });
            }
        }
        let offer_classical =
            classical_only || client_rule["narrowed"] == json!(true);
        let lane_allowed = self.d.rules.lane_refusal(&lane);
        if !lane_allowed.ok() {
            return reasoned(
                lane_allowed.code.unwrap_or(codes::STS_AUTHN_0351),
                "lane",
                &why_of(&lane_allowed),
            );
        }
        if !self.d.ports.writes_keys() {
            return errors(
                codes::STS_AUTHN_0059,
                "No credential store is installed, so a security key cannot \
                 be enrolled.",
            );
        }
        if !self.d.env.predicate("autoCreates")
            && !self.d.credentials.entry_exists(&name)
        {
            return errors(
                codes::STS_AUTHN_0024,
                "This service is in product mode, where a security key can \
                 only be enrolled for somebody who already exists.",
            );
        }
        let held = self.d.credentials.keys_of(&name);
        let cap = self.d.rules.max_keys_per_person();
        if held.len() as f64 >= cap {
            return errors(
                codes::STS_AUTHN_0067,
                &format!(
                    "You already hold {} security key(s), which is the most \
                     this service allows. Remove one first.",
                    held.len()
                ),
            );
        }
        self.sweep_pending();
        let asked_kind = js::string_or_empty(opts.get("kind"));
        let kind = if self.d.rules.authenticator_kinds().contains(&asked_kind) {
            asked_kind
        } else {
            String::new()
        };
        let id = b64u(&self.d.env.random_bytes(24));
        let challenge = b64u(&self.d.env.random_bytes(32));
        let offered = self.d.rules.algorithm_ids(&lane, offer_classical);
        let mut handle = self.user_handle_of(&name, true, &lane);
        if handle.is_empty() {
            handle = self.new_user_handle();
        }
        let exclude: Vec<Json> = held
            .iter()
            .filter(|k| crate::evidence::key_lane(k) == lane)
            .map(|k| k["credentialId"].clone())
            .collect();
        let issued = self.now();
        let expires = self.now() + self.key_enrolment_ttl_ms();
        let record = json!({
            "id": id, "username": name, "challenge": challenge,
            "kind": kind, "lane": lane, "classicalOnly": offer_classical,
            "clientRule": client_rule,
            "offered": offered.iter().map(|n| js::num(*n)).collect::<Vec<_>>(),
            "label": "", "userHandle": handle, "exclude": exclude,
            "issuedAt": js::num(issued), "expires": js::num(expires)
        });
        self.d
            .pending
            .in_realm(&self.realm())
            .set(&name.to_lowercase(), record.clone());
        tracing::info!(
            "credentials: {} started enrolling a passkey{}{}. {} \
             authenticator(s) already enrolled are excluded.",
            name,
            if kind.is_empty() {
                String::new()
            } else {
                format!(" ({kind})")
            },
            if lane != "classical" {
                format!(" in the {lane} lane")
            } else {
                String::new()
            },
            exclude.len()
        );
        Verdict::of(json!({ "ok": true, "enrolmentId": id,
            "challenge": challenge, "kind": kind, "lane": lane,
            "classicalOnly": classical_only, "clientRule": client_rule,
            "exclude": exclude, "userHandle": handle,
            "expiresAt": sts_pki::foreign::iso_ms(expires as i64) }))
    }

    /// `pendingKeyEnrolmentFor(username)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn pending_key_enrolment_for(&self, username: &str) -> Option<Json> {
        self.sweep_pending();
        self.d
            .pending
            .in_realm(&self.realm())
            .get(&js::trim(username).to_lowercase())
    }

    /// `abandonKeyEnrolment(username)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn abandon_key_enrolment(&self, username: &str) {
        self.d
            .pending
            .in_realm(&self.realm())
            .delete(&js::trim(username).to_lowercase());
    }

    // -----------------------------------------------------------------------
    // Step two: verify what the browser produced, and only then write it.
    // -----------------------------------------------------------------------

    /// `confirmKeyEnrolment(username, enrolmentId, credential, { origin,
    /// rpId, door, application })`: `addKey()`'s answer, or a refusal,
    /// with the ceremony's row recorded however it ends.
    #[tracing::instrument(level = "debug", skip(self, credential, opts))]
    pub fn confirm_key_enrolment(
        &self,
        username: &str,
        enrolment_id: &str,
        credential: &Json,
        opts: &Json,
    ) -> Verdict {
        let name = js::trim(username).to_string();
        let held = self.pending_key_enrolment_for(&name);
        let door = if opts.get("door") == Some(&json!("activation")) {
            "activation"
        } else {
            "portal"
        };
        let answer =
            self.check_key_enrolment(&name, enrolment_id, credential, opts);
        let ok = answer.ok();
        let key = if ok {
            let id = js::string_or_empty(answer.value.get("credentialId"));
            self.d
                .credentials
                .keys_of(&name)
                .into_iter()
                .find(|k| js::string_or_empty(k.get("credentialId")) == id)
        } else {
            None
        };
        let lane = held
            .as_ref()
            .and_then(|h| h.get("lane"))
            .filter(|l| js::truthy(l))
            .map_or("classical".to_string(), js::string);
        let offered = match held.as_ref().and_then(|h| h["offered"].as_array())
        {
            Some(l) if !l.is_empty() => Json::Array(l.clone()),
            _ => json!(self
                .d
                .rules
                .algorithm_ids(&lane, false)
                .iter()
                .map(|n| js::num(*n))
                .collect::<Vec<_>>()),
        };
        let narrowed = held
            .as_ref()
            .map(|h| &h["clientRule"])
            .filter(|r| js::truthy(r))
            .map_or(String::new(), |r| js::string_or_empty(r.get("record")));
        self.d.ports.ceremony(&json!({
            "ceremony": "registration", "door": door, "username": name,
            "lane": lane,
            "outcome": if ok { "success" } else { "refused" },
            "errorCode": if ok { "" } else { answer.code_text() },
            "offered": offered,
            "algorithm": key.as_ref().map_or(Json::String(String::new()),
                |k| Credentials::key_algorithm(k)["name"].clone()),
            "posted": credential,
            "attestation": key.as_ref().map_or(Json::Null,
                |k| k.get("attestation").cloned().unwrap_or(Json::Null)),
            "narrowed": narrowed,
            "application": js::string_or_empty(opts.get("application")),
            "issuedAt": held.as_ref().map_or(json!(0), |h| {
                let n = js::number_opt(h.get("issuedAt"));
                js::num(if n.is_nan() { 0.0 } else { n })
            })
        }));
        answer
    }

    fn check_key_enrolment(
        &self,
        name: &str,
        enrolment_id: &str,
        credential: &Json,
        opts: &Json,
    ) -> Verdict {
        let Some(held) = self.pending_key_enrolment_for(name) else {
            return reasoned(
                codes::STS_AUTHN_0075,
                "expired",
                "That enrolment has expired. Start again.",
            );
        };
        if js::truthy_opt(held.get("upgrade")) {
            return reasoned(
                codes::STS_AUTHN_0456,
                "mismatch",
                "A passkey upgrade is in progress, not a new passkey. Finish \
                 or cancel the upgrade.",
            );
        }
        if enrolment_id != js::string_or_empty(held.get("id")) {
            return reasoned(
                codes::STS_AUTHN_0094,
                "mismatch",
                "That enrolment is not the one in progress. Start again.",
            );
        }
        let stored =
            self.verify_key_registration(name, &held, credential, opts);
        match stored {
            Ok(stored) => self.key_enrolment_written(name, &held, stored),
            Err(refusal) => refusal,
        }
    }

    /// `verifyKeyRegistration()`: `Ok` is the claimed write's answer,
    /// `Err` a refusal before it.
    fn verify_key_registration(
        &self,
        name: &str,
        held: &Json,
        credential: &Json,
        opts: &Json,
    ) -> Result<Verdict, Verdict> {
        let response = &credential["response"];
        if !js::truthy_opt(response.get("attestationObject")) {
            let said = if js::truthy_opt(credential.get("error")) {
                format!(
                    "{}: {}",
                    js::string(&credential["error"]),
                    js::string_or_empty(
                        credential.get("message").filter(|m| js::truthy(m))
                    )
                )
            } else {
                "the browser sent no credential".to_string()
            };
            return Err(reasoned(codes::STS_AUTHN_0022, "browser", &said));
        }
        self.select(name);
        let lane = js::string_or_empty(held.get("lane"));
        let classical = held.get("classicalOnly") == Some(&json!(true));
        let input = RegistrationInput {
            attestation_object: js::string(&response["attestationObject"]),
            client_data_json: js::string_or_empty(
                response.get("clientDataJSON"),
            ),
            expected_challenge: held["challenge"].clone(),
            expected_origin: json!(js::string_or_empty(
                opts.get("origin").filter(|o| js::truthy(o))
            )),
            expected_rp_id: js::string_or_empty(
                opts.get("rpId").filter(|o| js::truthy(o)),
            ),
            require_user_verification: self.d.rules.require_user_verification(),
            expected_algorithms: Some(held_to_offer(
                &self.d.rules.algorithm_ids(&lane, classical),
                &held["offered"],
            )),
        };
        let registration = match verify_registration(&input) {
            Ok(r) => r,
            Err(e) => {
                return Err(reasoned(
                    codes::STS_AUTHN_0027,
                    "invalid",
                    &format!("The registration could not be checked: {e}"),
                ))
            }
        };
        let verdict = &registration.answer;
        if verdict["ok"] != json!(true) {
            let failed: Vec<String> = verdict["failed"]
                .as_array()
                .map(|l| l.iter().map(js::string).collect())
                .unwrap_or_default();
            tracing::info!(
                "credentials: a security key enrolment for {} did not verify \
                 — {}",
                name,
                failed.join("; ")
            );
            return Err(reasoned(
                failure_code_for(verdict),
                "invalid",
                &format!(
                    "The registration did not verify — {}.",
                    failed.join("; ")
                ),
            ));
        }
        let credential_id = js::string_or_empty(verdict.get("credentialId"));
        if held["exclude"]
            .as_array()
            .is_some_and(|l| l.iter().any(|e| js::string(e) == credential_id))
        {
            return Err(reasoned(
                codes::STS_AUTHN_0095,
                "duplicate",
                "That authenticator is already enrolled. Use a DIFFERENT one \
                 — a backup on the same device is lost with the original.",
            ));
        }
        let attested =
            Attestation::new(self.d.attestation.as_ref()).assess(&registration);
        if !attested.ok() {
            let why = js::string_or_empty(attested.value.get("why"));
            tracing::info!(
                "credentials: a security key enrolment for {name} was \
                 refused on its attestation — {why}"
            );
            return Err(reasoned(
                attested.code.unwrap_or(codes::STS_AUTHN_0241),
                "attestation",
                &why,
            ));
        }
        let attestation = attested.value["attestation"].clone();
        let named = self.key_provider_for(
            &js::string_or_empty(verdict.get("aaguid")),
            &attestation,
        );
        let flags = &verdict["flags"];
        let mut key = Map::new();
        key.insert("provider".into(), named.0);
        key.insert("providerSource".into(), named.1);
        key.insert("credentialId".into(), verdict["credentialId"].clone());
        key.insert("publicKeyJwk".into(), verdict["publicKeyJwk"].clone());
        key.insert("signCount".into(), verdict["signCount"].clone());
        if js::truthy_opt(held.get("label")) {
            key.insert("label".into(), held["label"].clone());
        }
        key.insert(
            "attachment".into(),
            credential
                .get("authenticatorAttachment")
                .filter(|a| js::truthy(a))
                .cloned()
                .unwrap_or(Json::Null),
        );
        key.insert("userVerified".into(), json!(flags["uv"] == json!(true)));
        let or_null = |k: &str| {
            verdict
                .get(k)
                .filter(|v| js::truthy(v))
                .cloned()
                .unwrap_or(Json::Null)
        };
        key.insert("aaguid".into(), or_null("aaguid"));
        key.insert("algorithm".into(), or_null("algorithm"));
        key.insert("coseAlg".into(), or_null("coseAlg"));
        key.insert("attestation".into(), attestation);
        key.insert("backupEligible".into(), json!(flags["be"] == json!(true)));
        key.insert("backupState".into(), json!(flags["bs"] == json!(true)));
        key.insert("transports".into(), transports_of(credential));
        key.insert("discoverable".into(), discoverable_of(credential));
        key.insert("minPinLength".into(), reported_min_pin_length(verdict));
        key.insert("userHandle".into(), held["userHandle"].clone());
        key.insert(
            "lane".into(),
            json!(if lane.is_empty() {
                "classical".to_string()
            } else {
                lane
            }),
        );
        if js::truthy_opt(held.get("enrolledBy")) {
            key.insert("enrolledBy".into(), held["enrolledBy"].clone());
        }
        Ok(self.add_key_claimed(name, &Json::Object(key)))
    }

    /// `keyProviderFor(aaguid, attestation)`: MDS where a usable BLOB is
    /// loaded, else the credential-manager table.
    #[tracing::instrument(level = "debug", skip(self, attestation))]
    pub fn key_provider_for(
        &self,
        aaguid: &str,
        attestation: &Json,
    ) -> (Json, Json) {
        let id = aaguid_string(aaguid);
        if self.d.ports.mds_usable() {
            let mut model = js::string_or_empty(attestation.get("model"));
            if model.is_empty() && !id.is_empty() {
                model = match self.d.ports.lookup_authenticator(&id) {
                    Ok(Some(l)) => {
                        js::string_or_empty(l["model"].get("description"))
                    }
                    _ => String::new(),
                };
            }
            return (json!(model), json!("mds"));
        }
        let named = provider_name_of(&id);
        let source = if named.is_empty() { "" } else { "table" };
        (json!(named), json!(source))
    }

    /// The end of `confirmKeyEnrolment()` (`keyEnrolmentWritten()`).
    fn key_enrolment_written(
        &self,
        name: &str,
        held: &Json,
        stored: Verdict,
    ) -> Verdict {
        if !stored.ok() {
            return coded(
                stored.code.unwrap_or(codes::STS_AUTHN_0068),
                json!({ "ok": false, "reason": "refused",
                        "errors": stored.value.get("errors").cloned()
                            .unwrap_or(Json::Null) }),
            );
        }
        self.abandon_key_enrolment(name);
        let count = self.d.credentials.keys_of(name).len();
        tracing::info!(
            "credentials: {} enrolled a passkey{}. They now hold {}.",
            name,
            if held["lane"] == json!("pqc") {
                " in the pqc lane"
            } else {
                ""
            },
            count
        );
        Verdict::of(json!({ "ok": true, "username": name,
            "credentialId": stored.value["credentialId"],
            "held": self.d.credentials.keys_of(name).len() }))
    }

    // -----------------------------------------------------------------------
    // The one writer.
    // -----------------------------------------------------------------------

    /// `addKeyClaimed(username, credential)`: the credential id claimed
    /// across the cluster first, given back on a refused write.
    #[tracing::instrument(level = "debug", skip(self, credential))]
    pub fn add_key_claimed(
        &self,
        username: &str,
        credential: &Json,
    ) -> Verdict {
        let id = js::string_or_empty(
            credential.get("credentialId").filter(|v| js::truthy(v)),
        );
        if id.is_empty() {
            return self.add_key(username, credential);
        }
        let name = js::trim(username).to_string();
        let claimed = self.d.ports.claim(
            WEBAUTHN_REGISTRATION_SCOPE,
            &id,
            WEBAUTHN_REGISTRATION_CLAIM_MS,
            &self.realm(),
        );
        if claimed["ok"] != json!(true) && claimed["reason"] == json!("used") {
            tracing::warn!(
                "credentials: a security key registration for {name} was \
                 REFUSED: its credential id is being registered, or was just \
                 registered, by another request or node."
            );
            return reasoned(
                codes::STS_AUTHN_0193,
                "duplicate",
                "That authenticator has just been registered by another \
                 request. It is enrolled once; look for it on your key list.",
            );
        }
        if claimed["ok"] != json!(true) {
            tracing::error!(
                "{}credentials: whether the credential id of a security key \
                 for {} is already registered elsewhere could not be asked \
                 ({}), so it was not enrolled.",
                tag(codes::STS_AUTHN_0194),
                name,
                js::string_or_empty(
                    claimed
                        .get("why")
                        .filter(|w| js::truthy(w))
                        .or(claimed.get("reason"))
                )
            );
            return reasoned(
                codes::STS_AUTHN_0194,
                "store",
                "The security key could not be registered just now. Try \
                 again.",
            );
        }
        let stored = self.add_key(username, credential);
        if !stored.ok() {
            self.d.ports.release(&claimed["handle"]);
        }
        stored
    }

    /// `addKey(username, credential)`: THE ONE WRITER of a key.
    #[tracing::instrument(level = "debug", skip(self, credential))]
    pub fn add_key(&self, username: &str, credential: &Json) -> Verdict {
        let name = js::trim(username).to_string();
        if !self.d.ports.writes_keys() {
            return errors(
                codes::STS_AUTHN_0059,
                "No credential store is installed, so a security key cannot \
                 be recorded.",
            );
        }
        let allowed = self.d.rules.enrolment_allowed();
        if !allowed.ok() {
            tracing::info!(
                "credentials: a passkey was NOT enrolled for {}. {}",
                name,
                why_of(&allowed)
            );
            return errors(
                allowed.code.unwrap_or(codes::STS_AUTHN_0044),
                &why_of(&allowed),
            );
        }
        let lane = match credential.get("lane") {
            Some(l) if js::truthy(l) => js::string(l),
            _ => "classical".to_string(),
        };
        let lane_allowed = self.d.rules.lane_refusal(&lane);
        if !lane_allowed.ok() {
            return reasoned(
                lane_allowed.code.unwrap_or(codes::STS_AUTHN_0351),
                "lane",
                &why_of(&lane_allowed),
            );
        }
        self.select(&name);
        let enrolled_by =
            enrolled_by_of(credential.get("enrolledBy").unwrap_or(&Json::Null));
        if let Some(by) = &enrolled_by {
            if !self.d.profile.admin_enrolment_allowed() {
                tracing::info!(
                    "credentials: a passkey {} enrolled for {} was NOT \
                     written: the passkey policy does not let an \
                     administrator enrol one (adminEnrolment off).",
                    js::string_or_empty(by.get("username")),
                    name
                );
                return reasoned(
                    codes::STS_AUTHN_0440,
                    "admin-enrolment",
                    ADMIN_ENROLMENT_OFF,
                );
            }
        }
        let mut facts = Map::new();
        facts.insert("username".into(), json!(name));
        if let Some(v) = credential.get("minPinLength") {
            facts.insert("minPinLength".into(), v.clone());
        }
        if let Some(v) = credential["attestation"].get("deviceSerial") {
            facts.insert("serial".into(), v.clone());
        }
        facts.insert(
            "algorithm".into(),
            Credentials::key_algorithm(&json!({
                "algorithm": credential.get("algorithm").cloned()
                    .unwrap_or(Json::Null),
                "coseAlg": credential.get("coseAlg").cloned()
                    .unwrap_or(Json::Null),
                "publicKeyJwk": credential.get("publicKeyJwk").cloned()
                    .unwrap_or(Json::Null) }))["name"]
                .clone(),
        );
        facts.insert("lane".into(), json!(lane));
        facts.insert(
            "attestationAlgorithms".into(),
            recorded_algorithms(
                credential.get("attestation").unwrap_or(&Json::Null),
            ),
        );
        if let Some(b @ Json::Bool(_)) = credential.get("backupEligible") {
            facts.insert("backupEligible".into(), b.clone());
        }
        if let Some(by) = &enrolled_by {
            facts.insert("enrolledBy".into(), by.clone());
        }
        if let Some(refused) = self
            .d
            .profile
            .refusal_for("registration", &Json::Object(facts))
        {
            let given = js::string_or_empty(refused.get("reason"));
            let reason = match given.as_str() {
                "pin-length"
                | "backup-eligible"
                | "post-quantum"
                | "attestation-algorithm"
                | "profile-algorithm" => given.clone(),
                r if r.starts_with("serial-") => "device-serial".to_string(),
                _ => "passkey-policy".to_string(),
            };
            let code = js::string_or_empty(refused.get("code"));
            tracing::info!(
                "credentials: a passkey was NOT enrolled for {} ({}, {}): {}",
                name,
                code,
                reason,
                js::string_or_empty(refused.get("why"))
            );
            return coded(
                sts_core::errors::known(&code).unwrap_or(codes::STS_AUTHN_0044),
                json!({ "ok": false, "reason": reason,
                        "errors": [refused.get("why").cloned()
                                   .unwrap_or(Json::Null)] }),
            );
        }
        let held = self.d.credentials.keys_of(&name);
        let wanted = js::string_or_empty(
            credential.get("credentialId").filter(|v| js::truthy(v)),
        );
        if !wanted.is_empty()
            && held
                .iter()
                .any(|k| js::string_or_empty(k.get("credentialId")) == wanted)
        {
            return reasoned(
                codes::STS_AUTHN_0095,
                "duplicate",
                "That authenticator is already enrolled. Use a DIFFERENT one \
                 — a backup on the same device is lost with the original.",
            );
        }
        let cap = self.d.rules.max_keys_per_person();
        if held.len() as f64 >= cap {
            tracing::info!(
                "credentials: {} already holds {} passkey(s) and \
                 webauthn.maxKeysPerPerson is {}, so another was not enrolled.",
                name,
                held.len(),
                js::number_text(cap)
            );
            return errors(
                codes::STS_AUTHN_0067,
                &format!(
                    "{} already holds {} security key(s), which is the most \
                     this realm allows (webauthn.maxKeysPerPerson). Remove one \
                     first.",
                    name,
                    held.len()
                ),
            );
        }
        let mut record = self.record_of(credential, &lane, enrolled_by);
        if js::string_or_empty(record.get("label")).is_empty() {
            let as_json = Json::Object(record.clone());
            let kind = if key_group(&as_json) == "security-key" {
                "Security key"
            } else {
                "Passkey"
            };
            let label = self
                .d
                .profile
                .credential_label_for(&key_provider(&as_json), kind);
            let label = if label.is_empty() {
                default_key_name(&as_json)
            } else {
                label
            };
            record.insert("label".into(), json!(label));
        }
        let record = Json::Object(record);
        let written =
            match self.d.ports.write_webauthn(&name, &record.to_string()) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!(
                    "{}credentials: writing a security key for {} threw: {}",
                    tag(codes::STS_AUTHN_0068),
                    name,
                    e
                );
                    return errors(
                        codes::STS_AUTHN_0068,
                        &format!("The credential store refused the write: {e}"),
                    );
                }
            };
        if !written {
            return errors(
                codes::STS_AUTHN_0061,
                &format!(
                    "There is nobody called \"{name}\" in this realm's \
                     directory."
                ),
            );
        }
        tracing::info!("credentials: a passkey was enrolled for {name}.");
        self.mark_possibly_replaced(&name, &record);
        if is_android_recheckable(&record) {
            self.d
                .ports
                .android_registration(&format!("a security key of {name}"));
        }
        let handle = js::string_or_empty(record.get("userHandle"));
        if !handle.is_empty()
            && self.user_handle_of(&name, false, &lane).is_empty()
            && self.d.ports.writes_user_handles()
            && (lane != "pqc"
                || !self.user_handle_of(&name, true, "classical").is_empty())
        {
            if let Err(e) =
                self.d.ports.write_user_handle(&name, &handle, &lane)
            {
                tracing::warn!(
                    "{}credentials: storing the WebAuthn user handle of the \
                     key just enrolled for {} threw: {}. The key works where \
                     the username is typed.",
                    tag(codes::STS_AUTHN_0068),
                    name,
                    e
                );
            }
        }
        let advised = self.d.rules.use_allowed("mfa")
            && self.d.credentials.has_password(&name)
            && self.d.credentials.backup_codes().offered()
            && !self.d.credentials.holds_backup_codes(&name);
        Verdict::of(json!({ "ok": true, "username": name,
            "credentialId": record["credentialId"],
            "recoveryAdvised": advised,
            "recoveryNote": if advised {
                "This passkey can be your SECOND factor, and you hold no \
                 recovery codes. Generate a set from your account page before \
                 you need it — this service will not issue one for you, and a \
                 set is shown once."
            } else { "" } }))
    }

    /// The row `addKey()` writes, in Node's member order.
    fn record_of(
        &self,
        c: &Json,
        lane: &str,
        enrolled_by: Option<Json>,
    ) -> Map<String, Json> {
        let mut r = Map::new();
        let text = |k: &str| match c.get(k) {
            Some(v) if js::truthy(v) => js::string(v),
            _ => String::new(),
        };
        let boolean = |k: &str| match c.get(k) {
            Some(b @ Json::Bool(_)) => b.clone(),
            _ => Json::Null,
        };
        r.insert(
            "credentialId".into(),
            json!(js::string_or(c.get("credentialId"), "undefined")),
        );
        r.insert(
            "publicKeyJwk".into(),
            c.get("publicKeyJwk").cloned().unwrap_or(Json::Null),
        );
        let count =
            js::number_opt(c.get("signCount").filter(|v| js::truthy(v)));
        r.insert(
            "signCount".into(),
            js::num(if c.get("signCount").is_some_and(js::truthy) {
                count
            } else {
                0.0
            }),
        );
        r.insert("enrolledAt".into(), js::num(self.now()));
        let label = text("label");
        let units: Vec<u16> =
            js::trim(&label).encode_utf16().take(60).collect();
        r.insert("label".into(), json!(String::from_utf16_lossy(&units)));
        r.insert("attachment".into(), json!(text("attachment")));
        r.insert("aaguid".into(), json!(aaguid_string(&text("aaguid"))));
        let algorithm = {
            let a = text("algorithm");
            if a.is_empty() {
                js::string_or_empty(
                    c["publicKeyJwk"].get("alg").filter(|v| js::truthy(v)),
                )
            } else {
                a
            }
        };
        r.insert(
            "algorithm".into(),
            if algorithm.is_empty() {
                Json::Null
            } else {
                json!(algorithm)
            },
        );
        let cose = js::number_opt(c.get("coseAlg"));
        r.insert(
            "coseAlg".into(),
            if cose.is_nan() || cose == 0.0 {
                Json::Null
            } else {
                js::num(cose)
            },
        );
        r.insert(
            "attestation".into(),
            c.get("attestation")
                .filter(|a| js::truthy(a))
                .cloned()
                .unwrap_or(Json::Null),
        );
        r.insert("backupEligible".into(), boolean("backupEligible"));
        r.insert("backupState".into(), boolean("backupState"));
        let transports: Vec<Json> = c["transports"]
            .as_array()
            .map(|l| {
                l.iter()
                    .map(js::string)
                    .filter(|t| transport_word(t))
                    .take(8)
                    .map(Json::String)
                    .collect()
            })
            .unwrap_or_default();
        r.insert("transports".into(), Json::Array(transports));
        r.insert("discoverable".into(), boolean("discoverable"));
        r.insert("userVerified".into(), boolean("userVerified"));
        r.insert(
            "minPinLength".into(),
            match c.get("minPinLength") {
                Some(n @ Json::Number(_)) => n.clone(),
                _ => Json::Null,
            },
        );
        if let Some(h) = c.get("userHandle").filter(|h| is_user_handle(h)) {
            r.insert("userHandle".into(), h.clone());
        }
        if lane == "pqc" {
            r.insert("lane".into(), json!("pqc"));
        }
        if let Some(by) = enrolled_by {
            r.insert("enrolledBy".into(), by);
        }
        let provider = text("provider");
        let units: Vec<u16> = provider.encode_utf16().take(120).collect();
        r.insert("provider".into(), json!(String::from_utf16_lossy(&units)));
        let source = text("providerSource");
        r.insert(
            "providerSource".into(),
            json!(if source == "mds" || source == "table" {
                source
            } else {
                String::new()
            }),
        );
        r
    }

    /// `markPossiblyReplaced(name, record)` (#1101): an older row under the
    /// same user handle and AAGUID marked, never deleted.
    fn mark_possibly_replaced(&self, name: &str, record: &Json) {
        let handle = js::string_or_empty(record.get("userHandle"));
        let aaguid = aaguid_string(&js::string_or_empty(record.get("aaguid")));
        if handle.is_empty()
            || aaguid.is_empty()
            || record.get("discoverable") == Some(&json!(false))
        {
            return;
        }
        let id = js::string_or_empty(record.get("credentialId"));
        let older: Vec<Json> = self
            .d
            .credentials
            .keys_of(name)
            .into_iter()
            .filter(|one| {
                js::string_or_empty(one.get("credentialId")) != id
                    && js::string_or_empty(one.get("userHandle")) == handle
                    && aaguid_string(&js::string_or_empty(one.get("aaguid")))
                        == aaguid
                    && one.get("discoverable") != Some(&json!(false))
                    && !js::truthy_opt(one.get("possiblyReplacedBy"))
            })
            .collect();
        for one in older {
            let at = self.now();
            let other = js::string_or_empty(one.get("credentialId"));
            let marked =
                self.d.credentials.rewrite_key(name, &other, |found| {
                    found["possiblyReplacedBy"] = json!(id);
                    found["possiblyReplacedAt"] = js::num(at);
                    true
                });
            if matches!(marked, Ok(Some(_))) {
                tracing::info!(
                    "credentials: a passkey of {name} may have been replaced \
                     on its authenticator by the one just registered (same \
                     user handle, AAGUID {aaguid}); marked."
                );
                self.d.ports.possibly_replaced(&json!({ "username": name,
                    "credentialId": other, "by": id, "aaguid": aaguid }));
            }
        }
    }

    // -----------------------------------------------------------------------
    // An assertion spent, and the counter it carried.
    // -----------------------------------------------------------------------

    /// `spendAssertion({ username, credentialId, challenge, signCount,
    /// flags, ttlMs })`: the challenge claimed once, the counter advanced.
    #[tracing::instrument(level = "debug", skip(self, spec))]
    pub fn spend_assertion(&self, spec: &Json) -> Verdict {
        let name = js::trim(&js::string_or_empty(
            spec.get("username").filter(|v| js::truthy(v)),
        ))
        .to_string();
        let credential_id = js::string_or_empty(
            spec.get("credentialId").filter(|v| js::truthy(v)),
        );
        let realm = self.realm();
        let raw = js::number_opt(spec.get("signCount"));
        let sign_count = if raw.is_nan() {
            0.0
        } else {
            raw.floor().max(0.0)
        };
        if credential_id.is_empty() || !js::truthy_opt(spec.get("challenge")) {
            return coded(
                codes::STS_AUTHN_0182,
                json!({ "ok": false, "reason": "store", "detail": "The \
                    assertion names no credential or challenge, so it cannot \
                    be spent." }),
            );
        }
        let ttl = js::number_opt(spec.get("ttlMs"));
        let claimed = self.d.ports.claim(
            WEBAUTHN_CHALLENGE_SCOPE,
            &js::string(&spec["challenge"]),
            60_000f64.max(if ttl.is_nan() { 0.0 } else { ttl }),
            &realm,
        );
        if claimed["ok"] != json!(true) {
            if claimed["reason"] == json!("used") {
                tracing::warn!(
                    "credentials: a security-key assertion for {name} \
                     verified and was REFUSED: its challenge had already been \
                     answered, by another node or a request racing this one."
                );
                return coded(
                    codes::STS_AUTHN_0181,
                    json!({ "ok": false, "reason": "replay",
                        "detail": "this sign-in step has already been answered" }),
                );
            }
            return coded(
                codes::STS_AUTHN_0182,
                json!({ "ok": false, "reason": "store",
                    "detail": "the assertion could not be checked just now" }),
            );
        }
        let answer = self.d.ports.advance(
            WEBAUTHN_COUNTER_SCOPE,
            &credential_id,
            sign_count,
            &realm,
        );
        if answer["ok"] != json!(true) {
            self.d.ports.release(&claimed["handle"]);
            if answer["reason"] == json!("behind") {
                let highest = js::string(&answer["highest"]);
                let count = js::number_text(sign_count);
                self.note_key_cloned(
                    &name,
                    &credential_id,
                    &format!(
                        "signature counter {count}, highest recorded \
                              {highest}"
                    ),
                );
                return coded(
                    codes::STS_AUTHN_0035,
                    json!({ "ok": false, "reason": "counter",
                        "highest": answer["highest"],
                        "detail": format!("the signature counter did not \
                            increase (now {count}, highest seen {highest}) — \
                            the key may have been cloned") }),
                );
            }
            return coded(
                codes::STS_AUTHN_0182,
                json!({ "ok": false, "reason": "store",
                    "detail": "the signature counter could not be checked \
                               just now" }),
            );
        }
        let recorded = self.note_key_used(
            &name,
            &credential_id,
            sign_count,
            spec.get("flags").unwrap_or(&Json::Null),
        );
        Verdict::of(json!({ "ok": true, "recorded": js::truthy(&recorded),
                            "advanced": answer.get("advanced").cloned()
                                .unwrap_or(Json::Null) }))
    }

    /// `noteKeyUsed(username, credentialId, signCount, flags)`: the new
    /// counter, the last use, the backup state the assertion carried; what
    /// the directory answered, or false.
    #[tracing::instrument(level = "debug", skip(self, flags))]
    pub fn note_key_used(
        &self,
        username: &str,
        credential_id: &str,
        sign_count: f64,
        flags: &Json,
    ) -> Json {
        let now = self.now();
        let outcome =
            self.d
                .credentials
                .rewrite_key(username, credential_id, |found| {
                    found["signCount"] = js::num(sign_count);
                    found["lastUsedAt"] = js::num(now);
                    if let Some(o) = found.as_object_mut() {
                        o.shift_remove("possiblyReplacedBy");
                        o.shift_remove("possiblyReplacedAt");
                    }
                    if let Some(b @ Json::Bool(_)) = flags.get("bs") {
                        found["backupState"] = b.clone();
                    }
                    if let Some(b @ Json::Bool(_)) = flags.get("be") {
                        if !found
                            .get("backupEligible")
                            .is_some_and(Json::is_boolean)
                        {
                            found["backupEligible"] = b.clone();
                        }
                    }
                    true
                });
        match outcome {
            Ok(Some(result)) => result,
            Ok(None) => json!(false),
            Err(e) => {
                tracing::error!(
                    "{}credentials: the signature counter for {} could not be \
                     recorded: {}",
                    tag(codes::STS_AUTHN_0038),
                    username,
                    e
                );
                json!(false)
            }
        }
    }

    /// `noteKeyCloned(username, credentialId, evidence)`: a RISC
    /// credential-compromise and the risk engine told; neither waited on.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_key_cloned(
        &self,
        username: &str,
        credential_id: &str,
        evidence: &str,
    ) {
        let name = js::trim(username).to_string();
        let record = self
            .d
            .credentials
            .keys_of(&name)
            .into_iter()
            .find(|k| {
                js::string_or_empty(k.get("credentialId")) == credential_id
            })
            .unwrap_or(Json::Null);
        let label =
            js::string_or_empty(record.get("label").filter(|l| js::truthy(l)));
        let announced = self.d.ports.credential_compromised(&json!({
            "username": name,
            "credentialType": key_credential_type(&record),
            "initiatingEntity": "system", "via": "sign-in",
            "reasonAdmin": format!("A security key of {name}{} presented a \
                signature counter that did not go up ({evidence}): it may \
                have been cloned.",
                if label.is_empty() { String::new() }
                else { format!(" (\"{label}\")") }),
            "reasonUser": "A security key of yours may have been copied. \
                Remove it and enrol a new one."
        }));
        self.d.ports.authenticator_compromised(&json!({
            "realm": self.realm(), "username": name, "evidence": evidence,
            "compromiseAnnounced": announced }));
        tracing::info!(
            "credentials: a security key of {name} presented a counter that \
             did not go up ({evidence}); RISC was told the key is compromised \
             and risk scoring was given the evidence."
        );
    }
}

/// `/^[a-z-]{1,20}$/`.
fn transport_word(t: &str) -> bool {
    (1..=20).contains(&t.len())
        && t.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
}

/// `Credentials.transportsOf(credential)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn transports_of(credential: &Json) -> Json {
    Json::Array(
        credential["response"]["transports"]
            .as_array()
            .map(|l| {
                l.iter()
                    .map(js::string)
                    .filter(|t| transport_word(t))
                    .take(8)
                    .map(Json::String)
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// `Credentials.discoverableOf(credential)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn discoverable_of(credential: &Json) -> Json {
    match credential["clientExtensionResults"]["credProps"].get("rk") {
        Some(b @ Json::Bool(_)) => b.clone(),
        _ => Json::Null,
    }
}

/// `Credentials.reportedMinPinLength(verdict)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn reported_min_pin_length(verdict: &Json) -> Json {
    match verdict["extensions"].get("minPinLength") {
        Some(Json::Number(n))
            if n.as_f64().is_some_and(|v| {
                v.fract() == 0.0 && (0.0..=255.0).contains(&v)
            }) =>
        {
            Json::Number(n.clone())
        }
        _ => Json::Null,
    }
}

/// `Credentials.legacyUserHandle(username)`: the username's bytes,
/// base64url — the handle of a key registered before #474.
#[tracing::instrument(level = "trace")]
pub fn legacy_user_handle(username: &str) -> String {
    b64u(username.as_bytes())
}

/// `Credentials.keyName(key)`: its label, or its default name.
#[tracing::instrument(level = "trace", skip_all)]
pub fn key_name(key: &Json) -> String {
    let label = js::trim(&js::string_or(key.get("label"), "")).to_string();
    let legacy = label.is_empty()
        || label == "security key"
        || label == "this device"
        || (label.starts_with("security key (") && label.ends_with(')'));
    if legacy {
        default_key_name(key)
    } else {
        label
    }
}

/// `Credentials.PQC_NAME_SUFFIX`.
pub const PQC_NAME_SUFFIX: &str = "+ml-dsa";
/// `Credentials.PQC_DISPLAY_SUFFIX`.
pub const PQC_DISPLAY_SUFFIX: &str = " (ML-DSA)";

/// `Credentials.laneUser(username, display, lane)` (#643): `{ name,
/// displayName }`, the post-quantum lane's suffixed.
#[tracing::instrument(level = "trace")]
pub fn lane_user(username: &str, display_name: &str, lane: &str) -> Json {
    let shown = if display_name.is_empty() {
        username
    } else {
        display_name
    };
    if lane != "pqc" {
        return json!({ "name": username, "displayName": shown });
    }
    let room = 64 - PQC_DISPLAY_SUFFIX.chars().count();
    let cut: String = shown.chars().take(room).collect();
    json!({ "name": format!("{username}{PQC_NAME_SUFFIX}"),
            "displayName": format!("{}{}", js::trim(&cut),
                                   PQC_DISPLAY_SUFFIX) })
}
