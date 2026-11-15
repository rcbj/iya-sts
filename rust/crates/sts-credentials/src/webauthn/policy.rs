// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE WEBAUTHN POLICY AND THE PASSKEY POLICY'S CEREMONY QUESTIONS: a port
//! of `authn/webauthn_policy.ts` (the ceremony's options — `settings()`,
//! `creationOptions()`, `requestOptions()`, `discoverableRequestOptions()`
//! — the lanes, the classical retry, the uses a key may answer, and the
//! enrolment gate) and of the half of `common/passkey_policy.ts` a ceremony
//! reads (the profile SELECTED for a person and an application, its rows
//! as the ceremony reads them, and the passkey question: `question()`,
//! `refusalFor()` and the sentence each reason has always had).
//!
//! **THE PASSKEY QUESTION IS ANSWERED AS NODE ANSWERS IT BY DEFAULT.**
//! `refusalFor()` asks the issuance policy (`issuance_gate.checkPasskey()`,
//! rule 3v), whose built-in document `tests/passkey_xacml.js` holds to one
//! truth table with `common/passkey_rules.js`'s `strictReading()`. That
//! reading is ported here ([`strict_reading`]); a realm's own XACML rule is
//! the XACML slice's, and until it lands the built-in rules decide, as Node
//! decides with no XACML family loaded.
//!
//! WHAT REPLACED WHAT. Node's profile selection is AMBIENT — kept per
//! request (`byRequest`, an `AsyncLocalStorage` outside one) by `select()`
//! and read by every question after it. Here it is a thread-local
//! ([`clear_selection`], [`WebauthnPolicy::select`]): every door that
//! selects asks its questions in the same synchronous run, and the door
//! clears it as each request arrives, so one request's selection cannot be
//! read by the next. `withRows()`'s override is held the same way for the
//! one synchronous call it wraps. Settings, mode predicates, the realm, the
//! stored profiles (`sts-policy`'s passkey kind) and the directory's
//! attribute values are [`PolicySource`]'s.

use std::cell::RefCell;
use std::sync::{Arc, LazyLock};

use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};

use super::trust::conveyance_for;
use crate::js;
use crate::Verdict;

/// `DEFAULT_PROFILE`.
pub const DEFAULT_PROFILE: &str = "default";
/// `FALLBACK_ALGS`.
const FALLBACK_ALGS: [&str; 2] = ["ES256", "RS256"];
/// `PQC_ALGS`: `passkeyPolicy.POST_QUANTUM_ALGORITHMS`.
pub const PQC_ALGS: [&str; 3] = ["ML-DSA-87", "ML-DSA-65", "ML-DSA-44"];
/// `LANES`.
const LANES: [&str; 2] = ["classical", "pqc"];
const RESIDENT_KEY_VALUES: [&str; 3] = ["discouraged", "preferred", "required"];
const MIN_PIN_LENGTH: f64 = 4.0;
const MAX_PIN_LENGTH: f64 = 63.0;
const HINTS: [&str; 3] = ["security-key", "client-device", "hybrid"];
const NO_HINTS: &str = "none";
const REALM_LIST: &str = "realm";
const REGISTRATION_MODES: [&str; 4] =
    ["realm", "pq-only", "pq-first", "classical-only"];
const POST_QUANTUM_REQUIRED_VALUES: [&str; 3] =
    ["off", "sign-in", "registration-and-sign-in"];
const LANES_VALUES: [&str; 3] = ["realm", "both", "one"];
const ATTESTATION_ALGORITHM_VALUES: [&str; 6] = [
    "post-quantum",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "slh-dsa",
    "composite-ml-dsa",
];
const RECOVERY_ASSURANCE: [&str; 3] = ["any", "not-weaker", "operator-only"];

/// `RECOVERY_DOORS`: each door, and whether it is the person's own.
const RECOVERY_DOORS: [(&str, bool); 8] = [
    ("forgot-password", true),
    ("password-reset", true),
    ("admin-reset", false),
    ("admin-password", false),
    ("activation", false),
    ("recovery-code", true),
    ("email-code", true),
    ("email-link", true),
];

/// `RECOVERY_CREDENTIALS`: a sign-in's credential kind that is itself a
/// recovery door.
#[tracing::instrument(level = "trace")]
pub fn recovery_door_of_credential(kind: &str) -> &'static str {
    match kind {
        "backup-code" => "recovery-code",
        "email-code" => "email-code",
        "email-link" => "email-link",
        _ => "",
    }
}

/// `REGISTRATION_ALGORITHM_VALUES` (#940): `webauthn.algorithms`' own
/// values, less RS1, from the settings row so the two cannot drift.
static REGISTRATION_ALGORITHM_VALUES: LazyLock<Vec<String>> =
    LazyLock::new(|| {
        sts_core::settings::row("webauthn.algorithms")
            .and_then(|r| r.csv_values)
            .map(|values| {
                values
                    .iter()
                    .filter(|v| **v != "RS1")
                    .map(|v| v.to_string())
                    .collect()
            })
            .unwrap_or_default()
    });

/// `ALG_IDS[name]`: the verifier's COSE id for a JOSE name (the last row
/// of the table naming it, as the inversion of `COSE_ALGS` leaves it).
#[tracing::instrument(level = "trace")]
pub fn alg_id(name: &str) -> Option<i64> {
    sts_crypto::webauthn::COSE_SIGNATURE_ALGS
        .iter()
        .rev()
        .find(|a| a.name == name)
        .map(|a| a.id)
}

/// `INSECURE_ALGS`: the broken algorithms' names.
fn insecure_algs() -> Vec<&'static str> {
    sts_crypto::webauthn::COSE_SIGNATURE_ALGS
        .iter()
        .filter(|a| a.insecure)
        .map(|a| a.name)
        .collect()
}

fn is_pq(name: &str) -> bool {
    PQC_ALGS.contains(&name)
}

/// `PasskeyPolicy.isPostQuantum(algorithm)`.
#[tracing::instrument(level = "trace")]
pub fn is_post_quantum(algorithm: &str) -> bool {
    is_pq(algorithm)
}

fn pq_known() -> Vec<String> {
    PQC_ALGS
        .iter()
        .filter(|n| alg_id(n).is_some())
        .map(|n| n.to_string())
        .collect()
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// `String(x == null ? '' : x)`.
fn text(v: Option<&Json>) -> String {
    js::string_or_empty(v)
}

/// The registration rows a profile resolves to (`RegistrationRows`, #940).
#[derive(Debug, Clone, PartialEq)]
pub struct Rows {
    pub registration_algorithms: Vec<String>,
    pub registration_mode: String,
    pub post_quantum_required: String,
    pub lanes: String,
}

/// What the policy reads beyond itself.
pub trait PolicySource: Send + Sync {
    /// `config.value(key)` in the ambient realm.
    fn setting(&self, key: &str) -> Json;
    /// `mode.valueInForce(key)`.
    fn value_in_force(&self, key: &str) -> Json {
        self.setting(key)
    }
    /// A `common/mode.js` predicate by its name there.
    fn predicate(&self, name: &str) -> bool;
    /// `realms.currentId()`.
    fn realm_id(&self) -> String;
    /// `realms.current().name`, or ''.
    fn realm_name(&self) -> String;
    /// `passkeyPolicy.read(name)`: the profile's values, `default` for a
    /// name the realm does not hold.
    fn profile(&self, name: &str) -> Json;
    /// `passkeyPolicy.selectionFor(username, application)`.
    fn selection_for(&self, username: &str, application: &str) -> String;
    /// `authnPolicy.allows(mechanism, role)`.
    fn authn_allows(&self, mechanism: &str, role: &str) -> bool;
    /// `directory.personAttributeValues(username, attribute)`.
    fn person_attribute_values(
        &self,
        _username: &str,
        _attribute: &str,
    ) -> Vec<String> {
        Vec::new()
    }
    /// `passkeyPolicy.clientRuleFor(client, profile)`: the configured
    /// `clientRules` row matching a client, or ''.
    fn client_rule_for(&self, _profile: &Json, _client: &str) -> String {
        String::new()
    }
}

thread_local! {
    /// The selected profile's name (Node's `byRequest`/`loose`).
    static SELECTED: RefCell<Option<String>> = const { RefCell::new(None) };
    /// `withRows()`'s override (`rowsOverride`).
    static ROWS: RefCell<Option<Rows>> = const { RefCell::new(None) };
}

/// Forgets the selection: called as a request arrives, so the next
/// request selects its own.
#[tracing::instrument(level = "trace")]
pub fn clear_selection() {
    SELECTED.with(|s| *s.borrow_mut() = None);
}

/// The WebAuthn policy and the passkey profile's ceremony questions.
pub struct WebauthnPolicy {
    src: Arc<dyn PolicySource>,
}

impl WebauthnPolicy {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(src: Arc<dyn PolicySource>) -> WebauthnPolicy {
        WebauthnPolicy { src }
    }

    fn setting(&self, key: &str) -> Json {
        self.src.setting(key)
    }

    /// `config.value(key) !== false`.
    fn not_false(&self, key: &str) -> bool {
        self.setting(key) != Json::Bool(false)
    }

    /// `config.value(key) === true`.
    fn is_true(&self, key: &str) -> bool {
        self.setting(key) == Json::Bool(true)
    }

    fn one_of(value: &Json, allowed: &[&str], dflt: &str) -> String {
        let wanted = match value {
            Json::Null => String::new(),
            v => js::string(v),
        };
        if allowed.contains(&wanted.as_str()) {
            wanted
        } else {
            dflt.to_string()
        }
    }

    fn clamp(value: &Json, low: f64, high: f64, dflt: f64) -> f64 {
        let n = js::number(value);
        if !n.is_finite() {
            return dflt;
        }
        n.min(high).max(low)
    }

    // -------------------------------------------------------------------
    // The selected passkey profile (`passkey_policy.ts`).
    // -------------------------------------------------------------------

    /// `selectedName()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn selected_name(&self) -> String {
        SELECTED
            .with(|s| s.borrow().clone())
            .unwrap_or_else(|| DEFAULT_PROFILE.to_string())
    }

    /// `hasSelection()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn has_selection(&self) -> bool {
        SELECTED.with(|s| s.borrow().is_some())
    }

    /// `select(username, application)`: the profile chosen, and kept for
    /// the questions after it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn select(&self, username: &str, application: &str) -> String {
        let name = self.src.selection_for(username, application);
        let name = if name.is_empty() {
            DEFAULT_PROFILE.to_string()
        } else {
            name
        };
        SELECTED.with(|s| *s.borrow_mut() = Some(name.clone()));
        name
    }

    /// `selectionFor(username, application)`, selecting nothing.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn selection_for(&self, username: &str, application: &str) -> String {
        self.src.selection_for(username, application)
    }

    /// `read(name)`: the named profile, or the selected one.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read(&self, name: Option<&str>) -> Json {
        let asked = match name {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => self.selected_name(),
        };
        self.src.profile(&asked)
    }

    fn rules(&self, profile: Option<&Json>) -> Json {
        match profile {
            Some(p) => p.clone(),
            None => self.read(None),
        }
    }

    /// `allowsUsernameless(profile)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn allows_usernameless(&self, profile: Option<&Json>) -> bool {
        self.rules(profile)["allowUsernameless"] == json!(true)
    }

    /// `requiresUsernameless(profile)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn requires_usernameless(&self, profile: Option<&Json>) -> bool {
        let rules = self.rules(profile);
        rules["requireUsernameless"] == json!(true)
            && rules["allowUsernameless"] == json!(true)
    }

    /// `securityKeyResidentKey(profile)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn security_key_resident_key(&self, profile: Option<&Json>) -> String {
        let rules = self.rules(profile);
        let asked = js::string(&rules["securityKeyResidentKey"]);
        if rules["allowUsernameless"] != json!(true)
            || !RESIDENT_KEY_VALUES.contains(&asked.as_str())
        {
            "required".into()
        } else {
            asked
        }
    }

    /// `requiresPostQuantum(at, profile)`.
    #[tracing::instrument(level = "trace", skip(self, profile))]
    pub fn requires_post_quantum(
        &self,
        at: &str,
        profile: Option<&Json>,
    ) -> bool {
        let rules = self.rules(profile);
        let row = js::string_or(rules.get("postQuantumRequired"), "off");
        if at == "registration" {
            row == "registration-and-sign-in"
        } else {
            row == "sign-in" || row == "registration-and-sign-in"
        }
    }

    /// `postQuantumAllowCredentials(profile)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn post_quantum_allow_credentials(
        &self,
        profile: Option<&Json>,
    ) -> String {
        let rules = self.rules(profile);
        let row =
            js::string_or(rules.get("postQuantumAllowCredentials"), "realm");
        let chosen = if row == "narrow" || row == "list-and-refuse" {
            row
        } else {
            js::string_or(
                Some(&self.setting("webauthn.postQuantumAllowCredentials")),
                "",
            )
        };
        if chosen == "list-and-refuse" {
            "list-and-refuse".into()
        } else {
            "narrow".into()
        }
    }

    fn registration_algorithms_of(rules: &Json) -> Vec<String> {
        let text = match rules.get("registrationAlgorithms") {
            None | Some(Json::Null) => REALM_LIST.to_string(),
            Some(v) => js::string(v),
        };
        if text == REALM_LIST {
            return Vec::new();
        }
        text.split(',')
            .filter(|one| {
                REGISTRATION_ALGORITHM_VALUES.iter().any(|v| v == one)
            })
            .map(String::from)
            .collect()
    }

    fn registration_mode_of(rules: &Json) -> String {
        let row = js::string_or(rules.get("registrationMode"), "realm");
        if REGISTRATION_MODES.contains(&row.as_str()) {
            row
        } else {
            "realm".into()
        }
    }

    /// `registrationRows(profile)` (#940).
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn registration_rows_of(&self, profile: Option<&Json>) -> Rows {
        let rules = self.rules(profile);
        let pq = js::string(&rules["postQuantumRequired"]);
        let lanes = js::string(&rules["lanes"]);
        Rows {
            registration_algorithms: Self::registration_algorithms_of(&rules),
            registration_mode: Self::registration_mode_of(&rules),
            post_quantum_required: if POST_QUANTUM_REQUIRED_VALUES
                .contains(&pq.as_str())
            {
                pq
            } else {
                "off".into()
            },
            lanes: if LANES_VALUES.contains(&lanes.as_str()) {
                lanes
            } else {
                "realm".into()
            },
        }
    }

    /// `registrationAlgorithmsFrom(profile)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn registration_algorithms_from(
        &self,
        profile: Option<&Json>,
    ) -> String {
        let rules = self.rules(profile);
        if !Self::registration_algorithms_of(&rules).is_empty()
            || Self::registration_mode_of(&rules) != "realm"
        {
            "profile".into()
        } else {
            "realm".into()
        }
    }

    /// `clientRuleFor(client, profile)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn client_rule_for(&self, client: &str) -> String {
        if client.is_empty() {
            return String::new();
        }
        let rules = self.read(None);
        self.src.client_rule_for(&rules, client)
    }

    /// `attachmentFor(kind)`.
    fn attachment_for(&self, kind: &str) -> String {
        let setting = js::string_or(
            Some(&self.setting("webauthn.authenticatorAttachment")),
            "any",
        );
        if setting != "any" {
            setting
        } else if kind == "security-key" {
            "cross-platform".into()
        } else {
            String::new()
        }
    }

    fn hint_attachment(hint: &str) -> Option<&'static str> {
        match hint {
            "security-key" | "hybrid" => Some("cross-platform"),
            "client-device" => Some("platform"),
            _ => None,
        }
    }

    /// `PasskeyPolicy.listOf(value)`.
    fn list_of(value: Option<&Json>) -> Vec<String> {
        let text = text(value);
        if text == NO_HINTS {
            return Vec::new();
        }
        text.split(',')
            .filter(|one| HINTS.contains(one))
            .map(String::from)
            .collect()
    }

    /// `hintsFor(kind, profile)` (#531).
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn hints_for(&self, kind: &str) -> Vec<String> {
        let key = match kind {
            "passkey" => "passkeyHints",
            "security-key" => "securityKeyHints",
            "sign-in" => "signInHints",
            _ => return Vec::new(),
        };
        let rules = self.read(None);
        let list = Self::list_of(rules.get(key));
        let attachment = self.attachment_for(kind);
        let bad: Vec<String> = if kind == "sign-in" || attachment.is_empty() {
            Vec::new()
        } else {
            list.iter()
                .filter(|h| {
                    Self::hint_attachment(h).is_some_and(|a| a != attachment)
                })
                .cloned()
                .collect()
        };
        if !bad.is_empty() {
            tracing::warn!(
                "{}passkey policy: the {} hint(s) {} contradict \
                 webauthn.authenticatorAttachment, changed since the policy \
                 was saved, and are not sent.",
                sts_core::log::tag(codes::STS_AUTHN_0319),
                key,
                bad.join(", ")
            );
        }
        list.into_iter().filter(|h| !bad.contains(h)).collect()
    }

    /// `PasskeyPolicy.displaySafe(value, max)`.
    #[tracing::instrument(level = "trace")]
    pub fn display_safe(value: &str, max: usize) -> String {
        let collapse = |t: &str| -> String {
            let mut out = String::new();
            let mut in_space = false;
            for c in t.chars() {
                if js::is_space(c) {
                    if !in_space {
                        out.push(' ');
                    }
                    in_space = true;
                } else {
                    out.push(c);
                    in_space = false;
                }
            }
            out
        };
        let stripped: String = collapse(value)
            .chars()
            .filter(|c| {
                let n = *c as u32;
                !(n <= 0x1f
                    || (0x7f..=0x9f).contains(&n)
                    || n == 0x061c
                    || n == 0x200e
                    || n == 0x200f
                    || (0x202a..=0x202e).contains(&n)
                    || (0x2066..=0x2069).contains(&n))
            })
            .collect();
        let again = collapse(&stripped);
        let cut: String = js::trim(&again).chars().take(max).collect();
        js::trim(&cut).to_string()
    }

    /// `displayNameFor(username, fallback, profile)` (#533).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn display_name_for(&self, username: &str, fallback: &str) -> String {
        let rules = self.read(None);
        let groups: Vec<Vec<String>> = text(rules.get("userDisplayName"))
            .split(',')
            .map(|one| {
                js::trim(one)
                    .split(js::is_space)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .filter(|g| !g.is_empty())
            .collect();
        let mut found = String::new();
        for group in &groups {
            let parts: Vec<String> = group
                .iter()
                .map(|attribute| {
                    let values =
                        self.src.person_attribute_values(username, attribute);
                    Self::display_safe(
                        values.first().map(String::as_str).unwrap_or(""),
                        64,
                    )
                })
                .collect();
            if parts.iter().all(|p| !p.is_empty()) {
                found = Self::display_safe(&parts.join(" "), 64);
            }
            if !found.is_empty() {
                break;
            }
        }
        if !found.is_empty() {
            return found;
        }
        let shown = Self::display_safe(
            if fallback.is_empty() {
                username
            } else {
                fallback
            },
            64,
        );
        if shown.is_empty() {
            username.to_string()
        } else {
            shown
        }
    }

    /// `rpNameFor(base, realmName, organisation, profile)` (#533).
    #[tracing::instrument(level = "trace", skip(self, profile))]
    pub fn rp_name_for(
        &self,
        base: &str,
        realm_name: &str,
        organisation: &str,
        profile: Option<&Json>,
    ) -> String {
        let rules = self.rules(profile);
        let extras = js::string_or(rules.get("rpNameExtras"), "none");
        let mut parts = vec![Self::display_safe(base, 64)];
        if extras == "realm" || extras == "realm-and-organisation" {
            parts.push(Self::display_safe(realm_name, 64));
        }
        if extras == "organisation" || extras == "realm-and-organisation" {
            parts.push(Self::display_safe(organisation, 64));
        }
        parts
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(" — ")
    }

    /// `credentialLabelFor(provider, kind, profile)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn credential_label_for(&self, provider: &str, kind: &str) -> String {
        let rules = self.read(None);
        let template = js::string_or(rules.get("credentialLabel"), "");
        if template.is_empty() {
            return String::new();
        }
        let p = if provider.is_empty() { kind } else { provider };
        Self::display_safe(
            &template.replace("{provider}", p).replace("{kind}", kind),
            60,
        )
    }

    /// `aggregatesDevices(profile)` (#534).
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn aggregates_devices(&self) -> bool {
        self.read(None)["aggregateDevices"] != json!(false)
    }

    /// `recoveryAssurance(profile)` (#724).
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn recovery_assurance(&self, profile: Option<&Json>) -> String {
        let rules = self.rules(profile);
        let value = js::string_or(rules.get("recoveryAssurance"), "");
        if RECOVERY_ASSURANCE.contains(&value.as_str()) {
            value
        } else if self.src.predicate("recoversWeakerThanPasskeys") {
            "any".into()
        } else {
            "not-weaker".into()
        }
    }

    /// `enterpriseSerialAttribute(profile)` (#532).
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn enterprise_serial_attribute(
        &self,
        profile: Option<&Json>,
    ) -> String {
        js::string_or(self.rules(profile).get("enterpriseSerialAttribute"), "")
    }

    /// `attestationAlgorithms(profile)` (#941).
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn attestation_algorithms(
        &self,
        profile: Option<&Json>,
    ) -> Vec<String> {
        let rules = self.rules(profile);
        let t = match rules.get("attestationAlgorithms") {
            None | Some(Json::Null) => NO_HINTS.to_string(),
            Some(v) => js::string(v),
        };
        if t == NO_HINTS {
            return Vec::new();
        }
        t.split(',')
            .filter(|one| ATTESTATION_ALGORITHM_VALUES.contains(one))
            .map(String::from)
            .collect()
    }

    /// `adminEnrolmentAllowed(profile)` (#945).
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn admin_enrolment_allowed(&self) -> bool {
        js::string_or(self.read(None).get("adminEnrolment"), "off") == "on"
    }

    /// `enforcesAttestationAtSignIn(profile)` (#530).
    fn enforces_attestation_at_sign_in(rules: &Json) -> bool {
        rules["enforceAttestationAtSignIn"] == json!(true)
    }

    /// `pinLengthRule(profile)` (#529): `{ enforce, min, onlyIfSupported }`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn pin_length_rule(&self, profile: Option<&Json>) -> Json {
        let rules = self.rules(profile);
        let min = js::number_opt(rules.get("minPinLength"));
        json!({ "enforce": rules["enforcePinLength"] == json!(true),
                "min": js::num(if (MIN_PIN_LENGTH..=MAX_PIN_LENGTH).contains(&min) {
                    min } else { MIN_PIN_LENGTH }),
                "onlyIfSupported": rules["pinLengthOnlyIfSupported"] == json!(true) })
    }

    /// `PasskeyPolicy.attestationAlgorithmAllowed(facts, allowed)` (#941).
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn attestation_algorithm_allowed(
        facts: &Json,
        allowed: &[String],
    ) -> bool {
        if allowed.is_empty() {
            return true;
        }
        let certificates = facts["certificates"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if facts["verified"] != json!(true)
            || facts["trusted"] != json!(true)
            || certificates.is_empty()
        {
            return false;
        }
        let one = |name: &str, family: &str, pq: bool| -> bool {
            let lower = name.to_lowercase();
            allowed.iter().any(|value| match value.as_str() {
                "post-quantum" => pq,
                "slh-dsa" => family == "SLH-DSA",
                "composite-ml-dsa" => family == "Composite ML-DSA",
                v => lower == v,
            })
        };
        let statements =
            facts["statements"].as_array().cloned().unwrap_or_default();
        statements.iter().all(|s| {
            let name = js::string(s);
            one(
                &name,
                if name.starts_with("ML-DSA-") {
                    "ML-DSA"
                } else {
                    ""
                },
                is_pq(&name),
            )
        }) && certificates.iter().all(|c| {
            one(
                &text(c.get("algorithm")),
                &text(c.get("family")),
                c["postQuantum"] == json!(true),
            )
        })
    }

    /// `question(at, facts, profile)` (#536): the passkey question for the
    /// issuance policy.
    #[tracing::instrument(level = "debug", skip(self, facts, profile))]
    pub fn question(
        &self,
        at: &str,
        facts: &Json,
        profile: Option<&Json>,
    ) -> Json {
        let given = facts.as_object().cloned().unwrap_or_default();
        let rules = self.rules(profile);
        let has = |k: &str| given.contains_key(k);
        let mut groups: Vec<&str> = Vec::new();
        let mut out = Map::new();
        out.insert(
            "action".into(),
            json!(match at {
                "registration" => "register-passkey",
                "recovery" => "recover-account",
                _ => "use-passkey",
            }),
        );
        out.insert(
            "subject".into(),
            json!(js::string_or(given.get("username"), "")),
        );
        out.insert("realm".into(), json!(self.src.realm_id()));
        out.insert(
            "profile".into(),
            json!(js::string_or(rules.get("name"), DEFAULT_PROFILE)),
        );
        if has("backupEligible") {
            groups.push("backup-eligible");
            if let Some(Json::Bool(b)) = given.get("backupEligible") {
                out.insert("backupEligible".into(), json!(b));
            }
        }
        if has("minPinLength") {
            groups.push("pin-length");
            let v = given.get("minPinLength").and_then(Json::as_f64);
            out.insert(
                "minPinLength".into(),
                match v {
                    Some(n) if n.fract() == 0.0 && n.is_finite() => js::num(n),
                    _ => Json::Null,
                },
            );
        }
        let attribute = self.enterprise_serial_attribute(Some(&rules));
        if has("serial") {
            groups.push("serial");
            let serial = js::trim(&text(given.get("serial"))).to_string();
            let held = !serial.is_empty()
                && !attribute.is_empty()
                && self
                    .src
                    .person_attribute_values(
                        &js::string_or(given.get("username"), ""),
                        &attribute,
                    )
                    .iter()
                    .any(|one| {
                        js::trim(one).to_lowercase() == serial.to_lowercase()
                    });
            out.insert("serial".into(), json!(serial));
            out.insert("serialHeld".into(), json!(held));
        }
        if has("attestation") && js::truthy_opt(given.get("attestation")) {
            groups.push("attestation");
            out.insert("attestation".into(), given["attestation"].clone());
            out.insert(
                "settings".into(),
                given
                    .get("attestationSettings")
                    .filter(|s| js::truthy(s))
                    .cloned()
                    .unwrap_or(json!({})),
            );
        }
        if has("algorithm") {
            groups.push("algorithm");
            let algorithm = js::trim(&text(given.get("algorithm"))).to_string();
            let pq = is_pq(&algorithm);
            out.insert("algorithm".into(), json!(algorithm));
            out.insert("postQuantum".into(), json!(pq));
            out.insert(
                "lane".into(),
                json!(if given.get("lane") == Some(&json!("pqc")) {
                    "pqc"
                } else {
                    "classical"
                }),
            );
        }
        if has("attestationAlgorithms") {
            groups.push("attestation-algorithm");
            let a = given
                .get("attestationAlgorithms")
                .filter(|v| js::truthy(v))
                .cloned()
                .unwrap_or(json!({}));
            let statements: Vec<Json> = a["statements"]
                .as_array()
                .map(|l| {
                    l.iter().take(8).map(|s| json!(js::string(s))).collect()
                })
                .unwrap_or_default();
            let certificates: Vec<Json> = a["certificates"]
                .as_array()
                .map(|l| {
                    l.iter()
                        .take(16)
                        .map(|c| json!(js::string_or(c.get("algorithm"), "")))
                        .collect()
                })
                .unwrap_or_default();
            out.insert(
                "attestationAlgorithm".into(),
                json!({ "verified": a["verified"] == json!(true),
                        "trusted": a["trusted"] == json!(true),
                        "recorded": a["recorded"] == json!(true),
                        "statement": js::string_or(a.get("statement"), ""),
                        "statements": statements,
                        "certificates": certificates,
                        "postQuantum": a["postQuantum"] == json!(true) }),
            );
            out.insert(
                "attestationAlgorithmAllowed".into(),
                json!(Self::attestation_algorithm_allowed(
                    &a,
                    &self.attestation_algorithms(Some(&rules))
                )),
            );
        }
        if has("upgrade") && js::truthy_opt(given.get("upgrade")) {
            groups.push("upgrade");
            let u = &given["upgrade"];
            let previous = js::string_or(u.get("previousAlgorithm"), "");
            out.insert(
                "upgrade".into(),
                json!({ "mode": if u["mode"] == json!("alongside") { "alongside" }
                                else { "replace" },
                        "previousAlgorithm": previous,
                        "previousPostQuantum": is_pq(&previous) }),
            );
        }
        let rows = self.registration_rows_of(Some(&rules));
        let offered_here = self.registration_algorithms_allowed(Some(&rows));
        if at == "registration" && has("algorithm") {
            groups.push("profile-algorithm");
            let alg = text(out.get("algorithm"));
            out.insert(
                "profileAlgorithmOffered".into(),
                json!(offered_here.contains(&alg)),
            );
        }
        if has("enrolledBy")
            && js::truthy_opt(given.get("enrolledBy"))
            && !js::string_or(given["enrolledBy"].get("username"), "")
                .is_empty()
        {
            groups.push("enrolment");
            out.insert("enrolledByAdmin".into(), json!(true));
            let by = js::string(&given["enrolledBy"]["username"]);
            out.insert(
                "enrolledBy".into(),
                json!(by.chars().take(256).collect::<String>()),
            );
        }
        if has("recovery") && js::truthy_opt(given.get("recovery")) {
            groups.push("recovery");
            let r = &given["recovery"];
            let door = js::string_or(r.get("door"), "");
            let self_service =
                RECOVERY_DOORS.iter().any(|(d, own)| *d == door && *own);
            out.insert(
                "recovery".into(),
                json!({ "door": door, "at": js::string_or(r.get("at"), ""),
                        "credential": js::string_or(r.get("credential"), ""),
                        "selfService": self_service,
                        "covered": r["covered"] == json!(true),
                        "pending": r["pending"] == json!(true) }),
            );
        }
        out.insert("groups".into(), json!(groups));
        let pin = self.pin_length_rule(Some(&rules));
        let pq_required = js::string(&rules["postQuantumRequired"]);
        out.insert(
            "policy".into(),
            json!({
                "backupEligibility": js::string_or(rules.get("backupEligibility"), "allow"),
                "enforcePinLength": pin["enforce"],
                "minPinLength": pin["min"],
                "pinLengthOnlyIfSupported": pin["onlyIfSupported"],
                "enforceAttestationAtSignIn": match given.get("enforceAttestation") {
                    Some(Json::Bool(b)) => *b,
                    _ => Self::enforces_attestation_at_sign_in(&rules),
                },
                "enterpriseSerialAttribute": attribute,
                "postQuantumRequired": if POST_QUANTUM_REQUIRED_VALUES.contains(&pq_required.as_str()) {
                    pq_required } else { "off".into() },
                "recoveryAssurance": self.recovery_assurance(Some(&rules)),
                "attestationAlgorithms": self.attestation_algorithms(Some(&rules)),
                "postQuantumAllowCredentials": self.post_quantum_allow_credentials(Some(&rules)),
                "registrationMode": rows.registration_mode,
                "registrationAlgorithms": offered_here,
                "registrationAlgorithmsFrom": self.registration_algorithms_from(Some(&rules)),
                "adminEnrolment": if js::string_or(rules.get("adminEnrolment"), "off") == "on" {
                    "on" } else { "off" },
            }),
        );
        Json::Object(out)
    }

    /// `refusalFor(at, facts, profile)` (#536): `{ code, why, reason }`, or
    /// none where the policy allows it.
    #[tracing::instrument(level = "debug", skip(self, facts, profile))]
    pub fn refusal_for(
        &self,
        at: &str,
        facts: &Json,
        profile: Option<&Json>,
    ) -> Option<Json> {
        let rules = self.rules(profile);
        let asked = self.question(at, facts, Some(&rules));
        let answer = strict_reading(&asked);
        if answer["verdict"] != json!("refuse") {
            return None;
        }
        let reason = text(answer.get("reason"));
        let code =
            js::string_or(answer.get("code"), codes::STS_AUTHN_0322.as_str());
        Some(json!({ "code": code, "reason": reason,
                     "why": Self::sentence_for(&reason, at, &asked, facts) }))
    }

    /// `postQuantumRefusal(key, at, profile)` (#718).
    #[tracing::instrument(level = "debug", skip(self, key))]
    pub fn post_quantum_refusal(&self, key: &Json, at: &str) -> Option<Json> {
        let algorithm = js::string_or(
            key.get("name")
                .filter(|v| js::truthy(v))
                .or(key.get("algorithm")),
            "",
        );
        if algorithm.is_empty() {
            return None;
        }
        self.refusal_for(
            at,
            &json!({ "algorithm": algorithm,
                     "lane": js::string_or(key.get("lane"), "") }),
            None,
        )
    }

    /// `recoveryRefusal(facts, profile)` (#724).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn recovery_refusal(&self, given: &Json) -> Option<Json> {
        self.refusal_for(
            "recovery",
            &json!({ "username": js::string_or(given.get("username"), ""),
                "recovery": { "door": js::string_or(given.get("door"), ""),
                    "at": js::string_or(given.get("at"), "door"),
                    "credential": js::string_or(given.get("credential"), ""),
                    "covered": given["covered"] == json!(true),
                    "pending": given["pending"] == json!(true) } }),
            None,
        )
    }

    /// `sentenceFor(reason, at, asked, facts)`: the one sentence each reason
    /// has always had.
    #[tracing::instrument(level = "trace", skip(asked, facts))]
    pub fn sentence_for(
        reason: &str,
        at: &str,
        asked: &Json,
        facts: &Json,
    ) -> String {
        let registering = at == "registration";
        let policy = &asked["policy"];
        match reason {
            "backup-eligible" => format!(
                "That passkey can be synced or backed up (its authenticator \
                 set the backup-eligible flag), and this realm accepts only \
                 device-bound passkeys (the passkey policy's \
                 backupEligibility is disallow). {}",
                if registering {
                    "Use a security key, or a passkey kept on this device only."
                } else {
                    "Sign in another way, and register a device-bound key."
                }
            ),
            "pin-length" => {
                let value = &asked["minPinLength"];
                let min = js::string(&policy["minPinLength"]);
                format!(
                    "{}{}",
                    if value.is_null() {
                        format!(
                            "That passkey did not report its minimum PIN \
                             length, and this realm requires a PIN of at \
                             least {} characters (the passkey policy's \
                             enforcePinLength). A security key reports it \
                             only to services it was configured to tell. ",
                            min
                        )
                    } else {
                        format!(
                            "That passkey accepts a PIN of {} characters, and \
                             this realm requires at least {} (the passkey \
                             policy's minPinLength). ",
                            js::string(value),
                            min
                        )
                    },
                    if registering {
                        "Use a key configured with a longer minimum PIN."
                    } else {
                        "Sign in another way, and register a key whose \
                         minimum PIN is long enough."
                    }
                )
            }
            "serial-missing" => "That security key's attestation names no \
                device serial this service can read, and this realm binds \
                security keys to the serials issued to each person (the \
                passkey policy's enterpriseSerialAttribute). Use a key from \
                your organisation, registered where enterprise attestation is \
                enabled."
                .into(),
            "post-quantum" => format!(
                "That passkey signs with {}, and this realm requires a \
                 post-quantum passkey, one that signs with ML-DSA (the \
                 passkey policy's postQuantumRequired is {}). {}",
                js::string_or(asked.get("algorithm"), "a classical algorithm"),
                js::string_or(policy.get("postQuantumRequired"), ""),
                if registering {
                    "Use an authenticator that can make an ML-DSA passkey."
                } else {
                    "Sign in another way, and register a post-quantum passkey."
                }
            ),
            "attestation-algorithm" => {
                let a = &asked["attestationAlgorithm"];
                let mut signed: Vec<String> = Vec::new();
                for l in [&a["statements"], &a["certificates"]] {
                    for v in l.as_array().into_iter().flatten() {
                        if js::truthy(v) {
                            signed.push(js::string(v));
                        }
                    }
                }
                signed.truncate(8);
                let signed = signed.join(", ");
                let certs = a["certificates"].as_array().map_or(0, Vec::len);
                let listed: Vec<String> = policy["attestationAlgorithms"]
                    .as_array()
                    .map(|l| l.iter().map(js::string).collect())
                    .unwrap_or_default();
                format!(
                    "{}{}, and this realm requires one signed with {} (the \
                     passkey policy's attestationAlgorithms). {}",
                    if registering {
                        "That passkey's attestation "
                    } else {
                        "This passkey was registered with an attestation that "
                    },
                    if a["verified"] != json!(true)
                        || a["trusted"] != json!(true)
                    {
                        if registering {
                            "is not one this service verified and trusts"
                                .to_string()
                        } else {
                            "this service did not verify and trust".to_string()
                        }
                    } else if certs == 0 {
                        "carries no certificate".to_string()
                    } else {
                        format!(
                            "is signed with {}",
                            if signed.is_empty() {
                                "algorithms never recorded".to_string()
                            } else {
                                signed
                            }
                        )
                    },
                    if listed.is_empty() {
                        "nothing".to_string()
                    } else {
                        listed.join(", ")
                    },
                    if registering {
                        "Use an authenticator whose attestation is signed that \
                         way."
                    } else {
                        "Sign in another way, and register a passkey whose \
                         attestation is."
                    }
                )
            }
            "profile-algorithm" => {
                let listed: Vec<String> = policy["registrationAlgorithms"]
                    .as_array()
                    .map(|l| l.iter().map(js::string).collect())
                    .unwrap_or_default();
                format!(
                    "That passkey signs with {}, which is not one the passkey \
                     policy offers here (profile {}: {}, registrationMode \
                     {}). Use an authenticator that can make one of those.",
                    js::string_or(
                        asked.get("algorithm"),
                        "an algorithm never recorded"
                    ),
                    js::string_or(asked.get("profile"), DEFAULT_PROFILE),
                    if listed.is_empty() {
                        "nothing".to_string()
                    } else {
                        listed.join(", ")
                    },
                    js::string_or(policy.get("registrationMode"), "")
                )
            }
            "serial-not-held" => {
                format!(
                "That security key (serial {}) is not one issued to you: its \
                 serial is not on your directory entry ({}). Use the key your \
                 organisation issued you.",
                text(asked.get("serial")).chars().take(64).collect::<String>(),
                js::string(&policy["enterpriseSerialAttribute"])
            )
            }
            "recovery-self-service" => "This account is protected by a \
                passkey, and this realm lets it be recovered only by whoever \
                manages it (the passkey policy's recoveryAssurance is \
                operator-only). Sign in with your passkey, or ask an \
                administrator for a reset or activation link."
                .into(),
            "recovery-enrol-first" => "This account was recovered without its \
                passkey, and this realm lets it reach no application until a \
                passkey has signed you in (the passkey policy's \
                recoveryAssurance). Register a new passkey, then sign in with \
                it."
            .into(),
            other => facts["attestationSentences"]
                .get(other)
                .filter(|s| js::truthy(s))
                .map(js::string)
                .unwrap_or_else(|| {
                    format!(
                        "This realm's issuance policy {}",
                        if registering {
                            "does not let that passkey be registered here."
                        } else {
                            "no longer lets that passkey sign you in. Sign in \
                             another way."
                        }
                    )
                }),
        }
    }

    /// `webauthnAttestation.signInVerdict(key, { username, enforced })`
    /// (#530, #536): the recorded attestation held to the rules in force
    /// at sign-in — `{ ok }`, or `{ ok: false, why, reason }` marked. The
    /// FIDO metadata is looked up only while the profile enforces
    /// (`signInFacts(key, gather)`).
    #[tracing::instrument(level = "debug", skip(self, key, metadata))]
    pub fn sign_in_verdict(
        &self,
        key: &Json,
        username: &str,
        metadata: &dyn super::trust::Metadata,
    ) -> Verdict {
        use super::trust::{
            compromised_statuses, demanded_by, fips_certified, held_level,
            level_problem, recorded_algorithms, LEVELS,
        };
        let enforced = Self::enforces_attestation_at_sign_in(&self.read(None));
        let settings = self.attestation_settings();
        let rec = &key["attestation"];
        let aaguid = {
            let own = js::string_or(rec.get("aaguid"), "");
            if own.is_empty() {
                super::trust::aaguid_string(&js::string_or(
                    key.get("aaguid"),
                    "",
                ))
            } else {
                own
            }
        };
        let mut facts = Map::new();
        facts.insert("verified".into(), json!(rec["verified"] == json!(true)));
        facts.insert("trusted".into(), json!(rec["trusted"] == json!(true)));
        facts.insert(
            "aaguid".into(),
            json!(aaguid.to_lowercase().replace('-', "")),
        );
        let mut sentences = Map::new();
        sentences.insert(
            "attestation-untrusted".into(),
            json!(format!(
                "This passkey was registered {}, and this realm now requires \
                 a trusted one ({}).",
                if rec["verified"] == json!(true) {
                    "with an attestation that does not chain to a trust anchor"
                } else {
                    "without an attestation this service verified"
                },
                demanded_by(&settings)
            )),
        );
        sentences.insert(
            "attestation-aaguid".into(),
            json!(format!(
                "This passkey's model (AAGUID {}) is no longer one this realm \
                 allows (webauthn.attestationAllowedAaguids).",
                if aaguid.is_empty() { "none" } else { &aaguid }
            )),
        );
        sentences.insert(
            "attestation-unchecked".into(),
            json!(
                "This passkey's attestation could not be checked against \
                   this realm's rules. Try again."
            ),
        );
        let level = text(settings.get("minCertificationLevel"));
        let rank = LEVELS.iter().position(|l| *l == level).unwrap_or(0);
        let settings_facts = json!({
            "attestationPolicy": settings["policy"],
            "allowedAaguids": settings["allowedAaguids"],
            "requiredRank": rank,
            "requireFips": settings["requireFips"] == json!(true) });
        if enforced {
            let hex = text(facts.get("aaguid"));
            let mut listed = if hex.is_empty() {
                Ok(None)
            } else {
                metadata.lookup_authenticator_by("aaguid", &hex)
            };
            if matches!(listed, Ok(None))
                && js::truthy_opt(rec.get("attestationKeyId"))
            {
                listed = metadata.lookup_authenticator_by(
                    "acki",
                    &js::string(&rec["attestationKeyId"]),
                );
            }
            match listed {
                Ok(listed) => {
                    let m = listed
                        .as_ref()
                        .map(|l| l["model"].clone())
                        .unwrap_or(json!({}));
                    facts.insert("listed".into(), json!(listed.is_some()));
                    facts.insert(
                        "compromised".into(),
                        json!(js::truthy_opt(m.get("compromised"))),
                    );
                    if listed.is_some() {
                        let held = held_level(&m);
                        facts.insert(
                            "rank".into(),
                            json!(LEVELS
                                .iter()
                                .position(|l| *l == held)
                                .unwrap_or(0)),
                        );
                        facts.insert("fips".into(), json!(fips_certified(&m)));
                    }
                    let named = js::string_or(m.get("description"), "");
                    sentences.insert(
                        "attestation-compromised".into(),
                        json!(format!(
                            "The FIDO Metadata Service now reports this \
                             passkey's model ({}) as {}, so it no longer \
                             signs anybody in here.",
                            if !named.is_empty() {
                                named
                            } else if !aaguid.is_empty() {
                                aaguid.clone()
                            } else {
                                "unnamed".into()
                            },
                            compromised_statuses(&m).join(", ")
                        )),
                    );
                    let problem = level_problem(listed.as_ref(), &settings);
                    for k in [
                        "attestation-unlisted",
                        "attestation-level",
                        "attestation-fips",
                    ] {
                        sentences.insert(k.into(), json!(problem));
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "{}webauthn: holding a passkey's attestation to the \
                         rules at sign-in threw: {}",
                        sts_core::log::tag(codes::STS_AUTHN_0317),
                        e
                    );
                    facts.insert("unchecked".into(), json!(true));
                }
            }
        }
        let mut asked = Map::new();
        asked.insert("username".into(), json!(username));
        asked.insert("attestation".into(), Json::Object(facts));
        asked.insert("attestationSettings".into(), settings_facts);
        asked.insert("attestationSentences".into(), Json::Object(sentences));
        asked.insert("enforceAttestation".into(), json!(enforced));
        if enforced {
            asked.insert(
                "attestationAlgorithms".into(),
                recorded_algorithms(rec),
            );
        }
        match self.refusal_for("sign-in", &Json::Object(asked), None) {
            None => Verdict::of(json!({ "ok": true })),
            Some(r) => Verdict {
                code: sts_core::errors::known(&text(r.get("code"))),
                value: json!({ "ok": false, "why": r["why"],
                               "reason": r["reason"] }),
            },
        }
    }

    // -------------------------------------------------------------------
    // The WebAuthn settings (`webauthn_policy.ts`).
    // -------------------------------------------------------------------

    /// `settings()`: every WebAuthn setting, each bounded to its values.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn settings(&self) -> Json {
        let attachment = js::string_or(
            Some(&self.setting("webauthn.authenticatorAttachment")),
            "any",
        );
        let passkeys = self.read(None);
        let realm_name = {
            let n = self.src.realm_name();
            if n.is_empty() {
                self.src.realm_id()
            } else {
                n
            }
        };
        let pin = self.pin_length_rule(Some(&passkeys));
        json!({
            "enabled": self.not_false("webauthn.enabled"),
            "rpName": self.rp_name_for(
                &js::string_or(Some(&self.setting("webauthn.rpName")), "Authorization server"),
                &realm_name,
                &js::string_or(Some(&self.setting("saml.organizationName")), ""),
                Some(&passkeys)),
            "rpId": js::trim(&js::string_or(Some(&self.setting("webauthn.rpId")), "")),
            "algorithms": self.algorithms_offered("", false),
            "userVerification": Self::one_of(&self.setting("webauthn.userVerification"),
                &["discouraged", "preferred", "required"], "required"),
            "attestation": Self::one_of(&self.setting("webauthn.attestation"),
                &["none", "indirect", "direct", "enterprise"], "direct"),
            "timeoutMs": js::num(Self::clamp(&self.setting("webauthn.timeoutMs"),
                10000.0, 600000.0, 60000.0)),
            "authenticatorAttachment": Self::one_of(&json!(attachment),
                &["any", "platform", "cross-platform"], "any"),
            "residentKey": self.security_key_resident_key(Some(&passkeys)),
            "credProps": self.not_false("webauthn.credProps"),
            "primaryAllowed": self.not_false("webauthn.primaryAllowed"),
            "usernameless": self.allows_usernameless(Some(&passkeys)),
            "minPinLength": pin["enforce"],
            "mfaAllowed": self.not_false("webauthn.mfaAllowed"),
            "insecureAlgorithms": self.insecure_algorithms_allowed(),
            "pqcOnly": self.pqc_only(),
            "pqcAlongsideClassical": self.alongside_classical(),
            "maxKeysPerPerson": js::num(Self::clamp(&self.setting("webauthn.maxKeysPerPerson"),
                1.0, 50.0, 10.0)),
        })
    }

    /// `WebauthnPolicy.enterpriseRpIdsOf(raw)` (#1114).
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn enterprise_rp_ids_of(raw: &Json) -> Vec<String> {
        let list: Vec<String> = match raw {
            Json::Array(l) => l.iter().map(|v| text(Some(v))).collect(),
            other => text(Some(other)).split(',').map(String::from).collect(),
        };
        let mut out: Vec<String> = Vec::new();
        for one in list {
            let id = js::trim(&one).to_lowercase();
            if !id.is_empty() && !out.contains(&id) {
                out.push(id);
            }
        }
        out
    }

    /// `attestationSettings()` (#105).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn attestation_settings(&self) -> Json {
        let configured = Self::one_of(
            &self.src.value_in_force("webauthn.attestationPolicy"),
            &["by-mode", "off", "verify-if-present", "require-trusted"],
            "by-mode",
        );
        let policy = if configured == "by-mode" {
            if self.src.predicate("acceptsUnverifiedAttestation") {
                "off".to_string()
            } else {
                "verify-if-present".to_string()
            }
        } else {
            configured.clone()
        };
        let asked = self.setting("webauthn.attestationAllowedAaguids");
        let raw: Vec<String> = match &asked {
            Json::Array(l) => l.iter().map(|v| text(Some(v))).collect(),
            other => js::string_or(Some(other), "")
                .split(',')
                .map(String::from)
                .collect(),
        };
        let aaguids: Vec<String> = raw
            .iter()
            .map(|one| js::trim(one).to_lowercase().replace('-', ""))
            .filter(|one| {
                one.len() == 32 && one.chars().all(|c| c.is_ascii_hexdigit())
            })
            .collect();
        let level = Self::one_of(
            &self.setting("webauthn.attestationMinCertificationLevel"),
            &["none", "L1", "L1plus", "L2", "L2plus", "L3", "L3plus"],
            "none",
        );
        let fips = self.is_true("webauthn.attestationRequireFips");
        let serial = self.enterprise_serial_attribute(None);
        let algorithms = self.attestation_algorithms(None);
        let conveyance = Self::one_of(
            &self.setting("webauthn.attestation"),
            &["none", "indirect", "direct", "enterprise"],
            "direct",
        );
        let demands = policy == "require-trusted"
            || !aaguids.is_empty()
            || level != "none"
            || fips
            || !serial.is_empty()
            || !algorithms.is_empty();
        json!({
            "configured": configured, "policy": policy,
            "trustAnchorsPem": js::string_or(Some(&self.setting("webauthn.attestationTrustAnchors")), ""),
            "allowedAaguids": aaguids, "minCertificationLevel": level,
            "requireFips": fips,
            "allowSafetynet": self.is_true("webauthn.attestationAllowSafetynet"),
            "androidSoftwareKeys": self.is_true("webauthn.attestationAndroidSoftwareKeys"),
            "enterpriseSerialAttribute": serial,
            "attestationAlgorithms": algorithms,
            "conveyance": conveyance,
            "enterpriseRpIds": Self::enterprise_rp_ids_of(&self.setting("webauthn.attestationEnterpriseRpIds")),
            "demandsTrust": demands,
        })
    }

    /// `attestationConveyance(rpId)` (#1114).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn attestation_conveyance(&self, rp_id: &str) -> Json {
        let settings = self.attestation_settings();
        let wanted = js::trim(rp_id).to_lowercase();
        let listed = settings["enterpriseRpIds"]
            .as_array()
            .is_some_and(|l| l.iter().any(|v| js::string(v) == wanted));
        conveyance_for(&settings, listed)
    }

    /// `insecureAlgorithmsAllowed()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn insecure_algorithms_allowed(&self) -> bool {
        self.is_true("webauthn.insecureAlgorithms")
            && self.src.predicate("usesBrokenAlgorithms")
    }

    /// `pqcOnly()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn pqc_only(&self) -> bool {
        self.is_true("webauthn.pqcOnly")
    }

    fn registration_rows(&self) -> Rows {
        ROWS.with(|r| r.borrow().clone())
            .unwrap_or_else(|| self.registration_rows_of(None))
    }

    /// `registrationMode()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn registration_mode(&self) -> String {
        self.registration_rows().registration_mode
    }

    /// `requestsPostQuantumOnly()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn requests_post_quantum_only(&self) -> bool {
        let mode = self.registration_mode();
        mode == "pq-only" || (mode == "realm" && self.pqc_only())
    }

    fn requires_post_quantum_at(&self, at: &str) -> bool {
        match ROWS.with(|r| r.borrow().clone()) {
            None => self.requires_post_quantum(at, None),
            Some(rows) => {
                let row = rows.post_quantum_required;
                if at == "registration" {
                    row == "registration-and-sign-in"
                } else {
                    row == "sign-in" || row == "registration-and-sign-in"
                }
            }
        }
    }

    fn registers_post_quantum_only(&self) -> bool {
        self.requires_post_quantum_at("registration")
            || self.registration_mode() == "pq-only"
    }

    fn with_rows<T>(&self, rows: Option<&Rows>, f: impl FnOnce() -> T) -> T {
        let Some(rows) = rows else {
            return f();
        };
        let before = ROWS.with(|r| r.borrow().clone());
        let laid = Rows {
            registration_algorithms: rows
                .registration_algorithms
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect(),
            registration_mode: if REGISTRATION_MODES
                .contains(&rows.registration_mode.as_str())
            {
                rows.registration_mode.clone()
            } else {
                "realm".into()
            },
            post_quantum_required: if rows.post_quantum_required.is_empty() {
                "off".into()
            } else {
                rows.post_quantum_required.clone()
            },
            lanes: if rows.lanes.is_empty() {
                "realm".into()
            } else {
                rows.lanes.clone()
            },
        };
        ROWS.with(|r| *r.borrow_mut() = Some(laid));
        let out = f();
        ROWS.with(|r| *r.borrow_mut() = before);
        out
    }

    /// `configuredAlgorithms()`.
    fn configured_algorithms(&self) -> Vec<String> {
        let rows = self.registration_rows();
        let list: Vec<String> = if !rows.registration_algorithms.is_empty() {
            rows.registration_algorithms.clone()
        } else {
            match self.setting("webauthn.algorithms") {
                Json::Array(l) => l
                    .iter()
                    .map(|v| js::trim(&text(Some(v))).to_string())
                    .collect(),
                other => js::string_or(Some(&other), "")
                    .split(',')
                    .map(|s| js::trim(s).to_string())
                    .collect(),
            }
        };
        let list: Vec<String> =
            list.into_iter().filter(|s| !s.is_empty()).collect();
        let insecure_allowed = self.insecure_algorithms_allowed();
        let insecure = insecure_algs();
        let mut kept: Vec<String> = Vec::new();
        for name in &list {
            if alg_id(name).is_none() {
                tracing::warn!(
                    "webauthn: \"{}\" is not an algorithm this service can \
                     verify, so it is NOT being offered to browsers. Offering \
                     one it cannot check would enrol a credential that never \
                     works again.",
                    name
                );
                continue;
            }
            if insecure.contains(&name.as_str()) && !insecure_allowed {
                continue;
            }
            if !kept.contains(name) {
                kept.push(name.clone());
            }
        }
        if insecure_allowed {
            for name in insecure {
                if !kept.iter().any(|k| k == name) {
                    kept.push(name.to_string());
                }
            }
        }
        if self.requests_post_quantum_only() {
            kept.retain(|n| is_pq(n));
            if kept.is_empty() {
                return strings(&PQC_ALGS);
            }
        }
        if rows.registration_mode == "pq-first" {
            let named: Vec<String> =
                kept.iter().filter(|n| is_pq(n)).cloned().collect();
            let mut pq = if named.is_empty() { pq_known() } else { named };
            pq.extend(kept.iter().filter(|n| !is_pq(n)).cloned());
            kept = pq;
        } else if rows.registration_mode == "classical-only" {
            kept.retain(|n| !is_pq(n));
        }
        if kept.is_empty() {
            tracing::warn!(
                "webauthn: webauthn.algorithms named nothing this service can \
                 verify, so the ceremony is offering {} instead. An empty \
                 pubKeyCredParams is refused by the browser and would look \
                 like a hardware failure.",
                FALLBACK_ALGS.join(" and ")
            );
            return strings(&FALLBACK_ALGS);
        }
        kept
    }

    /// `lanedAlgorithms(lane)`.
    fn laned_algorithms(&self, lane: &str) -> Vec<String> {
        let all = self.configured_algorithms();
        if lane.is_empty() || !self.alongside_classical() {
            return all;
        }
        if lane == "pqc" {
            let named: Vec<String> =
                all.iter().filter(|n| is_pq(n)).cloned().collect();
            return if named.is_empty() { pq_known() } else { named };
        }
        let classical: Vec<String> =
            all.into_iter().filter(|n| !is_pq(n)).collect();
        if classical.is_empty() {
            strings(&FALLBACK_ALGS)
        } else {
            classical
        }
    }

    fn classical_retry_algorithms(&self, lane: &str) -> Vec<String> {
        let retry_lane = self.classical_retry_lane(lane);
        let out: Vec<String> = self
            .laned_algorithms(&retry_lane)
            .into_iter()
            .filter(|n| !is_pq(n))
            .collect();
        if out.is_empty() {
            strings(&FALLBACK_ALGS)
        } else {
            out
        }
    }

    /// `algorithmsOffered(lane, classicalOnly)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn algorithms_offered(
        &self,
        lane: &str,
        classical_only: bool,
    ) -> Vec<String> {
        if classical_only && self.classical_retry_refusal("").ok() {
            return self.classical_retry_algorithms(lane);
        }
        let offered = self.laned_algorithms(lane);
        if !self.requires_post_quantum_at("registration") {
            return offered;
        }
        let pq: Vec<String> =
            offered.into_iter().filter(|n| is_pq(n)).collect();
        if pq.is_empty() {
            pq_known()
        } else {
            pq
        }
    }

    /// `offersPostQuantum(rows)` (#718).
    #[tracing::instrument(level = "debug", skip(self, rows))]
    pub fn offers_post_quantum(&self, rows: Option<&Rows>) -> bool {
        self.with_rows(rows, || {
            let lanes: Vec<&str> = if self.alongside_classical() {
                LANES.to_vec()
            } else {
                vec![""]
            };
            lanes.iter().any(|lane| {
                self.laned_algorithms(lane).iter().any(|n| is_pq(n))
            })
        })
    }

    /// `enrolmentLane(asked)` (#718).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn enrolment_lane(&self, asked: &str) -> String {
        if (asked.is_empty() || asked == "classical")
            && self.alongside_classical()
            && self.registers_post_quantum_only()
        {
            "pqc".into()
        } else if asked.is_empty() {
            "classical".into()
        } else {
            asked.into()
        }
    }

    /// `classicalRetryRefusal(at)` (#944).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn classical_retry_refusal(&self, at: &str) -> Verdict {
        let refuse = |reason: &str, why: &str| {
            Verdict::coded(
                codes::STS_AUTHN_0420,
                json!({ "ok": false, "reason": reason, "why": why }),
            )
        };
        if self.registration_mode() == "pq-only" {
            return refuse(
                "registrationMode pq-only",
                "The passkey policy offers post-quantum (ML-DSA) passkeys \
                 only here (registrationMode is pq-only), so a classical one \
                 cannot be made instead. Use a device or a security key that \
                 can make an ML-DSA passkey.",
            );
        }
        if self.requests_post_quantum_only() {
            return refuse(
                "webauthn.pqcOnly",
                "This realm requests post-quantum (ML-DSA) passkeys only \
                 (webauthn.pqcOnly), so a classical one cannot be made \
                 instead. Use a device or a security key that can make an \
                 ML-DSA passkey.",
            );
        }
        if self.requires_post_quantum_at("registration") {
            return refuse(
                "postQuantumRequired registration-and-sign-in",
                "The passkey policy requires a post-quantum (ML-DSA) passkey \
                 at registration (postQuantumRequired is \
                 registration-and-sign-in), so a classical one cannot be made \
                 instead. Use a device or a security key that can make an \
                 ML-DSA passkey.",
            );
        }
        if at == "sign-in" && self.requires_post_quantum_at("sign-in") {
            return refuse(
                "postQuantumRequired sign-in",
                "The passkey policy requires a post-quantum (ML-DSA) passkey \
                 to sign in here (postQuantumRequired), so a classical one \
                 made now would not sign you in. Use a device or a security \
                 key that can make an ML-DSA passkey.",
            );
        }
        Verdict::of(json!({ "ok": true }))
    }

    /// `classicalRetryLane(lane)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn classical_retry_lane(&self, lane: &str) -> String {
        if self.alongside_classical() || lane.is_empty() {
            "classical".into()
        } else {
            lane.into()
        }
    }

    /// `classicalFallbackOffered(lane, at)` (#944).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn classical_fallback_offered(&self, lane: &str, at: &str) -> bool {
        self.classical_retry_refusal(at).ok()
            && self
                .algorithms_offered(lane, false)
                .iter()
                .any(|n| is_pq(n))
    }

    /// `asksPostQuantum(lane, classicalOnly)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn asks_post_quantum(&self, lane: &str, classical_only: bool) -> bool {
        self.algorithms_offered(lane, classical_only)
            .iter()
            .any(|n| is_pq(n))
    }

    /// `upgradeAlgorithms()` (#939).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn upgrade_algorithms(&self) -> Vec<String> {
        let lane = if self.alongside_classical() {
            "pqc"
        } else {
            ""
        };
        let named: Vec<String> = self
            .laned_algorithms(lane)
            .into_iter()
            .filter(|n| is_pq(n))
            .collect();
        if named.is_empty() {
            pq_known()
        } else {
            named
        }
    }

    /// `upgradeAlgorithmIds()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn upgrade_algorithm_ids(&self) -> Vec<f64> {
        self.upgrade_algorithms()
            .iter()
            .filter_map(|n| alg_id(n))
            .map(|n| n as f64)
            .collect()
    }

    /// `registrationAlgorithmsAllowed(rows)` (#940).
    #[tracing::instrument(level = "debug", skip(self, rows))]
    pub fn registration_algorithms_allowed(
        &self,
        rows: Option<&Rows>,
    ) -> Vec<String> {
        self.with_rows(rows, || {
            let mut all: Vec<String> = Vec::new();
            let mut add = |names: Vec<String>| {
                for n in names {
                    if !all.contains(&n) {
                        all.push(n);
                    }
                }
            };
            for lane in ["", "classical", "pqc"] {
                add(self.algorithms_offered(lane, false));
            }
            if self.classical_retry_refusal("").ok() {
                add(self.algorithms_offered("", true));
            }
            all
        })
    }

    /// `alongsideClassical()` (#643).
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn alongside_classical(&self) -> bool {
        let lanes = self.registration_rows().lanes;
        let lanes = if lanes.is_empty() {
            "realm".to_string()
        } else {
            lanes
        };
        (lanes == "both"
            || (lanes == "realm"
                && self.is_true("webauthn.pqcAlongsideClassical")))
            && !self.pqc_only()
            && self.registration_mode() != "classical-only"
    }

    /// `lanes()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn lanes(&self) -> Vec<String> {
        if !self.alongside_classical() {
            strings(&["classical"])
        } else if self.registers_post_quantum_only() {
            strings(&["pqc"])
        } else {
            strings(&LANES)
        }
    }

    /// `laneRefusal(lane)` (#643).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn lane_refusal(&self, lane: &str) -> Verdict {
        let refuse = |code: ErrorCode, why: String| {
            Verdict::coded(code, json!({ "ok": false, "why": why }))
        };
        if !LANES.contains(&lane) {
            return refuse(
                codes::STS_AUTHN_0350,
                format!(
                    "A passkey is created in the \"classical\" lane or the \
                     \"pqc\" lane. \"{}\" is neither.",
                    lane
                ),
            );
        }
        if lane == "pqc" && self.registration_mode() == "classical-only" {
            return refuse(
                codes::STS_AUTHN_0433,
                "The passkey policy offers classical passkeys only here \
                 (registrationMode is classical-only), so a post-quantum one \
                 cannot be created. A post-quantum passkey already registered \
                 goes on working."
                    .into(),
            );
        }
        if lane == "pqc" && !self.alongside_classical() {
            return refuse(
                codes::STS_AUTHN_0351,
                format!(
                    "A post-quantum passkey beside a classical one is not \
                     offered in this realm (webauthn.pqcAlongsideClassical{}). \
                     A post-quantum passkey already registered goes on working.",
                    if self.pqc_only() {
                        ", and webauthn.pqcOnly is on"
                    } else {
                        ""
                    }
                ),
            );
        }
        if lane == "pqc" && self.algorithms_offered("pqc", false).is_empty() {
            return refuse(
                codes::STS_AUTHN_0352,
                "This service can verify no ML-DSA algorithm, so a \
                 post-quantum passkey cannot be created."
                    .into(),
            );
        }
        Verdict::of(json!({ "ok": true }))
    }

    /// `algorithmIds(lane, classicalOnly)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn algorithm_ids(&self, lane: &str, classical_only: bool) -> Vec<f64> {
        self.algorithms_offered(lane, classical_only)
            .iter()
            .filter_map(|n| alg_id(n))
            .map(|n| n as f64)
            .collect()
    }

    /// `offered()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn offered(&self) -> bool {
        self.not_false("webauthn.enabled")
    }

    /// `useAllowed(use)`: `{ ok }`, or `{ ok: false, why }` marked.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn use_allowed(&self, key_use: &str) -> Verdict {
        let refuse = |code: ErrorCode, why: &str| {
            Verdict::coded(code, json!({ "ok": false, "why": why }))
        };
        if key_use == "primary" && !self.not_false("webauthn.primaryAllowed") {
            return refuse(
                codes::STS_AUTHN_0045,
                "A passkey cannot sign anybody in on its own in this realm \
                 (webauthn.primaryAllowed). Sign in with a password, and your \
                 passkey is asked for next where the realm allows it.",
            );
        }
        if key_use == "mfa" && !self.not_false("webauthn.mfaAllowed") {
            return refuse(
                codes::STS_AUTHN_0046,
                "A passkey cannot be a second factor in this realm \
                 (webauthn.mfaAllowed). An authenticator app is the other one, \
                 where the authentication policy allows it.",
            );
        }
        let primary = key_use == "primary";
        let (mechanism, role, code) = if primary {
            ("passkey", "primary", codes::STS_AUTHN_0253)
        } else {
            ("securityKey", "second-factor", codes::STS_AUTHN_0254)
        };
        if !self.src.authn_allows(mechanism, role) {
            return refuse(
                code,
                if primary {
                    "This realm's authentication policy does not accept a \
                     passkey as a first factor. Sign in with what it does \
                     accept."
                } else {
                    "This realm's authentication policy does not accept a \
                     passkey as a second factor."
                },
            );
        }
        Verdict::of(json!({ "ok": true }))
    }

    /// `enrolmentAllowed()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn enrolment_allowed(&self) -> Verdict {
        if !self.not_false("webauthn.enabled") {
            return Verdict::coded(
                codes::STS_AUTHN_0044,
                json!({ "ok": false, "why": "Passkeys are switched off in this \
                    realm (webauthn.enabled). A passkey already registered goes \
                    on being listed; no new one can be registered." }),
            );
        }
        if !self.use_allowed("primary").ok() && !self.use_allowed("mfa").ok() {
            return Verdict::coded(
                codes::STS_AUTHN_0531,
                json!({ "ok": false, "why": "This realm accepts a passkey \
                    neither as a way to sign in on its own nor as a second \
                    factor (webauthn.primaryAllowed, webauthn.mfaAllowed and \
                    the authentication policy), so a new one could never be \
                    used." }),
            );
        }
        Verdict::of(json!({ "ok": true }))
    }

    /// `creationOptions(rpId, kind, lane, classicalOnly)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn creation_options(
        &self,
        rp_id: &str,
        kind: &str,
        lane: &str,
        classical_only: bool,
    ) -> Json {
        let live = self.settings();
        let attachment = text(live.get("authenticatorAttachment"));
        let asked = if attachment == "any" && kind == "security-key" {
            "cross-platform"
        } else {
            ""
        };
        let resident = if kind == "passkey" {
            "required".to_string()
        } else {
            text(live.get("residentKey"))
        };
        let hints = self.hints_for(kind);
        let attestation =
            self.attestation_conveyance(rp_id)["requested"].clone();
        let mut selection = Map::new();
        selection.insert(
            "userVerification".into(),
            live["userVerification"].clone(),
        );
        selection.insert("residentKey".into(), json!(resident));
        selection
            .insert("requireResidentKey".into(), json!(resident == "required"));
        if attachment != "any" {
            selection
                .insert("authenticatorAttachment".into(), json!(attachment));
        } else if !asked.is_empty() {
            selection.insert("authenticatorAttachment".into(), json!(asked));
        }
        let mut out = Map::new();
        out.insert("rp".into(), json!({ "name": live["rpName"], "id": rp_id }));
        out.insert(
            "algorithms".into(),
            json!(self
                .algorithm_ids(lane, classical_only)
                .iter()
                .map(|n| js::num(*n))
                .collect::<Vec<_>>()),
        );
        out.insert("attestation".into(), attestation);
        out.insert("timeout".into(), live["timeoutMs"].clone());
        out.insert("authenticatorSelection".into(), Json::Object(selection));
        out.insert("credProps".into(), live["credProps"].clone());
        if live["minPinLength"] == json!(true) {
            out.insert("minPinLength".into(), json!(true));
        }
        out.insert("hints".into(), json!(hints));
        Json::Object(out)
    }

    /// `authenticatorKinds()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn authenticator_kinds(&self) -> Vec<String> {
        match text(self.settings().get("authenticatorAttachment")).as_str() {
            "platform" => strings(&["passkey"]),
            "cross-platform" => strings(&["security-key"]),
            _ => strings(&["passkey", "security-key"]),
        }
    }

    /// `requestOptions(rpId)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn request_options(&self, rp_id: &str) -> Json {
        let live = self.settings();
        let mut out = Map::new();
        out.insert("rpId".into(), json!(rp_id));
        out.insert("userVerification".into(), live["userVerification"].clone());
        out.insert("timeout".into(), live["timeoutMs"].clone());
        let hints = self.hints_for("sign-in");
        if !hints.is_empty() {
            out.insert("hints".into(), json!(hints));
        }
        Json::Object(out)
    }

    /// `usernamelessOffered()` (#474).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn usernameless_offered(&self) -> Verdict {
        let live = self.settings();
        let why = if live["enabled"] != json!(true) {
            "Passkeys are switched off in this realm (webauthn.enabled)."
        } else if live["primaryAllowed"] != json!(true) {
            "A passkey may not sign anybody in on its own in this realm \
             (webauthn.primaryAllowed)."
        } else if live["usernameless"] != json!(true) {
            "Signing in with a passkey and no username is switched off in \
             this realm (the passkey policy's allowUsernameless, on \
             Directory → Policies)."
        } else {
            ""
        };
        if why.is_empty() {
            Verdict::of(json!({ "ok": true }))
        } else {
            Verdict::coded(
                codes::STS_AUTHN_0301,
                json!({ "ok": false, "why": why }),
            )
        }
    }

    /// `discoverableRequestOptions(rpId)`: user verification REQUIRED.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn discoverable_request_options(&self, rp_id: &str) -> Json {
        let mut out = Map::new();
        out.insert("rpId".into(), json!(rp_id));
        out.insert("userVerification".into(), json!("required"));
        out.insert("timeout".into(), self.settings()["timeoutMs"].clone());
        let hints = self.hints_for("sign-in");
        if !hints.is_empty() {
            out.insert("hints".into(), json!(hints));
        }
        Json::Object(out)
    }

    /// `requireUserVerification()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn require_user_verification(&self) -> bool {
        self.settings()["userVerification"] == json!("required")
    }
}

/// `common/passkey_rules.js`'s `REASONS`: the code each reason records,
/// per stage (`register` the first, `use` the second).
fn code_for(reason: &str, action: &str) -> Option<ErrorCode> {
    let c = codes::STS_AUTHN_0316;
    let (register, use_) = match reason {
        "backup-eligible" => {
            (Some(codes::STS_AUTHN_0312), Some(codes::STS_AUTHN_0313))
        }
        "pin-length" => {
            (Some(codes::STS_AUTHN_0314), Some(codes::STS_AUTHN_0315))
        }
        "serial-missing" => (Some(codes::STS_AUTHN_0321), None),
        "serial-not-held" => (Some(codes::STS_AUTHN_0320), None),
        "attestation-unchecked" => (None, Some(codes::STS_AUTHN_0317)),
        "attestation-compromised"
        | "attestation-untrusted"
        | "attestation-aaguid"
        | "attestation-unlisted"
        | "attestation-level"
        | "attestation-fips" => (None, Some(c)),
        "post-quantum" => {
            (Some(codes::STS_AUTHN_0355), Some(codes::STS_AUTHN_0356))
        }
        "attestation-algorithm" => {
            (Some(codes::STS_AUTHN_0411), Some(codes::STS_AUTHN_0412))
        }
        "profile-algorithm" => (Some(codes::STS_AUTHN_0432), None),
        "recovery-self-service" => (None, Some(codes::STS_AUTHN_0380)),
        "recovery-enrol-first" => (None, Some(codes::STS_AUTHN_0381)),
        _ => (None, None),
    };
    if action == "register-passkey" {
        register
    } else {
        use_
    }
}

/// `passkey_rules.strictReading(question)`: the built-in passkey rules,
/// read from the facts — what the issuance policy's built-in document
/// answers, held to one truth table with it.
#[tracing::instrument(level = "debug", skip_all)]
pub fn strict_reading(q: &Json) -> Json {
    let groups: Vec<String> = q["groups"]
        .as_array()
        .map(|l| l.iter().map(js::string).collect())
        .unwrap_or_default();
    let carries = |g: &str| groups.iter().any(|x| x == g);
    let policy = &q["policy"];
    let settings = &q["settings"];
    let att = &q["attestation"];
    let whole = |v: &Json| v.as_f64().is_some_and(|n| n.fract() == 0.0);
    let serial_bound = js::truthy_opt(policy.get("enterpriseSerialAttribute"));
    let aaguids: Vec<String> = settings["allowedAaguids"]
        .as_array()
        .map(|l| l.iter().map(js::string).collect())
        .unwrap_or_default();
    let rank = js::number_opt(settings.get("requiredRank"));
    let required_rank = if rank > 0.0 { rank } else { 0.0 };
    let demands = settings["attestationPolicy"] == json!("require-trusted")
        || !aaguids.is_empty()
        || required_rank > 0.0
        || settings["requireFips"] == json!(true)
        || serial_bound;
    let attestation_held = carries("attestation")
        && policy["enforceAttestationAtSignIn"] == json!(true)
        && (settings["attestationPolicy"] != json!("off") || demands);
    let action = js::string_or(q.get("action"), "");
    let register = action == "register-passkey";
    let mut reason = "";
    if action == "recover-account" {
        let r = &q["recovery"];
        let row = js::string_or(policy.get("recoveryAssurance"), "");
        if !carries("recovery") || r["covered"] != json!(true) {
            reason = "";
        } else if r["selfService"] == json!(true) && row == "operator-only" {
            reason = "recovery-self-service";
        } else if r["at"] == json!("session")
            && (r["pending"] == json!(true) || js::truthy_opt(r.get("door")))
            && js::string_or(r.get("credential"), "") != "webauthn"
            && (row == "not-weaker" || row == "operator-only")
        {
            reason = "recovery-enrol-first";
        }
    } else if carries("backup-eligible")
        && q["backupEligible"] == json!(true)
        && policy["backupEligibility"] == json!("disallow")
    {
        reason = "backup-eligible";
    } else if carries("pin-length")
        && policy["enforcePinLength"] == json!(true)
        && ((!whole(&q["minPinLength"])
            && policy["pinLengthOnlyIfSupported"] != json!(true))
            || (whole(&q["minPinLength"])
                && whole(&policy["minPinLength"])
                && js::number(&q["minPinLength"])
                    < js::number(&policy["minPinLength"])))
    {
        reason = "pin-length";
    } else if register {
        let serial = js::string_or_empty(q.get("serial"));
        if carries("serial") && serial_bound && serial.is_empty() {
            reason = "serial-missing";
        } else if carries("serial")
            && serial_bound
            && !serial.is_empty()
            && !js::truthy_opt(q.get("serialHeld"))
        {
            reason = "serial-not-held";
        }
    } else if attestation_held {
        let level =
            required_rank > 0.0 || settings["requireFips"] == json!(true);
        if att["unchecked"] == json!(true) {
            reason = "attestation-unchecked";
        } else if att["compromised"] == json!(true) {
            reason = "attestation-compromised";
        } else if demands && att["trusted"] != json!(true) {
            reason = "attestation-untrusted";
        } else if !aaguids.is_empty()
            && !aaguids.contains(&js::string_or(att.get("aaguid"), ""))
        {
            reason = "attestation-aaguid";
        } else if level && att["listed"] != json!(true) {
            reason = "attestation-unlisted";
        } else if required_rank > 0.0
            && whole(&att["rank"])
            && js::number(&att["rank"]) < required_rank
        {
            reason = "attestation-level";
        } else if settings["requireFips"] == json!(true)
            && att["listed"] == json!(true)
            && att["fips"] != json!(true)
        {
            reason = "attestation-fips";
        }
    }
    let required = js::string_or(policy.get("postQuantumRequired"), "off");
    let pq_stage = if register {
        required == "registration-and-sign-in"
    } else {
        required == "sign-in" || required == "registration-and-sign-in"
    };
    if reason.is_empty()
        && carries("algorithm")
        && q["postQuantum"] != json!(true)
        && pq_stage
    {
        reason = "post-quantum";
    }
    let listed = policy["attestationAlgorithms"]
        .as_array()
        .is_some_and(|l| !l.is_empty());
    if reason.is_empty()
        && action != "recover-account"
        && carries("attestation-algorithm")
        && listed
        && (register || policy["enforceAttestationAtSignIn"] == json!(true))
        && q["attestationAlgorithmAllowed"] != json!(true)
    {
        reason = "attestation-algorithm";
    }
    if reason.is_empty()
        && register
        && carries("profile-algorithm")
        && policy["registrationAlgorithmsFrom"] == json!("profile")
        && q["profileAlgorithmOffered"] != json!(true)
    {
        reason = "profile-algorithm";
    }
    if reason.is_empty() {
        json!({ "verdict": "allow", "code": "", "reason": "" })
    } else {
        json!({ "verdict": "refuse",
                "code": code_for(reason, &action).map_or("", ErrorCode::as_str),
                "reason": reason })
    }
}

/// The key doors' view of the WebAuthn policy (`KeyDoors`' `rules`).
impl super::enrolment::WebauthnRules for WebauthnPolicy {
    fn enrolment_allowed(&self) -> Verdict {
        WebauthnPolicy::enrolment_allowed(self)
    }

    fn enrolment_lane(&self, asked: &str) -> String {
        WebauthnPolicy::enrolment_lane(self, asked)
    }

    fn classical_retry_refusal(&self, at: &str) -> Verdict {
        WebauthnPolicy::classical_retry_refusal(self, at)
    }

    fn classical_retry_lane(&self, lane: &str) -> String {
        WebauthnPolicy::classical_retry_lane(self, lane)
    }

    fn lane_refusal(&self, lane: &str) -> Verdict {
        WebauthnPolicy::lane_refusal(self, lane)
    }

    fn max_keys_per_person(&self) -> f64 {
        js::number(&self.settings()["maxKeysPerPerson"])
    }

    fn authenticator_kinds(&self) -> Vec<String> {
        WebauthnPolicy::authenticator_kinds(self)
    }

    fn algorithm_ids(&self, lane: &str, classical_only: bool) -> Vec<f64> {
        WebauthnPolicy::algorithm_ids(self, lane, classical_only)
    }

    fn require_user_verification(&self) -> bool {
        WebauthnPolicy::require_user_verification(self)
    }

    fn use_allowed(&self, key_use: &str) -> bool {
        WebauthnPolicy::use_allowed(self, key_use).ok()
    }

    fn asks_post_quantum(&self, lane: &str) -> bool {
        WebauthnPolicy::asks_post_quantum(self, lane, false)
    }

    fn alongside_classical(&self) -> bool {
        WebauthnPolicy::alongside_classical(self)
    }
}

/// The key doors' view of the selected passkey profile (`KeyDoors`'
/// `profile`).
impl super::enrolment::PasskeyProfile for WebauthnPolicy {
    fn has_selection(&self) -> bool {
        WebauthnPolicy::has_selection(self)
    }

    fn select(&self, name: &str) {
        WebauthnPolicy::select(self, name, "");
    }

    fn admin_enrolment_allowed(&self) -> bool {
        WebauthnPolicy::admin_enrolment_allowed(self)
    }

    fn credential_label_for(&self, provider: &str, kind: &str) -> String {
        WebauthnPolicy::credential_label_for(self, provider, kind)
    }

    fn client_rule_for(&self, client: &str) -> String {
        WebauthnPolicy::client_rule_for(self, client)
    }

    fn refusal_for(&self, at: &str, facts: &Json) -> Option<Json> {
        WebauthnPolicy::refusal_for(self, at, facts, None)
    }
}
