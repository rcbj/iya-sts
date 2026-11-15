// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! PASSKEYS IN THE SIGN-IN SCREENS (#444, phase 5, the `passkeys` slice):
//! what `authn/authn.ts` answers the passkey family of `/authn-api` with,
//! branch for branch —
//!
//! | Node | Here |
//! |---|---|
//! | `passkeyOptions()`, `passkeyOffered()`, `usernamelessRequired()`, `passkeyChallengeFor()` | [`SignIn::passkey_options`] and its helpers |
//! | `passkeySignIn()`, `passkeyRefused()`, `signalsUnknown()` | [`SignIn::passkey_sign_in`] |
//! | `keyForAssertion()`, `webauthnFacts()` | [`SignIn::key_for_assertion`], [`SignIn::webauthn_facts`] |
//! | `mfaWebauthnOptions()`, `mfaWebauthnAct()`, `finishWebauthn()` | the passkey step's ceremony |
//! | `mfaSetupFacts()`, `mfaSetupAct()` | the set-up step (an authenticator app, a passkey, Ignore) |
//! | `postLoginStep()`, `finishPostLogin()`, `postLoginAct()` | the post-login step (#1096) |
//! | `rpIdOf()`, `rpIdProblem()`, `originOf()`, `expectedOriginFor()` | the RP ID and the origin |
//! | `attestationAtSignIn()`, `noteStepCeremony()`, `notePasskeyCeremony()` | the attestation rules at sign-in and the ceremony rows |
//!
//! **THE SESSION IS THE IDENTITY** (`authn/CLAUDE.md`): a verified assertion
//! or registration is EVIDENCE (`sts_credentials::evidence`), handed to
//! `Sessions::start_session()` exactly where Node calls `startSession()`.
//!
//! WHAT IS NOT HERE, and how it answers meanwhile (the report says why):
//! a post-login UPGRADE (#1100, #939's ceremony: `postLoginUpgradeAct()`,
//! `upgradeStepFacts()`) — the upgrade's doors are a later slice's, so a
//! step armed for one answers [`Outcome::Unported`] (Express's 404); a
//! proof before an enrolment (`thenEnrol`, #475) answers the same, as the
//! other steps already do; an account recovery's enrolment (#724) is minted
//! by doors not in this runtime, so no step carries `recovery`.

use serde_json::{json, Map, Value as Json};
use sts_authn::ports::Response;
use sts_core::errors::{codes, ErrorCode};
use sts_credentials::evidence::{key_lane, Evidence};
use sts_credentials::webauthn::ceremony::{
    from_base64url, verify_assertion, verify_registration, AssertionInput,
    RegistrationInput,
};
use sts_credentials::webauthn::enrolment::{
    cloned_key_verdict, discoverable_of, failure_code_for, held_to_offer,
    is_user_handle, key_credential_type, key_name, lane_user,
    reported_min_pin_length, transports_of,
};
use sts_credentials::Verdict;

use super::{
    encode_component, num, number, text, truthy, Answer, Call, Outcome, SignIn,
    LOGIN_PATH, MFA_SETUP_PATH, WEBAUTHN_PATH,
};
use sts_credentials::credentials::Credentials;

/// The post-login step's page.
pub const POST_LOGIN_PATH: &str = "/authn/post-login";

/// `applications.HOSTED_SURFACE_CLIENT_IDS`.
const HOSTED_SURFACE_CLIENT_IDS: [&str; 4] = [
    "sts-admin-console",
    "sts-user-portal",
    "sts-report",
    "sts-debugger-ui",
];

const SAID: &str = "That passkey could not sign you in.";
const LEGACY_SAID: &str = "This passkey was registered before passkeys \
    could sign in without a username. Type your username to use it, or \
    register it again at /portal/keys.";

fn code_of_text(t: &str) -> Option<ErrorCode> {
    sts_core::errors::known(t)
}

/// What a ceremony POST names a key by.
fn named_id(credential: &Json) -> String {
    let raw = credential.get("rawId").filter(|v| truthy(Some(v)));
    text(raw.or(credential.get("id")))
}

/// The JSON a ceremony's form posted, or the refusal.
fn parsed_credential(posted: &str) -> Result<Json, ()> {
    if posted.is_empty() {
        return Ok(json!({}));
    }
    match serde_json::from_str::<Json>(posted) {
        Ok(Json::Null) => Ok(json!({})),
        Ok(v) => Ok(v),
        Err(_) => Err(()),
    }
}

impl SignIn {
    // -------------------------------------------------------------------
    // The RP ID and the origin.
    // -------------------------------------------------------------------

    /// `originOf(base)`.
    #[tracing::instrument(level = "trace")]
    pub fn origin_of(base: &str) -> String {
        match url::Url::parse(base) {
            Ok(u) => u.origin().ascii_serialization(),
            Err(_) => {
                let re = regex::Regex::new(r"^(https?://[^/?#]+).*$").ok();
                re.and_then(|r| r.captures(base).map(|c| c[1].to_string()))
                    .unwrap_or_else(|| base.to_string())
            }
        }
    }

    fn host_of(base: &str) -> String {
        match url::Url::parse(base) {
            Ok(u) => {
                let h = u.host_str().unwrap_or("").to_string();
                // `URL.hostname` keeps an IPv6 literal's brackets.
                h
            }
            Err(_) => base
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split(':')
                .next()
                .unwrap_or("")
                .to_string(),
        }
    }

    fn wanted_rp_id(&self) -> String {
        text(self.webauthn.settings().get("rpId"))
    }

    /// `rpIdProblem(base)`: in product mode, a configured RP ID that does
    /// not fit this address refuses the ceremony.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn rp_id_problem(&self, base: &str) -> String {
        let wanted = self.wanted_rp_id();
        if wanted.is_empty()
            || self.facts.predicate("acceptsUnregisteredAddresses")
        {
            return String::new();
        }
        let host = SignIn::host_of(base);
        let lower = host.to_lowercase();
        let want = wanted.to_lowercase();
        if lower == want || lower.ends_with(&format!(".{want}")) {
            return String::new();
        }
        format!(
            "webauthn.rpId is \"{wanted}\", which is neither the host this \
             request reached (\"{host}\") nor a registrable domain suffix of \
             it, and in product mode a security-key ceremony is not run \
             against an address the configuration did not name. Reach this \
             service at a host under \"{wanted}\", or set \
             global.publicBaseUrl to one."
        )
    }

    /// `rpIdOf(base)`: `webauthn.rpId` where it is the host or a domain
    /// suffix of it, else the host.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn rp_id_of(&self, base: &str) -> String {
        let host = SignIn::host_of(base);
        let wanted = self.wanted_rp_id();
        if wanted.is_empty() {
            return host;
        }
        let lower = host.to_lowercase();
        let want = wanted.to_lowercase();
        if lower == want || lower.ends_with(&format!(".{want}")) {
            return want;
        }
        tracing::warn!(
            "authn: webauthn.rpId is \"{}\", which is NOT this origin's host \
             (\"{}\") nor a registrable domain suffix of it. WebAuthn forbids \
             that and the browser would refuse the ceremony with an error \
             indistinguishable from a hardware failure, so this service is \
             using \"{}\" instead and telling you why. Set webauthn.rpId to \
             \"\" or to a suffix of the host you reach this service on.{}",
            wanted,
            host,
            host,
            if self.facts.predicate("acceptsUnregisteredAddresses") {
                ""
            } else {
                " In product mode the ceremony itself is refused — see \
                 rpIdProblem()."
            }
        );
        host
    }

    /// `allowedOrigins()`.
    fn allowed_origins(&self) -> Vec<String> {
        let raw = self.facts.setting("webauthn.allowedOrigins");
        let list: Vec<String> = match raw {
            Json::Array(l) => l.iter().map(|v| text(Some(v))).collect(),
            other => text(Some(&other)).split(',').map(String::from).collect(),
        };
        list.iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| SignIn::origin_of(&s))
            .collect()
    }

    /// `expectedOriginFor(base, credential)`. A cell's own console address
    /// (#361) is the cells slice's; one cell here, so the base's origin is
    /// the implicit list.
    #[tracing::instrument(level = "debug", skip(self, credential))]
    pub fn expected_origin_for(&self, base: &str, credential: &Json) -> String {
        let list = self.allowed_origins();
        if list.is_empty() {
            return SignIn::origin_of(base);
        }
        let bytes = from_base64url(&text(
            credential
                .get("response")
                .and_then(|r| r.get("clientDataJSON")),
        ));
        let claimed = serde_json::from_slice::<Json>(&bytes)
            .ok()
            .map(|c| text(c.get("origin")))
            .unwrap_or_default();
        if !claimed.is_empty() && list.contains(&claimed) {
            return claimed;
        }
        list[0].clone()
    }

    // -------------------------------------------------------------------
    // A passkey and no username (#474).
    // -------------------------------------------------------------------

    /// `passkeyOffered(record)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn passkey_offered(&self, record: &Json) -> Verdict {
        let offered = self.webauthn.usernameless_offered();
        if !offered.ok() {
            return offered;
        }
        let restricted: Vec<String> = record
            .get("allowedMechanisms")
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|v| text(Some(v))).collect())
            .unwrap_or_default();
        let why = if truthy(record.get("lockedUsername")) {
            "Linking an account signs in with its password, so a passkey on \
             its own is not offered here."
        } else if !self.facts.authn_allows("passkey", "primary") {
            "This realm's authentication policy does not accept a passkey as \
             a first factor."
        } else if !restricted.is_empty()
            && !restricted.iter().any(|r| r == "webauthn")
        {
            "This application does not allow a passkey sign-in."
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

    /// `usernamelessRequired(record)` (#608).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn usernameless_required(&self, record: &Json) -> bool {
        let allowed: Vec<String> = record
            .get("allowedMechanisms")
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|v| text(Some(v))).collect())
            .unwrap_or_default();
        let alone = truthy(record.get("forcePasswordless"))
            && text(record.get("mechanismSource")) == "application"
            && text(record.get("mechanism")) == "webauthn"
            && allowed.iter().all(|a| a == "webauthn");
        if !alone || truthy(record.get("lockedUsername")) {
            return false;
        }
        let application = text(record.get("application"));
        let name = self.webauthn.selection_for("", &application);
        let profile = self.webauthn.read(Some(&name));
        let required = self.webauthn.requires_usernameless(Some(&profile));
        if required
            && (name.is_empty() || name == "default")
            && HOSTED_SURFACE_CLIENT_IDS.contains(&application.as_str())
        {
            return false;
        }
        required && self.passkey_offered(record).ok()
    }

    /// `passkeyChallengeFor(record)`: minted on the record and kept there
    /// until a POST takes it.
    fn passkey_challenge_for(&self, record: &mut Json) -> String {
        if !truthy(record.get("passkeyChallenge")) {
            record["passkeyChallenge"] = json!(self.facts.random_id(32));
            record["passkeyChallengeAt"] = num(self.facts.now_ms().floor());
            let id = text(record.get("id"));
            if !id.is_empty() && self.stores.pending.has(&id) {
                self.stores.pending.set(&id, record.clone());
            }
        }
        text(record.get("passkeyChallenge"))
    }

    /// `passkeyOptions(req, record)`: `{ ok, challenge, rpId, options }`,
    /// or the refusal's code and sentence.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn passkey_options(
        &self,
        call: &Call,
        mut record: Json,
    ) -> Result<Json, (ErrorCode, String)> {
        self.webauthn.select("", &text(record.get("application")));
        let offered = self.passkey_offered(&record);
        if !offered.ok() {
            return Err((
                offered.code.unwrap_or(codes::STS_AUTHN_0301),
                text(offered.value.get("why")),
            ));
        }
        if let Some(r) = record.as_object_mut() {
            r.remove("passkeyChallenge");
        }
        let rp_id = self.rp_id_of(&call.base);
        let challenge = self.passkey_challenge_for(&mut record);
        Ok(json!({ "ok": true, "challenge": challenge, "rpId": rp_id,
                   "options": self.webauthn.discoverable_request_options(&rp_id) }))
    }

    /// `signalsUnknown(credentialId)`: one realm and one cell only.
    fn signals_unknown(&self, id: &str) -> String {
        let shape = !id.is_empty()
            && id.len() <= 1400
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if shape && !self.facts.realms_active() {
            id.to_string()
        } else {
            String::new()
        }
    }

    /// `passkeyRefused(res, base, record, code, logged, shown, unknownId)`.
    #[allow(clippy::too_many_arguments)]
    fn passkey_refused(
        &self,
        call: &Call,
        record: &mut Json,
        held: &Json,
        code: ErrorCode,
        logged: &str,
        shown: &str,
        unknown: &str,
    ) -> Answer {
        tracing::info!(
            "authn: a passkey sign-in with no username was refused ({}): {}",
            code.as_str(),
            logged
        );
        self.note_passkey_ceremony(call, held, code.as_str());
        let id = text(record.get("id"));
        if !id.is_empty()
            && !self.stores.pending.has(&id)
            && !self.expired(record)
        {
            self.stores.pending.set(&id, record.clone());
        }
        let mut answer =
            self.screen_refused(call, record, shown, 400, false, false);
        answer.body["passkey"] =
            json!({ "unknownCredential": unknown, "autofill": false });
        answer.marked(code)
    }

    /// `notePasskeyCeremony(res, refusedWith)`: the usernameless row.
    fn note_passkey_ceremony(&self, call: &Call, held: &Json, refused: &str) {
        if !held.is_object() {
            return;
        }
        let owner = text(held.get("owner"));
        let known = &held["known"];
        let keys = if owner.is_empty() {
            Vec::new()
        } else {
            self.credentials.keys_of(&owner)
        };
        self.ceremonies.record(
            &json!({
                "ceremony": "assertion", "door": "usernameless",
                "username": owner, "role": "primary",
                "lane": if known.is_object() { key_lane(known) } else { String::new() },
                "outcome": if refused.is_empty() { "success" } else { "refused" },
                "errorCode": refused,
                "offered": keys.iter().map(|k| Credentials::key_algorithm(k)["name"].clone())
                    .collect::<Vec<_>>(),
                "algorithm": if truthy(held.get("algorithm")) { held["algorithm"].clone() }
                    else if known.is_object() { Credentials::key_algorithm(known)["name"].clone() }
                    else { json!("") },
                "posted": held["posted"], "application": held["application"],
                "issuedAt": held["issuedAt"],
                "userAgent": call.request.user_agent }),
            self.facts.now_ms(),
        );
    }

    /// `keyForAssertion(username, use, presentedId)`: the key it names,
    /// where the realm lets a key answer this step.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn key_for_assertion(
        &self,
        username: &str,
        key_use: &str,
        presented: &str,
    ) -> Result<Json, (ErrorCode, String)> {
        let allowed = self.webauthn.use_allowed(key_use);
        if !allowed.ok() {
            return Err((
                allowed.code.unwrap_or(codes::STS_AUTHN_0044),
                text(allowed.value.get("why")),
            ));
        }
        let usable = self.credentials.keys_of(username);
        if let Some(k) = usable
            .iter()
            .find(|k| text(k.get("credentialId")) == presented)
        {
            return Ok(k.clone());
        }
        Err(if usable.is_empty() {
            (
                codes::STS_AUTHN_0025,
                format!("no passkey is enrolled for {username}"),
            )
        } else {
            (
                codes::STS_AUTHN_0026,
                format!(
                    "the assertion names a credential that is not one of the \
                     {} passkey(s) enrolled for {}",
                    usable.len(),
                    username
                ),
            )
        })
    }

    /// `attestationAtSignIn(username, key, application)` (#530): `Some((
    /// code, why))` where the rules in force refuse the key.
    fn attestation_at_sign_in(
        &self,
        username: &str,
        key: &Json,
        application: &str,
    ) -> Option<(ErrorCode, String)> {
        if !key.is_object() {
            return None;
        }
        let verdict = self.webauthn.sign_in_verdict(
            key,
            username,
            self.metadata.as_ref(),
        );
        if verdict.ok() {
            return None;
        }
        let code = verdict.code.unwrap_or(codes::STS_AUTHN_0316);
        let why = text(verdict.value.get("why"));
        tracing::info!(
            "authn: a passkey of \"{}\" was REFUSED at sign-in by the \
             attestation rules in force ({}): {}",
            username,
            code.as_str(),
            why
        );
        self.facts.audit(&json!({
            "action": "session.refuse", "actor": username,
            "errorCode": code.as_str(), "protocol": "WebAuthn",
            "channel": "http", "target": "",
            "summary": format!("a passkey of {username} was refused at \
                sign-in: the attestation rules in force no longer accept it"),
            "detail": { "application": application, "method": "webauthn",
                        "credential": "webauthn",
                        "aaguid": sts_credentials::evidence::aaguid_string(
                            &text(key.get("aaguid"))) } }));
        if code == codes::STS_AUTHN_0316 || code == codes::STS_AUTHN_0412 {
            let id = text(key.get("credentialId"));
            if self.credentials.note_key_attestation_refused(
                username,
                &id,
                code.as_str(),
                &why,
            ) {
                self.facts.credential_changed(&json!({
                    "username": username,
                    "credentialType": key_credential_type(key),
                    "changeType": "update", "initiatingEntity": "policy",
                    "via": "sign-in" }));
            }
        }
        Some((code, why))
    }

    /// `passkeySignIn(req, res, base, record, body)`: a discoverable
    /// credential's assertion signs a person in with no username.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn passkey_sign_in(
        &self,
        call: &Call,
        mut record: Json,
        posted: &str,
    ) -> Answer {
        let application = text(record.get("application"));
        self.webauthn.select("", &application);
        let mut held = json!({ "posted": {}, "owner": "", "known": null,
            "algorithm": "", "application": application, "issuedAt": 0 });
        let offered = self.passkey_offered(&record);
        if !offered.ok() {
            let why = text(offered.value.get("why"));
            return self.passkey_refused(
                call,
                &mut record,
                &Json::Null,
                offered.code.unwrap_or(codes::STS_AUTHN_0301),
                &why,
                &why,
                "",
            );
        }
        let challenge = text(record.get("passkeyChallenge"));
        let challenge_at = {
            let n = number(record.get("passkeyChallengeAt"));
            if n.is_finite() {
                n
            } else {
                0.0
            }
        };
        if let Some(r) = record.as_object_mut() {
            r.remove("passkeyChallenge");
            r.remove("passkeyChallengeAt");
        }
        let id = text(record.get("id"));
        self.stores.pending.set(&id, record.clone());
        let Ok(credential) = parsed_credential(posted) else {
            return self.passkey_refused(
                call,
                &mut record,
                &Json::Null,
                codes::STS_AUTHN_0021,
                "the posted credential was not JSON",
                "The browser returned something this server could not read.",
                "",
            );
        };
        held["posted"] = credential.clone();
        held["issuedAt"] = if challenge.is_empty() {
            json!(0)
        } else {
            num(challenge_at)
        };
        if truthy(credential.get("error"))
            || !truthy(credential.get("response"))
        {
            let error = text(credential.get("error"));
            let (logged, shown) = if error.is_empty() {
                (
                    "the browser ran no ceremony".to_string(),
                    "Your browser did not run the ceremony. Signing in with a \
                     passkey needs JavaScript — a passkey is used by the \
                     browser and no form can do it. Allow scripts for this \
                     page, or type your username."
                        .to_string(),
                )
            } else {
                (
                    format!("the browser refused: {error}"),
                    format!("Your browser did not use a passkey ({error})."),
                )
            };
            return self.passkey_refused(
                call,
                &mut record,
                &held,
                codes::STS_AUTHN_0022,
                &logged,
                &shown,
                "",
            );
        }
        if challenge.is_empty() {
            return self.passkey_refused(
                call,
                &mut record,
                &held,
                codes::STS_AUTHN_0019,
                "the screen armed no challenge, or it was spent",
                "That passkey request has expired. Try again.",
                "",
            );
        }
        let rp_refusal = self.rp_id_problem(&call.base);
        if !rp_refusal.is_empty() {
            return self.passkey_refused(
                call,
                &mut record,
                &held,
                codes::STS_AUTHN_0023,
                &rp_refusal,
                &rp_refusal,
                "",
            );
        }
        let credential_id = named_id(&credential);
        let handle = text(credential["response"].get("userHandle"));
        let owner = self.keys.owner_of_user_handle(&handle);
        if !owner.is_empty() {
            self.webauthn.select(&owner, &application);
            held["owner"] = json!(owner);
        }
        if owner.is_empty() {
            let legacy_name = if !handle.is_empty()
                && !is_user_handle(&json!(handle))
            {
                String::from_utf8_lossy(&from_base64url(&handle)).to_string()
            } else {
                String::new()
            };
            let legacy = !legacy_name.is_empty()
                && self.credentials.keys_of(&legacy_name).iter().any(|k| {
                    text(k.get("credentialId")) == credential_id
                        && !truthy(k.get("userHandle"))
                });
            if legacy {
                return self.passkey_refused(
                    call,
                    &mut record,
                    &held,
                    codes::STS_AUTHN_0304,
                    "a key registered before #474 under the username",
                    LEGACY_SAID,
                    "",
                );
            }
            let unknown = if handle.is_empty() {
                String::new()
            } else {
                self.signals_unknown(&credential_id)
            };
            return self.passkey_refused(
                call,
                &mut record,
                &held,
                codes::STS_AUTHN_0302,
                if handle.is_empty() {
                    "the authenticator returned no user handle"
                } else {
                    "the user handle is held by nobody in this realm"
                },
                SAID,
                &unknown,
            );
        }
        let known =
            match self.key_for_assertion(&owner, "primary", &credential_id) {
                Ok(k) => k,
                Err((code, why)) => {
                    return self.passkey_refused(
                        call,
                        &mut record,
                        &held,
                        code,
                        &why,
                        SAID,
                        "",
                    )
                }
            };
        held["known"] = known.clone();
        let handled =
            self.keys.user_handle_refusal(&owner, &known, &handle, true);
        if !handled.ok() {
            let code = handled.code.unwrap_or(codes::STS_AUTHN_0303);
            return self.passkey_refused(
                call,
                &mut record,
                &held,
                code,
                &text(handled.value.get("why")),
                if code == codes::STS_AUTHN_0304 {
                    LEGACY_SAID
                } else {
                    SAID
                },
                "",
            );
        }
        let response = &credential["response"];
        let verdict = match verify_assertion(&AssertionInput {
            authenticator_data: text(response.get("authenticatorData")),
            client_data_json: text(response.get("clientDataJSON")),
            signature: text(response.get("signature")),
            expected_challenge: json!(challenge),
            expected_origin: json!(
                self.expected_origin_for(&call.base, &credential)
            ),
            expected_rp_id: self.rp_id_of(&call.base),
            require_user_verification: true,
            previous_sign_count: Some(number(known.get("signCount")))
                .filter(|n| n.is_finite()),
            public_key_jwk: known["publicKeyJwk"].clone(),
            allow_insecure: self.webauthn.insecure_algorithms_allowed(),
        }) {
            Ok(v) => v,
            Err(e) => {
                return self.passkey_refused(
                    call,
                    &mut record,
                    &held,
                    codes::STS_AUTHN_0027,
                    &format!("verification threw: {e}"),
                    SAID,
                    "",
                )
            }
        };
        if cloned_key_verdict(&verdict) {
            self.keys.note_key_cloned(
                &owner,
                &text(known.get("credentialId")),
                &format!(
                    "signature counter {}, last recorded {}",
                    text(verdict.get("signCount")),
                    text(known.get("signCount"))
                ),
            );
        }
        if verdict["ok"] != json!(true) {
            let code = failure_code_for(&verdict);
            self.note_refused(
                &record,
                &owner,
                "webauthn",
                code,
                "assertion-did-not-verify",
            );
            let failed: Vec<String> = verdict["failed"]
                .as_array()
                .map(|l| l.iter().map(|v| text(Some(v))).collect())
                .unwrap_or_default();
            return self.passkey_refused(
                call,
                &mut record,
                &held,
                code,
                &format!(
                    "the assertion did not verify — {}",
                    failed.join("; ")
                ),
                SAID,
                "",
            );
        }
        let spent = self.keys.spend_assertion(&json!({
            "username": owner, "credentialId": known["credentialId"],
            "signCount": verdict["signCount"], "flags": verdict["flags"],
            "challenge": challenge, "ttlMs": num(self.mfa_step_ttl_ms()) }));
        if !spent.ok() {
            let said = text(
                spent
                    .value
                    .get("detail")
                    .filter(|d| truthy(Some(d)))
                    .or(spent.value.get("reason")),
            );
            return self.passkey_refused(
                call,
                &mut record,
                &held,
                spent.code.unwrap_or(codes::STS_AUTHN_0182),
                &said,
                SAID,
                "",
            );
        }
        if let Some((code, why)) =
            self.attestation_at_sign_in(&owner, &known, &application)
        {
            return self.passkey_refused(
                call,
                &mut record,
                &held,
                code,
                &why,
                &why,
                "",
            );
        }
        held["algorithm"] = json!(text(verdict.get("algorithm")));
        self.note_passkey_ceremony(call, &held, "");
        self.stores.pending.delete(&id);
        let mut said = Map::new();
        said.insert("postLoginHold".into(), json!(true));
        said.insert("application".into(), json!(application));
        let credential_said = sts_credentials::evidence::webauthn_credential(
            &known,
            &verdict,
            "assertion",
        );
        let mut response = Response::default();
        let started = Evidence::discoverable_passkey(credential_said)
            .start_session(
                &self.sessions,
                &mut response,
                &owner,
                &text(record.get("protocol")),
                &mut said,
                Some(&call.request),
            );
        tracing::info!(
            "authn: {} signed in with a passkey and no username{}.",
            owner,
            if started.is_some() {
                ""
            } else {
                " (the session was refused)"
            }
        );
        self.after_session(
            call,
            &mut record,
            &owner,
            started,
            &said,
            response,
            false,
        )
    }

    // -------------------------------------------------------------------
    // The passkey step.
    // -------------------------------------------------------------------

    /// `postQuantumHelp()` (#946).
    pub(crate) fn post_quantum_help(&self) -> Json {
        json!({ "register": if self.webauthn.offered() { "/portal/keys" } else { "" } })
    }

    /// `webauthnFacts(base, mfaId, step, chosenKey, lane)`: the page's
    /// facts and, as `ceremony`, the options the browser's ceremony is
    /// armed with. The two refusals' codes are returned beside them (the
    /// facts are an answer, so a code is a MARK and no member, #1355).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn webauthn_facts(
        &self,
        call: &Call,
        id: &str,
        step: &mut Json,
        chosen_key: &str,
        lane: &str,
    ) -> (Json, Option<ErrorCode>, Option<ErrorCode>) {
        let username = text(step.get("username"));
        let passwordless = truthy(step.get("passwordless"));
        let application = step
            .get("authn")
            .map(|a| text(a.get("application")))
            .unwrap_or_default();
        self.webauthn.select(&username, &application);
        let held = self.credentials.keys_of(&username);
        let pq_required = self.webauthn.requires_post_quantum("sign-in", None);
        let alg_of = |k: &Json| Credentials::key_algorithm(k);
        let pq_held: Vec<Json> = if pq_required {
            held.iter()
                .filter(|k| {
                    self.webauthn
                        .post_quantum_refusal(&alg_of(k), "sign-in")
                        .is_none()
                })
                .cloned()
                .collect()
        } else {
            held.clone()
        };
        let list_all = pq_required
            && self.webauthn.post_quantum_allow_credentials(None)
                == "list-and-refuse";
        let known = if list_all {
            held.clone()
        } else {
            pq_held.clone()
        };
        let recovery = truthy(step.get("recovery"));
        let post_login = truthy(step.get("postLogin"));
        let pq_refusal = if !recovery
            && !post_login
            && pq_required
            && !held.is_empty()
            && pq_held.is_empty()
        {
            self.webauthn
                .post_quantum_refusal(&alg_of(&held[0]), "sign-in")
        } else {
            None
        };
        let mode = if recovery || post_login || held.is_empty() {
            "create"
        } else {
            "get"
        };
        let phrh = step
            .get("authn")
            .map(|a| text(a.get("phishingClass")))
            .unwrap_or_default()
            == "phrh"
            && mode == "get"
            && pq_refusal.is_none();
        let mut hardware_known = known.clone();
        let mut hardware_refusal: Option<(ErrorCode, String)> = None;
        if phrh {
            hardware_known = known
                .iter()
                .filter(|k| sts_credentials::phishing::PhishingResistance::stored_key_earns_hardware(k))
                .cloned()
                .collect();
            if !known.is_empty() && hardware_known.is_empty() {
                hardware_refusal = Some((
                    codes::STS_AUTHN_0459,
                    "This sign-in asks for a hardware-protected \
                     phishing-resistant passkey, and none of the passkeys \
                     held for this step can earn it. A synced passkey, or one \
                     whose attestation is not trusted, is not enough."
                        .into(),
                ));
            }
        }
        let offered: Vec<Json> = if hardware_refusal.is_some() {
            Vec::new()
        } else {
            hardware_known
        };
        let separate = mode == "get"
            && offered.len() > 1
            && !self.webauthn.aggregates_devices();
        let chosen = if separate {
            offered
                .iter()
                .find(|k| text(k.get("credentialId")) == chosen_key)
                .cloned()
        } else {
            None
        };
        let choosing = separate && chosen.is_none();
        let allowed: Vec<Json> = match &chosen {
            Some(c) => vec![c.clone()],
            None => offered.clone(),
        };
        let chosen_lane = if mode == "create" && !lane.is_empty() && !post_login
        {
            self.webauthn.enrolment_lane(lane)
        } else {
            String::new()
        };
        let step_lane_now = {
            let l = text(step.get("lane"));
            if l.is_empty() {
                "classical".to_string()
            } else {
                l
            }
        };
        if !chosen_lane.is_empty() && chosen_lane != step_lane_now {
            step["lane"] = json!(chosen_lane);
            step["userHandle"] = json!("");
            self.stores.mfa.set(id, step.clone());
        } else if mode == "create"
            && !truthy(step.get("lane"))
            && self.webauthn.enrolment_lane("") != "classical"
        {
            step["lane"] = json!(self.webauthn.enrolment_lane(""));
            step["userHandle"] = json!("");
            self.stores.mfa.set(id, step.clone());
        }
        let step_lane = {
            let l = text(step.get("lane"));
            if l.is_empty() {
                "classical".to_string()
            } else {
                l
            }
        };
        if mode == "create" && !truthy(step.get("userHandle")) {
            let minted = self.keys.user_handle_of(&username, true, &step_lane);
            step["userHandle"] = json!(if minted.is_empty() {
                self.keys.new_user_handle()
            } else {
                minted
            });
            self.stores.mfa.set(id, step.clone());
        }
        let rp_id = self.rp_id_of(&call.base);
        let options = self.webauthn.settings();
        let classical_only = truthy(step.get("classicalOnly"));
        let pl = &step["postLogin"];
        let pl_fallback = post_login
            && text(pl.get("reason")) == "none"
            && text(pl.get("fallback")) == "classical";
        let pl_retrying = pl_fallback && classical_only;
        let post_login_algs: Option<Vec<String>> =
            if mode == "create" && post_login {
                Some(if pl_retrying {
                    self.webauthn.algorithms_offered(&step_lane, true)
                } else {
                    self.webauthn.upgrade_algorithms()
                })
            } else {
                None
            };
        let narrowed_rule =
            step["clientRule"].get("narrowed") == Some(&json!(true));
        let fallback = if post_login_algs.is_some() {
            json!({ "asksPostQuantum": !pl_retrying,
                    "classical": pl_fallback && !pl_retrying
                        && self.webauthn.classical_fallback_offered(&step_lane, "sign-in"),
                    "retrying": pl_retrying })
        } else if mode == "create" {
            json!({ "asksPostQuantum": self.webauthn.asks_post_quantum(&step_lane, classical_only),
                    "classical": !classical_only
                        && self.webauthn.classical_fallback_offered(&step_lane, "sign-in"),
                    "retrying": classical_only && !narrowed_rule })
        } else {
            Json::Null
        };
        let choice = |k: &Json| json!({ "id": text(k.get("credentialId")), "name": key_name(k) });
        let problem = {
            let rp = self.rp_id_problem(&call.base);
            if !rp.is_empty() {
                rp
            } else if let Some(r) = &pq_refusal {
                text(r.get("why"))
            } else if let Some((_, why)) = &hardware_refusal {
                why.clone()
            } else {
                String::new()
            }
        };
        let algorithms: Vec<Json> = match &post_login_algs {
            Some(a) => a.iter().map(|s| json!(s)).collect(),
            None if mode == "create" => self
                .webauthn
                .algorithms_offered(&step_lane, classical_only)
                .iter()
                .map(|s| json!(s))
                .collect(),
            None => options["algorithms"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        };
        let lanes: Vec<String> = if post_login_algs.is_some() {
            vec![step_lane.clone()]
        } else if mode == "create" {
            self.webauthn.lanes()
        } else {
            Vec::new()
        };
        let display = self.webauthn.display_name_for(&username, &username);
        let mut user = lane_user(
            &username,
            &display,
            if mode == "create" {
                &step_lane
            } else {
                "classical"
            },
        );
        user["id"] = json!(text(step.get("userHandle")));
        let ceremony_options = if let Some(_algs) = &post_login_algs {
            if pl_retrying {
                self.webauthn.creation_options(&rp_id, "", &step_lane, true)
            } else {
                let mut o = self
                    .webauthn
                    .creation_options(&rp_id, "", &step_lane, false);
                o["algorithms"] = json!(self
                    .webauthn
                    .upgrade_algorithm_ids()
                    .iter()
                    .map(|n| num(*n))
                    .collect::<Vec<_>>());
                o
            }
        } else if mode == "create" {
            self.webauthn.creation_options(
                &rp_id,
                "",
                &step_lane,
                classical_only,
            )
        } else {
            self.webauthn.request_options(&rp_id)
        };
        let exclude: Vec<Json> = self
            .credentials
            .keys_of(&username)
            .iter()
            .filter(|k| key_lane(k) == step_lane)
            .map(|k| json!(text(k.get("credentialId"))))
            .collect();
        let challenge = text(step.get("challenge"));
        let facts = json!({
            "mode": mode, "passwordless": passwordless,
            "choices": if choosing { offered.iter().map(choice).collect::<Vec<_>>() } else { Vec::new() },
            "chosen": chosen.as_ref().map(choice).unwrap_or(Json::Null),
            "problem": problem,
            "postQuantumRefused": pq_refusal.as_ref()
                .map(|r| json!({ "why": r["why"] })).unwrap_or(Json::Null),
            "hardwareRefused": hardware_refusal.as_ref()
                .map(|(_, why)| json!({ "why": why })).unwrap_or(Json::Null),
            "postQuantumHelp": if pq_refusal.is_some() { self.post_quantum_help() } else { Json::Null },
            "postQuantumAllowCredentials": if pq_required {
                if list_all { "list-and-refuse" } else { "narrow" } } else { "" },
            "fallback": fallback,
            "rpId": rp_id, "widened": truthy(options.get("rpId")),
            "challenge": challenge,
            "attestation": text(self.webauthn.attestation_conveyance(&rp_id).get("requested")),
            "algorithms": algorithms,
            "postLogin": if post_login { json!({ "required": pl["required"] == json!(true) }) }
                         else { Json::Null },
            "lanes": lanes,
            "lane": if mode == "create" { step_lane.clone() } else { String::new() },
            "userVerification": text(options.get("userVerification")),
            "residentKey": text(options.get("residentKey")),
            "attachment": text(options.get("authenticatorAttachment")),
            "ceremony": {
                "mode": mode, "challenge": challenge, "rpId": rp_id,
                "user": user,
                "allow": allowed.iter().map(|k| json!(text(k.get("credentialId")))).collect::<Vec<_>>(),
                "exclude": exclude,
                "options": ceremony_options,
                "fallback": fallback,
            }
        });
        let pq_code = pq_refusal
            .as_ref()
            .and_then(|r| code_of_text(&text(r.get("code"))));
        (facts, pq_code, hardware_refusal.map(|(c, _)| c))
    }

    /// `mfaWebauthnOptions(req, res, mfaId, key, lane, algorithms)`.
    #[tracing::instrument(level = "debug", skip(self, call))]
    pub fn mfa_webauthn_options(
        &self,
        call: &Call,
        id: &str,
        key: &str,
        lane: &str,
        algorithms: &str,
    ) -> Outcome {
        let mut step = match self.step_problem("webauthn", id) {
            Ok(s) => s,
            Err((code, why)) => {
                return Outcome::Answered(
                    SignIn::step_refused(&why, 400).marked(code),
                )
            }
        };
        if truthy(step.get("upgradeId")) {
            return Outcome::Unported("postLoginUpgradeOptions");
        }
        let post_login = truthy(step.get("postLogin"));
        let pl = step["postLogin"].clone();
        let pl_retry_allowed = post_login
            && text(pl.get("reason")) == "none"
            && text(pl.get("fallback")) == "classical";
        if post_login
            && (!lane.is_empty()
                || (algorithms == "classical" && !pl_retry_allowed))
        {
            return Outcome::Answered(
                SignIn::step_refused(
                    "This step registers a post-quantum passkey only; a \
                     classical one cannot be made here.",
                    400,
                )
                .marked(codes::STS_AUTHN_0420),
            );
        }
        if !lane.is_empty() {
            let allowed = self.webauthn.lane_refusal(lane);
            if !allowed.ok() {
                return Outcome::Answered(
                    SignIn::step_refused(&text(allowed.value.get("why")), 400)
                        .marked(allowed.code.unwrap_or(codes::STS_AUTHN_0351)),
                );
            }
        }
        let username = text(step.get("username"));
        let application = step
            .get("authn")
            .map(|a| text(a.get("application")))
            .unwrap_or_default();
        let retry = algorithms == "classical";
        let mut step_lane = lane.to_string();
        if retry {
            self.webauthn.select(&username, &application);
            let allowed = self.webauthn.classical_retry_refusal("sign-in");
            if !allowed.ok() {
                return Outcome::Answered(
                    SignIn::step_refused(&text(allowed.value.get("why")), 400)
                        .marked(allowed.code.unwrap_or(codes::STS_AUTHN_0420)),
                );
            }
            let current = if step_lane.is_empty() {
                text(step.get("lane"))
            } else {
                step_lane.clone()
            };
            step_lane = self.webauthn.classical_retry_lane(&current);
        }
        let mut client_rule = Json::Null;
        if !retry && !post_login {
            self.webauthn.select(&username, &application);
            let current = if step_lane.is_empty() {
                text(step.get("lane"))
            } else {
                step_lane.clone()
            };
            let decided = self
                .keys
                .offer_for("sign-in", &self.webauthn.enrolment_lane(&current));
            if truthy(decided.get("record")) {
                client_rule = json!({ "narrowed": decided["narrowed"],
                                      "record": decided["record"] });
            }
        }
        let classical_only = retry || client_rule["narrowed"] == json!(true);
        let step_rule = step.get("clientRule").cloned().unwrap_or(Json::Null);
        if truthy(step.get("classicalOnly")) != classical_only
            || step_rule != client_rule
        {
            step["classicalOnly"] = json!(classical_only);
            step["clientRule"] = client_rule;
            self.stores.mfa.set(id, step.clone());
        }
        let (facts, pq_code, hw_code) =
            self.webauthn_facts(call, id, &mut step, key, &step_lane);
        let protocol = step
            .get("authn")
            .map(|a| text(a.get("protocol")))
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "OAuth 2.0 / OIDC".into());
        for (refused, code, summary) in [
            (&facts["postQuantumRefused"], pq_code,
             "the passkey policy requires a post-quantum passkey and they hold none"),
            (&facts["hardwareRefused"], hw_code,
             "phrh was required and no held key can earn it"),
        ] {
            if refused.is_null() {
                continue;
            }
            let code = code.unwrap_or(codes::STS_AUTHN_0356);
            self.facts.audit(&json!({
                "action": "session.refuse", "actor": username,
                "errorCode": code.as_str(), "protocol": protocol,
                "channel": "http", "target": "",
                "summary": format!("a session for {username} was refused \
                    before the passkey step's ceremony: {summary}"),
                "detail": { "application": application, "method": "webauthn",
                            "credential": "webauthn" } }));
            return Outcome::Answered(
                SignIn::step_refused(&text(refused.get("why")), 400).marked(code),
            );
        }
        if facts["choices"].as_array().is_some_and(|l| !l.is_empty()) {
            return Outcome::Answered(
                SignIn::step_refused("Choose one of your passkeys first.", 400)
                    .marked(codes::STS_AUTHN_0329),
            );
        }
        if facts["mode"] == json!("create") {
            step["offered"] = json!(facts["ceremony"]["options"]["algorithms"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|v| num(number(Some(v))))
                .collect::<Vec<_>>());
        }
        step["optionsAt"] = num(self.facts.now_ms().floor());
        self.stores.mfa.set(id, step);
        let mut out = Map::new();
        out.insert("ok".into(), json!(true));
        if let Some(c) = facts["ceremony"].as_object() {
            for (k, v) in c {
                out.insert(k.clone(), v.clone());
            }
        }
        Outcome::Answered(Answer::json(200, Json::Object(out)))
    }

    /// `noteStepCeremony(req, body, step, refusedWith, verdict)`.
    fn note_step_ceremony(
        &self,
        call: &Call,
        mode: &str,
        posted: &Json,
        step: &Json,
        refused: &str,
        verdict: &Json,
    ) {
        let registration = mode == "create";
        let lane = {
            let l = text(step.get("lane"));
            if l.is_empty() {
                "classical".to_string()
            } else {
                l
            }
        };
        let username = text(step.get("username"));
        let keys = self.credentials.keys_of(&username);
        let named = named_id(posted);
        let own = keys.iter().find(|k| {
            if registration {
                text(k.get("credentialId")) == text(verdict.get("credentialId"))
            } else {
                text(k.get("credentialId")) == named
            }
        });
        let offered = if registration {
            match step["offered"].as_array() {
                Some(l) if !l.is_empty() => Json::Array(l.clone()),
                _ => json!(self
                    .webauthn
                    .algorithm_ids(&lane, false)
                    .iter()
                    .map(|n| num(*n))
                    .collect::<Vec<_>>()),
            }
        } else {
            json!(keys
                .iter()
                .map(|k| Credentials::key_algorithm(k)["name"].clone())
                .collect::<Vec<_>>())
        };
        let algorithm = if truthy(verdict.get("algorithm")) {
            verdict["algorithm"].clone()
        } else {
            own.map_or(json!(""), |k| {
                Credentials::key_algorithm(k)["name"].clone()
            })
        };
        self.ceremonies.record(
            &json!({
                "ceremony": if registration { "registration" } else { "assertion" },
                "door": "sign-in-step", "username": username,
                "role": if registration { "" } else if truthy(step.get("passwordless")) {
                    "primary" } else { "mfa" },
                "lane": if registration { lane.clone() }
                        else { own.map_or(String::new(), key_lane) },
                "outcome": if refused.is_empty() { "success" } else { "refused" },
                "errorCode": refused, "offered": offered, "algorithm": algorithm,
                "posted": posted,
                "attestation": if registration {
                    own.map_or(Json::Null, |k| k["attestation"].clone()) } else { Json::Null },
                "narrowed": if registration && truthy(step.get("clientRule")) {
                    text(step["clientRule"].get("record")) } else { String::new() },
                "application": step.get("authn").map(|a| text(a.get("application")))
                    .unwrap_or_default(),
                "issuedAt": num({ let n = number(step.get("optionsAt"));
                                  if n.is_finite() { n } else { 0.0 } }),
                "userAgent": call.request.user_agent }),
            self.facts.now_ms(),
        );
    }

    /// `mfaWebauthnAct(req, res, mfaId, posted)`: the passkey step's
    /// ceremony result, verified, and the step finished.
    #[tracing::instrument(level = "debug", skip(self, call, posted))]
    pub fn mfa_webauthn_act(
        &self,
        call: &Call,
        id: &str,
        posted: &str,
    ) -> Outcome {
        let mut step = match self.step_problem("webauthn", id) {
            Ok(s) => s,
            Err((code, why)) => {
                return Outcome::Answered(
                    SignIn::step_refused(&why, 400).marked(code),
                )
            }
        };
        if truthy(step.get("upgradeId")) {
            return Outcome::Unported("postLoginUpgradeAct");
        }
        let (facts, _, _) = self.webauthn_facts(call, id, &mut step, "", "");
        let mode = text(facts.get("mode"));
        let Ok(credential) = parsed_credential(posted) else {
            return Outcome::Answered(
                SignIn::step_refused(
                    "The browser returned something this server could not read.",
                    400,
                )
                .marked(codes::STS_AUTHN_0021),
            );
        };
        let refuse = |why: &str, code: ErrorCode| {
            Outcome::Answered(SignIn::step_refused(why, 400).marked(code))
        };
        if !truthy(credential.get("error"))
            && !truthy(credential.get("response"))
        {
            return refuse(
                "Your browser did not run the ceremony. This step needs \
                 JavaScript — a passkey is used by the browser and no form can \
                 do it. Allow scripts for this page and try again.",
                codes::STS_AUTHN_0022,
            );
        }
        let username = text(step.get("username"));
        if truthy(credential.get("error")) {
            self.note_step_ceremony(
                call,
                &mode,
                &credential,
                &step,
                codes::STS_AUTHN_0022.as_str(),
                &Json::Null,
            );
            if truthy(step.get("postLogin")) {
                self.post_login_unsupported(
                    &step,
                    &text(credential.get("error")),
                );
                if facts["fallback"]["classical"] != json!(true) {
                    step["factor"] = json!("post-login");
                    step["postLogin"]["failed"] = json!({
                        "error": sts_credentials::webauthn::ceremonies::client_error_name(
                            &credential["error"]),
                        "at": num(self.facts.now_ms().floor()) });
                    self.stores.mfa.set(id, step);
                    return Outcome::Answered(
                        self.step_answer(
                            call,
                            "mfa",
                            "post-login",
                            id,
                            POST_LOGIN_PATH,
                            "mfa",
                        )
                        .marked(codes::STS_AUTHN_0022),
                    );
                }
            }
            return refuse(
                &format!(
                    "{} (WebAuthn reports one error for several situations, \
                     so this does not say which.)",
                    text(credential.get("error"))
                ),
                codes::STS_AUTHN_0022,
            );
        }
        let rp_refusal = self.rp_id_problem(&call.base);
        if !rp_refusal.is_empty() {
            tracing::warn!(
                "authn: a WebAuthn ceremony for \"{}\" was REFUSED. {}",
                username,
                rp_refusal
            );
            self.note_step_ceremony(
                call,
                &mode,
                &credential,
                &step,
                codes::STS_AUTHN_0023.as_str(),
                &Json::Null,
            );
            return refuse(&rp_refusal, codes::STS_AUTHN_0023);
        }
        let expected_origin = self.expected_origin_for(&call.base, &credential);
        let expected_rp_id = self.rp_id_of(&call.base);
        let response = &credential["response"];
        let threw = |code: ErrorCode, why: String| -> Outcome {
            self.note_step_ceremony(
                call,
                &mode,
                &credential,
                &step,
                code.as_str(),
                &Json::Null,
            );
            Outcome::Answered(
                SignIn::step_refused(
                    &format!("The second factor could not be checked: {why}"),
                    400,
                )
                .marked(code),
            )
        };
        if mode == "create" {
            if !self.webauthn.offered() {
                tracing::info!(
                    "authn: a WebAuthn ENROLMENT was refused for \"{}\" — \
                     security keys are switched off in this realm \
                     (webauthn.enabled). An already-enrolled key is unaffected.",
                    username
                );
                self.note_step_ceremony(
                    call,
                    &mode,
                    &credential,
                    &step,
                    codes::STS_AUTHN_0044.as_str(),
                    &Json::Null,
                );
                return refuse(
                    "Passkeys are switched off in this realm \
                     (webauthn.enabled), so a new one cannot be registered \
                     here. A passkey already registered goes on working.",
                    codes::STS_AUTHN_0044,
                );
            }
            let lane = {
                let l = text(step.get("lane"));
                if l.is_empty() {
                    "classical".to_string()
                } else {
                    l
                }
            };
            let registration = match verify_registration(&RegistrationInput {
                attestation_object: text(response.get("attestationObject")),
                client_data_json: text(response.get("clientDataJSON")),
                expected_challenge: step["challenge"].clone(),
                expected_origin: json!(expected_origin),
                expected_rp_id: expected_rp_id.clone(),
                require_user_verification: self
                    .webauthn
                    .require_user_verification(),
                expected_algorithms: Some(held_to_offer(
                    &self.webauthn.algorithm_ids(
                        &lane,
                        truthy(step.get("classicalOnly")),
                    ),
                    &step["offered"],
                )),
            }) {
                Ok(r) => r,
                Err(e) => return threw(codes::STS_AUTHN_0027, e),
            };
            let verdict = registration.answer.clone();
            if verdict["ok"] != json!(true) {
                return self.finish_webauthn(
                    call,
                    id,
                    &mode,
                    &credential,
                    step,
                    Verdict::of(verdict),
                );
            }
            let passwordless = truthy(step.get("passwordless"));
            if passwordless
                && !truthy(step.get("postLogin"))
                && !self.facts.predicate("enrolsKeysOnFirstUse")
            {
                tracing::info!(
                    "authn: product mode, so a primary security key was NOT \
                     enrolled for \"{}\" at the sign-in screen.",
                    username
                );
                return self.finish_webauthn(call, id, &mode, &credential, step,
                    Verdict::coded(codes::STS_AUTHN_0206, json!({ "ok": false,
                        "why": "This service is in product mode, where a passkey \
                            that signs in on its own is added at /portal/keys \
                            after signing in, never at the sign-in screen." })));
            }
            if !self.facts.predicate("autoCreates")
                && !self.credentials.entry_exists(&username)
            {
                tracing::info!(
                    "authn: product mode, so a WebAuthn key was NOT enrolled \
                     for \"{}\" — there is no directory entry for them and \
                     enrolling would create one.",
                    username
                );
                return self.finish_webauthn(call, id, &mode, &credential, step,
                    Verdict::coded(codes::STS_AUTHN_0024, json!({ "ok": false,
                        "why": "This service is in product mode, where a passkey \
                            can only be registered for somebody who already \
                            exists. Create the person first." })));
            }
            let attested = self.keys.assess(&registration);
            if !attested.ok() {
                let why = text(attested.value.get("why"));
                tracing::info!(
                    "authn: the security key \"{}\" presented was NOT \
                     registered: {}",
                    username,
                    why
                );
                let refused = Verdict {
                    code: Some(attested.code.unwrap_or(codes::STS_AUTHN_0241)),
                    value: json!({ "ok": false, "checks": verdict["checks"],
                        "failed": [why], "why": why,
                        "algorithm": verdict["algorithm"] }),
                };
                return self.finish_webauthn(
                    call,
                    id,
                    &mode,
                    &credential,
                    step,
                    refused,
                );
            }
            let flags = &verdict["flags"];
            let attestation = attested.value["attestation"].clone();
            let (provider, source) = self
                .keys
                .key_provider_for(&text(verdict.get("aaguid")), &attestation);
            let or_null = |k: &str| {
                verdict
                    .get(k)
                    .filter(|v| truthy(Some(v)))
                    .cloned()
                    .unwrap_or(Json::Null)
            };
            let mut record = Map::new();
            record
                .insert("credentialId".into(), verdict["credentialId"].clone());
            record
                .insert("publicKeyJwk".into(), verdict["publicKeyJwk"].clone());
            record.insert("signCount".into(), verdict["signCount"].clone());
            record.insert(
                "attachment".into(),
                credential
                    .get("authenticatorAttachment")
                    .filter(|a| truthy(Some(a)))
                    .cloned()
                    .unwrap_or(Json::Null),
            );
            record.insert("discoverable".into(), discoverable_of(&credential));
            record.insert(
                "minPinLength".into(),
                reported_min_pin_length(&verdict),
            );
            if truthy(step.get("userHandle")) {
                record.insert("userHandle".into(), step["userHandle"].clone());
            }
            record.insert("lane".into(), json!(lane));
            record.insert(
                "userVerified".into(),
                json!(flags["uv"] == json!(true)),
            );
            record.insert("aaguid".into(), or_null("aaguid"));
            record.insert("algorithm".into(), or_null("algorithm"));
            record.insert("coseAlg".into(), or_null("coseAlg"));
            record.insert(
                "backupEligible".into(),
                json!(flags["be"] == json!(true)),
            );
            record.insert(
                "backupState".into(),
                json!(flags["bs"] == json!(true)),
            );
            record.insert("transports".into(), transports_of(&credential));
            record.insert("attestation".into(), attestation);
            record.insert("provider".into(), provider);
            record.insert("providerSource".into(), source);
            let record = Json::Object(record);
            let stored = self.keys.add_key_claimed(&username, &record);
            let verdict = if !stored.ok() {
                let errors: Vec<String> = stored.value["errors"]
                    .as_array()
                    .map(|l| l.iter().map(|e| text(Some(e))).collect())
                    .unwrap_or_default();
                tracing::info!(
                    "authn: the security key \"{}\" just registered was NOT \
                     stored: {}",
                    username,
                    errors.join(" ")
                );
                Verdict {
                    code: Some(stored.code.unwrap_or(codes::STS_AUTHN_0068)),
                    value: json!({ "ok": false, "checks": verdict["checks"],
                        "failed": [errors.join(" ")], "why": errors.join(" "),
                        "algorithm": verdict["algorithm"] }),
                }
            } else {
                self.facts.credential_changed(&json!({
                    "username": username,
                    "credentialType": key_credential_type(&record),
                    "fido2Aaguid": sts_credentials::evidence::aaguid_string(
                        &text(record.get("aaguid"))),
                    "friendlyName": "", "changeType": "create",
                    "initiatingEntity": "user", "via": "sign-in",
                    "reasonAdmin": format!("{username} registered a security \
                        key while signing in."),
                    "reasonUser": "You registered a security key." }));
                Verdict::of(verdict)
            };
            return self.finish_webauthn(
                call,
                id,
                &mode,
                &credential,
                step,
                verdict,
            );
        }
        // An assertion.
        let known = match self.key_for_assertion(
            &username,
            if truthy(step.get("passwordless")) {
                "primary"
            } else {
                "mfa"
            },
            &named_id(&credential),
        ) {
            Ok(k) => k,
            Err((code, why)) => return threw(code, why),
        };
        let phrh = step
            .get("authn")
            .map(|a| text(a.get("phishingClass")))
            .unwrap_or_default()
            == "phrh";
        if phrh && !sts_credentials::phishing::PhishingResistance::stored_key_earns_hardware(&known) {
            return threw(
                codes::STS_AUTHN_0459,
                "This sign-in asks for a hardware-protected phishing-resistant \
                 passkey, and the passkey that answered cannot earn it."
                    .into(),
            );
        }
        let handled = self.keys.user_handle_refusal(
            &username,
            &known,
            &text(response.get("userHandle")),
            false,
        );
        if !handled.ok() {
            return threw(
                handled.code.unwrap_or(codes::STS_AUTHN_0303),
                text(handled.value.get("why")),
            );
        }
        let verdict = match verify_assertion(&AssertionInput {
            authenticator_data: text(response.get("authenticatorData")),
            client_data_json: text(response.get("clientDataJSON")),
            signature: text(response.get("signature")),
            expected_challenge: step["challenge"].clone(),
            expected_origin: json!(expected_origin),
            expected_rp_id,
            require_user_verification: self
                .webauthn
                .require_user_verification(),
            previous_sign_count: Some(number(known.get("signCount")))
                .filter(|n| n.is_finite()),
            public_key_jwk: known["publicKeyJwk"].clone(),
            allow_insecure: self.webauthn.insecure_algorithms_allowed(),
        }) {
            Ok(v) => v,
            Err(e) => return threw(codes::STS_AUTHN_0027, e),
        };
        if cloned_key_verdict(&verdict) {
            self.keys.note_key_cloned(
                &username,
                &text(known.get("credentialId")),
                &format!(
                    "signature counter {}, last recorded {}",
                    text(verdict.get("signCount")),
                    text(known.get("signCount"))
                ),
            );
        }
        if verdict["ok"] != json!(true) {
            return self.finish_webauthn(
                call,
                id,
                &mode,
                &credential,
                step,
                Verdict::of(verdict),
            );
        }
        let mut verdict = verdict;
        verdict["answeredBy"] = json!({ "id": known["credentialId"],
            "aaguid": known.get("aaguid").filter(|a| truthy(Some(a))).cloned().unwrap_or(Json::Null),
            "lane": key_lane(&known),
            "attestationTrusted": known["attestation"]["trusted"] == json!(true) });
        let spent = self.keys.spend_assertion(&json!({
            "username": username, "credentialId": known["credentialId"],
            "signCount": verdict["signCount"], "flags": verdict["flags"],
            "challenge": step["challenge"], "ttlMs": num(self.mfa_step_ttl_ms()) }));
        let verdict = if !spent.ok() {
            Verdict {
                code: Some(spent.code.unwrap_or(codes::STS_AUTHN_0182)),
                value: json!({ "ok": false, "checks": verdict["checks"],
                               "failed": [spent.value.get("detail").cloned().unwrap_or(Json::Null)] }),
            }
        } else {
            let held = self
                .credentials
                .keys_of(&username)
                .into_iter()
                .find(|k| {
                    text(k.get("credentialId"))
                        == text(known.get("credentialId"))
                })
                .unwrap_or(Json::Null);
            match self.attestation_at_sign_in(
                &username,
                &held,
                &step
                    .get("authn")
                    .map(|a| text(a.get("application")))
                    .unwrap_or_default(),
            ) {
                Some((code, why)) => Verdict {
                    code: Some(code),
                    value: json!({ "ok": false, "checks": verdict["checks"], "failed": [why] }),
                },
                None => {
                    if spent.value.get("recorded") == Some(&json!(false)) {
                        tracing::warn!(
                            "{}authn: the signature counter for \"{}\" could not \
                             be recorded on the entry. The sign-in stands; the \
                             counter is advanced in the store.",
                            sts_core::log::tag(codes::STS_AUTHN_0038),
                            username
                        );
                    }
                    Verdict::of(verdict)
                }
            }
        };
        self.finish_webauthn(call, id, &mode, &credential, step, verdict)
    }

    /// `finishWebauthn(req, res, base, body, step, verdict)`.
    fn finish_webauthn(
        &self,
        call: &Call,
        id: &str,
        mode: &str,
        posted: &Json,
        step: Json,
        verdict: Verdict,
    ) -> Outcome {
        let v = &verdict.value;
        let refused_code = if v["ok"] == json!(true) {
            None
        } else {
            Some(verdict.code.unwrap_or_else(|| failure_code_for(v)))
        };
        self.note_step_ceremony(
            call,
            mode,
            posted,
            &step,
            refused_code.map_or("", ErrorCode::as_str),
            v,
        );
        let username = text(step.get("username"));
        if let Some(code) = refused_code {
            let failed: Vec<String> = match v["failed"].as_array() {
                Some(l) if !l.is_empty() => {
                    l.iter().map(|f| text(Some(f))).collect()
                }
                _ => vec![if truthy(v.get("why")) {
                    text(v.get("why"))
                } else {
                    "refused".into()
                }],
            };
            self.note_refused(
                &step,
                &username,
                "webauthn",
                code,
                "assertion-did-not-verify",
            );
            tracing::info!(
                "authn: the security key for \"{}\" was refused: {}",
                username,
                failed.join("; ")
            );
            return Outcome::Answered(
                SignIn::step_refused(
                    &format!(
                        "The second factor did not verify — {}.",
                        failed.join("; ")
                    ),
                    400,
                )
                .marked(code),
            );
        }
        self.stores.mfa.delete(id);
        let passwordless = truthy(step.get("passwordless"));
        let step_lane = {
            let l = text(step.get("lane"));
            if l.is_empty() {
                "classical".to_string()
            } else {
                l
            }
        };
        if truthy(step.get("postLogin")) {
            self.post_login.note_done(&username, &step["postLogin"]);
            self.facts.audit(&json!({
                "action": "authn.post-login.done", "outcome": "success",
                "actor": username, "target": username, "channel": "http",
                "protocol": step.get("authn").and_then(|a| a.get("protocol")).cloned()
                    .unwrap_or(Json::Null),
                "summary": format!("{username} registered a post-quantum \
                    passkey after signing in"),
                "detail": { "activity": text(step["postLogin"].get("activity")),
                    "algorithm": text(v.get("algorithm")),
                    "lane": step_lane,
                    "profile": text(step["postLogin"].get("profile")) } }));
            return Outcome::Answered(self.finish_post_login(call, step));
        }
        if truthy(step.get("thenEnrol")) && !passwordless {
            // `enrolAfterProof()` (#475), as the other steps answer it.
            return Outcome::Unported("thenEnrol");
        }
        let registered = mode == "create";
        let answered = if v["answeredBy"].is_object() {
            v["answeredBy"].clone()
        } else {
            json!({ "id": v["credentialId"], "aaguid": v["aaguid"] })
        };
        let flags = &v["flags"];
        let mut credential = Map::new();
        credential.insert("kind".into(), json!("webauthn"));
        credential.insert("id".into(), json!(text(answered.get("id"))));
        credential.insert(
            "aaguid".into(),
            json!(if truthy(answered.get("aaguid")) {
                sts_credentials::evidence::aaguid_string(&text(
                    answered.get("aaguid"),
                ))
            } else {
                String::new()
            }),
        );
        if let Some(b @ Json::Bool(_)) = flags.get("be") {
            credential.insert("backupEligible".into(), b.clone());
        }
        if let Some(b @ Json::Bool(_)) = flags.get("bs") {
            credential.insert("backupState".into(), b.clone());
        }
        credential.insert("algorithm".into(), json!(text(v.get("algorithm"))));
        let cose = number(v.get("coseAlg"));
        if cose.is_finite() && cose != 0.0 {
            credential.insert("coseAlg".into(), num(cose));
        }
        let answered_lane = text(answered.get("lane"));
        credential.insert(
            "lane".into(),
            json!(if answered_lane.is_empty() {
                step_lane.clone()
            } else {
                answered_lane
            }),
        );
        credential.insert(
            "ceremony".into(),
            json!(if registered {
                "registration"
            } else {
                "assertion"
            }),
        );
        credential.insert(
            "attestationTrusted".into(),
            json!(!registered && answered["attestationTrusted"] == json!(true)),
        );
        let evidence = if passwordless {
            Evidence::passkey_alone(Json::Object(credential))
        } else {
            Evidence::key_after(&step, Json::Object(credential))
        };
        let application = step
            .get("authn")
            .map(|a| text(a.get("application")))
            .unwrap_or_default();
        let mut said = Map::new();
        said.insert("postLoginHold".into(), json!(true));
        if let Some(risk) = step.get("risk").filter(|r| !r.is_null()) {
            said.insert("risk".into(), risk.clone());
        }
        said.insert("application".into(), json!(application));
        let protocol = step
            .get("authn")
            .map(|a| text(a.get("protocol")))
            .unwrap_or_default();
        let mut response = Response::default();
        let started = evidence.start_session(
            &self.sessions,
            &mut response,
            &username,
            &protocol,
            &mut said,
            Some(&call.request),
        );
        let mut record = step.get("authn").cloned().unwrap_or(Json::Null);
        tracing::info!(
            "authn: \"{}\"{}",
            username,
            if passwordless {
                " signed in with a security key alone."
            } else {
                " completed the second factor."
            }
        );
        Outcome::Answered(self.after_session(
            call,
            &mut record,
            &username,
            started,
            &said,
            response,
            true,
        ))
    }

    // -------------------------------------------------------------------
    // The set-up step.
    // -------------------------------------------------------------------

    /// `mfaSetupFacts(base, step)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn mfa_setup_facts(&self, call: &Call, step: &Json) -> Json {
        let allowed: Vec<String> = step
            .get("mfaAllowed")
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|v| text(Some(v))).collect())
            .unwrap_or_default();
        let (totp, webauthn) = self.enrolment_offered_for(&allowed);
        let mut out = json!({ "state": "choose",
            "offered": { "totp": totp, "webauthn": webauthn },
            "optional": truthy(step.get("optional")),
            "proved": truthy(step.get("proved")),
            "recovery": truthy(step.get("recovery")), "totp": null });
        let username = text(step.get("username"));
        let held = if text(step.get("factor")) == "enrol-totp" {
            self.credentials.pending_totp_for(&username)
        } else {
            None
        };
        if let Some(held) = held {
            let t = self.credentials.totp();
            let algorithm = text(held.get("algorithm"));
            out["state"] = json!("totp");
            out["totp"] = json!({
                "uri": sts_credentials::totp::Totp::otpauth_uri(
                    &t.issuer_for(&call.base), &username,
                    &text(held.get("secret")), &algorithm,
                    number(held.get("digits")), number(held.get("period"))),
                "secret": sts_credentials::totp::Totp::grouped(&text(held.get("secret"))),
                "algorithm": format!("HMAC-{}", algorithm.replacen("SHA", "SHA-", 1)),
                "digits": held["digits"], "period": held["period"] });
        }
        out
    }

    /// `mfaSetupAct(req, res, setupId, action, body)`: `totp`,
    /// `confirm`, `webauthn` or `skip`.
    #[tracing::instrument(level = "debug", skip(self, call, code))]
    pub fn mfa_setup_act(
        &self,
        call: &Call,
        id: &str,
        action: &str,
        code: &str,
    ) -> Outcome {
        let mut step = match self.step_problem("setup", id) {
            Ok(s) => s,
            Err((c, why)) => {
                return Outcome::Answered(
                    SignIn::step_refused(&why, 400).marked(c),
                )
            }
        };
        let refuse = |why: &str, c: ErrorCode| {
            Outcome::Answered(SignIn::step_refused(why, 400).marked(c))
        };
        let username = text(step.get("username"));
        let allowed: Vec<String> = step
            .get("mfaAllowed")
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|v| text(Some(v))).collect())
            .unwrap_or_default();
        let (totp_offered, key_offered) = self.enrolment_offered_for(&allowed);
        if !truthy(step.get("proved"))
            && truthy(self.mechanisms_for(&username).get("mfaRequired"))
        {
            self.stores.mfa.delete(id);
            return refuse(
                "A second factor is already set up for this account. Start the \
                 request again from the application that sent you here and \
                 sign in with it.",
                codes::STS_AUTHN_0175,
            );
        }
        let protocol = step
            .get("authn")
            .and_then(|a| a.get("protocol"))
            .cloned()
            .unwrap_or(Json::Null);
        let required_by = text(step.get("requiredBy"));
        let application = step
            .get("authn")
            .map(|a| text(a.get("application")))
            .unwrap_or_default();
        match action {
            "skip" => {
                if !truthy(step.get("optional")) {
                    return refuse(
                        "A second factor is required for this account; it \
                         cannot be ignored.",
                        codes::STS_AUTHN_0270,
                    );
                }
                self.stores.mfa.delete(id);
                self.facts.audit(&json!({
                    "action": "authn.mfa.enrolment.declined", "outcome": "success",
                    "actor": username, "target": username, "channel": "http",
                    "protocol": protocol,
                    "summary": format!("{username} ignored the offer of a second \
                        factor and signed in with a password"),
                    "detail": { "requiredBy": required_by } }));
                let mut said = Map::new();
                said.insert("postLoginHold".into(), json!(true));
                said.insert("gated".into(), json!(true));
                said.insert("application".into(), json!(application));
                if let Some(risk) = step.get("risk").filter(|r| !r.is_null()) {
                    said.insert("risk".into(), risk.clone());
                }
                if let Some(d) = step.get("riskDecision") {
                    said.insert("riskDecision".into(), d.clone());
                }
                let mut response = Response::default();
                let started = Evidence::password().start_session(
                    &self.sessions,
                    &mut response,
                    &username,
                    &text(Some(&protocol)),
                    &mut said,
                    Some(&call.request),
                );
                let mut record = step["authn"].take();
                Outcome::Answered(self.after_session(
                    call,
                    &mut record,
                    &username,
                    started,
                    &said,
                    response,
                    true,
                ))
            }
            "webauthn" => {
                if !key_offered {
                    return refuse(
                        "Security keys cannot be set up in this realm.",
                        codes::STS_AUTHN_0175,
                    );
                }
                step["factor"] = json!("webauthn");
                step["atSignIn"] = json!(true);
                self.stores.mfa.set(id, step);
                Outcome::Answered(self.step_answer(
                    call,
                    "mfa",
                    "webauthn",
                    id,
                    WEBAUTHN_PATH,
                    "mfa",
                ))
            }
            "totp" => {
                if !totp_offered {
                    return refuse(
                        "Authenticator apps cannot be set up in this realm.",
                        codes::STS_AUTHN_0175,
                    );
                }
                let begun = self
                    .credentials
                    .begin_totp_enrolment(&username, &call.base);
                if !begun.ok()
                    || self.credentials.pending_totp_for(&username).is_none()
                {
                    let said = begun.value["errors"]
                        .as_array()
                        .and_then(|l| l.first())
                        .map(|e| text(Some(e)))
                        .filter(|e| !e.is_empty())
                        .unwrap_or_else(|| {
                            "The authenticator app could not be set up.".into()
                        });
                    return refuse(
                        &said,
                        begun.code.unwrap_or(codes::STS_AUTHN_0176),
                    );
                }
                step["factor"] = json!("enrol-totp");
                self.stores.mfa.set(id, step);
                self.facts.audit(&json!({
                    "action": "authn.mfa.enrolment.started", "outcome": "success",
                    "actor": username, "target": username, "channel": "http",
                    "protocol": protocol,
                    "summary": format!("an authenticator app secret was shown to \
                        {username} at sign-in, because a second factor is required"),
                    "detail": { "requiredBy": required_by } }));
                Outcome::Answered(self.step_answer(
                    call,
                    "mfa",
                    "enrol-totp",
                    id,
                    MFA_SETUP_PATH,
                    "mfa",
                ))
            }
            _ => {
                if text(step.get("factor")) != "enrol-totp" {
                    return refuse(
                        "Choose a second factor to set up first.",
                        codes::STS_AUTHN_0174,
                    );
                }
                if let Some(refused) = self.rate_limited(
                    "mfa-code",
                    call,
                    &username,
                    codes::STS_AUTHN_0040,
                    "one-time code",
                ) {
                    return Outcome::Answered(refused);
                }
                let confirmed = match self
                    .credentials
                    .confirm_totp_enrolment(&username, &json!(code))
                {
                    Ok(v) => v,
                    Err(e) => {
                        // Node's would throw out of the handler; the code
                        // is the confirmation's own.
                        tracing::error!(
                            "{}authn: confirming an authenticator app for \
                             \"{}\" threw: {}",
                            sts_core::log::tag(codes::STS_AUTHN_0177),
                            username,
                            e
                        );
                        Verdict::coded(
                            codes::STS_AUTHN_0177,
                            json!({ "ok": false, "errors": [] }),
                        )
                    }
                };
                if !confirmed.ok() {
                    let c = confirmed.code.unwrap_or(codes::STS_AUTHN_0177);
                    if self.credentials.pending_totp_for(&username).is_none() {
                        step["factor"] = json!("enrol");
                        self.stores.mfa.set(id, step);
                        return refuse(
                            "That set-up expired before it was confirmed. Start \
                             it again.",
                            c,
                        );
                    }
                    let said = confirmed.value["errors"]
                        .as_array()
                        .and_then(|l| l.first())
                        .map(|e| text(Some(e)))
                        .unwrap_or_else(|| "That code is not right.".into());
                    return refuse(&said, c);
                }
                self.limits.succeeded(
                    "mfa-code",
                    &call.request.address,
                    &username,
                    false,
                );
                self.stores.mfa.delete(id);
                self.facts.audit(&json!({
                    "action": "authn.mfa.enrolled", "outcome": "success",
                    "actor": username, "target": username, "channel": "http",
                    "protocol": protocol,
                    "summary": format!("{username} set up an authenticator app \
                        at sign-in, because a second factor is required"),
                    "detail": { "requiredBy": required_by } }));
                tracing::info!(
                    "authn: \"{}\" enrolled an authenticator app at sign-in; \
                     signing them in with two factors.",
                    username
                );
                self.facts.credential_changed(&json!({
                    "username": username, "credentialType": "app",
                    "changeType": "create", "initiatingEntity": "user",
                    "via": "sign-in",
                    "reasonAdmin": format!("{username} set up an authenticator \
                        app at sign-in."),
                    "reasonUser": "You set up an authenticator app." }));
                let mut amr: Vec<String> = SignIn::first_amr_of(&step)
                    .into_iter()
                    .filter(|a| a != "otp")
                    .collect();
                amr.push("otp".into());
                let evidence = Evidence {
                    amr,
                    acr: "mfa".into(),
                    credential: json!({ "kind": "totp" }),
                };
                let mut said = Map::new();
                said.insert("postLoginHold".into(), json!(true));
                if let Some(risk) = step.get("risk").filter(|r| !r.is_null()) {
                    said.insert("risk".into(), risk.clone());
                }
                said.insert("application".into(), json!(application));
                let mut response = Response::default();
                let started = evidence.start_session(
                    &self.sessions,
                    &mut response,
                    &username,
                    &text(Some(&protocol)),
                    &mut said,
                    Some(&call.request),
                );
                let mut record = step["authn"].take();
                Outcome::Answered(self.after_session(
                    call,
                    &mut record,
                    &username,
                    started,
                    &said,
                    response,
                    true,
                ))
            }
        }
    }

    // -------------------------------------------------------------------
    // The post-login step (#1096).
    // -------------------------------------------------------------------

    /// The post-login page's facts (`mfaView()`'s `post-login` branch).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn post_login_view(&self, step: &Json) -> Json {
        let due = if step["postLogin"].is_object() {
            step["postLogin"].clone()
        } else {
            json!({})
        };
        let required = due["required"] == json!(true);
        let method = text(due.get("method"));
        let deadline = number(due.get("deadline"));
        let snooze = number(due.get("snoozeDays"));
        json!({
            "activity": text(due.get("activity")),
            "reason": text(due.get("reason")), "required": required,
            "canSkip": !required, "method": method,
            "failed": if truthy(due.get("failed")) {
                let e = text(due["failed"].get("error"));
                if e.is_empty() { "Error".to_string() } else { e } } else { String::new() },
            "separate": method == "alongside" && self.post_login_lane("alongside") == "classical",
            "snoozeDays": num(if snooze.is_finite() { snooze } else { 0.0 }),
            "deadline": if deadline.is_finite() && deadline > 0.0 {
                chrono::DateTime::<chrono::Utc>::from_timestamp_millis(deadline as i64)
                    .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
                    .unwrap_or_default() } else { String::new() } })
    }

    /// `postLogin.lane(method)`.
    fn post_login_lane(&self, method: &str) -> String {
        if method != "upgrade" && self.webauthn.alongside_classical() {
            "pqc".into()
        } else {
            "classical".into()
        }
    }

    /// `postLogin.canRegister(method)`. An upgrade's own refusal
    /// (`upgradeRefusal()`) is the upgrade's slice's; its conditions are
    /// the others' here.
    fn post_login_can_register(&self) -> bool {
        self.webauthn.offered()
            && self.webauthn.enrolment_allowed().ok()
            && self.webauthn.offers_post_quantum(None)
            && !self.webauthn.upgrade_algorithms().is_empty()
            && (!self.webauthn.alongside_classical()
                || self.webauthn.lane_refusal("pqc").ok())
    }

    /// `postLoginUnsupported(req, step, error)` (#1105): the platform that
    /// could not make the passkey, on the audit log.
    fn post_login_unsupported(&self, step: &Json, error: &str) {
        let username = text(step.get("username"));
        self.facts.audit(&json!({
            "action": "authn.post-login.unsupported", "outcome": "failure",
            "actor": username, "target": username, "channel": "http",
            "protocol": "WebAuthn",
            "summary": format!("{username}'s device did not make the \
                post-quantum passkey a post-login activity asked for"),
            "detail": { "activity": text(step["postLogin"].get("activity")),
                "clientError": sts_credentials::webauthn::ceremonies::client_error_name(
                    &json!(error)) } }));
    }

    /// `postLoginStep(res, record, username, said)`: the step minted on
    /// the pending sign-in the door held; `None` where nothing is due.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn post_login_step(
        &self,
        call: &Call,
        record: &Json,
        username: &str,
        said: &Map<String, Json>,
    ) -> Option<Answer> {
        let hold = said.get("postLogin").cloned().unwrap_or(json!({}));
        let due = hold.get("due").filter(|d| truthy(Some(d)))?.clone();
        let row = self.post_login.note_asked(username, &due);
        let grace = number(due.get("graceDays"));
        let deadline = if due["enforceable"] == json!(true) && grace > 0.0 {
            number(row.get("invitedAt")) + grace * 24.0 * 60.0 * 60.0 * 1000.0
        } else {
            0.0
        };
        let or = |k: &str, d: f64| {
            let n = number(due.get(k));
            if n.is_finite() && n != 0.0 {
                n
            } else {
                d
            }
        };
        let step_id = self.facts.random_id(24);
        let fallback = {
            let f = text(due.get("fallback"));
            if f.is_empty() {
                "none".to_string()
            } else {
                f
            }
        };
        let step = json!({
            "authn": record, "username": username,
            "challenge": self.facts.random_id(32),
            "factor": "post-login", "alternate": "", "backup": false,
            "passwordless": false, "proved": true,
            "postLogin": {
                "activity": text(due.get("activity")),
                "reason": text(due.get("reason")),
                "required": due["required"] == json!(true),
                "method": text(due.get("method")),
                "fallback": fallback,
                "snoozeDays": num(or("snoozeDays", 1.0)),
                "graceDays": num(or("graceDays", 0.0)),
                "deadline": num(if deadline.is_finite() { deadline } else { 0.0 }),
                "profile": text(due.get("profile")),
                "askedBy": text(due.get("askedBy")) },
            "held": {
                "amr": hold.get("amr").filter(|a| a.is_array()).cloned().unwrap_or(json!([])),
                "acr": text(hold.get("acr")), "via": text(hold.get("via")),
                "application": text(said.get("application")),
                "credential": said.get("credential").cloned().unwrap_or(Json::Null),
                "gated": said.get("gated") == Some(&json!(true)),
                "method": text(said.get("method")) },
            "risk": said.get("risk").cloned().unwrap_or(Json::Null),
            "riskDecision": said.get("riskDecision").cloned().unwrap_or(Json::Null),
            "expires": num(self.facts.now_ms() + self.mfa_step_ttl_ms()) });
        self.stores.mfa.set(&step_id, step);
        let required = due["required"] == json!(true);
        self.facts.audit(&json!({
            "action": "authn.post-login.asked", "outcome": "success",
            "actor": username, "target": username, "channel": "http",
            "protocol": record.get("protocol").cloned().unwrap_or(Json::Null),
            "summary": format!("{username} was asked, after signing in, to \
                register a post-quantum passkey{}",
                if required { "; it is required" } else { "" }),
            "detail": { "activity": text(due.get("activity")),
                "reason": text(due.get("reason")), "required": required,
                "profile": text(due.get("profile")),
                "askedBy": text(due.get("askedBy")),
                "application": text(record.get("application")) } }));
        tracing::info!(
            "authn: \"{}\" signed in and is asked for a post-login activity \
             ({}{}, asked by {}) before the session starts.",
            username,
            text(due.get("activity")),
            if required { ", required" } else { "" },
            {
                let a = text(due.get("askedBy"));
                if a.is_empty() {
                    "policy".to_string()
                } else {
                    a
                }
            }
        );
        Some(self.step_answer(
            call,
            "mfa",
            "post-login",
            &step_id,
            POST_LOGIN_PATH,
            "mfa",
        ))
    }

    /// `finishPostLogin(req, res, base, step)`: the session the step held,
    /// started as the door would have started it.
    fn finish_post_login(&self, call: &Call, step: Json) -> Answer {
        let held = if step["held"].is_object() {
            step["held"].clone()
        } else {
            json!({})
        };
        let username = text(step.get("username"));
        let mut said = Map::new();
        said.insert("postLoginDone".into(), json!(true));
        said.insert("gated".into(), json!(held["gated"] == json!(true)));
        said.insert("application".into(), json!(text(held.get("application"))));
        said.insert(
            "credential".into(),
            if truthy(held.get("credential")) {
                held["credential"].clone()
            } else {
                json!({ "kind": "password" })
            },
        );
        if let Some(r) = step.get("risk") {
            said.insert("risk".into(), r.clone());
        }
        if let Some(r) = step.get("riskDecision") {
            said.insert("riskDecision".into(), r.clone());
        }
        if truthy(held.get("method")) {
            said.insert("method".into(), json!(text(held.get("method"))));
        }
        let amr: Vec<String> = held["amr"]
            .as_array()
            .map(|l| l.iter().map(|v| text(Some(v))).collect())
            .unwrap_or_default();
        let acr = {
            let a = text(held.get("acr"));
            if a.is_empty() {
                "1".to_string()
            } else {
                a
            }
        };
        let via = {
            let v = text(held.get("via"));
            if v.is_empty() {
                step.get("authn")
                    .map(|a| text(a.get("protocol")))
                    .unwrap_or_default()
            } else {
                v
            }
        };
        let mut response = Response::default();
        let started = self.sessions.start_session(
            &mut response,
            &username,
            &amr,
            &acr,
            &via,
            &mut said,
            Some(&call.request),
        );
        let mut record = step.get("authn").cloned().unwrap_or(Json::Null);
        self.after_session(
            call,
            &mut record,
            &username,
            started,
            &said,
            response,
            true,
        )
    }

    /// `postLoginAct(req, res, stepId, action)`: `register` or `skip`.
    #[tracing::instrument(level = "debug", skip(self, call))]
    pub fn post_login_act(
        &self,
        call: &Call,
        id: &str,
        action: &str,
    ) -> Outcome {
        let mut step = match self.step_problem("post-login", id) {
            Ok(s) => s,
            Err((code, why)) => {
                return Outcome::Answered(
                    SignIn::step_refused(&why, 400).marked(code),
                )
            }
        };
        let due = step["postLogin"].clone();
        let username = text(step.get("username"));
        self.webauthn
            .select(&username, &text(step["held"].get("application")));
        if action == "skip" {
            let skipped = if due["required"] == json!(true) {
                json!({ "ok": false })
            } else {
                self.post_login.note_skipped(&username, &due)
            };
            if skipped["ok"] != json!(true) {
                return Outcome::Answered(
                    SignIn::step_refused(
                        "The time allowed for this has passed, so it cannot be \
                         skipped any more. Register the passkey to finish \
                         signing in.",
                        400,
                    )
                    .marked(codes::STS_AUTHN_0474),
                );
            }
            self.stores.mfa.delete(id);
            let until = number(skipped.get("snoozedUntil"));
            self.facts.audit(&json!({
                "action": "authn.post-login.skipped", "outcome": "success",
                "actor": username, "target": username, "channel": "http",
                "protocol": step.get("authn").and_then(|a| a.get("protocol")).cloned()
                    .unwrap_or(Json::Null),
                "summary": format!("{username} put off registering a \
                    post-quantum passkey for {} day(s)", text(due.get("snoozeDays"))),
                "detail": { "activity": text(due.get("activity")),
                    "snoozedUntil": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                        if until.is_finite() { until as i64 } else { 0 })
                        .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
                        .unwrap_or_default(),
                    "profile": text(due.get("profile")),
                    "askedBy": text(due.get("askedBy")) } }));
            return Outcome::Answered(self.finish_post_login(call, step));
        }
        let method = text(due.get("method"));
        if method == "upgrade" {
            // #1100's upgrade (`beginKeyUpgrade()`) is a later slice's.
            return Outcome::Unported("beginKeyUpgrade");
        }
        if !self.post_login_can_register() {
            self.stores.mfa.delete(id);
            tracing::info!(
                "{}authn: the post-login passkey of \"{}\" cannot be \
                 registered here any more (the realm makes no ML-DSA \
                 passkey); the held session is started without it.",
                sts_core::log::tag(codes::STS_AUTHN_0475),
                username
            );
            return Outcome::Answered(
                self.finish_post_login(call, step)
                    .marked(codes::STS_AUTHN_0475),
            );
        }
        step["factor"] = json!("webauthn");
        step["atSignIn"] = json!(true);
        step["passwordless"] = json!(false);
        step["lane"] = json!(self.post_login_lane(&method));
        step["userHandle"] = json!("");
        step["classicalOnly"] = json!(false);
        self.stores.mfa.set(id, step);
        Outcome::Answered(self.step_answer(
            call,
            "mfa",
            "webauthn",
            id,
            WEBAUTHN_PATH,
            "mfa",
        ))
    }

    /// The screen's address for a refusal answered from a step.
    #[allow(dead_code)]
    fn screen_location(&self, call: &Call, id: &str) -> String {
        self.location_of(
            call,
            &format!(
                "{}{}?authn={}",
                call.prefix,
                LOGIN_PATH,
                encode_component(id)
            ),
        )
    }
}
