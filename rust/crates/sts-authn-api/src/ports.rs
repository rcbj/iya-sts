// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the sign-in surface reaches beyond the session core
//! (`sts-authn`) and the credentials (`sts-credentials`), each a trait
//! method — Node's `AuthnDeps` narrowed to what the screen's views and
//! acts read.
//!
//! WHAT REPLACED WHAT. `authn/authn.ts` reaches `config`, `mode`, the
//! authentication and WebAuthn policies, the issuance gate, the
//! application register's client display, the locale policy, the audit
//! log, the identity register's refusal row, `common/browser_devices.ts`
//! and `common/websecurity.ts` through its deps and by `require()`. Here
//! the ones that are not the session or the credentials are this one
//! trait, built by the composition root ([`crate::wiring`]) over what the
//! runtime holds; a test answers it from a table.
//!
//! THE ACCOUNT SETS (#561) are the session core's (`sts-authn`'s
//! `sessions::accounts`), reached on `Sessions` directly.

use serde_json::Value as Json;
use sts_core::errors::ErrorCode;

/// The questions the screen asks that are neither the session's nor a
/// credential's.
pub trait SignInFacts: Send + Sync {
    /// `config.value(key)`, in the ambient realm.
    fn setting(&self, key: &str) -> Json;
    /// A `common/mode.js` predicate, by its name there
    /// (`verifiesCredentials`, `hidesStepIds`, `bindsSignInSteps`,
    /// `enrolsKeysOnFirstUse`).
    fn predicate(&self, name: &str) -> bool;
    /// `Date.now()`.
    fn now_ms(&self) -> f64;
    /// `helpers.randomId(bytes)`: base64url of that many random bytes.
    fn random_id(&self, bytes: usize) -> String;
    /// `authnPolicy.allows(mechanism, role)`.
    fn authn_allows(&self, mechanism: &str, role: &str) -> bool;
    /// `authnPolicy.active(mechanism, role)`: allowed, and able to work
    /// (an emailed factor needs mail).
    fn authn_active(&self, mechanism: &str, role: &str) -> bool;
    /// `webauthnPolicy.settings()`: `{ enabled, mfaAllowed,
    /// primaryAllowed }`.
    fn key_policy(&self) -> Json;
    /// `webauthnPolicy.useAllowed(use)`: `Ok` or the sentence and its code.
    fn key_use_allowed(&self, key_use: &str)
        -> Result<(), (String, ErrorCode)>;
    /// `gate.check({ application, kind: SESSION, subject, … })`:
    /// `{ allowed, why, retiring }`.
    fn gate_session(
        &self,
        application: &str,
        username: &str,
        authenticated: bool,
    ) -> Json;
    /// `mfaAllowedFor(application, username)`: the second factors an
    /// application narrows a sign-in to (#475); empty for every one.
    fn mfa_allowed_for(&self, application: &str, username: &str)
        -> Vec<String>;
    /// `clientDisplay(application)`: `{ name, logo, logoOrigin, policy,
    /// tos }`, or null.
    fn client_display(&self, application: &str) -> Json;
    /// `preferredLanguageOf(username)`: `{ value, populated }`, or none.
    fn preferred_language_of(&self, username: &str) -> Option<Json>;
    /// `browserDevices().enabled()`: whether "remember this browser" is
    /// offered (#265).
    fn remembers_browsers(&self) -> bool;
    /// `offersPasswordReset()` (#63).
    fn offers_password_reset(&self) -> bool;
    /// `fingerprinting()` (#62 P6): the screen's fingerprint fact.
    fn fingerprinting(&self) -> Json;
    /// `breached_passwords.screen(password).breached`, where
    /// `risk.breachCheckAtSignIn` asks it.
    fn breached(&self, password: &str) -> bool;
    /// `credentials.setPasswordResetRequired(username, false)`: `pwdReset`
    /// cleared on the entry; false where it could not be written.
    fn clear_password_reset(&self, username: &str) -> bool;
    /// `audit.audit(row)`.
    fn audit(&self, row: &Json);
    /// `stats.recordRefusedAuthentication(row)` (#954).
    fn note_refused(&self, row: &Json);
    /// `realms.active() || cells.isMulti()`: whether a credential id this
    /// realm cannot place may be another realm's or cell's, so the browser
    /// is never told to forget it (`signalsUnknown()`).
    fn realms_active(&self) -> bool {
        false
    }
    /// `accountSignals.credentialChanged(facts)` (#145): a CAEP
    /// credential-change, which the SSF slice delivers.
    fn credential_changed(&self, _facts: &Json) {}
}

/// `common/post_login.ts`'s progress rows (#1096): what a post-login step
/// writes about the activity it asks for. The register is the post-login
/// slice's; a realm with no post-login policy, the default, asks nothing,
/// so no step is minted and none of these is reached.
pub trait PostLogin: Send + Sync {
    /// `noteAsked(username, due)`: the row, `invitedAt` set at the first.
    fn note_asked(&self, username: &str, due: &Json) -> Json;
    /// `noteSkipped(username, due)`: `{ ok, snoozedUntil }`.
    fn note_skipped(&self, username: &str, due: &Json) -> Json;
    /// `noteDone(username, due)`.
    fn note_done(&self, username: &str, due: &Json);
}

/// THE SIGN-OUT'S PAGE OPERATIONS (`logout/logout.ts`'s `signOutView()`,
/// `signOutAct()`, `signOutAccountsView()`, `signOutAccountsAct()`), which
/// Node's door reaches by a lazy `require()` of the logout module
/// (`AuthnApi.logout()`): the door here is the binding, the query and the
/// body, and the logic is the logout crate's (`sts-logout`), built long
/// after this one (the root `CLAUDE.md`'s 23a against 8-api) — so it is a
/// late binding, [`crate::door::AuthnApi::set_sign_out`]. Each answers the
/// status, the JSON, the cookies and headers the act wrote, and the code.
pub trait SignOutPages: Send + Sync {
    /// `GET /authn-api/logout`, the query already held to the model.
    fn view(
        &self,
        call: &crate::flow::Call,
        query: &serde_json::Map<String, Json>,
    ) -> crate::flow::Answer;
    /// `POST /authn-api/logout`, bound and its body held to the model.
    fn act(
        &self,
        call: &crate::flow::Call,
        query: &serde_json::Map<String, Json>,
        body: &serde_json::Map<String, Json>,
    ) -> crate::flow::Answer;
    /// `GET /authn-api/logout/accounts`.
    fn accounts_view(
        &self,
        call: &crate::flow::Call,
        query: &serde_json::Map<String, Json>,
    ) -> crate::flow::Answer;
    /// `POST /authn-api/logout/accounts`.
    fn accounts_act(
        &self,
        call: &crate::flow::Call,
        query: &serde_json::Map<String, Json>,
        body: &serde_json::Map<String, Json>,
    ) -> crate::flow::Answer;
}
