// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The credentials a sign-in step checks, and the evidence each puts on an
//! authentication event (#444 phase 5, the credentials slice).
//!
//! A port of what Node does now in `common/credentials.ts` (THE ONE PLACE
//! a presented credential is verified), its mechanisms — `common/totp.ts`,
//! `common/backup_codes.ts` (3y), `common/app_passwords.ts` (3ax) — the
//! WebAuthn verifier `authn/webauthn.js` and the attestation statements of
//! `authn/webauthn_attestation.ts`, and `common/phishing_resistance.ts`
//! (3cp). `authn/CLAUDE.md` is the design: the session is THE identity and
//! a credential is EVIDENCE on one of its events. This crate holds the
//! evidence; the session record is the session slice's (`sts-authn`), and
//! [`evidence`] is the narrow port between them.
//!
//! **PERMISSIVENESS IS AN IMPLEMENTATION HERE, NOT AN ABSENCE**, as it is in
//! Node: every door always answers, and what `global.mode` changes (through
//! the `verifiesCredentials` predicate) is what it answers with — except
//! the reserved password `invalid`, refused in every mode, and a disabled
//! account, refused in every mode.
//!
//! WHAT REPLACED WHAT. Node's modules are instances in slots, the directory
//! installed by `setDirectory()` from `ldap/ldap_server.js`, the pending
//! stores module-level `realms.map()`s read in the ambient realm. Here each
//! is built over [`ports`] (trait objects handed to the constructor), and
//! the pending stores are `sts-core`'s `RealmMap`s declared under Node's
//! persist names, so a pending enrolment a 1.x node wrote is one this
//! process reads.

#![forbid(unsafe_code)]

pub mod app_passwords;
pub mod backup_codes;
pub mod credentials;
pub mod evidence;
pub mod js;
pub mod limits;
pub mod mail_factor;
pub mod phishing;
pub mod ports;
pub mod totp;
pub mod webauthn;

use serde_json::Value as Json;
use sts_core::errors::ErrorCode;

/// What a door answers: the value Node returns, and the error code Node
/// marks on it (`errorCodes.mark()`, never part of the value and never
/// sent).
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub value: Json,
    pub code: Option<ErrorCode>,
}

impl Verdict {
    /// An unmarked answer.
    /// A hot path, so it carries no span (the logging rule's exemption).
    pub fn of(value: Json) -> Verdict {
        Verdict { value, code: None }
    }

    /// `errorCodes.mark(value, code)`.
    /// A hot path, so it carries no span (the logging rule's exemption).
    pub fn coded(code: ErrorCode, value: Json) -> Verdict {
        Verdict {
            value,
            code: Some(code),
        }
    }

    /// `answer.ok`.
    /// A hot path, so it carries no span (the logging rule's exemption).
    pub fn ok(&self) -> bool {
        self.value.get("ok") == Some(&Json::Bool(true))
    }

    /// `answer.reason`, or empty.
    /// A hot path, so it carries no span (the logging rule's exemption).
    pub fn reason(&self) -> &str {
        self.value
            .get("reason")
            .and_then(Json::as_str)
            .unwrap_or("")
    }

    /// The code's text, or empty.
    /// A hot path, so it carries no span (the logging rule's exemption).
    pub fn code_text(&self) -> &'static str {
        self.code.map_or("", ErrorCode::as_str)
    }
}
