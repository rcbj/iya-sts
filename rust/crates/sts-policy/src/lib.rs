// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The named policies on Directory > Policies (#444 phase 4, the policy
//! slice): a port of `common/policy_selection.ts` (rule 3cx), of the seven
//! kinds `admin-core/policy_kinds.ts` lists — the password (3ac, with its
//! generator), authentication (3bd), service-account (3cd), passkey (3ch),
//! locale (3ci), attribute (3co) and post-login (3ct) policies — and of
//! that list itself.
//!
//! Each kind reads its rows from the model's generated tables
//! ([`tables`]), the same rows Node's `ModelTables` hands it, and answers
//! what its Node module answers: the profile in force (`read()`, with the
//! realm's own entry, the default realm's and the built-in defaults in
//! Node's order), the policy that applies to a sign-in, a person or a group
//! (the shared [`selection`]), and every save, reset and act an
//! administrator sends through `/admin-api/policies`, with each refusal's
//! sentence and code. It reaches the directory, the application register
//! and the rest through the [`ports`]; the answers are JSON values, as the
//! Node answers are, so the API layer hands them on as they are.
//!
//! WHAT REPLACED WHAT. Node's kinds are instances in slots, each handed the
//! directory by `ldap/ldap_server.js` and reaching other registers lazily
//! to avoid require cycles; here a kind is a value built over [`Ports`],
//! and the realm the Node code reads ambiently is an argument.

#![forbid(unsafe_code)]

pub mod js;
pub mod kinds;
pub mod ports;
pub mod registry;
pub mod selection;
pub mod tables;

use serde_json::Value;
use sts_core::errors::ErrorCode;

pub use ports::Ports;

/// What a kind's method answers: the value Node returns, and the error code
/// Node marks on it (`errorCodes.mark()`, never part of the value).
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub value: Value,
    pub code: Option<ErrorCode>,
}

impl Answer {
    /// An unmarked answer.
    pub fn of(value: Value) -> Answer {
        // A hot path: every answer is made here.
        Answer { value, code: None }
    }

    /// `errorCodes.mark({ ok: false, errors }, code)`.
    pub fn refused(code: ErrorCode, errors: Vec<String>) -> Answer {
        // A hot path: every refusal is made here.
        Answer {
            value: js::object(vec![
                ("ok", Value::Bool(false)),
                ("errors", js::strings(&errors)),
            ]),
            code: Some(code),
        }
    }

    /// Whether the answer's `ok` is false.
    pub fn is_refusal(&self) -> bool {
        // A hot path: asked of every answer a caller passes on.
        self.value.get("ok") == Some(&Value::Bool(false))
    }
}
