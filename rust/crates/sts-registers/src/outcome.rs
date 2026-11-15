// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a register act answers: Node's result object, and the code Node
//! MARKS on it (`errorCodes.mark(result, code)`, a non-enumerable member
//! read back by `errorCodes.codeOf()`). The code is the operator's and is
//! recorded, never sent (root `CLAUDE.md`); the API layer puts it on the
//! audit row and the response's extensions, and the answer to the client.

use serde_json::Value;
use sts_core::errors::ErrorCode;

/// A result and the code marked on it.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub answer: Value,
    pub code: Option<ErrorCode>,
}

impl Outcome {
    /// An unmarked result.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn ok(answer: Value) -> Outcome {
        Outcome { answer, code: None }
    }

    /// `errorCodes.mark(answer, code)`.
    #[tracing::instrument(level = "debug", skip(answer))]
    pub fn marked(code: ErrorCode, answer: Value) -> Outcome {
        Outcome {
            answer,
            code: Some(code),
        }
    }

    /// `result.ok === false`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn refused(&self) -> bool {
        self.answer.get("ok") == Some(&Value::Bool(false))
    }

    /// `result.ok === true` (or truthy, as the callers test it).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn is_ok(&self) -> bool {
        self.answer.get("ok").is_some_and(crate::js::truthy)
    }

    /// The member `why` or the first of `errors`, as text.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn why(&self) -> Value {
        self.answer.get("why").cloned().unwrap_or(Value::Null)
    }
}
