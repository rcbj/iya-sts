// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! STUB (to be ported): `common/validation.js`'s URI checks.

#![allow(unused_variables)]

/// `redirectUriProblem(value, {privateUse})`: '' for none.
#[tracing::instrument(level = "debug")]
pub fn redirect_uri_problem(value: &str, private_use: bool) -> Option<String> {
    None
}

/// `frontchannelUriProblem(value)`.
#[tracing::instrument(level = "debug")]
pub fn frontchannel_uri_problem(value: &str) -> Option<String> {
    None
}

/// `backchannelUriProblem(value)`.
#[tracing::instrument(level = "debug")]
pub fn backchannel_uri_problem(value: &str) -> Option<String> {
    None
}

/// `normaliseOrigin(value)`: '' when it is not an origin.
#[tracing::instrument(level = "debug")]
pub fn normalise_origin(value: &str) -> String {
    value.to_string()
}
