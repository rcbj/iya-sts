// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The authorization server and OpenID provider (`oauth-oidc/`), ported a
//! module at a time (#444, phase 6). What is here so far:
//!
//! * [`jwt_access_token`] — RFC 9068's resource-server half: the `typ`, the
//!   issuer and the audience a resource server here checks after it has
//!   verified a token's signature. The issuance half (`audiencePlan()`)
//!   arrives with the token endpoint.
//! * [`mtls`] — RFC 8705 section 3.1: a certificate-bound token held to
//!   the connection's certificate.
//! * [`revocation`] — the revoked-token register every resource server
//!   asks.
//! * [`dpop`] — RFC 9449's proof check, its stores behind a trait, and
//!   [`dpop_stores`] — the nonces and the replay history behind it, and
//!   [`dpop_reservation`] — the cluster's reservation of a proof's jti.

#![forbid(unsafe_code)]

pub mod dpop;
pub mod dpop_reservation;
pub mod dpop_stores;
pub mod jwt_access_token;
pub mod mtls;
pub mod revocation;
