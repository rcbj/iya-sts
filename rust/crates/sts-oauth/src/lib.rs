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
//! * [`sender_constraints`] — a resource that accepts only bound tokens.
//! * [`revocation`] — the revoked-token register every resource server
//!   asks.
//! * [`dpop`] — RFC 9449's proof check, its stores behind a trait, and
//!   [`dpop_stores`] — the nonces and the replay history behind it, and
//!   [`dpop_reservation`] — the cluster's reservation of a proof's jti.

//!
//! The authorization server's core (#444, phase 5):
//!
//! * [`model`] — every endpoint's request validated from
//!   `models/generated/oauth.json`, as `validation.js` and zod answer;
//! * [`client_auth`] and [`bcp`] — the client authentication methods and
//!   RFC 9700 section 2.5's observation and policy;
//! * [`clients`] — `clientConfigOf()` over the application register;
//! * [`token_endpoint`] — `POST /oauth2/token`: the checks before a grant
//!   and the client credentials grant, the RFC 9068 access token;
//! * [`refresh_crypto`] — the realm-encrypted refresh token;
//! * [`minted`] — the token register (`admin_stats.tokens`) and the
//!   session core's sign-out revocation;
//! * [`jwks`] — `GET /oauth2/jwks` as Node builds it;
//! * [`answer`] and [`js`] — an endpoint's answer, and the JavaScript
//!   behaviours the sentences depend on.

#![forbid(unsafe_code)]

pub mod answer;
pub mod authorize;
pub mod bcp;
pub mod client_auth;
pub mod clients;
pub mod dpop;
pub mod dpop_reservation;
pub mod dpop_stores;
pub mod grants;
pub mod id_token;
pub mod js;
pub mod jwks;
pub mod jwt_access_token;
pub mod minted;
pub mod model;
pub mod mtls;
pub mod refresh_crypto;
pub mod revocation;
pub mod scopes;
pub mod sender_constraints;
pub mod signin;
pub mod token_endpoint;
