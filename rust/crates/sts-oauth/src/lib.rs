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
//!
//! The rest of the core (#444, phase 5, the `oauth2` slice), which the
//! hosted console and portal sign in through:
//!
//! * [`authorize`] — `/oauth2/authorize`: the vetting, RFC 6749 section
//!   4.1.2.1's redirect-or-answer, the session hand-off to sign-in
//!   ([`signin`], `beginAuthentication()` over `authn.pending`), consent as
//!   far as global consent answers it, and the code in Node's record;
//! * [`token_endpoint`]'s `authorization_code` and `refresh_token` grants:
//!   single use and replay, PKCE, DPoP verified here and binding the code
//!   and the tokens, RFC 8707's audience, refresh families with rotation
//!   and reuse detection, the core ID Token ([`id_token`]);
//! * [`grants`] — the codes, redemptions, transactions and refresh
//!   families, in Node's stores;
//! * [`scopes`] — the scope policy, delegated permissions and RFC 8707's
//!   registered targets;
//! * [`metadata`] — RFC 8414 discovery.

#![forbid(unsafe_code)]

pub mod answer;
pub mod authorization_servers;
pub mod authorize;
pub mod bcp;
pub mod client_auth;
pub mod clients;
pub mod consent;
pub mod dpop;
pub mod dpop_reservation;
pub mod dpop_stores;
pub mod grants;
pub mod id_token;
pub mod jarm;
pub mod js;
pub mod jwks;
pub mod jwt_access_token;
pub mod metadata;
pub mod minted;
pub mod model;
pub mod mtls;
pub mod oauth21;
pub mod pairwise;
pub mod par;
pub mod refresh_crypto;
pub mod reports;
pub mod request_object;
pub mod revocation;
pub mod scopes;
pub mod secret_limit;
pub mod sender_constraints;
pub mod signin;
pub mod token_endpoint;
pub mod userinfo;
