// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CORE OF AN ID TOKEN (`oauth2.ts`'s `idToken()`), as far as the code
//! flow of this service's own surfaces needs it: `iss`, `sub` (the public
//! subject), `aud` and `azp` (the client), `iat`, `nbf`, `exp`
//! (`oauth2.idTokenTtlS`, or the client's own), `auth_time`, `jti`, `amr`,
//! `acr`, the request's `nonce`, `sid` where front- or back-channel logout
//! is on, and `at_hash` of the access token beside it — signed with
//! RS256, the default `id_token_signed_response_alg`, under the realm's
//! key, `typ` JWT.
//!
//! WHAT THE OIDC SLICE ADDS, and what is answered meanwhile: the scope
//! claims of an implicit response and the person's profile from the
//! directory (`personFromDirectory()`, `scopeClaimsOf()`), a client's own
//! signing algorithm and ID Token encryption, pairwise and ephemeral
//! subjects, the enterprise claims, `claims` requests, the Claims Providers,
//! `cnf` for `bound_key`, the device claims and `ds_hash`, and
//! `oauth2.breakIdTokenNonce`. A client registered for a pairwise or
//! ephemeral subject, or for another algorithm, is given NO ID Token here
//! rather than one that would lie about it.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::settings::Settings;

use crate::clients::Clients;
use crate::token_endpoint::{IdTokens, Signer};

/// The core ID Token.
pub struct CoreIdTokens {
    pub settings: Arc<Settings>,
    pub clients: Arc<dyn Clients>,
    pub signer: Arc<dyn Signer>,
    pub now_s: Arc<dyn Fn() -> i64 + Send + Sync>,
}

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// `idTokenHalfHash(value, 'RS256')`: the left half of SHA-256,
/// base64url.
#[tracing::instrument(level = "debug", skip_all)]
pub fn half_hash(value: &str) -> String {
    let digest = sts_crypto::jws_alg::Hash::Sha256.digest(value.as_bytes());
    sts_crypto::b64::encode(&digest[..digest.len() / 2])
}

impl IdTokens for CoreIdTokens {
    #[tracing::instrument(level = "debug", skip_all)]
    fn id_token(&self, base: &str, issuing: &Json) -> Option<String> {
        let client_id = s(issuing.get("client_id"));
        let registered = self.clients.client_config_of(&client_id);
        let subject_type = s(registered.get("subject_type"));
        if !subject_type.is_empty() && subject_type != "public" {
            tracing::warn!(
                "oauth2: \"{}\" is registered for {} subject identifiers, \
                 which this runtime does not mint yet; no ID Token is \
                 issued rather than one naming the public subject.",
                client_id,
                subject_type
            );
            return None;
        }
        let alg = s(registered.get("id_token_signed_response_alg"));
        if !alg.is_empty() && alg != "RS256" {
            tracing::warn!(
                "oauth2: \"{}\" registered id_token_signed_response_alg \
                 \"{}\", which this runtime does not sign with yet; no ID \
                 Token is issued.",
                client_id,
                alg
            );
            return None;
        }
        let iat = (self.now_s)();
        let ttl = self
            .clients
            .setting_for(&client_id, "oauth2.idTokenTtlS")
            .map(|v| crate::js::to_number(&v) as i64)
            .unwrap_or_else(|| {
                self.settings.value_of("oauth2.idTokenTtlS").as_int()
            });
        let user = issuing.get("user").cloned().unwrap_or(Json::Null);
        let sub = match s(issuing.get("sub")) {
            v if v.is_empty() => s(user.get("sub")),
            v => v,
        };
        let mut p = Map::new();
        p.insert(
            "iss".into(),
            json!(crate::jwt_access_token::JwtAccessTokens::new(
                self.settings.clone()
            )
            .issuer_for(base)),
        );
        p.insert("sub".into(), json!(sub));
        p.insert("aud".into(), json!(client_id));
        p.insert("iat".into(), json!(iat));
        p.insert("nbf".into(), json!(iat));
        p.insert("exp".into(), json!(iat + ttl));
        let auth_time = crate::js::to_number(
            issuing.get("auth_time").unwrap_or(&Json::Null),
        );
        if auth_time.is_finite() && auth_time > 0.0 {
            p.insert("auth_time".into(), json!(auth_time as i64));
        }
        p.insert("azp".into(), json!(client_id));
        p.insert(
            "jti".into(),
            json!(sts_crypto::b64::encode(
                &sts_crypto::random::random_bytes(16).unwrap_or_default()
            )),
        );
        if let Some(amr) = issuing.get("amr").filter(|a| a.is_array()) {
            p.insert("amr".into(), amr.clone());
        }
        let acr = s(issuing.get("acr"));
        if !acr.is_empty() {
            p.insert("acr".into(), json!(acr));
        }
        let nonce = s(issuing.get("nonce"));
        if !nonce.is_empty() {
            p.insert("nonce".into(), json!(nonce));
        }
        let sid = s(issuing.get("session_id"));
        if !sid.is_empty()
            && (self
                .settings
                .value_of("oauth2.frontchannelLogout")
                .as_bool()
                || self.settings.value_of("oauth2.backchannelLogout").as_bool())
        {
            p.insert("sid".into(), json!(sid));
        }
        let access = s(issuing.get("access_token"));
        if !access.is_empty() {
            p.insert("at_hash".into(), json!(half_hash(&access)));
        }
        match self.signer.sign(&p, "JWT", "RS256") {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(
                    "{}the ID Token could not be signed: {}",
                    sts_core::log::tag(sts_core::errors::codes::STS_OAUTH_0184),
                    e
                );
                None
            }
        }
    }
}
