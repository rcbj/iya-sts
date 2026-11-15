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
//! THE CLIENT'S OWN ALGORITHM (OIDC Core section 3.1.3.7): the token is
//! signed with the `id_token_signed_response_alg` the client registered —
//! PS256 under FAPI 1.0 Advanced where it registered none, RS256 otherwise
//! — with the realm's own RSA or curve key, or with the client's secret for
//! an HMAC algorithm; `at_hash`, `c_hash` and `s_hash` use that algorithm's
//! hash (#118). One it cannot sign with issues no ID Token, logged, where
//! Node throws (`server_error`).
//!
//! THE SUBJECT is the client's ([`crate::pairwise`]): public, pairwise per
//! sector, or ephemeral per authentication.
//!
//! WHAT IS NOT HERE, and what is answered meanwhile: ID Token encryption,
//! the enterprise claims, `claims` requests, the Claims Providers, `cnf`
//! for `bound_key`, the device claims and `ds_hash`, and
//! `oauth2.breakIdTokenNonce`; a post-quantum algorithm (the key set holds
//! no post-quantum signing key here) issues no ID Token.

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
    /// The client-facing subject; `None` tells every client the public
    /// one.
    pub pairwise: Option<Arc<crate::pairwise::PairwiseSubjects>>,
}

/// `fapi.defaultSigningAlg()`: PS256 under FAPI 1.0 Advanced.
fn fapi_default_alg(settings: &Settings) -> &'static str {
    if settings.value_of("oauth2.fapi").as_str() == "1-advanced" {
        "PS256"
    } else {
        ""
    }
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

impl CoreIdTokens {
    /// `idTokenHalfHash(value, alg)`.
    fn half(value: &str, alg: &str) -> String {
        sts_crypto::jws_alg::id_token_half_hash(value, alg)
    }

    /// The signature: an HMAC with the client's secret, or the realm's key.
    fn sign(
        &self,
        payload: &Map<String, Json>,
        alg: &str,
        registered: &Json,
    ) -> Result<String, String> {
        if alg.starts_with("HS") {
            let secret = s(registered.get("client_secret"));
            if secret.is_empty() {
                return Err(format!(
                    "{} is signed with the client_secret, and this client \
                     has none — a public client cannot use a symmetric \
                     algorithm.",
                    alg
                ));
            }
            let key = sts_crypto::keys::JwsKey::from_jwk(&json!({
                "kty": "oct",
                "k": sts_crypto::b64::encode(secret.as_bytes()),
            }))
            .map_err(|e| e.to_string())?;
            return sts_crypto::jws::sign_jws(
                payload,
                &key,
                &sts_crypto::jws::SignOptions {
                    algorithm: Some(alg.to_string()),
                    ..sts_crypto::jws::SignOptions::default()
                },
            )
            .map_err(|e| e.to_string());
        }
        self.signer.sign(payload, "JWT", alg)
    }
}

impl IdTokens for CoreIdTokens {
    #[tracing::instrument(level = "debug", skip_all)]
    fn id_token(&self, base: &str, issuing: &Json) -> Option<String> {
        let client_id = s(issuing.get("client_id"));
        let registered = self.clients.client_config_of(&client_id);
        let alg = match s(registered.get("id_token_signed_response_alg")) {
            a if !a.is_empty() => a,
            _ => match fapi_default_alg(&self.settings) {
                "" => "RS256".to_string(),
                d => d.to_string(),
            },
        };
        if sts_crypto::jws_alg::JwsAlg::by_name(&alg).is_none() {
            tracing::warn!(
                "{}oauth2: \"{}\" registered id_token_signed_response_alg \
                 \"{}\", which this service does not sign ID Tokens with; \
                 no ID Token is issued.",
                sts_core::log::tag(sts_core::errors::codes::STS_OAUTH_0184),
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
            v if !v.is_empty() => v,
            _ => {
                let local = s(user.get("sub"));
                match &self.pairwise {
                    None => local,
                    Some(p) => match p.subject_for(
                        &client_id,
                        &local,
                        &s(issuing.get("session_id")),
                    ) {
                        Ok(v) => v,
                        Err(why) => {
                            tracing::error!(
                                "{}oauth2: no ID Token: {}",
                                sts_core::log::tag(
                                    sts_core::errors::codes::STS_OAUTH_0184
                                ),
                                why
                            );
                            return None;
                        }
                    },
                }
            }
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
        if let Some(Json::Object(claims)) = issuing.get("scope_claims") {
            for (k, v) in claims {
                if !p.contains_key(k) {
                    p.insert(k.clone(), v.clone());
                }
            }
        }
        let access = s(issuing.get("access_token"));
        if !access.is_empty() {
            p.insert("at_hash".into(), json!(Self::half(&access, &alg)));
        }
        let code = s(issuing.get("code"));
        if !code.is_empty() {
            p.insert("c_hash".into(), json!(Self::half(&code, &alg)));
        }
        let state = s(issuing.get("state"));
        if !state.is_empty() {
            p.insert("s_hash".into(), json!(Self::half(&state, &alg)));
        }
        match self.sign(&p, &alg, &registered) {
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
