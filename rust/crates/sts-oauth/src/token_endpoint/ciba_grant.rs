// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! CIBA's grant at the token endpoint (`oauth2.ts`'s
//! `urn:openid:params:grant-type:ciba` branch, section 10.1): a poll or
//! ping client redeems an approved `auth_req_id`, each refusal Node's code,
//! error and sentence; and `/oauth2/bc-authorize`
//! (`backchannelAuthentication()`, section 7) — the client authenticated
//! as at the token endpoint, exactly one hint resolved to a person,
//! `binding_message`, `user_code`, `requested_expiry`,
//! `client_notification_token` and `request_context` checked, and the
//! request written in Node's row, so the person's approval (Node's
//! `/account-api`) and a ping or push (Node's queue) follow it.
//!
//! NOT HERE, and what this answers meanwhile: a SIGNED request (section
//! 7.1.1, `cibaSignedRequest()`) is refused `STS-OAUTH-0643` — the request
//! object verifier for CIBA is not ported; FAPI-CIBA's refusals (#142) are
//! not asked under a FAPI profile; Grant Management (`grant_id`,
//! `grant_management_action`) is not planned; an ephemeral subject in an
//! `id_token_hint` is not mapped back (#149).

use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;

use super::{s, Issuing, Mint, TokenEndpoint};
use crate::answer::Answer;
use crate::introspection::EndpointAsk;

impl TokenEndpoint {
    /// The CIBA grant.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(super) async fn ciba_grant(&self, issuing: &Issuing<'_>) -> Answer {
        let Some(ciba) = self.ciba.as_ref().filter(|c| c.enabled()) else {
            return self.refusal(
                codes::STS_OAUTH_0638,
                400,
                "unsupported_grant_type",
                "OpenID Connect CIBA is not enabled in this realm.",
            );
        };
        let client_id = issuing.client.client_id.clone();
        let mode = self.clients.ciba_mode_of(&client_id);
        if mode != "poll" && mode != "ping" {
            return self.refusal(
                codes::STS_OAUTH_0654,
                400,
                "unauthorized_client",
                &format!(
                    "this client is registered for {}; only a poll or ping \
                     client asks the token endpoint (section 10).",
                    if mode.is_empty() {
                        "no CIBA delivery mode"
                    } else {
                        &mode
                    }
                ),
            );
        }
        let (state, record) =
            ciba.poll(&s(issuing.body.get("auth_req_id")), &client_id);
        if state != "approved" {
            let interval = record
                .as_ref()
                .map(|r| crate::js::stringify(&r["interval"]))
                .unwrap_or_else(|| "undefined".into());
            let (code, error, description) = match state.as_str() {
                "pending" => (
                    codes::STS_OAUTH_0656,
                    "authorization_pending",
                    "The person has not answered yet.".to_string(),
                ),
                "slow_down" => (
                    codes::STS_OAUTH_0657,
                    "slow_down",
                    format!(
                        "Polled sooner than the interval; wait {} seconds \
                         between requests.",
                        interval
                    ),
                ),
                "expired" => (
                    codes::STS_OAUTH_0658,
                    "expired_token",
                    "The request expired before the person answered."
                        .to_string(),
                ),
                "denied" => (
                    codes::STS_OAUTH_0659,
                    "access_denied",
                    "The person denied the request.".to_string(),
                ),
                "redeemed" => (
                    codes::STS_OAUTH_0660,
                    "invalid_grant",
                    "The tokens for this request have already been issued."
                        .to_string(),
                ),
                _ => (
                    codes::STS_OAUTH_0655,
                    "invalid_grant",
                    "auth_req_id names no request of this client.".to_string(),
                ),
            };
            return self.refusal(code, 400, error, &description);
        }
        let record = record.unwrap_or(Json::Null);
        let user = self.people.user_for(&s(record.get("username")));
        let nobody =
            s(user.get("sub")).is_empty() && self.people.has_subject_resolver();
        if nobody || !ciba.redeem(&record).await {
            return self.refusal(
                codes::STS_OAUTH_0660,
                400,
                "invalid_grant",
                "The tokens for this request have already been issued.",
            );
        }
        let plan = &record["grantManagement"];
        let approval = &record["approval"];
        let opts = Mint {
            jkt: issuing.dpop_jkt.clone(),
            sub: s(user.get("sub")),
            username: s(user.get("username")),
            user,
            client_id,
            scope: if plan.is_object() {
                s(plan.get("scope"))
            } else {
                s(record.get("scope"))
            },
            auth_time: crate::js::to_number(&approval["authTime"]),
            amr: approval.get("amr").cloned().unwrap_or(Json::Null),
            acr: approval
                .get("acr")
                .filter(|a| crate::js::truthy(Some(a)))
                .cloned()
                .unwrap_or(Json::Null),
            session_id: s(approval.get("sessionId")),
            grant: "ciba".into(),
            with_refresh: true,
            ..Mint::default()
        };
        self.respond(self.issue(issuing, opts))
    }
}

impl TokenEndpoint {
    /// `POST /oauth2/bc-authorize` (CIBA Core section 7).
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn bc_authorize(&self, ask: &EndpointAsk) -> Answer {
        let mut answer = self.bc_authorize_inner(ask).await;
        answer.set("Cache-Control", "no-store");
        answer
    }

    /// `cibaHintPerson(kind, value, issuer)`: the username, or Node's
    /// `(code, error, why)`.
    fn ciba_hint_person(
        &self,
        kind: &str,
        value: &str,
        issuer: &str,
    ) -> Result<String, (sts_core::errors::ErrorCode, &'static str, String)>
    {
        let unknown = || {
            (
                codes::STS_OAUTH_0646,
                "unknown_user_id",
                format!(
                    "the {} names nobody this realm holds (section 13).",
                    kind
                ),
            )
        };
        let username = if kind == "login_hint" {
            value.trim().to_string()
        } else {
            let now = self.clock.now_s();
            let verified = if kind == "id_token_hint" {
                self.signer.verify_own_signature(value, now)
            } else {
                self.signer.verify_own(value, now)
            };
            let claims = match verified {
                Ok(c) => Some(c),
                Err(why) => {
                    if kind == "login_hint_token"
                        && why.to_lowercase().contains("expired")
                    {
                        return Err((
                            codes::STS_OAUTH_0648,
                            "expired_login_hint_token",
                            "the login_hint_token has expired.".into(),
                        ));
                    }
                    None
                }
            };
            let stands = claims.as_ref().is_some_and(|c| {
                let jti = s(c.get("jti"));
                s(c.get("iss")) == issuer
                    && (jti.is_empty() || !self.register_revoked(&jti))
                    && (kind != "id_token_hint"
                        || super::exchange::own_token_kind(value, c)
                            == "id_token")
            });
            if !stands {
                return Err((
                    codes::STS_OAUTH_0647,
                    "invalid_request",
                    format!(
                        "the {} is not a token this authorization server \
                         issued and still stands by.",
                        kind
                    ),
                ));
            }
            let sub = claims.map(|c| s(c.get("sub"))).unwrap_or_default();
            self.people.name_for_subject(&sub).unwrap_or(sub)
        };
        if username.is_empty() {
            return Err(unknown());
        }
        let person = self.people.user_for(&username);
        if s(person.get("sub")).is_empty() {
            return Err(unknown());
        }
        let named = s(person.get("username"));
        Ok(if named.is_empty() { username } else { named })
    }

    async fn bc_authorize_inner(&self, ask: &EndpointAsk) -> Answer {
        let Some(ciba) = self.ciba.as_ref().filter(|c| c.enabled()) else {
            return self.refusal(
                codes::STS_OAUTH_0638,
                404,
                "invalid_request",
                "OpenID Connect CIBA is not enabled in this realm \
                 (oauth2.ciba).",
            );
        };
        let folded = crate::js::fold(&crate::js::form_decode(&ask.body));
        let params: Map<String, Json> =
            match crate::model::check("bc-authorize", &folded, "body") {
                Ok(b) => b,
                Err(r) => {
                    return self.refusal(
                        codes::STS_OAUTH_0639,
                        400,
                        "invalid_request",
                        &r.detail,
                    )
                }
            };
        let refuse = |_: Option<sts_core::errors::ErrorCode>, why: &str| {
            (
                codes::STS_OAUTH_0641,
                401u16,
                true,
                format!(
                    "CIBA Core section 7.1: the client authenticates to this \
                     endpoint as it does to the token endpoint, in every \
                     mode — and {}",
                    why
                ),
            )
        };
        let caller = match self
            .endpoint_caller(
                ask,
                &params,
                "/oauth2/bc-authorize",
                false,
                false,
                &refuse,
            )
            .await
        {
            Ok(c) => c,
            Err(a) => return a,
        };
        let client_id = caller.client_id.clone();
        let registered = self.clients.ciba_of(&client_id);
        let mode = s(registered.get("mode"));
        if mode.is_empty() {
            return self.refusal(
                codes::STS_OAUTH_0642,
                400,
                "unauthorized_client",
                &format!(
                    "client \"{}\" registered no backchannel_token_delivery_\
                     mode, so it may not use CIBA (section 4).",
                    client_id
                ),
            );
        }
        let issuer = crate::jwt_access_token::JwtAccessTokens::new(
            self.settings.clone(),
        )
        .issuer_for(&ask.base);
        if crate::js::truthy(params.get("request"))
            || !s(registered.get("signingAlg")).is_empty()
        {
            let why = if crate::js::truthy(params.get("request")) {
                "the signed request did not verify: signed CIBA requests \
                 are not verified by this runtime yet."
            } else {
                "this client registered \
                 backchannel_authentication_request_signing_alg, so its \
                 requests must be signed (section 7.1.1)."
            };
            return self.refusal(
                codes::STS_OAUTH_0643,
                400,
                "invalid_request",
                why,
            );
        }
        let scope = s(params.get("scope")).trim().to_string();
        if !scope.split_whitespace().any(|w| w == "openid") {
            return self.refusal(
                codes::STS_OAUTH_0644,
                400,
                "invalid_scope",
                "a CIBA request is an OpenID Connect authentication request: \
                 its scope must contain openid (section 7.1).",
            );
        }
        if let Some(r) = self.scopes.refusal(&scope, &client_id) {
            return self.refusal(r.code, 400, "invalid_scope", &r.description);
        }
        let hints: Vec<&str> =
            ["login_hint_token", "id_token_hint", "login_hint"]
                .into_iter()
                .filter(|n| !s(params.get(*n)).is_empty())
                .collect();
        if hints.len() != 1 {
            return self.refusal(
                codes::STS_OAUTH_0645,
                400,
                "invalid_request",
                &format!(
                    "exactly one of login_hint_token, id_token_hint and \
                     login_hint is required (section 7.1); this request has \
                     {}.",
                    if hints.is_empty() {
                        "none".to_string()
                    } else {
                        hints.join(", ")
                    }
                ),
            );
        }
        let username = match self.ciba_hint_person(
            hints[0],
            &s(params.get(hints[0])),
            &issuer,
        ) {
            Ok(u) => u,
            Err((code, error, why)) => {
                return self.refusal(code, 400, error, &why)
            }
        };
        let binding = s(params.get("binding_message"));
        if binding.encode_utf16().count() > 200
            || binding
                .chars()
                .any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
        {
            return self.refusal(
                codes::STS_OAUTH_0649,
                400,
                "invalid_binding_message",
                "binding_message must be at most 200 printable characters: \
                 it is shown to the person as it is.",
            );
        }
        if registered.get("userCode") == Some(&Json::Bool(true)) {
            let code = s(params.get("user_code"));
            if code.is_empty() {
                return self.refusal(
                    codes::STS_OAUTH_0650,
                    400,
                    "missing_user_code",
                    "this client registered backchannel_user_code_parameter, \
                     so every request carries the person's user_code.",
                );
            }
            if !ciba.user_code_matches(&username, &code) {
                return self.refusal(
                    codes::STS_OAUTH_0651,
                    400,
                    "invalid_user_code",
                    "the user_code is not the one this person set.",
                );
            }
        }
        let expiry = s(params.get("requested_expiry"));
        let expiry_ok = expiry.is_empty()
            || (expiry.len() <= 9
                && expiry.chars().all(|c| c.is_ascii_digit())
                && !expiry.starts_with('0'));
        if !expiry_ok {
            return self.refusal(
                codes::STS_OAUTH_0652,
                400,
                "invalid_request",
                "requested_expiry must be a positive whole number of seconds.",
            );
        }
        let notification = s(params.get("client_notification_token"));
        if (mode == "ping" || mode == "push") && notification.is_empty() {
            return self.refusal(
                codes::STS_OAUTH_0653,
                400,
                "invalid_request",
                &format!(
                    "client_notification_token is required of a {} client \
                     (section 7.1).",
                    mode
                ),
            );
        }
        let mut context = Json::Null;
        if let Some(raw) = params
            .get("request_context")
            .filter(|v| !matches!(v, Json::String(t) if t.is_empty()))
        {
            let parsed = match raw {
                Json::String(t) => serde_json::from_str::<Json>(t).ok(),
                other => Some(other.clone()),
            };
            match parsed {
                Some(p @ Json::Object(_)) if p.to_string().len() <= 4096 => {
                    context = p;
                }
                _ => {
                    return self.refusal(
                        codes::STS_OAUTH_0664,
                        400,
                        "invalid_request",
                        "request_context must be a JSON object of at most \
                         4096 characters (FAPI-CIBA section 5.3).",
                    )
                }
            }
        }
        let acr_values: Vec<String> = s(params.get("acr_values"))
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let made = ciba.create(&json!({
            "clientId": client_id,
            "clientName": self.clients.registered_client_name(&client_id),
            "username": username, "scope": scope, "acrValues": acr_values,
            "bindingMessage": binding, "mode": mode,
            "notificationToken": notification,
            "notificationEndpoint": registered["endpoint"],
            "requestedExpiry": expiry, "base": ask.base,
            "requestContext": context,
        }));
        match made {
            Ok((record, id, expires_in)) => {
                let mut ack = Map::new();
                ack.insert("auth_req_id".into(), json!(id));
                ack.insert("expires_in".into(), json!(expires_in));
                if mode != "push" {
                    ack.insert("interval".into(), record["interval"].clone());
                }
                Answer::json(Json::Object(ack))
            }
            Err((code, error, description)) => {
                self.refusal(code, 403, &error, &description)
            }
        }
    }
}
