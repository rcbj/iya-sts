// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 8628 at the authorization server (`oauth2.ts`'s
//! `deviceAuthorizationRequest()` and `tokenGrant()`'s device_code branch,
//! #150): the device authorization endpoint, and the grant the device
//! polls with — each refusal Node's code, status, error and sentence.
//!
//! OPENID CONNECT KEY BINDING: a device code requested with a DPoP proof
//! is redeemed only by that key (`STS-OAUTH-0701`), and a grant of
//! `bound_key` needs a proof whose `c_s256` is the SHA-256 of the device
//! code (`boundKeyProofRefusal()`, `STS-OAUTH-0702`, `0703`).
//!
//! NOT HERE: the person's answer, on `/portal/device` — the portal's
//! static surface and its `/account-api` operations (`portal_device.ts`),
//! which are the API slice's crate; they answer through
//! [`crate::device_authorization::DeviceCodes::answer`]. A named
//! authorization server's advertised authentication methods are not
//! asked (the default advertises every method), and the verification URI
//! is on this base (custom listeners, `rebaseTo()`, are not ported).

use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;

use super::{s, Issuing, Mint, TokenEndpoint};
use crate::answer::Answer;
use crate::device_authorization::{DeviceCodes, GRANT_TYPE};
use crate::introspection::EndpointAsk;

/// `boundKeyProofRefusal(scope, code, proof)`: `(code, sentence)`, or
/// `None`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn bound_key_proof_refusal(
    key_binding_on: bool,
    scope: &str,
    code: &str,
    proof_claims: Option<&Json>,
) -> Option<(sts_core::errors::ErrorCode, String)> {
    if !key_binding_on || !scope.split_whitespace().any(|w| w == "bound_key") {
        return None;
    }
    let Some(claims) = proof_claims else {
        return Some((
            codes::STS_OAUTH_0702,
            "bound_key was granted, so the token request must carry a DPoP \
             proof (OpenID Connect Key Binding section 2)."
                .into(),
        ));
    };
    let expected = sts_crypto::b64::encode(
        &sts_crypto::jws_alg::Hash::Sha256.digest(code.as_bytes()),
    );
    if s(claims.get("c_s256")) != expected {
        return Some((
            codes::STS_OAUTH_0703,
            "the DPoP proof's c_s256 is not the SHA-256 of the code being \
             redeemed (OpenID Connect Key Binding section 2)."
                .into(),
        ));
    }
    None
}

impl TokenEndpoint {
    fn key_binding_on(&self) -> bool {
        !matches!(
            self.settings.value_of("oauth2.keyBinding"),
            sts_core::settings::SettingValue::Bool(false)
        )
    }

    fn devices_on(&self) -> Option<&std::sync::Arc<DeviceCodes>> {
        self.devices.as_ref().filter(|d| d.enabled())
    }

    /// The device_code grant (section 3.4).
    #[tracing::instrument(level = "debug", skip_all)]
    pub(super) async fn device_grant(&self, issuing: &Issuing<'_>) -> Answer {
        let Some(devices) = self.devices_on() else {
            return self.refusal(
                codes::STS_OAUTH_0689,
                400,
                "unsupported_grant_type",
                "The device authorization grant is not enabled in this realm.",
            );
        };
        let device_code = s(issuing.body.get("device_code"));
        let (state, record) =
            devices.poll(&device_code, &issuing.client.client_id);
        if state != "approved" {
            let interval = record
                .as_ref()
                .map(|r| crate::js::stringify(&r["interval"]))
                .unwrap_or_else(|| "undefined".into());
            let (code, error, description) = match state.as_str() {
                "pending" => (
                    codes::STS_OAUTH_0696,
                    "authorization_pending",
                    "The person has not answered yet.".to_string(),
                ),
                "slow_down" => (
                    codes::STS_OAUTH_0697,
                    "slow_down",
                    format!(
                        "Polled sooner than the interval; wait {} seconds \
                         between requests.",
                        interval
                    ),
                ),
                "expired" => (
                    codes::STS_OAUTH_0698,
                    "expired_token",
                    "The device code expired before the person answered."
                        .to_string(),
                ),
                "denied" => (
                    codes::STS_OAUTH_0699,
                    "access_denied",
                    "The person denied the request.".to_string(),
                ),
                "redeemed" => (
                    codes::STS_OAUTH_0700,
                    "invalid_grant",
                    "The tokens for this device code have already been \
                     issued."
                        .to_string(),
                ),
                _ => (
                    codes::STS_OAUTH_0695,
                    "invalid_grant",
                    "device_code names no device authorization of this \
                     client."
                        .to_string(),
                ),
            };
            return self.refusal(code, 400, error, &description);
        }
        let record = record.unwrap_or(Json::Null);
        let bound = s(record.get("dpopJkt"));
        if !bound.is_empty() && bound != issuing.dpop_jkt {
            return self.refusal(
                codes::STS_OAUTH_0701,
                400,
                "invalid_dpop_proof",
                &format!(
                    "This device code is bound to DPoP key {}; the token \
                     request must carry a proof from that key.",
                    bound
                ),
            );
        }
        let scope = s(record.get("scope"));
        if let Some((code, description)) = bound_key_proof_refusal(
            self.key_binding_on(),
            &scope,
            &device_code,
            (!issuing.dpop_claims.is_null()).then_some(&issuing.dpop_claims),
        ) {
            return self.refusal(code, 400, "invalid_dpop_proof", &description);
        }
        // `provisionedPerson(username)`.
        let user = self.people.user_for(&s(record.get("username")));
        let nobody =
            s(user.get("sub")).is_empty() && self.people.has_subject_resolver();
        if nobody || !devices.redeem(&record).await {
            return self.refusal(
                codes::STS_OAUTH_0700,
                400,
                "invalid_grant",
                "The tokens for this device code have already been issued.",
            );
        }
        let approval = &record["approval"];
        let opts = Mint {
            jkt: issuing.dpop_jkt.clone(),
            sub: s(user.get("sub")),
            username: s(user.get("username")),
            user,
            client_id: issuing.client.client_id.clone(),
            scope,
            auth_time: crate::js::to_number(&approval["authTime"]),
            amr: approval.get("amr").cloned().unwrap_or(Json::Null),
            acr: approval
                .get("acr")
                .filter(|a| crate::js::truthy(Some(a)))
                .cloned()
                .unwrap_or(Json::Null),
            session_id: s(approval.get("sessionId")),
            grant: "device_code".into(),
            with_refresh: true,
            ..Mint::default()
        };
        self.respond(self.issue(issuing, opts))
    }

    /// `POST /oauth2/device_authorization` (section 3.1): `dpop` is the
    /// request's `DPoP` header, `htu` the endpoint's URL as a proof names
    /// it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn device_authorization(
        &self,
        ask: &EndpointAsk,
        dpop: Option<&str>,
        htu: &str,
    ) -> Answer {
        let mut answer = self.device_authorization_inner(ask, dpop, htu).await;
        answer.set("Cache-Control", "no-store");
        answer
    }

    async fn device_authorization_inner(
        &self,
        ask: &EndpointAsk,
        dpop: Option<&str>,
        htu: &str,
    ) -> Answer {
        let Some(devices) = self.devices_on() else {
            return self.refusal(
                codes::STS_OAUTH_0689,
                404,
                "invalid_request",
                "the device authorization grant is not enabled in this realm \
                 (oauth2.deviceAuthorization).",
            );
        };
        let folded = crate::js::fold(&crate::js::form_decode(&ask.body));
        let body: Map<String, Json> = match crate::model::check(
            "device-authorization",
            &folded,
            "body",
        ) {
            Ok(b) => b,
            Err(r) => {
                return self.refusal(
                    codes::STS_OAUTH_0690,
                    400,
                    "invalid_request",
                    &r.detail,
                )
            }
        };
        let refuse = |_: Option<sts_core::errors::ErrorCode>, why: &str| {
            (
                codes::STS_OAUTH_0691,
                401u16,
                true,
                format!(
                    "RFC 8628 section 3.1: a confidential client \
                     authenticates here as at the token endpoint — and {}",
                    why
                ),
            )
        };
        let caller = match self
            .endpoint_caller(
                ask,
                &body,
                "/oauth2/device_authorization",
                true,
                false,
                &refuse,
            )
            .await
        {
            Ok(c) => c,
            Err(a) => return a,
        };
        let client_id = caller.client_id.clone();
        let declared: Option<Vec<String>> = self
            .clients
            .declared_flows_of(&client_id)
            .and_then(|f| f.get("grant_types").cloned())
            .and_then(|g| g.as_array().cloned())
            .map(|l| l.iter().map(|v| s(Some(v))).collect());
        if let Some(list) = declared {
            if !list.is_empty() && !list.iter().any(|g| g == GRANT_TYPE) {
                return self.refusal(
                    codes::STS_OAUTH_0692,
                    400,
                    "unauthorized_client",
                    &format!(
                        "client \"{}\" did not declare the device_code grant \
                         (RFC 7591 section 2).",
                        client_id
                    ),
                );
            }
        }
        let scope = s(body.get("scope")).trim().to_string();
        if !scope.is_empty() {
            if let Some(r) = self.scopes.refusal(&scope, &client_id) {
                return self.refusal(
                    r.code,
                    400,
                    "invalid_scope",
                    &r.description,
                );
            }
        }
        let mut jkt = String::new();
        if let Some(header) = dpop {
            let skew = super::sts_oauth_dpop_skew(&self.dpop);
            let reservation = crate::dpop_reservation::Reservation::reserve(
                self.claims.as_ref(),
                Some(header),
                skew,
            )
            .await;
            let checked = {
                let ctx = crate::dpop_reservation::Reserved {
                    local: self.dpop.as_ref(),
                    reservation: reservation.as_ref(),
                };
                crate::dpop::verify_proof(
                    Some(header),
                    &crate::dpop::ProofRequest {
                        htm: "POST",
                        htu,
                        access_token: None,
                        expected_jkt: None,
                        now: self.clock.now_s(),
                    },
                    &ctx,
                )
            };
            if let Some(r) = &reservation {
                r.settle(self.claims.as_ref()).await;
            }
            match checked {
                Ok(proof) => jkt = proof.jkt,
                Err(f) => {
                    return self.refusal(
                        f.code,
                        400,
                        "invalid_dpop_proof",
                        &f.description,
                    )
                }
            }
        }
        let name = self.clients.registered_client_name(&client_id);
        let made = devices.create(&client_id, &name, &scope, &jkt);
        let verification = format!("{}/portal/device", ask.base);
        let user_code = s(made.get("userCode"));
        let (head, tail) = user_code.split_at(user_code.len().min(4));
        let expires_in = ((crate::js::to_number(&made["expiresAt"])
            - crate::js::to_number(&made["createdAt"]))
            / 1000.0)
            .round() as i64;
        Answer::json(json!({
            "device_code": made["deviceCode"],
            "user_code": format!("{}-{}", head, tail),
            "verification_uri": verification,
            "verification_uri_complete": format!(
                "{}?user_code={}", verification,
                crate::js::encode_uri_component(&user_code)),
            "expires_in": expires_in,
            "interval": made["interval"],
        }))
    }
}
