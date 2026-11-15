// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! CIBA's grant at the token endpoint (`oauth2.ts`'s
//! `urn:openid:params:grant-type:ciba` branch, section 10.1): a poll or
//! ping client redeems an approved `auth_req_id`, each refusal Node's code,
//! error and sentence. See [`crate::ciba`] for what is Node's still.

use serde_json::Value as Json;
use sts_core::errors::codes;

use super::{s, Issuing, Mint, TokenEndpoint};
use crate::answer::Answer;

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
