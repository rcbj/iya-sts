// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! OIDC CORE SECTION 5.5, THE CLAIMS REQUEST (`oauth2.ts`'s
//! `parseClaimsRequest()`, `parseIndividualClaimRequest()`,
//! `requestedClaimNames()` and `requestedClaimsOf()`), with OpenID Connect
//! for Identity Assurance's `verified_claims` inside it
//! ([`crate::identity_assurance`]).
//!
//! WHERE IT IS READ. The authorization endpoint parses the `claims`
//! parameter (a refusal is `invalid_request`, `STS-OAUTH-0157`, sent back
//! to the client); the code carries the parsed request, and the token
//! endpoint copies it into the access token (`claims`) and the refresh
//! token, because UserInfo sees the token and nothing else. The ID Token
//! answers its `id_token` member LAST, so a claim a client named wins over
//! every layer below; UserInfo answers the `userinfo` member of the
//! token's request merged with the request's own `claims` and `claim`
//! parameters, the token's winning.
//!
//! WHAT IS ANSWERED. Each name through the claim catalogue's rows (the
//! person's entry under `ou=users`), a grouped name (`address`) as the
//! object its rows make; a name the catalogue has no row for from the six
//! claims the person object carries (`PERSONA_CLAIMS`); `verified_claims`
//! from the recorded verifications. A name nothing produces is LOGGED,
//! never refused (section 5.5.1), and `essential` changes nothing.
//! `value` and `values` are checked and reported, not honoured, on an
//! ordinary claim.
//!
//! NOT PORTED, and how this answers meanwhile: the claim names with a
//! language tag (`name#ja`), the custom attributes a realm declares, the
//! `also` claims (`address.country_code`), and the values Node INVENTS
//! where a realm invents claim values and the entry holds none — each is
//! simply not answered; the federation release policy
//! (`stats.applyClaimRelease()`), which federation's slice owns; the
//! Claims Providers (#147).

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::settings::Settings;

use crate::userinfo::{first_value, to_claim, ClaimDirectory, ROWS};

/// `CLAIMS_REQUEST_MEMBERS`.
pub const MEMBERS: [&str; 2] = ["userinfo", "id_token"];

/// `MAX_REQUESTED_CLAIMS`, the default of `oauth2.maxRequestedClaims`.
pub const MAX_REQUESTED_CLAIMS: usize = 64;

/// `PERSONA_CLAIMS`: what the person object answers that the catalogue
/// does not.
const PERSONA_CLAIMS: [&str; 6] = [
    "name",
    "given_name",
    "family_name",
    "preferred_username",
    "email",
    "email_verified",
];

fn type_word(v: &Json) -> String {
    match v {
        Json::Array(_) => "an array".into(),
        Json::String(_) => "a string".into(),
        Json::Number(_) => "a number".into(),
        Json::Bool(_) => "a boolean".into(),
        _ => "an object".into(),
    }
}

/// The claims request, parsed and answered.
pub struct RequestedClaims {
    pub directory: Arc<dyn ClaimDirectory>,
    pub settings: Arc<Settings>,
    /// `mode.inventsClaimValues()`, for Identity Assurance's demo
    /// verification.
    pub invents: Arc<dyn Fn() -> bool + Send + Sync>,
    pub now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl RequestedClaims {
    /// `maxRequestedClaims()`.
    fn max(&self) -> usize {
        match self.settings.value_of("oauth2.maxRequestedClaims").as_int() {
            n if n > 0 => n as usize,
            _ => MAX_REQUESTED_CLAIMS,
        }
    }

    /// `parseIndividualClaimRequest(member, name, raw)`.
    fn individual(
        member: &str,
        name: &str,
        raw: &Json,
    ) -> Result<Json, String> {
        let Json::Object(m) = raw else {
            if raw.is_null() {
                return Ok(Json::Null);
            }
            return Err(format!(
                "claims.{}[\"{}\"] must be null or a JSON object (OpenID \
                 Connect Core section 5.5.1); this one is {}.",
                member,
                name,
                type_word(raw)
            ));
        };
        let mut entry = Map::new();
        if let Some(e) = m.get("essential") {
            if !e.is_boolean() {
                return Err(format!(
                    "claims.{}[\"{}\"].essential must be a boolean.",
                    member, name
                ));
            }
            entry.insert("essential".into(), e.clone());
        }
        if let Some(v) = m.get("value") {
            entry.insert("value".into(), v.clone());
        }
        if let Some(v) = m.get("values") {
            if !v.as_array().is_some_and(|a| !a.is_empty()) {
                return Err(format!(
                    "claims.{}[\"{}\"].values must be a non-empty array.",
                    member, name
                ));
            }
            entry.insert("values".into(), v.clone());
        }
        Ok(if entry.is_empty() {
            Json::Null
        } else {
            Json::Object(entry)
        })
    }

    /// `parseClaimsRequest(raw)`: `Ok(None)` for no request (or one
    /// naming no member this service acts on), `Ok(Some(parsed))`, or the
    /// sentence refusing it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn parse(&self, raw: Option<&Json>) -> Result<Option<Json>, String> {
        let parsed = match raw {
            None | Some(Json::Null) => return Ok(None),
            Some(Json::String(t)) if t.is_empty() => return Ok(None),
            Some(Json::String(t)) => match serde_json::from_str::<Json>(t) {
                Ok(v) => v,
                Err(e) => {
                    return Err(format!(
                        "the claims parameter must be a JSON object (OpenID \
                         Connect Core section 5.5): {}. It is sent as \
                         ordinary URL-encoded JSON — no base64, no JWT — \
                         unless it is inside a Request Object.",
                        crate::js::json_parse_message(t, &e)
                    ))
                }
            },
            Some(other) => other.clone(),
        };
        let Json::Object(members) = parsed else {
            return Err("the claims parameter must be a JSON OBJECT with a \
                        \"userinfo\" and/or an \"id_token\" member (OpenID \
                        Connect Core section 5.5)."
                .into());
        };
        let mut out = Map::new();
        let mut ignored: Vec<String> = Vec::new();
        let mut total = 0usize;
        let max = self.max();
        for (member, value) in &members {
            if !MEMBERS.contains(&member.as_str()) {
                ignored.push(member.clone());
                continue;
            }
            if value.is_null() {
                continue;
            }
            let Json::Object(names) = value else {
                return Err(format!(
                    "claims.{} must be a JSON object whose members are claim \
                     names (OpenID Connect Core section 5.5); this one is {}.",
                    member,
                    type_word(value)
                ));
            };
            let mut bucket = Map::new();
            for (raw_name, spec) in names {
                let name = raw_name.trim();
                if name.is_empty() {
                    return Err(format!(
                        "claims.{} has a member with an empty name.",
                        member
                    ));
                }
                if name == "verified_claims" {
                    let (elements, count) =
                        crate::identity_assurance::parse_request(spec, member)?;
                    total += count;
                    if total > max {
                        return Err(format!(
                            "a claims request may name at most {} claims \
                             here, and each member of verified_claims \
                             counts as one.",
                            max
                        ));
                    }
                    bucket.insert(name.into(), Json::Array(elements));
                    continue;
                }
                total += 1;
                if total > max {
                    return Err(format!(
                        "a claims request may name at most {} claims here. \
                         The parsed request is copied into the access \
                         token, and one large enough to overflow a header \
                         would fail at a client in a way nothing points \
                         back here.",
                        max
                    ));
                }
                bucket
                    .insert(name.into(), Self::individual(member, name, spec)?);
            }
            out.insert(member.clone(), Json::Object(bucket));
        }
        if !ignored.is_empty() {
            tracing::info!(
                "A claims request carried the member(s) {}, which OpenID \
                 Connect Core section 5.5 does not define and this service \
                 therefore ignores. The two it acts on are userinfo and \
                 id_token.",
                ignored.join(", ")
            );
        }
        Ok(if out.is_empty() {
            None
        } else {
            Some(Json::Object(out))
        })
    }

    /// `requestedClaimNames(request, member)`.
    pub fn names(request: Option<&Json>, member: &str) -> Vec<String> {
        request
            .and_then(|r| r.get(member))
            .and_then(Json::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// `mergedUserinfoRequest(fromToken, fromRequest)`: the token's entry
    /// wins where both name a claim.
    pub fn merged_userinfo(
        from_token: Option<&Json>,
        from_request: Option<&Json>,
    ) -> Option<Json> {
        let mut merged = Map::new();
        for one in [from_request, from_token].into_iter().flatten() {
            if let Some(Json::Object(m)) = one.get("userinfo") {
                for (k, v) in m {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        if merged.is_empty() {
            None
        } else {
            Some(json!({ "userinfo": merged }))
        }
    }

    /// `claimAttributes.requestedClaimsFor(username, names)`: the claims
    /// the catalogue produces from the entry, and the names it cannot.
    fn catalogue(
        &self,
        username: &str,
        names: &[String],
    ) -> (Map<String, Json>, Vec<String>) {
        let mut claims = Map::new();
        let mut unknown = Vec::new();
        for name in names {
            let flat: Vec<&(&[&str], &str)> = ROWS
                .iter()
                .filter(|(path, attr)| {
                    !attr.is_empty() && path.join(".") == *name
                })
                .collect();
            let grouped: Vec<&(&[&str], &str)> = ROWS
                .iter()
                .filter(|(path, attr)| {
                    !attr.is_empty() && path.len() > 1 && path[0] == name
                })
                .collect();
            if let Some((path, attr)) = flat.first() {
                match first_value(self.directory.as_ref(), username, attr) {
                    Some(v) => {
                        let v = json!(to_claim(attr, v));
                        if path.len() > 1 {
                            let node = claims
                                .entry(path[0].to_string())
                                .or_insert_with(|| json!({}));
                            if let Json::Object(m) = node {
                                m.insert(path[1].to_string(), v);
                            }
                        } else {
                            claims.insert(name.clone(), v);
                        }
                    }
                    None => unknown.push(name.clone()),
                }
                continue;
            }
            if !grouped.is_empty() {
                let mut object = Map::new();
                for (path, attr) in grouped {
                    if let Some(v) =
                        first_value(self.directory.as_ref(), username, attr)
                    {
                        object.insert(
                            path[1].to_string(),
                            json!(to_claim(attr, v)),
                        );
                    }
                }
                if object.is_empty() {
                    unknown.push(name.clone());
                } else {
                    claims.insert(name.clone(), Json::Object(object));
                }
                continue;
            }
            unknown.push(name.clone());
        }
        (claims, unknown)
    }

    /// `requestedClaimsOf(request, member, username, user)`: the claims
    /// to merge into the answer, `verified_claims` among them.
    #[tracing::instrument(level = "debug", skip(self, request, user))]
    pub fn answer(
        &self,
        request: Option<&Json>,
        member: &str,
        username: &str,
        user: &Json,
    ) -> Map<String, Json> {
        let names: Vec<String> = Self::names(request, member)
            .into_iter()
            .filter(|n| n != "verified_claims")
            .collect();
        let mut out = Map::new();
        if let Some(asked) = request
            .and_then(|r| r.get(member))
            .and_then(|m| m.get("verified_claims"))
        {
            let elements: Vec<Json> = match asked {
                Json::Array(a) => a.clone(),
                other => vec![other.clone()],
            };
            let as_array = asked.as_array().is_some_and(|a| a.len() > 1);
            let (value, _) = crate::identity_assurance::respond(
                self,
                username,
                &elements,
                as_array,
                (self.invents)(),
                (self.now_ms)(),
            );
            if let Some(v) = value {
                out.insert("verified_claims".into(), v);
            }
        }
        if names.is_empty() {
            return out;
        }
        let (built, unknown) = self.catalogue(username, &names);
        let mut claims = built;
        for (k, v) in out {
            claims.insert(k, v);
        }
        let mut unresolved = Vec::new();
        for name in unknown {
            match user.get(&name) {
                Some(v)
                    if PERSONA_CLAIMS.contains(&name.as_str())
                        && !v.is_null() =>
                {
                    claims.insert(name, v.clone());
                }
                _ => unresolved.push(name),
            }
        }
        if !unresolved.is_empty() {
            tracing::info!(
                "oauth2: the {} claims request named {} that nothing here \
                 produces for {}; not refused (OpenID Connect Core section \
                 5.5.1).",
                member,
                unresolved.join(", "),
                username
            );
        }
        claims
    }
}

impl crate::identity_assurance::Verifications for RequestedClaims {
    fn records(&self, username: &str) -> Vec<Json> {
        let raw = self
            .directory
            .values_of(username, crate::identity_assurance::ATTRIBUTE)
            .and_then(|v| v.into_iter().next());
        crate::identity_assurance::list(raw.as_deref(), username)
    }

    fn current(&self, username: &str, names: &[String]) -> Map<String, Json> {
        self.catalogue(username, names).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Entry;
    impl ClaimDirectory for Entry {
        fn values_of(&self, _u: &str, a: &str) -> Option<Vec<String>> {
            match a.to_ascii_lowercase().as_str() {
                "givenname" => Some(vec!["OIDC".into()]),
                "sn" => Some(vec!["alice".into()]),
                "l" => Some(vec!["Testville".into()]),
                "c" => Some(vec!["US".into()]),
                _ => None,
            }
        }
    }

    fn claims() -> RequestedClaims {
        RequestedClaims {
            directory: Arc::new(Entry),
            settings: Arc::new(Settings::new(
                Json::Null,
                std::collections::HashMap::new(),
            )),
            invents: Arc::new(|| false),
            now_ms: Arc::new(|| 0),
        }
    }

    #[test]
    fn a_member_that_is_not_an_object_is_refused_in_nodes_words() {
        let e = claims()
            .parse(Some(&json!("{\"userinfo\": [1]}")))
            .unwrap_err();
        assert_eq!(
            e,
            "claims.userinfo must be a JSON object whose members are claim \
             names (OpenID Connect Core section 5.5); this one is an array."
        );
    }

    #[test]
    fn a_grouped_name_answers_the_object_its_rows_make() {
        let c = claims();
        let request = c
            .parse(Some(&json!(
                "{\"id_token\":{\"address\":null,\
                \"given_name\":{\"essential\":true}}}"
            )))
            .unwrap();
        let out = c.answer(request.as_ref(), "id_token", "alice", &json!({}));
        assert_eq!(
            Json::Object(out),
            json!({ "address": { "locality": "Testville", "country": "US" },
                    "given_name": "OIDC" })
        );
    }
}
