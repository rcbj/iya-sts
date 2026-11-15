// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREDENTIALS BOUND TO AN ENTRY — the ACME External Account Binding key
//! and the SCEP challenge password — and an administrator's registered
//! host names (`createEab()`, `findEab()`, `bindEab()`, `bindEabOnce()`,
//! `deleteEab()`, `createScepChallenge()`, `redeemScepChallenge()`,
//! `redeemScepChallengeOnce()`, `deleteScepChallenge()`, `changeHostName()`).
//!
//! **THE IDENTIFIER NAMES THE ENTRY** — `eab-p-<base64url(id)>-<16 hex>`,
//! `scep-p-…-<16 hex>.<secret>` — so neither needs a register or a scan; a
//! guessed prefix gains nothing, the MAC key or the secret authenticates.
//! In a single-cell service no cell tag follows the hex, as Node's
//! `cellLocator.stamp()` appends none there.
//!
//! The records are Node's JSON, member for member: an EAB key's MAC key is
//! sealed where key material persists; a challenge keeps only the SHA-256
//! of its secret.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_core::errors::codes;

use super::{
    iso, ms_of, normal_host_name, now_ms, parse_json_values, str_of, stringify,
    well_formed_id, Core, Entry, Outcome, Refusal, MAX_CREDENTIALS_PER_ENTRY,
};

/// How long an EAB key's claim is held — see `bind_eab_once()`.
const EAB_CLAIM_TTL_MS: f64 = 30.0 * 24.0 * 60.0 * 60.0 * 1000.0;

/// `findEab()`'s answer.
#[derive(Debug, Clone)]
pub struct FoundEab {
    pub entry: Entry,
    pub kid: String,
    pub hmac_key: Vec<u8>,
    pub expired: bool,
    pub bound_account: Option<String>,
    pub expires_at: String,
}

/// `createEab()`'s answer: the MAC key is shown ONCE.
#[derive(Debug, Clone)]
pub struct CreatedEab {
    pub kid: String,
    pub hmac_key: String,
    pub alg: String,
    pub expires_at: String,
    pub target: Entry,
}

/// `redeemScepChallenge()`'s answer.
#[derive(Debug, Clone)]
pub struct Redeemed {
    pub id: String,
    pub entry: Entry,
    pub profile: String,
}

/// `createScepChallenge()`'s answer.
#[derive(Debug, Clone)]
pub struct CreatedChallenge {
    pub id: String,
    pub challenge: String,
    pub profile: String,
    pub expires_at: String,
    pub target: Entry,
}

fn random_hex(n: usize) -> String {
    sts_crypto::random::random_bytes(n)
        .map(|b| sts_pki::der::hex(&b))
        .unwrap_or_default()
}

fn random_b64url(n: usize) -> String {
    sts_crypto::random::random_bytes(n)
        .map(|b| URL_SAFE_NO_PAD.encode(b))
        .unwrap_or_default()
}

/// `credentialId(prefix, entry)`.
#[tracing::instrument(level = "debug")]
pub fn credential_id(prefix: &str, entry: &Entry) -> String {
    format!(
        "{}-{}-{}-{}",
        prefix,
        if entry.kind == "person" { "p" } else { "a" },
        URL_SAFE_NO_PAD.encode(entry.id.as_bytes()),
        random_hex(8)
    )
}

/// `entryOfCredentialId(prefix, id)`: the entry a credential id names,
/// canonical base64url only; the twelve-character cell tag Node may append
/// after the hex is accepted.
#[tracing::instrument(level = "debug")]
pub fn entry_of_credential_id(prefix: &str, id: &str) -> Option<Entry> {
    let re = regex::Regex::new(&format!(
        "^{}-([pa])-([A-Za-z0-9_-]{{1,400}})-([0-9a-f]{{16}})(?:[A-Za-z0-9_-]{{12}})?$",
        regex::escape(prefix)
    ))
    .ok()?;
    let m = re.captures(id)?;
    let encoded = m.get(2)?.as_str();
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    if !well_formed_id(&decoded)
        || URL_SAFE_NO_PAD.encode(decoded.as_bytes()) != encoded
    {
        return None;
    }
    let kind = if m.get(1)?.as_str() == "p" {
        "person"
    } else {
        "application"
    };
    Some(Entry::new(kind, &decoded))
}

impl Core {
    fn lifetime_of(&self, asked: Option<i64>, setting: &str) -> i64 {
        let configured = self.setting_int(setting);
        match asked {
            Some(w) if w >= 60 && w <= configured => w,
            _ => configured,
        }
    }

    fn signal_enrolment_credential(
        &self,
        entry: &Entry,
        which: &str,
        change: &str,
        by: &str,
        id: &str,
    ) {
        if entry.kind != "person" && entry.kind != "application" {
            return;
        }
        let what = if which == "eab" {
            "ACME External Account Binding key"
        } else {
            "SCEP challenge password"
        };
        let done = if change == "create" {
            "created"
        } else {
            "deleted"
        };
        self.d.signals.credential_changed(&json!({
            "username": if entry.kind == "person" { entry.id.clone() } else { String::new() },
            "application": if entry.kind == "application" { entry.id.clone() } else { String::new() },
            "credentialType": if which == "eab" { "acme-eab-key" } else { "password" },
            "changeType": change,
            "initiatingEntity": if !by.is_empty() && by == entry.id { "user" } else { "admin" },
            "friendlyName": format!("{} {}", what, id),
            "via": if which == "eab" { "ACME" } else { "SCEP" },
            "reasonAdmin": format!("An {} of {} was {}.", what, entry.id, done),
            "reasonUser": format!("An {} of yours was {}.", what, done),
        }));
    }

    /// `createEab({ target, lifetimeS, createdBy })`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn create_eab(
        &self,
        target: &Entry,
        lifetime_s: Option<i64>,
        created_by: &str,
    ) -> Outcome<CreatedEab> {
        let resolved = self.resolve_entry(&target.kind, &target.id)?;
        let now = now_ms();
        let kept: Vec<Json> = parse_json_values(&resolved.held("eab"))
            .into_iter()
            .filter(|one| {
                one.get("boundAccount")
                    .is_some_and(|b| !b.is_null() && b != &json!(""))
                    || ms_of(str_of(one, "expiresAt")) > now
            })
            .collect();
        let unbound = kept
            .iter()
            .filter(|one| {
                !one.get("boundAccount")
                    .is_some_and(|b| !b.is_null() && b != &json!(""))
            })
            .count();
        if unbound >= MAX_CREDENTIALS_PER_ENTRY {
            return Err(Refusal::new(
                codes::STS_ENROLL_0044,
                409,
                format!(
                    "The {} already has {} unused EAB keys. Delete one first.",
                    resolved.entry.label(),
                    MAX_CREDENTIALS_PER_ENTRY
                ),
            ));
        }
        let kid = credential_id("eab", &resolved.entry);
        let hmac_key = random_b64url(32);
        let Some(sealed) = self.seal_text(
            &hmac_key,
            "acme-eab-key",
            if resolved.entry.kind == "person" {
                "cell"
            } else {
                ""
            },
        ) else {
            return Err(Refusal::new(
                codes::STS_ENROLL_0043,
                503,
                "The EAB key could not be sealed for storage.",
            ));
        };
        let lifetime = self.lifetime_of(lifetime_s, "acme.eabLifetimeS");
        let record = json!({
            "kid": kid,
            "hmacKey": sealed,
            "createdAt": iso(now),
            "expiresAt": iso(now + lifetime as f64 * 1000.0),
            "createdBy": created_by,
            "boundAccount": null,
            "boundAt": null,
        });
        let mut values: Vec<String> = kept.iter().map(stringify).collect();
        values.push(stringify(&record));
        if !self.write_attribute(&resolved.entry, "eab", &values) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0041,
                503,
                format!(
                    "The EAB key could not be written onto the {}.",
                    resolved.entry.label()
                ),
            ));
        }
        self.d.audit.record(&json!({
            "category": "configuration", "action": "enrollment.eab.create",
            "protocol": "ACME", "outcome": "success", "actor": created_by,
            "target": resolved.entry.uri(),
            "summary": format!("an ACME External Account Binding key was created for the {}",
                resolved.entry.label()),
            "detail": { "kid": kid, "expiresAt": record["expiresAt"] },
        }));
        self.signal_enrolment_credential(
            &resolved.entry,
            "eab",
            "create",
            created_by,
            &kid,
        );
        Ok(CreatedEab {
            kid,
            hmac_key,
            alg: "HS256".into(),
            expires_at: str_of(&record, "expiresAt").to_string(),
            target: resolved.entry,
        })
    }

    /// `findEab(kid)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn find_eab(&self, kid: &str) -> Option<FoundEab> {
        let entry = entry_of_credential_id("eab", kid)?;
        let values = self.read_attribute(&entry, "eab")?;
        let record = parse_json_values(&values)
            .into_iter()
            .find(|one| str_of(one, "kid") == kid)?;
        let opened =
            self.open_text(str_of(&record, "hmacKey"), "acme-eab-key")?;
        let bound = record
            .get("boundAccount")
            .and_then(Json::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        Some(FoundEab {
            entry,
            kid: str_of(&record, "kid").to_string(),
            hmac_key: URL_SAFE_NO_PAD
                .decode(opened.trim_end_matches('='))
                .unwrap_or_default(),
            expired: ms_of(str_of(&record, "expiresAt")) <= now_ms(),
            bound_account: bound,
            expires_at: str_of(&record, "expiresAt").to_string(),
        })
    }

    /// `bindEab(kid, accountThumbprint)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn bind_eab(&self, kid: &str, thumbprint: &str) -> Outcome<Entry> {
        let unknown = || {
            Refusal::new(
                codes::STS_ENROLL_0080,
                401,
                "The External Account Binding key is not known in this realm.",
            )
        };
        let entry = entry_of_credential_id("eab", kid).ok_or_else(unknown)?;
        let values = self.read_attribute(&entry, "eab").ok_or_else(unknown)?;
        let mut result: Option<Outcome<Entry>> = None;
        let rewritten: Vec<Json> = parse_json_values(&values)
            .into_iter()
            .map(|mut one| {
                if str_of(&one, "kid") != kid {
                    return one;
                }
                let bound = str_of(&one, "boundAccount").to_string();
                if !bound.is_empty() && bound != thumbprint {
                    result = Some(Err(Refusal::new(
                        codes::STS_ENROLL_0081,
                        401,
                        "That External Account Binding key has already bound another account.",
                    )));
                    return one;
                }
                if ms_of(str_of(&one, "expiresAt")) <= now_ms() && bound.is_empty() {
                    result = Some(Err(Refusal::new(
                        codes::STS_ENROLL_0082,
                        401,
                        "That External Account Binding key has expired.",
                    )));
                    return one;
                }
                if bound.is_empty() {
                    one["boundAccount"] = Json::from(thumbprint);
                    one["boundAt"] = Json::from(iso(now_ms()));
                }
                result = Some(Ok(entry.clone()));
                one
            })
            .collect();
        let result = result.ok_or_else(unknown)?;
        if result.is_ok() {
            let values: Vec<String> = rewritten.iter().map(stringify).collect();
            let _written = self.write_attribute(&entry, "eab", &values);
        }
        result
    }

    /// `bindEabOnce(kid, accountThumbprint)`: the key id claimed before
    /// the binding is written, so two accounts cannot both bind it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn bind_eab_once(
        &self,
        kid: &str,
        thumbprint: &str,
    ) -> Outcome<Entry> {
        let known = self.find_eab(kid);
        if known.as_ref().and_then(|k| k.bound_account.as_deref())
            == Some(thumbprint)
        {
            return self.bind_eab(kid, thumbprint);
        }
        let claimed = self
            .d
            .claims
            .claim("acme.eab-bind", kid, "", EAB_CLAIM_TTL_MS)
            .await;
        match claimed {
            Err(sts_cluster::scheduler::ClaimRefused::Held) => {
                if known.as_ref().is_some_and(|k| k.bound_account.is_some()) {
                    return self.bind_eab(kid, thumbprint);
                }
                tracing::warn!(
                    "cert_enrollment: an External Account Binding key was presented for a new \
                     account while it is being or has been bound to another, on this node or \
                     another. Refused."
                );
                Err(Refusal::new(
                    codes::STS_ENROLL_0081,
                    401,
                    "That External Account Binding key has already bound another account.",
                ))
            }
            Err(e) => {
                tracing::error!(
                    "{}cert_enrollment: an External Account Binding key could not be proved \
                     unbound ({:?}), so it was refused.",
                    sts_core::log::tag(codes::STS_ENROLL_0091.as_str()),
                    e
                );
                Err(Refusal::new(
                    codes::STS_ENROLL_0091,
                    503,
                    "The External Account Binding key could not be checked just now. Try again.",
                ))
            }
            Ok(claim) => {
                let bound = self.bind_eab(kid, thumbprint);
                if bound.is_err() {
                    self.d.claims.release(&claim.handle).await;
                }
                bound
            }
        }
    }

    /// `deleteEab(kid, by)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn delete_eab(&self, kid: &str, by: &str) -> Outcome<Entry> {
        let none = || {
            Refusal::new(
                codes::STS_ENROLL_0080,
                404,
                "There is no such External Account Binding key in this realm.",
            )
        };
        let entry = entry_of_credential_id("eab", kid).ok_or_else(none)?;
        let records = parse_json_values(
            &self.read_attribute(&entry, "eab").unwrap_or_default(),
        );
        let left: Vec<String> = records
            .iter()
            .filter(|o| str_of(o, "kid") != kid)
            .map(stringify)
            .collect();
        if left.len() == records.len() {
            return Err(none());
        }
        let _written = self.write_attribute(&entry, "eab", &left);
        self.d.audit.record(&json!({
            "category": "configuration", "action": "enrollment.eab.delete",
            "protocol": "ACME", "outcome": "success", "actor": by, "target": entry.uri(),
            "summary": "an ACME External Account Binding key was deleted",
            "detail": { "kid": kid },
        }));
        self.signal_enrolment_credential(&entry, "eab", "delete", by, kid);
        Ok(entry)
    }

    /// `eabsFrom(values)`, the public view of each key.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn eabs_from(values: &[String]) -> Vec<Json> {
        let now = now_ms();
        parse_json_values(values)
            .iter()
            .map(|one| {
                let bound = one.get("boundAccount").cloned().filter(|b| !b.is_null()).unwrap_or(Json::Null);
                let status = if !bound.is_null() && bound != json!("") {
                    "bound"
                } else if ms_of(str_of(one, "expiresAt")) <= now {
                    "expired"
                } else {
                    "unused"
                };
                json!({ "kid": one["kid"], "createdAt": one["createdAt"],
                        "expiresAt": one["expiresAt"], "createdBy": one["createdBy"],
                        "boundAccount": bound, "boundAt": one.get("boundAt").cloned().unwrap_or(Json::Null),
                        "status": status })
            })
            .collect()
    }

    /// `createScepChallenge({ target, profile, lifetimeS, createdBy })`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn create_scep_challenge(
        &self,
        target: &Entry,
        profile: Option<&str>,
        lifetime_s: Option<i64>,
        created_by: &str,
    ) -> Outcome<CreatedChallenge> {
        let wanted = profile
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| self.default_profile("scep", Some(target)));
        let profile =
            self.check_profile("scep", &wanted, Some(target), false)?;
        let resolved = self.resolve_entry(&target.kind, &target.id)?;
        let now = now_ms();
        let kept: Vec<Json> = parse_json_values(&resolved.held("challenge"))
            .into_iter()
            .filter(|one| {
                ms_of(str_of(one, "expiresAt")) > now
                    && one
                        .get("usedAt")
                        .is_none_or(|u| u.is_null() || u == &json!(""))
            })
            .collect();
        if kept.len() >= MAX_CREDENTIALS_PER_ENTRY {
            return Err(Refusal::new(
                codes::STS_ENROLL_0044,
                409,
                format!(
                    "The {} already has {} unused SCEP challenges. Delete one first.",
                    resolved.entry.label(),
                    MAX_CREDENTIALS_PER_ENTRY
                ),
            ));
        }
        let id = credential_id("scep", &resolved.entry);
        let secret = random_b64url(24);
        let lifetime = self.lifetime_of(lifetime_s, "scep.challengeLifetimeS");
        let record = json!({
            "id": id,
            "sha256": sts_pki::der::hex(&sts_crypto::jws_alg::Hash::Sha256.digest(secret.as_bytes())),
            "profile": profile,
            "createdAt": iso(now),
            "expiresAt": iso(now + lifetime as f64 * 1000.0),
            "createdBy": created_by,
            "usedAt": null,
        });
        let mut values: Vec<String> = kept.iter().map(stringify).collect();
        values.push(stringify(&record));
        if !self.write_attribute(&resolved.entry, "challenge", &values) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0041,
                503,
                format!(
                    "The challenge could not be written onto the {}.",
                    resolved.entry.label()
                ),
            ));
        }
        self.d.audit.record(&json!({
            "category": "configuration", "action": "enrollment.challenge.create",
            "protocol": "SCEP", "outcome": "success", "actor": created_by,
            "target": resolved.entry.uri(),
            "summary": format!("a SCEP challenge password was created for the {} ({})",
                resolved.entry.label(), profile),
            "detail": { "id": id, "profile": profile, "expiresAt": record["expiresAt"] },
        }));
        self.signal_enrolment_credential(
            &resolved.entry,
            "scep",
            "create",
            created_by,
            &id,
        );
        Ok(CreatedChallenge {
            challenge: format!("{}.{}", id, secret),
            id,
            profile,
            expires_at: str_of(&record, "expiresAt").to_string(),
            target: resolved.entry,
        })
    }

    /// `redeemScepChallenge(challenge, { peek })`.
    #[tracing::instrument(level = "debug", skip(self, challenge))]
    pub fn redeem_scep_challenge(
        &self,
        challenge: &str,
        peek: bool,
    ) -> Outcome<Redeemed> {
        let generic = || {
            Refusal::new(
                codes::STS_ENROLL_0083,
                401,
                "The challenge password was not accepted.",
            )
        };
        let dot = challenge.rfind('.').filter(|d| *d > 0);
        let (id, secret) = match dot {
            Some(d) => (&challenge[..d], &challenge[d + 1..]),
            None => ("", ""),
        };
        let entry = entry_of_credential_id("scep", id).ok_or_else(generic)?;
        let values = self
            .read_attribute(&entry, "challenge")
            .ok_or_else(generic)?;
        if secret.is_empty() || secret.encode_utf16().count() > 128 {
            return Err(generic());
        }
        let mut records = parse_json_values(&values);
        let Some(index) =
            records.iter().position(|one| str_of(one, "id") == id)
        else {
            return Err(generic());
        };
        let presented =
            sts_crypto::jws_alg::Hash::Sha256.digest(secret.as_bytes());
        let expected = hex_bytes(str_of(&records[index], "sha256"));
        if expected.len() != presented.len()
            || !sts_crypto::secrets::constant_time_equals(&presented, &expected)
        {
            return Err(generic());
        }
        let record = &records[index];
        if record
            .get("usedAt")
            .is_some_and(|u| !u.is_null() && u != &json!(""))
        {
            return Err(Refusal::new(
                codes::STS_ENROLL_0084,
                401,
                "That challenge password has already been used.",
            ));
        }
        if ms_of(str_of(record, "expiresAt")) <= now_ms() {
            return Err(Refusal::new(
                codes::STS_ENROLL_0085,
                401,
                "That challenge password has expired.",
            ));
        }
        let profile = str_of(record, "profile").to_string();
        if !peek {
            records[index]["usedAt"] = Json::from(iso(now_ms()));
            let values: Vec<String> = records.iter().map(stringify).collect();
            let _written = self.write_attribute(&entry, "challenge", &values);
        }
        Ok(Redeemed {
            id: id.to_string(),
            entry,
            profile,
        })
    }

    /// `redeemScepChallengeOnce(challenge)`: claimed between the look and
    /// the write, so two requests at two nodes cannot both spend it.
    #[tracing::instrument(level = "debug", skip(self, challenge))]
    pub async fn redeem_scep_challenge_once(
        &self,
        challenge: &str,
    ) -> Outcome<Redeemed> {
        let peek = self.redeem_scep_challenge(challenge, true)?;
        let expires = parse_json_values(
            &self
                .read_attribute(&peek.entry, "challenge")
                .unwrap_or_default(),
        )
        .into_iter()
        .find(|one| str_of(one, "id") == peek.id)
        .map(|one| ms_of(str_of(&one, "expiresAt")))
        .unwrap_or(f64::NAN);
        let remaining = expires - now_ms();
        let ttl = (if remaining.is_finite() {
            remaining
        } else {
            0.0
        } + 60_000.0)
            .max(60_000.0);
        match self
            .d
            .claims
            .claim("scep.challenge", &peek.id, "", ttl)
            .await
        {
            Err(sts_cluster::scheduler::ClaimRefused::Held) => {
                tracing::warn!(
                    "cert_enrollment: a SCEP challenge password was presented while another \
                     request is spending it or has spent it, on this node or another. Refused."
                );
                Err(Refusal::new(
                    codes::STS_ENROLL_0084,
                    401,
                    "That challenge password has already been used.",
                ))
            }
            Err(e) => {
                tracing::error!(
                    "{}cert_enrollment: a SCEP challenge password could not be proved unspent \
                     ({:?}), so it was refused.",
                    sts_core::log::tag(codes::STS_ENROLL_0091.as_str()),
                    e
                );
                Err(Refusal::new(
                    codes::STS_ENROLL_0091,
                    503,
                    "The challenge password could not be checked just now. Try again.",
                ))
            }
            Ok(claim) => {
                let spent = self.redeem_scep_challenge(challenge, false);
                if spent.is_err() {
                    self.d.claims.release(&claim.handle).await;
                }
                spent
            }
        }
    }

    /// `deleteScepChallenge(id, by)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn delete_scep_challenge(&self, id: &str, by: &str) -> Outcome<Entry> {
        let none = || {
            Refusal::new(
                codes::STS_ENROLL_0083,
                404,
                "There is no such SCEP challenge in this realm.",
            )
        };
        let entry = entry_of_credential_id("scep", id).ok_or_else(none)?;
        let records = parse_json_values(
            &self.read_attribute(&entry, "challenge").unwrap_or_default(),
        );
        let left: Vec<String> = records
            .iter()
            .filter(|o| str_of(o, "id") != id)
            .map(stringify)
            .collect();
        if left.len() == records.len() {
            return Err(none());
        }
        let _written = self.write_attribute(&entry, "challenge", &left);
        self.d.audit.record(&json!({
            "category": "configuration", "action": "enrollment.challenge.delete",
            "protocol": "SCEP", "outcome": "success", "actor": by, "target": entry.uri(),
            "summary": "a SCEP challenge password was deleted", "detail": { "id": id },
        }));
        self.signal_enrolment_credential(&entry, "scep", "delete", by, id);
        Ok(entry)
    }

    /// `changeHostName(entry, name, add, by)`: an administrator's act.
    /// The names now held.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn change_host_name(
        &self,
        entry: &Entry,
        name: &str,
        add: bool,
        by: &str,
    ) -> Outcome<Vec<String>> {
        let resolved = self.resolve_entry(&entry.kind, &entry.id)?;
        let host = normal_host_name(name);
        if host.is_empty() {
            let shown: String = name
                .encode_utf16()
                .take(253)
                .collect::<Vec<u16>>()
                .iter()
                .map(|&u| char::from_u32(u as u32).unwrap_or('?'))
                .collect();
            return Err(Refusal::new(
                codes::STS_ENROLL_0057,
                400,
                format!("\"{}\" is not a DNS name or an IP address.", shown),
            ));
        }
        let current = resolved.host_names.clone();
        let has = current.contains(&host);
        if add && has {
            return Ok(current);
        }
        if !add && !has {
            return Err(Refusal::new(
                codes::STS_ENROLL_0058,
                404,
                format!(
                    "\"{}\" is not registered on the {}.",
                    host,
                    resolved.entry.label()
                ),
            ));
        }
        let next: Vec<String> = if add {
            let mut n = current.clone();
            n.push(host.clone());
            n
        } else {
            current.into_iter().filter(|h| *h != host).collect()
        };
        if !self.write_attribute(&resolved.entry, "hostName", &next) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0041,
                503,
                "The host name could not be written.",
            ));
        }
        self.d.audit.record(&json!({
            "category": "configuration",
            "action": if add { "enrollment.hostname.add" } else { "enrollment.hostname.remove" },
            "outcome": "success", "actor": by, "target": resolved.entry.uri(),
            "summary": format!("the host name {} was {} the {}", host,
                if add { "registered on" } else { "removed from" }, resolved.entry.label()),
            "detail": { "hostName": host },
        }));
        Ok(next)
    }
}

fn hex_bytes(text: &str) -> Vec<u8> {
    // `Buffer.from(text, 'hex')`: pairs until the first that is not hex.
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        let pair = std::str::from_utf8(&b[i..i + 2]).ok();
        match pair.and_then(|p| u8::from_str_radix(p, 16).ok()) {
            Some(v) => out.push(v),
            None => break,
        }
        i += 2;
    }
    out
}
