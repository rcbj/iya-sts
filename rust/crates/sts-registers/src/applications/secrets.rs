// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! AN APPLICATION'S CLIENT SECRETS (#49 P5, several since 2026-10-01):
//! `parseClientSecretValue()`, `formatClientSecretRecord()`,
//! `clientSecretRecordsOf()`, `primaryClientSecretOf()`,
//! `clientSecretSummariesOf()`, `putClientSecret()`, and the four acts —
//! `addClientSecret()`, `removeClientSecret()`, `rotateClientSecret()`
//! and `regenerateClientSecret()` — with `finishClientSecretWrite()`.
//!
//! A secret is stored as a JSON record `{id, secret, created, expires,
//! description?}`, sealed under the key-encryption key where keys persist;
//! a bare value (an `ldapmodify`, an older entry) reads as a record whose
//! id is the digest of the secret. The newest unexpired secret is the
//! primary: the one this service signs and encrypts with.

use serde_json::{json, Map, Value};
use sts_core::errors::codes;

use super::checks::Coded;
use super::record::{first_of, iso_string, values_of, Fields, Record};
use super::{refused, ApplicationRegistry, Marked};

/// One client secret.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SecretRecord {
    pub id: String,
    pub secret: String,
    /// Seconds.
    pub created_at: i64,
    /// Seconds; 0 never expires.
    pub expires_at: i64,
    pub description: String,
}

const CLIENT_SECRET_LABEL: &str = "client-secret";

/// `REGISTRATION_TOKEN_LABEL`.
pub const REGISTRATION_TOKEN_LABEL: &str = "registration-access-token";

// `Math.max(0, Math.floor(Number(x) || 0))` over a JSON member.
fn whole_seconds(value: Option<&Value>) -> i64 {
    let n = match value {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => js_number(s),
        Some(Value::Bool(true)) => 1.0,
        _ => 0.0,
    };
    if !n.is_finite() {
        return 0;
    }
    (n.floor() as i64).max(0)
}

impl ApplicationRegistry {
    // `digestSecretId(secret)`.
    fn digest_secret_id(&self, secret: &str) -> String {
        let hex = self.env.sha256_hex(secret);
        format!("cs-{}", &hex[..12.min(hex.len())])
    }

    // `newSecretId()`.
    fn new_secret_id(&self) -> String {
        let bytes = self.env.random_bytes(6);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        format!("cs-{hex}")
    }

    /// `mintClientSecret()`: `oauth2.registeredSecretBytes` random bytes,
    /// base64url.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn mint_client_secret(&self) -> String {
        let n = self.client_secret_bytes();
        sts_crypto::b64::encode(&self.env.random_bytes(n))
    }

    fn client_secret_bytes(&self) -> usize {
        self.env
            .setting("oauth2.registeredSecretBytes")
            .as_f64()
            .unwrap_or(0.0)
            .max(0.0) as usize
    }

    // `openCredentialText(text, label, what)`: '' when it will not open.
    pub(crate) fn open_credential_text(
        &self,
        text: &str,
        label: &str,
    ) -> String {
        self.env.open(text, label).unwrap_or_default()
    }

    /// `sealCredentialText(text, label, what)`: sealed where client
    /// secrets are, STS-REG-0213 when the seal fails.
    #[tracing::instrument(level = "debug", skip(self, text))]
    pub fn seal_credential_text(
        &self,
        text: &str,
        label: &str,
        what: &str,
    ) -> Result<String, Coded> {
        if !self.env.seals_client_secrets() {
            return Ok(text.to_string());
        }
        self.env.seal(text, label).ok_or_else(|| {
            Coded::new(
                codes::STS_REG_0213,
                format!(
                    "{} could not be encrypted, so it was not stored. Storing \
                     it in the clear where keys persist would put a working \
                     credential in every directory dump. The key-encryption \
                     key is the one /admin/persistence reports on.",
                    what
                ),
            )
        })
    }

    /// `parseClientSecretValue(value)`: a stored value as a record, or
    /// None for an empty one.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn parse_client_secret_value(
        &self,
        value: &str,
    ) -> Option<SecretRecord> {
        let stored = crate::js::trim(value).to_string();
        let opened = if self.env.is_sealed(&stored) {
            self.open_credential_text(&stored, CLIENT_SECRET_LABEL)
        } else {
            stored
        };
        let text = crate::js::trim(&opened).to_string();
        if text.is_empty() {
            return None;
        }
        if text.starts_with('{') {
            if let Ok(Value::Object(parsed)) =
                serde_json::from_str::<Value>(&text)
            {
                if let Some(Value::String(secret)) = parsed.get("secret") {
                    if !secret.is_empty() {
                        let id = parsed
                            .get("id")
                            .filter(|v| crate::js::truthy(v))
                            .map(crate::js::string)
                            .unwrap_or_else(|| self.digest_secret_id(secret));
                        return Some(SecretRecord {
                            id,
                            secret: secret.clone(),
                            created_at: whole_seconds(parsed.get("created")),
                            expires_at: whole_seconds(parsed.get("expires")),
                            description: crate::js::or_empty(
                                parsed.get("description"),
                            ),
                        });
                    }
                }
            }
        }
        Some(SecretRecord {
            id: self.digest_secret_id(&text),
            secret: text,
            ..SecretRecord::default()
        })
    }

    /// `formatClientSecretRecord(record)`: the JSON record, sealed.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn format_client_secret_record(
        &self,
        record: &SecretRecord,
    ) -> Result<String, Coded> {
        let mut out = Map::new();
        out.insert("id".into(), Value::String(record.id.clone()));
        out.insert("secret".into(), Value::String(record.secret.clone()));
        out.insert("created".into(), json!(record.created_at));
        out.insert("expires".into(), json!(record.expires_at));
        if !record.description.is_empty() {
            out.insert(
                "description".into(),
                Value::String(record.description.clone()),
            );
        }
        let text =
            serde_json::to_string(&Value::Object(out)).unwrap_or_default();
        self.seal_credential_text(&text, CLIENT_SECRET_LABEL, "A client secret")
    }

    /// `clientSecretRecordsOf(fields)`: each distinct secret once, newest
    /// first, ties in stored order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn client_secret_records_of(
        &self,
        fields: &Fields,
    ) -> Vec<SecretRecord> {
        let mut seen: Vec<String> = Vec::new();
        let mut records: Vec<SecretRecord> = Vec::new();
        for one in values_of(fields.get("oauthClientSecret")) {
            if let Some(r) = self.parse_client_secret_value(&one) {
                if seen.contains(&r.secret) {
                    continue;
                }
                seen.push(r.secret.clone());
                records.push(r);
            }
        }
        // A stable sort on createdAt, descending: ties keep their order.
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        records
    }

    pub(crate) fn now_sec(&self) -> i64 {
        self.env.now_ms().div_euclid(1000)
    }

    /// `primaryClientSecretOf(fields, nowS)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn primary_client_secret_of(
        &self,
        fields: &Fields,
        now_s: Option<i64>,
    ) -> Option<SecretRecord> {
        let at = now_s.unwrap_or_else(|| self.now_sec());
        let records = self.client_secret_records_of(fields);
        records
            .iter()
            .find(|one| !expired(one, at))
            .cloned()
            .or_else(|| records.first().cloned())
    }

    /// `secretExpiryOf(fields)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn secret_expiry_of(&self, fields: &Fields) -> i64 {
        self.primary_client_secret_of(fields, None)
            .map(|p| p.expires_at)
            .unwrap_or(0)
    }

    /// `clientSecretSummariesOf(fields, nowS)`: what a page may show of
    /// each secret — never the secret.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn client_secret_summaries_of(
        &self,
        fields: &Fields,
        now_s: Option<i64>,
    ) -> Vec<Value> {
        let at = now_s.unwrap_or_else(|| self.now_sec());
        let primary = self.primary_client_secret_of(fields, Some(at));
        self.client_secret_records_of(fields)
            .into_iter()
            .map(|one| {
                json!({
                    "id": one.id,
                    "createdAt": one.created_at,
                    "expiresAt": one.expires_at,
                    "description": one.description,
                    "expired": expired(&one, at),
                    "primary": primary.as_ref().is_some_and(|p| p.id == one.id),
                })
            })
            .collect()
    }

    // `defaultClientSecretExpiry(nowS)`.
    fn default_client_secret_expiry(&self, now_s: i64) -> i64 {
        let days = self
            .env
            .setting("oauth2.clientSecretLifetimeDays")
            .as_f64()
            .unwrap_or(0.0);
        if days.is_finite() && days > 0.0 {
            now_s + (days.floor() as i64) * 86_400
        } else {
            0
        }
    }

    /// `newClientSecretRecord(secret, {expiresAt, description})`.
    #[tracing::instrument(level = "debug", skip(self, secret))]
    pub fn new_client_secret_record(
        &self,
        secret: &str,
        expires_at: Option<i64>,
        description: &str,
    ) -> SecretRecord {
        let at = self.now_sec();
        SecretRecord {
            id: self.new_secret_id(),
            secret: secret.to_string(),
            created_at: at,
            expires_at: expires_at
                .unwrap_or_else(|| self.default_client_secret_expiry(at)),
            description: description.to_string(),
        }
    }

    /// `writeClientSecretRecords(record, records)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn write_client_secret_records(
        &self,
        record: &mut Record,
        records: &[SecretRecord],
    ) -> Result<(), Coded> {
        if records.is_empty() {
            record.fields.shift_remove("oauthClientSecret");
            return Ok(());
        }
        let mut out = Vec::new();
        for one in records {
            out.push(Value::String(self.format_client_secret_record(one)?));
        }
        record
            .fields
            .insert("oauthClientSecret".into(), Value::Array(out));
        Ok(())
    }

    /// `putClientSecret(record, value, {expiresAt})`: a secret given on a
    /// create or a set REPLACES what the entry holds; the same secret again
    /// changes nothing. A whole record keeps the expiry it carries.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn put_client_secret(
        &self,
        record: &mut Record,
        value: &Value,
        expires_at: Option<i64>,
    ) -> Result<bool, Coded> {
        let given = given_secret_text(value);
        let Some(parsed) = self.parse_client_secret_value(&given) else {
            return Ok(false);
        };
        let held = self.client_secret_records_of(&record.fields);
        if held.iter().any(|one| one.secret == parsed.secret) {
            return Ok(false);
        }
        let wrapped = if is_whole_secret_record(&given, &parsed) {
            parsed
        } else {
            self.new_client_secret_record(&parsed.secret, expires_at, "")
        };
        self.write_client_secret_records(record, &[wrapped])?;
        Ok(true)
    }

    /// `registrationAccessTokenOf(fields)`: opened where sealed.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn registration_access_token_of(&self, fields: &Fields) -> String {
        let stored = first_of(fields, "appRegistrationAccessToken");
        if self.env.is_sealed(&stored) {
            self.open_credential_text(&stored, REGISTRATION_TOKEN_LABEL)
        } else {
            stored
        }
    }

    // `pinnedSecretOf(identifier)`: `adminApi.clientSecret` for the
    // default realm's `sts-api-client`.
    fn pinned_secret_of(&self, identifier: &str) -> String {
        if identifier == "sts-api-client"
            && sts_core::realm::current_id() == "default"
        {
            crate::js::or_empty(Some(
                &self.env.setting("adminApi.clientSecret"),
            ))
        } else {
            String::new()
        }
    }

    // `clientSecretsMax()`.
    fn client_secrets_max(&self) -> i64 {
        let n = self
            .env
            .setting("oauth2.clientSecretsMax")
            .as_f64()
            .unwrap_or(0.0);
        let n = if n.is_finite() && n != 0.0 { n } else { 1.0 };
        (n as i64).max(1)
    }

    /// `clientSecretLifetimeOf(raw)`: `Ok(None)` for empty, `Ok(days)` for
    /// a whole number of days 0..=730, `Err` otherwise.
    #[tracing::instrument(level = "debug")]
    pub fn client_secret_lifetime_of(
        raw: Option<&Value>,
    ) -> Result<Option<i64>, ()> {
        let text = match raw {
            None | Some(Value::Null) => String::new(),
            Some(v) => crate::js::trim(&crate::js::string(v)).to_string(),
        };
        if text.is_empty() {
            return Ok(None);
        }
        let days = js_number(&text);
        if !days.is_finite()
            || !(0.0..=730.0).contains(&days)
            || days.fract() != 0.0
        {
            return Err(());
        }
        Ok(Some(days as i64))
    }

    // `finishClientSecretWrite(identifier, record, opts, detail, summary)`.
    fn finish_client_secret_write(
        &self,
        identifier: &str,
        record: &mut Record,
        actor: &str,
        detail: Value,
        summary: &str,
    ) -> (bool, String) {
        let primary = self.primary_client_secret_of(&record.fields, None);
        let method_before = crate::js::trim(&first_of(
            &record.fields,
            "oauthTokenEndpointAuthMethod",
        ))
        .to_string();
        let method_set = primary.is_some()
            && (method_before.is_empty() || method_before == "none");
        if method_set {
            if method_before == "none" {
                record.fields.shift_remove("oauthTokenEndpointAuthMethod");
            }
            let _ = self.set_field(
                record,
                "oauthTokenEndpointAuthMethod",
                &Value::String("client_secret_basic".into()),
            );
        }
        super::checks::values::record_oauth_confidential(record, None);
        let stored = match record.fields.get("appRegistrationJson") {
            Some(v) if crate::js::truthy(v) => Some(crate::js::string(v)),
            _ => None,
        };
        if let Some(text) = stored {
            match serde_json::from_str::<Value>(&text) {
                Ok(mut document) => {
                    if let Some(d) = document.as_object_mut() {
                        match &primary {
                            Some(p) => {
                                d.insert(
                                    "client_secret".into(),
                                    Value::String(p.secret.clone()),
                                );
                                d.insert(
                                    "client_secret_expires_at".into(),
                                    json!(p.expires_at),
                                );
                            }
                            None => {
                                d.shift_remove("client_secret");
                                d.shift_remove("client_secret_expires_at");
                            }
                        }
                        if method_set {
                            d.insert(
                                "token_endpoint_auth_method".into(),
                                Value::String("client_secret_basic".into()),
                            );
                        }
                    }
                    let text =
                        serde_json::to_string(&document).unwrap_or_default();
                    let _ = self.set_field(
                        record,
                        "appRegistrationJson",
                        &Value::String(text),
                    );
                }
                Err(e) => tracing::warn!(
                    "{}applications: appRegistrationJson on \"{}\" is not \
                     valid JSON, so the client secret is on the attribute \
                     and not in the stored document. {}",
                    sts_core::log::tag(codes::STS_REG_0024),
                    identifier,
                    e
                ),
            }
        }
        if record.last_at == 0 {
            record.last_at = self.env.now_ms();
        }
        self.save(record, &super::write::How::actor(actor));
        let mut d = Map::new();
        d.insert("identifier".into(), Value::String(identifier.into()));
        d.insert(
            "attribute".into(),
            Value::String("oauthClientSecret".into()),
        );
        d.insert(
            "tokenEndpointAuthMethod".into(),
            Value::String(if method_set {
                "client_secret_basic".into()
            } else {
                String::new()
            }),
        );
        if let Value::Object(more) = detail {
            for (k, v) in more {
                d.insert(k, v);
            }
        }
        self.effects.audit(&json!({
            "action": "application.update",
            "actor": actor,
            "protocol": "console",
            "channel": "internal",
            "target": identifier,
            "summary": format!("Application \"{}\": {}", identifier, summary),
            "detail": Value::Object(d),
        }));
        (method_set, method_before)
    }

    // `mintedSentence(written)`.
    fn minted_sentence(&self, method_set: bool, method_before: &str) -> String {
        let mut out = format!(
            " It is {} random bytes, base64url, minted the way a registration \
             mints one.",
            self.client_secret_bytes()
        );
        if method_set {
            out.push_str(&format!(
                " Its token endpoint authentication method was {} and is now \
                 client_secret_basic, the default for a client with a secret.",
                if method_before.is_empty() {
                    "not set"
                } else {
                    method_before
                }
            ));
        }
        out
    }

    fn unknown_application(identifier: &str) -> Marked {
        refused(
            codes::STS_REG_0021,
            vec![format!(
                "There is no application called \"{}\" in this registry.",
                identifier
            )],
        )
    }

    /// `addClientSecret(identifier, {description, lifetimeDays, actor})`.
    #[tracing::instrument(level = "debug", skip(self, options))]
    pub fn add_client_secret(
        &self,
        identifier: &str,
        options: &Value,
    ) -> Marked {
        let loaded = self.load(identifier);
        if !loaded.known {
            return Self::unknown_application(identifier);
        }
        let description =
            crate::js::trim(&crate::js::or_empty(options.get("description")))
                .to_string();
        let lifetime =
            Self::client_secret_lifetime_of(options.get("lifetimeDays"));
        if crate::js::len_utf16(&description) > 200
            || description.contains(['\r', '\n', '\0'])
            || lifetime.is_err()
        {
            return refused(
                codes::STS_REG_0211,
                vec!["A client secret's lifetime is a whole number of days \
                      from 0 (never expires) to 730, or empty for \
                      oauth2.clientSecretLifetimeDays; its description is one \
                      line of at most 200 characters."
                    .to_string()],
            );
        }
        let days = lifetime.unwrap_or(None);
        let actor = crate::js::or_empty(options.get("actor"));
        let mut record = loaded.record;
        let held = self.client_secret_records_of(&record.fields);
        let max = self.client_secrets_max();
        if held.len() as i64 >= max {
            return refused(
                codes::STS_REG_0208,
                vec![format!(
                    "\"{}\" already holds {} client secret(s), and \
                     oauth2.clientSecretsMax is {}. Remove one before adding \
                     another.",
                    identifier,
                    held.len(),
                    max
                )],
            );
        }
        let at = self.now_sec();
        let secret = self.mint_client_secret();
        let added = self.new_client_secret_record(
            &secret,
            expiry_of_lifetime(days, at),
            &description,
        );
        let mut all = vec![added.clone()];
        all.extend(held.iter().cloned());
        if let Err(e) = self.write_client_secret_records(&mut record, &all) {
            return refused(e.code, vec![e.message]);
        }
        let (method_set, method_before) = self.finish_client_secret_write(
            identifier,
            &mut record,
            &actor,
            json!({ "mode": "add", "secretId": added.id,
                    "expiresAt": added.expires_at }),
            &format!("a client secret was added ({})", added.id),
        );
        let expiry = if added.expires_at != 0 {
            format!("It expires at {}.", iso_string(added.expires_at * 1000))
        } else {
            "It does not expire.".to_string()
        };
        Marked::ok(json!({
            "ok": true,
            "changed": true,
            "clientSecret": secret,
            "secretId": added.id,
            "expiresAt": added.expires_at,
            "application": self.view_after_write(identifier, &record),
            "message": format!(
                "A client secret was added beside the {} already held; it is \
                 the newest, so it is the one this service signs and \
                 encrypts with, and every unexpired secret still \
                 authenticates. {}{}",
                held.len(),
                expiry,
                self.minted_sentence(method_set, &method_before)
            ),
        }))
    }

    /// `removeClientSecret(identifier, {id, actor})`.
    #[tracing::instrument(level = "debug", skip(self, options))]
    pub fn remove_client_secret(
        &self,
        identifier: &str,
        options: &Value,
    ) -> Marked {
        let loaded = self.load(identifier);
        if !loaded.known {
            return Self::unknown_application(identifier);
        }
        let actor = crate::js::or_empty(options.get("actor"));
        let mut record = loaded.record;
        let held = self.client_secret_records_of(&record.fields);
        let wanted = crate::js::trim(&crate::js::or_empty(options.get("id")))
            .to_string();
        let Some(target) = held.iter().find(|one| one.id == wanted) else {
            let ids: Vec<String> =
                held.iter().map(|one| one.id.clone()).collect();
            return refused(
                codes::STS_REG_0209,
                vec![format!(
                    "\"{}\" holds no client secret with the id \"{}\". Its \
                     secrets are: {}.",
                    identifier,
                    wanted,
                    if ids.is_empty() {
                        "none".to_string()
                    } else {
                        ids.join(", ")
                    }
                )],
            );
        };
        let pinned = self.pinned_secret_of(identifier);
        if !pinned.is_empty() && target.secret == pinned {
            return refused(
                codes::STS_REG_0210,
                vec!["That client secret of \"sts-api-client\" is pinned by \
                      the adminApi.clientSecret setting, which is what every \
                      token for /admin-api is minted with. Change the setting \
                      instead."
                    .to_string()],
            );
        }
        let left: Vec<SecretRecord> = held
            .iter()
            .filter(|one| one.id != wanted)
            .cloned()
            .collect();
        if let Err(e) = self.write_client_secret_records(&mut record, &left) {
            return refused(e.code, vec![e.message]);
        }
        self.finish_client_secret_write(
            identifier,
            &mut record,
            &actor,
            json!({ "mode": "remove", "secretId": wanted }),
            &format!("a client secret was removed ({})", wanted),
        );
        Marked::ok(json!({
            "ok": true,
            "changed": true,
            "left": left.len(),
            "application": self.view_after_write(identifier, &record),
            "message": format!(
                "The client secret {} was removed and stops authenticating at \
                 the token endpoint now. {}",
                wanted,
                if left.is_empty() {
                    "The application holds no client secret now.".to_string()
                } else {
                    format!("{} secret(s) remain.", left.len())
                }
            ),
        }))
    }

    /// `rotateClientSecret(identifier, options)`: a regeneration that
    /// keeps the secrets it replaces for `oauth2.clientSecretOverlapS`.
    #[tracing::instrument(level = "debug", skip(self, options))]
    pub fn rotate_client_secret(
        &self,
        identifier: &str,
        options: &Value,
    ) -> Marked {
        let mut asked = options.as_object().cloned().unwrap_or_default();
        asked.insert("keepPrevious".into(), Value::Bool(true));
        self.regenerate_client_secret(identifier, &Value::Object(asked))
    }

    /// `regenerateClientSecret(identifier, {keepPrevious, actor})`.
    #[tracing::instrument(level = "debug", skip(self, options))]
    pub fn regenerate_client_secret(
        &self,
        identifier: &str,
        options: &Value,
    ) -> Marked {
        let loaded = self.load(identifier);
        if !loaded.known {
            return Self::unknown_application(identifier);
        }
        if !self.pinned_secret_of(identifier).is_empty() {
            return refused(
                codes::STS_REG_0061,
                vec!["The client secret of \"sts-api-client\" is pinned by the \
                      adminApi.clientSecret setting, which is what every token \
                      for /admin-api is minted with. Regenerating it here would \
                      leave the entry and the setting disagreeing, and the \
                      management API unreachable wherever the secret is \
                      checked. Change the setting instead."
                    .to_string()],
            );
        }
        let actor = crate::js::or_empty(options.get("actor"));
        let mut record = loaded.record;
        let held = self.client_secret_records_of(&record.fields);
        let at = self.now_sec();
        let overlap_raw = self
            .env
            .setting("oauth2.clientSecretOverlapS")
            .as_f64()
            .unwrap_or(0.0);
        let overlap_s = if overlap_raw.is_finite() {
            (overlap_raw.floor() as i64).max(0)
        } else {
            0
        };
        let keeps = options.get("keepPrevious").is_some_and(crate::js::truthy)
            && overlap_s > 0
            && held.iter().any(|one| !expired(one, at));
        let kept: Vec<SecretRecord> = if keeps {
            held.iter()
                .filter(|one| !expired(one, at))
                .map(|one| {
                    let until = at + overlap_s;
                    let mut c = one.clone();
                    c.expires_at = if one.expires_at > 0 {
                        one.expires_at.min(until)
                    } else {
                        until
                    };
                    c
                })
                .collect()
        } else {
            Vec::new()
        };
        let max = self.client_secrets_max();
        if kept.len() as i64 + 1 > max {
            return refused(
                codes::STS_REG_0208,
                vec![format!(
                    "A rotation would leave \"{}\" holding {} client secrets, \
                     and oauth2.clientSecretsMax is {}. Remove one first, or \
                     regenerate, which replaces them all.",
                    identifier,
                    kept.len() + 1,
                    max
                )],
            );
        }
        let replaced = !held.is_empty();
        let secret = self.mint_client_secret();
        let added = self.new_client_secret_record(&secret, None, "");
        let mut all = vec![added.clone()];
        all.extend(kept.iter().cloned());
        if let Err(e) = self.write_client_secret_records(&mut record, &all) {
            return refused(e.code, vec![e.message]);
        }
        let overlap_until = if keeps { (at + overlap_s) * 1000 } else { 0 };
        let (method_set, method_before) = self.finish_client_secret_write(
            identifier,
            &mut record,
            &actor,
            json!({ "mode": if keeps { "rotate" } else { "regenerate" },
                    "replaced": replaced, "secretId": added.id,
                    "overlapUntil": overlap_until }),
            &format!(
                "the client secret was {}",
                if keeps {
                    "rotated"
                } else if replaced {
                    "regenerated"
                } else {
                    "generated"
                }
            ),
        );
        let lead = if keeps {
            format!(
                "A new client secret was added, and the {} it replaces go on \
                 authenticating at the token endpoint until {} \
                 (oauth2.clientSecretOverlapS), so the client can change over.",
                kept.len(),
                iso_string(overlap_until)
            )
        } else if replaced {
            "A new client secret replaced every secret the application held, \
             which stop authenticating at the token endpoint now."
                .to_string()
        } else {
            "A client secret was generated.".to_string()
        };
        Marked::ok(json!({
            "ok": true,
            "changed": true,
            "replaced": replaced,
            "clientSecret": secret,
            "secretId": added.id,
            "expiresAt": added.expires_at,
            "application": self.view_after_write(identifier, &record),
            "overlapUntil": overlap_until,
            "message": format!(
                "{}{}",
                lead,
                self.minted_sentence(method_set, &method_before)
            ),
        }))
    }
}

// `clientSecretExpired(record, nowS)`.
fn expired(record: &SecretRecord, now_s: i64) -> bool {
    record.expires_at > 0 && record.expires_at <= now_s
}

// `isWholeSecretRecord(given, parsed)`.
fn is_whole_secret_record(given: &str, parsed: &SecretRecord) -> bool {
    given.starts_with('{') && parsed.created_at > 0
}

/// `givenSecretText(value)`: the first non-empty value, trimmed.
#[tracing::instrument(level = "debug", skip_all)]
pub fn given_secret_text(value: &Value) -> String {
    let list: Vec<Value> = match value {
        Value::Array(l) => l.clone(),
        other => vec![other.clone()],
    };
    list.iter()
        .map(|one| {
            crate::js::trim(&crate::js::unless_null(Some(one))).to_string()
        })
        .find(|s| !s.is_empty())
        .unwrap_or_default()
}

/// `expiryOfLifetime(days, at)`: None for the setting's default.
#[tracing::instrument(level = "debug")]
pub fn expiry_of_lifetime(days: Option<i64>, at: i64) -> Option<i64> {
    days.map(|d| if d > 0 { at + d * 86_400 } else { 0 })
}

/// `Number(text)` for a string: '' is 0, and anything that is not a
/// number is NaN.
#[tracing::instrument(level = "debug")]
pub fn js_number(text: &str) -> f64 {
    let t = crate::js::trim(text);
    if t.is_empty() {
        return 0.0;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16)
            .map(|n| n as f64)
            .unwrap_or(f64::NAN);
    }
    match t {
        "Infinity" | "+Infinity" => f64::INFINITY,
        "-Infinity" => f64::NEG_INFINITY,
        _ if t.contains(|c: char| {
            c.is_ascii_alphabetic() && c != 'e' && c != 'E'
        }) =>
        {
            f64::NAN
        }
        _ => t.parse::<f64>().unwrap_or(f64::NAN),
    }
}
