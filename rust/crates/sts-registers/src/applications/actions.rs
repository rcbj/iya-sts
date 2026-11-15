// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `POST /admin-api/applications/{action}`: `admin_actions.ts`'s
//! `applicationsAction()` for the acts this runtime has the register for —
//! `create`, `set`, `add`, `remove`, `update-fields`, `confirm-address`,
//! `discard-address`, `add-owner`, `remove-owner`, `regenerate-secret`,
//! `rotate-secret`, `add-secret`, `remove-secret` and `forget` — with
//! `applicationFieldsFrom()`, `emptyListBoxesIn()`, `fieldsCoveredBy()`,
//! `updateApplicationFields()`, `withScopeWarnings()` and
//! `refusedBy()`.
//!
//! An act of another family (a certificate issued, a software statement
//! signed, a DID key made, a claim set, an FGA policy) is the not-yet-
//! ported list's in `sts-mgmt-api`, and is never answered here; an action
//! nobody knows is refused as Node refuses it (STS-ADMIN-0500), naming
//! every action Node's switch takes.

use serde_json::{json, Map, Value};
use sts_core::errors::{codes, ErrorCode};

use super::checks::values;
use super::record::{values_of, Record};
use super::tables::Tables;
use super::write::primary_name_attributes;
use super::{refused, ApplicationRegistry, Marked};

/// `APPLICATION_ACTIONS`: every action Node's switch takes, in its order.
pub const APPLICATION_ACTIONS: &[&str] = &[
    "create",
    "set",
    "add",
    "remove",
    "update-fields",
    "confirm-address",
    "discard-address",
    "regenerate-secret",
    "rotate-secret",
    "add-secret",
    "remove-secret",
    "reveal-secret",
    "generate-secret",
    "issue-software-statement",
    "issue-tls-client-certificate",
    "revoke-tls-client-certificate",
    "issue-signing-certificate",
    "revoke-signing-certificate",
    "add-certificate",
    "remove-certificate",
    "revoke-registration",
    "refresh-metadata",
    "load-resource-metadata",
    "generate-did-key",
    "sign-domain-linkage",
    "set-custom-claim",
    "remove-custom-claim",
    "set-claim-attributes",
    "set-claim-selections",
    "inherit-claim-attributes",
    "set-access-type",
    "remove-access-type",
    "set-access-type-row",
    "remove-access-type-row",
    "set-not-for-policy",
    "fga-enable",
    "fga-disable",
    "fga-create-policy",
    "fga-reset-policy",
    "set-permission-claims",
    "clear-permission-claims",
    "export-ldif",
    "import-ldif",
    "forget",
    "add-owner",
    "remove-owner",
];

/// The acts this module answers.
pub const PORTED_ACTIONS: &[&str] = &[
    "create",
    "set",
    "add",
    "remove",
    "update-fields",
    "confirm-address",
    "discard-address",
    "add-owner",
    "remove-owner",
    "regenerate-secret",
    "rotate-secret",
    "add-secret",
    "remove-secret",
    "forget",
];

// The actions that name an application (`needsOne`).
const NEEDS_ONE: &[&str] = &[
    "set",
    "add",
    "remove",
    "update-fields",
    "add-owner",
    "remove-owner",
    "confirm-address",
    "discard-address",
    "regenerate-secret",
    "rotate-secret",
    "add-secret",
    "remove-secret",
    "reveal-secret",
    "issue-software-statement",
    "issue-tls-client-certificate",
    "revoke-tls-client-certificate",
    "issue-signing-certificate",
    "revoke-signing-certificate",
    "add-certificate",
    "remove-certificate",
    "revoke-registration",
    "generate-did-key",
    "sign-domain-linkage",
    "set-custom-claim",
    "remove-custom-claim",
    "set-claim-attributes",
    "set-claim-selections",
    "inherit-claim-attributes",
    "set-access-type",
    "remove-access-type",
    "set-access-type-row",
    "remove-access-type-row",
    "set-not-for-policy",
    "fga-enable",
    "fga-disable",
    "fga-create-policy",
    "fga-reset-policy",
    "set-permission-claims",
    "clear-permission-claims",
    "export-ldif",
    "forget",
];

/// `FIELD_PREFIX`.
const FIELD_PREFIX: &str = "field.";

/// `LONG_TEXT_ATTRIBUTES`: an attribute whose one value may hold line
/// breaks, so a form posts it whole.
pub const LONG_TEXT_ATTRIBUTES: &[&str] = &[
    "oauthJwks",
    "samlSpMetadata",
    "samlEncryptionCertificate",
    "samlSpMetadataSigningCertificate",
    "oauthSamlAssertionSigningCertificate",
    "gnapKey",
    "gnapJweKey",
    "oauthResourceMetadata",
    "secretDestCaCertificates",
    "scimClientTlsCertificate",
    "scimClientCaCertificates",
];

/// What an act reads outside the register: the SAML metadata consumer
/// (`sp_metadata.ts`) and the scope policy's warnings.
pub trait ActionPorts: Send + Sync {
    /// `spMetadata.consume(identifier, text, 'upload')` (a create) or
    /// `spMetadata.upload(identifier, text, actor)` (a write): `{ok,
    /// message, errors}`.
    fn sp_metadata(
        &self,
        identifier: &str,
        text: &str,
        actor: &str,
        create: bool,
    ) -> Value;
    /// `scope_policy.configuredScopeWarnings(identifier)`: `[{text, …}]`.
    fn scope_warnings(&self, identifier: &str) -> Vec<Value>;
}

/// No SAML metadata consumer and no scope policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoActionPorts;

impl ActionPorts for NoActionPorts {
    fn sp_metadata(&self, _: &str, _: &str, _: &str, _: bool) -> Value {
        json!({ "ok": false, "errors": [
            "The SAML 2.0 metadata consumer is not part of this runtime yet."
        ] })
    }

    fn scope_warnings(&self, _: &str) -> Vec<Value> {
        Vec::new()
    }
}

// `String(x || '')` / `String(x == null ? '' : x)`.
fn text(body: &Value, key: &str) -> String {
    crate::js::or_empty(body.get(key))
}

fn plain(value: Option<&Value>) -> String {
    match value {
        None => String::new(),
        Some(v) => crate::js::string(v),
    }
}

/// `refusedBy(code, result)`: a refusal keeps the code its register
/// marked, else takes `code`.
#[tracing::instrument(level = "debug", skip(result))]
pub fn refused_by(code: ErrorCode, mut result: Marked) -> Marked {
    if result.refused() && result.code.is_none() {
        result.code = Some(code);
    }
    result
}

/// `applicationFieldsFrom(body)`: `fields` as given, then every
/// `field.<name>` (a list split on lines, a long text whole, a numbered
/// box `field.<name>.<n>` in its order).
#[tracing::instrument(level = "debug", skip_all)]
pub fn application_fields_from(body: &Value) -> Map<String, Value> {
    let mut fields = Map::new();
    if let Some(Value::Object(given)) = body.get("fields") {
        for (k, v) in given {
            fields.insert(k.clone(), v.clone());
        }
    }
    let mut indexed: Vec<(String, Vec<(f64, String)>)> = Vec::new();
    if let Some(o) = body.as_object() {
        for (key, raw) in o {
            let Some(name) = key.strip_prefix(FIELD_PREFIX) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let whole = crate::js::string(raw);
            if let Some((base, n)) = numbered_box(name) {
                let value = crate::js::trim(&whole).to_string();
                match indexed.iter_mut().find(|(b, _)| *b == base) {
                    Some((_, list)) => list.push((n, value)),
                    None => indexed.push((base, vec![(n, value)])),
                }
                continue;
            }
            let values: Vec<String> = if LONG_TEXT_ATTRIBUTES.contains(&name) {
                let t = crate::js::trim(&whole);
                if t.is_empty() {
                    Vec::new()
                } else {
                    vec![t.to_string()]
                }
            } else {
                whole
                    .split('\n')
                    .map(|one| one.strip_suffix('\r').unwrap_or(one))
                    .map(|one| crate::js::trim(one).to_string())
                    .filter(|one| !one.is_empty())
                    .collect()
            };
            if !values.is_empty() {
                fields.insert(name.to_string(), json!(values));
            }
        }
    }
    for (name, mut list) in indexed {
        list.sort_by(|a, b| {
            a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
        });
        let values: Vec<String> = list
            .into_iter()
            .map(|(_, v)| v)
            .filter(|v| !v.is_empty())
            .collect();
        if !values.is_empty() {
            fields.insert(name, json!(values));
        }
    }
    fields
}

// `/^(.+)\.(\d+)$/`.
fn numbered_box(name: &str) -> Option<(String, f64)> {
    let at = name.rfind('.')?;
    let (base, digits) = (&name[..at], &name[at + 1..]);
    if base.is_empty()
        || digits.is_empty()
        || !digits.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some((base.to_string(), digits.parse::<f64>().unwrap_or(0.0)))
}

/// `emptyListBoxesIn(body)`: every list with a box posted empty.
#[tracing::instrument(level = "debug", skip_all)]
pub fn empty_list_boxes_in(body: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(o) = body.as_object() {
        for (key, raw) in o {
            let Some(name) = key.strip_prefix(FIELD_PREFIX) else {
                continue;
            };
            if let Some((base, _)) = numbered_box(name) {
                if crate::js::trim(&crate::js::string(raw)).is_empty()
                    && !out.contains(&base)
                {
                    out.push(base);
                }
            }
        }
    }
    out
}

/// `emptyListBoxesSentence(names)`.
#[tracing::instrument(level = "debug")]
pub fn empty_list_boxes_sentence(names: &[String]) -> String {
    format!(
        "Every box shown for a list must hold a value. Fill in or delete the \
         empty box{} of {}. A list with no values is a list with no boxes.",
        if names.len() == 1 { "" } else { "es" },
        names.join(", ")
    )
}

// `fieldsCoveredBy(body)`.
fn fields_covered_by(body: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut note = |name: &str| {
        let clean = crate::js::trim(name).to_string();
        if !clean.is_empty() && !out.contains(&clean) {
            out.push(clean);
        }
    };
    if let Some(present) = body.get("present") {
        let list: Vec<Value> = match present {
            Value::Array(l) => l.clone(),
            other => vec![other.clone()],
        };
        for one in list {
            for part in crate::js::string(&one)
                .split(|c: char| crate::js::is_space(c) || c == ',')
            {
                note(part);
            }
        }
    }
    if let Some(Value::Object(f)) = body.get("fields") {
        for k in f.keys() {
            note(k);
        }
    }
    if let Some(o) = body.as_object() {
        for key in o.keys() {
            if let Some(name) = key.strip_prefix(FIELD_PREFIX) {
                let base = numbered_box(name)
                    .map(|(b, _)| b)
                    .unwrap_or_else(|| name.to_string());
                note(&base);
            }
        }
    }
    out
}

// `[].concat(value).map(String).map(trim).filter(non-empty)`.
fn trimmed_values(value: Option<&Value>) -> Vec<String> {
    let list: Vec<Value> = match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(l)) => l.clone(),
        Some(other) => vec![other.clone()],
    };
    list.iter()
        .map(|one| crate::js::trim(&crate::js::string(one)).to_string())
        .filter(|one| !one.is_empty())
        .collect()
}

fn same_values(current: &[String], wanted: &[String]) -> bool {
    current.len() == wanted.len()
        && current.iter().all(|one| wanted.contains(one))
}

impl ApplicationRegistry {
    /// `writeOauthConfidential(identifier)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn write_oauth_confidential(&self, identifier: &str) -> Value {
        let loaded = self.load(identifier);
        if !loaded.known {
            return json!({ "ok": false, "changed": false, "application": null });
        }
        let mut record = loaded.record;
        let changed = values::record_oauth_confidential(&mut record, None);
        if changed {
            if record.last_at == 0 {
                record.last_at = self.env.now_ms();
            }
            self.save(&mut record, &super::write::How::default());
            self.effects.audit(&json!({
                "action": "application.update", "actor": "",
                "protocol": "console", "channel": "internal",
                "target": identifier,
                "summary": format!(
                    "Application \"{}\": oauthConfidential is now \"{}\"",
                    identifier,
                    crate::js::or_empty(record.fields.get("oauthConfidential"))
                ),
                "detail": { "identifier": identifier,
                            "attribute": "oauthConfidential", "mode": "set",
                            "editedByHand": true },
            }));
        }
        json!({ "ok": true, "changed": changed,
                "application": self.view_after_write(identifier, &record) })
    }

    // `withScopeWarnings(identifier, result)`.
    fn with_scope_warnings(
        ports: &dyn ActionPorts,
        identifier: &str,
        result: Marked,
    ) -> Marked {
        if result.refused() || identifier.is_empty() {
            return result;
        }
        let warnings = ports.scope_warnings(identifier);
        if warnings.is_empty() {
            return result;
        }
        let said: Vec<String> = warnings
            .iter()
            .map(|w| crate::js::unless_null(w.get("text")))
            .collect();
        let mut answer = result.answer.as_object().cloned().unwrap_or_default();
        let message = crate::js::or_empty(answer.get("message"));
        answer.insert("warnings".into(), Value::Array(warnings));
        answer.insert(
            "message".into(),
            json!(format!(
                "{}WARNING: {}",
                if message.is_empty() {
                    "Saved. ".to_string()
                } else {
                    format!("{} ", message)
                },
                said.join(" ")
            )),
        );
        Marked {
            answer: Value::Object(answer),
            code: result.code,
        }
    }

    /// `applicationsAction(body, protocols, {actor})` for the ported acts.
    /// `protocols` is the declared families as the route read them
    /// (`familiesOfChoices(namesOf(req, body, 'protocol', 'protocols'))`),
    /// None where the route did not.
    #[tracing::instrument(level = "debug", skip(self, body, ports))]
    pub fn applications_action(
        &self,
        body: &Value,
        protocols: Option<Vec<String>>,
        actor: &str,
        ports: &dyn ActionPorts,
    ) -> Marked {
        let action = text(body, "action");
        let identifier =
            crate::js::trim(&text(body, "application")).to_string();
        if NEEDS_ONE.contains(&action.as_str()) && identifier.is_empty() {
            return refused(
                codes::STS_ADMIN_0529,
                vec!["Which application? Send `application` with the \
                      identifier exactly as this registry holds it — the \
                      client_id, wtrealm, AppliesTo, entityID or service \
                      principal name."
                    .to_string()],
            );
        }
        match action.as_str() {
            "create" => self.create_action(body, protocols, actor, ports),
            "set" | "add" | "remove" => {
                let attribute = text(body, "attribute");
                let metadata = plain(body.get("value"));
                if action != "remove"
                    && attribute == "samlSpMetadata"
                    && !crate::js::trim(&metadata).is_empty()
                {
                    return self.consume_written_metadata(
                        &identifier,
                        &metadata,
                        actor,
                        ports,
                    );
                }
                let mut change = json!({
                    "mode": action,
                    "attribute": attribute,
                    "value": metadata,
                });
                if let Some(c) = body.get("confirm") {
                    change["confirm"] = c.clone();
                }
                let result = self.update_application(&identifier, &change);
                refused_by(
                    codes::STS_ADMIN_0531,
                    Self::with_scope_warnings(ports, &identifier, result),
                )
            }
            "update-fields" => Self::with_scope_warnings(
                ports,
                &identifier,
                self.update_application_fields(
                    &identifier,
                    body,
                    protocols.as_deref(),
                    actor,
                    ports,
                ),
            ),
            "confirm-address" | "discard-address" => {
                let change = json!({
                    "attribute": text(body, "attribute"),
                    "value": plain(body.get("value")),
                });
                let result = if action == "confirm-address" {
                    self.confirm_return_address(&identifier, &change)
                } else {
                    self.discard_return_address(&identifier, &change)
                };
                refused_by(codes::STS_ADMIN_0531, result)
            }
            "add-owner" | "remove-owner" => {
                let adding = action == "add-owner";
                let owner = crate::js::trim(&text(body, "owner")).to_string();
                let result = if adding {
                    self.add_owner(&identifier, &owner)
                } else {
                    self.remove_owner(&identifier, &owner)
                };
                if result.is_ok()
                    && result.answer.get("changed") == Some(&Value::Bool(true))
                {
                    let shown = crate::js::or_empty(result.answer.get("owner"));
                    self.effects.audit(&json!({
                        "action": if adding {
                            "application.add-owner"
                        } else {
                            "application.remove-owner"
                        },
                        "actor": actor, "target": identifier,
                        "channel": "http",
                        "detail": format!(
                            "{}{}{}{}",
                            if adding { "made " } else { "took " },
                            shown,
                            if adding {
                                " an owner of "
                            } else {
                                " off the owners of "
                            },
                            identifier
                        ),
                    }));
                }
                refused_by(
                    if adding {
                        codes::STS_ADMIN_0856
                    } else {
                        codes::STS_ADMIN_0857
                    },
                    result,
                )
            }
            "regenerate-secret" => refused_by(
                codes::STS_ADMIN_0620,
                self.regenerate_client_secret(
                    &identifier,
                    &json!({ "actor": actor }),
                ),
            ),
            "rotate-secret" => refused_by(
                codes::STS_ADMIN_0620,
                self.rotate_client_secret(
                    &identifier,
                    &json!({ "actor": actor }),
                ),
            ),
            "add-secret" => {
                let mut o = json!({ "actor": actor });
                for k in ["lifetimeDays", "description"] {
                    if let Some(v) = body.get(k) {
                        o[k] = v.clone();
                    }
                }
                refused_by(
                    codes::STS_ADMIN_0620,
                    self.add_client_secret(&identifier, &o),
                )
            }
            "remove-secret" => {
                let mut o = json!({ "actor": actor });
                if let Some(v) = body.get("secret") {
                    o["id"] = v.clone();
                }
                refused_by(
                    codes::STS_ADMIN_0620,
                    self.remove_client_secret(&identifier, &o),
                )
            }
            "forget" => refused_by(
                codes::STS_ADMIN_0535,
                self.delete_application(&identifier, &json!({})),
            ),
            _ => refused(
                codes::STS_ADMIN_0500,
                vec![format!(
                    "Unknown action \"{}\". The {} are: {}.",
                    action,
                    crate::js::number_word(APPLICATION_ACTIONS.len()),
                    APPLICATION_ACTIONS.join(", ")
                )],
            ),
        }
    }

    // The `create` act.
    fn create_action(
        &self,
        body: &Value,
        protocols: Option<Vec<String>>,
        actor: &str,
        ports: &dyn ActionPorts,
    ) -> Marked {
        let asked = match protocols {
            Some(p) => json!(p),
            None => body.get("protocols").cloned().unwrap_or_else(|| json!([])),
        };
        let empty = empty_list_boxes_in(body);
        if !empty.is_empty() {
            return refused(
                codes::STS_ADMIN_0834,
                vec![empty_list_boxes_sentence(&empty)],
            );
        }
        let identifier = {
            let i = text(body, "identifier");
            if i.is_empty() {
                text(body, "application")
            } else {
                i
            }
        };
        let fields = application_fields_from(body);
        let mut detail = json!({
            "identifier": identifier,
            "name": text(body, "name"),
            "kind": text(body, "kind"),
            "protocols": asked,
            "fields": Value::Object(fields.clone()),
        });
        if let Some(l) = body.get("lifetimeDays") {
            detail["lifetimeDays"] = l.clone();
        }
        let result = self.create_application(&detail);
        if !result.is_ok() {
            return refused_by(codes::STS_ADMIN_0530, result);
        }
        let application = result.answer["application"].clone();
        let id = crate::js::or_empty(application.get("identifier"));
        let declared = crate::js::strings(application.get("allowedProtocols"));
        let pasted = crate::js::or_empty(fields.get("samlSpMetadata"));
        let mut consumed: Option<Value> = None;
        if !crate::js::trim(&pasted).is_empty() {
            consumed = Some(ports.sp_metadata(&id, &pasted, actor, true));
        }
        if let Some(c) = &consumed {
            if !c.get("ok").is_some_and(crate::js::truthy) {
                self.delete_application(&id, &json!({}));
                let errs = crate::js::strings(c.get("errors")).join(" ");
                return refused(
                    codes::STS_ADMIN_0917,
                    vec![format!(
                        "Nothing was created, because the metadata document \
                         was refused: {}",
                        errs
                    )],
                );
            }
        }
        let consumed_sentence = consumed
            .as_ref()
            .map(|c| format!(" {}", crate::js::unless_null(c.get("message"))))
            .unwrap_or_default();
        let declared_sentence = if declared.is_empty() {
            "No protocol family was declared for it, which changes nothing \
             about what it may reach — the declaration is a record of intent. "
                .to_string()
        } else {
            format!(
                "It is DECLARED for {}, which is a note on the entry and not \
                 a permission: nothing in this service reads it, and this \
                 application can still reach every other protocol here. ",
                declared.join(", ")
            )
        };
        let tail = if !fields.is_empty() {
            "The attributes given with it are on the entry now: a redirect URI \
             among them is what RFC 9700 mode matches the next authorization \
             request against, by exact string comparison, and the rest are \
             recorded rather than checked."
                .to_string()
        } else {
            format!(
                "{}Give it the ones it is allowed and RFC 9700 mode will judge \
                 it against them; without them a redirect_uri is judged \
                 against the oauth2.redirectUris setting instead — and in \
                 OAuth 2.1 mode it is refused.",
                if declared.is_empty() {
                    "It carries no identifier and no redirect URI yet. "
                } else {
                    "Where a ticked family's own identifier was left empty, \
                     the identifier is that name. It carries no redirect URI \
                     yet. "
                }
            )
        };
        let shown = if consumed.is_some() {
            self.get(&id).unwrap_or(application)
        } else {
            application
        };
        Marked::ok(json!({
            "ok": true,
            "application": shown,
            "message": format!(
                "\"{}\" is in the registry. It has authenticated nothing yet \
                 — the counters are zero and the entry says it was created by \
                 hand, so it cannot be mistaken for one that turned up once. \
                 {}{}{}",
                id, declared_sentence, tail, consumed_sentence
            ),
        }))
    }

    // `consumeWrittenMetadata(identifier, text, actor)`.
    fn consume_written_metadata(
        &self,
        identifier: &str,
        text: &str,
        actor: &str,
        ports: &dyn ActionPorts,
    ) -> Marked {
        let consumed = ports.sp_metadata(identifier, text, actor, false);
        if !consumed.get("ok").is_some_and(crate::js::truthy) {
            let mut errors = vec!["The metadata document was not written, \
                                   because it was refused: "
                .to_string()];
            errors.extend(crate::js::strings(consumed.get("errors")));
            return refused(codes::STS_ADMIN_0935, errors);
        }
        Marked::ok(json!({
            "ok": true, "changed": true,
            "application": self.get(identifier).unwrap_or(Value::Null),
            "message": crate::js::unless_null(consumed.get("message")),
        }))
    }

    /// `updateApplicationFields(identifier, body, protocols, actor)`: the
    /// application page's field grid, every attribute it carries at once.
    #[tracing::instrument(level = "debug", skip(self, body, ports))]
    pub fn update_application_fields(
        &self,
        identifier: &str,
        body: &Value,
        protocols: Option<&[String]>,
        actor: &str,
        ports: &dyn ActionPorts,
    ) -> Marked {
        let empty = empty_list_boxes_in(body);
        if !empty.is_empty() {
            return refused(
                codes::STS_ADMIN_0834,
                vec![empty_list_boxes_sentence(&empty)],
            );
        }
        let Some(entry) = self.get(identifier) else {
            return refused(
                codes::STS_ADMIN_0531,
                vec![format!(
                    "No application called \"{}\" is in this realm's registry.",
                    identifier
                )],
            );
        };
        let given = application_fields_from(body);
        let covered = fields_covered_by(body);
        let with_protocols =
            body.get("protocolsPresent").is_some_and(crate::js::truthy)
                || body.get("protocols").is_some();
        if covered.is_empty() && !with_protocols {
            return refused(
                codes::STS_ADMIN_0835,
                vec![
                    "Name the attributes to change: `fields` (each member an \
                      attribute, a string or an array of strings; empty clears \
                      it), `protocols`, or both."
                        .to_string(),
                ],
            );
        }
        let t = Tables::get();
        let mode_of = |name: &str| -> String {
            t.editable_attributes("")
                .iter()
                .rev()
                .find(|r| r.name == name)
                .map(|r| r.editable.clone())
                .unwrap_or_default()
        };
        let posted_protocols = || -> Vec<String> {
            match protocols {
                Some(p) if !p.is_empty() => p.to_vec(),
                _ => trimmed_values(body.get("protocols")),
            }
        };
        let mut changes: Vec<(String, Vec<String>)> = Vec::new();
        if with_protocols {
            changes.push(("appAllowedProtocol".into(), posted_protocols()));
        }
        for name in &covered {
            if name != "appAllowedProtocol" {
                changes.push((name.clone(), trimmed_values(given.get(name))));
            }
        }
        let fields = entry["fields"].as_object().cloned().unwrap_or_default();
        let mut sync_confidential = false;
        if let Some(at) =
            changes.iter().position(|(a, _)| a == "oauthConfidential")
        {
            let projected: Vec<String> = changes
                .iter()
                .find(|(a, _)| a == "oauthTokenEndpointAuthMethod")
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| {
                    // `OAuthClient.fromEntry(fields).tokenEndpointAuthMethods`.
                    trimmed_values(fields.get("oauthTokenEndpointAuthMethod"))
                });
            let mut preview = Record::default();
            preview.fields.insert(
                "oauthTokenEndpointAuthMethod".into(),
                json!(projected),
            );
            let determination = values::oauth_confidential_of(
                entry.get("registered").is_some_and(crate::js::truthy),
                &preview.fields,
            );
            let stated = &changes[at].1;
            let problem = match stated.len() {
                1 => values::confidential_disagreement(
                    &stated[0],
                    &determination,
                ),
                0 => values::confidential_clear_sentence(),
                _ => values::confidential_disagreement(
                    &stated.join(" "),
                    &determination,
                ),
            };
            if !problem.is_empty() {
                return refused(codes::STS_REG_0363, vec![problem]);
            }
            sync_confidential = true;
            changes.remove(at);
        }
        let confirm = body.get("confirm");
        let mut bounds: Vec<super::checks::Coded> = Vec::new();
        for (name, wanted) in &changes {
            if mode_of(name) != "set"
                || !values::is_hosted_session_client(identifier)
                || !values::hosted_bound_attribute(name)
            {
                continue;
            }
            let current = trimmed_values(fields.get(name));
            if same_values(&current, wanted) {
                continue;
            }
            if let Some(r) = values::hosted_session_bound_refusal(
                self,
                identifier,
                name,
                wanted.first().map(String::as_str).unwrap_or(""),
                confirm,
            ) {
                bounds.push(r);
            }
        }
        if !bounds.is_empty() {
            let code = if bounds.iter().any(|b| b.code == codes::STS_REG_0369) {
                codes::STS_REG_0369
            } else {
                codes::STS_REG_0368
            };
            return refused(
                code,
                bounds.into_iter().map(|b| b.message).collect(),
            );
        }
        let mut changed: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut metadata = String::new();
        for (name, wanted) in &changes {
            let mode = mode_of(name);
            if mode.is_empty() {
                errors.push(format!("{} cannot be edited here.", name));
                continue;
            }
            let current = trimmed_values(fields.get(name));
            if name == "samlSpMetadata"
                && wanted.len() == 1
                && !(current.len() == 1 && current[0] == wanted[0])
            {
                metadata = wanted[0].clone();
                continue;
            }
            if name == "oauthTokenEndpointAuthMethod" {
                let p = values::auth_methods_problem(Some(&json!(wanted)));
                if !p.is_empty() {
                    errors.push(p);
                    continue;
                }
            }
            if same_values(&current, wanted) {
                continue;
            }
            if mode == "set" {
                if wanted.len() > 1 {
                    errors.push(format!(
                        "{} holds one value, and {} were given.",
                        name,
                        wanted.len()
                    ));
                    continue;
                }
                let mut c = json!({ "mode": "set", "attribute": name,
                                    "value": wanted.first().cloned()
                                        .unwrap_or_default() });
                if let Some(v) = confirm {
                    c["confirm"] = v.clone();
                }
                let set = self.update_application(identifier, &c);
                if set.is_ok() {
                    changed.push(name.clone());
                } else {
                    errors.extend(crate::js::strings(set.answer.get("errors")));
                }
                continue;
            }
            let mut ok = true;
            for value in current.iter().filter(|one| !wanted.contains(one)) {
                let r = self.update_application(
                    identifier,
                    &json!({ "mode": "remove", "attribute": name,
                             "value": value }),
                );
                if !r.is_ok() {
                    ok = false;
                    errors.extend(crate::js::strings(r.answer.get("errors")));
                }
            }
            for value in wanted.iter().filter(|one| !current.contains(one)) {
                let r = self.update_application(
                    identifier,
                    &json!({ "mode": "add", "attribute": name, "value": value }),
                );
                if !r.is_ok() {
                    ok = false;
                    errors.extend(crate::js::strings(r.answer.get("errors")));
                }
            }
            if ok {
                changed.push(name.clone());
            }
        }
        if errors.is_empty() && with_protocols {
            let previous = trimmed_values(fields.get("appAllowedProtocol"));
            let added: Vec<String> = posted_protocols()
                .into_iter()
                .filter(|id| !previous.contains(id))
                .collect();
            let fresh = self.get(identifier);
            if let (Some(fresh), false) = (fresh, added.is_empty()) {
                for name in primary_name_attributes(&added) {
                    if covered.iter().any(|c| c == name)
                        || !values_of(fresh["fields"].get(name)).is_empty()
                    {
                        continue;
                    }
                    let verb =
                        if mode_of(name) == "set" { "set" } else { "add" };
                    let own = crate::js::or_empty(fresh.get("identifier"));
                    let written = self.update_application(
                        identifier,
                        &json!({ "mode": verb, "attribute": name,
                                 "value": if own.is_empty() {
                                     identifier.to_string()
                                 } else {
                                     own
                                 } }),
                    );
                    if written.is_ok() {
                        changed.push(name.to_string());
                    } else {
                        errors.extend(crate::js::strings(
                            written.answer.get("errors"),
                        ));
                    }
                }
            }
        }
        if errors.is_empty() && !metadata.is_empty() {
            let consumed = self
                .consume_written_metadata(identifier, &metadata, actor, ports);
            if consumed.is_ok() {
                changed.push("samlSpMetadata".into());
            } else {
                errors
                    .extend(crate::js::strings(consumed.answer.get("errors")));
            }
        }
        if !errors.is_empty() {
            let mut all = Vec::new();
            if !changed.is_empty() {
                all.push(format!(
                    "Saved {}; the rest was refused:",
                    changed.join(", ")
                ));
            }
            all.extend(errors);
            return Marked::marked(
                codes::STS_ADMIN_0836,
                json!({ "ok": false, "changed": changed, "errors": all }),
            );
        }
        if sync_confidential {
            let synced = self.write_oauth_confidential(identifier);
            if synced.get("changed") == Some(&Value::Bool(true)) {
                changed.push("oauthConfidential".into());
            }
        }
        Marked::ok(json!({
            "ok": true,
            "changed": changed,
            "application": self.get(identifier).unwrap_or(Value::Null),
            "message": if changed.is_empty() {
                "Nothing changed: every field already held what was submitted."
                    .to_string()
            } else {
                format!(
                    "Saved {} attribute(s) of \"{}\": {}.",
                    changed.len(),
                    identifier,
                    changed.join(", ")
                )
            },
        }))
    }
}
