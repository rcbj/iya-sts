// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `GET /admin-api/applications` without `?application=`:
//! `admin_views.ts`'s `applicationsListJson()` — the register filtered by
//! `q`, `kind` and `exclude`, paged (`pagingOf()`, `pagedRows()`), every
//! shown row with its credentials masked (`maskedApplicationRow()`) and its
//! client secret's expiry (`secretExpiryOf()`), and the counts the page
//! draws. The page's settings block (`configSettingsJson()`) is
//! `sts-mgmt-api`'s, handed in.

use serde_json::{json, Map, Value};

use super::tables::{Tables, KINDS, PROTOCOLS};
use super::ApplicationRegistry;

/// `DEFAULT_PER_PAGE`.
const DEFAULT_PER_PAGE: i64 = 50;
/// `MAX_ROWS`.
const MAX_ROWS: i64 = 300;

// `parseInt(String(x || ''), 10)`: None for NaN.
fn parse_int(value: Option<&Value>) -> Option<i64> {
    let text = match value {
        Some(Value::Array(l)) => {
            l.first().map(crate::js::string).unwrap_or_default()
        }
        Some(v) if crate::js::truthy(v) => crate::js::string(v),
        _ => String::new(),
    };
    let t = crate::js::trim(&text);
    let (neg, digits) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let lead: String =
        digits.chars().take_while(char::is_ascii_digit).collect();
    if lead.is_empty() {
        return None;
    }
    let n = lead.parse::<i64>().ok()?;
    Some(if neg { -n } else { n })
}

// A query member as text (`String(req.query.x || '')`).
fn text(query: &Map<String, Value>, key: &str) -> String {
    match query.get(key) {
        Some(Value::Array(l)) => l
            .iter()
            .map(crate::js::string)
            .collect::<Vec<_>>()
            .join(","),
        other => crate::js::or_empty(other),
    }
}

/// `pagingOf(query, total, {noun})`.
#[tracing::instrument(level = "debug", skip(query))]
pub fn paging_of(
    query: &Map<String, Value>,
    total: usize,
    noun: &str,
) -> Value {
    let asked = parse_int(query.get("per"));
    let per = match asked {
        Some(n) if n > 0 => n.min(MAX_ROWS),
        _ => DEFAULT_PER_PAGE.min(MAX_ROWS),
    };
    let total = total as i64;
    let pages = ((total + per - 1) / per).max(1);
    let page = parse_int(query.get("page")).unwrap_or(1).max(1).min(pages);
    let offset = (page - 1) * per;
    json!({
        "page": page, "perPage": per, "pages": pages, "offset": offset,
        "total": total,
        "firstRow": if total > 0 { offset + 1 } else { 0 },
        "lastRow": (offset + per).min(total),
        "param": "page", "noun": noun,
    })
}

/// `pagingJson(pg)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn paging_json(pg: &Value) -> Value {
    json!({
        "page": pg["page"], "pages": pg["pages"], "perPage": pg["perPage"],
        "firstRow": pg["firstRow"], "lastRow": pg["lastRow"],
        "total": pg["total"], "param": pg["param"], "noun": pg["noun"],
    })
}

// `maskedCredential(value)`.
fn masked_credential(value: &Value) -> Value {
    const MASK: &str = "(set — not returned)";
    match value {
        Value::Array(l) => {
            Value::Array(l.iter().map(|_| json!(MASK)).collect())
        }
        Value::Null => Value::Null,
        Value::String(s) if s.is_empty() => value.clone(),
        _ => json!(MASK),
    }
}

// THE REGISTRATION DOCUMENT CARRIES TWO CREDENTIALS (Node's
// `maskedRegistrationJson()`, 2026-11-14, #444 D12). `appRegistrationJson`
// is the RFC 7591 registration response kept as it was answered, and that
// answer holds the `client_secret` and the RFC 7592
// `registration_access_token`. The attribute is not a credential, so it was
// answered whole to every Admin Read caller while
// `appRegistrationAccessToken` beside it was masked. The two members are
// masked as the attribute is; the rest of the document stands, and a value
// that is not a JSON object is answered as it is.
fn masked_registration_json(value: &Value) -> Value {
    match value {
        Value::Array(l) => {
            Value::Array(l.iter().map(masked_registration_json).collect())
        }
        Value::String(text) if !text.is_empty() => {
            let Ok(Value::Object(mut document)) =
                serde_json::from_str::<Value>(text)
            else {
                return value.clone();
            };
            for name in ["client_secret", "registration_access_token"] {
                if let Some(v) = document.get_mut(name) {
                    *v = masked_credential(v);
                }
            }
            // `JSON.stringify()`: serde_json keeps the member order
            // (preserve_order) and writes the compact form Node does.
            json!(Value::Object(document).to_string())
        }
        _ => value.clone(),
    }
}

/// `KINDS`, as the page publishes them.
#[tracing::instrument(level = "debug")]
pub fn kinds_json() -> Value {
    Value::Array(
        KINDS
            .iter()
            .map(
                |k| json!({ "kind": k.kind, "label": k.label, "what": k.what }),
            )
            .collect(),
    )
}

/// `PROTOCOLS`, as the page publishes them: a member a row does not carry
/// is not there.
#[tracing::instrument(level = "debug")]
pub fn protocols_json() -> Value {
    Value::Array(
        PROTOCOLS
            .iter()
            .map(|p| {
                let mut o = Map::new();
                o.insert("id".into(), json!(p.id));
                o.insert("label".into(), json!(p.label));
                o.insert("kind".into(), json!(p.kind));
                o.insert("kinds".into(), json!(p.kinds));
                o.insert(
                    "identifierAttribute".into(),
                    json!(p.identifier_attribute),
                );
                o.insert(
                    "redirectAttribute".into(),
                    json!(p.redirect_attribute),
                );
                for (k, v) in [
                    ("logoutAttribute", p.logout_attribute),
                    ("secretAttribute", p.secret_attribute),
                    ("deliveryAttribute", p.delivery_attribute),
                    ("eventsAttribute", p.events_attribute),
                ] {
                    if !v.is_empty() {
                        o.insert(k.into(), json!(v));
                    }
                }
                o.insert("what".into(), json!(p.what));
                Value::Object(o)
            })
            .collect(),
    )
}

impl ApplicationRegistry {
    // `maskedApplicationRow(row)`: every sensitive attribute's values
    // masked, in `fields` and in `attributes`.
    fn masked_application_row(&self, row: &Value) -> Value {
        let names: Vec<&str> = Tables::get()
            .schema
            .attributes
            .iter()
            .filter(|r| r.sensitive)
            .map(|r| r.name.as_str())
            .collect();
        let mut out = row.clone();
        for member in ["fields", "attributes"] {
            if let Some(Value::Object(o)) = out.get_mut(member) {
                for (k, v) in o.iter_mut() {
                    if names.contains(&k.as_str()) {
                        *v = masked_credential(v);
                    } else if k == "appRegistrationJson" {
                        *v = masked_registration_json(v);
                    }
                }
            }
        }
        out
    }

    // `secretExpiryOf(row)`: `{state, at}`.
    fn row_secret_expiry(&self, row: &Value) -> Value {
        let identifier = crate::js::or_empty(row.get("identifier"));
        let fields = self
            .get(&identifier)
            .and_then(|r| r["fields"].as_object().cloned())
            .unwrap_or_default();
        let expires = if fields
            .get("oauthClientSecret")
            .is_some_and(crate::js::truthy)
        {
            self.secret_expiry_of(&fields)
        } else {
            0
        };
        if expires == 0 {
            return json!({ "state": "", "at": "" });
        }
        let now_s = self.now_sec();
        let warn_s = self
            .env
            .setting("oauth2.clientSecretExpiryWarningDays")
            .as_f64()
            .unwrap_or(0.0)
            * 86_400.0;
        let state = if expires <= now_s {
            "expired"
        } else if ((expires - now_s) as f64) <= warn_s {
            "soon"
        } else {
            ""
        };
        json!({ "state": state,
                "at": super::record::iso_string(expires * 1000) })
    }

    /// `applicationsListJson(req).json`, with the page's settings block.
    #[tracing::instrument(level = "debug", skip(self, query, settings))]
    pub fn applications_list_json(
        &self,
        query: &Map<String, Value>,
        settings: Value,
    ) -> Value {
        let all = self.list();
        let wanted_text = crate::js::trim(&text(query, "q")).to_string();
        let wanted_kind = crate::js::trim(&text(query, "kind")).to_string();
        let needle = wanted_text.to_lowercase();
        let excluded: Vec<String> = match query.get("exclude") {
            None => Vec::new(),
            Some(Value::Array(l)) => l.iter().map(crate::js::string).collect(),
            Some(v) => vec![crate::js::string(v)],
        }
        .into_iter()
        .map(|one| crate::js::trim(&one).to_string())
        .filter(|one| !one.is_empty())
        .collect();
        let has = |row: &Value, member: &str, kind: &str| -> bool {
            crate::js::strings(row.get(member))
                .iter()
                .any(|k| k == kind)
        };
        let filtered: Vec<&Value> = all
            .iter()
            .filter(|row| {
                let id = crate::js::or_empty(row.get("identifier"));
                if excluded.contains(&id) {
                    return false;
                }
                if !wanted_kind.is_empty()
                    && !has(row, "kinds", &wanted_kind)
                    && !has(row, "declaredKinds", &wanted_kind)
                {
                    return false;
                }
                if needle.is_empty() {
                    return true;
                }
                id.to_lowercase().contains(&needle)
                    || crate::js::unless_null(row.get("name"))
                        .to_lowercase()
                        .contains(&needle)
            })
            .collect();
        let pg = paging_of(query, filtered.len(), "applications");
        let offset = pg["offset"].as_i64().unwrap_or(0) as usize;
        let per = pg["perPage"].as_i64().unwrap_or(1) as usize;
        let shown: Vec<&Value> =
            filtered.iter().skip(offset).take(per).copied().collect();
        let registered = all
            .iter()
            .filter(|row| {
                row.get("registered") == Some(&Value::Bool(true))
                    || row.get("registeredBy").is_some_and(crate::js::truthy)
            })
            .count();
        let mut kind_counts = Map::new();
        for k in KINDS {
            let n = all
                .iter()
                .filter(|row| {
                    has(row, "kinds", k.kind)
                        || has(row, "declaredKinds", k.kind)
                })
                .count();
            kind_counts.insert(k.kind.into(), json!(n));
        }
        let authentications: i64 = all
            .iter()
            .map(|r| {
                r.get("authentications")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
            })
            .sum();
        let rows: Vec<Value> = shown
            .iter()
            .map(|row| {
                let mut out = self.masked_application_row(row);
                out["secretExpiry"] = self.row_secret_expiry(row);
                out
            })
            .collect();
        json!({
            "applicationCount": all.len(),
            "matched": filtered.len(),
            "shown": shown.len(),
            "registered": registered,
            "filter": {
                "q": if wanted_text.is_empty() { Value::Null } else { json!(wanted_text) },
                "kind": if wanted_kind.is_empty() { Value::Null } else { json!(wanted_kind) },
                "exclude": if excluded.is_empty() { Value::Null } else { json!(excluded) },
            },
            "page": pg["page"], "pages": pg["pages"], "perPage": pg["perPage"],
            "firstRow": pg["firstRow"], "lastRow": pg["lastRow"],
            "container": self.container_dn(),
            "max": self.max_applications(),
            "kinds": kinds_json(),
            "settings": settings,
            "paging": paging_json(&pg),
            "kindCounts": Value::Object(kind_counts),
            "authentications": authentications,
            "protocols": protocols_json(),
            "applications": rows,
        })
    }
}

#[cfg(test)]
mod registration_json_tests {
    use super::masked_registration_json;
    use serde_json::json;

    // `maskedRegistrationJson()` (Node's fix of 2026-11-14): the two
    // credentials masked, the rest of the document as it stood, anything
    // that is not a JSON object answered as it is.
    #[test]
    fn the_two_credentials_are_masked_and_nothing_else() {
        let doc = r#"{"client_id":"c","client_secret":"s","registration_access_token":"t","n":1}"#;
        assert_eq!(
            masked_registration_json(&json!([doc])),
            json!(["{\"client_id\":\"c\",\"client_secret\":\"(set — not \
                 returned)\",\"registration_access_token\":\"(set — not \
                 returned)\",\"n\":1}"])
        );
        assert_eq!(masked_registration_json(&json!("[1]")), json!("[1]"));
        assert_eq!(masked_registration_json(&json!("x{")), json!("x{"));
        assert_eq!(masked_registration_json(&json!("")), json!(""));
        assert_eq!(
            masked_registration_json(&json!(r#"{"client_secret":""}"#)),
            json!(r#"{"client_secret":""}"#)
        );
    }
}
