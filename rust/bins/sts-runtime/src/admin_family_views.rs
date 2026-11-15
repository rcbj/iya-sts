// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ENROLLMENT FAMILIES' VIEWS ON `/admin-api` (rule 7): what
//! `GET /admin-api/acme`, `/est` and `/scep` and their monitors answer —
//! `acme_console.ts`'s `acmeView()` and `acmeMonitorView()`,
//! `est_console.ts`'s `estView()` and `estMonitorView()`, and
//! `scep_console.ts`'s `scepView()` and `scepMonitorView()` — over
//! `sts-enroll`'s core, its stores and its monitor.
//!
//! The constant tables (each family's operations, actions and
//! vocabularies, the core's profiles and refusals, the mode's requirement
//! row) are Node's own, exported by `tests/tools/export-admin-api-tables.js`
//! into `sts-mgmt-api`'s tables, so a sentence cannot drift between the two.
//!
//! Every base URL is the request's (`baseUrlOf(req)`), which is what
//! `rebaseTo()` and `baseUrlOf(req, app)` answer while no hosted application
//! is moved to a custom listener — and this runtime advertises none
//! (`listeners_of()` answers no listener).

use serde_json::{json, Map, Value as Json};
use sts_core::realm;
use sts_core::settings::SettingValue;
use sts_enroll::core::Entry;
use sts_enroll::wiring::Families;
use sts_mgmt_api::families::Asked;
use sts_mgmt_api::paging::{Options, Paging};
use sts_mgmt_api::tables::tables;
use sts_pki::authority::Authority;

/// The exported tables of the three views.
fn t() -> &'static Json {
    &tables().family_views
}

/// `config.value(key) !== false`.
fn on(f: &Families, key: &str) -> bool {
    !matches!(f.settings.value_of(key), SettingValue::Bool(false))
}

/// `Number(config.value(key))`.
fn number_of(f: &Families, key: &str) -> Json {
    match f.settings.value_of(key) {
        SettingValue::Int(n) => Json::from(n),
        other => {
            let text = other.as_str().trim().to_string();
            text.parse::<i64>()
                .map(Json::from)
                .or_else(|_| text.parse::<f64>().map(Json::from))
                .unwrap_or(Json::Null)
        }
    }
}

/// `x || null` of a member.
fn or_null(v: &Json, key: &str) -> Json {
    match v.get(key) {
        None | Some(Json::Null) | Some(Json::Bool(false)) => Json::Null,
        Some(Json::String(s)) if s.is_empty() => Json::Null,
        Some(other) => other.clone(),
    }
}

/// `x || ''` of a member.
fn or_empty(v: &Json, key: &str) -> Json {
    match or_null(v, key) {
        Json::Null => Json::from(""),
        other => other,
    }
}

/// `x || []` of a member.
fn or_list(v: &Json, key: &str) -> Json {
    match v.get(key) {
        Some(Json::Array(a)) => Json::Array(a.clone()),
        _ => Json::Array(Vec::new()),
    }
}

/// A member as it stands, absent when it is (`JSON.stringify` drops an
/// `undefined`).
fn put(out: &mut Map<String, Json>, key: &str, from: &Json, member: &str) {
    if let Some(v) = from.get(member) {
        out.insert(key.into(), v.clone());
    }
}

/// `paged(query, rows, name, noun, decorate)`: one list's page.
fn paged(
    asked: &Asked<'_>,
    rows: &[Json],
    name: &str,
    noun: &str,
    decorate: impl Fn(&Json) -> Json,
) -> Json {
    let paging = Paging::of(
        asked.query,
        rows.len(),
        Options {
            name,
            noun,
            ..Options::default()
        },
    );
    let shown: Vec<Json> = paging.slice(rows).iter().map(decorate).collect();
    json!({ "paging": paging.to_json(), "rows": shown })
}

/// `tableOf(counts)` / `table(counts)`: `{ name, count }`, largest first,
/// then by name.
fn table_of(counts: &Json) -> Json {
    let mut rows: Vec<(String, f64)> = counts
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_f64().unwrap_or(0.0)))
                .collect()
        })
        .unwrap_or_default();
    rows.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| sts_registers::js::locale_compare(&a.0, &b.0))
    });
    Json::Array(
        rows.into_iter()
            .map(|(name, count)| {
                let count = if count.fract() == 0.0 {
                    Json::from(count as i64)
                } else {
                    Json::from(count)
                };
                json!({ "name": name, "count": count })
            })
            .collect(),
    )
}

/// `snap.x || 0`.
fn zero(snap: &Json, key: &str) -> Json {
    match snap.get(key) {
        Some(Json::Number(n)) if n.as_f64() != Some(0.0) => {
            Json::Number(n.clone())
        }
        _ => Json::from(0),
    }
}

/// The settings block of the enrollment tab, one family's group.
fn settings_of(asked: &Asked<'_>, group: &str) -> Json {
    asked.setup.map_or(Json::Null, |s| {
        s.page_settings_only("/admin/cert-issuance", &[group])
    })
}

/// The mode's `certificate-enrollment` requirement row.
fn requirement() -> &'static Json {
    &t()["requirement"]
}

/// `core.PROFILE_NEEDS[id] || null`.
fn needs_of(id: &str) -> Json {
    or_null(&t()["profileNeeds"], id)
}

// ---------------------------------------------------------------------
// ACME
// ---------------------------------------------------------------------

/// `endpointsOf(req)`: this realm's ACME endpoints as the request
/// reached it.
fn acme_endpoints(base: &str) -> Json {
    let b = format!("{}/enroll/acme", base);
    json!({
        "directory": format!("{}/directory", b),
        "newNonce": format!("{}/new-nonce", b),
        "newAccount": format!("{}/new-account", b),
        "newOrder": format!("{}/new-order", b),
        "account": format!("{}/account/{{id}}", b),
        "orders": format!("{}/account/{{id}}/orders", b),
        "order": format!("{}/order/{{id}}", b),
        "finalize": format!("{}/order/{{id}}/finalize", b),
        "authorization": format!("{}/authz/{{id}}", b),
        "challenge": format!("{}/challenge/{{id}}", b),
        "certificate": format!("{}/cert/{{id}}", b),
        "revokeCert": format!("{}/revoke-cert", b),
        "keyChange": format!("{}/key-change", b),
        "renewalInfo": format!("{}/renewal-info/{{certID}}", b),
    })
}

/// `accountRow(account)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn acme_account_row(account: &Json) -> Json {
    let entry_uri = account
        .get("entry")
        .and_then(Entry::from_json)
        .map_or(Json::Null, |e| Json::from(e.uri()));
    let orders = account
        .get("orderIds")
        .and_then(Json::as_array)
        .map_or(0, Vec::len);
    let mut row = Map::new();
    put(&mut row, "id", account, "id");
    put(&mut row, "status", account, "status");
    put(&mut row, "entry", account, "entry");
    row.insert("entryUri".into(), entry_uri);
    row.insert("eabKid".into(), or_null(account, "eabKid"));
    put(&mut row, "thumbprint", account, "thumbprint");
    row.insert("contact".into(), or_list(account, "contact"));
    row.insert("orders".into(), Json::from(orders));
    put(&mut row, "createdAt", account, "createdAt");
    row.insert("deactivatedAt".into(), or_null(account, "deactivatedAt"));
    Json::Object(row)
}

/// `authorityJson()`: the ACME Issuing CA, or `present: false`.
fn acme_authority(f: &Families) -> Json {
    let Some(d) = f.core.authority_of("acme") else {
        return json!({ "present": false,
            "note": "This realm has no ACME Issuing CA yet. Build the \
                     hierarchy on /admin/pki; a branch built before the \
                     enrollment use cases existed is topped up with one on \
                     the first issuance." });
    };
    let subject_of = |key: &str| {
        d.get(key)
            .filter(|v| !v.is_null())
            .map_or(Json::Null, |v| v["subject"].clone())
    };
    json!({
        "present": true, "subject": d["subject"], "serialHex": d["serialHex"],
        "keyAlg": d["keyAlg"], "signatureAlg": d["signatureAlg"],
        "notBefore": d["notBefore"], "notAfter": d["notAfter"],
        "thumbprint": d["thumbprint"],
        "intermediate": subject_of("intermediate"), "root": subject_of("root"),
    })
}

/// `modeJson()`.
fn acme_mode(f: &Families) -> Json {
    let row = requirement();
    let text = |k: &str| or_empty(row, k);
    let product = f.core.mode().current() == "product";
    json!({
        "current": f.core.mode().current(), "what": text("what"),
        "development": text("development"), "product": text("product"),
        "inForce": if product { text("product") } else { text("development") },
    })
}

/// `acmeView(req)`: what the ACME server is in this realm.
#[tracing::instrument(level = "debug", skip_all)]
pub fn acme_view(f: &Families, asked: &Asked<'_>) -> Json {
    let core = &f.core;
    let store = f.acme.store();
    let allowed = core.allowed_profiles("acme", None);
    let dflt = core.default_profile("acme", None);
    let descriptions = &t()["acme"]["profileDescriptions"];
    let profiles: Vec<Json> = t()["profileIds"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|id| {
            let id = id.as_str().unwrap_or("");
            json!({ "id": id, "description": or_empty(descriptions, id),
                    "needs": needs_of(id),
                    "allowed": allowed.iter().any(|a| a == id),
                    "isDefault": id == dflt })
        })
        .collect();
    let eab_row = |one: &Json| {
        let bound = one
            .get("boundAccount")
            .and_then(Json::as_str)
            .filter(|b| !b.is_empty())
            .and_then(|b| store.account_by_thumbprint(b));
        json!({ "kid": one["kid"], "entry": one["entry"],
                "entryUri": one["entryUri"], "status": one["status"],
                "createdAt": one["createdAt"], "expiresAt": one["expiresAt"],
                "createdBy": or_empty(one, "createdBy"),
                "boundAt": or_null(one, "boundAt"),
                "boundAccount": bound.map_or(Json::Null, |b| b["id"].clone()) })
    };
    let certificate_row = |one: &Json| {
        let held = store.certificate_by_serial(
            one.get("serialHex").and_then(Json::as_str).unwrap_or(""),
        );
        let mut row = Map::new();
        put(&mut row, "serialHex", one, "serialHex");
        put(&mut row, "profile", one, "profile");
        put(&mut row, "subject", one, "subject");
        row.insert("names".into(), or_list(one, "names"));
        put(&mut row, "entry", one, "entry");
        put(&mut row, "entryUri", one, "entryUri");
        put(&mut row, "status", one, "status");
        row.insert("keyAlg".into(), or_empty(one, "keyAlg"));
        put(&mut row, "notBefore", one, "notBefore");
        put(&mut row, "notAfter", one, "notAfter");
        put(&mut row, "issuedAt", one, "issuedAt");
        row.insert("revoked".into(), or_null(one, "revoked"));
        row.insert(
            "account".into(),
            held.map_or(Json::Null, |h| h["accountId"].clone()),
        );
        Json::Object(row)
    };
    let endpoints = acme_endpoints(asked.base);
    json!({
        "page": "/admin/acme",
        "title": "ACME",
        "enabled": on(f, "acme.enabled"),
        "specifications": ["RFC 8555", "RFC 9773", "RFC 8738", "RFC 8823",
                           "draft-ietf-acme-profiles",
                           "draft-ietf-acme-device-attest"],
        "directory": endpoints["directory"],
        "endpoints": endpoints,
        "challengeType": t()["acme"]["challengeType"],
        "identifierTypes": t()["acme"]["identifierTypes"],
        "authority": acme_authority(f),
        "profiles": profiles,
        "refusedProfiles": t()["refusedProfiles"],
        "mode": acme_mode(f),
        "eabLifetimeS": number_of(f, "acme.eabLifetimeS"),
        "eabKeys": paged(asked, &core.eabs_in_realm(), "credentials",
                         "EAB keys", eab_row),
        "accounts": paged(asked, &store.list_accounts(), "accounts",
                          "accounts", acme_account_row),
        "certificates": paged(asked, &core.certificates_in_realm(Some("acme")),
                              "certificates", "certificates",
                              certificate_row),
        "hostNames": paged(asked, &core.host_names_in_realm(), "hostNames",
                           "entries", Json::clone),
        "revocationReasons": t()["revocationReasonIds"],
        "actions": t()["acme"]["actions"],
        "settings": settings_of(asked, "ACME"),
    })
}

/// `acmeMonitorView(req)`: what the ACME server has done in this realm.
#[tracing::instrument(level = "debug", skip_all)]
pub fn acme_monitor_view(f: &Families, asked: &Asked<'_>) -> Json {
    let snap = f.monitor.snapshot("acme").unwrap_or_else(|| json!({}));
    let recent = snap["recent"].as_array().cloned().unwrap_or_default();
    let page = paged(asked, &recent, "", "requests", Json::clone);
    let mut out = Map::new();
    out.insert("page".into(), Json::from("/admin/acme/monitor"));
    out.insert("title".into(), Json::from("ACME enrollments"));
    put(&mut out, "since", &snap, "startedAt");
    put(&mut out, "realm", &snap, "realm");
    put(&mut out, "processes", &snap, "processes");
    out.insert(
        "totals".into(),
        json!({
            "requests": zero(&snap, "requests"), "issued": zero(&snap, "issued"),
            "refused": zero(&snap, "refused"), "revoked": zero(&snap, "revoked"),
            "accountsBound": zero(&snap, "credentialsRedeemed"),
            "accounts": f.acme.store().list_accounts().len(),
            "certificatesHeld":
                f.core.certificate_counts_in_realm(Some("acme"))["held"],
        }),
    );
    out.insert("operations".into(), table_of(&snap["operations"]));
    out.insert("profiles".into(), table_of(&snap["profiles"]));
    out.insert("principals".into(), table_of(&snap["principals"]));
    out.insert("errorCodes".into(), table_of(&snap["codes"]));
    out.insert("statuses".into(), table_of(&snap["statuses"]));
    out.insert("lastAt".into(), or_null(&snap, "lastAt"));
    out.insert("paging".into(), page["paging"].clone());
    out.insert("recent".into(), page["rows"].clone());
    Json::Object(out)
}

// ---------------------------------------------------------------------
// EST
// ---------------------------------------------------------------------

/// EST's `certificateRow(one)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn est_certificate_row(one: &Json) -> Json {
    let mut row = Map::new();
    for key in ["serialHex", "entry", "entryUri", "profile", "subject"] {
        put(&mut row, key, one, key);
    }
    row.insert("names".into(), or_list(one, "names"));
    row.insert("keyAlg".into(), or_empty(one, "keyAlg"));
    for key in ["keySource", "via", "notBefore", "notAfter", "issuedAt"] {
        put(&mut row, key, one, key);
    }
    row.insert("requestedBy".into(), or_null(one, "requestedBy"));
    row.insert("replaces".into(), or_null(one, "replaces"));
    put(&mut row, "status", one, "status");
    row.insert("revoked".into(), or_null(one, "revoked"));
    put(&mut row, "thumbprint", one, "thumbprint");
    Json::Object(row)
}

/// EST's `modeNote()`.
fn est_mode(f: &Families) -> Json {
    let row = requirement();
    let text = |k: &str| {
        if row.is_null() {
            Json::from("")
        } else {
            row.get(k).cloned().unwrap_or(Json::Null)
        }
    };
    let mut out = Map::new();
    out.insert("current".into(), Json::from(f.core.mode().current()));
    for key in ["development", "product", "where"] {
        let v = text(key);
        if !v.is_null() {
            out.insert(key.into(), v);
        }
    }
    Json::Object(out)
}

/// `estView(req)`: what the EST server is in this realm.
#[tracing::instrument(level = "debug", skip_all)]
pub fn est_view(
    f: &Families,
    registry: &realm::RealmRegistry,
    asked: &Asked<'_>,
) -> Json {
    let core = &f.core;
    let base = asked.base;
    // `realms.estLabelPath()`: a realm other than the default, not itself
    // named like a label, is reached in the label position too.
    let id = realm::current_id();
    let prefix = registry.current_prefix();
    let origin = base.strip_suffix(prefix.as_str()).unwrap_or(base);
    let label_base = (id != realm::DEFAULT_ID && !registry.is_est_label(&id))
        .then(|| format!("{}/.well-known/est/{}", origin, id));
    let operations = t()["est"]["operations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let allowed = core.allowed_profiles("est", None);
    let dflt = core.default_profile("est", None);
    let chain = core.ca_chain_of("est");
    let authority = core.authority_of("est");
    let certificates = core.certificates_in_realm(Some("est"));
    let device = t()["deviceProfile"].as_str().unwrap_or("device");
    let mut ids: Vec<String> = t()["profileIds"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    ids.push(device.to_string());
    let profiles: Vec<Json> = ids
        .iter()
        .map(|id| {
            let mut urls = Map::new();
            for op in &operations {
                let name = op["name"].as_str().unwrap_or("");
                urls.insert(
                    name.into(),
                    Json::from(format!(
                        "{}/.well-known/est/{}/{}",
                        base, id, name
                    )),
                );
            }
            json!({
                "id": id,
                "needs": if id == device {
                    Json::from("a device entry — the one the request's \
                                urn:sts:device: names, or a new one; a TPM \
                                key attestation in product, made over a \
                                nonce from /nonce (#257); simpleenroll only")
                } else {
                    needs_of(id)
                },
                "allowed": allowed.iter().any(|a| a == id),
                "isDefault": *id == dflt,
                "urls": urls,
            })
        })
        .collect();
    let paging = Paging::of(
        asked.query,
        certificates.len(),
        Options {
            name: "certificates",
            noun: "certificates",
            ..Options::default()
        },
    );
    let refused: Vec<Json> = t()["refusedProfiles"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|one| json!({ "id": one["id"], "why": one["why"] }))
        .collect();
    json!({
        "page": "/admin/est",
        "title": "EST",
        "enabled": on(f, "est.enabled"),
        "specifications": ["RFC 7030", "RFC 8951", "RFC 5967", "RFC 2986",
                           "RFC 5652", "RFC 5958",
                           "draft-ietf-lamps-csr-attestation-29",
                           "draft-ietf-lamps-attestation-freshness-08"],
        "endpoints": operations.iter().map(|op| {
            let name = op["name"].as_str().unwrap_or("");
            json!({ "operation": op["name"], "method": op["method"],
                    "section": op["section"], "what": op["what"],
                    "url": format!("{}/.well-known/est/{}", base, name),
                    "labelFormUrl": label_base.as_ref().map_or(Json::Null,
                        |l| Json::from(format!("{}/{}", l, name))) })
        }).collect::<Vec<_>>(),
        "labelForm": label_base.as_ref().map_or(Json::Null, |l| json!({
            "base": l,
            "note": format!(
                "For an EST client that can be given only a host, a port \
                 and one label (libest's estclient is one): this realm is \
                 named in the label position, and a profile after it \
                 ({}/<profile>/<operation>) for a client that can send two \
                 segments. The /realm/ form and this one reach the same \
                 server; a request names the realm once.", l),
        })),
        "hierarchy": {
            "built": chain.is_some(),
            "note": if chain.is_some() { "" } else {
                "This realm has no EST Issuing CA yet: nothing can be \
                 enrolled and /cacerts answers 503. Build the hierarchy on \
                 /admin/pki; the EST Issuing CA is made with the branch." },
            "authority": authority.as_ref().map_or(Json::Null, |a| json!({
                "subject": a["subject"], "serialHex": a["serialHex"],
                "keyAlg": a["keyAlg"], "notBefore": a["notBefore"],
                "notAfter": a["notAfter"], "thumbprint": a["thumbprint"],
                "certificatePem": a["certificatePem"],
            })),
            "chainPem": chain.as_ref().map_or(json!([]), |c| json!(c.chain_pem)),
        },
        "authentication": {
            "basic": on(f, "est.basicAuthentication"),
            "certificate": on(f, "est.certificateAuthentication"),
            "serverKeyGeneration": on(f, "est.serverKeyGeneration"),
            "credentials": [
                { "kind": "password", "what": "HTTP Basic with a person's \
                  directory password (userPassword). Checked in product \
                  mode only.", "managedAt": "/admin/users" },
                { "kind": "client-secret", "what": "HTTP Basic with an \
                  application's client_id and client_secret. Required in \
                  product mode.", "managedAt": "/admin/applications" },
                { "kind": "certificate", "what": "A TLS client certificate \
                  this realm issued and the entry still holds, mapped by its \
                  urn:sts: name. Verified in both modes.",
                  "managedAt": "/admin/est" },
            ],
        },
        "profiles": profiles,
        "defaultProfile": dflt,
        "refusedProfiles": refused,
        "hostNames": core.host_names_in_realm(),
        "certificates": {
            "paging": paging.to_json(),
            "rows": paging.slice(&certificates).iter()
                .map(est_certificate_row).collect::<Vec<_>>(),
        },
        "keyAlgorithms": t()["est"]["keyAlgorithms"],
        "revocationReasons": t()["est"]["revocationReasons"],
        "csrAttributes": {
            "signatureAlgorithms": t()["est"]["signatureAlgorithms"],
        },
        "mode": est_mode(f),
        "actions": t()["est"]["actions"],
        "settings": settings_of(asked, "EST"),
        "monitor": "/admin/est/monitor",
    })
}

/// `estMonitorView(req)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn est_monitor_view(f: &Families, asked: &Asked<'_>) -> Json {
    let snap = f.monitor.snapshot("est").unwrap_or_else(|| json!({}));
    let recent = snap["recent"].as_array().cloned().unwrap_or_default();
    let page = paged(asked, &recent, "", "requests", Json::clone);
    let held = f.core.certificate_counts_in_realm(Some("est"));
    json!({
        "page": "/admin/est/monitor",
        "title": "EST enrollments",
        "since": or_null(&snap, "startedAt"),
        "processes": match snap.get("processes") {
            Some(Json::Number(n)) if n.as_f64() != Some(0.0) =>
                Json::Number(n.clone()),
            _ => Json::from(1),
        },
        "totals": {
            "requests": zero(&snap, "requests"), "issued": zero(&snap, "issued"),
            "refused": zero(&snap, "refused"), "revoked": zero(&snap, "revoked"),
        },
        "certificates": {
            "held": held["held"], "valid": held["valid"],
            "revoked": held["revoked"], "expired": held["expired"],
        },
        "operations": table_of(&snap["operations"]),
        "profiles": table_of(&snap["profiles"]),
        "principals": table_of(&snap["principals"]),
        "errorCodes": table_of(&snap["codes"]),
        "statuses": table_of(&snap["statuses"]),
        "lastAt": or_null(&snap, "lastAt"),
        "paging": page["paging"],
        "recent": page["rows"],
    })
}

// ---------------------------------------------------------------------
// SCEP
// ---------------------------------------------------------------------

/// SCEP's `certificateRow(one)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn scep_certificate_row(one: &Json) -> Json {
    let mut row = Map::new();
    for key in ["serialHex", "entry", "entryUri", "profile", "subject"] {
        put(&mut row, key, one, key);
    }
    row.insert("names".into(), or_list(one, "names"));
    row.insert("keyAlg".into(), or_empty(one, "keyAlg"));
    for key in ["status", "notBefore", "notAfter", "issuedAt"] {
        put(&mut row, key, one, key);
    }
    row.insert("requestedBy".into(), or_null(one, "requestedBy"));
    row.insert("replaces".into(), or_null(one, "replaces"));
    row.insert("revoked".into(), or_null(one, "revoked"));
    row.insert("thumbprint".into(), or_empty(one, "thumbprint"));
    Json::Object(row)
}

/// `scepView(req)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn scep_view(f: &Families, asked: &Asked<'_>) -> Json {
    let core = &f.core;
    let scep_base = format!("{}/enroll/scep", asked.base);
    let chain = core.ca_chain_of("scep");
    let challenges = core.challenges_in_realm();
    let credential_paging = Paging::of(
        asked.query,
        challenges.len(),
        Options {
            name: "credentials",
            noun: "challenge passwords",
            ..Options::default()
        },
    );
    let certificates = core.certificates_in_realm(Some("scep"));
    let certificate_paging = Paging::of(
        asked.query,
        certificates.len(),
        Options {
            name: "certificates",
            noun: "certificates",
            ..Options::default()
        },
    );
    let authority = core.authority_of("scep").map(|d| {
        let short = |key: &str, with_after: bool| {
            d.get(key).filter(|v| !v.is_null()).map_or(Json::Null, |v| {
                if with_after {
                    json!({ "subject": v["subject"],
                            "notAfter": v["notAfter"] })
                } else {
                    json!({ "subject": v["subject"] })
                }
            })
        };
        json!({
            "subject": d["subject"], "serialHex": d["serialHex"],
            "keyAlg": d["keyAlg"], "signatureAlg": d["signatureAlg"],
            "notBefore": d["notBefore"], "notAfter": d["notAfter"],
            "thumbprint": d["thumbprint"],
            "certificatePem": d["certificatePem"],
            "intermediate": short("intermediate", true),
            "root": short("root", true),
        })
    });
    let allowed = core.allowed_profiles("scep", None);
    let device = t()["deviceProfile"].as_str().unwrap_or("device");
    let mut ids: Vec<String> = t()["profileIds"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    ids.push(device.to_string());
    let profiles: Vec<Json> = ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "allowed": allowed.iter().any(|x| x == id),
                "needs": if id == device {
                    Json::from("a device entry — the one the request's \
                                urn:sts:device: names, or a new one; a TPM \
                                key attestation in product")
                } else {
                    or_empty(&t()["profileNeeds"], id)
                },
                "keys": "RSA only over SCEP",
                "url": format!("{}/{}", scep_base, id),
            })
        })
        .collect();
    json!({
        "page": "/admin/scep",
        "title": "SCEP",
        "realm": realm::current_id(),
        "enabled": on(f, "scep.enabled"),
        "specifications": ["RFC 8894", "RFC 5652", "RFC 2986", "RFC 5280"],
        "endpoints": {
            "scep": scep_base,
            "cgi": format!("{}/pkiclient.exe", scep_base),
            "getCaCaps": format!("{}?operation=GetCACaps", scep_base),
            "getCaCert": format!("{}?operation=GetCACert", scep_base),
            "pkiOperation": format!("{}?operation=PKIOperation", scep_base),
        },
        "capabilities": t()["scep"]["capabilities"],
        "operations": t()["scep"]["operations"],
        "messageTypes": t()["scep"]["messageTypes"],
        "algorithms": t()["scep"]["algorithms"],
        "authority": authority.unwrap_or(Json::Null),
        "hierarchyBuilt": chain.is_some(),
        "authorityNote": if chain.is_some() { "" } else {
            "This realm has no SCEP Issuing CA yet. Build the hierarchy on \
             /admin/pki (or POST /admin-api/pki/build); GetCACert answers \
             503 until then." },
        "ra": f.scep.describe_ra(),
        "profiles": profiles,
        "refusedProfiles": t()["refusedProfiles"],
        "defaultProfile": core.default_profile("scep", None),
        "challenges": {
            "paging": credential_paging.to_json(),
            "rows": credential_paging.slice(&challenges).iter().map(|one| {
                let mut row = Map::new();
                for key in ["id", "entry", "entryUri", "profile", "status",
                            "createdAt", "expiresAt"] {
                    put(&mut row, key, one, key);
                }
                row.insert("createdBy".into(), or_empty(one, "createdBy"));
                put(&mut row, "usedAt", one, "usedAt");
                row.insert("url".into(), Json::from(format!("{}/{}",
                    scep_base, one["profile"].as_str().unwrap_or(""))));
                Json::Object(row)
            }).collect::<Vec<_>>(),
        },
        "hostNames": core.host_names_in_realm(),
        "certificates": {
            "paging": certificate_paging.to_json(),
            "rows": certificate_paging.slice(&certificates).iter()
                .map(scep_certificate_row).collect::<Vec<_>>(),
        },
        "exceptions": t()["scep"]["exceptions"],
        "mode": {
            "mode": f.core.mode().current(),
            "requirement": requirement(),
            "scep": "SCEP is not refused over plain HTTP in either mode: \
                     its messages are signed and encrypted CMS (RFC 8894 \
                     section 2.1). The challenge password and the request \
                     signature are verified in both modes.",
        },
        "revokeReasons": t()["scep"]["revokeReasons"],
        "actions": t()["scep"]["actions"],
        "settings": settings_of(asked, "SCEP"),
    })
}

/// `scepMonitorView(req)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn scep_monitor_view(f: &Families, asked: &Asked<'_>) -> Json {
    let snap = f.monitor.snapshot("scep").unwrap_or_else(|| json!({}));
    let recent = snap["recent"].as_array().cloned().unwrap_or_default();
    let page = paged(asked, &recent, "", "requests", Json::clone);
    let obj = |k: &str| match snap.get(k) {
        Some(Json::Object(o)) => Json::Object(o.clone()),
        _ => json!({}),
    };
    let mut out = Map::new();
    out.insert("page".into(), Json::from("/admin/scep/monitor"));
    out.insert("title".into(), Json::from("SCEP enrollments"));
    out.insert("realm".into(), Json::from(realm::current_id()));
    put(&mut out, "since", &snap, "startedAt");
    put(&mut out, "processes", &snap, "processes");
    out.insert(
        "totals".into(),
        json!({
            "requests": zero(&snap, "requests"), "issued": zero(&snap, "issued"),
            "refused": zero(&snap, "refused"), "revoked": zero(&snap, "revoked"),
            "challengesCreated": zero(&snap, "credentialsCreated"),
        }),
    );
    out.insert("operations".into(), obj("operations"));
    out.insert("profiles".into(), obj("profiles"));
    out.insert("principals".into(), obj("principals"));
    out.insert("errorCodes".into(), obj("codes"));
    out.insert("statuses".into(), obj("statuses"));
    out.insert("failInfo".into(), obj("failInfos"));
    out.insert(
        "issuedCertificates".into(),
        f.core.certificate_counts_in_realm(Some("scep"))["held"].clone(),
    );
    out.insert("lastAt".into(), or_null(&snap, "lastAt"));
    out.insert("paging".into(), page["paging"].clone());
    out.insert("recent".into(), page["rows"].clone());
    Json::Object(out)
}

// ---------------------------------------------------------------------
// THE CERTIFICATE AUTHORITY: `GET /admin-api/pki` (`pki_admin.ts`'s
// `pkiJson()`).
//
// PORTED: the realm, the three-tier `chain`, the vocabularies and tiers,
// the revocation REGISTER of the authorities this realm is under (each
// list searched, then paged, five a page), the report's sentences, the
// published actions, the subject kinds and purposes, the person key-pair
// constants, the page's defaults and the settings block.
//
// `issued` with its paging, search and shown rows (the `apis3` slice) and
// `personsStorable` are ported.
//
// NOT PORTED, and absent from the answer rather than answered empty (each
// member is optional in the model, and an empty list would say "none"):
// `persons` with its paging, search and shown rows (a person's key pairs,
// `personAssertions.holders()`, are not in this runtime), `tree`, `workbench` (the Certificate Workbench,
// `common/pki_authoring.ts`), `pinnedSigners` and `personsStorable`. A
// post-quantum tier's `pqc` is null here (`pqcSupport.of()` is not ported;
// a classical one is null in Node too). `revocationNote` is the sentence
// Node writes under the mode's DEFAULT revocation policy; a policy changed
// by `pki.revocation*` settings is not described
// (`revocation_status.describePolicy()` is not ported).
// ---------------------------------------------------------------------

/// `PKI_MAX_PER_PAGE`, which is also `REVOCATION_PER_PAGE`.
const PKI_MAX_PER_PAGE: i64 = 5;

/// `searchRows(term, rows, textOf)`: a case-insensitive substring of any
/// of the row's texts; every row for no term.
fn search_rows(
    term: Option<&str>,
    rows: Vec<Json>,
    text_of: impl Fn(&Json) -> Vec<Json>,
) -> Vec<Json> {
    let needle = term.unwrap_or("").trim().to_lowercase();
    if needle.is_empty() {
        return rows;
    }
    rows.into_iter()
        .filter(|row| {
            text_of(row).iter().any(|t| {
                let s = match t {
                    Json::Null => return false,
                    Json::String(s) => s.clone(),
                    other => other.to_string(),
                };
                s.to_lowercase().contains(&needle)
            })
        })
        .collect()
}

/// `listNameOf(scopeSegment, ca)`.
fn list_name_of(segment: &str, ca: &str) -> String {
    let clean = |text: &str| {
        let t = if text.is_empty() { "default" } else { text };
        let mapped: String = t
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || c == '_'
                    || c == '-'
                {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        mapped.chars().take(58).collect::<String>()
    };
    format!("ca-{}-{}", clean(segment), clean(ca))
}

/// A search term as `keyPairListView()` keeps it: trimmed, at most 200.
fn term_of(asked: &Asked<'_>, name: &str) -> Option<String> {
    let raw = asked.query.get(name)?;
    let text = match raw {
        Json::String(s) => s.trim().to_string(),
        Json::Null => return None,
        other => other.to_string(),
    };
    (!text.is_empty() && text.encode_utf16().count() <= 200).then_some(text)
}

/// `describeEntry(one)`.
fn describe_entry(one: &Json) -> Json {
    let reason = one["reason"].as_str().unwrap_or("");
    let what = t()["pki"]["reasons"]
        .as_array()
        .and_then(|a| a.iter().find(|r| r["id"] == reason))
        .map_or(Json::from(""), |r| r["what"].clone());
    let mut row = Map::new();
    put(&mut row, "serialHex", one, "serialHex");
    put(&mut row, "revokedAt", one, "revokedAt");
    put(&mut row, "reason", one, "reason");
    put(&mut row, "reasonCode", one, "reasonCode");
    row.insert("reasonWhat".into(), what);
    row.insert("subject".into(), or_empty(one, "subject"));
    row.insert("note".into(), or_empty(one, "note"));
    Json::Object(row)
}

/// `revocationModel(query)`: the register of the authorities this realm is
/// under — the Root, the process branch and this realm's.
fn revocation_model(a: &Authority, f: &Families, asked: &Asked<'_>) -> Json {
    use sts_pki::authority::catalog::{scope_segment, PROCESS_SCOPE};
    use sts_pki::authority::merge::normal_serial;
    let mut scopes = vec![PROCESS_SCOPE.to_string()];
    let here = realm::current_id();
    if !scopes.contains(&here) {
        scopes.push(here);
    }
    let mut total_revoked = 0usize;
    let authorities: Vec<Json> = a
        .authorities(&scopes)
        .into_iter()
        .map(|one| {
            let points = a.distribution_points(&one.scope, &one.ca);
            let segment = scope_segment(&one.scope);
            let list_name = list_name_of(&segment, &one.ca);
            let issued_all = a.issued_list(&one.scope, &one.ca);
            let revoked_all = a.list_for(&one.scope, &one.ca);
            total_revoked += revoked_all.len();
            let by_serial: std::collections::HashMap<String, Json> =
                revoked_all
                    .iter()
                    .map(|e| {
                        (
                            normal_serial(
                                e["serialHex"].as_str().unwrap_or(""),
                            ),
                            e.clone(),
                        )
                    })
                    .collect();
            let issued_serials: std::collections::HashSet<String> = issued_all
                .iter()
                .map(|c| c["serialHex"].as_str().unwrap_or("").to_string())
                .collect();
            let orphans_all: Vec<Json> = revoked_all
                .iter()
                .filter(|e| {
                    !issued_serials.contains(&normal_serial(
                        e["serialHex"].as_str().unwrap_or(""),
                    ))
                })
                .cloned()
                .collect();
            let issued_search =
                term_of(asked, &format!("{}-issuedq", list_name));
            let orphans_search =
                term_of(asked, &format!("{}-orphansq", list_name));
            let issued_matched = search_rows(
                issued_search.as_deref(),
                issued_all.clone(),
                |c| {
                    vec![
                        c["serialHex"].clone(),
                        c["subject"].clone(),
                        c["label"].clone(),
                        c["kind"].clone(),
                    ]
                },
            );
            let orphans_matched = search_rows(
                orphans_search.as_deref(),
                orphans_all.clone(),
                |e| {
                    vec![
                        e["serialHex"].clone(),
                        Json::from(normal_serial(
                            e["serialHex"].as_str().unwrap_or(""),
                        )),
                        e["subject"].clone(),
                        e["reason"].clone(),
                        e["note"].clone(),
                    ]
                },
            );
            let issued_name = format!("{}-issued", list_name);
            let orphans_name = format!("{}-orphans", list_name);
            let five = Options {
                default_per: Some(PKI_MAX_PER_PAGE),
                max_per: Some(PKI_MAX_PER_PAGE),
                ..Options::default()
            };
            let issued_page = Paging::of(
                asked.query,
                issued_matched.len(),
                Options {
                    name: &issued_name,
                    noun: "certificates",
                    ..five
                },
            );
            let orphans_page = Paging::of(
                asked.query,
                orphans_matched.len(),
                Options {
                    name: &orphans_name,
                    noun: "revoked serials",
                    ..five
                },
            );
            let issued: Vec<Json> = issued_page
                .slice(&issued_matched)
                .into_iter()
                .map(|cert| {
                    let serial = cert["serialHex"].as_str().unwrap_or("");
                    let entry = by_serial.get(serial);
                    let mut row = cert.as_object().cloned().unwrap_or_default();
                    row.insert("revoked".into(), Json::Bool(entry.is_some()));
                    row.insert(
                        "revokedAt".into(),
                        entry.map_or(Json::Null, |e| e["revokedAt"].clone()),
                    );
                    row.insert(
                        "revokedReason".into(),
                        entry.map_or(Json::Null, |e| e["reason"].clone()),
                    );
                    row.insert(
                        "held".into(),
                        Json::Bool(
                            entry.is_some_and(|e| {
                                e["reason"] == "certificateHold"
                            }),
                        ),
                    );
                    Json::Object(row)
                })
                .collect();
            let revoked: Vec<Json> = issued
                .iter()
                .filter(|c| c["revoked"] == true)
                .filter_map(|c| by_serial.get(c["serialHex"].as_str()?))
                .map(describe_entry)
                .collect();
            json!({
                "scope": one.scope, "scopeSegment": segment, "ca": one.ca,
                "label": one.label, "subject": one.tier["subject"],
                "notAfter": one.tier["notAfter"],
                "issued": issued,
                "issuedTotal": issued_all.len(),
                "issuedPaging": issued_page.to_json(),
                "issuedSearch": issued_search,
                "orphansSearch": orphans_search,
                "revoked": revoked,
                "revokedTotal": revoked_all.len(),
                "revokedNotIssued": orphans_page.slice(&orphans_matched)
                    .iter().map(describe_entry).collect::<Vec<_>>(),
                "revokedNotIssuedTotal": orphans_all.len(),
                "orphansPaging": orphans_page.to_json(),
                "crl": { "http": points.http, "ldap": points.ldap },
                "ocsp": points.ocsp,
                "caIssuers": points.ca_issuers,
                "directoryDn": points.dn,
                "listName": list_name,
            })
        })
        .collect();
    json!({
        "reasons": t()["pki"]["reasons"],
        "authorities": authorities,
        "totalRevoked": total_revoked,
        "crlLifetimeMinutes": number_of(f, "pki.crlLifetimeMinutes"),
        "publishedToDirectory": on_truthy(f, "pki.publishCrlToDirectory"),
    })
}

/// `!!config.value(key)`.
fn on_truthy(f: &Families, key: &str) -> bool {
    match f.settings.value_of(key) {
        SettingValue::Bool(b) => b,
        other => !other.as_str().is_empty(),
    }
}

/// `report.residency`: where the CA private keys live.
fn residency(a: &Authority) -> Json {
    if a.persists() {
        Json::from(
            "The CA private keys are in the persistence store, sealed under \
             the same key-encryption key as the signing keys, and survive a \
             restart.",
        )
    } else {
        t()["pki"]["residency"].clone()
    }
}

/// Every node of the chain holding a certificate gains `pqc`
/// (`classify()`); null for a classical key, as Node answers it.
fn classify(node: &mut Json) {
    match node {
        Json::Array(items) => items.iter_mut().for_each(classify),
        Json::Object(o) => {
            if o.contains_key("certificatePem") && !o.contains_key("pqc") {
                o.insert("pqc".into(), Json::Null);
            }
            for (k, v) in o.iter_mut() {
                if k != "pqc" && (v.is_object() || v.is_array()) {
                    classify(v);
                }
            }
        }
        _ => {}
    }
}

/// `listenerDefaultKeyAlg()`: `pki.keyAlgorithm`, or the classical default
/// where that is a composite no listener chain may hold.
fn listener_default_key_alg(a: &Authority, f: &Families) -> String {
    let configured =
        f.settings.value_of("pki.keyAlgorithm").as_str().to_string();
    if !configured.is_empty()
        && sts_pki::authority::hierarchy::is_composite(&configured)
    {
        format!("rsa-{}", a.config().default_rsa_bits)
    } else {
        configured
    }
}

/// `pkiJson(req)`: what `GET /admin-api/pki` answers.
#[tracing::instrument(level = "debug", skip_all)]
pub fn pki_view(
    a: &Authority,
    f: &Families,
    asked: &Asked<'_>,
    applications: Vec<Json>,
) -> Json {
    let p = &t()["pki"];
    // `realmLabel()`: the realm's id.
    let label = realm::current_id();
    let mut chain = super::describe_chain(a, &realm::current_id());
    classify(&mut chain);
    let setting = |key: &str| match f.settings.value_of(key) {
        SettingValue::Int(n) => Json::from(n),
        SettingValue::Bool(b) => Json::Bool(b),
        other => Json::from(other.as_str()),
    };
    let (issued, issued_paging, issued_search, issued_shown) =
        issued_rows(p, &applications, asked);
    json!({
        "issued": issued,
        "issuedPaging": issued_paging,
        "issuedSearch": issued_search,
        "issuedShown": issued_shown,
        // `personAssertions.storable()`: `!!directory`, and the directory
        // is always loaded here.
        "personsStorable": true,
        "realm": label,
        "chain": chain,
        "keyAlgorithms": p["keyAlgorithms"],
        "signatureAlgorithms": p["signatureAlgorithms"],
        "tiers": p["tiers"],
        "revocation": revocation_model(a, f, asked),
        // The sentence of the mode's default revocation policy: soft-fail
        // in development, hard-fail in product.
        "revocationNote": if f.core.mode().current() == "product" {
            p["revocationNoteProduct"].clone()
        } else {
            p["revocationNote"].clone()
        },
        "residency": residency(a),
        "encoder": p["encoder"],
        "actions": p["actions"],
        "personSigningKeyMax": p["personSigningKeyMax"],
        "personRevocationReasons": p["personRevocationReasons"],
        "personAttributes": p["personAttributes"],
        "personIssuerAttribute": p["personIssuerAttribute"],
        "subjectKinds": p["subjectKinds"],
        "purposes": p["purposes"],
        "settings": asked.setup.map_or(Json::Null,
                                       |s| s.page_settings("/admin/pki")),
        "pageDefaults": {
            "keyAlgorithm": listener_default_key_alg(a, f),
            "organisation": setting("pki.organisation"),
            "leafLifetimeDays": setting("pki.leafLifetimeDays"),
            "alternativeKeyAlgorithm": setting("pki.alternativeKeyAlgorithm"),
        },
        "tierLabels": p["tierLabels"],
        "serviceScope": p["serviceScope"],
    })
}

/// `KEY_PAIR_ATTRIBUTES[purpose]`: the issuer, handle, private key,
/// expiry, certificate, source and registered-key attributes.
fn key_pair_attributes(purpose: &str) -> [&'static str; 7] {
    if purpose == "saml" {
        [
            "oauthSamlAssertionIssuer",
            "oauthSamlAssertionThumbprint",
            "oauthSamlAssertionPrivateKey",
            "oauthSamlAssertionExpiresAt",
            "oauthSamlAssertionCertificate",
            "oauthSamlAssertionKeySource",
            "oauthSamlAssertionSigningCertificate",
        ]
    } else {
        [
            "oauthAssertionIssuer",
            "oauthAssertionKid",
            "oauthAssertionPrivateKey",
            "oauthAssertionExpiresAt",
            "oauthAssertionCertificate",
            "oauthAssertionKeySource",
            "oauthJwks",
        ]
    }
}

/// `String(value)` of a field: an array joined with commas.
fn js_text(value: &Json) -> String {
    match value {
        Json::Null => "null".into(),
        Json::String(s) => s.clone(),
        Json::Array(l) => l
            .iter()
            .map(|v| match v {
                Json::Null => String::new(),
                other => js_text(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

/// `!!value`, as a field holds one.
fn js_truthy(value: Option<&Json>) -> bool {
    match value {
        None | Some(Json::Null) | Some(Json::Bool(false)) => false,
        Some(Json::String(s)) => !s.is_empty(),
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true,
    }
}

/// `pkiJson()`'s `issued` — every application holding a managed key pair,
/// an assertion issuer or a key registered by value, per purpose — and
/// `keyPairPaging()`'s page of it: searched by `issuedq` (the identifier,
/// the purpose's label, the handle and the issuers), five a page, the shown
/// rows by index. Each row's `pqc` is null, as a classical certificate's
/// is in Node (`pqcSupport.of()` is not ported).
fn issued_rows(
    p: &Json,
    applications: &[Json],
    asked: &Asked<'_>,
) -> (Vec<Json>, Json, Json, Json) {
    let mut rows: Vec<Json> = Vec::new();
    for purpose in ["jwt", "saml"] {
        let [issuer, handle, private_key, expires, certificate, source, registered] =
            key_pair_attributes(purpose);
        let label = p["purposes"]
            .as_array()
            .and_then(|l| l.iter().find(|one| one["id"] == purpose))
            .map_or(Json::from(""), |one| one["label"].clone());
        for one in applications {
            let fields = &one["fields"];
            let field = |k: &str| fields.get(k).filter(|v| js_truthy(Some(v)));
            let text = |k: &str| field(k).map(js_text).unwrap_or_default();
            let issuers: Vec<String> = match fields.get(issuer) {
                None | Some(Json::Null) => Vec::new(),
                Some(Json::Array(l)) => l.iter().map(js_text).collect(),
                Some(v) => vec![js_text(v)],
            }
            .into_iter()
            .filter(|v| !v.is_empty())
            .collect();
            let has_key_pair =
                field(private_key).is_some() || field(certificate).is_some();
            let registered_own = field(registered).is_some();
            if !(has_key_pair || !issuers.is_empty() || registered_own) {
                continue;
            }
            rows.push(json!({
                "identifier": one["identifier"],
                "name": one["name"],
                "purpose": purpose,
                "purposeLabel": label,
                "handleLabel": if purpose == "saml" { "thumbprint" }
                               else { "kid" },
                "handle": text(handle),
                "expiresAt": text(expires),
                "hasKeyPair": has_key_pair,
                "privateKeyHeld": field(private_key).is_some(),
                "source": if field(source).is_some() { text(source) }
                          else if field(private_key).is_some() {
                              "issued".to_string() }
                          else { String::new() },
                "assertionIssuers": issuers,
                "registeredOwnKeys": registered_own,
                "pqc": Json::Null,
            }));
        }
    }
    let search = term_of(asked, "issuedq");
    let matched = search_rows(search.as_deref(), rows.clone(), |one| {
        let mut texts = vec![
            one["identifier"].clone(),
            one["purposeLabel"].clone(),
            one["handle"].clone(),
        ];
        texts.extend(
            one["assertionIssuers"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
        texts
    });
    let paging = Paging::of(
        asked.query,
        matched.len(),
        Options {
            name: "issued",
            noun: "application rows",
            default_per: Some(PKI_MAX_PER_PAGE),
            max_per: Some(PKI_MAX_PER_PAGE),
        },
    );
    let shown: Vec<Json> = paging
        .slice(&matched)
        .iter()
        .filter_map(|row| rows.iter().position(|r| r == row))
        .map(Json::from)
        .collect();
    (
        rows,
        paging.to_json(),
        search.map_or(Json::Null, Json::from),
        Json::Array(shown),
    )
}

/// `protocolEndpoints` (`forPage()`), appended to a successful GET that
/// mirrors a Protocols page as `sendJson()` appends it: Node's HTTP rows
/// for the page, each `url` the request's realm base and the route. The
/// SPIFFE socket rows Node adds report its live listeners, which are not
/// in this runtime, and are left out.
#[tracing::instrument(level = "trace", skip_all)]
pub fn with_protocol_endpoints(mut body: Json, asked: &Asked<'_>) -> Json {
    let Some(rows) = t()["protocolEndpoints"]
        .get(asked.operation_id)
        .and_then(Json::as_array)
    else {
        return body;
    };
    let rows: Vec<Json> = rows
        .iter()
        .map(|one| {
            let mut row = one.clone();
            let path = one["url"].as_str().unwrap_or("");
            row["url"] = Json::from(format!("{}{}", asked.base, path));
            row
        })
        .collect();
    if let Some(o) = body.as_object_mut() {
        o.insert("protocolEndpoints".into(), Json::Array(rows));
    }
    body
}
