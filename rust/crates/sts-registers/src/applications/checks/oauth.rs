// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE OAUTH AND OPENID METADATA CHECKS of `common/applications.js`, as an
//! ATTRIBUTE WRITE reaches them (`normaliseFields()`,
//! `updateApplication()`): each `…AttributeProblem()` builds the members
//! its `…MetadataProblem()` reads from the value written and the entry's
//! other attributes, and answers that function's sentence with the member
//! name replaced by the attribute's.
//!
//! What an attribute write can hand them is a STRING (or, for
//! `require_signed_request_object`, a boolean read off `TRUE`/`FALSE`), so
//! the `registrationTypeFits()` arms that refuse a registration document's
//! wrong JSON type cannot be reached from here and are not carried; they
//! belong to the registration endpoint's port.
//!
//! THE ALGORITHM LISTS. Node's `stsCrypto.JWS_SIGNING_ALGS` is the
//! algorithm registry's recorded JOSE names (`Registry::recorded_names`),
//! `JWE_ASYMMETRIC_ALGS` / `JWE_DECRYPT_ALGS` are `sts_crypto::jwe::algs()`
//! (in `crypto.js`'s `JWE_ALGS` order) without and with the symmetric
//! ones, and `JWE_ENCS`' keys are `sts_crypto::jwe::ENCS`. `helpers.js`'s
//! narrowing of each (`signableJwsAlgs()`, `offeredJwsAlgs()`,
//! `offeredJweAlgs()`, `decryptableJweAlgs()`, the signature policy's
//! `joseSignList()` and unapproved-curve rule) is ported below over the
//! settings and mode predicates the register's environment answers.
//!
//! THE EXTERNAL MODULES THE RFC 9396 AND RFC 8705 CHECKS REACH —
//! `xacml/fga_map.ts` (`mappingOf()`, `uncovered()`),
//! `xacml/xacml_attribute_rows.ts` (the row grammar),
//! `authzen/authzen_catalogue.ts` (`parse()`) and
//! `common/certificate_subject.js` (`valueProblem()`) — are ported here in
//! the parts these checks call, because no Rust crate holds them yet.
//!
//! TWO TEXTS ARE OTHER LIBRARIES' WORDS. `JSON.parse()`'s message is V8's,
//! reproduced by [`v8_json_problem`] for every refusal V8 words; ajv's
//! compile error for a schema that is not a JSON Schema is the
//! `jsonschema` crate's here, after Node's own prefix.

use regex::Regex;
use serde_json::{Map, Value};
use sts_core::errors::{codes, ErrorCode};
use sts_crypto::algorithms::{Registry, Surface};
use sts_crypto::jwe;

use super::Coded;
use crate::applications::record::values_of;
use crate::applications::{ApplicationRegistry, Fields};
use crate::js;

// ---------------------------------------------------------------------------
// The algorithm lists and their narrowing.
// ---------------------------------------------------------------------------

// `stsCrypto.JWS_SIGNING_ALGS`.
fn jws_signing_algs() -> Vec<String> {
    Registry::get().recorded_names("jose")
}

fn jose_family(alg: &str) -> String {
    Registry::get()
        .by_spelling(Surface::Jose, alg)
        .map(|row| row.family.clone())
        .unwrap_or_default()
}

// `stsCrypto.isPqJwsAlg(alg)`.
fn is_pq_jws_alg(alg: &str) -> bool {
    jose_family(alg) == "pq"
}

// `helpers.isEddsaJwsAlg(alg)`.
fn is_eddsa_jws_alg(alg: &str) -> bool {
    alg == "Ed25519" || alg == "Ed448" || jose_family(alg) == "okp"
}

// `SignaturePolicy.parsed(raw)`: a csv setting as a list.
fn parsed_list(raw: &Value) -> Vec<String> {
    let items: Vec<String> = match raw {
        Value::Array(list) => list.iter().map(js::string).collect(),
        other => js::or_empty(Some(other))
            .split(',')
            .map(str::to_string)
            .collect(),
    };
    items
        .into_iter()
        .map(|one| js::trim(&one).to_string())
        .filter(|one| !one.is_empty())
        .collect()
}

// `SignaturePolicy.joseSignList()`.
fn jose_sign_list(reg: &ApplicationRegistry) -> Option<Vec<String>> {
    let mut list = parsed_list(&reg.env().setting("keys.signingAlgorithms"));
    if list.is_empty() {
        return None;
    }
    if !list.iter().any(|one| one == "RS256") {
        list.push("RS256".into());
    }
    Some(list)
}

// `helpers.listedSigningAlgs(base)`, with `signingAlgListed()` and
// `SignaturePolicy.omitsUnapprovedCurves()`.
fn listed_signing_algs(
    reg: &ApplicationRegistry,
    base: Vec<String>,
) -> Vec<String> {
    let list = jose_sign_list(reg);
    let omits =
        list.is_none() && reg.env().mode("omitsUnapprovedSigningCurves");
    if list.is_none() && !omits {
        return base;
    }
    base.into_iter()
        .filter(|alg| match &list {
            Some(l) => alg == "none" || l.contains(alg),
            None => !(alg == "ES256K" && omits),
        })
        .collect()
}

// `helpers.offeredJwsAlgs(base)`.
fn offered_jws_algs(reg: &ApplicationRegistry, base: Vec<String>) -> Vec<String> {
    let on =
        reg.env().setting("keys.postQuantumSigning") != Value::Bool(false);
    base.into_iter()
        .filter(|alg| on || !is_pq_jws_alg(alg))
        .collect()
}

// `helpers.signableJwsAlgs(base)`.
fn signable_jws_algs(
    reg: &ApplicationRegistry,
    base: Vec<String>,
) -> Vec<String> {
    let on = reg.env().setting("keys.eddsaSigning") == Value::Bool(true);
    listed_signing_algs(reg, offered_jws_algs(reg, base))
        .into_iter()
        .filter(|alg| on || !is_eddsa_jws_alg(alg))
        .collect()
}

// `stsCrypto.describeJweKemAlg(alg)` is not null.
fn is_kem_jwe_alg(alg: &str) -> bool {
    jwe::alg(alg).is_some_and(|a| {
        matches!(
            a.kind,
            jwe::AlgKind::MlKem { .. } | jwe::AlgKind::Hpke { .. }
        )
    })
}

// `stsCrypto.JWE_ASYMMETRIC_ALGS`.
fn jwe_asymmetric_algs() -> Vec<String> {
    jwe::algs()
        .into_iter()
        .filter(|a| !a.is_symmetric())
        .map(|a| a.name)
        .collect()
}

// `stsCrypto.JWE_DECRYPT_ALGS`: every one.
fn jwe_decrypt_algs() -> Vec<String> {
    jwe::algs().into_iter().map(|a| a.name).collect()
}

// `Object.keys(stsCrypto.JWE_ENCS)`.
fn jwe_encs() -> Vec<String> {
    jwe::ENCS.iter().map(|e| e.name.to_string()).collect()
}

// `helpers.offeredJweAlgs(base)`.
fn offered_jwe_algs(reg: &ApplicationRegistry, base: Vec<String>) -> Vec<String> {
    let offered =
        reg.env().setting("keys.offerKemEncryption") == Value::Bool(true);
    let legacy = reg.env().mode("allowsLegacyHashes");
    base.into_iter()
        .filter(|one| legacy || one != "RSA-OAEP")
        .filter(|alg| offered || !is_kem_jwe_alg(alg))
        .collect()
}

// `helpers.kemAlgsConfigured()`.
fn kem_algs_configured(reg: &ApplicationRegistry) -> Vec<String> {
    let asymmetric = jwe_asymmetric_algs();
    let mut out: Vec<String> = Vec::new();
    for one in parsed_list(&reg.env().setting("keys.encryptionKemAlgs")) {
        if !out.contains(&one) && asymmetric.contains(&one) && is_kem_jwe_alg(&one)
        {
            out.push(one);
        }
    }
    out
}

// `helpers.decryptableJweAlgs(base)`.
fn decryptable_jwe_algs(
    reg: &ApplicationRegistry,
    base: Vec<String>,
) -> Vec<String> {
    let held = kem_algs_configured(reg);
    base.into_iter()
        .filter(|alg| !is_kem_jwe_alg(alg) || held.contains(alg))
        .collect()
}

// `permittedEncs(list)`: the CBC ones only where the mode allows them.
fn permitted_encs(reg: &ApplicationRegistry, list: Vec<String>) -> Vec<String> {
    if reg.env().mode("allowsCbcJwe") {
        return list;
    }
    list.into_iter().filter(|one| !one.contains("CBC")).collect()
}

// ---------------------------------------------------------------------------
// The shared shape of a metadata refusal.
// ---------------------------------------------------------------------------

// A `…MetadataProblem()` answer: the member and its sentence.
struct Refusal {
    member: String,
    description: String,
}

fn refusal(member: &str, description: impl AsRef<str>) -> Refusal {
    Refusal {
        member: member.to_string(),
        description: format!("{}: {}", member, description.as_ref()),
    }
}

// `problem.description.replace(problem.member, ATTRIBUTES[problem.member])`.
fn renamed(problem: Refusal, table: &[(&str, &str)]) -> String {
    let attribute = table
        .iter()
        .find(|(m, _)| *m == problem.member)
        .map(|(_, a)| *a)
        .unwrap_or("undefined");
    problem.description.replacen(&problem.member, attribute, 1)
}

// The member a table names for an attribute.
fn member_of(
    table: &[(&'static str, &str)],
    attribute: &str,
) -> Option<&'static str> {
    table.iter().find(|(_, a)| *a == attribute).map(|(m, _)| *m)
}

// The attribute a table names for a member.
fn attribute_of<'t>(table: &[(&str, &'t str)], member: &str) -> &'t str {
    table
        .iter()
        .find(|(m, _)| *m == member)
        .map(|(_, a)| *a)
        .unwrap_or("")
}

// `String(valuesOf(fields[name])[0])`, '' for none.
fn held(fields: &Fields, name: &str) -> String {
    values_of(fields.get(name)).into_iter().next().unwrap_or_default()
}

// `String(value === undefined || value === null ? '' : value).trim()`.
fn trimmed(value: &str) -> String {
    js::trim(value).to_string()
}

// `JSON.stringify(text)`.
fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_default()
}

// `String(asked[name] || '').trim()`.
fn str_member(values: &Map<String, Value>, name: &str) -> String {
    trimmed(&js::or_empty(values.get(name)))
}

fn upper_bool(text: &str) -> bool {
    ["TRUE", "FALSE"].contains(&text.to_uppercase().as_str())
}

// ---------------------------------------------------------------------------
// RFC 9701: the introspection response members.
// ---------------------------------------------------------------------------

/// `INTROSPECTION_ATTRIBUTES`.
pub const INTROSPECTION_ATTRIBUTES: &[(&str, &str)] = &[
    (
        "introspection_signed_response_alg",
        "oauthIntrospectionSignedResponseAlg",
    ),
    (
        "introspection_encrypted_response_alg",
        "oauthIntrospectionEncryptedResponseAlg",
    ),
    (
        "introspection_encrypted_response_enc",
        "oauthIntrospectionEncryptedResponseEnc",
    ),
];

// `introspectionResponseProblem(values)`, over string members.
fn introspection_response_problem(
    reg: &ApplicationRegistry,
    values: &Map<String, Value>,
) -> Option<Refusal> {
    let sign = str_member(values, "introspection_signed_response_alg");
    let alg = str_member(values, "introspection_encrypted_response_alg");
    let enc = str_member(values, "introspection_encrypted_response_enc");
    let signable = signable_jws_algs(reg, jws_signing_algs());
    if !sign.is_empty() && !signable.contains(&sign) {
        let why = if sign.to_lowercase() == "none" {
            "is refused: RFC 9701 section 5 says an introspection response \
             MUST be cryptographically secured, so there is no unsigned one."
                .to_string()
        } else {
            format!(
                "is not an algorithm this service signs with. It signs with \
                 {} (see introspection_signing_alg_values_supported).",
                signable.join(", ")
            )
        };
        return Some(refusal(
            "introspection_signed_response_alg",
            format!("\"{}\" {}", sign, why),
        ));
    }
    let offered = offered_jwe_algs(reg, jwe_asymmetric_algs());
    if !alg.is_empty() && !offered.contains(&alg) {
        return Some(refusal(
            "introspection_encrypted_response_alg",
            format!(
                "\"{}\" is not an algorithm this service encrypts a response \
                 with. It encrypts with {} (see \
                 introspection_encryption_alg_values_supported). The \
                 symmetric families are for a document encrypted TO this \
                 service; a response is encrypted to the key you registered.",
                alg,
                offered.join(", ")
            ),
        ));
    }
    if !enc.is_empty() && alg.is_empty() {
        return Some(refusal(
            "introspection_encrypted_response_enc",
            "RFC 9701 section 6 says it MUST NOT be specified without \
             introspection_encrypted_response_alg, and none is registered.",
        ));
    }
    let encs = permitted_encs(reg, jwe_encs());
    if !enc.is_empty() && !encs.contains(&enc) {
        return Some(refusal(
            "introspection_encrypted_response_enc",
            format!(
                "\"{}\" is not a content encryption algorithm this service \
                 has. It has {} (see \
                 introspection_encryption_enc_values_supported).",
                enc,
                encs.join(", ")
            ),
        ));
    }
    None
}

/// `introspectionAttributeProblem(attribute, value, fields)`.
#[tracing::instrument(level = "debug", skip(reg, fields))]
pub fn introspection_attribute_problem(
    reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
    fields: &Fields,
) -> Option<String> {
    let member = member_of(INTROSPECTION_ATTRIBUTES, attribute)?;
    if js::trim(value).is_empty() {
        return None;
    }
    let mut values = Map::new();
    for (name, attr) in INTROSPECTION_ATTRIBUTES {
        values.insert((*name).into(), Value::String(held(fields, attr)));
    }
    values.insert(member.into(), Value::String(value.to_string()));
    introspection_response_problem(reg, &values)
        .map(|p| renamed(p, INTROSPECTION_ATTRIBUTES))
}

// ---------------------------------------------------------------------------
// RFC 9101: the request object members.
// ---------------------------------------------------------------------------

/// `REQUEST_OBJECT_ATTRIBUTES`.
pub const REQUEST_OBJECT_ATTRIBUTES: &[(&str, &str)] = &[
    ("request_uris", "oauthRequestUri"),
    ("request_object_signing_alg", "oauthRequestObjectSigningAlg"),
    ("request_object_encryption_alg", "oauthRequestObjectEncryptionAlg"),
    ("request_object_encryption_enc", "oauthRequestObjectEncryptionEnc"),
    (
        "require_signed_request_object",
        "oauthRequireSignedRequestObject",
    ),
];

/// `requestUriProblem(value)`: None for a usable request_uri.
#[tracing::instrument(level = "debug", skip(reg))]
pub fn request_uri_problem(
    reg: &ApplicationRegistry,
    value: &str,
) -> Option<String> {
    let text = trimmed(value);
    if text.is_empty() {
        return Some("a request_uri is empty".into());
    }
    let length = js::len_utf16(&text);
    if length > 2048 {
        return Some(format!(
            "a request_uri is {} characters, and RFC 9101 section 5.2 says \
             one SHOULD NOT exceed 512 (2048 is the most this service \
             stores)",
            length
        ));
    }
    let Ok(parsed) = url::Url::parse(&text) else {
        return Some(format!("\"{}\" is not an absolute URL", text));
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Some(format!(
            "\"{}\" carries a user name or password, which this service \
             will not send anywhere",
            text
        ));
    }
    let scheme = parsed.scheme();
    if scheme == "https" {
        return None;
    }
    if scheme == "http" && reg.env().mode("acceptsLooseRequestUris") {
        return None;
    }
    Some(format!(
        "\"{}\" is {}, and RFC 9101 section 5.2 makes a request_uri https{}",
        text,
        scheme,
        if scheme == "http" {
            " — plain http is accepted in development mode only"
        } else {
            ""
        }
    ))
}

// `requestObjectMetadataProblem(values)` for the members an attribute
// write names (the `request_uris` arm is `requestUriProblem()` directly).
fn request_object_metadata_problem(
    reg: &ApplicationRegistry,
    values: &Map<String, Value>,
) -> Option<Refusal> {
    let required = values.get("require_signed_request_object")
        == Some(&Value::Bool(true));
    let sign = str_member(values, "request_object_signing_alg");
    if sign == "none" {
        if !reg.env().mode("acceptsUnsignedRequestObjects") || required {
            return Some(refusal(
                "request_object_signing_alg",
                format!(
                    "`none` is refused: {}.",
                    if required {
                        "this registration also sets \
                         require_signed_request_object"
                    } else {
                        "this realm is in product mode, where RFC 9101 \
                         section 4's signed request object is required"
                    }
                ),
            ));
        }
    } else if !sign.is_empty() {
        let verifiable = offered_jws_algs(reg, jws_signing_algs());
        if !verifiable.contains(&sign) {
            return Some(refusal(
                "request_object_signing_alg",
                format!(
                    "\"{}\" is not an algorithm this service verifies. It \
                     verifies {} (see \
                     request_object_signing_alg_values_supported).",
                    sign,
                    verifiable.join(", ")
                ),
            ));
        }
    }
    let alg = str_member(values, "request_object_encryption_alg");
    let enc = str_member(values, "request_object_encryption_enc");
    let decryptable = decryptable_jwe_algs(reg, jwe_decrypt_algs());
    if !alg.is_empty() && !decryptable.contains(&alg) {
        return Some(refusal(
            "request_object_encryption_alg",
            format!(
                "\"{}\" is not an algorithm this service decrypts a request \
                 object with. It decrypts {} (see \
                 request_object_encryption_alg_values_supported){}.",
                alg,
                decryptable.join(", "),
                if is_kem_jwe_alg(&alg) {
                    "; an ML-KEM or HPKE algorithm is decrypted only where \
                     the realm holds a key for it (keys.encryptionKemAlgs)"
                } else {
                    ""
                }
            ),
        ));
    }
    if !enc.is_empty() && alg.is_empty() {
        return Some(refusal(
            "request_object_encryption_enc",
            "it may not be registered without request_object_encryption_alg, \
             and none is.",
        ));
    }
    let encs = permitted_encs(reg, jwe_encs());
    if !enc.is_empty() && !encs.contains(&enc) {
        return Some(refusal(
            "request_object_encryption_enc",
            format!(
                "\"{}\" is not a content encryption algorithm this service \
                 has. It has {}.",
                enc,
                encs.join(", ")
            ),
        ));
    }
    None
}

/// `requestObjectAttributeProblem(attribute, value, fields)`.
#[tracing::instrument(level = "debug", skip(reg, fields))]
pub fn request_object_attribute_problem(
    reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
    fields: &Fields,
) -> Option<String> {
    let member = member_of(REQUEST_OBJECT_ATTRIBUTES, attribute)?;
    let text = trimmed(value);
    if text.is_empty() {
        return None;
    }
    if member == "request_uris" {
        return request_uri_problem(reg, &text)
            .map(|uri| format!("{}: {}.", attribute, uri));
    }
    let held_of = |name: &str| {
        held(fields, attribute_of(REQUEST_OBJECT_ATTRIBUTES, name))
    };
    if member == "require_signed_request_object" && !upper_bool(&text) {
        return Some(format!(
            "{}: \"{}\" is not TRUE or FALSE.",
            attribute, text
        ));
    }
    let mut values = Map::new();
    for name in [
        "request_object_signing_alg",
        "request_object_encryption_alg",
        "request_object_encryption_enc",
    ] {
        values.insert(name.into(), Value::String(held_of(name)));
    }
    values.insert(
        "require_signed_request_object".into(),
        Value::Bool(
            held_of("require_signed_request_object").to_uppercase() == "TRUE",
        ),
    );
    let set = if member == "require_signed_request_object" {
        Value::Bool(text.to_uppercase() == "TRUE")
    } else {
        Value::String(text.clone())
    };
    values.insert(member.into(), set);
    request_object_metadata_problem(reg, &values)
        .map(|p| renamed(p, REQUEST_OBJECT_ATTRIBUTES))
}

// ---------------------------------------------------------------------------
// The response and request-default members (#290).
// ---------------------------------------------------------------------------

/// `CLIENT_RESPONSE_ATTRIBUTES`.
pub const CLIENT_RESPONSE_ATTRIBUTES: &[(&str, &str)] = &[
    ("id_token_signed_response_alg", "oauthIdTokenSignedResponseAlg"),
    (
        "id_token_encrypted_response_alg",
        "oauthIdTokenEncryptedResponseAlg",
    ),
    (
        "id_token_encrypted_response_enc",
        "oauthIdTokenEncryptedResponseEnc",
    ),
    ("userinfo_signed_response_alg", "oauthUserinfoSignedResponseAlg"),
    (
        "userinfo_encrypted_response_alg",
        "oauthUserinfoEncryptedResponseAlg",
    ),
    (
        "userinfo_encrypted_response_enc",
        "oauthUserinfoEncryptedResponseEnc",
    ),
    (
        "authorization_signed_response_alg",
        "oauthAuthorizationSignedResponseAlg",
    ),
    (
        "authorization_encrypted_response_alg",
        "oauthAuthorizationEncryptedResponseAlg",
    ),
    (
        "authorization_encrypted_response_enc",
        "oauthAuthorizationEncryptedResponseEnc",
    ),
    ("default_acr_values", "oauthDefaultAcrValues"),
    ("default_max_age", "oauthDefaultMaxAge"),
];

// The three encryption pairs (`idTokenEncryptionMetadataProblem()`,
// `userinfoEncryptionMetadataProblem()` and JARM's half), which differ in
// their member names, their code's sentence and their pointers.
struct EncryptionPair {
    alg: &'static str,
    enc: &'static str,
    unknown_alg: &'static str,
    missing_alg: &'static str,
    enc_see: &'static str,
}

const ID_TOKEN_PAIR: EncryptionPair = EncryptionPair {
    alg: "id_token_encrypted_response_alg",
    enc: "id_token_encrypted_response_enc",
    unknown_alg: "an ID Token with. It encrypts with {} (see \
                  id_token_encryption_alg_values_supported). The symmetric \
                  families are for a document encrypted TO this service; an \
                  ID Token is encrypted to the key you registered in \
                  \"jwks\".",
    missing_alg: "OpenID Connect Dynamic Client Registration section 2 says \
                  id_token_encrypted_response_alg MUST also be provided, and \
                  none is.",
    enc_see: " (see id_token_encryption_enc_values_supported)",
};

const USERINFO_PAIR: EncryptionPair = EncryptionPair {
    alg: "userinfo_encrypted_response_alg",
    enc: "userinfo_encrypted_response_enc",
    unknown_alg: "a UserInfo response with. It encrypts with {} (see \
                  userinfo_encryption_alg_values_supported). The symmetric \
                  families are for a document encrypted TO this service; a \
                  response is encrypted to the key you registered.",
    missing_alg: "OpenID Connect Dynamic Client Registration section 2 says \
                  userinfo_encrypted_response_alg MUST also be provided, and \
                  none is.",
    enc_see: " (see userinfo_encryption_enc_values_supported)",
};

const JARM_PAIR: EncryptionPair = EncryptionPair {
    alg: "authorization_encrypted_response_alg",
    enc: "authorization_encrypted_response_enc",
    unknown_alg: "an authorization response with. It encrypts with {}, to \
                  the key registered in \"jwks\".",
    missing_alg: "JARM section 3 says authorization_encrypted_response_alg \
                  MUST also be provided, and none is.",
    enc_see: "",
};

fn encryption_pair_problem(
    reg: &ApplicationRegistry,
    values: &Map<String, Value>,
    pair: &EncryptionPair,
) -> Option<Refusal> {
    let alg = str_member(values, pair.alg);
    let enc = str_member(values, pair.enc);
    let offered = offered_jwe_algs(reg, jwe_asymmetric_algs());
    if !alg.is_empty() && !offered.contains(&alg) {
        return Some(refusal(
            pair.alg,
            format!(
                "\"{}\" is not an algorithm this service encrypts {}",
                alg,
                pair.unknown_alg.replacen("{}", &offered.join(", "), 1)
            ),
        ));
    }
    if !enc.is_empty() && alg.is_empty() {
        return Some(refusal(pair.enc, pair.missing_alg));
    }
    let encs = permitted_encs(reg, jwe_encs());
    if !enc.is_empty() && !encs.contains(&enc) {
        return Some(refusal(
            pair.enc,
            format!(
                "\"{}\" is not a content encryption algorithm this service \
                 has. It has {}{}.",
                enc,
                encs.join(", "),
                pair.enc_see
            ),
        ));
    }
    None
}

// `jarmMetadataProblem(values)`: the signing half, then the pair.
fn jarm_problem(
    reg: &ApplicationRegistry,
    values: &Map<String, Value>,
) -> Option<Refusal> {
    let sign = str_member(values, "authorization_signed_response_alg");
    let signable = signable_jws_algs(reg, jws_signing_algs());
    if !sign.is_empty() && !signable.contains(&sign) {
        return Some(refusal(
            "authorization_signed_response_alg",
            format!(
                "\"{}\" is not an algorithm this service signs an \
                 authorization response with{}. It signs with {} (see \
                 authorization_signing_alg_values_supported).",
                sign,
                if sign == "none" {
                    " — JARM section 3 does not allow none"
                } else {
                    ""
                },
                signable.join(", ")
            ),
        ));
    }
    encryption_pair_problem(reg, values, &JARM_PAIR)
}

// `signedResponseAlgProblem(values)`.
fn signed_response_alg_problem(
    reg: &ApplicationRegistry,
    values: &Map<String, Value>,
) -> Option<Refusal> {
    let mut userinfo = jws_signing_algs();
    userinfo.push("none".into());
    let lists = [
        (
            "id_token_signed_response_alg",
            signable_jws_algs(reg, jws_signing_algs()),
        ),
        (
            "userinfo_signed_response_alg",
            signable_jws_algs(reg, userinfo),
        ),
    ];
    for (member, algs) in lists {
        let Some(value) = values.get(member).filter(|v| !v.is_null()) else {
            continue;
        };
        if !algs.contains(&js::string(value)) {
            return Some(Refusal {
                member: member.into(),
                description: format!(
                    "{}: {} is not an algorithm this service signs with; it \
                     signs with {}.",
                    member,
                    serde_json::to_string(value).unwrap_or_default(),
                    algs.join(", ")
                ),
            });
        }
    }
    None
}

// `ACR_VALUE_SHAPE` and `STEP_UP_ACR_VALUE`
// (`/^[\x21\x23-\x5B\x5D-\x7E]{1,256}$/`): printable ASCII with no double
// quote or backslash.
fn acr_value_shaped(text: &str) -> bool {
    (1..=256).contains(&text.len())
        && text.bytes().all(|b| {
            b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)
        })
}

// `requestDefaultsProblem(values)`.
fn request_defaults_problem(values: &Map<String, Value>) -> Option<Refusal> {
    if let Some(age) = values.get("default_max_age") {
        let fits = age
            .as_f64()
            .is_some_and(|f| age.is_number() && f.fract() == 0.0 && f >= 0.0);
        if !fits {
            return Some(refusal(
                "default_max_age",
                "must be a non-negative whole number of seconds.",
            ));
        }
    }
    if let Some(flag) = values.get("require_auth_time") {
        if !flag.is_boolean() {
            return Some(refusal("require_auth_time", "must be a boolean."));
        }
    }
    if let Some(acr) = values.get("default_acr_values") {
        let fits = acr.as_array().is_some_and(|list| {
            list.iter()
                .all(|one| one.as_str().is_some_and(acr_value_shaped))
        });
        if !fits {
            return Some(refusal(
                "default_acr_values",
                "must be an array of acr values.",
            ));
        }
    }
    None
}

// `clientResponseMetadataProblem(values)`.
fn client_response_metadata_problem(
    reg: &ApplicationRegistry,
    values: &Map<String, Value>,
) -> Option<Refusal> {
    encryption_pair_problem(reg, values, &ID_TOKEN_PAIR)
        .or_else(|| encryption_pair_problem(reg, values, &USERINFO_PAIR))
        .or_else(|| jarm_problem(reg, values))
        .or_else(|| signed_response_alg_problem(reg, values))
        .or_else(|| request_defaults_problem(values))
}

// `clientResponseMemberValue(member, text)`.
fn client_response_member_value(member: &str, text: &str) -> Value {
    if member == "default_acr_values" {
        return Value::Array(
            js::split_on(text, js::is_space)
                .into_iter()
                .map(Value::String)
                .collect(),
        );
    }
    if member == "default_max_age"
        && (1..=15).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_digit())
    {
        if let Ok(n) = text.parse::<u64>() {
            return Value::from(n);
        }
    }
    Value::String(text.to_string())
}

/// `clientResponseAttributeProblem(attribute, value, fields)`.
#[tracing::instrument(level = "debug", skip(reg, fields))]
pub fn client_response_attribute_problem(
    reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
    fields: &Fields,
) -> Option<String> {
    let member = member_of(CLIENT_RESPONSE_ATTRIBUTES, attribute)?;
    let text = trimmed(value);
    if text.is_empty() {
        return None;
    }
    let mut asked = Map::new();
    asked.insert(member.into(), client_response_member_value(member, &text));
    let pair = match member {
        "id_token_encrypted_response_enc" => {
            Some("id_token_encrypted_response_alg")
        }
        "userinfo_encrypted_response_enc" => {
            Some("userinfo_encrypted_response_alg")
        }
        "authorization_encrypted_response_enc" => {
            Some("authorization_encrypted_response_alg")
        }
        _ => None,
    };
    if let Some(alg_member) = pair {
        let alg = trimmed(&held(
            fields,
            attribute_of(CLIENT_RESPONSE_ATTRIBUTES, alg_member),
        ));
        if !alg.is_empty() {
            asked.insert(alg_member.into(), Value::String(alg));
        }
    }
    client_response_metadata_problem(reg, &asked)
        .map(|p| renamed(p, CLIENT_RESPONSE_ATTRIBUTES))
}

// ---------------------------------------------------------------------------
// OpenID Connect subject types, the sector, the assertion's algorithm.
// ---------------------------------------------------------------------------

/// `OIDC_SUBJECT_ATTRIBUTES`.
pub const OIDC_SUBJECT_ATTRIBUTES: &[(&str, &str)] = &[
    ("subject_type", "oauthSubjectType"),
    ("sector_identifier_uri", "oauthSectorIdentifierUri"),
    (
        "token_endpoint_auth_signing_alg",
        "oauthTokenEndpointAuthSigningAlg",
    ),
];

// `new URL(text).host`: the host, and a port other than the default.
fn url_host(parsed: &url::Url) -> String {
    let host = parsed.host_str().unwrap_or("");
    match parsed.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    }
}

// `oidcSubjectMetadataProblem(values)`, over string members.
fn oidc_subject_metadata_problem(
    reg: &ApplicationRegistry,
    values: &Map<String, Value>,
) -> Option<Refusal> {
    let subject_type = str_member(values, "subject_type");
    let sector = str_member(values, "sector_identifier_uri");
    let signing = str_member(values, "token_endpoint_auth_signing_alg");
    if !subject_type.is_empty()
        && !["public", "pairwise", "ephemeral"].contains(&subject_type.as_str())
    {
        return Some(refusal(
            "subject_type",
            format!(
                "\"{}\" is not one this service supports; \
                 subject_types_supported is [\"public\", \"pairwise\", \
                 \"ephemeral\"] (OIDC Core section 8; the Ephemeral Subject \
                 Identifier draft, #149).",
                subject_type
            ),
        ));
    }
    if !sector.is_empty() {
        let usable = url::Url::parse(&sector).is_ok_and(|p| {
            p.scheme() == "https" && p.fragment().is_none_or(str::is_empty)
        });
        if !usable {
            return Some(refusal(
                "sector_identifier_uri",
                format!(
                    "\"{}\" is not an https URL with no fragment (OIDC Core \
                     section 8.1 and Dynamic Client Registration section 5).",
                    sector
                ),
            ));
        }
    }
    if subject_type == "pairwise" && sector.is_empty() {
        let mut hosts: Vec<String> = Vec::new();
        for uri in values_of(values.get("redirect_uris")) {
            if let Ok(parsed) = url::Url::parse(&uri) {
                let host = url_host(&parsed);
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        if hosts.len() > 1 {
            return Some(refusal(
                "sector_identifier_uri",
                format!(
                    "a pairwise client whose redirect_uris are on {} hosts \
                     ({}) must register a sector_identifier_uri: with none, \
                     the sector is the one host they share (OIDC Core section \
                     8.1).",
                    hosts.len(),
                    hosts.join(", ")
                ),
            ));
        }
    }
    if !signing.is_empty() {
        let method = str_member(values, "token_endpoint_auth_method");
        let verifiable = offered_jws_algs(reg, jws_signing_algs());
        if !verifiable.contains(&signing) {
            return Some(refusal(
                "token_endpoint_auth_signing_alg",
                format!(
                    "\"{}\" is not a JWS algorithm this service verifies \
                     ({}); `none` is never one (OIDC Core section 9).",
                    signing,
                    verifiable.join(", ")
                ),
            ));
        }
        let hmac = signing.starts_with("HS");
        if (method == "client_secret_jwt" && !hmac)
            || (method == "private_key_jwt" && hmac)
        {
            return Some(refusal(
                "token_endpoint_auth_signing_alg",
                format!(
                    "\"{}\" cannot sign a {} assertion: {}.",
                    signing,
                    method,
                    if hmac {
                        "private_key_jwt is asymmetric"
                    } else {
                        "client_secret_jwt is an HMAC (HS256, HS384 or HS512)"
                    }
                ),
            ));
        }
    }
    None
}

/// `oidcSubjectAttributeProblem(attribute, value, fields)`.
#[tracing::instrument(level = "debug", skip(reg, fields))]
pub fn oidc_subject_attribute_problem(
    reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
    fields: &Fields,
) -> Option<String> {
    let member = member_of(OIDC_SUBJECT_ATTRIBUTES, attribute)?;
    let text = trimmed(value);
    if text.is_empty() {
        return None;
    }
    let mut values = Map::new();
    values.insert(
        "token_endpoint_auth_method".into(),
        Value::String(held(fields, "oauthTokenEndpointAuthMethod")),
    );
    values.insert(
        "redirect_uris".into(),
        Value::Array(
            values_of(fields.get("oauthRedirectUri"))
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    for (name, attr) in OIDC_SUBJECT_ATTRIBUTES {
        values.insert((*name).into(), Value::String(held(fields, attr)));
    }
    values.insert(member.into(), Value::String(text));
    oidc_subject_metadata_problem(reg, &values)
        .map(|p| renamed(p, OIDC_SUBJECT_ATTRIBUTES))
}

/// `pushedAuthorizationAttributeProblem(attribute, value)`: the two
/// boolean attributes hold TRUE or FALSE.
#[tracing::instrument(level = "debug", skip(_reg))]
pub fn pushed_authorization_attribute_problem(
    _reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
) -> Option<String> {
    let text = trimmed(value);
    if (attribute != "oauthRequirePushedAuthorizationRequests"
        && attribute != "oauthHttpSignedRequests")
        || text.is_empty()
        || upper_bool(&text)
    {
        return None;
    }
    Some(format!("{}: \"{}\" is not TRUE or FALSE.", attribute, text))
}

// ---------------------------------------------------------------------------
// RFC 8705: the certificate subject parameters
// (`common/certificate_subject.js`).
// ---------------------------------------------------------------------------

// `certificateSubject.MEMBERS`: member, attribute, kind.
const TLS_SUBJECT_MEMBERS: &[(&str, &str, &str)] = &[
    ("tls_client_auth_subject_dn", "oauthTlsClientAuthSubjectDn", "dn"),
    ("tls_client_auth_san_dns", "oauthTlsClientAuthSanDns", "dns"),
    ("tls_client_auth_san_uri", "oauthTlsClientAuthSanUri", "uri"),
    ("tls_client_auth_san_ip", "oauthTlsClientAuthSanIp", "ip"),
    (
        "tls_client_auth_san_email",
        "oauthTlsClientAuthSanEmail",
        "email",
    ),
];

/// `TLS_BOUND_TOKENS_ATTRIBUTE`.
pub const TLS_BOUND_TOKENS_ATTRIBUTE: &str =
    "oauthTlsClientCertificateBoundAccessTokens";

// `certificate_subject.js`'s `parseDn(text)` read for its verdict alone:
// whether RFC 4514 reads it into at least one RDN (`normalDn()` not null).
fn parses_as_dn(source: &str) -> bool {
    let s: Vec<char> = source.chars().collect();
    let n = s.len();
    let type_shape =
        Regex::new(r"^([A-Za-z][A-Za-z0-9-]*|[0-9]+(\.[0-9]+)*)$").ok();
    let mut rdns = 0usize;
    let mut rdn = 0usize;
    let mut i = 0usize;
    while i <= n {
        while i < n && s[i] == ' ' {
            i += 1;
        }
        let start = i;
        while i < n && s[i] != '=' {
            i += 1;
        }
        if i >= n {
            if rdns == 0 && rdn == 0 && source.trim().is_empty() {
                break;
            }
            return false;
        }
        let ty: String = s[start..i].iter().collect();
        if !type_shape.as_ref().is_some_and(|r| r.is_match(ty.trim())) {
            return false;
        }
        i += 1;
        while i < n && s[i] == ' ' {
            i += 1;
        }
        if i < n && s[i] == '#' {
            let hex_start = i + 1;
            i = hex_start;
            while i < n && s[i].is_ascii_hexdigit() {
                i += 1;
            }
            let len = i - hex_start;
            if len == 0 || len % 2 == 1 {
                return false;
            }
            while i < n && s[i] == ' ' {
                i += 1;
            }
        } else {
            while i < n && s[i] != ',' && s[i] != '+' {
                let ch = s[i];
                if ch == '\\' {
                    if i + 1 >= n {
                        return false;
                    }
                    let hex2 = s[i + 1].is_ascii_hexdigit()
                        && i + 2 < n
                        && s[i + 2].is_ascii_hexdigit();
                    i += if hex2 { 3 } else { 2 };
                    continue;
                }
                if matches!(ch, '"' | ';' | '<' | '>') {
                    return false;
                }
                i += 1;
            }
        }
        if i < n && s[i] != ',' && s[i] != '+' {
            return false;
        }
        rdn += 1;
        if i < n && s[i] == '+' {
            i += 1;
            continue;
        }
        rdns += 1;
        rdn = 0;
        if i < n && s[i] == ',' {
            i += 1;
            if i >= n {
                return false;
            }
            continue;
        }
        break;
    }
    rdns > 0
}

// The dNSName shape (`valueProblem()`'s regular expression), its
// `(?=.{1,253}$)` lookahead checked by hand: the regex crate has no
// lookaround.
fn dns_shaped(text: &str) -> bool {
    let n = text.chars().count();
    if !(1..=253).contains(&n) || text.contains('\n') {
        return false;
    }
    Regex::new(
        r"^([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$",
    )
    .is_ok_and(|r| r.is_match(text))
}

// `/^[^\s@]+@[^\s@]+$/`.
fn email_shaped(text: &str) -> bool {
    let Some(at) = text.find('@') else {
        return false;
    };
    let ok = |part: &str| {
        !part.is_empty() && !part.chars().any(|c| c == '@' || js::is_space(c))
    };
    ok(&text[..at]) && ok(&text[at + 1..])
}

// `certificateSubject.valueProblem(member, value)` for a string value.
fn certificate_value_problem(member: &str, value: &str) -> Option<String> {
    let Some((_, _, kind)) =
        TLS_SUBJECT_MEMBERS.iter().find(|(m, _, _)| *m == member)
    else {
        return Some(format!(
            "{} is not one of RFC 8705 section 2.1.2's five certificate \
             subject parameters.",
            member
        ));
    };
    let text = js::trim(value);
    if text.is_empty()
        || js::len_utf16(text) > 1024
        || text.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
    {
        return Some(format!(
            "{} must be a printable value of 1 to 1024 characters.",
            member
        ));
    }
    match *kind {
        "dn" if !parses_as_dn(text) => Some(format!(
            "{} \"{}\" is not a distinguished name in RFC 4514 form (for \
             example CN=client,O=Example,C=US; a comma, plus sign, quote, \
             backslash, angle bracket or semicolon inside a value is escaped \
             with a backslash).",
            member, text
        )),
        "dns" if !dns_shaped(text) => Some(format!(
            "{} \"{}\" is not a DNS host name. A wildcard is not accepted: \
             RFC 8705 names the value a certificate carries, not a pattern.",
            member, text
        )),
        "uri"
            if url::Url::parse(text).is_err()
                || text.chars().any(js::is_space) =>
        {
            Some(format!("{} \"{}\" is not an absolute URI.", member, text))
        }
        "ip" if text.parse::<std::net::IpAddr>().is_err() => Some(format!(
            "{} \"{}\" is not an IPv4 or IPv6 address.",
            member, text
        )),
        "email" if !email_shaped(text) => Some(format!(
            "{} \"{}\" is not an rfc822Name (local@domain).",
            member, text
        )),
        _ => None,
    }
}

/// `mtlsAttributeProblem(attribute, value, fields)`.
#[tracing::instrument(level = "debug", skip(_reg, fields))]
pub fn mtls_attribute_problem(
    _reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
    fields: &Fields,
) -> Option<Coded> {
    let text = trimmed(value);
    if text.is_empty() {
        return None;
    }
    if attribute == TLS_BOUND_TOKENS_ATTRIBUTE {
        if !upper_bool(&text) {
            return Some(Coded::new(
                codes::STS_REG_0136,
                format!("{}: \"{}\" is not TRUE or FALSE.", attribute, text),
            ));
        }
        return None;
    }
    let (member, _, _) =
        TLS_SUBJECT_MEMBERS.iter().find(|(_, a, _)| *a == attribute)?;
    if let Some(said) = certificate_value_problem(member, &text) {
        return Some(Coded::new(
            codes::STS_REG_0134,
            format!(
                "{}: {}",
                attribute,
                said.replacen(&format!("{} ", member), "", 1)
            ),
        ));
    }
    let other = TLS_SUBJECT_MEMBERS.iter().map(|(_, a, _)| *a).find(|name| {
        *name != attribute
            && values_of(fields.get(*name))
                .iter()
                .any(|one| !js::trim(one).is_empty())
    })?;
    Some(Coded::new(
        codes::STS_REG_0135,
        format!(
            "{}: this application already registers {}, and RFC 8705 \
             section 2.1.2 gives a client exactly one certificate subject \
             parameter. Clear {} first.",
            attribute, other, other
        ),
    ))
}

// `gnapRealmMtlsTrust()`.
fn gnap_realm_mtls_trust(reg: &ApplicationRegistry) -> String {
    let set = js::or_empty(Some(&reg.env().setting("gnap.mtlsTrust")));
    if set == "pki" || set == "pinned" {
        return set;
    }
    if reg.env().mode("requiresPkiForGnapMtls") {
        "pki".into()
    } else {
        "pinned".into()
    }
}

/// `gnapMtlsTrustProblem(attribute, value)`.
#[tracing::instrument(level = "debug", skip(reg))]
pub fn gnap_mtls_trust_problem(
    reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
) -> Option<Coded> {
    let text = trimmed(value);
    if attribute != "gnapMtlsTrust" || text.is_empty() {
        return None;
    }
    if text != "pki" && text != "pinned" {
        return Some(Coded::new(
            codes::STS_REG_0195,
            format!("gnapMtlsTrust: \"{}\" is not pki or pinned.", text),
        ));
    }
    if text == "pinned" && gnap_realm_mtls_trust(reg) == "pki" {
        return Some(Coded::new(
            codes::STS_REG_0196,
            "gnapMtlsTrust: this realm holds every GNAP key proved by mutual \
             TLS to a PKI (gnap.mtlsTrust resolves to pki), and an \
             application may make that stricter for itself, never weaker. A \
             pinned certificate cannot be revoked or rotated at a certificate \
             authority (RFC 9635 section 11.4).",
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// RFC 9470: step-up.
// ---------------------------------------------------------------------------

/// `STEP_UP_MAX_AGE_LIMIT`: ten years of seconds.
pub const STEP_UP_MAX_AGE_LIMIT: u64 = 315_360_000;

/// `stepUpAttributeProblem(attribute, value)`.
#[tracing::instrument(level = "debug", skip(_reg))]
pub fn step_up_attribute_problem(
    _reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
) -> Option<Coded> {
    let text = trimmed(value);
    if text.is_empty() {
        return None;
    }
    if attribute == "oauthStepUpAcrValues" {
        let bad: Vec<String> = js::split_on(&text, js::is_space)
            .into_iter()
            .filter(|one| !acr_value_shaped(one))
            .map(|one| quoted(&js::slice_utf16(&one, 60)))
            .collect();
        if bad.is_empty() {
            return None;
        }
        return Some(Coded::new(
            codes::STS_REG_0140,
            format!(
                "{}: {} cannot be an acr value. A value is printable ASCII \
                 with no double quote or backslash, because it is repeated in \
                 a WWW-Authenticate challenge (RFC 9470 section 3).",
                attribute,
                bad.join(", ")
            ),
        ));
    }
    if attribute == "oauthStepUpMaxAge" {
        let ok = (1..=9).contains(&text.len())
            && text.bytes().all(|b| b.is_ascii_digit())
            && text.parse::<u64>().is_ok_and(|n| n <= STEP_UP_MAX_AGE_LIMIT);
        if ok {
            return None;
        }
        return Some(Coded::new(
            codes::STS_REG_0141,
            format!(
                "{}: \"{}\" is not a whole number of seconds between 0 and \
                 {}.",
                attribute,
                js::slice_utf16(&text, 60),
                STEP_UP_MAX_AGE_LIMIT
            ),
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// The XACML attribute row grammar (`xacml/xacml_attribute_rows.ts`) and
// the model's URIs (`xacml/xacml_model.js`), as these checks read them.
// ---------------------------------------------------------------------------

const ACCESS_SUBJECT: &str =
    "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
const RESOURCE: &str =
    "urn:oasis:names:tc:xacml:3.0:attribute-category:resource";
const ACTION: &str = "urn:oasis:names:tc:xacml:3.0:attribute-category:action";
const ENVIRONMENT: &str =
    "urn:oasis:names:tc:xacml:3.0:attribute-category:environment";

// `CATEGORY_NAMES`; the first five are `SUBJECT_CATEGORIES`.
const CATEGORY_NAMES: &[(&str, &str)] = &[
    ("access-subject", ACCESS_SUBJECT),
    (
        "recipient-subject",
        "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject",
    ),
    (
        "intermediary-subject",
        "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject",
    ),
    (
        "codebase",
        "urn:oasis:names:tc:xacml:1.0:subject-category:codebase",
    ),
    (
        "requesting-machine",
        "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine",
    ),
    ("resource", RESOURCE),
    ("action", ACTION),
    ("environment", ENVIRONMENT),
];

// `TYPE_NAMES`.
const TYPE_NAMES: &[(&str, &str)] = &[
    ("string", "http://www.w3.org/2001/XMLSchema#string"),
    ("boolean", "http://www.w3.org/2001/XMLSchema#boolean"),
    ("integer", "http://www.w3.org/2001/XMLSchema#integer"),
    ("double", "http://www.w3.org/2001/XMLSchema#double"),
    ("time", "http://www.w3.org/2001/XMLSchema#time"),
    ("date", "http://www.w3.org/2001/XMLSchema#date"),
    ("dateTime", "http://www.w3.org/2001/XMLSchema#dateTime"),
    (
        "dayTimeDuration",
        "http://www.w3.org/2001/XMLSchema#dayTimeDuration",
    ),
    (
        "yearMonthDuration",
        "http://www.w3.org/2001/XMLSchema#yearMonthDuration",
    ),
    ("anyURI", "http://www.w3.org/2001/XMLSchema#anyURI"),
    ("hexBinary", "http://www.w3.org/2001/XMLSchema#hexBinary"),
    ("base64Binary", "http://www.w3.org/2001/XMLSchema#base64Binary"),
    (
        "rfc822Name",
        "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name",
    ),
    ("x500Name", "urn:oasis:names:tc:xacml:1.0:data-type:x500Name"),
    ("dnsName", "urn:oasis:names:tc:xacml:2.0:data-type:dnsName"),
    ("ipAddress", "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress"),
];

// `RESERVED_IDS`.
const RESERVED_IDS: &[&str] = &[
    "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
    "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
    "urn:oasis:names:tc:xacml:1.0:action:action-id",
    "urn:oasis:names:tc:xacml:1.0:environment:current-time",
    "urn:oasis:names:tc:xacml:1.0:environment:current-date",
    "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime",
];

const RESERVED_PREFIX: &str = "urn:sts:xacml:";
const MAX_DEPTH: usize = 6;
const MAX_ID_LENGTH: usize = 512;

// `XacmlAttributeRows.isDirectoryName()`.
fn is_directory_name(attribute_id: &str, category: &str) -> bool {
    let bare = Regex::new(r"^[A-Za-z][A-Za-z0-9;-]*$")
        .is_ok_and(|r| r.is_match(attribute_id));
    CATEGORY_NAMES[..5].iter().any(|(_, uri)| *uri == category) && bare
}

// `XacmlAttributeRows.reservedProblem()`.
fn reserved_problem(attribute_id: &str, category: &str) -> Option<String> {
    if attribute_id.to_lowercase().starts_with(RESERVED_PREFIX) {
        return Some(format!(
            "\"{}\" is in this service's own namespace ({}), where every \
             trusted fact lives — the roles, the realm, the protocol, the \
             caller and its application. A request-supplied attribute \
             suppresses the PIP, so a row mapping onto one would let a caller \
             forge it",
            attribute_id, RESERVED_PREFIX
        ));
    }
    if RESERVED_IDS.contains(&attribute_id) {
        return Some(format!(
            "\"{}\" is filled by the adapter from the request's own \
             identifiers (AuthZEN's subject.id, action.name or resource.id; \
             an authorization detail's trusted facts), or supplied by the \
             PDP, and from nothing else",
            attribute_id
        ));
    }
    if is_directory_name(attribute_id, category) {
        return Some(format!(
            "\"{}\" in a subject category is read as the subject's directory \
             attribute, and for a subject this realm resolves the directory \
             is authoritative. Send the member under an identifier of your \
             own, such as urn:example:{}",
            attribute_id, attribute_id
        ));
    }
    None
}

// `ownMembers.read(table, text)`, or the URI itself.
fn named_or_uri(table: &[(&str, &str)], text: &str) -> String {
    if let Some((_, uri)) = table.iter().find(|(k, _)| *k == text) {
        return (*uri).to_string();
    }
    if table.iter().any(|(_, uri)| *uri == text) {
        return text.to_string();
    }
    String::new()
}

fn names_of(table: &[(&str, &str)]) -> String {
    table.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", ")
}

// `XacmlAttributeRows.dataTypeOf(text)`: '' is `string`.
fn data_type_of(text: &str) -> String {
    named_or_uri(TYPE_NAMES, if text.is_empty() { "string" } else { text })
}

// `XacmlAttributeRows.segmentsOf(text)`.
fn segments_of(text: &str) -> Option<Vec<String>> {
    if text.is_empty() {
        return None;
    }
    let segments: Vec<String> = text.split('.').map(str::to_string).collect();
    let shaped = |one: &String| {
        (1..=64).contains(&one.chars().count())
            && one.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '_' | '$' | '@' | ':' | '-')
            })
    };
    if segments.len() > MAX_DEPTH || !segments.iter().all(shaped) {
        return None;
    }
    Some(segments)
}

// `XacmlAttributeRows.idShaped(id)`.
fn id_shaped(attribute_id: &str) -> bool {
    !attribute_id.is_empty()
        && js::len_utf16(attribute_id) <= MAX_ID_LENGTH
        && !attribute_id.chars().any(js::is_space)
}

// `typeof given[key] === 'string' ? given[key].trim() : ''`.
fn text_member(given: &Map<String, Value>, key: &str) -> String {
    given
        .get(key)
        .and_then(Value::as_str)
        .map(|s| js::trim(s).to_string())
        .unwrap_or_default()
}

// `Object.keys(o)`: array-index keys first, ascending, then the rest in
// insertion order — the order a JavaScript object enumerates.
fn js_keys(o: &Map<String, Value>) -> Vec<String> {
    let index = |k: &str| -> Option<u64> {
        k.parse::<u64>()
            .ok()
            .filter(|n| *n < u64::from(u32::MAX) && n.to_string() == k)
    };
    let mut ints: Vec<(u64, String)> = o
        .keys()
        .filter_map(|k| index(k).map(|n| (n, k.clone())))
        .collect();
    ints.sort();
    let mut out: Vec<String> = ints.into_iter().map(|(_, k)| k).collect();
    out.extend(o.keys().filter(|k| index(k).is_none()).cloned());
    out
}

// ---------------------------------------------------------------------------
// `authzen/authzen_catalogue.ts`'s `parse()`.
// ---------------------------------------------------------------------------

const AUTHZEN_OBJECTS: &[&str] = &["subject", "resource", "action", "context"];

// `AuthzenModel.reservedContext()`: the evaluation's `context` fields
// (`models/authzen/authzen.tsp`'s `Context`).
const RESERVED_CONTEXT: &[&str] =
    &["supported_obligations", "approval", "application"];

// `BINDING_CONTEXT`.
const BINDING_CONTEXT: &[&str] = &[
    "client_id",
    "acr",
    "amr",
    "auth_time",
    "cnf",
    "jti",
    "subject_token_type",
    "actor_token_type",
    "subject_token",
    "act",
    "may_act",
];

// `AuthzenCatalogue.parse(value)` for a string value: None for a row, else
// the code and the problem.
fn authzen_catalogue_problem(value: &str) -> Option<(ErrorCode, String)> {
    let bad = codes::STS_AUTHZEN_0010;
    let given = match parse_like_json(value) {
        Ok(v) => v,
        Err(message) => {
            return Some((
                bad,
                format!(
                    "a catalogue row is a JSON object, and this is not JSON: \
                     {}",
                    message
                ),
            ));
        }
    };
    let Some(given) = given.as_object() else {
        return Some((
            bad,
            "a catalogue row is a JSON object with object, property, \
             attributeId, and optionally category, dataType and multiplicity"
                .into(),
        ));
    };
    let known = [
        "object",
        "property",
        "attributeId",
        "category",
        "dataType",
        "multiplicity",
        "description",
    ];
    let unknown: Vec<String> = js_keys(given)
        .into_iter()
        .filter(|k| !known.contains(&k.as_str()))
        .map(|k| format!("\"{}\"", js::slice_utf16(&k, 40)))
        .collect();
    if !unknown.is_empty() {
        return Some((
            bad,
            format!(
                "a catalogue row has no member {}; it takes {}",
                unknown.join(", "),
                known.join(", ")
            ),
        ));
    }
    let object = text_member(given, "object");
    if !AUTHZEN_OBJECTS.contains(&object.as_str()) {
        return Some((
            bad,
            format!("object must be one of {}", AUTHZEN_OBJECTS.join(", ")),
        ));
    }
    let Some(segments) = segments_of(&text_member(given, "property")) else {
        return Some((
            bad,
            format!(
                "property must be a member name, or a dotted path of at most \
                 {} names, each of letters, digits, _ $ @ : or -",
                MAX_DEPTH
            ),
        ));
    };
    if object == "context" && RESERVED_CONTEXT.contains(&segments[0].as_str()) {
        return Some((
            codes::STS_AUTHZEN_0011,
            format!(
                "context.{} is read by the adapter itself (the caller's \
                 application, the obligations the PEP can carry out, or an \
                 access request's approval), never sent to the policy as a \
                 property",
                segments[0]
            ),
        ));
    }
    if object == "context" && BINDING_CONTEXT.contains(&segments[0].as_str()) {
        return Some((
            codes::STS_AUTHZEN_0011,
            format!(
                "context.{} is read by the OAuth token-exchange binding's \
                 fixed conversion rules (docs/authzen.md), which a catalogue \
                 row may add to but never override",
                segments[0]
            ),
        ));
    }
    let attribute_id = text_member(given, "attributeId");
    if !id_shaped(&attribute_id) {
        return Some((
            bad,
            format!(
                "attributeId must be a non-empty identifier with no white \
                 space, at most {} characters",
                MAX_ID_LENGTH
            ),
        ));
    }
    let category_text = text_member(given, "category");
    let category = if category_text.is_empty() {
        match object.as_str() {
            "subject" => ACCESS_SUBJECT,
            "resource" => RESOURCE,
            "action" => ACTION,
            _ => ENVIRONMENT,
        }
        .to_string()
    } else {
        let c = named_or_uri(CATEGORY_NAMES, &category_text);
        if c.is_empty() {
            return Some((
                bad,
                format!(
                    "category must be one of {}, or its XACML URI",
                    names_of(CATEGORY_NAMES)
                ),
            ));
        }
        c
    };
    if data_type_of(&text_member(given, "dataType")).is_empty() {
        return Some((
            bad,
            format!(
                "dataType must be one of {}, or its URI",
                names_of(TYPE_NAMES)
            ),
        ));
    }
    let multiplicity = text_member(given, "multiplicity");
    if !multiplicity.is_empty() && multiplicity != "single" && multiplicity != "bag"
    {
        return Some((bad, "multiplicity must be single or bag".into()));
    }
    let reserved = reserved_problem(&attribute_id, &category)?;
    let code = if is_directory_name(&attribute_id, &category) {
        codes::STS_AUTHZEN_0012
    } else {
        codes::STS_AUTHZEN_0011
    };
    Some((code, reserved))
}

/// `authzenAttributeProblem(attribute, value)`.
#[tracing::instrument(level = "debug", skip(_reg))]
pub fn authzen_attribute_problem(
    _reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
) -> Option<Coded> {
    let text = trimmed(value);
    if attribute != "authzenAttribute" || text.is_empty() {
        return None;
    }
    authzen_catalogue_problem(&text).map(|(code, problem)| {
        Coded::new(code, format!("{}: {}.", attribute, problem))
    })
}

// ---------------------------------------------------------------------------
// RFC 9396: the authorization details types and the access-type
// catalogue (rule 3bz).
// ---------------------------------------------------------------------------

/// `AUTHORIZATION_DETAILS_BUILT_IN`.
pub const AUTHORIZATION_DETAILS_BUILT_IN: &[&str] = &["openid_credential"];

// The access-type definition's members, in the model's order
// (`models/gnap/gnap.tsp`'s `AccessTypeDefinition`, which Node reads from
// `gnap.json`'s `access-type-definition`).
const DEFINITION_MEMBERS: &[&str] = &[
    "type",
    "description",
    "locations",
    "schema",
    "actions",
    "datatypes",
    "privileges",
    "required",
    "interaction",
    "consentActions",
    "bearer",
    "maxLifetimeS",
    "acr",
    "derivableFrom",
    "introspectionClaims",
    "limits",
    "xacml",
    "notForPolicy",
];

// `ACCESS_TYPE_INTERACTIONS`: the model's `interaction` values.
const ACCESS_TYPE_INTERACTIONS: &[&str] = &["always", "default", "never"];

// `INTROSPECTION_RESERVED`.
const INTROSPECTION_RESERVED: &[&str] = &[
    "active",
    "access",
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "flags",
    "key",
    "label",
    "act",
    "instance_id",
    "format",
    "scope",
    "client_id",
    "username",
    "token_type",
    "cnf",
    "authorization_details",
    "acr",
    "auth_time",
    "device_id",
    "may_act",
    "status",
    "grant_id",
];

// `LIMITS_SCHEMA_KEYWORDS`.
const LIMITS_SCHEMA_KEYWORDS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "pattern",
    "format",
    "minItems",
    "maxItems",
    "uniqueItems",
    "description",
    "title",
];

const LIMITS_SCHEMA_TYPES: &[&str] =
    &["object", "string", "number", "integer", "boolean", "array"];

const ACCESS_TYPE_MAX_LIFETIME_S: f64 = 31_536_000.0;
const AUTHORIZATION_DETAILS_DEFINITION_MAX: usize = 65_536;

// One `xacml` row as `FgaMap.mappingOf()` keeps it, what coverage reads.
#[derive(Debug, Clone, PartialEq)]
struct FgaRow {
    path: String,
    attribute_id: String,
    category: String,
}

// What `authorizationDetailsTypeOf()` answers that these checks read.
#[derive(Debug, Clone, Default)]
struct Definition {
    type_name: String,
    schema: Option<Value>,
    xacml: Vec<FgaRow>,
    not_for_policy: Vec<String>,
    problem: String,
}

// `authorizationDetailsTypeNameProblem(value)`.
fn type_name_problem(value: &Value) -> String {
    let text = value.as_str().unwrap_or("");
    if text.is_empty() {
        return "a type is not a non-empty string".into();
    }
    if js::len_utf16(text) > 512
        || !text.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return format!(
            "\"{}\" is not a type name: 1 to 512 printable ASCII characters \
             with no space",
            js::slice_utf16(text, 80)
        );
    }
    String::new()
}

// `authorizationDetailsLocationProblem(value)`.
fn location_problem(value: &Value) -> String {
    let Some(text) = value.as_str().filter(|s| !s.is_empty()) else {
        return "a location is not a non-empty string".into();
    };
    let Ok(parsed) = url::Url::parse(text) else {
        return format!(
            "\"{}\" is not an absolute URI",
            js::slice_utf16(text, 200)
        );
    };
    if parsed.fragment().is_some_and(|f| !f.is_empty()) || text.contains('#') {
        return format!(
            "\"{}\" carries a fragment",
            js::slice_utf16(text, 200)
        );
    }
    String::new()
}

// `authorizationDetailsSchemaCompiler().compile(schema)`: ajv's 2020-12
// class, not strict, unknown formats ignored. The refusal's wording after
// Node's own prefix is the jsonschema crate's, not ajv's.
fn schema_compile_problem(schema: &Value) -> Option<String> {
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(schema)
        .err()
        .map(|e| e.to_string())
}

// `accessTypeListProblem(name, value)`.
fn list_problem(name: &str, value: &Value) -> String {
    let Some(list) = value.as_array() else {
        return format!("{} must be an array of strings", name);
    };
    if list.len() > 256 {
        return format!(
            "{} lists {} values, and at most 256 are kept",
            name,
            list.len()
        );
    }
    for (i, one) in list.iter().enumerate() {
        let ok = one.as_str().is_some_and(|s| {
            !s.is_empty()
                && js::len_utf16(s) <= 512
                && !s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
        });
        if !ok {
            return format!(
                "{}[{}] is not a non-empty string of at most 512 characters \
                 with no control character",
                name, i
            );
        }
        if list.iter().position(|x| x == one) != Some(i) {
            return format!(
                "{} names \"{}\" twice",
                name,
                js::slice_utf16(one.as_str().unwrap_or(""), 80)
            );
        }
    }
    String::new()
}

fn strings_of(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|l| l.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

// `limitsSchemaProblem(node, path, depth)`.
fn limits_schema_problem(node: &Value, path: &str, depth: usize) -> String {
    if depth > 8 {
        return format!("{} nests more than eight schemas deep", path);
    }
    let Some(o) = node.as_object() else {
        return format!("{} is not a schema object", path);
    };
    for key in js_keys(o) {
        if !LIMITS_SCHEMA_KEYWORDS.contains(&key.as_str()) {
            return format!(
                "{} uses \"{}\", and a limits schema may use only {}",
                path,
                js::slice_utf16(&key, 60),
                LIMITS_SCHEMA_KEYWORDS.join(", ")
            );
        }
    }
    if let Some(ty) = o.get("type") {
        let types: Vec<Value> = match ty {
            Value::Array(l) => l.clone(),
            other => vec![other.clone()],
        };
        if types.is_empty()
            || types.iter().any(|t| {
                !t.as_str().is_some_and(|s| LIMITS_SCHEMA_TYPES.contains(&s))
            })
        {
            return format!(
                "{}.type must be one or more of {}",
                path,
                LIMITS_SCHEMA_TYPES.join(", ")
            );
        }
    }
    if let Some(properties) = o.get("properties") {
        let Some(props) = properties.as_object() else {
            return format!("{}.properties must be an object of schemas", path);
        };
        for name in js_keys(props) {
            let inner = limits_schema_problem(
                &props[&name],
                &format!("{}.properties.{}", path, name),
                depth + 1,
            );
            if !inner.is_empty() {
                return inner;
            }
        }
    }
    if let Some(items) = o.get("items") {
        let inner =
            limits_schema_problem(items, &format!("{}.items", path), depth + 1);
        if !inner.is_empty() {
            return inner;
        }
    }
    if o.get("additionalProperties").is_some_and(|v| !v.is_boolean()) {
        return format!(
            "{}.additionalProperties must be true or false (a schema there \
             is outside the subset)",
            path
        );
    }
    if let Some(required) = o.get("required") {
        let p = list_problem(&format!("{}.required", path), required);
        if !p.is_empty() {
            return p;
        }
    }
    String::new()
}

// `accessTypeCatalogueProblem(definition, out)`.
fn catalogue_problem(definition: &Map<String, Value>, own_type: &str) -> String {
    let mut kept: Vec<(&str, Vec<String>)> = Vec::new();
    for name in [
        "actions",
        "datatypes",
        "privileges",
        "required",
        "consentActions",
        "derivableFrom",
        "introspectionClaims",
    ] {
        let Some(value) = definition.get(name) else {
            continue;
        };
        let p = list_problem(name, value);
        if !p.is_empty() {
            return p;
        }
        kept.push((name, strings_of(value)));
    }
    let list = |name: &str| -> Option<Vec<String>> {
        kept.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone())
    };
    if list("required")
        .unwrap_or_default()
        .iter()
        .any(|s| s == "type")
    {
        return "required need not name \"type\", which every right carries"
            .into();
    }
    if let Some(actions) = list("actions") {
        if list("consentActions")
            .unwrap_or_default()
            .iter()
            .any(|one| !actions.contains(one))
        {
            return "consentActions names an action the type does not list \
                    in actions"
                .into();
        }
    }
    for one in list("derivableFrom").unwrap_or_default() {
        let name = type_name_problem(&Value::String(one.clone()));
        if !name.is_empty() {
            return format!("derivableFrom: {}", name);
        }
        if one == own_type {
            return "derivableFrom names the type itself, and a right of a \
                    type is derivable from its own type only as a subset, \
                    which needs no declaration"
                .into();
        }
    }
    let claim_shape = Regex::new(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$").ok();
    for claim in list("introspectionClaims").unwrap_or_default() {
        if !claim_shape.as_ref().is_some_and(|r| r.is_match(&claim)) {
            return format!(
                "introspectionClaims: \"{}\" is not a claim name",
                js::slice_utf16(&claim, 80)
            );
        }
        if INTROSPECTION_RESERVED.contains(&claim.as_str()) {
            return format!(
                "introspectionClaims: \"{}\" is a member every introspection \
                 response already carries or reserves",
                claim
            );
        }
    }
    if definition.get("interaction").is_some_and(|i| {
        !i.as_str()
            .is_some_and(|s| ACCESS_TYPE_INTERACTIONS.contains(&s))
    }) {
        return format!(
            "interaction must be one of {}",
            ACCESS_TYPE_INTERACTIONS.join(", ")
        );
    }
    if definition.get("bearer").is_some_and(|b| !b.is_boolean()) {
        return "bearer must be true or false".into();
    }
    if let Some(life) = definition.get("maxLifetimeS") {
        let ok = life.as_f64().is_some_and(|f| {
            f.fract() == 0.0 && f >= 1.0 && f <= ACCESS_TYPE_MAX_LIFETIME_S
        });
        if !ok {
            return format!(
                "maxLifetimeS must be a whole number of seconds from 1 to {}",
                ACCESS_TYPE_MAX_LIFETIME_S as u64
            );
        }
    }
    if definition.get("acr").is_some_and(|acr| {
        !acr.as_str().is_some_and(|s| {
            (1..=256).contains(&s.len())
                && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
        })
    }) {
        return "acr must be one authentication context class reference, 1 \
                to 256 printable characters with no space"
            .into();
    }
    if let Some(limits) = definition.get("limits") {
        let shape = limits_schema_problem(limits, "limits", 0);
        if !shape.is_empty() {
            return shape;
        }
        if let Some(e) = schema_compile_problem(limits) {
            return format!("limits does not compile as a JSON Schema: {}", e);
        }
    }
    String::new()
}

// `xacml/fga_map.ts`'s `within(path, base)`.
fn within(path: &str, base: &str) -> bool {
    path == base || path.starts_with(&format!("{}.", base))
}

// `COMMON_FIELDS` and their `COMMON_ROWS` attribute ids.
const COMMON_ROW_IDS: &[(&str, &str)] = &[
    ("locations", "urn:sts:xacml:fga:detail:location"),
    ("actions", "urn:sts:xacml:fga:detail:action"),
    ("datatypes", "urn:sts:xacml:fga:detail:datatype"),
    ("identifier", "urn:sts:xacml:fga:detail:identifier"),
    ("privileges", "urn:sts:xacml:fga:detail:privilege"),
];

fn is_common_field(name: &str) -> bool {
    COMMON_ROW_IDS.iter().any(|(p, _)| *p == name)
}

const ROW_MEMBERS: &[&str] = &[
    "path",
    "attributeId",
    "category",
    "dataType",
    "multiplicity",
    "description",
];

const MAX_ROWS: usize = 256;

// `FgaMap.fixedMemberProblem(name)`.
fn fixed_member_problem(name: &str) -> String {
    if name == "type" {
        return "\"type\" is sent by the adapter as \
                urn:sts:xacml:fga:detail-type, a trusted fact, and nothing \
                else may map it"
            .into();
    }
    if let Some((_, id)) = COMMON_ROW_IDS.iter().find(|(p, _)| *p == name) {
        return format!(
            "\"{}\" is one of RFC 9396 section 2.2's common data fields, \
             which a built-in row always maps ({})",
            name, id
        );
    }
    String::new()
}

// `FgaMap.parseRow(value, where)`.
fn parse_row(value: &Value, at: &str) -> Result<FgaRow, String> {
    let Some(given) = value.as_object() else {
        return Err(format!(
            "{} is not a JSON object of path, attributeId, and optionally \
             category, dataType, multiplicity and description",
            at
        ));
    };
    let stray: Vec<String> = js_keys(given)
        .into_iter()
        .filter(|k| !ROW_MEMBERS.contains(&k.as_str()))
        .map(|k| format!("\"{}\"", js::slice_utf16(&k, 40)))
        .collect();
    if !stray.is_empty() {
        return Err(format!(
            "{} has no member {}; a row takes {}",
            at,
            stray.join(", "),
            ROW_MEMBERS.join(", ")
        ));
    }
    let Some(segments) = segments_of(&text_member(given, "path")) else {
        return Err(format!(
            "{}.path must be a member name, or a dotted path of at most {} \
             names, each of letters, digits, _ $ @ : or -",
            at, MAX_DEPTH
        ));
    };
    let fixed = fixed_member_problem(&segments[0]);
    if !fixed.is_empty() {
        return Err(format!("{}.path: {}", at, fixed));
    }
    let attribute_id = text_member(given, "attributeId");
    if !id_shaped(&attribute_id) {
        return Err(format!(
            "{}.attributeId must be a non-empty identifier with no white \
             space, at most {} characters",
            at, MAX_ID_LENGTH
        ));
    }
    let category_text = text_member(given, "category");
    let category = if category_text.is_empty() {
        RESOURCE.to_string()
    } else {
        named_or_uri(CATEGORY_NAMES, &category_text)
    };
    if category.is_empty() {
        return Err(format!(
            "{}.category must be one of {}, or its XACML URI",
            at,
            names_of(CATEGORY_NAMES)
        ));
    }
    if data_type_of(&text_member(given, "dataType")).is_empty() {
        return Err(format!(
            "{}.dataType must be one of {}, or its URI",
            at,
            names_of(TYPE_NAMES)
        ));
    }
    let multiplicity = text_member(given, "multiplicity");
    if !multiplicity.is_empty() && multiplicity != "single" && multiplicity != "bag"
    {
        return Err(format!("{}.multiplicity must be single or bag", at));
    }
    if let Some(reserved) = reserved_problem(&attribute_id, &category) {
        return Err(format!("{}.attributeId: {}", at, reserved));
    }
    Ok(FgaRow {
        path: segments.join("."),
        attribute_id,
        category,
    })
}

// `FgaMap.mappingOf(definition)`: the rows and the paths left out, or the
// problem.
fn mapping_of(
    given: &Map<String, Value>,
) -> Result<(Vec<FgaRow>, Vec<String>), String> {
    let mut rows: Vec<FgaRow> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    if let Some(xacml) = given.get("xacml") {
        let Some(list) = xacml.as_array().filter(|l| l.len() <= MAX_ROWS)
        else {
            return Err(format!(
                "xacml must be an array of at most {} rows",
                MAX_ROWS
            ));
        };
        for (i, one) in list.iter().enumerate() {
            let row = parse_row(one, &format!("xacml[{}]", i))?;
            if let Some(clash) = rows.iter().find(|o| {
                within(&row.path, &o.path) || within(&o.path, &row.path)
            }) {
                return Err(format!(
                    "xacml[{}] maps {}, and {}",
                    i,
                    row.path,
                    if clash.path == row.path {
                        "another row maps it too".to_string()
                    } else {
                        format!(
                            "another row maps {}, so one would be an object \
                             holding the other",
                            clash.path
                        )
                    }
                ));
            }
            if let Some(twin) = rows.iter().find(|o| {
                o.attribute_id == row.attribute_id && o.category == row.category
            }) {
                return Err(format!(
                    "xacml[{}] sends {}, which the row for {} sends already; \
                     two members under one attribute could not be told apart \
                     by a policy",
                    i, row.attribute_id, twin.path
                ));
            }
            rows.push(row);
        }
    }
    if let Some(nfp) = given.get("notForPolicy") {
        let Some(list) = nfp.as_array().filter(|l| l.len() <= MAX_ROWS) else {
            return Err(format!(
                "notForPolicy must be an array of at most {} member paths",
                MAX_ROWS
            ));
        };
        for (j, value) in list.iter().enumerate() {
            let at = format!("notForPolicy[{}]", j);
            let Some(segments) =
                value.as_str().and_then(|s| segments_of(js::trim(s)))
            else {
                return Err(format!(
                    "{} must be a member name, or a dotted path of at most {} \
                     names",
                    at, MAX_DEPTH
                ));
            };
            let fixed = fixed_member_problem(&segments[0]);
            if !fixed.is_empty() {
                return Err(format!("{}: {}", at, fixed));
            }
            let path = segments.join(".");
            let overlap = skipped
                .iter()
                .find(|o| within(&path, o) || within(o, &path))
                .cloned();
            let mapped = rows
                .iter()
                .find(|o| within(&path, &o.path) || within(&o.path, &path))
                .map(|o| o.path.clone());
            if overlap.is_some() || mapped.is_some() {
                let which = match &mapped {
                    Some(m) => format!("the row for {} maps", m),
                    None => format!(
                        "notForPolicy names already, as {}",
                        overlap.unwrap_or_default()
                    ),
                };
                return Err(format!(
                    "{} names {}, which {}; a member is mapped or \
                     deliberately not, never both",
                    at, path, which
                ));
            }
            skipped.push(path);
        }
    }
    Ok((rows, skipped))
}

// `authorizationDetailsTypeOf(value)`, as far as the checks read it.
fn authorization_details_type_of(value: &str) -> Definition {
    let mut out = Definition::default();
    let text = trimmed(value);
    if text.is_empty() {
        out.problem = "the definition is empty".into();
        return out;
    }
    let length = js::len_utf16(&text);
    if length > AUTHORIZATION_DETAILS_DEFINITION_MAX {
        out.problem = format!(
            "the definition is {} characters, and at most {} are stored",
            length, AUTHORIZATION_DETAILS_DEFINITION_MAX
        );
        return out;
    }
    let definition = if text.starts_with('{') {
        match parse_like_json(&text) {
            Ok(v) => v,
            Err(message) => {
                out.problem = format!(
                    "the definition starts with \"{{\" and is not readable \
                     JSON: {}",
                    message
                );
                return out;
            }
        }
    } else {
        let mut m = Map::new();
        m.insert("type".into(), Value::String(text.clone()));
        Value::Object(m)
    };
    let Some(def) = definition.as_object() else {
        out.problem = "the definition is not a JSON object".into();
        return out;
    };
    let stray: Vec<String> = js_keys(def)
        .into_iter()
        .filter(|k| !DEFINITION_MEMBERS.contains(&k.as_str()))
        .collect();
    if !stray.is_empty() {
        out.problem = format!(
            "the definition carries {}, and a definition holds only {}",
            stray.join(", "),
            DEFINITION_MEMBERS.join(", ")
        );
        return out;
    }
    let type_value = def.get("type").cloned().unwrap_or(Value::Null);
    let name = type_name_problem(&type_value);
    if !name.is_empty() {
        out.problem = name;
        return out;
    }
    out.type_name = type_value.as_str().unwrap_or("").to_string();
    if AUTHORIZATION_DETAILS_BUILT_IN.contains(&out.type_name.as_str()) {
        out.problem = format!(
            "\"{}\" is OpenID4VCI's type, which this service understands \
             itself and no application may declare",
            out.type_name
        );
        return out;
    }
    if def.get("description").is_some_and(|d| !d.is_string()) {
        out.problem = "description must be a string".into();
        return out;
    }
    if let Some(locations) = def.get("locations") {
        let Some(list) = locations.as_array() else {
            out.problem = "locations must be an array of absolute URIs".into();
            return out;
        };
        for one in list {
            let p = location_problem(one);
            if !p.is_empty() {
                out.problem = format!("locations: {}", p);
                return out;
            }
        }
    }
    if let Some(schema) = def.get("schema") {
        if !schema.is_object() {
            out.problem = "schema must be a JSON Schema object".into();
            return out;
        }
        if let Some(e) = schema_compile_problem(schema) {
            out.problem =
                format!("schema does not compile as a JSON Schema: {}", e);
            return out;
        }
        out.schema = Some(schema.clone());
    }
    let catalogue = catalogue_problem(def, &out.type_name);
    if !catalogue.is_empty() {
        out.problem = catalogue;
        return out;
    }
    if def.contains_key("xacml") || def.contains_key("notForPolicy") {
        match mapping_of(def) {
            Ok((rows, skipped)) => {
                out.xacml = rows;
                out.not_for_policy = skipped;
            }
            Err(problem) => {
                out.problem = problem;
                return out;
            }
        }
    }
    out
}

/// `authorizationDetailsAttributeProblem(attribute, value)`.
#[tracing::instrument(level = "debug", skip(_reg))]
pub fn authorization_details_attribute_problem(
    _reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
) -> Option<Coded> {
    let text = trimmed(value);
    if text.is_empty() {
        return None;
    }
    if attribute == "oauthAuthorizationDetailsTypes" {
        let problem = type_name_problem(&Value::String(text));
        return (!problem.is_empty()).then(|| {
            Coded::new(
                codes::STS_REG_0111,
                format!("{}: {}.", attribute, problem),
            )
        });
    }
    if attribute == "oauthAuthorizationDetailsType" {
        let definition = authorization_details_type_of(&text);
        return (!definition.problem.is_empty()).then(|| {
            Coded::new(
                codes::STS_REG_0112,
                format!("{}: {}.", attribute, definition.problem),
            )
        });
    }
    None
}

// `FgaMap.closed(schema)`.
fn schema_closed(schema: &Map<String, Value>) -> bool {
    let patterns = schema
        .get("patternProperties")
        .and_then(Value::as_object)
        .is_some_and(|p| !p.is_empty());
    if patterns {
        return false;
    }
    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
        return true;
    }
    let applied = [
        "allOf",
        "anyOf",
        "oneOf",
        "$ref",
        "$dynamicRef",
        "if",
        "then",
        "else",
        "dependentSchemas",
    ]
    .iter()
    .any(|k| schema.contains_key(*k));
    schema.get("unevaluatedProperties") == Some(&Value::Bool(false)) && !applied
}

// `FgaMap.uncoveredAt(schema, prefix, rows, skipped, out, depth)`.
fn uncovered_at(
    schema: Option<&Value>,
    prefix: &str,
    rows: &[String],
    skipped: &[String],
    out: &mut Vec<String>,
    depth: usize,
) {
    let open = if prefix.is_empty() {
        "*".to_string()
    } else {
        format!("{}.*", prefix)
    };
    if schema == Some(&Value::Bool(false)) {
        return;
    }
    let Some(o) = schema.and_then(Value::as_object) else {
        out.push(open);
        return;
    };
    let empty = Map::new();
    let properties = o
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    for name in js_keys(properties) {
        if prefix.is_empty() && (name == "type" || is_common_field(&name)) {
            continue;
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}.{}", prefix, name)
        };
        if rows.contains(&path) || skipped.iter().any(|one| within(&path, one))
        {
            continue;
        }
        let reached = rows
            .iter()
            .chain(skipped.iter())
            .any(|one| one.starts_with(&format!("{}.", path)));
        if reached && depth + 1 < MAX_DEPTH {
            uncovered_at(
                properties.get(&name),
                &path,
                rows,
                skipped,
                out,
                depth + 1,
            );
            continue;
        }
        out.push(path);
    }
    if !schema_closed(o) {
        out.push(open);
    }
}

/// `fgaCoverageProblem(fields, value)`: on an application enforcing
/// fine-grained authorization, a type whose detail members are neither
/// mapped nor listed in `notForPolicy` (`FgaMap.uncovered()`).
#[tracing::instrument(level = "debug", skip(_reg, fields))]
pub fn fga_coverage_problem(
    _reg: &ApplicationRegistry,
    fields: &Fields,
    value: &str,
) -> Option<String> {
    if held(fields, "appFgaEnforced").to_uppercase() != "TRUE" {
        return None;
    }
    let definition = authorization_details_type_of(value);
    if !definition.problem.is_empty() {
        return None;
    }
    let rows: Vec<String> =
        definition.xacml.iter().map(|r| r.path.clone()).collect();
    let mut paths: Vec<String> = Vec::new();
    uncovered_at(
        definition.schema.as_ref(),
        "",
        &rows,
        &definition.not_for_policy,
        &mut paths,
        0,
    );
    // `out.sort()` compares UTF-16 code units; for these ASCII paths that
    // is the byte order.
    paths.sort();
    if paths.is_empty() {
        return None;
    }
    Some(format!(
        "oauthAuthorizationDetailsType: this application enforces \
         fine-grained authorization, and the type \"{}\" would leave {} \
         neither mapped (xacml) nor listed in notForPolicy, so every detail \
         carrying one would be refused. Map each, list it in notForPolicy, or \
         close the schema (additionalProperties: false) where \"*\" is shown \
         — or switch enforcement off first.",
        definition.type_name,
        paths.join(", ")
    ))
}

// ---------------------------------------------------------------------------
// `JSON.parse()`, and V8's words for what it refuses.
// ---------------------------------------------------------------------------

// `JSON.parse(text)`: the value, or V8's message.
fn parse_like_json(text: &str) -> Result<Value, String> {
    if let Some(message) = v8_json_problem(text) {
        return Err(message);
    }
    serde_json::from_str::<Value>(text).map_err(|e| e.to_string())
}

/// V8's `JSON.parse()` message (Node 22) for a text it refuses, None for
/// one it reads: the same walk V8's parser makes, so the same position,
/// line and column, and the same ten characters of context either side of
/// an unexpected token.
#[tracing::instrument(level = "debug", skip(text))]
pub fn v8_json_problem(text: &str) -> Option<String> {
    let mut p = V8Json {
        s: text.encode_utf16().collect(),
        i: 0,
    };
    let at = p.value().and_then(|()| {
        p.ws();
        if p.i < p.s.len() {
            Err(V8Error::At(
                "Unexpected non-whitespace character after JSON",
                p.i,
            ))
        } else {
            Ok(())
        }
    });
    at.err().map(|e| p.message(e))
}

enum V8Error {
    End,
    Token(usize),
    At(&'static str, usize),
}

struct V8Json {
    s: Vec<u16>,
    i: usize,
}

impl V8Json {
    fn peek(&self) -> Option<u16> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(0x20 | 0x09 | 0x0a | 0x0d)) {
            self.i += 1;
        }
    }

    fn value(&mut self) -> Result<(), V8Error> {
        self.ws();
        let Some(c) = self.peek() else {
            return Err(V8Error::End);
        };
        match c {
            0x7b => self.object(),
            0x5b => self.array(),
            0x22 => self.string(),
            0x2d | 0x30..=0x39 => self.number(),
            0x74 => self.literal("true"),
            0x66 => self.literal("false"),
            0x6e => self.literal("null"),
            _ => Err(V8Error::Token(self.i)),
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), V8Error> {
        for w in word.encode_utf16() {
            match self.peek() {
                None => return Err(V8Error::End),
                Some(c) if c == w => self.i += 1,
                Some(_) => return Err(V8Error::Token(self.i)),
            }
        }
        Ok(())
    }

    fn object(&mut self) -> Result<(), V8Error> {
        self.i += 1;
        self.ws();
        if self.peek() == Some(0x7d) {
            self.i += 1;
            return Ok(());
        }
        let mut first = true;
        loop {
            if self.peek() != Some(0x22) {
                return Err(V8Error::At(
                    if first {
                        "Expected property name or '}'"
                    } else {
                        "Expected double-quoted property name"
                    },
                    self.i,
                ));
            }
            first = false;
            self.string()?;
            self.ws();
            if self.peek() != Some(0x3a) {
                return Err(V8Error::At(
                    "Expected ':' after property name",
                    self.i,
                ));
            }
            self.i += 1;
            self.value()?;
            self.ws();
            match self.peek() {
                Some(0x2c) => {
                    self.i += 1;
                    self.ws();
                }
                Some(0x7d) => {
                    self.i += 1;
                    return Ok(());
                }
                _ => {
                    return Err(V8Error::At(
                        "Expected ',' or '}' after property value",
                        self.i,
                    ));
                }
            }
        }
    }

    fn array(&mut self) -> Result<(), V8Error> {
        self.i += 1;
        self.ws();
        if self.peek() == Some(0x5d) {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.value()?;
            self.ws();
            match self.peek() {
                Some(0x2c) => self.i += 1,
                Some(0x5d) => {
                    self.i += 1;
                    return Ok(());
                }
                _ => {
                    return Err(V8Error::At(
                        "Expected ',' or ']' after array element",
                        self.i,
                    ));
                }
            }
        }
    }

    fn hex_digit(c: u16) -> bool {
        matches!(c, 0x30..=0x39 | 0x41..=0x46 | 0x61..=0x66)
    }

    fn string(&mut self) -> Result<(), V8Error> {
        self.i += 1;
        loop {
            let Some(c) = self.peek() else {
                return Err(V8Error::At("Unterminated string", self.i));
            };
            match c {
                0x22 => {
                    self.i += 1;
                    return Ok(());
                }
                0x00..=0x1f => {
                    return Err(V8Error::At(
                        "Bad control character in string literal",
                        self.i,
                    ));
                }
                0x5c => {
                    self.i += 1;
                    let Some(e) = self.peek() else {
                        return Err(V8Error::At("Unterminated string", self.i));
                    };
                    match e {
                        0x22 | 0x5c | 0x2f | 0x62 | 0x66 | 0x6e | 0x72
                        | 0x74 => self.i += 1,
                        0x75 => {
                            self.i += 1;
                            for _ in 0..4 {
                                match self.peek() {
                                    None => {
                                        return Err(V8Error::At(
                                            "Unterminated string",
                                            self.i,
                                        ));
                                    }
                                    Some(h) if Self::hex_digit(h) => {
                                        self.i += 1;
                                    }
                                    Some(_) => {
                                        return Err(V8Error::At(
                                            "Bad Unicode escape",
                                            self.i,
                                        ));
                                    }
                                }
                            }
                        }
                        _ => {
                            return Err(V8Error::At(
                                "Bad escaped character",
                                self.i,
                            ));
                        }
                    }
                }
                _ => self.i += 1,
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(0x30..=0x39)) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<(), V8Error> {
        if self.peek() == Some(0x2d) {
            self.i += 1;
            if !matches!(self.peek(), Some(0x30..=0x39)) {
                return Err(V8Error::At("No number after minus sign", self.i));
            }
        }
        if self.peek() == Some(0x30) {
            self.i += 1;
            if matches!(self.peek(), Some(0x30..=0x39)) {
                return Err(V8Error::At("Unexpected number", self.i));
            }
        } else {
            self.digits();
        }
        if self.peek() == Some(0x2e) {
            self.i += 1;
            if self.digits() == 0 {
                return Err(V8Error::At(
                    "Unterminated fractional number",
                    self.i,
                ));
            }
        }
        if matches!(self.peek(), Some(0x65 | 0x45)) {
            self.i += 1;
            if matches!(self.peek(), Some(0x2b | 0x2d)) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(V8Error::At(
                    "Exponent part is missing a number",
                    self.i,
                ));
            }
        }
        Ok(())
    }

    fn text(&self, from: usize, to: usize) -> String {
        String::from_utf16_lossy(&self.s[from..to])
    }

    fn message(&self, e: V8Error) -> String {
        match e {
            V8Error::End => "Unexpected end of JSON input".into(),
            V8Error::At(what, pos) => {
                let before = &self.s[..pos.min(self.s.len())];
                let line = before.iter().filter(|c| **c == 0x0a).count() + 1;
                let column = match before.iter().rposition(|c| *c == 0x0a) {
                    Some(nl) => pos - nl,
                    None => pos + 1,
                };
                format!(
                    "{} in JSON at position {} (line {} column {})",
                    what, pos, line, column
                )
            }
            V8Error::Token(pos) => {
                const CONTEXT: usize = 10;
                let token = self.text(pos, pos + 1);
                let n = self.s.len();
                let context = if n < CONTEXT * 2 + 1 {
                    format!("\"{}\"", self.text(0, n))
                } else {
                    let from = pos.saturating_sub(CONTEXT);
                    let to = (pos + CONTEXT + 1).min(n);
                    format!(
                        "{}\"{}\"{}",
                        if from > 0 { "..." } else { "" },
                        self.text(from, to),
                        if to < n { "..." } else { "" }
                    )
                };
                format!(
                    "Unexpected token '{}', {} is not valid JSON",
                    token, context
                )
            }
        }
    }
}
