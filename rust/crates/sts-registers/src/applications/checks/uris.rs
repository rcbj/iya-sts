// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The URI and name checks of `common/applications.js`: the permissions
//! and their base, the RFC 9728 resource metadata, the home page,
//! `initiate_login_uri`, the client display URIs, GNAP's owner lookup URI,
//! the return and logout addresses, the CORS origins, scope tokens, the
//! SSF event list, the delegation attributes, the Kerberos S4U2Self realm
//! and the self references. Each answers Node's sentence word for word, or
//! `None` where Node answers `''` or `null`.
//!
//! Three checks ask another family a question Node reaches by a lazy
//! `require` — whether the SSF transmitter knows an event type
//! (`ssf_events.EVENT_BY_URI`), whether the outbound policy would dial a
//! URL (`federation_http.urlProblem()`), whether the realm's Kerberos
//! trusts accept a realm (`krb5_trusts.acceptsRealm()`) — and take the
//! answer as a function argument, so this module requires none of them.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;
use sts_core::errors::codes;

use super::validation::{self, js_url};
use super::{address_kind, Coded};
use crate::applications::record::values_of;
use crate::applications::tables::{Tables, PROTOCOLS};
use crate::applications::{ApplicationRegistry, Fields};

/// `parsePermissionValue(value)`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ParsedPermission {
    pub name: String,
    pub description: String,
}

/// `parsePermissionValue(value)`: `name|description`, each trimmed.
#[tracing::instrument(level = "debug")]
pub fn parse_permission_value(value: &str) -> ParsedPermission {
    let (name, description) = match value.find('|') {
        Some(at) => (&value[..at], &value[at + 1..]),
        None => (value, ""),
    };
    ParsedPermission {
        name: crate::js::trim(name).to_string(),
        description: crate::js::trim(description).to_string(),
    }
}

// RFC 6749 section 3.3's scope token: printable ASCII but space, `"` and
// `\`.
static SCOPE_TOKEN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[\x21\x23-\x5B\x5D-\x7E]+$").ok());

static OPERATOR_CODE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"STS-[A-Z]+-[0-9]{4}").ok());

static COMMAND_ENDPOINT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)^https://[^\s#]+$").ok());

static PLAIN_HTTP: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)^http:").ok());

static DN_SHAPE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^[A-Za-z][A-Za-z0-9-]*=[^,]+(,\s*[A-Za-z][A-Za-z0-9-]*=[^,]+)*$",
    )
    .ok()
});

static IDENTIFIER_SEGMENT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"/\{identifier\}(/|$)").ok());

/// `permissionBaseProblem(value)`: a base must be an absolute URI.
#[tracing::instrument(level = "debug")]
pub fn permission_base_problem(value: &str) -> Option<String> {
    let text = crate::js::trim(value);
    if text.is_empty() {
        return None;
    }
    // `!parsed.protocol` cannot be true of a URL that parsed, so the
    // "has no scheme" branch of Node is unreachable and not ported.
    if js_url(text).is_none() {
        return Some(format!(
            "\"{text}\" is not an absolute URI. A permission base is what an \
             access token asking for one of this application's permissions \
             is AUDIENCED to, and an audience that is not absolute is one \
             nothing can compare against. Microsoft Entra ID spells this \
             `api://<guid>`; anything absolute works here."
        ));
    }
    None
}

/// `permissionOperatorCodeProblem(name, description)` (#1426).
#[tracing::instrument(level = "debug")]
pub fn permission_operator_code_problem(
    name: &str,
    description: &str,
) -> Option<String> {
    let text = format!("{name}\n{description}");
    if OPERATOR_CODE.as_ref().is_some_and(|r| r.is_match(&text)) {
        return Some(
            "A permission name or description may not contain an operator \
             error code. That value is returned on every page that lists \
             the permission, and a code is recorded rather than sent."
                .into(),
        );
    }
    None
}

/// `permissionNameProblem(name)`: a name is one scope token.
#[tracing::instrument(level = "debug")]
pub fn permission_name_problem(name: &str) -> Option<String> {
    if crate::js::trim(name).is_empty() {
        return Some(
            "A permission needs a name — the word a client will put in its \
             `scope`, such as `read` or `Widgets.ReadWrite.All`."
                .into(),
        );
    }
    if name != crate::js::trim(name) {
        return Some(
            "A permission name may not begin or end with whitespace: it is \
             sent as one word in an OAuth `scope` parameter, which is \
             space-delimited."
                .into(),
        );
    }
    if name.contains('|') {
        return Some(
            "A permission name may not contain \"|\". That character \
             separates the name from the description in the \
             `oauthPermission` attribute, so a name carrying one could \
             never be read back as the name that was written — put the text \
             after the first \"|\" and it becomes the description."
                .into(),
        );
    }
    if !SCOPE_TOKEN.as_ref().is_some_and(|r| r.is_match(name)) {
        return Some(format!(
            "\"{name}\" is not a legal OAuth scope token. RFC 6749 section \
             3.3 allows any printable ASCII except space, double quote and \
             backslash, because a scope list is space-delimited — a name \
             outside that set cannot survive the round trip through a \
             `scope` parameter."
        ));
    }
    None
}

/// `roleGatedProblem(value)`: a gated permission must be one of the
/// application's own, by name.
#[tracing::instrument(level = "debug")]
pub fn role_gated_problem(value: &str) -> String {
    format!(
        "\"{value}\" is not one of this application's own permissions, and \
         only a permission it defines (`oauthPermission`) can be gated by \
         role. Give the NAME, as `oauthPermission` holds it (`write`), not \
         the full identifier."
    )
}

/// `resourceMetadataProblem(value)`: an RFC 9728 document, a JSON object
/// carrying a `resource` string. The parser's own message is quoted, as
/// V8 words it.
#[tracing::instrument(level = "debug")]
pub fn resource_metadata_problem(value: &str) -> Option<String> {
    let text = crate::js::trim(value);
    if text.is_empty() {
        return None;
    }
    let document = match validation::json_parse(text) {
        Ok(d) => d,
        Err(message) => {
            return Some(format!(
                "`oauthResourceMetadata` is not JSON ({message}). It holds \
                 an RFC 9728 protected resource metadata document, which is \
                 a JSON object."
            ));
        }
    };
    let usable = match document.get("resource") {
        Some(Value::String(s)) if document.is_object() => {
            !crate::js::trim(s).is_empty()
        }
        _ => false,
    };
    if !usable {
        return Some(
            "`oauthResourceMetadata` must be a JSON object carrying a \
             `resource` string — the one member RFC 9728 section 2 makes \
             REQUIRED."
                .into(),
        );
    }
    None
}

/// `resourceMetadataUrlProblem(value)`: where a document was fetched from,
/// an http or https URL.
#[tracing::instrument(level = "debug")]
pub fn resource_metadata_url_problem(value: &str) -> Option<String> {
    let text = crate::js::trim(value);
    if text.is_empty() {
        return None;
    }
    if let Some(parsed) = js_url(text) {
        if parsed.protocol == "http:" || parsed.protocol == "https:" {
            return None;
        }
    }
    Some(format!(
        "\"{text}\" is not an http or https URL, and \
         `oauthResourceMetadataUrl` records where an RFC 9728 document was \
         fetched from."
    ))
}

/// `homePageProblem(value)`: an http or https URL a portal may link to.
#[tracing::instrument(level = "debug")]
pub fn home_page_problem(value: &str) -> Option<String> {
    let text = crate::js::trim(value);
    if text.is_empty() {
        return None;
    }
    let Some(parsed) = js_url(text) else {
        return Some(format!(
            "\"{text}\" is not an absolute URL. A home page is what \
             /portal/applications links this application to, so it has to \
             be somewhere a browser can be sent — \
             `https://expenses.example.com/` is the shape. A path on its own \
             is relative to whichever page it is drawn on, which would be \
             this service."
        ));
    };
    if parsed.protocol != "http:" && parsed.protocol != "https:" {
        return Some(format!(
            "\"{text}\" has the scheme `{}` and a home page must be http or \
             https. This value becomes a link on a page somebody is signed \
             in to, so the schemes are an allowlist rather than a list of \
             the ones to avoid: a private-use scheme like \
             `com.example.app:/callback` is a native client's redirect URI \
             and not a web page, and a `urn:` is a name rather than an \
             address.",
            parsed.protocol
        ));
    }
    None
}

/// `initiateLoginUriProblem(value)`: an https URL with no fragment
/// (OpenID Connect Registration section 2, Core section 4).
#[tracing::instrument(level = "debug")]
pub fn initiate_login_uri_problem(value: &str) -> Option<String> {
    let text = crate::js::trim(value);
    match js_url(text) {
        None => {
            Some("oauthInitiateLoginUri must be an absolute https URL.".into())
        }
        Some(parsed) if parsed.protocol != "https:" => Some(
            "oauthInitiateLoginUri must be an https URL (OpenID Connect \
             Registration section 2)."
                .into(),
        ),
        Some(parsed) if !parsed.hash.is_empty() => Some(
            "oauthInitiateLoginUri may not carry a fragment: OpenID Connect \
             Core section 4 appends a query to it."
                .into(),
        ),
        Some(_) => None,
    }
}

/// `clientDisplayUriProblem(name, value)`: `logo_uri`, `policy_uri` and
/// `tos_uri` are absolute https URLs with a host and no credentials.
#[tracing::instrument(level = "debug")]
pub fn client_display_uri_problem(name: &str, value: &str) -> Option<String> {
    if value.is_empty() || value.chars().any(crate::js::is_space) {
        return Some(format!(
            "{name} must be an absolute https URL with no spaces (OpenID \
             Connect Registration section 2)."
        ));
    }
    match js_url(value) {
        None => Some(format!(
            "{name} must be an absolute https URL (OpenID Connect \
             Registration section 2)."
        )),
        Some(parsed)
            if parsed.protocol != "https:" || parsed.hostname.is_empty() =>
        {
            Some(format!(
                "{name} must be an https URL: the sign-in and consent \
                 screens are served over https and draw it there (OpenID \
                 Connect Registration section 2)."
            ))
        }
        Some(parsed)
            if !parsed.username.is_empty() || !parsed.password.is_empty() =>
        {
            Some(format!("{name} may not carry a user name or password."))
        }
        Some(_) => None,
    }
}

/// `ownerLookupUriProblem(value)`: GNAP's owner lookup, an https URL with
/// `{identifier}` exactly once as a whole path segment.
#[tracing::instrument(level = "debug")]
pub fn owner_lookup_uri_problem(value: &str) -> Option<String> {
    let text = crate::js::trim(value);
    if text.is_empty() {
        return None;
    }
    let why = "gnapOwnerLookupUri must be an https URL with a host, no user \
               information, query or fragment, and {identifier} exactly \
               once as a whole path segment \
               (https://rs.example.com/owners/{identifier})";
    let once = text.matches("{identifier}").count() == 1;
    let rest = text.replacen("{identifier}", "", 1);
    if !once
        || rest.contains('{')
        || rest.contains('}')
        || !IDENTIFIER_SEGMENT
            .as_ref()
            .is_some_and(|r| r.is_match(text))
    {
        return Some(why.into());
    }
    let usable =
        js_url(&text.replacen("{identifier}", "x", 1)).is_some_and(|p| {
            p.protocol == "https:"
                && !p.hostname.is_empty()
                && p.username.is_empty()
                && p.password.is_empty()
                && p.search.is_empty()
                && p.hash.is_empty()
                && !text.contains('?')
                && !text.contains('#')
                && p.pathname.contains("/x")
        });
    if !usable {
        return Some(why.into());
    }
    None
}

// `commandMetadataProblem({command_endpoint})`: an https URL with no
// fragment (OpenID Provider Commands 1.0).
fn command_endpoint_problem(value: &str) -> bool {
    !value.is_empty()
        && !COMMAND_ENDPOINT.as_ref().is_some_and(|r| r.is_match(value))
}

/// `addressProblem(attribute, value)`: a return or logout address as its
/// attribute's own rule reads it.
#[tracing::instrument(level = "debug")]
pub fn address_problem(attribute: &str, value: &str) -> Option<String> {
    let kind = address_kind(attribute)?;
    if kind == "command" {
        return command_endpoint_problem(value).then(|| {
            format!(
                "\"{value}\" cannot be {attribute}: it must be an https URL \
                 with no fragment."
            )
        });
    }
    let problem = match kind {
        "saml" => validation::redirect_uri_problem(value, false),
        "frontchannel" => validation::frontchannel_uri_problem(value),
        "backchannel" => validation::backchannel_uri_problem(value),
        _ => validation::redirect_uri_problem(value, true),
    };
    problem.map(|p| format!("\"{value}\" cannot be {attribute}: it {p}."))
}

/// `backchannelSchemeProblem(uri, publicClient)`: http only for a
/// confidential client (Back-Channel Logout 1.0 section 2.2), and only to
/// an address the outbound policy would dial — `dial_problem` is
/// `federation_http.urlProblem()`, '' where it may be dialled.
#[tracing::instrument(level = "debug", skip(dial_problem))]
pub fn backchannel_scheme_problem(
    uri: &str,
    public_client: bool,
    dial_problem: &dyn Fn(&str) -> String,
) -> Option<Coded> {
    if !PLAIN_HTTP.as_ref().is_some_and(|r| r.is_match(uri)) {
        return None;
    }
    if public_client {
        return Some(Coded::new(
            codes::STS_REG_0189,
            "backchannel_logout_uri: an http URI is allowed only to a \
             confidential client (Back-Channel Logout 1.0 section 2.2); this \
             client authenticates with none. Use https.",
        ));
    }
    let undeliverable = dial_problem(uri);
    if !undeliverable.is_empty() {
        return Some(Coded::new(
            codes::STS_REG_0190,
            format!(
                "backchannel_logout_uri: every Logout Token to this address \
                 would be dead-lettered — {undeliverable}. Use https."
            ),
        ));
    }
    None
}

/// `frontchannelOriginProblem(uri, redirectUris)`: the front-channel
/// logout URI shares an origin with a registered redirect URI
/// (Front-Channel Logout 1.0 section 2).
#[tracing::instrument(level = "debug", skip(redirect_uris))]
pub fn frontchannel_origin_problem(
    uri: &str,
    redirect_uris: Option<&Value>,
) -> Option<String> {
    let origin = js_url(uri).map(|p| p.origin).unwrap_or_default();
    if origin.is_empty() || origin == "null" {
        return Some(format!(
            "\"{uri}\" is not a URL with a scheme, host and port."
        ));
    }
    let origins: Vec<String> = values_of(redirect_uris)
        .iter()
        .map(|one| js_url(one).map(|p| p.origin).unwrap_or_default())
        .collect();
    if origins.contains(&origin) {
        return None;
    }
    let said = if origins.iter().any(|o| !o.is_empty()) {
        "no registered redirect URI is (the scheme, host and port must be \
         the same as one of them)"
    } else {
        "the client registers no redirect URI for it to match"
    };
    Some(format!(
        "\"{uri}\" is at {origin}, and {said} — Front-Channel Logout 1.0 \
         section 2."
    ))
}

/// `corsOriginWriteProblem(value)`: an exact origin (`originProblem()`).
#[tracing::instrument(level = "debug")]
pub fn cors_origin_write_problem(value: &str) -> Option<String> {
    validation::origin_problem(value)
        .map(|p| format!("\"{value}\" cannot be appCorsOrigin: it {p}."))
}

/// `scopeTokenProblem(value)`: a scope is one RFC 6749 scope token.
#[tracing::instrument(level = "debug")]
pub fn scope_token_problem(value: &str) -> Option<String> {
    if crate::js::trim(value).is_empty() {
        return Some(
            "Which scope? It is the word a client puts in its `scope` \
             parameter — `openid`, `profile`, or a whole delegated \
             permission identifier such as `https://example.com/write`."
                .into(),
        );
    }
    if value != crate::js::trim(value) {
        return Some(
            "A scope may not begin or end with whitespace: a `scope` \
             parameter is space-delimited, so the value would arrive at the \
             authorization endpoint as a different word from the one \
             written here and would never match."
                .into(),
        );
    }
    if !SCOPE_TOKEN.as_ref().is_some_and(|r| r.is_match(value)) {
        return Some(format!(
            "\"{value}\" is not a legal OAuth scope token. RFC 6749 section \
             3.3 allows any printable ASCII except space, double quote and \
             backslash, because a scope list is space-delimited. A value \
             outside that set can never match a scope a client asked for, \
             so consenting it would consent nothing."
        ));
    }
    None
}

/// CAEP's event type prefix (`ssf_events.CAEP_PREFIX`).
pub const CAEP_PREFIX: &str =
    "https://schemas.openid.net/secevent/caep/event-type/";

/// RISC's event type prefix (`ssf_events.RISC_PREFIX`).
pub const RISC_PREFIX: &str =
    "https://schemas.openid.net/secevent/risc/event-type/";

// `Object.prototype`'s own names: `EVENT_BY_URI[word]` is truthy for each
// of them, because the catalogue is a plain object (a Node defect, ported
// so the two runtimes agree).
const OBJECT_PROTOTYPE_NAMES: &[&str] = &[
    "constructor",
    "__defineGetter__",
    "__defineSetter__",
    "hasOwnProperty",
    "__lookupGetter__",
    "__lookupSetter__",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toString",
    "valueOf",
    "__proto__",
    "toLocaleString",
];

/// `ssfAllowedEventProblem(value)`: `caep`, `risc`, or one event type URI
/// the transmitter knows — `known_event` is `ssf_events.EVENT_BY_URI`.
#[tracing::instrument(level = "debug", skip(known_event))]
pub fn ssf_allowed_event_problem(
    value: &str,
    known_event: &dyn Fn(&str) -> bool,
) -> Option<String> {
    let word = crate::js::trim(value);
    if word.is_empty() {
        return Some("\"ssfAllowedEvents\" was given an empty value.".into());
    }
    let lower = crate::js::lower(word);
    if lower == "caep" || lower == "risc" {
        return None;
    }
    if known_event(word) || OBJECT_PROTOTYPE_NAMES.contains(&word) {
        return None;
    }
    Some(format!(
        "\"{word}\" is not an event type this transmitter knows. An \
         ssfAllowedEvents value is `caep`, `risc`, or one event type URI — \
         {CAEP_PREFIX}<name> for a session event, {RISC_PREFIX}<name> for \
         an account event."
    ))
}

/// `DELEGATION_SEMANTICS`.
const DELEGATION_SEMANTICS: &[&str] = &["delegation", "impersonation"];

/// `delegationAttributeProblem(attribute, value)`: the delegation flags,
/// semantics and DNs.
#[tracing::instrument(level = "debug", skip(_reg))]
pub fn delegation_attribute_problem(
    _reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
) -> Option<String> {
    let text = crate::js::trim(value);
    if text.is_empty() {
        return None;
    }
    if (attribute == "appNotDelegated"
        || attribute == "krb5TrustedForDelegation")
        && !["TRUE", "FALSE"].contains(&text.to_uppercase().as_str())
    {
        return Some(format!("{attribute}: \"{text}\" is not TRUE or FALSE."));
    }
    if (attribute == "appDelegationSemantics"
        || attribute == "appDefaultDelegationSemantics")
        && !DELEGATION_SEMANTICS.contains(&crate::js::lower(text).as_str())
    {
        return Some(format!(
            "{attribute}: \"{text}\" is not delegation or impersonation."
        ));
    }
    if (attribute == "appDelegationSubjectGroup" || attribute == "appMayAct")
        && !DN_SHAPE.as_ref().is_some_and(|r| r.is_match(text))
    {
        let what = if attribute == "appMayAct" {
            "delegate"
        } else {
            "group"
        };
        return Some(format!(
            "{attribute}: \"{text}\" is not a DN. Name the {what} by its \
             distinguished name."
        ));
    }
    None
}

/// `kerberosTrustAttributeProblem(attribute, value)`: `krb5S4uSelfRealm`
/// names a realm this realm's trusts accept tickets from —
/// `accepts_realm` is `krb5_trusts.acceptsRealm()`.
#[tracing::instrument(level = "debug", skip(_reg, accepts_realm))]
pub fn kerberos_trust_attribute_problem(
    _reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
    accepts_realm: &dyn Fn(&str) -> bool,
) -> Option<String> {
    let text = crate::js::trim(value);
    if attribute != "krb5S4uSelfRealm" || text.is_empty() {
        return None;
    }
    if accepts_realm(text) {
        return None;
    }
    Some(format!(
        "{attribute}: \"{text}\" is not a Kerberos realm this realm's trusts \
         accept tickets from. Add a trust holding an incoming key from it \
         (ou=kerberosTrusts), or one a transitive trust routes, first."
    ))
}

/// `APPLICATION_REFERENCE_ATTRIBUTES`: the two lists naming the OTHER
/// applications of a delegation.
pub const APPLICATION_REFERENCE_ATTRIBUTES: &[&str] =
    &["appAllowedToDelegateTo", "appAllowedToActOnBehalfOf"];

// `comparableDn(dn)`.
fn comparable_dn(dn: &str) -> String {
    static SPACED_COMMA: LazyLock<Option<Regex>> =
        LazyLock::new(|| Regex::new(r"\s*,\s*").ok());
    let lower = crate::js::lower(crate::js::trim(dn));
    match SPACED_COMMA.as_ref() {
        Some(r) => r.replace_all(&lower, ",").into_owned(),
        None => lower,
    }
}

/// One row of `identifiersOf()`: an identifier attribute an entry holds,
/// the protocol's word for it, the families it serves, its values.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentifierRow {
    pub attribute: String,
    pub name: String,
    pub families: Vec<String>,
    pub values: Vec<String>,
}

/// `IDENTIFIER_ATTRIBUTES`: the attributes `declarationAttributes()`
/// first notes in the `identifier` role, each with the labels of every
/// family that names it (in any role), in table order.
#[tracing::instrument(level = "debug")]
pub fn identifier_attributes() -> Vec<(String, Vec<String>)> {
    let t = Tables::get();
    let mut rows: Vec<(String, &str, Vec<String>)> = Vec::new();
    for family in PROTOCOLS {
        for (attribute, role) in [
            (family.identifier_attribute, "identifier"),
            (family.redirect_attribute, "redirect"),
            (family.logout_attribute, "logout"),
            (family.delivery_attribute, "delivery"),
            (family.events_attribute, "events"),
            (family.secret_attribute, "secret"),
        ] {
            if attribute.is_empty() || t.attribute(attribute).is_none() {
                continue;
            }
            match rows.iter_mut().find(|r| r.0 == attribute) {
                Some(row) => row.2.push(family.label.to_string()),
                None => rows.push((
                    attribute.to_string(),
                    role,
                    vec![family.label.to_string()],
                )),
            }
        }
    }
    rows.into_iter()
        .filter(|r| r.1 == "identifier")
        .map(|r| (r.0, r.2))
        .collect()
}

/// `identifiersOf(fields)`: what an application answers to in each
/// family.
#[tracing::instrument(level = "debug", skip_all)]
pub fn identifiers_of(fields: &Fields) -> Vec<IdentifierRow> {
    let t = Tables::get();
    identifier_attributes()
        .into_iter()
        .filter_map(|(attribute, families)| {
            let values = values_of(fields.get(&attribute));
            if values.is_empty() {
                return None;
            }
            let name = t
                .attribute(&attribute)
                .map(|r| r.identifier_name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| attribute.clone());
            Some(IdentifierRow {
                attribute,
                name,
                families,
                values,
            })
        })
        .collect()
}

/// `selfReferenceProblem(attribute, value, identifier, fields, entryDn)`:
/// a delegation list may not name the application itself.
#[tracing::instrument(level = "debug", skip(reg, fields))]
pub fn self_reference_problem(
    reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
    identifier: &str,
    fields: &Fields,
    dn: Option<&str>,
) -> Option<String> {
    let text = crate::js::trim(value);
    if attribute == "appMayAct" && !text.is_empty() {
        let mut own: Vec<String> = Vec::new();
        if let Some(d) = dn.filter(|d| !d.is_empty()) {
            own.push(comparable_dn(d));
        }
        if let Some(container) = reg.container_dn() {
            own.push(comparable_dn(&format!(
                "cn={},{}",
                reg.label_for(identifier),
                container
            )));
        }
        if !own.contains(&comparable_dn(text)) {
            return None;
        }
        return Some(format!(
            "{attribute}: \"{text}\" is this application's own entry. It \
             names the OTHER party that may act for it, and an application \
             acting for itself is not a delegation."
        ));
    }
    if !APPLICATION_REFERENCE_ATTRIBUTES.contains(&attribute) || text.is_empty()
    {
        return None;
    }
    let mut own = vec![crate::js::trim(identifier).to_string()];
    for row in identifiers_of(fields) {
        own.extend(row.values.iter().map(|v| crate::js::trim(v).to_string()));
    }
    own.extend(
        values_of(fields.get("oauthAudience"))
            .iter()
            .map(|v| crate::js::trim(v).to_string()),
    );
    if !own.iter().any(|o| o == text) {
        return None;
    }
    Some(format!(
        "{attribute}: \"{text}\" names this application itself. It lists the \
         OTHER applications of a delegation, and an application acting \
         towards itself is not one."
    ))
}
