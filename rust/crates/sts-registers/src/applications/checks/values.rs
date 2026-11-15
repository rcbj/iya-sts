// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE VALUE CHECKS of `common/applications.js` that are not URIs or OAuth
//! metadata: a DID's keys, services and aliases; the claim rows and
//! selections; the permission claims; the CLOSED CHOICES an attribute
//! takes (`ATTRIBUTE_CHOICES`, `choiceProblem()`); the response and token
//! response types; the token endpoint's authentication methods and the
//! `oauthConfidential` flag written from them; the setting overrides'
//! strict and mode checks; the SAML certificates; and the hosted
//! surfaces' own session bounds. Each sentence is Node's, word for word.
//!
//! WHAT IS ANOTHER MODULE'S, AND HOW IT ARRIVES. Node reaches eight answers
//! here through a lazy `require` of a module this register never loads
//! eagerly: `admin_stats.checkClaimEntries()`, `claim_attributes`' and
//! `vc_claims`' `checkNames()`, `claim_attributes.permissionClaimsProblem()`,
//! `oauth2_bcp.tokenResponsesAllowed()`, `helpers.offeredJwsAlgs()`, the
//! five named policy registers' `list()`/`named()`, and `crypto.js`'s
//! `xmlSignatureKeyProblem()` (whose policy is the realm's settings). They
//! are the [`ValueSources`] slot here — filled by the composition root,
//! the way `setFgaLifecycle()` is — and until it is filled [`NoSources`]
//! answers: no claim check, every policy list empty (only `default`), the
//! classical asymmetric JWS algorithms, implicit token responses allowed
//! only by `oauth2.allowImplicitTokenResponses`, and the development XML
//! policy. The static lists Node `require`s (the client authentication
//! methods, the enrollment profiles, the secret destinations, the SCIM
//! client rules, the scope-claims modes) are copied here.
//!
//! A JWK's readability is `sts_crypto::keys::JwsKey::from_jwk()`, and the
//! RSA modulus length is read off `n` itself. The RFC 7638 thumbprint
//! `didSameness()` compares is replaced by the canonical JSON it hashes:
//! the comparison is for equality, and the canonical text is equal exactly
//! when its SHA-256 is.

use std::sync::{Arc, LazyLock, RwLock};

use regex::Regex;
use serde_json::Value;
use sts_core::errors::codes;

use super::Coded;
use crate::applications::record::values_of;
use crate::applications::{ApplicationRegistry, Fields, Record};

// ---------------------------------------------------------------------------
// The slot.
// ---------------------------------------------------------------------------

/// What another module answers for a value check (see the module header).
pub trait ValueSources: Send + Sync {
    /// `admin_stats.checkClaimEntries(setId, rows).errors`.
    fn check_claim_entries(&self, set_id: &str, rows: &Value) -> Vec<String>;
    /// `checkNames(names).errors`: `vc_claims`' for a credential's
    /// selection, `claim_attributes`' otherwise.
    fn check_claim_names(&self, credential: bool, names: &Value)
        -> Vec<String>;
    /// `claim_attributes.permissionClaimsProblem(value, exposed)`.
    fn permission_claims_problem(
        &self,
        value: &str,
        exposed: &[String],
    ) -> String;
    /// `oauth2_bcp.tokenResponsesAllowed()`.
    fn token_responses_allowed(&self, reg: &ApplicationRegistry) -> bool;
    /// `helpers.offeredJwsAlgs(stsCrypto.JWS_ASYMMETRIC_ALGS)`.
    fn offered_asymmetric_jws_algs(&self) -> Vec<String>;
    /// The names a policy register lists (`authn_policy.named()`, or
    /// `list()` of `passkey`, `locale`, `password`, `post_login`).
    fn policy_names(&self, kind: &str) -> Vec<String>;
    /// `stsCrypto.xmlSignatureKeyProblem(der)`: '' for a usable key.
    fn xml_signature_key_problem(&self, der_base64: &str) -> String;
}

/// The answers before the slot is filled.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSources;

impl ValueSources for NoSources {
    fn check_claim_entries(&self, _: &str, _: &Value) -> Vec<String> {
        Vec::new()
    }

    fn check_claim_names(&self, _: bool, _: &Value) -> Vec<String> {
        Vec::new()
    }

    fn permission_claims_problem(&self, _: &str, _: &[String]) -> String {
        String::new()
    }

    fn token_responses_allowed(&self, reg: &ApplicationRegistry) -> bool {
        crate::js::truthy(
            &reg.env().setting("oauth2.allowImplicitTokenResponses"),
        )
    }

    fn offered_asymmetric_jws_algs(&self) -> Vec<String> {
        [
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
            "ES384", "ES512", "EdDSA",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn policy_names(&self, _: &str) -> Vec<String> {
        Vec::new()
    }

    fn xml_signature_key_problem(&self, der_base64: &str) -> String {
        sts_crypto::xmldsig::xml_signature_key_problem(
            der_base64,
            &sts_crypto::xmldsig::XmlPolicy::default(),
        )
        .unwrap_or_default()
    }
}

static SOURCES: LazyLock<RwLock<Arc<dyn ValueSources>>> =
    LazyLock::new(|| RwLock::new(Arc::new(NoSources)));

/// Fills the [`ValueSources`] slot (`None` empties it again).
#[tracing::instrument(level = "debug", skip_all)]
pub fn set_value_sources(sources: Option<Arc<dyn ValueSources>>) {
    if let Ok(mut held) = SOURCES.write() {
        *held = sources.unwrap_or_else(|| Arc::new(NoSources));
    }
}

fn sources() -> Arc<dyn ValueSources> {
    SOURCES
        .read()
        .map(|h| h.clone())
        .unwrap_or_else(|_| Arc::new(NoSources))
}

fn trimmed(value: &str) -> String {
    crate::js::trim(value).to_string()
}

fn matches(pattern: &str, text: &str) -> bool {
    Regex::new(pattern).is_ok_and(|r| r.is_match(text))
}

// ---------------------------------------------------------------------------
// DIDs.
// ---------------------------------------------------------------------------

/// `DID_PRIVATE_JWK_MEMBERS`.
pub const DID_PRIVATE_JWK_MEMBERS: &[&str] =
    &["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"];

/// `DID_SERVICE_TYPES`: the W3C DID Specification Registries' types.
pub const DID_SERVICE_TYPES: &[&str] = &[
    "LinkedDomains",
    "DIDCommMessaging",
    "LinkedVerifiablePresentation",
    "DecentralizedWebNode",
    "CredentialRegistry",
    "WotThing",
    "WotDirectory",
];

/// `DID_KEY_ALGS`: a key's shape to the algorithms it signs with.
pub const DID_KEY_ALGS: &[(&str, &[&str])] = &[
    ("EC P-256", &["ES256"]),
    ("EC P-384", &["ES384"]),
    ("EC P-521", &["ES512"]),
    ("EC secp256k1", &["ES256K"]),
    ("OKP Ed25519", &["EdDSA", "Ed25519"]),
    ("OKP Ed448", &["EdDSA", "Ed448"]),
    (
        "RSA",
        &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
    ),
];

/// `DID_AKP_ALGS`.
pub const DID_AKP_ALGS: &[&str] = &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

// `didUrlOf(text)`: an absolute http(s) URL with a host and no blank.
fn did_url_of(text: &str) -> Option<url::Url> {
    let url = url::Url::parse(text).ok()?;
    let scheme_ok = url.scheme() == "https" || url.scheme() == "http";
    let host = url.host_str().unwrap_or("");
    if scheme_ok && !host.is_empty() && !text.chars().any(char::is_whitespace) {
        Some(url)
    } else {
        None
    }
}

// `didLocalHost(url)`.
fn did_local_host(url: &url::Url) -> bool {
    matches!(
        url.host_str().unwrap_or(""),
        "localhost" | "127.0.0.1" | "[::1]"
    )
}

// `String(jwk[name] || '')`.
fn member_text(jwk: &Value, name: &str) -> String {
    crate::js::or_empty(jwk.get(name))
}

// The RSA modulus length in bits, read off `n` (Node's
// `asymmetricKeyDetails.modulusLength`).
fn rsa_bits(jwk: &Value) -> i64 {
    let n = jwk.get("n").and_then(Value::as_str).unwrap_or("");
    let Ok(bytes) = sts_crypto::b64::decode_loose(n) else {
        return 0;
    };
    let Some(at) = bytes.iter().position(|b| *b != 0) else {
        return 0;
    };
    ((bytes.len() - at) * 8) as i64 - i64::from(bytes[at].leading_zeros())
}

// `didKeyProblem(jwk)`.
fn did_key_problem(jwk: &Value) -> String {
    let kty = member_text(jwk, "kty");
    if !["EC", "OKP", "RSA", "AKP"].contains(&kty.as_str()) {
        return format!(
            "didPublicKeyJwk takes an EC, OKP, RSA or AKP key; this one's \
             kty is \"{}\".",
            kty
        );
    }
    let secret: Vec<&str> = DID_PRIVATE_JWK_MEMBERS
        .iter()
        .copied()
        .filter(|m| jwk.get(*m).is_some())
        .collect();
    if !secret.is_empty() {
        return format!(
            "didPublicKeyJwk takes the PUBLIC half of a key only, because \
             the DID document is published to anybody; this one carries {}.",
            secret.join(", ")
        );
    }
    if let Some(u) = jwk.get("use") {
        if u.as_str() != Some("sig") {
            return format!(
                "didPublicKeyJwk keys are listed for authentication and \
                 assertionMethod, so their use is \"sig\"; this one says \
                 \"{}\".",
                crate::js::string(u)
            );
        }
    }
    let alg = jwk.get("alg");
    let alg_text = alg
        .map(crate::js::string)
        .unwrap_or_else(|| "undefined".into());
    if kty == "AKP" {
        let pub_ok = jwk
            .get("pub")
            .and_then(Value::as_str)
            .is_some_and(|p| matches(r"^[A-Za-z0-9_-]+$", p));
        return if DID_AKP_ALGS.contains(&alg_text.as_str()) && pub_ok {
            String::new()
        } else {
            format!(
                "An AKP key in didPublicKeyJwk needs an alg of {} and a \
                 base64url pub.",
                DID_AKP_ALGS.join(", ")
            )
        };
    }
    let crv = jwk
        .get("crv")
        .map(crate::js::string)
        .unwrap_or_else(|| "undefined".into());
    if kty == "OKP" && crv != "Ed25519" && crv != "Ed448" {
        return format!(
            "An OKP key in didPublicKeyJwk must be Ed25519 or Ed448, a \
             signing curve; \"{}\" is not.",
            member_text(jwk, "crv")
        );
    }
    if sts_crypto::keys::JwsKey::from_jwk(jwk).is_err() {
        let crv_part = if jwk.get("crv").is_some_and(crate::js::truthy) {
            format!(" {}", crv)
        } else {
            String::new()
        };
        return format!(
            "didPublicKeyJwk could not read this key: its members do not \
             make a valid {}{} public key.",
            kty, crv_part
        );
    }
    if kty == "RSA" {
        let bits = rsa_bits(jwk);
        if bits < 2048 {
            return format!(
                "An RSA key in didPublicKeyJwk must be 2048 bits or more; \
                 this one is {}.",
                bits
            );
        }
    }
    let shape = if kty == "RSA" {
        "RSA".to_string()
    } else {
        format!("{} {}", kty, member_text(jwk, "crv"))
    };
    let Some((_, algs)) = DID_KEY_ALGS.iter().find(|(s, _)| *s == shape) else {
        return format!(
            "didPublicKeyJwk takes EC keys on P-256, P-384, P-521 or \
             secp256k1; \"{}\" is not one.",
            member_text(jwk, "crv")
        );
    };
    if alg.is_some() && !algs.contains(&alg_text.as_str()) {
        return format!(
            "This {} key cannot be used with alg \"{}\"; it takes {}.",
            shape,
            alg_text,
            algs.join(", ")
        );
    }
    String::new()
}

/// `didValueProblem(attribute, value)`: '' when the value is usable.
#[tracing::instrument(level = "debug", skip(reg))]
pub fn did_value_problem(
    reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
) -> String {
    let text = trimmed(value);
    if text.is_empty()
        || ![
            "didPublicKeyJwk",
            "didService",
            "didAlsoKnownAs",
            "didPrivateKeys",
        ]
        .contains(&attribute)
    {
        return String::new();
    }
    if attribute == "didPrivateKeys" {
        let keys = if reg.env().is_sealed(&text) {
            Some(Value::Array(Vec::new()))
        } else {
            serde_json::from_str::<Value>(&text).ok()
        };
        let ok = keys.as_ref().and_then(Value::as_array).is_some_and(|l| {
            l.iter().all(|one| {
                one.is_object()
                    && one.get("d").is_some_and(Value::is_string)
                    && one.get("kty").is_some_and(|k| {
                        let k = crate::js::string(k);
                        k == "EC" || k == "OKP"
                    })
            })
        });
        return if ok {
            String::new()
        } else {
            "didPrivateKeys holds a JSON array of private EC or OKP JWKs, \
             written by Generate a key pair."
                .to_string()
        };
    }
    if attribute == "didPublicKeyJwk" {
        return match serde_json::from_str::<Value>(&text) {
            Ok(jwk @ Value::Object(_)) => did_key_problem(&jwk),
            _ => "didPublicKeyJwk takes one JWK as a JSON object per value, \
                  such as {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"…\",\
                  \"y\":\"…\"}."
                .to_string(),
        };
    }
    if attribute == "didService" {
        let (ty, endpoint) = match text.find('|') {
            Some(bar) if bar > 0 => {
                (trimmed(&text[..bar]), trimmed(&text[bar + 1..]))
            }
            _ => (String::new(), String::new()),
        };
        let form = "didService takes <type>|<serviceEndpoint>, such as \
                    LinkedDomains|https://app.example.com";
        if ty.is_empty() || endpoint.is_empty() {
            return format!("{}; \"{}\" is not.", form, text);
        }
        let registered = DID_SERVICE_TYPES.contains(&ty.as_str());
        if !registered && !matches(r"^[A-Za-z][A-Za-z0-9+.-]*:\S+$", &ty) {
            let lower = ty.to_lowercase();
            let near: Vec<&str> = DID_SERVICE_TYPES
                .iter()
                .copied()
                .filter(|one| {
                    let o = one.to_lowercase();
                    o == lower || o.contains(&lower) || lower.contains(&o)
                })
                .collect();
            return format!(
                "The service type \"{}\" is not one the W3C DID \
                 Specification Registries define ({}); a type of your own \
                 must be an absolute URI.{}",
                ty,
                DID_SERVICE_TYPES.join(", "),
                if near.is_empty() {
                    String::new()
                } else {
                    format!(" Did you mean {}?", near.join(" or "))
                }
            );
        }
        let Some(url) = did_url_of(&endpoint) else {
            return format!(
                "{}; the endpoint \"{}\" is not an absolute http or https \
                 URL.",
                form, endpoint
            );
        };
        if url.scheme() != "https" && !did_local_host(&url) {
            return format!(
                "A service endpoint must be https, except on localhost; \
                 \"{}\" is not.",
                endpoint
            );
        }
        if !url.username().is_empty() || url.password().is_some() {
            return format!(
                "A service endpoint may not carry a user name or password; \
                 \"{}\" does.",
                endpoint
            );
        }
        let search = url.query().is_some_and(|q| !q.is_empty());
        let hash = url.fragment().is_some_and(|f| !f.is_empty());
        if ty == "LinkedDomains" && (url.path() != "/" || search || hash) {
            return format!(
                "A LinkedDomains endpoint is an origin — scheme, host and \
                 port, with no path — such as https://app.example.com; \
                 \"{}\" is not.",
                endpoint
            );
        }
        return String::new();
    }
    let as_url = if matches(r"(?i)^https?:", &text) {
        did_url_of(&text)
    } else {
        None
    };
    let ok = as_url.is_some()
        || matches(r"(?i)^urn:[A-Za-z0-9][A-Za-z0-9-]{0,31}:\S+$", &text)
        || matches(r"^did:[a-z0-9]+:[A-Za-z0-9._:%-]*[A-Za-z0-9._-]$", &text);
    if !ok {
        return format!(
            "didAlsoKnownAs takes an absolute https URL, a URN or a DID, \
             such as https://app.example.com; \"{}\" is not.",
            text
        );
    }
    String::new()
}

// `canonicalJwk(jwk)`: RFC 7638's members, or None where Node throws.
fn canonical_jwk(jwk: &Value) -> Option<String> {
    let kty = jwk.get("kty").filter(|k| crate::js::truthy(k))?;
    let members: &[&str] = match crate::js::string(kty).as_str() {
        "AKP" => &["alg", "kty", "pub"],
        "EC" => &["crv", "kty", "x", "y"],
        "RSA" => &["e", "kty", "n"],
        "OKP" => &["crv", "kty", "x"],
        "oct" => &["k", "kty"],
        _ => return None,
    };
    let mut parts = Vec::new();
    for m in members {
        match jwk.get(*m) {
            None | Some(Value::Null) => return None,
            Some(Value::String(s)) if s.is_empty() => return None,
            Some(v) => parts.push(format!(
                "{}:{}",
                serde_json::to_string(m).ok()?,
                serde_json::to_string(v).ok()?
            )),
        }
    }
    Some(format!("{{{}}}", parts.join(",")))
}

/// `didSameness(attribute, value)`: what two values are compared by.
#[tracing::instrument(level = "debug")]
pub fn did_sameness(attribute: &str, value: &str) -> String {
    let text = trimmed(value);
    if attribute == "didPublicKeyJwk" {
        return serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|jwk| canonical_jwk(&jwk))
            .map(|c| format!("jkt:{}", c))
            .unwrap_or(text);
    }
    text.to_lowercase()
}

/// `didDuplicateProblem(attribute, value, existing)`.
#[tracing::instrument(level = "debug", skip(existing))]
pub fn did_duplicate_problem(
    attribute: &str,
    value: &str,
    existing: &[String],
) -> String {
    if !["didPublicKeyJwk", "didService", "didAlsoKnownAs"].contains(&attribute)
    {
        return String::new();
    }
    let mine = did_sameness(attribute, value);
    if existing
        .iter()
        .any(|one| did_sameness(attribute, one) == mine)
    {
        format!(
            "{} already holds {}; each value appears once.",
            attribute,
            if attribute == "didPublicKeyJwk" {
                "this key".to_string()
            } else {
                format!("\"{}\"", trimmed(value))
            }
        )
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Claims.
// ---------------------------------------------------------------------------

/// `CLAIM_ROW_SETS`: an attribute of claim rows to the set it is checked
/// as.
pub const CLAIM_ROW_SETS: &[(&str, &str)] = &[
    ("oauthClaimsAccessToken", "access_token"),
    ("oauthClaimsIdToken", "id_token"),
    ("oauthClaimsUserinfo", "userinfo"),
    ("saml2CustomAttributes", "saml2"),
    ("saml11CustomAttributes", "saml11"),
    ("krb5ClaimsPac", "kerberos-pac"),
    ("gnapClaimsAccessToken", "gnap_access_token"),
];

/// `CLAIM_SELECTION_ATTRIBUTES`.
pub const CLAIM_SELECTION_ATTRIBUTES: &[&str] = &[
    "oauthClaimAttributesAccessToken",
    "oauthClaimAttributesIdToken",
    "oauthClaimAttributesUserinfo",
    "saml2ClaimAttributes",
    "saml11ClaimAttributes",
    "vcCredentialClaimAttributes",
];

/// `claimRowsProblem(attribute, value)`.
#[tracing::instrument(level = "debug")]
pub fn claim_rows_problem(attribute: &str, value: &str) -> String {
    let Some((_, set_id)) =
        CLAIM_ROW_SETS.iter().find(|(a, _)| *a == attribute)
    else {
        return String::new();
    };
    let text = trimmed(value);
    if text.is_empty() {
        return String::new();
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(rows @ Value::Array(_)) => {
            sources().check_claim_entries(set_id, &rows).join(" ")
        }
        _ => format!("{} holds a JSON array of claim rows.", attribute),
    }
}

/// `claimSelectionProblem(attribute, value)`.
#[tracing::instrument(level = "debug")]
pub fn claim_selection_problem(attribute: &str, value: &str) -> String {
    let text = trimmed(value);
    if !CLAIM_SELECTION_ATTRIBUTES.contains(&attribute) || text.is_empty() {
        return String::new();
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(names @ Value::Array(_)) => sources()
            .check_claim_names(
                attribute == "vcCredentialClaimAttributes",
                &names,
            )
            .join(" "),
        _ => format!("{} holds a JSON array of attribute names.", attribute),
    }
}

/// `permissionClaimsProblem(value, record)`, `fields` the record's.
#[tracing::instrument(level = "debug", skip(fields))]
pub fn permission_claims_problem(value: &str, fields: &Fields) -> String {
    let mut source = serde_json::Map::new();
    source.insert("fields".into(), Value::Object(fields.clone()));
    let exposed: Vec<String> =
        crate::app_permissions::permissions_of(&Value::Object(source))
            .iter()
            .map(|one| crate::js::or_empty(one.get("name")))
            .collect();
    sources().permission_claims_problem(value, &exposed)
}

// ---------------------------------------------------------------------------
// The closed choices.
// ---------------------------------------------------------------------------

/// `BOOLEAN_ATTRIBUTES`.
pub const BOOLEAN_ATTRIBUTES: &[&str] = &[
    "scimClientEnabled",
    "oauthFrontchannelLogoutSessionRequired",
    "oauthBackchannelLogoutSessionRequired",
    "oauthNativeSso",
    "oauthBackchannelUserCodeParameter",
    "oauthRequireSignedRequestObject",
    "oauthRequirePushedAuthorizationRequests",
    "oauthHttpSignedRequests",
    "oauthTlsClientCertificateBoundAccessTokens",
    "saml2EncryptAssertion",
    "saml2EncryptLogoutNameId",
    "oauthRevokeRefreshOnLogout",
    "appNotDelegated",
    "appGroupsClaim",
    "oauthDidClaimWithPairwise",
    "krb5TrustedForDelegation",
    "saml2SignAssertion",
    "saml2SignResponse",
    "saml11SignAssertion",
    "saml11SignResponse",
    "gnapBearerTokens",
    "gnapSkipInteraction",
    "gnapScopedSignals",
    "appFederationAutoRedirect",
    "ssfCaepIncludeReasons",
    "ssfCaepOmitEventTimestamp",
    "ssfRiscIncludeReasons",
    "ssfRiscOmitEventTimestamp",
    "saml2IdpInitiatedSso",
    "saml2SpInitiatedSso",
    "saml11IdpInitiatedSso",
    "saml11SpInitiatedSso",
    "wsfedIdpInitiatedSso",
    "wsfedSpInitiatedSso",
    "oauthThirdPartyInitiatedLogin",
    "oauthSpInitiatedSso",
    "saml2SsoConsent",
    "saml11SsoConsent",
    "wsfedSsoConsent",
    "umaOwnsResources",
];

/// `DELEGATION_SEMANTICS`.
pub const DELEGATION_SEMANTICS: &[&str] = &["delegation", "impersonation"];

/// `LAUNCH_PROTOCOLS`.
pub const LAUNCH_PROTOCOLS: &[&str] = &["saml2", "saml11", "wsfed", "oidc"];

/// `FLOW_RESPONSE_TYPES`.
pub const FLOW_RESPONSE_TYPES: &[&str] = &[
    "code",
    "token",
    "id_token",
    "code token",
    "code id_token",
    "id_token token",
    "code id_token token",
    "none",
];

/// `TOKEN_RESPONSE_TYPES`: the response types that issue an access token
/// from the authorization endpoint.
pub const TOKEN_RESPONSE_TYPES: &[&str] = &[
    "token",
    "code token",
    "id_token token",
    "code id_token token",
];

/// `FLOW_GRANT_TYPES`.
pub const FLOW_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "implicit",
    "refresh_token",
    "client_credentials",
    "password",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:ietf:params:oauth:grant-type:saml2-bearer",
    "urn:openid:params:grant-type:ciba",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:uma-ticket",
];

/// `client_auth.METHODS`: every client authentication method.
pub const CLIENT_AUTH_METHODS: &[&str] = &[
    "none",
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "saml2_bearer",
    "tls_client_auth",
    "self_signed_tls_client_auth",
    "attest_jwt_client_auth",
    "attest_jwt_client_auth_dpop",
];

/// `enrollment_profiles.PROFILE_IDS`.
pub const ENROLLMENT_PROFILE_IDS: &[&str] = &[
    "tls-server",
    "tls-client",
    "tls-server-client",
    "digital-signature",
    "key-encipherment",
    "code-signing",
    "email",
    "timestamping",
    "smartcard-logon",
];

/// `POLICY_REFERENCES`: the attributes naming a named policy.
pub const POLICY_REFERENCES: &[&str] = &[
    "appAuthnPolicy",
    "appPasskeyPolicy",
    "appLocalePolicy",
    "appPasswordPolicy",
    "appPostLoginPolicy",
];

/// `CHOICES_CHECKED_HERE`: the attributes whose value must be one of
/// their choices.
pub const CHOICES_CHECKED_HERE: &[&str] = &[
    "oauthTokenEndpointAuthMethod",
    "oauthBackchannelTokenDeliveryMode",
    "oauthBackchannelAuthenticationRequestSigningAlg",
    "gnapKeyProof",
    "gnapSymmetricAlg",
    "gnapInteractionStartModes",
    "gnapAccessTokenFormat",
    "acmeAllowedProfiles",
    "acmeDefaultProfile",
    "estAllowedProfiles",
    "estDefaultProfile",
    "scepAllowedProfiles",
    "scepDefaultProfile",
    "secretDestProvider",
    "secretDestPayload",
    "appAuthnPolicy",
    "appPasskeyPolicy",
    "appLocalePolicy",
    "appPasswordPolicy",
    "appPostLoginPolicy",
    "scimClientAuthMethod",
    "scimClientOAuthClientAuth",
    "scimClientTlsSource",
    "scimClientScopeMode",
    "scimClientGroupMode",
    "scimClientDeprovision",
    "oauthClaimsCombineAccessToken",
    "oauthClaimsCombineIdToken",
    "oauthClaimsCombineUserinfo",
    "saml2ClaimsCombine",
    "saml11ClaimsCombine",
    "oauthAccessTokenClaim",
    "oauthAccessTokenClaimsCombine",
    "appLaunchProtocol",
    "oauthGrantType",
    "oauthResponseType",
    "oauthAllowedTokenResponseTypes",
    "krb5ForeignTgtDelegation",
];

/// `scope_claims.DECLARABLE_CLAIMS`: OIDC Core section 5.4's claims.
pub const DECLARABLE_CLAIMS: &[&str] = &[
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
    "email",
    "email_verified",
    "address",
    "phone_number",
    "phone_number_verified",
];

fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// `settingValues(key)`: a setting's enum (or csv) values, the empty one
/// dropped.
#[tracing::instrument(level = "debug")]
pub fn setting_values(key: &str) -> Vec<String> {
    let Some(row) = sts_core::settings::row(key) else {
        return Vec::new();
    };
    let list: &[&str] = if !row.enum_values.is_empty() {
        row.enum_values
    } else {
        row.csv_values.unwrap_or(&[])
    };
    list.iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

// `['default'].concat(<policy register>.list() names, 'default' dropped)`;
// the authentication policy's `named()` is not filtered.
fn policy_choices(kind: &str) -> Vec<String> {
    let mut out = vec!["default".to_string()];
    out.extend(
        sources()
            .policy_names(kind)
            .into_iter()
            .filter(|n| kind == "authn" || n != "default"),
    );
    out
}

/// `attributeChoices(attribute)`: what an attribute may hold, or None for
/// an attribute with no closed list here.
#[tracing::instrument(level = "debug")]
pub fn attribute_choices(attribute: &str) -> Option<Vec<String>> {
    let realm_modes =
        || owned(&["application", "union", "intersection", "realm"]);
    let profiles = |device: bool| {
        let mut ids = owned(ENROLLMENT_PROFILE_IDS);
        if device {
            ids.push("device".into());
        }
        ids
    };
    Some(match attribute {
        "oauthGrantType" => owned(FLOW_GRANT_TYPES),
        "oauthResponseType" => owned(FLOW_RESPONSE_TYPES),
        "oauthAllowedTokenResponseTypes" => owned(TOKEN_RESPONSE_TYPES),
        "appLaunchProtocol" => owned(LAUNCH_PROTOCOLS),
        "appDelegationSemantics" | "appDefaultDelegationSemantics" => {
            owned(DELEGATION_SEMANTICS)
        }
        "krb5ForeignTgtDelegation" => owned(&["inherit", "deny"]),
        "oauthTokenEndpointAuthMethod" => owned(CLIENT_AUTH_METHODS),
        "oauthBackchannelTokenDeliveryMode" => owned(&["poll", "ping", "push"]),
        "oauthBackchannelAuthenticationRequestSigningAlg" => {
            sources().offered_asymmetric_jws_algs()
        }
        "oauthSubjectType" => owned(&["public", "pairwise", "ephemeral"]),
        "gnapKeyProof" => owned(&["httpsig", "jwsd", "jws"]),
        "gnapSymmetricAlg" => {
            owned(&["HS256", "HS384", "HS512", "hmac-sha256"])
        }
        "gnapInteractionStartModes" => {
            setting_values("gnap.interactionStartModes")
        }
        "gnapAccessTokenFormat" => setting_values("gnap.accessTokenFormat"),
        "appAuthnPolicy" => policy_choices("authn"),
        "appPasskeyPolicy" => policy_choices("passkey"),
        "appLocalePolicy" => policy_choices("locale"),
        "appPasswordPolicy" => policy_choices("password"),
        "appPostLoginPolicy" => policy_choices("post_login"),
        "acmeAllowedProfiles" | "acmeDefaultProfile" => profiles(false),
        "estAllowedProfiles"
        | "estDefaultProfile"
        | "scepAllowedProfiles"
        | "scepDefaultProfile" => profiles(true),
        "secretDestProvider" => {
            owned(&["aws", "gcp", "azure", "vault", "file"])
        }
        "secretDestPayload" => owned(&["password", "json"]),
        "scimClientAuthMethod" => owned(&["basic", "oauth2", "none"]),
        "scimClientOAuthClientAuth" => {
            owned(&["client_secret_basic", "client_secret_post"])
        }
        "scimClientTlsSource" => owned(&["none", "issued", "uploaded"]),
        "scimClientScopeMode" => owned(&["all", "groups", "filter"]),
        "scimClientGroupMode" => {
            owned(&["none", "selected", "member-groups", "all"])
        }
        "scimClientDeprovision" => owned(&["deactivate", "delete"]),
        "oauthClaimsCombineAccessToken"
        | "oauthClaimsCombineIdToken"
        | "oauthClaimsCombineUserinfo"
        | "saml2ClaimsCombine"
        | "saml11ClaimsCombine" => realm_modes(),
        "oauthAccessTokenClaim" => owned(DECLARABLE_CLAIMS),
        "oauthAccessTokenClaimsCombine" => {
            owned(&["union", "intersection", "client", "resource"])
        }
        // The remaining ATTRIBUTE_CHOICES rows (the JOSE algorithm lists,
        // gnapMtlsTrust) are drawn by the console; none is in
        // CHOICES_CHECKED_HERE, so no write is decided by them here.
        _ => return None,
    })
}

/// `choiceProblem(attribute, value)`: '' for a value the attribute takes.
#[tracing::instrument(level = "debug")]
pub fn choice_problem(attribute: &str, value: &str) -> String {
    let text = trimmed(value);
    if !CHOICES_CHECKED_HERE.contains(&attribute) || text.is_empty() {
        return String::new();
    }
    match attribute_choices(attribute) {
        Some(choices) if !choices.contains(&text) => format!(
            "\"{}\" is not a value {} takes. It is one of {}.",
            text,
            attribute,
            choices.join(", ")
        ),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Response types and authentication methods.
// ---------------------------------------------------------------------------

/// `canonicalResponseType(value)`: the words sorted, one space apart.
#[tracing::instrument(level = "debug")]
pub fn canonical_response_type(value: &str) -> String {
    let mut words: Vec<&str> = value
        .split(crate::js::is_space)
        .filter(|w| !w.is_empty())
        .collect();
    words.sort();
    words.join(" ")
}

/// `tokenResponseTypesProblem(values)`.
#[tracing::instrument(level = "debug", skip(reg))]
pub fn token_response_types_problem(
    reg: &ApplicationRegistry,
    values: &[String],
) -> String {
    let asked: Vec<String> = values
        .iter()
        .map(|one| trimmed(one))
        .filter(|one| !one.is_empty())
        .collect();
    if asked.is_empty() || sources().token_responses_allowed(reg) {
        return String::new();
    }
    format!(
        "oauthAllowedTokenResponseTypes cannot list {}: this realm does not \
         allow the response types that issue an access token from the \
         authorization endpoint (RFC 9700 section 2.1.2). An administrator \
         allows them with oauth2.allowImplicitTokenResponses, which OAuth \
         2.1 mode and the FAPI profiles override.",
        asked.join(", ")
    )
}

/// `authMethodList(value)`: the methods, trimmed, once each.
#[tracing::instrument(level = "debug")]
pub fn auth_method_list(value: Option<&Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for one in values_of(value) {
        let m = trimmed(&one);
        if !m.is_empty() && !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

/// `credentialAuthMethod(fields)`: what a client created with these
/// credentials authenticates with.
#[tracing::instrument(level = "debug", skip_all)]
pub fn credential_auth_method(fields: &Fields) -> String {
    let present = |name: &str| {
        values_of(fields.get(name))
            .iter()
            .any(|one| !trimmed(one).is_empty())
    };
    if present("oauthClientSecret") {
        "client_secret_basic".into()
    } else if present("oauthJwks") || present("oauthJwksUri") {
        "private_key_jwt".into()
    } else {
        "none".into()
    }
}

/// `previewAuthMethods(protocols, fields)`.
#[tracing::instrument(level = "debug", skip(fields))]
pub fn preview_auth_methods(
    protocols: &[String],
    fields: &Fields,
) -> Vec<String> {
    let declared = auth_method_list(fields.get("oauthTokenEndpointAuthMethod"));
    if !declared.is_empty() {
        return declared;
    }
    if protocols.iter().any(|p| p == "oauth2" || p == "oidc") {
        return vec![credential_auth_method(fields)];
    }
    Vec::new()
}

/// `authMethodsProblem(values)`: `none` held with another method.
#[tracing::instrument(level = "debug")]
pub fn auth_methods_problem(values: Option<&Value>) -> String {
    let methods = auth_method_list(values);
    if !methods.iter().any(|m| m == "none") || methods.len() < 2 {
        return String::new();
    }
    let others: Vec<&str> = methods
        .iter()
        .filter(|m| *m != "none")
        .map(String::as_str)
        .collect();
    format!(
        "oauthTokenEndpointAuthMethod \"none\" declares a PUBLIC client, one \
         with no credential, so it cannot be held with {}. Choose \"none\" \
         alone, or the methods the client authenticates with.",
        others.join(", ")
    )
}

// ---------------------------------------------------------------------------
// oauthConfidential.
// ---------------------------------------------------------------------------

/// `statedConfidential(value)`: 'TRUE', 'FALSE' or '' for neither.
#[tracing::instrument(level = "debug")]
pub fn stated_confidential(value: &str) -> String {
    let text = trimmed(value).to_uppercase();
    if text == "TRUE" || text == "FALSE" {
        text
    } else {
        String::new()
    }
}

/// `oauthConfidentialOf(record)`, over a record's `registered` and fields.
#[tracing::instrument(level = "debug", skip(fields))]
pub fn oauth_confidential_of(registered: bool, fields: &Fields) -> String {
    let methods = auth_method_list(fields.get("oauthTokenEndpointAuthMethod"));
    let method = match methods.first() {
        Some(m) => m.clone(),
        None if registered => "client_secret_basic".into(),
        None => String::new(),
    };
    if !method.is_empty() && method != "none" {
        "TRUE".into()
    } else {
        "FALSE".into()
    }
}

/// `confidentialDisagreement(raw, determination)`: '' when they agree.
#[tracing::instrument(level = "debug")]
pub fn confidential_disagreement(raw: &str, determination: &str) -> String {
    let text = trimmed(raw);
    if text.is_empty() {
        return String::new();
    }
    let stated = stated_confidential(&text);
    if stated.is_empty() {
        return format!(
            "oauthConfidential is TRUE or FALSE, and \"{}\" is neither. The \
             registry writes it from oauthTokenEndpointAuthMethod: none, or \
             no method on an application created by hand, is FALSE, and any \
             other method is TRUE.",
            text
        );
    }
    if stated == determination {
        return String::new();
    }
    format!(
        "oauthConfidential {} does not match the token endpoint \
         authentication method, which makes this client {}. none, or no \
         method on an application created by hand, is FALSE, and any other \
         method is TRUE. Change oauthTokenEndpointAuthMethod to change it.",
        stated, determination
    )
}

/// `confidentialClearSentence()`.
#[tracing::instrument(level = "debug")]
pub fn confidential_clear_sentence() -> String {
    "oauthConfidential cannot be cleared. It is written from \
     oauthTokenEndpointAuthMethod: none, or no method on an application \
     created by hand, is FALSE, and any other method is TRUE. Change the \
     method to change it."
        .to_string()
}

/// `confidentialModeSentence()`.
#[tracing::instrument(level = "debug")]
pub fn confidential_mode_sentence() -> String {
    "oauthConfidential is written as a whole from \
     oauthTokenEndpointAuthMethod, so it is not added to or removed from. \
     Change the method to change it."
        .to_string()
}

/// `carriesOauthClient(record)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn carries_oauth_client(record: &Record) -> bool {
    let fields = &record.fields;
    let families: Vec<String> = values_of(fields.get("appAllowedProtocol"))
        .iter()
        .map(|one| trimmed(one))
        .collect();
    families
        .iter()
        .any(|f| f == "oauth2" || f == "oidc" || f == "oid4vci")
        || record.registered
        || !auth_method_list(fields.get("oauthTokenEndpointAuthMethod"))
            .is_empty()
        || fields.contains_key("oauthConfidential")
}

/// `recordOauthConfidential(record, {supplied})`: the flag written where
/// the record carries an OAuth client (or one was supplied); whether it
/// changed.
#[tracing::instrument(level = "debug", skip(record))]
pub fn record_oauth_confidential(
    record: &mut Record,
    supplied: Option<bool>,
) -> bool {
    if !carries_oauth_client(record) && supplied != Some(true) {
        return false;
    }
    let flag = oauth_confidential_of(record.registered, &record.fields);
    // setField(record, 'oauthConfidential', flag): a single-valued row.
    if record
        .fields
        .get("oauthConfidential")
        .and_then(Value::as_str)
        == Some(flag.as_str())
    {
        return false;
    }
    record
        .fields
        .insert("oauthConfidential".into(), Value::String(flag));
    true
}

// ---------------------------------------------------------------------------
// The setting overrides.
// ---------------------------------------------------------------------------

/// `overrideModeProblem(attribute, value)`: a value the realm's mode
/// ignores for the setting the attribute overrides.
#[tracing::instrument(level = "debug", skip(reg))]
pub fn override_mode_problem(
    reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
) -> String {
    let key = crate::applications::Tables::get()
        .attribute(attribute)
        .map(|r| r.overrides.clone())
        .unwrap_or_default();
    if key.is_empty() || value.is_empty() {
        return String::new();
    }
    let env = reg.env();
    match env.parse_as(&key, value) {
        Ok(parsed) if !env.allows_value(&key, &parsed) => format!(
            "\"{}\" cannot be set to {} here: it overrides {}, and this \
             realm is in product mode (global.mode=product), where that \
             value is ignored — {}",
            attribute,
            value,
            key,
            env.write_refusal_reason(&key)
        ),
        _ => String::new(),
    }
}

/// `strictOverrideProblem(attribute, value)`: a strict override's value
/// that its setting would refuse.
#[tracing::instrument(level = "debug", skip(reg))]
pub fn strict_override_problem(
    reg: &ApplicationRegistry,
    attribute: &str,
    value: &str,
) -> String {
    let Some(row) = crate::applications::Tables::get().attribute(attribute)
    else {
        return String::new();
    };
    let text = trimmed(value);
    if !row.strict_override || row.overrides.is_empty() || text.is_empty() {
        return String::new();
    }
    match reg.env().parse_as(&row.overrides, &text) {
        Err(problem) => format!(
            "\"{}\" overrides {} and cannot hold \"{}\": {}",
            attribute, row.overrides, value, problem
        ),
        Ok(parsed) => {
            if row.overrides.ends_with(".reasonLanguage")
                && !matches(
                    r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$",
                    &crate::js::string(&parsed),
                )
            {
                format!(
                    "\"{}\" must be a BCP 47 language tag such as en or \
                     fr-CA; \"{}\" is not one.",
                    attribute, value
                )
            } else {
                String::new()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SAML certificates.
// ---------------------------------------------------------------------------

/// `samlCertificateBase64(value)`: PEM armour and blanks removed.
#[tracing::instrument(level = "debug", skip(value))]
pub fn saml_certificate_base64(value: &str) -> String {
    let armour = Regex::new(r"-----[^-]+-----").ok();
    let unarmoured = match &armour {
        Some(r) => r.replace_all(value, "").into_owned(),
        None => value.to_string(),
    };
    unarmoured
        .chars()
        .filter(|c| !crate::js::is_space(*c))
        .collect()
}

/// `samlCertificateProblem(value)`: '' for a certificate whose key makes
/// an XML signature this service verifies.
#[tracing::instrument(level = "debug", skip(reg, value))]
pub fn saml_certificate_problem(
    reg: &ApplicationRegistry,
    value: &str,
) -> String {
    let der = saml_certificate_base64(value);
    if der.is_empty() {
        return "it is empty".into();
    }
    if !matches(r"^[A-Za-z0-9+/]+=*$", &der) {
        return "it is not base64".into();
    }
    let problem = sources().xml_signature_key_problem(&der);
    if !problem.is_empty() {
        return problem;
    }
    let bytes = sts_crypto::b64::decode_loose(&der).unwrap_or_default();
    match reg
        .effects
        .certificate_registration_problem("saml-signer", &bytes)
    {
        Some((why, _)) => why,
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// The hosted surfaces' own session bounds.
// ---------------------------------------------------------------------------

/// `HOSTED_SESSION_CLIENTS`.
pub const HOSTED_SESSION_CLIENTS: &[&str] =
    &["sts-admin-console", "sts-user-portal", "sts-report"];

/// `HOSTED_SESSION_BOUNDS`: each hosted client's shipped bounds.
pub const HOSTED_SESSION_BOUNDS: &[(&str, &[(&str, &str)])] = &[
    (
        "sts-admin-console",
        &[
            ("oauthMaxAuthAgeS", "3600"),
            ("oauthRefreshTokenTtlS", "3600"),
            ("oauthRefreshIdleSeconds", "900"),
        ],
    ),
    (
        "sts-user-portal",
        &[
            ("oauthMaxAuthAgeS", "28800"),
            ("oauthRefreshTokenTtlS", "28800"),
            ("oauthRefreshIdleSeconds", "3600"),
        ],
    ),
    (
        "sts-report",
        &[
            ("oauthMaxAuthAgeS", "3600"),
            ("oauthRefreshTokenTtlS", "3600"),
            ("oauthRefreshIdleSeconds", "900"),
        ],
    ),
];

/// `HOSTED_BOUND_ATTRIBUTES`: a bound attribute to the setting it bounds.
pub const HOSTED_BOUND_ATTRIBUTES: &[(&str, &str)] = &[
    ("oauthMaxAuthAgeS", "oauth2.maxAuthAgeS"),
    ("oauthRefreshTokenTtlS", "oauth2.refreshTokenTtlS"),
    ("oauthRefreshIdleSeconds", "oauth2.refreshIdleSeconds"),
];

/// `HOSTED_REALM_CAP`: the realm setting that caps each bound.
pub const HOSTED_REALM_CAP: &[(&str, &str)] = &[
    ("oauth2.maxAuthAgeS", "authn.sessionLifetimeS"),
    ("oauth2.refreshTokenTtlS", "oauth2.refreshTokenTtlS"),
    ("oauth2.refreshIdleSeconds", "oauth2.refreshIdleSeconds"),
];

/// `isHostedSessionClient(identifier)`.
#[tracing::instrument(level = "debug")]
pub fn is_hosted_session_client(identifier: &str) -> bool {
    HOSTED_SESSION_CLIENTS.contains(&identifier)
}

/// `hostedBoundAttribute(name)`.
#[tracing::instrument(level = "debug")]
pub fn hosted_bound_attribute(name: &str) -> bool {
    HOSTED_BOUND_ATTRIBUTES.iter().any(|(a, _)| *a == name)
}

// `Number(value)` of a JSON value, NaN where JavaScript's is.
fn js_number(value: &Value) -> f64 {
    match value {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Null => 0.0,
        Value::String(s) => {
            let t = crate::js::trim(s);
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Value::Array(_) | Value::Object(_) => {
            js_number(&Value::String(crate::js::string(value)))
        }
    }
}

/// `positiveLimit(value)`: a finite number above zero, or None.
#[tracing::instrument(level = "debug")]
pub fn positive_limit(value: &Value) -> Option<f64> {
    let n = js_number(value);
    if n.is_finite() && n > 0.0 {
        Some(n)
    } else {
        None
    }
}

/// `shorterLimit(left, right)`: the shorter of two positive limits, the
/// one given, or 0.
#[tracing::instrument(level = "debug")]
pub fn shorter_limit(left: &Value, right: &Value) -> f64 {
    match (positive_limit(left), positive_limit(right)) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => 0.0,
    }
}

/// `confirmAsked(value)`: `true`, or 'true', 'on' or '1'.
#[tracing::instrument(level = "debug")]
pub fn confirm_asked(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(true)) => true,
        None | Some(Value::Null) => false,
        Some(v) => {
            matches!(crate::js::string(v).as_str(), "true" | "on" | "1")
        }
    }
}

/// `hostedSessionBoundRefusal(identifier, attribute, value, confirm)`:
/// a hosted surface's own session bound cleared, zeroed, or changed
/// without `confirm`.
#[tracing::instrument(level = "debug", skip(reg))]
pub fn hosted_session_bound_refusal(
    reg: &ApplicationRegistry,
    identifier: &str,
    attribute: &str,
    value: &str,
    confirm: Option<&Value>,
) -> Option<Coded> {
    if !is_hosted_session_client(identifier)
        || !hosted_bound_attribute(attribute)
    {
        return None;
    }
    let key = HOSTED_BOUND_ATTRIBUTES
        .iter()
        .find(|(a, _)| *a == attribute)
        .map(|(_, k)| *k)
        .unwrap_or("");
    let text = trimmed(value);
    let parsed = if text.is_empty() {
        None
    } else {
        reg.env().parse_as(key, &text).ok()
    };
    if text.is_empty() || parsed.as_ref().and_then(positive_limit).is_none() {
        return Some(Coded::new(
            codes::STS_REG_0369,
            format!(
                "\"{}\" is this application's own session bound. It cannot \
                 be cleared, and 0 is refused: either would let a longer \
                 realm setting lengthen the admin console, the user portal \
                 or the reports application. Store a positive number of \
                 seconds.",
                attribute
            ),
        ));
    }
    if !confirm_asked(confirm) {
        return Some(Coded::new(
            codes::STS_REG_0368,
            format!(
                "\"{}\" is this application's own session bound. Changing \
                 it needs confirm set to true, so a save that did not mean \
                 to change the bound is refused and nothing is written.",
                attribute
            ),
        ));
    }
    None
}
