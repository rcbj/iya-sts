// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 8414 discovery (`oauth2.ts`'s `asMetadata()` and
//! `sendAsMetadata()`): `/.well-known/oauth-authorization-server`, member
//! for member and in Node's order, and the OAuth members of
//! `/.well-known/openid-configuration`.
//!
//! * **What the document says is what the endpoints do**: the authorization
//!   endpoint reads its response types, modes and PKCE methods from here
//!   (`capabilityFor()`), and RFC 9700 mode — which product implies —
//!   narrows them as `oauth2_bcp.applyToMetadata()` does: no `token`
//!   response type, no `password` grant, S256 alone.
//! * **The algorithm lists** are Node's tables (`stsCrypto.JWS_SIGNING_ALGS`,
//!   `jarm`'s, the introspection and request-object lists, DPoP's), held
//!   here as constants with Node's development values, narrowed as
//!   `helpers.narrowSigningAlgs()` and the JWE helpers narrow them under
//!   the default signature policy: product leaves out ES256K
//!   (`mode.omitsUnapprovedSigningCurves()`), RSA-OAEP (SHA-1) and the
//!   CBC-HMAC encryptions (`mode.allowsCbcJwe()`); `keys.postQuantumSigning`
//!   off leaves this service's own post-quantum signing algorithms out.
//!   A realm's own sign and accept lists (#1368's `keys.signingAlgorithms`
//!   and its kin) are the signature-policy port's, not read here yet.
//! * **`signed_metadata`** (RFC 8414 section 2.1): the document and `sub`,
//!   signed for an hour under the realm's key (`signPublishedDocument()`).
//!
//! [`oidc_metadata`] is `/.well-known/openid-configuration`'s document; a
//! named authorization server's profile is applied by the caller
//! ([`crate::authorization_servers`]).
//!
//! WHAT IS NOT HERE: a named server's FAPI profile, FAPI's own
//! narrowing, client attestation's methods, the device authorization and
//! CIBA grants and their endpoints, UMA's grant — each answered as Node
//! answers with it switched off, which is its default.

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::settings::{SettingValue, Settings};

const AUTHORIZATION_SIGNING_ALG_VALUES_SUPPORTED: &[&str] = &[
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHAKE-128s",
    "ML-DSA-44-ES256",
    "ML-DSA-65-ES256",
    "ML-DSA-87-ES384",
    "ML-DSA-44-Ed25519",
    "ML-DSA-65-Ed25519",
    "ML-DSA-87-Ed448",
];

pub(crate) const AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED: &[&str] = &[
    "RSA-OAEP-256",
    "RSA-OAEP",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
];

pub(crate) const AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED: &[&str] = &[
    "A128GCM",
    "A192GCM",
    "A256GCM",
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
];

const ASSERTION_SIGNING_ALG_VALUES_SUPPORTED: &[&str] = &[
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "EdDSA",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHAKE-128s",
    "ML-DSA-44-ES256",
    "ML-DSA-65-ES256",
    "ML-DSA-87-ES384",
    "ML-DSA-44-Ed25519",
    "ML-DSA-65-Ed25519",
    "ML-DSA-87-Ed448",
];

const ASSERTION_ENCRYPTION_ALG_VALUES_SUPPORTED: &[&str] = &[
    "RSA-OAEP-256",
    "RSA-OAEP",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "A128KW",
    "A192KW",
    "A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
    "dir",
];

const ASSERTION_ENCRYPTION_ENC_VALUES_SUPPORTED: &[&str] = &[
    "A128GCM",
    "A192GCM",
    "A256GCM",
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
];

const TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED: &[&str] = &[
    "none",
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "saml2_bearer",
    "tls_client_auth",
    "self_signed_tls_client_auth",
];

const TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED: &[&str] = &[
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "EdDSA",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHAKE-128s",
    "ML-DSA-44-ES256",
    "ML-DSA-65-ES256",
    "ML-DSA-87-ES384",
    "ML-DSA-44-Ed25519",
    "ML-DSA-65-Ed25519",
    "ML-DSA-87-Ed448",
];

const INTROSPECTION_SIGNING_ALG_VALUES_SUPPORTED: &[&str] = &[
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHAKE-128s",
    "ML-DSA-44-ES256",
    "ML-DSA-65-ES256",
    "ML-DSA-87-ES384",
    "ML-DSA-44-Ed25519",
    "ML-DSA-65-Ed25519",
    "ML-DSA-87-Ed448",
];

const INTROSPECTION_ENCRYPTION_ALG_VALUES_SUPPORTED: &[&str] = &[
    "RSA-OAEP-256",
    "RSA-OAEP",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
];

const INTROSPECTION_ENCRYPTION_ENC_VALUES_SUPPORTED: &[&str] = &[
    "A128GCM",
    "A192GCM",
    "A256GCM",
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
];

const REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED: &[&str] = &[
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "EdDSA",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHAKE-128s",
    "ML-DSA-44-ES256",
    "ML-DSA-65-ES256",
    "ML-DSA-87-ES384",
    "ML-DSA-44-Ed25519",
    "ML-DSA-65-Ed25519",
    "ML-DSA-87-Ed448",
    "none",
];

const REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED: &[&str] = &[
    "RSA-OAEP-256",
    "RSA-OAEP",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "A128KW",
    "A192KW",
    "A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
    "dir",
];

const REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED: &[&str] = &[
    "A128GCM",
    "A192GCM",
    "A256GCM",
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
];

const ACR_VALUES_SUPPORTED: &[&str] = &[
    "0",
    "1",
    "mfa",
    "phr",
    "phrh",
    "urn:sts:acr:compliant-device",
];

const DPOP_SIGNING_ALG_VALUES_SUPPORTED: &[&str] = &[
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "EdDSA",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
];

const GRANT_MANAGEMENT_ACTIONS_SUPPORTED: &[&str] =
    &["create", "merge", "replace", "query", "revoke"];

const AUTHORIZATION_DETAILS_TYPES_SUPPORTED: &[&str] = &["openid_credential"];

/// This service's own post-quantum signing algorithms.
fn is_post_quantum(alg: &str) -> bool {
    alg.starts_with("ML-DSA") || alg.starts_with("SLH-DSA")
}

fn list(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// What the document is built from.
pub struct MetadataInputs<'a> {
    pub settings: &'a std::sync::Arc<Settings>,
    pub mode: &'a Mode,
    /// : the realm's base URL.
    pub base: &'a str,
    /// 's tags.
    pub ui_locales: Vec<String>,
    /// The grants the token endpoint advertises
    /// ().
    pub grant_types: Vec<String>,
    /// : the main port asks for a client certificate.
    pub mtls_available: bool,
    /// `baseUrlOf(req)`: the REALM's base, where `base` is the
    /// authorization server's (`asBaseOf()`, `/<id>` after it for a named
    /// one). The crypto metadata, the documents and the status-list
    /// aggregation are the realm's, not a named server's.
    pub realm_base: &'a str,
}

fn not_false(settings: &Settings, key: &str) -> bool {
    !matches!(settings.value_of(key), SettingValue::Bool(false))
}

fn text(settings: &Settings, key: &str, fallback: &str) -> String {
    let v = settings.value_of(key);
    let t = v.as_str().trim().to_string();
    if t.is_empty() {
        fallback.to_string()
    } else {
        t
    }
}

///  for the default authorization server.
#[tracing::instrument(level = "debug", skip_all)]
pub fn as_metadata(inputs: &MetadataInputs<'_>) -> Json {
    let settings = inputs.settings;
    let mode = inputs.mode;
    let at = inputs.base;
    let product = mode.current() == "product";
    let bcp = settings.value_of("oauth2.rfc9700").as_bool()
        || settings.value_of("oauth2.oauth21").as_bool()
        || mode.enforces_oauth_security_bcp();
    let issuer =
        crate::jwt_access_token::JwtAccessTokens::new(settings.clone())
            .issuer_for(at);
    // The narrowing of every signing and encryption list.
    let own_signing = |items: &[&str]| -> Vec<String> {
        items
            .iter()
            .filter(|a| !(product && **a == "ES256K"))
            .filter(|a| {
                not_false(settings, "keys.postQuantumSigning")
                    || !is_post_quantum(a)
            })
            .map(|s| s.to_string())
            .collect()
    };
    let accepted = |items: &[&str]| -> Vec<String> {
        items
            .iter()
            .filter(|a| !(product && **a == "ES256K"))
            .map(|s| s.to_string())
            .collect()
    };
    let encryption = |items: &[&str]| -> Vec<String> {
        items
            .iter()
            .filter(|a| !(product && **a == "RSA-OAEP"))
            .map(|s| s.to_string())
            .collect()
    };
    let encs = |items: &[&str]| -> Vec<String> {
        items
            .iter()
            .filter(|e| !(product && e.contains("CBC")))
            .map(|s| s.to_string())
            .collect()
    };
    let methods: Vec<String> = TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
        .iter()
        .filter(|m| inputs.mtls_available || !m.contains("tls_client_auth"))
        .map(|s| s.to_string())
        .collect();
    let mut scopes = list(&[
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "offline_access",
        "device_sso",
    ]);
    if not_false(settings, "oauth2.keyBinding") {
        scopes.push("bound_key".into());
    }
    if not_false(settings, "scim.enabled") {
        scopes.push(text(settings, "scim.scopeRead", "scim:read"));
        scopes.push(text(settings, "scim.scopeWrite", "scim:write"));
    }
    if not_false(settings, "ssf.enabled") {
        for one in [
            text(settings, "ssf.authScopeRead", "ssf.read"),
            text(settings, "ssf.authScopeWrite", "ssf.manage"),
            "ssf.read".to_string(),
            "ssf.manage".to_string(),
        ] {
            if !scopes.contains(&one) {
                scopes.push(one);
            }
        }
    }
    if settings.value_of("oauth2.didClaim").as_bool() {
        scopes.push("did".into());
    }
    let mut response_types = list(&[
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "id_token token",
        "code id_token token",
        "none",
    ]);
    let waived = settings
        .value_of("oauth2.allowImplicitTokenResponses")
        .as_bool()
        && !settings.value_of("oauth2.oauth21").as_bool();
    if bcp && !waived {
        response_types.retain(|t| !t.split(' ').any(|w| w == "token"));
    }
    let mut grants = inputs.grant_types.clone();
    if bcp {
        let keep_implicit = response_types
            .iter()
            .any(|t| t.split(' ').any(|w| w == "token" || w == "id_token"));
        grants
            .retain(|g| g != "password" && (g != "implicit" || keep_implicit));
    }
    let mut m = Map::new();
    let mut put = |k: &str, v: Json| {
        m.insert(k.to_string(), v);
    };
    put("issuer", json!(issuer));
    put(
        "authorization_endpoint",
        json!(format!("{}/oauth2/authorize", at)),
    );
    put("token_endpoint", json!(format!("{}/oauth2/token", at)));
    put("response_types_supported", json!(response_types));
    put("jwks_uri", json!(format!("{}/oauth2/jwks", at)));
    put(
        "crypto_metadata_uri",
        json!(format!("{}/crypto/metadata.json", inputs.realm_base)),
    );
    if not_false(settings, "oauth2.dynamicRegistration") {
        put(
            "registration_endpoint",
            json!(format!("{}/oauth2/register", at)),
        );
    }
    put("scopes_supported", json!(scopes));
    put(
        "response_modes_supported",
        json!(list(&[
            "query",
            "fragment",
            "form_post",
            "jwt",
            "query.jwt",
            "fragment.jwt",
            "form_post.jwt"
        ])),
    );
    put(
        "authorization_signing_alg_values_supported",
        json!(own_signing(AUTHORIZATION_SIGNING_ALG_VALUES_SUPPORTED)),
    );
    put(
        "authorization_encryption_alg_values_supported",
        json!(encryption(AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED)),
    );
    put(
        "authorization_encryption_enc_values_supported",
        json!(encs(AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED)),
    );
    put("grant_types_supported", json!(grants));
    put(
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer_supported",
        json!(true),
    );
    put(
        "pre-authorized_grant_anonymous_access_supported",
        json!(true),
    );
    put(
        "urn:ietf:params:oauth:client-assertion-type:saml2-bearer_supported",
        json!(true),
    );
    put(
        "assertion_signing_alg_values_supported",
        json!(accepted(ASSERTION_SIGNING_ALG_VALUES_SUPPORTED)),
    );
    put(
        "assertion_encryption_alg_values_supported",
        json!(list(ASSERTION_ENCRYPTION_ALG_VALUES_SUPPORTED)),
    );
    put(
        "assertion_encryption_enc_values_supported",
        json!(encs(ASSERTION_ENCRYPTION_ENC_VALUES_SUPPORTED)),
    );
    put(
        "authorization_details_types_supported",
        json!(list(AUTHORIZATION_DETAILS_TYPES_SUPPORTED)),
    );
    // OAuth 2.1 mode (`oauth21.applyToMetadata()`): no `saml2_bearer`
    // client authentication, at the token endpoint alone.
    let token_methods: Vec<String> =
        if settings.value_of("oauth2.oauth21").as_bool() {
            methods
                .iter()
                .filter(|m| *m != "saml2_bearer")
                .cloned()
                .collect()
        } else {
            methods.clone()
        };
    put(
        "token_endpoint_auth_methods_supported",
        json!(token_methods),
    );
    put(
        "token_endpoint_auth_signing_alg_values_supported",
        json!(accepted(TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED)),
    );
    put(
        "service_documentation",
        json!(format!("{}/docs", inputs.realm_base)),
    );
    put("ui_locales_supported", json!(inputs.ui_locales));
    put(
        "op_policy_uri",
        json!(format!("{}/policy", inputs.realm_base)),
    );
    put("op_tos_uri", json!(format!("{}/tos", inputs.realm_base)));
    put(
        "revocation_endpoint",
        json!(format!("{}/oauth2/revoke", at)),
    );
    put("revocation_endpoint_auth_methods_supported", json!(methods));
    put(
        "revocation_endpoint_auth_signing_alg_values_supported",
        json!(accepted(TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED)),
    );
    put(
        "introspection_endpoint",
        json!(format!("{}/oauth2/introspect", at)),
    );
    put(
        "status_list_aggregation_endpoint",
        json!(format!("{}/status-lists", inputs.realm_base)),
    );
    put(
        "introspection_endpoint_auth_methods_supported",
        json!(methods),
    );
    put(
        "introspection_endpoint_auth_signing_alg_values_supported",
        json!(accepted(TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED)),
    );
    put(
        "introspection_signing_alg_values_supported",
        json!(own_signing(INTROSPECTION_SIGNING_ALG_VALUES_SUPPORTED)),
    );
    put(
        "introspection_encryption_alg_values_supported",
        json!(encryption(INTROSPECTION_ENCRYPTION_ALG_VALUES_SUPPORTED)),
    );
    put(
        "introspection_encryption_enc_values_supported",
        json!(encs(INTROSPECTION_ENCRYPTION_ENC_VALUES_SUPPORTED)),
    );
    put("request_parameter_supported", json!(true));
    put("request_uri_parameter_supported", json!(true));
    put("require_request_uri_registration", json!(true));
    let require_signed = settings
        .value_of("oauth2.requireSignedRequestObject")
        .as_bool();
    put("require_signed_request_object", json!(require_signed));
    let mut request_algs: Vec<String> = accepted(
        &REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED
            .iter()
            .filter(|a| **a != "none")
            .copied()
            .collect::<Vec<_>>(),
    );
    if mode.accepts_unsigned_request_objects() && !require_signed {
        request_algs.push("none".into());
    }
    put(
        "request_object_signing_alg_values_supported",
        json!(request_algs),
    );
    put(
        "request_object_encryption_alg_values_supported",
        json!(list(REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED)),
    );
    put(
        "request_object_encryption_enc_values_supported",
        json!(encs(REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED)),
    );
    let par = not_false(settings, "oauth2.pushedAuthorizationRequests");
    if par {
        put(
            "pushed_authorization_request_endpoint",
            json!(format!("{}/oauth2/par", at)),
        );
    }
    put(
        "require_pushed_authorization_requests",
        json!(settings
            .value_of("oauth2.requirePushedAuthorizationRequests")
            .as_bool()),
    );
    put(
        "code_challenge_methods_supported",
        json!(if bcp {
            list(&["S256"])
        } else {
            list(&["S256", "plain"])
        }),
    );
    put("acr_values_supported", json!(list(ACR_VALUES_SUPPORTED)));
    put(
        "authorization_response_iss_parameter_supported",
        json!(true),
    );
    put(
        "dpop_signing_alg_values_supported",
        json!(accepted(DPOP_SIGNING_ALG_VALUES_SUPPORTED)),
    );
    put(
        "tls_client_certificate_bound_access_tokens",
        json!(inputs.mtls_available),
    );
    // RFC 8628 section 4 (#150): the device authorization endpoint, only
    // where it is on.
    if settings.value_of("oauth2.deviceAuthorization").as_bool() {
        put(
            "device_authorization_endpoint",
            json!(format!("{}/oauth2/device_authorization", at)),
        );
    }
    if inputs.mtls_available {
        let mut aliases = Map::new();
        for (name, path) in [
            ("token_endpoint", "/oauth2/token"),
            ("revocation_endpoint", "/oauth2/revoke"),
            ("introspection_endpoint", "/oauth2/introspect"),
        ] {
            aliases.insert(name.into(), json!(format!("{}{}", at, path)));
        }
        if par {
            aliases.insert(
                "pushed_authorization_request_endpoint".into(),
                json!(format!("{}/oauth2/par", at)),
            );
        }
        put("mtls_endpoint_aliases", Json::Object(aliases));
    }
    if not_false(settings, "oauth2.grantManagement") {
        put(
            "grant_management_actions_supported",
            json!(list(GRANT_MANAGEMENT_ACTIONS_SUPPORTED)),
        );
        put(
            "grant_management_endpoint",
            json!(format!("{}/oauth2/grants", at)),
        );
    }
    Json::Object(m)
}

/// `USERINFO_SIGNING_ALGS`: the RSA, curve, post-quantum and HMAC tables,
/// then `none`.
pub(crate) const USERINFO_SIGNING_ALG_VALUES_SUPPORTED: &[&str] = &[
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHAKE-128s",
    "ML-DSA-44-ES256",
    "ML-DSA-65-ES256",
    "ML-DSA-87-ES384",
    "ML-DSA-44-Ed25519",
    "ML-DSA-65-Ed25519",
    "ML-DSA-87-Ed448",
    "HS256",
    "HS384",
    "HS512",
    "none",
];

/// `claims_supported`: the protocol's own claims, in `idToken()`'s order,
/// then OIDC Core section 5.4's four scopes' (`scope_claims.ts`), the
/// Identity Assurance registered claims and `verified_claims`.
const CLAIMS_SUPPORTED: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "auth_time",
    "nonce",
    "azp",
    "jti",
    "at_hash",
    "c_hash",
    "s_hash",
    "amr",
    "acr",
    "sid",
    "session_expiry",
    "tenant",
    "aud_sub",
    "device_id",
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
    "place_of_birth",
    "nationalities",
    "birth_family_name",
    "birth_given_name",
    "birth_middle_name",
    "salutation",
    "title",
    "msisdn",
    "also_known_as",
    "verified_claims",
];

/// `identity_assurance.ts`'s tables (section 7).
const EVIDENCE_TYPES: &[&str] = &[
    "document",
    "electronic_record",
    "vouch",
    "electronic_signature",
];
const DOCUMENT_TYPES: &[&str] = &[
    "idcard",
    "passport",
    "driving_permit",
    "residence_permit",
    "visa",
    "birth_certificate",
    "bank_statement",
    "utility_statement",
];
const CHECK_METHODS: &[&str] = &[
    "vpip", "vpiruv", "vri", "vdig", "vcrypt", "data", "auth", "token", "kbv",
    "pvp", "pvr", "bvp", "bvr",
];
const ELECTRONIC_RECORD_TYPES: &[&str] = &[
    "bank_account",
    "utility_account",
    "mortgage_account",
    "loan_account",
    "tax",
    "social_security",
    "prison_record",
    "urn:sts:verifiable-credential",
];
const VERIFIABLE_CLAIMS: &[&str] = &[
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "birthdate",
    "gender",
    "address",
    "email",
    "phone_number",
    "place_of_birth",
    "nationalities",
    "birth_family_name",
    "birth_given_name",
    "birth_middle_name",
    "salutation",
    "title",
    "msisdn",
    "also_known_as",
];

/// `DEMO_FRAMEWORK`: the framework development invents its values under.
const DEMO_FRAMEWORK: &str = "urn:sts:demo";

/// `identityAssurance.trustFrameworks()`: `oauth2.idaTrustFrameworks`,
/// trimmed, once each, the demonstration framework left out.
fn trust_frameworks(settings: &Settings) -> Vec<String> {
    let raw: Vec<String> = match settings.value_of("oauth2.idaTrustFrameworks")
    {
        SettingValue::List(l) => l,
        other => other.as_str().split(',').map(str::to_string).collect(),
    };
    let mut out: Vec<String> = Vec::new();
    for one in raw {
        let t = one.trim().to_string();
        if !t.is_empty() && t != DEMO_FRAMEWORK && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// OpenID Connect Discovery 1.0 (`oauth2.ts`'s `oidcMetadata()`): the RFC
/// 8414 document with the OpenID Connect members merged in — a member
/// already there keeps its place — and the issuer of the path-appended
/// form where one is given and `oauth2.issuer` is not pinned.
///
/// WHAT IS NOT HERE: the
/// FAPI profile's narrowing (FAPI's slice), and the OP iframe's member
/// (`oauth2.sessionManagement`, off by default) — each absent, as Node's
/// document is with its feature off.
#[tracing::instrument(level = "debug", skip_all)]
pub fn oidc_metadata(
    inputs: &MetadataInputs<'_>,
    issuer: Option<&str>,
) -> Json {
    let settings = inputs.settings;
    let product = inputs.mode.current() == "product";
    let at = inputs.base;
    let mut doc = as_metadata(inputs);
    let pq = not_false(settings, "keys.postQuantumSigning");
    let signing = |items: &[&str]| -> Vec<String> {
        items
            .iter()
            .filter(|a| !(product && **a == "ES256K"))
            .filter(|a| pq || !is_post_quantum(a))
            .map(|s| s.to_string())
            .collect()
    };
    let encryption: Vec<String> = AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED
        .iter()
        .filter(|a| !(product && **a == "RSA-OAEP"))
        .map(|s| s.to_string())
        .collect();
    let encs: Vec<String> = AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED
        .iter()
        .filter(|e| !(product && e.contains("CBC")))
        .map(|s| s.to_string())
        .collect();
    let front = settings.value_of("oauth2.frontchannelLogout").as_bool();
    let back = settings.value_of("oauth2.backchannelLogout").as_bool();
    let mut claims = list(CLAIMS_SUPPORTED);
    if settings.value_of("oauth2.didClaim").as_bool() {
        claims.push("did".into());
    }
    let Some(m) = doc.as_object_mut() else {
        return doc;
    };
    let mut put = |k: &str, v: Json| {
        m.insert(k.to_string(), v);
    };
    put(
        "userinfo_endpoint",
        json!(format!("{}/oauth2/userinfo", at)),
    );
    put(
        "userinfo_signing_alg_values_supported",
        json!(signing(USERINFO_SIGNING_ALG_VALUES_SUPPORTED)),
    );
    put(
        "userinfo_encryption_alg_values_supported",
        json!(encryption),
    );
    put("userinfo_encryption_enc_values_supported", json!(encs));
    put(
        "subject_types_supported",
        json!(["public", "pairwise", "ephemeral"]),
    );
    put(
        "id_token_encryption_alg_values_supported",
        json!(encryption),
    );
    put("id_token_encryption_enc_values_supported", json!(encs));
    put(
        "id_token_signing_alg_values_supported",
        json!(signing(AUTHORIZATION_SIGNING_ALG_VALUES_SUPPORTED)),
    );
    put("claims_supported", json!(claims));
    put(
        "claim_types_supported",
        json!(["normal", "aggregated", "distributed"]),
    );
    put(
        "prompt_values_supported",
        json!(["none", "login", "consent", "select_account"]),
    );
    put(
        "display_values_supported",
        json!(["page", "popup", "touch"]),
    );
    put("claims_locales_supported", json!(["en-US"]));
    put("claims_parameter_supported", json!(true));
    put(
        "end_session_endpoint",
        json!(format!("{}/oauth2/logout", at)),
    );
    if settings.value_of("oauth2.sessionManagement").as_bool() {
        put(
            "check_session_iframe",
            json!(format!("{}/oauth2/check_session", inputs.realm_base)),
        );
    }
    put("frontchannel_logout_supported", json!(front));
    put("frontchannel_logout_session_supported", json!(front));
    put("backchannel_logout_supported", json!(back));
    put("backchannel_logout_session_supported", json!(back));
    if let Some(i) = issuer {
        if settings.value_of("oauth2.issuer").as_str().is_empty() {
            put("issuer", json!(i));
        }
    }
    // OPENID CONNECT CIBA section 4 (#131), where it is on.
    if settings.value_of("oauth2.ciba").as_bool() {
        put(
            "backchannel_authentication_endpoint",
            json!(format!("{}/oauth2/bc-authorize", at)),
        );
        put(
            "backchannel_token_delivery_modes_supported",
            json!(["poll", "ping", "push"]),
        );
        put(
            "backchannel_authentication_request_signing_alg_values_supported",
            json!(sts_crypto::jws_alg::asymmetric_algs()),
        );
        put("backchannel_user_code_parameter_supported", json!(true));
    }
    let userinfo = format!("{}/oauth2/userinfo", at);
    if let Some(aliases) = m
        .get_mut("mtls_endpoint_aliases")
        .and_then(Json::as_object_mut)
    {
        aliases.insert("userinfo_endpoint".into(), json!(userinfo));
    }
    let mut frameworks = trust_frameworks(settings);
    if inputs.mode.invents_claim_values() {
        frameworks.push(DEMO_FRAMEWORK.into());
    }
    m.insert("verified_claims_supported".into(), json!(true));
    m.insert("trust_frameworks_supported".into(), json!(frameworks));
    m.insert("evidence_supported".into(), json!(list(EVIDENCE_TYPES)));
    m.insert("documents_supported".into(), json!(list(DOCUMENT_TYPES)));
    m.insert(
        "documents_check_methods_supported".into(),
        json!(list(CHECK_METHODS)),
    );
    m.insert(
        "electronic_records_supported".into(),
        json!(list(ELECTRONIC_RECORD_TYPES)),
    );
    m.insert(
        "claims_in_verified_claims_supported".into(),
        json!(list(VERIFIABLE_CLAIMS)),
    );
    m.insert("attachments_supported".into(), json!([]));
    m.insert("native_sso_supported".into(), json!(true));
    doc
}

/// 's claims: the document,  its issuer, and
/// the hour it is good for.
#[tracing::instrument(level = "debug", skip_all)]
pub fn signed_metadata_claims(meta: &Json, now_s: i64) -> Map<String, Json> {
    let mut claims = meta.as_object().cloned().unwrap_or_default();
    let issuer = meta.get("issuer").cloned().unwrap_or(Json::Null);
    claims.insert("sub".into(), issuer.clone());
    claims.insert("iat".into(), json!(now_s));
    claims.insert("exp".into(), json!(now_s + 3600));
    claims.insert("iss".into(), issuer);
    claims
}
