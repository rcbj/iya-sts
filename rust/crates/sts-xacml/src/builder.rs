// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One authorization request, built one way, for every PEP. A port of the
//! core of `xacml/xacml_request.js` (#306, #88 E).
//!
//! #88 section 7: every question this service asks — may this be issued,
//! may this surface be reached, what a remote PEP asks for somebody else —
//! is one shape, and a PEP says WHAT it knows rather than how XACML spells
//! it. It is an ENGINE module, so the remote PEP builds its requests with
//! the same code the runtime does. It decides nothing.
//!
//! The adapters for whole families of facts — `transfer()` (#98),
//! `exchange()` (#186), `passkey()` (#536) and `gnapRight()` (#432) — move
//! with the families that call them (rust/DESIGN.md section 11); the
//! vocabulary they use is here already, so nothing else can spell it
//! differently. The questions of the policies this engine evaluates for
//! several callers are here: AuthZEN's (#563), fine-grained authorization's
//! (#564) and User-Managed Access's (#1168).

use crate::model::{attribute, category, types};
use crate::request::{
    Request, RequestAttribute, RequestCategory, RequestValue,
};

/// The vocabulary of #88 section 7 that is not XACML's own: EVERY
/// identifier `xacml_request.js`'s `VOCABULARY` holds, in its order, so a
/// family ported later finds its facts already spelt, and no Rust module
/// can spell one differently (`tests/xacml_request.js`'s E2 holds each one
/// to Node's; `tests/node_vectors.rs` holds the whole table). URI-shaped,
/// so the PIP never mistakes one for a directory attribute name.
pub mod vocabulary {
    // The fields of #88 section 7, and the scope stage, mode and settings
    // (#305).
    pub const ROLE: &str = "urn:sts:xacml:role";
    pub const SUBJECT_KIND: &str = "urn:sts:xacml:subject-kind";
    pub const CLIENT_ID: &str = "urn:sts:xacml:client-id";
    pub const AUDIENCE: &str = "urn:sts:xacml:audience";
    pub const REQUESTED_SCOPE: &str = "urn:sts:xacml:requested-scope";
    pub const PROTOCOL: &str = "urn:sts:xacml:protocol";
    pub const GRANT_TYPE: &str = "urn:sts:xacml:grant-type";
    pub const MODE: &str = "urn:sts:xacml:mode";
    pub const SETTING_PREFIX: &str = "urn:sts:xacml:setting:";
    pub const ACR: &str = "urn:sts:xacml:acr";
    pub const SCOPE_STAGE: &str = "urn:sts:xacml:scope-stage";

    // A transfer question's facts (#98, D11), whose adapter is the cells
    // family's `transfer()`; and the realm every question is asked in.
    pub const HOME_JURISDICTION: &str = "urn:sts:xacml:home-jurisdiction";
    pub const SERVING_JURISDICTION: &str = "urn:sts:xacml:serving-jurisdiction";
    pub const CLIENT_COUNTRY: &str = "urn:sts:xacml:client-country";
    pub const TRANSFER_LISTED: &str = "urn:sts:xacml:transfer-listed";
    pub const DATA_CATEGORY: &str = "urn:sts:xacml:data-category";
    pub const PURPOSE: &str = "urn:sts:xacml:purpose";
    pub const REALM: &str = "urn:sts:xacml:realm";

    // A token exchange's facts (#186, #108): the adapter is the token
    // exchange's, `exchange()`.
    pub const EXCHANGE_SUBJECT_NOT_DELEGATED: &str =
        "urn:sts:xacml:exchange:subject-not-delegated";
    pub const EXCHANGE_SUBJECT_GROUP: &str =
        "urn:sts:xacml:exchange:subject-group";
    pub const EXCHANGE_ALLOWED_SEMANTICS: &str =
        "urn:sts:xacml:exchange:allowed-semantics";
    pub const EXCHANGE_DEFAULT_SEMANTICS: &str =
        "urn:sts:xacml:exchange:default-semantics";
    pub const EXCHANGE_ACTOR_KIND: &str = "urn:sts:xacml:exchange:actor-kind";
    pub const EXCHANGE_ACTOR_REGISTERED: &str =
        "urn:sts:xacml:exchange:actor-registered";
    pub const EXCHANGE_ACTOR_DELEGATES_TO: &str =
        "urn:sts:xacml:exchange:actor-delegates-to";
    pub const EXCHANGE_ACTOR_SUBJECT_GROUP: &str =
        "urn:sts:xacml:exchange:actor-subject-group";
    pub const EXCHANGE_SOURCE: &str = "urn:sts:xacml:exchange:source";
    pub const EXCHANGE_SOURCE_REQUIRED_ROLE: &str =
        "urn:sts:xacml:exchange:source-required-role";
    pub const EXCHANGE_SOURCE_DELEGATES_TO: &str =
        "urn:sts:xacml:exchange:source-delegates-to";
    pub const EXCHANGE_TARGET_COUNT: &str =
        "urn:sts:xacml:exchange:target-count";
    pub const EXCHANGE_TARGET_REGISTERED: &str =
        "urn:sts:xacml:exchange:target-registered";
    pub const EXCHANGE_TARGET_REQUIRED_ROLE: &str =
        "urn:sts:xacml:exchange:target-required-role";
    pub const EXCHANGE_TARGET_ACCEPTS: &str =
        "urn:sts:xacml:exchange:target-accepts";
    pub const EXCHANGE_REQUESTED_SEMANTICS: &str =
        "urn:sts:xacml:exchange:requested-semantics";
    pub const EXCHANGE_SEMANTICS: &str = "urn:sts:xacml:exchange:semantics";
    pub const EXCHANGE_MAY_ACT_PRESENT: &str =
        "urn:sts:xacml:exchange:may-act-present";
    pub const EXCHANGE_MAY_ACT_NAMES_ACTOR: &str =
        "urn:sts:xacml:exchange:may-act-names-actor";
    pub const EXCHANGE_PROTECTED_GROUP: &str =
        "urn:sts:xacml:exchange:protected-group";
    pub const EXCHANGE_SUBJECT_DELEGATE: &str =
        "urn:sts:xacml:exchange:subject-delegate";
    pub const EXCHANGE_SUBJECT_REALM: &str =
        "urn:sts:xacml:exchange:subject-realm";
    pub const EXCHANGE_ACTOR_REALM: &str = "urn:sts:xacml:exchange:actor-realm";
    pub const EXCHANGE_TARGET_REALM: &str =
        "urn:sts:xacml:exchange:target-realm";
    pub const EXCHANGE_TRUST_PARTNER: &str =
        "urn:sts:xacml:exchange:trust-partner";
    pub const EXCHANGE_TRUST_TYPE: &str = "urn:sts:xacml:exchange:trust-type";
    pub const EXCHANGE_TRUST_DIRECTION: &str =
        "urn:sts:xacml:exchange:trust-direction";
    pub const EXCHANGE_TRUST_ATTRIBUTE: &str =
        "urn:sts:xacml:exchange:trust-attribute";
    pub const EXCHANGE_TRUST_PATH: &str = "urn:sts:xacml:exchange:trust-path";
    pub const EXCHANGE_TRUST_HOPS: &str = "urn:sts:xacml:exchange:trust-hops";
    pub const EXCHANGE_TRUST_ENABLED: &str =
        "urn:sts:xacml:exchange:trust-enabled";
    pub const EXCHANGE_LOCAL_REALM: &str = "urn:sts:xacml:exchange:local-realm";
    pub const EXCHANGE_MECHANISM: &str = "urn:sts:xacml:exchange:mechanism";
    pub const EXCHANGE_ACTOR_SELF_REALM: &str =
        "urn:sts:xacml:exchange:actor-self-realm";
    pub const EXCHANGE_TARGET_FOREIGN_TGT_DELEGATION: &str =
        "urn:sts:xacml:exchange:target-foreign-tgt-delegation";

    // One GNAP access right's facts (#432): the adapter is GNAP's,
    // `gnapRight()`.
    pub const GNAP_RIGHT_KIND: &str = "urn:sts:xacml:gnap:right-kind";
    pub const GNAP_RIGHT_ACTION: &str = "urn:sts:xacml:gnap:right-action";
    pub const GNAP_RIGHT_LOCATION: &str = "urn:sts:xacml:gnap:right-location";
    pub const GNAP_RIGHT_DATATYPE: &str = "urn:sts:xacml:gnap:right-datatype";
    pub const GNAP_RIGHT_IDENTIFIER: &str =
        "urn:sts:xacml:gnap:right-identifier";
    pub const GNAP_RIGHT_PRIVILEGE: &str = "urn:sts:xacml:gnap:right-privilege";
    pub const GNAP_RIGHT_LISTED: &str = "urn:sts:xacml:gnap:right-listed";
    pub const GNAP_REFERENCE_REGISTERED: &str =
        "urn:sts:xacml:gnap:reference-registered";
    pub const GNAP_PROTECTED: &str = "urn:sts:xacml:gnap:protected";
    pub const GNAP_PROTECTED_DECLARED: &str =
        "urn:sts:xacml:gnap:protected-declared";
    pub const GNAP_CATALOGUED: &str = "urn:sts:xacml:gnap:catalogued";
    pub const GNAP_TYPE_OWNER: &str = "urn:sts:xacml:gnap:type-owner";
    pub const GNAP_TYPE_BEARER: &str = "urn:sts:xacml:gnap:type-bearer";
    pub const GNAP_TYPE_MAX_LIFETIME: &str =
        "urn:sts:xacml:gnap:type-max-lifetime";
    pub const GNAP_TYPE_ACR: &str = "urn:sts:xacml:gnap:type-acr";
    pub const GNAP_TYPE_INTERACTION: &str =
        "urn:sts:xacml:gnap:type-interaction";
    pub const GNAP_TYPE_CONSENT_ACTION: &str =
        "urn:sts:xacml:gnap:type-consent-action";
    pub const GNAP_TYPE_DERIVABLE_FROM: &str =
        "urn:sts:xacml:gnap:type-derivable-from";
    pub const GNAP_TYPE_INTROSPECTION_CLAIM: &str =
        "urn:sts:xacml:gnap:type-introspection-claim";
    pub const GNAP_LIMITS: &str = "urn:sts:xacml:gnap:limits";
    pub const GNAP_LIMIT_AMOUNT: &str = "urn:sts:xacml:gnap:limit-amount";
    pub const GNAP_LIMIT_CURRENCY: &str = "urn:sts:xacml:gnap:limit-currency";
    pub const GNAP_LIMIT_COUNT: &str = "urn:sts:xacml:gnap:limit-count";
    pub const GNAP_LIMIT_RECEIVER: &str = "urn:sts:xacml:gnap:limit-receiver";
    pub const GNAP_LIMIT_INTERVAL: &str = "urn:sts:xacml:gnap:limit-interval";
    pub const GNAP_LIMIT_NOT_BEFORE: &str =
        "urn:sts:xacml:gnap:limit-not-before";
    pub const GNAP_LIMIT_NOT_AFTER: &str = "urn:sts:xacml:gnap:limit-not-after";
    pub const GNAP_OWNER_KNOWN: &str = "urn:sts:xacml:gnap:owner-known";
    pub const GNAP_OWNER: &str = "urn:sts:xacml:gnap:owner";
    pub const GNAP_OWNER_SOURCE: &str = "urn:sts:xacml:gnap:owner-source";
    pub const GNAP_OWNER_UNRESOLVED: &str =
        "urn:sts:xacml:gnap:owner-unresolved";
    pub const GNAP_OWNER_MATCHES: &str = "urn:sts:xacml:gnap:owner-matches";
    pub const GNAP_TOKEN_LABEL: &str = "urn:sts:xacml:gnap:token-label";
    pub const GNAP_TOKEN_BEARER: &str = "urn:sts:xacml:gnap:token-bearer";
    pub const GNAP_TOKEN_FORMAT: &str = "urn:sts:xacml:gnap:token-format";
    pub const GNAP_TOKEN_TARGET: &str = "urn:sts:xacml:gnap:token-target";
    pub const GNAP_CLIENT_CLASS: &str = "urn:sts:xacml:gnap:client-class";
    pub const GNAP_CLIENT_HAS_ALLOWED_ACCESS: &str =
        "urn:sts:xacml:gnap:client-has-allowed-access";
    pub const GNAP_CLIENT_BEARER_REFUSED: &str =
        "urn:sts:xacml:gnap:client-bearer-refused";
    pub const GNAP_APPROVER: &str = "urn:sts:xacml:gnap:approver";
    pub const GNAP_APPROVAL: &str = "urn:sts:xacml:gnap:approval";
    pub const GNAP_SESSION_ACR: &str = "urn:sts:xacml:gnap:session-acr";
    pub const GNAP_SESSION_AMR: &str = "urn:sts:xacml:gnap:session-amr";
    pub const GNAP_RISK_LEVEL: &str = "urn:sts:xacml:gnap:risk-level";
    pub const GNAP_RISK_SIGNAL: &str = "urn:sts:xacml:gnap:risk-signal";
    pub const GNAP_DEVICE_RECOGNIZED: &str =
        "urn:sts:xacml:gnap:device-recognized";
    pub const GNAP_DEVICE_STATUS: &str = "urn:sts:xacml:gnap:device-status";
    pub const GNAP_DEVICE_COMPLIANCE: &str =
        "urn:sts:xacml:gnap:device-compliance";
    pub const GNAP_DEVICE_ATTESTATION: &str =
        "urn:sts:xacml:gnap:device-attestation";
    pub const GNAP_DEVICE_OWNER_MATCHES: &str =
        "urn:sts:xacml:gnap:device-owner-matches";

    // AuthZEN's facts (#563): `authzen()` below, and the token gate's
    // binding context (#1180) and an approved access request.
    pub const AUTHZEN_SUBJECT_TYPE: &str = "urn:sts:xacml:authzen:subject-type";
    pub const AUTHZEN_RESOURCE_TYPE: &str =
        "urn:sts:xacml:authzen:resource-type";
    pub const AUTHZEN_CALLER: &str = "urn:sts:xacml:authzen:caller";
    pub const AUTHZEN_APPLICATION: &str = "urn:sts:xacml:authzen:application";
    pub const AUTHZEN_SUPPLIED: &str = "urn:sts:xacml:authzen:supplied";
    pub const AUTHZEN_TOKEN_TYPE: &str = "urn:sts:xacml:authzen:token-type";
    pub const AUTHZEN_SUBJECT_TOKEN_TYPE: &str =
        "urn:sts:xacml:authzen:subject-token-type";
    pub const AUTHZEN_ACTOR_TOKEN_TYPE: &str =
        "urn:sts:xacml:authzen:actor-token-type";
    pub const AUTHZEN_ACT_DEPTH: &str = "urn:sts:xacml:authzen:act-depth";
    pub const AUTHZEN_APPROVAL_ID: &str = "urn:sts:xacml:authzen:approval-id";
    pub const AUTHZEN_APPROVED_UNTIL: &str =
        "urn:sts:xacml:authzen:approved-until";
    pub const AUTHZEN_APPROVER: &str = "urn:sts:xacml:authzen:approver";

    // Fine-grained authorization's facts (#564): `fga()` and `fga_access()`
    // below; the rows come from `xacml/fga_map.ts`.
    pub const FGA_APPLICATION: &str = "urn:sts:xacml:fga:application";
    pub const FGA_DETAIL_TYPE: &str = "urn:sts:xacml:fga:detail-type";
    pub const FGA_DEFINITION_DIGEST: &str =
        "urn:sts:xacml:fga:definition-digest";
    pub const FGA_STAGE: &str = "urn:sts:xacml:fga:stage";
    pub const FGA_SUPPLIED: &str = "urn:sts:xacml:fga:supplied";
    pub const FGA_DETAIL_ACTION: &str = "urn:sts:xacml:fga:detail:action";
    pub const FGA_DETAIL_LOCATION: &str = "urn:sts:xacml:fga:detail:location";
    pub const FGA_DETAIL_DATATYPE: &str = "urn:sts:xacml:fga:detail:datatype";
    pub const FGA_DETAIL_IDENTIFIER: &str =
        "urn:sts:xacml:fga:detail:identifier";
    pub const FGA_DETAIL_PRIVILEGE: &str = "urn:sts:xacml:fga:detail:privilege";

    // A User-Managed Access question's facts (#1168): `uma()` below.
    pub const UMA_RESOURCE_TYPE: &str = "urn:sts:xacml:uma:resource-type";
    pub const UMA_RESOURCE_SERVER: &str = "urn:sts:xacml:uma:resource-server";
    pub const UMA_RESOURCE_SERVER_DECLARED: &str =
        "urn:sts:xacml:uma:resource-server-declared";
    pub const UMA_OWNER: &str = "urn:sts:xacml:uma:owner";
    pub const UMA_OWNER_KIND: &str = "urn:sts:xacml:uma:owner-kind";
    pub const UMA_SCOPE: &str = "urn:sts:xacml:uma:scope";
    pub const UMA_REQUESTING_PARTY_KNOWN: &str =
        "urn:sts:xacml:uma:requesting-party-known";
    pub const UMA_REQUESTING_PARTY_IS_OWNER: &str =
        "urn:sts:xacml:uma:requesting-party-is-owner";
    pub const UMA_CLAIM_SOURCE: &str = "urn:sts:xacml:uma:claim-source";
    pub const UMA_CLAIM_ISSUER: &str = "urn:sts:xacml:uma:claim-issuer";
    pub const UMA_CLAIM_ISSUER_DECLARED: &str =
        "urn:sts:xacml:uma:claim-issuer-declared";
    pub const UMA_REQUESTING_PARTY_GROUP: &str =
        "urn:sts:xacml:uma:requesting-party-group";
    pub const UMA_CLIENT_GRANT_DECLARED: &str =
        "urn:sts:xacml:uma:client-grant-declared";
    pub const UMA_CLAIM_PREFIX: &str = "urn:sts:xacml:uma:claim:";
    pub const UMA_LAYER: &str = "urn:sts:xacml:uma:layer";
    pub const UMA_STAGE: &str = "urn:sts:xacml:uma:stage";
    pub const UMA_TICKET_AGE: &str = "urn:sts:xacml:uma:ticket-age";
    pub const UMA_RPT_PRESENTED: &str = "urn:sts:xacml:uma:rpt-presented";

    // A passkey question's facts (#536): the adapter is the passkey
    // ceremony's, `passkey()`.
    pub const PASSKEY_FACTS: &str = "urn:sts:xacml:passkey:facts";
    pub const PASSKEY_BACKUP_ELIGIBLE: &str =
        "urn:sts:xacml:passkey:backup-eligible";
    pub const PASSKEY_MIN_PIN_LENGTH: &str =
        "urn:sts:xacml:passkey:min-pin-length";
    pub const PASSKEY_SERIAL: &str = "urn:sts:xacml:passkey:serial";
    pub const PASSKEY_SERIAL_HELD: &str = "urn:sts:xacml:passkey:serial-held";
    pub const PASSKEY_ATTESTATION_VERIFIED: &str =
        "urn:sts:xacml:passkey:attestation-verified";
    pub const PASSKEY_ATTESTATION_TRUSTED: &str =
        "urn:sts:xacml:passkey:attestation-trusted";
    pub const PASSKEY_AAGUID: &str = "urn:sts:xacml:passkey:aaguid";
    pub const PASSKEY_MODEL_LISTED: &str = "urn:sts:xacml:passkey:model-listed";
    pub const PASSKEY_MODEL_COMPROMISED: &str =
        "urn:sts:xacml:passkey:model-compromised";
    pub const PASSKEY_CERTIFICATION_RANK: &str =
        "urn:sts:xacml:passkey:certification-rank";
    pub const PASSKEY_FIPS: &str = "urn:sts:xacml:passkey:fips";
    pub const PASSKEY_METADATA_UNCHECKED: &str =
        "urn:sts:xacml:passkey:metadata-unchecked";
    pub const PASSKEY_ALGORITHM: &str = "urn:sts:xacml:passkey:algorithm";
    pub const PASSKEY_POST_QUANTUM: &str = "urn:sts:xacml:passkey:post-quantum";
    pub const PASSKEY_LANE: &str = "urn:sts:xacml:passkey:lane";
    pub const PASSKEY_UPGRADE: &str = "urn:sts:xacml:passkey:upgrade";
    pub const PASSKEY_UPGRADE_MODE: &str = "urn:sts:xacml:passkey:upgrade-mode";
    pub const PASSKEY_UPGRADE_PREVIOUS_ALGORITHM: &str =
        "urn:sts:xacml:passkey:upgrade-previous-algorithm";
    pub const PASSKEY_ATTESTATION_STATEMENT_ALGORITHM: &str =
        "urn:sts:xacml:passkey:attestation-statement-algorithm";
    pub const PASSKEY_ATTESTATION_CERTIFICATE_ALGORITHM: &str =
        "urn:sts:xacml:passkey:attestation-certificate-algorithm";
    pub const PASSKEY_ATTESTATION_POST_QUANTUM: &str =
        "urn:sts:xacml:passkey:attestation-post-quantum";
    pub const PASSKEY_ATTESTATION_ALGORITHM_ALLOWED: &str =
        "urn:sts:xacml:passkey:attestation-algorithm-allowed";
    pub const PASSKEY_PROFILE_ALGORITHM_OFFERED: &str =
        "urn:sts:xacml:passkey:profile-algorithm-offered";
    pub const PASSKEY_ENROLLED_BY_ADMIN: &str =
        "urn:sts:xacml:passkey:enrolled-by-admin";
    pub const PASSKEY_ENROLLED_BY: &str = "urn:sts:xacml:passkey:enrolled-by";
    pub const PASSKEY_POLICY_PREFIX: &str = "urn:sts:xacml:passkey-policy:";
    pub const PASSKEY_RECOVERY_DOOR: &str =
        "urn:sts:xacml:passkey:recovery-door";
    pub const PASSKEY_RECOVERY_AT: &str = "urn:sts:xacml:passkey:recovery-at";
    pub const PASSKEY_RECOVERY_CREDENTIAL: &str =
        "urn:sts:xacml:passkey:recovery-credential";
    pub const PASSKEY_RECOVERY_SELF_SERVICE: &str =
        "urn:sts:xacml:passkey:recovery-self-service";
    pub const PASSKEY_RECOVERY_COVERED: &str =
        "urn:sts:xacml:passkey:recovery-covered";
    pub const PASSKEY_RECOVERY_PENDING: &str =
        "urn:sts:xacml:passkey:recovery-pending";
    pub const PASSKEY_REQUIRED_RANK: &str =
        "urn:sts:xacml:passkey:required-certification-rank";
}

/// The principal types a request may name; anything else is a person.
pub const SUBJECT_KINDS: [&str; 2] = ["user", "application"];

/// The moments a fine-grained authorization question is asked at (#564):
/// the authorization endpoint, the token endpoint, a refresh, a token
/// exchange and the PAR endpoint — the five ISSUANCE stages, whose action is
/// always [`FGA_GRANT_ACTION`] — and `access`, AuthZEN's per-request
/// question.
pub const FGA_STAGES: [&str; 6] =
    ["authorize", "token", "refresh", "exchange", "par", "access"];
pub const FGA_ISSUANCE_STAGES: [&str; 5] =
    ["authorize", "token", "refresh", "exchange", "par"];
/// The action-id of every issuance-stage FGA question.
pub const FGA_GRANT_ACTION: &str = "grant-authorization-detail";

/// The three policies a User-Managed Access question goes to (#1168): the
/// realm's, the resource owner's and the resource server's fine-grained
/// one; and the moments it is asked at.
pub const UMA_LAYERS: [&str; 3] = ["realm", "owner", "fga"];
pub const UMA_STAGES: [&str; 3] = ["assess", "upgrade", "approval"];
/// The action-id at the realm's layer, and at the fine-grained one.
pub const UMA_PERMISSION_ACTION: &str = "issue-uma-permission";
pub const UMA_FGA_ACTION: &str = "grant-uma-permission";
pub const UMA_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:uma-ticket";
/// Where a requesting party's claims came from.
pub const UMA_CLAIM_SOURCES: [&str; 3] = ["session", "claim_token", "pct"];

/// A value an attribute may carry, typed as the builder sends it.
#[derive(Debug, Clone, PartialEq)]
pub enum Fact {
    Text(String),
    Boolean(bool),
}

impl From<&str> for Fact {
    fn from(text: &str) -> Fact {
        Fact::Text(text.to_string())
    }
}

impl From<String> for Fact {
    fn from(text: String) -> Fact {
        Fact::Text(text)
    }
}

impl From<bool> for Fact {
    fn from(value: bool) -> Fact {
        Fact::Boolean(value)
    }
}

/// One catalogue-mapped attribute of an AuthZEN question: a row's category,
/// identifier and datatype, and the LEXICAL values the request carried.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthzenAttribute {
    pub category: String,
    pub attribute_id: String,
    pub data_type: String,
    pub values: Vec<String>,
}

/// The facts of one AuthZEN question (#563), as `xacml_request.js`'s
/// `authzen()` takes them: the five members AuthZEN requires, already
/// validated; the realm, the caller and its application, TRUSTED, from the
/// caller's authentication; every path the caller sent; and the catalogue's
/// attributes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuthzenFacts {
    pub subject_type: String,
    pub subject_id: String,
    pub action_name: String,
    pub resource_type: String,
    pub resource_id: String,
    pub realm: String,
    pub caller: String,
    pub application: String,
    pub supplied: Vec<String>,
    pub attributes: Vec<AuthzenAttribute>,
    /// An approved access request the question carries (#1180), sent only
    /// when it names an id.
    pub approval: Option<AuthzenApproval>,
}

/// An approval an AuthZEN question rests on (#1180): its id, the instant
/// it lapses (an `xs:dateTime`) and who approved it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuthzenApproval {
    pub approval_id: String,
    pub approved_until: String,
    pub approver: String,
}

/// The facts of one fine-grained authorization question (#564), as
/// `xacml_request.js`'s `fga()` takes them. Everything but `attributes` and
/// `supplied` is the adapter's own knowledge (`xacml/fga_map.ts`), never the
/// detail's. An empty string is a fact not known.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FgaFacts {
    pub realm: String,
    /// `oauth2` when empty.
    pub protocol: String,
    /// With no id there is no subject-id and no subject kind at all.
    pub subject_id: String,
    pub subject_kind: Option<String>,
    pub client_id: String,
    pub application: String,
    pub detail_type: String,
    pub definition_digest: String,
    /// One of [`FGA_STAGES`].
    pub stage: String,
    /// The action-id; at an issuance stage always [`FGA_GRANT_ACTION`].
    pub action: String,
    /// The resource-id; the detail's type when empty.
    pub resource_id: String,
    pub grant_type: String,
    pub supplied: Vec<String>,
    pub attributes: Vec<AuthzenAttribute>,
}

/// The resource of a User-Managed Access question: the registration's facts,
/// from the store and the PAT that made it — never the client's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UmaResource {
    pub id: String,
    pub resource_type: String,
    pub resource_server: String,
    pub resource_server_declared: bool,
    pub owner: String,
    /// `user` or `application`; anything else is left out.
    pub owner_kind: String,
}

/// Who asks, once anybody is known.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UmaParty {
    pub id: String,
    pub kind: Option<String>,
    pub known: bool,
    pub is_owner: bool,
    /// One of [`UMA_CLAIM_SOURCES`]; anything else is left out.
    pub claim_source: String,
    pub claim_issuer: String,
    /// `true` unless it is said to be `false`.
    pub claim_issuer_declared: Option<bool>,
    pub acr: String,
    pub groups: Vec<String>,
}

/// The facts of one User-Managed Access question (#1168), as
/// `xacml_request.js`'s `uma()` takes them: one resource, one scope, one
/// layer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UmaFacts {
    pub realm: String,
    /// One of [`UMA_LAYERS`]; anything else is `realm`.
    pub layer: String,
    /// One of [`UMA_STAGES`]; anything else is `assess`.
    pub stage: String,
    pub resource: UmaResource,
    pub scope: String,
    pub requesting_party: UmaParty,
    pub client_id: String,
    pub client_grant_declared: bool,
    /// The gathered claims, each VERIFIED; sent in name order.
    pub claims: std::collections::BTreeMap<String, Vec<String>>,
    /// Seconds since the ticket was issued; sent whole, and only when it is
    /// a finite number not below zero.
    pub ticket_age_s: Option<f64>,
    pub rpt_presented: bool,
    pub mode: String,
    /// As every issuance question carries them; sent in key order.
    pub settings: std::collections::BTreeMap<String, Option<Fact>>,
}

/// `one()` in `xacml_request.js`: an empty value is no value.
fn one(value: &str) -> Vec<&str> {
    if value.is_empty() {
        Vec::new()
    } else {
        vec![value]
    }
}

/// `name ? [name] : []`: an absent or empty name is no value.
fn named(name: Option<&str>) -> Option<&str> {
    name.filter(|n| !n.is_empty())
}

/// Builds a [`Request`]. Categories keep the order they were first named,
/// so a request is the same every time it is built and a reader of a logged
/// one finds the subject first.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    include_in_result: bool,
    drop_empty: bool,
    return_policy_id_list: bool,
    categories: Vec<RequestCategory>,
}

impl Default for AuthorizationRequest {
    fn default() -> AuthorizationRequest {
        AuthorizationRequest::new(true, false, true)
    }
}

impl AuthorizationRequest {
    /// `include_in_result`: each attribute asks to be returned with the
    /// result. `drop_empty`: an empty value is left out of its bag rather
    /// than sent as `""` (an empty subject-id is how several PEPs say
    /// "nobody", so the default keeps it).
    pub fn new(
        include_in_result: bool,
        drop_empty: bool,
        return_policy_id_list: bool,
    ) -> AuthorizationRequest {
        AuthorizationRequest {
            include_in_result,
            drop_empty,
            return_policy_id_list,
            categories: Vec::new(),
        }
    }

    /// The category's entry, made the first time it is named. Naming one
    /// with no attributes is how a PEP sends an EMPTY category.
    pub fn category(&mut self, id: &str) -> &mut RequestCategory {
        let index = match self.categories.iter().position(|c| c.category == id)
        {
            Some(index) => index,
            None => {
                self.categories.push(RequestCategory {
                    category: id.to_string(),
                    ..RequestCategory::default()
                });
                self.categories.len() - 1
            }
        };
        &mut self.categories[index]
    }

    /// One attribute, multi-valued: a bag everywhere. An empty list is an
    /// empty bag, which XACML reads as "nobody said". `type_uri` defaults to
    /// string; a boolean fact is always sent as a boolean.
    pub fn attribute<F: Into<Fact>>(
        &mut self,
        category_id: &str,
        attribute_id: &str,
        values: impl IntoIterator<Item = F>,
        type_uri: Option<&str>,
    ) -> &mut Self {
        let drop_empty = self.drop_empty;
        let values = values
            .into_iter()
            .map(Into::into)
            .filter(|fact| !(drop_empty && fact == &Fact::Text(String::new())))
            .map(|fact| match fact {
                Fact::Text(text) => RequestValue {
                    type_uri: type_uri.unwrap_or(types::STRING).to_string(),
                    lexical: text,
                },
                Fact::Boolean(b) => RequestValue {
                    type_uri: types::BOOLEAN.to_string(),
                    lexical: b.to_string(),
                },
            })
            .collect();
        let include_in_result = self.include_in_result;
        self.category(category_id)
            .attributes
            .push(RequestAttribute {
                attribute_id: attribute_id.to_string(),
                issuer: None,
                include_in_result,
                values,
            });
        self
    }

    pub fn subject<F: Into<Fact>>(
        &mut self,
        attribute_id: &str,
        values: impl IntoIterator<Item = F>,
    ) -> &mut Self {
        self.attribute(category::ACCESS_SUBJECT, attribute_id, values, None)
    }

    pub fn resource<F: Into<Fact>>(
        &mut self,
        attribute_id: &str,
        values: impl IntoIterator<Item = F>,
    ) -> &mut Self {
        self.attribute(category::RESOURCE, attribute_id, values, None)
    }

    pub fn action<F: Into<Fact>>(
        &mut self,
        attribute_id: &str,
        values: impl IntoIterator<Item = F>,
    ) -> &mut Self {
        self.attribute(category::ACTION, attribute_id, values, None)
    }

    pub fn environment<F: Into<Fact>>(
        &mut self,
        attribute_id: &str,
        values: impl IntoIterator<Item = F>,
    ) -> &mut Self {
        self.attribute(category::ENVIRONMENT, attribute_id, values, None)
    }

    /// principal and principal_type; the kind is sent only when given.
    pub fn principal(&mut self, name: &str, kind: Option<&str>) -> &mut Self {
        self.subject(attribute::SUBJECT_ID, [name]);
        if let Some(kind) = kind {
            let kind = if SUBJECT_KINDS.contains(&kind) {
                kind
            } else {
                "user"
            };
            self.subject(vocabulary::SUBJECT_KIND, [kind]);
        }
        self
    }

    pub fn roles<F: Into<Fact>>(
        &mut self,
        held: impl IntoIterator<Item = F>,
    ) -> &mut Self {
        self.subject(vocabulary::ROLE, held)
    }

    /// What is being issued FOR or reached; a string unless typed.
    pub fn target(&mut self, id: &str, type_uri: Option<&str>) -> &mut Self {
        self.attribute(
            category::RESOURCE,
            attribute::RESOURCE_ID,
            [id],
            type_uri,
        )
    }

    pub fn requested_action(&mut self, id: &str) -> &mut Self {
        self.action(attribute::ACTION_ID, [id])
    }

    pub fn requested_scopes<F: Into<Fact>>(
        &mut self,
        values: impl IntoIterator<Item = F>,
    ) -> &mut Self {
        self.action(vocabulary::REQUESTED_SCOPE, values)
    }

    pub fn client(&mut self, id: Option<&str>) -> &mut Self {
        self.subject(vocabulary::CLIENT_ID, named(id))
    }

    pub fn audience<F: Into<Fact>>(
        &mut self,
        values: impl IntoIterator<Item = F>,
    ) -> &mut Self {
        self.resource(vocabulary::AUDIENCE, values)
    }

    pub fn protocol(&mut self, name: Option<&str>) -> &mut Self {
        self.environment(vocabulary::PROTOCOL, named(name))
    }

    pub fn grant_type(&mut self, name: Option<&str>) -> &mut Self {
        self.environment(vocabulary::GRANT_TYPE, named(name))
    }

    pub fn mode(&mut self, name: Option<&str>) -> &mut Self {
        self.environment(vocabulary::MODE, named(name))
    }

    /// One setting's value: a boolean as a boolean, anything else a string.
    pub fn setting(&mut self, key: &str, value: Option<Fact>) -> &mut Self {
        let id = format!("{}{}", vocabulary::SETTING_PREFIX, key);
        self.environment(&id, value)
    }

    pub fn stage(&mut self, name: Option<&str>) -> &mut Self {
        self.environment(vocabulary::SCOPE_STAGE, named(name))
    }

    /// The party acting between subject and resource (intermediary-subject).
    pub fn intermediary(&mut self, name: &str) -> &mut Self {
        self.attribute(
            category::INTERMEDIARY_SUBJECT,
            attribute::SUBJECT_ID,
            [name],
            None,
        )
    }

    /// THE FACTS OF AN AUTHZEN QUESTION (#563), in exactly the order and
    /// spelling `xacml_request.js`'s `authzen()` writes them, so a policy
    /// written against one builder's request matches the other's: the
    /// subject's id is XACML's subject-id, the action's name its action-id
    /// and the resource's id its resource-id; everything else reaches the
    /// request only through the catalogue's rows. An empty realm, caller or
    /// application is left out rather than sent as `""`.
    ///
    /// A NODE DEFECT NOT CARRIED OVER: Node's `authzen()` given no action
    /// name or resource id sends the action-id and resource-id
    /// `"undefined"` (`String(undefined)`), where this sends `""`. AuthZEN
    /// requires both members and the service validates them before it
    /// builds, so neither builder is ever asked that; `tests/node_vectors.rs`
    /// pins the difference rather than copying the word.
    pub fn authzen(&mut self, facts: &AuthzenFacts) -> &mut Self {
        self.principal(&facts.subject_id, None);
        self.subject(
            vocabulary::AUTHZEN_SUBJECT_TYPE,
            one(&facts.subject_type),
        );
        self.requested_action(&facts.action_name);
        self.target(&facts.resource_id, None);
        self.resource(
            vocabulary::AUTHZEN_RESOURCE_TYPE,
            one(&facts.resource_type),
        );
        self.protocol(Some("authzen"));
        self.environment(vocabulary::REALM, one(&facts.realm));
        self.environment(vocabulary::AUTHZEN_CALLER, one(&facts.caller));
        self.environment(
            vocabulary::AUTHZEN_APPLICATION,
            one(&facts.application),
        );
        self.environment(
            vocabulary::AUTHZEN_SUPPLIED,
            facts.supplied.iter().map(String::as_str),
        );
        if let Some(approval) = facts
            .approval
            .as_ref()
            .filter(|a| !a.approval_id.is_empty())
        {
            self.environment(
                vocabulary::AUTHZEN_APPROVAL_ID,
                one(&approval.approval_id),
            );
            self.attribute(
                category::ENVIRONMENT,
                vocabulary::AUTHZEN_APPROVED_UNTIL,
                one(&approval.approved_until),
                Some(types::DATETIME),
            );
            self.environment(
                vocabulary::AUTHZEN_APPROVER,
                one(&approval.approver),
            );
        }
        self.rows(&facts.attributes)
    }

    /// The catalogue's rows, each with its own category, identifier and
    /// datatype, the values lexical.
    fn rows(&mut self, rows: &[AuthzenAttribute]) -> &mut Self {
        for row in rows {
            self.attribute(
                &row.category,
                &row.attribute_id,
                row.values.iter().map(String::as_str),
                Some(&row.data_type),
            );
        }
        self
    }

    /// THE FACTS OF A FINE-GRAINED AUTHORIZATION QUESTION (#564), in the
    /// order and spelling of `xacml_request.js`'s `fga()`.
    ///
    /// NOBODY IS NOT A SUBJECT CALLED ''. [`Self::principal`] writes '' for
    /// an absent name, which is how several PEPs say "nobody"; a
    /// fine-grained policy is written by an application's administrator, who
    /// would read `subject-id == ""` as a person with an empty name. So with
    /// no id there is NO subject-id and no subject kind — an empty bag, which
    /// a policy tests as absence. At an ISSUANCE stage the action is
    /// [`FGA_GRANT_ACTION`] whatever is given, so no caller can ask an
    /// issuance question as anything else.
    pub fn fga(&mut self, facts: &FgaFacts) -> &mut Self {
        let issuance = FGA_ISSUANCE_STAGES.contains(&facts.stage.as_str());
        if !facts.subject_id.is_empty() {
            self.principal(&facts.subject_id, facts.subject_kind.as_deref());
        }
        self.client(Some(&facts.client_id));
        let action = if issuance {
            FGA_GRANT_ACTION
        } else {
            facts.action.as_str()
        };
        if !action.is_empty() {
            self.requested_action(action);
        }
        let target = if facts.resource_id.is_empty() {
            &facts.detail_type
        } else {
            &facts.resource_id
        };
        self.target(target, None);
        self.resource(vocabulary::FGA_APPLICATION, one(&facts.application));
        self.resource(vocabulary::FGA_DETAIL_TYPE, one(&facts.detail_type));
        self.resource(
            vocabulary::FGA_DEFINITION_DIGEST,
            one(&facts.definition_digest),
        );
        self.protocol(Some(if facts.protocol.is_empty() {
            "oauth2"
        } else {
            &facts.protocol
        }));
        self.environment(vocabulary::REALM, one(&facts.realm));
        self.environment(vocabulary::FGA_STAGE, one(&facts.stage));
        if !facts.grant_type.is_empty() {
            self.grant_type(Some(&facts.grant_type));
        }
        self.environment(
            vocabulary::FGA_SUPPLIED,
            facts.supplied.iter().map(String::as_str),
        );
        self.rows(&facts.attributes)
    }

    /// AN AUTHZEN QUESTION DECIDED BY AN APPLICATION'S FINE-GRAINED POLICY
    /// (#564, P4): chained after [`Self::authzen`], it adds the two facts an
    /// FGA policy reads to know what it is asked — the application whose
    /// policy decides, and the stage, always `access`. Nothing else: the
    /// subject, action and resource are AuthZEN's, already written, and
    /// writing them again would make a bag of two. `fgaAccess()`.
    pub fn fga_access(&mut self, application: &str) -> &mut Self {
        self.resource(vocabulary::FGA_APPLICATION, one(application));
        self.environment(vocabulary::FGA_STAGE, ["access"]);
        self
    }

    /// THE FACTS OF A USER-MANAGED ACCESS QUESTION (#1168), in the order and
    /// spelling of `xacml_request.js`'s `uma()`. The action-id is forced by
    /// the layer, so no caller can ask the realm's or the resource server's
    /// policy as anything else; the scope is `urn:sts:xacml:uma:scope` on
    /// every layer. A fact not known is left out; the booleans are always
    /// sent. With no requesting party's id there is no subject-id at all,
    /// which lets a MustBePresent designator on it become the
    /// missing-attribute status the PEP reads as `need_info`.
    pub fn uma(&mut self, facts: &UmaFacts) -> &mut Self {
        let layer = if UMA_LAYERS.contains(&facts.layer.as_str()) {
            facts.layer.as_str()
        } else {
            "realm"
        };
        let stage = if UMA_STAGES.contains(&facts.stage.as_str()) {
            facts.stage.as_str()
        } else {
            "assess"
        };
        let resource = &facts.resource;
        let party = &facts.requesting_party;
        let boolean = |value: bool| [Fact::Boolean(value)];
        if !party.id.is_empty() {
            self.principal(&party.id, party.kind.as_deref());
        }
        self.client(Some(&facts.client_id));
        self.subject(
            vocabulary::UMA_REQUESTING_PARTY_KNOWN,
            boolean(party.known),
        );
        self.subject(
            vocabulary::UMA_REQUESTING_PARTY_IS_OWNER,
            boolean(party.is_owner),
        );
        let source = if UMA_CLAIM_SOURCES.contains(&party.claim_source.as_str())
        {
            one(&party.claim_source)
        } else {
            Vec::new()
        };
        self.subject(vocabulary::UMA_CLAIM_SOURCE, source);
        self.subject(vocabulary::UMA_CLAIM_ISSUER, one(&party.claim_issuer));
        self.subject(
            vocabulary::UMA_CLAIM_ISSUER_DECLARED,
            boolean(party.claim_issuer_declared != Some(false)),
        );
        self.subject(
            vocabulary::UMA_CLIENT_GRANT_DECLARED,
            boolean(facts.client_grant_declared),
        );
        self.subject(vocabulary::ACR, one(&party.acr));
        self.subject(
            vocabulary::UMA_REQUESTING_PARTY_GROUP,
            party
                .groups
                .iter()
                .map(String::as_str)
                .filter(|g| !g.is_empty()),
        );
        for (name, values) in &facts.claims {
            self.subject(
                &format!("{}{}", vocabulary::UMA_CLAIM_PREFIX, name),
                values.iter().map(String::as_str),
            );
        }
        let action = match layer {
            "owner" => facts.scope.as_str(),
            "fga" => UMA_FGA_ACTION,
            _ => UMA_PERMISSION_ACTION,
        };
        if !action.is_empty() {
            self.requested_action(action);
        }
        self.action(vocabulary::UMA_SCOPE, one(&facts.scope));
        self.target(&resource.id, None);
        self.resource(
            vocabulary::UMA_RESOURCE_TYPE,
            one(&resource.resource_type),
        );
        self.resource(
            vocabulary::UMA_RESOURCE_SERVER,
            one(&resource.resource_server),
        );
        self.resource(
            vocabulary::UMA_RESOURCE_SERVER_DECLARED,
            boolean(resource.resource_server_declared),
        );
        self.resource(vocabulary::UMA_OWNER, one(&resource.owner));
        let owner_kind =
            if SUBJECT_KINDS.contains(&resource.owner_kind.as_str()) {
                one(&resource.owner_kind)
            } else {
                Vec::new()
            };
        self.resource(vocabulary::UMA_OWNER_KIND, owner_kind);
        self.protocol(Some("uma"));
        self.grant_type(Some(UMA_GRANT_TYPE));
        self.environment(vocabulary::REALM, one(&facts.realm));
        self.environment(vocabulary::UMA_LAYER, [layer]);
        self.environment(vocabulary::UMA_STAGE, [stage]);
        // `String(Math.floor(age))`, so a large age is spelt as JavaScript
        // spells it.
        let age: Vec<String> = facts
            .ticket_age_s
            .filter(|age| age.is_finite() && *age >= 0.0)
            .map(|age| crate::value::js_number_string(age.floor()))
            .into_iter()
            .collect();
        self.attribute(
            category::ENVIRONMENT,
            vocabulary::UMA_TICKET_AGE,
            age,
            Some(types::INTEGER),
        );
        self.environment(
            vocabulary::UMA_RPT_PRESENTED,
            boolean(facts.rpt_presented),
        );
        if !facts.mode.is_empty() {
            self.mode(Some(&facts.mode));
        }
        for (key, value) in &facts.settings {
            self.setting(key, value.clone());
        }
        self
    }

    /// The request, in the engine's shape.
    pub fn build(&self) -> Request {
        Request {
            return_policy_id_list: self.return_policy_id_list,
            combined_decision: false,
            categories: self.categories.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_keep_first_named_order_and_empty_ones() {
        let mut req = AuthorizationRequest::default();
        req.category(category::ACCESS_SUBJECT);
        req.category(category::ENVIRONMENT);
        req.target("urn:x", Some(types::ANYURI))
            .requested_action("GET");
        let built = req.build();
        let order: Vec<&str> = built
            .categories
            .iter()
            .map(|c| c.category.as_str())
            .collect();
        assert_eq!(
            order,
            [
                category::ACCESS_SUBJECT,
                category::ENVIRONMENT,
                category::RESOURCE,
                category::ACTION
            ]
        );
        assert!(built.categories[0].attributes.is_empty());
        assert_eq!(
            built.categories[2].attributes[0].values[0].type_uri,
            types::ANYURI
        );
    }

    #[test]
    fn booleans_are_typed_and_empties_dropped_on_request() {
        let mut req = AuthorizationRequest::new(true, true, true);
        req.environment("x", [Fact::Boolean(true)]);
        req.subject("y", ["", "a"]);
        let built = req.build();
        assert_eq!(
            built.categories[0].attributes[0].values[0].type_uri,
            types::BOOLEAN
        );
        assert_eq!(built.categories[1].attributes[0].values.len(), 1);
    }
}
