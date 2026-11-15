// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The vocabularies of `common/applications.js`: the application KINDS,
//! the declared protocol FAMILIES (`PROTOCOLS`) and the model's SCHEMA
//! table (`ModelTables.schema('application')`), with the indexes Node
//! builds from them at load (`ATTRIBUTE_BY_NAME`, `PROTOCOL_BY_ID`,
//! `PROTOCOLS_BY_KIND`, `RETURN_ADDRESS_ATTRIBUTES`).
//!
//! The SCHEMA is read from `generated/application.schema.json`, which
//! `models/lib/rust_lib.mjs`'s `renderRustApplicationSchema()` writes from
//! the same model Node's `models/generated/application.schema.json` comes
//! from: one table, read by both runtimes. The KINDS and PROTOCOLS are
//! literals in the Node source, copied here verbatim (sentences and all,
//! because the console and the API publish them).

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;
use serde_json::Value;

/// One application kind (`KINDS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindRow {
    pub kind: &'static str,
    pub label: &'static str,
    pub what: &'static str,
}

/// One declared protocol family (`PROTOCOLS`). An empty attribute name is
/// Node's `''` (or a member the row does not carry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolRow {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: &'static str,
    pub kinds: &'static [&'static str],
    pub identifier_attribute: &'static str,
    pub redirect_attribute: &'static str,
    pub logout_attribute: &'static str,
    pub secret_attribute: &'static str,
    pub delivery_attribute: &'static str,
    pub events_attribute: &'static str,
    pub what: &'static str,
}

#[rustfmt::skip]
mod literal {
    use super::{KindRow, ProtocolRow};
    pub static KINDS: &[KindRow] = &[
        KindRow {
            kind: "oauth2-client",
            label: "OAuth 2.0 client",
            what: "A client_id presented at the authorization or token endpoint.",
        },
        KindRow {
            kind: "oauth2-resource-server",
            label: "OAuth 2.0 resource server",
            what: "An API access tokens are addressed to, named by its oauthAudience. It is never a client: its client_id is refused at every endpoint a client presents itself at.",
        },
        KindRow {
            kind: "oidc-relying-party",
            label: "OpenID Connect relying party",
            what: "The same client_id where the request asked for the openid scope — a relying party is an OAuth client that also wants an ID Token, so a record commonly carries both kinds.",
        },
        KindRow {
            kind: "saml2-service-provider",
            label: "SAML 2.0 service provider",
            what: "The audience of a SAML 2.0 assertion this service issued.",
        },
        KindRow {
            kind: "saml11-relying-party",
            label: "SAML 1.1 relying party",
            what: "The audience of a SAML 1.1 assertion — which is what a WS-Federation relying party is handed by default, so these two commonly appear together.",
        },
        KindRow {
            kind: "wsfed-relying-party",
            label: "WS-Federation application",
            what: "A wtrealm from a wsignin1.0 request (section 13.2.1).",
        },
        KindRow {
            kind: "wstrust-relying-party",
            label: "WS-Trust relying party",
            what: "An AppliesTo from a RequestSecurityToken — the service the token is for.",
        },
        KindRow {
            kind: "oid4vp-verifier",
            label: "OpenID4VP verifier",
            what: "The client_id this service's Verifier presents in an Authorization Request.",
        },
        KindRow {
            kind: "federation-identity-provider",
            label: "Federated identity provider",
            what: "A FOREIGN identity service this instance federates with as a service provider — it authenticates people TO this service rather than asking anything OF it, which makes it the one kind here that is not a client. It is in this registry anyway, because the question this container exists to answer is \"what parties has this service dealt with?\" and a federation partner is the most consequential of them: it is a party whose signature this service BELIEVES. See federation/CLAUDE.md. The relationship itself — the endpoints, the certificate, the attribute mapping — lives under ou=federations and not here; this record is the partner as a party, and that one is the arrangement with it.",
        },
        KindRow {
            kind: "kerberos-service",
            label: "Kerberos service principal",
            what: "A service principal name a ticket was issued for, or that the acceptor was asked to be.",
        },
        KindRow {
            kind: "gnap-client",
            label: "GNAP client instance",
            what: "A key (or instance identifier) that made a GNAP grant request.",
        },
        KindRow {
            kind: "gnap-resource-server",
            label: "GNAP resource server",
            what: "A key that called the RS-facing API: introspection, resource set registration, or a downstream token derivation.",
        },
    ];

    pub static PROTOCOLS: &[ProtocolRow] = &[
        ProtocolRow {
            id: "oauth2",
            label: "OAuth 2.0",
            kind: "oauth2-client",
            kinds: &["oauth2-client", "oidc-relying-party"],
            identifier_attribute: "oauthClientId",
            redirect_attribute: "oauthRedirectUri",
            logout_attribute: "oauthPostLogoutRedirectUri",
            secret_attribute: "oauthClientSecret",
            delivery_attribute: "",
            events_attribute: "",
            what: "A client_id at the authorization and token endpoints.",
        },
        ProtocolRow {
            id: "oidc",
            label: "OpenID Connect",
            kind: "oidc-relying-party",
            kinds: &["oidc-relying-party"],
            identifier_attribute: "oauthClientId",
            redirect_attribute: "oauthRedirectUri",
            logout_attribute: "oauthPostLogoutRedirectUri",
            secret_attribute: "oauthClientSecret",
            delivery_attribute: "",
            events_attribute: "",
            what: "The same client_id asking for the openid scope, and therefore for an ID Token. A relying party IS an OAuth client, so these two are usually ticked together; ticking this one alone is legal and says the entry is for an OIDC flow.",
        },
        ProtocolRow {
            id: "saml2",
            label: "SAML 2.0",
            kind: "saml2-service-provider",
            kinds: &["saml2-service-provider"],
            identifier_attribute: "samlEntityId",
            redirect_attribute: "samlAssertionConsumerService",
            logout_attribute: "samlSingleLogoutService",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A service provider entityID in the Web Browser SSO profile at /saml2, or the audience of a SAML 2.0 assertion issued anywhere else here.",
        },
        ProtocolRow {
            id: "saml11",
            label: "SAML 1.1",
            kind: "saml11-relying-party",
            kinds: &["saml11-relying-party"],
            identifier_attribute: "samlEntityId",
            redirect_attribute: "samlAssertionConsumerService",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A relying party of the two browser profiles at /saml11 — and what a WS-Federation application is handed by default, which is why these two are commonly ticked together.",
        },
        ProtocolRow {
            id: "wsfed",
            label: "WS-Federation",
            kind: "wsfed-relying-party",
            kinds: &["wsfed-relying-party"],
            identifier_attribute: "wsfedRealm",
            redirect_attribute: "wsfedReplyUrl",
            logout_attribute: "wsfedSignOutUri",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A wtrealm in a wsignin1.0 request (section 13.2.1).",
        },
        ProtocolRow {
            id: "wstrust",
            label: "WS-Trust",
            kind: "wstrust-relying-party",
            kinds: &["wstrust-relying-party"],
            identifier_attribute: "wstrustAppliesTo",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "An AppliesTo in a RequestSecurityToken — the service the token is issued FOR.",
        },
        ProtocolRow {
            id: "krb5",
            label: "Kerberos v5",
            kind: "kerberos-service",
            kinds: &["kerberos-service"],
            identifier_attribute: "krb5ServicePrincipalName",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A service principal name a ticket may be issued for, or that the acceptor may be asked to be. This covers SPNEGO (HTTP Negotiate, RFC 4559) to a Kerberos-protected service, which carries the same ticket. Signing people in to this application with SPNEGO is not a family: list spnego among the first-factor mechanisms of the authentication policy the application names (appAuthnPolicy), and declare the protocol the application gets its tokens or assertions through.",
        },
        ProtocolRow {
            id: "oid4vci",
            label: "OpenID4VCI",
            kind: "",
            kinds: &[],
            identifier_attribute: "oauthClientId",
            redirect_attribute: "oauthRedirectUri",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A wallet collecting a verifiable credential from the issuer. The wallet presents no application identifier of its own on that flow — it authenticates as an OAuth client and is recorded as one — so this family has no kind and nothing will ever mark it seen.",
        },
        ProtocolRow {
            id: "oid4vp",
            label: "OpenID4VP",
            kind: "oid4vp-verifier",
            kinds: &["oid4vp-verifier"],
            identifier_attribute: "oid4vpClientId",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A verifier client_id in an Authorization Request asking for a presentation.",
        },
        ProtocolRow {
            id: "federation",
            label: "Federation",
            kind: "federation-identity-provider",
            kinds: &["federation-identity-provider"],
            identifier_attribute: "federationPartnerId",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A FOREIGN identity service on the other side of a federation relationship. It is the one thing in this registry that is not a client of this service — it authenticates people TO it. Its SIGHTING is recorded under whichever protocol the relationship speaks, so the protocol label on such an entry is indistinguishable from an ordinary client's and the KIND is the only thing that tells them apart — which is the whole reason this table matches on kinds. The relationship itself lives under ou=federations; see federation/CLAUDE.md.",
        },
        ProtocolRow {
            id: "ldap",
            label: "LDAP",
            kind: "",
            kinds: &[],
            identifier_attribute: "ldapBindDn",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A directory client binding on 389 or LDAPS 636. EVERY BIND HERE SUCCEEDS and none of them names an application, so nothing will ever record a sighting for this family — ticking it says what the entry is for and nothing more.",
        },
        ProtocolRow {
            id: "scim",
            label: "SCIM 2.0",
            kind: "",
            kinds: &[],
            identifier_attribute: "scimClientId",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A provisioning client at /scim/v2. That surface authenticates its CALLER — in any of the six schemes RFC 7644 section 2 names — rather than an application identifier, so, as with LDAP, nothing writes this family into appProtocol.",
        },
        ProtocolRow {
            id: "spiffe",
            label: "SPIFFE",
            kind: "",
            kinds: &[],
            identifier_attribute: "spiffeWorkloadId",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A workload on the Workload API, or an agent or admin on the SPIRE Server API. A SPIFFE identity gets an entry of its own under ou=spiffe rather than one here (see spiffe/CLAUDE.md), so this is a declaration and never a record.",
        },
        ProtocolRow {
            id: "mtls",
            label: "TLS / mutual TLS",
            kind: "",
            kinds: &[],
            identifier_attribute: "oauthTlsClientAuthSubjectDn",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A client authenticating to the token endpoint under RFC 8705. A TLS client certificate issued to the application from its Credentials section authenticates it under tls_client_auth with nothing registered; a certificate from another authority needs ONE of the five subject parameters (oauthTlsClientAuthSubjectDn and the four oauthTlsClientAuthSan* attributes), and self_signed_tls_client_auth reads the jwks x5c or oauthTlsClientCertificateThumbprint — so ticking this box is the note to self, and those are the configuration.",
        },
        ProtocolRow {
            id: "ssf",
            label: "Shared Signals",
            kind: "ssf-receiver",
            kinds: &["ssf-receiver"],
            identifier_attribute: "ssfReceiverId",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "ssfDeliveryEndpoint",
            events_attribute: "ssfAllowedEvents",
            what: "A Shared Signals RECEIVER: something that agrees a stream at /ssf/stream and is then delivered Security Event Tokens. Its identifier is whatever it authenticated as when it created the stream, which is the `aud` those SETs carry, and its delivery endpoint is where a push goes. Neither is read as a permission — a stream carries its own delivery endpoint and this entry is where an operator writes down what a receiver is EXPECTED to be, beside everything else that application is.",
        },
        ProtocolRow {
            id: "gnap",
            label: "GNAP",
            kind: "gnap-client",
            kinds: &["gnap-client", "gnap-resource-server"],
            identifier_attribute: "gnapInstanceId",
            redirect_attribute: "gnapFinishUri",
            logout_attribute: "",
            secret_attribute: "gnapSymmetricKey",
            delivery_attribute: "",
            events_attribute: "",
            what: "A GNAP client instance, or a GNAP resource server, or both: a party that proves possession of a key to /gnap (RFC 9635) or to the RS-facing API (RFC 9767). Its key is gnapKey (a public key object) or gnapKeyReference with a sealed gnapSymmetricKey; its finish URIs are return addresses like any other; a resource server carries the locations it answers for and, once it has registered a resource set, the macaroon root key it verifies with.",
        },
        ProtocolRow {
            id: "uma",
            label: "UMA 2.0",
            kind: "",
            kinds: &[],
            identifier_attribute: "",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A User-Managed Access 2.0 resource server: an OAuth client that obtains a protection API token for /uma, registers the resources it holds for a resource owner, asks permission tickets for them, and is the audience of the requesting party tokens issued for them. Declaring the family is what admits it; umaOwnsResources lets the application itself be an owner.",
        },
        ProtocolRow {
            id: "acme",
            label: "ACME",
            kind: "",
            kinds: &[],
            identifier_attribute: "",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "Certificate enrollment over ACME (RFC 8555) at /enroll/acme: an ACME account bound to this application by an External Account Binding key. Its certificates name urn:sts:application:<id> and are kept on this entry.",
        },
        ProtocolRow {
            id: "est",
            label: "EST",
            kind: "",
            kinds: &[],
            identifier_attribute: "",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "Certificate enrollment over EST (RFC 7030) at /.well-known/est: this application authenticating with its client id and secret, or with a certificate this realm issued it.",
        },
        ProtocolRow {
            id: "scep",
            label: "SCEP",
            kind: "",
            kinds: &[],
            identifier_attribute: "",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "Certificate enrollment over SCEP (RFC 8894) at /enroll/scep: a single-use challenge password made for this application.",
        },
        ProtocolRow {
            id: "did",
            label: "Decentralized Identifier (DID)",
            kind: "",
            kinds: &[],
            identifier_attribute: "",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A W3C DID describing this application: did:web:<host>[:realm:<id>]:applications:<identifier>, its document advertised by this service at <base>/applications/<identifier>/did.json. The document publishes the public keys in didPublicKeyJwk (generate a key pair, or paste the public half of your own), the services in didService and the URIs in didAlsoKnownAs. Nothing is issued through this family: it is how the application is identified and its keys found.",
        },
        ProtocolRow {
            id: "secret-destination",
            label: "Secret push destination",
            kind: "",
            kinds: &[],
            identifier_attribute: "",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A secrets manager this service PUSHES a service account's rotated password to (#221): AWS Secrets Manager, Google Cloud Secret Manager, Azure Key Vault, or a HashiCorp Vault / OpenBao KV version 2 engine — and, in development mode only, a file. The secret must already exist there: a push writes a new version and never creates one. The write credential (secretDestCredential) is sealed on this entry and never shown. Nothing is issued through this family.",
        },
        ProtocolRow {
            id: "scim-client",
            label: "SCIM client (outbound provisioning)",
            kind: "",
            kinds: &[],
            identifier_attribute: "",
            redirect_attribute: "",
            logout_attribute: "",
            secret_attribute: "",
            delivery_attribute: "",
            events_attribute: "",
            what: "A remote SCIM 2.0 service provider this service PUSHES users and groups to (#552): RFC 7643 resources over RFC 7644, created, replaced or patched, deactivated or deleted as the directory changes, and reconciled on demand or on a schedule. It authenticates with HTTP Basic, an OAuth 2.0 client_credentials token, or a TLS client certificate; every credential is sealed on this entry and never shown. Configured on Protocols → SCIM → Clients. Nothing is issued through this family.",
        },
    ];
}

pub use literal::{KINDS, PROTOCOLS};

/// One row of the application SCHEMA, every member Node reads.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttributeRow {
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub what: String,
    /// `false`, `'set'` or `'multi'`; read as text, '' for `false`.
    #[serde(default, deserialize_with = "editable")]
    pub editable: String,
    #[serde(default)]
    pub families: Vec<String>,
    #[serde(default)]
    pub family_why: String,
    #[serde(default)]
    pub overrides: String,
    #[serde(default)]
    pub strict_override: bool,
    #[serde(default)]
    pub identifier: bool,
    #[serde(default)]
    pub identifier_name: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub standard: bool,
}

fn editable<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Value::deserialize(d)? {
        Value::String(s) => s,
        Value::Bool(true) => "true".to_string(),
        _ => String::new(),
    })
}

/// One object class of the SCHEMA.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ClassRow {
    pub name: String,
}

/// `ModelTables.schema('application')`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    #[serde(default)]
    pub object_classes: Vec<ClassRow>,
    #[serde(default)]
    pub attributes: Vec<AttributeRow>,
}

#[derive(Deserialize)]
struct Bundle {
    schema: Schema,
}

/// The SCHEMA, and the indexes Node builds from it and the two literals.
#[derive(Debug, Default)]
pub struct Tables {
    pub schema: Schema,
    by_name: HashMap<String, usize>,
    pub kind_ids: Vec<&'static str>,
    pub protocol_ids: Vec<&'static str>,
    protocols_by_kind: HashMap<&'static str, Vec<&'static str>>,
    /// `RETURN_ADDRESS_ATTRIBUTES`: every family's redirect attribute,
    /// once, in table order.
    pub return_address_attributes: Vec<&'static str>,
}

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let schema = serde_json::from_str::<Bundle>(include_str!(
        "../generated/application.schema.json"
    ))
    .map(|b| b.schema)
    .unwrap_or_default();
    Tables::from_schema(schema)
});

impl Tables {
    // A HOT PATH: every check asks it, so no span.
    /// The tables the crate was built with.
    pub fn get() -> &'static Tables {
        &TABLES
    }

    fn from_schema(schema: Schema) -> Tables {
        let mut by_name = HashMap::new();
        for (i, row) in schema.attributes.iter().enumerate() {
            // `ATTRIBUTE_BY_NAME[row.name] = row`: a later row wins.
            by_name.insert(row.name.clone(), i);
        }
        let mut protocols_by_kind: HashMap<&'static str, Vec<&'static str>> =
            HashMap::new();
        for row in PROTOCOLS {
            for kind in row.kinds {
                let ids = protocols_by_kind.entry(kind).or_default();
                if !ids.contains(&row.id) {
                    ids.push(row.id);
                }
            }
        }
        let mut return_address_attributes = Vec::new();
        for row in PROTOCOLS {
            let name = row.redirect_attribute;
            if !name.is_empty() && !return_address_attributes.contains(&name) {
                return_address_attributes.push(name);
            }
        }
        Tables {
            schema,
            by_name,
            kind_ids: KINDS.iter().map(|k| k.kind).collect(),
            protocol_ids: PROTOCOLS.iter().map(|p| p.id).collect(),
            protocols_by_kind,
            return_address_attributes,
        }
    }

    // A HOT PATH: every check asks it, so no span.
    /// `ATTRIBUTE_BY_NAME[name]`.
    pub fn attribute(&self, name: &str) -> Option<&AttributeRow> {
        self.by_name.get(name).map(|i| &self.schema.attributes[*i])
    }

    // A HOT PATH: every check asks it, so no span.
    /// `protocolRow(id)`.
    pub fn protocol(&self, id: &str) -> Option<&'static ProtocolRow> {
        PROTOCOLS.iter().find(|p| p.id == id)
    }

    /// `editableAttributes(mode)`: the rows whose `editable` is the mode,
    /// or every editable row for none.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn editable_attributes(&self, mode: &str) -> Vec<&AttributeRow> {
        self.schema
            .attributes
            .iter()
            .filter(|r| {
                if mode.is_empty() {
                    !r.editable.is_empty()
                } else {
                    r.editable == mode
                }
            })
            .collect()
    }

    /// `protocolIdsForKinds(kinds)`: the families a list of kinds means,
    /// in table order.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn protocol_ids_for_kinds(&self, kinds: &[String]) -> Vec<String> {
        let mut out: Vec<&str> = Vec::new();
        for kind in kinds {
            if let Some(ids) = self.protocols_by_kind.get(kind.as_str()) {
                for id in ids {
                    if !out.contains(id) {
                        out.push(id);
                    }
                }
            }
        }
        self.protocol_ids
            .iter()
            .filter(|id| out.contains(id))
            .map(|id| id.to_string())
            .collect()
    }

    /// The object classes an entry is written with
    /// (`SCHEMA.objectClasses.map(name)`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn object_classes(&self) -> Vec<String> {
        self.schema
            .object_classes
            .iter()
            .map(|c| c.name.clone())
            .collect()
    }
}
