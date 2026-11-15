// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The directory's generated tables (#1390), as `ldap/ldap_server.js`,
//! `common/model_tables.ts` and `common/domain_map.ts` read them.
//!
//! `src/generated/directory.json` is `models/lib/rust_lib.mjs`'s
//! `renderRustDirectory()`: the name lists (`directory.names.json`), the
//! facts and links, every authored object's `<id>.schema.json` and
//! `<id>.fields.json`, and the concepts (`domain.json`), each exactly what
//! the image build writes for Node. Nothing here restates a table; what is
//! derived (the spelling table, the policies' defaults) is derived the way
//! the Node module derives it, and says which function it ports.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;
use serde_json::Value as Json;

/// The bundle, parsed once. A bundle that does not parse is a build that
/// was not regenerated; the directory then knows no names, which every
/// vector test shows at once.
static MODEL: LazyLock<DirectoryModel> = LazyLock::new(|| {
    DirectoryModel::parse(include_str!("generated/directory.json"))
        .unwrap_or_default()
});

/// The spellings `learnName()` takes from the credential claim catalogue
/// (`oid4vc/vc_claims.ts`'s `CANONICAL_NAMES`) that neither of the model's
/// name lists holds. The catalogue is a literal in the Node source, not a
/// model table, so the list is pinned here and the vectors hold it to what
/// Node learns (`outsideSpellings`).
pub const CREDENTIAL_CLAIM_SPELLINGS: &[&str] = &[
    "salutation",
    "birthFamilyName",
    "birthGivenName",
    "birthMiddleName",
    "alsoKnownAs",
    "placeOfBirthCountry",
    "placeOfBirthRegion",
    "placeOfBirthLocality",
    "middleName",
    "timeZone",
    "pictureUrl",
    "profileUrl",
    "employeeStatus",
];

/// The directory's three name lists (`models/directory/names.tsp`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Names {
    /// Attribute types somebody else published (`STANDARD_NAMES`).
    #[serde(default)]
    pub standard: Vec<String>,
    /// This service's own (`OWN_NAMES`).
    #[serde(default)]
    pub own: Vec<String>,
    /// The credentials (`SECRET_ATTRIBUTES`), lower-cased.
    #[serde(default)]
    pub secret: Vec<String>,
}

/// One attribute of an object's schema.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SchemaAttribute {
    pub name: String,
    #[serde(default)]
    pub kind: Option<String>,
}

/// One object class of an object's schema.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SchemaClass {
    pub name: String,
}

/// An authored object's `<id>.schema.json`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    #[serde(default)]
    pub container: Option<String>,
    #[serde(default)]
    pub object_classes: Vec<SchemaClass>,
    #[serde(default)]
    pub attributes: Vec<SchemaAttribute>,
    #[serde(default)]
    pub person_attributes: Vec<SchemaAttribute>,
}

/// One field of a policy's `<id>.fields.json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyField {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub attribute: Option<String>,
    #[serde(default)]
    pub dflt: Json,
}

/// A policy's `<id>.fields.json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Fields {
    #[serde(default)]
    pub fields: Vec<PolicyField>,
}

/// Where a concept field is stored (`from`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FieldFrom {
    pub attr: String,
    #[serde(default)]
    pub on: Option<String>,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub transform: Option<String>,
}

/// One field of a concept, as `domain.json` holds it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConceptField {
    pub name: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub array: bool,
    #[serde(default)]
    pub from: Option<FieldFrom>,
    /// The sentence saying how it is derived; present means derived.
    #[serde(default)]
    pub derived: Option<String>,
    #[serde(default)]
    pub embedded: bool,
    #[serde(default)]
    pub concept: Option<String>,
}

/// A domain concept (`models/domain/*.tsp`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Concept {
    pub name: String,
    /// The directory object it is made from, for an entry concept.
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub record: Option<String>,
    #[serde(default)]
    pub fields: Vec<ConceptField>,
}

#[derive(Debug, Default, Deserialize)]
struct Bundle {
    #[serde(default)]
    names: Names,
    #[serde(default)]
    facts: Json,
    #[serde(default)]
    links: Json,
    #[serde(default)]
    schemas: HashMap<String, Schema>,
    #[serde(default)]
    fields: HashMap<String, Fields>,
    #[serde(default)]
    concepts: Vec<Concept>,
}

/// The directory's tables, and what `ldap_server.js` derives from them.
#[derive(Debug, Default)]
pub struct DirectoryModel {
    pub names: Names,
    pub facts: Json,
    pub links: Json,
    pub schemas: HashMap<String, Schema>,
    pub fields: HashMap<String, Fields>,
    pub concepts: Vec<Concept>,
    concept_index: HashMap<String, usize>,
    canonical: HashMap<String, String>,
    secret: Vec<String>,
}

/// The objects whose schema `ldap_server.js` learns spellings from, in the
/// order it learns them after the name lists and the two catalogues — the
/// applications, federation and roles schemas, then each policy's (with the
/// attributes it keeps on a person), the service-account schema's person
/// attributes, and the two XACML registers'. First spelling wins.
const LEARNT: &[(&str, bool, bool)] = &[
    ("application", true, false),
    ("federationRelationship", true, false),
    ("role", true, false),
    ("policy.password", true, true),
    ("policy.authn", true, true),
    ("policy.serviceAccount", true, false),
    ("serviceAccount", false, true),
    ("policy.passkey", true, true),
    ("policy.locale", true, true),
    ("policy.attributes", true, false),
    ("policy.postLogin", true, false),
    ("xacmlPolicy", true, false),
    ("xacmlPep", true, false),
];

impl DirectoryModel {
    /// The model the crate was built with.
    pub fn get() -> &'static DirectoryModel {
        &MODEL
    }

    /// Parses a bundle and derives the spelling table.
    #[tracing::instrument(level = "debug", skip(text))]
    pub fn parse(text: &str) -> Result<DirectoryModel, serde_json::Error> {
        let bundle: Bundle = serde_json::from_str(text)?;
        let mut model = DirectoryModel {
            secret: bundle
                .names
                .secret
                .iter()
                .map(|s| s.to_lowercase())
                .collect(),
            names: bundle.names,
            facts: bundle.facts,
            links: bundle.links,
            schemas: bundle.schemas,
            fields: bundle.fields,
            concept_index: HashMap::new(),
            canonical: HashMap::new(),
            concepts: bundle.concepts,
        };
        model.concept_index = model
            .concepts
            .iter()
            .enumerate()
            .map(|(i, c)| (c.name.clone(), i))
            .collect();
        model.learn_all();
        Ok(model)
    }

    // `learnName()` over every source, in `ldap_server.js`'s order: the
    // standard list, this service's own, the inetOrgPerson class (which
    // adds nothing the standard list lacks), the claim catalogue, then the
    // schemas. A second spelling is not learnt.
    fn learn_all(&mut self) {
        let mut order: Vec<String> = Vec::new();
        order.extend(self.names.standard.iter().cloned());
        order.extend(self.names.own.iter().cloned());
        order.extend(CREDENTIAL_CLAIM_SPELLINGS.iter().map(|s| s.to_string()));
        for (id, attributes, person) in LEARNT {
            if let Some(schema) = self.schemas.get(*id) {
                if *attributes {
                    order.extend(schema.attributes.iter().map(|a| a.name.clone()));
                }
                if *person {
                    order.extend(
                        schema.person_attributes.iter().map(|a| a.name.clone()),
                    );
                }
            }
        }
        for spelling in order {
            self.canonical
                .entry(spelling.to_lowercase())
                .or_insert(spelling);
        }
    }

    /// `canonicalName()`: a lower-cased attribute description spelt as its
    /// type is published, its options (`;binary`) kept as written.
    // A HOT PATH: once per attribute of every entry a search sends, so no
    // span, which would drown the log.
    pub fn canonical_name(&self, lower: &str) -> String {
        match lower.find(';') {
            Some(at) if at > 0 => {
                let ty = &lower[..at];
                let spelt = self.canonical.get(ty).map(String::as_str);
                format!("{}{}", spelt.unwrap_or(ty), &lower[at..])
            }
            _ => self
                .canonical
                .get(lower)
                .cloned()
                .unwrap_or_else(|| lower.to_string()),
        }
    }

    /// `isSecretAttribute()`: one of `SECRET_ATTRIBUTES`.
    // A HOT PATH: once per attribute of every entry a search considers.
    pub fn is_secret(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.secret.iter().any(|s| *s == lower)
    }

    /// A concept by its name.
    pub fn concept(&self, name: &str) -> Option<&Concept> {
        self.concept_index.get(name).map(|i| &self.concepts[*i])
    }

    /// A policy field's default (`dflt`), by the field's key.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn field_default(&self, object: &str, key: &str) -> Json {
        self.fields
            .get(object)
            .and_then(|f| f.fields.iter().find(|r| r.key == key))
            .map(|r| r.dflt.clone())
            .unwrap_or(Json::Null)
    }

    /// The first object class an object's schema names (the service-account
    /// schema's is `stsServiceAccount`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn object_class(&self, object: &str) -> String {
        self.schemas
            .get(object)
            .and_then(|s| s.object_classes.first())
            .map(|c| c.name.clone())
            .unwrap_or_default()
    }
}
