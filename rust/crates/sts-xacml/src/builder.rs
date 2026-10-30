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
//! The three adapters for whole families of facts — `transfer()` (#98),
//! `exchange()` (#186) and `gnapRight()` (#432) — move with the families
//! that call them (rust/DESIGN.md section 11); the vocabulary they use is
//! here already, so nothing else can spell it differently.

use crate::model::{attribute, category, types};
use crate::request::{
    Request, RequestAttribute, RequestCategory, RequestValue,
};

/// The vocabulary of #88 section 7 that is not XACML's own. URI-shaped, so
/// the PIP never mistakes one for a directory attribute name.
pub mod vocabulary {
    pub const ROLE: &str = "urn:sts:xacml:role";
    pub const SUBJECT_KIND: &str = "urn:sts:xacml:subject-kind";
    pub const CLIENT_ID: &str = "urn:sts:xacml:client-id";
    pub const AUDIENCE: &str = "urn:sts:xacml:audience";
    pub const REQUESTED_SCOPE: &str = "urn:sts:xacml:requested-scope";
    pub const PROTOCOL: &str = "urn:sts:xacml:protocol";
    pub const GRANT_TYPE: &str = "urn:sts:xacml:grant-type";
    pub const MODE: &str = "urn:sts:xacml:mode";
    pub const SETTING_PREFIX: &str = "urn:sts:xacml:setting:";
    pub const SCOPE_STAGE: &str = "urn:sts:xacml:scope-stage";
    pub const REALM: &str = "urn:sts:xacml:realm";
    // AuthZEN's facts (#563): written by the service's AuthZEN adapter
    // alone; spelt here so a policy reading them matches either builder.
    pub const AUTHZEN_SUBJECT_TYPE: &str =
        "urn:sts:xacml:authzen:subject-type";
    pub const AUTHZEN_RESOURCE_TYPE: &str =
        "urn:sts:xacml:authzen:resource-type";
    pub const AUTHZEN_CALLER: &str = "urn:sts:xacml:authzen:caller";
    pub const AUTHZEN_APPLICATION: &str =
        "urn:sts:xacml:authzen:application";
    pub const AUTHZEN_SUPPLIED: &str = "urn:sts:xacml:authzen:supplied";
    // Fine-grained authorization's facts (#564): written by the service's
    // FGA adapter (`xacml/fga_map.ts`) alone; spelt here so a policy
    // reading them matches either builder, and so an embedded FGA PDP in
    // the remote PEP — future work — finds them already named.
    pub const FGA_APPLICATION: &str = "urn:sts:xacml:fga:application";
    pub const FGA_DETAIL_TYPE: &str = "urn:sts:xacml:fga:detail-type";
    pub const FGA_DEFINITION_DIGEST: &str =
        "urn:sts:xacml:fga:definition-digest";
    pub const FGA_STAGE: &str = "urn:sts:xacml:fga:stage";
    pub const FGA_SUPPLIED: &str = "urn:sts:xacml:fga:supplied";
    pub const FGA_DETAIL_ACTION: &str = "urn:sts:xacml:fga:detail:action";
    pub const FGA_DETAIL_LOCATION: &str =
        "urn:sts:xacml:fga:detail:location";
    pub const FGA_DETAIL_DATATYPE: &str =
        "urn:sts:xacml:fga:detail:datatype";
    pub const FGA_DETAIL_IDENTIFIER: &str =
        "urn:sts:xacml:fga:detail:identifier";
    pub const FGA_DETAIL_PRIVILEGE: &str =
        "urn:sts:xacml:fga:detail:privilege";
    // The facts of a User-Managed Access question (#1168), spelt as
    // `xacml/xacml_request.js` spells them; the remote PEP builds none of
    // these today, and a policy written against one spelling must match
    // what both builders would send.
    pub const ACR: &str = "urn:sts:xacml:acr";
    pub const UMA_RESOURCE_TYPE: &str = "urn:sts:xacml:uma:resource-type";
    pub const UMA_RESOURCE_SERVER: &str =
        "urn:sts:xacml:uma:resource-server";
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
}

/// The principal types a request may name; anything else is a person.
pub const SUBJECT_KINDS: [&str; 2] = ["user", "application"];

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
}

/// `one()` in `xacml_request.js`: an empty value is no value.
fn one(value: &str) -> Vec<&str> {
    if value.is_empty() {
        Vec::new()
    } else {
        vec![value]
    }
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
        self.subject(vocabulary::CLIENT_ID, id)
    }

    pub fn audience<F: Into<Fact>>(
        &mut self,
        values: impl IntoIterator<Item = F>,
    ) -> &mut Self {
        self.resource(vocabulary::AUDIENCE, values)
    }

    pub fn protocol(&mut self, name: Option<&str>) -> &mut Self {
        self.environment(vocabulary::PROTOCOL, name)
    }

    pub fn grant_type(&mut self, name: Option<&str>) -> &mut Self {
        self.environment(vocabulary::GRANT_TYPE, name)
    }

    pub fn mode(&mut self, name: Option<&str>) -> &mut Self {
        self.environment(vocabulary::MODE, name)
    }

    /// One setting's value: a boolean as a boolean, anything else a string.
    pub fn setting(&mut self, key: &str, value: Option<Fact>) -> &mut Self {
        let id = format!("{}{}", vocabulary::SETTING_PREFIX, key);
        self.environment(&id, value)
    }

    pub fn stage(&mut self, name: Option<&str>) -> &mut Self {
        self.environment(vocabulary::SCOPE_STAGE, name)
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
        for row in &facts.attributes {
            self.attribute(
                &row.category,
                &row.attribute_id,
                row.values.iter().map(String::as_str),
                Some(&row.data_type),
            );
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
