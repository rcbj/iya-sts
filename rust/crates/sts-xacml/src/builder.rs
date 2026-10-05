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
use crate::request::{Request, RequestAttribute, RequestCategory, RequestValue};

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
        self.category(category_id).attributes.push(RequestAttribute {
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
            let kind = if SUBJECT_KINDS.contains(&kind) { kind } else { "user" };
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
        self.attribute(category::RESOURCE, attribute::RESOURCE_ID, [id],
                       type_uri)
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
        self.attribute(category::INTERMEDIARY_SUBJECT, attribute::SUBJECT_ID,
                       [name], None)
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
        req.target("urn:x", Some(types::ANYURI)).requested_action("GET");
        let built = req.build();
        let order: Vec<&str> =
            built.categories.iter().map(|c| c.category.as_str()).collect();
        assert_eq!(
            order,
            [category::ACCESS_SUBJECT, category::ENVIRONMENT,
             category::RESOURCE, category::ACTION]
        );
        assert!(built.categories[0].attributes.is_empty());
        assert_eq!(built.categories[2].attributes[0].values[0].type_uri,
                   types::ANYURI);
    }

    #[test]
    fn booleans_are_typed_and_empties_dropped_on_request() {
        let mut req = AuthorizationRequest::new(true, true, true);
        req.environment("x", [Fact::Boolean(true)]);
        req.subject("y", ["", "a"]);
        let built = req.build();
        assert_eq!(built.categories[0].attributes[0].values[0].type_uri,
                   types::BOOLEAN);
        assert_eq!(built.categories[1].attributes[0].values.len(), 1);
    }
}
