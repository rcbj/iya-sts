// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! OWNERS THROUGH THE MANAGEMENT API (`common/ownership.ts`, rule 3cn,
//! #607; #444, phase 5, the `apis4` slice).
//!
//! `sts-registers`' [`Ownership`] is the register; this module is what it
//! asks of the runtime and what the gate asks of it:
//!
//! * [`OwnerDir`]: `groupsOwnedBy()` and `groupOwnership()` over the
//!   registers' directory (`ldap_server.js`), and the groups claim's
//!   `groupsOfUser()`;
//! * [`OwnerScopes`]: `scopePolicy`'s protected, declared and delegated
//!   scopes, which decide whether an application is closed to its owners;
//! * [`Owns`]: `owns.anything(name)`, which `OWNER_READ` and `OWNER_WRITE`
//!   are computed from (`roles.ts`'s built-ins);
//! * [`OwnerAccess`]: the access-control policy with the owner PIP
//!   (`xacml_pip.ts`'s `ownerFact()`): the object's owners (lower-cased,
//!   the spaces beside a comma folded), whether it is closed to them, and
//!   who the person is as an owner (`identityOf(person).keys`).
//!
//! Setting a group's or a service account's protection
//! (`setGroupOwnerProtected()`) is not ported and is refused, and there are
//! no service accounts in this runtime yet (`NoServiceAccounts`), so a
//! service account is nobody's to own here.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::realm;
use sts_core::settings::Settings;
use sts_registers::ownership::Ownership;
use sts_registers::port as rp;
use sts_xacml::access::{Answer, Question};
use sts_xacml::model::category;
use sts_xacml::policy::Designator;

use super::LiveDir;

/// The directory's group questions for ownership.
pub struct OwnerDir(pub Arc<LiveDir>);

// `normalizeDn()`'s fold for an owner comparison.
fn folded(dn: &str) -> String {
    sts_ldap::service_dn::normalize_dn(Some(dn))
}

impl rp::GroupDirectory for OwnerDir {
    fn groups_of_user(&self, name: &str) -> Json {
        self.0
            .with(|t| match LiveDir::realm_index(t, &realm::current_id()) {
                Some(r) => super::groups_of_user(t, r, name),
                None => json!({ "dn": "", "entryFound": false, "groups": [] }),
            })
    }

    // `groupsOwnedBy(dns)`: the realm's groups naming any of them as an
    // owner, by `cn`.
    fn groups_owned_by(&self, dns: &[String]) -> Vec<Json> {
        let wanted: Vec<String> = dns
            .iter()
            .filter(|d| !d.is_empty())
            .map(|d| folded(d))
            .collect();
        let mut out: Vec<Json> = self.0.with(|t| {
            let Some(r) = LiveDir::realm_index(t, &realm::current_id()) else {
                return Vec::new();
            };
            t.realms()[r]
                .entries
                .values()
                .filter_map(|e| {
                    let owners = e.attributes.get("owner")?;
                    if owners.is_empty()
                        || t.group_rule(r, &e.dn, &e.attributes).is_empty()
                    {
                        return None;
                    }
                    let matched: Vec<&String> = owners
                        .iter()
                        .filter(|o| wanted.contains(&folded(o)))
                        .collect();
                    if matched.is_empty() {
                        return None;
                    }
                    let first = |k: &str| {
                        e.attributes
                            .get(k)
                            .and_then(|v| v.first())
                            .cloned()
                            .unwrap_or_default()
                    };
                    let count =
                        |k: &str| e.attributes.get(k).map_or(0, Vec::len);
                    Some(json!({
                        "dn": e.dn, "cn": first("cn"),
                        "description": first("description"),
                        "memberCount": count("member") + count("uniquemember")
                            + count("memberuid"),
                        "ownedAs": matched,
                    }))
                })
                .collect()
        });
        out.sort_by(|a, b| {
            sts_registers::js::locale_compare(
                a["cn"].as_str().unwrap_or(""),
                b["cn"].as_str().unwrap_or(""),
            )
        });
        out
    }

    // `groupOwnership(group)`: the group by its DN or its name.
    fn group_ownership(&self, name: &str) -> Json {
        self.0.with(|t| {
            let Some(r) = LiveDir::realm_index(t, &realm::current_id()) else {
                return Json::Null;
            };
            let dn = if name.contains('=') {
                name.to_string()
            } else {
                super::groups::Groups { tree: t, r }.group_dn_for(name)
            };
            let Some(e) = t.get(r, &dn) else {
                return Json::Null;
            };
            if t.group_rule(r, &e.dn, &e.attributes).is_empty() {
                return Json::Null;
            }
            let first = |k: &str| {
                e.attributes
                    .get(k)
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default()
            };
            json!({
                "dn": e.dn, "cn": first("cn"),
                "owners": e.attributes.get("owner").cloned().unwrap_or_default()
                    .into_iter().filter(|o| !o.is_empty()).collect::<Vec<_>>(),
                "ownerProtected":
                    first("stsownerprotected").eq_ignore_ascii_case("TRUE"),
            })
        })
    }

    fn set_group_owner_protected(
        &self,
        _name: &str,
        _flag: bool,
        _options: &Json,
    ) -> rp::Marked {
        rp::Marked {
            value: json!({ "ok": false, "errors": [
                "Closing a group to its owners is not ported to this \
                 runtime yet."] }),
            code: Some(sts_core::errors::codes::STS_API_0050),
        }
    }
}

/// `scopePolicy`'s questions ownership asks.
pub struct OwnerScopes {
    pub settings: Arc<Settings>,
    pub scopes: Arc<sts_oauth::scopes::ScopePolicy>,
}

impl rp::ScopePolicy for OwnerScopes {
    fn protected_scopes(&self) -> Vec<String> {
        sts_oauth::scopes::protected_scopes(&self.settings)
    }
    fn declared_scopes(&self, identifier: &str) -> Vec<String> {
        self.scopes.declared_scopes(identifier).unwrap_or_default()
    }
    fn delegated_permission_scopes(&self, identifier: &str) -> Vec<String> {
        self.scopes.delegated_permission_scopes(identifier)
    }
}

/// `owns.anything(name)`, over the register.
pub struct Owns(pub Arc<Ownership>);

impl rp::OwnsAnything for Owns {
    fn owns_anything(&self, name: &str) -> bool {
        self.0.owns_anything(name)
    }
}

/// The owner PIP for one question (`ownerFact()`).
struct OwnerPip<'a> {
    ownership: &'a Ownership,
    question: &'a Question,
}

impl OwnerPip<'_> {
    fn parse(
        designator: &Designator,
        values: &[String],
    ) -> Vec<sts_xacml::value::Value> {
        values
            .iter()
            .filter_map(|one| {
                sts_xacml::datatypes::DataTypes::standard()
                    .parse(&designator.data_type, one)
                    .ok()
            })
            .collect()
    }
}

impl sts_xacml::pdp::AttributeResolver for OwnerPip<'_> {
    fn resolve(&self, designator: &Designator) -> Vec<sts_xacml::value::Value> {
        let id = designator.attribute_id.as_str();
        let Some(object) = &self.question.owned_object else {
            return Vec::new();
        };
        if designator.category == category::RESOURCE
            && (id == sts_xacml::access::OBJECT_OWNER
                || id == sts_xacml::access::OBJECT_PROTECTED)
        {
            let facts = self.ownership.object_of(&object.kind, &object.id);
            if facts["found"] != json!(true) {
                return Vec::new();
            }
            if id == sts_xacml::access::OBJECT_OWNER {
                let owners: Vec<String> = facts["owners"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|o| {
                                let lower =
                                    o.as_str().unwrap_or("").to_lowercase();
                                lower
                                    .split(',')
                                    .map(str::trim)
                                    .collect::<Vec<_>>()
                                    .join(",")
                                    .trim()
                                    .to_string()
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                return Self::parse(designator, &owners);
            }
            let closed = facts["protected"] == json!(true);
            return Self::parse(
                designator,
                &[if closed { "true" } else { "false" }.to_string()],
            );
        }
        if designator.category == category::ACCESS_SUBJECT
            && id == sts_xacml::access::OWNER_IDENTITY
        {
            let person = if object.person.is_empty() {
                self.question.subject.clone()
            } else {
                object.person.clone()
            };
            if person.is_empty() {
                return Vec::new();
            }
            let keys: Vec<String> = self.ownership.identity_of(&person)["keys"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|k| k.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            return Self::parse(designator, &keys);
        }
        Vec::new()
    }
}

/// The built-in `access-control` document, decided with the owner PIP.
pub struct OwnerAccess {
    policy: Option<sts_xacml::policy::PolicyNode>,
    ownership: Arc<Ownership>,
}

impl OwnerAccess {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(ownership: Arc<Ownership>) -> OwnerAccess {
        let params =
            sts_xacml::access::Parameters::from_answers(&Default::default());
        OwnerAccess {
            policy: sts_xacml::access::built_in("access-control", &params).ok(),
            ownership,
        }
    }
}

impl sts_mgmt_api::gate::AccessPolicy for OwnerAccess {
    fn check(
        &self,
        question: &Question,
        held: &[String],
        required: &[String],
    ) -> Answer {
        // `BuiltInAccess::check()`'s roles: the built-ins of an
        // authenticated user, then the caller's.
        let mut all: Vec<String> = vec!["EVERYBODY".into()];
        if question.authenticated {
            all.push("ALL_AUTHENTICATED_USERS".into());
        }
        for one in held {
            if !all.contains(one) {
                all.push(one.clone());
            }
        }
        let Some(policy) = &self.policy else {
            return Answer {
                allowed: false,
                decision: sts_xacml::model::Decision::Indeterminate,
                refused: Some(sts_xacml::access::Refused::Indeterminate),
                why: "the access policy could not be loaded.".into(),
            };
        };
        let pip = OwnerPip {
            ownership: &self.ownership,
            question,
        };
        let options = sts_xacml::pdp::EvaluationOptions {
            resolver: Some(&pip),
            ..Default::default()
        };
        sts_xacml::access::decide_with(
            policy, question, &all, required, &options,
        )
    }
}
