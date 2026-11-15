// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE GROUPS CLAIM (`common/group_claims.ts`, rule 3d-ii): the groups
//! somebody is in, carried in every claim set at once — access token, ID
//! token, UserInfo, both SAML assertions, the Kerberos PAC, GNAP.
//!
//! **CARRYING A GROUP IS NOT GRANTING ONE.** No endpoint reads this claim
//! and nothing decides anything on it; the answer of [`GroupClaims::state`]
//! says so in its `grants` sentence. **ON BY DEFAULT IS DEFENSIBLE ONLY
//! BECAUSE THE CLAIM IS OMITTED FOR SOMEBODY IN NO GROUP** — absent, not an
//! empty list. **A NAME THIS SERVICE SETS ITSELF IS REFUSED AT ISSUANCE**
//! (`STS-REG-0046`), not when the setting is written.
//!
//! The directory owns what a group IS (`groupsOfUser()`: both group rules,
//! `member`, `uniqueMember`, `memberUid`, and the person's own `memberOf`
//! as `viaMemberOf`); this owns what a token BELIEVES —
//! `groups.claimFromMemberOf` decides whether the person's own claim counts.
//! Each setting may be overridden per application (`settingFor()`).

use std::sync::Arc;

use serde_json::{json, Value};
use sts_core::errors::codes;
use sts_core::log::tag;

use crate::js;
use crate::outcome::Outcome;
use crate::port::{Applications, ClaimTables, GroupDirectory, IdentityKeys};

/// The groups claim.
pub struct GroupClaims {
    directory: Option<Arc<dyn GroupDirectory>>,
    applications: Arc<dyn Applications>,
    keys: Arc<dyn IdentityKeys>,
    tables: Arc<dyn ClaimTables>,
}

const GRANTS: &str = "A group here grants nothing. No endpoint in this \
    service reads this claim and nothing decides anything on it; the token \
    merely carries it. The two admin-console roles are the one exception \
    and are not an exception to THIS sentence: they are read from the \
    directory by /admin and never from this claim, so a token carrying \
    admin-write can still do nothing a token without it cannot.";

const PRECEDENCE: &str = "A typed claim and a directory attribute of the \
    same name both win over the groups claim.";

impl GroupClaims {
    /// `setDirectory(hooks)` is the constructor's `directory`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        directory: Option<Arc<dyn GroupDirectory>>,
        applications: Arc<dyn Applications>,
        keys: Arc<dyn IdentityKeys>,
        tables: Arc<dyn ClaimTables>,
    ) -> GroupClaims {
        GroupClaims {
            directory,
            applications,
            keys,
            tables,
        }
    }

    fn setting(&self, app: &str, key: &str) -> Value {
        self.applications.setting_for(app, key)
    }

    /// `enabled(app)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn enabled(&self, app: &str) -> bool {
        js::truthy(&self.setting(app, "groups.claim"))
    }

    /// `claimName(app)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn claim_name(&self, app: &str) -> String {
        js::trim(&js::or_empty(Some(&self.setting(app, "groups.claimName"))))
            .to_string()
    }

    /// `valueForm(app)`: `cn` or `dn`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn value_form(&self, app: &str) -> String {
        match js::or_empty(Some(&self.setting(app, "groups.claimValue"))) {
            v if v.is_empty() => "cn".to_string(),
            v => js::trim(&v).to_string(),
        }
    }

    /// `memberOfCounts(app)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn member_of_counts(&self, app: &str) -> bool {
        js::truthy(&self.setting(app, "groups.claimFromMemberOf"))
    }

    /// `nameProblem(app)`.
    fn name_problem(&self, app: &str) -> String {
        let name = self.claim_name(app);
        if name.is_empty() {
            return "groups.claimName is empty, so there is no claim to add."
                .to_string();
        }
        let reserved = self.tables.reserved_jwt_claims();
        if reserved.contains(&name) {
            return format!(
                "\"{name}\" is one of the names this service sets itself \
                 ({}), so it is refused for the same reason a typed custom \
                 claim of that name is: a settable `exp` or `scope` would \
                 produce tokens that fail to verify, or change what UserInfo \
                 answers, with nothing pointing back at the setting. Choose \
                 another groups.claimName.",
                reserved.join(", ")
            );
        }
        String::new()
    }

    fn values_from(
        rows: &[Value],
        form: &str,
        use_member_of: bool,
    ) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for row in rows {
            let via =
                row.get("via").and_then(Value::as_array).map_or(0, Vec::len);
            if via == 0 && !use_member_of {
                continue;
            }
            let value =
                js::or_empty(row.get(if form == "dn" { "dn" } else { "cn" }));
            if value.is_empty() || out.contains(&value) {
                continue;
            }
            out.push(value);
        }
        out
    }

    /// `groupsOf(username, app)`: the groups and the values the claim
    /// would carry, and why it would not.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn groups_of(&self, username: &str, app: &str) -> Outcome {
        let mut out = json!({
            "user": username,
            "key": self.keys.identity_key_of(username),
            "application": app,
            "enabled": self.enabled(app),
            "loaded": self.directory.is_some(),
            "claim": self.claim_name(app),
            "valueForm": self.value_form(app),
            "memberOfCounts": self.member_of_counts(app),
            "reason": "", "dn": "", "entryFound": false,
            "groups": [], "values": [],
        });
        let set = |out: &mut Value, k: &str, v: Value| {
            if let Some(map) = out.as_object_mut() {
                map.insert(k.into(), v);
            }
        };
        if out["enabled"] != json!(true) {
            set(
                &mut out,
                "reason",
                json!(
                    "groups.claim is off, so no token \
                or assertion carries a groups claim."
                ),
            );
            return Outcome::ok(out);
        }
        let problem = self.name_problem(app);
        if !problem.is_empty() {
            set(&mut out, "reason", json!(problem));
            return Outcome::marked(codes::STS_REG_0046, out);
        }
        let Some(directory) = self.directory.as_ref() else {
            set(
                &mut out,
                "reason",
                json!(
                    "The embedded LDAP directory is not \
                loaded in this process, so there are no groups to read. \
                Nothing else is affected."
                ),
            );
            return Outcome::ok(out);
        };
        let read =
            directory.groups_of_user(&self.keys.identity_key_of(username));
        if !js::truthy(&read) {
            tracing::error!(
                "{}the directory gave no answer for the groups claim; the \
                 token is issued without it",
                tag(codes::STS_REG_0045)
            );
            set(
                &mut out,
                "reason",
                json!(
                    "The directory could not be read; \
                the token is issued without a groups claim."
                ),
            );
            return Outcome::marked(codes::STS_REG_0045, out);
        }
        let groups = read["groups"].as_array().cloned().unwrap_or_default();
        let form = js::string(&out["valueForm"]);
        let values = GroupClaims::values_from(
            &groups,
            &form,
            out["memberOfCounts"] == json!(true),
        );
        set(&mut out, "dn", read["dn"].clone());
        set(
            &mut out,
            "entryFound",
            json!(js::truthy(&read["entryFound"])),
        );
        set(&mut out, "groups", json!(groups));
        if values.is_empty() {
            set(
                &mut out,
                "reason",
                json!(if groups.is_empty() {
                    "This person is in no group here, so the claim is omitted \
                 entirely rather than sent as an empty list."
                        .to_string()
                } else {
                    format!(
                        "This person is named by {} group(s), but only \
                    through their own memberOf, and groups.claimFromMemberOf \
                    is off.",
                        groups.len()
                    )
                }),
            );
        }
        set(&mut out, "values", json!(values));
        Outcome::ok(out)
    }

    fn of_context(&self, context: &Value) -> Outcome {
        let pick = |keys: &[&str]| {
            keys.iter()
                .map(|k| js::or_empty(context.get(*k)))
                .find(|v| !v.is_empty())
                .unwrap_or_default()
        };
        self.groups_of(
            &pick(&["username", "subject"]),
            &pick(&["application", "client_id", "audience"]),
        )
    }

    /// `jwtClaimsFor(setId, context)`: `{<claim>: [values]}` or `{}`.
    #[tracing::instrument(level = "debug", skip(self, context))]
    pub fn jwt_claims_for(&self, set_id: &str, context: &Value) -> Value {
        let answer = self.of_context(context).answer;
        let values = answer["values"].as_array().cloned().unwrap_or_default();
        if values.is_empty() {
            return json!({});
        }
        let mut out = serde_json::Map::new();
        out.insert(js::string(&answer["claim"]), json!(values));
        Value::Object(out)
    }

    /// `samlAttributesFor(setId, context)`: one multi-valued attribute.
    #[tracing::instrument(level = "debug", skip(self, context))]
    pub fn saml_attributes_for(
        &self,
        set_id: &str,
        context: &Value,
    ) -> Vec<Value> {
        let answer = self.of_context(context).answer;
        let values = answer["values"].as_array().cloned().unwrap_or_default();
        if values.is_empty() {
            return Vec::new();
        }
        let mut attribute = json!({"name": answer["claim"],
            "value": values[0], "values": values});
        if set_id == "saml11" {
            if let Some(map) = attribute.as_object_mut() {
                map.insert(
                    "namespace".into(),
                    json!(self.tables.default_saml11_namespace()),
                );
            }
        }
        vec![attribute]
    }

    /// `state()`: what `/admin/groups` draws.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn state(&self) -> Value {
        let enabled = self.enabled("");
        json!({
            "enabled": enabled,
            "loaded": self.directory.is_some(),
            "claim": self.claim_name(""),
            "valueForm": self.value_form(""),
            "memberOfCounts": self.member_of_counts(""),
            "sets": self.tables.claim_set_ids(),
            "problem": if enabled { self.name_problem("") } else {
                String::new() },
            "grants": GRANTS,
            "precedence": PRECEDENCE,
            "settings": ["groups.claim", "groups.claimName",
                         "groups.claimValue", "groups.claimFromMemberOf"],
        })
    }
}
