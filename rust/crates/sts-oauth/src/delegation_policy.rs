// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHO MAY ACT FOR WHOM (`common/delegation_policy.ts`, rule 3az) — the
//! facts an RFC 8693 token exchange is decided on, and the decision.
//!
//! Node's `DelegationPolicy` gathers the FACTS — the subject, the actor, S
//! (the application the subject token was issued for) and R (the one the
//! new token is asked for), what each entry says, the roles each holds
//! and requires — and asks the issuance policy two questions through
//! `issuance_gate.checkExchange()`: which semantics
//! (`choose-exchange-semantics`) and whether the act is allowed
//! (`exchange-token`). A third, `assign-may-act`, says what an access
//! token's `may_act` names.
//!
//! WHAT REPLACED WHAT. Node evaluates the BUILT-IN issuance policy
//! document (`xacml_templates.ts`'s role-issuance rules, EXCHANGE_ATTRIBUTE)
//! with its XACML engine, and a realm's own policy where the embedded PEP
//! is loaded. The embedded PEP is not ported, so — as the runtime's
//! `RoleIssuance` does for the scope question — the built-in document's
//! rules are written here as the conditions they are
//! ([`exchange_verdict`]), in the document's order: ordered-deny-overrides,
//! so the first Deny that applies is the refusal the door reads and every
//! Permit is mutually exclusive. The rules across a Kerberos trust (#430)
//! read facts only a Kerberos question carries, and this door never sends
//! them, so they are not here. `tests/oauth8_vectors.rs` holds the two to
//! the same verdicts over Node's own evaluation.
//!
//! A LIBRARY: the application register and the person's entry are the
//! store, read through [`DelegationDirectory`].

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::settings::Settings;

/// The application-entry attributes the policy reads.
pub mod attributes {
    pub const DELEGATE_TO: &str = "appAllowedToDelegateTo";
    pub const ACT_ON_BEHALF_OF: &str = "appAllowedToActOnBehalfOf";
    pub const SUBJECT_GROUP: &str = "appDelegationSubjectGroup";
    pub const SEMANTICS: &str = "appDelegationSemantics";
    pub const DEFAULT_SEMANTICS: &str = "appDefaultDelegationSemantics";
    pub const NOT_DELEGATED: &str = "appNotDelegated";
    pub const MAY_ACT: &str = "appMayAct";
}

/// The directory the facts are read from: `applications.js` and
/// `credentials.ts`'s directory slot, and `roles.rolesOf()`.
pub trait DelegationDirectory: Send + Sync {
    /// `applications.get(identifier)`: the application's view
    /// (`identifier`, `dn`, `registeredBy`, `kinds`, `fields`).
    fn get(&self, identifier: &str) -> Option<Json>;
    /// `applications.forClientId(clientId)`.
    fn for_client_id(&self, client_id: &str) -> Option<Json>;
    /// `applications.forAudience(audience)`.
    fn for_audience(&self, audience: &str) -> Option<Json>;
    /// `applications.forAppliesTo(appliesTo)`.
    fn for_applies_to(&self, applies_to: &str) -> Option<Json>;
    /// `applications.isResourceServer(id)`.
    fn is_resource_server(&self, id: &str) -> bool;
    /// `applications.requiredRolesOf(identifier)`.
    fn required_roles_of(&self, identifier: &str) -> Vec<String>;
    /// `applications.list()`: every application's view.
    fn list(&self) -> Vec<Json>;
    /// `roles.rolesOf({ kind, name, authenticated: true })`.
    fn roles_of(&self, kind: &str, name: &str) -> Vec<String>;
    /// `credentials.delegationFactsFor(key)` (`ldap_server.js`'s
    /// `readDelegationFacts()`): `{ found, person, dn, username, sub,
    /// notDelegated, mayAct, delegate, groups, semantics,
    /// defaultSemantics }`, or `Null` with no store.
    fn delegation_facts(&self, key: &str) -> Json;
}

/// A directory with nothing in it: every party unknown.
pub struct NoDelegationDirectory;

impl DelegationDirectory for NoDelegationDirectory {
    fn get(&self, _: &str) -> Option<Json> {
        None
    }
    fn for_client_id(&self, _: &str) -> Option<Json> {
        None
    }
    fn for_audience(&self, _: &str) -> Option<Json> {
        None
    }
    fn for_applies_to(&self, _: &str) -> Option<Json> {
        None
    }
    fn is_resource_server(&self, _: &str) -> bool {
        false
    }
    fn required_roles_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn list(&self) -> Vec<Json> {
        Vec::new()
    }
    fn roles_of(&self, _: &str, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn delegation_facts(&self, _: &str) -> Json {
        Json::Null
    }
}

/// What a door asks (`DecideQuestion`), for the token exchange.
#[derive(Debug, Clone, Default)]
pub struct Question {
    pub protocol: String,
    /// The semantics the request asked for, '' for none.
    pub requested: String,
    pub actor: String,
    pub subject: String,
    pub source: Vec<String>,
    pub targets: Vec<String>,
    /// `audience` or `appliesTo`.
    pub target_kind: String,
    pub may_act_present: bool,
    pub may_act_names_actor: bool,
}

/// One target, as asked and as resolved.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Target {
    pub asked: String,
    pub application: String,
}

/// What `decide()` answers.
#[derive(Debug, Clone, Default)]
pub struct Decision {
    pub allowed: bool,
    pub enforced: bool,
    pub refusal: String,
    pub why: String,
    pub authorized_by: String,
    pub attribute: String,
    /// `self`, `delegation`, `impersonation`, or ''.
    pub semantics: String,
    pub audience: String,
    pub intermediary: String,
    pub decided_by: String,
    pub targets: Vec<Target>,
}

fn text(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

fn strings(v: Option<&Json>) -> Vec<String> {
    match v {
        Some(Json::Array(list)) => list.iter().map(|x| text(Some(x))).collect(),
        _ => Vec::new(),
    }
}

/// `DelegationPolicy.valuesOf(raw)`: trimmed non-empty strings.
#[tracing::instrument(level = "trace", skip_all)]
pub fn values_of(raw: Option<&Json>) -> Vec<String> {
    let list: Vec<Json> = match raw {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::String(s)) if s.is_empty() => Vec::new(),
        Some(Json::Array(a)) => a.clone(),
        Some(one) => vec![one.clone()],
    };
    list.iter()
        .map(|one| text(Some(one)).trim().to_string())
        .filter(|one| !one.is_empty())
        .collect()
}

/// `DelegationPolicy.normalizeDn(value)`: each RDN trimmed and lower-cased.
#[tracing::instrument(level = "trace")]
pub fn normalize_dn(value: &str) -> String {
    value
        .trim()
        .split(',')
        .map(|part| part.trim().to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

/// `DelegationPolicy.groupKeys(groups)`: each cn lower-cased, each DN
/// normalised, and the DN's leading cn, without repeats.
#[tracing::instrument(level = "trace", skip_all)]
pub fn group_keys(groups: &[(String, String)]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |v: String| {
        if !v.is_empty() && !out.contains(&v) {
            out.push(v);
        }
    };
    for (dn, cn) in groups {
        let cn = cn.trim().to_lowercase();
        let dn = normalize_dn(dn);
        add(cn);
        add(dn.clone());
        if let Some(rest) = dn.strip_prefix("cn=") {
            let leading: String =
                rest.chars().take_while(|c| *c != ',').collect();
            if !leading.is_empty() {
                add(leading);
            }
        }
    }
    out
}

/// `DelegationPolicy.mayActNames(mayAct, actor)`: the claim names the
/// actor by `sub` (or an alias), and an `iss` in it matches too.
#[tracing::instrument(level = "debug", skip_all)]
pub fn may_act_names(
    may_act: &Json,
    sub: &str,
    iss: &str,
    aliases: &[String],
) -> bool {
    if !may_act.is_object() {
        return false;
    }
    let mut names: Vec<&str> = vec![sub];
    names.extend(aliases.iter().map(String::as_str));
    let wanted = text(may_act.get("sub"));
    let sub_ok = names.iter().any(|n| !n.is_empty() && *n == wanted);
    let iss_ok = !crate::js::truthy(may_act.get("iss"))
        || text(may_act.get("iss")) == iss;
    sub_ok && iss_ok
}

// ---------------------------------------------------------------------------
// THE BUILT-IN ISSUANCE POLICY'S THREE EXCHANGE QUESTIONS
// (`xacml_exchange_verdicts.decide()` over `xacml_templates.ts`'s rules).
// ---------------------------------------------------------------------------

/// A party's fact bag: one value, or none when it is empty.
fn bag1(v: Option<&Json>) -> Vec<String> {
    let t = text(v);
    if t.is_empty() {
        Vec::new()
    } else {
        vec![t]
    }
}

/// A list fact, empty values left out (`xacml_request.js`'s `list()`).
fn bag(v: Option<&Json>) -> Vec<String> {
    strings(v).into_iter().filter(|x| !x.is_empty()).collect()
}

fn shares(a: &[String], b: &[String]) -> bool {
    a.iter().any(|x| b.contains(x))
}

/// The answer of [`exchange_verdict`]: `xacml_exchange_verdicts.decide()`'s
/// shape.
#[tracing::instrument(level = "debug", skip_all)]
pub fn exchange_verdict(facts: &Json, mode: &str, settings: &Json) -> Json {
    let subject = &facts["subject"];
    let actor = &facts["actor"];
    let source = &facts["source"];
    let target = &facts["target"];
    let product = mode == "product";
    // THE SEMANTICS, by precedence (choose-exchange-semantics).
    let requested = bag1(facts.get("requestedSemantics"));
    let actor_default = bag1(actor.get("defaultSemantics"));
    let subject_default = bag1(subject.get("defaultSemantics"));
    let realm_default = bag1(settings.get("defaultSemantics"));
    let said = requested
        .first()
        .or(actor_default.first())
        .or(subject_default.first())
        .or(realm_default.first())
        .cloned()
        .unwrap_or_default();
    let chosen = if said == "delegation" || said == "impersonation" {
        said
    } else {
        String::new()
    };
    // THE ACT (exchange-token), with the chosen semantics.
    let subject_id = bag1(subject.get("id"));
    let actor_id = bag1(actor.get("id"));
    let source_id = bag1(source.get("id"));
    let target_id = bag1(target.get("id"));
    let count = crate::js::to_number(&target["count"]);
    let count = if count.is_finite() { count as i64 } else { 0 };
    let is_self = shares(&actor_id, &subject_id)
        || (shares(&actor_id, &source_id)
            && (shares(&target_id, &source_id) || count == 0));
    let not_self = !is_self;
    let delegation = chosen == "delegation";
    let impersonation = chosen == "impersonation";
    let flag = |v: &Json, k: &str| v.get(k) == Some(&Json::Bool(true));
    let actor_semantics = bag(actor.get("semantics"));
    let subject_semantics = bag(subject.get("semantics"));
    let actor_allows = |v: &str| {
        actor_semantics.iter().any(|s| s == v)
            || (v == "delegation" && actor_semantics.is_empty())
    };
    let subject_allows = |v: &str| {
        subject_semantics.is_empty() || subject_semantics.iter().any(|s| s == v)
    };
    let subject_roles = bag(subject.get("roles"));
    let authority_for = |required: &[String]| {
        required.is_empty() || shares(&subject_roles, required)
    };
    let target_accepts = bag(target.get("accepts"));
    let source_delegates = shares(&target_id, &bag(source.get("delegatesTo")))
        || shares(&source_id, &target_accepts);
    let actor_role = bag1(settings.get("actorRole"));
    let subject_groups = bag(subject.get("groups"));
    let actor_subject_groups = bag(actor.get("subjectGroups"));
    let rules: [(&str, bool, bool); 12] = [
        (
            "may-act",
            flag(facts, "mayActPresent") && !flag(facts, "mayActNamesActor"),
            true,
        ),
        ("targets", count > 1, false),
        (
            "unregistered-target",
            count == 1 && !flag(target, "registered"),
            false,
        ),
        ("no-target", count == 0 && not_self, false),
        (
            "subject",
            not_self
                && (flag(subject, "notDelegated")
                    || shares(
                        &subject_groups,
                        &bag(facts.get("protectedGroups")),
                    )),
            false,
        ),
        (
            "intermediary",
            not_self && !flag(actor, "registered"),
            false,
        ),
        (
            "intermediary",
            not_self
                && text(actor.get("kind")) == "user"
                && !shares(&bag(actor.get("roles")), &actor_role),
            false,
        ),
        (
            "semantics",
            not_self
                && (!(delegation || impersonation)
                    || (delegation
                        && !(actor_allows("delegation")
                            && subject_allows("delegation")))
                    || (impersonation
                        && !(actor_allows("impersonation")
                            && subject_allows("impersonation")))),
            false,
        ),
        (
            "subject",
            not_self
                && !actor_subject_groups.is_empty()
                && !flag(facts, "mayActNamesActor")
                && !shares(&subject_groups, &actor_subject_groups),
            false,
        ),
        (
            "authority",
            (not_self
                && delegation
                && !authority_for(&bag(source.get("requiredRoles"))))
                || ((is_self || impersonation)
                    && count == 1
                    && !authority_for(&bag(target.get("requiredRoles")))),
            false,
        ),
        (
            "target",
            not_self
                && delegation
                && !((shares(&actor_id, &source_id)
                    || shares(&actor_id, &target_id)
                    || shares(&actor_id, &target_accepts))
                    && source_delegates),
            false,
        ),
        (
            "target",
            not_self
                && impersonation
                && !(shares(&actor_id, &target_id)
                    || shares(&target_id, &bag(actor.get("delegatesTo")))
                    || shares(&actor_id, &target_accepts)),
            false,
        ),
    ];
    let denied: Vec<&(&str, bool, bool)> =
        rules.iter().filter(|r| r.1).collect();
    if let Some(first) = denied.first() {
        // Ordered-deny-overrides: every Deny that applied contributes its
        // obligation, in order; `verdictOf()` reads the first refusal and
        // whether ANY says enforced.
        let enforced = product || denied.iter().any(|r| r.2);
        return json!({
            "verdict": "refuse", "refusal": first.0, "enforced": enforced,
            "semantics": "", "audience": "", "chosen": chosen,
            "decidedBy": "built-in",
        });
    }
    let first_of = |b: &[String]| b.first().cloned().unwrap_or_default();
    let (semantics, audience) = if is_self && count == 0 {
        ("self".to_string(), first_of(&source_id))
    } else if is_self && count == 1 {
        ("self".to_string(), first_of(&target_id))
    } else {
        (chosen.clone(), first_of(&target_id))
    };
    json!({
        "verdict": "allow", "refusal": "", "enforced": false,
        "semantics": semantics, "audience": audience, "chosen": chosen,
        "decidedBy": "built-in",
    })
}

/// The built-in answer of the third question (`assign-may-act`): the
/// party the subject named, and nobody when they named none.
#[tracing::instrument(level = "debug", skip_all)]
pub fn may_act_verdict(delegates: &[String]) -> Vec<String> {
    delegates
        .iter()
        .filter(|d| !d.is_empty())
        .cloned()
        .collect()
}

/// The attribute each refusal is about, for the act's row.
#[tracing::instrument(level = "trace")]
pub fn refusal_attribute(refusal: &str) -> &'static str {
    match refusal {
        "subject" => "stsNotDelegated",
        "self-realm" => "krb5S4uSelfRealm",
        "tgt-delegation" => "krb5ForeignTgtDelegation",
        "semantics" => "appDelegationSemantics",
        "target" | "no-target" | "intermediary" => "appAllowedToDelegateTo",
        _ => "",
    }
}

/// `DelegationPolicy.refusedBecause()`, for the protocols other than
/// Kerberos across a trust.
#[tracing::instrument(level = "debug", skip_all)]
pub fn refused_because(
    decision: &Decision,
    facts: &Json,
    question: &Question,
) -> String {
    let actor = format!("\"{}\"", text(facts["actor"].get("id")));
    let subject = format!("\"{}\"", text(facts["subject"].get("id")));
    let target_id = text(facts["target"].get("id"));
    let target = if target_id.is_empty() {
        "the unnamed target".to_string()
    } else {
        format!("\"{}\"", target_id)
    };
    let what = if decision.semantics.is_empty() {
        "act"
    } else {
        &decision.semantics
    };
    let ws = question.protocol == "WS-Trust";
    let kerberos = question.protocol == "Kerberos";
    let no_target = if ws {
        "no AppliesTo"
    } else if kerberos {
        "no service"
    } else {
        "neither audience nor resource"
    };
    let partner = || {
        let p = text(facts["trust"].get("partner"));
        if p.is_empty() {
            "the other realm".to_string()
        } else {
            p
        }
    };
    match decision.refusal.as_str() {
        "may-act" => format!(
            "{} (RFC 8693 section 4.4) names somebody other than {}.",
            if ws {
                format!(
                    "The JWT inside {} carries a may_act",
                    if question.requested == "impersonation" {
                        "<wst:OnBehalfOf>"
                    } else {
                        "<wst14:ActAs>"
                    }
                )
            } else {
                "The subject token's may_act".to_string()
            },
            actor
        ),
        "targets" => format!(
            "The request names {} targets; a token is issued for exactly one.",
            crate::js::stringify(&facts["target"]["count"])
        ),
        "unregistered-target" => format!(
            "No application in this realm registers {}, so there is nothing \
             to read its roles or relationships from.",
            target
        ),
        "no-target" => format!(
            "The request names no target ({}), and {}",
            no_target,
            if kerberos {
                "a Kerberos request always names the SPN it wants a ticket \
                 for."
                    .to_string()
            } else {
                format!(
                    "only a self {}",
                    if ws {
                        "request defaults to the presented token's own \
                         audience."
                    } else {
                        "exchange defaults to the subject token's own \
                         audience."
                    }
                )
            }
        ),
        "subject" => format!(
            "{} is protected — its entry says it is never delegated, it is \
             in a protected group (delegation.protectedGroups, the console \
             roster), or it is outside the groups {} may act for \
             (appDelegationSubjectGroup) — so {} may not act for it.",
            subject, actor, actor
        ),
        "intermediary" => format!(
            "{} may not act for anybody here: it has no entry in this realm, \
             or it is a person without the role delegation.actorRole names.",
            actor
        ),
        "semantics" => {
            if decision.semantics.is_empty() {
                "No semantics could be chosen for this act.".to_string()
            } else {
                format!(
                    "The semantics chosen, {}, are not allowed by {} or {} \
                     (their delegation semantics; an actor allows delegation \
                     only unless its entry says otherwise).",
                    decision.semantics, actor, subject
                )
            }
        }
        "authority" => format!(
            "{} holds none of the roles the application this {} stands on \
             requires.",
            subject, what
        ),
        "target" => {
            if decision.semantics == "impersonation" {
                format!(
                    "Nothing allows {} to reach {} as {}: R is not the actor \
                     itself, nor on its appAllowedToDelegateTo, nor does R \
                     accept it (appAllowedToActOnBehalfOf).",
                    actor, target, subject
                )
            } else if kerberos {
                format!(
                    "Nothing allows this S4U2Proxy to {}: the service the \
                     evidence ticket was issued to must delegate to the \
                     requested SPN (appAllowedToDelegateTo on it, classic \
                     constrained delegation), or the target must accept it \
                     (appAllowedToActOnBehalfOf, resource-based).",
                    target
                )
            } else {
                format!(
                    "Nothing allows this delegation to {}: the actor must be \
                     the application {} or the target, and that application \
                     must delegate to the target (appAllowedToDelegateTo on \
                     it, or appAllowedToActOnBehalfOf on the target).",
                    target,
                    if ws {
                        "the token inside <wst14:ActAs> was issued for"
                    } else {
                        "the subject token was issued for"
                    }
                )
            }
        }
        "trust-disabled" => {
            format!("The trust with {} is disabled.", partner())
        }
        "trust-direction" => format!(
            "This realm holds no trust ACCEPTING tickets from {} (an incoming \
             key), so it does not act for that realm's users.",
            partner()
        ),
        "classic-across-realms" => "Classic constrained delegation does not \
             cross a trust here unless the realm allows it \
             (krb5.crossRealmClassicDelegation); resource-based delegation \
             (appAllowedToActOnBehalfOf on the target, naming SPN@REALM) \
             does."
            .to_string(),
        _ => format!("The issuance policy refused this {}.", what),
    }
}

/// `DelegationPolicy.allowedBecause()`, for the token exchange and
/// WS-Trust.
#[tracing::instrument(level = "debug", skip_all)]
pub fn allowed_because(
    decision: &Decision,
    facts: &Json,
    question: &Question,
) -> String {
    let actor_id = text(facts["actor"].get("id"));
    if decision.semantics == "self" {
        return format!(
            "nothing was needed: \"{}\" acts for nobody but itself.",
            actor_id
        );
    }
    let ws = question.protocol == "WS-Trust";
    let element = if question.requested == "impersonation" {
        "<wst:OnBehalfOf>"
    } else {
        "<wst14:ActAs>"
    };
    let source_id = text(facts["source"].get("id"));
    let source = if source_id.is_empty() {
        String::new()
    } else if ws {
        format!(
            " (the token inside {} was issued for \"{}\")",
            element, source_id
        )
    } else {
        format!(" (the subject token was issued for \"{}\")", source_id)
    };
    format!(
        "the issuance policy allowed {} by \"{}\" for \"{}\" to \"{}\"{}{}{}.",
        decision.semantics,
        actor_id,
        text(facts["subject"].get("id")),
        decision.audience,
        if ws {
            ", the application the AppliesTo names"
        } else {
            ""
        },
        source,
        if question.may_act_names_actor {
            "; the subject named this actor in may_act"
        } else {
            ""
        }
    )
}

/// `DelegationPolicy.rowText(decision)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn row_text(decision: &Decision) -> String {
    if decision.allowed {
        decision.authorized_by.clone()
    } else if decision.enforced {
        format!("refused by the delegation policy: {}", decision.why)
    } else {
        format!(
            "nothing, in development mode — and it WOULD HAVE BEEN REFUSED in \
             product: {}",
            decision.why
        )
    }
}

/// The policy.
pub struct DelegationPolicy {
    pub directory: Arc<dyn DelegationDirectory>,
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
}

impl DelegationPolicy {
    fn setting(&self, key: &str) -> String {
        use sts_core::settings::SettingValue;
        match self.settings.value_of(key) {
            SettingValue::Text(t) => t,
            SettingValue::Int(n) => n.to_string(),
            SettingValue::Bool(b) => b.to_string(),
            SettingValue::List(l) => l.join(","),
        }
    }

    /// `applicationFor(name)`: an identifier, client_id or client subject.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn application_for(&self, name: &str) -> Option<Json> {
        let wanted = name.trim();
        if wanted.is_empty() {
            return None;
        }
        let client_id = wanted
            .strip_prefix("urn:sts:client:")
            .filter(|rest| !rest.is_empty())
            .unwrap_or("");
        self.directory
            .get(wanted)
            .or_else(|| self.directory.for_client_id(wanted))
            .or_else(|| {
                if client_id.is_empty() {
                    None
                } else {
                    self.directory.for_client_id(client_id)
                }
            })
    }

    /// `resolveTarget(asked, kind)`: the identifier of the application
    /// registering a target, '' for none (and, in product, for one only a
    /// development sighting filed, #496).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn resolve_target(&self, asked: &str, kind: &str) -> String {
        let wanted = asked.trim();
        let mut found = None;
        if !wanted.is_empty() {
            found = if kind == "appliesTo" {
                self.directory.for_applies_to(wanted)
            } else {
                self.directory
                    .for_audience(wanted)
                    .or_else(|| self.directory.for_client_id(wanted))
            };
            found = found.or_else(|| self.directory.get(wanted));
        }
        if let Some(f) = &found {
            if !self.mode.issues_to_unregistered_applications()
                && text(f.get("registeredBy")).is_empty()
            {
                found = None;
            }
        }
        found.map(|f| text(f.get("identifier"))).unwrap_or_default()
    }

    /// `protectedGroupNames()`: `delegation.protectedGroups` and the
    /// console roster's two groups.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn protected_group_names(&self) -> Vec<String> {
        use sts_core::settings::SettingValue;
        let mut out: Vec<String> =
            match self.settings.value_of("delegation.protectedGroups") {
                SettingValue::List(l) => l,
                SettingValue::Text(t) => {
                    t.split(',').map(|s| s.to_string()).collect()
                }
                _ => Vec::new(),
            }
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        for key in ["admin.readGroup", "admin.writeGroup"] {
            let v = self.setting(key).trim().to_string();
            if !v.is_empty() {
                out.push(v);
            }
        }
        out
    }

    /// `protectedGroupKeys()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn protected_group_keys(&self) -> Vec<String> {
        let groups: Vec<(String, String)> = self
            .protected_group_names()
            .into_iter()
            .map(|one| {
                if one.contains('=') {
                    (one, String::new())
                } else {
                    (String::new(), one)
                }
            })
            .collect();
        group_keys(&groups)
    }

    /// `resolvedList(values)`: each value resolved, the raw value kept.
    fn resolved_list(&self, values: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for one in values {
            let mut resolved = self.resolve_target(one, "audience");
            if resolved.is_empty() {
                resolved = self.resolve_target(one, "appliesTo");
            }
            for v in [resolved, one.clone()] {
                if !v.is_empty() && !out.contains(&v) {
                    out.push(v);
                }
            }
        }
        out
    }

    /// `partyFacts(name)`: a party as the exchange question states it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn party_facts(&self, name: &str) -> Json {
        let wanted = name.trim();
        if let Some(app) = self.application_for(wanted) {
            let id = text(app.get("identifier"));
            let fields = app.get("fields").cloned().unwrap_or(json!({}));
            let f = |k: &str| values_of(fields.get(k));
            return json!({
                "id": id, "kind": "application", "registered": true,
                "roles": self.directory.roles_of("application", &id),
                "notDelegated": f(attributes::NOT_DELEGATED).iter()
                    .any(|v| v.to_uppercase() == "TRUE"),
                "groups": [],
                "semantics": f(attributes::SEMANTICS).iter()
                    .map(|v| v.to_lowercase()).collect::<Vec<_>>(),
                "defaultSemantics": f(attributes::DEFAULT_SEMANTICS)
                    .first().map(|v| v.to_lowercase()).unwrap_or_default(),
                "delegatesTo": self.resolved_list(&f(attributes::DELEGATE_TO)),
                "subjectGroups": f(attributes::SUBJECT_GROUP).iter()
                    .map(|v| normalize_dn(v)).collect::<Vec<_>>(),
                "accepts": self.resolved_list(
                    &f(attributes::ACT_ON_BEHALF_OF)),
                "mayAct": "",
            });
        }
        let facts = if wanted.is_empty() {
            Json::Null
        } else {
            self.directory.delegation_facts(wanted)
        };
        if facts.get("found") == Some(&Json::Bool(true))
            && facts.get("person") == Some(&Json::Bool(true))
        {
            let mut username = text(facts.get("username"));
            if username.is_empty() {
                username = wanted.to_string();
            }
            let groups: Vec<(String, String)> = facts["groups"]
                .as_array()
                .map(|l| {
                    l.iter()
                        .map(|g| (text(g.get("dn")), text(g.get("cn"))))
                        .collect()
                })
                .unwrap_or_default();
            return json!({
                "id": username, "kind": "user", "registered": true,
                "roles": self.directory.roles_of("user", &username),
                "notDelegated": crate::js::truthy(facts.get("notDelegated")),
                "groups": group_keys(&groups),
                "semantics": strings(facts.get("semantics")).iter()
                    .map(|v| v.to_lowercase()).collect::<Vec<_>>(),
                "defaultSemantics": text(facts.get("defaultSemantics"))
                    .to_lowercase(),
                "delegatesTo": [], "subjectGroups": [], "accepts": [],
                "mayAct": text(facts.get("mayAct")),
            });
        }
        let lower = wanted.to_lowercase();
        json!({
            "id": wanted,
            "kind": if lower.starts_with("urn:uuid:") { "user" }
                    else { "application" },
            "registered": false, "roles": [], "notDelegated": false,
            "groups": [], "semantics": [], "defaultSemantics": "",
            "delegatesTo": [], "subjectGroups": [], "accepts": [],
            "mayAct": "",
        })
    }

    /// `decide(question)`: the facts, the built-in policy's answer, and the
    /// sentences.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn decide(&self, question: &Question) -> Decision {
        let (facts, decision) = self.decide_with_facts(question);
        let _ = facts;
        decision
    }

    /// [`DelegationPolicy::decide`], with the facts the policy was asked
    /// on.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn decide_with_facts(&self, question: &Question) -> (Json, Decision) {
        let subject = self.party_facts(&question.subject);
        let actor = self.party_facts(&question.actor);
        let mut source_id = String::new();
        for one in &question.source {
            source_id = self.resolve_target(one, &question.target_kind);
            if source_id.is_empty() {
                source_id = self
                    .application_for(one)
                    .map(|a| text(a.get("identifier")))
                    .unwrap_or_default();
            }
            if !source_id.is_empty()
                && self.directory.is_resource_server(&source_id)
            {
                source_id.clear();
            }
            if !source_id.is_empty() {
                break;
            }
        }
        let source =
            (!source_id.is_empty()).then(|| self.party_facts(&source_id));
        let asked: Vec<String> = question
            .targets
            .iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        let target_id = asked
            .first()
            .map(|a| self.resolve_target(a, &question.target_kind))
            .unwrap_or_default();
        let target =
            (!target_id.is_empty()).then(|| self.party_facts(&target_id));
        let facts = json!({
            "subject": subject, "actor": actor,
            "source": {
                "id": source_id,
                "requiredRoles": if source_id.is_empty() { vec![] }
                    else { self.directory.required_roles_of(&source_id) },
                "delegatesTo": source.as_ref()
                    .map(|s| s["delegatesTo"].clone()).unwrap_or(json!([])),
            },
            "target": {
                "id": if target_id.is_empty() {
                    asked.first().cloned().unwrap_or_default()
                } else { target_id.clone() },
                "count": asked.len(),
                "registered": !target_id.is_empty(),
                "requiredRoles": if target_id.is_empty() { vec![] }
                    else { self.directory.required_roles_of(&target_id) },
                "accepts": target.as_ref()
                    .map(|t| t["accepts"].clone()).unwrap_or(json!([])),
            },
            "requestedSemantics": question.requested,
            "mayActPresent": question.may_act_present,
            "mayActNamesActor": question.may_act_names_actor,
            "protectedGroups": self.protected_group_keys(),
        });
        let settings = json!({
            "defaultSemantics": self.setting("delegation.defaultSemantics"),
            "actorRole": self.setting("delegation.actorRole"),
        });
        let answer = exchange_verdict(&facts, self.mode.current(), &settings);
        let allowed = answer["verdict"] == "allow";
        let semantics = if allowed {
            text(answer.get("semantics"))
        } else {
            text(answer.get("chosen"))
        };
        let mut decision = Decision {
            allowed,
            enforced: !allowed && answer["enforced"] != Json::Bool(false),
            refusal: if allowed {
                String::new()
            } else {
                let r = text(answer.get("refusal"));
                if r.is_empty() {
                    "policy".into()
                } else {
                    r
                }
            },
            semantics: if ["self", "delegation", "impersonation"]
                .contains(&semantics.as_str())
            {
                semantics
            } else {
                String::new()
            },
            audience: if allowed {
                text(answer.get("audience"))
            } else {
                target_id.clone()
            },
            intermediary: text(facts["actor"].get("id")),
            decided_by: text(answer.get("decidedBy")),
            targets: asked
                .iter()
                .enumerate()
                .map(|(i, one)| Target {
                    asked: one.clone(),
                    application: if i == 0 {
                        target_id.clone()
                    } else {
                        self.resolve_target(one, &question.target_kind)
                    },
                })
                .collect(),
            ..Decision::default()
        };
        if allowed {
            decision.authorized_by =
                allowed_because(&decision, &facts, question);
        } else {
            decision.why = refused_because(&decision, &facts, question);
            decision.attribute =
                refusal_attribute(&decision.refusal).to_string();
            tracing::info!(
                "delegation_policy: {} {} {} by \"{}\" for \"{}\": {}",
                if decision.enforced {
                    "REFUSED"
                } else {
                    "would have refused (development records it)"
                },
                question.protocol,
                if decision.semantics.is_empty() {
                    "act"
                } else {
                    &decision.semantics
                },
                text(facts["actor"].get("id")),
                text(facts["subject"].get("id")),
                decision.why
            );
        }
        (facts, decision)
    }

    /// `mayActClaimFor(username)`: the `may_act` an access token about
    /// this party carries (RFC 8693 section 4.4), from their own
    /// `stsMayAct` (`appMayAct` on an application), or `None`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn may_act_claim_for(&self, username: &str) -> Option<Json> {
        let name = username.trim();
        if name.is_empty() {
            return None;
        }
        let declared = if let Some(app) = self.application_for(name) {
            let dn = values_of(app["fields"].get(attributes::MAY_ACT))
                .into_iter()
                .next()
                .unwrap_or_default();
            if dn.is_empty() {
                None
            } else {
                self.claim_for_dn(&dn)
            }
        } else {
            let facts = self.directory.delegation_facts(name);
            if crate::js::truthy(facts.get("person"))
                && crate::js::truthy(facts.get("mayAct"))
            {
                self.claim_for_delegate(&facts["delegate"])
            } else {
                None
            }
        };
        let declared = declared?;
        let parties = may_act_verdict(&[text(declared.get("sub"))]);
        parties.first().map(|p| json!({ "sub": p }))
    }

    fn claim_for_delegate(&self, delegate: &Json) -> Option<Json> {
        let kind = text(delegate.get("kind"));
        if kind == "person" && crate::js::truthy(delegate.get("sub")) {
            return Some(json!({ "sub": text(delegate.get("sub")) }));
        }
        if kind == "application" {
            return self.claim_for_dn(&text(delegate.get("dn")));
        }
        None
    }

    fn claim_for_dn(&self, dn: &str) -> Option<Json> {
        let wanted = normalize_dn(dn);
        if let Some(row) = self
            .directory
            .list()
            .into_iter()
            .find(|row| normalize_dn(&text(row.get("dn"))) == wanted)
        {
            let ids = values_of(row["fields"].get("oauthClientId"));
            return Some(json!({
                "sub": ids.first().cloned()
                    .unwrap_or_else(|| text(row.get("identifier"))),
            }));
        }
        let facts = self.directory.delegation_facts(dn);
        if crate::js::truthy(facts.get("found"))
            && crate::js::truthy(facts.get("person"))
        {
            return self.claim_for_delegate(&json!({
                "kind": "person", "sub": facts["sub"].clone(),
            }));
        }
        None
    }
}

/// The facts of a decision as a JSON object, for a vector.
#[tracing::instrument(level = "trace", skip_all)]
pub fn decision_json(d: &Decision) -> Json {
    let mut m = Map::new();
    m.insert("allowed".into(), json!(d.allowed));
    m.insert("enforced".into(), json!(d.enforced));
    m.insert("refusal".into(), json!(d.refusal));
    m.insert("why".into(), json!(d.why));
    m.insert("authorizedBy".into(), json!(d.authorized_by));
    m.insert("attribute".into(), json!(d.attribute));
    m.insert("semantics".into(), json!(d.semantics));
    m.insert("audience".into(), json!(d.audience));
    m.insert("intermediary".into(), json!(d.intermediary));
    Json::Object(m)
}
