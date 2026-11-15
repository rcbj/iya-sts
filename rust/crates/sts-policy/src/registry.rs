// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE KINDS OF POLICY ON DIRECTORY > POLICIES — a port of
//! `admin-core/policy_kinds.ts` (#64): the one list the page, its JSON and
//! the `/admin-api/policies` operations are drawn from, each kind a module
//! of its own answering `save-<id>-policy`, `reset-<id>-policy` and any
//! acts of its own; and the dispatch `admin_actions.ts`'s
//! `policiesAction()` makes over it, up to the module's answer (the audit
//! row and the console's sentences are the API layer's).

use serde_json::Value;
use sts_core::errors::{codes, ErrorCode};

use crate::js::{self, Object};
use crate::kinds::{
    attributes::AttributePolicy, authn::AuthnPolicy, locale::LocalePolicy,
    passkey::PasskeyPolicy, password::PasswordPolicy,
    post_login::PostLoginPolicy, service_account::ServiceAccountPolicy,
};
use crate::ports::Ports;
use crate::Answer;

/// An act a kind has beside save and reset (#396).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraAction {
    pub action: &'static str,
    /// The model's operation (`models/api/management.tsp`).
    pub operation_id: &'static str,
    pub audit_action: &'static str,
}

/// One kind on the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyKind {
    pub id: &'static str,
    pub label: &'static str,
    pub container: &'static str,
    pub governs: &'static str,
    pub audit_action: &'static str,
    /// Finishes "It applies to ...".
    pub applies_to: &'static str,
    /// Finishes "... and ... is in force".
    pub falls_back_to: &'static str,
    pub tabbed: bool,
    pub extra_actions: &'static [ExtraAction],
}

/// THE KINDS THIS SERVICE DEFINES, in the order the page draws them.
pub const KINDS: [PolicyKind; 7] = [
    PolicyKind {
        id: "password",
        label: "Password policy",
        container: "ou=passwordPolicies",
        governs: "userPassword",
        audit_action: "admin.password-policy.change",
        applies_to: "the NEXT password set in this realm and to nothing already stored",
        falls_back_to: "the built-in defaults",
        tabbed: true,
        extra_actions: &[],
    },
    PolicyKind {
        id: "authn",
        label: "Authentication policy",
        container: "ou=authnPolicies",
        governs: "which mechanisms are accepted as a first and as a second factor",
        audit_action: "admin.authn-policy.change",
        applies_to: "the NEXT sign-in in this realm; a session already started keeps the \
                     factors it was started with",
        falls_back_to: "the default realm's profile where it has one, and the built-in \
                        defaults where it has not",
        tabbed: true,
        extra_actions: &[
            ExtraAction {
                action: "save-named-authn-policy",
                operation_id: "saveNamedAuthnPolicy",
                audit_action: "admin.authn-policy.save-named",
            },
            ExtraAction {
                action: "delete-named-authn-policy",
                operation_id: "deleteNamedAuthnPolicy",
                audit_action: "admin.authn-policy.delete-named",
            },
        ],
    },
    PolicyKind {
        id: "serviceAccount",
        label: "Service-account policy",
        container: "ou=serviceAccountPolicies",
        governs: "what a service account may do — the second factor, the browser, the password \
                  doors — and how its password rotates",
        audit_action: "admin.service-account-policy.change",
        applies_to: "every service account it governs — those naming it, and for `default` \
                     those naming none — from the next time it signs in, binds or is rotated",
        falls_back_to: "the default realm's profile where it has one, and the built-in \
                        defaults where it has not",
        tabbed: true,
        extra_actions: &[],
    },
    PolicyKind {
        id: "passkey",
        label: "Passkey policy",
        container: "ou=passkeyPolicies",
        governs: "how passkeys behave — whether a sign-in may name no username, and what a \
                  security key is asked to store",
        audit_action: "admin.passkey-policy.change",
        applies_to: "the NEXT sign-in and the NEXT passkey enrolled in this realm; a passkey \
                     already enrolled keeps what its authenticator stored",
        falls_back_to: "the default realm's profile where it has one, and the built-in \
                        defaults where it has not",
        tabbed: true,
        extra_actions: &[
            ExtraAction {
                action: "clear-passkey-client",
                operation_id: "clearPasskeyClient",
                audit_action: "admin.passkey-client.clear",
            },
            ExtraAction {
                action: "clear-passkey-clients",
                operation_id: "clearPasskeyClients",
                audit_action: "admin.passkey-client.clear",
            },
        ],
    },
    PolicyKind {
        id: "locale",
        label: "Locale policy",
        container: "ou=localePolicies",
        governs: "the language a page falls back to, the language mail is written in when a \
                  person names none, and the preferredLanguage a new person is given",
        audit_action: "admin.locale-policy.change",
        applies_to: "the NEXT page drawn and the NEXT person created in this realm; a person \
                     created before keeps the preferredLanguage they have, or none",
        falls_back_to: "the default realm's profile where it has one, and the built-in \
                        defaults where it has not",
        tabbed: true,
        extra_actions: &[],
    },
    PolicyKind {
        id: "attributes",
        label: "Attribute policy",
        container: "ou=attributePolicies",
        governs: "the attributes every person in this realm must hold, and the custom \
                  attributes a person here may be given",
        audit_action: "admin.attribute-policy.change",
        applies_to: "the NEXT person created and the NEXT edit in this realm; a person who \
                     already lacks an attribute it requires keeps every other door",
        falls_back_to: "the default realm's profile where it has one, and the built-in default \
                        (givenName, sn and mail) where it has not",
        tabbed: true,
        extra_actions: &[
            ExtraAction {
                action: "define-person-attribute",
                operation_id: "definePersonAttribute",
                audit_action: "admin.attribute-policy.define",
            },
            ExtraAction {
                action: "update-person-attribute",
                operation_id: "updatePersonAttribute",
                audit_action: "admin.attribute-policy.update",
            },
            ExtraAction {
                action: "remove-person-attribute",
                operation_id: "removePersonAttribute",
                audit_action: "admin.attribute-policy.undefine",
            },
        ],
    },
    PolicyKind {
        id: "postLogin",
        label: "Post-login activity policy",
        container: "ou=postLoginPolicies",
        governs: "what a person is asked to do after signing in, before they are sent back to \
                  the application — today, to register a post-quantum passkey",
        audit_action: "admin.post-login-policy.change",
        applies_to: "the NEXT sign-in of every person the profile reaches in this realm; a \
                     session already started is not interrupted",
        falls_back_to: "the default realm's profile where it has one, and the built-in \
                        defaults (nobody is asked anything) where it has not",
        tabbed: true,
        extra_actions: &[],
    },
];

/// What a save or a reset answers, as templates (#543).
pub const MESSAGES: [(&str, &str); 4] = [
    ("saved", "The {{noun}} \"{{name}}\" is saved at {{dn}}. It applies to {{appliesTo}}."),
    (
        "savedNotEnforced",
        "The {{noun}} \"{{name}}\" is saved at {{dn}}. It applies to {{appliesTo}} — and it is \
         not enforced here until this realm is in product mode.",
    ),
    ("removed", "The stored profile is gone, and this realm follows {{fallsBackTo}}: {{rules}}."),
    (
        "nothingStored",
        "Nothing was stored in this realm, so it already followed {{fallsBackTo}}.",
    ),
];

/// Which part of a kind answers an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Save,
    Reset,
    Act,
}

impl Verb {
    /// As Node names it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Verb::Save => "save",
            Verb::Reset => "reset",
            Verb::Act => "act",
        }
    }
}

/// `helpers.numberWord()`: the word for 0 to 15, the digits otherwise.
#[tracing::instrument(level = "debug")]
pub fn number_word(count: usize) -> String {
    const WORDS: [&str; 16] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
        "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    ];
    WORDS
        .get(count)
        .map(|w| w.to_string())
        .unwrap_or_else(|| count.to_string())
}

impl PolicyKind {
    /// `nounOf()`: the label, lower-cased, and "profile".
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn noun(&self) -> String {
        format!("{} profile", self.label.to_lowercase())
    }

    /// `save-<id>-policy`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn save_action(&self) -> String {
        format!("save-{}-policy", self.id)
    }

    /// `reset-<id>-policy`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset_action(&self) -> String {
        format!("reset-{}-policy", self.id)
    }
}

/// `PolicyKinds.byId()`.
#[tracing::instrument(level = "debug")]
pub fn by_id(id: &str) -> Option<&'static PolicyKind> {
    KINDS.iter().find(|k| k.id == id)
}

/// `PolicyKinds.actions()`: save then reset, then its own, kind by kind.
#[tracing::instrument(level = "debug")]
pub fn actions() -> Vec<String> {
    let mut out = Vec::new();
    for k in KINDS.iter() {
        out.push(k.save_action());
        out.push(k.reset_action());
        out.extend(k.extra_actions.iter().map(|x| x.action.to_string()));
    }
    out
}

/// `PolicyKinds.forAction()`.
#[tracing::instrument(level = "debug")]
pub fn for_action(action: &str) -> Option<(&'static PolicyKind, Verb)> {
    for k in KINDS.iter() {
        if action == k.save_action() {
            return Some((k, Verb::Save));
        }
        if action == k.reset_action() {
            return Some((k, Verb::Reset));
        }
        if k.extra_actions.iter().any(|x| x.action == action) {
            return Some((k, Verb::Act));
        }
    }
    None
}

/// `policiesAction()`'s refusal of an action no kind answers
/// (STS-ADMIN-0500).
#[tracing::instrument(level = "debug")]
pub fn unknown_action(action: &str) -> Answer {
    let known = actions();
    Answer::refused(
        codes::STS_ADMIN_0500,
        vec![format!(
            "Unknown action \"{action}\". The {} are: {}.",
            number_word(known.len()),
            known.join(", ")
        )],
    )
}

/// The module's answer to an action of `/admin-api/policies/{action}`, as
/// `policiesAction()` hands it the body: `profile` names the profile a save
/// or a reset is about, and the act's own members its acts. A refusal keeps
/// the module's code; one the module did not mark is STS-ADMIN-0549 (a save
/// or an act) or STS-ADMIN-0550 (a reset), as `policiesAction()` falls back.
#[tracing::instrument(level = "debug", skip(ports, body))]
pub fn answer(
    ports: Ports,
    realm: &str,
    action: &str,
    body: &Object,
) -> Answer {
    let Some((kind, verb)) = for_action(action) else {
        return unknown_action(action);
    };
    // `String(body.profile || module.DEFAULT_PROFILE).trim()`, and the body
    // handed on whole, as `Object.assign({}, body)` hands it.
    let named = js::or_empty(body.get("profile"));
    let profile = Value::String(
        js::trim(if named.is_empty() { "default" } else { &named }).to_string(),
    );
    let given = body.clone();
    let out = match (kind.id, verb) {
        ("password", Verb::Save) => {
            PasswordPolicy::new(ports).save(realm, &profile, Some(&given))
        }
        ("password", _) => PasswordPolicy::new(ports).reset(realm, &profile),
        ("authn", Verb::Save) => {
            AuthnPolicy::new(ports).save(realm, &profile, Some(&given))
        }
        ("authn", Verb::Reset) => {
            AuthnPolicy::new(ports).reset(realm, &profile)
        }
        ("authn", Verb::Act) => {
            AuthnPolicy::new(ports).act(realm, action, Some(body))
        }
        ("serviceAccount", Verb::Save) => {
            ServiceAccountPolicy::new(ports).save(realm, &profile, Some(&given))
        }
        ("serviceAccount", _) => {
            ServiceAccountPolicy::new(ports).reset(realm, &profile)
        }
        ("passkey", Verb::Save) => {
            PasskeyPolicy::new(ports).save(realm, &profile, Some(&given))
        }
        ("passkey", Verb::Reset) => {
            PasskeyPolicy::new(ports).reset(realm, &profile)
        }
        ("passkey", Verb::Act) => {
            PasskeyPolicy::new(ports).act(realm, action, Some(body))
        }
        ("locale", Verb::Save) => {
            LocalePolicy::new(ports).save(realm, &profile, Some(&given))
        }
        ("locale", _) => LocalePolicy::new(ports).reset(realm, &profile),
        ("attributes", Verb::Save) => {
            AttributePolicy::new(ports).save(realm, &profile, Some(&given))
        }
        ("attributes", Verb::Reset) => {
            AttributePolicy::new(ports).reset(realm, &profile)
        }
        ("attributes", Verb::Act) => {
            AttributePolicy::new(ports).act(realm, action, Some(body))
        }
        ("postLogin", Verb::Save) => {
            PostLoginPolicy::new(ports).save(realm, &profile, Some(&given))
        }
        (_, _) => PostLoginPolicy::new(ports).reset(realm, &profile),
    };
    if out.is_refusal() && out.code.is_none() {
        let fallback: ErrorCode = if verb == Verb::Reset {
            codes::STS_ADMIN_0550
        } else {
            codes::STS_ADMIN_0549
        };
        return Answer {
            value: out.value,
            code: Some(fallback),
        };
    }
    out
}
