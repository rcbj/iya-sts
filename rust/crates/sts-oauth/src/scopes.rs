// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a scope and a resource indicator may be, as the authorization and
//! token endpoints ask it before anything is issued:
//!
//! * [`ScopePolicy`] — `common/scope_policy.ts` (rule 3au, #110, #1141): a
//!   client is issued this service's PROTECTED scopes only where it
//!   declares them (`oauthAllowedScope`, or for an API's own scope a
//!   delegated permission grant on that API's object, `urn:sts:admin-api:`
//!   and the rest), in every mode; in product every other scope too,
//!   unless it names another party or the client declares nothing and it
//!   is in the default set. `refusal()` is the request's answer, `narrow()`
//!   the backstop every mint passes (`STS-OAUTH-0579`);
//! * [`audience_scopes`] and [`permission_refusal`] — `oauth2.ts`'s
//!   `audienceScopes()` and `permissionRefusal()`: a scope naming a
//!   delegated permission by its whole identifier, or an application by
//!   its client_id, is an audience; a delegated permission the client was
//!   not granted is refused in product (or with
//!   `oauth2.delegatedPermissionsEnforced`);
//! * [`parse_resource_indicators`] and [`RegisteredTargets`] — RFC 8707's
//!   `resource`, and `common/registered_targets.ts`: a token is addressed
//!   only to one of this service's own resource servers or to a registered
//!   application.
//!
//! WHAT REPLACED WHAT. Node asks the issuance gate (`gate.checkScopes()`,
//! rule 3bt) and the XACML default policy answers from the facts gathered
//! here. Rust applies that default policy's rules directly
//! (`xacml/xacml_templates.ts`, `protected-undeclared`, `undeclared`,
//! `permission-not-granted`, each a request-stage refusal and a mint-stage
//! drop): an administrator's own issuance policy is phase 8's, and until
//! then the default's answer is the one given. Shared Signals'
//! `declarationCovers()` (a declared `ssf.manage` covering `ssf.read`) is
//! not here: a declaration is matched word for word.

use std::sync::Arc;

use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::settings::{SettingValue, Settings};

use crate::clients::Clients;
use crate::jwt_access_token::{JwtAccessTokens, OIDC_SCOPES};

/// `applications.API_PERMISSIONS`: each API's object, the base its
/// permissions are named under, and the permission words it defines.
pub const API_PERMISSIONS: [(&str, &str, &[&str]); 5] = [
    (
        "sts-management-api",
        "urn:sts:admin-api:",
        &[
            "admin:read",
            "admin:write",
            "admin:security",
            "admin:console",
            "owner:read",
            "owner:write",
        ],
    ),
    (
        "sts-account-api",
        "urn:sts:account-api:",
        &["account:manage"],
    ),
    (
        "sts-report-api",
        "urn:sts:report-api:",
        &["report:use", "report:admin"],
    ),
    (
        "sts-authzen-api",
        "urn:sts:authzen-api:",
        &["authzen:evaluate"],
    ),
    (
        "sts-uma-protection-api",
        "urn:sts:uma-protection-api:",
        &["uma_protection"],
    ),
];

/// The scopes of this service's own APIs and resource servers, with the
/// settings' SCIM names and the published Shared Signals names
/// (`protectedScopes()`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn protected_scopes(settings: &Settings) -> Vec<String> {
    let text = |key: &str, fallback: &str| {
        let v = settings.value_of(key);
        let s = v.as_str().trim().to_string();
        if s.is_empty() {
            fallback.to_string()
        } else {
            s
        }
    };
    let mut names: Vec<String> = [
        "admin:read",
        "admin:write",
        "admin:security",
        "admin:console",
        "report:use",
        "report:admin",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let mut more = vec![
        text("scim.scopeRead", "scim:read"),
        text("scim.scopeWrite", "scim:write"),
        "device:compliance".to_string(),
        "account:manage".to_string(),
        "authzen:evaluate".to_string(),
        "uma_protection".to_string(),
    ];
    // `ssfScopes.published()`: the configured names, then the profile's.
    more.push(text("ssf.authScopeRead", "ssf.read"));
    more.push(text("ssf.authScopeWrite", "ssf.manage"));
    more.push("ssf.read".to_string());
    more.push("ssf.manage".to_string());
    for one in [
        "grant_management_query",
        "grant_management_revoke",
        "vc-api:issue",
        "vc-api:verify",
        "owner:read",
        "owner:write",
    ] {
        more.push(one.to_string());
    }
    for one in more {
        if !names.contains(&one) {
            names.push(one);
        }
    }
    names
}

/// `ScopePolicy.split(scope)`: the distinct non-empty values, in order.
#[tracing::instrument(level = "debug")]
pub fn split(scope: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for one in scope.split_whitespace() {
        if !out.iter().any(|o| o == one) {
            out.push(one.to_string());
        }
    }
    out
}

fn quoted(list: &[String]) -> String {
    list.iter()
        .map(|one| format!("\"{}\"", one))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `judge()`'s answer.
#[derive(Debug, Clone, Default)]
pub struct Judged {
    pub kept: Vec<String>,
    pub protected_refused: Vec<String>,
    pub undeclared_refused: Vec<String>,
    pub declared: Option<Vec<String>>,
}

/// A refusal of a scope.
#[derive(Debug, Clone)]
pub struct ScopeRefusal {
    pub code: ErrorCode,
    pub description: String,
}

/// `common/scope_policy.ts`.
pub struct ScopePolicy {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub clients: Arc<dyn Clients>,
    /// `credentialScopes()`: the realm's OpenID4VCI scopes, which join the
    /// default set.
    pub credential_scopes: Vec<String>,
}

impl ScopePolicy {
    /// `delegatedPermissionApiOf(scope)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn delegated_permission_api_of(&self, scope: &str) -> String {
        API_PERMISSIONS
            .iter()
            .find(|(_, _, words)| words.contains(&scope))
            .map(|(api, _, _)| api.to_string())
            .unwrap_or_default()
    }

    /// `delegatedPermissionScopes(clientId)`: the words a client holds a
    /// delegated permission grant of, each defined by its API's own object.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn delegated_permission_scopes(&self, client_id: &str) -> Vec<String> {
        let who = client_id.trim();
        let mut out: Vec<String> = Vec::new();
        if who.is_empty() {
            return out;
        }
        for (api, base, words) in API_PERMISSIONS.iter() {
            for word in words.iter() {
                let id = format!("{}{}", base, word);
                let defined = self.clients.permission_defined_by(&id);
                if defined.as_deref() == Some(*api)
                    && self.clients.holds_permission(who, &id)
                    && !out.iter().any(|o| o == word)
                {
                    out.push(word.to_string());
                }
            }
        }
        out
    }

    /// `declaredScopes(clientId)`: `oauthAllowedScope` less the words a
    /// delegated permission grant declares instead.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn declared_scopes(&self, client_id: &str) -> Option<Vec<String>> {
        self.clients.allowed_scopes_of(client_id).map(|held| {
            held.into_iter()
                .filter(|one| self.delegated_permission_api_of(one).is_empty())
                .collect()
        })
    }

    /// `defaultScopes()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn default_scopes(&self) -> Vec<String> {
        let key_binding = !matches!(
            self.settings.value_of("oauth2.keyBinding"),
            SettingValue::Bool(false)
        );
        let mut out: Vec<String> = OIDC_SCOPES
            .iter()
            .filter(|one| key_binding || **one != "bound_key")
            .map(|s| s.to_string())
            .collect();
        for one in &self.credential_scopes {
            if !one.is_empty() && !out.contains(one) {
                out.push(one.clone());
            }
        }
        out
    }

    fn names_another_party(&self, scope: &str) -> bool {
        self.clients.permission_defined_by(scope).is_some()
            || self.clients.is_client_id(scope)
    }

    /// `judge(scope, clientId)` under the default issuance policy. A
    /// `device_sso` (Native SSO, #130) is refused to every client here, as
    /// to one whose Native SSO is not enabled, until Native SSO is ported.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn judge(&self, scope: &str, client_id: &str) -> Judged {
        let asked = split(scope);
        let mut out = Judged::default();
        if asked.is_empty() {
            return out;
        }
        let declared = self.declared_scopes(client_id);
        out.declared = declared.clone();
        let protected = protected_scopes(&self.settings);
        let defaults = if declared.is_some() {
            Vec::new()
        } else {
            self.default_scopes()
        };
        let delegated = self.delegated_permission_scopes(client_id);
        let product = self.mode.current() == "product";
        for one in asked {
            let is_protected = protected.contains(&one);
            let is_declared =
                if !self.delegated_permission_api_of(&one).is_empty() {
                    delegated.contains(&one)
                } else {
                    declared.as_ref().is_some_and(|d| d.contains(&one))
                };
            if is_protected && !is_declared {
                out.protected_refused.push(one);
                continue;
            }
            let undeclared = product
                && !is_protected
                && one != "device_sso"
                && !self.names_another_party(&one)
                && !is_declared
                && !(declared.is_none() && defaults.contains(&one));
            if undeclared {
                out.undeclared_refused.push(one);
                continue;
            }
            out.kept.push(one);
        }
        out
    }

    /// `refusal(scope, clientId)`: a protected scope first, then an
    /// undeclared one, or `None`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn refusal(
        &self,
        scope: &str,
        client_id: &str,
    ) -> Option<ScopeRefusal> {
        let judged = self.judge(scope, client_id);
        let who = client_id.trim();
        let client = if who.is_empty() {
            "a client that named no client_id".to_string()
        } else {
            format!("the client \"{}\"", who)
        };
        let where_ = " A client's declared scopes are `oauthAllowedScope` on its entry in ou=applications — the application's page under /admin/applications, or POST /admin-api/applications/add.";
        if !judged.protected_refused.is_empty() {
            let list = &judged.protected_refused;
            let one = list.len() == 1;
            return Some(ScopeRefusal {
                code: codes::STS_OAUTH_0577,
                description: format!(
                    "{}{} this service's own {}, issued in every mode only to a client that declares {}, and {} does not.{} An admin, owner, account or report scope is declared instead by a delegated permission grant on that API's object — urn:sts:admin-api:, urn:sts:account-api: or urn:sts:report-api: followed by the scope (POST /admin-api/permissions/grant-permission, #1141). A dynamic registration cannot declare one; an administrator does.",
                    quoted(list),
                    if one { " is" } else { " are" },
                    if one { "scope" } else { "scopes" },
                    if one { "it" } else { "them" },
                    client,
                    where_
                ),
            });
        }
        if !judged.undeclared_refused.is_empty() {
            return Some(ScopeRefusal {
                code: codes::STS_OAUTH_0578,
                description: format!(
                    "{} has not declared {}, and in product mode a client is issued only the scopes it declared (RFC 7591 section 2) — {}{}",
                    client,
                    quoted(&judged.undeclared_refused),
                    match &judged.declared {
                        Some(list) => format!("its list is {}.", quoted(list)),
                        None => format!(
                            "it declares none, so it may have the default set: {}.",
                            quoted(&self.default_scopes())
                        ),
                    },
                    where_
                ),
            });
        }
        None
    }

    /// `narrow(scope, clientId, { grant })`: the scope with every value
    /// `refusal()` would refuse taken off, the removal recorded under
    /// `STS-OAUTH-0579`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn narrow(&self, scope: &str, client_id: &str, grant: &str) -> String {
        let judged = self.judge(scope, client_id);
        let mut removed = judged.protected_refused.clone();
        removed.extend(judged.undeclared_refused.iter().cloned());
        if removed.is_empty() {
            return scope.to_string();
        }
        tracing::warn!(
            "{}oauth2: the scope(s) {} were not issued to {} ({}): not in \
             its oauthAllowedScope",
            sts_core::log::tag(codes::STS_OAUTH_0579),
            removed.join(", "),
            if client_id.trim().is_empty() {
                "an unnamed client"
            } else {
                client_id.trim()
            },
            grant
        );
        split(scope)
            .into_iter()
            .filter(|one| !removed.contains(one))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// One scope that names a delegated permission (`audienceScopes()`'s
/// `permissions`).
#[derive(Debug, Clone)]
pub struct NamedPermission {
    pub scope: String,
    pub identifier: String,
    pub permission: String,
    pub audience: String,
    pub granted: bool,
}

/// `audienceScopes(scope, clientId)`'s answer.
#[derive(Debug, Clone, Default)]
pub struct AudienceScopes {
    pub audiences: Vec<String>,
    /// Scopes naming an application by its client_id.
    pub applications: Vec<String>,
    pub permissions: Vec<NamedPermission>,
}

/// `protocolScopes()`: the names that never name another party.
#[tracing::instrument(level = "debug", skip_all)]
pub fn protocol_scopes(
    settings: &Settings,
    credential: &[String],
) -> Vec<String> {
    let mut names: Vec<String> =
        OIDC_SCOPES.iter().map(|s| s.to_string()).collect();
    for key in ["scim.scopeRead", "scim.scopeWrite"] {
        let v = settings.value_of(key);
        let t = v.as_str().to_string();
        names.push(if t.is_empty() {
            if key.ends_with("Read") {
                "scim:read".into()
            } else {
                "scim:write".into()
            }
        } else {
            t
        });
    }
    for one in credential {
        if !names.contains(one) {
            names.push(one.clone());
        }
    }
    names
}

/// `audienceScopes(scope, clientId)`: which requested scopes name a
/// delegated permission or an application, read as an audience.
#[tracing::instrument(level = "debug", skip(clients, reserved))]
pub fn audience_scopes(
    clients: &dyn Clients,
    reserved: &[String],
    scope: &str,
    client_id: &str,
) -> AudienceScopes {
    let mine = client_id.trim();
    let mut out = AudienceScopes::default();
    for one in scope.split_whitespace() {
        if reserved.iter().any(|r| r == one)
            || (!mine.is_empty() && one == mine)
        {
            continue;
        }
        if let Some((identifier, name, base)) = clients.permission_of(one) {
            if !out.audiences.contains(&base) {
                out.audiences.push(base.clone());
            }
            out.permissions.push(NamedPermission {
                scope: one.to_string(),
                identifier,
                permission: name,
                audience: base,
                granted: clients.holds_permission(mine, one),
            });
            continue;
        }
        if clients.is_client_id(one) && !out.audiences.iter().any(|a| a == one)
        {
            out.audiences.push(one.to_string());
            out.applications.push(one.to_string());
        }
    }
    out
}

/// `permissionRefusal(scope, clientId, grantType)` under the default
/// issuance policy's `permission-not-granted` rule: '' to allow.
#[tracing::instrument(level = "debug", skip(found, settings, mode))]
pub fn permission_refusal(
    found: &AudienceScopes,
    settings: &Settings,
    mode: &Mode,
    client_id: &str,
    grant_type: &str,
) -> String {
    if found.permissions.is_empty() {
        return String::new();
    }
    let enforced = mode.current() == "product"
        || settings
            .value_of("oauth2.delegatedPermissionsEnforced")
            .as_bool();
    if !enforced
        || grant_type == "urn:ietf:params:oauth:grant-type:token-exchange"
        || grant_type == "client_credentials"
    {
        return String::new();
    }
    let refused: Vec<&NamedPermission> =
        found.permissions.iter().filter(|p| !p.granted).collect();
    if refused.is_empty() {
        return String::new();
    }
    let who = client_id.trim();
    let honours = mode.current() != "product";
    format!(
        "{}{} has not been granted {}{}. {} defined by {}, and a grant is a value of `oauthDelegatedPermission` on the requesting application's own entry in ou=applications — made at /admin/delegation, or through POST /admin-api/permissions/grant. In development with the setting OFF this request is honoured and the token is audienced and scoped exactly as a granted one would be.",
        if honours {
            "oauth2.delegatedPermissionsEnforced is on, and "
        } else {
            "Product mode enforces delegated permissions, and "
        },
        if who.is_empty() {
            "this client".to_string()
        } else {
            format!("the client \"{}\"", who)
        },
        if refused.len() == 1 {
            "the permission "
        } else {
            "the permissions "
        },
        refused
            .iter()
            .map(|p| format!("\"{}\"", p.scope))
            .collect::<Vec<_>>()
            .join(", "),
        if refused.len() == 1 { "It is" } else { "They are" },
        refused
            .iter()
            .map(|p| format!("the application \"{}\"", p.identifier))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// `parseResourceIndicators(raw)`: each value an absolute URI with no
/// fragment, duplicates dropped; the refusal's sentence otherwise.
#[tracing::instrument(level = "debug")]
pub fn parse_resource_indicators(
    raw: &[String],
) -> Result<Vec<String>, String> {
    let mut wanted: Vec<String> = Vec::new();
    for one in raw {
        let text = one.trim();
        if text.is_empty() {
            continue;
        }
        let Ok(parsed) = url::Url::parse(text) else {
            return Err(format!(
                "RFC 8707 section 2: the resource parameter must be an absolute URI. \"{}\" is not one.",
                text
            ));
        };
        if parsed.fragment().is_some_and(|f| !f.is_empty()) {
            return Err(format!(
                "RFC 8707 section 2: the resource parameter must not include a fragment component. \"{}\" does — and a fragment is the part of a URI a server never receives, so an audience carrying one names something no resource server can match.",
                text
            ));
        }
        if !wanted.iter().any(|w| w == text) {
            wanted.push(text.to_string());
        }
    }
    Ok(wanted)
}

/// `common/registered_targets.ts`.
pub struct RegisteredTargets<'a> {
    pub clients: &'a dyn Clients,
    pub settings: &'a Settings,
}

impl RegisteredTargets<'_> {
    /// `namesManagementApi(target, req, base)`: the API under this base,
    /// or `adminApi.audience`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn names_management_api(&self, target: &str, base: &str) -> bool {
        let wanted = target.trim();
        if wanted.is_empty() {
            return false;
        }
        let configured = self.settings.value_of("adminApi.audience");
        let configured = configured.as_str().trim();
        wanted == format!("{}/admin-api", base)
            || (!configured.is_empty() && wanted == configured)
    }

    /// `ownResourceServer(target, req, base)`: the name of the resource
    /// server a target is, or ''.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn own_resource_server(
        &self,
        target: &str,
        bases: &[String],
    ) -> String {
        let wanted = target.trim();
        if wanted.is_empty() || bases.is_empty() {
            return String::new();
        }
        let under = |path: &str| {
            bases.iter().any(|b| wanted == format!("{}{}", b, path))
        };
        let on = |id: &str, name: &str| {
            if self.clients.seeded(id) {
                name.to_string()
            } else {
                String::new()
            }
        };
        if bases
            .iter()
            .any(|b| JwtAccessTokens::is_own_resource_audience(wanted, b))
        {
            return on(
                "sts-resource",
                "this service's resource server (UserInfo, SCIM, Shared Signals, OpenID4VCI)",
            );
        }
        if self.names_management_api(wanted, &bases[0]) || under("/admin-api") {
            return on("sts-management-api", "the management API (/admin-api)");
        }
        if under("/account-api") {
            return on("sts-account-api", "the account API (/account-api)");
        }
        if under("/report-api") {
            return on("sts-report-api", "the reports API (/report-api)");
        }
        if under("/access/v1") {
            return on("sts-authzen-api", "the AuthZEN API (/access/v1)");
        }
        if under("/uma") {
            return on(
                "sts-uma-protection-api",
                "the UMA 2.0 protection API (/uma)",
            );
        }
        String::new()
    }

    /// `unregistered(targets, req, base)`: those that name nothing
    /// registered.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn unregistered(
        &self,
        targets: &[String],
        bases: &[String],
    ) -> Vec<String> {
        targets
            .iter()
            .filter(|one| !one.is_empty())
            .filter(|one| {
                self.own_resource_server(one, bases).is_empty()
                    && !self.clients.registered_target(one)
            })
            .cloned()
            .collect()
    }
}

/// `RegisteredTargets.describe(targets)`.
#[tracing::instrument(level = "debug")]
pub fn describe_unregistered(targets: &[String]) -> String {
    let named = targets
        .iter()
        .map(|one| {
            let text: String = String::from_utf16_lossy(
                &one.encode_utf16().take(200).collect::<Vec<u16>>(),
            );
            format!("\"{}\"", text)
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{}{} no registered target. A token is addressed only to one of this service's own resource servers or to an application registered ahead of time (the console, /admin-api, RFC 7591, an LDAP add under ou=applications or an OpenID Federation), found by its oauthAudience, permission base URI, client_id or identifier; one that was only seen is not registered.",
        named,
        if targets.len() == 1 { " names" } else { " name" }
    )
}
