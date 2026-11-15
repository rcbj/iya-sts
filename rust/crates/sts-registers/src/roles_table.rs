// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The role tables of `common/roles.js` and `admin-ui/admin_rbac.ts`, word
//! for word: the built-in roles (`BUILT_IN`), the native roles
//! (`NATIVE_ROLES`, the console's three first) and the console roster's
//! three roles (`ROLES`). The sentences are what `/admin-api/roles` and
//! `/admin-api/rbac` answer; the vectors check every one.

use super::{BuiltIn, NativeRole, RosterRole};

pub const BUILT_IN: &[BuiltIn] = &[
    BuiltIn {
        name: "EVERYBODY",
        permission: None,
        what: concat!(
            "Anybody at all, authenticated or not, person or application. THIS ",
            "IS THE DEFAULT REQUIREMENT: an application that names no required ",
            "role requires this one, everybody holds it, and nothing is refused ",
            "— which is exactly how this service behaved before roles existed.",
        ),
    },
    BuiltIn {
        name: "ALL_AUTHENTICATED_USERS",
        permission: None,
        what: concat!(
            "A person with a live authenticated session in the security context ",
            "this decision is being made in.",
        ),
    },
    BuiltIn {
        name: "ALL_UNAUTHENTICATED_USERS",
        permission: None,
        what: concat!(
            "A person who has NOT authenticated. It is not the negation of the ",
            "role above as far as a policy is concerned — it is a name a target ",
            "can match, and XACML targets cannot say \"not\".",
        ),
    },
    BuiltIn {
        name: "ALL_APPLICATIONS",
        permission: None,
        what: "Any client, however it turned up.",
    },
    BuiltIn {
        name: "ALL_AUTHENTICATED_APPLICATIONS",
        permission: None,
        what: concat!(
            "A client that PROVED who it is — a secret, a private_key_jwt ",
            "assertion, or a verified client certificate. A public client that ",
            "merely sent a client_id is not this.",
        ),
    },
    BuiltIn {
        name: "ALL_UNAUTHENTICATED_APPLICATIONS",
        permission: None,
        what: "A public client that proved nothing.",
    },
    BuiltIn {
        name: "REMOTE_PEPS",
        permission: None,
        what: concat!(
            "A remote XACML Policy Enforcement Point: whoever is a member of ",
            "the group named by `roles.remotePepGroup` (default \"remote-peps\"). ",
            "It is what `/xacml/pep/register`, `/xacml/pep/policies` and ",
            "`/xacml/pep/heartbeat` require, and the party that holds it is ",
            "normally a client-certificate DN rather than a person — the ",
            "certificate says WHO, and this group says whether they may.",
        ),
    },
    BuiltIn {
        name: "XACML_USER",
        permission: None,
        what: concat!(
            "A caller of the XACML surface proper: whoever is a member of the ",
            "group named by `roles.xacmlUserGroup` (default \"xacml-users\"). It ",
            "is what `GET /xacml`, `POST /xacml/pdp` and `GET /xacml/policies` ",
            "require, and the party that holds it is normally a ",
            "client-certificate DN — the certificate says WHO, and this group ",
            "says whether they may. It is deliberately NOT REMOTE_PEPS: that ",
            "role reaches the three /xacml/pep endpoints, which hand out the ",
            "documents this service enforces its own access with, and one group ",
            "granting both would make admitting a caller to the XACML surface ",
            "proper silently admit it to those.",
        ),
    },
    BuiltIn {
        name: "AUTHZEN_PEPS",
        permission: None,
        what: concat!(
            "An AuthZEN Policy Enforcement Point: whoever is a member of the ",
            "group named by `roles.authzenPepGroup` (default \"authzen-peps\") — ",
            "a person, a service account, or an application calling with its ",
            "own access token. It is what the AuthZEN Authorization API under ",
            "`/access/v1` requires, and nothing else: it reads no policy and no ",
            "person's attributes, which is why it is neither XACML_USER nor ",
            "REMOTE_PEPS.",
        ),
    },
    BuiltIn {
        name: "OWNER_READ",
        permission: Some("owner:read"),
        what: concat!(
            "An OWNER (#607): whoever a role, a group, a service account or an ",
            "application in this realm names as an owner, directly or through a ",
            "group they are in. Authorizes the owner:read permission: reading, ",
            "through /admin-api, the objects they own and nothing else. ",
            "Computed when a decision is made.",
        ),
    },
    BuiltIn {
        name: "OWNER_WRITE",
        permission: Some("owner:write"),
        what: concat!(
            "An OWNER (#607), as OWNER_READ. Authorizes the owner:write ",
            "permission: changing, through /admin-api, the objects they own, ",
            "within the actions the access-control policy's owner rule allows ",
            "each kind — never creating, deleting or renaming one, and never an ",
            "object protected from its owners.",
        ),
    },
];

pub const NATIVE_ROLES: &[NativeRole] = &[
    NativeRole {
        name: "ADMIN_READ",
        console_role: "read",
        permission: "admin:read",
        group_settings: &["admin.readGroup", "admin.writeGroup", "admin.securityGroup"],
        seed_applications: &["sts-api-client"],
        seed_conferred_by: &[],
        seed_groups: &[],
        what: concat!(
            "Admin Read: every READ on /admin-api. Held by the console's Admin ",
            "Read, Admin Write and Security Administrator groups (both of the ",
            "others imply Admin Read) and by the applications listed here. ",
            "Authorizes the admin:read permission.",
        ),
    },
    NativeRole {
        name: "ADMIN_WRITE",
        console_role: "write",
        permission: "admin:write",
        group_settings: &["admin.writeGroup"],
        seed_applications: &["sts-api-client"],
        seed_conferred_by: &[],
        seed_groups: &[],
        what: concat!(
            "Admin Write: every /admin-api operation that CHANGES anything. ",
            "Held by the console's Admin Write group and by the applications ",
            "listed here. Authorizes the admin:write permission. It does not ",
            "imply Admin Read on a token: a token may carry either scope, and ",
            "the policy asks for the one the operation needs.",
        ),
    },
    NativeRole {
        name: "SECURITY_ADMIN",
        console_role: "security",
        permission: "admin:security",
        group_settings: &["admin.securityGroup"],
        seed_applications: &["sts-api-client"],
        seed_conferred_by: &[],
        seed_groups: &[],
        what: concat!(
            "Security Administrator: the /admin-api operations that change ",
            "security — a policy on Directory → Policies, a policy named on an ",
            "application, group or person, a grant of this role, and the ",
            "account of a person who holds it. Admin Write does not reach them. ",
            "Held by the console's Security Administrator group and by the ",
            "applications listed here. Authorizes the admin:security ",
            "permission.",
        ),
    },
    NativeRole {
        name: "ADMIN_CONSOLE",
        console_role: "",
        permission: "admin:console",
        group_settings: &[],
        seed_applications: &[],
        seed_conferred_by: &["sts-admin-console"],
        seed_groups: &[],
        what: concat!(
            "The admin console: the operations under /admin-api/console that ",
            "exist only to draw the console — its frame, its drawings and its ",
            "form helpers. Authorizes the admin:console permission. Conferred ",
            "by the console's own client, sts-admin-console, on every person ",
            "who signs in to the console, and held by nobody as a member. It ",
            "grants nothing else: a page that shows realm data also asks for ",
            "ADMIN_READ.",
        ),
    },
    NativeRole {
        name: "DEVICE_COMPLIANCE",
        console_role: "",
        permission: "device:compliance",
        group_settings: &[],
        seed_applications: &[],
        seed_conferred_by: &[],
        seed_groups: &[],
        what: concat!(
            "The device compliance feed: an MDM or posture feed reporting a ",
            "device's compliance through POST /admin-api/device-compliance, and ",
            "nothing else on /admin-api. Authorizes the device:compliance ",
            "permission. Seeded with no member: add the feed's application.",
        ),
    },
    NativeRole {
        name: "SSF_READ",
        console_role: "",
        permission: "ssf.read",
        group_settings: &[],
        seed_applications: &[],
        seed_conferred_by: &[],
        seed_groups: &["ssf-read"],
        what: concat!(
            "Shared Signals read. Authorizes the ssf.read permission. A person ",
            "is issued it only while they belong to this role's group, seeded ",
            "as ssf-read, and the application they are signing in to is a ",
            "member of this role. An application is issued it on its own token ",
            "only while it is a member. SSF_MANAGE does not authorize it.",
        ),
    },
    NativeRole {
        name: "SSF_MANAGE",
        console_role: "",
        permission: "ssf.manage",
        group_settings: &[],
        seed_applications: &[],
        seed_conferred_by: &[],
        seed_groups: &["ssf-manage"],
        what: concat!(
            "Shared Signals write. Authorizes the ssf.manage permission. A ",
            "person is issued it only while they belong to this role's group, ",
            "seeded as ssf-manage, and the application they are signing in to ",
            "is a member of this role. An application is issued it on its own ",
            "token only while it is a member. It does not authorize ssf.read.",
        ),
    },
    NativeRole {
        name: "REPORT_USE",
        console_role: "",
        permission: "report:use",
        group_settings: &[],
        seed_applications: &["sts-api-client"],
        seed_conferred_by: &[],
        seed_groups: &["report-users"],
        what: concat!(
            "Reports, as a user. Authorizes the report:use permission: the ",
            "reports application and /report-api for the definitions and jobs ",
            "the holder owns or is shared, as the access-control policy ",
            "decides. A person holds it through this role's group, seeded as ",
            "report-users, as a direct member, or on the console roster (Admin ",
            "Read or Admin Write); an application holds it as a member and is ",
            "issued it on its own token, reaching only the definitions and jobs ",
            "it defined. The bootstrap client, sts-api-client, is seeded a ",
            "member.",
        ),
    },
    NativeRole {
        name: "REPORT_ADMIN",
        console_role: "",
        permission: "report:admin",
        group_settings: &[],
        seed_applications: &[],
        seed_conferred_by: &[],
        seed_groups: &["report-admins"],
        what: concat!(
            "Reports, as an administrator. Authorizes the report:admin ",
            "permission: every definition and every job in the realm, as the ",
            "access-control policy decides. A person holds it through this ",
            "role's group, seeded as report-admins, as a direct member, or as ",
            "Admin Write on the console roster; an application holding it still ",
            "reaches only what it defined. It does not authorize report:use: a ",
            "token asks for the scopes it needs.",
        ),
    },
];

pub const ROSTER_ROLES: &[RosterRole] = &[
    RosterRole {
        id: "read",
        label: "Admin Read",
        setting: "admin.readGroup",
        implies: &[],
        what: concat!(
            "Look at every page of this console, and at every ?format=json view ",
            "of one. It changes nothing: a reader can see which tokens are ",
            "revoked and cannot revoke one.",
        ),
    },
    RosterRole {
        id: "write",
        label: "Admin Write",
        setting: "admin.writeGroup",
        implies: &["read"],
        what: concat!(
            "Post every form on this console — revoke a token, add a custom ",
            "claim, change a setting, create a person, grant a role — except ",
            "the ones that change security, which are the Security ",
            "Administrator's. IT INCLUDES READ, so a member of this role alone ",
            "can use the rest of the console.",
        ),
    },
    RosterRole {
        id: "security",
        label: "Security Administrator",
        setting: "admin.securityGroup",
        implies: &["read"],
        what: concat!(
            "Change security: save or reset a policy on Directory → Policies, ",
            "name a policy on an application, group or person, grant or revoke ",
            "this role, and act on the account of a person who holds it. Admin ",
            "Write cannot do any of these. IT INCLUDES READ AND NOT WRITE, so ",
            "it can be held by somebody who is not otherwise an administrator.",
        ),
    },
];
