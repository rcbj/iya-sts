// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE `/admin-api` OPERATIONS EACH REGISTER BACKS, for the API slice to
//! wire (`mgmt-api/admin_api.ts`'s route table). Each row is the operation
//! id the OpenAPI document publishes, its method and path, and the act in
//! this crate that answers it with Node's result and code; the HTTP status
//! (200, or 400 for a refusal) and the response model are the API layer's.
//!
//! An operation the same door serves but this crate does not port (the
//! other fifty-two `users` actions, the application register's own acts)
//! is not listed; [`crate::people::People::users`] answers `None` for one.

/// One operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operation {
    pub operation_id: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    /// The act, as `module::Type::method`.
    pub act: &'static str,
}

const fn op(
    operation_id: &'static str,
    method: &'static str,
    path: &'static str,
    act: &'static str,
) -> Operation {
    Operation {
        operation_id,
        method,
        path,
        act,
    }
}

/// Every operation this crate answers.
pub static OPERATIONS: &[Operation] = &[
    op(
        "createUser",
        "POST",
        "/admin-api/users/create",
        "people::People::users",
    ),
    op(
        "disableUserAccount",
        "POST",
        "/admin-api/users/disable",
        "people::People::users",
    ),
    op(
        "enableUserAccount",
        "POST",
        "/admin-api/users/enable",
        "people::People::users",
    ),
    op(
        "createGroup",
        "POST",
        "/admin-api/groups/create",
        "people::People::groups",
    ),
    op(
        "addGroupMember",
        "POST",
        "/admin-api/groups/add-member",
        "people::People::groups",
    ),
    op(
        "setGroupMail",
        "POST",
        "/admin-api/groups/set-mail",
        "people::People::groups",
    ),
    op(
        "setGroupPolicy",
        "POST",
        "/admin-api/groups/set-policy",
        "people::People::groups",
    ),
    op(
        "addGroupOwner",
        "POST",
        "/admin-api/groups/add-owner",
        "people::People::groups",
    ),
    op(
        "removeGroupOwner",
        "POST",
        "/admin-api/groups/remove-owner",
        "people::People::groups",
    ),
    op(
        "grantAdminRole",
        "POST",
        "/admin-api/rbac/grant",
        "rbac::Rbac::act",
    ),
    op(
        "revokeAdminRole",
        "POST",
        "/admin-api/rbac/revoke",
        "rbac::Rbac::act",
    ),
    op(
        "createRole",
        "POST",
        "/admin-api/roles/create-role",
        "role_actions::RoleActions::act",
    ),
    op(
        "deleteRole",
        "POST",
        "/admin-api/roles/delete-role",
        "role_actions::RoleActions::act",
    ),
    op(
        "describeRole",
        "POST",
        "/admin-api/roles/describe-role",
        "role_actions::RoleActions::act",
    ),
    op(
        "addRoleMember",
        "POST",
        "/admin-api/roles/add-member",
        "role_actions::RoleActions::act",
    ),
    op(
        "removeRoleMember",
        "POST",
        "/admin-api/roles/remove-member",
        "role_actions::RoleActions::act",
    ),
    op(
        "addRolePermission",
        "POST",
        "/admin-api/roles/add-permission",
        "role_actions::RoleActions::act",
    ),
    op(
        "removeRolePermission",
        "POST",
        "/admin-api/roles/remove-permission",
        "role_actions::RoleActions::act",
    ),
    op(
        "addRoleConferringClient",
        "POST",
        "/admin-api/roles/add-conferring-client",
        "role_actions::RoleActions::act",
    ),
    op(
        "removeRoleConferringClient",
        "POST",
        "/admin-api/roles/remove-conferring-client",
        "role_actions::RoleActions::act",
    ),
    op(
        "addRoleOwner",
        "POST",
        "/admin-api/roles/add-owner",
        "role_actions::RoleActions::act",
    ),
    op(
        "removeRoleOwner",
        "POST",
        "/admin-api/roles/remove-owner",
        "role_actions::RoleActions::act",
    ),
    op(
        "setPermissionBase",
        "POST",
        "/admin-api/permissions/set-permission-base",
        "app_permissions::AppPermissions::act",
    ),
    op(
        "definePermission",
        "POST",
        "/admin-api/permissions/define-permission",
        "app_permissions::AppPermissions::act",
    ),
    op(
        "removePermission",
        "POST",
        "/admin-api/permissions/remove-permission",
        "app_permissions::AppPermissions::act",
    ),
    op(
        "grantPermission",
        "POST",
        "/admin-api/permissions/grant-permission",
        "app_permissions::AppPermissions::act",
    ),
    op(
        "revokePermission",
        "POST",
        "/admin-api/permissions/revoke-permission",
        "app_permissions::AppPermissions::act",
    ),
    op(
        "setOwnerProtected",
        "POST",
        "/admin-api/ownership/set-protected",
        "ownership::Ownership::set_protected",
    ),
];
