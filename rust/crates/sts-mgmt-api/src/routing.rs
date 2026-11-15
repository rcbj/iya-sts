// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Which handler answers each operation of the model: an EXHAUSTIVE match
//! over [`Operation`], whose last arm is the list of operations not yet
//! ported (`not_yet_ported.rs`). So the build itself holds the rule Node's
//! route table holds by construction: every operation the model has is
//! routed or named as not yet ported, and nothing is routed that the model
//! does not have (a handler can only be bound to an `Operation`).

use crate::operations::Operation;

/// The handlers this crate has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    Index,
    OpenApi,
    ConsoleOperations,
    ConsoleOpenApi,
    Config,
    ConfigAction,
    Mode,
    Realms,
    RealmsAction,
    Status,
    /// `GET /admin-api/applications` (the list; the drill-down is not yet
    /// ported).
    Applications,
    /// `POST /admin-api/applications/{action}`, the register's own acts.
    ApplicationsAction,
}

include!("not_yet_ported.rs");

/// The handler of an operation, or `None` while it is not ported.
#[tracing::instrument(level = "debug")]
pub fn handler_of(operation: Operation) -> Option<Handler> {
    match operation {
        Operation::GetIndex => Some(Handler::Index),
        Operation::GetOpenApi => Some(Handler::OpenApi),
        Operation::GetConsoleOperations => Some(Handler::ConsoleOperations),
        Operation::GetConsoleOpenApi => Some(Handler::ConsoleOpenApi),
        Operation::GetConfig => Some(Handler::Config),
        Operation::SetSetting
        | Operation::SetSettings
        | Operation::ResetSetting
        | Operation::ResetAllSettings => Some(Handler::ConfigAction),
        Operation::GetMode => Some(Handler::Mode),
        Operation::GetRealms => Some(Handler::Realms),
        Operation::CreateRealm
        | Operation::UpdateRealm
        | Operation::SetRealmSetting
        | Operation::UnsetRealmSetting
        | Operation::RemoveRealm => Some(Handler::RealmsAction),
        Operation::GetStatus => Some(Handler::Status),
        Operation::GetApplications => Some(Handler::Applications),
        Operation::CreateApplication
        | Operation::SetApplicationAttribute
        | Operation::AddApplicationValue
        | Operation::RemoveApplicationValue
        | Operation::UpdateApplicationFields
        | Operation::ConfirmApplicationReturnAddress
        | Operation::DiscardApplicationReturnAddress
        | Operation::AddApplicationOwner
        | Operation::RemoveApplicationOwner
        | Operation::RegenerateApplicationClientSecret
        | Operation::RotateApplicationClientSecret
        | Operation::AddApplicationClientSecret
        | Operation::RemoveApplicationClientSecret
        | Operation::DeleteApplication => Some(Handler::ApplicationsAction),
        not_yet_ported!() => None,
    }
}

/// The handler a `:action` route's unknown action reaches: the one its
/// family's actions are answered by, which refuses it in its own words.
#[tracing::instrument(level = "debug")]
pub fn handler_of_route(route: &str) -> Option<Handler> {
    match route {
        "/admin-api/config/:action" => Some(Handler::ConfigAction),
        "/admin-api/realms/:action" => Some(Handler::RealmsAction),
        "/admin-api/applications/:action" => Some(Handler::ApplicationsAction),
        _ => None,
    }
}
