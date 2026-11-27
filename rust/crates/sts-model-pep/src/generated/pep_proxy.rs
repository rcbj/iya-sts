// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/pep/ (#1830) by models/lib/pep_lib.mjs, through
// models/lib/rust_lib.mjs (#444, D15). Do not edit: change the model and
// run tests/tools/regenerate-pep-model.sh. tests/model_pep.js fails when
// this differs.

pub mod components {
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Account {
        /// This account's id in the browser's set: 12 base64url characters.
        pub account: String,
        pub username: String,
        pub name: String,
        pub application: String,
        pub active: bool,
    }

    /// The form of /.iya-pep/accounts/switch and /.iya-pep/accounts/logout,
    /// application/x-www-form-urlencoded; the same names in the query are read too,
    /// the form winning.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AccountForm {
        pub account: String,
        /// Where to go next: a path on a configured route, not under /.iya-pep/;
        /// anything else is /.
        #[serde(rename = "return", default, skip_serializing_if = "Option::is_none")]
        pub return_: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Accounts {
        pub accounts: Vec<crate::pep_proxy::components::Account>,
        /// PEP_PROXY_MAX_ACCOUNTS: how many a browser may hold (1 to 32, 5 by
        /// default).
        pub max: i64,
    }

    pub type Page = String;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum RefusalError {
        #[serde(rename = "invalid_request")]
        InvalidRequest,
        #[serde(rename = "unauthorized")]
        Unauthorized,
        #[serde(rename = "invalid_token")]
        InvalidToken,
        #[serde(rename = "access_denied")]
        AccessDenied,
        #[serde(rename = "not_found")]
        NotFound,
        #[serde(rename = "method_not_allowed")]
        MethodNotAllowed,
        #[serde(rename = "payload_too_large")]
        PayloadTooLarge,
        #[serde(rename = "too_many_requests")]
        TooManyRequests,
        #[serde(rename = "temporarily_unavailable")]
        TemporarilyUnavailable,
        #[serde(rename = "gateway_timeout")]
        GatewayTimeout,
        #[serde(rename = "bad_gateway")]
        BadGateway,
    }

    /// A refusal to a request whose Accept does not name text/html (one that does
    /// gets the error page). error follows the status: 400 invalid_request, 401
    /// unauthorized or invalid_token, 403 access_denied, 404 not_found, 405
    /// method_not_allowed, 413 payload_too_large, 429 too_many_requests, 504
    /// gateway_timeout, any other bad_gateway. Cache-Control: no-store.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Refusal {
        pub error: RefusalError,
        pub error_description: String,
    }

    /// The form of /.iya-pep/accounts/logout-all.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReturnForm {
        #[serde(rename = "return", default, skip_serializing_if = "Option::is_none")]
        pub return_: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignedOut {
        /// Whether a session was held and ended.
        #[serde(rename = "signedOut")]
        pub signed_out: bool,
    }

}

/// The start page
pub mod get_start_page {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/";
    pub const OPERATION_ID: &str = "getStartPage";
}

/// The account chooser
pub mod get_accounts {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/.iya-pep/accounts";
    pub const OPERATION_ID: &str = "getAccounts";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "return", default, skip_serializing_if = "Option::is_none")]
        pub return_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
    }

    pub type Answer200 = crate::pep_proxy::components::Accounts;
}

/// Sign in another account
pub mod get_accounts_add {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/.iya-pep/accounts/add";
    pub const OPERATION_ID: &str = "getAccountsAdd";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "return")]
        pub return_: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
    }
}

/// Sign one account out
pub mod post_accounts_logout {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/.iya-pep/accounts/logout";
    pub const OPERATION_ID: &str = "postAccountsLogout";

    /// The body is not JSON (an upload): its bytes.
    pub type Body = Vec<u8>;
}

/// Sign every account out
pub mod post_accounts_logout_all {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/.iya-pep/accounts/logout-all";
    pub const OPERATION_ID: &str = "postAccountsLogoutAll";

    /// The body is not JSON (an upload): its bytes.
    pub type Body = Vec<u8>;
}

/// Make an account the active one
pub mod post_accounts_switch {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/.iya-pep/accounts/switch";
    pub const OPERATION_ID: &str = "postAccountsSwitch";

    /// The body is not JSON (an upload): its bytes.
    pub type Body = Vec<u8>;
}

/// The OpenID Connect redirect URI
pub mod get_callback {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/.iya-pep/callback";
    pub const OPERATION_ID: &str = "getCallback";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iss: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
    }
}

/// The logo the proxy's pages show
pub mod get_logo {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/.iya-pep/logo.png";
    pub const OPERATION_ID: &str = "getLogo";
}

/// Sign out of a single-account session
pub mod get_logout {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/.iya-pep/logout";
    pub const OPERATION_ID: &str = "getLogout";

    pub type Answer200 = crate::pep_proxy::components::SignedOut;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getAccounts", 200) => Some(serde_json::from_value::<get_accounts::Answer200>(value.clone()).map(|_| ())),
        ("getLogout", 200) => Some(serde_json::from_value::<get_logout::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
