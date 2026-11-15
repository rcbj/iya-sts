// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE OPERATION TABLE (`authn/authn_api.ts`'s `SCREEN_OPERATIONS`,
//! `WALLET_OPERATIONS`, `LOGOUT_OPERATIONS`, `ACCOUNT_OPERATIONS` and
//! `CONSENT_OPERATIONS`, in that order — the order `GET /authn-api` lists
//! them in).
//!
//! The NAMES of each operation (its summary, what it mirrors, its
//! parameters, its request and its answers) are the model's
//! (`models/api/authn.tsp`, served as `src/generated/openapi.authn.json`);
//! what is left here is the routing Node keeps in code: the path, the
//! handler, the access, the form action it is, and the code a body it does
//! not take is recorded under. `build.rs` refuses a row the model does not
//! have and an operation the model has that no row routes.

use sts_core::errors::{codes, ErrorCode};

/// Who may ask an operation, and what keys it (`Operation.access`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// None.
    Public,
    /// A pending sign-in's id.
    Pending,
    /// A forced password change's step id.
    Step,
    /// A second-factor or emailed-factor step's id.
    Mfa,
    /// A wallet sign-in's transaction.
    Wallet,
    /// A pending consent's id.
    Consent,
    /// The browser's `sts_session` cookie.
    Session,
}

impl Access {
    /// The word `GET /authn-api` names it by.
    // A hot path: once per operation listed; no span.
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Public => "public",
            Access::Pending => "pending",
            Access::Step => "step",
            Access::Mfa => "mfa",
            Access::Wallet => "wallet",
            Access::Consent => "consent",
            Access::Session => "session",
        }
    }
}

/// The handler a row names (`Operation.handler`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    Index,
    OpenApi,
    Screen,
    Partners,
    Act,
    PasskeyOptions,
    PasswordChange,
    ChangePassword,
    PasswordChangeStartOver,
    MfaStep,
    MfaAct,
    Wallet,
    LogoutView,
    LogoutAct,
    LogoutAccountsView,
    LogoutAccountsAct,
    AccountsGet,
    AccountsPost,
    AccountsList,
    Consent,
}

/// One operation of the API.
#[derive(Debug, Clone, Copy)]
pub struct Operation {
    pub method: &'static str,
    /// The Express path, `:id` a path parameter.
    pub path: &'static str,
    pub id: &'static str,
    pub access: Access,
    /// For an act: the form's `action` it is.
    pub action: Option<&'static str>,
    pub handler: Handler,
    /// The code a body this operation does not take is recorded under,
    /// where its form had one of its own.
    pub refused_code: Option<ErrorCode>,
}

const fn op(
    method: &'static str,
    path: &'static str,
    id: &'static str,
    access: Access,
    action: Option<&'static str>,
    handler: Handler,
    refused_code: Option<ErrorCode>,
) -> Operation {
    Operation {
        method,
        path,
        id,
        access,
        action,
        handler,
        refused_code,
    }
}

use Access as A;
use Handler as H;

/// Every operation, in Node's order.
pub static OPERATIONS: &[Operation] = &[
    op("GET", "/authn-api", "getIndex", A::Public, None, H::Index, None),
    op(
        "GET",
        "/authn-api/openapi.json",
        "getOpenApi",
        A::Public,
        None,
        H::OpenApi,
        None,
    ),
    op(
        "GET",
        "/authn-api/pending/:id",
        "getScreen",
        A::Pending,
        None,
        H::Screen,
        None,
    ),
    op(
        "GET",
        "/authn-api/pending/:id/partners",
        "getPartners",
        A::Pending,
        None,
        H::Partners,
        None,
    ),
    op(
        "POST",
        "/authn-api/pending/:id/password",
        "signInWithPassword",
        A::Pending,
        Some("login"),
        H::Act,
        None,
    ),
    op(
        "POST",
        "/authn-api/pending/:id/cancel",
        "cancelSignIn",
        A::Pending,
        Some("cancel"),
        H::Act,
        None,
    ),
    op(
        "POST",
        "/authn-api/pending/:id/anonymous",
        "continueAnonymously",
        A::Pending,
        Some("anonymous"),
        H::Act,
        None,
    ),
    op(
        "POST",
        "/authn-api/pending/:id/certificate",
        "continueWithCertificate",
        A::Pending,
        Some("certificate"),
        H::Act,
        None,
    ),
    op(
        "POST",
        "/authn-api/pending/:id/email",
        "signInByEmail",
        A::Pending,
        Some("email"),
        H::Act,
        None,
    ),
    op(
        "POST",
        "/authn-api/pending/:id/passkey/options",
        "passkeyOptions",
        A::Pending,
        Some("passkey-options"),
        H::PasskeyOptions,
        None,
    ),
    op(
        "POST",
        "/authn-api/pending/:id/passkey",
        "signInWithPasskey",
        A::Pending,
        Some("passkey"),
        H::Act,
        None,
    ),
    op(
        "GET",
        "/authn-api/password-change/:id",
        "getPasswordChange",
        A::Step,
        None,
        H::PasswordChange,
        None,
    ),
    op(
        "POST",
        "/authn-api/password-change/:id",
        "changePassword",
        A::Step,
        Some("password-change"),
        H::ChangePassword,
        None,
    ),
    op(
        "POST",
        "/authn-api/password-change/:id/start-over",
        "startOverFromPasswordChange",
        A::Step,
        Some("start-over"),
        H::PasswordChangeStartOver,
        None,
    ),
    op(
        "GET",
        "/authn-api/mfa/:id",
        "getStep",
        A::Mfa,
        None,
        H::MfaStep,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/totp",
        "checkCode",
        A::Mfa,
        Some("totp"),
        H::MfaAct,
        Some(codes::STS_AUTHN_0039),
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/backup-code",
        "spendRecoveryCode",
        A::Mfa,
        Some("backup-code"),
        H::MfaAct,
        Some(codes::STS_AUTHN_0041),
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/password",
        "checkFactorPassword",
        A::Mfa,
        Some("password"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/webauthn/options",
        "passkeyStepOptions",
        A::Mfa,
        Some("webauthn-options"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/webauthn",
        "finishPasskeyStep",
        A::Mfa,
        Some("webauthn"),
        H::MfaAct,
        Some(codes::STS_AUTHN_0020),
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/setup/totp",
        "beginAppEnrolment",
        A::Mfa,
        Some("totp"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/setup/confirm",
        "confirmAppEnrolment",
        A::Mfa,
        Some("confirm-totp"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/setup/webauthn",
        "beginKeyEnrolment",
        A::Mfa,
        Some("webauthn"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/skip",
        "ignoreOffer",
        A::Mfa,
        Some("ignore"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/post-login/register",
        "registerPostLoginPasskey",
        A::Mfa,
        Some("register"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/post-login/skip",
        "skipPostLoginActivity",
        A::Mfa,
        Some("skip"),
        H::MfaAct,
        Some(codes::STS_AUTHN_0474),
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/email/send",
        "sendEmailedFactor",
        A::Mfa,
        Some("send"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/email/code",
        "checkEmailedCode",
        A::Mfa,
        Some("verify"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/email-link/open",
        "spendEmailedLink",
        A::Mfa,
        Some("open"),
        H::MfaAct,
        None,
    ),
    op(
        "POST",
        "/authn-api/mfa/:id/start-over",
        "startOver",
        A::Mfa,
        Some("start-over"),
        H::MfaAct,
        None,
    ),
    // --- the wallet (#574) ---------------------------------------------------
    op(
        "GET",
        "/authn-api/wallet",
        "getWalletStart",
        A::Wallet,
        None,
        H::Wallet,
        None,
    ),
    op(
        "POST",
        "/authn-api/wallet",
        "startWalletSignIn",
        A::Wallet,
        None,
        H::Wallet,
        Some(codes::STS_VC_0069),
    ),
    op(
        "GET",
        "/authn-api/wallet/:state",
        "getWalletWait",
        A::Wallet,
        None,
        H::Wallet,
        None,
    ),
    op(
        "POST",
        "/authn-api/wallet/:state/status",
        "walletStatus",
        A::Wallet,
        None,
        H::Wallet,
        Some(codes::STS_VC_0069),
    ),
    op(
        "POST",
        "/authn-api/wallet/:state/dc-api",
        "answerWalletDcApi",
        A::Wallet,
        None,
        H::Wallet,
        Some(codes::STS_VC_0069),
    ),
    // --- the sign-out (#577) -------------------------------------------------
    op(
        "GET",
        "/authn-api/logout",
        "getSignOut",
        A::Session,
        None,
        H::LogoutView,
        None,
    ),
    op(
        "POST",
        "/authn-api/logout",
        "signOut",
        A::Session,
        Some("logout"),
        H::LogoutAct,
        Some(codes::STS_LOGOUT_0003),
    ),
    op(
        "GET",
        "/authn-api/logout/accounts",
        "getSignOutAccounts",
        A::Session,
        None,
        H::LogoutAccountsView,
        None,
    ),
    op(
        "POST",
        "/authn-api/logout/accounts",
        "chooseSignOutAccount",
        A::Session,
        Some("account"),
        H::LogoutAccountsAct,
        Some(codes::STS_LOGOUT_0003),
    ),
    // --- several accounts in one browser (#561) ------------------------------
    op(
        "GET",
        "/authn-api/pending/:id/accounts",
        "getAccountChoice",
        A::Pending,
        None,
        H::AccountsGet,
        None,
    ),
    op(
        "POST",
        "/authn-api/pending/:id/accounts/select",
        "selectAccount",
        A::Pending,
        Some("select"),
        H::AccountsPost,
        Some(codes::STS_AUTHN_0342),
    ),
    op(
        "POST",
        "/authn-api/pending/:id/accounts/another",
        "useAnotherAccount",
        A::Pending,
        Some("another"),
        H::AccountsPost,
        Some(codes::STS_AUTHN_0342),
    ),
    op(
        "POST",
        "/authn-api/pending/:id/accounts/forget",
        "forgetAccount",
        A::Pending,
        Some("forget"),
        H::AccountsPost,
        Some(codes::STS_AUTHN_0342),
    ),
    op(
        "GET",
        "/authn-api/accounts",
        "getAccounts",
        A::Session,
        None,
        H::AccountsList,
        None,
    ),
    // --- the consent screen (#576) -------------------------------------------
    op(
        "GET",
        "/authn-api/consent/:id",
        "getConsent",
        A::Consent,
        None,
        H::Consent,
        None,
    ),
    op(
        "POST",
        "/authn-api/consent/:id",
        "answerConsent",
        A::Consent,
        None,
        H::Consent,
        None,
    ),
];

impl Operation {
    /// The path as the document names it: `:id` as `{id}`.
    #[tracing::instrument(level = "trace")]
    pub fn document_path(&self) -> String {
        let mut out = String::new();
        for (i, part) in self.path.split('/').enumerate() {
            if i > 0 {
                out.push('/');
            }
            match part.strip_prefix(':') {
                Some(name) => {
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
                None => out.push_str(part),
            }
        }
        out
    }
}

/// The row an operation id names.
#[tracing::instrument(level = "trace")]
pub fn by_id(id: &str) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|op| op.id == id)
}

/// The row a request matches, with its path parameter (decoded), as
/// Express matches it: in table order, case-insensitively, with an
/// optional trailing slash. `Err` is a parameter that does not decode.
#[tracing::instrument(level = "trace")]
pub fn matching(
    method: &str,
    path: &str,
) -> Option<(&'static Operation, Result<Option<String>, ()>)> {
    for op in OPERATIONS {
        if !op.method.eq_ignore_ascii_case(method) {
            continue;
        }
        if let Some(found) = sts_http::surfaces::express_match(op.path, path) {
            return Some((op, found.map(|params| params.into_iter().next())));
        }
    }
    None
}
