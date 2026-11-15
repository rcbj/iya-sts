// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE FAMILIES' OWN OPERATIONS (rule 7): the certificate authority's and
//! the three enrollment protocols' acts on `/admin-api` —
//! `admin-ui/pki_admin.ts`'s `pkiAction()`, and `acme_console.ts`,
//! `est_console.ts` and `scep_console.ts`'s `*Action()` — answered by the
//! families' own crates (`sts-pki`, `sts-enroll`), which the composition
//! root holds once the store is open. This crate routes them
//! ([`crate::routing`]) and holds the answers to the model; the port
//! answers them, `None` before the families exist.

use serde_json::Value as Json;

use crate::gate::Caller;
use crate::request::Query;
use crate::setup::Answered;

/// One family operation, as the router hands it on.
pub struct Asked<'a> {
    /// The operationId (`createAcmeEab`), or '' for an action nobody
    /// defined on the family's `:action` route.
    pub operation_id: &'a str,
    /// The `:action` route's family: `pki`, `acme`, `est` or `scep`.
    pub family: &'a str,
    /// The action the path names (`create-eab`), or '' for a read.
    pub action: &'a str,
    pub query: &'a Query,
    pub body: &'a Json,
    pub caller: Option<&'a Caller>,
    /// The request's base URL, the ambient realm's prefix included.
    pub base: &'a str,
}

/// What answers them.
pub trait FamilyPorts: Send + Sync {
    /// The answer, or `None` while the families do not exist.
    fn answer(&self, asked: &Asked<'_>) -> Option<Answered> {
        let _ = asked;
        None
    }
}

/// A process with no family.
pub struct NoFamilies;

impl FamilyPorts for NoFamilies {}

/// The family an operation's path names.
#[tracing::instrument(level = "debug")]
pub fn family_of(path: &str) -> &'static str {
    let under = path.strip_prefix("/admin-api/").unwrap_or("");
    match under.split('/').next().unwrap_or("") {
        "pki" => "pki",
        "acme" => "acme",
        "est" => "est",
        "scep" => "scep",
        _ => "",
    }
}
