// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The one place `development` and `product` are told apart. A port of
//! `common/mode.js`, whose comments argue each predicate (rust/DESIGN.md
//! section 4.4).
//!
//! **A behaviour that differs between the modes is a PREDICATE at the call
//! site, named for the QUESTION** — `mode.verifies_credentials()` says why a
//! branch exists where "is this product?" says only when. So the mode itself
//! is private to this module: a family asks a predicate, and the day one
//! wants a setting of its own (as `embeds_protocol_debugger` has) or a third
//! mode arrives, no call site moves.
//!
//! **Every predicate reads the AMBIENT realm's `global.mode`**, through
//! [`Settings`], never cached — the mode is runtime-settable and per realm.
//!
//! The predicates' NAMES are `mode.js`'s, exported to `tables/mode.json`
//! with the two tables `/admin/mode` draws; a test here fails on a name this
//! module does not answer, so a predicate added to the Node module and not
//! here is caught before the cutover.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Mutex};

use serde_json::{json, Value as Json};

use crate::errors::codes;
use crate::log::tag;
use crate::settings::{
    keys, row, rows, DefaultValue, Refusal, SettingRow, SettingValue, Settings,
};

/// `global.mode`'s two values.
pub const DEVELOPMENT: &str = "development";
pub const PRODUCT: &str = "product";

/// The export of `mode.js`'s tables.
static TABLE: LazyLock<Json> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../tables/mode.json"))
        .unwrap_or(Json::Null)
});

/// Defines the predicates that are the mode and nothing else: `product`
/// answers true in product mode, `development` in development mode. Each
/// also answers to its `mode.js` name through [`Mode::predicate`], which
/// is how a settings row's `onlyWhile` marker names one.
macro_rules! predicates {
    ($($method:ident = $name:literal, $when:ident;)*) => {
        impl Mode {
            $(
                #[doc = concat!("`", $name, "` in `common/mode.js`.")]
                pub fn $method(&self) -> bool {
                    predicates!(@answer self, $when)
                }
            )*

            fn simple_predicate(&self, name: &str) -> Option<bool> {
                match name {
                    $($name => Some(self.$method()),)*
                    _ => None,
                }
            }
        }
    };
    (@answer $self:ident, product) => { $self.is_product() };
    (@answer $self:ident, development) => { !$self.is_product() };
}

/// The mode, over the settings it reads.
pub struct Mode {
    settings: Arc<Settings>,
    /// The (setting, source) pairs whose ignored value has been said, once
    /// per process (STS-CORE-0106): bounded by the table's rows and the
    /// attributes that override them, never by how many entries carry one.
    announced: Mutex<HashSet<String>>,
}

predicates! {
    verifies_credentials = "verifiesCredentials", product;
    believes_asserted_selectors = "believesAssertedSelectors", development;
    requires_workload_attestation = "requiresWorkloadAttestation", product;
    serves_unattested_workload_tcp = "servesUnattestedWorkloadTcp", development;
    registers_unidentifying_entries =
        "registersUnidentifyingEntries", development;
    serves_unattested_entries = "servesUnattestedEntries", development;
    accepts_credentials_without_status =
        "acceptsCredentialsWithoutStatus", development;
    trusts_unverified_local_socket = "trustsUnverifiedLocalSocket", development;
    spoils_on_purpose = "spoilsOnPurpose", development;
    uses_broken_algorithms = "usesBrokenAlgorithms", development;
    issues_unsigned_assertions = "issuesUnsignedAssertions", development;
    serves_without_security_header = "servesWithoutSecurityHeader", development;
    auto_creates = "autoCreates", development;
    requires_confidential_client_authentication =
        "requiresConfidentialClientAuthentication", product;
    enforces_oauth_security_bcp = "enforcesOauthSecurityBcp", product;
    seeds_demo_data = "seedsDemoData", development;
    rotates_signing_keys = "rotatesSigningKeys", product;
    rotates_kerberos_keys = "rotatesKerberosKeys", product;
    derives_krbtgt_from_password = "derivesKrbtgtFromPassword", development;
    refuses_expired_client_secrets = "refusesExpiredClientSecrets", product;
    lists_realms_before_sign_in = "listsRealmsBeforeSignIn", development;
    invents_claim_values = "inventsClaimValues", development;
    accepts_unregistered_addresses =
        "acceptsUnregisteredAddresses", development;
    opens_test_controls = "opensTestControls", development;
    requires_cell_kek = "requiresCellKek", product;
    opens_console_to_anyone = "opensConsoleToAnyone", development;
    authorizes_directory_writes = "authorizesDirectoryWrites", product;
    authorizes_directory_reads = "authorizesDirectoryReads", product;
    requires_directory_bind = "requiresDirectoryBind", product;
    withholds_directory_secrets = "withholdsDirectorySecrets", product;
    protects_operational_attributes = "protectsOperationalAttributes", product;
    requires_confidential_directory_binds =
        "requiresConfidentialDirectoryBinds", product;
    limits_directory_bind_failures = "limitsDirectoryBindFailures", product;
    sends_weaker_than_asked = "sendsWeakerThanAsked", development;
    refuses_unknown_revocation_status =
        "refusesUnknownRevocationStatus", product;
    refuses_unrevocable_certificates =
        "refusesUnrevocableCertificates", product;
    requires_pki_for_gnap_mtls = "requiresPkiForGnapMtls", product;
    requires_enrollment_tls = "requiresEnrollmentTls", product;
    opens_introspection = "opensIntrospection", development;
    opens_revocation = "opensRevocation", development;
    accepts_unverified_issuer_tokens =
        "acceptsUnverifiedIssuerTokens", development;
    exchanges_unverified_tokens = "exchangesUnverifiedTokens", development;
    authorizes_delegation = "authorizesDelegation", product;
    grants_undeclared_scopes = "grantsUndeclaredScopes", development;
    issues_through_undeclared_protocols =
        "issuesThroughUndeclaredProtocols", development;
    grants_uncatalogued_access = "grantsUncataloguedAccess", development;
    honours_ungranted_permissions = "honoursUngrantedPermissions", development;
    enrols_keys_on_first_use = "enrolsKeysOnFirstUse", development;
    accepts_unverified_attestation =
        "acceptsUnverifiedAttestation", development;
    accepts_unattested_device_keys = "acceptsUnattestedDeviceKeys", development;
    accepts_password_alone_from_second_factor_accounts =
        "acceptsPasswordAloneFromSecondFactorAccounts", development;
    issues_tickets_on_password_alone =
        "issuesTicketsOnPasswordAlone", development;
    matches_federated_names = "matchesFederatedNames", development;
    accepts_unsigned_federated_logout =
        "acceptsUnsignedFederatedLogout", development;
    accepts_unencrypted_federated_assertions =
        "acceptsUnencryptedFederatedAssertions", development;
    certifies_request_host = "certifiesRequestHost", development;
    accepts_unsigned_request_objects =
        "acceptsUnsignedRequestObjects", development;
    accepts_loose_request_uris = "acceptsLooseRequestUris", development;
    accepts_unsigned_saml_requests = "acceptsUnsignedSamlRequests", development;
    encrypts_to_observed_certificates =
        "encryptsToObservedCertificates", development;
    registers_from_metadata_query = "registersFromMetadataQuery", development;
    publishes_metadata_for_unregistered_providers =
        "publishesMetadataForUnregisteredProviders", development;
    limits_debugger_destinations = "limitsDebuggerDestinations", product;
    dials_internal_addresses = "dialsInternalAddresses", development;
    skips_outbound_tls_verification =
        "skipsOutboundTlsVerification", development;
    dials_plain_http_outbound = "dialsPlainHttpOutbound", development;
    captures_mail = "capturesMail", development;
    mails_links_from_listener_address =
        "mailsLinksFromListenerAddress", development;
    accepts_nonconforming_resource_metadata =
        "acceptsNonconformingResourceMetadata", development;
    gates_management_api = "gatesManagementApi", product;
    observes_risk_only = "observesRiskOnly", development;
}

impl Mode {
    pub fn new(settings: Arc<Settings>) -> Mode {
        Mode {
            settings,
            announced: Mutex::new(HashSet::new()),
        }
    }

    /// The ambient realm's mode: `product`, or `development` for anything
    /// else.
    pub fn current(&self) -> &'static str {
        if self.settings.value(keys::GLOBAL_MODE).as_str() == PRODUCT {
            PRODUCT
        } else {
            DEVELOPMENT
        }
    }

    // Private on purpose: see the module's header.
    fn is_product(&self) -> bool {
        self.current() == PRODUCT
    }

    /// Whether the embedded protocol debugger is served: `debugger.enabled`
    /// `on` or `off` decides, `auto` follows the mode.
    pub fn embeds_protocol_debugger(&self) -> bool {
        let asked = self.settings.value(keys::DEBUGGER_ENABLED);
        match asked.as_str() {
            "on" => true,
            "off" => false,
            _ => !self.is_product(),
        }
    }

    /// The console's gate. Cannot be turned off in either mode.
    pub fn gates_console(&self) -> bool {
        true
    }

    /// SCIM's credential. Cannot be turned off in either mode.
    pub fn gates_scim(&self) -> bool {
        true
    }

    /// Shared Signals' bearer token. Cannot be turned off in either mode.
    pub fn gates_shared_signals(&self) -> bool {
        true
    }

    /// The SPIRE Server API's X509-SVID. Cannot be turned off.
    pub fn gates_spire_server_api(&self) -> bool {
        true
    }

    /// Whether a received SET that does not verify is refused: always in
    /// product, and in development where `ssf.receiveRequireSignature` says.
    pub fn refuses_unverified_signals(&self) -> bool {
        self.is_product()
            || self
                .settings
                .value(keys::SSF_RECEIVE_REQUIRE_SIGNATURE)
                .as_bool()
    }

    /// Whether received signals are recorded and not acted on: development,
    /// unless `ssf.actOnSignalsInDevelopment` is on.
    pub fn observes_signals_only(&self) -> bool {
        !self.is_product()
            && !self
                .settings
                .value(keys::SSF_ACT_ON_SIGNALS_IN_DEVELOPMENT)
                .as_bool()
    }

    /// A predicate by its `mode.js` name — a settings row's `onlyWhile`.
    pub fn predicate(&self, name: &str) -> Option<bool> {
        match name {
            "embedsProtocolDebugger" => Some(self.embeds_protocol_debugger()),
            "gatesConsole" => Some(self.gates_console()),
            "gatesScim" => Some(self.gates_scim()),
            "gatesSharedSignals" => Some(self.gates_shared_signals()),
            "gatesSpireServerApi" => Some(self.gates_spire_server_api()),
            "refusesUnverifiedSignals" => {
                Some(self.refuses_unverified_signals())
            }
            "observesSignalsOnly" => Some(self.observes_signals_only()),
            other => self.simple_predicate(other),
        }
    }

    /// Whether the mode allows `key` to hold `value`: true for a row with
    /// no marker, for the row's default, for a value `onlyWhileValues`
    /// does not name, and wherever the marker's predicate answers true. A
    /// list is judged element by element (`krb5.enctypes`' `23`).
    pub fn allows_value(&self, key: &str, value: &SettingValue) -> bool {
        let Some(row) = row(key) else {
            return true;
        };
        let Some(predicate) = row.only_while else {
            return true;
        };
        match (value, row.only_while_values) {
            (SettingValue::List(list), Some(_)) => {
                if marked(row, list).is_empty() {
                    return true;
                }
            }
            _ if equals_default(value, row.default) => return true,
            (value, Some(names))
                if !names.contains(&value_text(value).as_str()) =>
            {
                return true;
            }
            _ => {}
        }
        // A marker naming no predicate is a defect in the table; refusing
        // is the direction that cannot loosen anything.
        self.predicate(predicate).unwrap_or(false)
    }

    /// A setting as the ambient realm's mode lets it be.
    pub fn value_in_force(&self, key: &str) -> SettingValue {
        let value = self.settings.value_of(key);
        self.in_force(key, value, key)
    }

    /// A value from anywhere — an application's override of a setting — as
    /// the mode lets it be. A refused value is read as the product value and
    /// said once per process and source (STS-CORE-0106).
    pub fn in_force(
        &self,
        key: &str,
        value: SettingValue,
        source: &str,
    ) -> SettingValue {
        if self.allows_value(key, &value) {
            return value;
        }
        let Some(row) = row(key) else {
            return value;
        };
        let read = product_value(row, &value);
        let said = format!("{}|{}", key, source);
        let first = match self.announced.lock() {
            Ok(mut seen) => seen.insert(said),
            Err(poisoned) => poisoned.into_inner().insert(said),
        };
        if first {
            let who = if source != key {
                format!("{} (overriding {})", source, key)
            } else {
                key.to_string()
            };
            let what = match (&value, row.only_while_values) {
                (SettingValue::List(list), Some(_)) => format!(
                    " names {}, which is IGNORED, ",
                    to_json(&SettingValue::List(marked(row, list)))
                ),
                _ => format!(" is set to {} and is IGNORED, ", to_json(&value)),
            };
            tracing::warn!(
                "{}mode: {}{}because this realm is in product mode \
                 (global.mode=product): {} It is read as {} until it is \
                 reset. Said once per process.",
                tag(codes::STS_CORE_0106),
                who,
                what,
                write_refusal_reason(row.only_while.unwrap_or("")),
                to_json(&read)
            );
        }
        read
    }

    /// The mode's half of a write's check (`config.js`'s
    /// `modeWriteProblem()` and `modeWriteCode()`): the capture transport
    /// in product, and a development-only value. The pinned-signer rule is
    /// the certificate authority's, added as a [`crate::settings::WriteRule`].
    pub fn write_problem(&self, key: &str, raw: &Json) -> Option<Refusal> {
        let as_text = match raw {
            Json::Null => String::new(),
            Json::String(text) => text.clone(),
            other => other.to_string(),
        };
        if key == "mail.transport"
            && as_text.trim() == "capture"
            && !self.captures_mail()
        {
            return Some(Refusal {
                problem: "\"mail.transport\" cannot be \"capture\" here: \
                          this realm is in product mode (global.mode=product), \
                          where a captured message would put its body — a \
                          password reset link, a verification link — on the \
                          console. Configure smtp, ses, acs or gmail, or \
                          leave it \"default\" (off)."
                    .to_string(),
                code: codes::STS_MAIL_0003,
            });
        }
        let row = row(key)?;
        let predicate = row.only_while?;
        if row.check(raw).is_some() {
            return None;
        }
        let parsed = row.parse(Some(raw));
        if self.allows_value(key, &parsed) {
            return None;
        }
        let verb = match parsed {
            SettingValue::Bool(true) => "turned on".to_string(),
            SettingValue::Bool(false) => "turned off".to_string(),
            _ => format!("set to {}", js_text(raw)),
        };
        Some(Refusal {
            problem: format!(
                "\"{}\" cannot be {} here: this realm is in product mode \
                 (global.mode=product), where it is ignored — {}",
                key,
                verb,
                write_refusal_reason(predicate)
            ),
            code: codes::STS_CORE_0103,
        })
    }

    /// `checkWrite()`: the settings' own check, then the mode's — for the
    /// doors that write a value somebody asked for.
    pub fn check_write(
        &self,
        key: &str,
        raw: &Json,
        for_realm: Option<bool>,
    ) -> Option<Refusal> {
        self.settings
            .check_override(key, raw, for_realm)
            .or_else(|| self.write_problem(key, raw))
    }

    /// Every row carrying the marker, with the value held and the value in
    /// force — which differ where a development-only value is stored in a
    /// product realm. Read through `allows_value()`, so drawing logs
    /// nothing.
    pub fn development_only_settings(&self) -> Vec<Json> {
        rows()
            .iter()
            .filter_map(|row| {
                let predicate = row.only_while?;
                let stored = self.settings.value_of(row.key);
                let allowed = self.allows_value(row.key, &stored);
                let in_force = if allowed {
                    stored.clone()
                } else {
                    product_value(row, &stored)
                };
                Some(json!({
                    "key": row.key,
                    "group": row.group,
                    "predicate": predicate,
                    "developmentOnlyValues": row.only_while_values,
                    "default": default_json(row.default),
                    "value": to_json(&stored),
                    "inForce": to_json(&in_force),
                    "ignored": !allowed,
                    "why": write_refusal_reason(predicate),
                }))
            })
            .collect()
    }

    /// The whole answer for `/admin/mode`, `GET /admin-api/mode` and the
    /// metadata report.
    pub fn report(&self) -> Json {
        let product = self.is_product();
        let requirements: Vec<Json> = requirements()
            .iter()
            .map(|one| {
                let mut row = serde_json::Map::new();
                let chosen = if product { "product" } else { "development" };
                row.insert(
                    "inForce".into(),
                    one.get(chosen).cloned().unwrap_or(Json::Null),
                );
                if let Some(fields) = one.as_object() {
                    for (k, v) in fields {
                        row.insert(k.clone(), v.clone());
                    }
                }
                Json::Object(row)
            })
            .collect();
        json!({
            "mode": self.current(),
            "isProduct": product,
            "requirements": requirements,
            "developmentOnlySettings": self.development_only_settings(),
            "notYet": TABLE.get("notYet").cloned().unwrap_or(json!([])),
        })
    }
}

/// The predicate names `mode.js` exports.
pub fn predicate_names() -> Vec<&'static str> {
    TABLE
        .get("predicates")
        .and_then(Json::as_array)
        .map(|list| list.iter().filter_map(Json::as_str).collect())
        .unwrap_or_default()
}

/// REQUIREMENTS: what each mode does, row by row.
pub fn requirements() -> &'static [Json] {
    TABLE
        .get("requirements")
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Why a marked row's value is not allowed, by the predicate it names.
pub fn write_refusal_reason(predicate: &str) -> &'static str {
    TABLE
        .get("writeRefusals")
        .and_then(|map| map.get(predicate))
        .or_else(|| TABLE.get("writeRefusalFallback"))
        .and_then(Json::as_str)
        .unwrap_or("the setting is for development mode only.")
}

/// JavaScript's `value === row.dflt`: a scalar against the raw default; a
/// list is never the same object as anything.
fn equals_default(value: &SettingValue, default: DefaultValue) -> bool {
    match (value, default) {
        (SettingValue::Text(text), DefaultValue::Text(d)) => text == d,
        (SettingValue::Int(n), DefaultValue::Int(d)) => *n == d,
        (SettingValue::Bool(b), DefaultValue::Bool(d)) => *b == d,
        _ => false,
    }
}

/// A scalar value as `indexOf()` compares it against `onlyWhileValues`.
fn value_text(value: &SettingValue) -> String {
    match value {
        SettingValue::Text(text) => text.clone(),
        SettingValue::Int(n) => n.to_string(),
        SettingValue::Bool(b) => b.to_string(),
        SettingValue::List(_) => String::new(),
    }
}

/// The elements of a list the row's `onlyWhileValues` names, compared as
/// text.
fn marked(row: &SettingRow, list: &[String]) -> Vec<String> {
    let names = row.only_while_values.unwrap_or(&[]);
    list.iter()
        .filter(|one| names.contains(&one.as_str()))
        .cloned()
        .collect()
}

/// What a value the mode refuses is read as: the default, or for a list the
/// list without the marked elements — and where nothing would be left, the
/// default without them, so a product KDC is never left offering nothing.
fn product_value(row: &SettingRow, value: &SettingValue) -> SettingValue {
    let dflt = row.parse(Some(&default_json(row.default)));
    let (SettingValue::List(list), Some(_)) = (value, row.only_while_values)
    else {
        return dflt;
    };
    let withheld = marked(row, list);
    let kept: Vec<String> = list
        .iter()
        .filter(|one| !withheld.contains(one))
        .cloned()
        .collect();
    if !kept.is_empty() {
        return SettingValue::List(kept);
    }
    let fallback = dflt.as_list().to_vec();
    let marked_default = marked(row, &fallback);
    SettingValue::List(
        fallback
            .into_iter()
            .filter(|one| !marked_default.contains(one))
            .collect(),
    )
}

fn default_json(default: DefaultValue) -> Json {
    match default {
        DefaultValue::Text(text) => json!(text),
        DefaultValue::Int(n) => json!(n),
        DefaultValue::Bool(b) => json!(b),
        DefaultValue::List(list) => json!(list),
        DefaultValue::Derived => Json::Null,
    }
}

fn to_json(value: &SettingValue) -> Json {
    match value {
        SettingValue::Text(text) => json!(text),
        SettingValue::Int(n) => json!(n),
        SettingValue::Bool(b) => json!(b),
        SettingValue::List(list) => json!(list),
    }
}

/// `'set to ' + raw`: a raw value as JavaScript concatenates it.
fn js_text(raw: &Json) -> String {
    match raw {
        Json::String(text) => text.clone(),
        Json::Array(items) => {
            items.iter().map(js_text).collect::<Vec<_>>().join(",")
        }
        Json::Null => "null".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn mode(mode: &str) -> Mode {
        let mut env = HashMap::new();
        env.insert("STS_MODE".to_string(), mode.to_string());
        Mode::new(Arc::new(Settings::new(Json::Null, env)))
    }

    #[test]
    fn every_node_predicate_is_answered() {
        let names = predicate_names();
        assert_eq!(names.len(), 78);
        let m = mode(PRODUCT);
        let missing: Vec<&&str> =
            names.iter().filter(|n| m.predicate(n).is_none()).collect();
        assert!(missing.is_empty(), "{:?}", missing);
        for row in rows() {
            if let Some(p) = row.only_while {
                assert!(m.predicate(p).is_some(), "{} names {}", row.key, p);
            }
        }
    }

    #[test]
    fn the_modes_answer_opposite_questions() {
        let product = mode(PRODUCT);
        let development = mode(DEVELOPMENT);
        assert!(product.verifies_credentials());
        assert!(!development.verifies_credentials());
        assert!(development.seeds_demo_data());
        assert!(!product.seeds_demo_data());
        assert!(product.gates_console() && development.gates_console());
        assert!(development.embeds_protocol_debugger());
        assert!(!product.embeds_protocol_debugger());
        assert_eq!(mode("nonsense").current(), DEVELOPMENT);
    }

    #[test]
    fn a_development_only_value_in_product() {
        let product = mode(PRODUCT);
        let development = mode(DEVELOPMENT);
        let key = rows()
            .iter()
            .find(|r| {
                r.only_while.is_some()
                    && r.only_while_values.is_none()
                    && r.default == DefaultValue::Bool(false)
            })
            .map(|r| r.key)
            .unwrap_or("");
        assert!(!key.is_empty());
        assert!(product.allows_value(key, &SettingValue::Bool(false)));
        assert!(!product.allows_value(key, &SettingValue::Bool(true)));
        assert!(development.allows_value(key, &SettingValue::Bool(true)));
        let refused = product.write_problem(key, &json!(true));
        assert!(refused.is_some_and(|r| r.code == codes::STS_CORE_0103
            && r.problem.contains("cannot be turned on")));
        assert_eq!(
            product.in_force(key, SettingValue::Bool(true), key),
            SettingValue::Bool(false)
        );
    }

    #[test]
    fn a_marked_element_of_a_list() {
        let product = mode(PRODUCT);
        let enctypes = product.value_in_force("krb5.enctypes");
        assert!(!enctypes.as_list().iter().any(|e| e == "23"));
        assert!(!enctypes.as_list().is_empty());
        let only_rc4 = SettingValue::List(vec!["23".into()]);
        let read = product.in_force("krb5.enctypes", only_rc4, "test");
        assert!(!read.as_list().is_empty());
        assert!(!read.as_list().iter().any(|e| e == "23"));
    }

    #[test]
    fn capture_is_refused_in_product() {
        let refused =
            mode(PRODUCT).write_problem("mail.transport", &json!("capture"));
        assert!(refused.is_some_and(|r| r.code == codes::STS_MAIL_0003));
        assert!(mode(DEVELOPMENT)
            .write_problem("mail.transport", &json!("capture"))
            .is_none());
    }

    #[test]
    fn the_report() {
        let report = mode(PRODUCT).report();
        assert_eq!(report["mode"], "product");
        assert_eq!(report["requirements"].as_array().map(Vec::len), Some(72));
        assert_eq!(
            report["requirements"][0]["inForce"],
            report["requirements"][0]["product"]
        );
        assert!(report["developmentOnlySettings"]
            .as_array()
            .is_some_and(|rows| rows.len() == 26));
    }
}
