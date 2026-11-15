// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE LISTENERS' POLICY (#423, #429, #212): `tls/tls_server.js`'s
//! `policyFor()`, `protocolOptions()`, `clientAuthOptions()`,
//! `policyWriteRule()` and `checkProtocolOptions()`.
//!
//! A [`ListenerPolicy`] is what one listener is held to: the floor, TLS 1.2
//! on or off, the TLS 1.3 suites, the TLS 1.2 list, the groups, the
//! signature algorithms, post-quantum only, the session lifetime and cache,
//! its own anchors file and whether the service Root vouches for its client
//! certificates, and its client authentication. [`policy_for`] reads it
//! from the settings — a listener's own `listener<Kind>.<name>` row where it
//! has one, the service-wide `tls.*` row where it inherits — and
//! [`ProtocolOptions::of`] turns it into what OpenSSL is told, which the
//! runtime's context builder applies.
//!
//! WHAT "POST-QUANTUM SAFE" MEANS, as Node says it: the 256-bit TLS 1.3
//! suites (Grover halves a key), the ML-KEM groups (what protects a
//! recorded session), and TLS 1.3. The signature algorithms are not
//! restricted: authentication cannot be broken retroactively.
//!
//! This crate names no OpenSSL type: it is data a listener is built from,
//! and the management API's write rules and pages read it too.

use std::sync::{Arc, Weak};

use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_core::settings::{row, SettingValue, Settings, WriteRule};

/// The five TLS 1.3 suites RFC 8446 defines, with their key size; the
/// 256-bit ones are the post-quantum safe ones.
pub const TLS13_SUITES: &[(&str, u32)] = &[
    ("TLS_AES_256_GCM_SHA384", 256),
    ("TLS_CHACHA20_POLY1305_SHA256", 256),
    ("TLS_AES_128_GCM_SHA256", 128),
    ("TLS_AES_128_CCM_SHA256", 128),
    ("TLS_AES_128_CCM_8_SHA256", 128),
];

/// The ML-KEM groups OpenSSL 3.5 implements: three hybrids, three pure.
pub const PQ_GROUPS: &[&str] = &[
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
];

/// The groups post-quantum only falls back to where `tls.groups` lists none.
pub const PQ_DEFAULT_GROUPS: &str =
    "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024";

/// node's `tls.DEFAULT_CIPHERS` with its TLS 1.3 names taken out: what an
/// EMPTY `tls.ciphers` means (`tls12Ciphers()`). node 24.22.1's value.
pub const NODE_DEFAULT_TLS12_CIPHERS: &str = "ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:\
DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:\
HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA";

/// The kinds of listener (`LISTENER_KINDS`, and `custom` for one of
/// `listeners.custom` / `listeners.realm`, #472).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerKind {
    /// The service-wide policy (`policyFor()` with no kind).
    Process,
    Main,
    Ldaps,
    Debugger,
    SpiffeServer,
    SpiffeBroker,
    Cell,
    Revocation,
    /// A custom listener, by id; its `tls` block and `clientAuth`.
    Custom {
        id: String,
        tls: serde_json::Map<String, Json>,
        client_auth: String,
    },
}

impl ListenerKind {
    /// The kind's name as Node spells it in `policy.kind`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn name(&self) -> &str {
        match self {
            ListenerKind::Process => "process",
            ListenerKind::Main => "main",
            ListenerKind::Ldaps => "ldaps",
            ListenerKind::Debugger => "debugger",
            ListenerKind::SpiffeServer => "spiffeServer",
            ListenerKind::SpiffeBroker => "spiffeBroker",
            ListenerKind::Cell => "cell",
            ListenerKind::Revocation => "revocation",
            ListenerKind::Custom { .. } => "custom",
        }
    }

    /// The kind from its name (`spiffe` is `spiffeServer`, as before #429).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn named(name: &str) -> Option<ListenerKind> {
        Some(match name {
            "main" => ListenerKind::Main,
            "ldaps" => ListenerKind::Ldaps,
            "debugger" => ListenerKind::Debugger,
            "spiffe" | "spiffeServer" => ListenerKind::SpiffeServer,
            "spiffeBroker" => ListenerKind::SpiffeBroker,
            "cell" => ListenerKind::Cell,
            "revocation" => ListenerKind::Revocation,
            _ => return None,
        })
    }

    /// The prefix of its own rows: `listenerMain`, `listenerSpiffeServer`.
    fn row_prefix(&self) -> Option<String> {
        match self {
            ListenerKind::Process | ListenerKind::Custom { .. } => None,
            other => {
                let n = other.name();
                let mut chars = n.chars();
                let first = chars.next()?.to_ascii_uppercase();
                Some(format!("listener{}{}", first, chars.as_str()))
            }
        }
    }

    /// The pair of toggles its client authentication is read from; `None`
    /// for a kind whose protocol fixes it (SPIFFE's gRPC, the cell channel)
    /// or that carries it in its definition (custom).
    fn client_auth_settings(&self) -> Option<(&'static str, &'static str)> {
        match self {
            ListenerKind::Main => Some((
                "tls.mainPortDisableOptionalClientCertificate",
                "tls.mainPortRequireClientCertificate",
            )),
            ListenerKind::Ldaps => Some((
                "ldap.ldapsDisableOptionalClientCertificate",
                "ldap.ldapsRequireClientCertificate",
            )),
            ListenerKind::Debugger => Some((
                "debugger.disableOptionalClientCertificate",
                "debugger.requireClientCertificate",
            )),
            _ => None,
        }
    }
}

/// A listener's own value of one setting, as Json-ish text, or `None` to
/// inherit (`ownValue()`): `inherit` in an enum, the empty string, an empty
/// list, -1 for a number, or no such row.
#[derive(Debug, Clone, PartialEq)]
pub enum Own {
    Bool(bool),
    Text(String),
    Int(i64),
}

fn own_of_setting(value: &SettingValue) -> Option<Own> {
    match value {
        SettingValue::Text(t) => {
            let t = t.trim();
            match t {
                "" | "inherit" => None,
                "on" => Some(Own::Bool(true)),
                "off" => Some(Own::Bool(false)),
                other => Some(Own::Text(other.to_string())),
            }
        }
        SettingValue::Int(-1) => None,
        SettingValue::Int(n) => Some(Own::Int(*n)),
        SettingValue::Bool(b) => Some(Own::Bool(*b)),
        SettingValue::List(l) if l.is_empty() => None,
        SettingValue::List(l) => Some(Own::Text(l.join(","))),
    }
}

fn own_of_json(value: &Json) -> Option<Own> {
    match value {
        Json::Null => None,
        Json::Bool(b) => Some(Own::Bool(*b)),
        Json::Number(n) => match n.as_i64() {
            Some(-1) | None => None,
            Some(n) => Some(Own::Int(n)),
        },
        Json::String(s) => own_of_setting(&SettingValue::Text(s.clone())),
        Json::Array(a) if a.is_empty() => None,
        Json::Array(a) => Some(Own::Text(
            a.iter()
                .map(|v| v.as_str().map_or(v.to_string(), str::to_string))
                .collect::<Vec<_>>()
                .join(","),
        )),
        Json::Object(_) => None,
    }
}

/// `ownValue()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn own_value(
    settings: &Settings,
    kind: &ListenerKind,
    name: &str,
) -> Option<Own> {
    match kind {
        ListenerKind::Custom { tls, .. } => tls.get(name).and_then(own_of_json),
        other => {
            let key = format!("{}.{}", other.row_prefix()?, name);
            row(&key)?;
            own_of_setting(&settings.value_of(&key))
        }
    }
}

/// A list setting as trimmed, non-empty entries (`listOf()`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn list_of(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn text_of(value: &SettingValue) -> String {
    match value {
        SettingValue::Text(t) => t.clone(),
        SettingValue::List(l) => l.join(","),
        SettingValue::Int(n) => n.to_string(),
        SettingValue::Bool(b) => b.to_string(),
    }
}

/// The 256-bit suites of a list, in its order (`postQuantumSuites()`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn post_quantum_suites(suites: &[String]) -> Vec<String> {
    suites
        .iter()
        .filter(|s| TLS13_SUITES.iter().any(|(n, bits)| n == s && *bits == 256))
        .cloned()
        .collect()
}

/// An OpenSSL groups list with only its ML-KEM groups kept, tuples and
/// order as written (`postQuantumGroups()`); empty where it held none.
#[tracing::instrument(level = "debug", skip_all)]
pub fn post_quantum_groups(groups: &str) -> String {
    let wanted: Vec<String> =
        PQ_GROUPS.iter().map(|g| g.to_ascii_lowercase()).collect();
    groups
        .split('/')
        .map(|tuple| {
            tuple
                .split(':')
                .map(str::trim)
                .filter(|g| {
                    wanted.contains(
                        &g.trim_start_matches('*').to_ascii_lowercase(),
                    )
                })
                .collect::<Vec<_>>()
                .join(":")
        })
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join(" / ")
}

/// What a client-authentication mode is (`none`, `optional`, `required`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    None,
    Optional,
    Required,
}

impl ClientAuth {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn named(name: &str) -> ClientAuth {
        match name {
            "none" => ClientAuth::None,
            "required" => ClientAuth::Required,
            _ => ClientAuth::Optional,
        }
    }

    /// node's `requestCert` and `rejectUnauthorized`
    /// (`clientAuthOptions()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn request_and_reject(self) -> (bool, bool) {
        (self != ClientAuth::None, self == ClientAuth::Required)
    }
}

/// `policyFor()`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenerPolicy {
    pub kind: String,
    /// For a custom listener, its id.
    pub realm: Option<String>,
    pub min_version: String,
    pub disable_tls12: bool,
    pub pqc_only: bool,
    pub tls13_suites: Vec<String>,
    pub ciphers12: String,
    pub groups: String,
    pub sigalgs: String,
    /// Its OWN anchors file, replacing the service's file anchors for it;
    /// empty where it inherits them.
    pub trust_anchors_file: String,
    pub trust_issued: bool,
    pub session_timeout_s: u32,
    pub session_cache_size: u32,
    /// `None` for a kind whose protocol decides it.
    pub client_auth: Option<ClientAuth>,
}

/// `policyFor(kind, realmId)`.
#[tracing::instrument(level = "debug", skip(settings))]
pub fn policy_for(settings: &Settings, kind: &ListenerKind) -> ListenerPolicy {
    let pick = |name: &str, base: &str| -> Own {
        match own_value(settings, kind, name) {
            Some(own) => own,
            None => match settings.value_of(base) {
                SettingValue::Bool(b) => Own::Bool(b),
                SettingValue::Int(n) => Own::Int(n),
                other => Own::Text(text_of(&other)),
            },
        }
    };
    let as_bool = |o: Own| matches!(o, Own::Bool(true));
    let as_text = |o: Own| match o {
        Own::Text(t) => t,
        Own::Int(n) => n.to_string(),
        Own::Bool(b) => b.to_string(),
    };
    let as_int = |o: Own| match o {
        Own::Int(n) => n,
        Own::Text(t) => t.trim().parse().unwrap_or(0),
        Own::Bool(_) => 0,
    };
    let pqc_only = as_bool(pick("pqcOnly", "tls.pqcOnly"));
    let mut suites: Vec<String> =
        list_of(&as_text(pick("tls13CipherSuites", "tls.tls13CipherSuites")))
            .into_iter()
            .filter(|s| TLS13_SUITES.iter().any(|(n, _)| n == s))
            .collect();
    // A list that holds nothing usable falls back to the default rather
    // than a listener with no TLS 1.3 at all (a store edited by hand: the
    // write rule refuses such a list).
    if suites.is_empty() {
        suites = vec![
            "TLS_AES_256_GCM_SHA384".to_string(),
            "TLS_AES_128_GCM_SHA256".to_string(),
            "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        ];
    }
    if pqc_only {
        let kept = post_quantum_suites(&suites);
        suites = if kept.is_empty() {
            vec!["TLS_AES_256_GCM_SHA384".to_string()]
        } else {
            kept
        };
    }
    let client_auth = match kind {
        ListenerKind::Custom { client_auth, .. } => {
            Some(ClientAuth::named(client_auth))
        }
        other => other.client_auth_settings().map(|(off, require)| {
            if settings.value_of(require).as_bool() {
                ClientAuth::Required
            } else if settings.value_of(off).as_bool() {
                ClientAuth::None
            } else {
                ClientAuth::Optional
            }
        }),
    };
    let disable_tls12 = as_bool(pick("disableTls12", "tls.disableTls12"))
        || pqc_only
        || *kind == ListenerKind::Cell;
    let min_version = as_text(pick("minVersion", "tls.minVersion"));
    ListenerPolicy {
        kind: kind.name().to_string(),
        realm: match kind {
            ListenerKind::Custom { id, .. } => Some(id.clone()),
            _ => None,
        },
        min_version: if min_version.is_empty() {
            "TLSv1.2".to_string()
        } else {
            min_version
        },
        disable_tls12,
        pqc_only,
        tls13_suites: suites,
        ciphers12: as_text(pick("ciphers", "tls.ciphers")).trim().to_string(),
        groups: as_text(pick("groups", "tls.groups")).trim().to_string(),
        sigalgs: as_text(pick(
            "signatureAlgorithms",
            "tls.signatureAlgorithms",
        ))
        .trim()
        .to_string(),
        trust_anchors_file: match kind {
            ListenerKind::Process => String::new(),
            k => match own_value(settings, k, "trustAnchorsFile") {
                Some(Own::Text(t)) => t,
                _ => String::new(),
            },
        },
        trust_issued: !matches!(
            pick(
                "trustIssuedClientCertificates",
                "tls.trustIssuedClientCertificates"
            ),
            Own::Bool(false)
        ),
        session_timeout_s: {
            let n = as_int(pick("sessionTimeoutS", "tls.sessionTimeoutS"));
            if n <= 0 {
                300
            } else {
                u32::try_from(n).unwrap_or(u32::MAX)
            }
        },
        session_cache_size: u32::try_from(
            as_int(pick("sessionCacheSize", "tls.sessionCacheSize")).max(0),
        )
        .unwrap_or(0),
        client_auth,
    }
}

/// A protocol version OpenSSL is told as a floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    /// node's spelling: `TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn named(name: &str) -> Option<TlsVersion> {
        Some(match name {
            "TLSv1" | "TLSv1.0" => TlsVersion::Tls10,
            "TLSv1.1" => TlsVersion::Tls11,
            "TLSv1.2" => TlsVersion::Tls12,
            "TLSv1.3" => TlsVersion::Tls13,
            _ => return None,
        })
    }
}

/// `protocolOptions(policy)`: what OpenSSL is told.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolOptions {
    /// `minVersion`: TLS 1.3 when TLS 1.2 is off.
    pub min_version: TlsVersion,
    /// `SSL_CTX_set_ciphersuites`: the TLS 1.3 suites, never empty.
    pub tls13_suites: String,
    /// `SSL_CTX_set_cipher_list`: the TLS 1.2 list, empty when TLS 1.2 is
    /// off. node puts both in one string; OpenSSL takes them apart.
    pub tls12_ciphers: String,
    /// `ecdhCurve`; `None` leaves OpenSSL's own.
    pub groups: Option<String>,
    /// `sigalgs`; `None` leaves OpenSSL's own.
    pub sigalgs: Option<String>,
    /// `honorCipherOrder`: the server's order wins.
    pub server_preference: bool,
    /// `SSL_OP_NO_RENEGOTIATION`, unconditional (#212).
    pub no_renegotiation: bool,
    /// `sessionTimeout`.
    pub session_timeout_s: u32,
}

impl ProtocolOptions {
    /// `protocolOptions(policy)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn of(policy: &ListenerPolicy) -> ProtocolOptions {
        let floor =
            TlsVersion::named(&policy.min_version).unwrap_or(TlsVersion::Tls12);
        let groups = if policy.pqc_only {
            let pq = post_quantum_groups(&policy.groups);
            Some(if pq.is_empty() {
                PQ_DEFAULT_GROUPS.to_string()
            } else {
                pq
            })
        } else if policy.groups.is_empty() {
            None
        } else {
            Some(policy.groups.clone())
        };
        ProtocolOptions {
            min_version: if policy.disable_tls12 {
                TlsVersion::Tls13
            } else {
                floor
            },
            tls13_suites: policy.tls13_suites.join(":"),
            tls12_ciphers: if policy.disable_tls12 {
                String::new()
            } else {
                tls12_ciphers(&policy.ciphers12)
            },
            groups,
            sigalgs: if policy.sigalgs.is_empty() {
                None
            } else {
                Some(policy.sigalgs.clone())
            },
            server_preference: true,
            no_renegotiation: true,
            session_timeout_s: policy.session_timeout_s,
        }
    }

    /// OpenSSL's groups list syntax: node hands `tls.groups` straight to
    /// `SSL_CTX_set1_groups_list`, whose tuple separator is `/` and which
    /// takes the spaces around it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn groups_for_openssl(&self) -> Option<String> {
        self.groups.as_ref().map(|g| {
            g.split('/').map(str::trim).collect::<Vec<_>>().join(" / ")
        })
    }
}

/// `tls12Ciphers()`: the setting's TLS 1.2 suites, or node's default list
/// without its TLS 1.3 names where it is empty.
#[tracing::instrument(level = "debug", skip_all)]
pub fn tls12_ciphers(listed: &str) -> String {
    let raw = listed.trim();
    let raw = if raw.is_empty() {
        NODE_DEFAULT_TLS12_CIPHERS
    } else {
        raw
    };
    raw.split(':')
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with("TLS_"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The listener kinds every startup checks (`LISTENER_KINDS`).
pub const STARTUP_KINDS: &[ListenerKind] = &[
    ListenerKind::Main,
    ListenerKind::Ldaps,
    ListenerKind::Debugger,
    ListenerKind::SpiffeServer,
    ListenerKind::SpiffeBroker,
    ListenerKind::Cell,
    ListenerKind::Revocation,
];

/// A refusal: Node's sentence and the code it is logged under.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyRefusal {
    pub message: String,
    pub code: ErrorCode,
}

/// `policyWriteRule(key, parsed)` over the value a write would leave:
/// `problem(key, written)` reads every other value from the settings.
#[tracing::instrument(level = "debug", skip(settings, written))]
pub fn write_problem(
    settings: &Settings,
    key: &str,
    written: &SettingValue,
) -> Option<PolicyRefusal> {
    let refuse = |message: String| PolicyRefusal {
        message,
        code: codes::STS_TLS_0043,
    };
    // ONE LISTENER'S OWN ROW (#429): the same rule, for that listener.
    if let Some(rest) = key.strip_prefix("listener") {
        if let Some((kind_name, name)) = rest.split_once('.') {
            if !matches!(name, "pqcOnly" | "tls13CipherSuites" | "groups")
                || !kind_name.starts_with(|c: char| c.is_ascii_uppercase())
            {
                return None;
            }
            let mut k = kind_name.to_string();
            if let Some(first) = k.get_mut(0..1) {
                first.make_ascii_lowercase();
            }
            let kind = ListenerKind::named(&k)?;
            let written_own = own_of_setting(written);
            let value_of = |n: &str, base: &str| -> String {
                if n == name {
                    if let Some(own) = &written_own {
                        return match own {
                            Own::Bool(b) => b.to_string(),
                            Own::Text(t) => t.clone(),
                            Own::Int(i) => i.to_string(),
                        };
                    }
                    return text_of(&settings.value_of(base));
                }
                match own_value(settings, &kind, n) {
                    Some(Own::Bool(b)) => b.to_string(),
                    Some(Own::Text(t)) => t,
                    Some(Own::Int(i)) => i.to_string(),
                    None => text_of(&settings.value_of(base)),
                }
            };
            if value_of("pqcOnly", "tls.pqcOnly") == "true" {
                let suites = list_of(&value_of(
                    "tls13CipherSuites",
                    "tls.tls13CipherSuites",
                ));
                if post_quantum_suites(&suites).is_empty() {
                    return Some(refuse(format!(
                        "post-quantum only on the {} listener needs a 256-bit TLS 1.3 suite in its suites \
                         (its own, or tls.tls13CipherSuites, which it inherits) — TLS_AES_256_GCM_SHA384 \
                         or TLS_CHACHA20_POLY1305_SHA256.",
                        k
                    )));
                }
                let groups = value_of("groups", "tls.groups");
                if !groups.trim().is_empty()
                    && post_quantum_groups(&groups).is_empty()
                {
                    return Some(refuse(format!(
                        "post-quantum only on the {} listener needs an ML-KEM group in its groups (its own, \
                         or tls.groups, which it inherits).",
                        k
                    )));
                }
            }
            return None;
        }
    }
    let text = text_of(written);
    if key == "tls.tls13CipherSuites" && list_of(&text).is_empty() {
        return Some(refuse(
            "\"tls.tls13CipherSuites\" needs at least one suite: with none, no listener completes a TLS 1.3 \
             handshake."
                .to_string(),
        ));
    }
    if key == "tls.ciphers"
        && text.split(':').any(|s| s.trim().starts_with("TLS_"))
    {
        return Some(refuse(
            "\"tls.ciphers\" is the TLS 1.2 list; the TLS 1.3 suites are chosen in tls.tls13CipherSuites."
                .to_string(),
        ));
    }
    let pqc = if key == "tls.pqcOnly" {
        written.as_bool()
    } else {
        settings.value_of("tls.pqcOnly").as_bool()
    };
    if pqc
        && ["tls.pqcOnly", "tls.tls13CipherSuites", "tls.groups"].contains(&key)
    {
        let suites = if key == "tls.tls13CipherSuites" {
            list_of(&text)
        } else {
            list_of(&text_of(&settings.value_of("tls.tls13CipherSuites")))
        };
        if post_quantum_suites(&suites).is_empty() {
            return Some(refuse(
                "post-quantum only (tls.pqcOnly) needs a 256-bit TLS 1.3 suite in tls.tls13CipherSuites — \
                 TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256 — and the list holds none."
                    .to_string(),
            ));
        }
        let groups = if key == "tls.groups" {
            text
        } else {
            text_of(&settings.value_of("tls.groups"))
        };
        if !groups.trim().is_empty() && post_quantum_groups(&groups).is_empty()
        {
            return Some(refuse(
                "post-quantum only (tls.pqcOnly) needs an ML-KEM group in tls.groups (X25519MLKEM768, \
                 SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM512/768/1024), and the list holds none."
                    .to_string(),
            ));
        }
    }
    None
}

/// The rule, installed with `Settings::add_write_rule` (`config.addWriteRule(
/// policyWriteRule)`). It holds the settings weakly: they hold it.
pub struct PolicyWriteRule {
    settings: Weak<Settings>,
}

impl PolicyWriteRule {
    /// Installs the rule on the settings.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn install(settings: &Arc<Settings>) {
        settings.add_write_rule(Arc::new(PolicyWriteRule {
            settings: Arc::downgrade(settings),
        }));
    }
}

impl WriteRule for PolicyWriteRule {
    fn problem(
        &self,
        key: &str,
        parsed: &SettingValue,
        _in_realm: bool,
    ) -> Option<(String, ErrorCode)> {
        let settings = self.settings.upgrade()?;
        write_problem(&settings, key, parsed).map(|r| (r.message, r.code))
    }
}

/// `checkProtocolOptions()`'s first half: a TLS 1.3 name in `tls.ciphers`,
/// an empty suite list, post-quantum only with nothing post-quantum — the
/// write rules, at startup, where a value from the environment or a file
/// reached the process unasked. `STS-TLS-0042`, fatal. (The second half,
/// that every policy BUILDS a context, is the context builder's.)
#[tracing::instrument(level = "debug", skip_all)]
pub fn startup_problem(settings: &Settings) -> Option<PolicyRefusal> {
    for key in ["tls.ciphers", "tls.tls13CipherSuites", "tls.pqcOnly"] {
        if let Some(r) = write_problem(settings, key, &settings.value_of(key)) {
            return Some(PolicyRefusal {
                message: format!("tls: NOT STARTING. {}", r.message),
                code: codes::STS_TLS_0042,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn settings(operator: Json) -> Settings {
        Settings::new(operator, HashMap::new())
    }

    #[test]
    fn the_default_main_policy_is_tls13_with_three_suites() {
        let s = settings(json!({}));
        let p = policy_for(&s, &ListenerKind::Main);
        assert!(p.disable_tls12);
        assert_eq!(
            p.tls13_suites,
            vec![
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256"
            ]
        );
        assert_eq!(p.client_auth, Some(ClientAuth::Optional));
        assert_eq!(p.session_timeout_s, 300);
        let o = ProtocolOptions::of(&p);
        assert_eq!(o.min_version, TlsVersion::Tls13);
        assert_eq!(o.tls12_ciphers, "");
        assert_eq!(
            o.groups_for_openssl().unwrap(),
            "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024 / X25519:P-256 / X448:P-384:P-521"
        );
        assert!(o.sigalgs.unwrap().starts_with("mldsa65:"));
    }

    #[test]
    fn a_listener_row_overrides_and_inherit_falls_back() {
        let s = settings(json!({
            "tls": { "disableTls12": true },
            "listenerMain": { "disableTls12": "off", "pqcOnly": "inherit" }
        }));
        let p = policy_for(&s, &ListenerKind::Main);
        assert!(!p.disable_tls12);
        let o = ProtocolOptions::of(&p);
        assert_eq!(o.min_version, TlsVersion::Tls12);
        assert!(o.tls12_ciphers.starts_with("ECDHE-ECDSA-AES128-GCM-SHA256"));
        // LDAPS inherits the service's.
        assert!(policy_for(&s, &ListenerKind::Ldaps).disable_tls12);
    }

    #[test]
    fn pqc_only_keeps_the_256_bit_suites_and_ml_kem_groups() {
        let s = settings(json!({ "tls": { "pqcOnly": true } }));
        let p = policy_for(&s, &ListenerKind::Main);
        assert_eq!(
            p.tls13_suites,
            vec!["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
        );
        let o = ProtocolOptions::of(&p);
        assert_eq!(
            o.groups.unwrap(),
            "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024"
        );
    }

    #[test]
    fn the_write_rules_refuse_what_would_refuse_every_client() {
        let s = settings(json!({}));
        let r = write_problem(
            &s,
            "tls.ciphers",
            &SettingValue::Text("TLS_AES_128_GCM_SHA256".into()),
        )
        .unwrap();
        assert_eq!(r.code, codes::STS_TLS_0043);
        assert!(write_problem(
            &s,
            "tls.tls13CipherSuites",
            &SettingValue::List(vec![])
        )
        .is_some());
        let pq = settings(json!({ "tls": { "pqcOnly": true } }));
        assert!(write_problem(
            &pq,
            "tls.tls13CipherSuites",
            &SettingValue::List(vec!["TLS_AES_128_GCM_SHA256".into()])
        )
        .is_some());
        assert!(write_problem(
            &s,
            "listenerMain.pqcOnly",
            &SettingValue::Text("on".into())
        )
        .is_none());
        assert!(startup_problem(&s).is_none());
        let bad =
            settings(json!({ "tls": { "ciphers": "TLS_AES_128_GCM_SHA256" } }));
        assert_eq!(startup_problem(&bad).unwrap().code, codes::STS_TLS_0042);
    }

    #[test]
    fn post_quantum_groups_keeps_tuples() {
        assert_eq!(
            post_quantum_groups(
                "X25519MLKEM768:SecP256r1MLKEM768 / X25519:P-256"
            ),
            "X25519MLKEM768:SecP256r1MLKEM768"
        );
        assert_eq!(post_quantum_groups("X25519 / P-256"), "");
    }

    #[test]
    fn a_custom_listener_reads_its_definition() {
        let s = settings(json!({}));
        let mut tls = serde_json::Map::new();
        tls.insert("disableTls12".into(), json!("off"));
        let p = policy_for(
            &s,
            &ListenerKind::Custom {
                id: "mtls".into(),
                tls,
                client_auth: "required".into(),
            },
        );
        assert!(!p.disable_tls12);
        assert_eq!(p.client_auth, Some(ClientAuth::Required));
        assert_eq!(p.realm.as_deref(), Some("mtls"));
    }
}
