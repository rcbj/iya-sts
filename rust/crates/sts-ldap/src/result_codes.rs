// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! LDAP result codes (RFC 4511 section 4.1.9 and appendix A) and the
//! error classes node-ldapjs builds from them (`lib/errors/`): for each
//! `LDAP_X_Y` but success, an `XYError` (suffix not doubled) whose default
//! message is its own name and whose `getMessage(code)` text is "X Y";
//! and `ConnectionError`, `AbandonedError`, `TimeoutError`, which carry
//! `LDAP_OTHER`. These are the codes and texts a handler's error turns
//! into on the wire.

/// `lib/errors/codes.js`, in its order.
pub const CODES: &[(&str, i32)] = &[
    ("LDAP_SUCCESS", 0),
    ("LDAP_OPERATIONS_ERROR", 1),
    ("LDAP_PROTOCOL_ERROR", 2),
    ("LDAP_TIME_LIMIT_EXCEEDED", 3),
    ("LDAP_SIZE_LIMIT_EXCEEDED", 4),
    ("LDAP_COMPARE_FALSE", 5),
    ("LDAP_COMPARE_TRUE", 6),
    ("LDAP_AUTH_METHOD_NOT_SUPPORTED", 7),
    ("LDAP_STRONG_AUTH_REQUIRED", 8),
    ("LDAP_REFERRAL", 10),
    ("LDAP_ADMIN_LIMIT_EXCEEDED", 11),
    ("LDAP_UNAVAILABLE_CRITICAL_EXTENSION", 12),
    ("LDAP_CONFIDENTIALITY_REQUIRED", 13),
    ("LDAP_SASL_BIND_IN_PROGRESS", 14),
    ("LDAP_NO_SUCH_ATTRIBUTE", 16),
    ("LDAP_UNDEFINED_ATTRIBUTE_TYPE", 17),
    ("LDAP_INAPPROPRIATE_MATCHING", 18),
    ("LDAP_CONSTRAINT_VIOLATION", 19),
    ("LDAP_ATTRIBUTE_OR_VALUE_EXISTS", 20),
    ("LDAP_INVALID_ATTRIBUTE_SYNTAX", 21),
    ("LDAP_NO_SUCH_OBJECT", 32),
    ("LDAP_ALIAS_PROBLEM", 33),
    ("LDAP_INVALID_DN_SYNTAX", 34),
    ("LDAP_ALIAS_DEREF_PROBLEM", 36),
    ("LDAP_INAPPROPRIATE_AUTHENTICATION", 48),
    ("LDAP_INVALID_CREDENTIALS", 49),
    ("LDAP_INSUFFICIENT_ACCESS_RIGHTS", 50),
    ("LDAP_BUSY", 51),
    ("LDAP_UNAVAILABLE", 52),
    ("LDAP_UNWILLING_TO_PERFORM", 53),
    ("LDAP_LOOP_DETECT", 54),
    ("LDAP_SORT_CONTROL_MISSING", 60),
    ("LDAP_INDEX_RANGE_ERROR", 61),
    ("LDAP_NAMING_VIOLATION", 64),
    ("LDAP_OBJECTCLASS_VIOLATION", 65),
    ("LDAP_NOT_ALLOWED_ON_NON_LEAF", 66),
    ("LDAP_NOT_ALLOWED_ON_RDN", 67),
    ("LDAP_ENTRY_ALREADY_EXISTS", 68),
    ("LDAP_OBJECTCLASS_MODS_PROHIBITED", 69),
    ("LDAP_AFFECTS_MULTIPLE_DSAS", 71),
    ("LDAP_CONTROL_ERROR", 76),
    ("LDAP_OTHER", 80),
    ("LDAP_PROXIED_AUTHORIZATION_DENIED", 123),
];

/// An error class: its name and the code it answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorClass {
    pub name: String,
    pub code: i32,
}

/// The class name and message text node-ldapjs derives from `LDAP_X_Y`.
fn derive(code_name: &str) -> (String, String) {
    let pieces: Vec<String> = code_name
        .split('_')
        .skip(1)
        .map(|p| {
            let lc = p.to_lowercase();
            let mut c = lc.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect();
    let mut err = pieces.concat();
    let msg = pieces.join(" ");
    // `/\w+Error$/`: a name of at least one word character then "Error".
    if !(err.len() > 5 && err.ends_with("Error")) {
        err.push_str("Error");
    }
    (err, msg)
}

/// `getMessage(code)`: the text for a code, "" for success or an unknown.
#[tracing::instrument(level = "debug")]
pub fn message(code: i32) -> String {
    CODES
        .iter()
        .find(|(n, c)| *c == code && *n != "LDAP_SUCCESS")
        .map(|(n, _)| derive(n).1)
        .unwrap_or_default()
}

/// Every error class, sorted by name, as `Object.keys(ldap)` filtered to
/// `…Error` sorts them.
#[tracing::instrument(level = "debug")]
pub fn error_classes() -> Vec<ErrorClass> {
    let mut out: Vec<ErrorClass> = CODES
        .iter()
        .filter(|(n, _)| *n != "LDAP_SUCCESS")
        .map(|(n, c)| ErrorClass {
            name: derive(n).0,
            code: *c,
        })
        .collect();
    for n in ["ConnectionError", "AbandonedError", "TimeoutError"] {
        out.push(ErrorClass {
            name: n.to_string(),
            code: 80,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}
