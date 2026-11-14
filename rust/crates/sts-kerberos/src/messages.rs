// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The RFC 4120 messages: `kerberos/krb5_messages.js`.
//!
//! Every structure has an `encode()` and a `read()`, each the Node
//! function of the same name, field for field and in Node's order — the
//! order matters, because when two fields are wrong the one Node reads
//! first is the one its error names. Two things a reader of the Node file
//! keeps having to remember are kept here too:
//!
//! * **an optional field Node tests for TRUTH is omitted when it is
//!   "empty" in the JavaScript sense**: an empty `crealm` or `e-text` is
//!   omitted from a KRB-ERROR, an empty address list is omitted, but an
//!   empty authorization-data list (an empty array is truthy) and an empty
//!   `e-data` (so is an empty `Uint8Array`) are WRITTEN. Each encoder says
//!   which rule its field follows;
//! * **a ticket and a request body keep their RAW bytes**, and re-encoding
//!   one writes those bytes back rather than rebuilding them: a checksum
//!   (the PA-TGS-REQ authenticator's, FAST's) is over the bytes that
//!   arrived.
//!
//! The structures serialize to the JSON Node's readers return (camelCase,
//! `null` for absent), bytes as hex and times as ISO 8601 — what the parity
//! vectors compare, and what a debugger page would render.

use serde::Serialize;

use crate::asn1::{self, Fields, Tlv};
use crate::crypto;
use crate::error::{Krb5Error, Krb5Result};
use crate::time::KrbTime;

/// The protocol version.
pub const PVNO: i64 = 5;

/// `msg-type` values.
pub mod msg_type {
    pub const AS_REQ: i64 = 10;
    pub const AS_REP: i64 = 11;
    pub const TGS_REQ: i64 = 12;
    pub const TGS_REP: i64 = 13;
    pub const AP_REQ: i64 = 14;
    pub const AP_REP: i64 = 15;
    pub const SAFE: i64 = 20;
    pub const PRIV: i64 = 21;
    pub const CRED: i64 = 22;
    pub const ERROR: i64 = 30;
}

/// `[APPLICATION n]` numbers.
pub mod application {
    pub const TICKET: u8 = 1;
    pub const AUTHENTICATOR: u8 = 2;
    pub const ENC_TICKET_PART: u8 = 3;
    pub const AS_REQ: u8 = 10;
    pub const AS_REP: u8 = 11;
    pub const TGS_REQ: u8 = 12;
    pub const TGS_REP: u8 = 13;
    pub const AP_REQ: u8 = 14;
    pub const AP_REP: u8 = 15;
    pub const KRB_CRED: u8 = 22;
    pub const ENC_AS_REP_PART: u8 = 25;
    pub const ENC_TGS_REP_PART: u8 = 26;
    pub const ENC_AP_REP_PART: u8 = 27;
    pub const ENC_KRB_PRIV_PART: u8 = 28;
    pub const ENC_KRB_CRED_PART: u8 = 29;
    pub const KRB_ERROR: u8 = 30;
}

/// The name of an application number: Node's `APPLICATION_NAMES`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn application_name(n: u8) -> Option<&'static str> {
    Some(match n {
        1 => "Ticket",
        2 => "Authenticator",
        3 => "EncTicketPart",
        10 => "AS-REQ",
        11 => "AS-REP",
        12 => "TGS-REQ",
        13 => "TGS-REP",
        14 => "AP-REQ",
        15 => "AP-REP",
        22 => "KRB-CRED",
        25 => "EncASRepPart",
        26 => "EncTGSRepPart",
        27 => "EncAPRepPart",
        28 => "EncKrbPrivPart",
        29 => "EncKrbCredPart",
        30 => "KRB-ERROR",
        _ => return None,
    })
}

/// Principal name types.
pub mod name_type {
    pub const UNKNOWN: i64 = 0;
    pub const PRINCIPAL: i64 = 1;
    pub const SRV_INST: i64 = 2;
    pub const SRV_HST: i64 = 3;
    pub const SRV_XHST: i64 = 4;
    pub const UID: i64 = 5;
    pub const X500_PRINCIPAL: i64 = 6;
    pub const SMTP_NAME: i64 = 7;
    pub const ENTERPRISE: i64 = 10;
}

/// PA-DATA types, as Node's `PA_TYPE` names them.
pub const PA_TYPES: [(&str, i64); 13] = [
    ("TGS_REQ", 1),
    ("ENC_TIMESTAMP", 2),
    ("PW_SALT", 3),
    ("ETYPE_INFO", 11),
    ("ETYPE_INFO2", 19),
    ("PAC_REQUEST", 128),
    ("FOR_USER", 129),
    ("FX_COOKIE", 133),
    ("FX_FAST", 136),
    ("FX_ERROR", 137),
    ("ENCRYPTED_CHALLENGE", 138),
    ("S4U_X509_USER", 130),
    ("PAC_OPTIONS", 167),
];

/// Node's `PA_TYPE_NAMES[type] || "PA-" + type`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn pa_type_name(t: i64) -> String {
    PA_TYPES
        .iter()
        .find(|(_, n)| *n == t)
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| format!("PA-{}", t))
}

/// KDCOptions bits.
pub const KDC_OPTIONS: [(&str, u32); 16] = [
    ("FORWARDABLE", 1),
    ("FORWARDED", 2),
    ("PROXIABLE", 3),
    ("PROXY", 4),
    ("ALLOW_POSTDATE", 5),
    ("POSTDATED", 6),
    ("RENEWABLE", 8),
    ("OPT_HARDWARE_AUTH", 11),
    ("CNAME_IN_ADDL_TKT", 14),
    ("CANONICALIZE", 15),
    ("REQUEST_ANONYMOUS", 16),
    ("DISABLE_TRANSITED_CHECK", 26),
    ("RENEWABLE_OK", 27),
    ("ENC_TKT_IN_SKEY", 28),
    ("RENEW", 30),
    ("VALIDATE", 31),
];

/// TicketFlags bits.
pub const TICKET_FLAGS: [(&str, u32); 15] = [
    ("FORWARDABLE", 1),
    ("FORWARDED", 2),
    ("PROXIABLE", 3),
    ("PROXY", 4),
    ("MAY_POSTDATE", 5),
    ("POSTDATED", 6),
    ("INVALID", 7),
    ("RENEWABLE", 8),
    ("INITIAL", 9),
    ("PRE_AUTHENT", 10),
    ("HW_AUTHENT", 11),
    ("TRANSITED_POLICY_CHECKED", 12),
    ("OK_AS_DELEGATE", 13),
    ("ENC_PA_REP", 15),
    ("ANONYMOUS", 16),
];

/// APOptions bits.
pub const AP_OPTIONS: [(&str, u32); 2] =
    [("USE_SESSION_KEY", 1), ("MUTUAL_REQUIRED", 2)];

/// PA-PAC-OPTIONS bits (MS-KILE 2.2.10).
pub const PAC_OPTIONS: [(&str, u32); 4] = [
    ("CLAIMS", 0),
    ("BRANCH_AWARE", 1),
    ("FORWARD_TO_FULL_DC", 2),
    ("RESOURCE_BASED_CONSTRAINED_DELEGATION", 3),
];

/// Node's `flagNames()`: lowercase, `-` for `_`, `bit-N` when unnamed.
#[tracing::instrument(level = "debug", skip_all)]
pub fn flag_names(table: &[(&str, u32)], bits: &[u32]) -> Vec<String> {
    bits.iter()
        .map(|b| match table.iter().rev().find(|(_, n)| n == b) {
            Some((name, _)) => name.to_lowercase().replace('_', "-"),
            None => format!("bit-{}", b),
        })
        .collect()
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn kdc_option_names(bits: &[u32]) -> Vec<String> {
    flag_names(&KDC_OPTIONS, bits)
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn ticket_flag_names(bits: &[u32]) -> Vec<String> {
    flag_names(&TICKET_FLAGS, bits)
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn ap_option_names(bits: &[u32]) -> Vec<String> {
    flag_names(&AP_OPTIONS, bits)
}

/// RFC 4120 section 7.5.9's codes with Node's explanations: its
/// `ERROR_CODE` table, generated from it.
const ERROR_CODES: &[(i64, &str, &str)] = &[
    (0, "KDC_ERR_NONE",
     "No error"),
    (1, "KDC_ERR_NAME_EXP",
     "The client's entry has expired"),
    (2, "KDC_ERR_SERVICE_EXP",
     "The server's entry has expired"),
    (3, "KDC_ERR_BAD_PVNO",
     "The KDC does not speak this protocol version"),
    (6, "KDC_ERR_C_PRINCIPAL_UNKNOWN",
     "No such client principal in this realm — check the spelling AND the realm, which is case-sensitive"),
    (7, "KDC_ERR_S_PRINCIPAL_UNKNOWN",
     "No such service principal — an SPN that is not registered, or registered on a different account"),
    (8, "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
     "More than one entry matches this principal (a duplicate SPN)"),
    (9, "KDC_ERR_NULL_KEY",
     "The principal has no key — often an account that has never had a password set"),
    (10, "KDC_ERR_CANNOT_POSTDATE",
     "A postdated ticket was requested and is not allowed"),
    (11, "KDC_ERR_NEVER_VALID",
     "The requested validity window is empty or inverted"),
    (12, "KDC_ERR_POLICY",
     "Refused by policy — logon hours, workstation restrictions, or a disabled account"),
    (13, "KDC_ERR_BADOPTION",
     "An option in the request cannot be honoured for this principal (delegation is a common one)"),
    (14, "KDC_ERR_ETYPE_NOSUPP",
     "The KDC supports none of the encryption types offered. In 2026 this is usually RC4 being disabled, or an account whose msDS-SupportedEncryptionTypes excludes AES"),
    (15, "KDC_ERR_SUMTYPE_NOSUPP",
     "The KDC supports none of the checksum types offered"),
    (16, "KDC_ERR_PADATA_TYPE_NOSUPP",
     "The pre-authentication type is not supported — also what AD answers when PKINIT is attempted without a certificate it trusts"),
    (17, "KDC_ERR_TRTYPE_NOSUPP",
     "The transited encoding type is not supported"),
    (18, "KDC_ERR_CLIENT_REVOKED",
     "The client's credentials are revoked — a disabled or locked-out account"),
    (19, "KDC_ERR_SERVICE_REVOKED",
     "The service's credentials are revoked"),
    (20, "KDC_ERR_TGT_REVOKED",
     "The TGT has been revoked"),
    (21, "KDC_ERR_CLIENT_NOTYET",
     "The client is not yet valid"),
    (22, "KDC_ERR_SERVICE_NOTYET",
     "The server is not yet valid"),
    (23, "KDC_ERR_KEY_EXPIRED",
     "The password has expired and must be changed"),
    (24, "KDC_ERR_PREAUTH_FAILED",
     "Pre-authentication failed — the classic wrong password, but ALSO what a wrong salt or a clock outside the skew produces"),
    (25, "KDC_ERR_PREAUTH_REQUIRED",
     "Pre-authentication is required. Not a failure: the accompanying PA-ETYPE-INFO2 carries the salt and iteration count needed to build the real request"),
    (26, "KDC_ERR_SERVER_NOMATCH",
     "The server and ticket do not match"),
    (27, "KDC_ERR_MUST_USE_USER2USER",
     "The service requires user-to-user authentication"),
    (28, "KDC_ERR_PATH_NOT_ACCEPTED",
     "The KDC will not accept the transited path"),
    (29, "KDC_ERR_SVC_UNAVAILABLE",
     "The service is unavailable"),
    (31, "KRB_AP_ERR_BAD_INTEGRITY",
     "Decryption integrity check failed. Indistinguishable at this layer from a wrong password, a wrong key usage number, a wrong salt or a wrong encoding"),
    (32, "KRB_AP_ERR_TKT_EXPIRED",
     "The ticket has expired"),
    (33, "KRB_AP_ERR_TKT_NYV",
     "The ticket is not yet valid"),
    (34, "KRB_AP_ERR_REPEAT",
     "The request is a replay — the service's replay cache has seen this authenticator"),
    (35, "KRB_AP_ERR_NOT_US",
     "The ticket is not for this service"),
    (36, "KRB_AP_ERR_BADMATCH",
     "The ticket and the authenticator do not match"),
    (37, "KRB_AP_ERR_SKEW",
     "The clock skew is too great. AD's default tolerance is five minutes; the KDC's own time is in this message's stime, so the skew can be measured rather than guessed"),
    (38, "KRB_AP_ERR_BADADDR",
     "The request is from an address the ticket does not permit"),
    (39, "KRB_AP_ERR_BADVERSION",
     "The protocol version does not match"),
    (40, "KRB_AP_ERR_MSG_TYPE",
     "An unexpected message type"),
    (41, "KRB_AP_ERR_MODIFIED",
     "The message was modified in transit"),
    (42, "KRB_AP_ERR_BADORDER",
     "The message is out of order"),
    (44, "KRB_AP_ERR_BADKEYVER",
     "The ticket was encrypted with a different key version than the service holds — a keytab that is out of date with the account's password"),
    (45, "KRB_AP_ERR_NOKEY",
     "The service has no key of the required type"),
    (46, "KRB_AP_ERR_MUT_FAIL",
     "Mutual authentication failed"),
    (47, "KRB_AP_ERR_BADDIRECTION",
     "The message is in the wrong direction"),
    (48, "KRB_AP_ERR_METHOD",
     "An alternative authentication method is required"),
    (49, "KRB_AP_ERR_BADSEQ",
     "An incorrect sequence number"),
    (50, "KRB_AP_ERR_INAPP_CKSUM",
     "The checksum type is inappropriate — this is what a wrong 0x8003 GSS checksum looks like"),
    (51, "KRB_AP_PATH_NOT_ACCEPTED",
     "The path is not accepted"),
    (52, "KRB_ERR_RESPONSE_TOO_BIG",
     "The reply will not fit in a UDP datagram; retry over TCP. Expected rather than exceptional against AD, whose PAC makes most replies large"),
    (60, "KRB_ERR_GENERIC",
     "A generic error — read e-text, which is where the KDC says what it actually objected to"),
    (61, "KRB_ERR_FIELD_TOOLONG",
     "A field is too long for this implementation"),
    (62, "KDC_ERROR_CLIENT_NOT_TRUSTED",
     "The client certificate is not trusted (PKINIT)"),
    (63, "KDC_ERROR_KDC_NOT_TRUSTED",
     "The KDC certificate is not trusted (PKINIT)"),
    (64, "KDC_ERROR_INVALID_SIG",
     "An invalid signature (PKINIT)"),
    (68, "KDC_ERR_WRONG_REALM",
     "Wrong realm — with a referral this is informational, and the correct realm is in this message"),
    (69, "KRB_AP_ERR_USER_TO_USER_REQUIRED",
     "User-to-user authentication is required"),
    (71, "KDC_ERR_PATH_NOT_ACCEPTED",
     "The KDC will not accept the transited path"),
    (76, "KDC_ERR_PREAUTH_EXPIRED",
     "The pre-authentication data has expired"),
    (93, "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED",
     "More pre-authentication is required (FAST)"),
];

/// A code, named and explained: Node's `describeError()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorDescription {
    pub code: i64,
    pub name: String,
    pub meaning: String,
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn describe_error(code: i64) -> ErrorDescription {
    match ERROR_CODES.iter().find(|(c, _, _)| *c == code) {
        Some((_, name, meaning)) => ErrorDescription {
            code,
            name: name.to_string(),
            meaning: meaning.to_string(),
        },
        None => ErrorDescription {
            code,
            name: format!("UNKNOWN_ERROR_{}", code),
            meaning: "Not a code this codec knows".to_string(),
        },
    }
}

/// The context-tagged fields of an element's SEQUENCE.
fn fields<'a>(t: &Tlv<'a>) -> Krb5Result<Fields<'a>> {
    asn1::read_tagged_sequence(t.value, 0)
}

/// Node's `elementBytes()` over an absent field.
fn element_of<'a>(f: &Fields<'a>, n: u8) -> Krb5Result<&'a [u8]> {
    f.get(n).map(|t| t.raw).ok_or_else(|| {
        Krb5Error::new("krb5: expected bytes or a parsed ASN.1 element")
    })
}

fn opt_time(f: &Fields<'_>, n: u8) -> Krb5Result<Option<KrbTime>> {
    f.get(n).map(asn1::dec_kerberos_time).transpose()
}

fn opt_int(f: &Fields<'_>, n: u8) -> Krb5Result<Option<i64>> {
    f.get(n).map(asn1::dec_integer).transpose()
}

fn opt_string(f: &Fields<'_>, n: u8) -> Krb5Result<Option<String>> {
    f.get(n).map(asn1::dec_general_string).transpose()
}

fn flags_of(t: &Tlv<'_>) -> Krb5Result<Vec<u32>> {
    Ok(asn1::bits_from_flags(asn1::dec_flags(t)?))
}

fn time(t: KrbTime) -> Option<Vec<u8>> {
    Some(asn1::enc_kerberos_time(t))
}

fn int(v: i64) -> Option<Vec<u8>> {
    Some(asn1::enc_integer(v))
}

fn string(s: &str) -> Option<Vec<u8>> {
    Some(asn1::enc_general_string(s))
}

/// A string Node writes only when it is truthy (non-empty).
fn truthy(s: &Option<String>) -> Option<Vec<u8>> {
    s.as_deref()
        .filter(|s| !s.is_empty())
        .map(asn1::enc_general_string)
}

/// PrincipalName.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrincipalName {
    pub r#type: i64,
    pub name: Vec<String>,
}

impl PrincipalName {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(r#type: i64, name: &[&str]) -> Self {
        PrincipalName {
            r#type,
            name: name.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        let components: Vec<Vec<u8>> = self
            .name
            .iter()
            .map(|c| asn1::enc_general_string(c))
            .collect();
        asn1::enc_tagged_sequence(&[
            (0, int(self.r#type)),
            (1, Some(asn1::enc_sequence(&components))),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let f = fields(t)?;
        Ok(PrincipalName {
            r#type: asn1::dec_integer(f.tag_of(0)?)?,
            name: asn1::dec_sequence_of(f.tag_of(1)?)?
                .iter()
                .map(asn1::dec_general_string)
                .collect::<Krb5Result<_>>()?,
        })
    }

    /// Node's `principalToString()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn to_text(&self, realm: Option<&str>) -> String {
        let s = self.name.join("/");
        match realm.filter(|r| !r.is_empty()) {
            Some(r) => format!("{}@{}", s, r),
            None => s,
        }
    }
}

/// A principal parsed from text: Node's `parsePrincipal()` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedPrincipal {
    pub r#type: i64,
    pub name: Vec<String>,
    pub realm: Option<String>,
}

/// Node's `parsePrincipal()`: the realm after the LAST `@` (not at the
/// start), components split on `/`, and a type guessed from the shape
/// when none is given.
#[tracing::instrument(level = "debug", skip_all)]
pub fn parse_principal(
    text: &str,
    default_type: Option<i64>,
) -> Krb5Result<ParsedPrincipal> {
    let mut s = text.trim().to_string();
    let mut realm = None;
    if let Some(at) = s.rfind('@').filter(|at| *at > 0) {
        realm = Some(s[at + 1..].to_string());
        s.truncate(at);
    }
    let parts: Vec<String> = s
        .split('/')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    if parts.is_empty() {
        return Err(Krb5Error::new("krb5: empty principal name"));
    }
    let r#type = default_type.unwrap_or(if parts.len() > 1 {
        if parts[0] == "krbtgt" {
            name_type::SRV_INST
        } else {
            name_type::SRV_HST
        }
    } else {
        name_type::PRINCIPAL
    });
    Ok(ParsedPrincipal {
        r#type,
        name: parts,
        realm,
    })
}

/// EncryptedData.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedData {
    pub etype: i64,
    pub etype_name: String,
    pub kvno: Option<i64>,
    #[serde(serialize_with = "crate::hex::ser")]
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(etype: i64, kvno: Option<i64>, cipher: Vec<u8>) -> Self {
        EncryptedData {
            etype,
            etype_name: crypto::etype_name(etype),
            kvno,
            cipher,
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, int(self.etype)),
            (1, self.kvno.map(asn1::enc_integer)),
            (2, Some(asn1::enc_octet_string(&self.cipher))),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let f = fields(t)?;
        let etype = asn1::dec_integer(f.tag_of(0)?)?;
        Ok(EncryptedData {
            etype,
            etype_name: crypto::etype_name(etype),
            kvno: opt_int(&f, 1)?,
            cipher: asn1::dec_octet_string(f.tag_of(2)?)?.to_vec(),
        })
    }
}

/// EncryptionKey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionKey {
    pub etype: i64,
    pub etype_name: String,
    #[serde(serialize_with = "crate::hex::ser")]
    pub key: Vec<u8>,
}

impl EncryptionKey {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(etype: i64, key: Vec<u8>) -> Self {
        EncryptionKey {
            etype,
            etype_name: crypto::etype_name(etype),
            key,
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, int(self.etype)),
            (1, Some(asn1::enc_octet_string(&self.key))),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let f = fields(t)?;
        let etype = asn1::dec_integer(f.tag_of(0)?)?;
        Ok(EncryptionKey {
            etype,
            etype_name: crypto::etype_name(etype),
            key: asn1::dec_octet_string(f.tag_of(1)?)?.to_vec(),
        })
    }
}

/// Checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checksum {
    pub r#type: i64,
    #[serde(serialize_with = "crate::hex::ser")]
    pub checksum: Vec<u8>,
}

impl Checksum {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, int(self.r#type)),
            (1, Some(asn1::enc_octet_string(&self.checksum))),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let f = fields(t)?;
        Ok(Checksum {
            r#type: asn1::dec_integer(f.tag_of(0)?)?,
            checksum: asn1::dec_octet_string(f.tag_of(1)?)?.to_vec(),
        })
    }
}

/// PA-DATA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaData {
    pub r#type: i64,
    pub type_name: String,
    #[serde(serialize_with = "crate::hex::ser")]
    pub value: Vec<u8>,
}

impl PaData {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(r#type: i64, value: Vec<u8>) -> Self {
        PaData {
            r#type,
            type_name: pa_type_name(r#type),
            value,
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (1, int(self.r#type)),
            (2, Some(asn1::enc_octet_string(&self.value))),
        ])
    }

    /// Node's `readPaData()`: a missing value is empty, not a refusal.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let f = fields(t)?;
        let r#type = asn1::dec_integer(f.tag_of(1)?)?;
        Ok(PaData {
            r#type,
            type_name: pa_type_name(r#type),
            value: match f.get(2) {
                Some(v) => asn1::dec_octet_string(v)?.to_vec(),
                None => Vec::new(),
            },
        })
    }

    /// The first of a type in a list: Node's `find()` (FAST codec).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn find(list: &[PaData], r#type: i64) -> Option<&PaData> {
        list.iter().find(|p| p.r#type == r#type)
    }
}

fn padata_list(t: &Tlv<'_>) -> Krb5Result<Vec<PaData>> {
    asn1::dec_sequence_of(t)?.iter().map(PaData::read).collect()
}

/// A SEQUENCE OF PA-DATA.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_padata_list(list: &[PaData]) -> Vec<u8> {
    let items: Vec<Vec<u8>> = list.iter().map(PaData::encode).collect();
    asn1::enc_sequence(&items)
}

/// HostAddress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostAddress {
    pub r#type: i64,
    #[serde(serialize_with = "crate::hex::ser")]
    pub address: Vec<u8>,
}

impl HostAddress {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, int(self.r#type)),
            (1, Some(asn1::enc_octet_string(&self.address))),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let f = fields(t)?;
        Ok(HostAddress {
            r#type: asn1::dec_integer(f.tag_of(0)?)?,
            address: asn1::dec_octet_string(f.tag_of(1)?)?.to_vec(),
        })
    }
}

/// HostAddresses: Node's `encHostAddresses()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_host_addresses(list: &[HostAddress]) -> Vec<u8> {
    let items: Vec<Vec<u8>> = list.iter().map(HostAddress::encode).collect();
    asn1::enc_sequence(&items)
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn read_host_addresses(t: &Tlv<'_>) -> Krb5Result<Vec<HostAddress>> {
    asn1::dec_sequence_of(t)?
        .iter()
        .map(HostAddress::read)
        .collect()
}

fn addresses(list: &Option<Vec<HostAddress>>) -> Option<Vec<u8>> {
    // `(x && x.length)`: an empty list is omitted.
    list.as_ref()
        .filter(|l| !l.is_empty())
        .map(|l| enc_host_addresses(l))
}

/// One AuthorizationData entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationEntry {
    pub r#type: i64,
    #[serde(serialize_with = "crate::hex::ser")]
    pub data: Vec<u8>,
}

/// AuthorizationData: Node's `encAuthorizationData()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_authorization_data(list: &[AuthorizationEntry]) -> Vec<u8> {
    let items: Vec<Vec<u8>> = list
        .iter()
        .map(|e| {
            asn1::enc_tagged_sequence(&[
                (0, int(e.r#type)),
                (1, Some(asn1::enc_octet_string(&e.data))),
            ])
        })
        .collect();
    asn1::enc_sequence(&items)
}

/// Node's `readAuthorizationData()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read_authorization_data(
    t: &Tlv<'_>,
) -> Krb5Result<Vec<AuthorizationEntry>> {
    asn1::dec_sequence_of(t)?
        .iter()
        .map(|a| {
            let f = fields(a)?;
            Ok(AuthorizationEntry {
                r#type: asn1::dec_integer(f.tag_of(0)?)?,
                data: asn1::dec_octet_string(f.tag_of(1)?)?.to_vec(),
            })
        })
        .collect()
}

fn authz(list: &Option<Vec<AuthorizationEntry>>) -> Option<Vec<u8>> {
    // `x ? enc(x) : null`: an empty list is truthy and written.
    list.as_ref().map(|l| enc_authorization_data(l))
}

/// Ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ticket {
    pub tkt_vno: i64,
    pub realm: String,
    pub sname: PrincipalName,
    pub enc_part: EncryptedData,
    #[serde(serialize_with = "crate::hex::opt")]
    pub raw: Option<Vec<u8>>,
}

impl Ticket {
    /// Node's `encTicket()`: the raw bytes when it has them.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        if let Some(raw) = &self.raw {
            return raw.clone();
        }
        asn1::enc_application(
            application::TICKET,
            &asn1::enc_tagged_sequence(&[
                (0, int(PVNO)),
                (1, string(&self.realm)),
                (2, Some(self.sname.encode())),
                (3, Some(self.enc_part.encode())),
            ]),
        )
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app = asn1::read_application(bytes, Some(application::TICKET))?;
        let f = fields(&app.sequence)?;
        Ok(Ticket {
            tkt_vno: asn1::dec_integer(f.tag_of(0)?)?,
            realm: asn1::dec_general_string(f.tag_of(1)?)?,
            sname: PrincipalName::read(f.value_of(2)?)?,
            enc_part: EncryptedData::read(f.value_of(3)?)?,
            raw: Some(bytes.to_vec()),
        })
    }
}

/// TransitedEncoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Transited {
    pub r#type: i64,
    #[serde(serialize_with = "crate::hex::ser")]
    pub contents: Vec<u8>,
}

/// EncTicketPart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncTicketPart {
    pub flags: Vec<u32>,
    pub key: EncryptionKey,
    pub crealm: String,
    pub cname: PrincipalName,
    pub transited: Option<Transited>,
    pub authtime: KrbTime,
    pub starttime: Option<KrbTime>,
    pub endtime: KrbTime,
    pub renew_till: Option<KrbTime>,
    pub caddr: Option<Vec<HostAddress>>,
    pub authorization_data: Option<Vec<AuthorizationEntry>>,
}

impl EncTicketPart {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        let (tt, tc) = match &self.transited {
            Some(t) => (t.r#type, t.contents.clone()),
            None => (0, Vec::new()),
        };
        Ok(asn1::enc_application(
            application::ENC_TICKET_PART,
            &asn1::enc_tagged_sequence(&[
                (0, Some(asn1::enc_flags(&self.flags)?)),
                (1, Some(self.key.encode())),
                (2, string(&self.crealm)),
                (3, Some(self.cname.encode())),
                (
                    4,
                    Some(asn1::enc_tagged_sequence(&[
                        (0, int(tt)),
                        (1, Some(asn1::enc_octet_string(&tc))),
                    ])),
                ),
                (5, time(self.authtime)),
                (6, self.starttime.and_then(time)),
                (7, time(self.endtime)),
                (8, self.renew_till.and_then(time)),
                (9, addresses(&self.caddr)),
                (10, authz(&self.authorization_data)),
            ]),
        ))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app =
            asn1::read_application(bytes, Some(application::ENC_TICKET_PART))?;
        let f = fields(&app.sequence)?;
        Ok(EncTicketPart {
            flags: flags_of(f.tag_of(0)?)?,
            key: EncryptionKey::read(f.value_of(1)?)?,
            crealm: asn1::dec_general_string(f.tag_of(2)?)?,
            cname: PrincipalName::read(f.value_of(3)?)?,
            transited: {
                let tf = fields(f.value_of(4)?)?;
                Some(Transited {
                    r#type: asn1::dec_integer(tf.tag_of(0)?)?,
                    contents: asn1::dec_octet_string(tf.tag_of(1)?)?.to_vec(),
                })
            },
            authtime: asn1::dec_kerberos_time(f.tag_of(5)?)?,
            starttime: opt_time(&f, 6)?,
            endtime: asn1::dec_kerberos_time(f.tag_of(7)?)?,
            renew_till: opt_time(&f, 8)?,
            caddr: f.get(9).map(read_host_addresses).transpose()?,
            authorization_data: f
                .get(10)
                .map(read_authorization_data)
                .transpose()?,
        })
    }
}

/// KDC-REQ-BODY.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdcReqBody {
    pub kdc_options: Vec<u32>,
    pub cname: Option<PrincipalName>,
    pub realm: String,
    pub sname: Option<PrincipalName>,
    pub from: Option<KrbTime>,
    pub till: KrbTime,
    pub rtime: Option<KrbTime>,
    pub nonce: i64,
    pub etypes: Vec<i64>,
    pub addresses: Option<Vec<HostAddress>>,
    pub enc_authorization_data: Option<EncryptedData>,
    pub additional_tickets: Option<Vec<Ticket>>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub raw: Option<Vec<u8>>,
}

impl KdcReqBody {
    /// Node's `encKdcReqBody()` — always built, never the raw bytes (the
    /// callers that keep raw bytes test for them themselves).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        let etypes: Vec<Vec<u8>> =
            self.etypes.iter().map(|e| asn1::enc_integer(*e)).collect();
        Ok(asn1::enc_tagged_sequence(&[
            (0, Some(asn1::enc_flags(&self.kdc_options)?)),
            (1, self.cname.as_ref().map(PrincipalName::encode)),
            (2, string(&self.realm)),
            (3, self.sname.as_ref().map(PrincipalName::encode)),
            (4, self.from.and_then(time)),
            (5, time(self.till)),
            (6, self.rtime.and_then(time)),
            (7, int(self.nonce)),
            (8, Some(asn1::enc_sequence(&etypes))),
            (9, addresses(&self.addresses)),
            (
                10,
                self.enc_authorization_data
                    .as_ref()
                    .map(EncryptedData::encode),
            ),
            (
                11,
                self.additional_tickets
                    .as_ref()
                    .filter(|l| !l.is_empty())
                    .map(|l| {
                        let t: Vec<Vec<u8>> =
                            l.iter().map(Ticket::encode).collect();
                        asn1::enc_sequence(&t)
                    }),
            ),
        ]))
    }

    /// The raw bytes when it has them, else built: what `encKdcReq()` and
    /// `encFastReq()` write.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn bytes(&self) -> Krb5Result<Vec<u8>> {
        match &self.raw {
            Some(r) => Ok(r.clone()),
            None => self.encode(),
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let f = fields(t)?;
        Ok(KdcReqBody {
            kdc_options: flags_of(f.tag_of(0)?)?,
            cname: f.get(1).map(PrincipalName::read).transpose()?,
            realm: asn1::dec_general_string(f.tag_of(2)?)?,
            sname: f.get(3).map(PrincipalName::read).transpose()?,
            from: opt_time(&f, 4)?,
            till: asn1::dec_kerberos_time(f.tag_of(5)?)?,
            rtime: opt_time(&f, 6)?,
            nonce: asn1::dec_integer(f.tag_of(7)?)?,
            etypes: asn1::dec_sequence_of(f.tag_of(8)?)?
                .iter()
                .map(asn1::dec_integer)
                .collect::<Krb5Result<_>>()?,
            addresses: f.get(9).map(read_host_addresses).transpose()?,
            enc_authorization_data: f
                .get(10)
                .map(EncryptedData::read)
                .transpose()?,
            additional_tickets: f
                .get(11)
                .map(|t| {
                    asn1::dec_sequence_of(t)?
                        .iter()
                        .map(|x| Ticket::read(x.raw))
                        .collect::<Krb5Result<Vec<_>>>()
                })
                .transpose()?,
            raw: Some(t.raw.to_vec()),
        })
    }
}

/// AS-REQ and TGS-REQ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdcReq {
    pub pvno: i64,
    pub msg_type: i64,
    pub padata: Vec<PaData>,
    pub req_body: KdcReqBody,
}

impl KdcReq {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        let tgs = self.msg_type == msg_type::TGS_REQ;
        Ok(asn1::enc_application(
            if tgs {
                application::TGS_REQ
            } else {
                application::AS_REQ
            },
            &asn1::enc_tagged_sequence(&[
                (1, int(PVNO)),
                (2, int(self.msg_type)),
                (
                    3,
                    Some(&self.padata)
                        .filter(|l| !l.is_empty())
                        .map(|l| enc_padata_list(l)),
                ),
                (4, Some(self.req_body.bytes()?)),
            ]),
        ))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app = asn1::read_application(bytes, None)?;
        if app.number != application::AS_REQ
            && app.number != application::TGS_REQ
        {
            return Err(Krb5Error::new(format!(
                "krb5: expected AS-REQ [APPLICATION 10] or TGS-REQ \
                 [APPLICATION 12], found [APPLICATION {}]",
                app.number
            )));
        }
        let f = fields(&app.sequence)?;
        let out = KdcReq {
            pvno: asn1::dec_integer(f.tag_of(1)?)?,
            msg_type: asn1::dec_integer(f.tag_of(2)?)?,
            padata: match f.get(3) {
                Some(t) => padata_list(t)?,
                None => Vec::new(),
            },
            req_body: KdcReqBody::read(f.value_of(4)?)?,
        };
        if out.pvno != PVNO {
            return Err(Krb5Error::new(format!(
                "krb5: protocol version {}, expected 5",
                out.pvno
            )));
        }
        Ok(out)
    }
}

/// AS-REP and TGS-REP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdcRep {
    pub pvno: i64,
    pub msg_type: i64,
    pub padata: Vec<PaData>,
    pub crealm: String,
    pub cname: PrincipalName,
    pub ticket: Ticket,
    pub enc_part: EncryptedData,
}

impl KdcRep {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        let tgs = self.msg_type == msg_type::TGS_REP;
        asn1::enc_application(
            if tgs {
                application::TGS_REP
            } else {
                application::AS_REP
            },
            &asn1::enc_tagged_sequence(&[
                (0, int(PVNO)),
                (1, int(self.msg_type)),
                (
                    2,
                    Some(&self.padata)
                        .filter(|l| !l.is_empty())
                        .map(|l| enc_padata_list(l)),
                ),
                (3, string(&self.crealm)),
                (4, Some(self.cname.encode())),
                (5, Some(self.ticket.encode())),
                (6, Some(self.enc_part.encode())),
            ]),
        )
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app = asn1::read_application(bytes, None)?;
        if app.number != application::AS_REP
            && app.number != application::TGS_REP
        {
            return Err(Krb5Error::new(format!(
                "krb5: expected AS-REP [APPLICATION 11] or TGS-REP \
                 [APPLICATION 13], found [APPLICATION {}]",
                app.number
            )));
        }
        let f = fields(&app.sequence)?;
        Ok(KdcRep {
            pvno: asn1::dec_integer(f.tag_of(0)?)?,
            msg_type: asn1::dec_integer(f.tag_of(1)?)?,
            padata: match f.get(2) {
                Some(t) => padata_list(t)?,
                None => Vec::new(),
            },
            crealm: asn1::dec_general_string(f.tag_of(3)?)?,
            cname: PrincipalName::read(f.value_of(4)?)?,
            ticket: Ticket::read(element_of(&f, 5)?)?,
            enc_part: EncryptedData::read(f.value_of(6)?)?,
        })
    }
}

/// One LastReq entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastReq {
    pub r#type: i64,
    pub value: KrbTime,
}

/// EncASRepPart / EncTGSRepPart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncKdcRepPart {
    pub tagged_as: String,
    pub key: EncryptionKey,
    pub last_req: Vec<LastReq>,
    pub nonce: i64,
    pub key_expiration: Option<KrbTime>,
    pub flags: Vec<u32>,
    pub authtime: KrbTime,
    pub starttime: Option<KrbTime>,
    pub endtime: KrbTime,
    pub renew_till: Option<KrbTime>,
    pub srealm: String,
    pub sname: PrincipalName,
    pub caddr: Option<Vec<HostAddress>>,
    pub encrypted_pa_data: Option<Vec<PaData>>,
}

impl EncKdcRepPart {
    /// Node's `encEncKdcRepPart(p, applicationNumber)`, 25 by default.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(
        &self,
        application_number: Option<u8>,
    ) -> Krb5Result<Vec<u8>> {
        let last: Vec<Vec<u8>> = self
            .last_req
            .iter()
            .map(|lr| {
                asn1::enc_tagged_sequence(&[
                    (0, int(lr.r#type)),
                    (1, time(lr.value)),
                ])
            })
            .collect();
        Ok(asn1::enc_application(
            application_number
                .filter(|n| *n != 0)
                .unwrap_or(application::ENC_AS_REP_PART),
            &asn1::enc_tagged_sequence(&[
                (0, Some(self.key.encode())),
                (1, Some(asn1::enc_sequence(&last))),
                (2, int(self.nonce)),
                (3, self.key_expiration.and_then(time)),
                (4, Some(asn1::enc_flags(&self.flags)?)),
                (5, time(self.authtime)),
                (6, self.starttime.and_then(time)),
                (7, time(self.endtime)),
                (8, self.renew_till.and_then(time)),
                (9, string(&self.srealm)),
                (10, Some(self.sname.encode())),
                (11, addresses(&self.caddr)),
                (
                    12,
                    self.encrypted_pa_data
                        .as_ref()
                        .filter(|l| !l.is_empty())
                        .map(|l| enc_padata_list(l)),
                ),
            ]),
        ))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app = asn1::read_application(bytes, None)?;
        if app.number != application::ENC_AS_REP_PART
            && app.number != application::ENC_TGS_REP_PART
        {
            return Err(Krb5Error::new(format!(
                "krb5: expected EncASRepPart [APPLICATION 25] or \
                 EncTGSRepPart [APPLICATION 26], found [APPLICATION {}]",
                app.number
            )));
        }
        let f = fields(&app.sequence)?;
        Ok(EncKdcRepPart {
            tagged_as: if app.number == application::ENC_AS_REP_PART {
                "EncASRepPart"
            } else {
                "EncTGSRepPart"
            }
            .to_string(),
            key: EncryptionKey::read(f.value_of(0)?)?,
            last_req: asn1::dec_sequence_of(f.tag_of(1)?)?
                .iter()
                .map(|lr| {
                    let lf = fields(lr)?;
                    Ok(LastReq {
                        r#type: asn1::dec_integer(lf.tag_of(0)?)?,
                        value: asn1::dec_kerberos_time(lf.tag_of(1)?)?,
                    })
                })
                .collect::<Krb5Result<_>>()?,
            nonce: asn1::dec_integer(f.tag_of(2)?)?,
            key_expiration: opt_time(&f, 3)?,
            flags: flags_of(f.tag_of(4)?)?,
            authtime: asn1::dec_kerberos_time(f.tag_of(5)?)?,
            starttime: opt_time(&f, 6)?,
            endtime: asn1::dec_kerberos_time(f.tag_of(7)?)?,
            renew_till: opt_time(&f, 8)?,
            srealm: asn1::dec_general_string(f.tag_of(9)?)?,
            sname: PrincipalName::read(f.value_of(10)?)?,
            caddr: f.get(11).map(read_host_addresses).transpose()?,
            encrypted_pa_data: f.get(12).map(padata_list).transpose()?,
        })
    }
}

/// Authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authenticator {
    pub vno: i64,
    pub crealm: String,
    pub cname: PrincipalName,
    pub cksum: Option<Checksum>,
    pub cusec: i64,
    pub ctime: KrbTime,
    pub subkey: Option<EncryptionKey>,
    pub seq_number: Option<i64>,
    pub authorization_data: Option<Vec<AuthorizationEntry>>,
}

impl Authenticator {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_application(
            application::AUTHENTICATOR,
            &asn1::enc_tagged_sequence(&[
                (0, int(PVNO)),
                (1, string(&self.crealm)),
                (2, Some(self.cname.encode())),
                (3, self.cksum.as_ref().map(Checksum::encode)),
                (4, int(self.cusec)),
                (5, time(self.ctime)),
                (6, self.subkey.as_ref().map(EncryptionKey::encode)),
                (7, self.seq_number.map(asn1::enc_integer)),
                (8, authz(&self.authorization_data)),
            ]),
        )
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app =
            asn1::read_application(bytes, Some(application::AUTHENTICATOR))?;
        let f = fields(&app.sequence)?;
        Ok(Authenticator {
            vno: asn1::dec_integer(f.tag_of(0)?)?,
            crealm: asn1::dec_general_string(f.tag_of(1)?)?,
            cname: PrincipalName::read(f.value_of(2)?)?,
            cksum: f.get(3).map(Checksum::read).transpose()?,
            cusec: asn1::dec_integer(f.tag_of(4)?)?,
            ctime: asn1::dec_kerberos_time(f.tag_of(5)?)?,
            subkey: f.get(6).map(EncryptionKey::read).transpose()?,
            seq_number: opt_int(&f, 7)?,
            authorization_data: f
                .get(8)
                .map(read_authorization_data)
                .transpose()?,
        })
    }
}

/// AP-REQ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApReq {
    pub pvno: i64,
    pub msg_type: i64,
    pub ap_options: Vec<u32>,
    pub ticket: Ticket,
    pub authenticator: EncryptedData,
}

impl ApReq {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        Ok(asn1::enc_application(
            application::AP_REQ,
            &asn1::enc_tagged_sequence(&[
                (0, int(PVNO)),
                (1, int(msg_type::AP_REQ)),
                (2, Some(asn1::enc_flags(&self.ap_options)?)),
                (3, Some(self.ticket.encode())),
                (4, Some(self.authenticator.encode())),
            ]),
        ))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app = asn1::read_application(bytes, Some(application::AP_REQ))?;
        let f = fields(&app.sequence)?;
        Ok(ApReq {
            pvno: asn1::dec_integer(f.tag_of(0)?)?,
            msg_type: asn1::dec_integer(f.tag_of(1)?)?,
            ap_options: flags_of(f.tag_of(2)?)?,
            ticket: Ticket::read(element_of(&f, 3)?)?,
            authenticator: EncryptedData::read(f.value_of(4)?)?,
        })
    }
}

/// AP-REP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApRep {
    pub pvno: i64,
    pub msg_type: i64,
    pub enc_part: EncryptedData,
}

impl ApRep {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_application(
            application::AP_REP,
            &asn1::enc_tagged_sequence(&[
                (0, int(PVNO)),
                (1, int(msg_type::AP_REP)),
                (2, Some(self.enc_part.encode())),
            ]),
        )
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app = asn1::read_application(bytes, Some(application::AP_REP))?;
        let f = fields(&app.sequence)?;
        Ok(ApRep {
            pvno: asn1::dec_integer(f.tag_of(0)?)?,
            msg_type: asn1::dec_integer(f.tag_of(1)?)?,
            enc_part: EncryptedData::read(f.value_of(2)?)?,
        })
    }
}

/// EncAPRepPart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncApRepPart {
    pub ctime: KrbTime,
    pub cusec: i64,
    pub subkey: Option<EncryptionKey>,
    pub seq_number: Option<i64>,
}

impl EncApRepPart {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_application(
            application::ENC_AP_REP_PART,
            &asn1::enc_tagged_sequence(&[
                (0, time(self.ctime)),
                (1, int(self.cusec)),
                (2, self.subkey.as_ref().map(EncryptionKey::encode)),
                (3, self.seq_number.map(asn1::enc_integer)),
            ]),
        )
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app =
            asn1::read_application(bytes, Some(application::ENC_AP_REP_PART))?;
        let f = fields(&app.sequence)?;
        Ok(EncApRepPart {
            ctime: asn1::dec_kerberos_time(f.tag_of(0)?)?,
            cusec: asn1::dec_integer(f.tag_of(1)?)?,
            subkey: f.get(2).map(EncryptionKey::read).transpose()?,
            seq_number: opt_int(&f, 3)?,
        })
    }
}

/// KRB-ERROR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KrbError {
    pub pvno: i64,
    pub msg_type: i64,
    pub ctime: Option<KrbTime>,
    pub cusec: Option<i64>,
    pub stime: KrbTime,
    pub susec: i64,
    pub error_code: i64,
    pub error: ErrorDescription,
    pub crealm: Option<String>,
    pub cname: Option<PrincipalName>,
    pub realm: String,
    pub sname: PrincipalName,
    pub e_text: Option<String>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub e_data: Option<Vec<u8>>,
    /// Present only when `e-data` is non-empty, as in Node: the PA-DATA
    /// list it carries, or `null` when it carries none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e_data_pa_data: Option<Option<Vec<PaData>>>,
    /// Why `e-data` is not a PA-DATA list, when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e_data_note: Option<String>,
}

impl KrbError {
    /// A KRB-ERROR to send: the fields a KDC fills, the rest absent.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        error_code: i64,
        stime: KrbTime,
        realm: &str,
        sname: PrincipalName,
    ) -> Self {
        KrbError {
            pvno: PVNO,
            msg_type: msg_type::ERROR,
            ctime: None,
            cusec: None,
            stime,
            susec: 0,
            error_code,
            error: describe_error(error_code),
            crealm: None,
            cname: None,
            realm: realm.to_string(),
            sname,
            e_text: None,
            e_data: None,
            e_data_pa_data: None,
            e_data_note: None,
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_application(
            application::KRB_ERROR,
            &asn1::enc_tagged_sequence(&[
                (0, int(PVNO)),
                (1, int(msg_type::ERROR)),
                (2, self.ctime.and_then(time)),
                (3, self.cusec.map(asn1::enc_integer)),
                (4, time(self.stime)),
                (5, int(self.susec)),
                (6, int(self.error_code)),
                (7, truthy(&self.crealm)),
                (8, self.cname.as_ref().map(PrincipalName::encode)),
                (9, string(&self.realm)),
                (10, Some(self.sname.encode())),
                (11, truthy(&self.e_text)),
                // An empty Uint8Array is truthy: written.
                (12, self.e_data.as_deref().map(asn1::enc_octet_string)),
            ]),
        )
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app = asn1::read_application(bytes, Some(application::KRB_ERROR))?;
        let f = fields(&app.sequence)?;
        let code = asn1::dec_integer(f.tag_of(6)?)?;
        let mut out = KrbError {
            pvno: asn1::dec_integer(f.tag_of(0)?)?,
            msg_type: asn1::dec_integer(f.tag_of(1)?)?,
            ctime: opt_time(&f, 2)?,
            cusec: opt_int(&f, 3)?,
            stime: asn1::dec_kerberos_time(f.tag_of(4)?)?,
            susec: asn1::dec_integer(f.tag_of(5)?)?,
            error_code: code,
            error: describe_error(code),
            crealm: opt_string(&f, 7)?,
            cname: f.get(8).map(PrincipalName::read).transpose()?,
            realm: asn1::dec_general_string(f.tag_of(9)?)?,
            sname: PrincipalName::read(f.value_of(10)?)?,
            e_text: opt_string(&f, 11)?,
            e_data: f
                .get(12)
                .map(|t| asn1::dec_octet_string(t).map(<[u8]>::to_vec))
                .transpose()?,
            e_data_pa_data: None,
            e_data_note: None,
        };
        if let Some(data) = out.e_data.as_deref().filter(|d| !d.is_empty()) {
            // Tolerated rather than refused: the note carries the reason.
            let listed = asn1::read_tlv(data, 0, 0).and_then(|t| {
                asn1::read_children(t.value, 0)?
                    .iter()
                    .map(PaData::read)
                    .collect::<Krb5Result<Vec<_>>>()
            });
            match listed {
                Ok(list) => out.e_data_pa_data = Some(Some(list)),
                Err(e) => {
                    out.e_data_pa_data = Some(None);
                    out.e_data_note = Some(format!(
                        "e-data is not a SEQUENCE OF PA-DATA ({})",
                        e.message()
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// PA-ENC-TS-ENC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaEncTsEnc {
    pub patimestamp: KrbTime,
    pub pausec: Option<i64>,
}

impl PaEncTsEnc {
    /// Node's `encPaEncTsEnc(when, usec)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(when: KrbTime, usec: Option<i64>) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, time(when)),
            (1, usec.map(asn1::enc_integer)),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = fields(&t)?;
        Ok(PaEncTsEnc {
            patimestamp: asn1::dec_kerberos_time(f.tag_of(0)?)?,
            pausec: opt_int(&f, 1)?,
        })
    }
}

/// One ETYPE-INFO2 entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EtypeInfo2Entry {
    pub etype: i64,
    pub etype_name: String,
    pub salt: Option<String>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub s2kparams: Option<Vec<u8>>,
}

/// Node's `encEtypeInfo2()`: an empty salt IS written (only null is not).
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_etype_info2(entries: &[EtypeInfo2Entry]) -> Vec<u8> {
    let items: Vec<Vec<u8>> = entries
        .iter()
        .map(|e| {
            asn1::enc_tagged_sequence(&[
                (0, int(e.etype)),
                (1, e.salt.as_deref().map(asn1::enc_general_string)),
                (2, e.s2kparams.as_deref().map(asn1::enc_octet_string)),
            ])
        })
        .collect();
    asn1::enc_sequence(&items)
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn read_etype_info2(bytes: &[u8]) -> Krb5Result<Vec<EtypeInfo2Entry>> {
    let t = asn1::read_tlv(bytes, 0, 0)?;
    asn1::read_children(t.value, 0)?
        .iter()
        .map(|entry| {
            let f = fields(entry)?;
            let etype = asn1::dec_integer(f.tag_of(0)?)?;
            Ok(EtypeInfo2Entry {
                etype,
                etype_name: crypto::etype_name(etype),
                salt: opt_string(&f, 1)?,
                s2kparams: f
                    .get(2)
                    .map(|t| asn1::dec_octet_string(t).map(<[u8]>::to_vec))
                    .transpose()?,
            })
        })
        .collect()
}

/// One ETYPE-INFO entry (the older form, salt as an OCTET STRING).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EtypeInfoEntry {
    pub etype: i64,
    pub etype_name: String,
    pub salt: Option<String>,
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn read_etype_info(bytes: &[u8]) -> Krb5Result<Vec<EtypeInfoEntry>> {
    let t = asn1::read_tlv(bytes, 0, 0)?;
    asn1::read_children(t.value, 0)?
        .iter()
        .map(|entry| {
            let f = fields(entry)?;
            let etype = asn1::dec_integer(f.tag_of(0)?)?;
            Ok(EtypeInfoEntry {
                etype,
                etype_name: crypto::etype_name(etype),
                salt: f
                    .get(1)
                    .map(|t| {
                        asn1::dec_octet_string(t).map(crate::primitives::latin1)
                    })
                    .transpose()?,
            })
        })
        .collect()
}

/// KERB-PA-PAC-REQUEST: Node's `encPaPacRequest()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_pa_pac_request(include: bool) -> Vec<u8> {
    asn1::enc_sequence(&[asn1::enc_context(
        0,
        &asn1::tlv(asn1::tag::BOOLEAN, &[if include { 0xff } else { 0 }]),
    )])
}

/// Node's `readPaPacRequest()`: `includePac` is ABSENT (undefined in
/// Node) when the field is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaPacRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_pac: Option<bool>,
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn read_pa_pac_request(bytes: &[u8]) -> Krb5Result<PaPacRequest> {
    let t = asn1::read_tlv(bytes, 0, 0)?;
    let f = fields(&t)?;
    Ok(PaPacRequest {
        include_pac: f.get(0).map(|b| !b.value.is_empty() && b.value[0] != 0),
    })
}

/// PA-FOR-USER (MS-SFU 2.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaForUser {
    pub user_name: PrincipalName,
    pub user_realm: String,
    pub cksum: Checksum,
    pub auth_package: String,
}

impl PaForUser {
    /// Node's `encPaForUser()`: an empty auth-package is "Kerberos".
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        let package = if self.auth_package.is_empty() {
            "Kerberos"
        } else {
            &self.auth_package
        };
        asn1::enc_tagged_sequence(&[
            (0, Some(self.user_name.encode())),
            (1, string(&self.user_realm)),
            (2, Some(self.cksum.encode())),
            (3, string(package)),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = fields(&t)?;
        Ok(PaForUser {
            user_name: PrincipalName::read(f.value_of(0)?)?,
            user_realm: asn1::dec_general_string(f.tag_of(1)?)?,
            cksum: Checksum::read(f.value_of(2)?)?,
            auth_package: asn1::dec_general_string(f.tag_of(3)?)?,
        })
    }
}

/// PA-PAC-OPTIONS: Node's `encPaPacOptions()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_pa_pac_options(bits: &[u32]) -> Krb5Result<Vec<u8>> {
    Ok(asn1::enc_tagged_sequence(&[(
        0,
        Some(asn1::enc_flags(bits)?),
    )]))
}

/// Node's `readPaPacOptions()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaPacOptions {
    pub flags: Vec<u32>,
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn read_pa_pac_options(bytes: &[u8]) -> Krb5Result<PaPacOptions> {
    let t = asn1::read_tlv(bytes, 0, 0)?;
    let f = fields(&t)?;
    Ok(PaPacOptions {
        flags: flags_of(f.tag_of(0)?)?,
    })
}

/// KrbCredInfo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KrbCredInfo {
    pub key: EncryptionKey,
    pub prealm: Option<String>,
    pub pname: Option<PrincipalName>,
    pub flags: Option<Vec<u32>>,
    pub authtime: Option<KrbTime>,
    pub starttime: Option<KrbTime>,
    pub endtime: Option<KrbTime>,
    pub renew_till: Option<KrbTime>,
    pub srealm: Option<String>,
    pub sname: Option<PrincipalName>,
    pub caddr: Option<Vec<HostAddress>>,
}

impl KrbCredInfo {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        Ok(asn1::enc_tagged_sequence(&[
            (0, Some(self.key.encode())),
            (1, truthy(&self.prealm)),
            (2, self.pname.as_ref().map(PrincipalName::encode)),
            (3, self.flags.as_deref().map(asn1::enc_flags).transpose()?),
            (4, self.authtime.and_then(time)),
            (5, self.starttime.and_then(time)),
            (6, self.endtime.and_then(time)),
            (7, self.renew_till.and_then(time)),
            (8, truthy(&self.srealm)),
            (9, self.sname.as_ref().map(PrincipalName::encode)),
            (10, addresses(&self.caddr)),
        ]))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let f = fields(t)?;
        let key = match f.get(0) {
            Some(k) => EncryptionKey::read(k)?,
            None => {
                return Err(Krb5Error::new(
                    "krb5: a KrbCredInfo with no session key. Every other \
                     field is optional but that one is not — a forwarded \
                     ticket without its key cannot be used for anything.",
                ))
            }
        };
        Ok(KrbCredInfo {
            key,
            prealm: opt_string(&f, 1)?,
            pname: f.get(2).map(PrincipalName::read).transpose()?,
            flags: f.get(3).map(flags_of).transpose()?,
            authtime: opt_time(&f, 4)?,
            starttime: opt_time(&f, 5)?,
            endtime: opt_time(&f, 6)?,
            renew_till: opt_time(&f, 7)?,
            srealm: opt_string(&f, 8)?,
            sname: f.get(9).map(PrincipalName::read).transpose()?,
            caddr: f.get(10).map(read_host_addresses).transpose()?,
        })
    }
}

/// EncKrbCredPart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncKrbCredPart {
    pub ticket_info: Vec<KrbCredInfo>,
    pub nonce: Option<i64>,
    pub timestamp: Option<KrbTime>,
    pub usec: Option<i64>,
    pub s_address: Option<HostAddress>,
    pub r_address: Option<HostAddress>,
}

impl EncKrbCredPart {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        let infos = self
            .ticket_info
            .iter()
            .map(KrbCredInfo::encode)
            .collect::<Krb5Result<Vec<_>>>()?;
        Ok(asn1::enc_application(
            application::ENC_KRB_CRED_PART,
            &asn1::enc_tagged_sequence(&[
                (0, Some(asn1::enc_sequence(&infos))),
                (1, self.nonce.map(asn1::enc_integer)),
                (2, self.timestamp.and_then(time)),
                (3, self.usec.map(asn1::enc_integer)),
                (4, self.s_address.as_ref().map(HostAddress::encode)),
                (5, self.r_address.as_ref().map(HostAddress::encode)),
            ]),
        ))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app = asn1::read_application(
            bytes,
            Some(application::ENC_KRB_CRED_PART),
        )?;
        let f = fields(&app.sequence)?;
        Ok(EncKrbCredPart {
            ticket_info: asn1::dec_sequence_of(f.tag_of(0)?)?
                .iter()
                .map(KrbCredInfo::read)
                .collect::<Krb5Result<_>>()?,
            nonce: opt_int(&f, 1)?,
            timestamp: opt_time(&f, 2)?,
            usec: opt_int(&f, 3)?,
            s_address: f.get(4).map(HostAddress::read).transpose()?,
            r_address: f.get(5).map(HostAddress::read).transpose()?,
        })
    }
}

/// KRB-CRED.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KrbCred {
    pub pvno: i64,
    pub msg_type: i64,
    pub tickets: Vec<Ticket>,
    pub enc_part: EncryptedData,
}

impl KrbCred {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        let tickets: Vec<Vec<u8>> =
            self.tickets.iter().map(Ticket::encode).collect();
        asn1::enc_application(
            application::KRB_CRED,
            &asn1::enc_tagged_sequence(&[
                (0, int(PVNO)),
                (1, int(msg_type::CRED)),
                (2, Some(asn1::enc_sequence(&tickets))),
                (3, Some(self.enc_part.encode())),
            ]),
        )
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let app = asn1::read_application(bytes, Some(application::KRB_CRED))?;
        let f = fields(&app.sequence)?;
        let msg = asn1::dec_integer(f.tag_of(1)?)?;
        if msg != msg_type::CRED {
            return Err(Krb5Error::new(format!(
                "krb5: this is tagged [APPLICATION 22] but its msg-type is \
                 {}, not 22",
                msg
            )));
        }
        let tickets = asn1::dec_sequence_of(f.tag_of(2)?)?
            .iter()
            .map(|t| Ticket::read(t.raw))
            .collect::<Krb5Result<Vec<_>>>()?;
        if tickets.is_empty() {
            return Err(Krb5Error::new(
                "krb5: a KRB-CRED carrying no tickets. There is nothing to \
                 delegate.",
            ));
        }
        Ok(KrbCred {
            pvno: asn1::dec_integer(f.tag_of(0)?)?,
            msg_type: msg,
            tickets,
            enc_part: EncryptedData::read(f.value_of(3)?)?,
        })
    }
}

/// What a message's outermost tag says it is: Node's `identify()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identified {
    pub application_number: u8,
    pub name: String,
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn identify(bytes: &[u8]) -> Option<Identified> {
    let n = asn1::peek_application_number(bytes)?;
    Some(Identified {
        application_number: n,
        name: application_name(n)
            .map(str::to_string)
            .unwrap_or_else(|| format!("[APPLICATION {}]", n)),
    })
}

/// A KDC's answer: Node's `readKdcResponse()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum KdcResponse {
    Error { kind: String, error: KrbError },
    Reply { kind: String, rep: KdcRep },
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn read_kdc_response(bytes: &[u8]) -> Krb5Result<KdcResponse> {
    let id = identify(bytes).ok_or_else(|| {
        Krb5Error::new("krb5: not a Kerberos message (no [APPLICATION n] tag)")
    })?;
    if id.application_number == application::KRB_ERROR {
        return Ok(KdcResponse::Error {
            kind: "KRB-ERROR".to_string(),
            error: KrbError::read(bytes)?,
        });
    }
    if id.application_number == application::AS_REP
        || id.application_number == application::TGS_REP
    {
        return Ok(KdcResponse::Reply {
            kind: id.name,
            rep: KdcRep::read(bytes)?,
        });
    }
    Err(Krb5Error::new(format!(
        "krb5: a KDC answered with {}, which is neither a reply nor an error",
        id.name
    )))
}
