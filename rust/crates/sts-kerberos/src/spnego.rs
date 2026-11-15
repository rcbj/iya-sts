// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! SPNEGO's two messages (RFC 4178, and [MS-SPNG]'s NegTokenInit2):
//! `kerberos/krb5_spnego.js` — the CODEC, which knows nothing about
//! Kerberos beyond one OID. The negotiation (`spnego_exchange.js`: which
//! token answers which, the request-mic continuation, the pending map) is
//! state, and phase 9's.
//!
//! The four things that decode as something else rather than failing are
//! Node's and stay here: only the FIRST token is wrapped in an
//! InitialContextToken (every later one is a bare `[1] NegTokenResp`);
//! `mechListMIC` is computed over the DER of the mechTypes list exactly as
//! it arrived; negState is an ENUMERATED; and a list must not name SPNEGO
//! itself.
//!
//! **A NODE DEFECT PORTED AS IT IS**: `encodeOidContent()` writes the
//! first subidentifier (40·arc1 + arc2) as ONE octet, not base-128, so an
//! OID under `2.` with a second arc of 88 or more is written wrong (the
//! value truncated to a byte), and `decodeOidContent()` reads the first
//! octet the same way. Every OID SPNEGO meets starts `1.2.` or `1.3.`, so
//! nothing on the wire is affected; [`crate::pkinit`]'s OID coder, which
//! Node wrote separately, is correct.

use serde::Serialize;

use crate::asn1::{self, tag};
use crate::error::{Krb5Error, Krb5Result};
use crate::gss::{self, MicVerdict, Role, TokenOptions};
use crate::primitives;

/// 1.3.6.1.5.5.2.
pub const SPNEGO_OID: &str = "1.3.6.1.5.5.2";
pub const SPNEGO_OID_DER: [u8; 8] =
    [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
pub const KRB5_MECH_OID: &str = gss::KRB5_MECH_OID;
/// Microsoft's mis-typed Kerberos OID.
pub const MS_KRB5_MECH_OID: &str = "1.2.840.48018.1.2.2";

/// A mechanism a token may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Mech {
    pub oid: &'static str,
    pub name: &'static str,
    pub note: &'static str,
}

/// negState values.
pub const NEG_STATE_ACCEPT_COMPLETED: i64 = 0;
pub const NEG_STATE_ACCEPT_INCOMPLETE: i64 = 1;
pub const NEG_STATE_REJECT: i64 = 2;
pub const NEG_STATE_REQUEST_MIC: i64 = 3;

pub const MECHS: [Mech; 6] = [
    Mech {
        oid: "1.2.840.113554.1.2.2",
        name: "Kerberos v5",
        note: "RFC 4121's Kerberos mechanism — the one this debugger speaks.",
    },
    Mech {
        oid: "1.2.840.48018.1.2.2",
        name: "Kerberos v5 (MS OID)",
        note: "Microsoft's mis-typed Kerberos OID (48018 where 113554 was meant), kept for compatibility and still offered by every Windows client. Same mechanism, different number.",
    },
    Mech {
        oid: "1.2.840.113554.1.2.2.3",
        name: "Kerberos v5 user-to-user",
        note: "user-to-user, where the acceptor has no long-term key of its own and the ticket is sealed with a session key instead.",
    },
    Mech {
        oid: "1.3.6.1.4.1.311.2.2.10",
        name: "NTLMSSP",
        note: "NTLM. Offered by Windows as the fallback when no Kerberos ticket can be obtained — a name that cannot be resolved to an SPN, a machine off the domain, or an IP address in the URL rather than a host name.",
    },
    Mech {
        oid: "1.3.6.1.4.1.311.2.2.30",
        name: "NEGOEX",
        note: "the extended negotiation mechanism ([MS-NEGOEX]), which negotiates again inside SPNEGO.",
    },
    Mech {
        oid: "1.3.6.1.5.5.2",
        name: "SPNEGO",
        note: "SPNEGO itself. RFC 4178 section 4.1 says a mechTypes list MUST NOT contain it: a negotiation that can select itself does not terminate.",
    },
];

const NEG_STATE_INFO: [(&str, &str); 4] = [
    ("accept-completed",
     "the context is established and no further token is needed. On HTTP this is the state that comes with the 200."),
    ("accept-incomplete",
     "another token is expected from the other side. On HTTP this is a second 401 carrying a challenge rather than a refusal."),
    ("reject",
     "the negotiation has failed and no context exists. The reason is NOT in this structure — SPNEGO carries no error detail, which is why the mechanism's own error token (a KRB-ERROR here) matters."),
    ("request-mic",
     "the acceptor requires the mechListMIC exchange. Legal only in the acceptor's FIRST reply (RFC 4178 section 4.2.2)."),
];

/// Node's `mechByOid()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn mech_by_oid(oid: &str) -> Option<&'static Mech> {
    MECHS.iter().find(|m| m.oid == oid)
}

/// Node's `mechName()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn mech_name(oid: &str) -> &'static str {
    mech_by_oid(oid)
        .map(|m| m.name)
        .unwrap_or("unrecognised mechanism")
}

/// Node's `isKerberosMech()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_kerberos_mech(oid: &str) -> bool {
    oid == KRB5_MECH_OID || oid == MS_KRB5_MECH_OID
}

/// A negState, named: Node's `negStateInfo()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NegStateInfo {
    pub name: String,
    pub meaning: String,
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn neg_state_info(value: i64) -> NegStateInfo {
    match usize::try_from(value)
        .ok()
        .and_then(|v| NEG_STATE_INFO.get(v))
    {
        Some((name, meaning)) => NegStateInfo {
            name: name.to_string(),
            meaning: meaning.to_string(),
        },
        None => NegStateInfo {
            name: format!("unrecognised ({})", value),
            meaning: "RFC 4178 defines 0 through 3 only.".to_string(),
        },
    }
}

/// JavaScript's `Number()` of one arc: an empty string is 0.
fn arc_number(a: &str) -> Option<u64> {
    let t = a.trim();
    if t.is_empty() {
        return Some(0);
    }
    t.parse::<u64>().ok()
}

/// Node's `encodeOidContent()` (see the module note on its first octet).
// A hot path: a per-TLV codec primitive, run for every OID of every
// mechType list; no span (an Entering/Leaving pair would drown the log).
pub fn encode_oid_content(dotted: &str) -> Krb5Result<Vec<u8>> {
    let arcs: Option<Vec<u64>> = dotted.split('.').map(arc_number).collect();
    let arcs = match arcs {
        Some(a) if a.len() >= 2 => a,
        _ => {
            return Err(Krb5Error::new(format!(
                "krb5: {} is not an object identifier — it needs at least \
                 two non-negative integer arcs",
                crate::time::json_string(dotted)
            )))
        }
    };
    if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
        return Err(Krb5Error::new(format!(
            "krb5: object identifier {} cannot be encoded — the first arc \
             must be 0, 1 or 2, and under 2 the second arc must be below 40",
            dotted
        )));
    }
    // ONE octet, as Node writes it (a Uint8Array keeps the low byte).
    let mut out = vec![(40 * arcs[0] + arcs[1]) as u8];
    for v in &arcs[2..] {
        let mut v = *v;
        let mut chunk = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            chunk.insert(0, ((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        out.extend(chunk);
    }
    Ok(out)
}

// A hot path: a per-TLV codec primitive, run for every OID of every
// mechType list; no span (an Entering/Leaving pair would drown the log).
pub fn encode_oid(dotted: &str) -> Krb5Result<Vec<u8>> {
    Ok(asn1::tlv(
        tag::OBJECT_IDENTIFIER,
        &encode_oid_content(dotted)?,
    ))
}

/// Node's `decodeOidContent()`.
// A hot path: a per-TLV codec primitive, run for every OID of every
// mechType list; no span (an Entering/Leaving pair would drown the log).
pub fn decode_oid_content(b: &[u8]) -> Krb5Result<String> {
    if b.is_empty() {
        return Err(Krb5Error::new("krb5: a zero-length OBJECT IDENTIFIER"));
    }
    if b[b.len() - 1] & 0x80 != 0 {
        return Err(Krb5Error::new(
            "krb5: this OBJECT IDENTIFIER is truncated — its last octet \
             still carries the base-128 continuation bit",
        ));
    }
    let first = u64::from(b[0]);
    let a0 = (first / 40).min(2);
    let mut arcs = vec![a0, first - 40 * a0];
    let mut value: u64 = 0;
    for x in &b[1..] {
        value = value.wrapping_mul(128).wrapping_add(u64::from(x & 0x7f));
        if x & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    Ok(arcs
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

/// Node's `decodeOid()`.
// A hot path: a per-TLV codec primitive, run for every OID of every
// mechType list; no span (an Entering/Leaving pair would drown the log).
pub fn decode_oid(t: &asn1::Tlv<'_>) -> Krb5Result<String> {
    asn1::expect_tag(t, tag::OBJECT_IDENTIFIER, "an OBJECT IDENTIFIER")?;
    decode_oid_content(t.value)
}

/// The DER of a MechTypeList: Node's `mechTypeListDer()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn mech_type_list_der(oids: &[String]) -> Krb5Result<Vec<u8>> {
    if oids.is_empty() {
        return Err(Krb5Error::new(
            "krb5: a SPNEGO mechTypes list may not be empty — RFC 4178 \
             section 4.1 requires at least one mechanism",
        ));
    }
    if oids.iter().any(|o| o == SPNEGO_OID) {
        return Err(Krb5Error::new(
            "krb5: a mechTypes list must not contain SPNEGO itself \
             (1.3.6.1.5.5.2). RFC 4178 section 4.1 — a negotiation that can \
             select itself does not terminate.",
        ));
    }
    let items = oids
        .iter()
        .map(|o| encode_oid(o))
        .collect::<Krb5Result<Vec<_>>>()?;
    Ok(asn1::enc_sequence(&items))
}

/// An encoded NegTokenInit, and the list DER its MIC is over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedInit {
    pub token: Vec<u8>,
    pub mech_list_der: Vec<u8>,
    pub mech_types: Vec<String>,
}

/// Node's `encodeNegTokenInit()`: the mechTypes default to Kerberos.
#[tracing::instrument(level = "debug", skip_all)]
pub fn encode_neg_token_init(
    mech_types: Option<&[String]>,
    mech_token: Option<&[u8]>,
    mech_list_mic: Option<&[u8]>,
) -> Krb5Result<EncodedInit> {
    let mechs: Vec<String> = match mech_types {
        Some(m) => m.to_vec(),
        None => vec![KRB5_MECH_OID.to_string()],
    };
    let mech_list = mech_type_list_der(&mechs)?;
    let mut parts = vec![asn1::enc_context(0, &mech_list)];
    if let Some(t) = mech_token {
        parts.push(asn1::enc_context(2, &asn1::enc_octet_string(t)));
    }
    if let Some(m) = mech_list_mic {
        parts.push(asn1::enc_context(3, &asn1::enc_octet_string(m)));
    }
    let neg_token_init = asn1::enc_context(0, &asn1::enc_sequence(&parts));
    let mut body = SPNEGO_OID_DER.to_vec();
    body.extend(neg_token_init);
    let mut token = vec![0x60];
    token.extend(asn1::encode_length(body.len()));
    token.extend(body);
    Ok(EncodedInit {
        token,
        mech_list_der: mech_list,
        mech_types: mechs,
    })
}

/// Node's `encodeNegTokenResp()`: a bare `[1]`, never wrapped.
#[tracing::instrument(level = "debug", skip_all)]
pub fn encode_neg_token_resp(
    neg_state: Option<i64>,
    supported_mech: Option<&str>,
    response_token: Option<&[u8]>,
    mech_list_mic: Option<&[u8]>,
) -> Krb5Result<Vec<u8>> {
    let mut fields = Vec::new();
    if let Some(s) = neg_state {
        fields.push(asn1::enc_context(
            0,
            &asn1::tlv(tag::ENUMERATED, &asn1::integer_content(s)),
        ));
    }
    if let Some(m) = supported_mech.filter(|m| !m.is_empty()) {
        fields.push(asn1::enc_context(1, &encode_oid(m)?));
    }
    if let Some(t) = response_token {
        fields.push(asn1::enc_context(2, &asn1::enc_octet_string(t)));
    }
    if let Some(m) = mech_list_mic {
        fields.push(asn1::enc_context(3, &asn1::enc_octet_string(m)));
    }
    Ok(asn1::enc_context(1, &asn1::enc_sequence(&fields)))
}

/// NegHints ([MS-SPNG]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NegHints {
    pub hint_name: Option<String>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub hint_address: Option<Vec<u8>>,
}

/// A decoded NegTokenInit or NegTokenInit2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NegTokenInit {
    pub kind: String,
    pub mech_types: Vec<String>,
    pub mech_type_names: Vec<String>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub req_flags: Option<Vec<u8>>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub mech_token: Option<Vec<u8>>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub mech_list_mic: Option<Vec<u8>>,
    pub neg_hints: Option<NegHints>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub mech_list_der: Option<Vec<u8>>,
    pub problems: Vec<String>,
    #[serde(serialize_with = "crate::hex::ser")]
    pub raw: Vec<u8>,
}

/// A decoded NegTokenResp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NegTokenResp {
    pub kind: String,
    pub neg_state: Option<i64>,
    pub neg_state_name: Option<String>,
    pub neg_state_meaning: Option<String>,
    pub supported_mech: Option<String>,
    pub supported_mech_name: Option<String>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub response_token: Option<Vec<u8>>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub mech_list_mic: Option<Vec<u8>>,
    pub problems: Vec<String>,
    #[serde(serialize_with = "crate::hex::ser")]
    pub raw: Vec<u8>,
}

/// A bare Kerberos InitialContextToken where SPNEGO was expected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawKerberos {
    pub kind: String,
    pub mech_oid: String,
    pub mech_name: String,
    #[serde(serialize_with = "crate::hex::ser")]
    pub raw: Vec<u8>,
    pub note: String,
}

/// What `decodeNegotiationToken()` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum NegotiationToken {
    Init(NegTokenInit),
    Resp(NegTokenResp),
    RawKerberos(RawKerberos),
}

const RAW_KERBEROS_NOTE: &str = "An RFC 2743 InitialContextToken naming the \
    Kerberos mechanism directly, with no negotiation around it. Inside a \
    SPNEGO mechToken or responseToken that is exactly what belongs there — \
    the negotiation wrapper is one layer further out. On its own, as the \
    whole of an Authorization header, it is a client speaking Kerberos \
    rather than negotiating: legal, and what some clients send, but a \
    server expecting SPNEGO will refuse it without saying why.";

/// Node's `decodeNegotiationToken()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn decode_negotiation_token(b: &[u8]) -> Krb5Result<NegotiationToken> {
    if b.is_empty() {
        return Err(Krb5Error::new("krb5: an empty SPNEGO token"));
    }
    if b[0] == 0xa1 {
        let resp = asn1::read_tlv(b, 0, 0)?;
        return Ok(NegotiationToken::Resp(decode_neg_token_resp_body(
            resp.value, b,
        )?));
    }
    if b[0] != 0x60 {
        return Err(Krb5Error::new(format!(
            "krb5: this is not a SPNEGO token. It begins with 0x{:x}; a \
             negotiation token begins with 0x60 (the initiator's first \
             token) or 0xa1 (every token after it){}",
            b[0],
            if b[0] == 0x6e {
                ". 0x6e is a bare AP-REQ, which is the Kerberos message \
                 that belongs INSIDE the mechToken."
            } else {
                "."
            }
        )));
    }
    let outer = asn1::read_tlv(b, 0, 0)?;
    let value = outer.value;
    if value.len() < SPNEGO_OID_DER.len()
        || !primitives::equal_constant_time(
            &value[..SPNEGO_OID_DER.len()],
            &SPNEGO_OID_DER,
        )
    {
        let n = gss::KRB5_MECH_OID_DER.len();
        if value.len() >= n
            && primitives::equal_constant_time(
                &value[..n],
                &gss::KRB5_MECH_OID_DER,
            )
        {
            return Ok(NegotiationToken::RawKerberos(RawKerberos {
                kind: "RawKerberos".to_string(),
                mech_oid: KRB5_MECH_OID.to_string(),
                mech_name: "Kerberos v5".to_string(),
                raw: b.to_vec(),
                note: RAW_KERBEROS_NOTE.to_string(),
            }));
        }
        let oid_text =
            match asn1::read_tlv(value, 0, 0).and_then(|t| decode_oid(&t)) {
                Ok(t) => t,
                Err(_) => format!(
                    "unreadable ({}…)",
                    primitives::to_hex(&value[..value.len().min(16)])
                ),
            };
        return Err(Krb5Error::new(format!(
            "krb5: this GSS token names {} ({}), not SPNEGO ({}).",
            oid_text,
            mech_name(&oid_text),
            SPNEGO_OID
        )));
    }
    let inner = asn1::read_tlv(value, SPNEGO_OID_DER.len(), 0)?;
    if inner.tag != 0xa0 {
        return Err(Krb5Error::new(format!(
            "krb5: a SPNEGO InitialContextToken must carry [0] NegTokenInit, \
             and this carries tag 0x{:x}{}",
            inner.tag,
            if inner.tag == 0xa1 {
                " — a NegTokenResp, which is never wrapped in an \
                 InitialContextToken (RFC 4178 section 4.2)."
            } else {
                "."
            }
        )));
    }
    let init_seq = asn1::read_tlv(inner.value, 0, 0)?;
    asn1::expect_tag(&init_seq, tag::SEQUENCE, "the NegTokenInit SEQUENCE")?;
    Ok(NegotiationToken::Init(decode_neg_token_init_body(
        init_seq.value,
        b,
    )?))
}

fn decode_neg_token_init_body(
    body: &[u8],
    raw: &[u8],
) -> Krb5Result<NegTokenInit> {
    let mut out = NegTokenInit {
        kind: "NegTokenInit".to_string(),
        mech_types: Vec::new(),
        mech_type_names: Vec::new(),
        req_flags: None,
        mech_token: None,
        mech_list_mic: None,
        neg_hints: None,
        mech_list_der: None,
        problems: Vec::new(),
        raw: raw.to_vec(),
    };
    for field in asn1::read_children(body, 1)? {
        match field.tag {
            0xa0 => {
                let list = asn1::read_tlv(field.value, 0, 0)?;
                asn1::expect_tag(&list, tag::SEQUENCE, "the MechTypeList")?;
                out.mech_list_der = Some(list.raw.to_vec());
                for e in asn1::read_children(list.value, 2)? {
                    let oid = decode_oid(&e)?;
                    out.mech_type_names.push(mech_name(&oid).to_string());
                    if oid == SPNEGO_OID {
                        out.problems.push(
                            "The mechTypes list contains SPNEGO itself \
                             (1.3.6.1.5.5.2), which RFC 4178 section 4.1 \
                             forbids: a negotiation that can select itself \
                             does not terminate."
                                .to_string(),
                        );
                    }
                    out.mech_types.push(oid);
                }
            }
            0xa1 => {
                out.req_flags =
                    Some(asn1::read_tlv(field.value, 0, 0)?.value.to_vec());
                out.problems.push(
                    "reqFlags is present. RFC 4178 section 4.2.1 deprecates \
                     it — senders SHOULD omit it and receivers MUST ignore \
                     it. The flags a service actually reads are in the \
                     0x8003 checksum inside the Kerberos AP-REQ."
                        .to_string(),
                );
            }
            0xa2 => {
                let t = asn1::read_tlv(field.value, 0, 0)?;
                out.mech_token = Some(asn1::dec_octet_string(&t)?.to_vec());
            }
            0xa3 => {
                let inner = asn1::read_tlv(field.value, 0, 0)?;
                if inner.tag == tag::SEQUENCE {
                    out.neg_hints = Some(decode_neg_hints(inner.value)?);
                    out.kind = "NegTokenInit2".to_string();
                } else {
                    out.mech_list_mic =
                        Some(asn1::dec_octet_string(&inner)?.to_vec());
                }
            }
            0xa4 => {
                let t = asn1::read_tlv(field.value, 0, 0)?;
                out.mech_list_mic = Some(asn1::dec_octet_string(&t)?.to_vec());
                out.kind = "NegTokenInit2".to_string();
            }
            other => out.problems.push(format!(
                "An unrecognised field with tag 0x{:x} — RFC 4178's \
                 NegTokenInit defines [0] through [3], and [MS-SPNG]'s \
                 NegTokenInit2 adds [4].",
                other
            )),
        }
    }
    if out.mech_types.is_empty() {
        out.problems.push(
            "There is no mechTypes list. It is the one mandatory field of a \
             NegTokenInit."
                .to_string(),
        );
    }
    Ok(out)
}

fn decode_neg_hints(body: &[u8]) -> Krb5Result<NegHints> {
    let mut hints = NegHints {
        hint_name: None,
        hint_address: None,
    };
    for field in asn1::read_children(body, 3)? {
        if field.tag == 0xa0 {
            hints.hint_name = Some(asn1::dec_general_string(&asn1::read_tlv(
                field.value,
                0,
                0,
            )?)?);
        } else if field.tag == 0xa1 {
            hints.hint_address = Some(
                asn1::dec_octet_string(&asn1::read_tlv(field.value, 0, 0)?)?
                    .to_vec(),
            );
        }
    }
    Ok(hints)
}

fn decode_neg_token_resp_body(
    body: &[u8],
    raw: &[u8],
) -> Krb5Result<NegTokenResp> {
    let seq = asn1::read_tlv(body, 0, 0)?;
    asn1::expect_tag(&seq, tag::SEQUENCE, "the NegTokenResp SEQUENCE")?;
    let mut out = NegTokenResp {
        kind: "NegTokenResp".to_string(),
        neg_state: None,
        neg_state_name: None,
        neg_state_meaning: None,
        supported_mech: None,
        supported_mech_name: None,
        response_token: None,
        mech_list_mic: None,
        problems: Vec::new(),
        raw: raw.to_vec(),
    };
    for field in asn1::read_children(seq.value, 1)? {
        match field.tag {
            0xa0 => {
                let e = asn1::read_tlv(field.value, 0, 0)?;
                if e.tag != tag::ENUMERATED && e.tag != tag::INTEGER {
                    out.problems.push(format!(
                        "negState is tag 0x{:x} rather than ENUMERATED \
                         (0x0a).",
                        e.tag
                    ));
                }
                let state = asn1::dec_integer_content(e.value)?;
                let info = neg_state_info(state);
                out.neg_state = Some(state);
                out.neg_state_name = Some(info.name);
                out.neg_state_meaning = Some(info.meaning);
            }
            0xa1 => {
                let oid = decode_oid(&asn1::read_tlv(field.value, 0, 0)?)?;
                out.supported_mech_name = Some(mech_name(&oid).to_string());
                out.supported_mech = Some(oid);
            }
            0xa2 => {
                let t = asn1::read_tlv(field.value, 0, 0)?;
                out.response_token = Some(asn1::dec_octet_string(&t)?.to_vec());
            }
            0xa3 => {
                let t = asn1::read_tlv(field.value, 0, 0)?;
                out.mech_list_mic = Some(asn1::dec_octet_string(&t)?.to_vec());
            }
            other => out.problems.push(format!(
                "An unrecognised field with tag 0x{:x} — RFC 4178's \
                 NegTokenResp defines [0] through [3].",
                other
            )),
        }
    }
    if out.neg_state == Some(NEG_STATE_REJECT) && out.response_token.is_none() {
        out.problems.push(
            "The negotiation was rejected and no mechanism token came with \
             it, so nothing here says why. SPNEGO carries no error detail of \
             its own — when a server can say more, it says it in the \
             mechanism's own error token (a KRB-ERROR)."
                .to_string(),
        );
    }
    Ok(out)
}

/// The mechListMIC: a GSS MIC over the list DER. Node's
/// `computeMechListMic()`, the role an initiator's by default.
#[tracing::instrument(level = "debug", skip_all)]
pub fn compute_mech_list_mic(
    key: &[u8],
    etype: i64,
    role: Role,
    acceptor_subkey: bool,
    mech_list_der: &[u8],
    sequence_number: u64,
) -> Krb5Result<Vec<u8>> {
    gss::get_mic(&TokenOptions {
        key,
        etype,
        role,
        acceptor_subkey,
        message: mech_list_der,
        sequence_number,
    })
}

/// Node's `verifyMechListMic()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn verify_mech_list_mic(
    key: &[u8],
    etype: i64,
    mic: &[u8],
    mech_list_der: &[u8],
) -> Krb5Result<MicVerdict> {
    gss::verify_mic(key, etype, mic, mech_list_der)
}

/// Whether RFC 4178 section 5 requires the mechListMIC exchange: Node's
/// `micRequirement()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MicRequirement {
    pub required: bool,
    pub reason: String,
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn mic_requirement(
    mech_types: &[String],
    selected: Option<&str>,
) -> MicRequirement {
    let Some(selected) = selected.filter(|s| !s.is_empty()) else {
        return MicRequirement {
            required: true,
            reason: "No mechanism has been selected, so nothing can be \
                     assumed about the negotiation."
                .to_string(),
        };
    };
    if mech_types.first().map(String::as_str) == Some(selected) {
        return MicRequirement {
            required: false,
            reason: format!(
                "The selected mechanism ({}) is the first one the initiator \
                 listed, so RFC 4178 section 5 makes the mechListMIC \
                 exchange OPTIONAL: there was no downgrade to detect.",
                mech_name(selected)
            ),
        };
    }
    MicRequirement {
        required: true,
        reason: format!(
            "The selected mechanism ({}) is not the initiator's first \
             preference ({}), so RFC 4178 section 5 makes the mechListMIC \
             exchange MANDATORY. Without it, an attacker who removed the \
             preferred mechanism from the list on the wire would be \
             indistinguishable from an acceptor that does not support it.",
            mech_name(selected),
            mech_types
                .first()
                .map(|m| mech_name(m))
                .unwrap_or("none listed")
        ),
    }
}
