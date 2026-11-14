// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The wire format of FAST (RFC 6113), OTP pre-authentication (RFC 6560)
//! and authentication indicators (RFC 7751, RFC 8129):
//! `kerberos/krb5_fast_codec.ts`. It knows no key and no policy —
//! encryption, KRB-FX-CF2 and what a factor proves are `krb5_fast.ts`'s
//! (phase 9) — and is built on [`crate::messages`]' readers, so a
//! KrbFastReq's req-body is the same reader an AS-REQ's is, raw bytes
//! included.
//!
//! RFC 6113 is EXPLICIT tags and RFC 6560 is IMPLICIT, which is why the
//! OTP structures have their own field reader ([`implicit_fields`]): the
//! context tag REPLACES the universal one, so a field is read by putting
//! the universal tag back ([`as_universal`]).
//!
//! Node reads a UTF8String with `Buffer.toString('utf8')`, which replaces
//! a malformed sequence with U+FFFD rather than refusing it;
//! `String::from_utf8_lossy` substitutes the same maximal subparts.

use serde::Serialize;

use crate::asn1::{self, tag, Fields, Tlv};
use crate::error::{Krb5Error, Krb5Result};
use crate::messages::{
    enc_padata_list, read_authorization_data, AuthorizationEntry, Checksum,
    EncryptedData, EncryptionKey, KdcReqBody, PaData, PrincipalName,
};
use crate::primitives;
use crate::time::KrbTime;

/// PA-DATA types.
pub mod pa {
    pub const FX_COOKIE: i64 = 133;
    pub const AUTHENTICATION_SET: i64 = 134;
    pub const AUTH_SET_SELECTED: i64 = 135;
    pub const FX_FAST: i64 = 136;
    pub const FX_ERROR: i64 = 137;
    pub const ENCRYPTED_CHALLENGE: i64 = 138;
    pub const OTP_CHALLENGE: i64 = 141;
    pub const OTP_REQUEST: i64 = 142;
    pub const OTP_PIN_CHANGE: i64 = 144;
}

/// Key usage numbers.
pub mod key_usage {
    pub const OTP_REQUEST: u32 = 45;
    pub const FAST_REQ_CHKSUM: u32 = 50;
    pub const FAST_ENC: u32 = 51;
    pub const FAST_REP: u32 = 52;
    pub const FAST_FINISHED: u32 = 53;
    pub const ENC_CHALLENGE_CLIENT: u32 = 54;
    pub const ENC_CHALLENGE_KDC: u32 = 55;
    pub const CAMMAC: u32 = 64;
    pub const FX_COOKIE: u32 = 513;
}

/// Authorization-data types.
pub mod ad {
    pub const IF_RELEVANT: i64 = 1;
    pub const FX_FAST_ARMOR: i64 = 71;
    pub const FX_FAST_USED: i64 = 72;
    pub const CAMMAC: i64 = 96;
    pub const AUTHENTICATION_INDICATOR: i64 = 97;
}

/// The one armor type, an AP-REQ.
pub const ARMOR_AP_REQUEST: i64 = 1;

/// FastOptions bits.
pub mod fast_option {
    pub const RESERVED: u32 = 0;
    pub const HIDE_CLIENT_NAMES: u32 = 1;
    pub const KDC_FOLLOW_REFERRALS: u32 = 16;
}

/// OTPFlags bits.
pub mod otp_flag {
    pub const NEXT_OTP: u32 = 1;
    pub const COMBINE: u32 = 2;
    pub const COLLECT_PIN: u32 = 3;
    pub const DO_NOT_COLLECT_PIN: u32 = 4;
    pub const MUST_ENCRYPT_NONCE: u32 = 5;
    pub const SEPARATE_PIN_REQUIRED: u32 = 6;
    pub const CHECK_DIGIT: u32 = 7;
}

/// otp-format values.
pub mod otp_format {
    pub const DECIMAL: i64 = 0;
    pub const HEXADECIMAL: i64 = 1;
    pub const ALPHANUMERIC: i64 = 2;
    pub const BINARY: i64 = 3;
    pub const BASE64: i64 = 4;
}

/// RFC 6113 and RFC 6560 error codes.
pub mod error {
    pub const PREAUTH_EXPIRED: i64 = 90;
    pub const MORE_PREAUTH_DATA_REQUIRED: i64 = 91;
    pub const PREAUTH_BAD_AUTHENTICATION_SET: i64 = 92;
    pub const UNKNOWN_CRITICAL_FAST_OPTIONS: i64 = 93;
    pub const INVALID_HASH_ALG: i64 = 94;
    pub const INVALID_ITERATION_COUNT: i64 = 95;
    pub const PIN_EXPIRED: i64 = 96;
    pub const PIN_REQUIRED: i64 = 97;
}

fn err(m: String) -> Krb5Error {
    Krb5Error::new(m)
}

/// A UTF8String: Node's `encUtf8()`.
// A hot path: a per-TLV helper, run for every field of every FAST
// message; no span (an Entering/Leaving pair here would drown the log).
pub fn enc_utf8(text: &str) -> Vec<u8> {
    asn1::tlv(tag::UTF8_STRING, text.as_bytes())
}

/// Node's `decUtf8()`.
// A hot path: a per-TLV helper, run for every field of every FAST
// message; no span (an Entering/Leaving pair here would drown the log).
pub fn dec_utf8(t: Option<&Tlv<'_>>) -> Krb5Result<String> {
    match t {
        Some(t) if t.tag == tag::UTF8_STRING => {
            Ok(String::from_utf8_lossy(t.value).into_owned())
        }
        Some(t) => Err(err(format!(
            "krb5-fast: expected a UTF8String, saw tag 0x{:x}",
            t.tag
        ))),
        None => Err(err(
            "krb5-fast: expected a UTF8String, saw tag 0x??".to_string()
        )),
    }
}

/// The one element inside an explicit `[n]` at the front of some bytes:
/// Node's `explicit()`.
// A hot path: a per-TLV helper, run for every field of every FAST
// message; no span (an Entering/Leaving pair here would drown the log).
pub fn explicit(bytes: &[u8], n: u8) -> Krb5Result<Tlv<'_>> {
    let outer = asn1::read_tlv(bytes, 0, 0)?;
    if outer.tag != asn1::context_tag(n)? {
        return Err(err(format!(
            "krb5-fast: expected [{}], saw tag 0x{:x}",
            n, outer.tag
        )));
    }
    let inner = asn1::read_children(outer.value, 0)?;
    if inner.len() != 1 {
        return Err(err(format!(
            "krb5-fast: [{}] wraps {} elements, expected 1",
            n,
            inner.len()
        )));
    }
    Ok(inner[0])
}

/// A SEQUENCE's explicit fields: Node's `fieldsOf()`.
// A hot path: a per-TLV helper, run for every field of every FAST
// message; no span (an Entering/Leaving pair here would drown the log).
pub fn fields_of<'a>(
    t: Option<&Tlv<'a>>,
    what: &str,
) -> Krb5Result<Fields<'a>> {
    match t {
        Some(t) if t.tag == tag::SEQUENCE => {
            asn1::read_tagged_sequence(t.value, 0)
        }
        _ => Err(err(format!("krb5-fast: {} is not a SEQUENCE", what))),
    }
}

/// Node's `required()`.
// A hot path: a per-TLV helper, run for every field of every FAST
// message; no span (an Entering/Leaving pair here would drown the log).
pub fn required<'f, 'a>(
    f: &'f Fields<'a>,
    n: u8,
    what: &str,
) -> Krb5Result<&'f Tlv<'a>> {
    f.get(n)
        .ok_or_else(|| err(format!("krb5-fast: {} has no field [{}]", what, n)))
}

fn padata_list(t: &Tlv<'_>) -> Krb5Result<Vec<PaData>> {
    asn1::dec_sequence_of(t)?.iter().map(PaData::read).collect()
}

/// Node's `implicit(n, encoded)`: the first octet replaced by `[n]`,
/// constructed if the element was.
// A hot path: a per-TLV helper, run for every field of every FAST
// message; no span (an Entering/Leaving pair here would drown the log).
pub fn implicit(n: u8, encoded: Vec<u8>) -> Vec<u8> {
    let mut out = encoded;
    if let Some(first) = out.first_mut() {
        *first = if *first & 0x20 != 0 {
            0xa0 | n
        } else {
            0x80 | n
        };
    }
    out
}

/// Node's `asUniversal(t, tag)`: an implicit field re-read under its
/// universal tag.
// A hot path: a per-TLV helper, run for every field of every FAST
// message; no span (an Entering/Leaving pair here would drown the log).
pub fn as_universal(t: &Tlv<'_>, universal: u8) -> Vec<u8> {
    let mut raw = t.raw.to_vec();
    raw[0] = universal;
    raw
}

fn reread<T>(
    t: &Tlv<'_>,
    universal: u8,
    f: impl Fn(&Tlv<'_>) -> Krb5Result<T>,
) -> Krb5Result<T> {
    let raw = as_universal(t, universal);
    let back = asn1::read_tlv(&raw, 0, 0)?;
    f(&back)
}

/// An implicitly tagged SEQUENCE's fields, not unwrapped: Node's
/// `implicitFields()`.
#[derive(Debug, Clone, Default)]
pub struct ImplicitFields<'a> {
    map: std::collections::BTreeMap<u8, Tlv<'a>>,
}

impl<'a> ImplicitFields<'a> {
    // A hot path: a per-TLV helper, run for every field of every FAST
    // message; no span (an Entering/Leaving pair here would drown the log).
    pub fn get(&self, n: u8) -> Option<&Tlv<'a>> {
        self.map.get(&n)
    }

    fn required(&self, n: u8, what: &str) -> Krb5Result<&Tlv<'a>> {
        self.get(n).ok_or_else(|| {
            err(format!("krb5-fast: {} has no field [{}]", what, n))
        })
    }
}

// A hot path: a per-TLV helper, run for every field of every FAST
// message; no span (an Entering/Leaving pair here would drown the log).
pub fn implicit_fields<'a>(
    t: &Tlv<'a>,
    what: &str,
) -> Krb5Result<ImplicitFields<'a>> {
    if t.tag != tag::SEQUENCE {
        return Err(err(format!("krb5-fast: {} is not a SEQUENCE", what)));
    }
    let mut map = std::collections::BTreeMap::new();
    for child in asn1::read_children(t.value, 0)? {
        if child.tag & 0xc0 != 0x80 {
            return Err(err(format!(
                "krb5-fast: {} has a field that is not context-tagged",
                what
            )));
        }
        map.insert(child.tag & 0x1f, child);
    }
    Ok(ImplicitFields { map })
}

fn i_octets(n: u8, v: Option<&[u8]>) -> Option<Vec<u8>> {
    v.map(|v| implicit(n, asn1::enc_octet_string(v)))
}

fn i_utf8(n: u8, v: Option<&str>) -> Option<Vec<u8>> {
    v.map(|v| implicit(n, enc_utf8(v)))
}

fn i_int(n: u8, v: Option<i64>) -> Option<Vec<u8>> {
    v.map(|v| implicit(n, asn1::enc_integer(v)))
}

fn implicit_sequence(fields: Vec<Option<Vec<u8>>>) -> Vec<u8> {
    let present: Vec<Vec<u8>> = fields.into_iter().flatten().collect();
    asn1::enc_sequence(&present)
}

/// A string Node writes with `x || null`: omitted when empty.
fn nonempty(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// KrbFastArmor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Armor {
    pub r#type: i64,
    #[serde(serialize_with = "crate::hex::ser")]
    pub value: Vec<u8>,
}

impl Armor {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, Some(asn1::enc_integer(self.r#type))),
            (1, Some(asn1::enc_octet_string(&self.value))),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let f = fields_of(Some(t), "KrbFastArmor")?;
        Ok(Armor {
            r#type: asn1::dec_integer(required(&f, 0, "KrbFastArmor")?)?,
            value: asn1::dec_octet_string(required(&f, 1, "KrbFastArmor")?)?
                .to_vec(),
        })
    }
}

/// PA-FX-FAST-REQUEST's KrbFastArmoredReq.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FastRequest {
    pub armor: Option<Armor>,
    pub req_checksum: Checksum,
    pub enc_fast_req: EncryptedData,
}

impl FastRequest {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_context(
            0,
            &asn1::enc_tagged_sequence(&[
                (0, self.armor.as_ref().map(Armor::encode)),
                (1, Some(self.req_checksum.encode())),
                (2, Some(self.enc_fast_req.encode())),
            ]),
        )
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let inner = explicit(bytes, 0)?;
        let f = fields_of(Some(&inner), "KrbFastArmoredReq")?;
        Ok(FastRequest {
            armor: f.get(0).map(Armor::read).transpose()?,
            req_checksum: Checksum::read(required(
                &f,
                1,
                "KrbFastArmoredReq",
            )?)?,
            enc_fast_req: EncryptedData::read(required(
                &f,
                2,
                "KrbFastArmoredReq",
            )?)?,
        })
    }
}

/// KrbFastReq.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FastReq {
    pub fast_options: Vec<u32>,
    pub padata: Vec<PaData>,
    pub req_body: KdcReqBody,
}

impl FastReq {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        Ok(asn1::enc_tagged_sequence(&[
            (0, Some(asn1::enc_flags(&self.fast_options)?)),
            (1, Some(enc_padata_list(&self.padata))),
            (2, Some(self.req_body.bytes()?)),
        ]))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = fields_of(Some(&t), "KrbFastReq")?;
        Ok(FastReq {
            fast_options: asn1::bits_from_flags(asn1::dec_flags(required(
                &f,
                0,
                "KrbFastReq",
            )?)?),
            padata: padata_list(required(&f, 1, "KrbFastReq")?)?,
            req_body: KdcReqBody::read(required(&f, 2, "KrbFastReq")?)?,
        })
    }
}

/// PA-FX-FAST-REPLY: Node's `encFastReply()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_fast_reply(enc_fast_rep: &EncryptedData) -> Vec<u8> {
    asn1::enc_context(
        0,
        &asn1::enc_tagged_sequence(&[(0, Some(enc_fast_rep.encode()))]),
    )
}

/// Node's `readFastReply()`: the KrbFastArmoredRep's enc-fast-rep.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read_fast_reply(bytes: &[u8]) -> Krb5Result<EncryptedData> {
    let inner = explicit(bytes, 0)?;
    let f = fields_of(Some(&inner), "KrbFastArmoredRep")?;
    EncryptedData::read(required(&f, 0, "KrbFastArmoredRep")?)
}

/// KrbFastFinished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FastFinished {
    pub timestamp: KrbTime,
    pub usec: i64,
    pub crealm: String,
    pub cname: PrincipalName,
    pub ticket_checksum: Checksum,
}

impl FastFinished {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, Some(asn1::enc_kerberos_time(self.timestamp))),
            (1, Some(asn1::enc_integer(self.usec))),
            (2, Some(asn1::enc_general_string(&self.crealm))),
            (3, Some(self.cname.encode())),
            (4, Some(self.ticket_checksum.encode())),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let w = "KrbFastFinished";
        let f = fields_of(Some(t), w)?;
        Ok(FastFinished {
            timestamp: asn1::dec_kerberos_time(required(&f, 0, w)?)?,
            usec: asn1::dec_integer(required(&f, 1, w)?)?,
            crealm: asn1::dec_general_string(required(&f, 2, w)?)?,
            cname: PrincipalName::read(required(&f, 3, w)?)?,
            ticket_checksum: Checksum::read(required(&f, 4, w)?)?,
        })
    }
}

/// KrbFastResponse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FastResponse {
    pub padata: Vec<PaData>,
    pub strengthen_key: Option<EncryptionKey>,
    pub finished: Option<FastFinished>,
    pub nonce: i64,
}

impl FastResponse {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, Some(enc_padata_list(&self.padata))),
            (1, self.strengthen_key.as_ref().map(EncryptionKey::encode)),
            (2, self.finished.as_ref().map(FastFinished::encode)),
            (3, Some(asn1::enc_integer(self.nonce))),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let w = "KrbFastResponse";
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = fields_of(Some(&t), w)?;
        Ok(FastResponse {
            padata: padata_list(required(&f, 0, w)?)?,
            strengthen_key: f.get(1).map(EncryptionKey::read).transpose()?,
            finished: f.get(2).map(FastFinished::read).transpose()?,
            nonce: asn1::dec_integer(required(&f, 3, w)?)?,
        })
    }
}

/// OTP-TOKENINFO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    pub flags: Vec<u32>,
    pub vendor: Option<String>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub challenge: Option<Vec<u8>>,
    pub length: Option<i64>,
    pub format: Option<i64>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub token_id: Option<Vec<u8>>,
    pub alg_id: Option<String>,
    /// Read only: whether the token asked for a hashed OTP.
    pub hashing: bool,
}

impl TokenInfo {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        Ok(implicit_sequence(vec![
            Some(implicit(0, asn1::enc_flags(&self.flags)?)),
            i_utf8(1, nonempty(&self.vendor)),
            i_octets(2, self.challenge.as_deref()),
            i_int(3, self.length),
            i_int(4, self.format),
            i_octets(5, self.token_id.as_deref()),
            i_utf8(6, nonempty(&self.alg_id)),
        ]))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let w = "OTP-TOKENINFO";
        let f = implicit_fields(t, w)?;
        let flags = reread(f.required(0, w)?, tag::BIT_STRING, |b| {
            Ok(asn1::bits_from_flags(asn1::dec_flags(b)?))
        })?;
        Ok(TokenInfo {
            flags,
            vendor: f
                .get(1)
                .map(|v| String::from_utf8_lossy(v.value).into_owned()),
            challenge: f.get(2).map(|v| v.value.to_vec()),
            length: f
                .get(3)
                .map(|v| reread(v, tag::INTEGER, asn1::dec_integer))
                .transpose()?,
            format: f
                .get(4)
                .map(|v| reread(v, tag::INTEGER, asn1::dec_integer))
                .transpose()?,
            token_id: f.get(5).map(|v| v.value.to_vec()),
            alg_id: f
                .get(6)
                .map(|v| String::from_utf8_lossy(v.value).into_owned()),
            hashing: f.get(7).is_some() || f.get(8).is_some(),
        })
    }
}

/// PA-OTP-CHALLENGE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpChallenge {
    #[serde(serialize_with = "crate::hex::ser")]
    pub nonce: Vec<u8>,
    pub service: Option<String>,
    pub token_info: Vec<TokenInfo>,
    pub salt: Option<String>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub s2kparams: Option<Vec<u8>>,
}

impl OtpChallenge {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        let infos = self
            .token_info
            .iter()
            .map(TokenInfo::encode)
            .collect::<Krb5Result<Vec<_>>>()?;
        Ok(implicit_sequence(vec![
            i_octets(0, Some(&self.nonce)),
            i_utf8(1, nonempty(&self.service)),
            Some(implicit(2, asn1::enc_sequence(&infos))),
            nonempty(&self.salt)
                .map(|s| implicit(3, asn1::enc_general_string(s))),
            i_octets(4, self.s2kparams.as_deref()),
        ]))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let w = "PA-OTP-CHALLENGE";
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = implicit_fields(&t, w)?;
        let nonce = f.required(0, w)?;
        let tokens = f.required(2, w)?;
        Ok(OtpChallenge {
            nonce: nonce.value.to_vec(),
            service: f
                .get(1)
                .map(|v| String::from_utf8_lossy(v.value).into_owned()),
            token_info: asn1::read_children(tokens.value, 0)?
                .iter()
                .map(TokenInfo::read)
                .collect::<Krb5Result<_>>()?,
            salt: f.get(3).map(|v| primitives::latin1(v.value)),
            s2kparams: f.get(4).map(|v| v.value.to_vec()),
        })
    }
}

/// PA-OTP-REQUEST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpRequest {
    pub flags: Vec<u32>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub nonce: Option<Vec<u8>>,
    pub enc_data: EncryptedData,
    /// Read only: a hash algorithm or iteration count was sent.
    pub hashing: bool,
    pub value: Option<String>,
    pub pin: Option<String>,
    pub time: Option<KrbTime>,
    pub vendor: Option<String>,
}

impl OtpRequest {
    /// Node's `encOtpRequest()`: the OTP value is written as its UTF-8;
    /// an empty PIN IS written (only an absent one is not).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        Ok(implicit_sequence(vec![
            Some(implicit(0, asn1::enc_flags(&self.flags)?)),
            // `req.nonce || null`: an empty Uint8Array is truthy, so written.
            i_octets(1, self.nonce.as_deref()),
            Some(implicit(2, self.enc_data.encode())),
            i_octets(5, self.value.as_deref().map(str::as_bytes)),
            i_utf8(6, self.pin.as_deref()),
            self.time.map(|t| implicit(8, asn1::enc_kerberos_time(t))),
            i_utf8(13, nonempty(&self.vendor)),
        ]))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let w = "PA-OTP-REQUEST";
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = implicit_fields(&t, w)?;
        let flags = reread(f.required(0, w)?, tag::BIT_STRING, |b| {
            Ok(asn1::bits_from_flags(asn1::dec_flags(b)?))
        })?;
        let enc_data =
            reread(f.required(2, w)?, tag::SEQUENCE, EncryptedData::read)?;
        let hashing = f.get(3).is_some()
            || match f.get(4) {
                Some(v) => reread(v, tag::INTEGER, asn1::dec_integer)? > 0,
                None => false,
            };
        Ok(OtpRequest {
            flags,
            nonce: f.get(1).map(|v| v.value.to_vec()),
            enc_data,
            hashing,
            value: f.get(5).map(|v| primitives::latin1(v.value)),
            pin: f
                .get(6)
                .map(|v| String::from_utf8_lossy(v.value).into_owned()),
            time: f
                .get(8)
                .map(|v| {
                    reread(v, tag::GENERALIZED_TIME, asn1::dec_kerberos_time)
                })
                .transpose()?,
            vendor: f
                .get(13)
                .map(|v| String::from_utf8_lossy(v.value).into_owned()),
        })
    }
}

/// PA-OTP-ENC-REQUEST: Node's `encOtpEncRequest()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_otp_enc_request(nonce: &[u8]) -> Vec<u8> {
    implicit_sequence(vec![i_octets(0, Some(nonce))])
}

/// What a PA-OTP-REQUEST's encData opened to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum OtpEncData {
    Timestamp {
        timestamp: KrbTime,
    },
    Nonce {
        #[serde(serialize_with = "crate::hex::ser")]
        nonce: Vec<u8>,
    },
}

/// Node's `readOtpEncData()`: a PA-ENC-TS-ENC or a PA-OTP-ENC-REQUEST.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read_otp_enc_data(bytes: &[u8]) -> Krb5Result<OtpEncData> {
    let t = asn1::read_tlv(bytes, 0, 0)?;
    if t.tag != tag::SEQUENCE {
        return Err(err(
            "krb5-fast: the PA-OTP-REQUEST encData is not a SEQUENCE"
                .to_string(),
        ));
    }
    let children = asn1::read_children(t.value, 0)?;
    match children.first() {
        Some(first) if first.tag == 0xa0 => Ok(OtpEncData::Timestamp {
            timestamp: crate::messages::PaEncTsEnc::read(bytes)?.patimestamp,
        }),
        Some(first) if first.tag == 0x80 => Ok(OtpEncData::Nonce {
            nonce: first.value.to_vec(),
        }),
        _ => Err(err("krb5-fast: the PA-OTP-REQUEST encData is neither a \
             PA-OTP-ENC-REQUEST nor a PA-ENC-TS-ENC"
            .to_string())),
    }
}

/// Verifier-MAC (RFC 7751).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifierMac {
    pub identifier: Option<PrincipalName>,
    pub kvno: Option<i64>,
    pub enctype: Option<i64>,
    pub mac: Checksum,
}

impl VerifierMac {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, self.identifier.as_ref().map(PrincipalName::encode)),
            (1, self.kvno.map(asn1::enc_integer)),
            (2, self.enctype.map(asn1::enc_integer)),
            (3, Some(self.mac.encode())),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(t: &Tlv<'_>) -> Krb5Result<Self> {
        let w = "Verifier-MAC";
        let f = fields_of(Some(t), w)?;
        Ok(VerifierMac {
            identifier: f.get(0).map(PrincipalName::read).transpose()?,
            kvno: f.get(1).map(asn1::dec_integer).transpose()?,
            enctype: f.get(2).map(asn1::dec_integer).transpose()?,
            mac: Checksum::read(required(&f, 3, w)?)?,
        })
    }
}

/// AD-CAMMAC (RFC 7751).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cammac {
    /// The elements' DER as it arrived — what the verifiers are over.
    #[serde(serialize_with = "crate::hex::ser")]
    pub elements_bytes: Vec<u8>,
    pub elements: Vec<AuthorizationEntry>,
    pub kdc_verifier: Option<VerifierMac>,
    pub svc_verifier: Option<VerifierMac>,
}

impl Cammac {
    /// Node's `encCammac()`: the elements are written from their bytes.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, Some(self.elements_bytes.clone())),
            (1, self.kdc_verifier.as_ref().map(VerifierMac::encode)),
            (2, self.svc_verifier.as_ref().map(VerifierMac::encode)),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let w = "AD-CAMMAC";
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = fields_of(Some(&t), w)?;
        let elements = required(&f, 0, w)?;
        Ok(Cammac {
            elements_bytes: elements.raw.to_vec(),
            elements: read_authorization_data(elements)?,
            kdc_verifier: f.get(1).map(VerifierMac::read).transpose()?,
            svc_verifier: f.get(2).map(VerifierMac::read).transpose()?,
        })
    }
}

/// AD-AUTHENTICATION-INDICATOR (RFC 8129): Node's `encIndicators()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_indicators(list: &[String]) -> Vec<u8> {
    let items: Vec<Vec<u8>> = list.iter().map(|s| enc_utf8(s)).collect();
    asn1::enc_sequence(&items)
}

/// Node's `readIndicators()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read_indicators(bytes: &[u8]) -> Krb5Result<Vec<String>> {
    let t = asn1::read_tlv(bytes, 0, 0)?;
    asn1::dec_sequence_of(&t)?
        .iter()
        .map(|e| dec_utf8(Some(e)))
        .collect()
}
