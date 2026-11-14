// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The wire format of PKINIT (RFC 4556, RFC 8070, RFC 8636, RFC 8062) for
//! the AS exchange: `kerberos/krb5_pkinit_codec.ts`. Structures to DER and
//! back, nothing else: the CMS SignedData inside each, the certificates and
//! the key agreement are `sts-crypto`'s and `sts-pki`'s, and their bytes
//! are handed over untouched, because a signature is checked over the
//! bytes that ARRIVED. What a structure means is `krb5_pkinit.ts`'s
//! (phase 9).
//!
//! The tags: RFC 4556's module is EXPLICIT TAGS except where a field says
//! IMPLICIT (signedAuthPack, kdcPkId, dhSignedData, encKeyPack and the
//! three fields of an ExternalPrincipalIdentifier). PA-PK-AS-REP's
//! `dhInfo [0]` is therefore EXPLICIT round DHRepInfo's SEQUENCE — Node
//! first wrote it implicit and MIT's `kinit` refused the reply — and the
//! reader takes both forms.

use serde::Serialize;

use crate::asn1::{self, tag, Tlv};
use crate::error::{Krb5Error, Krb5Result};
use crate::fast::{fields_of, implicit, implicit_fields, required};
use crate::messages::PrincipalName;
use crate::time::KrbTime;

/// PA-DATA types.
pub mod pa {
    pub const PK_AS_REQ: i64 = 16;
    pub const PK_AS_REP: i64 = 17;
    pub const PKINIT_KX: i64 = 147;
    pub const AS_FRESHNESS: i64 = 150;
}

/// RFC 4556 / RFC 8636 error codes.
pub mod error {
    pub const CLIENT_NOT_TRUSTED: i64 = 62;
    pub const INVALID_SIG: i64 = 64;
    pub const DH_KEY_PARAMETERS_NOT_ACCEPTED: i64 = 65;
    pub const CANT_VERIFY_CERTIFICATE: i64 = 70;
    pub const INVALID_CERTIFICATE: i64 = 71;
    pub const REVOKED_CERTIFICATE: i64 = 72;
    pub const REVOCATION_STATUS_UNKNOWN: i64 = 73;
    pub const CLIENT_NAME_MISMATCH: i64 = 75;
    pub const INCONSISTENT_KEY_PURPOSE: i64 = 77;
    pub const DIGEST_IN_CERT_NOT_ACCEPTED: i64 = 78;
    pub const PA_CHECKSUM_MUST_BE_INCLUDED: i64 = 79;
    pub const DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED: i64 = 80;
    pub const PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED: i64 = 81;
    pub const PREAUTH_EXPIRED: i64 = 90;
    pub const NO_ACCEPTABLE_KDF: i64 = 100;
}

/// TD-* typed-data types.
pub mod td {
    pub const TRUSTED_CERTIFIERS: i64 = 104;
    pub const INVALID_CERTIFICATES: i64 = 105;
    pub const DH_PARAMETERS: i64 = 109;
    pub const CMS_DIGEST_ALGORITHMS: i64 = 111;
    pub const CERT_DIGEST_ALGORITHMS: i64 = 112;
}

/// AD-INITIAL-VERIFIED-CAS.
pub const AD_INITIAL_VERIFIED_CAS: i64 = 9;
/// RFC 8062's key usage for PA-PKINIT-KX.
pub const KEY_USAGE_PA_PKINIT_KX: u32 = 44;

fn err(m: &str) -> Krb5Error {
    Krb5Error::new(m)
}

/// An OBJECT IDENTIFIER, every arc base-128 (the first one included,
/// unlike [`crate::spnego`]'s): Node's `encOid()`, over BigInt there and
/// u128 here.
// A hot path: a per-TLV codec primitive, run for every field of every
// PKINIT structure; no span (an Entering/Leaving pair would drown the log).
pub fn enc_oid(dotted: &str) -> Krb5Result<Vec<u8>> {
    let arcs = dotted
        .split('.')
        .map(|a| {
            a.trim().parse::<u128>().map_err(|_| {
                Krb5Error::new(format!("Cannot convert {} to a BigInt", a))
            })
        })
        .collect::<Krb5Result<Vec<u128>>>()?;
    if arcs.len() < 2 {
        return Err(Krb5Error::new(
            "Cannot mix BigInt and other types, use explicit conversions",
        ));
    }
    let mut out = Vec::new();
    let mut write = |arc: u128| {
        let mut septets = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            septets.insert(0, ((rest & 0x7f) as u8) | 0x80);
            rest >>= 7;
        }
        out.extend(septets);
    };
    write(arcs[0] * 40 + arcs[1]);
    arcs[2..].iter().for_each(|a| write(*a));
    Ok(asn1::tlv(tag::OBJECT_IDENTIFIER, &out))
}

/// Node's `decOid()`.
// A hot path: a per-TLV codec primitive, run for every field of every
// PKINIT structure; no span (an Entering/Leaving pair would drown the log).
pub fn dec_oid(t: Option<&Tlv<'_>>) -> Krb5Result<String> {
    let t = match t {
        Some(t) if t.tag == tag::OBJECT_IDENTIFIER && !t.value.is_empty() => t,
        _ => return Err(err("krb5-pkinit: expected an OBJECT IDENTIFIER")),
    };
    let mut arcs: Vec<u128> = Vec::new();
    let mut value: u128 = 0;
    for b in t.value {
        value = (value << 7) | u128::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    let Some(head) = arcs.first().copied() else {
        return Err(err(
            "Cannot mix BigInt and other types, use explicit conversions",
        ));
    };
    let first = if head < 80 { head / 40 } else { 2 };
    let mut out = vec![first, head - first * 40];
    out.extend_from_slice(&arcs[1..]);
    Ok(out
        .iter()
        .map(u128::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

/// A BIT STRING of whole octets: Node's `encBitString()`.
// A hot path: a per-TLV codec primitive, run for every field of every
// PKINIT structure; no span (an Entering/Leaving pair would drown the log).
pub fn enc_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![0];
    v.extend_from_slice(bytes);
    asn1::tlv(tag::BIT_STRING, &v)
}

/// Node's `decBitString()`.
// A hot path: a per-TLV codec primitive, run for every field of every
// PKINIT structure; no span (an Entering/Leaving pair would drown the log).
pub fn dec_bit_string<'a>(t: Option<&Tlv<'a>>) -> Krb5Result<&'a [u8]> {
    match t {
        Some(t)
            if t.tag == tag::BIT_STRING
                && !t.value.is_empty()
                && t.value[0] == 0 =>
        {
            Ok(&t.value[1..])
        }
        _ => Err(err("krb5-pkinit: expected a BIT STRING of whole octets")),
    }
}

fn implicit_octets<'a>(
    t: Option<&Tlv<'a>>,
    what: &str,
) -> Krb5Result<&'a [u8]> {
    match t {
        Some(t) if t.tag & 0x20 == 0 => Ok(t.value),
        _ => Err(Krb5Error::new(format!(
            "krb5-pkinit: {} is not a primitive OCTET STRING",
            what
        ))),
    }
}

fn i_octets(n: u8, v: Option<&[u8]>) -> Option<Vec<u8>> {
    v.map(|v| implicit(n, asn1::enc_octet_string(v)))
}

fn implicit_sequence(fields: Vec<Option<Vec<u8>>>) -> Vec<u8> {
    let present: Vec<Vec<u8>> = fields.into_iter().flatten().collect();
    asn1::enc_sequence(&present)
}

/// KRB5PrincipalName, the id-pkinit-san otherName.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Krb5PrincipalName {
    pub realm: String,
    pub name: PrincipalName,
}

impl Krb5PrincipalName {
    /// Node's `encKrb5PrincipalName(realm, name)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, Some(asn1::enc_general_string(&self.realm))),
            (1, Some(self.name.encode())),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let w = "KRB5PrincipalName";
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = fields_of(Some(&t), w)?;
        Ok(Krb5PrincipalName {
            realm: asn1::dec_general_string(required(&f, 0, w)?)?,
            name: PrincipalName::read(required(&f, 1, w)?)?,
        })
    }
}

/// PA-PK-AS-REQ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaPkAsReq {
    #[serde(serialize_with = "crate::hex::ser")]
    pub signed_auth_pack: Vec<u8>,
    /// The `[1]` field's bytes as they arrived; never written.
    #[serde(serialize_with = "crate::hex::opt")]
    pub trusted_certifiers: Option<Vec<u8>>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub kdc_pk_id: Option<Vec<u8>>,
}

impl PaPkAsReq {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        implicit_sequence(vec![
            i_octets(0, Some(&self.signed_auth_pack)),
            i_octets(2, self.kdc_pk_id.as_deref()),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = implicit_fields(&t, "PA-PK-AS-REQ")?;
        if f.get(0).is_none() {
            return Err(err("krb5-pkinit: PA-PK-AS-REQ has no signedAuthPack"));
        }
        Ok(PaPkAsReq {
            signed_auth_pack: implicit_octets(f.get(0), "signedAuthPack")?
                .to_vec(),
            trusted_certifiers: f.get(1).map(|t| t.raw.to_vec()),
            kdc_pk_id: f
                .get(2)
                .map(|t| {
                    implicit_octets(Some(t), "kdcPkId").map(<[u8]>::to_vec)
                })
                .transpose()?,
        })
    }
}

/// AuthPack, with its PKAuthenticator flattened in, as Node returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPack {
    pub cusec: i64,
    pub ctime: KrbTime,
    pub nonce: i64,
    #[serde(serialize_with = "crate::hex::opt")]
    pub pa_checksum: Option<Vec<u8>>,
    #[serde(serialize_with = "crate::hex::opt")]
    pub freshness_token: Option<Vec<u8>>,
    /// SubjectPublicKeyInfo DER, as it arrived.
    #[serde(serialize_with = "crate::hex::opt")]
    pub client_public_value: Option<Vec<u8>>,
    /// Read only: how many supportedCMSTypes were listed.
    pub supported_cms_types: usize,
    #[serde(serialize_with = "crate::hex::opt")]
    pub client_dh_nonce: Option<Vec<u8>>,
    pub supported_kdfs: Option<Vec<String>>,
}

impl AuthPack {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        let authenticator = asn1::enc_tagged_sequence(&[
            (0, Some(asn1::enc_integer(self.cusec))),
            (1, Some(asn1::enc_kerberos_time(self.ctime))),
            (2, Some(asn1::enc_integer(self.nonce))),
            (3, self.pa_checksum.as_deref().map(asn1::enc_octet_string)),
            (
                4,
                self.freshness_token.as_deref().map(asn1::enc_octet_string),
            ),
        ]);
        let kdfs = self
            .supported_kdfs
            .as_ref()
            .map(|l| {
                l.iter()
                    .map(|o| enc_kdf_algorithm_id(o))
                    .collect::<Krb5Result<Vec<_>>>()
                    .map(|items| asn1::enc_sequence(&items))
            })
            .transpose()?;
        Ok(asn1::enc_tagged_sequence(&[
            (0, Some(authenticator)),
            (1, self.client_public_value.clone()),
            (
                3,
                self.client_dh_nonce.as_deref().map(asn1::enc_octet_string),
            ),
            (4, kdfs),
        ]))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = fields_of(Some(&t), "AuthPack")?;
        let w = "PKAuthenticator";
        let a = fields_of(Some(required(&f, 0, "AuthPack")?), w)?;
        let oct = |t: Option<&Tlv<'_>>| -> Krb5Result<Option<Vec<u8>>> {
            t.map(|t| asn1::dec_octet_string(t).map(<[u8]>::to_vec))
                .transpose()
        };
        Ok(AuthPack {
            cusec: asn1::dec_integer(required(&a, 0, w)?)?,
            ctime: asn1::dec_kerberos_time(required(&a, 1, w)?)?,
            nonce: asn1::dec_integer(required(&a, 2, w)?)?,
            pa_checksum: oct(a.get(3))?,
            freshness_token: oct(a.get(4))?,
            client_public_value: f.get(1).map(|t| t.raw.to_vec()),
            supported_cms_types: match f.get(2) {
                Some(t) => asn1::dec_sequence_of(t)?.len(),
                None => 0,
            },
            client_dh_nonce: oct(f.get(3))?,
            supported_kdfs: f
                .get(4)
                .map(|t| {
                    asn1::dec_sequence_of(t)?
                        .iter()
                        .map(read_kdf_algorithm_id)
                        .collect::<Krb5Result<Vec<_>>>()
                })
                .transpose()?,
        })
    }
}

/// KDFAlgorithmId: Node's `encKdfAlgorithmId()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_kdf_algorithm_id(oid: &str) -> Krb5Result<Vec<u8>> {
    Ok(asn1::enc_tagged_sequence(&[(0, Some(enc_oid(oid)?))]))
}

/// Node's `readKdfAlgorithmId()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read_kdf_algorithm_id(t: &Tlv<'_>) -> Krb5Result<String> {
    let f = fields_of(Some(t), "KDFAlgorithmId")?;
    dec_oid(Some(required(&f, 0, "KDFAlgorithmId")?))
}

/// KDCDHKeyInfo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdcDhKeyInfo {
    #[serde(serialize_with = "crate::hex::ser")]
    pub subject_public_key: Vec<u8>,
    pub nonce: i64,
}

impl KdcDhKeyInfo {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        asn1::enc_tagged_sequence(&[
            (0, Some(enc_bit_string(&self.subject_public_key))),
            (1, Some(asn1::enc_integer(self.nonce))),
        ])
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let w = "KDCDHKeyInfo";
        let t = asn1::read_tlv(bytes, 0, 0)?;
        let f = fields_of(Some(&t), w)?;
        Ok(KdcDhKeyInfo {
            subject_public_key: dec_bit_string(Some(required(&f, 0, w)?))?
                .to_vec(),
            nonce: asn1::dec_integer(required(&f, 1, w)?)?,
        })
    }
}

/// PA-PK-AS-REP's dhInfo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaPkAsRep {
    #[serde(serialize_with = "crate::hex::ser")]
    pub dh_signed_data: Vec<u8>,
    pub kdf: Option<String>,
}

impl PaPkAsRep {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Krb5Result<Vec<u8>> {
        let mut fields = vec![i_octets(0, Some(&self.dh_signed_data))];
        if let Some(kdf) = self.kdf.as_deref().filter(|k| !k.is_empty()) {
            fields
                .push(Some(asn1::enc_context(2, &enc_kdf_algorithm_id(kdf)?)));
        }
        Ok(asn1::enc_context(0, &implicit_sequence(fields)))
    }

    /// Node's `readPaPkAsRep()`: the DHRepInfo SEQUENCE inside `[0]`, or
    /// its fields directly (the implicit form).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn read(bytes: &[u8]) -> Krb5Result<Self> {
        let outer = asn1::read_tlv(bytes, 0, 0)?;
        if outer.tag != 0xa0 {
            return Err(err("krb5-pkinit: PA-PK-AS-REP is not dhInfo"));
        }
        let kids = asn1::read_children(outer.value, 0)?;
        let inner = if kids.len() == 1 && kids[0].tag == tag::SEQUENCE {
            asn1::read_children(kids[0].value, 0)?
        } else {
            kids
        };
        let mut by_tag = std::collections::BTreeMap::new();
        for one in inner {
            by_tag.insert(one.tag & 0x1f, one);
        }
        let Some(signed) = by_tag.get(&0) else {
            return Err(err("krb5-pkinit: DHRepInfo has no dhSignedData"));
        };
        Ok(PaPkAsRep {
            dh_signed_data: signed.value.to_vec(),
            kdf: match by_tag.get(&2) {
                Some(k) => {
                    let first = asn1::read_children(k.value, 0)?;
                    match first.first() {
                        Some(t) => Some(read_kdf_algorithm_id(t)?),
                        None => {
                            return Err(err(
                                "krb5-fast: KDFAlgorithmId is not a SEQUENCE",
                            ))
                        }
                    }
                }
                None => None,
            },
        })
    }
}

/// RFC 8636 section 6.3's OtherInfo, the KDF's input: Node's
/// `encOtherInfo()`.
pub struct OtherInfo<'a> {
    pub kdf: &'a str,
    pub client: &'a [u8],
    pub server: &'a [u8],
    pub etype: i64,
    pub as_req: &'a [u8],
    pub pk_as_rep: &'a [u8],
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_other_info(o: &OtherInfo<'_>) -> Krb5Result<Vec<u8>> {
    let supp = asn1::enc_tagged_sequence(&[
        (0, Some(asn1::enc_integer(o.etype))),
        (1, Some(asn1::enc_octet_string(o.as_req))),
        (2, Some(asn1::enc_octet_string(o.pk_as_rep))),
    ]);
    Ok(asn1::enc_sequence(&[
        asn1::enc_sequence(&[enc_oid(o.kdf)?]),
        asn1::enc_context(0, &asn1::enc_octet_string(o.client)),
        asn1::enc_context(1, &asn1::enc_octet_string(o.server)),
        asn1::enc_context(2, &asn1::enc_octet_string(&supp)),
    ]))
}

/// One TYPED-DATA entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypedData {
    pub r#type: i64,
    #[serde(serialize_with = "crate::hex::opt")]
    pub value: Option<Vec<u8>>,
}

/// Node's `encTypedData()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn enc_typed_data(list: &[TypedData]) -> Vec<u8> {
    let items: Vec<Vec<u8>> = list
        .iter()
        .map(|one| {
            asn1::enc_tagged_sequence(&[
                (0, Some(asn1::enc_integer(one.r#type))),
                (1, one.value.as_deref().map(asn1::enc_octet_string)),
            ])
        })
        .collect();
    asn1::enc_sequence(&items)
}

/// Node's `readTypedData()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read_typed_data(bytes: &[u8]) -> Krb5Result<Vec<TypedData>> {
    let t = asn1::read_tlv(bytes, 0, 0)?;
    asn1::dec_sequence_of(&t)?
        .iter()
        .map(|e| {
            let f = fields_of(Some(e), "TYPED-DATA")?;
            Ok(TypedData {
                r#type: asn1::dec_integer(required(&f, 0, "TYPED-DATA")?)?,
                value: f
                    .get(1)
                    .map(|v| asn1::dec_octet_string(v).map(<[u8]>::to_vec))
                    .transpose()?,
            })
        })
        .collect()
}

/// A SEQUENCE OF already-encoded elements: Node's `encSequenceOfRaw()`.
// A hot path: a per-TLV codec primitive, run for every field of every
// PKINIT structure; no span (an Entering/Leaving pair would drown the log).
pub fn enc_sequence_of_raw(elements: &[Vec<u8>]) -> Vec<u8> {
    asn1::enc_sequence(elements)
}

/// ExternalPrincipalIdentifier, its three fields IMPLICIT.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalPrincipalIdentifier {
    pub subject_name: Option<Vec<u8>>,
    pub issuer_and_serial_number: Option<Vec<u8>>,
    pub subject_key_identifier: Option<Vec<u8>>,
}

impl ExternalPrincipalIdentifier {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encode(&self) -> Vec<u8> {
        implicit_sequence(vec![
            i_octets(0, self.subject_name.as_deref()),
            i_octets(1, self.issuer_and_serial_number.as_deref()),
            i_octets(2, self.subject_key_identifier.as_deref()),
        ])
    }
}

/// AD-INITIAL-VERIFIED-CAS: Node's `initialVerifiedCas()`, as the
/// authorization-data entry it becomes.
#[tracing::instrument(level = "debug", skip_all)]
pub fn initial_verified_cas(
    epis: &[ExternalPrincipalIdentifier],
) -> crate::messages::AuthorizationEntry {
    let items: Vec<Vec<u8>> = epis
        .iter()
        .map(ExternalPrincipalIdentifier::encode)
        .collect();
    crate::messages::AuthorizationEntry {
        r#type: AD_INITIAL_VERIFIED_CAS,
        data: asn1::enc_sequence(&items),
    }
}
