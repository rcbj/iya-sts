// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The Kerberos GSS-API mechanism's wire pieces (RFC 4121, RFC 2743):
//! `kerberos/krb5_gss.js` — the 0x8003 authenticator checksum, the
//! InitialContextToken framing, and the MIC and Wrap per-message tokens.
//!
//! Two traps the Node file names and this one keeps: the 0x8003 checksum
//! is LITTLE-endian throughout, unlike the rest of Kerberos; and a
//! per-message token's key usage depends on WHO SENT IT (an initiator signs
//! with 25 and seals with 24, an acceptor with 23 and 22), so a verifier
//! reads the sender's role out of the token rather than using its own.

use serde::Serialize;

use crate::asn1;
use crate::crypto::{key_usage, Enctype};
use crate::error::{Krb5Error, Krb5Result};
use crate::primitives;

/// 1.2.840.113554.1.2.2, the Kerberos v5 mechanism.
pub const KRB5_MECH_OID: &str = "1.2.840.113554.1.2.2";
/// The same, DER-encoded, as every comparison uses it.
pub const KRB5_MECH_OID_DER: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];
const SPNEGO_OID_DER: [u8; 8] =
    [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// RFC 4121 section 4.1's token ids, big-endian pairs.
pub const TOK_IDS: [(&str, [u8; 2]); 5] = [
    ("AP_REQ", [0x01, 0x00]),
    ("AP_REP", [0x02, 0x00]),
    ("KRB_ERROR", [0x03, 0x00]),
    ("MIC", [0x04, 0x04]),
    ("WRAP", [0x05, 0x04]),
];
pub const TOK_ID_AP_REQ: [u8; 2] = [0x01, 0x00];
pub const TOK_ID_AP_REP: [u8; 2] = [0x02, 0x00];
pub const TOK_ID_KRB_ERROR: [u8; 2] = [0x03, 0x00];
pub const TOK_ID_MIC: [u8; 2] = [0x04, 0x04];
pub const TOK_ID_WRAP: [u8; 2] = [0x05, 0x04];

/// RFC 4121 section 4.1.1.1's flags, in Node's key order.
pub const GSS_FLAGS: [(&str, u32); 6] = [
    ("DELEG", 1),
    ("MUTUAL", 2),
    ("REPLAY", 4),
    ("SEQUENCE", 8),
    ("CONF", 16),
    ("INTEG", 32),
];
pub const GSS_FLAG_DELEG: u32 = 1;

/// The checksum type of the 0x8003 "checksum".
pub const CHECKSUM_TYPE_GSS: i64 = 0x8003;

/// Who is speaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Initiator,
    Acceptor,
}

impl Role {
    /// Node's role check, with its sentence.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn parse(role: &str) -> Krb5Result<Role> {
        match role {
            "initiator" => Ok(Role::Initiator),
            "acceptor" => Ok(Role::Acceptor),
            other => Err(Krb5Error::new(format!(
                "krb5: the GSS role must be \"initiator\" or \"acceptor\", \
                 got {}",
                crate::time::json_string(other)
            ))),
        }
    }
}

/// What a per-message key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Sign,
    Seal,
}

/// Node's `usageFor()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn usage_for(role: Role, purpose: Purpose) -> u32 {
    match (role, purpose) {
        (Role::Initiator, Purpose::Sign) => key_usage::GSS_INITIATOR_SIGN,
        (Role::Acceptor, Purpose::Sign) => key_usage::GSS_ACCEPTOR_SIGN,
        (Role::Initiator, Purpose::Seal) => key_usage::GSS_INITIATOR_SEAL,
        (Role::Acceptor, Purpose::Seal) => key_usage::GSS_ACCEPTOR_SEAL,
    }
}

/// The flags byte of a per-message header: Node's `messageFlags()`.
fn message_flags(role: Role, sealed: bool, acceptor_subkey: bool) -> u8 {
    (if role == Role::Acceptor { 0x01 } else { 0 })
        | (if sealed { 0x02 } else { 0 })
        | (if acceptor_subkey { 0x04 } else { 0 })
}

/// What goes into a 0x8003 checksum: Node's `buildGssChecksum(options)`.
#[derive(Debug, Clone, Default)]
pub struct GssChecksumOptions {
    pub flags: Vec<u32>,
    /// Sixteen bytes; sixteen zeros when absent.
    pub channel_bindings: Option<Vec<u8>>,
    /// A KRB-CRED; requires GSS_C_DELEG_FLAG.
    pub delegation: Option<Vec<u8>>,
    pub extensions: Option<Vec<u8>>,
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn build_gss_checksum(opts: &GssChecksumOptions) -> Krb5Result<Vec<u8>> {
    let flags = opts.flags.iter().fold(0u32, |a, f| a | f);
    let bindings = opts
        .channel_bindings
        .clone()
        .unwrap_or_else(|| vec![0u8; 16]);
    if bindings.len() != 16 {
        return Err(Krb5Error::new(format!(
            "krb5: GSS channel bindings must be exactly 16 bytes, got {}",
            bindings.len()
        )));
    }
    let mut out = 16u32.to_le_bytes().to_vec();
    out.extend(bindings);
    out.extend(flags.to_le_bytes());
    if let Some(cred) = &opts.delegation {
        if flags & GSS_FLAG_DELEG == 0 {
            return Err(Krb5Error::new(
                "krb5: a delegated credential was supplied but \
                 GSS_C_DELEG_FLAG is not set; a service reads the flag, so \
                 the credential would be ignored",
            ));
        }
        // DlgOpt is 1 for a KRB-CRED, per RFC 4121.
        out.extend(1u16.to_le_bytes());
        out.extend((cred.len() as u16).to_le_bytes());
        out.extend_from_slice(cred);
    }
    if let Some(ext) = &opts.extensions {
        out.extend_from_slice(ext);
    }
    Ok(out)
}

/// A delegated credential in a 0x8003 checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Delegation {
    pub option: u16,
    #[serde(serialize_with = "crate::hex::ser")]
    pub credential: Vec<u8>,
}

/// A parsed 0x8003 checksum: Node's `parseGssChecksum()` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GssChecksum {
    pub bindings_length: u32,
    #[serde(serialize_with = "crate::hex::ser")]
    pub channel_bindings: Vec<u8>,
    pub has_channel_bindings: bool,
    pub flags: u32,
    pub flag_names: Vec<String>,
    pub delegation: Option<Delegation>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::hex::opt"
    )]
    pub extensions: Option<Vec<u8>>,
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn parse_gss_checksum(b: &[u8]) -> Krb5Result<GssChecksum> {
    if b.len() < 24 {
        return Err(Krb5Error::new(format!(
            "krb5: a 0x8003 checksum is at least 24 bytes (4 + 16 + 4), got {}",
            b.len()
        )));
    }
    let declared = le32(b, 0);
    if declared != 16 {
        return Err(Krb5Error::new(format!(
            "krb5: the 0x8003 checksum declares a bindings length of {} \
             rather than 16{}",
            declared,
            if declared == 0x1000_0000 {
                " — 16 written BIG-endian. Every integer in this structure \
                 is little-endian, unlike the rest of Kerberos."
            } else {
                "."
            }
        )));
    }
    let flags = le32(b, 20);
    let mut out = GssChecksum {
        bindings_length: declared,
        channel_bindings: b[4..20].to_vec(),
        has_channel_bindings: b[4..20].iter().any(|v| *v != 0),
        flags,
        flag_names: GSS_FLAGS
            .iter()
            .filter(|(_, v)| flags & v != 0)
            .map(|(n, _)| n.to_string())
            .collect(),
        delegation: None,
        extensions: None,
    };
    let mut at = 24;
    if flags & GSS_FLAG_DELEG != 0 && b.len() >= at + 4 {
        let option = u16::from_le_bytes([b[at], b[at + 1]]);
        let dlgth = usize::from(u16::from_le_bytes([b[at + 2], b[at + 3]]));
        at += 4;
        if b.len() >= at + dlgth {
            out.delegation = Some(Delegation {
                option,
                credential: b[at..at + dlgth].to_vec(),
            });
            at += dlgth;
        }
    }
    if at < b.len() {
        out.extensions = Some(b[at..].to_vec());
    }
    Ok(out)
}

/// RFC 2743 section 3.1's framing: `[APPLICATION 0]` round the mechanism
/// OID and the token id and inner bytes. Node's
/// `encodeInitialContextToken()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn encode_initial_context_token(tok_id: [u8; 2], inner: &[u8]) -> Vec<u8> {
    let mut body = KRB5_MECH_OID_DER.to_vec();
    body.extend_from_slice(&tok_id);
    body.extend_from_slice(inner);
    let mut out = vec![0x60];
    out.extend(asn1::encode_length(body.len()));
    out.extend(body);
    out
}

/// A decoded InitialContextToken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitialContextToken {
    pub tok_id: [u8; 2],
    pub tok_id_name: Option<String>,
    pub mech_oid: String,
    #[serde(serialize_with = "crate::hex::ser")]
    pub inner: Vec<u8>,
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn decode_initial_context_token(
    b: &[u8],
) -> Krb5Result<InitialContextToken> {
    if b.is_empty() || b[0] != 0x60 {
        return Err(Krb5Error::new(format!(
            "krb5: not a GSS InitialContextToken — it must begin with 0x60 \
             ([APPLICATION 0]), this begins with 0x{}{}",
            b.first()
                .map(|x| format!("{:x}", x))
                .unwrap_or_else(|| "nothing".to_string()),
            if b.first() == Some(&0x6e) {
                ". 0x6e is a bare AP-REQ: a Windows service expects it \
                 WRAPPED in this token, not on its own."
            } else {
                "."
            }
        )));
    }
    let outer = asn1::read_tlv(b, 0, 0)?;
    let value = outer.value;
    if value.len() < KRB5_MECH_OID_DER.len() {
        return Err(Krb5Error::new(
            "krb5: the GSS token is too short to carry a mechanism OID",
        ));
    }
    let oid = &value[..KRB5_MECH_OID_DER.len()];
    if !primitives::equal_constant_time(oid, &KRB5_MECH_OID_DER) {
        let is_spnego = value.len() >= SPNEGO_OID_DER.len()
            && primitives::equal_constant_time(
                &value[..SPNEGO_OID_DER.len()],
                &SPNEGO_OID_DER,
            );
        return Err(Krb5Error::new(format!(
            "krb5: this GSS token names {}.",
            if is_spnego {
                "the SPNEGO mechanism (1.3.6.1.5.5.2), which is a \
                 NEGOTIATION around this one rather than this one. Decode \
                 it with krb5_spnego.js and pass its mechToken here"
                    .to_string()
            } else {
                format!(
                    "a mechanism this build does not know ({})",
                    primitives::to_hex(oid)
                )
            }
        )));
    }
    let rest = &value[KRB5_MECH_OID_DER.len()..];
    if rest.len() < 2 {
        return Err(Krb5Error::new("krb5: the GSS token carries no token id"));
    }
    let id = [rest[0], rest[1]];
    Ok(InitialContextToken {
        tok_id: id,
        tok_id_name: TOK_IDS
            .iter()
            .find(|(_, v)| *v == id)
            .map(|(n, _)| n.to_string()),
        mech_oid: KRB5_MECH_OID.to_string(),
        inner: rest[2..].to_vec(),
    })
}

/// What a per-message token is made with.
#[derive(Debug, Clone)]
pub struct TokenOptions<'a> {
    pub key: &'a [u8],
    pub etype: i64,
    pub role: Role,
    pub acceptor_subkey: bool,
    pub message: &'a [u8],
    pub sequence_number: u64,
}

/// GSS_GetMIC: Node's `getMic()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn get_mic(o: &TokenOptions<'_>) -> Krb5Result<Vec<u8>> {
    let profile = Enctype::by_id(o.etype)?;
    let mut header = TOK_ID_MIC.to_vec();
    header.push(message_flags(o.role, false, o.acceptor_subkey));
    header.extend([0xff; 5]);
    header.extend(o.sequence_number.to_be_bytes());
    // The checksum covers the message AND the header.
    let mut input = o.message.to_vec();
    input.extend_from_slice(&header);
    let checksum =
        profile.checksum(o.key, usage_for(o.role, Purpose::Sign), &input)?;
    header.extend(checksum);
    Ok(header)
}

/// What `verifyMic()` found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MicVerdict {
    pub ok: bool,
    pub sender_role: Role,
    pub sequence_number: u64,
    pub sealed: bool,
    pub acceptor_subkey: bool,
}

fn be64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_be_bytes(a)
}

/// Node's `verifyMic()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn verify_mic(
    key: &[u8],
    etype: i64,
    token: &[u8],
    message: &[u8],
) -> Krb5Result<MicVerdict> {
    if token.len() < 16 {
        return Err(Krb5Error::new(format!(
            "krb5: a MIC token is at least 16 bytes, got {}",
            token.len()
        )));
    }
    if token[..2] != TOK_ID_MIC {
        return Err(Krb5Error::new(format!(
            "krb5: this is not a MIC token (its id is 0x{}, expected 0404)",
            primitives::to_hex(&token[..2])
        )));
    }
    let profile = Enctype::by_id(etype)?;
    let header = &token[..16];
    let sender = if header[2] & 1 != 0 {
        Role::Acceptor
    } else {
        Role::Initiator
    };
    let mut input = message.to_vec();
    input.extend_from_slice(header);
    let expected =
        profile.checksum(key, usage_for(sender, Purpose::Sign), &input)?;
    Ok(MicVerdict {
        ok: primitives::equal_constant_time(&token[16..], &expected),
        sender_role: sender,
        sequence_number: be64(&header[8..16]),
        sealed: header[2] & 0x02 != 0,
        acceptor_subkey: header[2] & 0x04 != 0,
    })
}

/// GSS_Wrap with confidentiality: Node's `wrap()`. The header is APPENDED
/// to the plaintext before encryption and the ciphertext rotated right by
/// RRC. Node always draws a fresh confounder; `confounder` lets a parity
/// test rebuild a token Node made.
#[tracing::instrument(level = "debug", skip_all)]
pub fn wrap(
    o: &TokenOptions<'_>,
    extra_count: u16,
    rrc: u16,
    confounder: Option<&[u8]>,
) -> Krb5Result<Vec<u8>> {
    let profile = Enctype::by_id(o.etype)?;
    let mut header = TOK_ID_WRAP.to_vec();
    header.push(message_flags(o.role, true, o.acceptor_subkey));
    header.push(0xff);
    header.extend(extra_count.to_be_bytes());
    header.extend(rrc.to_be_bytes());
    header.extend(o.sequence_number.to_be_bytes());
    let mut plain = o.message.to_vec();
    plain.extend(vec![0u8; usize::from(extra_count)]);
    plain.extend_from_slice(&header);
    let cipher = profile.encrypt(
        o.key,
        usage_for(o.role, Purpose::Seal),
        &plain,
        confounder,
    )?;
    header.extend(rotate_right(&cipher, usize::from(rrc)));
    Ok(header)
}

/// What `unwrap()` found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Unwrapped {
    #[serde(serialize_with = "crate::hex::ser")]
    pub message: Vec<u8>,
    pub sender_role: Role,
    pub sequence_number: u64,
    pub extra_count: u16,
    pub rrc: u16,
    /// The confounder the sender drew (not in Node's answer).
    #[serde(skip)]
    pub confounder: Vec<u8>,
}

/// Node's `unwrap()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn unwrap(key: &[u8], etype: i64, token: &[u8]) -> Krb5Result<Unwrapped> {
    if token.len() < 16 {
        return Err(Krb5Error::new(format!(
            "krb5: a Wrap token is at least 16 bytes, got {}",
            token.len()
        )));
    }
    if token[..2] != TOK_ID_WRAP {
        return Err(Krb5Error::new(format!(
            "krb5: this is not a Wrap token (its id is 0x{}, expected 0504)",
            primitives::to_hex(&token[..2])
        )));
    }
    let header = &token[..16];
    let flags = header[2];
    if flags & 0x02 == 0 {
        return Err(Krb5Error::new(
            "krb5: this Wrap token is not sealed (its flags say integrity \
             only), so there is nothing to decrypt",
        ));
    }
    let ec = u16::from_be_bytes([header[4], header[5]]);
    let rrc = u16::from_be_bytes([header[6], header[7]]);
    let sender = if flags & 1 != 0 {
        Role::Acceptor
    } else {
        Role::Initiator
    };
    let profile = Enctype::by_id(etype)?;
    let unrotated = rotate_left(&token[16..], usize::from(rrc));
    let (confounder, plain) = profile.decrypt_with_confounder(
        key,
        usage_for(sender, Purpose::Seal),
        &unrotated,
    )?;
    if plain.len() < 16 + usize::from(ec) {
        return Err(Krb5Error::new(
            "krb5: the unwrapped plaintext is too short to contain its own \
             header",
        ));
    }
    let trailing = &plain[plain.len() - 16..];
    if trailing[..3] != header[..3] {
        return Err(Krb5Error::new(
            "krb5: the Wrap token's clear header does not match the \
             encrypted copy inside it, so the header was altered in transit",
        ));
    }
    Ok(Unwrapped {
        message: plain[..plain.len() - 16 - usize::from(ec)].to_vec(),
        sender_role: sender,
        sequence_number: be64(&header[8..16]),
        extra_count: ec,
        rrc,
        confounder,
    })
}

/// Node's `rotateRight()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn rotate_right(b: &[u8], count: usize) -> Vec<u8> {
    if b.is_empty() || count == 0 || count % b.len() == 0 {
        return b.to_vec();
    }
    let n = count % b.len();
    let mut out = b[b.len() - n..].to_vec();
    out.extend_from_slice(&b[..b.len() - n]);
    out
}

/// Node's `rotateLeft()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn rotate_left(b: &[u8], count: usize) -> Vec<u8> {
    if b.is_empty() || count == 0 || count % b.len() == 0 {
        return b.to_vec();
    }
    let n = count % b.len();
    let mut out = b[n..].to_vec();
    out.extend_from_slice(&b[..n]);
    out
}
