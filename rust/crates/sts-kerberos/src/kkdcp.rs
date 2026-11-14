// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The two framings a Kerberos message travels in besides UDP: RFC 4120
//! section 7.2.2's TCP length prefix, and MS-KKDCP's KDC-PROXY-MESSAGE,
//! which is that same framed message wrapped in a small DER envelope and
//! POSTed over HTTPS.
//!
//! In Node both are inline in `krb5_kdc.js` (`/KdcProxy` and the TCP
//! listener) and `krb5_home.ts` (`messageOf()`, the cell router's reading
//! of the same body). They are pure functions of their bytes, so they are
//! the codec's here and the KDC's handler (phase 9) calls them.
//!
//! ```text
//! KDC-PROXY-MESSAGE ::= SEQUENCE {
//!     kerb-message    [0] OCTET STRING,   -- 4-byte length, then the message
//!     target-domain   [1] KERB-REALM OPTIONAL,
//!     dclocator-hint  [2] INTEGER OPTIONAL }
//! ```
//!
//! The two optional fields are ignored, as in Node. A declared length
//! longer than what follows is not refused: the message is what there is
//! (`subarray(4, 4 + declared)`), and the KDC's reader refuses it if it is
//! short.

use sts_core::errors::{codes, ErrorCode};

use crate::asn1;
use crate::error::Krb5Error;

/// Why `/KdcProxy` refuses a body (HTTP 400), with the code it marks and
/// the `text/plain` sentence it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyRefusal {
    /// No body at all.
    Empty,
    /// The envelope does not decode; Node's message.
    Undecodable(Krb5Error),
    /// A kerb-message shorter than its own length prefix.
    TooShort,
}

impl ProxyRefusal {
    /// The code `krb5_kdc.js` marks on the response.
    pub fn code(&self) -> ErrorCode {
        match self {
            ProxyRefusal::Empty => codes::STS_KRB_0055,
            ProxyRefusal::Undecodable(_) => codes::STS_KRB_0056,
            ProxyRefusal::TooShort => codes::STS_KRB_0057,
        }
    }

    /// The 400's body.
    pub fn body(&self) -> String {
        match self {
            ProxyRefusal::Empty => {
                "a KDC-PROXY-MESSAGE is required".to_string()
            }
            ProxyRefusal::Undecodable(e) => format!(
                "the KDC-PROXY-MESSAGE does not decode: {}",
                e.message()
            ),
            ProxyRefusal::TooShort => {
                "the kerb-message is too short to be framed".to_string()
            }
        }
    }
}

/// The Kerberos message inside a KDC-PROXY-MESSAGE: `krb5_kdc.js`'s
/// `/KdcProxy` reading, refusal for refusal.
#[tracing::instrument(level = "debug", skip_all)]
pub fn unwrap_proxy_message(body: &[u8]) -> Result<Vec<u8>, ProxyRefusal> {
    if body.is_empty() {
        return Err(ProxyRefusal::Empty);
    }
    let framed = (|| {
        let outer = asn1::read_tlv(body, 0, 0)?;
        let fields = asn1::read_tagged_sequence(outer.value, 0)?;
        Ok(asn1::dec_octet_string(fields.tag_of(0)?)?.to_vec())
    })()
    .map_err(ProxyRefusal::Undecodable)?;
    if framed.len() < 4 {
        return Err(ProxyRefusal::TooShort);
    }
    let declared =
        u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]])
            as usize;
    let end = framed.len().min(4usize.saturating_add(declared));
    Ok(framed[4..end].to_vec())
}

/// `krb5_home.ts`'s `Krb5Home.messageOf()`: the same reading, `None` for
/// anything that is not one.
pub fn message_of(body: &[u8]) -> Option<Vec<u8>> {
    unwrap_proxy_message(body).ok()
}

/// A reply as `/KdcProxy` answers it: framed, then enveloped.
#[tracing::instrument(level = "debug", skip_all)]
pub fn wrap_proxy_message(reply: &[u8]) -> Vec<u8> {
    asn1::enc_sequence(&[asn1::enc_context(
        0,
        &asn1::enc_octet_string(&tcp_frame(reply)),
    )])
}

/// A KDC-PROXY-MESSAGE a CLIENT sends: the request framed and enveloped,
/// with the optional target realm.
pub fn client_proxy_message(
    request: &[u8],
    target_domain: Option<&str>,
) -> Vec<u8> {
    asn1::enc_tagged_sequence(&[
        (0, Some(asn1::enc_octet_string(&tcp_frame(request)))),
        (1, target_domain.map(asn1::enc_general_string)),
    ])
}

/// RFC 4120 section 7.2.2's four-byte big-endian length prefix.
pub fn tcp_frame(message: &[u8]) -> Vec<u8> {
    let mut out = (message.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(message);
    out
}

/// What a TCP stream's buffer holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpFrame {
    /// Not yet a whole message; read more.
    Incomplete,
    /// The reserved top bit of the length is set: the KDC closes the
    /// connection (`STS-KRB-0050`).
    ReservedBit,
    /// One message, and the bytes after it.
    Message { message: Vec<u8>, rest: Vec<u8> },
}

impl TcpFrame {
    /// The code a refusal is recorded under.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            TcpFrame::ReservedBit => Some(codes::STS_KRB_0050),
            _ => None,
        }
    }
}

/// The TCP listener's reading of its buffer, as `krb5_kdc.js` does it on
/// each chunk (the size cap, a setting, is the listener's).
pub fn tcp_unframe(buffer: &[u8]) -> TcpFrame {
    if buffer.len() < 4 {
        return TcpFrame::Incomplete;
    }
    let declared =
        u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    if declared & 0x8000_0000 != 0 {
        return TcpFrame::ReservedBit;
    }
    let end = 4 + declared as usize;
    if buffer.len() < end {
        return TcpFrame::Incomplete;
    }
    TcpFrame::Message {
        message: buffer[4..end].to_vec(),
        rest: buffer[end..].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_round_trip_and_refusals() {
        let msg = vec![0x6a, 0x03, 0x30, 0x01, 0x00];
        let wrapped = wrap_proxy_message(&msg);
        assert_eq!(unwrap_proxy_message(&wrapped).unwrap(), msg);
        assert_eq!(
            unwrap_proxy_message(&client_proxy_message(&msg, Some("X")))
                .unwrap(),
            msg
        );
        assert_eq!(unwrap_proxy_message(&[]), Err(ProxyRefusal::Empty));
        let short = asn1::enc_sequence(&[asn1::enc_context(
            0,
            &asn1::enc_octet_string(&[0, 0]),
        )]);
        assert_eq!(unwrap_proxy_message(&short), Err(ProxyRefusal::TooShort));
        let none = asn1::enc_sequence(&[]);
        assert_eq!(
            unwrap_proxy_message(&none).unwrap_err().body(),
            "the KDC-PROXY-MESSAGE does not decode: Cannot read properties \
             of undefined (reading 'tag')"
        );
        assert_eq!(tcp_unframe(&[0x80, 0, 0, 0]), TcpFrame::ReservedBit);
        assert_eq!(tcp_unframe(&[0, 0, 0, 2, 1]), TcpFrame::Incomplete);
    }
}
