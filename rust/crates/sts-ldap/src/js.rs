// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The few JavaScript semantics node-ldapjs's bytes depend on.
//!
//! node-ldapjs is JavaScript, and several of the answers existing clients
//! see today come from the language rather than from the library's own
//! logic: `parseInt(s, 16)` reading a leading run of hex digits after
//! optional whitespace and a sign, `String.prototype.trim()`'s set of
//! white space (which is not Rust's), `Buffer.from(s, 'base64')` skipping
//! what is not in the alphabet and stopping at `=`, `Buffer.from(array)`
//! keeping each number's low byte, `JSON.stringify` of a string, a
//! `subarray()` whose negative bounds count from the end, and
//! `String.fromCharCode(byte)` turning a byte into the Latin-1 character
//! of that code point. Each is ported here once, so that the modules that
//! use them read like the Node functions they port.
//!
//! These functions are a hot path — called per byte or per field of every
//! PDU a client sends — and carry no span (rust/DESIGN.md D3, section 4.5:
//! a stated hot-path exemption from `#[tracing::instrument]`).

/// `subarray(start, end)` on a buffer of `len` bytes, with JavaScript's
/// rules: a negative bound counts from the end, both are clamped to the
/// buffer, and an end before the start is an empty range.
pub fn range(len: usize, start: i64, end: i64) -> (usize, usize) {
    let n = len as i64;
    let clamp = |v: i64| -> i64 {
        if v < 0 {
            (n + v).max(0)
        } else {
            v.min(n)
        }
    };
    let s = clamp(start);
    let e = clamp(end);
    if e < s {
        (s as usize, s as usize)
    } else {
        (s as usize, e as usize)
    }
}

/// `buffer.subarray(start, end)`.
pub fn subarray(buf: &[u8], start: i64, end: i64) -> &[u8] {
    let (s, e) = range(buf.len(), start, end);
    &buf[s..e]
}

/// `buffer.toString('utf8')`: invalid sequences become U+FFFD, maximal
/// subpart by maximal subpart, which is what V8 and Rust both do.
pub fn utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `String.fromCharCode(byte)`: the character whose code point is the byte
/// (a Latin-1 character above 0x7f), and NUL for `undefined`, which is what
/// `fromCharCode` makes of a read past the end of a buffer.
pub fn from_char_code(byte: Option<u8>) -> char {
    char::from(byte.unwrap_or(0))
}

/// Whether `c` is white space to `String.prototype.trim()` and to
/// `parseInt`: ECMAScript's WhiteSpace and LineTerminator. Not Rust's
/// `char::is_whitespace`, which also takes U+0085 and leaves out U+FEFF.
pub fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}'
            | '\u{a}'
            | '\u{b}'
            | '\u{c}'
            | '\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `String.prototype.trim()`.
pub fn trim(s: &str) -> &str {
    s.trim_matches(is_js_space)
}

/// `parseInt(s, 16)`: leading white space, an optional sign, an optional
/// `0x`, then as many hex digits as there are. `None` is `NaN`.
pub fn parse_int_hex(s: &str) -> Option<i64> {
    let t = s.trim_start_matches(is_js_space);
    let (neg, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let t = if t.starts_with("0x") || t.starts_with("0X") {
        &t[2..]
    } else {
        t
    };
    let digits: String =
        t.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if digits.is_empty() {
        return None;
    }
    // Two characters at most reach here from the DN and filter escapes;
    // a longer run saturates rather than wrapping.
    let mut v: i64 = 0;
    for c in digits.chars() {
        let d = i64::from(c.to_digit(16).unwrap_or(0));
        v = v.saturating_mul(16).saturating_add(d);
    }
    Some(if neg { -v } else { v })
}

/// What `Buffer.from([n])` keeps of a number: its low byte, and 0 for NaN.
pub fn to_uint8(n: Option<i64>) -> u8 {
    match n {
        Some(v) => (v.rem_euclid(256)) as u8,
        None => 0,
    }
}

/// `n.toString(16)`, which has no padding and keeps a minus sign.
pub fn hex_js(n: i64) -> String {
    if n < 0 {
        format!("-{:x}", n.unsigned_abs())
    } else {
        format!("{n:x}")
    }
}

/// Lowercase hex of bytes, `buffer.toString('hex')`.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `JSON.stringify(s)` for a string: `"` and `\` escaped, the C0 controls
/// as `\b \t \n \f \r` or `\u00XX` (lowercase), everything else as it is.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

const B64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `buffer.toString('base64')`, padded.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n =
            (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(char::from(B64[(n >> 18) as usize & 63]));
        out.push(char::from(B64[(n >> 12) as usize & 63]));
        if chunk.len() > 1 {
            out.push(char::from(B64[(n >> 6) as usize & 63]));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(B64[n as usize & 63]));
        } else {
            out.push('=');
        }
    }
    out
}

/// `Buffer.from(s, 'base64')`: both alphabets, every other character
/// skipped, decoding stopped at the first `=`, and a trailing group of one
/// character dropped — so `"not base64 !"` is the six bytes of
/// `"notbase6"`, as an attribute named `…;binary` with such a value is
/// sent today.
pub fn base64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            _ => continue,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// A string as JavaScript indexes it: UTF-16 code units. The filter
/// string parser and the service's DN helpers count positions this way.
pub fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Code units back to a string (they were cut only at ASCII characters,
/// so no surrogate pair is ever split).
pub fn from_units(u: &[u16]) -> String {
    String::from_utf16_lossy(u)
}

/// `str.indexOf(needle, from)` on code units.
pub fn index_of(hay: &[u16], needle: &[u16], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(from.min(hay.len()));
    }
    if hay.len() < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len())
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

/// `str.split(sep)` on code units, for a one-unit separator.
pub fn split_units(hay: &[u16], sep: u16) -> Vec<Vec<u16>> {
    hay.split(|&u| u == sep).map(<[u16]>::to_vec).collect()
}

/// `str.slice(start, end)` on code units.
pub fn slice_units(u: &[u16], start: i64, end: i64) -> &[u16] {
    let (s, e) = range(u.len(), start, end);
    &u[s..e]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_int_reads_a_prefix() {
        assert_eq!(parse_int_hex("4,"), Some(4));
        assert_eq!(parse_int_hex(" a"), Some(10));
        assert_eq!(parse_int_hex("-1"), Some(-1));
        assert_eq!(parse_int_hex("zz"), None);
        assert_eq!(parse_int_hex("\0\0"), None);
        assert_eq!(parse_int_hex("0x"), None);
    }

    #[test]
    fn base64_is_nodes() {
        assert_eq!(hex(&base64_decode("not base64 !")), "9e8b5b6ac7ba");
        assert_eq!(hex(&base64_decode("QQ==QQ")), "41");
        assert_eq!(hex(&base64_decode("-_8")), "fbff");
        assert_eq!(base64_encode(&[0x30, 0x82, 0xff, 0x00]), "MIL/AA==");
    }

    #[test]
    fn trim_is_javascripts() {
        assert_eq!(trim("\u{feff}x\u{85}"), "x\u{85}");
    }
}
