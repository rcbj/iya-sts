// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The CBOR decoder `authn/webauthn.js` reads attestation objects, COSE
//! keys and extension outputs with (`cborRead()`): exactly what WebAuthn's
//! CTAP2 canonical CBOR needs — unsigned and negative integers inside the
//! exactly-representable range, byte and text strings, arrays, maps (a
//! repeated key refused), `true`, `false` and `null` — and nothing else, no
//! indefinite lengths, no tags, no floats, nesting at most 24 deep. Each
//! refusal is Node's sentence, because a ceremony that throws is answered
//! with it.

use serde_json::{json, Map, Value as Json};

/// The deepest nesting decoded.
pub const MAX_DEPTH: usize = 24;

/// A decoded item.
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    /// Major types 0 and 1, as the double Node holds.
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    /// Insertion order kept, as a JavaScript `Map` keeps it.
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    /// `map.get(key)` for an integer key.
    /// A hot path (every COSE member), so it carries no span.
    pub fn get_int(&self, key: i64) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries
                .iter()
                .find(|(k, _)| *k == Cbor::Int(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// `map.get(key)` for a text key.
    /// A hot path, so it carries no span.
    pub fn get_text(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// The bytes of a byte string.
    /// A hot path, so it carries no span.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The value of an integer.
    /// A hot path, so it carries no span.
    pub fn int(&self) -> Option<i64> {
        match self {
            Cbor::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// How `String(value)` prints it in a sentence.
    /// A hot path, so it carries no span.
    pub fn text_of(&self) -> String {
        match self {
            Cbor::Int(n) => n.to_string(),
            Cbor::Text(t) => t.clone(),
            Cbor::Bool(b) => b.to_string(),
            Cbor::Null => "null".to_string(),
            Cbor::Bytes(b) => String::from_utf8_lossy(b).to_string(),
            Cbor::Array(_) | Cbor::Map(_) => "[object Object]".to_string(),
        }
    }

    /// `plainOf()`: a map whose keys are all text becomes an object; any
    /// other map stays a map. As JSON, a byte string is what a Node
    /// `Buffer` serialises to (`{ type: 'Buffer', data }`), and a map with
    /// other keys a `{}` (what `JSON.stringify` makes of a `Map`).
    /// A hot path, so it carries no span.
    pub fn plain(&self) -> Json {
        match self {
            Cbor::Int(n) => json!(n),
            Cbor::Text(t) => json!(t),
            Cbor::Bool(b) => json!(b),
            Cbor::Null => Json::Null,
            Cbor::Bytes(b) => buffer_json(b),
            Cbor::Array(items) => {
                Json::Array(items.iter().map(Cbor::plain).collect())
            }
            Cbor::Map(entries) => {
                if !entries.iter().all(|(k, _)| matches!(k, Cbor::Text(_))) {
                    return json!({});
                }
                let mut out = Map::new();
                for (k, v) in entries {
                    if let Cbor::Text(t) = k {
                        out.insert(t.clone(), v.plain());
                    }
                }
                Json::Object(out)
            }
        }
    }
}

/// A `Buffer` as `JSON.stringify` writes it.
/// A hot path, so it carries no span.
pub fn buffer_json(bytes: &[u8]) -> Json {
    json!({ "type": "Buffer", "data": bytes })
}

fn read_u(buf: &[u8], at: usize, n: usize) -> Result<u64, String> {
    // Node's readUIntBE throws a RangeError past the end.
    if at + n > buf.len() {
        return Err(format!(
            "The value of \"offset\" is out of range. It must be >= 0 and <= \
             {}. Received {}",
            buf.len().saturating_sub(n),
            at
        ));
    }
    let mut v = 0u64;
    for b in &buf[at..at + n] {
        v = (v << 8) | u64::from(*b);
    }
    Ok(v)
}

/// `cborDecodeFirst(buf, offset)`: the first item and the offset past it.
#[tracing::instrument(level = "debug", skip(buf))]
pub fn decode_first(
    buf: &[u8],
    offset: usize,
) -> Result<(Cbor, usize), String> {
    read(buf, offset, 0)
}

fn read(
    buf: &[u8],
    offset: usize,
    depth: usize,
) -> Result<(Cbor, usize), String> {
    if depth > MAX_DEPTH {
        return Err(format!("CBOR nested deeper than {MAX_DEPTH} levels"));
    }
    if offset >= buf.len() {
        return Err(format!("CBOR ran off the end of the buffer at {offset}"));
    }
    let initial = buf[offset];
    let major = initial >> 5;
    let info = initial & 0x1f;
    let mut cursor = offset + 1;
    let value: u64 = match info {
        0..=23 => u64::from(info),
        24 => {
            let v = read_u(buf, cursor, 1)?;
            cursor += 1;
            v
        }
        25 => {
            let v = read_u(buf, cursor, 2)?;
            cursor += 2;
            v
        }
        26 => {
            let v = read_u(buf, cursor, 4)?;
            cursor += 4;
            v
        }
        27 => {
            let hi = read_u(buf, cursor, 4)?;
            let lo = read_u(buf, cursor + 4, 4)?;
            cursor += 8;
            let v = (hi << 32) | lo;
            if v > (1u64 << 53) - 1 {
                return Err(
                    "CBOR argument exceeds the exactly-representable range"
                        .to_string(),
                );
            }
            v
        }
        _ => {
            return Err(format!(
                "CBOR additional information {info} is reserved or \
                 indefinite; CTAP2 canonical CBOR uses neither"
            ))
        }
    };
    match major {
        0 => Ok((Cbor::Int(value as i64), cursor)),
        1 => Ok((Cbor::Int(-1 - value as i64), cursor)),
        2 => {
            let end = cursor as u64 + value;
            if end > buf.len() as u64 {
                return Err(format!(
                    "a CBOR byte string claims {value} bytes, past the end of \
                     the input"
                ));
            }
            let end = end as usize;
            Ok((Cbor::Bytes(buf[cursor..end].to_vec()), end))
        }
        3 => {
            let end = cursor as u64 + value;
            if end > buf.len() as u64 {
                return Err(format!(
                    "a CBOR text string claims {value} bytes, past the end of \
                     the input"
                ));
            }
            let end = end as usize;
            Ok((
                Cbor::Text(
                    String::from_utf8_lossy(&buf[cursor..end]).to_string(),
                ),
                end,
            ))
        }
        4 => {
            let mut items = Vec::new();
            for _ in 0..value {
                let (item, next) = read(buf, cursor, depth + 1)?;
                items.push(item);
                cursor = next;
            }
            Ok((Cbor::Array(items), cursor))
        }
        5 => {
            let mut entries: Vec<(Cbor, Cbor)> = Vec::new();
            for _ in 0..value {
                let (k, after_key) = read(buf, cursor, depth + 1)?;
                let (v, after_value) = read(buf, after_key, depth + 1)?;
                // SameValueZero: only a primitive key can repeat; two byte
                // strings, arrays or maps are two objects to a Map.
                let primitive = matches!(
                    k,
                    Cbor::Int(_) | Cbor::Text(_) | Cbor::Bool(_) | Cbor::Null
                );
                if primitive && entries.iter().any(|(x, _)| *x == k) {
                    return Err(format!(
                        "a CBOR map repeats the key {}",
                        json_of_key(&k)
                    ));
                }
                entries.push((k, v));
                cursor = after_value;
            }
            Ok((Cbor::Map(entries), cursor))
        }
        7 => match info {
            20 => Ok((Cbor::Bool(false), cursor)),
            21 => Ok((Cbor::Bool(true), cursor)),
            22 => Ok((Cbor::Null, cursor)),
            _ => Err(format!("CBOR simple value {info} is not decoded here")),
        },
        _ => Err(format!("CBOR major type {major} is not decoded here")),
    }
}

fn json_of_key(k: &Cbor) -> String {
    match k {
        Cbor::Int(n) => n.to_string(),
        Cbor::Text(t) => Json::String(t.clone()).to_string(),
        Cbor::Bool(b) => b.to_string(),
        _ => "null".to_string(),
    }
}
