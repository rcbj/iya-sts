// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The MIT keytab file format, version 0x502 — a writer and a reader:
//! `kerberos/krb5_keytab.ts`. A keytab is how a real Kerberos service
//! holds its long-term key; the console and `/admin-api` hand one over,
//! once, when a service principal's random key is minted or rotated.
//!
//! ```text
//! uint16  0x0502
//! then, repeated to end of file:
//!   int32   size of the entry (NEGATIVE: a hole, |size| bytes skipped)
//!   uint16  number of name components
//!   data    realm              (uint16 length, then the bytes)
//!   data    component * count
//!   uint32  name type
//!   uint32  timestamp
//!   uint8   kvno, modulo 256
//!   uint16  enctype
//!   data    key
//!   uint32  kvno               (optional; when present it wins)
//! ```
//!
//! Everything is big-endian. Names are read with Node's
//! `Buffer.toString('utf8')`, which substitutes U+FFFD rather than
//! refusing, and so does this reader.

use serde::Serialize;

use crate::error::{Krb5Error, Krb5Result};

/// The only version written or read.
pub const KEYTAB_VERSION: u16 = 0x0502;
/// KRB5_NT_PRINCIPAL, what `ktadd` writes.
pub const NAME_TYPE_PRINCIPAL: u32 = 1;
const MAX_DATA: usize = 0xffff;

/// One entry to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeytabEntry {
    pub realm: String,
    pub components: Vec<String>,
    /// KRB5_NT_PRINCIPAL when absent.
    pub name_type: Option<u32>,
    /// Seconds since the epoch, written modulo 2^32. Absent — or ZERO,
    /// which Node's `entry.timestamp || Date.now() / 1000` treats the same
    /// way — is the time of writing.
    pub timestamp: Option<i64>,
    pub kvno: u32,
    /// Written modulo 2^16, as Node's `& 0xffff` does.
    pub etype: i64,
    pub key: Vec<u8>,
}

/// One entry read: Node's `readKeytab()` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadEntry {
    pub realm: String,
    pub components: Vec<String>,
    pub name_type: u32,
    pub timestamp: u32,
    pub kvno: u32,
    pub etype: u16,
    #[serde(serialize_with = "crate::hex::ser")]
    pub key: Vec<u8>,
}

fn counted(out: &mut Vec<u8>, bytes: &[u8]) -> Krb5Result<()> {
    if bytes.len() > MAX_DATA {
        return Err(Krb5Error::new(format!(
            "krb5_keytab: a field of {} bytes does not fit a keytab's 16-bit \
             length",
            bytes.len()
        )));
    }
    out.extend((bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Node's `writeKeytab()`: the eight-bit kvno AND the 32-bit one, always.
#[tracing::instrument(level = "debug", skip_all)]
pub fn write_keytab(entries: &[KeytabEntry]) -> Krb5Result<Vec<u8>> {
    let mut out = KEYTAB_VERSION.to_be_bytes().to_vec();
    for (index, entry) in entries.iter().enumerate() {
        if entry.components.is_empty()
            || entry.components.iter().any(String::is_empty)
        {
            return Err(Krb5Error::new(format!(
                "krb5_keytab: entry {} names no principal",
                index
            )));
        }
        if entry.key.is_empty() {
            return Err(Krb5Error::new(format!(
                "krb5_keytab: entry {} carries no key",
                index
            )));
        }
        let mut body = (entry.components.len() as u16).to_be_bytes().to_vec();
        counted(&mut body, entry.realm.as_bytes())?;
        for c in &entry.components {
            counted(&mut body, c.as_bytes())?;
        }
        body.extend(
            entry.name_type.unwrap_or(NAME_TYPE_PRINCIPAL).to_be_bytes(),
        );
        let stamp = match entry.timestamp.filter(|t| *t != 0) {
            Some(t) => t,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        };
        body.extend((stamp as u32).to_be_bytes());
        body.push((entry.kvno & 0xff) as u8);
        body.extend(((entry.etype & 0xffff) as u16).to_be_bytes());
        counted(&mut body, &entry.key)?;
        body.extend(entry.kvno.to_be_bytes());
        out.extend((body.len() as i32).to_be_bytes());
        out.extend(body);
    }
    Ok(out)
}

fn truncated(at: usize) -> Krb5Error {
    Krb5Error::new(format!("krb5_keytab: truncated at byte {}", at))
}

fn need(buf: &[u8], at: usize, n: usize) -> Krb5Result<()> {
    if at + n > buf.len() {
        return Err(truncated(at));
    }
    Ok(())
}

/// Node's `Buffer.readUInt16BE()` out of range, as its RangeError says.
fn u16_at(buf: &[u8], at: usize) -> Krb5Result<u16> {
    if at + 2 > buf.len() {
        return Err(Krb5Error::new(format!(
            "The value of \"offset\" is out of range. It must be >= 0 and <= \
             {}. Received {}",
            buf.len() as i64 - 2,
            at
        )));
    }
    Ok(u16::from_be_bytes([buf[at], buf[at + 1]]))
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn data<'a>(buf: &'a [u8], at: &mut usize, end: usize) -> Krb5Result<&'a [u8]> {
    need(buf, *at, 2)?;
    let len = usize::from(u16_at(buf, *at)?);
    *at += 2;
    if *at + len > end {
        return Err(Krb5Error::new(format!(
            "krb5_keytab: a field runs past its entry at byte {}",
            at
        )));
    }
    let out = &buf[*at..*at + len];
    *at += len;
    Ok(out)
}

/// Node's `readKeytab()`: holes skipped, the 32-bit kvno preferred.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read_keytab(buf: &[u8]) -> Krb5Result<Vec<ReadEntry>> {
    if buf.len() < 2 || u16::from_be_bytes([buf[0], buf[1]]) != KEYTAB_VERSION {
        return Err(Krb5Error::new("krb5_keytab: not a version 0x502 keytab"));
    }
    let mut entries = Vec::new();
    let mut at = 2;
    while at < buf.len() {
        need(buf, at, 4)?;
        let size = i32::from_be_bytes([
            buf[at],
            buf[at + 1],
            buf[at + 2],
            buf[at + 3],
        ]);
        at += 4;
        if size < 0 {
            let skip = size.unsigned_abs() as usize;
            need(buf, at, skip)?;
            at += skip;
            continue;
        }
        let size = size as usize;
        need(buf, at, size)?;
        let end = at + size;
        let count = u16_at(buf, at)?;
        at += 2;
        let realm =
            String::from_utf8_lossy(data(buf, &mut at, end)?).into_owned();
        let mut components = Vec::new();
        for _ in 0..count {
            components.push(
                String::from_utf8_lossy(data(buf, &mut at, end)?).into_owned(),
            );
        }
        if at + 11 > end {
            return Err(Krb5Error::new(
                "krb5_keytab: an entry ends before its key",
            ));
        }
        let name_type = u32_at(buf, at);
        let timestamp = u32_at(buf, at + 4);
        let mut kvno = u32::from(buf[at + 8]);
        let etype = u16::from_be_bytes([buf[at + 9], buf[at + 10]]);
        at += 11;
        let key = data(buf, &mut at, end)?.to_vec();
        if end - at >= 4 {
            kvno = u32_at(buf, at);
        }
        at = end;
        entries.push(ReadEntry {
            realm,
            components,
            name_type,
            timestamp,
            kvno,
            etype,
            key,
        });
    }
    Ok(entries)
}
