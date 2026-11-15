// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! BER as node-ldapjs reads and writes it: `@ldapjs/asn1` 2.0.0's
//! `BerReader` ([`Reader`]), the 1.2.0 one `@ldapjs/controls` carries for
//! control values ([`ReaderV1`]), and the writer both versions share
//! ([`Writer`] — their bytes are the same).
//!
//! The readers are ported operation for operation rather than written as
//! a strict DER/BER parser, because the outcome a client sees for a
//! malformed PDU is decided by them: a length is up to four bytes and
//! read into a 32-bit integer (`0x84 0xff…` is -1), a field whose length
//! runs past the buffer reads as `null` without moving the offset, an
//! integer of any width is folded into 32 bits, a read past the end is
//! `0` (`undefined & 0xff`), and an offset may go backwards. Offsets and
//! lengths are therefore `i64`, as JavaScript's numbers hold them.
//!
//! These functions are a hot path — every field of every PDU — and carry
//! no span (rust/DESIGN.md D3, section 4.5: a stated hot-path exemption
//! from `#[tracing::instrument]`).

use crate::fault::{Fault, Outcome};
use crate::js;

/// `Expected 0x30: got 0x04`, as 2.0.0 words a tag mismatch.
fn expected(tag: u8, found: Option<u8>) -> Fault {
    match found {
        Some(f) => {
            Fault::thrown(format!("Expected 0x{tag:02x}: got 0x{f:02x}"))
        }
        None => Fault::null_read("toString"),
    }
}

/// `parseIntegerBuffer()`: the bytes folded into a 32-bit integer, with
/// the sign of the first byte applied as 2.0.0 applies it (`1 << (i * 8)`
/// is itself a 32-bit shift, so a five-byte value is corrected by 256).
pub fn parse_integer(bytes: &[u8]) -> i32 {
    let mut value: i32 = 0;
    for b in bytes {
        value = value.wrapping_shl(8) | i32::from(*b);
    }
    let i = bytes.len();
    let first = bytes.first().copied().unwrap_or(0);
    if first & 0x80 == 0x80 && i != 4 {
        let shift = ((i * 8) % 32) as u32;
        let sub = i64::from(1i32.wrapping_shl(shift));
        return (i64::from(value) - sub) as i32;
    }
    value
}

/// `@ldapjs/asn1` 2.0.0's `BerReader`.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    offset: i64,
    len: i64,
    seq_start: i64,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader {
            buf,
            offset: 0,
            len: 0,
            seq_start: 0,
        }
    }

    fn size(&self) -> i64 {
        self.buf.len() as i64
    }

    /// The byte at `i`, `0` outside the buffer (`undefined & 0xff`).
    fn at(&self, i: i64) -> u8 {
        if i >= 0 && i < self.size() {
            self.buf[i as usize]
        } else {
            0
        }
    }

    pub fn buffer(&self) -> &'a [u8] {
        self.buf
    }

    pub fn offset(&self) -> i64 {
        self.offset
    }

    pub fn length(&self) -> i64 {
        self.len
    }

    pub fn remain(&self) -> i64 {
        self.size() - self.offset
    }

    pub fn set_offset(&mut self, position: i64) {
        self.offset = position;
    }

    pub fn peek(&self) -> Option<u8> {
        if self.size() - self.offset < 1 {
            None
        } else {
            Some(self.at(self.offset))
        }
    }

    /// `readLength(offset)`: the offset of the value, with the length in
    /// [`Reader::length`]; `None` when the length's bytes are not all
    /// there.
    pub fn read_length(&mut self, offset: i64) -> Outcome<Option<i64>> {
        read_length(self.buf, offset, &mut self.len, LengthWords::V2)
    }

    pub fn read_sequence(&mut self, tag: Option<u8>) -> Outcome<Option<u8>> {
        let found = self.peek();
        if let Some(t) = tag {
            if Some(t) != found {
                return Err(expected(t, found));
            }
        }
        self.seq_start = self.offset;
        let Some(vo) = self.read_length(self.offset + 1)? else {
            return Ok(None);
        };
        self.offset = vo;
        Ok(found)
    }

    /// `readTag(tag)`: the value's bytes, the offset left at the value.
    fn read_tag(&mut self, tag: u8) -> Outcome<Option<&'a [u8]>> {
        let found = self.peek();
        if found != Some(tag) {
            return Err(expected(tag, found));
        }
        let Some(fo) = self.read_length(self.offset + 1)? else {
            return Ok(None);
        };
        if self.len > self.size() - fo {
            return Ok(None);
        }
        self.offset = fo;
        Ok(Some(js::subarray(
            self.buf,
            self.offset,
            self.offset + self.len,
        )))
    }

    /// `readInt(tag)`, and so `readEnumeration()` (tag 0x0a).
    pub fn read_int(&mut self, tag: u8) -> Outcome<i32> {
        let Some(b) = self.read_tag(tag)? else {
            return Err(Fault::null_read("length"));
        };
        self.offset += b.len() as i64;
        Ok(parse_integer(b))
    }

    pub fn read_enumeration(&mut self) -> Outcome<i32> {
        self.read_int(0x0a)
    }

    pub fn read_boolean(&mut self, tag: u8) -> Outcome<bool> {
        Ok(self.read_int(tag)? != 0)
    }

    /// `readString(tag, true)`: the value's bytes, `None` for `null`.
    pub fn read_bytes(&mut self, tag: u8) -> Outcome<Option<Vec<u8>>> {
        let found = self.peek();
        if found != Some(tag) {
            return Err(expected(tag, found));
        }
        let Some(vo) = self.read_length(self.offset + 1)? else {
            return Ok(None);
        };
        if self.len > self.size() - vo {
            return Ok(None);
        }
        self.offset = vo;
        if self.len == 0 {
            return Ok(Some(Vec::new()));
        }
        let s = js::subarray(self.buf, self.offset, self.offset + self.len);
        self.offset += self.len;
        Ok(Some(s.to_vec()))
    }

    /// `readString(tag)`: the value decoded as UTF-8, `None` for `null`.
    pub fn read_string(&mut self, tag: u8) -> Outcome<Option<String>> {
        Ok(self.read_bytes(tag)?.map(|b| js::utf8(&b)))
    }

    /// `readRawBuffer(tag)`: a whole TLV. `tag` is `None` when the caller
    /// passed what `peek()` found at the end of the buffer.
    pub fn read_raw_buffer(
        &mut self,
        tag: Option<u8>,
    ) -> Outcome<Option<&'a [u8]>> {
        let Some(tag) = tag else {
            return Err(Fault::thrown("must specify an integer tag"));
        };
        let found = self.peek();
        if found != Some(tag) {
            return Err(expected(tag, found));
        }
        let cur = self.offset;
        let Some(vo) = self.read_length(cur + 1)? else {
            return Ok(None);
        };
        let end = cur + self.len + (vo - cur);
        if end > self.size() {
            return Ok(None);
        }
        let out = js::subarray(self.buf, cur, end);
        self.offset = end;
        Ok(Some(out))
    }

    /// `sequenceToReader()`: the last sequence read, tag to end, as a
    /// reader of its own.
    pub fn sequence_to_reader(&self) -> Reader<'a> {
        let tl = self.offset - self.seq_start;
        Reader::new(js::subarray(
            self.buf,
            self.seq_start,
            self.seq_start + tl + self.len,
        ))
    }
}

#[derive(Clone, Copy)]
enum LengthWords {
    V2,
    V1,
}

fn read_length(
    buf: &[u8],
    offset: i64,
    len: &mut i64,
    words: LengthWords,
) -> Outcome<Option<i64>> {
    let size = buf.len() as i64;
    if offset >= size {
        return Ok(None);
    }
    let at = |i: i64| -> u8 {
        if i >= 0 && i < size {
            buf[i as usize]
        } else {
            0
        }
    };
    let mut o = offset;
    let mut lb = i64::from(at(o));
    o += 1;
    if lb & 0x80 == 0x80 {
        lb &= 0x7f;
        if lb == 0 {
            return Err(Fault::thrown(match words {
                LengthWords::V2 => "Indefinite length not supported.",
                LengthWords::V1 => "Indefinite length not supported",
            }));
        }
        if lb > 4 {
            return Err(Fault::thrown(match words {
                LengthWords::V2 => "Encoding too long.",
                LengthWords::V1 => "encoding too long",
            }));
        }
        if size - o < lb {
            return Ok(None);
        }
        let mut v: i32 = 0;
        for _ in 0..lb {
            v = v.wrapping_shl(8).wrapping_add(i32::from(at(o)));
            o += 1;
        }
        *len = i64::from(v);
    } else {
        *len = lb;
    }
    Ok(Some(o))
}

/// `@ldapjs/asn1` 1.2.0's reader, which `@ldapjs/controls` builds over a
/// control's value: `null` rather than a throw at the end of the buffer,
/// integers of at most four bytes, and `readBoolean()` true for `null`.
#[derive(Debug, Clone)]
pub struct ReaderV1<'a> {
    buf: &'a [u8],
    offset: i64,
    len: i64,
}

fn expected_v1(tag: u8, found: u8) -> Fault {
    Fault::thrown(format!("Expected 0x{tag:x}: got 0x{found:x}"))
}

impl<'a> ReaderV1<'a> {
    pub fn new(buf: &'a [u8]) -> ReaderV1<'a> {
        ReaderV1 {
            buf,
            offset: 0,
            len: 0,
        }
    }

    fn size(&self) -> i64 {
        self.buf.len() as i64
    }

    pub fn peek(&self) -> Option<u8> {
        if self.size() - self.offset < 1 {
            None
        } else if self.offset >= 0 {
            Some(self.buf[self.offset as usize])
        } else {
            Some(0)
        }
    }

    pub fn read_sequence(&mut self, tag: Option<u8>) -> Outcome<Option<u8>> {
        let Some(seq) = self.peek() else {
            return Ok(None);
        };
        if let Some(t) = tag {
            if t != seq {
                return Err(expected_v1(t, seq));
            }
        }
        let Some(o) = read_length(
            self.buf,
            self.offset + 1,
            &mut self.len,
            LengthWords::V1,
        )?
        else {
            return Ok(None);
        };
        self.offset = o;
        Ok(Some(seq))
    }

    /// `_readTag(tag)`: an integer of at most four bytes, `None` for `null`.
    pub fn read_tag(&mut self, tag: u8) -> Outcome<Option<i32>> {
        let Some(b) = self.peek() else {
            return Ok(None);
        };
        if b != tag {
            return Err(expected_v1(tag, b));
        }
        let Some(o) = read_length(
            self.buf,
            self.offset + 1,
            &mut self.len,
            LengthWords::V1,
        )?
        else {
            return Ok(None);
        };
        if self.len > 4 {
            return Err(Fault::thrown(format!(
                "Integer too long: {}",
                self.len
            )));
        }
        if self.len > self.size() - o {
            return Ok(None);
        }
        self.offset = o;
        let buf = self.buf;
        let size = self.size();
        let at = |i: i64| -> u8 {
            if i >= 0 && i < size {
                buf[i as usize]
            } else {
                0
            }
        };
        let fb = at(self.offset);
        let mut value: i32 = 0;
        let mut i: i64 = 0;
        while i < self.len {
            value = value.wrapping_shl(8) | i32::from(at(self.offset));
            self.offset += 1;
            i += 1;
        }
        if fb & 0x80 == 0x80 && i != 4 {
            value = value.wrapping_sub(1i32.wrapping_shl((i * 8) as u32));
        }
        Ok(Some(value))
    }

    pub fn read_int(&mut self) -> Outcome<Option<i32>> {
        self.read_tag(0x02)
    }

    pub fn read_enumeration(&mut self) -> Outcome<Option<i32>> {
        self.read_tag(0x0a)
    }

    /// `readBoolean(tag)`: `_readTag(tag) !== 0`, so `null` reads as true.
    pub fn read_boolean(&mut self, tag: u8) -> Outcome<bool> {
        Ok(self.read_tag(tag)? != Some(0))
    }

    pub fn read_bytes(&mut self, tag: u8) -> Outcome<Option<Vec<u8>>> {
        let Some(b) = self.peek() else {
            return Ok(None);
        };
        if b != tag {
            return Err(expected_v1(tag, b));
        }
        let Some(o) = read_length(
            self.buf,
            self.offset + 1,
            &mut self.len,
            LengthWords::V1,
        )?
        else {
            return Ok(None);
        };
        if self.len > self.size() - o {
            return Ok(None);
        }
        self.offset = o;
        if self.len == 0 {
            return Ok(Some(Vec::new()));
        }
        let s = js::subarray(self.buf, self.offset, self.offset + self.len);
        self.offset += self.len;
        Ok(Some(s.to_vec()))
    }

    pub fn read_string(&mut self, tag: u8) -> Outcome<Option<String>> {
        Ok(self.read_bytes(tag)?.map(|b| js::utf8(&b)))
    }
}

/// `BerWriter`, either version: a sequence's length is written in the
/// fewest bytes, up to three (`0x83`), and more is refused.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
    open: Vec<(u8, usize)>,
}

fn length_bytes(len: usize) -> Outcome<Vec<u8>> {
    Ok(if len <= 0x7f {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len <= 0xff_ffff {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        return Err(Fault::thrown("length too long (> 4 bytes)"));
    })
}

impl Writer {
    pub fn new() -> Writer {
        Writer::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn write_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_length(&mut self, len: usize) -> Outcome<()> {
        let l = length_bytes(len)?;
        self.buf.extend_from_slice(&l);
        Ok(())
    }

    pub fn start_sequence(&mut self, tag: u8) {
        self.open.push((tag, self.buf.len()));
    }

    pub fn end_sequence(&mut self) -> Outcome<()> {
        let Some((tag, start)) = self.open.pop() else {
            return Ok(());
        };
        let len = self.buf.len() - start;
        if len > 0xff_ffff {
            return Err(Fault::thrown("sequence too long"));
        }
        let mut head = vec![tag];
        head.extend_from_slice(&length_bytes(len)?);
        self.buf.splice(start..start, head);
        Ok(())
    }

    /// `writeInt(n, tag)`: the fewest two's-complement bytes of the 32-bit
    /// value.
    pub fn write_int(&mut self, n: i32, tag: u8) {
        let mut i = n;
        let mut size = 4;
        while ((i as u32 & 0xff80_0000) == 0
            || (i as u32 & 0xff80_0000) == 0xff80_0000)
            && size > 1
        {
            size -= 1;
            i = i.wrapping_shl(8);
        }
        self.buf.push(tag);
        self.buf.push(size as u8);
        for _ in 0..size {
            self.buf.push(((i as u32 & 0xff00_0000) >> 24) as u8);
            i = i.wrapping_shl(8);
        }
    }

    pub fn write_enumeration(&mut self, n: i32) {
        self.write_int(n, 0x0a);
    }

    pub fn write_boolean(&mut self, b: bool, tag: u8) {
        self.buf
            .extend_from_slice(&[tag, 0x01, if b { 0xff } else { 0x00 }]);
    }

    pub fn write_string(&mut self, s: &str, tag: u8) -> Outcome<()> {
        self.write_buffer(s.as_bytes(), tag)
    }

    pub fn write_buffer(&mut self, b: &[u8], tag: u8) -> Outcome<()> {
        self.buf.push(tag);
        self.write_length(b.len())?;
        self.buf.extend_from_slice(b);
        Ok(())
    }

    pub fn write_null(&mut self) {
        self.buf.extend_from_slice(&[0x05, 0x00]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_fold_into_32_bits() {
        assert_eq!(parse_integer(&[0x01, 0, 0, 0, 7]), 7);
        assert_eq!(parse_integer(&[0xff]), -1);
        assert_eq!(parse_integer(&[0x80, 0, 0, 0]), i32::MIN);
        assert_eq!(parse_integer(&[]), 0);
    }

    #[test]
    fn writer_is_minimal() {
        let mut w = Writer::new();
        w.write_int(128, 2);
        w.write_int(-129, 2);
        w.write_int(0, 2);
        assert_eq!(
            js::hex(w.bytes()),
            "0202008002 02ff7f020100".replace(' ', "")
        );
    }
}
