// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The raw RFC 5322 message: what `mail_transports.ts`'s `compose()` has
//! nodemailer's `MailComposer` build, byte for byte, for the one shape the
//! channel sends — a From (with a display name or without), one To, a
//! Subject, a Message-ID, a Date, `Auto-Submitted: auto-generated`,
//! `Content-Language`, and a `multipart/alternative` of a text part and an
//! HTML part.
//!
//! Ported from nodemailer 8 (`mime-node`, `mime-funcs`, `qp`, `base64`):
//! the header order (the caller's headers first, then From, To, Subject,
//! Message-ID, Date, MIME-Version, Content-Type last), RFC 2047 encoded
//! words (`Q` where Latin letters outnumber the rest, else `B`, split at 40
//! octets and folded at 76), and per part 7bit, quoted-printable or base64
//! by the same test nodemailer applies. A text part keeps its bare line
//! feeds, as nodemailer does: no newline normalisation is configured.
//!
//! **THE BOUNDARY IS RANDOM IN NODE** (`crypto.randomBytes(8)`); here it is
//! made through `sts_crypto` the same way, or handed in.

use crate::js;

/// What the channel hands a transport (`OutMessage`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OutMessage {
    pub from: String,
    pub from_name: String,
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
    pub message_id: String,
    /// The Date header's instant, milliseconds.
    pub date_ms: i64,
    pub lang: String,
}

const LINE: usize = 76;

/// `_getTextEncoding()`: `Q` where Latin letters outnumber the 8-bit and
/// control code units, else `B`. Counted in UTF-16 code units.
fn text_encoding(value: &str) -> char {
    let mut non_latin = 0usize;
    let mut latin = 0usize;
    for code in value.encode_utf16() {
        if code <= 0x08
            || code == 0x0b
            || code == 0x0c
            || (0x0e..=0x1f).contains(&code)
            || code >= 0x80
        {
            non_latin += 1;
        } else if (0x41..=0x5a).contains(&code) || (0x61..=0x7a).contains(&code)
        {
            latin += 1;
        }
    }
    if non_latin < latin {
        'Q'
    } else {
        'B'
    }
}

fn qp_literal(b: u8) -> bool {
    b == 0x09
        || b == 0x0a
        || b == 0x0d
        || (0x20..=0x3c).contains(&b)
        || (0x3e..=0x7e).contains(&b)
}

/// `qp.encodeBytes()` (text mode: a CR or LF is a line break).
fn qp_bytes(buf: &[u8], next: Option<u8>) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(buf.len() * 3);
    for (i, &ord) in buf.iter().enumerate() {
        let following = buf.get(i + 1).copied().or(next);
        let space = ord == 0x20 || ord == 0x09;
        let at_end = matches!(following, None | Some(0x0a) | Some(0x0d));
        if qp_literal(ord) && !(space && at_end) {
            out.push(ord as char);
            continue;
        }
        out.push('=');
        out.push(HEX[(ord / 16) as usize] as char);
        out.push(HEX[(ord % 16) as usize] as char);
    }
    out
}

/// `qp.wrap(str, 76)`, over the encoder's ASCII output.
fn qp_wrap(text: &str, line_length: usize) -> String {
    let s = text.as_bytes();
    if s.len() <= line_length {
        return text.to_string();
    }
    let margin = line_length / 3;
    let len = s.len();
    let mut pos = 0usize;
    let mut result = String::new();
    let hex = |b: u8| b.is_ascii_hexdigit();
    while pos < len {
        let mut line: Vec<u8> = s[pos..(pos + line_length).min(len)].to_vec();
        if let Some(at) = line.windows(2).position(|w| w == b"\r\n") {
            line.truncate(at + 2);
            pos += line.len();
            result.push_str(&String::from_utf8_lossy(&line));
            continue;
        }
        if line.last() == Some(&b'\n') {
            pos += line.len();
            result.push_str(&String::from_utf8_lossy(&line));
            continue;
        }
        // `line.substr(-lineMargin).match(/\n.*?$/)`: `.` stops at a line
        // feed and `$` is the end, so it is the LAST line feed that matches.
        let tail_from = line.len().saturating_sub(margin);
        if let Some(nl) = line[tail_from..].iter().rposition(|&b| b == b'\n') {
            let matched = line.len() - (tail_from + nl);
            line.truncate(line.len() - (matched - 1));
            pos += line.len();
            result.push_str(&String::from_utf8_lossy(&line));
            continue;
        }
        let breakable =
            |b: u8| matches!(b, b' ' | b'\t' | b'.' | b',' | b'!' | b'?');
        let mut cut = false;
        if line.len() > line_length - margin {
            let tail = &line[tail_from..];
            if let Some(at) = tail.iter().rposition(|&b| breakable(b)) {
                let matched = tail.len() - at;
                line.truncate(line.len() - (matched - 1));
                cut = true;
            }
        }
        if !cut {
            // `/[=][\da-f]{0,2}$/i`
            let n = line.len();
            let ends_escape = (n >= 1 && line[n - 1] == b'=')
                || (n >= 2 && line[n - 2] == b'=' && hex(line[n - 1]))
                || (n >= 3
                    && line[n - 3] == b'='
                    && hex(line[n - 2])
                    && hex(line[n - 1]));
            if ends_escape {
                // `/[=][\da-f]{0,1}$/i`
                let n = line.len();
                if n >= 1 && line[n - 1] == b'=' {
                    line.truncate(n - 1);
                } else if n >= 2 && line[n - 2] == b'=' && hex(line[n - 1]) {
                    line.truncate(n - 2);
                }
                loop {
                    let n = line.len();
                    if !(n > 3 && n < len - pos) {
                        break;
                    }
                    let whole_escapes = n % 3 == 0
                        && n / 3 >= 1
                        && n / 3 <= 4
                        && line
                            .chunks(3)
                            .all(|c| c[0] == b'=' && hex(c[1]) && hex(c[2]));
                    if whole_escapes {
                        break;
                    }
                    if !(line[n - 3] == b'='
                        && hex(line[n - 2])
                        && hex(line[n - 1]))
                    {
                        break;
                    }
                    let code = u8::from_str_radix(
                        &String::from_utf8_lossy(&line[n - 2..]),
                        16,
                    )
                    .unwrap_or(0);
                    if code < 128 {
                        break;
                    }
                    line.truncate(n - 3);
                    if code >= 0xc0 {
                        break;
                    }
                }
            }
        }
        if line.is_empty() {
            line = s[pos..(pos + line_length).min(len)].to_vec();
        }
        if pos + line.len() < len && line.last() != Some(&b'\n') {
            let n = line.len();
            if n == line_length
                && n >= 3
                && line[n - 3] == b'='
                && hex(line[n - 2])
                && hex(line[n - 1])
            {
                line.truncate(n - 3);
            } else if n == line_length {
                line.truncate(n - 1);
            }
            pos += line.len();
            line.extend_from_slice(b"=\r\n");
        } else {
            pos += line.len();
        }
        result.push_str(&String::from_utf8_lossy(&line));
    }
    result
}

/// `qp.Encoder` fed the whole body as one chunk: trailing white space held
/// back to the flush, 64 KiB slices, the current line carried between.
fn qp_body(bytes: &[u8]) -> String {
    const SLICE: usize = 64 * 1024;
    let mut out = String::new();
    let mut cur = String::new();
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    let (main, rest) = if bytes.len() - end <= SLICE {
        (&bytes[..end], &bytes[end..])
    } else {
        (bytes, &bytes[bytes.len()..])
    };
    let slices = |buf: &[u8], cur: &mut String, out: &mut String| {
        let mut start = 0;
        while start < buf.len() {
            let stop = (start + SLICE).min(buf.len());
            let next = buf.get(stop).copied();
            let qp = qp_wrap(
                &format!("{}{}", cur, qp_bytes(&buf[start..stop], next)),
                LINE,
            );
            let last = qp.rfind('\n').map_or(0, |i| i + 1);
            *cur = qp[last..].to_string();
            out.push_str(&qp[..last]);
            start = stop;
        }
    };
    slices(main, &mut cur, &mut out);
    slices(rest, &mut cur, &mut out);
    out.push_str(&cur);
    out
}

fn base64_standard(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}

/// `base64.Encoder`: the body's base64 in lines of 76, CRLF between.
fn base64_body(bytes: &[u8]) -> String {
    let all = base64_standard(bytes);
    all.as_bytes()
        .chunks(LINE)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// `splitMimeEncodedString(str, maxlen)`.
fn split_encoded(text: &str, maxlen: usize) -> Vec<String> {
    let maxlen = maxlen.max(12);
    let mut lines = Vec::new();
    let mut s = text.as_bytes().to_vec();
    let hex = |b: u8| b.is_ascii_hexdigit();
    while !s.is_empty() {
        let mut cur: Vec<u8> = s[..maxlen.min(s.len())].to_vec();
        let n = cur.len();
        if n >= 1 && cur[n - 1] == b'=' {
            cur.truncate(n - 1);
        } else if n >= 2 && cur[n - 2] == b'=' && hex(cur[n - 1]) {
            cur.truncate(n - 2);
        }
        let fallback = if cur.is_empty() {
            s[..maxlen.min(s.len())].to_vec()
        } else {
            cur.clone()
        };
        let mut done = false;
        while !done && !cur.is_empty() {
            done = true;
            let after = &s[cur.len()..];
            if after.len() >= 3
                && after[0] == b'='
                && hex(after[1])
                && hex(after[2])
            {
                let chr = u8::from_str_radix(
                    &String::from_utf8_lossy(&after[1..3]),
                    16,
                )
                .unwrap_or(0);
                if chr < 0xc2 && chr > 0x7f {
                    let n = cur.len();
                    cur.truncate(n.saturating_sub(3));
                    done = false;
                }
            }
        }
        if cur.is_empty() {
            cur = fallback;
        }
        let used = cur.len();
        lines.push(String::from_utf8_lossy(&cur).into_owned());
        s.drain(..used);
    }
    lines
}

/// `mimeFuncs.encodeWord(data, encoding, 52)`.
fn encode_word(data: &str, encoding: char) -> String {
    let max = 52 - (7 + 5);
    let encoded = if encoding == 'Q' {
        let qp = qp_bytes(data.as_bytes(), None);
        let mut out = String::new();
        for c in qp.chars() {
            if c.is_ascii_alphanumeric() || "!*+-/=".contains(c) {
                out.push(c);
            } else if c == ' ' {
                out.push('_');
            } else {
                out.push_str(&format!("={:02X}", c as u32));
            }
        }
        if out.len() > max {
            split_encoded(&out, max).join("?= =?UTF-8?Q?")
        } else {
            out
        }
    } else {
        let max_b = (3usize).max(((max - (max % 4)) / 4) * 3);
        if base64_standard(data.as_bytes()).len() > max_b {
            let mut parts: Vec<String> = Vec::new();
            let mut part = String::new();
            for (i, c) in data.chars().enumerate() {
                let mut grown = part.clone();
                grown.push(c);
                if grown.len() <= max_b || i == 0 {
                    part = grown;
                } else {
                    parts.push(base64_standard(part.as_bytes()));
                    part = c.to_string();
                }
            }
            if !part.is_empty() {
                parts.push(base64_standard(part.as_bytes()));
            }
            parts.join("?= =?UTF-8?B?")
        } else {
            base64_standard(data.as_bytes())
        }
    };
    let closing = if encoded.ends_with("?=") { "" } else { "?=" };
    format!("=?UTF-8?{}?{}{}", encoding, encoded, closing)
}

/// `_encodeHeaderText()`: an unstructured value, encoded whole when it
/// carries a control character, a quote or a non-ASCII character.
fn header_text(value: &str) -> String {
    let control = value.chars().any(|c| {
        let u = c as u32;
        u <= 0x08
            || u == 0x0b
            || u == 0x0c
            || (0x0e..=0x1f).contains(&u)
            || u == 0x7f
    });
    let special = value.encode_utf16().any(|u| u == 0x22 || u >= 0x80);
    if control || special {
        encode_word(value, text_encoding(value))
    } else {
        value.to_string()
    }
}

/// `_encodeAddressName()`.
fn address_name(name: &str) -> String {
    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ' ')
    {
        return name.to_string();
    }
    if name.chars().all(|c| (' '..='~').contains(&c)) {
        return format!(
            "\"{}\"",
            name.replace('\\', "\\\\").replace('"', "\\\"")
        );
    }
    encode_word(name, text_encoding(name))
}

/// `foldLines(str, 76)` (folding before the white space).
fn fold(text: &str) -> String {
    let s: Vec<char> = text.chars().collect();
    let len = s.len();
    let mut pos = 0;
    let mut result = String::new();
    let space = |c: char| js::is_space(c);
    while pos < len {
        let mut line: Vec<char> = s[pos..(pos + LINE).min(len)].to_vec();
        if line.len() < LINE {
            result.extend(line);
            break;
        }
        if let Some(at) = line.iter().position(|&c| c == '\r' || c == '\n') {
            let end = if line[at] == '\r' && line.get(at + 1) == Some(&'\n') {
                at + 2
            } else {
                at + 1
            };
            line.truncate(end);
            pos += line.len();
            result.extend(line);
            continue;
        }
        // `/(\s+)[^\s]*$/`, shorter than the line.
        let mut k = line.len();
        while k > 0 && !space(line[k - 1]) {
            k -= 1;
        }
        let mut w = k;
        while w > 0 && space(line[w - 1]) {
            w -= 1;
        }
        let matched = line.len() - w;
        if k > 0 && matched < line.len() {
            line.truncate(line.len() - matched);
        } else {
            // `str.substr(pos + line.length).match(/^[^\s]+(\s*)/)`
            let mut j = pos + line.len();
            let from = j;
            while j < len && !space(s[j]) {
                j += 1;
            }
            if j > from {
                line.extend_from_slice(&s[from..j]);
            }
        }
        pos += line.len();
        result.extend(line);
        if pos < len {
            result.push_str("\r\n");
        }
    }
    result
}

/// The Date header: `toUTCString()` with `GMT` written `+0000`.
fn date_header(ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(ms) {
        Some(at) => at.format("%a, %d %b %Y %H:%M:%S +0000").to_string(),
        None => String::new(),
    }
}

/// One part's headers and body, as `MimeNode` streams it.
fn part(content_type: &str, content: &str) -> (String, String) {
    let plain = !content.chars().any(|c| {
        let u = c as u32;
        u <= 0x08
            || u == 0x0b
            || u == 0x0c
            || (0x0e..=0x1f).contains(&u)
            || u >= 0x80
    });
    let long = js::len(content) > 128 * 1024
        || content
            .split(['\n', '\r', '\u{2028}', '\u{2029}'])
            .any(|line| js::len(line) > LINE);
    let (encoding, body) = if plain && !long {
        ("7bit", content.to_string())
    } else if text_encoding(content) == 'Q' {
        ("quoted-printable", qp_body(content.as_bytes()))
    } else {
        ("base64", base64_body(content.as_bytes()))
    };
    let headers = [
        fold(&format!("Content-Type: {}; charset=utf-8", content_type)),
        fold(&format!("Content-Transfer-Encoding: {}", encoding)),
    ]
    .join("\r\n");
    (headers, body)
}

/// `MailTransports.compose()`: the raw message, with the base boundary
/// nodemailer would have drawn (sixteen hex digits).
#[tracing::instrument(level = "debug", skip(message))]
pub fn compose(message: &OutMessage, base_boundary: &str) -> Vec<u8> {
    let boundary = format!("--_NmP-{}-Part_1", base_boundary);
    let from = if message.from_name.is_empty() {
        message.from.clone()
    } else {
        format!("{} <{}>", address_name(&message.from_name), message.from)
    };
    let lang = if message.lang.is_empty() {
        "en"
    } else {
        message.lang.as_str()
    };
    let id = if message.message_id.starts_with('<') {
        message.message_id.clone()
    } else {
        format!("<{}", message.message_id)
    };
    let id = if id.ends_with('>') {
        id
    } else {
        format!("{}>", id)
    };
    let headers = [
        fold("Auto-Submitted: auto-generated"),
        fold(&format!("Content-Language: {}", header_text(lang))),
        fold(&format!("From: {}", from)),
        fold(&format!("To: {}", message.to)),
        fold(&format!("Subject: {}", header_text(&message.subject))),
        fold(&format!("Message-ID: {}", id)),
        fold(&format!("Date: {}", date_header(message.date_ms))),
        "MIME-Version: 1.0".to_string(),
        fold(&format!(
            "Content-Type: multipart/alternative; boundary=\"{}\"",
            boundary
        )),
    ]
    .join("\r\n");
    let (text_headers, text_body) = part("text/plain", &message.text);
    let (html_headers, html_body) = part("text/html", &message.html);
    let mut out = String::new();
    out.push_str(&headers);
    out.push_str("\r\n\r\n");
    out.push_str(&format!("--{}\r\n", boundary));
    out.push_str(&text_headers);
    out.push_str("\r\n\r\n");
    out.push_str(&text_body);
    out.push_str(&format!("\r\n--{}\r\n", boundary));
    out.push_str(&html_headers);
    out.push_str("\r\n\r\n");
    out.push_str(&html_body);
    out.push_str(&format!("\r\n--{}--\r\n", boundary));
    out.into_bytes()
}

/// A fresh base boundary, as nodemailer draws one: eight random bytes in
/// hex, through `sts_crypto`.
#[tracing::instrument(level = "debug")]
pub fn base_boundary() -> String {
    match sts_crypto::random::random_bytes(8) {
        Ok(bytes) => bytes.iter().map(|b| format!("{:02x}", b)).collect(),
        Err(e) => {
            // A boundary only has to be absent from the body; the
            // message id is unique and serves when randomness is not.
            tracing::debug!("no random boundary: {}", e);
            "0000000000000000".to_string()
        }
    }
}
