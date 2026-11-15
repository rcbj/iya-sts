// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `common/validation.js`'s URI and origin checks the application register
//! calls — `redirectUriProblem()`, `frontchannelUriProblem()`,
//! `backchannelUriProblem()`, `originProblem()` and `normaliseOrigin()` —
//! and `JSON.parse()` as V8 refuses a text, because one register sentence
//! (`resourceMetadataProblem()`) quotes the parser's own message.
//!
//! Node's `new URL()` is the WHATWG URL parser; the `url` crate is the same
//! standard, so `protocol`, `hostname`, `origin`, `username`, `password`,
//! `search`, `hash` and `pathname` are read off a `url::Url` the way
//! [`JsUrl`] spells them.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Number, Value};

/// `CAP.URI`: the longest URI any check accepts, in UTF-16 units.
pub const CAP_URI: usize = 2048;

/// The parts of a WHATWG URL Node's checks read, spelt as `new URL()`
/// spells them.
#[derive(Debug, Clone, PartialEq)]
pub struct JsUrl {
    /// `protocol`: the scheme and its colon.
    pub protocol: String,
    pub hostname: String,
    pub origin: String,
    pub username: String,
    pub password: String,
    /// `search`: '' for no query and for an empty one.
    pub search: String,
    /// `hash`: '' for no fragment and for an empty one.
    pub hash: String,
    pub pathname: String,
}

/// `new URL(text)`, or `None` where it throws.
#[tracing::instrument(level = "debug")]
pub fn js_url(text: &str) -> Option<JsUrl> {
    let parsed = url::Url::parse(text).ok()?;
    let query = parsed.query().unwrap_or("");
    let fragment = parsed.fragment().unwrap_or("");
    Some(JsUrl {
        protocol: format!("{}:", parsed.scheme()),
        hostname: parsed.host_str().unwrap_or("").to_string(),
        origin: parsed.origin().ascii_serialization(),
        username: parsed.username().to_string(),
        password: parsed.password().unwrap_or("").to_string(),
        search: if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        },
        hash: if fragment.is_empty() {
            String::new()
        } else {
            format!("#{fragment}")
        },
        pathname: parsed.path().to_string(),
    })
}

static PRIVATE_USE_SCHEME: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9+-]*(?:\.[a-z0-9+-]+)+$").ok());

static HTTP_WITH_HOST: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)^https?://[^/]").ok());

static ORIGIN_SHAPE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#\s]+)/?$").ok()
});

/// `redirectUriProblem(value, {privateUse})`: why a value may not be a
/// redirection endpoint, as a clause, or `None`. An http or https URL with
/// a host, or (with `private_use`) a private-use scheme containing a
/// period (RFC 8252 section 7.1); never a fragment.
#[tracing::instrument(level = "debug")]
pub fn redirect_uri_problem(value: &str, private_use: bool) -> Option<String> {
    if value.is_empty() {
        return Some("is empty".into());
    }
    if crate::js::len_utf16(value) > CAP_URI {
        return Some(format!("is longer than {CAP_URI} characters"));
    }
    if value.contains('#') {
        return Some(
            "must not contain a fragment (RFC 6749 section 3.1.2)".into(),
        );
    }
    let Some(parsed) = js_url(value) else {
        return Some("is not an absolute URI".into());
    };
    let scheme = parsed.protocol.to_lowercase();
    let scheme = scheme.strip_suffix(':').unwrap_or(&scheme).to_string();
    if scheme == "http" || scheme == "https" {
        // The TEXT, not the parse: `https:/cb` parses with the host `cb`.
        if !HTTP_WITH_HOST.as_ref().is_some_and(|r| r.is_match(value))
            || parsed.hostname.is_empty()
        {
            return Some(format!("is an {scheme} URL with no host"));
        }
        return None;
    }
    if private_use
        && PRIVATE_USE_SCHEME
            .as_ref()
            .is_some_and(|r| r.is_match(&scheme))
    {
        return None;
    }
    Some(if private_use {
        format!(
            "must be an http or https URL, or a native application's \
             private-use scheme named for a domain in reverse order, such \
             as com.example.app:/callback (RFC 8252 section 7.1; a scheme \
             with no period, like \"{scheme}:\", is refused)"
        )
    } else {
        "must be an http or https URL".to_string()
    })
}

/// `frontchannelUriProblem(value)`: http or https only, no fragment.
#[tracing::instrument(level = "debug")]
pub fn frontchannel_uri_problem(value: &str) -> Option<String> {
    redirect_uri_problem(value, false)
}

/// `backchannelUriProblem(value)`: http or https only, no fragment.
#[tracing::instrument(level = "debug")]
pub fn backchannel_uri_problem(value: &str) -> Option<String> {
    redirect_uri_problem(value, false)
}

// `readOrigin(value)`: the serialised origin, or the reason it is not one.
fn read_origin(value: &str) -> Result<String, String> {
    let text = crate::js::trim(value);
    if text.is_empty() {
        return Err("is empty".into());
    }
    if crate::js::len_utf16(text) > CAP_URI {
        return Err(format!("is longer than {CAP_URI} characters"));
    }
    if text.contains('*') {
        return Err("is a wildcard, and CORS here is an allowlist of exact \
                    origins — list each origin a page is served from"
            .into());
    }
    if text.to_lowercase() == "null" {
        return Err("is the opaque origin, which every sandboxed frame, \
                    data: document and local file shares — allowing it \
                    would allow all of them"
            .into());
    }
    let Some(shape) = ORIGIN_SHAPE.as_ref().and_then(|r| r.captures(text))
    else {
        return Err("is not an origin: it must be scheme://host or \
                    scheme://host:port with no path, query or fragment, \
                    such as https://app.example.com"
            .into());
    };
    let host = shape.get(2).map(|m| m.as_str()).unwrap_or("");
    if host.contains('@') {
        return Err("carries a user name, which an origin never does".into());
    }
    let scheme = shape
        .get(1)
        .map(|m| m.as_str())
        .unwrap_or("")
        .to_lowercase();
    if scheme != "http" && scheme != "https" {
        return Ok(format!("{}://{}", scheme, host.to_lowercase()));
    }
    let Some(parsed) = js_url(text) else {
        return Err("is not an origin: its host or port does not parse".into());
    };
    if parsed.hostname.is_empty() || parsed.origin == "null" {
        return Err(format!("is an {scheme} origin with no host"));
    }
    Ok(parsed.origin)
}

/// `originProblem(value)`: why a value may not be held as a CORS origin.
#[tracing::instrument(level = "debug")]
pub fn origin_problem(value: &str) -> Option<String> {
    read_origin(value).err()
}

/// `normaliseOrigin(value)`: the origin as a browser sends it (RFC 6454
/// section 6.1), '' when it is not one.
#[tracing::instrument(level = "debug")]
pub fn normalise_origin(value: &str) -> String {
    read_origin(value).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// JSON.parse() AS V8 REFUSES A TEXT. The one register sentence that quotes
// the parser (`oauthResourceMetadata` is not JSON (<message>)) needs the
// message word for word, so this is a JSON reader over UTF-16 units that
// fails where V8's JsonParser fails, with V8's message templates
// (`kJsonParse…` in messages.h, as Node 22 words them): the position in
// UTF-16 units, the line and column counted with `\r`, `\n` and `\r\n`
// each one break, and the unexpected-token context of ten units either
// side of the token once the source is 21 units or more.
// ---------------------------------------------------------------------------

struct Reader<'a> {
    s: &'a [u16],
    i: usize,
}

const MAX_CONTEXT: usize = 10;
const MIN_SOURCE_FOR_CONTEXT: usize = MAX_CONTEXT * 2 + 1;

fn is_digit(c: Option<u16>) -> bool {
    matches!(c, Some(d) if (0x30..=0x39).contains(&d))
}

impl Reader<'_> {
    fn peek(&self) -> Option<u16> {
        self.s.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(0x20 | 0x09 | 0x0a | 0x0d)) {
            self.i += 1;
        }
    }

    fn at(&self, template: &str, pos: usize) -> String {
        let (line, column) = line_and_column(self.s, pos);
        format!(
            "{template} in JSON at position {pos} (line {line} column \
             {column})"
        )
    }

    // `ReportUnexpectedToken()` for the character at `pos` (or the end).
    fn unexpected(&self, pos: usize) -> String {
        let Some(c) = self.s.get(pos).copied() else {
            return "Unexpected end of JSON input".into();
        };
        let source = String::from_utf16_lossy(self.s);
        if ["NaN", "Infinity", "undefined", "[object Object]"]
            .contains(&source.as_str())
        {
            return format!("\"{source}\" is not valid JSON");
        }
        let token = String::from_utf16_lossy(&[c]);
        let length = self.s.len();
        if length < MIN_SOURCE_FOR_CONTEXT {
            return format!(
                "Unexpected token '{token}', \"{source}\" is not valid JSON"
            );
        }
        let start = pos.saturating_sub(MAX_CONTEXT);
        let end = if pos + MAX_CONTEXT < length {
            pos + MAX_CONTEXT
        } else {
            length
        };
        let part = String::from_utf16_lossy(&self.s[start..end]);
        let quoted = match (start > 0, end < length) {
            (false, _) => format!("\"{part}\"..."),
            (true, false) => format!("...\"{part}\""),
            (true, true) => format!("...\"{part}\"..."),
        };
        format!("Unexpected token '{token}', {quoted} is not valid JSON")
    }

    fn value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        match self.peek() {
            Some(0x22) => self.string().map(Value::String),
            Some(0x7b) => self.object(),
            Some(0x5b) => self.array(),
            Some(0x74) => self.literal("true", Value::Bool(true)),
            Some(0x66) => self.literal("false", Value::Bool(false)),
            Some(0x6e) => self.literal("null", Value::Null),
            Some(0x2d) => self.number(),
            c if is_digit(c) => self.number(),
            _ => Err(self.unexpected(self.i)),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, String> {
        for b in word.bytes() {
            if self.peek() == Some(u16::from(b)) {
                self.i += 1;
            } else {
                return Err(self.unexpected(self.i));
            }
        }
        Ok(value)
    }

    fn digits(&mut self) -> usize {
        let from = self.i;
        while is_digit(self.peek()) {
            self.i += 1;
        }
        self.i - from
    }

    fn number(&mut self) -> Result<Value, String> {
        let from = self.i;
        if self.peek() == Some(0x2d) {
            self.i += 1;
            if !is_digit(self.peek()) {
                return Err(self.at("No number after minus sign", self.i));
            }
        }
        if self.peek() == Some(0x30) {
            self.i += 1;
            if is_digit(self.peek()) {
                return Err(self.at("Unexpected number", self.i));
            }
        } else {
            self.digits();
        }
        if self.peek() == Some(0x2e) {
            self.i += 1;
            if self.digits() == 0 {
                return Err(self.at("Unterminated fractional number", self.i));
            }
        }
        if matches!(self.peek(), Some(0x65 | 0x45)) {
            self.i += 1;
            if matches!(self.peek(), Some(0x2b | 0x2d)) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(
                    self.at("Exponent part is missing a number", self.i)
                );
            }
        }
        let text = String::from_utf16_lossy(&self.s[from..self.i]);
        let n =
            text.parse::<i64>().ok().map(Number::from).or_else(|| {
                text.parse::<f64>().ok().and_then(Number::from_f64)
            });
        Ok(n.map(Value::Number).unwrap_or(Value::Null))
    }

    fn hex(&mut self) -> Result<u16, String> {
        let mut out: u16 = 0;
        for _ in 0..4 {
            let digit = self.peek().and_then(|c| {
                char::from_u32(u32::from(c)).and_then(|ch| ch.to_digit(16))
            });
            let Some(d) = digit else {
                return Err(self.at("Bad Unicode escape", self.i));
            };
            out = out * 16 + d as u16;
            self.i += 1;
        }
        Ok(out)
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut units: Vec<u16> = Vec::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(self.at("Unterminated string", self.i));
            };
            if c == 0x22 {
                self.i += 1;
                return Ok(String::from_utf16_lossy(&units));
            }
            if c == 0x5c {
                self.i += 1;
                let Some(e) = self.peek() else {
                    return Err(self.unexpected(self.i));
                };
                let mapped = match e {
                    0x22 | 0x5c | 0x2f => Some(e),
                    0x62 => Some(0x08),
                    0x66 => Some(0x0c),
                    0x6e => Some(0x0a),
                    0x72 => Some(0x0d),
                    0x74 => Some(0x09),
                    _ => None,
                };
                if let Some(m) = mapped {
                    units.push(m);
                    self.i += 1;
                } else if e == 0x75 {
                    self.i += 1;
                    units.push(self.hex()?);
                } else {
                    return Err(self.at("Bad escaped character", self.i));
                }
                continue;
            }
            if c < 0x20 {
                return Err(
                    self.at("Bad control character in string literal", self.i)
                );
            }
            units.push(c);
            self.i += 1;
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.i += 1;
        let mut out = Map::new();
        self.skip_ws();
        if self.peek() == Some(0x7d) {
            self.i += 1;
            return Ok(Value::Object(out));
        }
        if self.peek() != Some(0x22) {
            return Err(self.at("Expected property name or '}'", self.i));
        }
        loop {
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(0x3a) {
                return Err(self.at("Expected ':' after property name", self.i));
            }
            self.i += 1;
            let v = self.value()?;
            out.insert(key, v);
            self.skip_ws();
            match self.peek() {
                Some(0x2c) => {
                    self.i += 1;
                    self.skip_ws();
                    if self.peek() != Some(0x22) {
                        return Err(self.at(
                            "Expected double-quoted property name",
                            self.i,
                        ));
                    }
                }
                Some(0x7d) => {
                    self.i += 1;
                    return Ok(Value::Object(out));
                }
                _ => {
                    return Err(self.at(
                        "Expected ',' or '}' after property value",
                        self.i,
                    ));
                }
            }
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.i += 1;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(0x5d) {
            self.i += 1;
            return Ok(Value::Array(out));
        }
        loop {
            out.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(0x2c) => self.i += 1,
                Some(0x5d) => {
                    self.i += 1;
                    return Ok(Value::Array(out));
                }
                _ => {
                    return Err(self.at(
                        "Expected ',' or ']' after array element",
                        self.i,
                    ));
                }
            }
        }
    }
}

// V8's line and column of a position: `\r`, `\n` and `\r\n` each end a
// line.
fn line_and_column(s: &[u16], pos: usize) -> (usize, usize) {
    let mut line = 1;
    let mut start = 0;
    let mut i = 0;
    while i < pos.min(s.len()) {
        if s[i] == 0x0d {
            if s.get(i + 1) == Some(&0x0a) && i + 1 < pos {
                i += 1;
            }
            line += 1;
            start = i + 1;
        } else if s[i] == 0x0a {
            line += 1;
            start = i + 1;
        }
        i += 1;
    }
    (line, pos - start + 1)
}

/// `JSON.parse(text)`: the value, or V8's message for the text it refuses.
/// A lone surrogate in a string is read as U+FFFD, which no caller of this
/// reads.
#[tracing::instrument(level = "debug", skip(text))]
pub fn json_parse(text: &str) -> Result<Value, String> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let mut r = Reader { s: &units, i: 0 };
    let value = r.value()?;
    r.skip_ws();
    if r.i < units.len() {
        return Err(r.at("Unexpected non-whitespace character after JSON", r.i));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::json_parse;

    // Node 22's own messages, as `node -e 'JSON.parse(…)'` printed them.
    #[test]
    fn refuses_as_v8_does() {
        let cases = [
            ("abc", "Unexpected token 'a', \"abc\" is not valid JSON"),
            ("{", "Expected property name or '}' in JSON at position 1 (line 1 column 2)"),
            ("", "Unexpected end of JSON input"),
            ("1 2", "Unexpected non-whitespace character after JSON at position 2 (line 1 column 3)"),
            ("{\"a\":1,}", "Expected double-quoted property name in JSON at position 7 (line 1 column 8)"),
            ("\"x", "Unterminated string in JSON at position 2 (line 1 column 3)"),
            ("aaaaaaaaaaaaaaaaaaaaa", "Unexpected token 'a', \"aaaaaaaaaa\"... is not valid JSON"),
            ("[1,2,3,4,5,6,7,8,9,10,11,x,13,14,15]", "Unexpected token 'x', ...\"8,9,10,11,x,13,14,15\"... is not valid JSON"),
            ("[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,x]", "Unexpected token 'x', ...\",14,15,16,x]\" is not valid JSON"),
            ("{\r\n\"a\" x}", "Expected ':' after property name in JSON at position 7 (line 2 column 5)"),
            ("{\r\"a\":1\r x}", "Expected ',' or '}' after property value in JSON at position 9 (line 3 column 2)"),
            ("\"\\u00", "Bad Unicode escape in JSON at position 5 (line 1 column 6)"),
            ("\"\\x\"", "Bad escaped character in JSON at position 2 (line 1 column 3)"),
            ("01", "Unexpected number in JSON at position 1 (line 1 column 2)"),
            ("-", "No number after minus sign in JSON at position 1 (line 1 column 2)"),
            ("1.", "Unterminated fractional number in JSON at position 2 (line 1 column 3)"),
            ("1e", "Exponent part is missing a number in JSON at position 2 (line 1 column 3)"),
            ("Infinity", "\"Infinity\" is not valid JSON"),
            ("nul", "Unexpected end of JSON input"),
            ("nul!", "Unexpected token '!', \"nul!\" is not valid JSON"),
        ];
        for (text, message) in cases {
            assert_eq!(json_parse(text).unwrap_err(), message, "{text:?}");
        }
    }
}
