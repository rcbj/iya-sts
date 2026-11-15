// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a destination is SENT (`common/audit_export.ts`'s static half):
//! the canonical event (`canonical()`), its redaction (`redact()`), a
//! webhook's template (`fillTemplate()`), the RFC 5424 line
//! (`syslogLine()`, `structuredData()`, `sdEscape()`, `token()`), and the
//! small readers (`ackUrl()`, `retryAfter()`, `parseMode()`, `safeWhy()`,
//! `classifyHttp()`, `transportOf()`, `portOf()`). All of it is Node's
//! bytes: a receiver deduplicating on the event id, or a parser keyed on
//! the structured-data element, sees no difference at the cutover.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;

use crate::js;

/// The fixed half of the redaction set (`ALWAYS_REDACT`).
pub const ALWAYS_REDACT: &[&str] = &[
    "password",
    "secret",
    "token",
    "authorization",
    "client_secret",
    "assertion",
    "access_token",
    "refresh_token",
    "id_token",
];

/// The longest body read back from a receiver.
pub const BODY_CAP: usize = 65536;

const NIL: &str = "-";

static TEMPLATE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\{([a-z_]+)\}").ok());

static URLS: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)https?://\S+").ok());

static BREAKS: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"[\r\n\t]+").ok());

static MODE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^0?[0-7]{3}$").ok());

/// What one attempt decided (`SendResult`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SendResult {
    pub ok: bool,
    /// `ok`, `ack-wait`, `transient`, `pause` or `permanent`.
    pub kind: String,
    pub disposition: String,
    pub code: String,
    pub why: String,
    #[serde(rename = "retryAfterMs")]
    pub retry_after_ms: f64,
    #[serde(rename = "ackId")]
    pub ack_id: Json,
}

impl SendResult {
    /// `failed(kind, code, why)`.
    #[tracing::instrument(level = "debug")]
    pub fn failed(kind: &str, code: &str, why: &str) -> SendResult {
        SendResult {
            ok: false,
            kind: kind.to_string(),
            disposition: "failed".to_string(),
            code: code.to_string(),
            why: why.to_string(),
            retry_after_ms: 0.0,
            ack_id: Json::Null,
        }
    }

    /// An accepted send, `accepted` or `transmitted`.
    #[tracing::instrument(level = "debug")]
    pub fn accepted(disposition: &str) -> SendResult {
        SendResult {
            ok: true,
            kind: "ok".to_string(),
            disposition: disposition.to_string(),
            code: String::new(),
            why: String::new(),
            retry_after_ms: 0.0,
            ack_id: Json::Null,
        }
    }
}

/// What `postHttp()` answers.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Posted {
    pub ok: bool,
    pub status: u16,
    pub code: String,
    pub why: String,
    pub retry_after_ms: f64,
    pub json: Json,
}

/// A number as JavaScript writes it into JSON: an integral value without a
/// fraction. A hot path (every exported event): no span.
pub(crate) fn js_num(f: f64) -> Json {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.007e15 {
        Json::from(f as i64)
    } else {
        serde_json::Number::from_f64(f).map(Json::Number).unwrap_or(Json::Null)
    }
}

/// `Number(value)`: `None` (absent) is `NaN`, `null` and `''` are 0. A hot
/// path: no span.
pub(crate) fn js_number(value: Option<&Json>) -> f64 {
    match value {
        None => f64::NAN,
        Some(Json::Null) => 0.0,
        Some(Json::Bool(b)) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Some(Json::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Json::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                return 0.0;
            }
            let numeric = t
                .trim_start_matches(['+', '-'])
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'));
            if !numeric {
                return f64::NAN;
            }
            t.parse::<f64>().unwrap_or(f64::NAN)
        }
        Some(Json::Array(a)) if a.is_empty() => 0.0,
        Some(_) => f64::NAN,
    }
}

/// `redact(value, names)`: every member whose name is in `names` (lower
/// case), at any depth, through arrays, becomes `[redacted]`. A hot path
/// (every attribute of every exported event): no span.
pub fn redact(value: &Json, names: &HashSet<String>) -> Json {
    match value {
        Json::Array(items) => {
            Json::Array(items.iter().map(|v| redact(v, names)).collect())
        }
        Json::Object(map) => {
            let mut out = Map::new();
            for key in js::keys_of(map) {
                let v = map.get(&key).cloned().unwrap_or(Json::Null);
                if names.contains(&key.to_lowercase()) {
                    out.insert(key, Json::from("[redacted]"));
                } else {
                    out.insert(key, redact(&v, names));
                }
            }
            Json::Object(out)
        }
        other => other.clone(),
    }
}

/// `redactNames(extra)`: the fixed names, `auditExport.redactKeys`, and a
/// destination's own comma-separated list.
#[tracing::instrument(level = "debug")]
pub fn redact_names(configured: &str, extra: &str) -> HashSet<String> {
    format!("{},{},{}", ALWAYS_REDACT.join(","), configured, extra)
        .split(',')
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty())
        .collect()
}

fn member_text(row: &Json, key: &str) -> String {
    row.get(key).and_then(Json::as_str).unwrap_or("").to_string()
}

/// What `canonical()` is handed beside the row.
#[derive(Debug, Clone, Default)]
pub struct CanonicalOptions {
    pub realm: String,
    pub origin: String,
    pub source: String,
    pub names: HashSet<String>,
    /// `Date.now()`, for a row with no instant.
    pub now: i64,
}

/// `canonical(row, opts)`: the event a destination receives, built at
/// delivery from the row read through the `AuditEvent` concept (a member
/// of the wrong type is absent).
#[tracing::instrument(level = "debug", skip_all)]
pub fn canonical(row: &Json, opts: &CanonicalOptions) -> Json {
    let detail = match row.get("detail") {
        Some(Json::Object(m)) => Json::Object(m.clone()),
        _ => Json::Object(Map::new()),
    };
    let sequence = row.get("seq").filter(|v| v.is_number()).cloned();
    let held_origin = member_text(row, "origin");
    let origin = if !opts.origin.is_empty() {
        opts.origin.clone()
    } else {
        held_origin
    };
    let at = match row.get("at").and_then(Json::as_f64) {
        Some(f) if f != 0.0 && f.is_finite() => f,
        _ => opts.now as f64,
    };
    let outcome = member_text(row, "outcome");
    let id_origin = if origin.is_empty() { "local" } else { &origin };
    let seq_text = match &sequence {
        Some(Json::Number(n)) => js::number_text(n),
        _ => "undefined".to_string(),
    };
    let client = if js::truthy(detail.get("client_id")) {
        detail["client_id"].clone()
    } else if js::truthy(detail.get("application")) {
        detail["application"].clone()
    } else {
        Json::from("")
    };
    let mut out = Map::new();
    out.insert("id".into(), Json::from(format!("{}:{}", id_origin, seq_text)));
    if let Some(seq) = sequence {
        out.insert("seq".into(), seq);
    }
    let rest = json!({
        "origin": origin,
        "timestamp": js::iso(at as i64),
        "at": js_num(at),
        "severity": severity_name(&outcome),
        "category": member_text(row, "category"),
        "action": member_text(row, "action"),
        "outcome": outcome,
        "errorCode": member_text(row, "errorCode"),
        "source": opts.source,
        "realm": opts.realm,
        "subject": member_text(row, "actor"),
        "subjectForm": member_text(row, "actorForm"),
        "client": client,
        "address": member_text(row, "address"),
        "target": member_text(row, "target"),
        "protocol": member_text(row, "protocol"),
        "channel": member_text(row, "channel"),
        "message": member_text(row, "summary"),
        "attributes": redact(&detail, &opts.names),
    });
    if let Json::Object(m) = rest {
        out.extend(m);
    }
    Json::Object(out)
}

/// `severityName()`: notice, warning or error.
#[tracing::instrument(level = "debug")]
pub fn severity_name(outcome: &str) -> &'static str {
    match outcome {
        "success" => "notice",
        "refused" => "warning",
        _ => "error",
    }
}

/// `severityNumber()`: RFC 5424's 5, 4 or 3.
#[tracing::instrument(level = "debug")]
pub fn severity_number(outcome: &str) -> i64 {
    match outcome {
        "success" => 5,
        "refused" => 4,
        _ => 3,
    }
}

/// `fillTemplate()`: one pass over `{name}` placeholders; an unknown one is
/// left as written, and a value holding `{message}` is not expanded again.
#[tracing::instrument(level = "debug", skip(event))]
pub fn fill_template(template: &str, event: &Json) -> String {
    let field = |k: &str| js::text_if_truthy(event.get(k));
    let value = |key: &str| -> Option<String> {
        Some(match key {
            "timestamp" => field("timestamp"),
            "severity" => field("severity"),
            "event_type" => field("action"),
            "subject" => field("subject"),
            "message" => field("message"),
            "id" => field("id"),
            "realm" => field("realm"),
            "outcome" => field("outcome"),
            "category" => field("category"),
            "target" => field("target"),
            "address" => field("address"),
            "origin" => field("origin"),
            "protocol" => field("protocol"),
            "channel" => field("channel"),
            _ => return None,
        })
    };
    match TEMPLATE.as_ref() {
        Some(re) => re
            .replace_all(template, |caps: &regex::Captures| {
                value(&caps[1]).unwrap_or_else(|| caps[0].to_string())
            })
            .into_owned(),
        None => template.to_string(),
    }
}

fn removed(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}' || (c as u32) < 0x20
}

/// `token(value, max)`: no spaces or controls, cut to `max`, `-` when
/// empty.
#[tracing::instrument(level = "debug")]
pub fn token(value: &str, max: usize) -> String {
    let clean: String = value.chars().filter(|c| !removed(*c)).collect();
    let cut = js::head16(&clean, max);
    if cut.is_empty() {
        NIL.to_string()
    } else {
        cut
    }
}

/// `hostToken(os)`: the hostname, spaces and controls removed.
#[tracing::instrument(level = "debug")]
pub fn host_token(hostname: &str) -> String {
    let clean: String = hostname.chars().filter(|c| !removed(*c)).collect();
    js::head16(&clean, 255)
}

/// `sdEscape()`: RFC 5424's three escapes.
#[tracing::instrument(level = "debug")]
pub fn sd_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"").replace(']', "\\]")
}

/// `structuredData()`: the `iyaAudit` element (a local name, not an IANA
/// SD-ID).
#[tracing::instrument(level = "debug", skip(event))]
pub fn structured_data(event: &Json) -> String {
    let parts: Vec<String> =
        ["id", "realm", "origin", "seq", "category", "outcome"]
            .iter()
            .map(|k| {
                format!("{}=\"{}\"", k, sd_escape(&js::text_or_empty(event.get(*k))))
            })
            .collect();
    format!("[iyaAudit {}]", parts.join(" "))
}

/// `clamp()`: `fallback` when not a number.
fn clamp(value: Option<&Json>, min: f64, max: f64, fallback: f64) -> f64 {
    let n = js_number(value);
    let used = if n.is_finite() { n } else { fallback };
    used.max(min).min(max)
}

/// `syslogLine(event, dest)`: one RFC 5424 message, no trailing newline.
/// `hostname` and `pid` are this process's.
#[tracing::instrument(level = "debug", skip(event, dest))]
pub fn syslog_line(
    event: &Json,
    dest: &Json,
    hostname: &str,
    pid: u32,
    now: i64,
) -> String {
    let facility = clamp(dest.get("facility"), 0.0, 23.0, 16.0) as i64;
    let outcome = event.get("outcome").and_then(Json::as_str).unwrap_or("");
    let pri = facility * 8 + severity_number(outcome);
    let at = if js::truthy(event.get("at")) {
        js_number(event.get("at")) as i64
    } else {
        now
    };
    let host = token(&host_token(hostname), 255);
    let app = token(&js::text_if_truthy(dest.get("appName")).to_string(), 48);
    let app = if js::truthy(dest.get("appName")) {
        app
    } else {
        token("iya-sts", 48)
    };
    let msgid = token(&js::text_if_truthy(event.get("action")).replace(' ', "_"), 32);
    let sd = structured_data(event);
    let mut msg: String = js::text_if_truthy(event.get("message"))
        .chars()
        .map(|c| if c == '\0' || c == '\r' || c == '\n' { ' ' } else { c })
        .collect();
    if msg.chars().any(|c| (c as u32) > 0x7f) {
        msg = format!("\u{feff}{}", msg);
    }
    let mut line = format!(
        "<{}>1 {} {} {} {} {} {}",
        pri,
        js::iso(at),
        host,
        app,
        pid,
        msgid,
        sd
    );
    if !msg.is_empty() {
        line.push(' ');
        line.push_str(&msg);
    }
    line
}

/// `ackUrl()`: the acknowledgement URL beside a HEC event URL, its query
/// and fragment dropped.
#[tracing::instrument(level = "debug")]
pub fn ack_url(event_url: &str) -> Result<String, String> {
    let mut url = url::Url::parse(event_url).map_err(|e| e.to_string())?;
    let path = url.path().to_string();
    let path = if let Some(head) = path.strip_suffix("/event") {
        format!("{}/ack", head)
    } else if path.ends_with("/collector") {
        format!("{}/ack", path)
    } else {
        format!("{}/ack", path.strip_suffix('/').unwrap_or(&path))
    };
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

/// `retryAfter(response)`: integer seconds or an HTTP-date, capped at an
/// hour; 0 when absent or past.
#[tracing::instrument(level = "debug")]
pub fn retry_after(header: Option<&str>, now: i64) -> f64 {
    let Some(text) = header.filter(|t| !t.is_empty()) else {
        return 0.0;
    };
    let t = text.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        let ms = t.parse::<f64>().unwrap_or(0.0) * 1000.0;
        return ms.min(3_600_000.0);
    }
    let Ok(when) = chrono::DateTime::parse_from_rfc2822(t) else {
        return 0.0;
    };
    let ms = (when.timestamp_millis() - now) as f64;
    if ms > 0.0 {
        ms.min(3_600_000.0)
    } else {
        0.0
    }
}

/// `parseMode()`: three octal digits; empty is `0o640`; `-1` when not
/// usable.
#[tracing::instrument(level = "debug")]
pub fn parse_mode(value: Option<&Json>) -> i64 {
    match value {
        None | Some(Json::Null) => return 0o640,
        Some(Json::String(s)) if s.is_empty() => return 0o640,
        Some(Json::Number(n)) if n.as_f64() == Some(0.0) => return 0o640,
        _ => {}
    }
    let text = js::text_or_empty(value).trim().to_string();
    if text.is_empty() || text == "0" {
        return 0o640;
    }
    if !MODE.as_ref().is_some_and(|re| re.is_match(&text)) {
        return -1;
    }
    i64::from_str_radix(&text, 8).unwrap_or(-1)
}

/// `safeWhy()`: no URL, no line break, at most 300 characters.
#[tracing::instrument(level = "debug")]
pub fn safe_why(text: &str) -> String {
    let mut out = text.to_string();
    if let Some(re) = URLS.as_ref() {
        out = re.replace_all(&out, "[url]").into_owned();
    }
    if let Some(re) = BREAKS.as_ref() {
        out = re.replace_all(&out, " ").into_owned();
    }
    let out = out.trim().to_string();
    if js::len16(&out) > 300 {
        format!("{}...", js::head16(&out, 297))
    } else {
        out
    }
}

/// `classifyHttp(posted, wantAck)`.
#[tracing::instrument(level = "debug", skip(posted))]
pub fn classify_http(posted: &Posted, want_ack: bool) -> SendResult {
    let status = posted.status;
    let or = |why: &str| {
        if posted.why.is_empty() {
            why.to_string()
        } else {
            posted.why.clone()
        }
    };
    let code_or = |code: &str| {
        if posted.code.is_empty() {
            code.to_string()
        } else {
            posted.code.clone()
        }
    };
    let result = |kind: &str, code: String, why: String, retry: f64| SendResult {
        ok: false,
        kind: kind.to_string(),
        disposition: "failed".to_string(),
        code,
        why,
        retry_after_ms: retry,
        ack_id: Json::Null,
    };
    if posted.code == codes::STS_AUDIT_0014.as_str()
        || (300..400).contains(&status)
    {
        return result(
            "pause",
            codes::STS_AUDIT_0014.as_str().into(),
            or("a redirect is not followed"),
            posted.retry_after_ms,
        );
    }
    if posted.code == codes::STS_CORE_0104.as_str() {
        return result(
            "pause",
            codes::STS_CORE_0104.as_str().into(),
            or("the CA file is unusable"),
            0.0,
        );
    }
    if (200..300).contains(&status) {
        let collector = posted.json.get("code");
        if js::truthy(collector) {
            return result(
                "pause",
                codes::STS_AUDIT_0007.as_str().into(),
                format!("the collector answered code {}",
                        js::text_or_empty(collector)),
                0.0,
            );
        }
        let ack = posted.json.get("ackId").filter(|v| !v.is_null());
        if let (true, Some(ack)) = (want_ack, ack) {
            return SendResult {
                ok: true,
                kind: "ack-wait".to_string(),
                disposition: "accepted".to_string(),
                code: String::new(),
                why: String::new(),
                retry_after_ms: 0.0,
                ack_id: ack.clone(),
            };
        }
        return SendResult::accepted("accepted");
    }
    if status == 400 {
        return result(
            "permanent",
            codes::STS_AUDIT_0015.as_str().into(),
            "the destination rejected the event".into(),
            0.0,
        );
    }
    if status == 401 || status == 403 {
        return result(
            "pause",
            codes::STS_AUDIT_0007.as_str().into(),
            format!("the destination answered {}", status),
            0.0,
        );
    }
    let answered = format!("the destination answered {}", status);
    if status == 429 || status == 408 || status >= 500 || status == 0 {
        return result(
            "transient",
            code_or(codes::STS_AUDIT_0007.as_str()),
            or(&answered),
            posted.retry_after_ms,
        );
    }
    result("pause", code_or(codes::STS_AUDIT_0007.as_str()), or(&answered), 0.0)
}

/// `transportOf()`: `udp` and `tls` as stored, anything else TCP.
#[tracing::instrument(level = "debug", skip(dest))]
pub fn transport_of(dest: &Json) -> &'static str {
    match dest.get("transport").and_then(Json::as_str) {
        Some("udp") => "udp",
        Some("tls") => "tls",
        _ => "tcp",
    }
}

/// `portOf()`: the port, or 6514 for TLS and 514 otherwise.
#[tracing::instrument(level = "debug", skip(dest))]
pub fn port_of(dest: &Json) -> u16 {
    let given = js_number(dest.get("port"));
    if given.is_finite() && given > 0.0 {
        return given as u16;
    }
    if transport_of(dest) == "tls" {
        6514
    } else {
        514
    }
}
