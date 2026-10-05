// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The log: bunyan JSON lines, as the Node service and its PEP write them.
//!
//! **The owner's condition on decision D3 (rust/DESIGN.md section 9) is that
//! the END RESULT of logging and tracing stays intact.** So this layer writes
//! exactly the line bunyan writes — `name`, `hostname`, `pid`, `level` (10,
//! 20, 30, 40, 50, 60), the event's other fields, `msg`, `time` (ISO 8601 to
//! the millisecond, `Z`) and `v: 0` — and it turns a function's
//! `#[tracing::instrument]` span into the two lines the parent project's
//! style rule writes by hand: `Entering NAME().` when the span opens and
//! `Leaving NAME().` when it closes, at `debug`. On a closed span rather than
//! an exited one, because an `async fn`'s span is entered and exited once per
//! poll and would otherwise say Entering a dozen times.
//!
//! An error code goes at the front of the message, as `tag()` puts it there
//! in Node — `tag(codes::STS_XPEP_0013)`, the constant from
//! [`crate::errors::codes`], in `tracing::error!("{}could not start", …)`.

use std::fmt;
use std::io::Write;
use std::sync::Mutex;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

/// bunyan's numeric levels.
fn bunyan_level(level: &Level) -> u8 {
    match *level {
        Level::TRACE => 10,
        Level::DEBUG => 20,
        Level::INFO => 30,
        Level::WARN => 40,
        Level::ERROR => 50,
    }
}

/// The lowest level written, from bunyan's names (`trace` … `fatal`). An
/// unknown name is `info`, every appconfig file's level.
pub fn parse_level(name: &str) -> u8 {
    match name.trim().to_ascii_lowercase().as_str() {
        "trace" => 10,
        "debug" => 20,
        "warn" => 40,
        "error" => 50,
        "fatal" => 60,
        _ => 30,
    }
}

/// The `[STS-…] ` prefix a coded log line starts with — the registry's own
/// format (`common/error_codes.js` `tag()`).
pub fn tag(code: impl AsRef<str>) -> String {
    format!("[{}] ", code.as_ref())
}

/// Collects an event's message and its other fields.
#[derive(Default)]
struct Fields {
    message: String,
    extra: serde_json::Map<String, serde_json::Value>,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.extra.insert(field.name().into(), value.into());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let text = format!("{:?}", value);
        if field.name() == "message" {
            self.message = text;
        } else {
            self.extra.insert(field.name().into(), text.into());
        }
    }
}

/// The layer. One per process; everything it writes goes to stdout, a line
/// at a time under one lock, so two threads cannot interleave a line.
pub struct BunyanLayer {
    name: String,
    hostname: String,
    pid: u32,
    min_level: u8,
    out: Mutex<Box<dyn Write + Send>>,
}

impl BunyanLayer {
    pub fn new(name: &str, min_level: u8) -> BunyanLayer {
        BunyanLayer::with_writer(name, min_level, Box::new(std::io::stdout()))
    }

    pub fn with_writer(
        name: &str,
        min_level: u8,
        out: Box<dyn Write + Send>,
    ) -> BunyanLayer {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|h| h.trim().to_string())
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "localhost".to_string());
        BunyanLayer {
            name: name.to_string(),
            hostname,
            pid: std::process::id(),
            min_level,
            out: Mutex::new(out),
        }
    }

    fn write(
        &self,
        level: u8,
        message: &str,
        extra: serde_json::Map<String, serde_json::Value>,
    ) {
        if level < self.min_level {
            return;
        }
        let mut line = serde_json::Map::new();
        line.insert("name".into(), self.name.clone().into());
        line.insert("hostname".into(), self.hostname.clone().into());
        line.insert("pid".into(), self.pid.into());
        line.insert("level".into(), level.into());
        for (key, value) in extra {
            line.insert(key, value);
        }
        line.insert("msg".into(), message.into());
        line.insert("time".into(), crate::time::iso_now().into());
        line.insert("v".into(), 0.into());
        let text = serde_json::Value::Object(line).to_string();
        // A poisoned lock means another thread panicked mid-write; the line
        // is still worth writing, so the guard is taken back.
        let mut out = match self.out.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Err(error) = writeln!(out, "{}", text) {
            // Nowhere left to report it but stderr.
            eprintln!("log line not written: {}", error);
        }
    }
}

impl<S> Layer<S> for BunyanLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.write(
            bunyan_level(event.metadata().level()),
            &fields.message,
            fields.extra,
        );
    }

    fn on_new_span(
        &self,
        attrs: &Attributes<'_>,
        _id: &Id,
        _ctx: Context<'_, S>,
    ) {
        if attrs.metadata().level() <= &Level::DEBUG {
            let message = format!("Entering {}().", attrs.metadata().name());
            self.write(20, &message, serde_json::Map::new());
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(&id) {
            if span.metadata().level() <= &Level::DEBUG {
                let message = format!("Leaving {}().", span.metadata().name());
                self.write(20, &message, serde_json::Map::new());
            }
        }
    }
}

/// Installs the bunyan layer as the process's subscriber. Called once, at
/// the top of `main`.
pub fn install(name: &str, min_level: u8) {
    let subscriber =
        tracing_subscriber::registry().with(BunyanLayer::new(name, min_level));
    if let Err(error) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("the log was already installed: {}", error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tracing::instrument(level = "debug")]
    fn decide_something() {
        tracing::info!(
            "{}said something",
            tag(crate::errors::codes::STS_XPEP_0013)
        );
    }

    #[test]
    fn writes_bunyan_lines_with_entering_and_leaving() {
        let captured = Captured::default();
        let layer =
            BunyanLayer::with_writer("pep", 20, Box::new(captured.clone()));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, decide_something);
        let text =
            String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["msg"], "Entering decide_something().");
        assert_eq!(lines[0]["level"], 20);
        assert_eq!(lines[1]["msg"], "[STS-XPEP-0013] said something");
        assert_eq!(lines[1]["level"], 30);
        assert_eq!(lines[2]["msg"], "Leaving decide_something().");
        let keys: Vec<&String> = lines[1].as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            ["name", "hostname", "pid", "level", "msg", "time", "v"]
        );
    }

    #[test]
    fn info_level_hides_the_function_lines() {
        let captured = Captured::default();
        let layer = BunyanLayer::with_writer(
            "pep",
            parse_level("info"),
            Box::new(captured.clone()),
        );
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, decide_something);
        let text =
            String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 1);
    }
}
