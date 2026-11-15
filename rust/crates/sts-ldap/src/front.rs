// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The front of the directory's socket: what node-ldapjs's server does
//! with the bytes a connection reads, before any handler of the service's
//! runs (`lib/server.js`'s `newConnection()` and `lib/messages/parser.js`,
//! created with the options `ldap/ldap_server.js` passes:
//! `routeAnonymousBinds`, `encodeErrorMessage`, `saslMechanisms:
//! ['EXTERNAL']`, `bindDnFromHandler`, `errorCloseDelay: 0`, and a handler
//! on the `''` route of every DN operation and on unbind, and no extended
//! operation).
//!
//! A [`Connection`] is fed what one read returned and answers [`Event`]s:
//!
//! * [`Event::Dispatch`] — a request for the service's handlers, as they
//!   would see it (a modify's object made a DN, a bind's name checked);
//! * [`Event::Write`] — an answer the library sends itself:
//!   `invalidDNSyntax` (34) for a bind, add, compare, delete or modify
//!   whose DN does not parse or is empty (add, compare), `authMethodNot
//!   Supported` (7) for a SASL mechanism other than the configured ones,
//!   and `protocolError` (2) "`<OID>` not supported" for every extended
//!   request; an abandon is answered with nothing;
//! * [`Event::Destroy`] — a PDU that does not decode, a response from the
//!   client, an unknown operation;
//! * [`Event::Thrown`] — the parser's own `assert` failing, which in Node
//!   escapes the read handler (and nothing more is read);
//! * [`Event::Stalled`] — never produced since the `rcbj/node-ldapjs`
//!   fork stopped looping for ever on a malformed SEQUENCE OF or DN
//!   (#1784): those are [`Event::Destroy`] now, in Node and here. The
//!   variant stays only while `sts-runtime`'s listener still matches it.
//!
//! Framing is the parser's: bytes are kept until the outer TLV is complete
//! (a first tag of 0x00 is never complete — the bytes are kept for ever),
//! any outer tag is accepted, PDUs that arrive together are decoded in
//! turn, and a destroyed connection still decodes — and dispatches — what
//! the same read held after the PDU that destroyed it.

use crate::ber::Reader;
use crate::dn::Dn;
use crate::fault::Fault;
use crate::js;
use crate::message::{Message, Operation, ResultMessage};

/// What the server is configured with.
#[derive(Debug, Clone)]
pub struct FrontOptions {
    /// The SASL mechanisms routed to the bind handlers.
    pub sasl_mechanisms: Vec<String>,
    /// Whether an answer's error message is sent as diagnosticMessage.
    pub encode_error_message: bool,
}

impl Default for FrontOptions {
    /// `ldap/ldap_server.js`'s.
    fn default() -> FrontOptions {
        FrontOptions {
            sasl_mechanisms: vec!["EXTERNAL".to_string()],
            encode_error_message: true,
        }
    }
}

/// What a read did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Dispatch(Box<Message>),
    Write(Vec<u8>),
    Destroy,
    /// Never produced (see the module comment).
    Stalled,
    Thrown(String),
}

/// One connection's parser and the library's answers.
#[derive(Debug)]
pub struct Connection {
    options: FrontOptions,
    buffer: Option<Vec<u8>>,
    destroyed: bool,
    halted: bool,
}

impl Connection {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(options: FrontOptions) -> Connection {
        Connection {
            options,
            buffer: None,
            destroyed: false,
            halted: false,
        }
    }

    /// Bytes held for a PDU not yet complete.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn pending(&self) -> usize {
        self.buffer.as_ref().map_or(0, Vec::len)
    }

    /// Whether the connection was destroyed (or halted).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn is_closed(&self) -> bool {
        self.destroyed || self.halted
    }

    /// Whether an exception escaped the read handler ([`Event::Thrown`]),
    /// after which nothing more is read.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    fn destroy(&mut self, events: &mut Vec<Event>) {
        if !self.destroyed {
            events.push(Event::Destroy);
        }
        self.destroyed = true;
    }

    fn write(&self, events: &mut Vec<Event>, bytes: Vec<u8>) {
        if !self.destroyed {
            events.push(Event::Write(bytes));
        }
    }

    /// `Parser.prototype.write(data)`, for one read.
    #[tracing::instrument(level = "debug", skip_all, fields(len = data.len()))]
    pub fn feed(&mut self, data: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        let mut input = data.to_vec();
        loop {
            let buf = match self.buffer.take() {
                Some(mut b) => {
                    b.extend_from_slice(&input);
                    b
                }
                None => input,
            };
            let mut ber = Reader::new(&buf);
            let found = match ber.read_sequence(None) {
                Ok(t) => t,
                Err(_) => {
                    self.destroy(&mut events);
                    None
                }
            };
            if !matches!(found, Some(t) if t != 0)
                || ber.remain() < ber.length()
            {
                self.buffer = Some(buf);
                return events;
            }
            let mut next = None;
            let whole = if ber.remain() > ber.length() {
                let cut = ber.offset() + ber.length();
                next = Some(js::subarray(&buf, cut, buf.len() as i64).to_vec());
                let mut again = Reader::new(js::subarray(&buf, 0, cut));
                // Node's `ber.readSequence()` and `assert.equal()` here
                // throw out of the read handler.
                if let Err(e) = again.read_sequence(None) {
                    events.push(Event::Thrown(e.message().to_string()));
                    self.halted = true;
                    return events;
                }
                if again.remain() != again.length() {
                    events.push(Event::Thrown(format!(
                        "{} == {}",
                        again.remain(),
                        again.length()
                    )));
                    self.halted = true;
                    return events;
                }
                again
            } else {
                ber
            };
            match Message::decode(&whole.sequence_to_reader()) {
                Ok(m) => self.on_message(m, &mut events),
                Err(Fault::Thrown(_)) => {
                    self.destroy(&mut events);
                    return events;
                }
            }
            match next {
                Some(n) => input = n,
                None => return events,
            }
        }
    }

    fn answer(
        &self,
        events: &mut Vec<Event>,
        m: &Message,
        op: u8,
        status: i32,
        error: &str,
    ) {
        let diag = if self.options.encode_error_message {
            error.to_string()
        } else {
            String::new()
        };
        let res = ResultMessage {
            message_id: m.message_id,
            protocol_op: op,
            status,
            diagnostic_message: diag,
            ..ResultMessage::default()
        };
        if let Ok(b) = res.to_ber() {
            self.write(events, b);
        }
    }

    /// The server's `'message'` listener.
    fn on_message(&mut self, mut m: Message, events: &mut Vec<Event>) {
        const INVALID_DN: i32 = 34;
        let checked = match &mut m.operation {
            Operation::Response(_) => {
                self.destroy(events);
                return;
            }
            Operation::Bind(b) => {
                Dn::parse_nullable(b.name.as_deref()).map(|_| true)
            }
            Operation::Add(a) => Ok(a.entry.is_some()),
            Operation::Compare(c) => Ok(c.entry.is_some()),
            Operation::Delete { entry } => Ok(entry.is_some()),
            Operation::Modify(md) => Dn::parse_nullable(md.object.as_deref())
                .map(|d| {
                    md.object_dn = Some(d);
                    true
                }),
            _ => Ok(true),
        };
        let invalid = match checked {
            Ok(ok) => !ok,
            Err(Fault::Thrown(_)) => true,
        };
        if invalid {
            let op = match m.protocol_op() {
                0x4a => 0x6b,
                o => o + 1,
            };
            self.answer(events, &m, op, INVALID_DN, "");
            return;
        }
        match &m.operation {
            Operation::Bind(b) => {
                if let Some(s) = &b.sasl {
                    if !self.options.sasl_mechanisms.contains(&s.mechanism) {
                        let error = format!(
                            "SASL mechanism {} is not supported",
                            js::json_string(&s.mechanism)
                        );
                        self.answer(events, &m, 0x61, 7, &error);
                        return;
                    }
                }
            }
            Operation::Extended(e) => {
                let error = format!("{} not supported", e.request_name);
                self.answer(events, &m, 0x78, 2, &error);
                return;
            }
            Operation::Abandon { .. } => return,
            _ => {}
        }
        events.push(Event::Dispatch(Box::new(m)));
    }
}
