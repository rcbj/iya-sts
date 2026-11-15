// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! LDAPMessage (RFC 4511 section 4.2–4.14) as `@ldapjs/messages` 1.3.0
//! decodes and encodes it, with the `rcbj/node-ldapjs` fork's decoding of
//! a SASL bind (`lib/messages/sasl_bind.js`).
//!
//! [`Message::decode`] is `parseSaslBind(reader) || LdapMessage.parse(
//! reader)`: each request's `parseToPojo()`, then its constructor's checks
//! (which is where a bad entry DN, base DN, newRDN, scope, attribute list
//! or filter string is refused), then the controls. Responses a client
//! sends are decoded too, because whether one decodes decides whether the
//! next PDU in the same read is reached (the server then destroys the
//! connection either way). [`Message::to_ber`] is `toBer()`, and
//! [`ResultMessage`] is every response the service sends.
//!
//! Its functions are a hot path — every PDU — and carry no span
//! (rust/DESIGN.md D3, section 4.5).

use crate::attribute::{Attribute, Change};
use crate::ber::{Reader, Writer};
use crate::control::Control;
use crate::dn::Dn;
use crate::fault::{advanced, Fault, Outcome};
use crate::filter::{Filter, JsStr};
use crate::js;

pub const CANCEL_REQUEST: &str = "1.3.6.1.1.8";
pub const PASSWORD_MODIFY: &str = "1.3.6.1.4.1.4203.1.11.1";

/// A SASL bind's mechanism and credentials (RFC 4511 section 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sasl {
    pub mechanism: String,
    pub credentials: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    pub version: i32,
    /// The name as sent; `None` is a `null` read. The server checks it is
    /// a DN but hands the string on (Node's `req.name = …` hits a getter).
    pub name: Option<String>,
    /// The simple password; `None` is a `null` read.
    pub credentials: Option<String>,
    pub sasl: Option<Sasl>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub base_object: Dn,
    /// 0 base, 1 one level ("single"), 2 subtree.
    pub scope: u8,
    pub deref_aliases: i32,
    pub size_limit: i32,
    pub time_limit: i32,
    pub types_only: bool,
    /// The filter parsed back from its string form.
    pub filter: Filter,
    pub attributes: Vec<String>,
}

impl SearchRequest {
    pub fn scope_name(&self) -> &'static str {
        match self.scope {
            0 => "base",
            1 => "single",
            _ => "subtree",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddRequest {
    /// `None` when the entry was empty or unreadable: the server answers
    /// invalidDNSyntax.
    pub entry: Option<Dn>,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyRequest {
    /// The object as sent (`None` empty or unreadable); the server makes
    /// it a DN.
    pub object: Option<String>,
    /// Set by the server when the object parses.
    pub object_dn: Option<Dn>,
    pub changes: Vec<Change>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyDnRequest {
    pub entry: Dn,
    pub new_rdn: Dn,
    pub delete_old_rdn: bool,
    pub new_superior: Option<Dn>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareRequest {
    pub entry: Option<Dn>,
    pub attribute: String,
    pub value: String,
}

/// An extended request's value as the library decodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendedValue {
    /// No `requestValue`.
    Absent,
    /// An OID it does not know: the value as a string (`None` is null).
    Text(Option<String>),
    /// RFC 3909's cancelID.
    Cancel(i32),
    /// RFC 3062's three fields.
    PasswordModify {
        user_identity: JsStr,
        old_password: JsStr,
        new_password: JsStr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedRequest {
    pub request_name: String,
    pub request_value: ExtendedValue,
}

/// What a client sent that is a RESPONSE. Decoded only to learn whether it
/// decodes; the server destroys the connection either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResponse {
    pub protocol_op: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Bind(BindRequest),
    Search(SearchRequest),
    Add(AddRequest),
    Modify(ModifyRequest),
    ModifyDn(ModifyDnRequest),
    Compare(CompareRequest),
    Delete {
        /// `None` when unreadable: the server answers invalidDNSyntax.
        entry: Option<Dn>,
    },
    Extended(ExtendedRequest),
    Abandon {
        abandon_id: i32,
    },
    Unbind,
    Response(ClientResponse),
}

/// An LDAPMessage a client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub message_id: i32,
    pub operation: Operation,
    pub controls: Vec<Control>,
}

fn wrong_op(found: Option<u8>) -> Fault {
    match found {
        Some(f) => {
            Fault::thrown(format!("found wrong protocol operation: 0x{f:02x}"))
        }
        None => Fault::null_read("toString"),
    }
}

fn expect_op(ber: &mut Reader<'_>, op: u8) -> Outcome<()> {
    let found = ber.read_sequence(None)?;
    if found != Some(op) {
        return Err(wrong_op(found));
    }
    Ok(())
}

/// `/^[a-zA-Z][\w\d.;-]*$/` and its siblings: `isValidAttributeString()`.
fn valid_attribute_string(s: &str) -> bool {
    if matches!(s, "*" | "1.1" | "+") {
        return true;
    }
    let b = s.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    if b.first() == Some(&b'@')
        && b.get(1).is_some_and(u8::is_ascii_alphabetic)
        && b[2..].iter().all(|&c| word(c) || c == b'.' || c == b'-')
    {
        return true;
    }
    if b.first().is_some_and(u8::is_ascii_alphabetic)
        && b[1..]
            .iter()
            .all(|&c| word(c) || c == b'.' || c == b';' || c == b'-')
    {
        return true;
    }
    // `^[a-zA-Z][\w\d.-]*(;[\w\d.-]+)*;range=\d+-(\d+|\*)(;[\w\d.-]+)*$`
    let parts: Vec<&str> = s.split(';').collect();
    let token = |p: &str| {
        !p.is_empty() && p.bytes().all(|c| word(c) || c == b'.' || c == b'-')
    };
    let range = |p: &str| {
        let Some(r) = p.strip_prefix("range=") else {
            return false;
        };
        let Some((lo, hi)) = r.split_once('-') else {
            return false;
        };
        let digits =
            |d: &str| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit());
        digits(lo) && (hi == "*" || digits(hi))
    };
    let head = parts[0];
    head.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && head.bytes().all(|c| word(c) || c == b'.' || c == b'-')
        && parts[1..].iter().filter(|p| range(p)).count() == 1
        && parts[1..].iter().all(|p| range(p) || token(p))
}

/// The message-level controls loop: `while (ber.offset < end)`, with the
/// fork's guard (`parse-to-message.js`, and `sasl_bind.js`'s copy).
fn read_controls(ber: &mut Reader<'_>, out: &mut Vec<Control>) -> Outcome<()> {
    ber.read_sequence(None)?;
    let end = ber.offset() + ber.length();
    while ber.offset() < end {
        let before = ber.offset();
        if let Some(c) = Control::read(ber)? {
            out.push(c);
        }
        advanced(ber.offset(), before, "control")?;
    }
    Ok(())
}

impl Message {
    /// Decodes one LDAPMessage, its reader positioned at the SEQUENCE.
    pub fn decode(reader: &Reader<'_>) -> Outcome<Message> {
        let mut r = reader.clone();
        if let Some(m) = Message::decode_sasl_bind(&mut r)? {
            return Ok(m);
        }
        let mut ber = reader.clone();
        Message::decode_ldapjs(&mut ber)
    }

    /// The fork's `parseSaslBind()`: `Ok(None)` for any other message.
    fn decode_sasl_bind(ber: &mut Reader<'_>) -> Outcome<Option<Message>> {
        ber.read_sequence(None)?;
        let message_id = ber.read_int(0x02)?;
        if ber.peek() != Some(0x60) {
            return Ok(None);
        }
        ber.read_sequence(Some(0x60))?;
        let version = ber.read_int(0x02)?;
        let name = ber.read_string(0x04)?;
        if ber.peek() != Some(0xa3) {
            return Ok(None);
        }
        ber.read_sequence(Some(0xa3))?;
        let end = ber.offset() + ber.length();
        let Some(mechanism) = ber.read_string(0x04)? else {
            return Err(Fault::thrown(
                "malformed SaslCredentials: no mechanism",
            ));
        };
        let mut credentials = None;
        if ber.offset() < end {
            match ber.read_bytes(0x04)? {
                Some(b) => credentials = Some(b),
                None => {
                    return Err(Fault::thrown(
                        "malformed SaslCredentials: unreadable credentials",
                    ))
                }
            }
        }
        let mut controls = Vec::new();
        if ber.remain() > 0 && ber.peek() == Some(0xa0) {
            read_controls(ber, &mut controls)?;
        }
        Ok(Some(Message {
            message_id,
            operation: Operation::Bind(BindRequest {
                version,
                name,
                credentials: Some(String::new()),
                sasl: Some(Sasl {
                    mechanism,
                    credentials,
                }),
            }),
            controls,
        }))
    }

    /// `parseToMessage()`.
    fn decode_ldapjs(ber: &mut Reader<'_>) -> Outcome<Message> {
        ber.read_sequence(None)?;
        let message_id = ber.read_int(0x02)?;
        let op = ber.peek();
        let operation = match op {
            Some(0x60) => Message::bind(ber)?,
            Some(0x63) => Message::search(ber)?,
            Some(0x68) => Message::add(ber)?,
            Some(0x66) => Message::modify(ber)?,
            Some(0x6c) => Message::modify_dn(ber)?,
            Some(0x6e) => Message::compare(ber)?,
            Some(0x4a) => {
                let entry = ber.read_string(0x4a)?;
                Operation::Delete {
                    entry: match entry {
                        Some(s) => Some(Dn::parse(&s)?),
                        None => None,
                    },
                }
            }
            Some(0x77) => Message::extended(ber)?,
            Some(0x50) => Operation::Abandon {
                abandon_id: ber.read_int(0x50)?,
            },
            Some(0x42) => {
                expect_op(ber, 0x42)?;
                Operation::Unbind
            }
            Some(
                t @ (0x00 | 0x61 | 0x65 | 0x67 | 0x69 | 0x6b | 0x6d | 0x6f),
            ) => {
                result_from_client(ber, t)?;
                Operation::Response(ClientResponse { protocol_op: t })
            }
            Some(0x78) => {
                result_from_client(ber, 0x78)?;
                if ber.peek() == Some(0x8a) {
                    ber.read_string(0x8a)?;
                }
                if ber.peek() == Some(0x8b) && ber_read_tag_null(ber, 0x8b)? {
                    return Err(Fault::null_read("toString"));
                }
                Operation::Response(ClientResponse { protocol_op: 0x78 })
            }
            Some(0x64) => {
                expect_op(ber, 0x64)?;
                let object_name = ber.read_string(0x04)?.unwrap_or_default();
                ber.read_sequence(None)?;
                let end = ber.offset() + ber.length();
                while ber.offset() < end {
                    let before = ber.offset();
                    Attribute::read(ber)?;
                    advanced(ber.offset(), before, "attribute")?;
                }
                Dn::parse(&object_name)?;
                Operation::Response(ClientResponse { protocol_op: 0x64 })
            }
            Some(0x73) => {
                expect_op(ber, 0x73)?;
                let end = ber.offset() + ber.length();
                let mut uris = Vec::new();
                while ber.offset() < end {
                    let before = ber.offset();
                    let u = ber.read_string(0x04)?;
                    advanced(ber.offset(), before, "reference URI")?;
                    uris.push(u);
                }
                if uris.iter().any(Option::is_none) {
                    return Err(Fault::thrown(
                        "uri must be an array of strings",
                    ));
                }
                Operation::Response(ClientResponse { protocol_op: 0x73 })
            }
            Some(0x79) => {
                expect_op(ber, 0x79)?;
                let mut name = None;
                match ber.peek() {
                    Some(0x80) => {
                        name = ber.read_string(0x80)?;
                        if ber.peek() == Some(0x81) {
                            ber.read_string(0x81)?;
                        }
                    }
                    Some(0x81) => {
                        ber.read_string(0x81)?;
                    }
                    _ => {}
                }
                if let Some(n) = name {
                    let dotted = n.split('.').all(|p| {
                        !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
                    });
                    if !dotted {
                        return Err(Fault::thrown(
                            "responseName must be a numeric OID",
                        ));
                    }
                }
                Operation::Response(ClientResponse { protocol_op: 0x79 })
            }
            _ => {
                return Err(Fault::undefined_read("parseToPojo"));
            }
        };
        let mut controls = Vec::new();
        if ber.peek() == Some(0xa0) {
            read_controls(ber, &mut controls)?;
        }
        Ok(Message {
            message_id,
            operation,
            controls,
        })
    }

    fn bind(ber: &mut Reader<'_>) -> Outcome<Operation> {
        expect_op(ber, 0x60)?;
        let version = ber.read_int(0x02)?;
        let name = ber.read_string(0x04)?;
        let tag = ber.peek();
        if tag != Some(0x80) {
            return Err(match tag {
                Some(t) => Fault::thrown(format!(
                    "authentication 0x{t:02x} not supported"
                )),
                None => Fault::null_read("toString"),
            });
        }
        let credentials = ber.read_string(0x80)?;
        Ok(Operation::Bind(BindRequest {
            version,
            name,
            credentials,
            sasl: None,
        }))
    }

    fn search(ber: &mut Reader<'_>) -> Outcome<Operation> {
        expect_op(ber, 0x63)?;
        let base = ber.read_string(0x04)?;
        let scope = ber.read_enumeration()?;
        let deref_aliases = ber.read_enumeration()?;
        let size_limit = ber.read_int(0x02)?;
        let time_limit = ber.read_int(0x02)?;
        let types_only = ber.read_boolean(0x01)?;
        let tag = ber.peek();
        let raw = ber.read_raw_buffer(tag)?.ok_or_else(|| {
            Fault::thrown("Must supply a Buffer instance to read.")
        })?;
        let parsed = Filter::parse_ber(&mut Reader::new(raw))?;
        let filter_text = parsed.to_text()?;
        let mut attributes: Vec<Option<String>> = Vec::new();
        ber.read_sequence(None)?;
        let end = ber.offset() + ber.length();
        while ber.offset() < end {
            let before = ber.offset();
            let a = ber.read_string(0x04)?;
            advanced(ber.offset(), before, "attribute selector")?;
            attributes.push(a);
        }
        // The constructor, in its order.
        let base_object = Dn::parse(&base.unwrap_or_default())?;
        if !(0..=2).contains(&scope) {
            return Err(Fault::thrown(format!(
                "{scope} is an invalid search scope"
            )));
        }
        let filter = Filter::parse(&filter_text)?;
        let mut kept = Vec::new();
        for a in attributes {
            match a {
                Some(s) if valid_attribute_string(&s) => kept.push(s),
                Some(s) if s.is_empty() => {}
                _ => {
                    return Err(Fault::thrown(
                        "attribute must be a valid string",
                    ))
                }
            }
        }
        Ok(Operation::Search(SearchRequest {
            base_object,
            scope: scope as u8,
            deref_aliases,
            size_limit,
            time_limit,
            types_only,
            filter,
            attributes: kept,
        }))
    }

    fn add(ber: &mut Reader<'_>) -> Outcome<Operation> {
        expect_op(ber, 0x68)?;
        let entry = ber.read_string(0x04)?;
        let mut attributes = Vec::new();
        ber.read_sequence(None)?;
        let end = ber.offset() + ber.length();
        while ber.offset() < end {
            let before = ber.offset();
            let mut a = Attribute::read(ber)?;
            advanced(ber.offset(), before, "attribute")?;
            a.attr_type = a.attr_type.to_lowercase();
            attributes.push(a);
        }
        let entry = match entry {
            Some(s) if !s.is_empty() => Some(Dn::parse(&s)?),
            _ => None,
        };
        Ok(Operation::Add(AddRequest { entry, attributes }))
    }

    fn modify(ber: &mut Reader<'_>) -> Outcome<Operation> {
        expect_op(ber, 0x66)?;
        let object = ber.read_string(0x04)?;
        let mut changes = Vec::new();
        ber.read_sequence(None)?;
        let end = ber.offset() + ber.length();
        while ber.offset() < end {
            let before = ber.offset();
            let change = Change::read(ber)?;
            advanced(ber.offset(), before, "change")?;
            changes.push(change);
        }
        Ok(Operation::Modify(ModifyRequest {
            object: object.filter(|s| !s.is_empty()),
            object_dn: None,
            changes,
        }))
    }

    fn modify_dn(ber: &mut Reader<'_>) -> Outcome<Operation> {
        expect_op(ber, 0x6c)?;
        let entry = ber.read_string(0x04)?;
        let new_rdn = ber.read_string(0x04)?;
        let delete_old_rdn = ber.read_boolean(0x01)?;
        let mut new_superior = None;
        if ber.peek() == Some(0x80) {
            new_superior = ber.read_string(0x80)?;
        }
        let entry = Dn::parse(&entry.unwrap_or_default())?;
        let new_rdn = Dn::parse(&new_rdn.unwrap_or_default())?;
        let new_superior = match new_superior {
            Some(s) if !s.is_empty() => Some(Dn::parse(&s)?),
            _ => None,
        };
        Ok(Operation::ModifyDn(ModifyDnRequest {
            entry,
            new_rdn,
            delete_old_rdn,
            new_superior,
        }))
    }

    fn compare(ber: &mut Reader<'_>) -> Outcome<Operation> {
        expect_op(ber, 0x6e)?;
        let entry = ber.read_string(0x04)?;
        ber.read_sequence(None)?;
        let attribute = ber.read_string(0x04)?;
        let value = ber.read_string(0x04)?;
        let entry = match entry {
            Some(s) if !s.is_empty() => Some(Dn::parse(&s)?),
            _ => None,
        };
        Ok(Operation::Compare(CompareRequest {
            entry,
            attribute: attribute.unwrap_or_default(),
            value: value.unwrap_or_default(),
        }))
    }

    fn extended(ber: &mut Reader<'_>) -> Outcome<Operation> {
        expect_op(ber, 0x77)?;
        let name = ber.read_string(0x80)?;
        let request_name = name.clone().unwrap_or_default();
        if ber.peek() != Some(0x81) {
            return Ok(Operation::Extended(ExtendedRequest {
                request_name,
                request_value: ExtendedValue::Absent,
            }));
        }
        let request_value = match name.as_deref() {
            Some(CANCEL_REQUEST) => {
                ber.read_sequence(Some(0x81))?;
                ber.read_sequence(None)?;
                ExtendedValue::Cancel(ber.read_int(0x02)?)
            }
            Some(PASSWORD_MODIFY) => {
                ber.read_sequence(Some(0x81))?;
                ber.read_sequence(None)?;
                let mut field = |tag: u8| -> Outcome<JsStr> {
                    if ber.peek() == Some(tag) {
                        Ok(match ber.read_string(tag)? {
                            Some(s) => JsStr::Str(s),
                            None => JsStr::Null,
                        })
                    } else {
                        Ok(JsStr::Undefined)
                    }
                };
                let user_identity = field(0x80)?;
                let old_password = field(0x81)?;
                let new_password = field(0x82)?;
                ExtendedValue::PasswordModify {
                    user_identity,
                    old_password,
                    new_password,
                }
            }
            _ => ExtendedValue::Text(ber.read_string(0x81)?),
        };
        Ok(Operation::Extended(ExtendedRequest {
            request_name,
            request_value,
        }))
    }

    /// The protocolOp tag.
    pub fn protocol_op(&self) -> u8 {
        match &self.operation {
            Operation::Bind(_) => 0x60,
            Operation::Search(_) => 0x63,
            Operation::Add(_) => 0x68,
            Operation::Modify(_) => 0x66,
            Operation::ModifyDn(_) => 0x6c,
            Operation::Compare(_) => 0x6e,
            Operation::Delete { .. } => 0x4a,
            Operation::Extended(_) => 0x77,
            Operation::Abandon { .. } => 0x50,
            Operation::Unbind => 0x42,
            Operation::Response(r) => r.protocol_op,
        }
    }

    /// The message's type name, as node-ldapjs gives it.
    pub fn type_name(&self) -> &'static str {
        match &self.operation {
            Operation::Bind(_) => "BindRequest",
            Operation::Search(_) => "SearchRequest",
            Operation::Add(_) => "AddRequest",
            Operation::Modify(_) => "ModifyRequest",
            Operation::ModifyDn(_) => "ModifyDnRequest",
            Operation::Compare(_) => "CompareRequest",
            Operation::Delete { .. } => "DeleteRequest",
            Operation::Extended(_) => "ExtensionRequest",
            Operation::Abandon { .. } => "AbandonRequest",
            Operation::Unbind => "UnbindRequest",
            Operation::Response(_) => "Response",
        }
    }

    /// `toBer()`.
    pub fn to_ber(&self) -> Outcome<Vec<u8>> {
        let mut w = Writer::new();
        w.start_sequence(0x30);
        w.write_int(self.message_id, 0x02);
        match &self.operation {
            Operation::Bind(b) => {
                w.start_sequence(0x60);
                w.write_int(b.version, 0x02);
                w.write_string(b.name.as_deref().unwrap_or(""), 0x04)?;
                w.write_string(b.credentials.as_deref().unwrap_or(""), 0x80)?;
                w.end_sequence()?;
            }
            Operation::Search(s) => {
                w.start_sequence(0x63);
                w.write_string(&s.base_object.to_text(), 0x04)?;
                w.write_enumeration(i32::from(s.scope));
                w.write_enumeration(s.deref_aliases);
                w.write_int(s.size_limit, 0x02);
                w.write_int(s.time_limit, 0x02);
                w.write_boolean(s.types_only, 0x01);
                w.append(&s.filter.to_ber()?);
                w.start_sequence(0x30);
                for a in &s.attributes {
                    w.write_string(a, 0x04)?;
                }
                w.end_sequence()?;
                w.end_sequence()?;
            }
            Operation::Add(a) => {
                w.start_sequence(0x68);
                let entry = a
                    .entry
                    .as_ref()
                    .ok_or_else(|| Fault::null_read("toString"))?;
                w.write_string(&entry.to_text(), 0x04)?;
                w.start_sequence(0x30);
                for at in &a.attributes {
                    w.append(&at.to_ber()?);
                }
                w.end_sequence()?;
                w.end_sequence()?;
            }
            Operation::Modify(m) => {
                w.start_sequence(0x66);
                let object = match (&m.object_dn, &m.object) {
                    (Some(d), _) => d.to_text(),
                    (None, Some(s)) => s.clone(),
                    (None, None) => return Err(Fault::null_read("toString")),
                };
                w.write_string(&object, 0x04)?;
                w.start_sequence(0x30);
                for c in &m.changes {
                    w.append(&c.to_ber()?);
                }
                w.end_sequence()?;
                w.end_sequence()?;
            }
            Operation::ModifyDn(m) => {
                w.start_sequence(0x6c);
                w.write_string(&m.entry.to_text(), 0x04)?;
                w.write_string(&m.new_rdn.to_text(), 0x04)?;
                w.write_boolean(m.delete_old_rdn, 0x01);
                if let Some(s) = &m.new_superior {
                    w.write_string(&s.to_text(), 0x80)?;
                }
                w.end_sequence()?;
            }
            Operation::Compare(c) => {
                w.start_sequence(0x6e);
                let entry = c
                    .entry
                    .as_ref()
                    .ok_or_else(|| Fault::null_read("toString"))?;
                w.write_string(&entry.to_text(), 0x04)?;
                w.start_sequence(0x30);
                w.write_string(&c.attribute, 0x04)?;
                w.write_string(&c.value, 0x04)?;
                w.end_sequence()?;
                w.end_sequence()?;
            }
            Operation::Delete { entry } => {
                let entry = entry
                    .as_ref()
                    .ok_or_else(|| Fault::null_read("toString"))?;
                w.write_string(&entry.to_text(), 0x4a)?;
            }
            Operation::Extended(e) => {
                w.start_sequence(0x77);
                w.write_string(&e.request_name, 0x80)?;
                match &e.request_value {
                    ExtendedValue::Absent
                    | ExtendedValue::Text(None)
                    | ExtendedValue::Cancel(0) => {}
                    ExtendedValue::Text(Some(t)) if t.is_empty() => {}
                    v if e.request_name == CANCEL_REQUEST => {
                        w.start_sequence(0x81);
                        w.start_sequence(0x30);
                        match v {
                            ExtendedValue::Cancel(n) => w.write_int(*n, 0x02),
                            _ => {
                                return Err(Fault::thrown(
                                    "intToWrite must be a Number",
                                ))
                            }
                        }
                        w.end_sequence()?;
                        w.end_sequence()?;
                    }
                    ExtendedValue::PasswordModify {
                        user_identity,
                        old_password,
                        new_password,
                    } if e.request_name == PASSWORD_MODIFY => {
                        w.start_sequence(0x81);
                        w.start_sequence(0x30);
                        for (f, tag) in [
                            (user_identity, 0x80),
                            (old_password, 0x81),
                            (new_password, 0x82),
                        ] {
                            if let Some(s) = f.truthy() {
                                w.write_string(s, tag)?;
                            }
                        }
                        w.end_sequence()?;
                        w.end_sequence()?;
                    }
                    ExtendedValue::Text(Some(t)) => w.write_string(t, 0x81)?,
                    _ => {
                        return Err(Fault::thrown(
                            "stringToWrite must be a string",
                        ))
                    }
                }
                w.end_sequence()?;
            }
            Operation::Abandon { abandon_id } => w.write_int(*abandon_id, 0x50),
            Operation::Unbind => w.write_string("", 0x42)?,
            Operation::Response(_) => {
                return Err(Fault::thrown(
                    "a response from a client is not re-encoded",
                ))
            }
        }
        if !self.controls.is_empty() {
            w.start_sequence(0xa0);
            for c in &self.controls {
                c.write(&mut w)?;
            }
            w.end_sequence()?;
        }
        w.end_sequence()?;
        Ok(w.into_bytes())
    }
}

/// `readTag(tag)` of an extended response's value: whether it read `null`
/// (which Node then calls `toString()` on).
fn ber_read_tag_null(ber: &mut Reader<'_>, tag: u8) -> Outcome<bool> {
    match ber.read_raw_buffer(Some(tag)) {
        Ok(None) => Ok(true),
        Ok(Some(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// `LdapResult._parseToPojo()` of a result a client sent.
fn result_from_client(ber: &mut Reader<'_>, op: u8) -> Outcome<()> {
    expect_op(ber, op)?;
    ber.read_enumeration()?;
    ber.read_string(0x04)?;
    ber.read_string(0x04)?;
    if ber.peek() == Some(0xa3) {
        ber.read_sequence(Some(0xa3))?;
        // Node compares the absolute offset with the sequence's length.
        let end = ber.length();
        while ber.offset() < end {
            let before = ber.offset();
            ber.read_string(0x04)?;
            advanced(ber.offset(), before, "referral")?;
        }
    }
    Ok(())
}

/// A result the service sends (RFC 4511 section 4.1.9), or an extended
/// response (section 4.12).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResultMessage {
    pub message_id: i32,
    /// 0x61 bind, 0x65 searchResDone, 0x67 modify, 0x69 add, 0x6b delete,
    /// 0x6d modifyDN, 0x6f compare, 0x78 extended.
    pub protocol_op: u8,
    pub status: i32,
    pub matched_dn: String,
    pub diagnostic_message: String,
    pub referrals: Vec<String>,
    /// Written when non-empty (`if (this.responseName)`).
    pub response_name: Option<String>,
    /// Written when present, even empty.
    pub response_value: Option<String>,
}

impl ResultMessage {
    /// `LdapResult.toBer()`.
    pub fn to_ber(&self) -> Outcome<Vec<u8>> {
        let mut w = Writer::new();
        w.start_sequence(0x30);
        w.write_int(self.message_id, 0x02);
        w.start_sequence(self.protocol_op);
        w.write_enumeration(self.status);
        w.write_string(&self.matched_dn, 0x04)?;
        w.write_string(&self.diagnostic_message, 0x04)?;
        if !self.referrals.is_empty() {
            w.start_sequence(0xa3);
            for r in &self.referrals {
                w.write_string(r, 0x04)?;
            }
            w.end_sequence()?;
        }
        if self.protocol_op == 0x78 {
            if let Some(n) =
                self.response_name.as_deref().filter(|n| !n.is_empty())
            {
                w.write_string(n, 0x8a)?;
            }
            if let Some(v) = &self.response_value {
                w.write_string(v, 0x8b)?;
            }
        }
        w.end_sequence()?;
        w.end_sequence()?;
        Ok(w.into_bytes())
    }
}

/// A search result entry (section 4.5.2), as `SearchResultEntry.toBer()`
/// writes it: the name parsed and printed as a DN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchEntry {
    pub message_id: i32,
    pub object_name: String,
    pub attributes: Vec<Attribute>,
}

impl SearchEntry {
    pub fn to_ber(&self) -> Outcome<Vec<u8>> {
        let dn = Dn::parse(&self.object_name)?;
        let mut w = Writer::new();
        w.start_sequence(0x30);
        w.write_int(self.message_id, 0x02);
        w.start_sequence(0x64);
        w.write_string(&dn.to_text(), 0x04)?;
        w.start_sequence(0x30);
        for a in &self.attributes {
            w.append(&a.to_ber()?);
        }
        w.end_sequence()?;
        w.end_sequence()?;
        w.end_sequence()?;
        Ok(w.into_bytes())
    }
}

/// A search result reference (section 4.5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchReference {
    pub message_id: i32,
    pub uris: Vec<String>,
}

impl SearchReference {
    pub fn to_ber(&self) -> Outcome<Vec<u8>> {
        let mut w = Writer::new();
        w.start_sequence(0x30);
        w.write_int(self.message_id, 0x02);
        w.start_sequence(0x73);
        for u in &self.uris {
            w.write_string(u, 0x04)?;
        }
        w.end_sequence()?;
        w.end_sequence()?;
        Ok(w.into_bytes())
    }
}

/// The hex of a message, for logs and vectors.
pub fn hex(bytes: &[u8]) -> String {
    js::hex(bytes)
}
