// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Request and response controls as `@ldapjs/controls` 2.1.0 reads and
//! writes them (RFC 4511 section 4.1.11).
//!
//! `getControl()` reads the control's SEQUENCE with the message's reader
//! and its value with `@ldapjs/asn1` 1.2.0 ([`ReaderV1`]), and knows eight
//! OIDs. What a client sees from it, ported here:
//!
//! * a control with no value is refused (the connection destroyed) for
//!   paged results, persistent search, entry-change notification and the
//!   password policy request — their constructors require a value — and
//!   accepted for server-side sorting (an empty key list);
//! * the virtual list view request and response are ALWAYS refused: their
//!   constructors end in `throw Error('control is not enabled')`;
//! * a value is parsed only when its outer SEQUENCE is there (a value that
//!   does not start with one leaves the defaults), and a short field reads
//!   as `null` rather than failing;
//! * an unknown OID keeps its value's bytes, and re-encodes them through
//!   `toString()` — so a value that is not UTF-8 is sent back changed.
//!
//! Its functions are a hot path — every control of every request — and
//! carry no span (rust/DESIGN.md D3, section 4.5).

use crate::ber::{Reader, ReaderV1, Writer};
use crate::fault::{Fault, Outcome};
use crate::filter::JsStr;
use crate::js;

pub const PAGED_RESULTS: &str = "1.2.840.113556.1.4.319";
pub const PERSISTENT_SEARCH: &str = "2.16.840.1.113730.3.4.3";
pub const ENTRY_CHANGE_NOTIFICATION: &str = "2.16.840.1.113730.3.4.7";
pub const PASSWORD_POLICY: &str = "1.3.6.1.4.1.42.2.27.8.5.1";
pub const SORT_REQUEST: &str = "1.2.840.113556.1.4.473";
pub const SORT_RESPONSE: &str = "1.2.840.113556.1.4.474";
pub const VLV_REQUEST: &str = "2.16.840.1.113730.3.4.9";
pub const VLV_RESPONSE: &str = "2.16.840.1.113730.3.4.10";

/// One server-side sorting key (RFC 2891).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortKey {
    /// `None` is `null` (a short field).
    pub attribute_type: Option<String>,
    /// Absent, `null`, or a rule.
    pub ordering_rule: Option<Option<String>>,
    pub reverse_order: Option<bool>,
}

/// The password policy response value (draft-behera-ldap-password-policy),
/// each field present only when read; `Some(None)` is a `null` read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordPolicy {
    pub time_before_expiration: Option<Option<i32>>,
    pub grace_authns_remaining: Option<Option<i32>>,
    pub error: Option<Option<i32>>,
}

/// A control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// An OID `getControl()` does not know. `oid` is `undefined` for an
    /// empty control and `null` for a short one.
    Generic {
        oid: JsStr,
        criticality: bool,
        value: Option<Vec<u8>>,
    },
    PagedResults {
        criticality: bool,
        size: Option<i32>,
        cookie: Vec<u8>,
    },
    PersistentSearch {
        criticality: bool,
        change_types: Option<i32>,
        changes_only: bool,
        return_ecs: bool,
    },
    EntryChangeNotification {
        criticality: bool,
        change_type: Option<i32>,
        /// Present only for a modify-DN change (8).
        previous_dn: Option<JsStr>,
        /// Absent when the value was never parsed.
        change_number: Option<Option<i32>>,
    },
    PasswordPolicy {
        criticality: bool,
        value: PasswordPolicy,
    },
    /// `None` keys are `undefined`: a value present but without its outer
    /// SEQUENCE leaves the field unset.
    SortRequest {
        criticality: bool,
        keys: Option<Vec<SortKey>>,
    },
    SortResponse {
        result: Option<Option<i32>>,
        failed_attribute: Option<Option<String>>,
    },
}

fn needs_value() -> Fault {
    Fault::thrown("options.value must be a Buffer or Object")
}

impl Control {
    /// The control's OID, as `type`.
    pub fn oid(&self) -> JsStr {
        let s = |o: &str| JsStr::Str(o.to_string());
        match self {
            Control::Generic { oid, .. } => oid.clone(),
            Control::PagedResults { .. } => s(PAGED_RESULTS),
            Control::PersistentSearch { .. } => s(PERSISTENT_SEARCH),
            Control::EntryChangeNotification { .. } => {
                s(ENTRY_CHANGE_NOTIFICATION)
            }
            Control::PasswordPolicy { .. } => s(PASSWORD_POLICY),
            Control::SortRequest { .. } => s(SORT_REQUEST),
            Control::SortResponse { .. } => s(SORT_RESPONSE),
        }
    }

    pub fn criticality(&self) -> bool {
        match self {
            Control::Generic { criticality, .. }
            | Control::PagedResults { criticality, .. }
            | Control::PersistentSearch { criticality, .. }
            | Control::EntryChangeNotification { criticality, .. }
            | Control::PasswordPolicy { criticality, .. }
            | Control::SortRequest { criticality, .. } => *criticality,
            Control::SortResponse { .. } => false,
        }
    }

    /// `getControl(ber)`: `None` when the control's SEQUENCE cannot be
    /// read (the caller's loop then reads it again — Node's endless loop).
    pub fn read(ber: &mut Reader<'_>) -> Outcome<Option<Control>> {
        if ber.read_sequence(None)?.is_none() {
            return Ok(None);
        }
        let mut oid = JsStr::Undefined;
        let mut criticality = false;
        let mut value: Option<Vec<u8>> = None;
        if ber.length() != 0 {
            let end = ber.offset() + ber.length();
            oid = match ber.read_string(0x04)? {
                Some(s) => JsStr::Str(s),
                None => JsStr::Null,
            };
            if ber.offset() < end && ber.peek() == Some(0x01) {
                criticality = ber.read_boolean(0x01)?;
            }
            if ber.offset() < end {
                value = ber.read_bytes(0x04)?;
            }
        }
        let known = match &oid {
            JsStr::Str(s) => s.as_str(),
            _ => "",
        };
        Ok(Some(match known {
            PAGED_RESULTS => {
                let v = value.ok_or_else(needs_value)?;
                let mut size = Some(0);
                let mut cookie = Vec::new();
                let mut r = ReaderV1::new(&v);
                if is_truthy(r.read_sequence(None)?) {
                    size = r.read_int()?;
                    cookie = r.read_bytes(0x04)?.unwrap_or_default();
                }
                Control::PagedResults {
                    criticality,
                    size,
                    cookie,
                }
            }
            PERSISTENT_SEARCH => {
                let v = value.ok_or_else(needs_value)?;
                let mut out = (Some(15), true, true);
                let mut r = ReaderV1::new(&v);
                if is_truthy(r.read_sequence(None)?) {
                    let t = r.read_int()?;
                    let c = r.read_boolean(0x01)?;
                    let e = r.read_boolean(0x01)?;
                    out = (t, c, e);
                }
                Control::PersistentSearch {
                    criticality,
                    change_types: out.0,
                    changes_only: out.1,
                    return_ecs: out.2,
                }
            }
            ENTRY_CHANGE_NOTIFICATION => {
                let v = value.ok_or_else(needs_value)?;
                let mut change_type = Some(4);
                let mut previous_dn = None;
                let mut change_number = None;
                let mut r = ReaderV1::new(&v);
                if is_truthy(r.read_sequence(None)?) {
                    change_type = r.read_int()?;
                    if change_type == Some(8) {
                        previous_dn = Some(match r.read_string(0x04)? {
                            Some(s) => JsStr::Str(s),
                            None => JsStr::Null,
                        });
                    }
                    change_number = Some(r.read_int()?);
                }
                Control::EntryChangeNotification {
                    criticality,
                    change_type,
                    previous_dn,
                    change_number,
                }
            }
            PASSWORD_POLICY => {
                let v = value.ok_or_else(needs_value)?;
                let mut p = PasswordPolicy::default();
                let mut r = ReaderV1::new(&v);
                if is_truthy(r.read_sequence(None)?) {
                    if r.peek() == Some(0xa0) {
                        r.read_sequence(Some(0xa0))?;
                        if r.peek() == Some(0x80) {
                            p.time_before_expiration = Some(r.read_tag(0x80)?);
                        } else if r.peek() == Some(0x81) {
                            p.grace_authns_remaining = Some(r.read_tag(0x81)?);
                        }
                    }
                    if r.peek() == Some(0x81) {
                        p.error = Some(r.read_tag(0x81)?);
                    }
                }
                Control::PasswordPolicy {
                    criticality,
                    value: p,
                }
            }
            SORT_REQUEST => {
                let keys = match value {
                    None => Some(Vec::new()),
                    Some(v) => {
                        let mut r = ReaderV1::new(&v);
                        let mut keys = None;
                        if is_truthy(r.read_sequence(Some(0x30))?) {
                            let mut list = Vec::new();
                            let limit = crate::fault::pass_limit(v.len());
                            while is_truthy(r.read_sequence(Some(0x30))?) {
                                if list.len() > limit {
                                    return Err(Fault::Stalled);
                                }
                                let attribute_type = r.read_string(0x04)?;
                                let mut ordering_rule = None;
                                if r.peek() == Some(0x80) {
                                    ordering_rule = Some(r.read_string(0x80)?);
                                }
                                let mut reverse_order = None;
                                if r.peek() == Some(0x81) {
                                    reverse_order =
                                        Some(r.read_tag(0x81)? != Some(0));
                                }
                                list.push(SortKey {
                                    attribute_type,
                                    ordering_rule,
                                    reverse_order,
                                });
                            }
                            keys = Some(list);
                        }
                        keys
                    }
                };
                Control::SortRequest { criticality, keys }
            }
            SORT_RESPONSE => {
                let mut result = None;
                let mut failed_attribute = None;
                if let Some(v) = value {
                    let mut r = ReaderV1::new(&v);
                    if is_truthy(r.read_sequence(Some(0x30))?) {
                        result = Some(r.read_enumeration()?);
                        if r.peek() == Some(0x80) {
                            failed_attribute = Some(r.read_string(0x80)?);
                        }
                    }
                }
                Control::SortResponse {
                    result,
                    failed_attribute,
                }
            }
            VLV_REQUEST => {
                let v = value.ok_or_else(needs_value)?;
                let mut r = ReaderV1::new(&v);
                if is_truthy(r.read_sequence(None)?) {
                    r.read_int()?;
                    r.read_int()?;
                    if r.peek() == Some(0xa0)
                        && is_truthy(r.read_sequence(Some(0xa0))?)
                    {
                        r.read_int()?;
                        r.read_int()?;
                    }
                    if r.peek() == Some(0x81) {
                        r.read_string(0x81)?;
                    }
                }
                return Err(Fault::thrown("control is not enabled"));
            }
            VLV_RESPONSE => {
                let Some(v) = value else {
                    return Err(Fault::thrown("control not enabled"));
                };
                let mut r = ReaderV1::new(&v);
                if is_truthy(r.read_sequence(None)?) {
                    // `if (ber.peek(0x02))`: peek takes no argument, so any
                    // byte but 0 reads an integer.
                    if is_truthy(r.peek()) {
                        r.read_int()?;
                    }
                    if is_truthy(r.peek()) {
                        r.read_int()?;
                    }
                    r.read_enumeration()?;
                    r.read_bytes(0x04)?;
                }
                return Err(Fault::thrown("control not enabled"));
            }
            _ => Control::Generic {
                oid,
                criticality,
                value,
            },
        }))
    }

    /// `control.toBer(writer)` into the message's writer.
    pub fn write(&self, w: &mut Writer) -> Outcome<()> {
        w.start_sequence(0x30);
        let oid = self.oid();
        w.write_string(oid.truthy().unwrap_or(""), 0x04)?;
        w.write_boolean(self.criticality(), 0x01);
        let int = |n: Option<i32>| {
            n.ok_or_else(|| Fault::thrown("argument must be a Number"))
        };
        let mut inner = Writer::new();
        let wrote = match self {
            Control::Generic { value, .. } => {
                if let Some(v) = value {
                    w.write_string(&js::utf8(v), 0x04)?;
                }
                false
            }
            Control::PagedResults { size, cookie, .. } => {
                inner.start_sequence(0x30);
                inner.write_int(int(*size)?, 0x02);
                if cookie.is_empty() {
                    inner.write_string("", 0x04)?;
                } else {
                    inner.write_buffer(cookie, 0x04)?;
                }
                inner.end_sequence()?;
                true
            }
            Control::PersistentSearch {
                change_types,
                changes_only,
                return_ecs,
                ..
            } => {
                inner.start_sequence(0x30);
                inner.write_int(int(*change_types)?, 0x02);
                inner.write_boolean(*changes_only, 0x01);
                inner.write_boolean(*return_ecs, 0x01);
                inner.end_sequence()?;
                true
            }
            Control::EntryChangeNotification {
                change_type,
                previous_dn,
                change_number,
                ..
            } => {
                inner.start_sequence(0x30);
                inner.write_int(int(*change_type)?, 0x02);
                if let Some(p) = previous_dn.as_ref().and_then(JsStr::truthy) {
                    inner.write_string(p, 0x04)?;
                }
                if let Some(n) = change_number {
                    // `parseInt(changeNumber, 10)`: null is NaN, written 0.
                    inner.write_int(n.unwrap_or(0), 0x02);
                }
                inner.end_sequence()?;
                true
            }
            Control::PasswordPolicy { value: p, .. } => {
                if p.time_before_expiration.is_none()
                    && p.grace_authns_remaining.is_none()
                    && p.error.is_none()
                {
                    false
                } else {
                    inner.start_sequence(0x30);
                    if let Some(t) = p.time_before_expiration {
                        inner.start_sequence(0xa0);
                        inner.write_int(int(t)?, 0x80);
                        inner.end_sequence()?;
                    } else if let Some(g) = p.grace_authns_remaining {
                        inner.start_sequence(0xa0);
                        inner.write_int(int(g)?, 0x81);
                        inner.end_sequence()?;
                    }
                    if let Some(e) = p.error {
                        inner.write_int(int(e)?, 0x81);
                    }
                    inner.end_sequence()?;
                    true
                }
            }
            Control::SortRequest { keys, .. } => {
                let Some(keys) = keys else {
                    return Err(Fault::undefined_read("length"));
                };
                if keys.is_empty() {
                    false
                } else {
                    inner.start_sequence(0x30);
                    for k in keys {
                        inner.start_sequence(0x30);
                        let s = |v: &Option<String>| -> Outcome<String> {
                            v.clone().ok_or_else(|| {
                                Fault::thrown(
                                    "argument must be a string (was: object)",
                                )
                            })
                        };
                        inner.write_string(&s(&k.attribute_type)?, 0x04)?;
                        if let Some(r) = &k.ordering_rule {
                            inner.write_string(&s(r)?, 0x80)?;
                        }
                        if let Some(b) = k.reverse_order {
                            inner.write_boolean(b, 0x81);
                        }
                        inner.end_sequence()?;
                    }
                    inner.end_sequence()?;
                    true
                }
            }
            Control::SortResponse {
                result,
                failed_attribute,
            } => match result {
                None => false,
                Some(r) => {
                    inner.start_sequence(0x30);
                    let r = int(*r)?;
                    inner.write_enumeration(r);
                    if let Some(Some(f)) = failed_attribute {
                        if r != 0 && !f.is_empty() {
                            inner.write_string(f, 0x80)?;
                        }
                    }
                    inner.end_sequence()?;
                    true
                }
            },
        };
        if wrote {
            w.write_buffer(inner.bytes(), 0x04)?;
        }
        w.end_sequence()
    }
}

/// `if (ber.readSequence())`: a tag of 0 is false.
fn is_truthy(t: Option<u8>) -> bool {
    matches!(t, Some(t) if t != 0)
}
