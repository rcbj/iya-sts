// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The embedded directory's LDAPv3 wire layer (#444): what the Node
//! service's directory (`ldap/ldap_server.js`, on the `rcbj/node-ldapjs`
//! fork) does with the bytes a client sends and what it sends back, so
//! that the Rust runtime answers every existing LDAP client as Node does
//! today — a compatible upgrade (rust/DESIGN.md D11). No I/O and no state
//! beyond one connection's unread bytes; the directory store, the access
//! rules and the server's handlers are not here.
//!
//! * [`ber`] — `@ldapjs/asn1`'s readers (2.0.0, and the 1.2.0 one control
//!   values are read with) and its writer;
//! * [`message`] — RFC 4511's PDUs: bind (simple and SASL), search,
//!   compare, add, modify, modify DN, delete, extended, abandon, unbind,
//!   and the results, entries and references the service sends;
//! * [`control`] — the controls `@ldapjs/controls` knows, and the rest;
//! * [`attribute`] — attributes and modifications;
//! * [`dn`] — RFC 4514 DNs as `@ldapjs/dn` parses, prints and compares
//!   them, and [`service_dn`] — the service's own DN string helpers;
//! * [`filter`] — RFC 4515 filters as `@ldapjs/filter` reads, prints,
//!   parses and writes them;
//! * [`front`] — the server's handling of a connection's reads, up to the
//!   handlers: framing, decoding, the answers the library sends itself;
//! * [`result_codes`] — the result codes and node-ldapjs's error classes.
//!
//! WHY NOT `ldap3_proto`. rust/DESIGN.md section 7 named Kanidm's codec.
//! It is a correct RFC 4511 codec, and that is the problem: node-ldapjs is
//! not one, and its bytes are what existing clients see. Measured against
//! the Node vectors (`tests/ldap3_compare.rs` counts every place), it
//! refuses PDUs Node accepts, accepts PDUs Node destroys the connection
//! for, prints neither filters nor DNs (the string forms are what the
//! handlers and the service's store see), and has none of the library's
//! rewriting (a filter's round trip through its string form, the modify
//! values' round trip through UTF-8, the lowercased add types). So every
//! piece is written here, ported from the JavaScript; `ldap3_proto` is a
//! dev-dependency only, for that comparison.
//!
//! Where node-ldapjs NEVER RETURNED — a SEQUENCE OF read that looped for
//! ever on bytes a client chose, which on Node stopped the whole process —
//! this crate used to close the connection instead. The `rcbj/node-ldapjs`
//! fork now throws there too (#1784), so the two agree and
//! `tests/node_vectors.rs` holds every case to Node's answer.

#![forbid(unsafe_code)]

pub mod attribute;
pub mod ber;
pub mod control;
pub mod dn;
pub mod fault;
pub mod filter;
pub mod front;
pub mod js;
pub mod message;
pub mod result_codes;
pub mod service_dn;

pub use dn::Dn;
pub use fault::Fault;
pub use filter::Filter;
pub use front::{Connection, Event, FrontOptions};
pub use message::{Message, Operation};
