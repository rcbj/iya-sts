// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The embedded directory's model and operations (#444, phase 4): what
//! `ldap/ldap_server.js` and `common/domain_map.ts` do, without the socket
//! (`sts-ldap` is the wire) and without a store driver (`sts-store`'s,
//! reached through [`ports::DirectoryJournal`]).
//!
//! | Module | Node it ports |
//! |---|---|
//! | [`model`] | the generated tables (`ModelTables`), `learnName()`, `canonicalName()`, `SECRET_ATTRIBUTES` |
//! | [`entry`] | one stored entry |
//! | [`directory`] | the per-realm trees, `putEntry()`, the add, modify, delete, modify DN, compare and search handlers, and the group and owner rewrites they cause |
//! | [`matching`] | `ldap/ldap_matching.ts` over `@ldapjs/filter`'s leaves |
//! | [`read_policy`] | `ldap/directory_read_policy.ts` |
//! | [`uuid`] | `entryUUID`: `nameBasedUuid()`, `backfilledEntryUuid()` |
//! | [`domain_map`] | `common/domain_map.ts` |
//! | [`ports`] | what the directory asks of the rest of the service |
//! | [`error`] | a refusal: the ldapjs class, its result code, the sentence and the STS code |
//!
//! Proved against Node by `tests/node_vectors.rs` over `directory-node.json`
//! (`tests/tools/directory-vectors.js`), and the other way by
//! `tests/rust_crypto_vectors.js` over `directory-rust.json`.

#![forbid(unsafe_code)]

pub mod directory;
pub mod domain_map;
pub mod entry;
pub mod error;
pub mod matching;
pub mod model;
pub mod ports;
pub mod read_policy;
pub mod uuid;

pub use directory::{
    Change, Directory, Operation, Outcome, Request, SearchEntry,
};
pub use domain_map::{DomainMap, FromOptions};
pub use entry::{Attributes, Entry, EntryExt};
pub use error::LdapError;
pub use model::DirectoryModel;
