// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The Rust home of the Kerberos family (#444; rust/DESIGN.md section 6's
//! Kerberos row and decision D1). Phase 2b ports the CODEC only — the
//! deterministic layer the KDC and the acceptor stand on, which knows
//! nothing about this service:
//!
//! | Module | Node file it ports |
//! |---|---|
//! | [`primitives`] | `kerberos/krb5_primitives.js` |
//! | [`asn1`] | `kerberos/krb5_asn1.js` |
//! | [`crypto`] | `kerberos/krb5_crypto.js` |
//! | [`messages`] | `kerberos/krb5_messages.js` |
//! | [`gss`] | `kerberos/krb5_gss.js` |
//! | [`spnego`] | `kerberos/krb5_spnego.js` (the RFC 4178 codec, not the negotiation) |
//! | [`fast`] | `kerberos/krb5_fast_codec.ts` |
//! | [`pkinit`] | `kerberos/krb5_pkinit_codec.ts` |
//! | [`kkdcp`] | the MS-KKDCP envelope `krb5_kdc.js` and `krb5_home.ts` read and write |
//!
//! **THE DER CODER IS NODE'S, NOT `rasn-kerberos`** (a deviation from the
//! design's table, argued in [`asn1`]): the compatible-upgrade rule makes
//! Node's verdicts the specification, and Node's coder is lenient in ways a
//! schema-driven decoder is not — a KerberosString that arrives as an
//! IA5String, a field order it does not check, a later duplicate field that
//! wins, a Latin-1 reading of a name that is not UTF-8. A strict decoder
//! would refuse captures and clients Node accepts.
//!
//! Not here, and phase 9's: the KDC, the acceptor, the principal database,
//! SPNEGO's negotiation, the replay cache and anything else that holds
//! state. The PAC and its NDR (`krb5_pac.js`, `krb5_ndr.js`) and the keytab
//! format (`krb5_keytab.ts`) are pure codecs too and are not yet ported.
//!
//! Proved against Node by `tests/node_vectors.rs` over
//! `krb5-codec-node.json` (`tests/tools/crypto-vectors.js`), and the other
//! way by `tests/rust_crypto_vectors.js` over `krb5-codec-rust.json`.

#![forbid(unsafe_code)]

pub mod asn1;
pub mod crypto;
pub mod error;
pub mod fast;
pub mod gss;
mod hex;
pub mod kkdcp;
pub mod messages;
pub mod pkinit;
pub mod primitives;
pub mod spnego;
pub mod time;

pub use error::{Krb5Error, Krb5Result};
