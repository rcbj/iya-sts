// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! CERTIFICATE ENROLLMENT (#444, phase 6, the `enroll` slice):
//! `common/cert_enrollment.ts` (rule 3ag) and the three protocol families
//! over it — `acme/` (RFC 8555), `est/` (RFC 7030), `scep/` (RFC 8894).
//! Every certificate is issued by `sts-pki`'s
//! `Authority::issue_enrolled()`, which records it so OCSP and the CRL
//! know it. `common/CLAUDE.md`'s 3ag and the three directories'
//! `CLAUDE.md` are the design.
//!
//! | Module | Node it ports |
//! |---|---|
//! | [`core`] | `common/cert_enrollment.ts` |
//! | [`model`] | `common/enrollment_model.ts` over `models/generated/enrollment.json` |
//! | [`acme`] | `acme/acme.ts`, `acme_jws.ts`, `acme_store.ts` |
//! | [`est`] | `est/est.ts`, `est_codec.ts` |
//! | [`scep`] | `scep/scep.ts`, `scep_cms.ts`, `scep_ra.ts` |
//! | [`http`] | the request and answer every family reads and writes, and the routes |
//! | [`ports`] | one trait per module the core reads |
//! | [`wiring`] | what the runtime answers each port with |
//!
//! **NO CHALLENGE DIALS OUT.** Node implements no `http-01`, `dns-01` or
//! `tls-alpn-01`: an identifier is owned when it is registered on the
//! account's entry (`sts-entry-binding-01`, created valid), so this
//! service never fetches an address a caller supplied — `federation/`'s
//! dialed-URL rule holds for ACME by construction, here as there.
//!
//! The console pages (`acme_admin.ts`, `est_admin.ts`, `scep_admin.ts`)
//! and the `/admin-api/{acme,est,scep}` operations are the
//! management-API slice's: they answer no published protocol endpoint.

#![forbid(unsafe_code)]

pub mod acme;
pub mod core;
pub mod est;
pub mod http;
pub mod model;
pub mod monitor;
pub mod ports;
pub mod scep;
pub mod wiring;
