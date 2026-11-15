// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WebAuthn Level 3: the CBOR the ceremonies carry ([`cbor`]), the two
//! ceremonies as `authn/webauthn.js` checks them ([`ceremony`]), and the
//! attestation statements of section 8 as
//! `authn/webauthn_attestation.ts` verifies them ([`attestation`]). The
//! COSE signatures and the TPM structures beneath them are `sts-crypto`'s
//! (`common/crypto.js` section 10), and the certificate facts `sts-pki`'s.

pub mod attestation;
pub mod cbor;
pub mod ceremony;
pub mod enrolment;
pub mod metadata;
pub mod trust;
