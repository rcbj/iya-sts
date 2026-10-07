// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_providers.ts
//
// ---------------------------------------------------------------------------
// WHICH CREDENTIAL MANAGER SAVED A PASSKEY, BY ITS AAGUID (#470, 2026-10-06).
//
// The passkey management guidelines #470 follows name each passkey by the
// credential manager that holds it — "iCloud Keychain", "Google Password
// Manager", "Windows Hello" — because that is the name a person recognises
// when they open the password manager on their phone. The only name this
// service had was the model the FIDO Metadata Service lists, and only where
// the attestation chained to it; a synced passkey sends `none` (WebAuthn
// Level 3 section 5.4.7 allows it, and #105 recorded why `require-trusted`
// is therefore not product's default), so every one of them was listed as
// "security key".
//
// **THIS TABLE NAMES; IT PROVES NOTHING.** An AAGUID that did not arrive in a
// statement chaining to an anchor is the authenticator's own claim, which is
// why `webauthn_attestation.ts` will not let an AAGUID allow-list rest on one.
// A NAME is a different kind of use: it helps a person tell their own
// passkeys apart, and an authenticator that lies about its AAGUID only
// mislabels a row on its own owner's page. Nothing that DECIDES reads this
// file — not the attestation policy, not the issuance policy, not risk.
//
// **IT IS OUR OWN, SHORT, AND WRITTEN BY HAND.** The community list of
// provider AAGUIDs carries no licence (checked on #470), so it is not copied
// here; these are the identifiers the major credential managers publish,
// each cross-checked as a fact. A provider missing from this table is named
// by FIDO MDS where the attestation is trusted, and otherwise by its group
// ("Passkey" or "Security key") — `credentials.ts`'s `defaultKeyName()`.
//
// A DATA MODULE, and it requires nothing but the logger, so it can be loaded
// lazily from `common/credentials.ts` without joining the parent project's
// Kerberos COPY closure (`kerberos/CLAUDE.md`).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');

/**
 * Names the credential manager behind a passkey from the AAGUID in its
 * attested credential data.
 */
class PasskeyProviders {
  // AAGUID (lower-case, hyphenated) → the name the provider uses for itself.
  static readonly NAMES: Readonly<Record<string, string>> = Object.freeze({
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
    'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
    'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (Managed)',
    '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
    'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
    'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
    '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane',
    '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
    '50726f74-6f6e-5061-7373-50726f746f6e': 'Proton Pass',
    'fdb141b2-5d84-443e-8a35-4698c205a502': 'KeePassXC',
    'f3809540-7f14-49c1-a8b3-8f813b225541': 'Enpass'
  });

  /**
   * Answers the provider's name for an AAGUID, or '' when this table does
   * not know it.
   *
   * @param aaguid - a UUID string, either case, with or without hyphens
   * @returns the provider's name, or ''
   */
  static nameOf(aaguid: unknown): string {
    helpers.log.debug('Entering PasskeyProviders.nameOf().');
    const hex = String(aaguid || '').toLowerCase().replace(/-/g, '');
    if (!/^[0-9a-f]{32}$/.test(hex)) {
      helpers.log.debug('Leaving PasskeyProviders.nameOf(). Not an AAGUID.');
      return '';
    }
    const id = hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' +
      hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
    const name = PasskeyProviders.NAMES[id] || '';
    helpers.log.debug('Leaving PasskeyProviders.nameOf(). ' +
                      (name || 'Unknown.'));
    return name;
  }
}

export = PasskeyProviders;
