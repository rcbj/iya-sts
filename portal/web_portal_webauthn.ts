// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_portal_webauthn.ts
//
// ---------------------------------------------------------------------------
// THE PORTAL'S WEBAUTHN CEREMONIES, IN ITS OWN BUNDLE (#568).
//
// The server-rendered portal loaded `/authn/webauthn.js` on the three pages
// that run a ceremony — `/portal/keys` (a passkey or a security key made),
// `/portal/activate` (a key instead of a password), `/portal/devices` (a
// platform credential linked to a device) — and that script finished by
// calling `form.submit()`. A static application cannot use it as it is: a
// native submit goes around the runtime to a path that is now the shell, and
// the ceremony's answer would never reach `/account-api`. So the part of
// that script the portal uses is here, reading the SAME markup — `#wa-data`
// with its `data-*`, the `#wa-go` button, the hidden `#wa-credential` in
// `#wa-form`, and `#wa-signal` — and handing the form to the runtime.
//
// What is ported, and nothing else: the create and get ceremonies with every
// parameter from `data-options` (the relying party, the algorithms, the
// authenticator selection, `excludeCredentials`, credProps and minPinLength,
// the hints, the attestation, the timeout), and the Signal API (WebAuthn
// Level 3 section 5.1.10). The sign-in screen's username-less passkey is
// that screen's own bundle's since #571 (`authn/web_authn.ts`); what both
// share is `common/web_webauthn.ts`.
//
// A `web_` MODULE: it requires only `common/web_webauthn.ts` and logs
// nothing. Its browser objects
// arrive as arguments, so a test drives it with stand-ins.
// ---------------------------------------------------------------------------

import WebWebAuthn = require('../common/web_webauthn');

type Json = any;

/**
 * The portal's WebAuthn ceremonies. A static utility class.
 */
class PortalWebAuthn {
  // THE BYTES AND THE JSON FORMS ARE `common/web_webauthn.ts`'s since #571,
  // which the sign-in screen's passkey shares; these names stay for the
  // portal's callers.
  static readonly b64u = WebWebAuthn.b64u;

  static readonly bytes = WebWebAuthn.bytes;

  static readonly created = WebWebAuthn.created;

  static readonly asserted = WebWebAuthn.asserted;

  /**
   * The ceremony a `#wa-data` element describes.
   *
   * @param d - the element
   * @param navigator - the browser's navigator
   * @returns the promise of the credential's JSON form
   */
  static ceremony(d: Json, navigator: Json): Promise<Json> {
    const challenge = PortalWebAuthn.bytes(d.getAttribute('data-challenge'));
    const rpId = d.getAttribute('data-rpid');
    const user = d.getAttribute('data-user');
    const allow = d.getAttribute('data-allow');
    const exclude = String(d.getAttribute('data-exclude') || '').split(',')
      .filter(function (id: string): boolean {
        return !!id;
      });
    let o: Json = {};
    try {
      o = JSON.parse(d.getAttribute('data-options') || '{}') || {};
    } catch (e) {
      o = {};
    }
    const sel = o.authenticatorSelection || { userVerification: 'preferred' };
    const algs = (o.algorithms && o.algorithms.length ? o.algorithms
                                                      : [-7, -257])
      .map(function (a: number): Json {
        return { type: 'public-key', alg: a };
      });
    if (d.getAttribute('data-mode') === 'create') {
      return navigator.credentials.create({ publicKey: {
        rp: o.rp || { name: 'IYA STS', id: rpId },
        // THE USER HANDLE (#474): random bytes the page names, never the
        // username — WebAuthn Level 3 section 5.4.3.
        user: { id: PortalWebAuthn.bytes(d.getAttribute('data-userid') || ''),
                name: user, displayName: d.getAttribute('data-display') ||
                                         user },
        challenge: challenge,
        pubKeyCredParams: algs,
        authenticatorSelection: sel,
        excludeCredentials: exclude.map(function (id: string): Json {
          return { type: 'public-key', id: PortalWebAuthn.bytes(id) };
        }),
        extensions: (o.credProps || o.minPinLength)
          ? Object.assign(o.credProps ? { credProps: true } : {},
                          o.minPinLength ? { minPinLength: true } : {})
          : undefined,
        hints: o.hints && o.hints.length ? o.hints : undefined,
        attestation: o.attestation || 'direct',
        timeout: o.timeout || 60000 } }).then(PortalWebAuthn.created);
    }
    return navigator.credentials.get({ publicKey: {
      challenge: challenge, rpId: o.rpId || rpId,
      allowCredentials: allow ? allow.split(',').map(function (id: string) {
        return { type: 'public-key', id: PortalWebAuthn.bytes(id) };
      }) : undefined,
      userVerification: o.userVerification || 'preferred',
      hints: o.hints && o.hints.length ? o.hints : undefined,
      timeout: o.timeout || 60000 } }).then(PortalWebAuthn.asserted);
  }

  // THE SIGNAL API (#470), WebAuthn Level 3 section 5.1.10: where the page
  // carries `#wa-signal`, the credential manager is told which of this
  // person's passkeys this service still accepts, and their name.
  // Feature-detected and best-effort.
  /**
   * Sends the signals a `#wa-signal` element describes.
   *
   * @param sg - the element
   * @param window - the browser's window
   * @returns nothing
   */
  static signal(sg: Json, window: Json): void {
    const PKC = window && window.PublicKeyCredential;
    if (!sg || !PKC) {
      return;
    }
    const rpId = sg.getAttribute('data-rpid');
    const userId = sg.getAttribute('data-userid');
    const quiet = function (): void {
      return undefined;
    };
    if (PKC.signalAllAcceptedCredentials) {
      PKC.signalAllAcceptedCredentials({ rpId: rpId, userId: userId,
        allAcceptedCredentialIds: String(sg.getAttribute('data-accepted') ||
                                         '').split(',')
          .filter(function (id: string): boolean {
            return !!id;
          }) }).catch(quiet);
    }
    if (PKC.signalCurrentUserDetails) {
      PKC.signalCurrentUserDetails({ rpId: rpId, userId: userId,
        name: sg.getAttribute('data-name'),
        displayName: sg.getAttribute('data-display') }).catch(quiet);
    }
  }

  /**
   * Wires the page just drawn: the signal, and the ceremony button, whose
   * answer goes in `#wa-credential` and whose form is handed to `submit`.
   *
   * @param doc - the document
   * @param window - the window
   * @param submit - the runtime's submit, given the form
   * @returns nothing
   */
  static wire(doc: Json, window: Json, submit: (form: Json) => void): void {
    PortalWebAuthn.signal(doc.getElementById('wa-signal'), window);
    const d = doc.getElementById('wa-data');
    const go = doc.getElementById('wa-go');
    if (!d || !go) {
      return;
    }
    go.addEventListener('click', function (event: Json): void {
      if (event && event.preventDefault) {
        event.preventDefault();
      }
      const send = function (payload: Json): void {
        const field = doc.getElementById('wa-credential');
        const form = doc.getElementById('wa-form');
        if (field) {
          field.value = JSON.stringify(payload);
        }
        if (form) {
          submit(form);
        }
      };
      PortalWebAuthn.ceremony(d, window.navigator).then(send, function (e) {
        send({ error: e && e.name, message: e && e.message });
      });
    });
  }
}

export = PortalWebAuthn;
