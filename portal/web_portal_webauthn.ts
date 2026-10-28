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
  // Feature-detected and best-effort. ONCE PER LANE (#643): `#wa-signal-pqc`
  // carries the post-quantum lane's own handle, name and ids, sent apart.
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
   * The server's fallback facts (#944) a `#wa-data` element carries, as
   * `data-fallback`; empty where it carries none.
   *
   * @param d - the element
   * @returns the facts
   */
  static fallbackOf(d: Json): Json {
    try {
      return JSON.parse(d.getAttribute('data-fallback') || '{}') || {};
    } catch (e) {
      // Markup this page did not draw: no facts, and the failure is sent.
      return {};
    }
  }

  // THE GUIDANCE'S REPORT (#961). `offerFallback()` calls this only when it
  // is about to show `#wa-fallback`. The finish must hear the failure — the
  // ceremony log is that post — and the page must not be replaced: `submit()`
  // draws whatever the account API answers, and an answer with a view is a
  // new document in which the guidance was never unhidden. So this does not
  // write `#wa-credential` and does not hand `#wa-form` to `submit`. The body
  // is the sign-in screen's: `credential` is the JSON of `{ error,
  // capabilities }`. `capabilities` is null where the platform reported
  // none, never left out — `JSON.stringify` drops `undefined`, and a body
  // with no such property is the ordinary refusal, which is abandoned.
  // `quiet` is the runtime's post, which carries the same DPoP proof a form
  // submit would and then ignores the answer. Without it (no runtime) the
  // post is a fetch of the form's action, also ignored: a `web_` module has
  // no logger, and drawing or rejecting here would replace the guidance.
  /**
   * Reports a registration the guidance is showing, without submitting it.
   *
   * @param doc - the document
   * @param window - the window
   * @param quiet - the runtime's post, given the form and the body
   * @param error - the allowlisted browser error
   * @param capabilities - the platform's booleans, or null
   * @returns nothing
   */
  static reportKept(doc: Json, window: Json,
                    quiet: ((form: Json, body: Json) => void) | undefined,
                    error: string, capabilities: Json): void {
    const form = doc.getElementById('wa-form');
    if (!form) {
      return;
    }
    const caps = capabilities === undefined ? null : capabilities;
    const body = { credential: JSON.stringify({ error: error,
                                                capabilities: caps }) };
    if (typeof quiet === 'function') {
      quiet(form, body);
      return;
    }
    const action = form.getAttribute ? String(form.getAttribute('action') ||
                                              '') : '';
    if (!action || !window || typeof window.fetch !== 'function') {
      return;
    }
    let posted: Json = null;
    try {
      posted = window.fetch(action, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Accept': 'application/json',
                   'Content-Type': 'application/json' },
        body: JSON.stringify(body) });
    } catch (e) {
      // A web_ module logs nothing. The guidance is already shown; a throw
      // here rejects the click, and the browser may replace the page.
      return;
    }
    if (posted && typeof posted.then === 'function') {
      posted.then(function (): void {
        return undefined;
      }, function (): void {
        // The answer is ignored on purpose (#961). Logging is not available
        // in this bundle, and there is nothing further to draw.
        return undefined;
      });
    }
  }

  /**
   * Wires the page just drawn: the signal, and the ceremony button, whose
   * answer goes in `#wa-credential` and whose form is handed to `submit`.
   * A registration the guidance handles is reported through `quiet` instead,
   * which must not draw the answer (#961).
   *
   * @param doc - the document
   * @param window - the window
   * @param submit - the runtime's submit, given the form
   * @param quiet - the runtime's report of a failure the guidance shows,
   *   given the form and the body; absent, the report is a fetch of the
   *   form's action whose answer is ignored
   * @returns nothing
   */
  static wire(doc: Json, window: Json, submit: (form: Json) => void,
              quiet?: (form: Json, body: Json) => void): void {
    PortalWebAuthn.signal(doc.getElementById('wa-signal'), window);
    PortalWebAuthn.signal(doc.getElementById('wa-signal-pqc'), window);
    const d = doc.getElementById('wa-data');
    const go = doc.getElementById('wa-go');
    if (!d || (!go && d.getAttribute('data-autostart') !== '1')) {
      return;
    }
    // STARTED ON DRAW OR ON THE BUTTON (rcbj, 2026-10-28): the Passkeys
    // page marks its ceremony `data-autostart`, because the call to action
    // a person pressed a moment ago is the request and a second button
    // beside it asked the same question twice. The activation's key step
    // and the device link still draw `#wa-go` and run on its click. One
    // function either way, so the two cannot drift.
    const run = function (event: Json): void {
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
        // A REGISTRATION THAT ASKED FOR ML-DSA AND FAILED ON THE DEVICE
        // (#944, #961). The guidance is shown in place. The failure is
        // reported through the finish, and `#wa-form` is not submitted:
        // submitting drew the account API's answer over the guidance, and
        // that answer abandoned the enrolment, so the classical retry was
        // gone. The report carries its own `capabilities` property, which
        // is how the finish tells it from the ordinary refusal. An error
        // the guidance does not handle is still sent as given, and that
        // one is abandoned.
        const facts = PortalWebAuthn.fallbackOf(d);
        const offer = d.getAttribute('data-mode') === 'create'
          ? WebWebAuthn.offerFallback(doc, window, e,
              { surface: 'portal', fallback: facts,
                report: function (error: string, capabilities: Json): void {
                  PortalWebAuthn.reportKept(doc, window, quiet, error,
                                            capabilities);
                } })
          : Promise.resolve(false);
        offer.then(function (shown: boolean): void {
          if (!shown) {
            send({ error: e && e.name });
          }
        });
      });
    };
    if (d.getAttribute('data-autostart') === '1') {
      run(null);
    } else {
      go.addEventListener('click', run);
    }
  }
}

export = PortalWebAuthn;
