// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_webauthn.ts
//
// ---------------------------------------------------------------------------
// WHAT EVERY WEBAUTHN CEREMONY IN A BROWSER SHARES (#571, 2026-10-12).
//
// The portal ran its ceremonies in its own bundle since #568
// (`portal/web_portal_webauthn.ts`), and the sign-in screen runs its
// username-less passkey in its bundle since #571 (`authn/web_authn.ts`).
// Both read and write the same bytes the server reads: base64url without
// padding, and a credential's JSON form — `/authn/webauthn.js`'s, the
// script the server-drawn pages loaded, which both bundles replace for the
// pages they draw. So that part is one copy, here.
//
// Since #944 it also holds what both do when a registration that asked for
// ML-DSA fails on the device (`offerFallback()`, below).
//
// A `web_` MODULE: it requires nothing and logs nothing. It runs in a
// browser; a test drives it with stand-ins.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * Base64url and a credential's JSON form. A static utility class.
 */
class WebWebAuthn {
  /**
   * Base64url of bytes, no padding.
   *
   * @param b - an ArrayBuffer or a view
   * @returns the encoding
   */
  static b64u(b: Json): string {
    const bytes = new Uint8Array(b);
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return btoa(s).split('+').join('-').split('/').join('_')
      .split('=').join('');
  }

  /**
   * Bytes of a base64url string.
   *
   * @param s - the encoding
   * @returns the bytes
   */
  static bytes(s: string): Uint8Array {
    let t = String(s || '').split('-').join('+').split('_').join('/');
    while (t.length % 4) {
      t += '=';
    }
    const bin = atob(t);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  /**
   * A registration's answer, as the server reads it.
   *
   * @param c - the PublicKeyCredential
   * @returns the JSON form
   */
  static created(c: Json): Json {
    let ext = {};
    try {
      ext = c.getClientExtensionResults ? c.getClientExtensionResults() : {};
    } catch (e) {
      // A browser that throws here still has a credential to post (#912):
      // the registration goes on without the extension results, and the
      // server records what it cannot read from them (credProps, so the
      // key's discoverability) as unknown, which is all it would know.
      ext = {};
    }
    return { id: c.id, rawId: WebWebAuthn.b64u(c.rawId), type: c.type,
      authenticatorAttachment: c.authenticatorAttachment || null,
      clientExtensionResults: ext, response: {
        clientDataJSON: WebWebAuthn.b64u(c.response.clientDataJSON),
        transports: c.response.getTransports ? c.response.getTransports()
                                             : [],
        attestationObject: WebWebAuthn.b64u(c.response.attestationObject)
      } };
  }

  /**
   * An assertion's answer, as the server reads it.
   *
   * @param a - the PublicKeyCredential
   * @returns the JSON form
   */
  static asserted(a: Json): Json {
    return { id: a.id, rawId: WebWebAuthn.b64u(a.rawId), type: a.type,
      authenticatorAttachment: a.authenticatorAttachment || null,
      response: {
        clientDataJSON: WebWebAuthn.b64u(a.response.clientDataJSON),
        authenticatorData: WebWebAuthn.b64u(a.response.authenticatorData),
        signature: WebWebAuthn.b64u(a.response.signature),
        userHandle: a.response.userHandle
          ? WebWebAuthn.b64u(a.response.userHandle) : null } };
  }

  // ---------------------------------------------------------------------------
  // WHEN A REGISTRATION THAT ASKED FOR ML-DSA FAILS ON THE DEVICE (#944).
  //
  // The list is ML-DSA first, and a platform may fail the whole ceremony when
  // offered an algorithm its authenticator cannot do, rather than take the
  // next one. WebAuthn Level 3 section 5.1.3 names `NotSupportedError` for
  // "no offered algorithm is supported"; what a platform says when an
  // authenticator refuses part-way is less specific — `NotAllowedError` is
  // also a cancelled prompt and a timeout, and `UnknownError` is anything —
  // so those two are UNCERTAIN, and the page words its guidance as "if".
  //
  // Both pages draw the guidance HIDDEN (`#wa-fallback`, with
  // `#wa-fallback-unsupported`, `#wa-fallback-uncertain` and
  // `#wa-fallback-hybrid` inside it) in their own language, from what the
  // server said the realm allows: a retry with the classical algorithms only
  // — a form the server refuses again where the realm forbids it
  // (STS-AUTHN-0420) — or the sentence that this device cannot make the key
  // the realm requires. This runtime only decides which parts to show.
  //
  // WHAT THE PLATFORM REPORTS, where it reports anything:
  // `PublicKeyCredential.getClientCapabilities()` (Level 3 section 5.1.7),
  // feature-detected. It has no member for an algorithm, so it cannot say
  // beforehand whether ML-DSA will work; what it does say that helps is
  // `hybridTransport` — whether the browser can make the passkey on a phone
  // or another device nearby — and the hybrid line is shown only then. The
  // whole record goes with the failure to `reportCeremonyFailure()`.
  // ---------------------------------------------------------------------------
  /**
   * How a failed registration's error reads (#944): `unsupported` for
   * `NotSupportedError`, `uncertain` for `NotAllowedError` and
   * `UnknownError`, '' for anything else.
   *
   * @param name - the error's name
   * @returns the kind, or ''
   */
  static failureKind(name: string): string {
    const n = String(name || '');
    if (n === 'NotSupportedError') {
      return 'unsupported';
    }
    return n === 'NotAllowedError' || n === 'UnknownError' ? 'uncertain' : '';
  }

  /**
   * What the platform reports about itself, where it reports anything:
   * `PublicKeyCredential.getClientCapabilities()`, feature-detected.
   *
   * @param window - the browser's window
   * @returns the promise of the capability record, or of null
   */
  static capabilities(window: Json): Promise<Json> {
    const PKC = window && window.PublicKeyCredential;
    if (!PKC || typeof PKC.getClientCapabilities !== 'function') {
      return Promise.resolve(null);
    }
    try {
      return Promise.resolve(PKC.getClientCapabilities())
        .then(function (caps: Json): Json {
          return caps && typeof caps === 'object' ? caps : null;
        }, function (): Json {
          // A platform that rejects the question has answered nothing.
          return null;
        });
    } catch (e) {
      // A platform that throws has answered nothing either.
      return Promise.resolve(null);
    }
  }

  // THE CEREMONY-FAILURE REPORT (#952): the owning surface supplies the
  // existing authenticated ceremony operation as `send`. The only values
  // forwarded are an allowlisted DOMException name and capability booleans;
  // never the exception's free-text message.
  /**
   * Reports a ceremony that failed in the browser through its owning surface.
   *
   * @param report - `{ surface, ceremony, error, kind,
   *   capabilities, offered, retrying }`
   * @param send - the surface's authenticated ceremony operation
   * @returns nothing
   */
  static reportCeremonyFailure(report: Json,
      send?: (error: string, capabilities: Json) => void): void {
    const safe = report || {};
    const allowed = ['NotAllowedError', 'NotSupportedError',
      'InvalidStateError', 'SecurityError', 'AbortError', 'ConstraintError',
      'UnknownError', 'TimeoutError', 'OperationError', 'EncodingError',
      'NotReadableError', 'DataError', 'TypeError'];
    const name = allowed.indexOf(String(safe.error || '')) >= 0
      ? String(safe.error) : 'UnknownError';
    if (typeof send === 'function') {
      const capNames = ['conditionalCreate', 'conditionalGet',
        'hybridTransport', 'userVerifyingPlatformAuthenticator',
        'relatedOrigin', 'signalAllAcceptedCredentials',
        'signalCurrentUserDetails', 'signalUnknownCredential'];
      const caps: Json = {};
      capNames.forEach(function (key: string): void {
        if (safe.capabilities && safe.capabilities[key] === true) {
          caps[key] = true;
        }
      });
      send(name, Object.keys(caps).length ? caps : null);
    }
  }

  /**
   * Shows the page's guidance after a registration failed (#944), where the
   * page drew one and the error is one it is for; the failure is reported
   * either way it is handled.
   *
   * @param doc - the document
   * @param window - the window
   * @param error - what the ceremony threw
   * @param said - `{ surface, fallback }`: the page's surface and the
   *   server's fallback facts
   * @returns the promise of whether the guidance was shown, in place of
   *   sending the failure on
   */
  static offerFallback(doc: Json, window: Json, error: Json,
                       said: Json): Promise<boolean> {
    const name = String((error && error.name) || '');
    const kind = WebWebAuthn.failureKind(name);
    const block = doc && doc.getElementById &&
                  doc.getElementById('wa-fallback');
    const facts = (said && said.fallback) || {};
    return WebWebAuthn.capabilities(window).then(function (caps: Json) {
      if (!kind || !block) {
        return false;
      }
      WebWebAuthn.reportCeremonyFailure({
        surface: String((said && said.surface) || ''),
        ceremony: 'create', error: name,
        kind: kind,
        capabilities: caps, offered: facts.asksPostQuantum === true
          ? 'post-quantum-first' : 'classical',
        retrying: facts.retrying === true }, said && said.report);
      const show = function (id: string): void {
        const el = doc.getElementById(id);
        if (el) {
          el.hidden = false;
        }
      };
      show('wa-fallback-' + kind);
      if (caps && caps.hybridTransport === true) {
        show('wa-fallback-hybrid');
      }
      block.hidden = false;
      return true;
    });
  }
}

export = WebWebAuthn;
