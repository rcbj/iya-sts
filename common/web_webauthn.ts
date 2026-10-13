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
}

export = WebWebAuthn;
