// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_spa_client.ts
//
// ---------------------------------------------------------------------------
// WHAT THE TWO STATIC APPLICATIONS SHARE AS OAUTH CLIENTS (#568).
//
// The admin console (#446) and the user portal (#568) are both static
// applications in the browser and both PUBLIC clients of this service's own
// authorization server: the authorization code flow with PKCE (S256), and
// every token bound by DPoP (RFC 9449) to a P-256 key the page makes
// NON-EXTRACTABLE — the condition rcbj attached to a public console, and to a
// public portal on #568. This class is that half, moved out of
// `ConsoleRuntime` verbatim when the portal became the second of them, so the
// two cannot drift into two readings of one RFC:
//
//   * the key and the proof (`ensureKey()`, `proof()`), a server's
//     `DPoP-Nonce` kept for the next proof (`keepNonce()`);
//   * the token endpoint (`tokenRequest()`), retried once on
//     `use_dpop_nonce`, and what it answered kept in memory only
//     (`keepTokens()`) — a reload signs in again, silently while the sign-on
//     session lasts;
//   * the authorization request (`authorizationRequestUrl()`), pushed first
//     where the realm requires it, and a JARM answer opened and checked
//     (`openAuthorizationResponse()`).
//
// What each application does with a page — routing, drawing, its forms —
// stays in its own runtime (`admin-ui/web_runtime.ts`,
// `portal/web_portal_runtime.ts`).
//
// IN `common/` SINCE #570 (it was `admin-ui/web_spa_client.ts`), with what a
// runtime needs whether or not it is a client — the address of a path, the
// query, fetch, forms, links — moved under it into `web_page.ts`, which the
// public surfaces of #569 stand on directly: they hold no token. Nothing in
// this class changed in the move; in particular the push still carries no
// DPoP proof and a JARM answer is still opened before anything in it is
// believed (both argued where they are below).
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires `web_page.ts`
// and nothing else, logs nothing, and is bundled for a browser by
// `build-typescript.sh`. Everything it touches in the browser arrives in
// `env`, so a test drives it in node.
// ---------------------------------------------------------------------------

import WebPage = require('./web_page');

type Json = any;

/**
 * What a static application's client is: its id, what it asks for and where
 * its own pages and API are.
 */
interface SpaClientOptions {
  // The registered public client.
  clientId: string;
  // The scope the authorization request asks for.
  scope: string;
  // The `data-sts-*` attributes of the shell's html element, by the first
  // path segment each stands for: `{ '/oauth2': 'data-sts-oauth', ... }`.
  elsewhere: Record<string, string>;
}

/**
 * A static application's OAuth 2.0 client: PKCE, DPoP and the tokens.
 */
class SpaClient extends WebPage {
  protected clientId: string;
  protected scope: string;
  protected accessToken: string;
  protected refreshToken: string;
  protected expiresAt: number;
  protected key: Json;
  protected publicJwk: Json;
  protected nonce: string;
  // WHO SIGNED IN (#508): the ID Token's `sub`.
  protected subject: string;
  // Where the authorization server, the API and the sign-in service are when
  // they are not on this application's own listener (#472) is `WebPage`'s
  // `elsewhere`, read from the shell's `data-sts-*` attributes.
  // The realm's authorization server metadata, read once (`asMetadata()`).
  protected metadata: Json;

  /**
   * Makes the client.
   *
   * @param env - the browser's objects: `fetch`, `crypto` (WebCrypto),
   *   `location`, `history`, `document`, `sessionStorage`, `navigator`,
   *   `window`, and, for a test, `now` (milliseconds; `Date.now` where left
   *   out)
   * @param prefix - the realm's path prefix, '' in the default realm
   * @param options - the client's id, its scope and the shell's attributes
   */
  constructor(env: Json, prefix: string, options: SpaClientOptions) {
    super(env, prefix, options.elsewhere);
    this.clientId = options.clientId;
    this.scope = options.scope;
    this.accessToken = '';
    this.refreshToken = '';
    this.expiresAt = 0;
    this.key = null;
    this.publicJwk = null;
    this.nonce = '';
    this.subject = '';
    this.metadata = null;
  }

  // `SpaClient.queryOf()` is `WebPage.queryOf()`, inherited.

  // --- encoding and crypto -------------------------------------------------

  /**
   * Base64url without padding.
   *
   * @param bytes - the bytes
   * @returns the encoding
   */
  static b64u(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Random bytes, base64url.
   *
   * @param n - how many bytes
   * @returns the encoding
   */
  random(n: number): string {
    const bytes = new Uint8Array(n);
    this.env.crypto.getRandomValues(bytes);
    return SpaClient.b64u(bytes);
  }

  /**
   * SHA-256 of a string, base64url.
   *
   * @param text - the string
   * @returns the digest's encoding
   */
  async sha256(text: string): Promise<string> {
    const digest = await this.env.crypto.subtle.digest('SHA-256',
      new TextEncoder().encode(text));
    return SpaClient.b64u(new Uint8Array(digest));
  }

  // THE OPENID CONNECT `nonce` (Core section 3.1.2.1), which FAPI 1.0
  // requires on every request asking for `openid` and the console and portal
  // always do. It is DERIVED from the sign-in's PKCE verifier rather than
  // kept beside it: the verifier already crosses the redirect (and a
  // popup's sign-in) in what each runtime saves, so the nonce needs no
  // storage of its own and cannot be lost apart from it. The verifier is
  // never sent; this hash of it, under its own label so it is not the code
  // challenge, is. The ID Token the token endpoint answers this page with is
  // then held to it (`nonceMatches()`).
  /**
   * The `nonce` of a sign-in whose PKCE verifier this is.
   *
   * @param verifier - the sign-in's PKCE verifier
   * @returns the nonce, base64url
   */
  async nonceFor(verifier: string): Promise<string> {
    return this.sha256('nonce:' + verifier);
  }

  // READ, NOT VERIFIED, for `subjectOf()`'s reason: the ID Token came to
  // this page straight from the token endpoint over TLS, which is what
  // OpenID Connect Core section 3.1.3.7 accepts in place of the signature
  // for the code flow, and the nonce is compared with what this page itself
  // asked for.
  /**
   * Whether an ID Token carries the nonce of the sign-in that verifier
   * began.
   *
   * @param idToken - the compact JWT the token endpoint answered
   * @param verifier - the sign-in's PKCE verifier
   * @returns whether the nonce is there and is that sign-in's
   */
  async nonceMatches(idToken: Json, verifier: string): Promise<boolean> {
    const carried = SpaClient.claimOf(idToken, 'nonce');
    return carried !== '' && carried === await this.nonceFor(verifier);
  }

  // THE KEY IS MADE NON-EXTRACTABLE, which is the condition rcbj attached
  // to a public console: the private key can sign and cannot be exported, so
  // a script that reads this page can use the key while the page lives and
  // cannot carry it away. Only the public half is exported, for the proof's
  // header.
  /**
   * Makes this page load's DPoP key, once.
   *
   * @returns nothing
   */
  async ensureKey(): Promise<void> {
    if (this.key) {
      return;
    }
    const pair = await this.env.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const jwk = await this.env.crypto.subtle.exportKey('jwk',
                                                         pair.publicKey);
    this.key = pair;
    this.publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  }

  // RFC 9449 section 4.2: `typ` dpop+jwt, the public key in the header, and
  // `jti`, `htm`, `htu` (no query, no fragment), `iat`, `ath` with an access
  // token and `nonce` once a server has given one. WebCrypto's ECDSA
  // signature is r || s, which is JOSE's ES256 form already.
  /**
   * Makes a DPoP proof for one request.
   *
   * @param method - the request's method
   * @param url - the request's URL; its query and fragment are dropped
   * @param accessToken - the access token it is sent with, or ''
   * @returns the proof
   */
  async proof(method: string, url: string,
              accessToken: string): Promise<string> {
    await this.ensureKey();
    const now = this.env.now ? this.env.now() : Date.now();
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: this.publicJwk };
    const claims: Json = {
      jti: this.random(16), htm: method.toUpperCase(),
      htu: String(url).replace(/[?#].*$/, ''), iat: Math.floor(now / 1000)
    };
    if (accessToken) {
      claims.ath = await this.sha256(accessToken);
    }
    if (this.nonce) {
      claims.nonce = this.nonce;
    }
    const enc = function (obj) {
      return SpaClient.b64u(new TextEncoder().encode(JSON.stringify(obj)));
    };
    const input = enc(header) + '.' + enc(claims);
    const signature = await this.env.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, this.key.privateKey,
      new TextEncoder().encode(input));
    return input + '.' + SpaClient.b64u(new Uint8Array(signature));
  }

  // --- the authorization server --------------------------------------------
  // (This realm's address for a path, `url()`, is `WebPage`'s.)

  // A token endpoint answer with `error: use_dpop_nonce` is retried once
  // with the nonce it sent (RFC 9449 section 8).
  /**
   * Posts a form to the token endpoint with a DPoP proof.
   *
   * @param form - the form fields
   * @returns the response's JSON and status
   */
  async tokenRequest(form: Json): Promise<Json> {
    const endpoint = this.url('/oauth2/token');
    for (let attempt = 0; attempt < 2; attempt++) {
      const res = await this.env.fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded',
                   'DPoP': await this.proof('POST', endpoint, '') },
        body: new URLSearchParams(form).toString()
      });
      this.keepNonce(res);
      const json = await res.json().catch(function () {
        return {};
      });
      if (res.status === 400 && json.error === 'use_dpop_nonce' &&
          attempt === 0) {
        continue;
      }
      return { status: res.status, json: json };
    }
    return { status: 400, json: { error: 'use_dpop_nonce' } };
  }

  // ---------------------------------------------------------------------------
  // PUSHED AUTHORIZATION REQUESTS (RFC 9126), WHERE THE REALM REQUIRES THEM
  // (#568). FAPI 2.0 makes PAR the only way to send an authorization request,
  // and a realm may require it on its own (`oauth2.requirePar`). The server-
  // rendered surfaces pushed through `oidc_rp.ts`; a static one pushes from
  // the browser: its parameters POSTed to the PAR endpoint the metadata names
  // — a public client authenticates with nothing, as section 2 allows — and
  // the browser sent to the authorization endpoint with the
  // `request_uri` it answered and the client id alone. Where the metadata
  // requires nothing, the request is the ordinary query, as it always was.
  // ---------------------------------------------------------------------------
  /**
   * The authorization server's metadata for this realm (RFC 8414), once.
   *
   * @returns the metadata, or {} where it cannot be read
   */
  async asMetadata(): Promise<Json> {
    if (this.metadata) {
      return this.metadata;
    }
    let json: Json = {};
    try {
      const res = await this.env.fetch(
        this.url('/.well-known/oauth-authorization-server'),
        { headers: { 'Accept': 'application/json' } });
      json = res.status === 200 ? await res.json() : {};
    } catch (e) {
      // No metadata: the ordinary request, which a realm that requires PAR
      // refuses in words the page draws.
      json = {};
    }
    this.metadata = json || {};
    return this.metadata;
  }

  /**
   * The authorization request's URL: pushed first where the realm requires
   * it, the query otherwise.
   *
   * @param params - the request's parameters, `client_id` among them
   * @returns the URL to send the browser to
   */
  async authorizationRequestUrl(params: Json): Promise<string> {
    const authorize = this.url('/oauth2/authorize');
    const meta = await this.asMetadata();
    // JARM WHERE THE REALM OFFERS NOTHING ELSE (FAPI 2.0 Message Signing,
    // which leaves only the JWT-secured modes in `response_modes_supported`):
    // the answer comes back as a signed `response`, which
    // `openAuthorizationResponse()` verifies.
    const modes = meta.response_modes_supported;
    if (Array.isArray(modes) && modes.indexOf('query') < 0 &&
        (modes.indexOf('jwt') >= 0 || modes.indexOf('query.jwt') >= 0)) {
      params.response_mode = modes.indexOf('jwt') >= 0 ? 'jwt' : 'query.jwt';
    }
    if (meta.require_pushed_authorization_requests !== true) {
      return authorize + '?' + SpaClient.formOf(params);
    }
    const endpoint = String(meta.pushed_authorization_request_endpoint ||
                            this.url('/oauth2/par'));
    // NO DPoP PROOF ON THE PUSH: a proof there binds the authorization code
    // to its key (RFC 9449 section 10), and the key is this page load's —
    // the callback is another page load, with another key that cannot
    // redeem it. The tokens are bound where they are issued, at the token
    // request, by the key that will use them.
    const res = await this.env.fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: SpaClient.formOf(params) });
    const json = await res.json().catch(function () {
      return {};
    });
    if (res.status === 201 && json.request_uri) {
      return authorize + '?' + new URLSearchParams({
        client_id: String(params.client_id || this.clientId),
        request_uri: String(json.request_uri) }).toString();
    }
    // A REFUSED PUSH: the ordinary request, which the authorization endpoint
    // then refuses with the reason, drawn where the person can read it.
    return authorize + '?' + SpaClient.formOf(params);
  }

  /**
   * Form-encodes parameters, a value that is an array as the parameter
   * repeated — RFC 8707's `resource`, which a client asking for two
   * resources sends twice (#607). `URLSearchParams(object)` would join the
   * array with commas into one value naming no resource.
   *
   * @param params - the parameters
   * @returns the encoded form
   */
  static formOf(params: Json): string {
    const form = new URLSearchParams();
    Object.keys(params || {}).forEach(function (name) {
      [].concat(params[name]).forEach(function (one) {
        form.append(name, String(one));
      });
    });
    return form.toString();
  }

  // ---------------------------------------------------------------------------
  // A JWT-SECURED AUTHORIZATION RESPONSE (JARM, #568), OPENED AND CHECKED
  // BEFORE ANYTHING IN IT IS BELIEVED: the signature against the realm's
  // published key (by `kid`, verified with WebCrypto), `iss` the realm's
  // issuer, `aud` this client, `exp` in the future — JARM section 2.4. Only
  // then are its `code`, `state` and `error` handed back, in the shape an
  // ordinary callback's query has. An answer that is not a JWT is that query.
  // ---------------------------------------------------------------------------
  /**
   * Bytes of a base64url string.
   *
   * @param text - the encoding
   * @returns the bytes
   */
  static fromB64u(text: string): Uint8Array {
    let t = String(text || '').replace(/-/g, '+').replace(/_/g, '/');
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
   * WebCrypto's names for a JWS algorithm: how its key is imported and how
   * a signature is verified, or null for one WebCrypto does not do.
   *
   * @param alg - the JWS `alg`
   * @returns `{ importAs, verifyAs }`, or null
   */
  static webCryptoAlg(alg: string): Json {
    const ec = function (curve: string, hash: string): Json {
      return { importAs: { name: 'ECDSA', namedCurve: curve },
               verifyAs: { name: 'ECDSA', hash: hash } };
    };
    const pss = function (hash: string, salt: number): Json {
      return { importAs: { name: 'RSA-PSS', hash: hash },
               verifyAs: { name: 'RSA-PSS', saltLength: salt } };
    };
    const rsa = function (hash: string): Json {
      return { importAs: { name: 'RSASSA-PKCS1-v1_5', hash: hash },
               verifyAs: { name: 'RSASSA-PKCS1-v1_5' } };
    };
    const table: Json = {
      ES256: ec('P-256', 'SHA-256'), ES384: ec('P-384', 'SHA-384'),
      ES512: ec('P-521', 'SHA-512'),
      PS256: pss('SHA-256', 32), PS384: pss('SHA-384', 48),
      PS512: pss('SHA-512', 64),
      RS256: rsa('SHA-256'), RS384: rsa('SHA-384'), RS512: rsa('SHA-512'),
      EdDSA: { importAs: { name: 'Ed25519' }, verifyAs: { name: 'Ed25519' } },
      Ed25519: { importAs: { name: 'Ed25519' },
                 verifyAs: { name: 'Ed25519' } }
    };
    return table[alg] || null;
  }

  /**
   * The authorization response a callback carries: a JARM `response`
   * opened and checked, or the query itself.
   *
   * @param query - the callback's query
   * @returns `{ code, state, error, error_description, iss }`
   */
  async openAuthorizationResponse(query: Json): Promise<Json> {
    if (!query || !query.response) {
      return query || {};
    }
    const refused = function (why: string): Json {
      return { error: 'invalid_response', state: '',
               error_description: 'The authorization response could not ' +
                 'be trusted: ' + why + '.' };
    };
    const parts = String(query.response).split('.');
    if (parts.length !== 3) {
      return refused('it is not a signed JWT');
    }
    let header: Json = null;
    let claims: Json = null;
    try {
      header = JSON.parse(new TextDecoder().decode(
        SpaClient.fromB64u(parts[0])));
      claims = JSON.parse(new TextDecoder().decode(
        SpaClient.fromB64u(parts[1])));
    } catch (e) {
      return refused('its header or claims are not JSON');
    }
    const how = SpaClient.webCryptoAlg(String(header.alg || ''));
    if (!how) {
      return refused('its algorithm ' + JSON.stringify(header.alg) +
                     ' is not one this browser can verify');
    }
    const meta = await this.asMetadata();
    let keys: Json[] = [];
    try {
      const res = await this.env.fetch(String(meta.jwks_uri ||
        this.url('/oauth2/jwks')),
        { headers: { 'Accept': 'application/json' } });
      keys = ((await res.json()) || {}).keys || [];
    } catch (e) {
      return refused('the realm\'s keys could not be read');
    }
    const jwk = keys.filter(function (one: Json): boolean {
      return !header.kid || one.kid === header.kid;
    })[0];
    if (!jwk) {
      return refused('no published key has its kid');
    }
    const material: Json = { kty: jwk.kty };
    ['crv', 'x', 'y', 'n', 'e'].forEach(function (name) {
      if (jwk[name] !== undefined) {
        material[name] = jwk[name];
      }
    });
    let valid = false;
    try {
      const key = await this.env.crypto.subtle.importKey('jwk', material,
        how.importAs, false, ['verify']);
      valid = await this.env.crypto.subtle.verify(how.verifyAs, key,
        SpaClient.fromB64u(parts[2]),
        new TextEncoder().encode(parts[0] + '.' + parts[1]));
    } catch (e) {
      valid = false;
    }
    if (!valid) {
      return refused('its signature does not verify');
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const now = Math.floor((this.env.now ? this.env.now() : Date.now()) /
                           1000);
    if (meta.issuer && claims.iss !== meta.issuer) {
      return refused('it names another issuer');
    }
    if (audiences.indexOf(this.clientId) < 0) {
      return refused('it is for another client');
    }
    if (!claims.exp || Number(claims.exp) <= now) {
      return refused('it has expired');
    }
    return { code: claims.code, state: claims.state, error: claims.error,
             error_description: claims.error_description, iss: claims.iss };
  }

  /**
   * Keeps the tokens a token endpoint answered with.
   *
   * @param json - the token response
   * @returns nothing
   */
  keepTokens(json: Json): void {
    const now = this.env.now ? this.env.now() : Date.now();
    this.accessToken = String(json.access_token || '');
    // ROTATED: a refresh answers a new refresh token, and the old one is
    // spent. One that answered none keeps the one in hand.
    if (json.refresh_token) {
      this.refreshToken = String(json.refresh_token);
    }
    this.expiresAt = now + (Number(json.expires_in) || 300) * 1000;
    // WHO IT IS FOR (#508), from the ID Token the token endpoint answered
    // this page directly. Read, not verified: it is compared with the one
    // this page signed in with, never trusted for anything the API decides.
    const subject = SpaClient.subjectOf(json.id_token);
    if (subject) {
      this.subject = subject;
    }
  }

  /**
   * The `sub` of an ID Token, read without verifying it.
   *
   * @param idToken - the compact JWT, or nothing
   * @returns the subject, or ''
   */
  static subjectOf(idToken: Json): string {
    return SpaClient.claimOf(idToken, 'sub');
  }

  /**
   * A string claim of an ID Token, read without verifying it.
   *
   * @param idToken - the compact JWT, or nothing
   * @param name - the claim
   * @returns its value, or ''
   */
  static claimOf(idToken: Json, name: string): string {
    const parts = String(idToken || '').split('.');
    if (parts.length !== 3) {
      return '';
    }
    try {
      const text = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
      return String(JSON.parse(text)[name] || '');
    } catch (e) {
      // Not a JWT this page can read: no claim, which a sign-in again
      // then treats as a different person, and a nonce check as a refusal.
      return '';
    }
  }

  /**
   * Keeps the nonce a response carried, for the next proof.
   *
   * @param res - a fetch response
   * @returns nothing
   */
  keepNonce(res: Json): void {
    const nonce = res && res.headers && res.headers.get
      ? res.headers.get('DPoP-Nonce') : '';
    if (nonce) {
      this.nonce = nonce;
    }
  }
}

export = SpaClient;
