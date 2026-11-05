// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: atproto_client.ts
//
// ===========================================================================
// THE AT PROTOCOL'S OAUTH PROFILE, AS A CLIENT (#746, 2026-11-05): signing a
// person in with Bluesky. `federation/CLAUDE.md` argues the choices.
//
// It differs from an ordinary OAuth 2.0 relationship in four ways, and each is
// a MUST of the profile:
//
//   * **The client id is a URL**, the address of a public metadata document
//     this service serves (`clientMetadata()`), with no registration.
//   * **Pushed Authorization Requests** (RFC 9126), so the authorization
//     request is a POST made here before the browser is sent anywhere.
//   * **DPoP** (RFC 9449) on the push and the token request, with a key made
//     for this one sign-in and the server's nonce answered once
//     (`postWithDpop()`). The token is never used here, because a person's
//     profile is public, so no proof is ever made for a resource.
//   * **THE ANSWER'S `sub` IS A CLAIM TO BE CHECKED** (`subjectProblem()`). An
//     authorization server answers with a DID, and in this protocol anybody
//     can run one, so its word alone would let it name anyone. The DID's own
//     document names the person's data server, and that server names the
//     authorization servers it trusts: only if this issuer is among them is
//     the answer believed. This is the step the whole sign-in rests on.
//
// **did:plc only, and only the issuer the relationship names.** A did:web
// would be a host a caller's kind of value names, and the PLC directory is one
// address an operator chose (`federation.atprotoPlcDirectory`). What a DID's
// document names is dialled through `fetchPublished()`, so product mode refuses
// an internal address: the twenty-fourth URL in `federation/CLAUDE.md`.
//
// A public client (`token_endpoint_auth_method: none`), because nothing is kept
// past the sign-in: the access token is dropped, and no refresh token is asked
// for, so client authentication would protect nothing here.
//
// **ALL CRYPTOGRAPHY IS `common/crypto.js`'s** (rule 3r). A static utility
// class, whose dialler is handed in by `federation_sp.ts`.
// ===========================================================================

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');

const log = helpers.log;

type Json = any;

// `federation_http.ts`'s `fetchPublished()`.
type Fetch = (url: string, options?: Json) => Promise<Json>;

// A did:plc is 24 base32 characters.
const DID_PLC = /^did:plc:[a-z2-7]{24}$/;

const SCOPE = 'atproto';

/**
 * The AT Protocol's OAuth profile as a client. A static utility class.
 */
class AtprotoClient {
  static readonly SCOPE = SCOPE;

  /**
   * Parses a dial's body as JSON.
   *
   * @param answer - what `fetchPublished()` answered
   * @returns the JSON, or null
   */
  static jsonOf(answer: Json): Json {
    log.debug("Entering AtprotoClient.jsonOf().");
    let out: Json = null;
    try {
      out = JSON.parse(String(answer && answer.body));
    } catch (e) {
      log.debug("Caught in AtprotoClient.jsonOf(): " +
                ((e && e.name) || 'a parse error'));
      out = null;
    }
    log.debug("Leaving AtprotoClient.jsonOf().");
    return out;
  }

  /**
   * Makes the key one sign-in's proofs are signed with.
   *
   * @returns `{ pem, jwk }`, `jwk` the public half alone
   */
  static newKey(): Json {
    log.debug("Entering AtprotoClient.newKey().");
    const pair = stsCrypto.generateSigningJwkPair('ES256');
    const open = pair.publicJwk;
    log.debug("Leaving AtprotoClient.newKey().");
    return { pem: pair.privateKeyPem,
             jwk: { kty: open.kty, crv: open.crv, x: open.x, y: open.y } };
  }

  /**
   * Signs a DPoP proof (RFC 9449 section 4.2).
   *
   * @param key - what `newKey()` made
   * @param url - the address the proof is for
   * @param nonce - the server's nonce, if it has given one
   * @returns the proof
   */
  static proof(key: Json, url: string, nonce: string): string {
    log.debug("Entering AtprotoClient.proof().");
    const target = new URL(url);
    const claims: Json = {
      jti: stsCrypto.randomToken(128), htm: 'POST',
      htu: target.origin + target.pathname,
      iat: Math.floor(Date.now() / 1000)
    };
    if (nonce) {
      claims.nonce = nonce;
    }
    log.debug("Leaving AtprotoClient.proof().");
    return stsCrypto.signJws(claims, key.pem, {
      algorithm: 'ES256', header: { typ: 'dpop+jwt', jwk: key.jwk } });
  }

  /**
   * Posts a form with a DPoP proof, answering the server's nonce once. The
   * profile's servers refuse a first proof by design, saying `use_dpop_nonce`.
   *
   * @param dial - the dialler
   * @param url - the address
   * @param form - the form's fields
   * @param key - what `newKey()` made
   * @returns `{ ok, status, json }`
   */
  static async postWithDpop(dial: Fetch, url: string, form: Json,
                            key: Json): Promise<Json> {
    log.debug("Entering AtprotoClient.postWithDpop().");
    const send = function (nonce: string): Promise<Json> {
      log.debug("Entering send().");
      log.debug("Leaving send().");
      return dial(url, {
        method: 'POST', accept: 'application/json',
        contentType: 'application/x-www-form-urlencoded',
        body: new URLSearchParams(form).toString(),
        headers: { DPoP: AtprotoClient.proof(key, url, nonce) } });
    };
    let answer = await send('');
    let json = AtprotoClient.jsonOf(answer);
    const nonce = String((answer.headers || {})['dpop-nonce'] || '');
    if (!answer.ok && nonce && json && json.error === 'use_dpop_nonce') {
      answer = await send(nonce);
      json = AtprotoClient.jsonOf(answer);
    }
    log.debug("Leaving AtprotoClient.postWithDpop(). " + answer.status);
    return { ok: !!answer.ok, status: answer.status, json: json };
  }

  /**
   * Reads the authorization server's metadata (RFC 8414), held to naming the
   * issuer the relationship names.
   *
   * @param dial - the dialler
   * @param issuer - `fedPeer`
   * @returns the endpoints, or null
   */
  static async serverMetadata(dial: Fetch, issuer: string): Promise<Json> {
    log.debug("Entering AtprotoClient.serverMetadata().");
    const answer = await dial(issuer.replace(/\/$/, '') +
      '/.well-known/oauth-authorization-server',
    { accept: 'application/json' });
    const doc = answer.ok ? AtprotoClient.jsonOf(answer) : null;
    const usable = !!doc && doc.issuer === issuer &&
      !!doc.pushed_authorization_request_endpoint &&
      !!doc.authorization_endpoint && !!doc.token_endpoint;
    log.debug("Leaving AtprotoClient.serverMetadata(). " + usable);
    return usable ? doc : null;
  }

  /**
   * The public document whose address is this relationship's client id.
   *
   * @param clientId - its address
   * @param redirectUri - the assertion consumer service
   * @param name - what a person is shown
   * @returns the document
   */
  static clientMetadata(clientId: string, redirectUri: string,
                        name: string): Json {
    log.debug("Entering AtprotoClient.clientMetadata().");
    log.debug("Leaving AtprotoClient.clientMetadata().");
    return {
      client_id: clientId, client_name: name, application_type: 'web',
      redirect_uris: [redirectUri], scope: SCOPE,
      grant_types: ['authorization_code'], response_types: ['code'],
      token_endpoint_auth_method: 'none', dpop_bound_access_tokens: true
    };
  }

  /**
   * Says why the answer's `sub` is not to be believed, or '' when it may be:
   * the DID's document names a data server, and that server must name this
   * issuer. See the header.
   *
   * @param dial - the dialler
   * @param did - the answer's `sub`
   * @param issuer - `fedPeer`
   * @param directory - `federation.atprotoPlcDirectory`
   * @returns the problem, or ''
   */
  static async subjectProblem(dial: Fetch, did: string, issuer: string,
                              directory: string): Promise<string> {
    log.debug("Entering AtprotoClient.subjectProblem().");
    const refused = function (why: string): string {
      log.debug("Leaving AtprotoClient.subjectProblem(). " + why);
      return why;
    };
    if (!DID_PLC.test(String(did || ''))) {
      return refused('its subject is not a did:plc');
    }
    const named = await dial(String(directory).replace(/\/$/, '') + '/' + did,
                             { accept: 'application/json' });
    const doc = named.ok ? AtprotoClient.jsonOf(named) : null;
    const service = ((doc && doc.service) || []).filter(function (one: Json) {
      return one && String(one.id || '').endsWith('#atproto_pds');
    })[0];
    if (!doc || doc.id !== did || !service || !service.serviceEndpoint) {
      return refused('the directory names no data server for it');
    }
    const resource = await dial(String(service.serviceEndpoint)
      .replace(/\/$/, '') + '/.well-known/oauth-protected-resource',
    { accept: 'application/json' });
    const servers = resource.ok
      ? (AtprotoClient.jsonOf(resource) || {}).authorization_servers : null;
    if (!Array.isArray(servers) || servers.indexOf(issuer) < 0) {
      return refused('its data server does not name this issuer');
    }
    log.debug("Leaving AtprotoClient.subjectProblem().");
    return '';
  }
}

export = AtprotoClient;
