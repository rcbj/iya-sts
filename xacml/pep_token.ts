// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: pep_token.ts
//
// ---------------------------------------------------------------------------
// A REMOTE PEP'S ACCESS TOKEN, READ AT THE TWO DOORS IT REACHES (#1827's
// follow-up, rcbj-approved plan, 2026-11-16, phase 1).
//
// Until this plan a remote PEP proved who it was by its client certificate
// on every call: `/xacml/pep/*` and `POST /xacml/pip` through
// `xacml.ts`'s `callerIdentity()`, and the edge PDP's forward of a
// fine-grained evaluation through `authzen_caller.ts`'s certificate door.
// The plan replaces the certificate with an RFC 7523 self-assertion the PEP
// signs with ONE key, presented through the public client `sts-remote-pep`
// for a DPoP-bound (RFC 9449) access token per audience. This file is the
// one reading of such a token, so the two doors cannot come to disagree
// about which token is a PEP's or which entry it names:
//
//   1. IT IS OURS: a JWS this realm signed (`helpers.verifyOwnJws()`, any
//      generation of the key) or an opaque handle this realm issued, not
//      expired, an access token (RFC 9068 `at+jwt`), from this realm's
//      authorization server, not revoked.
//   2. IT IS THE PEP'S: issued to `sts-remote-pep` and nobody else. A token
//      of any other client is not a PEP's, and each door decides what to do
//      with it (the XACML door refuses it; the AuthZEN door hands it to its
//      own token door, where it always went).
//   3. IT IS FOR THIS DOOR: its audience is the realm's `/xacml/pep` or
//      `/access/v1`, and it carries that door's scope (`xacml:pep`,
//      `authzen:evaluate`) while the client still holds the delegated
//      permission grant of it.
//   4. IT IS BOUND, AND THE BINDING HOLDS: it carries `cnf.jkt`, arrived as
//      `Authorization: DPoP`, and the `DPoP` header is a proof by that key
//      for this method and URL with the token's `ath` — `dpop.verifyProof()`,
//      the twelve checks every resource here asks, the replay record and the
//      server nonce included. A certificate binding it also carries holds as
//      well (`mtls.checkBinding()`).
//   5. IT NAMES ONE PERSON: its `sub`, `urn:uuid:<entryUUID>`, is exactly
//      one entry under this realm's `ou=users` — the PEP's own entry, a
//      service account — and the PEP is named by that entry's USERNAME, the
//      common name a certificate this service issued it carried, so its
//      `ou=peps` row and its cluster membership are the ones it had.
//
// **WHAT THIS DOES NOT ASK** is whether the entry may do anything: that is
// REMOTE_PEPS and the access-control policy, links 3 and 4 of the chain,
// asked by each door exactly as for a certificate. A token whose subject has
// left the group still verifies here and is refused there.
//
// A refusal is a `reason` each door maps to its own error code; nothing here
// writes a response.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');

type Req = import('express').Request;
type Json = any;

/**
 * The client a remote PEP's token is issued through.
 */
const PEP_CLIENT = 'sts-remote-pep';

/**
 * What one door asks a token to be for: the path under the realm's base its
 * audience names, and the scope it must carry.
 */
interface PepTokenWant {
  path: string;
  scope: string;
}

/**
 * What `verify()` answers. `reason` is '' on success, else one of `none`,
 * `invalid`, `client`, `audience`, `scope`, `not-dpop`, `proof`, `subject`.
 */
interface PepTokenResult {
  ok: boolean;
  reason: string;
  description: string;
  // A DPoP refusal that is a request for a server nonce (RFC 9449 section
  // 9), and the code `dpop.verifyProof()` gave the proof's refusal.
  needNonce?: boolean;
  proofCode?: string;
  claims?: Json;
  clientId?: string;
  jkt?: string;
  sub?: string;
  dn?: string;
  username?: string;
}

/**
 * The modules a token is read through.
 */
interface PepTokenDeps {
  log: typeof helpers.log;
  helpers: Json;
  mtls: Json;
  // `xacml_pip.ts`'s `locateSubject()`, the directory's one reading of a
  // `urn:uuid:` subject.
  pip: Json;
  // The OAuth libraries, loaded at the first token rather than at load, as
  // `authzen_caller.ts` loads them: `jwt`, `opaque`, `dpop`, `stats`,
  // `scopes`.
  loadOAuth(): Json;
}

/**
 * Reads a remote PEP's DPoP-bound access token (#1827's follow-up).
 */
class PepToken {
  /**
   * The module's `PEP_CLIENT`.
   */
  static readonly PEP_CLIENT = PEP_CLIENT;

  /**
   * Builds the reader over its dependencies.
   *
   * @param deps - the logger, helpers, mutual TLS, the PIP and the lazy
   *   OAuth loader
   */
  constructor(private readonly deps: PepTokenDeps) {
    deps.log.debug("Entering PepToken.constructor().");
    deps.log.debug("Leaving PepToken.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): PepTokenDeps {
    helpers.log.debug("Entering PepToken.defaultDeps().");
    helpers.log.debug("Leaving PepToken.defaultDeps().");
    return {
      log: helpers.log,
      helpers: helpers,
      mtls: require('../oauth-oidc/mtls'),
      pip: require('./xacml_pip'),
      loadOAuth: function (): Json {
        helpers.log.debug("Entering loadOAuth().");
        helpers.log.debug("Leaving loadOAuth().");
        return {
          jwt: require('../oauth-oidc/jwt_access_token'),
          opaque: require('../oauth-oidc/opaque_access_token'),
          dpop: require('../oauth-oidc/dpop'),
          stats: require('../common/admin_stats'),
          scopes: require('../common/scope_policy')
        };
      }
    };
  }

  /**
   * The token a request presents in `Authorization`, and its scheme.
   *
   * @param req - the request
   * @returns `{ token, scheme }`, both '' when there is none
   */
  static presented(req: Req): { token: string; scheme: string } {
    helpers.log.debug("Entering PepToken.presented().");
    const header = String((req && req.headers &&
                           req.headers.authorization) || '');
    const matched = /^(Bearer|DPoP)\s+([A-Za-z0-9\-._~+/]+=*)\s*$/i
      .exec(header);
    helpers.log.debug("Leaving PepToken.presented().");
    return matched ? { token: matched[2], scheme: matched[1].toLowerCase() }
      : { token: '', scheme: '' };
  }

  // Step 1: the claims of a token this realm issued, or null. Opaque only
  // where the realm issues opaque handles and this one is live.
  private claimsOf(token: string): { claims: Json; opaque: boolean } {
    const { log, helpers: h } = this.deps;
    log.debug("Entering PepToken.claimsOf().");
    let claims: Json = null;
    try {
      claims = h.verifyOwnJws(token);
    } catch (e) {
      log.debug("Caught in PepToken.claimsOf(): " + ((e && e.message) || e));
      claims = null;
    }
    if (claims) {
      log.debug("Leaving PepToken.claimsOf(). A JWS.");
      return { claims: claims, opaque: false };
    }
    if (token.indexOf('.') < 0) {
      const found = this.deps.loadOAuth().opaque.lookup(token);
      if (found && found.kind === 'active') {
        log.debug("Leaving PepToken.claimsOf(). An opaque handle.");
        return { claims: found.claims, opaque: true };
      }
    }
    log.debug("Leaving PepToken.claimsOf(). Not ours.");
    return { claims: null, opaque: false };
  }

  /**
   * Whether a request presents a token this realm issued to the remote
   * PEP's client — the question the AuthZEN door asks before it decides
   * which of its doors a token goes through. Nothing else is checked.
   *
   * @param req - the request
   * @returns true for a verified token whose `client_id` is sts-remote-pep
   */
  isPepToken(req: Req): boolean {
    const { log } = this.deps;
    log.debug("Entering PepToken.isPepToken().");
    const presented = PepToken.presented(req);
    if (!presented.token) {
      log.debug("Leaving PepToken.isPepToken(). No token.");
      return false;
    }
    const read = this.claimsOf(presented.token);
    const answer = !!read.claims &&
      String(read.claims.client_id || '') === PEP_CLIENT;
    log.debug("Leaving PepToken.isPepToken(). " + answer);
    return answer;
  }

  /**
   * Whether a token's audiences name the realm's door, with or without the
   * trailing slash a permission base adds.
   *
   * @param claims - the token's claims
   * @param base - the realm's base URL
   * @param path - the door's path
   * @returns true when one does
   */
  static audienceOk(claims: Json, base: string, path: string): boolean {
    helpers.log.debug("Entering PepToken.audienceOk().");
    const aud = claims ? claims.aud : undefined;
    const audiences = Array.isArray(aud) ? aud
      : (aud === undefined || aud === null ? [] : [aud]);
    const exact = base + path;
    const ok = audiences.some(function (one: unknown) {
      return String(one) === exact || String(one) === exact + '/';
    });
    helpers.log.debug("Leaving PepToken.audienceOk(). " + ok);
    return ok;
  }

  /**
   * Reads a remote PEP's token for one door: the five steps in the file's
   * header. Never writes a response.
   *
   * @param req - the request
   * @param want - `{ path, scope }`: the door's path and scope
   * @returns the result; `ok` with `dn`, `username` and `jkt`, or a
   *   `reason` and a `description`
   */
  verify(req: Req, want: PepTokenWant): PepTokenResult {
    const self = this;
    const { log, helpers: h, mtls, pip } = this.deps;
    log.debug("Entering PepToken.verify(). " + want.path);
    const refuse = function (reason: string, description: string,
                             extra?: Json): PepTokenResult {
      log.debug("Entering refuse().");
      log.debug("Leaving refuse(). " + reason);
      return Object.assign({ ok: false, reason: reason,
                             description: description }, extra || {});
    };
    const presented = PepToken.presented(req);
    if (!presented.token) {
      log.debug("Leaving PepToken.verify(). No token.");
      return refuse('none', 'No access token was presented.');
    }
    const oauth = self.deps.loadOAuth();
    // 1. OURS.
    const read = self.claimsOf(presented.token);
    const claims = read.claims;
    if (!claims) {
      log.debug("Leaving PepToken.verify(). Not ours.");
      return refuse('invalid', 'That access token was not issued by this ' +
                    'realm, or its signature does not verify.');
    }
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && Number(claims.exp) <= now) {
      log.debug("Leaving PepToken.verify(). Expired.");
      return refuse('invalid', 'That access token has expired.');
    }
    if (!read.opaque && !oauth.jwt.isAccessTokenType(
        oauth.jwt.typOf(presented.token))) {
      log.debug("Leaving PepToken.verify(). Not an access token.");
      return refuse('invalid', 'That token is not an access token.');
    }
    const base = String(h.baseUrlOf(req) || '');
    if (!oauth.jwt.isHostedIssuer(claims.iss, base)) {
      log.debug("Leaving PepToken.verify(). Another issuer.");
      return refuse('invalid', 'That access token was issued by another ' +
                    'authorization server than this realm\'s.');
    }
    if (claims.jti && oauth.stats.isRevoked(String(claims.jti))) {
      log.debug("Leaving PepToken.verify(). Revoked.");
      return refuse('invalid', 'That access token has been revoked.');
    }
    // 2. THE PEP'S.
    const clientId = String(claims.client_id || '');
    if (clientId !== PEP_CLIENT) {
      log.debug("Leaving PepToken.verify(). Another client's.");
      return refuse('client', 'That access token was issued to "' +
                    clientId + '"; a remote PEP\'s is issued to ' +
                    PEP_CLIENT + '.', { clientId: clientId });
    }
    // 3. FOR THIS DOOR.
    if (!PepToken.audienceOk(claims, base, want.path)) {
      log.debug("Leaving PepToken.verify(). Another audience.");
      return refuse('audience', 'That access token is not for this API: ' +
                    'its audience must be this realm\'s ' + want.path + '.');
    }
    const carried = String(claims.scope || '').split(/\s+/).filter(Boolean);
    if (carried.indexOf(want.scope) < 0 ||
        !oauth.scopes.declares(clientId, want.scope)) {
      log.debug("Leaving PepToken.verify(). Without " + want.scope + ".");
      return refuse('scope', 'That access token does not carry ' +
                    want.scope + ', or ' + PEP_CLIENT + ' no longer holds ' +
                    'the delegated permission grant of it.');
    }
    // 4. BOUND, AND THE BINDING HOLDS.
    const jkt = oauth.dpop.jktOf(claims);
    if (!jkt || presented.scheme !== 'dpop') {
      log.debug("Leaving PepToken.verify(). Not DPoP.");
      return refuse('not-dpop', jkt
        ? 'That access token is DPoP-bound, so it must be sent as ' +
          'Authorization: DPoP with a DPoP proof.'
        : 'A remote PEP\'s access token must be DPoP-bound (RFC 9449, ' +
          'cnf.jkt), and this one is not.');
    }
    const certificate = mtls.checkBinding(claims, req, true);
    if (certificate) {
      log.debug("Leaving PepToken.verify(). Certificate binding.");
      return refuse('invalid', String(certificate.description ||
        'The token is bound to a certificate that was not presented.'));
    }
    const checked = oauth.dpop.verifyProof(req.headers.dpop, {
      htm: req.method, htu: oauth.dpop.htuOf(req),
      accessToken: presented.token, expectedJkt: jkt, req: req });
    if (!checked.ok) {
      log.debug("Leaving PepToken.verify(). The DPoP proof was refused.");
      return refuse('proof', String(checked.description ||
                                    'The DPoP proof was refused.'),
                    { needNonce: !!checked.needNonce,
                      proofCode: String(checked.errorCode || '') });
    }
    // 5. ONE PERSON.
    const sub = String(claims.sub || '');
    let stored: Json = null;
    if (/^urn:uuid:/i.test(sub)) {
      try {
        stored = pip.locateSubject(sub);
      } catch (e) {
        log.debug("Caught in PepToken.verify(): " + ((e && e.message) || e));
        stored = null;
      }
    }
    const dn = stored && stored.dn ? String(stored.dn) : '';
    const username = dn ? String(h.nameForSubject(sub) || '') : '';
    if (!dn || !username || !/^[^,]+,ou=users,/i.test(dn)) {
      log.debug("Leaving PepToken.verify(). Names nobody here.");
      return refuse('subject', 'That access token\'s subject (' +
                    (sub || 'none') + ') names no entry under this ' +
                    'realm\'s ou=users. A remote PEP\'s token is its own ' +
                    'self-assertion, so its subject is the PEP\'s own ' +
                    'entry.', { sub: sub });
    }
    log.debug("Leaving PepToken.verify(). " + dn);
    return { ok: true, reason: '', description: '', claims: claims,
             clientId: clientId, jkt: jkt, sub: sub, dn: dn,
             username: username };
  }
}

export = PepToken;
