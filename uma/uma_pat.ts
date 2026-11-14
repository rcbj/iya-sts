// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma_pat.ts
//
// ===========================================================================
// THE PROTECTION API TOKEN (#1168 phase 2): the door of `/uma/rreg` and
// `/uma/perm`, Federated Authorization for UMA 2.0 section 2.
//
// A PAT IS AN ORDINARY ACCESS TOKEN of this realm (rcbj's decision 4 on
// #1168), audienced to the realm's `/uma` and carrying `uma_protection` —
// obtained by the code flow, where the resource owner is the person who
// consented to the resource server managing resources on their behalf, or
// by `client_credentials`, where the owner is the APPLICATION itself, which
// only an application carrying `umaOwnsResources` TRUE may be (decision 5).
// **THE PAT'S SUBJECT IS THE OWNER OF EVERYTHING REGISTERED WITH IT.**
// Nothing a resource server sends names an owner; a registration with no
// owner would have nobody's policy to ask.
//
// Read as `authzen/authzen_caller.ts` reads its token door, which read
// `report/report_api.ts`'s: this realm's signature (or an opaque handle
// looked up), the expiry, the `at+jwt` type, the hosted issuer, the
// audience, the revocation list, the certificate binding, the DPoP proof
// where the token is bound, the sender-constraint settings, the scope and
// the client's delegated permission grant of it — asked again on every
// call, so withdrawing the grant cuts off PATs already issued. Then the
// two facts a PAT adds: the client's application must be DECLARED for the
// protocol `uma` (it is no resource server otherwise, STS-UMA-0104), and a
// token issued to the client as itself needs `umaOwnsResources`
// (STS-UMA-0105). **CHECKED IN EVERY MODE**, as `/access/v1`'s doors are:
// without the PAT there is no owner.
//
// Every refusal is RFC 6750's: 401 with `WWW-Authenticate: Bearer` for a
// token that is missing or does not verify, 403 `insufficient_scope` for
// one that lacks the scope, 403 for a client that is no resource server
// or no owner. The body is `{ error, error_description }`.
//
// A LIBRARY (rule 3): no route. The OAuth libraries are loaded when a token
// arrives, never at load.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import applications = require('../common/applications');
import mtls = require('../oauth-oidc/mtls');
import scopePolicy = require('../common/scope_policy');

const { log } = helpers;

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;

/** Who presented a PAT, as the protection API sees them. */
interface PatCaller {
  // `user` where the PAT is a person's (the code flow), `application`
  // where it is the application's own (client_credentials).
  ownerKind: 'user' | 'application';
  // The owner's key: a person's subject (`urn:uuid:…`), or the
  // application's identifier.
  owner: string;
  // The person's username, '' for an application owner.
  username: string;
  // The OAuth client the PAT was issued to, and the application it is.
  clientId: string;
  resourceServer: string;
  scope: string[];
  jti: string;
}

interface UmaPatDeps {
  log: typeof log;
  helpers: typeof helpers;
  config: typeof config;
  errorCodes: typeof errorCodes;
  applications: typeof applications;
  mtls: typeof mtls;
  scopes: typeof scopePolicy;
  loadOAuth(): Json;
}

// The one scope the protection API takes.
const SCOPE = 'uma_protection';

/**
 * The protection API token's door.
 */
class UmaPat {
  /** The protection API's scope. */
  static readonly SCOPE = SCOPE;

  /**
   * Builds the door over its dependencies.
   *
   * @param deps - the logger, settings, error codes, the registry, the
   *   certificate binding, the scope policy and the lazy OAuth libraries
   */
  constructor(private readonly deps: UmaPatDeps) {
    deps.log.debug("Entering UmaPat.constructor().");
    deps.log.debug("Leaving UmaPat.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): UmaPatDeps {
    log.debug("Entering UmaPat.defaultDeps().");
    log.debug("Leaving UmaPat.defaultDeps().");
    return {
      log: log,
      helpers: helpers,
      config: config,
      errorCodes: errorCodes,
      applications: applications,
      mtls: mtls,
      scopes: scopePolicy,
      loadOAuth: function (): Json {
        log.debug("Entering loadOAuth().");
        log.debug("Leaving loadOAuth().");
        return {
          jwt: require('../oauth-oidc/jwt_access_token'),
          opaque: require('../oauth-oidc/opaque_access_token'),
          dpop: require('../oauth-oidc/dpop'),
          sender: require('../oauth-oidc/sender_constraints'),
          stats: require('../common/admin_stats')
        };
      }
    };
  }

  /**
   * The token a request presents, and the scheme it was sent under.
   *
   * @param req - the request
   * @returns `{ token, scheme }`, both '' when none
   */
  static presented(req: Req): { token: string; scheme: string } {
    log.debug("Entering UmaPat.presented().");
    const header = String(req.headers.authorization || '');
    const matched = /^(Bearer|DPoP)\s+([A-Za-z0-9\-._~+/]+=*)\s*$/i
      .exec(header);
    log.debug("Leaving UmaPat.presented().");
    return matched ? { token: matched[2], scheme: matched[1].toLowerCase() }
      : { token: '', scheme: '' };
  }

  /**
   * Sends a protection API refusal: RFC 6750's shape.
   *
   * @param res - the response
   * @param status - 401 or 403
   * @param error - the error, '' for a bare 401
   * @param description - the human-readable description
   * @param challenge - extra `WWW-Authenticate` parameters
   */
  static send(res: Res, status: number, error: string, description: string,
              challenge?: string): void {
    log.debug("Entering UmaPat.send(). " + status);
    const body: Json = {};
    if (error) {
      body.error = error;
    }
    if (description) {
      body.error_description = description;
    }
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store');
    if (challenge !== undefined) {
      res.set('WWW-Authenticate', challenge);
    }
    res.send(JSON.stringify(body));
    log.debug("Leaving UmaPat.send().");
  }

  /**
   * The realm's issuer base, for the challenge and the audience.
   *
   * @param req - the request
   * @returns the base URL
   */
  issuerOf(req: Req): string {
    const { log, helpers } = this.deps;
    log.debug("Entering UmaPat.issuerOf().");
    const out = String(helpers.baseUrlOf(req) || '');
    log.debug("Leaving UmaPat.issuerOf().");
    return out;
  }

  /**
   * The audiences a PAT may carry here: this realm's `/uma`, under the
   * request's base and under the protection API's own hosted base, with
   * or without a trailing slash.
   *
   * @param req - the request
   * @returns the acceptable audiences
   */
  audiencesOf(req: Req): string[] {
    const { log, helpers } = this.deps;
    log.debug("Entering UmaPat.audiencesOf().");
    const out: string[] = [];
    [helpers.baseUrlOf(req), helpers.baseUrlOf(req, 'uma')]
      .forEach(function (base: unknown) {
        const text = String(base || '').replace(/\/+$/, '');
        if (!text) {
          return;
        }
        [text + '/uma', text + '/uma/'].forEach(function (one: string) {
          if (out.indexOf(one) < 0) {
            out.push(one);
          }
        });
      });
    log.debug("Leaving UmaPat.audiencesOf(). " + out.length);
    return out;
  }

  // A 401 under its code, with the Bearer challenge section 3 of RFC 6750
  // writes.
  // error-code: none — marked with the caller's STS-UMA code below.
  private unauthenticated(req: Req, res: Res, code: string, error: string,
                          why: string): null {
    const { log, errorCodes } = this.deps;
    log.debug("Entering UmaPat.unauthenticated(). " + code);
    errorCodes.mark(res, code);
    const realm = this.issuerOf(req).replace(/"/g, '');
    const challenge = 'Bearer realm="' + realm + '"' +
      (error ? ', error="' + error + '"' : '');
    // error-code: none — marked on the line above.
    UmaPat.send(res, 401, error, why, challenge);
    log.debug("Leaving UmaPat.unauthenticated().");
    return null;
  }

  // A 403 under its code.
  private forbidden(res: Res, code: string, error: string, why: string,
                    challenge?: string): null {
    const { log, errorCodes } = this.deps;
    log.debug("Entering UmaPat.forbidden(). " + code);
    errorCodes.mark(res, code);
    // error-code: none — marked on the line above.
    UmaPat.send(res, 403, error, why, challenge);
    log.debug("Leaving UmaPat.forbidden().");
    return null;
  }

  /**
   * Authenticates a protection API request by its PAT, and answers who the
   * resource owner and the resource server are. Writes the refusal.
   *
   * @param req - the request
   * @param res - the response, written on a refusal
   * @returns the caller, or null when a refusal was written
   */
  authenticate(req: Req, res: Res): PatCaller | null {
    const self = this;
    const { log, helpers, mtls, applications, scopes } = this.deps;
    log.debug("Entering UmaPat.authenticate().");
    const presented = UmaPat.presented(req);
    if (!presented.token) {
      log.debug("Leaving UmaPat.authenticate(). None.");
      return self.unauthenticated(req, res, 'STS-UMA-0100', '',
        'The UMA protection API takes a protection API token (PAT): an ' +
        'access token of this realm audienced to its /uma and carrying ' +
        'uma_protection, sent as Authorization: Bearer (or DPoP).');
    }
    const oauth = self.deps.loadOAuth();
    let claims: Json = null;
    let opaque = false;
    try {
      claims = helpers.verifyOwnJws(presented.token);
    } catch (e) {
      log.debug("Caught in UmaPat.authenticate(): " +
                ((e && e.message) || e));
      claims = null;
    }
    if (!claims && presented.token.indexOf('.') < 0) {
      const found = oauth.opaque.lookup(presented.token);
      if (found && found.kind === 'active') {
        claims = found.claims;
        opaque = true;
      } else if (found && found.kind === 'unknown' &&
                 oauth.opaque.issuesOpaque()) {
        const limited = oauth.opaque.noteMiss(req);
        if (limited) {
          res.set('Retry-After', String(limited.retryAfterS));
          self.deps.errorCodes.mark(res, 'STS-OAUTH-0983');
          // error-code: none — marked on the line above.
          UmaPat.send(res, 429, '', 'Too many attempts. Wait ' +
                      limited.retryAfterS + ' seconds and try again.');
          log.debug("Leaving UmaPat.authenticate(). Too many handles.");
          return null;
        }
      }
    }
    const invalid = function (code: string, why: string): null {
      log.debug("Entering invalid(). " + code);
      log.debug("Leaving invalid().");
      // error-code: none — invalid()'s caller names STS-UMA-0101..0107.
      return self.unauthenticated(req, res, code, 'invalid_token', why);
    };
    if (!claims) {
      log.debug("Leaving UmaPat.authenticate(). Does not verify.");
      return invalid('STS-UMA-0101', 'That token was not issued by this ' +
                     'realm, or its signature does not verify.');
    }
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && Number(claims.exp) <= now) {
      log.debug("Leaving UmaPat.authenticate(). Expired.");
      return invalid('STS-UMA-0101', 'That token has expired.');
    }
    if (!opaque && !oauth.jwt.isAccessTokenType(
        oauth.jwt.typOf(presented.token))) {
      log.debug("Leaving UmaPat.authenticate(). Not an access token.");
      return invalid('STS-UMA-0101', 'That token is not an access token.');
    }
    const base = self.issuerOf(req);
    if (!oauth.jwt.isHostedIssuer(claims.iss, base)) {
      log.debug("Leaving UmaPat.authenticate(). Another issuer.");
      return invalid('STS-UMA-0101', 'That token was issued by another ' +
                     'authorization server.');
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud
      : (claims.aud === undefined || claims.aud === null ? [] : [claims.aud]);
    const wanted = self.audiencesOf(req);
    if (!audiences.some(function (one: unknown) {
      return wanted.indexOf(String(one)) >= 0;
    })) {
      log.debug("Leaving UmaPat.authenticate(). Another audience.");
      return invalid('STS-UMA-0102', 'That token is not a protection API ' +
                     'token for this realm: its audience must be this ' +
                     'realm\'s /uma.');
    }
    const clientId = String(claims.client_id || '');
    if (claims.jti && oauth.stats.isRevoked(String(claims.jti))) {
      log.debug("Leaving UmaPat.authenticate(). Revoked.");
      return invalid('STS-UMA-0106', 'That token has been revoked.');
    }
    const problem = mtls.checkBinding(claims, req, true);
    if (problem) {
      log.debug("Leaving UmaPat.authenticate(). Certificate binding.");
      return invalid('STS-UMA-0107', String(problem.description ||
        'The token is bound to a certificate that was not presented.'));
    }
    const jkt = oauth.dpop.jktOf(claims);
    let proofOk = false;
    if (jkt) {
      if (presented.scheme !== 'dpop') {
        log.debug("Leaving UmaPat.authenticate(). Sent as Bearer.");
        return invalid('STS-UMA-0107', 'That token is DPoP-bound, so it ' +
                       'must be sent as DPoP.');
      }
      const checked = oauth.dpop.verifyProof(req.headers.dpop, {
        htm: req.method, htu: oauth.dpop.htuOf(req),
        accessToken: presented.token, expectedJkt: jkt, req: req });
      if (!checked.ok) {
        if (checked.needNonce) {
          res.set('DPoP-Nonce', oauth.dpop.issueNonce());
        }
        log.debug("Leaving UmaPat.authenticate(). DPoP proof refused.");
        return invalid('STS-UMA-0107', String(checked.description ||
                       'The DPoP proof was refused.'));
      }
      proofOk = true;
    }
    let entry: Json = {};
    try {
      entry = applications.clientConfigOf(clientId) || {};
    } catch (e) {
      log.debug("Caught in UmaPat.authenticate(): " + ((e && e.message) || e));
      entry = {};
    }
    const thumb = mtls.boundThumbprintOf(claims);
    const required = oauth.sender.accessTokenRefusal({
      where: 'the UMA protection API',
      clientBound: oauth.sender.dpopBoundPublicClient(clientId,
        entry.token_endpoint_auth_method),
      boundJkt: jkt, proofOk: proofOk, boundThumbprint: thumb,
      certificate: !!mtls.peerCertificate(req),
      certificateMatches: !!thumb && mtls.peerVerified(req) &&
        mtls.presentedThumbprint(req) === thumb,
      mtlsAvailable: mtls.available()
    });
    if (required) {
      log.debug("Leaving UmaPat.authenticate(). Sender constraint.");
      return invalid('STS-UMA-0107', String(required.description ||
                     'The token\'s sender constraint was not met.'));
    }
    const carried = String(claims.scope || '').split(/\s+/).filter(Boolean);
    if (carried.indexOf(SCOPE) < 0 || !scopes.declares(clientId, SCOPE)) {
      log.debug("Leaving UmaPat.authenticate(). No uma_protection.");
      return self.forbidden(res, 'STS-UMA-0103', 'insufficient_scope',
        'That token does not carry uma_protection, or its client no longer ' +
        'holds a delegated permission grant of ' +
        'urn:sts:uma-protection-api:uma_protection on ' +
        'sts-uma-protection-api.',
        'Bearer realm="' + base.replace(/"/g, '') +
        '", error="insufficient_scope", scope="' + SCOPE + '"');
    }
    const registered = clientId ? applications.forClientId(clientId) : null;
    const identifier = registered ? String(registered.identifier || '') : '';
    const declared = registered
      ? applications.declaredFamiliesOf(registered) : [];
    if (!identifier || declared.indexOf('uma') < 0) {
      log.debug("Leaving UmaPat.authenticate(). Not a resource server.");
      return self.forbidden(res, 'STS-UMA-0104', 'invalid_token',
        'The client this token was issued to is not an application ' +
        'declared for the protocol uma (appAllowedProtocol), so it is no ' +
        'UMA resource server in this realm.');
    }
    // WHO THE OWNER IS. A client_credentials token's `sub` is its client_id,
    // or `urn:sts:client:<id>` in RFC 9700 mode (`oauth2.ts`'s tokenGrant);
    // anything else is a person's.
    const sub = String(claims.sub || '');
    const own = sub === clientId || sub === 'urn:sts:client:' + clientId;
    if (own) {
      const fields = (registered && registered.fields) || {};
      const may = String([].concat(fields.umaOwnsResources || [])[0] || '')
        .toUpperCase() === 'TRUE';
      if (!may) {
        log.debug("Leaving UmaPat.authenticate(). The application may not " +
                  "own resources.");
        return self.forbidden(res, 'STS-UMA-0105', 'invalid_token',
          'That token was issued to the client as itself, and the ' +
          'application "' + identifier + '" does not carry ' +
          'umaOwnsResources TRUE, so there is no resource owner for what ' +
          'it would register. Obtain the PAT by the code flow, as the ' +
          'resource owner, or let the application own resources.');
      }
      log.debug("Leaving UmaPat.authenticate(). The application owns.");
      return { ownerKind: 'application', owner: identifier, username: '',
               clientId: clientId, resourceServer: identifier,
               scope: carried, jti: String(claims.jti || '') };
    }
    const username = helpers.nameForSubject(sub);
    if (!sub || !username) {
      log.debug("Leaving UmaPat.authenticate(). The subject is nobody here.");
      return invalid('STS-UMA-0101', 'That token\'s subject is not a ' +
                     'person of this realm.');
    }
    log.debug("Leaving UmaPat.authenticate(). " + username);
    return { ownerKind: 'user', owner: sub, username: username,
             clientId: clientId, resourceServer: identifier, scope: carried,
             jti: String(claims.jti || '') };
  }
}

const slot = new InstanceSlot<UmaPat>(
  'uma/uma_pat',
  () => new UmaPat(UmaPat.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The UMA 2.0 protection API token's door (#1168).
 * @namespace
 */
export = {
  UmaPat: UmaPat,
  installInstance: (instance: UmaPat): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SCOPE: SCOPE,
  presented: UmaPat.presented,
  send: UmaPat.send,
  authenticate: slot.forward('authenticate'),
  audiencesOf: slot.forward('audiencesOf'),
  issuerOf: slot.forward('issuerOf')
};
