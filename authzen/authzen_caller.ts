// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen_caller.ts
//
// ===========================================================================
// WHO IS ASKING, WHETHER THEY MAY, AND ABOUT WHICH APPLICATION (#563, phase
// 2, #1161).
//
// AuthZEN 1.0 leaves authenticating the PEP to the deployment (section 11.2)
// and asks only that a failure be a 401 that SHOULD carry WWW-Authenticate
// (section 11.3). So everything here is this service's, and it is three
// questions asked in this order, each by the module that owns the answer:
//
//   1. WHO. `authzen.callerAuthentication`, per realm:
//        mtls          (THE DEFAULT, rcbj 2026-10-29) a client certificate
//                      this service VERIFIES, resolved to the directory
//                      entry storing it — `xacml/xacml.ts`'s
//                      `callerIdentity()`, the four links' first two, so one
//                      certificate names one entry on every surface;
//        bearer        an OAuth 2.0 access token from client_credentials,
//                      audienced to this realm's /access/v1 and carrying
//                      `authzen:evaluate`; the caller is the CLIENT;
//        mtls+bearer   both, and the token must be bound to the very
//                      certificate presented (RFC 8705's x5t#S256), so the
//                      two credentials name one party rather than two.
//      Checked in EVERY mode: a decision endpoint anybody can drive maps the
//      policy one question at a time.
//   2. MAY THEY. The roles that caller holds now, and the access-control
//      policy on resource `authzen-api` with AUTHZEN_PEPS required — the
//      four links' last two, `common/access_gate.ts`. A role, not an `if`,
//      so `/admin/xacml/decide` reproduces the answer.
//   3. ABOUT WHICH APPLICATION (decision 1). The REALM is AuthZEN's tenant,
//      set by the path prefix, and the caller is looked up in that realm's
//      directory, so another realm's caller is nobody here. Inside the realm
//      the scope is an administrator's: `stsAuthzenApplication` on a person's
//      or service account's entry, `appAuthzenApplication` on an
//      application's — and an OAuth caller's own application is always in
//      it. `context.application` must be in the set (403 otherwise); with
//      none named and exactly one in the set, that one.
//
// **THE SELF-REGISTERED `ou=peps` ROW IS NOT CONSULTED.** A remote PEP's
// registration is visibility and a nudge, never a permission
// (`xacml/xacml_pep_registry.ts`), and it would be the first thing a caller
// could write that decided what it may ask.
//
// **NOTHING LEARNT HERE REACHES THE QUESTION'S SUBJECT.** The caller and its
// application go into the request as TRUSTED facts in the environment
// (`urn:sts:xacml:authzen:caller`, `:application`); the subject the decision
// is ABOUT is the request's `subject`, exactly as on `POST /xacml/pdp`.
// ===========================================================================

import helpers = require('../common/helpers');

const { log } = helpers;

type Req = import('express').Request;
type Res = import('express').Response;

// The role `/access/v1` requires. Named once, for `xacml.ts`'s reason: a
// rename in `roles.js` is one line to follow here.
const AUTHZEN_ROLE = 'AUTHZEN_PEPS';

// The scope a token must carry. AuthZEN defines none.
const AUTHZEN_SCOPE = 'authzen:evaluate';

// The three doors.
const DOORS = Object.freeze(['mtls', 'bearer', 'mtls+bearer']);

// Who is asking, once authenticated.
interface Caller {
  // `entry` for a certificate's directory entry, `application` for a
  // client's own token.
  kind: string;
  // The trusted fact: an entry's DN, or the client_id.
  name: string;
  door: string;
  // The application entry an `application` caller is, and the client_id.
  identifier: string;
  clientId: string;
  roles: string[];
}

// What `applicationOf()` answers.
interface Scoped {
  application?: string;
  status?: number;
  code?: string;
  message?: string;
}

interface CallerDeps {
  log: typeof log;
  config: any;
  errorCodes: any;
  realms: any;
  roles: any;
  accessGate: any;
  applications: any;
  helpers: any;
  mtls: any;
  pip: any;
  // Loaded when a token arrives, never at load: the OAuth libraries.
  loadOAuth(): any;
  // `xacml/xacml.ts`'s surface, for the certificate reading.
  loadXacml(): any;
  // Loaded when a remote PEP pulls the edge caller list (#1189), never at
  // load: the AuthZEN tab's directory reading (the group's members), the
  // TLS client certificates this realm issued, and the directory codec's
  // one reading of a stored `userCertificate` value.
  loadAdmin(): any;
  loadCertificates(): any;
  loadCodec(): any;
  // The SHA-256 of a certificate's DER, lower-case hex: the spelling the
  // door's index keys a stored certificate by.
  sha256Hex(der: Buffer): string;
}

// What `admission()` answers.
interface Admission {
  allowed: boolean;
  why: string;
}

// The most group members, and the most certificates of one caller, the
// edge caller list reads (#1189). Bounds, because the list is built per
// pull; past either the list is CUT and says so, which leaves an edge
// narrower than the service and never wider.
const EDGE_MAX_MEMBERS = 500;
const EDGE_MAX_CERTIFICATES = 64;

// The two endpoints an edge PDP serves, whose paths the access-control
// policy is asked about for each caller — the path a request to the
// service itself would carry, so a policy that tells the single endpoint
// from the batch decides the edge's list the same way.
const EDGE_ENDPOINTS = Object.freeze([
  { name: 'evaluation', path: '/access/v1/evaluation' },
  { name: 'evaluations', path: '/access/v1/evaluations' }
]);

/**
 * The AuthZEN caller: its authentication, the access-control policy's
 * answer about it, and its application scope.
 */
class AuthzenCaller {
  /**
   * Builds the caller checks over their dependencies.
   *
   * @param deps - the logger, settings, error codes, realms, roles, the
   *   access gate, the application registry, helpers, mutual TLS, the PIP,
   *   and lazy loaders for the OAuth libraries and the XACML surface
   */
  constructor(private readonly deps: CallerDeps) {
    deps.log.debug("Entering AuthzenCaller.constructor().");
    deps.log.debug("Leaving AuthzenCaller.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): CallerDeps {
    log.debug("Entering AuthzenCaller.defaultDeps().");
    log.debug("Leaving AuthzenCaller.defaultDeps().");
    return {
      log: log,
      config: require('../common/config'),
      errorCodes: require('../common/error_codes'),
      realms: require('../common/realms'),
      roles: require('../common/roles'),
      accessGate: require('../common/access_gate'),
      applications: require('../common/applications'),
      helpers: helpers,
      mtls: require('../oauth-oidc/mtls'),
      pip: require('../xacml/xacml_pip'),
      loadOAuth: function (): any {
        log.debug("Entering loadOAuth().");
        log.debug("Leaving loadOAuth().");
        return {
          jwt: require('../oauth-oidc/jwt_access_token'),
          opaque: require('../oauth-oidc/opaque_access_token'),
          dpop: require('../oauth-oidc/dpop'),
          sender: require('../oauth-oidc/sender_constraints'),
          stats: require('../common/admin_stats'),
          scopes: require('../common/scope_policy')
        };
      },
      loadXacml: function (): any {
        log.debug("Entering loadXacml().");
        log.debug("Leaving loadXacml().");
        return require('../xacml/xacml');
      },
      loadAdmin: function (): any {
        log.debug("Entering loadAdmin().");
        log.debug("Leaving loadAdmin().");
        return require('./authzen_admin');
      },
      loadCertificates: function (): any {
        log.debug("Entering loadCertificates().");
        log.debug("Leaving loadCertificates().");
        return require('../common/tls_client_certificates');
      },
      loadCodec: function (): any {
        log.debug("Entering loadCodec().");
        log.debug("Leaving loadCodec().");
        return require('../persistence/directory_codec');
      },
      sha256Hex: function (der: Buffer): string {
        log.debug("Entering sha256Hex().");
        log.debug("Leaving sha256Hex().");
        return String(require('../common/crypto').digest('sha256', der,
                                                         'hex'));
      }
    };
  }

  /**
   * The realm's door: `authzen.callerAuthentication`, mtls unless it says
   * otherwise.
   *
   * @returns mtls, bearer or mtls+bearer
   */
  door(): string {
    const { log, config } = this.deps;
    log.debug("Entering AuthzenCaller.door().");
    const asked = String(config.value('authzen.callerAuthentication') || '');
    log.debug("Leaving AuthzenCaller.door(). " + asked);
    return DOORS.indexOf(asked) >= 0 ? asked : 'mtls';
  }

  /**
   * The realm's issuer, which a Bearer challenge names.
   *
   * @param req - the request
   * @returns the base URL of this realm
   */
  issuerOf(req: Req): string {
    const { log, helpers } = this.deps;
    log.debug("Entering AuthzenCaller.issuerOf().");
    log.debug("Leaving AuthzenCaller.issuerOf().");
    return String(helpers.baseUrlOf(req) || '');
  }

  /**
   * Writes an AuthZEN error: the status and a message, as
   * `{ error: { status, message } }` — the shape a batch item's
   * `context.error` takes, so a PEP reads one shape either way.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param message - what the caller is told
   */
  // error-code: none — the helper's definition, not a call to it.
  static send(res: Res, status: number, message: string): void {
    log.debug("Entering AuthzenCaller.send(). " + status);
    res.status(status).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: { status: status, message: message } },
                            null, 2));
    log.debug("Leaving AuthzenCaller.send().");
  }

  // A 401, with a Bearer challenge wherever a token is a door (section
  // 11.3's SHOULD); a door of certificates alone has no scheme to name.
  // error-code: none — the helper's definition; each caller passes its code.
  private unauthenticated(req: Req, res: Res, code: string, error: string,
                          message: string): null {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering AuthzenCaller.unauthenticated(). " + code);
    if (self.door() !== 'mtls') {
      res.set('WWW-Authenticate', 'Bearer realm="' +
              self.issuerOf(req).replace(/"/g, '') + '"' +
              (error ? ', error="' + error + '"' : ''));
    }
    errorCodes.mark(res, code);
    // error-code: none — marked on the line above with the caller's code.
    AuthzenCaller.send(res, 401, message);
    log.debug("Leaving AuthzenCaller.unauthenticated().");
    return null;
  }

  // A 403.
  private forbidden(res: Res, code: string, message: string): null {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AuthzenCaller.forbidden(). " + code);
    errorCodes.mark(res, code);
    // error-code: none — marked on the line above with the caller's code.
    AuthzenCaller.send(res, 403, message);
    log.debug("Leaving AuthzenCaller.forbidden().");
    return null;
  }

  /**
   * Authenticates the caller by the realm's door, answering 401 (or 403
   * for a token that is valid and not for this) when it cannot.
   *
   * @param req - the request
   * @param res - the response, written on a refusal
   * @returns the caller, or null when a refusal was written
   */
  authenticate(req: Req, res: Res): Caller | null {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AuthzenCaller.authenticate().");
    const door = self.door();
    let caller: Caller | null = null;
    if (door === 'mtls') {
      caller = self.byCertificate(req, res);
    } else {
      const certificate = door === 'mtls+bearer'
        ? self.byCertificate(req, res) : null;
      if (door === 'mtls+bearer' && !certificate) {
        log.debug("Leaving AuthzenCaller.authenticate(). No certificate.");
        return null;
      }
      caller = self.byToken(req, res, door === 'mtls+bearer');
    }
    if (caller) {
      caller.door = door;
    }
    log.debug("Leaving AuthzenCaller.authenticate(). " +
              (caller ? caller.kind + ' ' + caller.name : 'Refused.'));
    return caller;
  }

  // THE CERTIFICATE DOOR: links 1 and 2, read by the XACML surface's own
  // `callerIdentity()`.
  private byCertificate(req: Req, res: Res): Caller | null {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering AuthzenCaller.byCertificate().");
    const identity = self.deps.loadXacml().callerIdentity(req);
    if (!identity.authenticated) {
      log.debug("Leaving AuthzenCaller.byCertificate(). None.");
      return self.unauthenticated(req, res, 'STS-AUTHZEN-0015', '',
        'This AuthZEN API authenticates its caller by a client certificate ' +
        '(authzen.callerAuthentication is ' + self.door() + '), and none ' +
        'was presented.');
    }
    if (!identity.verified) {
      log.debug("Leaving AuthzenCaller.byCertificate(). Did not verify.");
      const code = identity.revocationRefused
        ? (errorCodes.codeOf(identity.revocation) || 'STS-PKI-0118')
        : 'STS-AUTHZEN-0016';
      return self.unauthenticated(req, res, code, '',
        'The client certificate did not verify against this service\'s ' +
        'client truststore: ' + String(identity.why || '').slice(0, 300));
    }
    if (identity.unmapped || !identity.dn) {
      log.debug("Leaving AuthzenCaller.byCertificate(). Names nobody.");
      return self.unauthenticated(req, res, 'STS-AUTHZEN-0017', '',
        'The client certificate verified and names no entry in this ' +
        'realm: ' + String(identity.why || 'it resolves to nobody') + '.');
    }
    log.debug("Leaving AuthzenCaller.byCertificate(). " + identity.dn);
    return { kind: 'entry', name: String(identity.dn), door: 'mtls',
             identifier: '', clientId: '', roles: [] };
  }

  // THE TOKEN DOOR: an access token this realm issued, to a client, for
  // this API. Read as `report/report_api.ts` reads its own, less the
  // person: an AuthZEN caller on this door is the client itself.
  private byToken(req: Req, res: Res, bound: boolean): Caller | null {
    const self = this;
    const { log, helpers, mtls, applications } = this.deps;
    log.debug("Entering AuthzenCaller.byToken().");
    const presented = AuthzenCaller.presented(req);
    if (!presented.token) {
      log.debug("Leaving AuthzenCaller.byToken(). None.");
      return self.unauthenticated(req, res, 'STS-AUTHZEN-0018', '',
        'This AuthZEN API takes an OAuth 2.0 access token from ' +
        'client_credentials, audienced to this realm\'s /access/v1 and ' +
        'carrying authzen:evaluate, sent as Authorization: Bearer (or ' +
        'DPoP).');
    }
    const oauth = self.deps.loadOAuth();
    let claims: any = null;
    let opaque = false;
    try {
      claims = helpers.verifyOwnJws(presented.token);
    } catch (e) {
      log.debug("Caught in AuthzenCaller.byToken(): " +
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
          AuthzenCaller.send(res, 429, 'Too many attempts. Wait ' +
                             limited.retryAfterS + ' seconds and try again.');
          log.debug("Leaving AuthzenCaller.byToken(). Too many handles.");
          return null;
        }
      }
    }
    const invalid = function (why: string): null {
      log.debug("Entering invalid().");
      log.debug("Leaving invalid().");
      return self.unauthenticated(req, res, 'STS-AUTHZEN-0019',
                                  'invalid_token', why);
    };
    if (!claims) {
      log.debug("Leaving AuthzenCaller.byToken(). Does not verify.");
      return invalid('That access token was not issued by this realm, or ' +
                     'its signature does not verify.');
    }
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && Number(claims.exp) <= now) {
      log.debug("Leaving AuthzenCaller.byToken(). Expired.");
      return invalid('That access token has expired.');
    }
    if (!opaque && !oauth.jwt.isAccessTokenType(
        oauth.jwt.typOf(presented.token))) {
      log.debug("Leaving AuthzenCaller.byToken(). Not an access token.");
      return invalid('That token is not an access token.');
    }
    const base = self.issuerOf(req);
    if (!oauth.jwt.isHostedIssuer(claims.iss, base)) {
      log.debug("Leaving AuthzenCaller.byToken(). Another issuer.");
      return invalid('That access token was issued by another ' +
                     'authorization server.');
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud
      : (claims.aud === undefined || claims.aud === null ? [] : [claims.aud]);
    if (!AuthzenCaller.audienceOk(audiences, base)) {
      log.debug("Leaving AuthzenCaller.byToken(). Another audience.");
      return self.unauthenticated(req, res, 'STS-AUTHZEN-0020',
        'invalid_token', 'That access token is not for this API: its ' +
        'audience must be this realm\'s /access/v1.');
    }
    const clientId = String(claims.client_id || '');
    if (claims.jti && oauth.stats.isRevoked(String(claims.jti))) {
      log.debug("Leaving AuthzenCaller.byToken(). Revoked.");
      return invalid('That access token has been revoked.');
    }
    const problem = mtls.checkBinding(claims, req, true);
    if (problem) {
      log.debug("Leaving AuthzenCaller.byToken(). Certificate binding.");
      return invalid(String(problem.description || 'The token is bound to ' +
                            'a certificate that was not presented.'));
    }
    const jkt = oauth.dpop.jktOf(claims);
    let proofOk = false;
    if (jkt) {
      if (presented.scheme !== 'dpop') {
        log.debug("Leaving AuthzenCaller.byToken(). Sent as Bearer.");
        return invalid('That access token is DPoP-bound, so it must be ' +
                       'sent as DPoP.');
      }
      const checked = oauth.dpop.verifyProof(req.headers.dpop, {
        htm: req.method, htu: oauth.dpop.htuOf(req),
        accessToken: presented.token, expectedJkt: jkt, req: req });
      if (!checked.ok) {
        if (checked.needNonce) {
          res.set('DPoP-Nonce', oauth.dpop.issueNonce());
        }
        log.debug("Leaving AuthzenCaller.byToken(). DPoP proof refused.");
        return invalid(String(checked.description || 'The DPoP proof was ' +
                              'refused.'));
      }
      proofOk = true;
    }
    let entry: any = {};
    try {
      entry = applications.clientConfigOf(clientId) || {};
    } catch (e) {
      log.debug("Caught in AuthzenCaller.byToken(): " +
                ((e && e.message) || e));
      entry = {};
    }
    const thumb = mtls.boundThumbprintOf(claims);
    const required = oauth.sender.accessTokenRefusal({
      where: 'the AuthZEN API',
      clientBound: oauth.sender.dpopBoundPublicClient(clientId,
        entry.token_endpoint_auth_method),
      boundJkt: jkt, proofOk: proofOk, boundThumbprint: thumb,
      certificate: !!mtls.peerCertificate(req),
      certificateMatches: !!thumb && mtls.peerVerified(req) &&
        mtls.presentedThumbprint(req) === thumb,
      mtlsAvailable: mtls.available()
    });
    if (required) {
      log.debug("Leaving AuthzenCaller.byToken(). Sender constraint.");
      return invalid(String(required.description || 'The token\'s sender ' +
                            'constraint was not met.'));
    }
    if (bound && !(thumb && mtls.peerVerified(req) &&
                   mtls.presentedThumbprint(req) === thumb)) {
      log.debug("Leaving AuthzenCaller.byToken(). Not bound to the " +
                "certificate presented.");
      return self.unauthenticated(req, res, 'STS-AUTHZEN-0023',
        'invalid_token', 'authzen.callerAuthentication is mtls+bearer, so ' +
        'the access token must be bound to the client certificate ' +
        'presented (RFC 8705, cnf x5t#S256), and this one is not.');
    }
    // THE CLIENT, NOT A PERSON. A client_credentials token's `sub` is its
    // client_id, or `urn:sts:client:<id>` in RFC 9700 mode
    // (`oauth2.ts`'s tokenGrant); anything else is a person's token, and a
    // person is not an enforcement point.
    const sub = String(claims.sub || '');
    if (!clientId || (sub !== clientId && sub !== 'urn:sts:client:' +
                      clientId)) {
      log.debug("Leaving AuthzenCaller.byToken(). A person's token.");
      return self.forbidden(res, 'STS-AUTHZEN-0022',
        'That access token was issued to a person. An AuthZEN caller is ' +
        'the client itself, on client_credentials.');
    }
    const carried = String(claims.scope || '').split(/\s+/).filter(Boolean);
    if (carried.indexOf(AUTHZEN_SCOPE) < 0 ||
        !oauth.scopes.declares(clientId, AUTHZEN_SCOPE)) {
      log.debug("Leaving AuthzenCaller.byToken(). No authzen:evaluate.");
      res.set('WWW-Authenticate', 'Bearer realm="' +
              base.replace(/"/g, '') + '", error="insufficient_scope", ' +
              'scope="' + AUTHZEN_SCOPE + '"');
      return self.forbidden(res, 'STS-AUTHZEN-0021',
        'That access token does not carry authzen:evaluate, or its client ' +
        'no longer holds a delegated permission grant of ' +
        'urn:sts:authzen-api:authzen:evaluate on sts-authzen-api.');
    }
    const registered = applications.forClientId(clientId);
    log.debug("Leaving AuthzenCaller.byToken(). " + clientId);
    return { kind: 'application', name: clientId, door: 'bearer',
             identifier: registered ? String(registered.identifier) : '',
             clientId: clientId, roles: [] };
  }

  /**
   * The token a request presents, and the scheme it was sent under.
   *
   * @param req - the request
   * @returns `{ token, scheme }`, both '' when there is none
   */
  static presented(req: Req): { token: string; scheme: string } {
    log.debug("Entering AuthzenCaller.presented().");
    const header = String(req.headers.authorization || '');
    const matched = /^(Bearer|DPoP)\s+([A-Za-z0-9\-._~+/]+=*)\s*$/i
      .exec(header);
    log.debug("Leaving AuthzenCaller.presented().");
    return matched ? { token: matched[2], scheme: matched[1].toLowerCase() }
      : { token: '', scheme: '' };
  }

  /**
   * Whether a token's audiences name this realm's /access/v1, with or
   * without the slash a permission base adds.
   *
   * @param audiences - the token's `aud` values
   * @param base - the realm's base URL
   * @returns true when one does
   */
  static audienceOk(audiences: unknown[], base: string): boolean {
    log.debug("Entering AuthzenCaller.audienceOk().");
    const exact = base + '/access/v1';
    const ok = (audiences || []).some(function (one: unknown) {
      return String(one) === exact || String(one) === exact + '/';
    });
    log.debug("Leaving AuthzenCaller.audienceOk(). " + ok);
    return ok;
  }

  /**
   * The roles a caller holds now. An entry's groups are the directory's
   * reading; an application's are the groups whose members name its entry,
   * which the role register does not read for an application by itself.
   *
   * @param caller - the caller
   * @returns the role names
   */
  rolesOf(caller: Caller): string[] {
    const { log, roles, applications } = this.deps;
    log.debug("Entering AuthzenCaller.rolesOf(). " + caller.kind);
    if (caller.kind === 'entry') {
      log.debug("Leaving AuthzenCaller.rolesOf(). An entry.");
      return roles.rolesOf({ kind: 'user', name: caller.name,
                             authenticated: true });
    }
    let groups: string[] = [];
    const entry = caller.identifier ? applications.get(caller.identifier)
      : null;
    if (entry && entry.dn) {
      try {
        groups = (roles.groupsOf(String(entry.dn)) || []).map(String);
      } catch (e) {
        // No directory: an application in no group, which holds no group
        // role — the refusal below says so.
        log.debug("Caught in AuthzenCaller.rolesOf(): " +
                  ((e && e.message) || e));
        groups = [];
      }
    }
    log.debug("Leaving AuthzenCaller.rolesOf(). An application in " +
              groups.length + " group(s).");
    return roles.rolesOf({ kind: 'application', name: caller.clientId,
                           authenticated: true, groups: groups });
  }

  /**
   * Asks the access-control policy whether the caller may ask: resource
   * `authzen-api`, AUTHZEN_PEPS required. Answers 403 when it may not.
   *
   * @param req - the request
   * @param res - the response, written on a refusal
   * @param caller - the authenticated caller; its `roles` are filled in
   * @returns true when it may ask
   */
  mayAsk(req: Req, res: Res, caller: Caller): boolean {
    const self = this;
    const { log, config } = this.deps;
    log.debug("Entering AuthzenCaller.mayAsk().");
    caller.roles = self.rolesOf(caller);
    const policy = self.admission(caller, req.method,
                                  req.originalUrl || req.url);
    if (policy.allowed) {
      log.debug("Leaving AuthzenCaller.mayAsk(). Allowed.");
      return true;
    }
    log.info('authzen: the access policy refused ' + caller.name + '. ' +
             policy.why);
    self.forbidden(res, 'STS-AUTHZEN-0024',
      'The access policy refused this caller. ' + policy.why + ' The ' +
      'AuthZEN API requires the built-in ' + AUTHZEN_ROLE + ' role, held by ' +
      'membership of the group named by roles.authzenPepGroup ("' +
      String(config.value('roles.authzenPepGroup') || '') + '"). This ' +
      'caller is ' + caller.name + ' and holds ' +
      (caller.roles.length ? caller.roles.join(', ') : 'no role') + '.');
    log.debug("Leaving AuthzenCaller.mayAsk(). Refused.");
    return false;
  }

  /**
   * The access-control policy's answer about a caller whose roles are
   * filled in, for a method and a path: resource `authzen-api`,
   * AUTHZEN_PEPS required. Writes nothing — `mayAsk()` writes the refusal
   * for a request, and `edgeCallers()` asks it for each caller a remote
   * PEP is told about, so the two cannot ask different questions.
   *
   * @param caller - the caller, `roles` filled in
   * @param method - the HTTP method
   * @param path - the request path, the realm's prefix included
   * @returns `{ allowed, why }`
   */
  admission(caller: Caller, method: string, path: string): Admission {
    const { log, accessGate } = this.deps;
    log.debug("Entering AuthzenCaller.admission().");
    const policy = accessGate.check({
      resource: accessGate.RESOURCE.AUTHZEN_API,
      // WRITE, for `POST /xacml/pdp`'s reason: a decision is work a caller
      // directs on this service's thread, not a page it reads.
      action: accessGate.ACTION.WRITE,
      requiredRoles: [AUTHZEN_ROLE],
      subject: { name: caller.kind === 'entry' ? caller.name
                                                : caller.clientId,
                 kind: caller.kind === 'entry' ? 'user' : 'application',
                 authenticated: true, roles: caller.roles },
      context: { method: method, path: path }
    });
    log.debug("Leaving AuthzenCaller.admission(). " + !!policy.allowed);
    return { allowed: !!policy.allowed, why: String(policy.why || '') };
  }

  /**
   * The applications a caller is scoped to: an entry's
   * `stsAuthzenApplication`, an application's `appAuthzenApplication` and
   * its own identifiers.
   *
   * @param caller - the caller
   * @returns the application names, in order, without repeats
   */
  scopeOf(caller: Caller): string[] {
    const { log, applications, pip } = this.deps;
    log.debug("Entering AuthzenCaller.scopeOf(). " + caller.kind);
    const out: string[] = [];
    const add = function (value: unknown): void {
      log.debug("Entering add().");
      const text = String(value == null ? '' : value).trim();
      if (text && out.indexOf(text) < 0) {
        out.push(text);
      }
      log.debug("Leaving add().");
    };
    if (caller.kind === 'entry') {
      const stored = pip.locateSubject(caller.name);
      const values = stored
        ? pip.rawAttribute(stored.attributes, 'stsAuthzenApplication') : null;
      (Array.isArray(values) ? values : (values ? [values] : []))
        .forEach(add);
    } else {
      add(caller.identifier);
      add(caller.clientId);
      const entry = caller.identifier ? applications.get(caller.identifier)
        : null;
      const values = entry && entry.fields
        ? entry.fields.appAuthzenApplication : null;
      (Array.isArray(values) ? values : (values ? [values] : []))
        .forEach(add);
    }
    log.debug("Leaving AuthzenCaller.scopeOf(). " + out.length);
    return out;
  }

  // ===========================================================================
  // THE CALLERS A REMOTE PEP'S EDGE PDP ADMITS (#1189).
  //
  // rcbj's decision on #1189: the `xacml-pep` container's AuthZEN edge PDP
  // admits callers by PULLING them from here (`GET
  // /xacml/pep/authzen-callers`), with the cost accepted that anybody holding
  // REMOTE_PEPS can read who may ask the PDP. So this is the three questions
  // above asked AHEAD of any request, of every certificate a candidate holds,
  // by the same functions a request is asked them by:
  //
  //   1. WHO. Each certificate goes through the certificate door's own
  //      reading — `xacml.ts`'s `certificateCaller()`, `callerIdentity()`
  //      without a socket, over `tls_client_certificates.js`'s one gate — so
  //      the NAME sent is the DN that door would resolve the certificate to,
  //      byte for byte the value a policy sees as
  //      `urn:sts:xacml:authzen:caller`, and the certificate is sent by the
  //      SHA-256 of its DER, which is what the edge compares.
  //   2. MAY THEY. `admission()`, the policy `mayAsk()` asks, for the path of
  //      each endpoint the edge serves, so the OUTCOME is sent — who holds
  //      AUTHZEN_PEPS now as the policy decides it — and not the membership.
  //   3. ABOUT WHICH APPLICATION. `scopeOf()`, as is.
  //
  // **THE CANDIDATES ARE THE GROUP'S MEMBERS** (`roles.authzenPepGroup`,
  // read by `authzen_admin.ts`), and their certificates are the two kinds
  // the door accepts: those stored in `userCertificate` on the entry (an
  // outside authority's, #1061 — and one of this service's own, if stored),
  // and the TLS client certificates this realm issued them that are still
  // valid (`activeFor()`). An entry the policy admits WITHOUT the role, or a
  // certificate enrolled over ACME, EST or SCEP and not stored on the entry,
  // is not found this way and is not listed: the edge is narrower there than
  // the service, never wider.
  //
  // **THE DOOR IS THE REALM'S.** The edge has mutual TLS only; a realm whose
  // `authzen.callerAuthentication` is `bearer` or `mtls+bearer` admits no
  // certificate alone, so it is sent no caller, and the edge admits nobody.
  //
  // **WHAT IS NOT KNOWN HERE IS NOT SENT AS KNOWN.** Whether a chain
  // verifies is each door's own (the service against its Client
  // Truststores, the edge against `PEP_AUTHZEN_CLIENT_CA`). Revocation is
  // the service's register only: a certificate it records as revoked is
  // left out, so a revocation of one it issued reaches the edge on the
  // poll, while an outside authority's CRL or OCSP answer never does.
  // ===========================================================================
  /**
   * The callers an edge PDP admits in the ambient realm: each the name a
   * policy sees, the SHA-256 of every certificate the door would resolve to
   * it, its application scope and the endpoints the policy admits it to.
   *
   * @returns `{ door, group, callers, members, candidates, unlocated,
   *   notAdmitted, unnamed, unreadable, truncated }`
   */
  edgeCallers(): any {
    const self = this;
    const { log, realms, errorCodes } = this.deps;
    log.debug("Entering AuthzenCaller.edgeCallers().");
    const door = self.door();
    const read = self.deps.loadAdmin().edgeCandidates(EDGE_MAX_MEMBERS) ||
      { group: '', total: 0, candidates: [], unlocated: 0 };
    const out: any = {
      door: door, group: String(read.group || ''), callers: [],
      members: Number(read.total || 0),
      candidates: (read.candidates || []).length,
      unlocated: Number(read.unlocated || 0),
      notAdmitted: 0, unnamed: 0, unreadable: 0,
      truncated: Number(read.total || 0) > EDGE_MAX_MEMBERS
    };
    if (door !== 'mtls') {
      log.debug("Leaving AuthzenCaller.edgeCallers(). The realm's door is " +
                door + ", which admits no certificate alone.");
      return out;
    }
    const xacml = self.deps.loadXacml();
    const named = new Map<string, any>();
    (read.candidates || []).forEach(function (candidate: any) {
      const held = self.edgeCertificatesOf(candidate);
      if (held.cut) {
        out.truncated = true;
      }
      out.unreadable += held.unreadable;
      held.certificates.forEach(function (one: any) {
        let identity: any = null;
        try {
          identity = xacml.certificateCaller(one.der);
        } catch (e) {
          log.debug("Caught in AuthzenCaller.edgeCallers(): " +
                    ((e && e.message) || e));
          identity = null;
        }
        if (!identity) {
          out.unreadable++;
          return;
        }
        if (!identity.verified || !identity.dn) {
          out.unnamed++;
          return;
        }
        const key = String(identity.dn).toLowerCase();
        const entry = named.get(key) ||
          { name: String(identity.dn), certificates: [] };
        if (!entry.certificates.some(function (c: any) {
          return c.sha256 === one.sha256;
        })) {
          entry.certificates.push({ sha256: one.sha256,
                                    source: one.source });
        }
        named.set(key, entry);
      });
    });
    const prefix = String(realms.currentPrefix() || '');
    Array.from(named.values()).forEach(function (entry: any) {
      const caller: Caller = { kind: 'entry', name: entry.name,
                               door: 'mtls', identifier: '', clientId: '',
                               roles: [] };
      caller.roles = self.rolesOf(caller);
      const endpoints = EDGE_ENDPOINTS.filter(function (one) {
        return self.admission(caller, 'POST', prefix + one.path).allowed;
      }).map(function (one) {
        return one.name;
      });
      if (!endpoints.length) {
        out.notAdmitted++;
        return;
      }
      out.callers.push({
        name: entry.name,
        certificates: entry.certificates.sort(function (a: any, b: any) {
          return a.sha256 < b.sha256 ? -1 : (a.sha256 > b.sha256 ? 1 : 0);
        }),
        applications: self.scopeOf(caller),
        endpoints: endpoints
      });
    });
    out.callers.sort(function (a: any, b: any) {
      const x = a.name.toLowerCase();
      const y = b.name.toLowerCase();
      return x < y ? -1 : (x > y ? 1 : 0);
    });
    if (out.truncated) {
      log.warn(errorCodes.tag('STS-AUTHZEN-0061') + 'authzen: the caller ' +
               'list a remote PEP pulled was cut: the group "' + out.group +
               '" has ' + out.members + ' member(s) and at most ' +
               EDGE_MAX_MEMBERS + ' are read, each with at most ' +
               EDGE_MAX_CERTIFICATES + ' certificates. A caller past the ' +
               'cut is refused at the edge and still answered here.');
    }
    if (out.unreadable) {
      log.warn(errorCodes.tag('STS-AUTHZEN-0062') + 'authzen: ' +
               out.unreadable + ' certificate(s) held by members of "' +
               out.group + '" could not be read for the caller list a ' +
               'remote PEP pulled, and were left out.');
    }
    log.debug("Leaving AuthzenCaller.edgeCallers(). " + out.callers.length +
              " caller(s).");
    return out;
  }

  // The certificates one candidate holds, each `{ der, sha256, source }`:
  // stored on its entry (`userCertificate`, either spelling, read as the
  // directory codec reads it for the index the door looks a digest up in),
  // then the TLS client certificates this realm issued it that are valid.
  private edgeCertificatesOf(candidate: any): any {
    const { log, realms } = this.deps;
    log.debug("Entering AuthzenCaller.edgeCertificatesOf(). " +
              candidate.kind + " " + candidate.name);
    const self = this;
    const codec = this.deps.loadCodec();
    const out: any[] = [];
    let unreadable = 0;
    let cut = false;
    const add = function (der: any, source: string): void {
      log.debug("Entering add().");
      if (!der) {
        unreadable++;
        log.debug("Leaving add(). Not a certificate.");
        return;
      }
      const sha256 = self.deps.sha256Hex(der);
      if (out.some(function (one: any) {
        return one.sha256 === sha256;
      })) {
        log.debug("Leaving add(). Already held.");
        return;
      }
      if (out.length >= EDGE_MAX_CERTIFICATES) {
        cut = true;
        log.debug("Leaving add(). Past the cap.");
        return;
      }
      out.push({ der: der, sha256: sha256, source: source });
      log.debug("Leaving add().");
    };
    const attributes = candidate.attributes || {};
    Object.keys(attributes).forEach(function (name: string) {
      const lower = name.toLowerCase();
      if (lower !== 'usercertificate;binary' && lower !== 'usercertificate') {
        return;
      }
      const values = attributes[name];
      (Array.isArray(values) ? values : [values]).forEach(function (value) {
        add(codec.certificateDerOf(value), 'stored');
      });
    });
    let issued: any[] = [];
    try {
      issued = this.deps.loadCertificates().activeFor(
        String(realms.currentId() || ''), candidate.name,
        candidate.kind === 'application' ? 'application' : 'person') || [];
    } catch (e) {
      // No certificate authority in this process: nothing was issued here,
      // so there is nothing of that kind to list.
      log.debug("Caught in AuthzenCaller.edgeCertificatesOf(): " +
                ((e && e.message) || e));
      issued = [];
    }
    issued.forEach(function (one: any) {
      add(codec.certificateDerOf(one && one.certificatePem), 'issued');
    });
    log.debug("Leaving AuthzenCaller.edgeCertificatesOf(). " + out.length +
              ".");
    return { certificates: out, unreadable: unreadable, cut: cut };
  }

  /**
   * Chooses the application a question is scoped to (decision 1).
   *
   * @param caller - the caller
   * @param asked - `context.application`, or ''
   * @returns `{ application }`, or `{ status, code, message }`
   */
  applicationOf(caller: Caller, asked: string): Scoped {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AuthzenCaller.applicationOf().");
    const scope = self.scopeOf(caller);
    if (asked) {
      if (scope.indexOf(asked) < 0) {
        log.debug("Leaving AuthzenCaller.applicationOf(). Out of scope.");
        return { status: 403, code: 'STS-AUTHZEN-0025',
                 message: 'context.application "' + asked.slice(0, 120) +
                          '" is not one this caller may ask about.' };
      }
      log.debug("Leaving AuthzenCaller.applicationOf(). As asked.");
      return { application: asked };
    }
    if (scope.length === 1) {
      log.debug("Leaving AuthzenCaller.applicationOf(). The only one.");
      return { application: scope[0] };
    }
    if (!scope.length) {
      log.debug("Leaving AuthzenCaller.applicationOf(). None.");
      return { status: 403, code: 'STS-AUTHZEN-0026',
               message: 'This caller is scoped to no application. An ' +
                        'administrator names the applications a caller may ' +
                        'ask about on its entry.' };
    }
    log.debug("Leaving AuthzenCaller.applicationOf(). Several.");
    return { status: 400, code: 'STS-AUTHZEN-0027',
             message: 'This caller may ask about ' + scope.length +
                      ' applications, so the request must name one in ' +
                      'context.application.' };
  }
}

/**
 * The AuthZEN caller checks (#563): authentication by the realm's door,
 * the access-control policy, and the application scope.
 * @namespace
 */
export = {
  AuthzenCaller: AuthzenCaller,
  AUTHZEN_ROLE: AUTHZEN_ROLE,
  AUTHZEN_SCOPE: AUTHZEN_SCOPE,
  DOORS: DOORS,
  EDGE_ENDPOINTS: EDGE_ENDPOINTS,
  EDGE_MAX_MEMBERS: EDGE_MAX_MEMBERS,
  EDGE_MAX_CERTIFICATES: EDGE_MAX_CERTIFICATES,
  send: AuthzenCaller.send,
  presented: AuthzenCaller.presented,
  audienceOk: AuthzenCaller.audienceOk
};
