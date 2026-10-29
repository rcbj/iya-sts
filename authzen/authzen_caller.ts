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
}

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
    const { log, config, accessGate } = this.deps;
    log.debug("Entering AuthzenCaller.mayAsk().");
    caller.roles = self.rolesOf(caller);
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
      context: { method: req.method, path: req.originalUrl || req.url }
    });
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
  send: AuthzenCaller.send,
  presented: AuthzenCaller.presented,
  audienceOk: AuthzenCaller.audienceOk
};
