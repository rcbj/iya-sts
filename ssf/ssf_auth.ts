// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_auth.ts
//
// ---------------------------------------------------------------------------
// WHO MAY DRIVE A STREAM.
//
// SSF 1.0 section 8 says the management, status, subject, verification and
// poll endpoints MUST be protected, and — unlike RFC 7644, which names six
// schemes and leaves it there — it says the transmitter PUBLISHES what it
// accepts, in `authorization_schemes` on its configuration metadata. So a
// receiver discovers how to authenticate rather than guessing, and this
// module's list and that member are one table.
//
// **FOUR SCHEMES, NOT SIX, AND THAT IS A DECISION.** SCIM offers all six of
// RFC 7644's because RFC 7644 names all six and a provisioning client meets
// them in the wild. SSF names none: `authorization_schemes` is an open list of
// `spec_urn` values and the only one the specification's own examples use is
// OAuth 2.0. So this offers the one the specification points at and HTTP Basic
// beside it, which exists for the reason the SCIM one exists — a client under
// test that has not implemented a token flow yet can still reach every
// endpoint, and its 401 path stays reachable when the credential is wrong. The
// third, GNAP (2026-09-12), is here for a different reason and attemptGnap()
// argues it: a GNAP client application owns a stream as ITSELF. The fourth,
// the receiver's TLS client certificate (#1049, part of #520), arrives at the
// same owner by another road, and attemptClientCertificate() argues it.
//
// **IN DEVELOPMENT BASIC IS A TURNSTILE AND NOT A LOCK**, exactly as
// `scim/CLAUDE.md` says of its own: any username with any password but
// `invalid` passes it. What the gate buys is that a client's 401, 403 and
// scope-handling paths can be run at all — none of which an unauthenticated
// endpoint can exercise.
//
// **A TOKEN'S SCOPE IS TIED TO ITS CLIENT, IN BOTH MODES (#110, 2026-09-22).**
// Until then anybody could get a token with either SSF scope from this
// service's token endpoint with any grant. The token endpoint and GNAP now
// issue a Shared Signals name only to a client whose `oauthAllowedScope`
// declares some name of that permission class (a read declaration does not
// authorize a write name, and a write declaration does not authorize a read
// name), and `undeclaredRefusal()` asks again on every call
// (`STS-SSF-0107`), of the class the TOKEN carries: a read stays honoured
// while a read name stays declared, or while `ssf.manage` stays declared as
// a write name. An allowance removed from a client stops the tokens it
// already holds.
//
// **IN PRODUCT MODE BASIC VERIFIES THE PASSWORD (2026-09-12)**, through
// `common/credentials.ts` — the one place a presented password is checked, and
// the call `scim/scim_auth.ts` already makes. Until this date this file never
// asked the mode at all, so a product deployment's SSF endpoints accepted any
// name with any password and granted both scopes: a stream is an agreement to
// be SENT security events about everybody in the realm, and to have this
// service dial a URL of the caller's choosing. `ssf.authBasic` turns the scheme
// off, which is the posture a deployment whose receivers all hold OAuth tokens
// should take.
//
// **TWO SCOPES, AND THE DIFFERENCE IS REAL.** A read scope (`ssf.read`, the
// CAEP Interoperability Profile's name and the default of
// `ssf.authScopeRead`, or another name that setting is set to) reads a
// stream, its status and the poll queue. The write scope (`ssf.manage`, the
// profile's name and the default of `ssf.authScopeWrite`, or another name
// that setting is set to) creates, changes and deletes a stream, adds and
// removes subjects, sets a status and asks for a verification event. WRITE
// INCLUDES READ, whatever the write scope is called. A token that lacks the
// permission the operation needs is refused with a 403 naming the scopes
// that would, which is the second place in this service where two scopes
// differ in what they permit. `common/ssf_scopes.ts` (#334) is the
// vocabulary and the rule.
//
// ---------------------------------------------------------------------------
// THE METADATA IS OPEN EITHER WAY AND MUST STAY SO.
//
// `/.well-known/ssf-configuration` is never gated. A receiver has to be able to
// read what the endpoints are and which schemes they take BEFORE it can
// authenticate to one, and a transmitter whose discovery document needs a
// credential is one nothing can bootstrap against. It is the same rule
// `scim.authDiscovery` expresses for the ServiceProviderConfig, with the
// setting left out because there is no version of this that is useful closed.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route. It requires `helpers.js`,
// `config.js` and `oauth-oidc/dpop.ts` — the last for
// `presentedAccessToken()`, which is the ONE access-token check the protected
// endpoints in this service share and must not be written a second time here.
// `dpop.js` is itself a library requiring only `helpers.js` and leaves, so
// this cannot join a cycle.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SsfAuth` takes `helpers`, `config`, `mode`, `credentials`, `dpop`,
// the error-code table and LOADERS for `ssf_cluster.ts` and the two GNAP
// modules (loaders, for the lazy requires argued beside `attemptGnap()`)
// through its constructor. The module still exports its old names as FACADES
// forwarding to the instance the composition root builds (#50, R2), for
// `ssf/ssf.ts`, `ssf/ssf_receivers.ts` and the tests. A process that loads
// this module without the root builds a default instance when the module
// loads.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// The mode. A LEAF (rule 3): registers nothing, requires only `config`.
import mode = require('../common/mode');
// The one place a presented password is verified. It decides the mode itself:
// in development it refuses the reserved string and accepts everything else,
// exactly as the branch it replaced did. It requires nothing in this
// directory.
import credentials = require('../common/credentials');
import dpop = require('../oauth-oidc/dpop');
// The error-code registry. A LEAF: a refusal decided here carries its code on
// the decision as `errorCode`, and `ssf.ts`'s gate marks the response with it.
// The decision object is never serialised to a caller — the route sends `err`
// and `description` and nothing else.
import errorCodes = require('../common/error_codes');
// WHICH CLIENTS MAY HOLD THE SHARED SIGNALS SCOPES (#110), asked again of
// every token. A library that requires only libraries.
import scopePolicy = require('../common/scope_policy');
// The Shared Signals scope names (#334): the two settings, the historical
// colon names and the profile names, and which of them covers a read.
// A library requiring only `config` and `helpers`.
import ssfScopes = require('../common/ssf_scopes');

interface Scheme {
  id: string;
  spec_urn: string;
  name: string;
  what: string;
}

// What `authenticate()` answers.
interface Decision {
  ok: boolean;
  status: number;
  err: string;
  description: string;
  headers: Record<string, unknown>;
  principal: string;
  scheme: string;
  scopes: string;
  errorCode?: string;
  anonymous?: boolean;
  note?: string;
  // WHAT KIND OF PARTY THE PRINCIPAL IS (#336, 2026-09-28), for a stream's
  // owner:
  // `client` (a client's own token), `person` (a token issued to a client
  // FOR a person, whose `sub` it carries), `basic` (a name and password) or
  // `gnap` (a GNAP application). `ssf_streams.ts` narrows a person's stream
  // to that person; see "A PERSON'S STREAM IS ABOUT THAT PERSON" there.
  owner?: { kind: string; sub?: string; client?: string; name?: string };
}

// The request members this gate reads.
interface AuthRequest {
  headers?: Record<string, any>;
  [member: string]: any;
}

interface SsfAuthDeps {
  helpers: {
    log: { debug(m: string): void };
    capturingResponse(): any;
    capturedDescription(captured: any): string;
    baseUrlOf(req: any): string;
  };
  config: { value(key: string): any };
  mode: {
    gatesSharedSignals(): boolean;
    verifiesCredentials(): boolean;
  };
  credentials: {
    verify(user: string, password: string, opts: object): any;
  };
  dpop: {
    presentedAccessToken(req: any, res: any, what: string): any;
  };
  errorCodes: { codeOf(value: any): string };
  scopePolicy: {
    declares(clientId: unknown, scope: string): boolean;
    declaredScopes(clientId: unknown): string[] | null;
  };
  // `common/ssf_scopes.ts`, the module. Called from methods, never at load.
  ssfScopes: {
    configuredRead(): string;
    configuredWrite(): string;
    namesGranting(permission: string): string[];
    covers(held: unknown, need: string): boolean;
    declarationCovers(declared: string[] | null, scope: unknown): boolean;
    stillDeclared(held: unknown, declared: string[] | null,
                  need: string): boolean;
    published(): string[];
  };
  // `ssf/ssf_cluster.ts`, `gnap/gnap_access.ts` and `gnap/gnap_rs.ts`,
  // required when first asked for. See `attemptGnap()`.
  loadSsfCluster(): {
    gnapSpentOf(req: any): any;
    sharedStore(): unknown;
  };
  loadGnapAccess(): { accessCovers(access: any, wanted: any[]): boolean };
  loadGnapRs(): { presentation(req: any): any };
  // `common/tls_client_certificates.js` (the one mapping from a verified
  // certificate to a directory entry), `common/role_permissions.ts` (the
  // roles that authorize a Shared Signals scope) and `common/audit.js`,
  // required when first asked for. See attemptClientCertificate().
  loadTlsClientCertificates(): {
    checkSocket(socket: any): any;
    stillHeld(identity: any): boolean;
  };
  loadRolePermissions(): {
    narrowScope(scope: unknown, subject: object, context?: object): {
      scope: string; removed: string[]; emptied: boolean; why: string };
  };
  loadAudit(): { failure(code: string, row: object): unknown };
}

// The `authorization_schemes` this transmitter publishes. `spec_urn` is the
// member SSF 1.0 section 7.1 defines; the rest is prose for `GET /ssf` and for
// the console, and no receiver reads it.
const SCHEMES: Scheme[] = [
  { id: 'oauth', spec_urn: 'urn:ietf:rfc:6749',
    name: 'OAuth 2.0 access token',
    what: 'A Bearer or DPoP-bound access token this service issued, ' +
          'carrying the read scope (ssf.read) or the write scope ' +
          '(ssf.manage), which includes read. It is the scheme SSF 1.0\'s ' +
          'own examples use, and the ' +
          'only one of the two that can express a DIFFERENCE between ' +
          'reading a stream and changing one.' },
  { id: 'basic', spec_urn: 'urn:ietf:rfc:7617',
    name: 'HTTP Basic',
    what: 'In development, any username with any password except the ' +
          'reserved "invalid", which is refused so that a 401 stays ' +
          'reachable. In product mode the password is verified against the ' +
          'hashed userPassword on the person\'s directory entry. Either way ' +
          'it grants BOTH scopes — a scheme with no scope in it cannot ' +
          'express the distinction, and pretending otherwise would be a ' +
          'refusal a client could not act on. Off with ssf.authBasic.' },
  // GNAP (2026-09-12). A GNAP client application is a stream OWNER in its own
  // right, and `gnap/gnap_signals.ts` scopes what a stream it owns may hear
  // about — so the principal has to be the APPLICATION, which a GNAP token
  // names and an OAuth token for a person does not. See attemptGnap().
  { id: 'gnap', spec_urn: 'urn:ietf:rfc:9635',
    name: 'GNAP access token',
    what: 'A key-bound access token this service issued through its GNAP ' +
          'grant endpoint, presented with the GNAP scheme and a proof by ' +
          'the key it is bound to, whose access includes the read scope ' +
          '("ssf.read") or the write scope ("ssf.manage"), which includes ' +
          'read, ' +
          'as a reference string or as an object of type "ssf" with those ' +
          'actions. The principal is the GNAP client application, which is ' +
          'what scopes a stream it owns to the people who approved a grant ' +
          'to it. Offered while gnap.enabled is on.' },
  // THE RECEIVER'S TLS CLIENT CERTIFICATE (#1049). SSF 1.0's own transmitter
  // configuration example lists `urn:ietf:rfc:8705` beside RFC 6749, which
  // is the URN a receiver looks for to learn that mutual TLS authenticates
  // it here. See attemptClientCertificate().
  { id: 'clientcert', spec_urn: 'urn:ietf:rfc:8705',
    name: 'TLS client certificate',
    what: 'The TLS client certificate on the connection, presented with no ' +
          'Authorization header. Only a certificate this realm issued to an ' +
          'application (its TLS client or enrollment Issuing CA, ' +
          'clientAuth, a urn:sts:application: subjectAltName), not revoked ' +
          'and still held by the application, is taken. The principal is ' +
          'the application\'s identifier, the owner a GNAP token for it ' +
          'would be, and it holds the Shared Signals scopes its ' +
          'oauthAllowedScope declares and its SSF_READ and SSF_MANAGE ' +
          'roles authorize; write includes read. Off with ssf.authClientCert.' }
];

// The one password Basic refuses, so that a wrong-credential path exists at
// all. The same value and the same reasoning as SCIM's.
const REFUSED_PASSWORD = 'invalid';

/**
 * The gate in front of the Shared Signals stream endpoints: OAuth 2.0 bearer
 * tokens, GNAP, HTTP Basic and the receiver's TLS client certificate, with a
 * read and a write scope.
 *
 * In development mode Basic accepts any password but `invalid`; in product mode
 * it verifies the password through `common/credentials.ts`.
 */
class SsfAuth {
  /**
   * The four schemes this gate knows, each with its id, name, `spec_urn` and a
   * description, in the order a 401 offers them.
   */
  static readonly SCHEMES = SCHEMES;
  /**
   * The one password Basic refuses in development mode, so that a
   * wrong-credential path exists.
   */
  static readonly REFUSED_PASSWORD = REFUSED_PASSWORD;

  // ---------------------------------------------------------------------------
  // WHO AN ACCESS TOKEN IS, AS A STREAM OWNER (2026-09-18).
  //
  // The principal was `sub`, which for a client_credentials token is the bare
  // client_id in development and `urn:sts:client:<client_id>` in RFC 9700
  // mode — which product mode implies (oauth2.ts, the client_credentials
  // grant). A stream's owner is matched against application identifiers, so
  // in product mode `ssfAllowedEvents` named nobody's owner and a restricted
  // application was agreed every event it asked for: found by
  // sts_ssf_allowed_events.js run against a product-mode deployment, and
  // invisible to every development-mode run. A CLIENT's token is its
  // client_id in both modes now; a person's `sub` is untouched.
  // ---------------------------------------------------------------------------
  /**
   * Returns the stream-owner principal named by an access token's claims.
   *
   * A client's token is its `client_id` in both modes, whether `sub` is the
   * bare client_id or `urn:sts:client:<client_id>`; otherwise `sub`.
   *
   * @param claims - the verified access token's claims
   * @returns the client_id for a client's token, else `sub` (or the client_id
   * when there is no `sub`)
   */
  static principalOfClaims(claims: any): string {
    helpers.log.debug('Entering SsfAuth.principalOfClaims().');
    const sub = String((claims && claims.sub) || '');
    const clientId = String((claims && claims.client_id) || '');
    if (clientId &&
        (sub === clientId || sub === 'urn:sts:client:' + clientId)) {
      helpers.log.debug('Leaving SsfAuth.principalOfClaims(). The client.');
      return clientId;
    }
    helpers.log.debug('Leaving SsfAuth.principalOfClaims().');
    return sub || clientId;
  }

  /**
   * Builds the gate from its dependencies.
   *
   * @param deps - the modules it reads, from `SsfAuth.defaultDeps()` or the
   * composition root
   */
  constructor(private readonly deps: SsfAuthDeps) {
    deps.helpers.log.debug("Entering SsfAuth.constructor().");
    deps.helpers.log.debug("Leaving SsfAuth.constructor().");
  }

  // Whether Basic is offered at all. A setting since 2026-09-12, mirroring
  // `scim.authBasic`; on by default, which is what this service always did.
  private basicOffered(): boolean {
    const { helpers: { log }, config } = this.deps;
    log.debug("Entering SsfAuth.basicOffered().");
    log.debug("Leaving SsfAuth.basicOffered().");
    return config.value('ssf.authBasic') !== false;
  }

  // Whether GNAP is offered: the family is on. It is read at call time, and
  // the GNAP modules are required lazily, because GNAP is 23d in the require
  // order and this library is loaded at 23b.
  private gnapOffered(): boolean {
    const { helpers: { log }, config } = this.deps;
    log.debug("Entering SsfAuth.gnapOffered().");
    log.debug("Leaving SsfAuth.gnapOffered().");
    return config.value('gnap.enabled') !== false;
  }

  // Whether a TLS client certificate is taken (#1049). A setting, mirroring
  // `ssf.authBasic`; on by default. Read at call time.
  private clientCertOffered(): boolean {
    const { helpers: { log }, config } = this.deps;
    log.debug("Entering SsfAuth.clientCertOffered().");
    log.debug("Leaving SsfAuth.clientCertOffered().");
    return config.value('ssf.authClientCert') !== false;
  }

  private offered(row: Scheme): boolean {
    const { helpers: { log } } = this.deps;
    log.debug("Entering SsfAuth.offered().");
    if (row.id === 'clientcert') {
      log.debug("Leaving SsfAuth.offered().");
      return this.clientCertOffered();
    }
    if (row.id === 'basic') {
      log.debug("Leaving SsfAuth.offered().");
      return this.basicOffered();
    }
    if (row.id === 'gnap') {
      log.debug("Leaving SsfAuth.offered().");
      return this.gnapOffered();
    }
    log.debug("Leaving SsfAuth.offered().");
    return true;
  }

  // The schemes actually offered right now, in `SCHEMES` order.
  private offeredSchemes(): Scheme[] {
    const { helpers: { log } } = this.deps;
    log.debug("Entering SsfAuth.offeredSchemes().");
    log.debug("Leaving SsfAuth.offeredSchemes().");
    return SCHEMES.filter((row) => {
      return this.offered(row);
    });
  }

  // THE MODE, since 2026-09-06, where this read `ssf.authRequired`. That
  // setting is gone with the other three: "is authentication required here"
  // had four answers across this service and now has one. See
  // common/mode.js.
  /**
   * Whether these endpoints require a credential, which is the mode's answer
   * (`mode.gatesSharedSignals()`).
   *
   * @returns true when a credential is required
   */
  authRequired(): boolean {
    const { helpers: { log }, mode } = this.deps;
    log.debug("Entering SsfAuth.authRequired().");
    const on = mode.gatesSharedSignals();
    log.debug("Leaving SsfAuth.authRequired(). " + on);
    return on;
  }

  /**
   * Returns the scope that permits reading a stream, its status and the poll
   * queue (`ssf.authScopeRead`, default `ssf.read`).
   *
   * @returns the read scope
   */
  scopeRead(): string {
    const { helpers: { log }, ssfScopes } = this.deps;
    log.debug("Entering SsfAuth.scopeRead().");
    const value = ssfScopes.configuredRead();
    log.debug("Leaving SsfAuth.scopeRead(). " + value);
    return value;
  }

  /**
   * Returns the scope that permits changing streams, subjects, status and
   * asking for verification (`ssf.authScopeWrite`, default `ssf.manage`).
   *
   * @returns the write scope
   */
  scopeWrite(): string {
    const { helpers: { log }, ssfScopes } = this.deps;
    log.debug("Entering SsfAuth.scopeWrite().");
    const value = ssfScopes.configuredWrite();
    log.debug("Leaving SsfAuth.scopeWrite(). " + value);
    return value;
  }

  // The realm named in every challenge. One string, so a client that caches a
  // credential per realm caches it once.
  /**
   * Returns the realm named in every challenge, always `ssf`.
   *
   * @returns the challenge realm
   */
  realm(): string {
    const { helpers: { log } } = this.deps;
    log.debug("Entering SsfAuth.realm().");
    log.debug("Leaving SsfAuth.realm().");
    return 'ssf';
  }

  // What a 401 offers, in the order this service prefers them.
  /**
   * Returns the `WWW-Authenticate` challenges a 401 offers, in this service's
   * order of preference: Bearer, then Basic when offered, then GNAP when
   * offered and a request is given (its `as_uri` needs the request's base).
   *
   * @param req - the request, when there is one
   * @returns the challenge strings
   */
  challenges(req?: AuthRequest | null): string[] {
    const { helpers: { log, baseUrlOf }, ssfScopes } = this.deps;
    log.debug("Entering SsfAuth.challenges().");
    const list = ['Bearer realm="' + this.realm() + '", scope="' +
      ssfScopes.published().join(' ') + '"'];
    if (this.basicOffered()) {
      list.push('Basic realm="' + this.realm() + '", charset="UTF-8"');
    }
    // RFC 9635 section 9.1's challenge names the grant endpoint, which needs
    // the request's base; a caller with no request gets the other schemes
    // only.
    if (this.gnapOffered() && req) {
      list.push('GNAP as_uri="' + baseUrlOf(req) + '/gnap"');
    }
    log.debug("Leaving SsfAuth.challenges(). " + list.length + '.');
    return list;
  }

  private authorizationScheme(req: AuthRequest): string {
    const { helpers: { log } } = this.deps;
    log.debug("Entering SsfAuth.authorizationScheme().");
    const header = String((req.headers || {}).authorization || '');
    const scheme = header.split(' ')[0].toLowerCase();
    log.debug("Leaving SsfAuth.authorizationScheme(). " +
              (scheme || '(none)'));
    return scheme;
  }

  private refusal(code: string, status: number, description: string,
                  headers?: Record<string, unknown>,
                  err?: string): Decision {
    const { helpers: { log } } = this.deps;
    log.debug("Entering SsfAuth.refusal(). " + status);
    log.debug("Leaving SsfAuth.refusal().");
    return { ok: false, status: status, err: err || 'authentication_failed',
      description: description, headers: headers || {}, principal: '',
      scheme: '', scopes: '', errorCode: code };
  }

  // -------------------------------------------------------------------------
  // THE OAUTH ATTEMPT.
  //
  // It goes through `dpop.presentedAccessToken()` and NOT through a check of
  // its own, for the reason `scim/scim_auth.ts` gives at length about the same
  // call: that function carries the RFC 9449 proof and the 401/DPoP-Nonce
  // handshake, the RFC 8705 certificate binding, the RFC 9700 refusal of a
  // token in the query string and the RFC 8707 audience check, and a second
  // implementation would be a version behind within a release.
  //
  // What it will not do is speak SSF, so it is handed a recording response
  // (`helpers.capturingResponse()`) and what it would have said is translated
  // into the `{err, description}` shape RFC 8935 and this family use. THE
  // HEADERS IT SET ARE KEPT VERBATIM — DPoP-Nonce and the `use_dpop_nonce`
  // challenge are how a client learns to retry.
  // -------------------------------------------------------------------------
  private attemptOAuth(req: AuthRequest, need: string): Decision | null {
    const { helpers: { log, capturingResponse, capturedDescription },
            dpop, errorCodes, ssfScopes } = this.deps;
    log.debug("Entering SsfAuth.attemptOAuth().");
    const scheme = this.authorizationScheme(req);
    if (scheme !== 'bearer' && scheme !== 'dpop') {
      log.debug("Leaving SsfAuth.attemptOAuth(). No OAuth credential.");
      return null;
    }
    const shim = capturingResponse();
    const presented = dpop.presentedAccessToken(req, shim.res,
                                                'the SSF endpoints');
    if (!presented) {
      log.debug("Leaving SsfAuth.attemptOAuth(). The shared check refused " +
                'it.');
      // The shared check may have named the condition itself; its code wins.
      return this.refusal(errorCodes.codeOf(shim.res) || 'STS-SSF-0002',
        shim.captured.status || 401,
        capturedDescription(shim.captured) ||
        'This access token could not be accepted.', shim.captured.headers);
    }
    const claims = presented.claims || {};
    if (!presented.verified) {
      log.debug("Leaving SsfAuth.attemptOAuth(). Not a token this service " +
                'signed.');
      return this.refusal('STS-SSF-0003', 401,
        'This access token was not issued by this service, or its signature ' +
        'does not verify against the key at /oauth2/jwks. A scope on a ' +
        'token nobody verified is a permission its holder wrote for ' +
        'themselves, and these endpoints decide what this transmitter ' +
        'delivers to whom. Get a token from this service\'s token endpoint ' +
        'with any grant.',
        { 'WWW-Authenticate': this.challenges() });
    }
    if (claims.typ !== 'Bearer') {
      log.debug("Leaving SsfAuth.attemptOAuth(). Wrong token type.");
      return this.refusal('STS-SSF-0004', 401,
        'This is a "' + (claims.typ || 'unknown') + '" token, not an access ' +
        'token. Every token this service issues is signed with the same ' +
        'key, so the typ claim is the only thing that tells a refresh token ' +
        'or an ID Token apart from the access token these endpoints need.',
        { 'WWW-Authenticate': this.challenges() });
    }
    const scopes = String(claims.scope || '');
    if (need !== 'none' && !ssfScopes.covers(scopes, need)) {
      const accepted = this.acceptedFor(need);
      log.debug('Leaving SsfAuth.attemptOAuth(). Missing a "' + need +
                '" scope.');
      return this.refusal('STS-SSF-0005', 403,
        'This access token carries ' + (scopes
          ? 'the scope(s) "' + scopes + '"' : 'no scope at all') +
        ' and this operation needs one of "' + accepted.join('", "') +
        '". Write includes read. A read scope reads a stream, its status ' +
        'and its poll queue, and a write scope ' +
        'changes what this transmitter delivers and to whom. Ask for the ' +
        'one you need, as a client whose oauthAllowedScope declares that ' +
        'permission.',
        { 'WWW-Authenticate': this.challenges() }, 'access_denied');
    }
    const withdrawn = this.undeclaredRefusal(String(claims.client_id || ''),
                                             need, scopes);
    if (withdrawn) {
      log.debug("Leaving SsfAuth.attemptOAuth(). The client no longer " +
                "declares the scope.");
      return withdrawn;
    }
    const principal = SsfAuth.principalOfClaims(claims);
    const clientId = String(claims.client_id || '');
    log.debug("Leaving SsfAuth.attemptOAuth(). Accepted.");
    return { ok: true, status: 200, scheme: presented.scheme === 'dpop'
      ? 'dpop' : 'bearer',
      principal: principal,
      scopes: scopes, err: '', description: '', headers: {},
      // A token whose principal is not its own client was issued FOR a
      // person: principalOfClaims() answers the client_id only for a
      // client's own token.
      owner: principal && principal !== clientId
        ? { kind: 'person', sub: principal, client: clientId }
        : { kind: 'client', client: clientId } };
  }

  // -------------------------------------------------------------------------
  // THE CLIENT STILL DECLARES THE PERMISSION (#110, 2026-09-22; #334). The
  // token endpoint and GNAP issue a Shared Signals name only to a client
  // whose `oauthAllowedScope` grants every permission that name grants;
  // asked again on every call, of the permission the operation needs, so an
  // allowance removed from a client stops the tokens it already holds. The
  // operation is still declared while the client declares some name that
  // grants it, and write includes read (`common/ssf_scopes.ts`). `client`
  // is an OAuth token's client_id, or the GNAP application's identifier.
  // Null when the permission is still declared, or when nothing is needed.
  // -------------------------------------------------------------------------
  private undeclaredRefusal(client: string, need: string,
                            held: unknown): Decision | null {
    const { helpers: { log }, scopePolicy, ssfScopes } = this.deps;
    log.debug("Entering SsfAuth.undeclaredRefusal().");
    if (need === 'none') {
      log.debug("Leaving SsfAuth.undeclaredRefusal(). Nothing needed.");
      return null;
    }
    const declared = scopePolicy.declaredScopes(client);
    if (ssfScopes.stillDeclared(held, declared, need)) {
      log.debug("Leaving SsfAuth.undeclaredRefusal(). Declared.");
      return null;
    }
    log.debug("Leaving SsfAuth.undeclaredRefusal(). Not declared.");
    return this.refusal('STS-SSF-0107', 403,
      'This token carries a Shared Signals scope this operation needs, and ' +
      'the client it was issued to, "' + client + '", no longer declares ' +
      'that permission in its oauthAllowedScope. A read stays honoured ' +
      'while a read or a write scope stays declared, because write ' +
      'includes read; a write stays honoured while a write scope stays ' +
      'declared. Removing the declaration from the application cuts off ' +
      'tokens already issued.',
      { 'WWW-Authenticate': this.challenges() }, 'access_denied');
  }

  // The names an operation accepts: every published name that grants the
  // permission. A read accepts the read names and the write names, because
  // write includes read; a write accepts the write names.
  private acceptedFor(need: string): string[] {
    const { helpers: { log }, ssfScopes } = this.deps;
    log.debug("Entering SsfAuth.acceptedFor().");
    const names = ssfScopes.namesGranting(need === 'write' ? 'write'
                                                           : 'read');
    log.debug("Leaving SsfAuth.acceptedFor(). " + names.length);
    return names;
  }

  // -------------------------------------------------------------------------
  // THE GNAP ATTEMPT.
  //
  // Through `gnap/gnap_rs.ts`'s `presentation()` and NOT a check of its own,
  // for `attemptOAuth()`'s reason: that function is the ONE place a presented
  // GNAP token is judged against this authorization server's record of it —
  // issued here, live, presented under the scheme RFC 9635 section 7.2
  // requires, and accompanied by a proof by the key it is bound to. It is the
  // synchronous half of `gnap_rs.ts`'s `authenticate()`; the
  // format's own verification is left out because this process holds the
  // record the format would re-derive, and this gate is synchronous across
  // every SSF endpoint.
  //
  // **ONLY THE GNAP SCHEME.** A BEARER GNAP token is sent with the Bearer
  // scheme (section 7.2), and on these endpoints the Bearer scheme means
  // OAuth 2.0 — taking both would make one header mean two things. A GNAP
  // client that wants a stream holds a bound token, which is what GNAP is
  // for.
  //
  // **A TOKEN ISSUED FOR A NAMED RESOURCE SERVER IS REFUSED.** Its audience
  // is that server, and a transmitter accepting it would be the confused
  // deputy RFC 9767's audience exists to prevent.
  // -------------------------------------------------------------------------
  // LAZY: ssf_cluster.ts requires the cluster layer, and this file is loaded
  // by tests that want the SSF gate alone.
  private ssfCluster(): ReturnType<SsfAuthDeps['loadSsfCluster']> {
    const { helpers: { log }, loadSsfCluster } = this.deps;
    log.debug("Entering SsfAuth.ssfCluster().");
    log.debug("Leaving SsfAuth.ssfCluster().");
    return loadSsfCluster();
  }

  private gnapCovers(access: unknown, need: string): boolean {
    const { helpers: { log }, loadGnapAccess } = this.deps;
    log.debug("Entering SsfAuth.gnapCovers().");
    const accessLib = loadGnapAccess();
    const names = this.acceptedFor(need);
    let covered = false;
    for (let i = 0; i < names.length; i++) {
      if (accessLib.accessCovers(access, [names[i]])) {
        covered = true;
        break;
      }
    }
    // An object of type `ssf` with the action, or — for a read — with the
    // `write` action, because write includes read.
    const actions = need === 'read' ? ['read', 'write'] : [need];
    for (let a = 0; !covered && a < actions.length; a++) {
      covered = accessLib.accessCovers(access,
        [{ type: 'ssf', actions: [actions[a]] }]);
    }
    log.debug("Leaving SsfAuth.gnapCovers(). " + covered);
    return covered;
  }

  // The published and configured names a GNAP access actually holds. A
  // string grant does not cover an object point, and an object grant does
  // not cover a string (`gnap/gnap_access.ts`), so both shapes are asked.
  // An object of type `ssf` contributes the configured name of each action
  // it covers; the write name it contributes for `write` reads as well.
  private gnapHeldScopes(access: unknown): string[] {
    const { helpers: { log }, loadGnapAccess, ssfScopes } = this.deps;
    log.debug("Entering SsfAuth.gnapHeldScopes().");
    const accessLib = loadGnapAccess();
    const held: string[] = [];
    const published = ssfScopes.published();
    for (let i = 0; i < published.length; i++) {
      if (accessLib.accessCovers(access, [published[i]])) {
        held.push(published[i]);
      }
    }
    if (accessLib.accessCovers(access,
        [{ type: 'ssf', actions: ['read'] }])) {
      const name = ssfScopes.configuredRead();
      if (held.indexOf(name) < 0) {
        held.push(name);
      }
    }
    if (accessLib.accessCovers(access,
        [{ type: 'ssf', actions: ['write'] }])) {
      const name = ssfScopes.configuredWrite();
      if (held.indexOf(name) < 0) {
        held.push(name);
      }
    }
    log.debug("Leaving SsfAuth.gnapHeldScopes(). " + held.length);
    return held;
  }

  private attemptGnap(req: AuthRequest, need: string): Decision | null {
    const { helpers: { log }, errorCodes, loadGnapRs, scopePolicy,
            ssfScopes } = this.deps;
    log.debug("Entering SsfAuth.attemptGnap().");
    if (this.authorizationScheme(req) !== 'gnap') {
      log.debug("Leaving SsfAuth.attemptGnap(). No GNAP credential.");
      return null;
    }
    if (!this.gnapOffered()) {
      log.debug("Leaving SsfAuth.attemptGnap(). GNAP is not offered.");
      return this.refusal('STS-SSF-0077', 401,
        'The GNAP scheme is not offered on these endpoints because GNAP is ' +
        'switched off in this realm (gnap.enabled). The WWW-Authenticate ' +
        'header says what to send instead.',
        { 'WWW-Authenticate': this.challenges(req) });
    }
    let rs;
    try {
      rs = loadGnapRs();
    } catch (e) {
      // The family is not loaded in this process (an in-process test that
      // required SSF alone). There is nothing that could judge the token.
      log.debug("Caught in SsfAuth.attemptGnap(): " +
                ((e && e.message) || e));
      log.debug("Leaving SsfAuth.attemptGnap(). GNAP is not loaded: " +
                e.message);
      return this.refusal('STS-SSF-0077', 401,
        'The GNAP scheme cannot be judged in this process.',
        { 'WWW-Authenticate': this.challenges(req) });
    }
    // -----------------------------------------------------------------------
    // SPENT ALREADY, WHERE THE ROUTE'S MIDDLEWARE RAN (2026-09-14, #46).
    //
    // `presentation()` checks the key proof against THIS PROCESS'S replay
    // cache, and the cluster half of that check needs an await this gate
    // cannot make — so `ssf_cluster.ts`'s `spendGnapProof` runs the
    // presentation and the spend before the handler and leaves both on the
    // request. Calling presentation() again here would judge the same proof
    // a second time, and the cache would refuse it as the replay it is not.
    //
    // A caller that did not go through the route — a test driving this
    // function directly — gets the synchronous presentation, which is the
    // whole check where no claim store is shared. Where one IS shared, a
    // proof nothing spent across the cluster is refused rather than trusted
    // (`STS-SSF-0099`): the in-memory cache alone is exactly the check a
    // second node's replay walks past.
    // -----------------------------------------------------------------------
    const prepared = this.ssfCluster().gnapSpentOf(req);
    let presented = prepared ? prepared.presented : null;
    if (!prepared) {
      if (this.ssfCluster().sharedStore()) {
        log.debug("Leaving SsfAuth.attemptGnap(). No spend on a shared " +
                  'store.');
        return this.refusal('STS-SSF-0099', 401,
          'This GNAP key proof could not be confirmed unused across the ' +
          'cluster: the request did not reach the step that spends it.',
          { 'WWW-Authenticate': this.challenges(req) }, 'invalid_token');
      }
      presented = rs.presentation(req);
    }
    if (!presented) {
      log.debug("Leaving SsfAuth.attemptGnap(). The presentation threw.");
      return this.refusal('STS-SSF-0078', 401,
        'This GNAP access token could not be accepted.',
        { 'WWW-Authenticate': this.challenges(req) }, 'invalid_token');
    }
    if (presented.ok && prepared &&
        !(prepared.spent && prepared.spent.ok)) {
      log.debug("Leaving SsfAuth.attemptGnap(). Refused at the spend.");
      return this.refusal(
        errorCodes.codeOf(prepared.spent) || 'STS-SSF-0099', 401,
        'This GNAP access token could not be accepted: ' +
        String((prepared.spent && prepared.spent.why) ||
               'its key proof could not be spent'),
        { 'WWW-Authenticate': this.challenges(req) }, 'invalid_token');
    }
    if (!presented.ok) {
      log.debug("Leaving SsfAuth.attemptGnap(). Refused: " + presented.why);
      return this.refusal(errorCodes.codeOf(presented) || 'STS-SSF-0078',
        401,
        'This GNAP access token could not be accepted: ' + presented.why,
        { 'WWW-Authenticate': this.challenges(req) },
        presented.gnapError || 'invalid_token');
    }
    const record = presented.record;
    if ((record.rsIdentifiers || []).length) {
      log.debug("Leaving SsfAuth.attemptGnap(). Issued for a named resource " +
                'server.');
      return this.refusal('STS-SSF-0079', 401,
        'This GNAP access token was issued for the resource server "' +
        record.rsIdentifiers.join('", "') + '", and this transmitter is ' +
        'not it. Ask the grant endpoint for a token whose access names "' +
        ssfScopes.published().join('" or "') +
        '" and no resource server.',
        { 'WWW-Authenticate': this.challenges(req) }, 'invalid_token');
    }
    if (need !== 'none' && !this.gnapCovers(record.access, need)) {
      const accepted = this.acceptedFor(need);
      log.debug("Leaving SsfAuth.attemptGnap(). Missing SSF access.");
      return this.refusal('STS-SSF-0080', 403,
        'This GNAP access token\'s access does not include "' +
        accepted.join('" or "') +
        '". Write includes read. Ask for one as ' +
        'a reference string, or as an object of type "ssf" with the "' +
        need + '" action.',
        { 'WWW-Authenticate': this.challenges(req) }, 'access_denied');
    }
    const held = this.gnapHeldScopes(record.access);
    const instanceId = String(record.instanceId || '');
    const gnapWithdrawn = this.undeclaredRefusal(instanceId, need, held);
    if (gnapWithdrawn) {
      log.debug("Leaving SsfAuth.attemptGnap(). The client no longer " +
                "declares the scope.");
      return gnapWithdrawn;
    }
    const declared = scopePolicy.declaredScopes(instanceId);
    // The names the client could be issued today: every permission each
    // grants is still declared.
    const granted = held.filter(function (name) {
      return ssfScopes.declarationCovers(declared, name);
    });
    log.debug("Leaving SsfAuth.attemptGnap(). Accepted " +
              record.instanceId + '.');
    return { ok: true, status: 200, scheme: 'gnap',
      principal: String(record.instanceId || ''),
      scopes: granted.join(' '), err: '', description: '', headers: {},
      owner: { kind: 'gnap' },
      note: 'GNAP access token (' + record.format + ', proofed by ' +
            presented.method + ')' };
  }

  // -------------------------------------------------------------------------
  // THE BASIC ATTEMPT.
  //
  // In development no password is checked but one, exactly as everywhere
  // else here. In product mode `credentials.verify()` checks it against the
  // person's hashed `userPassword` — one call, both modes, the call SCIM
  // makes.
  //
  // **IT GRANTS BOTH SCOPES IN BOTH MODES, AND THAT IS STATED RATHER THAN
  // INHERITED.** A scheme with no scope in it cannot express the difference
  // between reading and writing, and returning a read-only decision would be
  // a refusal a client could not act on — there would be nothing it could
  // send to get past it. What product mode changes is WHO: a verified
  // directory person, rather than any string. A deployment that wants the
  // read/write split enforced for everybody turns Basic off
  // (`ssf.authBasic`) and issues OAuth tokens, and one that wants a narrower
  // population narrows it at the access policy — which is also where SCIM's
  // identical grant is narrowed.
  // -------------------------------------------------------------------------
  private attemptBasic(req: AuthRequest): Decision | null {
    const { helpers: { log }, credentials, mode } = this.deps;
    log.debug("Entering SsfAuth.attemptBasic().");
    const scheme = this.authorizationScheme(req);
    if (scheme !== 'basic') {
      log.debug("Leaving SsfAuth.attemptBasic(). No Basic credential.");
      return null;
    }
    if (!this.basicOffered()) {
      log.debug("Leaving SsfAuth.attemptBasic(). Basic is not offered.");
      return this.refusal('STS-SSF-0006', 401,
        'HTTP Basic is not offered on these endpoints (ssf.authBasic is ' +
        'off). Present an OAuth 2.0 access token carrying the read scope ' +
        '(ssf.read) or the write scope (ssf.manage), which includes read; ' +
        'the ' +
        'WWW-Authenticate header says what to send.',
        { 'WWW-Authenticate': this.challenges() });
    }
    const header = String((req.headers || {}).authorization || '');
    const encoded = header.slice(header.indexOf(' ') + 1).trim();
    let decoded = '';
    try {
      decoded = Buffer.from(encoded, 'base64').toString('utf8');
    } catch (e) {
      log.debug("Caught in SsfAuth.attemptBasic(): " +
                ((e && e.message) || e));
      // Not base64. There is nothing to recover — the credential is malformed
      // rather than wrong, and saying which is the useful half.
      decoded = '';
    }
    const cut = decoded.indexOf(':');
    const user = cut < 0 ? decoded : decoded.slice(0, cut);
    const password = cut < 0 ? '' : decoded.slice(cut + 1);
    if (!user) {
      log.debug("Leaving SsfAuth.attemptBasic(). No username.");
      // Per mode (#543 round 2): "accepts any username with any password"
      // was the answer in product too, where the password is verified.
      return this.refusal('STS-SSF-0007', 401,
        'The Basic credential did not decode to "user:password". It is ' +
        'base64 of those two joined by a colon, and ' +
        (mode.verifiesCredentials()
          ? 'the password is verified against the person\'s directory ' +
            'entry.'
          : 'this realm, in development mode, accepts any username with ' +
            'any password except "' + REFUSED_PASSWORD + '".'),
        { 'WWW-Authenticate': this.challenges() });
    }
    // `door: 'ssf'` (#101): a password-only door — see credentials.ts.
    const checked = credentials.verify(user, password,
                                       { via: 'SSF HTTP Basic', door: 'ssf' });
    if (!checked.ok) {
      log.debug("Leaving SsfAuth.attemptBasic(). Refused: " + checked.reason);
      return this.refusal(checked.reason === 'reserved-refusal'
        ? 'STS-SSF-0008' : 'STS-SSF-0009', 401,
        checked.reason === 'reserved-refusal'
        ? 'The password "' + REFUSED_PASSWORD + '" is reserved and always ' +
          'refused, so that a wrong-credential path exists at all. In ' +
          'development mode every other password for every username is ' +
          'accepted.'
        // ONE SENTENCE FOR EVERY OTHER FAILURE: "no such user" and "wrong
        // password" must not be distinguishable to a caller. The reason is in
        // the log, where credentials.js wrote it.
        : 'Authentication failed. In product mode a Basic credential is ' +
          'verified against the hashed userPassword on the person\'s ' +
          'directory entry, and a person with none cannot authenticate at ' +
          'all.',
        { 'WWW-Authenticate': this.challenges() });
    }
    log.debug("Leaving SsfAuth.attemptBasic(). Accepted " + user + '.');
    return { ok: true, status: 200, scheme: 'basic', principal: user,
      scopes: this.scopeRead() + ' ' + this.scopeWrite(), err: '',
      description: '',
      headers: {},
      // A person only if the directory holds `user`; ssf_streams.ts asks.
      owner: { kind: 'basic', name: user },
      // An app password is said so (#101).
      note: checked.reason === 'app-password' && checked.appPassword
        ? 'HTTP Basic (an app password, "' + checked.appPassword.name +
          '", was verified)'
        : mode.verifiesCredentials()
        ? 'HTTP Basic (the password was verified)'
        : 'HTTP Basic (no password was checked)' };
  }

  // -------------------------------------------------------------------------
  // THE TLS CLIENT CERTIFICATE (#1049, part of #520, 2026-10-27).
  //
  // rcbj's decision on #520: stream management and the poll endpoint accept
  // a receiver authenticated by the TLS client certificate on its
  // connection, beside its bearer token, resolved to the receiver's
  // APPLICATION by the identity gate. A stream is its owner's either way, so
  // a certificate reaches only that application's streams.
  //
  // **THE ONE MAPPING.** `common/tls_client_certificates.js`'s
  // `checkSocket()` — `identityOf()` under this request's ambient realm — is
  // what says a verified certificate is somebody, and `stillHeld()` whether
  // the entry it names still lists it; RFC 8705's implicit mapping
  // (`oauth-oidc/client_auth.js`) and GNAP's PKI trust model ask the same
  // two. Nothing here reads a subject DN or a CN. So, from that gate:
  //
  //   * a chain through no authority this process holds (an anchor somebody
  //     installed at /admin-api/tls/trust) names nobody here, and is NOT
  //     THIS CREDENTIAL — the request is decided as if no certificate had
  //     been presented;
  //   * a certificate this service issued that the gate refuses (not from a
  //     realm's TLS client or enrollment Issuing CA, no clientAuth, not
  //     exactly one urn:sts: name, ANOTHER REALM'S authority — the realm
  //     boundary), or one issued to a PERSON, is refused STS-SSF-0147: a
  //     receiver is an application, and a person's own streams are reached
  //     with a token issued for them;
  //   * one the application's record no longer lists is STS-SSF-0148;
  //   * one refused on revocation (`req.certificateRevocation`, which
  //     `common/app.js` computed under `pki.revocationCheck` before any
  //     route) is STS-SSF-0150, with the certificate's own code audited.
  //
  // A refusal is answered only on an endpoint that needs a permission: the
  // open description (`need` none) never refuses anybody for what their
  // browser presented. It is answered in BOTH modes, because what was
  // presented is a wrong credential, as Basic's reserved password is, and a
  // receiver under test needs that path; development's turnstile is for a
  // request that presents nothing.
  //
  // **ONLY WITH NO AUTHORIZATION HEADER**, SCIM's rule: a header is the
  // caller choosing its credential, and a certificate-bound OAuth token
  // already reaches its binding through `attemptOAuth()`.
  //
  // **THE PRINCIPAL IS THE APPLICATION'S IDENTIFIER**, which is what a GNAP
  // token for it owns a stream as, what `ssfAllowedEvents`, `ssfReceiverId`
  // and the per-receiver settings are found by (`applications.js`'s
  // `findSsfOwner()`), and what a client_credentials token owns as wherever
  // the application's client_id is its identifier — the usual registration.
  //
  // **ITS SCOPES ARE WHAT A TOKEN WOULD BE ISSUED, ASKED ON EVERY CALL.**
  // There is no issuance step to ask #110's and #303's questions at, so they
  // are asked here: the Shared Signals names the application's
  // `oauthAllowedScope` declares, LITERALLY (a write declaration's implied
  // read is not asked for, so that an application holding only SSF_MANAGE
  // is not audited STS-ADMIN-0821 on every poll), narrowed by
  // `role_permissions.ts`'s `narrowScope()` — the issuance policy, with its
  // SSF_READ and SSF_MANAGE membership — exactly as a client_credentials
  // token request. Then `ssf_scopes.ts`'s one rule: write includes read. A
  // permission nothing authorizes is STS-SSF-0149, a 403 naming the two
  // halves. A role or a declaration taken away stops the certificate at its
  // next call, which is what #110 asks of a token.
  // -------------------------------------------------------------------------
  private attemptClientCertificate(req: AuthRequest,
                                   need: string): Decision | null {
    const { helpers: { log }, errorCodes, scopePolicy, ssfScopes,
            loadTlsClientCertificates, loadRolePermissions,
            loadAudit } = this.deps;
    log.debug("Entering SsfAuth.attemptClientCertificate().");
    if (this.authorizationScheme(req)) {
      log.debug("Leaving SsfAuth.attemptClientCertificate(). An " +
                "Authorization header was sent.");
      return null;
    }
    if (!this.clientCertOffered()) {
      log.debug("Leaving SsfAuth.attemptClientCertificate(). Not offered.");
      return null;
    }
    const socket = req.socket || req.connection;
    if (!socket || typeof socket.getPeerCertificate !== 'function' ||
        socket.authorized !== true) {
      log.debug("Leaving SsfAuth.attemptClientCertificate(). No verified " +
                "certificate on this connection.");
      return null;
    }
    const decides = need !== 'none';
    const revocation = req.certificateRevocation || null;
    if (revocation && revocation.refused) {
      const code = errorCodes.codeOf(revocation) || 'STS-PKI-0118';
      try {
        loadAudit().failure(code, {
          protocol: 'SSF', channel: 'http',
          target: req.originalUrl || req.url,
          summary: 'a verified client certificate was not accepted as a ' +
                   'Shared Signals receiver credential: ' + revocation.why,
          outcome: 'refused'
        });
      } catch (e) {
        // No audit log in this process (a test driving the gate alone). The
        // refusal below still carries its code.
        log.debug("Caught in SsfAuth.attemptClientCertificate(): " +
                  ((e && e.message) || e));
      }
      log.debug("Leaving SsfAuth.attemptClientCertificate(). Refused on " +
                "revocation.");
      return decides ? this.refusal('STS-SSF-0150', 401,
        'The TLS client certificate on this connection was refused on ' +
        'revocation (' + String(revocation.why || 'revoked') + '), so it ' +
        'authenticates no receiver. Present a certificate this realm ' +
        'issued to your application and has not revoked, or an access ' +
        'token.',
        { 'WWW-Authenticate': this.challenges(req) }) : null;
    }
    let gate: any = null;
    try {
      gate = loadTlsClientCertificates().checkSocket(socket);
    } catch (e) {
      // No certificate authority in this process, so nothing here was
      // issued by one and nothing names an application.
      log.debug("Caught in SsfAuth.attemptClientCertificate(): " +
                ((e && e.message) || e));
      gate = null;
    }
    const identity = (gate && gate.identity) || {};
    if (!gate || (gate.ok && !identity.issuedHere)) {
      log.debug("Leaving SsfAuth.attemptClientCertificate(). Not a " +
                "certificate this service issued.");
      return null;
    }
    if (!gate.ok || !identity.accepted || identity.kind !== 'application') {
      const why = !gate.ok
        ? String(gate.why || identity.why || 'it is not an identity here')
        : 'it was issued to the ' + String(identity.kind || 'holder') +
          ' "' + String(identity.username || '') + '", and a receiver ' +
          'authenticated by its certificate is an application';
      log.debug("Leaving SsfAuth.attemptClientCertificate(). Not an " +
                "application of this realm: " + why);
      return decides ? this.refusal('STS-SSF-0147', 401,
        'The TLS client certificate on this connection does not authenticate ' +
        'a Shared Signals receiver here: ' + why + '. A receiver presents a ' +
        'TLS client certificate this realm issued to its application, or an ' +
        'access token.',
        { 'WWW-Authenticate': this.challenges(req) }) : null;
    }
    const identifier = String(identity.username || '');
    let held = false;
    try {
      held = loadTlsClientCertificates().stillHeld(identity);
    } catch (e) {
      log.debug("Caught in SsfAuth.attemptClientCertificate(): " +
                ((e && e.message) || e));
      held = false;
    }
    if (!held) {
      log.debug("Leaving SsfAuth.attemptClientCertificate(). No longer " +
                "held.");
      return decides ? this.refusal('STS-SSF-0148', 401,
        'The TLS client certificate on this connection was issued to the ' +
        'application "' + identifier + '" (serial ' +
        String(identity.serialHex || '') + '), and its record no longer ' +
        'lists it — it was taken off or replaced. A certificate the ' +
        'application does not hold is not its credential.',
        { 'WWW-Authenticate': this.challenges(req) }) : null;
    }
    let scopes = '';
    if (decides) {
      const published = ssfScopes.published();
      const declared = (scopePolicy.declaredScopes(identifier) || [])
        .filter(function (one) {
          return published.indexOf(one) >= 0;
        });
      if (declared.length) {
        scopes = loadRolePermissions().narrowScope(declared.join(' '),
          { kind: 'application', name: identifier, authenticated: true },
          { clientId: identifier, grant: 'tls_client_certificate',
            stage: 'ssf' }).scope;
      }
      if (!ssfScopes.covers(scopes, need)) {
        const accepted = this.acceptedFor(need);
        log.debug("Leaving SsfAuth.attemptClientCertificate(). The " +
                  "application holds no \"" + need + "\" permission.");
        return this.refusal('STS-SSF-0149', 403,
          'The TLS client certificate authenticates the application "' +
          identifier + '", which ' + (declared.length
            ? 'declares ' + declared.join(', ') + ' and is authorized ' +
              (scopes ? 'only ' + scopes : 'none of them') + ' by its roles'
            : 'declares no Shared Signals scope in its oauthAllowedScope') +
          ', and this operation needs one of "' + accepted.join('", "') +
          '". Write includes read. A certificate holds what a token for ' +
          'the application would be issued: the scope declared on the ' +
          'application, and the application a member of SSF_READ or ' +
          'SSF_MANAGE.',
          { 'WWW-Authenticate': this.challenges(req) }, 'access_denied');
      }
    }
    log.debug("Leaving SsfAuth.attemptClientCertificate(). Accepted " +
              identifier + '.');
    return { ok: true, status: 200, scheme: 'clientcert',
      principal: identifier, scopes: scopes, err: '', description: '',
      headers: {},
      owner: { kind: 'application', name: identifier },
      note: 'TLS client certificate (serial ' +
            String(identity.serialHex || '') + ', ' +
            String(identity.why || 'issued by this realm') + ')' };
  }

  // -------------------------------------------------------------------------
  // THE ONE CALL EVERY PROTECTED ENDPOINT MAKES.
  //
  //   need   'read', 'write' or 'none'
  //
  // Returns `{ ok, status, err, description, headers, principal, scheme,
  // scopes, anonymous }` and answers nothing itself — the route decides the
  // body, because a stream management refusal and a poll refusal are
  // different documents.
  // -------------------------------------------------------------------------
  /**
   * Authenticates a request to a protected endpoint and decides whether it
   * holds the scope the operation needs.
   *
   * It tries OAuth, then GNAP, then Basic, then — with no Authorization
   * header — the TLS client certificate. It sends nothing itself: the
   * decision carries `ok`, `status`, `err`, `description`, `headers` (the
   * challenges on a 401), `principal`, `scheme`, `scopes` and, on a refusal,
   * the error code, and the route writes the body.
   *
   * @param req - the incoming request
   * @param need - `read`, `write` or `none` (the default)
   * @returns the decision
   */
  authenticate(req: AuthRequest, need?: string): Decision {
    const { helpers: { log }, mode } = this.deps;
    log.debug("Entering SsfAuth.authenticate(). need=" + need);
    const wanted = String(need || 'none');
    let decision = this.attemptOAuth(req, wanted);
    if (!decision) {
      decision = this.attemptGnap(req, wanted);
    }
    if (!decision) {
      decision = this.attemptBasic(req);
    }
    if (!decision) {
      decision = this.attemptClientCertificate(req, wanted);
    }
    if (decision) {
      log.debug("Leaving SsfAuth.authenticate(). A credential was " +
                'presented.');
      return decision;
    }
    if (!this.authRequired()) {
      log.debug("Leaving SsfAuth.authenticate(). Nothing required.");
      return { ok: true, status: 200, scheme: 'anonymous', principal: '',
        scopes: this.scopeRead() + ' ' + this.scopeWrite(), anonymous: true,
        err: '',
        description: '', headers: {},
        note: 'authentication is turned off' };
    }
    if (wanted === 'none') {
      log.debug("Leaving SsfAuth.authenticate(). Open endpoint.");
      return { ok: true, status: 200, scheme: 'anonymous', principal: '',
        scopes: '', anonymous: true, err: '', description: '', headers: {},
        note: 'this endpoint is open — a receiver has to be able to read ' +
              'what the endpoints are before it can authenticate to one' };
    }
    log.debug("Leaving SsfAuth.authenticate(). Nothing was presented.");
    return this.refusal('STS-SSF-0010', 401,
      'These endpoints decide what this transmitter delivers and to whom, ' +
      'so they require a credential. ' + (mode.verifiesCredentials()
        ? 'Send an access token from this service\'s own token endpoint ' +
          'with the read scope (ssf.read) or the write scope ' +
          '(ssf.manage), which includes read' +
          (this.basicOffered() ? ', or a directory person\'s username and ' +
           'password over Basic' : '') +
          (this.clientCertOffered() ? ', or a TLS client certificate this ' +
           'realm issued to your application' : '') + '.'
        : 'Any scheme in the WWW-Authenticate headers will do and each is ' +
          'permissive: an access token from this service\'s own token ' +
          'endpoint with the read scope (ssf.read) or the write scope ' +
          '(ssf.manage), which includes read' +
          (this.basicOffered() ? ', or any username with any password but ' +
          '"' + REFUSED_PASSWORD + '" over Basic' : '') +
          (this.clientCertOffered() ? ', or a TLS client certificate this ' +
           'realm issued to your application' : '') + '.') +
      ' The transmitter configuration at /.well-known/ssf-configuration ' +
      'lists the schemes and is readable without a credential for exactly ' +
      'that reason.',
      { 'WWW-Authenticate': this.challenges(req) });
  }

  // The `authorization_schemes` member of the transmitter metadata. SSF 1.0
  // defines only `spec_urn` on each entry, so that is the only member emitted
  // — a document carrying this service's own prose would be inviting a
  // receiver to depend on a member no specification defines.
  /**
   * Returns the `authorization_schemes` member of the transmitter
   * configuration: one `{ spec_urn }` per scheme offered right now.
   *
   * @returns the schemes, in preference order
   */
  schemesForMetadata(): Array<{ spec_urn: string }> {
    const { helpers: { log } } = this.deps;
    log.debug("Entering SsfAuth.schemesForMetadata().");
    const list = this.offeredSchemes().map(function (row) {
      return { spec_urn: row.spec_urn };
    });
    log.debug("Leaving SsfAuth.schemesForMetadata(). " + list.length + '.');
    return list;
  }

  // What this gate is, as data, for `GET /ssf` and `/admin/ssf`.
  /**
   * Describes this gate as data, for `GET /ssf` and `/admin/ssf`: whether it is
   * required, the realm, the scopes, the schemes and whether each is offered,
   * and a note on what the current mode verifies.
   *
   * @returns the description
   */
  describe(): Record<string, any> {
    const { helpers: { log }, mode, ssfScopes } = this.deps;
    log.debug("Entering SsfAuth.describe().");
    const out = {
      required: this.authRequired(),
      realm: this.realm(),
      scopes: { read: this.scopeRead(), write: this.scopeWrite(),
        readAlso: ssfScopes.namesGranting('read'),
        writeAlso: ssfScopes.namesGranting('write'),
        writeIncludesRead: true },
      refusedPassword: REFUSED_PASSWORD,
      metadataIsOpen: true,
      passwordVerified: mode.verifiesCredentials(),
      schemes: SCHEMES.map((row) => {
        return { id: row.id, name: row.name, spec_urn: row.spec_urn,
          what: row.what,
          offered: this.offered(row) };
      }),
      note: mode.verifiesCredentials()
        ? 'Product mode: a Basic password is verified against the ' +
          'person\'s directory entry, and a verified person is granted ' +
          'both scopes. An access token still has to be one this service ' +
          'issued, carrying the scope the operation needs, to a client that ' +
          'still declares it.'
        : 'A turnstile rather than a lock for Basic. A token\'s scope is ' +
          'issued only to a client whose oauthAllowedScope declares it, ' +
          'from this service\'s own token endpoint with any grant, and any ' +
          'username with any password but "' +
          REFUSED_PASSWORD + '" passes Basic. What it buys is that a ' +
          'client\'s 401, 403 and scope-handling paths can be run at all.'
    };
    log.debug("Leaving SsfAuth.describe().");
    return out;
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  /**
   * Returns the real modules this gate depends on, as the composition root
   * passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): SsfAuthDeps {
    helpers.log.debug("Entering SsfAuth.defaultDeps().");
    helpers.log.debug("Leaving SsfAuth.defaultDeps().");
    return {
      helpers: helpers,
      config: config,
      mode: mode,
      credentials: credentials,
      dpop: dpop,
      errorCodes: errorCodes,
      scopePolicy: scopePolicy,
      ssfScopes: ssfScopes,
      loadSsfCluster: function () {
        return require('./ssf_cluster');
      },
      loadGnapAccess: function () {
        return require('../gnap/gnap_access');
      },
      loadGnapRs: function () {
        return require('../gnap/gnap_rs');
      },
      loadTlsClientCertificates: function () {
        return require('../common/tls_client_certificates');
      },
      loadRolePermissions: function () {
        return require('../common/role_permissions');
      },
      loadAudit: function () {
        return require('../common/audit');
      }
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SsfAuth>(
  'ssf/ssf_auth',
  () => new SsfAuth(SsfAuth.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The Shared Signals endpoints' authentication gate.
 *
 * Exports the `SsfAuth` class and facades that forward to the instance the
 * composition root installs (or a default one built at load).
 *
 * @namespace
 */
export = {
  SsfAuth: SsfAuth,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: SsfAuth): void => slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  SCHEMES: SsfAuth.SCHEMES,
  REFUSED_PASSWORD: SsfAuth.REFUSED_PASSWORD,
  principalOfClaims: SsfAuth.principalOfClaims,
  authRequired: slot.forward('authRequired'),
  scopeRead: slot.forward('scopeRead'),
  scopeWrite: slot.forward('scopeWrite'),
  realm: slot.forward('realm'),
  challenges: slot.forward('challenges'),
  authenticate: slot.forward('authenticate'),
  schemesForMetadata: slot.forward('schemesForMetadata'),
  describe: slot.forward('describe')
};
