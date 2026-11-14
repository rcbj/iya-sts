// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_proxy.ts
//
// ===========================================================================
// THE REMOTE PEP AS A REVERSE PROXY — THE SERVICE'S HALF (#1760, phase 1).
//
// A registered remote PEP may be told to stand in front of an application:
// an ordered table of routes, each with the authentication mechanisms it
// accepts and the XACML resource and action it maps to. The container pulls
// that table (`GET /xacml/pep/proxy`) and, for what it cannot establish
// itself, asks four questions back over the same mutual-TLS channel
// (`POST /xacml/pep/{introspect,basic,saml,session}`). This module is
// everything those five doors and the two administrative actions DECIDE;
// `xacml.ts` answers the doors and `xacml_admin.ts` the actions.
//
// ---------------------------------------------------------------------------
// ONE VALIDATOR, ASKED TWICE.
//
// `validate()` is the grammar of the configuration document (the issue's
// D2). It is asked when an administrator writes one (`set-pep-proxy`) and
// AGAIN when the pull is built, because `ldapmodify` reaches
// `xacmlPepProxy` as it reaches every other attribute in `ou=peps`: a value
// that does not validate is pulled as `configured: false`, which makes the
// proxy answer 404 to everything — deny by default — and is logged with
// its code rather than sent half-understood.
//
// The document is CLOSED: a member this grammar does not name is refused by
// name, at the top and on a route. A proxy that ignored a member it did not
// know would be a proxy enforcing less than the administrator wrote.
//
// ---------------------------------------------------------------------------
// NO OPEN PROXY. `upstream` is fixed per PEP, absolute http(s), with no
// userinfo, query or fragment: nothing in a request can choose where the
// container forwards it. A path is refused where it holds a `.` or `..`
// segment, `//`, `%` or `\`, because each is a way for the path the policy
// is asked about to differ from the path the application serves.
//
// ---------------------------------------------------------------------------
// THE FOUR VALIDATION DOORS SAY AS LITTLE AS THEY CAN.
//
// * `basic()` is `credentials.verifyAsync()` behind the sign-in's own door
//   limits (`websecurity.doorBlocked/doorFailed/doorSucceeded`, door
//   `xacml-pep-basic`). A refusal is `{ valid: false }` and nothing else, so
//   it is no oracle for which usernames exist; the reason is in the log and
//   the audit row. Blocked is the one other answer, 429 with `retryAfterS`.
//   The password door named to `verifyAsync()` is `xacml-pep`, the sixth of
//   `common/app_password_doors.js`'s doors (#1760): a password alone cannot
//   ask for a second factor, so in product a person who holds or owes one
//   (everybody, unless `authn.allowOptionalSecondFactor`) is refused their
//   own password here and uses an APP PASSWORD scoped to `xacml-pep`, or the
//   door is listed in `authn.passwordAloneDoors`. Registering it was
//   additive: the Account API's app-password body gained `door_xacml-pep`
//   (`$membersFrom`), the management API's `doors` a value.
// * `introspect()` is `oauth2.introspectionFor()` — the authorization
//   server's own RFC 7662 reading of the token, `introspectionOf()` — with
//   the one difference that the caller is the PEP's certificate rather than
//   a registered resource server, so section 5's "intended for" narrowing is
//   not applied: the PEP holds the route's audience and checks `aud` itself.
// * `saml()` verifies an assertion THIS REALM issued: the enveloped
//   signature on the root `<saml:Assertion>` (and on no other element)
//   against the realm's XML signing certificates through `common/crypto.js`,
//   the issuer, the conditions with `oauth2.clockSkewS`, and the audience. An
//   `<EncryptedAssertion>` is refused by name: neither end holds a service
//   provider's decryption key.
// * `session()` is `oauth2.sessionIsLive()`, so a sign-out here ends the
//   proxy's session at the PEP's next check.
// * `identity()` (D11) is what a route forwards to its application about
//   the caller: the evidence (an access token, a SAML assertion, or the
//   ticket a valid Basic answered) validated AGAIN here, never trusted from
//   the PEP, then claims for the route's headers, an access token through
//   `oauth2.accessTokenAsync()` behind the issuance policy, or a signed SAML
//   Response through `saml2_sso.pepProxyResponse()`. The route must be one
//   of the asking PEP's own.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import mode = require('../common/mode');
import realms = require('../common/realms');
import cacheRegistry = require('../common/cache_registry');
import stsCrypto = require('../common/crypto');

const { log } = helpers;

// ---------------------------------------------------------------------------
// THE BASIC TICKET (#1760, D11). A valid `POST /xacml/pep/basic` answers a
// `ticket` the PEP later presents to `POST /xacml/pep/identity` as its
// evidence, so a route forwarding a token or an assertion about a Basic
// caller never sends the password again. It is OPAQUE (256 random bits,
// `crypto.randomToken()`), BOUND to the PEP it was handed to and the
// subject it is about, and lives TICKET_LIFETIME_S. It is NOT single-use: a
// proxy forwards one caller's identity on every request inside the window.
//
// Kept under the SHA-256 of the ticket, never the ticket, in a store per
// realm at its declaration (rule 2 of the realm design), persisted so a
// ticket handed out by one worker or node is found by another, with its
// expiry on the row (so the minted expiry purge takes it), checked at the
// read, bounded at the insert (the oldest dropped: a lost ticket costs the
// PEP one more Basic validation) and ejected by `caches.eject-expired`.
// ---------------------------------------------------------------------------
const TICKET_LIFETIME_S = 120;
const MAX_TICKETS = 10000;
const tickets: any = realms.map({
  persist: 'xacml.pepTickets',
  expiresAt: realms.expiryField('exp', 1000)
});

cacheRegistry.register({
  name: 'xacml.pep-tickets',
  title: 'Remote PEP Basic tickets',
  description: 'The tickets a valid POST /xacml/pep/basic handed a remote ' +
    'PEP, keyed by the SHA-256 of each; the ticket itself is not stored.',
  owner: 'xacml/xacml_pep_proxy.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a ticket was found by its digest',
  settings: [],
  maxEntries: function (): number {
    return MAX_TICKETS;
  },
  bound: 'Enforced: ' + MAX_TICKETS + ' per realm, the oldest dropped; the ' +
    'PEP validates the Basic credential again.',
  lifetime: function (): string {
    return TICKET_LIFETIME_S + ' s after it was handed out; an expired ' +
      'ticket is refused when it is presented and deleted by ' +
      'caches.eject-expired.';
  },
  eject: cacheRegistry.realmMapEjector(realms, tickets,
    function (row: any, key: unknown, now: number): boolean {
      const exp = Number(row && row.exp);
      return exp > 0 && exp * 1000 <= now;
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, tickets,
      function (row: any, key: unknown): any {
        const exp = Number(row && row.exp);
        return { key: cacheRegistry.digestKey(String(key)),
                 pep: String((row && row.pep) || ''),
                 validUntil: exp > 0 ? exp * 1000 : null };
      });
  }
});

// What every refusal of the validator answers.
interface Refusal {
  ok: false;
  why: string;
  code: string;
}

// One route, normalised: every member present.
interface ProxyRoute {
  id: string;
  path: string;
  match: string;
  methods: string[];
  public: boolean;
  mechanisms: string[];
  // The application in the realm's registry the route fronts (D10): what
  // each mechanism needs is read from its entry at the pull, never stored.
  application: string;
  resource: string;
  action: string;
  // How the identity reaches the application (D11).
  identity: Identity;
  forwardCredentials: boolean;
  // A session route's sign-out reaches the proxy through CAEP/RISC (true)
  // or through `POST /xacml/pep/session` polling (false).
  signals: boolean;
}

// How the identity reaches the application behind a route (D11).
interface Identity {
  mode: string;
  headers: Array<{ name: string; claim: string }>;
  separator: string;
}

// What the pull says about one route's application (D10).
interface Resolution {
  usable: boolean;
  why?: string;
  code?: string;
  audiences?: string[];
  samlAudience?: string;
  clientId?: string;
}

// What a session route's relying party needs, by client id. The secret is
// opened; this is sent only on the PEP's mutual-TLS pull.
interface ClientFacts {
  clientSecret: string;
  tokenEndpointAuthMethod: string;
  redirectUri: string;
  scopes: string[];
}

// The document, normalised.
interface ProxyDocument {
  enabled: boolean;
  upstream: string;
  publicBaseUrl: string;
  upstreamTimeoutMs: number;
  maxBodyBytes: number;
  routes: ProxyRoute[];
}

type Validated = { ok: true; proxy: ProxyDocument } | Refusal;

// What a validation door answers: an HTTP status and the closed body.
interface DoorAnswer {
  status: number;
  body: Record<string, unknown>;
  code?: string;
  // For the audit row and the log only; never in the body.
  reason?: string;
  actor?: string;
}

interface PepProxyDeps {
  log: typeof log;
  config: { value(key: string): any };
  errorCodes: typeof errorCodes;
  // Whether a browser may reach the proxy over plain http
  // (`mode.servesProxyBrowsersInTheClear()`).
  clearOriginAllowed(): boolean;
  loadCredentials(): { verifyAsync(username: string, password: string,
                                   opts?: any): Promise<any> };
  loadWebsecurity(): {
    doorBlocked(what: string, req: any, identity: unknown): any;
    doorFailed(what: string, req: any, identity: unknown): any;
    doorSucceeded(what: string, req: any, identity: unknown): any;
  };
  loadOauth2(): { introspectionFor(token: string): any;
                  sessionIsLive(sid: unknown, username?: unknown): boolean;
                  issuerOf(base: string): string;
                  accessTokenAsync(base: string, opts: any): Promise<any> };
  loadAuthn(): { sessionById(id: string): any;
                 warmSessionAsync(id: string): Promise<boolean> };
  loadApplications(): { get(identifier: string): any;
                        clientConfigOf(identifier: string): any };
  // The PEM chain this service's listener presents, leaf to Root, as
  // `GET /tls/server-certificate` publishes it.
  listenerChainPem(): string;
  // Every registered PEP of the ambient realm, for an application's page.
  allPeps(): Array<{ name: string; proxy: string }>;
  xmlSigningCertificates(): string[];
  subjectForName(name: string): string;
  rebase(base: string, family: string): string;
  verifyXmlSignature(xml: string, opts: any): any;
  parseXml(xml: string): any;
  now(): number;
  // The Basic ticket store (D11), and the two operations a ticket needs.
  tickets: Map<string, any>;
  randomToken(): string;
  digest(value: string): string;
  // The person a directory entry holds, as `saml/person_attributes.ts`
  // reads it, and the names of their groups.
  personOf(username: string): Record<string, unknown>;
  groupsOf(username: string): string[];
  // `common/issuance_gate.js`, for a token the jwt mode issues.
  loadGate(): { check(question: any): any;
                ISSUANCE: Record<string, string> };
  // `saml/saml2_sso.ts`, for the Response the saml mode builds.
  loadSaml2Sso(): { pepProxyResponse(opts: any): any };
}

// The members a document may carry, and a route; anything else is refused.
const DOCUMENT_MEMBERS = ['enabled', 'upstream', 'publicBaseUrl',
                          'upstreamTimeoutMs', 'maxBodyBytes', 'routes'];
const ROUTE_MEMBERS = ['id', 'path', 'match', 'methods', 'public',
                       'mechanisms', 'application', 'resource', 'action',
                       'identity', 'forwardCredentials', 'signals'];
const IDENTITY_MODES = ['headers', 'saml', 'jwt'];
const IDENTITY_MEMBERS = ['mode', 'headers', 'separator'];
const IDENTITY_CLAIMS = ['sub', 'username', 'email', 'name', 'given_name',
                         'family_name', 'groups', 'mechanism', 'acr', 'amr'];
const MAX_IDENTITY_HEADERS = 16;
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const MECHANISMS = ['session', 'oauth2', 'saml2', 'basic'];
const MATCHES = ['prefix', 'exact'];
const MAX_ROUTES = 64;
const ROUTE_ID = /^[A-Za-z0-9._-]{1,64}$/;
// RFC 9110 section 5.6.2's token.
const HEADER_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/;
// Headers the proxy itself owns on the forwarded request; naming one as the
// identity header would let the configuration overwrite framing or the very
// credential `forwardCredentials: false` strips.
const RESERVED_HEADERS = ['authorization', 'cookie', 'host', 'content-length',
                          'transfer-encoding', 'connection', 'upgrade', 'te',
                          'trailer', 'keep-alive', 'proxy-authorization',
                          'proxy-authenticate', 'proxy-connection',
                          'forwarded', 'set-cookie'];
const TEXT_MAX = 1024;
// The reserved callback path of the session mechanism (the issue's D6).
const CALLBACK_PATH = '/.iya-pep/callback';
const SAML2_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';
const XMLDSIG = 'http://www.w3.org/2000/09/xmldsig#';
// What one base64 assertion may be, decoded: a signed assertion is a few
// kilobytes; this bounds the parse.
const SAML_MAX_BYTES = 262144;

/**
 * The service's half of the remote PEP's reverse proxy: the configuration
 * grammar, the pull's body, the four validation doors and the session
 * mechanism's client.
 */
class PepProxy {
  static readonly METHODS = METHODS;
  static readonly MECHANISMS = MECHANISMS;
  static readonly CALLBACK_PATH = CALLBACK_PATH;

  /**
   * Builds it over its dependencies.
   * @param deps - the logger, settings, error codes, the mode's answer and
   *   lazy loaders for what the doors ask
   */
  constructor(private readonly deps: PepProxyDeps) {
    deps.log.debug("Entering PepProxy.constructor().");
    deps.log.debug("Leaving PepProxy.constructor().");
  }

  /**
   * The dependencies from the real modules.
   * @returns the dependencies
   */
  static defaultDeps(): PepProxyDeps {
    helpers.log.debug("Entering PepProxy.defaultDeps().");
    helpers.log.debug("Leaving PepProxy.defaultDeps().");
    return {
      log: log,
      config: config,
      errorCodes: errorCodes,
      clearOriginAllowed: function (): boolean {
        helpers.log.debug("Entering clearOriginAllowed().");
        helpers.log.debug("Leaving clearOriginAllowed().");
        return mode.servesProxyBrowsersInTheClear();
      },
      loadCredentials: function (): any {
        helpers.log.debug("Entering loadCredentials().");
        helpers.log.debug("Leaving loadCredentials().");
        return require('../common/credentials');
      },
      loadWebsecurity: function (): any {
        helpers.log.debug("Entering loadWebsecurity().");
        helpers.log.debug("Leaving loadWebsecurity().");
        return require('../common/websecurity');
      },
      // Lazily: `oauth2` is 9 and `authn` 8 in the require order, this
      // module 23c, so each is a cache hit that moves nothing.
      loadOauth2: function (): any {
        helpers.log.debug("Entering loadOauth2().");
        helpers.log.debug("Leaving loadOauth2().");
        return require('../oauth-oidc/oauth2');
      },
      loadAuthn: function (): any {
        helpers.log.debug("Entering loadAuthn().");
        helpers.log.debug("Leaving loadAuthn().");
        return require('../authn/authn');
      },
      loadApplications: function (): any {
        helpers.log.debug("Entering loadApplications().");
        helpers.log.debug("Leaving loadApplications().");
        return require('../common/applications');
      },
      listenerChainPem: function (): string {
        helpers.log.debug("Entering listenerChainPem().");
        // Lazily: `tls/tls_server.js` is 20 in the require order.
        const pem = require('../tls/tls_server').listenerChainPem();
        helpers.log.debug("Leaving listenerChainPem().");
        return String(pem || '');
      },
      allPeps: function (): Array<{ name: string; proxy: string }> {
        helpers.log.debug("Entering allPeps().");
        const rows = require('./xacml_pep_registry').all();
        helpers.log.debug("Leaving allPeps(). " + rows.length);
        return rows;
      },
      xmlSigningCertificates: function (): string[] {
        helpers.log.debug("Entering xmlSigningCertificates().");
        const rows = helpers.ownXmlSigningCertificates() || [];
        const out: string[] = [];
        rows.forEach(function (one: any) {
          const pem = String((one && one.certPem) || '');
          if (pem && out.indexOf(pem) < 0) {
            out.push(pem);
          }
        });
        helpers.log.debug("Leaving xmlSigningCertificates(). " + out.length);
        return out;
      },
      subjectForName: function (name: string): string {
        helpers.log.debug("Entering subjectForName().");
        helpers.log.debug("Leaving subjectForName().");
        return String(helpers.subjectForName(name) || '');
      },
      rebase: function (base: string, family: string): string {
        helpers.log.debug("Entering rebase().");
        helpers.log.debug("Leaving rebase().");
        return helpers.rebaseTo(base, family);
      },
      verifyXmlSignature: function (xml: string, opts: any): any {
        helpers.log.debug("Entering verifyXmlSignature().");
        helpers.log.debug("Leaving verifyXmlSignature().");
        return require('../common/crypto').verifyXmlSignature(xml, opts);
      },
      parseXml: function (xml: string): any {
        helpers.log.debug("Entering parseXml().");
        const { DOMParser } = require('../common/xml_parser');
        helpers.log.debug("Leaving parseXml().");
        return new DOMParser().parseFromString(xml, 'text/xml');
      },
      now: function (): number {
        helpers.log.debug("Entering now().");
        helpers.log.debug("Leaving now().");
        return Date.now();
      },
      tickets: tickets,
      randomToken: function (): string {
        helpers.log.debug("Entering randomToken().");
        helpers.log.debug("Leaving randomToken().");
        return stsCrypto.randomToken(256);
      },
      digest: function (value: string): string {
        helpers.log.debug("Entering digest().");
        helpers.log.debug("Leaving digest().");
        return stsCrypto.credentialDigest(value);
      },
      personOf: function (username: string): Record<string, unknown> {
        helpers.log.debug("Entering personOf().");
        const person = require('../saml/person_attributes')
          .personFor(helpers.userFor(username));
        helpers.log.debug("Leaving personOf().");
        return person || {};
      },
      groupsOf: function (username: string): string[] {
        helpers.log.debug("Entering groupsOf().");
        // Lazily: `ldap/ldap_server.js` is 21 in the require order and
        // registers routes when it is required.
        const found = require('../ldap/ldap_server').groupsOfUser(username);
        const out: string[] = [];
        ((found && found.groups) || []).forEach(function (one: any) {
          const name = String((one && one.cn) || '');
          if (name && out.indexOf(name) < 0) {
            out.push(name);
          }
        });
        helpers.log.debug("Leaving groupsOf(). " + out.length);
        return out;
      },
      loadGate: function (): any {
        helpers.log.debug("Entering loadGate().");
        helpers.log.debug("Leaving loadGate().");
        return require('../common/issuance_gate');
      },
      loadSaml2Sso: function (): any {
        helpers.log.debug("Entering loadSaml2Sso().");
        helpers.log.debug("Leaving loadSaml2Sso().");
        return require('../saml/saml2_sso');
      }
    };
  }

  // A refusal, coded.
  private refuse(why: string, code: string): Refusal {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PepProxy.refuse(). " + code);
    log.debug("Leaving PepProxy.refuse().");
    return errorCodes.mark({ ok: false, why: why, code: code }, code);
  }

  // An absolute http(s) URL with no userinfo, query or fragment, or a
  // sentence saying why not.
  private urlProblem(value: unknown, member: string): string {
    const { log } = this.deps;
    log.debug("Entering PepProxy.urlProblem(). " + member);
    if (typeof value !== 'string' || !value || value.length > TEXT_MAX) {
      log.debug("Leaving PepProxy.urlProblem(). Not a string.");
      return '`' + member + '` must be an absolute http or https URL of at ' +
        'most ' + TEXT_MAX + ' characters.';
    }
    let url: URL;
    try {
      url = new URL(value);
    } catch (e) {
      log.debug("Caught in PepProxy.urlProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving PepProxy.urlProblem(). Not a URL.");
      return '`' + member + '` is not an absolute URL: "' + value + '".';
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      log.debug("Leaving PepProxy.urlProblem(). Scheme.");
      return '`' + member + '` must be http or https, not ' + url.protocol +
        '.';
    }
    if (url.username || url.password || url.search || url.hash ||
        /[?#]/.test(value) || /\/\/[^/]*@/.test(value)) {
      log.debug("Leaving PepProxy.urlProblem(). Userinfo, query or fragment.");
      return '`' + member + '` may carry no user name, password, query or ' +
        'fragment: the proxy forwards to a fixed address and takes nothing ' +
        'of it from a request.';
    }
    log.debug("Leaving PepProxy.urlProblem(). Usable.");
    return '';
  }

  // A route path: starts with `/`, no `.` or `..` segment, no `//`, no `%`,
  // no `\`, no control character, `?` or `#`.
  private pathProblem(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering PepProxy.pathProblem().");
    if (typeof value !== 'string' || !value || value.length > TEXT_MAX ||
        value.charAt(0) !== '/') {
      log.debug("Leaving PepProxy.pathProblem(). Shape.");
      return 'a route `path` starts with "/" and is at most ' + TEXT_MAX +
        ' characters';
    }
    if (value.indexOf('//') >= 0 || value.indexOf('%') >= 0 ||
        value.indexOf('\\') >= 0 || /[\u0000- \u007f?#]/.test(value)) {
      log.debug("Leaving PepProxy.pathProblem(). A character.");
      return 'a route `path` may hold no "//", "%", "\\", "?", "#", space ' +
        'or control character, because each lets the path a policy is ' +
        'asked about differ from the path the application serves';
    }
    const dotted = value.split('/').some(function (segment) {
      return segment === '.' || segment === '..';
    });
    if (dotted) {
      log.debug("Leaving PepProxy.pathProblem(). A dot segment.");
      return 'a route `path` may hold no "." or ".." segment';
    }
    log.debug("Leaving PepProxy.pathProblem(). Usable.");
    return '';
  }

  // A header name, or '' for none.
  private headerProblem(value: unknown, member: string): string {
    const { log } = this.deps;
    log.debug("Entering PepProxy.headerProblem(). " + member);
    if (value === undefined || value === '') {
      log.debug("Leaving PepProxy.headerProblem(). None.");
      return '';
    }
    if (typeof value !== 'string' || !HEADER_TOKEN.test(value)) {
      log.debug("Leaving PepProxy.headerProblem(). Not a token.");
      return '`' + member + '` must be a header name (an RFC 9110 token of ' +
        'at most 128 characters), or empty for none';
    }
    if (RESERVED_HEADERS.indexOf(value.toLowerCase()) >= 0 ||
        /^x-forwarded-/i.test(value)) {
      log.debug("Leaving PepProxy.headerProblem(). Reserved.");
      return '`' + member + '` may not be ' + value + ', which the proxy ' +
        'itself writes or strips on the forwarded request';
    }
    log.debug("Leaving PepProxy.headerProblem(). Usable.");
    return '';
  }

  // An integer within [min, max], or the default when absent.
  private integerOf(value: unknown, dflt: number, min: number,
                    max: number): number | null {
    const { log } = this.deps;
    log.debug("Entering PepProxy.integerOf().");
    if (value === undefined) {
      log.debug("Leaving PepProxy.integerOf(). Default.");
      return dflt;
    }
    if (typeof value !== 'number' || !Number.isInteger(value) ||
        value < min || value > max) {
      log.debug("Leaving PepProxy.integerOf(). Out of range.");
      return null;
    }
    log.debug("Leaving PepProxy.integerOf().");
    return value;
  }

  // A string of at most TEXT_MAX characters with no control character, or
  // the default when absent; null when it is neither.
  private textOf(value: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering PepProxy.textOf().");
    if (value === undefined) {
      log.debug("Leaving PepProxy.textOf(). Absent.");
      return '';
    }
    if (typeof value !== 'string' || value.length > TEXT_MAX ||
        /[\u0000-\u001f\u007f]/.test(value)) {
      log.debug("Leaving PepProxy.textOf(). Refused.");
      return null;
    }
    log.debug("Leaving PepProxy.textOf().");
    return value;
  }

  // The first member of `node` not in `allowed`, or ''.
  private strayMember(node: Record<string, unknown>,
                      allowed: string[]): string {
    const { log } = this.deps;
    log.debug("Entering PepProxy.strayMember().");
    const stray = Object.keys(node).filter(function (key) {
      return allowed.indexOf(key) < 0;
    })[0] || '';
    log.debug("Leaving PepProxy.strayMember(). " + (stray || 'none'));
    return stray;
  }

  // A route's `identity` (D11), normalised, or a refusal naming it.
  private identityOf(raw: unknown, isPublic: boolean, where: string,
                     id: string): Identity | Refusal {
    const { log } = this.deps;
    log.debug("Entering PepProxy.identityOf().");
    const at = where + ' ("' + id + '")';
    if (raw === undefined) {
      log.debug("Leaving PepProxy.identityOf(). Default.");
      return { mode: 'headers', headers: [], separator: ',' };
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      log.debug("Leaving PepProxy.identityOf(). Not an object.");
      return this.refuse(at + ': `identity` is an object with ' +
        IDENTITY_MEMBERS.join(', ') + '.', 'STS-XACML-0224');
    }
    const node = raw as Record<string, unknown>;
    const stray = this.strayMember(node, IDENTITY_MEMBERS);
    if (stray) {
      log.debug("Leaving PepProxy.identityOf(). Stray.");
      return this.refuse(at + ': `identity` carries "' + stray + '", ' +
        'which it does not have.', 'STS-XACML-0185');
    }
    const mode = node.mode === undefined ? 'headers' : node.mode;
    if (typeof mode !== 'string' || IDENTITY_MODES.indexOf(mode) < 0) {
      log.debug("Leaving PepProxy.identityOf(). Mode.");
      return this.refuse(at + ': `identity.mode` is one of ' +
        IDENTITY_MODES.join(', ') + '.', 'STS-XACML-0224');
    }
    const headers = node.headers === undefined ? [] : node.headers;
    // A token or an assertion carries the identity itself, so mode saml or
    // jwt names no header. An empty list is its normalised form, so a saved
    // document validates again.
    if (mode !== 'headers' && Array.isArray(node.headers) &&
        node.headers.length) {
      log.debug("Leaving PepProxy.identityOf(). Headers on another mode.");
      return this.refuse(at + ': `identity.headers` belongs to mode ' +
        'headers alone.', 'STS-XACML-0224');
    }
    if (!Array.isArray(headers) || headers.length > MAX_IDENTITY_HEADERS) {
      log.debug("Leaving PepProxy.identityOf(). Headers list.");
      return this.refuse(at + ': `identity.headers` is a list of at most ' +
        MAX_IDENTITY_HEADERS + ' { name, claim }.', 'STS-XACML-0225');
    }
    const seen: string[] = [];
    const out: Array<{ name: string; claim: string }> = [];
    for (let i = 0; i < headers.length; i++) {
      const one = headers[i];
      if (!one || typeof one !== 'object' || Array.isArray(one) ||
          this.strayMember(one, ['name', 'claim'])) {
        log.debug("Leaving PepProxy.identityOf(). A header row.");
        return this.refuse(at + ': each of `identity.headers` is { name, ' +
          'claim } and nothing else.', 'STS-XACML-0225');
      }
      const problem = this.headerProblem(one.name, 'identity.headers.name');
      if (problem || !one.name) {
        log.debug("Leaving PepProxy.identityOf(). A header name.");
        return this.refuse(at + ': ' + (problem ||
          '`identity.headers.name` is required') + '.',
          problem ? 'STS-XACML-0198' : 'STS-XACML-0225');
      }
      const lower = String(one.name).toLowerCase();
      if (seen.indexOf(lower) >= 0) {
        log.debug("Leaving PepProxy.identityOf(). A header twice.");
        return this.refuse(at + ': `identity.headers` names ' + one.name +
          ' twice (header names are compared without case).',
          'STS-XACML-0225');
      }
      if (typeof one.claim !== 'string' ||
          IDENTITY_CLAIMS.indexOf(one.claim) < 0) {
        log.debug("Leaving PepProxy.identityOf(). A claim.");
        return this.refuse(at + ': the claim of ' + one.name + ' is one ' +
          'of ' + IDENTITY_CLAIMS.join(', ') + '.', 'STS-XACML-0226');
      }
      seen.push(lower);
      out.push({ name: String(one.name), claim: one.claim });
    }
    const separator = node.separator === undefined ? ',' : node.separator;
    if (typeof separator !== 'string' || separator.length !== 1 ||
        !/^[!-~]$/.test(separator) || /^[A-Za-z0-9]$/.test(separator)) {
      log.debug("Leaving PepProxy.identityOf(). Separator.");
      return this.refuse(at + ': `identity.separator` is one printable ' +
        'ASCII character that is not a letter or a digit.',
        'STS-XACML-0227');
    }
    // A PUBLIC ROUTE ESTABLISHES NOBODY, so it forwards nobody: only the
    // default (mode headers, no header) — which a saved document carries —
    // is accepted on one.
    if (isPublic && (mode !== 'headers' || out.length)) {
      log.debug("Leaving PepProxy.identityOf(). Public.");
      return this.refuse(at + ' is public and names an `identity`: a ' +
        'public route establishes nobody to forward.', 'STS-XACML-0224');
    }
    log.debug("Leaving PepProxy.identityOf(). " + mode);
    return { mode: mode, headers: out, separator: separator };
  }

  // One route, normalised, or a refusal naming it.
  private validateRoute(raw: unknown, index: number,
                        seen: string[]): ProxyRoute | Refusal {
    const { log } = this.deps;
    log.debug("Entering PepProxy.validateRoute(). " + index);
    const where = 'Route ' + (index + 1);
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      log.debug("Leaving PepProxy.validateRoute(). Not an object.");
      return this.refuse(where + ' is not an object.', 'STS-XACML-0191');
    }
    const route = raw as Record<string, unknown>;
    const stray = this.strayMember(route, ROUTE_MEMBERS);
    if (stray) {
      log.debug("Leaving PepProxy.validateRoute(). Stray member.");
      return this.refuse(where + ' carries "' + stray + '", which a route ' +
        'does not have. A route has ' + ROUTE_MEMBERS.join(', ') + '.',
        'STS-XACML-0185');
    }
    const id = route.id;
    if (typeof id !== 'string' || !ROUTE_ID.test(id)) {
      log.debug("Leaving PepProxy.validateRoute(). Id.");
      return this.refuse(where + '\'s `id` must be 1 to 64 letters, ' +
        'digits, dots, dashes or underscores.', 'STS-XACML-0192');
    }
    if (seen.indexOf(id) >= 0) {
      log.debug("Leaving PepProxy.validateRoute(). Id twice.");
      return this.refuse('Two routes are called "' + id + '"; a route ' +
        '`id` is unique.', 'STS-XACML-0192');
    }
    const pathProblem = this.pathProblem(route.path);
    if (pathProblem) {
      log.debug("Leaving PepProxy.validateRoute(). Path.");
      return this.refuse(where + ' ("' + id + '"): ' + pathProblem + '.',
                         'STS-XACML-0193');
    }
    const match = route.match === undefined ? 'prefix' : route.match;
    if (typeof match !== 'string' || MATCHES.indexOf(match) < 0) {
      log.debug("Leaving PepProxy.validateRoute(). Match.");
      return this.refuse(where + ' ("' + id + '"): `match` is "prefix" or ' +
        '"exact".', 'STS-XACML-0194');
    }
    const methods = route.methods === undefined ? [] : route.methods;
    if (!Array.isArray(methods) || methods.some(function (one) {
      return typeof one !== 'string' || METHODS.indexOf(one) < 0;
    }) || new Set(methods).size !== methods.length) {
      log.debug("Leaving PepProxy.validateRoute(). Methods.");
      return this.refuse(where + ' ("' + id + '"): `methods` is a list of ' +
        'distinct methods from ' + METHODS.join(', ') + ', or empty for ' +
        'any.', 'STS-XACML-0195');
    }
    const isPublic = route.public === undefined ? false : route.public;
    if (typeof isPublic !== 'boolean') {
      log.debug("Leaving PepProxy.validateRoute(). Public.");
      return this.refuse(where + ' ("' + id + '"): `public` is true or ' +
        'false.', 'STS-XACML-0199');
    }
    const mechanisms = route.mechanisms === undefined ? [] : route.mechanisms;
    if (!Array.isArray(mechanisms) || mechanisms.some(function (one) {
      return typeof one !== 'string' || MECHANISMS.indexOf(one) < 0;
    }) || new Set(mechanisms).size !== mechanisms.length) {
      log.debug("Leaving PepProxy.validateRoute(). Mechanisms.");
      return this.refuse(where + ' ("' + id + '"): `mechanisms` is a list ' +
        'of distinct mechanisms from ' + MECHANISMS.join(', ') + '.',
        'STS-XACML-0196');
    }
    if (isPublic && mechanisms.length) {
      log.debug("Leaving PepProxy.validateRoute(). Public with mechanisms.");
      return this.refuse(where + ' ("' + id + '") is public and names ' +
        'mechanisms: a public route takes no credential and asks no ' +
        'policy, so it names none.', 'STS-XACML-0196');
    }
    if (!isPublic && !mechanisms.length) {
      log.debug("Leaving PepProxy.validateRoute(). No mechanism.");
      return this.refuse(where + ' ("' + id + '") is not public and names ' +
        'no mechanism, so nobody could ever be let through it. Name at ' +
        'least one of ' + MECHANISMS.join(', ') + ', or make it public.',
        'STS-XACML-0196');
    }
    const application = this.textOf(route.application);
    const resource = this.textOf(route.resource);
    const action = this.textOf(route.action);
    if (application === null || resource === null || action === null) {
      log.debug("Leaving PepProxy.validateRoute(). Text member.");
      return this.refuse(where + ' ("' + id + '"): `application`, ' +
        '`resource` and `action` are strings of at most ' + TEXT_MAX +
        ' characters with no control character.', 'STS-XACML-0199');
    }
    // A ROUTE NAMES AN APPLICATION (D10): what a token's audience, an
    // assertion's Audience and the session's client are is read off that
    // application's entry at the pull, so a public route, which asks
    // nothing, names none, and every other route names one.
    if (isPublic && application) {
      log.debug("Leaving PepProxy.validateRoute(). Public with application.");
      return this.refuse(where + ' ("' + id + '") is public and names an ' +
        'application: a public route checks no credential, so there is ' +
        'nothing an application\'s entry could say about it.',
        'STS-XACML-0197');
    }
    if (!isPublic && !application) {
      log.debug("Leaving PepProxy.validateRoute(). No application.");
      return this.refuse(where + ' ("' + id + '") names no `application`: ' +
        'a token is accepted only for the audience of the application the ' +
        'route fronts, an assertion only for its entity ID, and a browser ' +
        'signs in as its client, so the route names it by its identifier.',
        'STS-XACML-0197');
    }
    const signals = route.signals === undefined ? true : route.signals;
    if (typeof signals !== 'boolean') {
      log.debug("Leaving PepProxy.validateRoute(). signals.");
      return this.refuse(where + ' ("' + id + '"): `signals` is true or ' +
        'false.', 'STS-XACML-0199');
    }
    const identity = this.identityOf(route.identity, isPublic, where, id);
    if ((identity as Refusal).ok === false) {
      log.debug("Leaving PepProxy.validateRoute(). Identity.");
      return identity as Refusal;
    }
    const forward = route.forwardCredentials === undefined
      ? false : route.forwardCredentials;
    if (typeof forward !== 'boolean') {
      log.debug("Leaving PepProxy.validateRoute(). forwardCredentials.");
      return this.refuse(where + ' ("' + id + '"): `forwardCredentials` is ' +
        'true or false.', 'STS-XACML-0199');
    }
    seen.push(id);
    log.debug("Leaving PepProxy.validateRoute(). Usable.");
    return {
      id: id, path: route.path as string, match: match,
      methods: methods.slice() as string[], public: isPublic,
      mechanisms: mechanisms.slice() as string[],
      application: application, resource: resource, action: action,
      identity: identity as Identity,
      forwardCredentials: forward, signals: signals
    };
  }

  // =========================================================================
  // THE GRAMMAR (D2).
  // =========================================================================
  /**
   * Validates a reverse-proxy configuration document whole and answers it
   * normalised, every member present, or refuses it by name with a code.
   *
   * @param input - the document, as an object or as JSON text
   * @returns `{ ok: true, proxy }`, or `{ ok: false, why, code }`
   */
  validate(input: unknown): Validated {
    const { log } = this.deps;
    log.debug("Entering PepProxy.validate().");
    let doc: unknown = input;
    if (typeof input === 'string') {
      try {
        doc = JSON.parse(input);
      } catch (e) {
        log.debug("Caught in PepProxy.validate(): " + ((e && e.message) || e));
        log.debug("Leaving PepProxy.validate(). Not JSON.");
        return this.refuse('The configuration is not JSON: ' +
                           ((e && e.message) || e) + '.', 'STS-XACML-0184');
      }
    }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      log.debug("Leaving PepProxy.validate(). Not an object.");
      return this.refuse('The configuration is a JSON object with ' +
        DOCUMENT_MEMBERS.join(', ') + '.', 'STS-XACML-0184');
    }
    const node = doc as Record<string, unknown>;
    const stray = this.strayMember(node, DOCUMENT_MEMBERS);
    if (stray) {
      log.debug("Leaving PepProxy.validate(). Stray member.");
      return this.refuse('The configuration carries "' + stray + '", which ' +
        'it does not have. It has ' + DOCUMENT_MEMBERS.join(', ') + '.',
        'STS-XACML-0185');
    }
    const enabled = node.enabled === undefined ? true : node.enabled;
    if (typeof enabled !== 'boolean') {
      log.debug("Leaving PepProxy.validate(). enabled.");
      return this.refuse('`enabled` is true or false.', 'STS-XACML-0186');
    }
    const upstreamProblem = this.urlProblem(node.upstream, 'upstream');
    if (upstreamProblem) {
      log.debug("Leaving PepProxy.validate(). upstream.");
      return this.refuse(upstreamProblem, 'STS-XACML-0187');
    }
    let publicBaseUrl = '';
    if (node.publicBaseUrl !== undefined && node.publicBaseUrl !== '') {
      const problem = this.urlProblem(node.publicBaseUrl, 'publicBaseUrl');
      if (problem) {
        log.debug("Leaving PepProxy.validate(). publicBaseUrl.");
        return this.refuse(problem, 'STS-XACML-0188');
      }
      const url = new URL(String(node.publicBaseUrl));
      if (url.pathname !== '/' ) {
        log.debug("Leaving PepProxy.validate(). publicBaseUrl has a path.");
        return this.refuse('`publicBaseUrl` is the ORIGIN a browser reaches ' +
          'the proxy at — scheme, host and port — with no path, because ' +
          'the session mechanism\'s callback is ' + CALLBACK_PATH + ' at its ' +
          'root.', 'STS-XACML-0188');
      }
      if (url.protocol !== 'https:' && !this.deps.clearOriginAllowed()) {
        log.debug("Leaving PepProxy.validate(). publicBaseUrl is http.");
        return this.refuse('`publicBaseUrl` must be https in product mode: ' +
          'the proxy\'s session cookie is Secure and the sign-in it ' +
          'completes carries an authorization code.', 'STS-XACML-0188');
      }
      publicBaseUrl = url.origin;
    }
    const timeout = this.integerOf(node.upstreamTimeoutMs, 10000, 1, 120000);
    if (timeout === null) {
      log.debug("Leaving PepProxy.validate(). upstreamTimeoutMs.");
      return this.refuse('`upstreamTimeoutMs` is an integer from 1 to ' +
                         '120000.', 'STS-XACML-0189');
    }
    const maxBody = this.integerOf(node.maxBodyBytes, 1048576, 0, 104857600);
    if (maxBody === null) {
      log.debug("Leaving PepProxy.validate(). maxBodyBytes.");
      return this.refuse('`maxBodyBytes` is an integer from 0 to ' +
                         '104857600.', 'STS-XACML-0190');
    }
    const rawRoutes = node.routes === undefined ? [] : node.routes;
    if (!Array.isArray(rawRoutes) || rawRoutes.length > MAX_ROUTES) {
      log.debug("Leaving PepProxy.validate(). routes.");
      return this.refuse('`routes` is a list of at most ' + MAX_ROUTES +
                         ' routes.', 'STS-XACML-0191');
    }
    const seen: string[] = [];
    const routes: ProxyRoute[] = [];
    for (let i = 0; i < rawRoutes.length; i++) {
      const one = this.validateRoute(rawRoutes[i], i, seen);
      if ((one as Refusal).ok === false) {
        log.debug("Leaving PepProxy.validate(). A route was refused.");
        return one as Refusal;
      }
      routes.push(one as ProxyRoute);
    }
    const session = routes.some(function (route) {
      return route.mechanisms.indexOf('session') >= 0;
    });
    if (session && !publicBaseUrl) {
      log.debug("Leaving PepProxy.validate(). Session with no origin.");
      return this.refuse('A route accepts the session mechanism and ' +
        '`publicBaseUrl` is empty: a browser is sent to sign in and back ' +
        'to ' + CALLBACK_PATH + ' at the origin it reaches the proxy at, ' +
        'so that origin is required.', 'STS-XACML-0188');
    }
    if (session && !/^https:/.test(publicBaseUrl)) {
      log.debug("Leaving PepProxy.validate(). Session over http.");
      return this.refuse('A route accepts the session mechanism and ' +
        '`publicBaseUrl` is not https: the relying party\'s callback is ' +
        'a redirect URI, which may be plain http only on a loopback ' +
        'address, and its session cookie is Secure.', 'STS-XACML-0188');
    }
    log.debug("Leaving PepProxy.validate(). " + routes.length + " route(s).");
    return {
      ok: true,
      proxy: {
        enabled: enabled, upstream: String(node.upstream),
        publicBaseUrl: publicBaseUrl, upstreamTimeoutMs: timeout,
        maxBodyBytes: maxBody, routes: routes
      }
    };
  }

  /**
   * Says whether a normalised document has a route using the session
   * mechanism.
   * @param proxy - the document
   * @returns true when it does
   */
  usesSession(proxy: ProxyDocument | null): boolean {
    const { log } = this.deps;
    log.debug("Entering PepProxy.usesSession().");
    const out = !!proxy && proxy.routes.some(function (route) {
      return route.mechanisms.indexOf('session') >= 0;
    });
    log.debug("Leaving PepProxy.usesSession(). " + out);
    return out;
  }

  // =========================================================================
  // A ROUTE'S APPLICATION, RESOLVED (D10). Asked when a configuration is
  // saved (an unusable one is refused) and again at every pull (an
  // application edited since moves the token; one deleted or no longer
  // qualifying leaves the route `usable: false`, which the PEP refuses).
  // =========================================================================
  /**
   * Resolves one route's application in the ambient realm.
   *
   * @param route - the normalised route
   * @param proxy - the normalised document, for the callback's origin
   * @returns the resolution and, for a session route, the client's facts
   */
  resolveRoute(route: ProxyRoute, proxy: ProxyDocument):
      { resolved: Resolution; client: ClientFacts | null } {
    const { log } = this.deps;
    log.debug("Entering PepProxy.resolveRoute(). " + route.id);
    if (route.public) {
      log.debug("Leaving PepProxy.resolveRoute(). Public.");
      return { resolved: { usable: true }, client: null };
    }
    const applications = this.deps.loadApplications();
    const entry = applications.get(route.application);
    const refused = function (code: string, why: string) {
      log.debug("Entering refused(). " + code);
      log.debug("Leaving refused().");
      return { resolved: { usable: false, code: code, why: why },
               client: null };
    };
    if (!entry) {
      log.debug("Leaving PepProxy.resolveRoute(). Unknown.");
      return refused('STS-XACML-0217', 'There is no application "' +
        route.application + '" in this realm\'s registry.');
    }
    const fields = entry.fields || {};
    const values = function (name: string): string[] {
      log.debug("Entering values(). " + name);
      log.debug("Leaving values().");
      const raw = fields[name];
      return (Array.isArray(raw) ? raw : (raw ? [raw] : []))
        .map(function (one: unknown) {
          return String(one).trim();
        }).filter(function (one: string) {
          return !!one;
        });
    };
    const resolved: Resolution = { usable: true };
    let client: ClientFacts | null = null;
    if (route.mechanisms.indexOf('oauth2') >= 0) {
      // THE AUDIENCES AN ACCESS TOKEN FOR THIS APPLICATION CARRIES: its
      // declared `oauthAudience` (what a client names in `resource` or
      // `audience`) and the base URI its delegated permissions hang off
      // (what a token for one of them is audienced to).
      const audiences: string[] = [];
      values('oauthAudience').concat(values('oauthPermissionBaseUri'))
        .forEach(function (one) {
          if (audiences.indexOf(one) < 0) {
            audiences.push(one);
          }
        });
      if (!audiences.length) {
        log.debug("Leaving PepProxy.resolveRoute(). No audience.");
        return refused('STS-XACML-0218', 'Route "' + route.id + '" ' +
          'accepts an OAuth 2.0 access token and its application "' +
          route.application + '" declares no audience (oauthAudience or ' +
          'oauthPermissionBaseUri), so no token is addressed to it.');
      }
      resolved.audiences = audiences;
    }
    if (route.mechanisms.indexOf('saml2') >= 0) {
      const entity = values('samlEntityId')[0] || '';
      if (!entity) {
        log.debug("Leaving PepProxy.resolveRoute(). No entity ID.");
        return refused('STS-XACML-0219', 'Route "' + route.id + '" ' +
          'accepts a SAML 2.0 assertion and its application "' +
          route.application + '" has no SAML entity ID (samlEntityId), ' +
          'which is the Audience an assertion for it names.');
      }
      resolved.samlAudience = entity;
    }
    // HOW THE IDENTITY REACHES IT (D11): an assertion needs the SP's entity
    // ID and its registered ACS; a token needs an audience.
    if (route.identity.mode === 'saml') {
      const entity = values('samlEntityId')[0] || '';
      const acs = values('samlAssertionConsumerService')[0] || '';
      if (!entity || !acs) {
        log.debug("Leaving PepProxy.resolveRoute(). No SP for saml.");
        return refused('STS-XACML-0228', 'Route "' + route.id + '" ' +
          'forwards the identity as a SAML assertion and its application "' +
          route.application + '" ' + (entity ? 'registers no assertion ' +
          'consumer service (samlAssertionConsumerService)' : 'has no ' +
          'SAML entity ID (samlEntityId)') + '.');
      }
    }
    if (route.identity.mode === 'jwt' &&
        !values('oauthAudience').concat(values('oauthPermissionBaseUri'))
          .length) {
      log.debug("Leaving PepProxy.resolveRoute(). No audience for jwt.");
      return refused('STS-XACML-0218', 'Route "' + route.id + '" forwards ' +
        'the identity as an access token and its application "' +
        route.application + '" declares no audience (oauthAudience or ' +
        'oauthPermissionBaseUri) to issue it for.');
    }
    if (route.mechanisms.indexOf('session') >= 0) {
      const clientId = values('oauthClientId')[0] || route.application;
      const config = applications.clientConfigOf(clientId) || {};
      const methods: string[] = (config.token_endpoint_auth_methods || [])
        .map(String);
      const method = ['client_secret_basic', 'client_secret_post']
        .filter(function (one) {
          return methods.indexOf(one) >= 0;
        })[0] || '';
      if (!config.known || !method) {
        log.debug("Leaving PepProxy.resolveRoute(). Not confidential.");
        return refused('STS-XACML-0220', 'Route "' + route.id + '" signs ' +
          'a browser in as application "' + route.application + '", which ' +
          'is not a confidential OpenID Connect client: its ' +
          'token_endpoint_auth_method must include client_secret_basic or ' +
          'client_secret_post.');
      }
      const grants = values('oauthGrantType');
      if (grants.length && grants.indexOf('authorization_code') < 0) {
        log.debug("Leaving PepProxy.resolveRoute(). No code grant.");
        return refused('STS-XACML-0221', 'Route "' + route.id + '": ' +
          'application "' + route.application + '" does not allow the ' +
          'authorization_code grant (oauthGrantType).');
      }
      const redirect = proxy.publicBaseUrl + CALLBACK_PATH;
      if ((config.redirect_uris || []).indexOf(redirect) < 0) {
        log.debug("Leaving PepProxy.resolveRoute(). No callback.");
        return refused('STS-XACML-0222', 'Route "' + route.id + '": ' +
          'application "' + route.application + '" does not register the ' +
          'proxy\'s callback ' + redirect + ' among its redirect URIs ' +
          '(oauthRedirectUri), and a sign-in may return only to one it ' +
          'registered.');
      }
      const nowS = Math.floor(this.deps.now() / 1000);
      const live = (config.client_secrets || []).filter(function (one: any) {
        return one && one.secret &&
          !(Number(one.expiresAt) > 0 && Number(one.expiresAt) <= nowS);
      })[0];
      if (!live) {
        log.debug("Leaving PepProxy.resolveRoute(). No secret.");
        return refused('STS-XACML-0223', 'Route "' + route.id + '": ' +
          'application "' + route.application + '" holds no unexpired ' +
          'client secret for the proxy to authenticate with.');
      }
      const scopes = ['openid'];
      values('oauthAllowedScope').forEach(function (one) {
        if (scopes.indexOf(one) < 0) {
          scopes.push(one);
        }
      });
      resolved.clientId = clientId;
      client = { clientSecret: String(live.secret),
                 tokenEndpointAuthMethod: method, redirectUri: redirect,
                 scopes: scopes };
    }
    log.debug("Leaving PepProxy.resolveRoute(). Usable.");
    return { resolved: resolved, client: client };
  }

  /**
   * The first route of a document whose application does not resolve, as a
   * refusal, or null when every one does: what a save asks.
   *
   * @param proxy - the normalised document
   * @returns the refusal, or null
   */
  resolutionProblem(proxy: ProxyDocument): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering PepProxy.resolutionProblem().");
    for (let i = 0; i < proxy.routes.length; i++) {
      const one = this.resolveRoute(proxy.routes[i], proxy).resolved;
      if (!one.usable) {
        log.debug("Leaving PepProxy.resolutionProblem(). " + one.code);
        return this.refuse(String(one.why), String(one.code));
      }
    }
    log.debug("Leaving PepProxy.resolutionProblem(). None.");
    return null;
  }

  /**
   * Which routes of this realm's remote PEPs front an application: the
   * reference only, for the application's console page.
   *
   * @param identifier - the application
   * @returns `{ pep, route, path, mechanisms }` rows
   */
  routesFronting(identifier: string): Array<Record<string, unknown>> {
    const { log } = this.deps;
    log.debug("Entering PepProxy.routesFronting(). " + identifier);
    const self = this;
    const out: Array<Record<string, unknown>> = [];
    this.deps.allPeps().forEach(function (row) {
      const checked = row.proxy ? self.validate(row.proxy) : null;
      if (!checked || !checked.ok) {
        return;
      }
      checked.proxy.routes.forEach(function (route) {
        if (!route.public && route.application === identifier) {
          out.push({ pep: row.name, route: route.id, path: route.path,
                     mechanisms: route.mechanisms.slice() });
        }
      });
    });
    log.debug("Leaving PepProxy.routesFronting(). " + out.length);
    return out;
  }

  // =========================================================================
  // THE PULL (D3).
  // =========================================================================
  /**
   * Builds the pull's answer and its sync token for one registered PEP (or
   * none), in the realm the request is answered in.
   *
   * @param base - the request's base URL (the realm's)
   * @param row - the PEP's register row, or null when it has none
   * @param name - the name its certificate gives it
   * @returns `{ token, body }`
   */
  pull(base: string, row: { name: string; proxy: string } | null,
       name: string): { token: string; body: Record<string, unknown> } {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PepProxy.pull(). name=" + name);
    let proxy: ProxyDocument | null = null;
    let note = '';
    if (!row) {
      note = 'No Policy Enforcement Point is registered under this name in ' +
        'this realm, so it holds no proxy configuration: register first ' +
        '(POST /xacml/pep/register), then an administrator configures it ' +
        '(set-pep-proxy). The proxy answers 404 to everything until then.';
    } else if (!row.proxy) {
      note = 'This PEP holds no proxy configuration; an administrator ' +
        'sets one on the Remote PEPs tab or with POST ' +
        '/admin-api/xacml/set-pep-proxy. The proxy answers 404 to ' +
        'everything until then.';
    } else {
      const checked = this.validate(row.proxy);
      if (checked.ok) {
        proxy = checked.proxy;
      } else {
        // An `ldapmodify` wrote something this grammar refuses. Logged with
        // its code, never sent half-understood.
        log.warn(errorCodes.tag('STS-XACML-0200') + 'xacml: the proxy ' +
                 'configuration stored for remote PEP "' + row.name + '" ' +
                 'does not validate (' + (checked as Refusal).code + ': ' +
                 (checked as Refusal).why +
                 '); it is pulled as configured: false.');
        note = 'The stored proxy configuration does not validate, so it ' +
          'is not sent and the proxy answers 404 to everything. An ' +
          'administrator sees why on the Remote PEPs tab and saves it ' +
          'again.';
      }
    }
    const sent: Record<string, unknown> = {
      pep: row ? row.name : name,
      configured: !!proxy
    };
    if (proxy) {
      const self = this;
      const clients: Record<string, ClientFacts> = {};
      const routes = proxy.routes.map(function (route) {
        const one = self.resolveRoute(route, proxy);
        if (!one.resolved.usable) {
          log.warn(errorCodes.tag(String(one.resolved.code)) + 'xacml: ' +
                   'remote PEP "' + (row ? row.name : name) + '" route "' +
                   route.id + '" is not usable: ' + one.resolved.why);
        }
        if (one.client && one.resolved.clientId) {
          clients[one.resolved.clientId] = one.client;
        }
        return Object.assign({}, route, { resolved: one.resolved });
      });
      sent.proxy = Object.assign({}, proxy, { routes: routes });
      sent.realm = this.realmFacts(base, clients);
      sent.validation = this.validationUrls(base);
    } else {
      sent.note = note;
    }
    const token = require('../common/crypto')
      .digest('sha256', JSON.stringify(sent), 'base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    log.debug("Leaving PepProxy.pull(). configured=" + !!proxy);
    return { token: token,
             body: Object.assign({ syncToken: token }, sent) };
  }

  /**
   * The realm facts the proxy validates locally with.
   * @param base - the realm's base URL
   * @param clients - the session routes' clients, by client id
   * @returns the `realm` member of the pull
   */
  realmFacts(base: string,
             clients: Record<string, ClientFacts>): Record<string, unknown> {
    const { log } = this.deps;
    log.debug("Entering PepProxy.realmFacts().");
    const oauth2 = this.deps.loadOauth2();
    const at = this.deps.rebase(base, 'oauth-oidc');
    const issuer = oauth2.issuerOf(at);
    const facts = {
      issuer: issuer,
      jwksUri: at + '/oauth2/jwks',
      authorizationEndpoint: at + '/oauth2/authorize',
      tokenEndpoint: at + '/oauth2/token',
      endSessionEndpoint: at + '/oauth2/logout',
      // The SAML entityID is the realm's one issuer (#523).
      samlIssuer: issuer,
      signingCertificates: this.deps.xmlSigningCertificates(),
      // The listener's chain, leaf to Root, for the relying party's TLS.
      tlsCaChain: this.deps.listenerChainPem(),
      clients: clients
    };
    log.debug("Leaving PepProxy.realmFacts().");
    return facts;
  }

  /**
   * The four validation doors' absolute URLs in this realm.
   * @param base - the realm's base URL
   * @returns the `validation` member of the pull
   */
  validationUrls(base: string): Record<string, string> {
    const { log } = this.deps;
    log.debug("Entering PepProxy.validationUrls().");
    const at = String(base || '');
    log.debug("Leaving PepProxy.validationUrls().");
    return {
      introspect: at + '/xacml/pep/introspect',
      basic: at + '/xacml/pep/basic',
      saml: at + '/xacml/pep/saml',
      session: at + '/xacml/pep/session',
      identity: at + '/xacml/pep/identity'
    };
  }

  // =========================================================================
  // THE FOUR VALIDATION DOORS (D4).
  // =========================================================================

  // A body member that must be a non-empty string of at most `max`.
  private member(body: any, key: string, max: number): string {
    const { log } = this.deps;
    log.debug("Entering PepProxy.member(). " + key);
    const value = body ? body[key] : undefined;
    const out = typeof value === 'string' && value && value.length <= max &&
      !/[\u0000]/.test(value) ? value : '';
    log.debug("Leaving PepProxy.member(). " + (out ? 'present' : 'absent'));
    return out;
  }

  /**
   * HTTP Basic, never validated in the PEP: the person's password through
   * `credentials.verifyAsync()` behind the sign-in's door limits.
   *
   * @param req - the request, for the address bucket
   * @param body - `{ username, password }`
   * @returns the status and the closed answer `{ valid, sub?, username? }`
   */
  async basic(req: any, body: any, pep?: string): Promise<DoorAnswer> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PepProxy.basic().");
    const username = this.member(body, 'username', 256);
    const password = typeof (body || {}).password === 'string' &&
      body.password.length <= 1024 ? body.password : null;
    if (!username || password === null) {
      log.debug("Leaving PepProxy.basic(). Malformed.");
      return { status: 400, code: 'STS-XACML-0204',
               body: { error: 'invalid_request',
                       error_description: 'A Basic validation is ' +
                         '{ "username", "password" }: two strings, the ' +
                         'username non-empty and at most 256 characters, ' +
                         'the password at most 1024.' } };
    }
    const websecurity = this.deps.loadWebsecurity();
    const blocked = websecurity.doorBlocked('xacml-pep-basic', req, username);
    if (blocked) {
      log.debug("Leaving PepProxy.basic(). Blocked.");
      return { status: 429, code: 'STS-XACML-0205', actor: username,
               reason: 'too many failed attempts',
               body: { valid: false,
                       retryAfterS: Number(blocked.retryAfterS) || 1 } };
    }
    const checked = await this.deps.loadCredentials().verifyAsync(
      username, password,
      { via: 'a remote PEP\'s HTTP Basic', door: 'xacml-pep' });
    if (!checked || !checked.ok) {
      websecurity.doorFailed('xacml-pep-basic', req, username);
      log.debug("Leaving PepProxy.basic(). Refused.");
      // ONE ANSWER FOR EVERY REFUSAL: no such person, a wrong password, a
      // disabled account and a second factor owed are told apart in the log
      // and the audit row only.
      return { status: 200, actor: username,
               code: errorCodes.codeOf(checked) || 'STS-XACML-0206',
               reason: String((checked && checked.reason) || 'refused'),
               body: { valid: false } };
    }
    websecurity.doorSucceeded('xacml-pep-basic', req, username);
    const sub = this.deps.subjectForName(username);
    log.debug("Leaving PepProxy.basic(). Valid.");
    const answer: Record<string, unknown> = { valid: true,
                                              username: username };
    if (sub) {
      answer.sub = sub;
    }
    answer.ticket = this.issueTicket(String(pep || ''), username, sub);
    return { status: 200, actor: username, reason: 'valid', body: answer };
  }

  /**
   * RFC 7662 introspection for the PEP: the authorization server's own
   * reading of the token.
   *
   * @param body - `{ token }`
   * @returns the status and the RFC 7662 answer
   */
  introspect(body: any): DoorAnswer {
    const { log } = this.deps;
    log.debug("Entering PepProxy.introspect().");
    const token = this.member(body, 'token', 16384);
    if (!token) {
      log.debug("Leaving PepProxy.introspect(). Malformed.");
      return { status: 400, code: 'STS-XACML-0207',
               body: { error: 'invalid_request',
                       error_description: 'An introspection is { "token" ' +
                         '}: one non-empty string of at most 16384 ' +
                         'characters.' } };
    }
    const read = this.deps.loadOauth2().introspectionFor(token) || {};
    if (read.active !== true) {
      log.debug("Leaving PepProxy.introspect(). Inactive.");
      return { status: 200, reason: 'inactive', body: { active: false } };
    }
    // THE CLOSED SET D4 NAMES, copied member by member so nothing the
    // authorization server's answer grows later reaches the PEP by accident.
    const answer: Record<string, unknown> = { active: true };
    ['sub', 'username', 'scope', 'client_id', 'aud', 'iss', 'exp', 'iat',
     'token_type', 'cnf'].forEach(function (key) {
      if (read[key] !== undefined && read[key] !== null) {
        answer[key] = read[key];
      }
    });
    log.debug("Leaving PepProxy.introspect(). Active.");
    return { status: 200, actor: String(read.username || read.sub || ''),
             reason: 'active', body: answer };
  }

  // The direct children of `parent` in the assertion namespace named `local`.
  private children(parent: any, local: string, ns: string): any[] {
    const { log } = this.deps;
    log.debug("Entering PepProxy.children(). " + local);
    const out: any[] = [];
    const nodes = parent ? parent.childNodes : null;
    for (let i = 0; nodes && i < nodes.length; i++) {
      const one = nodes[i];
      if (one.nodeType === 1 && one.localName === local &&
          one.namespaceURI === ns) {
        out.push(one);
      }
    }
    log.debug("Leaving PepProxy.children(). " + out.length);
    return out;
  }

  // The text of an element, trimmed.
  private textOfNode(node: any): string {
    const { log } = this.deps;
    log.debug("Entering PepProxy.textOfNode().");
    log.debug("Leaving PepProxy.textOfNode().");
    return node ? String(node.textContent || '').trim() : '';
  }

  // A SAML refusal: valid false, the reason in the log and the audit row.
  private samlRefusal(code: string, reason: string): DoorAnswer {
    const { log } = this.deps;
    log.debug("Entering PepProxy.samlRefusal(). " + code);
    log.debug("Leaving PepProxy.samlRefusal().");
    return { status: 200, code: code, reason: reason,
             body: { valid: false } };
  }

  /**
   * Verifies a SAML 2.0 assertion this realm issued: the enveloped
   * signature on the root assertion, the issuer, the conditions and the
   * audience. An encrypted assertion is refused by name.
   *
   * @param body - `{ assertion, audience }`, the assertion base64
   * @param base - the realm's base URL, whose issuer the assertion must name
   * @returns the status and `{ valid, subject, username, issuer,
   *   notOnOrAfter, sessionIndex }`
   */
  saml(body: any, base: string): DoorAnswer {
    const { log, config } = this.deps;
    log.debug("Entering PepProxy.saml().");
    const encoded = this.member(body, 'assertion', SAML_MAX_BYTES * 2);
    const audience = this.member(body, 'audience', TEXT_MAX);
    if (!encoded || !audience || !/^[A-Za-z0-9+/=\s]+$/.test(encoded)) {
      log.debug("Leaving PepProxy.saml(). Malformed.");
      return { status: 400, code: 'STS-XACML-0208',
               body: { error: 'invalid_request',
                       error_description: 'A SAML validation is { ' +
                         '"assertion", "audience" }: the assertion the ' +
                         'base64 of its XML, the audience the route\'s.' } };
    }
    const xml = Buffer.from(encoded.replace(/\s+/g, ''), 'base64')
      .toString('utf8');
    if (!xml || xml.length > SAML_MAX_BYTES) {
      log.debug("Leaving PepProxy.saml(). Size.");
      return { status: 400, code: 'STS-XACML-0208',
               body: { error: 'invalid_request',
                       error_description: 'The assertion is empty or ' +
                         'larger than ' + SAML_MAX_BYTES + ' bytes.' } };
    }
    let doc: any = null;
    try {
      doc = this.deps.parseXml(xml);
    } catch (e) {
      log.debug("Caught in PepProxy.saml(): " + ((e && e.message) || e));
      doc = null;
    }
    const root = doc && doc.documentElement;
    if (!root) {
      log.debug("Leaving PepProxy.saml(). Not XML.");
      return this.samlRefusal('STS-XACML-0208', 'not XML');
    }
    if (root.localName === 'EncryptedAssertion') {
      log.debug("Leaving PepProxy.saml(). Encrypted.");
      return this.samlRefusal('STS-XACML-0209', 'an EncryptedAssertion, ' +
        'which neither the PEP nor this service holds the service ' +
        'provider\'s key to');
    }
    if (root.localName !== 'Assertion' ||
        root.namespaceURI !== SAML2_ASSERTION) {
      log.debug("Leaving PepProxy.saml(). Not an assertion.");
      return this.samlRefusal('STS-XACML-0208', 'the root element is not ' +
        'a SAML 2.0 Assertion');
    }
    // THE SIGNATURE IS THE ROOT'S OWN, and its reference names the root's
    // ID: `verifyXmlSignature()` is told the element, and this refuses a
    // document whose root carries none — the verifier would otherwise find a
    // signed Assertion nested deeper, which is signature wrapping.
    const id = String(root.getAttribute('ID') || '');
    const signature = this.children(root, 'Signature', XMLDSIG)[0];
    if (!signature || !id) {
      log.debug("Leaving PepProxy.saml(). Unsigned.");
      return this.samlRefusal('STS-XACML-0210', 'the assertion is not ' +
        'signed at its root');
    }
    const certificates = this.deps.xmlSigningCertificates();
    let verified = false;
    for (let i = 0; i < certificates.length && !verified; i++) {
      const verdict = this.deps.verifyXmlSignature(xml, {
        element: 'Assertion', certPem: certificates[i] });
      verified = !!verdict && verdict.ok === true &&
        String(verdict.referenceUri || '') === '#' + id;
    }
    if (!verified) {
      log.debug("Leaving PepProxy.saml(). Signature.");
      return this.samlRefusal('STS-XACML-0210', 'the signature does not ' +
        'verify against this realm\'s XML signing certificates');
    }
    const issuer = this.textOfNode(this.children(root, 'Issuer',
                                                 SAML2_ASSERTION)[0]);
    const expected = this.deps.loadOauth2().issuerOf(
      this.deps.rebase(String(base || ''), 'oauth-oidc'));
    if (!issuer || issuer !== expected) {
      log.debug("Leaving PepProxy.saml(). Issuer.");
      return this.samlRefusal('STS-XACML-0211', 'the issuer "' + issuer +
        '" is not this realm\'s ("' + expected + '")');
    }
    const conditions = this.children(root, 'Conditions', SAML2_ASSERTION)[0];
    const skewMs = Math.max(0, Number(config.value('oauth2.clockSkewS')) ||
                               0) * 1000;
    const now = this.deps.now();
    const notBefore = conditions
      ? Date.parse(String(conditions.getAttribute('NotBefore') || '')) : NaN;
    const notOnOrAfterText = conditions
      ? String(conditions.getAttribute('NotOnOrAfter') || '') : '';
    const notOnOrAfter = Date.parse(notOnOrAfterText);
    if (!conditions || isNaN(notOnOrAfter) ||
        now >= notOnOrAfter + skewMs ||
        (!isNaN(notBefore) && now + skewMs < notBefore)) {
      log.debug("Leaving PepProxy.saml(). Time.");
      return this.samlRefusal('STS-XACML-0212', 'the assertion is outside ' +
        'its Conditions (NotBefore / NotOnOrAfter, with ' +
        'oauth2.clockSkewS), or names no NotOnOrAfter');
    }
    const self = this;
    const restrictions = this.children(conditions, 'AudienceRestriction',
                                       SAML2_ASSERTION);
    const audiences: string[] = [];
    restrictions.forEach(function (one) {
      self.children(one, 'Audience', SAML2_ASSERTION).forEach(function (a) {
        audiences.push(self.textOfNode(a));
      });
    });
    // Every AudienceRestriction must hold the audience (SAML core 2.5.1.4:
    // each restriction is a separate condition).
    const meets = restrictions.length > 0 &&
      restrictions.every(function (one) {
        return self.children(one, 'Audience', SAML2_ASSERTION)
          .some(function (a) {
            return self.textOfNode(a) === audience;
          });
      });
    if (!meets) {
      log.debug("Leaving PepProxy.saml(). Audience.");
      return this.samlRefusal('STS-XACML-0213', 'the assertion is not for ' +
        'the audience "' + audience + '" (it names ' +
        (audiences.join(', ') || 'none') + ')');
    }
    const subject = this.children(root, 'Subject', SAML2_ASSERTION)[0];
    const nameId = this.textOfNode(this.children(subject, 'NameID',
                                                 SAML2_ASSERTION)[0]);
    const statement = this.children(root, 'AuthnStatement',
                                    SAML2_ASSERTION)[0];
    const sessionIndex = statement
      ? String(statement.getAttribute('SessionIndex') || '') : '';
    const username = this.usernameOf(root) || nameId;
    log.debug("Leaving PepProxy.saml(). Valid.");
    return { status: 200, actor: username, reason: 'valid',
             body: { valid: true, subject: nameId, username: username,
                     issuer: issuer, notOnOrAfter: notOnOrAfterText,
                     sessionIndex: sessionIndex } };
  }

  // The person's username from the assertion's uid attribute (the X.500/LDAP
  // attribute profile's name this service sends), or ''.
  private usernameOf(root: any): string {
    const { log } = this.deps;
    log.debug("Entering PepProxy.usernameOf().");
    const self = this;
    let out = '';
    this.children(root, 'AttributeStatement', SAML2_ASSERTION)
      .forEach(function (statement) {
        self.children(statement, 'Attribute', SAML2_ASSERTION)
          .forEach(function (attribute) {
            const name = String(attribute.getAttribute('Name') || '');
            if (!out && (name === 'urn:oid:0.9.2342.19200300.100.1.1' ||
                         name === 'uid')) {
              out = self.textOfNode(self.children(attribute,
                'AttributeValue', SAML2_ASSERTION)[0]);
            }
          });
      });
    log.debug("Leaving PepProxy.usernameOf(). " + (out || 'none'));
    return out;
  }

  // A Basic ticket (D11), kept under its digest, bound to the PEP and the
  // subject. The store is bounded at the insert, the expired first.
  private issueTicket(pep: string, username: string, sub: string): string {
    const { log, tickets, randomToken, digest, now } = this.deps;
    log.debug("Entering PepProxy.issueTicket(). pep=" + pep);
    const nowMs = now();
    cacheRegistry.makeRoom(tickets, MAX_TICKETS, {
      expired: function (row: any): boolean {
        return !(Number(row && row.exp) * 1000 > nowMs);
      }
    });
    const ticket = randomToken();
    tickets.set(digest(ticket), {
      pep: pep, username: username, sub: sub, mechanism: 'basic',
      amr: ['pwd'], at: Math.floor(nowMs / 1000),
      exp: Math.floor(nowMs / 1000) + TICKET_LIFETIME_S
    });
    log.debug("Leaving PepProxy.issueTicket().");
    return ticket;
  }

  // An identity door's refusal: the status, the code and a sentence, the
  // body closed.
  private identityRefusal(status: number, code: string, error: string,
                          why: string, actor?: string): DoorAnswer {
    const { log } = this.deps;
    log.debug("Entering PepProxy.identityRefusal(). " + code);
    log.debug("Leaving PepProxy.identityRefusal().");
    return { status: status, code: code, reason: why, actor: actor,
             body: { error: error, error_description: why } };
  }

  // WHO THE EVIDENCE IS ABOUT, validated again here (D11): an access token
  // this realm issued and addressed to the route's application, a SAML
  // assertion this realm issued for the application, or a Basic ticket
  // handed to THIS PEP and not expired. A refusal is a DoorAnswer.
  private async subjectOf(evidence: any, pep: string, route: ProxyRoute,
                          resolved: Resolution, base: string,
                          entryFields: Record<string, unknown>)
      : Promise<any> {
    const { log, tickets, digest, now } = this.deps;
    log.debug("Entering PepProxy.subjectOf(). " + evidence.kind);
    const values = function (name: string): string[] {
      log.debug("Entering values(). " + name);
      log.debug("Leaving values().");
      const raw = entryFields[name];
      return (Array.isArray(raw) ? raw : (raw ? [raw] : []))
        .map(function (one: unknown) {
          return String(one).trim();
        }).filter(function (one: string) {
          return !!one;
        });
    };
    if (evidence.kind === 'ticket') {
      const row = tickets.get(digest(evidence.value));
      if (!row || String(row.pep || '') !== pep ||
          !(Number(row.exp) * 1000 > now())) {
        log.debug("Leaving PepProxy.subjectOf(). Ticket refused.");
        return this.identityRefusal(403, 'STS-XACML-0232', 'access_denied',
          'The ticket is not one this service handed this PEP, or it has ' +
          'expired (' + TICKET_LIFETIME_S + ' s): validate the Basic ' +
          'credential again.');
      }
      log.debug("Leaving PepProxy.subjectOf(). Ticket.");
      return { username: String(row.username || ''),
               sub: String(row.sub || ''), mechanism: 'basic',
               amr: ['pwd'], acr: '', authTime: Number(row.at) || 0 };
    }
    if (evidence.kind === 'access_token') {
      const read = this.deps.loadOauth2().introspectionFor(evidence.value) ||
        {};
      const audiences = values('oauthAudience')
        .concat(values('oauthPermissionBaseUri'));
      const aud = Array.isArray(read.aud) ? read.aud.map(String)
        : (read.aud ? [String(read.aud)] : []);
      const clientId = values('oauthClientId')[0] || route.application;
      const forThisApplication = String(read.client_id || '') === clientId ||
        aud.some(function (one: string) {
          return audiences.indexOf(one) >= 0;
        });
      if (read.active !== true || !read.username || !forThisApplication) {
        log.debug("Leaving PepProxy.subjectOf(). Token refused.");
        return this.identityRefusal(403, 'STS-XACML-0231', 'access_denied',
          read.active !== true
            ? 'The access token is not an active token of this realm.'
            : (!read.username
              ? 'The access token is about no person.'
              : 'The access token was issued neither to nor for the ' +
                'route\'s application "' + route.application + '".'));
      }
      log.debug("Leaving PepProxy.subjectOf(). Token.");
      return { username: String(read.username), sub: String(read.sub || ''),
               mechanism: String(read.client_id || '') === clientId &&
                 route.mechanisms.indexOf('session') >= 0
                 ? 'session' : 'oauth2',
               amr: [], acr: '', authTime: Number(read.iat) || 0 };
    }
    // A SAML assertion, held to `saml()`'s rules with the application's own
    // entity ID as the audience.
    const audience = values('samlEntityId')[0] || '';
    if (!audience) {
      log.debug("Leaving PepProxy.subjectOf(). No entity ID.");
      return this.identityRefusal(422, 'STS-XACML-0233',
        'invalid_request', 'The route\'s application "' +
        route.application + '" has no SAML entity ID (samlEntityId), so no ' +
        'assertion is addressed to it.');
    }
    const checked = this.saml({ assertion: evidence.value,
                                audience: audience }, base);
    if (checked.status !== 200 || !checked.body ||
        checked.body.valid !== true) {
      log.debug("Leaving PepProxy.subjectOf(). Assertion refused.");
      return this.identityRefusal(403, 'STS-XACML-0231', 'access_denied',
        'The SAML assertion does not validate: ' +
        String(checked.reason || 'refused') + '.');
    }
    log.debug("Leaving PepProxy.subjectOf(). Assertion.");
    return { username: String(checked.body.username || ''),
             sub: this.deps.subjectForName(String(checked.body.username ||
                                                  '')),
             mechanism: 'saml2', amr: [], acr: '',
             authTime: Math.floor(now() / 1000) };
  }

  // The claims a headers-mode route forwards, from the directory entry and
  // the evidence. A claim with no value is left out; `groups` is a list.
  private claimsFor(subject: any, wanted: string[]): Record<string, unknown> {
    const { log } = this.deps;
    log.debug("Entering PepProxy.claimsFor().");
    const person = this.deps.personOf(subject.username) || {};
    const out: Record<string, unknown> = {};
    const self = this;
    wanted.forEach(function (claim) {
      let value: unknown;
      if (claim === 'sub') {
        value = subject.sub || person.sub;
      } else if (claim === 'username') {
        value = person.username || subject.username;
      } else if (claim === 'groups') {
        value = self.deps.groupsOf(subject.username);
      } else if (claim === 'mechanism') {
        value = subject.mechanism;
      } else if (claim === 'acr') {
        value = subject.acr;
      } else if (claim === 'amr') {
        value = subject.amr && subject.amr.length ? subject.amr : undefined;
      } else {
        value = person[claim];
      }
      if (Array.isArray(value)) {
        out[claim] = value.map(String);
      } else if (value !== undefined && value !== null &&
                 String(value) !== '') {
        out[claim] = String(value);
      }
    });
    log.debug("Leaving PepProxy.claimsFor(). " + Object.keys(out).length);
    return out;
  }

  // A session-shaped record the SAML builder reads: the person, the
  // instant, how they authenticated. Never stored.
  private sessionFor(subject: any): any {
    const { log, digest } = this.deps;
    log.debug("Entering PepProxy.sessionFor().");
    const user = Object.assign({}, helpers.userFor(subject.username));
    log.debug("Leaving PepProxy.sessionFor().");
    return {
      id: 'pep-' + digest(subject.username + '|' +
                          String(subject.authTime)).slice(0, 24),
      user: user, authenticated: true,
      authTime: subject.authTime || Math.floor(this.deps.now() / 1000),
      amr: subject.amr || [], acr: subject.acr || '',
      via: subject.mechanism
    };
  }

  /**
   * `POST /xacml/pep/identity` (#1760, D11): what one of this PEP's routes
   * forwards to its application about the caller its evidence names.
   *
   * @param body - `{ route, evidence: { kind, value }, claims? }`
   * @param pep - the PEP's name, from its certificate
   * @param row - the PEP's register row, or null
   * @param base - the request's base URL
   * @returns the status and the closed answer: `{ claims }` for mode
   *   headers, `{ accessToken, tokenType, expiresIn }` for jwt,
   *   `{ samlResponse, acsUrl, notOnOrAfter }` for saml
   */
  async identity(body: any, pep: string,
                 row: { name: string; proxy: string } | null,
                 base: string): Promise<DoorAnswer> {
    const { log } = this.deps;
    log.debug("Entering PepProxy.identity(). pep=" + pep);
    const routeId = this.member(body, 'route', 64);
    const evidence = body && typeof body === 'object' ? body.evidence : null;
    const kinds = ['access_token', 'saml_assertion', 'ticket'];
    const stray = body && typeof body === 'object' && !Array.isArray(body)
      ? this.strayMember(body, ['route', 'evidence', 'claims', 'name'])
      : 'body';
    if (stray || !routeId || !evidence || typeof evidence !== 'object' ||
        Array.isArray(evidence) ||
        this.strayMember(evidence, ['kind', 'value']) ||
        kinds.indexOf(String(evidence.kind)) < 0 ||
        typeof evidence.value !== 'string' || !evidence.value ||
        evidence.value.length > SAML_MAX_BYTES * 2 ||
        (body.claims !== undefined &&
         (!Array.isArray(body.claims) || body.claims.length > 16 ||
          body.claims.some(function (one: unknown) {
            return IDENTITY_CLAIMS.indexOf(String(one)) < 0;
          })))) {
      log.debug("Leaving PepProxy.identity(). Malformed.");
      return this.identityRefusal(400, 'STS-XACML-0229', 'invalid_request',
        'An identity request is { "route", "evidence": { "kind", "value" }, ' +
        '"claims"? }: the kind one of ' + kinds.join(', ') + ', claims a ' +
        'list of ' + IDENTITY_CLAIMS.join(', ') + '.');
    }
    const checked = row && row.proxy ? this.validate(row.proxy) : null;
    const proxy = checked && checked.ok ? checked.proxy : null;
    const route = proxy ? proxy.routes.filter(function (one) {
      return one.id === routeId;
    })[0] : null;
    if (!proxy || !route || route.public) {
      log.debug("Leaving PepProxy.identity(). Not this PEP's route.");
      return this.identityRefusal(403, 'STS-XACML-0230', 'access_denied',
        'Route "' + routeId + '" is not a non-public route of this PEP\'s ' +
        'proxy configuration.');
    }
    const one = this.resolveRoute(route, proxy);
    if (!one.resolved.usable) {
      log.debug("Leaving PepProxy.identity(). Route unusable.");
      return this.identityRefusal(422, 'STS-XACML-0233', 'invalid_request',
        'Route "' + routeId + '" is not usable: ' + one.resolved.why);
    }
    const entry = this.deps.loadApplications().get(route.application) || {};
    const fields = entry.fields || {};
    const subject = await this.subjectOf(evidence, pep, route,
                                         one.resolved, base, fields);
    if (subject && subject.status) {
      log.debug("Leaving PepProxy.identity(). Evidence refused.");
      return subject as DoorAnswer;
    }
    const how = route.identity.mode;
    const headerClaims = route.identity.headers.map(function (h) {
      return h.claim;
    });
    if (body.claims !== undefined &&
        (how !== 'headers' || body.claims.some(function (c: string) {
          return headerClaims.indexOf(c) < 0;
        }))) {
      log.debug("Leaving PepProxy.identity(). Claims not the route's.");
      return this.identityRefusal(400, 'STS-XACML-0229', 'invalid_request',
        '`claims` narrows a headers route to claims its headers name (' +
        (headerClaims.join(', ') || 'none') + ').', subject.username);
    }
    if (how === 'headers') {
      const wanted = body.claims !== undefined ? body.claims : headerClaims;
      log.debug("Leaving PepProxy.identity(). Claims.");
      return { status: 200, actor: subject.username,
               reason: 'claims for route ' + routeId + ' by ' +
                 subject.mechanism,
               body: { claims: this.claimsFor(subject, wanted) } };
    }
    if (!subject.sub) {
      log.debug("Leaving PepProxy.identity(). Nobody in the directory.");
      return this.identityRefusal(422, 'STS-XACML-0233', 'invalid_request',
        'The directory holds no entry for the person the evidence names, ' +
        'so nothing is issued about them.', subject.username);
    }
    if (how === 'jwt') {
      return this.issueToken(subject, route, one.resolved, fields, base);
    }
    const values = function (name: string): string {
      log.debug("Entering values(). " + name);
      log.debug("Leaving values().");
      const raw = fields[name];
      return String((Array.isArray(raw) ? raw[0] : raw) || '').trim();
    };
    const acsUrl = values('samlAssertionConsumerService');
    const built = this.deps.loadSaml2Sso().pepProxyResponse({
      session: this.sessionFor(subject),
      spEntityId: values('samlEntityId'), acsUrl: acsUrl
    }) || {};
    if (!built.ok) {
      log.debug("Leaving PepProxy.identity(). No Response.");
      return built.policy
        ? this.identityRefusal(403, 'STS-XACML-0234', 'access_denied',
            'The issuance policy refused an assertion for this person: ' +
            String(built.why || ''), subject.username)
        : this.identityRefusal(422, 'STS-XACML-0235', 'invalid_request',
            'No assertion could be issued: ' + String(built.why || ''),
            subject.username);
    }
    log.debug("Leaving PepProxy.identity(). A SAML Response.");
    return { status: 200, actor: subject.username,
             reason: 'issued a SAML Response for route ' + routeId,
             body: { samlResponse: Buffer.from(String(built.xml), 'utf8')
                       .toString('base64'),
                     acsUrl: acsUrl,
                     notOnOrAfter: String(built.notOnOrAfter || '') } };
  }

  // Mode jwt: an access token about the person, for the route's
  // application, through the service's own issuance — the issuance policy
  // first, then `accessTokenAsync()` (recorded in the token register).
  private async issueToken(subject: any, route: ProxyRoute,
                           resolved: Resolution,
                           fields: Record<string, unknown>,
                           base: string): Promise<DoorAnswer> {
    const { log } = this.deps;
    log.debug("Entering PepProxy.issueToken().");
    const raw = fields.oauthClientId;
    const clientId = String((Array.isArray(raw) ? raw[0] : raw) ||
                            route.application);
    const audiences: string[] = [];
    ['oauthAudience', 'oauthPermissionBaseUri'].forEach(function (name) {
      const v = fields[name];
      (Array.isArray(v) ? v : (v ? [v] : [])).forEach(function (one) {
        const text = String(one).trim();
        if (text && audiences.indexOf(text) < 0) {
          audiences.push(text);
        }
      });
    });
    const gate = this.deps.loadGate();
    const user = helpers.userFor(subject.username);
    const answer = gate.check({
      application: clientId,
      kind: gate.ISSUANCE.ACCESS_TOKEN,
      client: clientId,
      grantType: 'urn:sts:xacml-pep:identity',
      subject: { kind: 'user', name: String(user.username || ''),
                 authenticated: true },
      claims: null,
      session: this.sessionFor(subject)
    }) || {};
    if (!answer.allowed) {
      log.debug("Leaving PepProxy.issueToken(). Refused by policy.");
      return this.identityRefusal(403, 'STS-XACML-0234', 'access_denied',
        'The issuance policy refused an access token for this person: ' +
        String(answer.why || ''), subject.username);
    }
    const oauth2 = this.deps.loadOauth2();
    let token = '';
    try {
      token = String(await oauth2.accessTokenAsync(
        this.deps.rebase(base, 'oauth-oidc'), {
          user: user, client_id: clientId, grant: 'xacml-pep',
          audience: audiences.length === 1 ? audiences[0] : audiences,
          auth_time: subject.authTime || undefined,
          amr: subject.amr && subject.amr.length ? subject.amr : undefined
        }) || '');
    } catch (e) {
      log.debug("Caught in PepProxy.issueToken(): " +
                ((e && e.message) || e));
      log.debug("Leaving PepProxy.issueToken(). Not issued.");
      return this.identityRefusal(422, 'STS-XACML-0235', 'invalid_request',
        'No access token could be issued: ' + ((e && e.message) || e),
        subject.username);
    }
    const read = oauth2.introspectionFor(token) || {};
    const nowS = Math.floor(this.deps.now() / 1000);
    log.debug("Leaving PepProxy.issueToken(). Issued.");
    return { status: 200, actor: subject.username,
             reason: 'issued an access token for route ' + route.id,
             body: { accessToken: token, tokenType: 'Bearer',
                     expiresIn: Math.max(0, (Number(read.exp) || nowS) -
                                            nowS) } };
  }

  /**
   * Whether the sign-on session an ID Token's `sid` names is still live.
   *
   * @param body - `{ sid }`
   * @returns the status and `{ live, sub?, username? }`
   */
  async session(body: any): Promise<DoorAnswer> {
    const { log } = this.deps;
    log.debug("Entering PepProxy.session().");
    const sid = this.member(body, 'sid', 512);
    if (!sid) {
      log.debug("Leaving PepProxy.session(). Malformed.");
      return { status: 400, code: 'STS-XACML-0214',
               body: { error: 'invalid_request',
                       error_description: 'A session check is { "sid" }: ' +
                         'the sid of the ID Token the proxy signed the ' +
                         'person in with.' } };
    }
    const authn = this.deps.loadAuthn();
    try {
      await authn.warmSessionAsync(sid);
    } catch (e) {
      // A warm that fails holds nothing; the synchronous read below answers.
      log.debug("Caught in PepProxy.session(): " + ((e && e.message) || e));
    }
    const live = this.deps.loadOauth2().sessionIsLive(sid);
    if (!live) {
      log.debug("Leaving PepProxy.session(). Not live.");
      return { status: 200, reason: 'ended', body: { live: false } };
    }
    const held = authn.sessionById(sid) || {};
    const user = held.user || {};
    const answer: Record<string, unknown> = { live: true };
    if (user.sub) {
      answer.sub = String(user.sub);
    }
    if (user.username) {
      answer.username = String(user.username);
    }
    log.debug("Leaving PepProxy.session(). Live.");
    return { status: 200, actor: String(user.username || ''),
             reason: 'live', body: answer };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), and a default one
// where nothing runs the root.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PepProxy>(
  'xacml/xacml_pep_proxy',
  () => new PepProxy(PepProxy.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The remote PEP's reverse proxy, the service's half (#1760).
 * @namespace
 */
export = {
  PepProxy: PepProxy,
  installInstance: (instance: PepProxy): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  METHODS: PepProxy.METHODS,
  MECHANISMS: PepProxy.MECHANISMS,
  CALLBACK_PATH: PepProxy.CALLBACK_PATH,
  validate: slot.forward('validate'),
  usesSession: slot.forward('usesSession'),
  resolveRoute: slot.forward('resolveRoute'),
  resolutionProblem: slot.forward('resolutionProblem'),
  routesFronting: slot.forward('routesFronting'),
  pull: slot.forward('pull'),
  realmFacts: slot.forward('realmFacts'),
  validationUrls: slot.forward('validationUrls'),
  basic: slot.forward('basic'),
  introspect: slot.forward('introspect'),
  saml: slot.forward('saml'),
  session: slot.forward('session'),
  identity: slot.forward('identity'),
  TICKET_LIFETIME_S: TICKET_LIFETIME_S
};
