'use strict';
//
// File: request_object.ts
//
// ===========================================================================
// RFC 9101 — THE JWT-SECURED AUTHORIZATION REQUEST (JAR), AND OPENID CONNECT
// CORE SECTION 6's REQUEST OBJECT (2026-09-13).
//
// An authorization request is a list of query parameters anybody on the path
// can read and change. RFC 9101 lets a client put those parameters in a JWT it
// SIGNS — and may encrypt — and send it instead:
//
//   GET /oauth2/authorize?client_id=app1&request=eyJ...            (by value)
//   GET /oauth2/authorize?client_id=app1&request_uri=https://...   (by reference)
//
// This file turns either into the parameters the authorization endpoint then
// runs on, and refuses everything RFC 9101 says to refuse. `oauth2.ts`'s
// `authorizeEndpoint()` calls `resolve()` before it reads anything else, and
// answers a refusal ON THIS SERVER as a 400 — never by redirecting — for the
// reason that endpoint's shape check gives: the redirect_uri is INSIDE the
// request object, and one not yet verified is not an address to send an error
// to.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS WERE ASKED OF RCBJ BEFORE THIS WAS BUILT, AND EACH TOOK THE
// RECOMMENDED ANSWER. They are the design:
//
//   1. A request_uri IS FETCHED ONLY WHEN THE CLIENT REGISTERED IT — exactly,
//      `#fragment` removed — in `request_uris` (`oauthRequestUri`). Section 5.2
//      says the server MUST GET it, and section 10.4 is a page on why that is a
//      server-side request forgery waiting to happen; this service's own
//      standing position was never to dial a URL a caller supplied. Both hold
//      at once because a registered request_uri was DECLARED on the client's
//      entry — by an operator, or by a registration — before any request named
//      it. No redirect is followed, the body is capped
//      (`oauth2.requestUriMaxBytes`), the wait is bounded
//      (`oauth2.requestUriTimeoutMs`), and in product mode it must be https and
//      answer `application/oauth-authz-req+jwt` or `application/jwt`
//      (`mode.acceptsLooseRequestUris()`).
//   2. AN UNSIGNED REQUEST OBJECT (`alg: none`) IS ACCEPTED IN DEVELOPMENT AND
//      REFUSED IN PRODUCT (`mode.acceptsUnsignedRequestObjects()`). RFC 9101
//      section 4 allows only signed ones; OpenID Connect Core 6.1 still allows
//      `none`, and many clients send it. Development refuses it too wherever a
//      signed one is REQUIRED — section 10.5's `require_signed_request_object`,
//      from the setting, the client's entry or the authorization server's
//      profile.
//   3. THE `typ` HEADER IS CHECKED FOR A WRONG TYPE, NOT FOR PRESENCE. Absent,
//      `JWT` and `oauth-authz-req+jwt` are accepted; any other explicit type —
//      `at+jwt`, `token-introspection+jwt`, `secevent+jwt` — is refused in
//      every mode. Section 10.8 says requiring the type "will break most
//      existing deployments"; refusing a DIFFERENT type is the cross-JWT
//      confusion defence without that cost.
//   4. ENCRYPTION IS TO A KEY THIS REALM PUBLISHES — an RSA and an EC key in
//      `/oauth2/jwks` marked `use: "enc"`, members of the realm's key set
//      (`helpers.requestObjectKeysFor()`) — or, for the symmetric families, to
//      the client's own secret.
//
// ---------------------------------------------------------------------------
// WHAT IS VERIFIED, IN ORDER, AND WHY THE ORDER.
//
//   * WHICH DOCUMENT: `request` and `request_uri` together are refused;
//     `client_id` is required as a query parameter (section 5), because it is
//     what says whose keys verify the object and whose request_uris may be
//     fetched — reading it out of an unverified object would be choosing the
//     verifier from a document that has not been verified.
//   * WHAT THE AUTHORIZATION SERVER OFFERS: a named authorization server's
//     profile may publish `request_parameter_supported: false`,
//     `request_uri_parameter_supported: false`, `require_signed_request_object`
//     and narrower algorithm lists, and each is enforced
//     (`authorization_servers.ts`).
//   * DECRYPTION (section 6.1), where the object is a five-part JWE, and a
//     client that registered an encryption algorithm must use it.
//   * THE TYPE, then THE SIGNATURE (section 6.2), with the client's registered
//     keys — `assertion_grant.keysForParty()`, the same answer to "which of
//     this party's keys may sign" RFC 7523 uses — or its secret for HMAC, and
//     the registered key's certificate chain and revocation after it verifies,
//     as every other signature from a client is checked here.
//   * THE CLAIMS: `exp` and `nbf` where present; `iss`, where present, is the
//     client; `aud`, where present, names this authorization server; the
//     `client_id` claim, where present, is the query's (section 6.3 "MUST be
//     identical").
//   * ASSEMBLY (section 6.3): "The authorization server MUST only use the
//     parameters in the Request Object, even if the same parameter is provided
//     in the query parameter." So the query is REPLACED, not merged — with two
//     exceptions that are this service's own and carry nothing of the client's:
//     `client_id`, which the section requires be identical, and the round-trip
//     markers the sign-in and consent screens append on the way back
//     (`ROUND_TRIP_FIELDS`).
//
// ---------------------------------------------------------------------------
// THE OPTIONAL HALF, EVERY ITEM OF IT (rcbj: "all optional spec features should
// be implemented").
//
//   * EXPLICIT TYPING REQUIRED (section 10.8's "a good idea for new OAuth
//     deployment profiles") — `oauth2.requireRequestObjectType`, off by
//     default.
//   * `iss` AND `aud` REQUIRED (section 4's SHOULD, enforced) —
//     `oauth2.requireRequestObjectIssuerAudience`, off by default.
//   * THE `kid` (section 6.2): a `kid` in the header MUST name the key used, so
//     one naming no key of this client is refused rather than every key tried.
//   * THE CONSENT SCREEN SAYS THE REQUEST WAS VETTED (section 11.1's SHOULD):
//     `resolve()` answers `alg` and `encrypted`, which `oauth2.ts` hands to the
//     sign-in and consent screens.
//   * A request_uri's CONTENT CACHED, and its FRAGMENT CHECKED (OpenID Connect
//     Core section 6.2: the server MAY cache, and a URI whose content may
//     change SHOULD carry the base64url SHA-256 of the content as its fragment)
//     — `oauth2.requestUriCacheS`, 0 (off) by default; a fragment of 43
//     base64url characters is checked against the content in every mode.
//   * `response_type` DUPLICATED IN THE QUERY MUST MATCH (OpenID Connect Core
//     section 6.1, where section 5 of RFC 9101 lets a client duplicate
//     parameters for backward compatibility) — a different value is refused.
//   * A PUSHED AUTHORIZATION REQUEST'S URN
//     (`urn:ietf:params:oauth:request_uri:`, RFC 9126 via section 5.2) is never
//     fetched: it is resolved by `oauth-oidc/par.ts` where that exists, and
//     `request_uri_not_supported` where it does not.
//
// **A REQUEST OBJECT'S `jti` IS ACCEPTED ONCE (#35, 2026-09-17).** Until
// that day this header said the opposite — "not remembered, so one may be
// replayed within its lifetime" — for two reasons, and neither survived being
// looked at. RFC 9101 does not ASK for it, true; but a signed request object
// is a bearer credential for the request inside it until it expires, which
// is the argument `common/used_assertions.js` makes for an RFC 7523 JWT, and
// this service remembers those. And the authorization endpoint runs every
// request twice — before the sign-in screen and after it — which a
// once-only rule AT THE READ would refuse; so the rule is not at the read.
// It is where `par.ts` put a pushed request_uri's:
//
//   * LOOKED AT on every pass (`lookUp()`, from `resolve()`): a `jti` already
//     spent, or reserved by a response still being written, is refused with
//     invalid_request_object before anybody is asked to sign in. A look that
//     cannot reach the store refuses nothing; the spend below decides.
//   * SPENT where something is issued on the object (`spend()`): by
//     `oauth2.ts`'s `issueAuthorizationResponse()`, below every refusal and
//     beside the pushed request_uri's claim, kept by a redirect or a
//     form_post page and released by a failure; and by the pushed
//     authorization request endpoint just before it keeps a pushed object,
//     kept by the 201. The push IS the object's one use — the URN it answers
//     with resolves to the stored parameters and spends nothing again. A
//     request REFUSED at the endpoint spends nothing, because an object that
//     bought nothing has not been used.
//   * KEPT in the used-assertion history as a third use of a `jwt`, keyed by
//     the client and the `jti`, so it persists in every store that history
//     does and is claimed atomically on postgres. Until `exp` plus
//     `oauth2.clientAssertionSkewS`; without `exp`, for
//     `oauth2.requestObjectJtiRetentionS`, after which a replay is accepted
//     and that setting says so.
//   * SWITCHABLE: `oauth2.requestObjectJtiOnce`, on by default in both modes,
//     restores the old behaviour when off. An object with no `jti` is
//     accepted either way — RFC 9101 does not require one, and there is
//     nothing to remember it by.
//
// **A LIBRARY (rule 3).** It registers no route and requires `common/` modules
// and `assertion_grant.js`, none of which requires it back.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `RequestObject` takes every module it uses through its constructor
// (`RequestObjectDeps`), `par.ts` among them as a LOADER, because that module
// requires this one and is still required only when a pushed request's URN
// arrives. The request_uri cache is still declared at module scope, as
// `realms.map()`, because a store becomes per realm at its declaration. The
// module still exports its old names, for `oauth2.ts`, `par.ts` and the
// tests, which require it by those names — the functions, since R2, FACADES
// over the instance the composition root builds and installs; a process
// without the root builds a default one at load.
// ---------------------------------------------------------------------------

import http = require('http');
import nodeCrypto = require('crypto');
import https = require('https');
import stsCrypto = require('../common/crypto');
import pki = require('../common/pki');
import errorCodes = require('../common/error_codes');
import revocationStatus = require('../common/revocation_status');
import applications = require('../common/applications');
import config = require('../common/config');
import mode = require('../common/mode');
import version = require('../common/version');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import cacheRegistry = require('../common/cache_registry');
// The used-assertion history, where a request object's `jti` is kept (#35).
import usedAssertions = require('../common/used_assertions');
// `keysForParty()`: which of a client's registered keys may verify something it
// signed. One answer for RFC 7523, the software statement and this.
import assertionGrant = require('./assertion_grant');
// FAPI 1.0 Advanced's request-object rules (#139). A leaf.
import fapi = require('./fapi');

// A loose JSON-shaped object: the claims, clients, profiles and results this
// file reads and answers. Their shapes are the libraries' own, and those
// libraries are being typed one at a time (#50).
type Json = any;

// The part of `par.ts` this file calls, when it is there.
interface PushedRequests {
  resolve?(uri: string, clientId: string, context: Json): Promise<Json>;
}

interface RequestObjectDeps {
  http: typeof http;
  nodeCrypto: typeof nodeCrypto;
  https: typeof https;
  stsCrypto: typeof stsCrypto;
  pki: typeof pki;
  errorCodes: typeof errorCodes;
  revocationStatus: typeof revocationStatus;
  applications: typeof applications;
  config: typeof config;
  mode: typeof mode;
  version: typeof version;
  helpers: typeof helpers;
  assertionGrant: typeof assertionGrant;
  usedAssertions: typeof usedAssertions;
  fapi: typeof fapi;
  log: typeof helpers.log;
  // `oauth-oidc/par`, required at the moment a pushed request's URN arrives
  // (see pushedRequest()). It may throw.
  loadPar(): PushedRequests;
}

// Section 4 and section 9.4.1.
const TYP = 'oauth-authz-req+jwt';
const MEDIA_TYPE = 'application/oauth-authz-req+jwt';

// What a registered request_uri may answer with. `application/jwt` beside the
// registered type, because OpenID Connect Core section 6.2 predates the
// registration and a great many request objects are served that way.
const ACCEPTED_MEDIA_TYPES = [MEDIA_TYPE, 'application/jwt'];

// A `typ` that says this is a request object, or says nothing more specific.
const ACCEPTED_TYPES = ['', 'jwt', TYP];

// The JWT claims a request object carries ABOUT ITSELF, which are not
// authorization request parameters and are not handed to the endpoint.
const JWT_CLAIMS = ['iss', 'aud', 'exp', 'iat', 'nbf', 'jti'];

// RFC 9126 section 2.2's URN, which names a pushed request held HERE.
const PAR_URN_PREFIX = 'urn:ietf:params:oauth:request_uri:';

// OpenID Connect Core section 6.2: a request_uri's content, per realm, for
// `oauth2.requestUriCacheS`. Keyed by the WHOLE registered URI, fragment
// included, because the fragment is what names a version of the content. Not
// persisted: it is a copy of something re-fetchable, and a stale copy restored
// after a restart would be the one thing the cache must not hand out.
const requestUriCache = realms.map();

const MAX_CACHED_REQUEST_URIS = 256;

// Described to `/admin/caches` (#74, rule 3ap). Only lookups made while the
// cache is on are counted: with `oauth2.requestUriCacheS` at 0 a fetch is not
// a miss, because nothing was asked of the cache.
const requestUriCount = cacheRegistry.register({
  name: 'oauth2.request-uri',
  title: 'Fetched request objects',
  description: 'The content of a registered RFC 9101 request_uri, kept so a ' +
    'client that sends the same URI again is not fetched again (OpenID ' +
    'Connect Core section 6.2). Off unless oauth2.requestUriCacheS is set.',
  owner: 'oauth-oidc/request_object.ts',
  scope: 'realm',
  settings: ['oauth2.requestUriCacheS'],
  maxEntries: function (): number {
    return MAX_CACHED_REQUEST_URIS;
  },
  bound: 'Enforced: ' + MAX_CACHED_REQUEST_URIS + ' fetched request objects ' +
    'per realm, the oldest dropped and fetched again when next used.',
  lifetime: function (): string {
    const seconds = Number(config.value('oauth2.requestUriCacheS')) || 0;
    return seconds > 0
      ? 'oauth2.requestUriCacheS (' + seconds + ' s) after the fetch, per ' +
        'realm; the oldest goes first when full.'
      : 'Off: oauth2.requestUriCacheS is 0, so nothing is kept.';
  },
  // A fetched Request Object past `until`, which `contentOf()` would fetch
  // again (#49 P5).
  eject: cacheRegistry.realmMapEjector(realms, requestUriCache,
    function (held: Json, key: unknown, now: number): boolean {
      return !(held && Number(held.until) > now);
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmRows(
      realms.list().map(function (r: { id: string }): string {
        return r.id;
      }),
      function (id: string): Map<unknown, unknown> {
        return requestUriCache.realmMap(id);
      },
      function (held: Json, key: unknown): Json {
        return { key: cacheRegistry.clipKey(key), validUntil: held.until };
      });
  }
});

// This service's own round-trip fields, which the sign-in and consent screens
// put in the URL on the way back to the authorization endpoint. They are not
// the client's, so the section 6.3 replacement keeps them from the query.
// `jar_prompt_honoured` is this file's own: the first pass honoured the
// object's `prompt`, and the second must not ask again for ever.
const ROUND_TRIP_FIELDS = ['authn_error', 'authn_error_description',
                           'consent_error', 'consent_error_description',
                           'jar_prompt_honoured'];

// THE KEY A CLIENT SECRET MAKES FOR A SYMMETRIC JWE — OpenID Connect Core
// section 10.2: the leftmost bits of the SHA-2 hash of the secret's octets, as
// many as the algorithm needs, using SHA-256 up to 256 bits, SHA-384 up to 384
// and SHA-512 up to 512. For `dir` the size is the content encryption key's.
// PBES2 is handed the secret itself, because stretching a password is what
// that family is for.
const SYMMETRIC_KEY_BYTES: Record<string, number> = {
  A128KW: 16, A192KW: 24, A256KW: 32,
  A128GCMKW: 16, A192GCMKW: 24, A256GCMKW: 32
};
const DIRECT_KEY_BYTES: Record<string, number> = {
  A128GCM: 16, A192GCM: 24, A256GCM: 32,
  'A128CBC-HS256': 32, 'A192CBC-HS384': 48, 'A256CBC-HS512': 64
};

class RequestObject {
  static readonly TYP = TYP;
  static readonly MEDIA_TYPE = MEDIA_TYPE;
  static readonly PAR_URN_PREFIX = PAR_URN_PREFIX;
  static readonly ROUND_TRIP_FIELDS = ROUND_TRIP_FIELDS;

  constructor(private readonly deps: RequestObjectDeps) {
    deps.log.debug("Entering RequestObject.constructor().");
    deps.log.debug("Leaving RequestObject.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  static defaultDeps(): RequestObjectDeps {
    helpers.log.debug("Entering RequestObject.defaultDeps().");
    helpers.log.debug("Leaving RequestObject.defaultDeps().");
    return {
      http: http,
      nodeCrypto: nodeCrypto,
      https: https,
      stsCrypto: stsCrypto,
      pki: pki,
      errorCodes: errorCodes,
      revocationStatus: revocationStatus,
      applications: applications,
      config: config,
      mode: mode,
      version: version,
      helpers: helpers,
      assertionGrant: assertionGrant,
      usedAssertions: usedAssertions,
      fapi: fapi,
      log: helpers.log,
      // Required LAZILY: `par.ts` requires this module for
      // `verifyObject()`, and a require back at load would close the cycle.
      loadPar: function () {
        return require('./par');
      }
    };
  }

  private skewSeconds(): Json {
    const { config, log } = this.deps;
    log.debug("Entering RequestObject.skewSeconds().");
    log.debug("Leaving RequestObject.skewSeconds().");
    // `assertion_grant.js`'s setting, for its reason: it answers how far out a
    // CLIENT'S clock may be, and a request object is a client's document.
    return config.value('oauth2.clientAssertionSkewS');
  }

  // A refusal: the RFC 9101 section 7 error, the sentence, and the code under
  // the Symbol `mark()` uses.
  private refusal(errorCode: Json, error: Json, description: Json): Json {
    const { errorCodes, log } = this.deps;
    log.debug("Entering RequestObject.refusal(). " + errorCode);
    log.debug("Leaving RequestObject.refusal().");
    return errorCodes.mark({ ok: false, error: error,
                             description: description }, errorCode);
  }

  // Whether a signed request object is REQUIRED for this request: the setting,
  // the client's entry, or the selected authorization server's profile.
  signedRequired(client: Json, profile: Json): Json {
    const { config, log } = this.deps;
    log.debug("Entering RequestObject.signedRequired().");
    // FAPI 1.0 Advanced requires one of every client (Part 2 section 5.2.2
    // item 1, #139).
    const required = !!config.value('oauth2.requireSignedRequestObject') ||
                     !!(client && client.require_signed_request_object) ||
                     !!(profile && profile.requireSigned === true) ||
                     this.deps.fapi.requiresSignedRequestObject();
    log.debug("Leaving RequestObject.signedRequired(). " + required);
    return required;
  }

  // Section 10.8: a type naming ANOTHER kind of JWT is refused; none, `JWT` and
  // this type are not. RFC 7515 section 4.1.9's case and prefix rules.
  typProblem(typ: Json, required: Json): Json {
    const { log } = this.deps;
    log.debug("Entering RequestObject.typProblem().");
    const text = typ === undefined || typ === null ? ''
      : String(typ).trim().toLowerCase().replace(/^application\//, '');
    if (required && text !== TYP) {
      log.debug("Leaving RequestObject.typProblem(). The type is required.");
      return 'its header is ' + (text ? 'typed "' + String(typ) + '"' :
                                 'not typed') + ', and ' +
             'oauth2.requireRequestObjectType requires every request object ' +
               'to ' +
             'be explicitly typed "' + TYP + '" (RFC 9101 section 10.8).';
    }
    if (typ === undefined || typ === null) {
      log.debug("Leaving RequestObject.typProblem(). No type.");
      return '';
    }
    if (ACCEPTED_TYPES.indexOf(text) >= 0) {
      log.debug("Leaving RequestObject.typProblem(). Accepted.");
      return '';
    }
    log.debug("Leaving RequestObject.typProblem(). Another kind of JWT.");
    return 'its header is typed "' + String(typ) + '", which is another ' +
           'kind of JWT. A request object is typed "' + TYP + '" (RFC 9101 ' +
           'section 4), ' +
           'or not typed at all; a JWT typed as something else is refused, ' +
             'so ' +
           'that a token issued for another purpose cannot be replayed as an ' +
           'authorization request (section 10.8).';
  }

  private withoutFragment(uri: Json): Json {
    const { log } = this.deps;
    log.debug("Entering RequestObject.withoutFragment().");
    const text = String(uri || '').trim();
    const hash = text.indexOf('#');
    log.debug("Leaving RequestObject.withoutFragment().");
    return hash >= 0 ? text.slice(0, hash) : text;
  }

  private jsonPart(compact: Json, index: Json): Json {
    const { log } = this.deps;
    log.debug("Entering RequestObject.jsonPart().");
    const part = String(compact || '').split('.')[index];
    log.debug("Leaving RequestObject.jsonPart().");
    return JSON.parse(Buffer.from(String(part || ''), 'base64url')
                            .toString('utf8'));
  }

  // ---------------------------------------------------------------------------
  // THE FETCH (section 5.2). Resolves `{ ok, jwt }` or a refusal and NEVER
  // rejects. Only ever called with a URI already matched against the client's
  // registration — see `resolve()`.
  // ---------------------------------------------------------------------------
  private fetchRequestUri(uri: Json): Json {
    const { http, https, config, mode, version, log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.fetchRequestUri().");
    const target = new URL(self.withoutFragment(uri));
    const secure = target.protocol === 'https:';
    const cap = Number(config.value('oauth2.requestUriMaxBytes')) || 65536;
    const timeout = Number(config.value('oauth2.requestUriTimeoutMs')) || 5000;
    if (!secure) {
      log.warn('request_object: fetching the registered request_uri ' +
               target.href + ' over plain http, which development mode ' +
               'allows and product mode refuses.');
    }
    log.debug("Leaving RequestObject.fetchRequestUri(). Dialling " +
              "" + target.origin + ".");
    return new Promise<Json>(function (resolve) {
      let settled = false;
      const done = function (result) {
        log.debug("Entering done().");
        if (!settled) {
          settled = true;
          resolve(result);
        }
        log.debug("Leaving done().");
      };
      let request = null;
      try {
        request = (secure ? https : http).request({
          protocol: target.protocol, hostname: target.hostname,
          port: target.port || (secure ? 443 : 80),
          path: target.pathname + target.search, method: 'GET',
          headers: { 'Accept': MEDIA_TYPE + ', application/jwt;q=0.9',
                     'User-Agent': version.userAgent('request-uri') },
          timeout: timeout
        }, function (response) {
          const status = response.statusCode;
          if (status !== 200) {
            response.resume();
            done(self.refusal('STS-OAUTH-0347', 'invalid_request_uri',
              'the request_uri "' + target.href + '" answered HTTP ' + status +
              (status >= 300 && status < 400
                ? ' — a redirect, which is not followed (RFC 9101 section 10.4)'
                : '') + ', where a request object was expected.'));
            return;
          }
          const type = String(response.headers['content-type'] || '')
            .split(';')[0].trim().toLowerCase();
          if (ACCEPTED_MEDIA_TYPES.indexOf(type) < 0) {
            if (!mode.acceptsLooseRequestUris()) {
              response.resume();
              done(self.refusal('STS-OAUTH-0348', 'invalid_request_uri',
                'the request_uri "' + target.href + '" answered with the ' +
                  'media ' +
                'type "' + (type || '(none)') + '", and a request object is ' +
                MEDIA_TYPE + ' (RFC 9101 section 5.2) or application/jwt. ' +
                'Product mode refuses anything else.'));
              return;
            }
            log.warn('request_object: the registered request_uri ' +
                     target.href + ' answered "' + (type || '(none)') + '" ' +
                     'rather than ' + MEDIA_TYPE + ', which development mode ' +
                     'accepts.');
          }
          const chunks = [];
          let size = 0;
          response.on('data', function (chunk) {
            size += chunk.length;
            if (size > cap) {
              response.destroy();
              done(self.refusal('STS-OAUTH-0347', 'invalid_request_uri',
                'the request_uri "' + target.href + '" answered with more ' +
                  'than ' +
                cap + ' bytes (oauth2.requestUriMaxBytes).'));
              return;
            }
            chunks.push(chunk);
          });
          response.on('end', function () {
            done({ ok: true,
                   jwt: Buffer.concat(chunks).toString('utf8').trim() });
          });
          response.on('error', function (e) {
            log.debug("Caught in RequestObject.fetchRequestUri(): " +
                      "" + ((e && e.message) || e));
            done(self.refusal('STS-OAUTH-0347', 'invalid_request_uri',
              'the request_uri "' + target.href + '" could not be read: ' +
              e.message + '.'));
          });
        });
      } catch (e) {
        log.debug("Caught in RequestObject.fetchRequestUri(): " +
                  "" + ((e && e.message) || e));
        done(self.refusal('STS-OAUTH-0347', 'invalid_request_uri',
          'the request_uri "' + target.href + '" could not be dialled: ' +
          e.message + '.'));
        return;
      }
      request.on('timeout', function () {
        request.destroy(new Error('no answer within ' + timeout + 'ms ' +
                                  '(oauth2.requestUriTimeoutMs)'));
      });
      request.on('error', function (e) {
        log.debug("Caught in RequestObject.fetchRequestUri(): " +
                  "" + ((e && e.message) || e));
        done(self.refusal('STS-OAUTH-0347', 'invalid_request_uri',
          'the request_uri "' + target.href + '" could not be fetched: ' +
          e.message + '.'));
      });
      request.end();
    });
  }

  // -------------------------------------------------------------------------
  // SECTION 6.1: A FIVE-PART REQUEST OBJECT IS DECRYPTED FIRST. Answers
  // `{ ok, jws, alg, enc }` or a refusal. The key a client secret makes is
  // `symmetricKeyFor()`'s; see SYMMETRIC_KEY_BYTES above.
  // -------------------------------------------------------------------------
  private symmetricKeyFor(alg: Json, enc: Json, secret: Json): Json {
    const { nodeCrypto, log } = this.deps;
    log.debug("Entering RequestObject.symmetricKeyFor(). " +
              "alg=" + alg + ", enc=" + enc);
    if (/^PBES2-/.test(alg)) {
      log.debug("Leaving RequestObject.symmetricKeyFor(). PBES2 takes the " +
                "secret.");
      return secret;
    }
    const bytes = alg === 'dir' ? DIRECT_KEY_BYTES[enc] :
      SYMMETRIC_KEY_BYTES[alg];
    if (!bytes) {
      log.debug("Leaving RequestObject.symmetricKeyFor(). No size known; " +
                "the secret as is.");
      return secret;
    }
    const hash = bytes <= 32 ? 'sha256' : bytes <= 48 ? 'sha384' : 'sha512';
    log.debug("Leaving RequestObject.symmetricKeyFor().");
    return nodeCrypto.createHash(hash)
      .update(Buffer.from(String(secret), 'utf8'))
      .digest().subarray(0, bytes);
  }

  private decrypt(compact: Json, client: Json, profile: Json,
                  keySet: Json): Json {
    const { stsCrypto, applications, helpers, log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.decrypt().");
    let header = null;
    try {
      header = self.jsonPart(compact, 0);
    } catch (e) {
      log.debug("Caught in RequestObject.decrypt(): " +
                "" + ((e && e.message) || e));
      log.debug("Leaving RequestObject.decrypt(). The header is not JSON.");
      return self.refusal('STS-OAUTH-0353', 'invalid_request_object',
        'the request object has five parts, so it is encrypted (RFC 9101 ' +
        'section 6.1), and its protected header is not base64url JSON: ' +
        e.message);
    }
    const alg = String(header.alg || '');
    const enc = String(header.enc || '');
    const registeredAlg = String(client.request_object_encryption_alg || '');
    const registeredEnc = registeredAlg
      ? String(client.request_object_encryption_enc || '') ||
        applications.REQUEST_OBJECT_DEFAULT_ENC
      : '';
    if (registeredAlg && (alg !== registeredAlg || enc !== registeredEnc)) {
      log.debug("Leaving RequestObject.decrypt(). Not what the client " +
                "registered.");
      return self.refusal('STS-OAUTH-0350', 'invalid_request_object',
        'the request object is encrypted "' + alg + '"/"' + enc + '", and ' +
          'this ' +
        'client registered request_object_encryption_alg "' + registeredAlg +
        '" with enc "' + registeredEnc + '".');
    }
    const offeredAlgs = (profile && profile.encryptionAlgs) ||
                        applications.REQUEST_OBJECT_ENCRYPTION_ALGS;
    const offeredEncs = (profile && profile.encryptionEncs) ||
                        applications.REQUEST_OBJECT_ENCRYPTION_ENCS;
    if (offeredAlgs.indexOf(alg) < 0 || offeredEncs.indexOf(enc) < 0) {
      log.debug("Leaving RequestObject.decrypt(). Not offered.");
      return self.refusal('STS-OAUTH-0351', 'invalid_request_object',
        'the request object is encrypted "' + alg + '"/"' + enc + '", and ' +
          'this ' +
        'authorization server decrypts request objects with ' +
        JSON.stringify(offeredAlgs) + ' and ' + JSON.stringify(offeredEncs) +
        ' (request_object_encryption_alg_values_supported and ' +
        'request_object_encryption_enc_values_supported).');
    }
    const options: Json = { allowedAlg: [alg], allowedEnc: [enc] };
    if (stsCrypto.JWE_SYMMETRIC_ALGS.indexOf(alg) >= 0) {
      if (!client.client_secret) {
        log.debug("Leaving RequestObject.decrypt(). No secret to decrypt " +
                  "with.");
        return self.refusal('STS-OAUTH-0352', 'invalid_request_object',
          'the request object is encrypted with the symmetric algorithm "' +
          alg + '", which is keyed by the client secret, and this client has ' +
          'none on its entry.');
      }
      options.secret = self.symmetricKeyFor(alg, enc, client.client_secret);
    } else {
      const keys = helpers.requestObjectKeysFor(keySet);
      const own = stsCrypto.JWE_ECDH_ALGS.indexOf(alg) >= 0 ? keys.ec
                                                            : keys.rsa;
      if (header.kid && own && own.publicJwk &&
          String(header.kid) !== String(own.publicJwk.kid)) {
        log.debug("Leaving RequestObject.decrypt(). Encrypted to another key.");
        return self.refusal('STS-OAUTH-0352', 'invalid_request_object',
          'the request object is encrypted to the key "' + header.kid + '", ' +
          'and this authorization server\'s request object encryption key ' +
            'for ' +
          alg + ' is "' + own.publicJwk.kid + '" — the key marked use "enc" ' +
          'at /oauth2/jwks. A key from another realm, or from before the ' +
            'keys ' +
          'were rotated, opens nothing here.');
      }
      options.privateKey = own.privateKey;
    }
    let opened = null;
    try {
      opened = stsCrypto.decryptJweCompact(compact, options);
    } catch (e) {
      log.debug("Caught in RequestObject.decrypt(): " +
                "" + ((e && e.message) || e));
      log.debug("Leaving RequestObject.decrypt(). It would not decrypt.");
      return self.refusal('STS-OAUTH-0353', 'invalid_request_object',
        'the encrypted request object could not be decrypted: ' + e.message);
    }
    const jws = String(opened.plaintext || '').trim();
    if (jws.split('.').length !== 3) {
      log.debug("Leaving RequestObject.decrypt(). Not a nested JWS.");
      return self.refusal('STS-OAUTH-0354', 'invalid_request_object',
        'the request object decrypted to something that is not a JWS. RFC ' +
          '9101 ' +
        'section 4 says a request object is signed and THEN encrypted, so ' +
          'what ' +
        'is inside the JWE must be a three-part JWT.');
    }
    log.debug("Leaving RequestObject.decrypt(). " + alg + " " + enc + ".");
    return { ok: true, jws: jws, alg: alg, enc: enc };
  }

  // The claims of an UNSIGNED request object, checked by hand for what
  // `verifyJwsAsync()` checks of a signed one.
  private unsignedClaims(jws: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.unsignedClaims().");
    const claims = self.jsonPart(jws, 1);
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
      throw new Error('its payload is not a JSON object');
    }
    const now = Math.floor(Date.now() / 1000);
    const skew = Number(self.skewSeconds()) || 0;
    if (claims.exp !== undefined && Number(claims.exp) + skew < now) {
      throw new Error('jwt expired');
    }
    if (claims.nbf !== undefined && Number(claims.nbf) - skew > now) {
      throw new Error('jwt not active');
    }
    log.debug("Leaving RequestObject.unsignedClaims().");
    return claims;
  }

  // ---------------------------------------------------------------------------
  // SECTION 6.2: THE SIGNATURE. Answers `{ ok, claims, alg }` or a refusal.
  // ---------------------------------------------------------------------------
  private async verify(jws: Json, client: Json, clientId: Json,
                       profile: Json, required: Json): Promise<Json> {
    const { stsCrypto, pki, errorCodes, revocationStatus, applications, config,
            mode, assertionGrant, log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.verify().");
    let header = null;
    try {
      header = self.jsonPart(jws, 0);
    } catch (e) {
      log.debug("Caught in RequestObject.verify(): " + ((e && e.message) || e));
      log.debug("Leaving RequestObject.verify(). Not a JWT.");
      return self.refusal('STS-OAUTH-0355', 'invalid_request_object',
        'the request object is not a JWT: ' + e.message);
    }
    const typeRequired = !!config.value('oauth2.requireRequestObjectType');
    const typ = self.typProblem(header.typ, typeRequired);
    if (typ) {
      log.debug("Leaving RequestObject.verify(). The wrong type.");
      return self.refusal(typeRequired && ACCEPTED_TYPES.indexOf(
                            String(header.typ || '').trim().toLowerCase()
                              .replace(/^application\//, '')) >= 0
                            ? 'STS-OAUTH-0368' : 'STS-OAUTH-0356',
                          'invalid_request_object',
                          'the request object is refused: ' + typ);
    }
    const alg = String(header.alg || '');
    // AN UNSIGNED OBJECT THAT IS REFUSED IS REFUSED FOR BEING UNSIGNED, before
    // the registered and advertised lists are read: a required signature takes
    // `none` off the advertised list too, and "not advertised" would name the
    // consequence rather than the rule.
    if (alg === 'none' && (!mode.acceptsUnsignedRequestObjects() || required)) {
      log.debug("Leaving RequestObject.verify(). Unsigned and refused.");
      return self.refusal('STS-OAUTH-0357', 'invalid_request_object',
        'the request object is unsigned (alg "none"), and ' +
        (required
          ? 'a signed request object is required here — by ' +
            'oauth2.requireSignedRequestObject, this client\'s ' +
            'require_signed_request_object or this authorization server\'s ' +
            'metadata (RFC 9101 section 10.5)'
          : 'this realm is in product mode, where RFC 9101 section 4\'s ' +
            'signed request object is required') + '.');
    }
    const registeredAlg = String(client.request_object_signing_alg || '');
    if (registeredAlg && alg !== registeredAlg) {
      log.debug("Leaving RequestObject.verify(). Not the registered " +
                "algorithm.");
      return self.refusal('STS-OAUTH-0358', 'invalid_request_object',
        'the request object is signed "' + alg + '", and this client ' +
        'registered request_object_signing_alg "' + registeredAlg + '" — ' +
          'every ' +
        'request object from it must use that algorithm.');
    }
    const offered = profile && profile.signingAlgs;
    if (Array.isArray(offered) && offered.indexOf(alg) < 0) {
      log.debug("Leaving RequestObject.verify(). Not offered.");
      return self.refusal('STS-OAUTH-0359', 'invalid_request_object',
        'the request object is signed "' + alg + '", and this authorization ' +
        'server advertises request_object_signing_alg_values_supported ' +
        JSON.stringify(offered) + '.');
    }
    // FAPI 1.0 Advanced section 8.6: PS256 or ES256 (#139).
    const profiled = self.deps.fapi.signingAlgRefusal(alg,
                                                     'the request object');
    if (profiled) {
      log.debug("Leaving RequestObject.verify(). Not an algorithm FAPI " +
                "Advanced allows.");
      return self.refusal(profiled.errorCode, 'invalid_request_object',
                          profiled.description);
    }
    if (alg === 'none') {
      try {
        const claims = self.unsignedClaims(jws);
        log.info('request_object: an UNSIGNED request object from "' +
                 clientId + '" was accepted, which development mode ' +
                 'allows (OpenID ' +
                 'Connect Core section 6.1) and product mode refuses.');
        log.debug("Leaving RequestObject.verify(). Unsigned, accepted.");
        return { ok: true, claims: claims, alg: 'none' };
      } catch (e) {
        log.debug("Caught in RequestObject.verify(): " +
                  "" + ((e && e.message) || e));
        log.debug("Leaving RequestObject.verify(). The unsigned claims are " +
                  "refused.");
        return self.refusal('STS-OAUTH-0364', 'invalid_request_object',
          'the unsigned request object is refused: ' + e.message + '.');
      }
    }
    if (applications.REQUEST_OBJECT_SIGNING_ALGS.indexOf(alg) < 0) {
      log.debug("Leaving RequestObject.verify(). An algorithm this service " +
                "has not.");
      return self.refusal('STS-OAUTH-0360', 'invalid_request_object',
        'the request object names the algorithm "' + alg + '", which this ' +
        'service does not verify. It verifies ' +
        applications.REQUEST_OBJECT_SIGNING_ALGS.join(', ') + '.');
    }
    let candidates = [];
    let why = '';
    if (/^HS/.test(alg)) {
      if (client.client_secret) {
        candidates.push({ kid: '', key: client.client_secret,
                          source: 'secret' });
      } else {
        why = 'it is signed with the HMAC algorithm "' + alg + '", which is ' +
              'keyed by the client secret, and this client has none';
      }
    } else {
      const read = assertionGrant.keysForParty({
        oauthJwks: client.jwks, oauthAssertionJwks: client.assertion_jwks
      }, 'application');
      candidates = read.keys;
      if (!candidates.length) {
        why = 'this client holds no key a request object could be verified ' +
              'with' + (read.problems.length
                ? ' (' + read.problems.join('; ') + ')' : '') +
              (client.jwks_uri
                ? ' — it registered a jwks_uri, which this service does not ' +
                  'fetch; register the keys by value as `jwks`'
                : '. Register its public keys as `jwks`, or issue it a key ' +
                  'pair from /admin/pki');
      }
    }
    if (!candidates.length) {
      log.debug("Leaving RequestObject.verify(). No key.");
      return self.refusal('STS-OAUTH-0361', 'invalid_request_object',
                          'the request object cannot be verified: ' + why +
                          '.');
    }
    // SECTION 6.2: "If a kid Header Parameter is present, the key identified
    // MUST be the key used and MUST be a key associated with the client." So a
    // `kid` naming none of this client's keys is refused rather than every key
    // tried. An HMAC secret has no kid, so a `kid` on an HS* object names
    // nothing and is ignored.
    let attempts = candidates;
    if (header.kid && !/^HS/.test(alg)) {
      attempts = candidates.filter(function (one) {
        return one.kid === String(header.kid);
      });
      if (!attempts.length) {
        log.debug("Leaving RequestObject.verify(). The kid names no key of " +
                  "this client.");
        return self.refusal('STS-OAUTH-0370', 'invalid_request_object',
          'the request object names the key "' + header.kid + '", which is ' +
          'not one of this client\'s keys (' + candidates.map(function (one) {
            return '"' + (one.kid || '(no kid)') + '"';
          }).join(', ') + '). RFC 9101 section 6.2: the key a kid identifies ' +
          'MUST be the key used and MUST be associated with the client.');
      }
    }
    let claims = null;
    let usedKey = null;
    let lastError = '';
    for (let i = 0; i < attempts.length && !claims; i++) {
      try {
        claims = await stsCrypto.verifyJwsAsync(jws, attempts[i].key, {
          algorithms: [alg], clockTolerance: self.skewSeconds()
        });
        usedKey = attempts[i];
      } catch (e) {
        log.debug("Caught in RequestObject.verify(): " +
                  "" + ((e && e.message) || e));
        lastError = e.message;
      }
    }
    if (!claims) {
      log.debug("Leaving RequestObject.verify(). It did not verify.");
      return self.refusal('STS-OAUTH-0362', 'invalid_request_object',
        'the request object did not verify with any key this client holds: ' +
        lastError + '.');
    }
    const usedX5c = usedKey && usedKey.jwk && Array.isArray(usedKey.jwk.x5c)
      ? usedKey.jwk.x5c : [];
    if (usedX5c.length) {
      const keyChain = await pki.verifySignerChain(undefined, {
        certificate: usedX5c[0], chain: usedX5c.slice(1), key: usedKey.jwk,
        source: 'the key "' + (usedKey.kid || '(no kid)') + '" in ' +
                usedKey.source + ' for "' + clientId + '"'
      });
      if (!keyChain.ok) {
        log.debug("Leaving RequestObject.verify(). The key's chain is " +
                  "refused.");
        return self.refusal(errorCodes.codeOf(keyChain) || 'STS-OAUTH-0363',
          'invalid_request_object',
          'the certificate of the key that verified this request object does ' +
          'not have a valid trust chain: ' + keyChain.why);
      }
    }
    if (usedKey && usedKey.jwk) {
      const verdict = await revocationStatus.registeredKeyVerdictFor(
        usedKey.jwk,
        'the key "' + (usedKey.kid || '(no kid)') + '" in ' + usedKey.source +
        ' for "' + clientId + '"');
      if (verdict && verdict.refused) {
        log.debug("Leaving RequestObject.verify(). The key is revoked.");
        return self.refusal('STS-PKI-0129', 'invalid_request_object',
          'the key that verified this request object may no longer be used: ' +
          verdict.why);
      }
    }
    log.debug("Leaving RequestObject.verify(). Verified with " + alg + ".");
    return { ok: true, claims: claims, alg: alg };
  }

  // ---------------------------------------------------------------------------
  // SECTION 6.3: THE PARAMETERS. Every claim that is not a JWT claim about the
  // object itself, as the endpoint reads a query: a string stays a string, a
  // number or a boolean becomes its text, `resource` keeps its array (RFC 8707
  // repeats it), and an object — `claims`, `authorization_details` — is the
  // JSON a query would have carried. `request` and `request_uri` inside an
  // object are dropped: a request object does not refer to another one.
  // ---------------------------------------------------------------------------
  parametersFrom(claims: Json, outer: Json, clientId: Json): Json {
    const { log } = this.deps;
    log.debug("Entering RequestObject.parametersFrom().");
    const params: Json = {};
    Object.keys(claims || {}).forEach(function (name) {
      if (JWT_CLAIMS.indexOf(name) >= 0 || name === 'request' ||
          name === 'request_uri') {
        return;
      }
      const value = claims[name];
      if (value === undefined || value === null) {
        return;
      }
      if (Array.isArray(value) && name === 'resource') {
        params[name] = value.map(String);
      } else if (typeof value === 'object') {
        params[name] = JSON.stringify(value);
      } else {
        params[name] = String(value);
      }
    });
    params.client_id = String(clientId);
    ROUND_TRIP_FIELDS.forEach(function (name) {
      if (outer && outer[name] !== undefined) {
        params[name] = outer[name];
      }
    });
    if (params.jar_prompt_honoured !== undefined) {
      delete params.prompt;
    }
    log.debug("Leaving RequestObject.parametersFrom(). " +
              "" + Object.keys(params).length +
              " parameter(s).");
    return params;
  }

  // ---------------------------------------------------------------------------
  // OPENID CONNECT CORE SECTION 6.2's FRAGMENT: a request_uri whose content may
  // change SHOULD carry the base64url SHA-256 of that content as its fragment.
  // A fragment that has that SHAPE — 43 base64url characters — is checked
  // against what was fetched, in every mode; any other fragment is the client's
  // own and is not read.
  // ---------------------------------------------------------------------------
  fragmentProblem(uri: Json, content: Json): Json {
    const { nodeCrypto, log } = this.deps;
    log.debug("Entering RequestObject.fragmentProblem().");
    const text = String(uri || '');
    const hash = text.indexOf('#');
    const fragment = hash >= 0 ? text.slice(hash + 1) : '';
    if (!/^[A-Za-z0-9_-]{43}$/.test(fragment)) {
      log.debug("Leaving RequestObject.fragmentProblem(). No SHA-256 " +
                "fragment.");
      return '';
    }
    const digest = nodeCrypto.createHash('sha256')
      .update(String(content), 'utf8').digest('base64url');
    log.debug("Leaving RequestObject.fragmentProblem().");
    return digest === fragment ? '' :
      'the request_uri\'s fragment is "' + fragment + '", which is the ' +
      'SHA-256 of a different request object: what it answers with now ' +
      'hashes to "' + digest + '" (OpenID Connect Core section 6.2). The ' +
      'content has changed since the URI was written, so it is not used.';
  }

  private cacheSeconds(): Json {
    const { config, log } = this.deps;
    log.debug("Entering RequestObject.cacheSeconds().");
    const seconds = Number(config.value('oauth2.requestUriCacheS'));
    log.debug("Leaving RequestObject.cacheSeconds().");
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 0;
  }

  // A registered request_uri's content: from the cache where
  // `oauth2.requestUriCacheS` is on and an unexpired copy is held, and fetched
  // otherwise. The fragment check runs on either. Resolves `{ ok, jwt, cached
  // }` or a refusal.
  private async contentOf(uri: Json): Promise<Json> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.contentOf().");
    const ttl = self.cacheSeconds();
    const now = Date.now();
    if (ttl) {
      const held = requestUriCache.get(uri);
      if (held && held.until > now) {
        requestUriCount.hit();
        log.debug("Leaving RequestObject.contentOf(). From the cache.");
        return { ok: true, jwt: held.jwt, cached: true };
      }
      requestUriCount.miss();
    }
    const fetched = await self.fetchRequestUri(uri);
    if (!fetched.ok) {
      log.debug("Leaving RequestObject.contentOf(). The fetch failed.");
      return fetched;
    }
    const problem = self.fragmentProblem(uri, fetched.jwt);
    if (problem) {
      log.debug("Leaving RequestObject.contentOf(). The fragment does not " +
                "match.");
      return self.refusal('STS-OAUTH-0349', 'invalid_request_uri', problem);
    }
    if (ttl) {
      while (requestUriCache.size >= MAX_CACHED_REQUEST_URIS) {
        requestUriCache.delete(requestUriCache.keys().next().value);
      }
      requestUriCache.set(uri, { jwt: fetched.jwt, until: now + ttl * 1000 });
    }
    log.debug("Leaving RequestObject.contentOf(). Fetched.");
    return { ok: true, jwt: fetched.jwt, cached: false };
  }

  // ---------------------------------------------------------------------------
  // A REQUEST OBJECT, FROM ITS COMPACT FORM TO THE PARAMETERS IT CARRIES.
  //
  // The half of `resolve()` that does not care how the object arrived, and the
  // function `oauth-oidc/par.ts` calls for a `request` pushed to it (RFC 9126
  // section 3), so a pushed request object and one sent to the authorization
  // endpoint are one verifier.
  //
  //   jwt       the compact JWS or JWE
  //   client    `applications.clientConfigOf(clientId)`
  //   clientId  the client that SENT it — the query's, or the authenticated one
  //   issuer    this authorization server's issuer identifier
  //   asBase    its base URL
  //   profile   see resolve()
  //   keySet    the realm's key set
  //   query     optional: the query it arrived with, for the round-trip fields
  //             and OpenID Connect's duplicated response_type
  //
  // Resolves `{ ok: true, params, alg, encrypted }` or a refusal. Never
  // rejects.
  // ---------------------------------------------------------------------------
  async verifyObject(opts: Json): Promise<Json> {
    const { config, helpers, log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.verifyObject().");
    const options = opts || {};
    const client = options.client || {};
    const profile = options.profile || {};
    const clientId = String(options.clientId || '');
    const query = options.query || {};
    const required = self.signedRequired(client, profile);
    const compact = String(options.jwt || '').trim();

    let jws = compact;
    let encrypted = '';
    const parts = compact.split('.').length;
    if (parts === 5) {
      const opened = self.decrypt(compact, client, profile, options.keySet);
      if (!opened.ok) {
        log.debug("Leaving RequestObject.verifyObject(). Decryption refused.");
        return opened;
      }
      jws = opened.jws;
      encrypted = opened.alg + ' ' + opened.enc;
    } else if (parts !== 3) {
      log.debug("Leaving RequestObject.verifyObject(). Not a JWT.");
      return self.refusal('STS-OAUTH-0355', 'invalid_request_object',
        'the request object is not a compact JWT: it has ' + parts + ' ' +
        'part(s), where a JWS has three and a JWE five.');
    } else if (client.request_object_encryption_alg) {
      log.debug("Leaving RequestObject.verifyObject(). Should have been " +
                "encrypted.");
      return self.refusal('STS-OAUTH-0350', 'invalid_request_object',
        'the request object is not encrypted, and this client registered ' +
        'request_object_encryption_alg "' +
        client.request_object_encryption_alg +
        '" — every request object from it must be encrypted.');
    }

    const verified = await self.verify(jws, client, clientId, profile,
                                       required);
    if (!verified.ok) {
      log.debug("Leaving RequestObject.verifyObject(). The object is refused.");
      return verified;
    }
    const claims = verified.claims;
    if (config.value('oauth2.requireRequestObjectIssuerAudience') &&
        (claims.iss === undefined || claims.aud === undefined)) {
      log.debug("Leaving RequestObject.verifyObject(). iss or aud missing.");
      return self.refusal('STS-OAUTH-0369', 'invalid_request_object',
        'the request object carries no ' +
        [claims.iss === undefined ? '`iss`' : '',
         claims.aud === undefined ? '`aud`' : ''].filter(Boolean)
          .join(' and no ') +
        ', and oauth2.requireRequestObjectIssuerAudience requires both (RFC ' +
        '9101 section 4: a signed request object SHOULD contain them).');
    }
    if (claims.iss !== undefined && String(claims.iss) !== clientId) {
      log.debug("Leaving RequestObject.verifyObject(). The wrong issuer.");
      return self.refusal('STS-OAUTH-0365', 'invalid_request_object',
        'the request object\'s `iss` is "' + claims.iss + '", and the client ' +
        'is "' + clientId + '". A request object is issued by the client ' +
          'that ' +
        'sends it.');
    }
    if (claims.aud !== undefined) {
      const audiences = (Array.isArray(claims.aud) ? claims.aud : [claims.aud])
        .map(String);
      const accepted = [String(options.issuer || ''),
                        String(options.asBase || '') + '/oauth2/authorize']
        .filter(Boolean);
      if (!audiences.some(function (one) {
        return accepted.indexOf(one) >= 0;
      })) {
        log.debug("Leaving RequestObject.verifyObject(). The wrong audience.");
        return self.refusal('STS-OAUTH-0366', 'invalid_request_object',
          'the request object\'s `aud` is ' + JSON.stringify(claims.aud) +
          ', ' +
          'and it is addressed to this authorization server by its issuer ' +
          'identifier "' + options.issuer + '" (RFC 9101 section 4) or its ' +
          'authorization endpoint.');
      }
    }
    // FAPI 1.0 Advanced (#139): exp and nbf required and within 60 minutes,
    // and aud this server's issuer (Part 2 section 5.2.2 items 13, 15, 17).
    const lifetime = self.deps.fapi.requestObjectRefusal(claims,
                                                         options.issuer);
    if (lifetime) {
      log.debug("Leaving RequestObject.verifyObject(). FAPI Advanced " +
                "refused its claims.");
      return self.refusal(lifetime.errorCode, lifetime.error,
                          lifetime.description);
    }
    if (claims.client_id !== undefined &&
        String(claims.client_id) !== clientId) {
      log.debug("Leaving RequestObject.verifyObject(). client_id differs.");
      return self.refusal('STS-OAUTH-0367', 'invalid_request_object',
        'the request object\'s `client_id` is "' + claims.client_id + '" and ' +
        'the query parameter is "' + clientId + '". RFC 9101 section 6.3 ' +
          'says ' +
        'the two MUST be identical.');
    }
    if (query.response_type !== undefined &&
        claims.response_type !== undefined &&
        String(query.response_type) !== String(claims.response_type)) {
      log.debug("Leaving RequestObject.verifyObject(). response_type differs.");
      return self.refusal('STS-OAUTH-0371', 'invalid_request_object',
        'the query says response_type "' + query.response_type + '" and the ' +
        'request object says "' + claims.response_type + '". A client may ' +
        'duplicate a parameter in the query for backward compatibility (RFC ' +
        '9101 section 5), and OpenID Connect Core section 6.1 says ' +
        'response_type MUST then match.');
    }
    const params = self.parametersFrom(claims, query, clientId);
    helpers.logArtifact('RFC 9101 request object',
                        'as verified (' + verified.alg +
                        (encrypted ? ', encrypted ' + encrypted : '') + ')',
                        params);
    // `claims` is the verified claim set itself, for `par.ts`: RFC 9126 section
    // 3 refuses an authenticated client's object with NO `client_id` claim,
    // which `params` cannot show because section 6.3's assembly always fills
    // one in. `once` is what the object is remembered by, or null (#35).
    log.debug("Leaving RequestObject.verifyObject(). " + verified.alg + ".");
    return { ok: true, params: params, alg: verified.alg, encrypted: encrypted,
             claims: claims, once: self.onceOf(claims, clientId) };
  }

  // ---------------------------------------------------------------------------
  // THE `jti`, REMEMBERED (#35). See this file's header for the design.
  //
  // `onceOf()` answers what the used-assertion history knows a verified object
  // by — `{ issuer, identifier, expiresAt }` — or null for an object with no
  // `jti`, or while `oauth2.requestObjectJtiOnce` is off. The ISSUER is the
  // client the object was verified for, not its `iss` claim: `iss` is
  // optional, and where present `verifyObject()` has already required it to be
  // that client.
  // ---------------------------------------------------------------------------
  onceOf(claims: Json, clientId: Json): Json {
    const { config, log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.onceOf().");
    if (!config.value('oauth2.requestObjectJtiOnce')) {
      log.debug("Leaving RequestObject.onceOf(). Switched off.");
      return null;
    }
    const jti = claims ? claims.jti : undefined;
    if (jti === undefined || jti === null || String(jti) === '') {
      log.debug("Leaving RequestObject.onceOf(). No jti.");
      return null;
    }
    const exp = claims.exp === undefined ? NaN : Number(claims.exp);
    // Until the object could no longer be accepted, which is its `exp` plus
    // the skew `verify()` allowed; an object without one is acceptable for
    // ever, so it is remembered for the retention window and no longer.
    const expiresAt = isFinite(exp)
      ? (exp + Number(self.skewSeconds() || 0)) * 1000
      : Date.now() +
        Number(config.value('oauth2.requestObjectJtiRetentionS')) * 1000;
    log.debug("Leaving RequestObject.onceOf().");
    return { issuer: String(clientId), identifier: String(jti),
             expiresAt: expiresAt };
  }

  // The sentence both refusals of a replay end with.
  private replayDescription(existing: Json): Json {
    const { usedAssertions, log } = this.deps;
    log.debug("Entering RequestObject.replayDescription().");
    log.debug("Leaving RequestObject.replayDescription().");
    return 'this request object has been used already' +
      usedAssertions.usedAs(existing) + '. Its `jti` is remembered until ' +
      'the object expires, because a signed request object captured off ' +
      'the wire is a credential for the request inside it until then. Sign ' +
      'a fresh one, with a new `jti`, for each authorization request.';
  }

  // The look every pass takes. Resolves null when the object may go on, or a
  // refusal when its `jti` is already spent or reserved.
  async lookUp(once: Json): Promise<Json> {
    const { usedAssertions, log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.lookUp().");
    if (!once) {
      log.debug("Leaving RequestObject.lookUp(). Nothing to look for.");
      return null;
    }
    const seen = await usedAssertions.peek({
      format: 'jwt', issuer: once.issuer, identifier: once.identifier
    });
    if (!seen.used) {
      log.debug("Leaving RequestObject.lookUp(). Not used" +
                (seen.unknown ? ", as far as the store could say." : "."));
      return null;
    }
    log.warn('request_object: client "' + once.issuer + '" sent a request ' +
             'object whose jti ' + JSON.stringify(once.identifier) + ' has ' +
             'been used already; it is refused.');
    log.debug("Leaving RequestObject.lookUp(). A replay.");
    return self.refusal('STS-OAUTH-0374', 'invalid_request_object',
                        self.replayDescription(seen.existing));
  }

  // THE SPEND. `request` binds the claim to its response — a status under
  // `keepBelow` keeps it, anything else releases it — and `clientId` is the
  // client asking, for the console's row. Resolves `{ ok: true }` or a refusal
  // carrying the HTTP `status` to answer it with.
  async spend(opts: Json): Promise<Json> {
    const { usedAssertions, errorCodes, log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.spend().");
    const o = opts || {};
    const once = o.once;
    if (!once) {
      log.debug("Leaving RequestObject.spend(). Nothing to spend.");
      return { ok: true };
    }
    const spent = await usedAssertions.claim({
      format: 'jwt', use: 'request-object',
      issuer: once.issuer, identifier: once.identifier,
      clientId: String(o.clientId || once.issuer),
      expiresAt: once.expiresAt,
      request: o.request, keepBelow: o.keepBelow
    });
    if (spent.ok) {
      log.debug("Leaving RequestObject.spend(). Spent.");
      return { ok: true };
    }
    if (spent.reason === 'replay') {
      log.warn('request_object: client "' + once.issuer + '" used the ' +
               'request object jti ' + JSON.stringify(once.identifier) +
               ' again; nothing is issued on it.');
      log.debug("Leaving RequestObject.spend(). A replay.");
      return Object.assign(self.refusal('STS-OAUTH-0374',
        'invalid_request_object', self.replayDescription(spent.existing)),
        { status: 400 });
    }
    if (spent.reason === 'full') {
      log.warn(errorCodes.tag('STS-OAUTH-0375') +
               'request_object: the used-assertion history for this realm ' +
               'is full of unexpired rows (oauth2.assertionReplayCacheSize ' +
               '= ' + spent.cap + '), so a request object from "' +
               once.issuer + '" is refused rather than a live one forgotten.');
      log.debug("Leaving RequestObject.spend(). The history is full.");
      return Object.assign(self.refusal('STS-OAUTH-0375',
        'temporarily_unavailable',
        'this authorization server is holding as many unexpired ' +
        'documents as it is configured to remember ' +
        '(oauth2.assertionReplayCacheSize), and it will not forget one that ' +
        'could still be replayed in order to accept this request object. ' +
        'Retry shortly.'), { status: 503 });
    }
    log.error(errorCodes.tag('STS-OAUTH-0376') +
              'request_object: the used-assertion history could not record ' +
              'the request object jti ' + JSON.stringify(once.identifier) +
              ' from "' + once.issuer + '": ' + (spent.why || 'no reason') +
              '. Nothing is issued on it.');
    log.debug("Leaving RequestObject.spend(). The store could not be asked.");
    return Object.assign(self.refusal('STS-OAUTH-0376', 'server_error',
      'this authorization server could not record that the request object ' +
      'has been used, so it has issued nothing on it.'), { status: 500 });
  }

  // A pushed authorization request's URN, handed to `par.ts` where it exists.
  // Required LAZILY: that module requires this one for `verifyObject()`, and a
  // require back at load would close the cycle.
  private async pushedRequest(uri: Json, clientId: Json,
                              context: Json): Promise<Json> {
    const { loadPar, log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.pushedRequest().");
    let par = null;
    try {
      par = loadPar();
    } catch (e) {
      log.debug("Caught in RequestObject.pushedRequest(): " +
                "" + ((e && e.message) || e));
      par = null;
    }
    if (!par || typeof par.resolve !== 'function') {
      log.debug("Leaving RequestObject.pushedRequest(). No PAR here.");
      return self.refusal('STS-OAUTH-0372', 'request_uri_not_supported',
        'the request_uri "' + uri + '" is a pushed authorization request URN ' +
        '(RFC 9126), and this service has no pushed authorization request ' +
        'endpoint to have issued it.');
    }
    try {
      // `authorizationServer` and `req` are what let a URN pushed at one named
      // authorization server be refused at another; par.ts decides that.
      const answer = await par.resolve(uri, clientId, context || {});
      log.debug("Leaving RequestObject.pushedRequest().");
      return answer || self.refusal('STS-OAUTH-0372', 'invalid_request_uri',
        'the pushed authorization request "' + uri + '" resolved to nothing.');
    } catch (e) {
      log.debug("Caught in RequestObject.pushedRequest(): " +
                "" + ((e && e.message) || e));
      log.debug("Leaving RequestObject.pushedRequest(). It threw.");
      return self.refusal('STS-OAUTH-0372', 'invalid_request_uri',
        'the pushed authorization request "' + uri + '" could not be ' +
        'resolved: ' + e.message);
    }
  }

  // ---------------------------------------------------------------------------
  // THE ONE ENTRY POINT FOR THE AUTHORIZATION ENDPOINT.
  //
  //   query    the request's own query, as express parsed it
  //   client   `applications.clientConfigOf()` for the query's client_id
  //   issuer   this authorization server's issuer identifier
  //   asBase   its base URL, for the authorization endpoint's address
  //   profile  what the selected authorization server PUBLISHES:
  //            { requestSupported, requestUriSupported, requireSigned,
  //              signingAlgs, encryptionAlgs, encryptionEncs } — a boolean or a
  //            list, or undefined/null where the profile removed the member
  //   keySet   the realm's key set (`helpers.stsKeysFor()`)
  //   authorizationServer, req
  //            handed to `par.ts` for a pushed request's URN, and read by
  //            nothing here
  //
  // Resolves `{ ok: true, used: false }` for a request that is not JWT-secured,
  // `{ ok: true, used: true, params, source, alg, encrypted, once }` for one
  // that is, or a refusal. NEVER rejects.
  // ---------------------------------------------------------------------------
  async resolve(opts: Json): Promise<Json> {
    const { applications, config, log } = this.deps;
    const self = this;
    log.debug("Entering RequestObject.resolve().");
    const options = opts || {};
    const query = options.query || {};
    const client = options.client || {};
    const profile = options.profile || {};
    const required = self.signedRequired(client, profile);
    const byValue = query.request !== undefined && query.request !== '';
    const byReference = query.request_uri !== undefined &&
                        query.request_uri !== '';
    if (!byValue && !byReference) {
      if (required) {
        log.debug("Leaving RequestObject.resolve(). A signed request object " +
                  "is required.");
        return self.refusal('STS-OAUTH-0340', 'invalid_request',
          'this authorization request carries no request object, and a ' +
            'signed ' +
          'one is required here (RFC 9101 section 10.5) — by ' +
          [config.value('oauth2.requireSignedRequestObject')
             ? 'oauth2.requireSignedRequestObject' : '',
           client.require_signed_request_object
             ? 'this client\'s require_signed_request_object' : '',
           profile.requireSigned === true
             ? 'this authorization server\'s ' +
               'require_signed_request_object' : '']
            .filter(Boolean).join(' and ') +
          '. Send the parameters in a signed JWT, as `request` or ' +
          '`request_uri`.');
      }
      log.debug("Leaving RequestObject.resolve(). Not a JWT-secured request.");
      return { ok: true, used: false };
    }
    if (byValue && byReference) {
      log.debug("Leaving RequestObject.resolve(). Both.");
      return self.refusal('STS-OAUTH-0341', 'invalid_request',
        'this authorization request carries both `request` and ' +
        '`request_uri`. RFC 9101 section 5 sends a request object by value ' +
          'or ' +
        'by reference, not both.');
    }
    if (Array.isArray(query.request) || Array.isArray(query.request_uri)) {
      log.debug("Leaving RequestObject.resolve(). Repeated.");
      return self.refusal('STS-OAUTH-0341', 'invalid_request',
        'this authorization request repeats `' +
        (byValue ? 'request' : 'request_uri') + '`; there is one request ' +
        'object per request.');
    }
    if (byValue && profile.requestSupported === false) {
      log.debug("Leaving RequestObject.resolve(). request not supported here.");
      return self.refusal('STS-OAUTH-0342', 'request_not_supported',
        'this authorization server publishes request_parameter_supported ' +
        'false, so a request object may not be sent by value here.');
    }
    // RFC 9126 section 5: a request_uri the PAR endpoint issued is usable here
    // "regardless of other authorization server metadata", so a URN is not
    // refused by request_uri_parameter_supported false.
    const pushedUrn = byReference &&
      String(query.request_uri).indexOf(PAR_URN_PREFIX) === 0;
    if (byReference && !pushedUrn && profile.requestUriSupported === false) {
      log.debug("Leaving RequestObject.resolve(). request_uri not supported " +
                "here.");
      return self.refusal('STS-OAUTH-0343', 'request_uri_not_supported',
        'this authorization server publishes request_uri_parameter_supported ' +
        'false, so a request object may not be sent by reference here.');
    }
    const clientId = String(query.client_id || '');
    if (!clientId) {
      log.debug("Leaving RequestObject.resolve(). No client_id.");
      return self.refusal('STS-OAUTH-0344', 'invalid_request',
        'this authorization request carries a request object and no ' +
        '`client_id` query parameter. RFC 9101 section 5 requires it: it is ' +
        'what says whose keys verify the object' +
        (byReference ? ' and whose registered request_uris may be fetched'
                     : '') +
        ', and reading it out of an object nobody has verified yet would ' +
        'choose the verifier from the document being verified.');
    }

    let compact = '';
    let cached = false;
    if (byValue) {
      compact = String(query.request).trim();
    } else if (pushedUrn) {
      const pushed = await self.pushedRequest(String(query.request_uri),
                                              clientId, {
        authorizationServer: options.authorizationServer, req: options.req
      });
      if (!pushed.ok) {
        log.debug("Leaving RequestObject.resolve(). The pushed request is " +
                  "refused.");
        return pushed;
      }
      if (pushed.params) {
        const params = Object.assign({}, pushed.params,
                                     { client_id: clientId });
        ROUND_TRIP_FIELDS.forEach(function (name) {
          if (query[name] !== undefined) {
            params[name] = query[name];
          }
        });
        if (params.jar_prompt_honoured !== undefined) {
          delete params.prompt;
        }
        log.debug("Leaving RequestObject.resolve(). A pushed request's " +
                  "parameters.");
        return { ok: true, used: true, params: params, source: 'par',
                 alg: pushed.alg || '', encrypted: pushed.encrypted || '',
                 pushed: pushed.pushed || null };
      }
      compact = String(pushed.jwt || '').trim();
    } else {
      const asked = String(query.request_uri).trim();
      const wanted = self.withoutFragment(asked);
      const registered = (client.request_uris || []).map(String);
      const match = registered.filter(function (one) {
        return self.withoutFragment(one) === wanted;
      })[0];
      if (match === undefined) {
        log.warn('request_object: client "' + clientId + '" sent a ' +
                 'request_uri ' +
                 'it has not registered, which was refused and not fetched.');
        log.debug("Leaving RequestObject.resolve(). An unregistered " +
                  "request_uri.");
        return self.refusal('STS-OAUTH-0345', 'invalid_request_uri',
          'the request_uri "' + wanted + '" is not one client "' + clientId +
          '" has registered (request_uris). This service fetches a ' +
          'request_uri only when the client registered it beforehand, so ' +
            'that ' +
          'it cannot be made to dial a URL a request chose (RFC 9101 section ' +
          '10.4). Register it on the application, or send the request object ' +
          'by value.');
      }
      if (asked.length > 512) {
        log.warn('request_object: client "' + clientId + '" sent a ' +
                 'request_uri ' +
                 'of ' + asked.length + ' characters; RFC 9101 section 5.2 ' +
                 'says one SHOULD NOT exceed 512.');
      }
      const problem = applications.requestUriProblem(wanted);
      if (problem) {
        log.debug("Leaving RequestObject.resolve(). A registered " +
                  "request_uri now refused.");
        return self.refusal('STS-OAUTH-0346', 'invalid_request_uri',
          'the registered request_uri cannot be fetched: ' + problem + '.');
      }
      // THE URI AS SENT, fragment and all: the fragment is what names a version
      // of the content for the cache and the SHA-256 check, and it is never
      // sent on the wire.
      const content = await self.contentOf(asked);
      if (!content.ok) {
        log.debug("Leaving RequestObject.resolve(). The content could not " +
                  "be had.");
        return content;
      }
      compact = content.jwt;
      cached = content.cached;
    }

    const object = await self.verifyObject({
      jwt: compact, client: client, clientId: clientId, issuer: options.issuer,
      asBase: options.asBase, profile: profile, keySet: options.keySet,
      query: query
    });
    if (!object.ok) {
      log.debug("Leaving RequestObject.resolve(). The object is refused.");
      return object;
    }
    // #35: a `jti` already spent is refused on this pass, before or after the
    // sign-in screen alike. The LAST refusal, so an object refused for
    // anything above is not reported as a replay. A pushed request never
    // reaches here with an object of its own to look at: its push was its
    // use.
    const replayed = pushedUrn ? null : await self.lookUp(object.once);
    if (replayed) {
      log.debug("Leaving RequestObject.resolve(). A replayed jti.");
      return replayed;
    }
    log.debug("Leaving RequestObject.resolve(). " +
              "" + (byValue ? 'By value' : 'By reference') +
              ", " + object.alg + ".");
    return { ok: true, used: true, params: object.params,
             source: byValue ? 'request' : 'request_uri', cached: cached,
             alg: object.alg, encrypted: object.encrypted,
             once: pushedUrn ? null : object.once };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<RequestObject>(
  'oauth-oidc/request_object',
  () => new RequestObject(RequestObject.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  RequestObject: RequestObject,
  installInstance: (instance: RequestObject): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  TYP: RequestObject.TYP,
  MEDIA_TYPE: RequestObject.MEDIA_TYPE,
  PAR_URN_PREFIX: RequestObject.PAR_URN_PREFIX,
  ROUND_TRIP_FIELDS: RequestObject.ROUND_TRIP_FIELDS,
  typProblem: slot.forward('typProblem'),
  signedRequired: slot.forward('signedRequired'),
  fragmentProblem: slot.forward('fragmentProblem'),
  parametersFrom: slot.forward('parametersFrom'),
  verifyObject: slot.forward('verifyObject'),
  onceOf: slot.forward('onceOf'),
  lookUp: slot.forward('lookUp'),
  spend: slot.forward('spend'),
  resolve: slot.forward('resolve')
};
