// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_api.ts
//
// ---------------------------------------------------------------------------
// THE W3C VERIFIABLE CREDENTIALS API (VCALM, the W3C CCG's VC API), OVER
// THIS SERVICE'S OWN ISSUER AND VERIFIER MACHINERY (#194-#199, 2026-09-26;
// A PRODUCT SURFACE SINCE #598, 2026-10-12).
//
// The VC API defines an issuer that secures a credential it is HANDED
// (`/credentials/issue`), a verifier that checks one (`/credentials/verify`,
// `/presentations/verify`), a holder that proves a presentation and derives
// a selective disclosure (`/presentations/prove`, `/credentials/derive`) and
// a status service (`/credentials/status`). This service issues through
// OpenID4VCI and verifies through OpenID4VP, and neither protocol secures a
// document a caller wrote: the issuer builds a credential from a directory
// entry and the Verifier judges a presentation against the query it asked.
// So this file is an ADAPTER, and what it adapts to is this service's own
// machinery, not a second copy of it:
//
//   * the signing is `vc_data_integrity.ts`'s (every cryptosuite the W3C
//     suites ask for, held to the specifications' own vectors in `tests/`)
//     and `vc_jose_cose.ts`'s;
//   * a credential's status is an index `vc_status.ts` allocates in the
//     realm's own Bitstring Status Lists, and a status change is
//     `setStatus()` — the act `/admin/vc/monitor` performs, one of the three
//     ways a credential is DISOWNED (`CLAUDE.md` 3ar);
//   * the data model's MUSTs are `vc_data_model.ts`, and the JSON-LD safe
//     mode that refuses an undefined term or a redefined protected one is
//     `vc_jsonld.ts`'s closed loader, which FETCHES NOTHING — so no caller
//     can make this service dial a URL by naming a context.
//
// IT WAS A TEST CONTROL (#194-#199, development-only since #585) and became
// a product surface on rcbj's decision 2 on #591. What that changed, each
// argued where it is done:
//
//   * **OFF UNTIL A REALM TURNS IT ON** (`vcApi.enabled`, `served()`). Off,
//     every route answers 501 with its own refusal (`STS-VC-0120`) — not
//     Express's 404 — exactly as `scim.enabled`, `ssf.enabled` and
//     `xacml.enabled` do: the feature is off, the URL is not wrong, and a
//     client trying to learn whether this service speaks the VC API is told
//     which. It also keeps `/admin/sts-metadata`'s list true in every realm:
//     a listed endpoint answers, on or off.
//   * **ITS OWN KEYS.** It signs with the realm key set's dedicated VC-API
//     member (`helpers.js` makeVcApiKeys(), `vcApiKeyFor()`), never with the
//     keys that sign this realm's tokens: a VC-JOSE-COSE issuer is a compact
//     JWS over a document the CALLER wrote, and with the token keys it was a
//     way to have an `iss`/`sub`/`aud` of the caller's choosing signed by a
//     key `verifyOwnJws()` believes (RFC 8725 section 3.12).
//   * **AUTHENTICATED IN EVERY MODE, AS IT ALWAYS WAS**: an access token THIS
//     realm issued, verified, not revoked, carrying `vc-api:issue` (issue,
//     prove, derive, status, the issuer list) or `vc-api:verify` (verify,
//     DID resolution) — this service's own protected scopes
//     (`common/scope_policy.ts`), issued only to a client whose
//     `oauthAllowedScope` declares them and re-checked on every call
//     (`STS-VC-0101`). No mode predicate is read anywhere in this file.
//   * **RATE LIMITED** per client and per address, per realm
//     (`vcApi.maxPerWindow`, `STS-VC-0121`): each call canonicalizes JSON-LD
//     and signs or verifies, and an admitted client could otherwise spend
//     this service's CPU in a loop.
//   * **AN OPTION IT DOES NOT UNDERSTAND IS REFUSED** (`STS-VC-0122`), as
//     VCALM requires ("Implementations MUST throw an error on options or
//     values they do not understand"), each option's shape checked. It
//     closed a hole the test control had: `securedByEnvelope`, this file's
//     own flag for "an envelope already verified this", was read from the
//     CALLER's options, and a verify request carrying it was answered
//     `verified: true` with no proof checked. It is an argument now, never an
//     option.
//   * **THE STATUS-LIST "PUBLISH" LEFT** for `/admin-api` (`POST
//     /admin-api/vc-status/publish`, Admin Write, beside the controls on
//     Monitoring → Verifiable Credentials): it was the W3C suites' hook, a
//     list here is computed on every read, and an operation that does
//     nothing but say so is an operator's question, not a protocol's.
//
// THE ROUTES, under a realm's prefix:
//
//   GET  /vc-api/issuers                     this adapter's issuers (not a
//        VCALM endpoint: an implementation manifest's list of instances)
//   POST /vc-api/issuers/{issuer}/credentials/issue
//        {issuer} names the securing mechanism and the key (`ISSUERS`); the
//        credential's `issuer` must be that key's did:key. 201
//        `{ verifiableCredential }`.
//   POST /vc-api/holders/{holder}/presentations/prove   201
//   POST /vc-api/credentials/derive          201
//   POST /vc-api/credentials/verify          200/400 `{ verified, … }`
//   POST /vc-api/presentations/verify        200/400 `{ verified, … }`
//   POST /vc-api/credentials/status          a status change, 200
//   GET  /vc-api/resolve, /vc-api/dereference   DID resolution (#199)
//
// A ROUTE MODULE: `common/protocol_stack.ts` registers it after the
// verifier, whose libraries it reads. It requires only libraries.
// ---------------------------------------------------------------------------

import crypto = require('../common/crypto');
import app = require('../common/app');
import helpers = require('../common/helpers');
import config = require('../common/config');
import websecurity = require('../common/websecurity');
import errorCodes = require('../common/error_codes');
import stats = require('../common/admin_stats');
import realms = require('../common/realms');
import scopePolicy = require('../common/scope_policy');
import InstanceSlot = require('../common/instance_slot');
import validation = require('../common/validation');
import cacheRegistry = require('../common/cache_registry');
import dpop = require('../oauth-oidc/dpop');
import vcDataIntegrity = require('./vc_data_integrity');
import vcDataModel = require('./vc_data_model');
import vcJsonLd = require('./vc_jsonld');
import vcStatus = require('./vc_status');
import vcJoseCose = require('./vc_jose_cose');
import vcDidResolver = require('./vc_did_resolver');

type RouteApp = typeof app;

interface VcApiDeps {
  log: typeof helpers.log;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  isRevoked: (jti: unknown) => boolean;
  declares: (clientId: unknown, scope: string) => boolean;
  presentedAccessToken: (req: any, res: any, where?: string,
                         options?: any) => any;
  di: typeof vcDataIntegrity;
  model: typeof vcDataModel;
  jsonld: typeof vcJsonLd;
  status: typeof vcStatus;
  jose: typeof vcJoseCose;
  resolver: typeof vcDidResolver;
  issued: any;
  now: () => number;
  checkDocument: (value: any, where: string, opts?: any) => any;
  // Whether the ambient realm serves the VC API (`vcApi.enabled`, #598).
  enabled: () => boolean;
  // The rate limiter's shared count, and the ceiling (#598).
  attemptShared: typeof websecurity.attemptShared;
  maxPerWindow: () => number;
  realmId: () => string;
}

// The two scopes, protected in both modes (`common/scope_policy.ts`).
/**
 * The scope that allows issuing through the VC-API, `vc-api:issue`, protected
 * in both modes.
 */
const SCOPE_ISSUE = 'vc-api:issue';
/**
 * The scope that allows verifying through the VC-API, `vc-api:verify`,
 * protected in both modes.
 */
const SCOPE_VERIFY = 'vc-api:verify';

const BASE = '/vc-api';

// THE SHAPE OF EACH OPTION AN ENDPOINT READS (#598), for `optionsOf()`.
// `verificationMethod` is this adapter's extension for an envelope whose
// `kid` resolves to nothing (VC-JOSE-COSE leaves key discovery to the
// verifier): a did:key or did:jwk URL, or a PUBLIC JWK under
// `publicKeyJwk` — a member that would be a private key is refused rather
// than ignored, so nobody learns by accident that one was sent here.
// `disclosurePaths` is its other one, the VC-JOSE-COSE suite's selectively
// disclosable claims for an SD-JWT.
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k',
  'secretKeyJwk', 'privateKeyJwk', 'privateKeyMultibase', 'secretKeyMultibase'];

function isStringList(value: any): boolean {
  helpers.log.debug("Entering isStringList().");
  helpers.log.debug("Leaving isStringList().");
  return Array.isArray(value) && value.length <= 256 &&
    value.every(function (one: any) {
      return typeof one === 'string' && one.length <= 1024;
    });
}

function isShortString(value: any): boolean {
  helpers.log.debug("Entering isShortString().");
  helpers.log.debug("Leaving isShortString().");
  return typeof value === 'string' && value.length > 0 && value.length <= 2048;
}

function isDateTime(value: any): boolean {
  helpers.log.debug("Entering isDateTime().");
  helpers.log.debug("Leaving isDateTime().");
  return typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/
      .test(value) && !isNaN(Date.parse(value));
}

function isStatusOption(value: any): boolean {
  helpers.log.debug("Entering isStatusOption().");
  helpers.log.debug("Leaving isStatusOption().");
  return !!value && typeof value === 'object' && !Array.isArray(value) &&
    value.type === 'BitstringStatusListEntry' &&
    Object.keys(value).every(function (name: string) {
      return name === 'type' || name === 'statusPurpose';
    }) &&
    (value.statusPurpose === undefined ||
     value.statusPurpose === 'revocation' ||
     value.statusPurpose === 'suspension');
}

function isPublicMethod(value: any): boolean {
  helpers.log.debug("Entering isPublicMethod().");
  if (typeof value === 'string') {
    helpers.log.debug("Leaving isPublicMethod(). A URL.");
    return /^did:(key|jwk):/.test(value) && value.length <= 4096;
  }
  const ok = !!value && typeof value === 'object' && !Array.isArray(value) &&
    PRIVATE_MEMBERS.every(function (name: string) {
      return value[name] === undefined;
    }) &&
    (value.publicKeyJwk === undefined ||
     (!!value.publicKeyJwk && typeof value.publicKeyJwk === 'object' &&
      PRIVATE_MEMBERS.every(function (name: string) {
        return value.publicKeyJwk[name] === undefined;
      })));
  helpers.log.debug("Leaving isPublicMethod(). " + ok);
  return ok;
}

const OPTION_SHAPES: Record<string, (value: any) => boolean> = {
  credentialStatus: isStatusOption,
  mandatoryPointers: isStringList,
  selectivePointers: isStringList,
  disclosurePaths: isStringList,
  checks: isStringList,
  created: isDateTime,
  challenge: isShortString,
  domain: isShortString,
  verificationMethod: isPublicMethod
};

const OPTION_WORDS: Record<string, string> = {
  credentialStatus: '{ "type": "BitstringStatusListEntry", ' +
    '"statusPurpose"?: "revocation" | "suspension" }',
  mandatoryPointers: 'an array of JSON pointers',
  selectivePointers: 'an array of JSON pointers',
  disclosurePaths: 'an array of claim paths',
  checks: 'an array of check names',
  created: 'an XML Schema dateTime with a time zone',
  challenge: 'a non-empty string',
  domain: 'a non-empty string',
  verificationMethod: 'a did:key or did:jwk URL, or an object carrying a ' +
    'public publicKeyJwk and no private member'
};

// THE TWO DID QUERIES (#598): a single bounded string each, no control
// character, `function` one of DID Core 7.1's two — what
// `validation.check()` holds a query to. A string that is not a DID is the
// RESOLVER's to refuse (invalidDid, DID Core 7.1.2), with the result shape
// the DID suite reads, so it is not refused here.
const vz = validation.z;
const vt = validation.types;
const RESOLVE_QUERY = vz.object({
  did: vt.opt(vt.text),
  function: vt.opt(vt.oneOf(['resolve', 'resolveRepresentation'])),
  accept: vt.opt(vt.text)
});
const DEREFERENCE_QUERY = vz.object({
  didUrl: vt.opt(vt.text),
  accept: vt.opt(vt.text)
});

// The options each endpoint reads.
const ISSUE_OPTIONS = ['credentialStatus', 'mandatoryPointers', 'created',
                       'disclosurePaths'];
const PROVE_OPTIONS = ['challenge', 'domain', 'disclosurePaths'];
const DERIVE_OPTIONS = ['selectivePointers'];
const VERIFY_CREDENTIAL_OPTIONS = ['checks', 'verificationMethod'];
const VERIFY_PRESENTATION_OPTIONS = ['checks', 'challenge', 'domain',
                                     'verificationMethod'];

// THE ISSUERS: a securing mechanism and the realm key it signs with.
// `kind` 'di' is an embedded Data Integrity proof; 'jose' an ENVELOPE of
// VC-JOSE-COSE (#198), `form` saying which.
/**
 * The VC-API issuers by name: a securing mechanism — an embedded Data Integrity
 * proof (`di`) or a VC-JOSE-COSE envelope (`jose`) — and the realm key it signs
 * with.
 */
const ISSUERS: Record<string, { kind: string; cryptosuite?: string;
                                form?: string; curve: string }> = {
  'eddsa-rdfc-2022': { kind: 'di', cryptosuite: 'eddsa-rdfc-2022',
                       curve: 'Ed25519' },
  'eddsa-jcs-2022': { kind: 'di', cryptosuite: 'eddsa-jcs-2022',
                      curve: 'Ed25519' },
  'ecdsa-rdfc-2019-p256': { kind: 'di', cryptosuite: 'ecdsa-rdfc-2019',
                            curve: 'P-256' },
  'ecdsa-rdfc-2019-p384': { kind: 'di', cryptosuite: 'ecdsa-rdfc-2019',
                            curve: 'P-384' },
  'ecdsa-jcs-2019-p256': { kind: 'di', cryptosuite: 'ecdsa-jcs-2019',
                           curve: 'P-256' },
  'ecdsa-jcs-2019-p384': { kind: 'di', cryptosuite: 'ecdsa-jcs-2019',
                           curve: 'P-384' },
  'ecdsa-sd-2023-p256': { kind: 'di', cryptosuite: 'ecdsa-sd-2023',
                          curve: 'P-256' },
  'jose-p256': { kind: 'jose', form: 'jwt', curve: 'P-256' },
  'sd-jwt-p256': { kind: 'jose', form: 'sdjwt', curve: 'P-256' },
  'cose-p256': { kind: 'jose', form: 'cose', curve: 'P-256' }
};

// The statements an ecdsa-sd-2023 base proof makes mandatory when the
// request names none: who issued it and when it is valid, and its status —
// what a verifier needs to judge any disclosure at all. Each only where
// the credential has it (a pointer to nothing is an error, 3.4.12).
const DEFAULT_MANDATORY = ['/issuer', '/validFrom', '/validUntil',
  '/issuanceDate', '/expirationDate', '/credentialStatus'];

// What a Data Integrity proof may be on a credential presented here.
const VERIFIABLE_SUITES = ['eddsa-rdfc-2022', 'eddsa-jcs-2022',
  'ecdsa-rdfc-2019', 'ecdsa-jcs-2019', 'ecdsa-sd-2023', 'mldsa44-jcs-2024',
  'slhdsa128-jcs-2024'];

const DATA_INTEGRITY_V2 = 'https://w3id.org/security/data-integrity/v2';

// How long a status index an adapter credential takes is held, when the
// credential names no `validUntil` (a year, `vc_status.allocate()`'s own
// default).
const DEFAULT_STATUS_MS = 365 * 86400000;
// How many issued credentials a realm remembers for a status change.
const MAX_ISSUED = 4096;

// credential id -> { idx, expiresAt }. PER REALM, persisted, so a status
// change reaches the index whichever process issued the credential.
// `expiresAt` (#333): the credential's own `expiresAt`, ms.
const issued = realms.map({ persist: 'vc_api.issued',
                            expiresAt: realms.expiryField('expiresAt', 1) });

const issuedCount = cacheRegistry.register({
  name: 'vc-api.issued',
  title: 'VC-API credentials with a status',
  description: 'Each credential the W3C VC API issued with a ' +
    'status entry, and the status-list index it took, so that a status ' +
    'change can find it.',
  owner: 'oid4vc/vc_api.ts',
  scope: 'realm',
  kind: 'cache',
  persisted: true,
  hitMeaning: 'a status change found the credential',
  settings: [],
  maxEntries: function (): number {
    return MAX_ISSUED;
  },
  bound: 'Enforced: ' + MAX_ISSUED + ' credentials per realm, the oldest ' +
    'forgotten first (its status can then no longer be changed here; the ' +
    'list entry itself is vc_status.ts\'s and stays).',
  lifetime: function (): string {
    return 'the credential\'s validUntil, or a year.';
  },
  eject: cacheRegistry.realmMapEjector(realms, issued,
    function (row: any, id: unknown, now: number): boolean {
      return !!(row && row.expiresAt && row.expiresAt <= now);
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, issued,
      function (row: any, id: unknown): object {
        return { key: String(id),
                 validUntil: Number((row && row.expiresAt) || 0) || null };
      });
  }
});

/**
 * The W3C VC API over this service's own issuer and verifier machinery (#194
 * to #199, a product surface since #598): issue, verify, prove, derive, status
 * changes and DID resolution.
 *
 * An adapter to this service's own machinery, not a second copy of it.
 */
class VcApi {
  /**
   * The VC-API issuers by name, each with its securing mechanism and key.
   */
  static readonly ISSUERS = ISSUERS;
  /**
   * The scope that allows issuing, `vc-api:issue`.
   */
  static readonly SCOPE_ISSUE = SCOPE_ISSUE;
  /**
   * The scope that allows verifying, `vc-api:verify`.
   */
  static readonly SCOPE_VERIFY = SCOPE_VERIFY;

  /**
   * Builds the adapter from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: VcApiDeps) {
    deps.log.debug("Entering VcApi.constructor().");
    deps.log.debug("Leaving VcApi.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): VcApiDeps {
    helpers.log.debug("Entering VcApi.defaultDeps().");
    helpers.log.debug("Leaving VcApi.defaultDeps().");
    return {
      log: helpers.log,
      baseUrlOf: helpers.baseUrlOf,
      errorCodes: errorCodes,
      isRevoked: stats.isRevoked,
      declares: scopePolicy.declares,
      presentedAccessToken: dpop.presentedAccessToken,
      di: vcDataIntegrity,
      model: vcDataModel,
      jsonld: vcJsonLd,
      status: vcStatus,
      jose: vcJoseCose,
      resolver: vcDidResolver,
      issued: issued,
      checkDocument: validation.checkDocument,
      enabled: function enabled(): boolean {
        helpers.log.debug("Entering enabled().");
        helpers.log.debug("Leaving enabled().");
        return config.value('vcApi.enabled') === true;
      },
      attemptShared: websecurity.attemptShared,
      maxPerWindow: function maxPerWindow(): number {
        helpers.log.debug("Entering maxPerWindow().");
        helpers.log.debug("Leaving maxPerWindow().");
        return Number(config.value('vcApi.maxPerWindow'));
      },
      realmId: function realmId(): string {
        helpers.log.debug("Entering realmId().");
        helpers.log.debug("Leaving realmId().");
        return String(realms.currentId());
      },
      now: function now(): number {
        helpers.log.debug("Entering now().");
        helpers.log.debug("Leaving now().");
        return Date.now();
      }
    };
  }

  // A JSON answer.
  private send(res: any, status: number, body: any): void {
    const { log } = this.deps;
    log.debug("Entering VcApi.send(). " + status);
    res.set('Cache-Control', 'no-store');
    if (status === 204) {
      res.status(204).end();
    } else {
      res.status(status).type('application/json')
        .send(JSON.stringify(body, null, 2));
    }
    log.debug("Leaving VcApi.send().");
  }

  // A refusal, marked with its code and sent as the VC-API's error shape.
  // error-code: none — every caller passes the code, marked below.
  private refuse(res: any, status: number, code: string, message: string,
                 extra?: any): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcApi.refuse(). " + code);
    errorCodes.mark(res, code);
    // error-code: none — marked on the line above.
    this.send(res, status, Object.assign({
      errors: [{ message: message }], message: message }, extra || {}));
    log.debug("Leaving VcApi.refuse().");
  }

  // ---------------------------------------------------------------------------
  // THE REQUEST BODY: JSON (every body arrives as text, `common/app.js`), and
  // a document `validation.checkDocument()` accepts — no polluting key, a
  // bounded depth and size. Null when it has answered the request itself.
  // ---------------------------------------------------------------------------
  /**
   * Reads the request body as a JSON document `validation.checkDocument()`
   * accepts, answering the request itself when it is not.
   *
   * @param req - the request
   * @param res - the response
   * @returns the body, or null when the request has been answered
   */
  readBody(req: any, res: any): any {
    const { log, checkDocument } = this.deps;
    log.debug("Entering VcApi.readBody().");
    let body: any = req.body;
    if (typeof body === 'string' || Buffer.isBuffer(body)) {
      try {
        body = JSON.parse(String(body || '{}'));
      } catch (e) {
        log.debug("Caught in VcApi.readBody(): " + ((e && e.message) || e));
        this.refuse(res, 400, 'STS-VC-0108', 'The request body is not ' +
                    'JSON: ' + String((e && e.message) || e));
        log.debug("Leaving VcApi.readBody(). Not JSON.");
        return null;
      }
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      this.refuse(res, 400, 'STS-VC-0108', 'The request body is not a JSON ' +
                  'object.');
      log.debug("Leaving VcApi.readBody(). Not an object.");
      return null;
    }
    const checked = checkDocument(body, 'VC-API request', { maxDepth: 32 });
    if (!checked.ok) {
      this.refuse(res, 400, 'STS-VC-0108', checked.detail);
      log.debug("Leaving VcApi.readBody(). Refused by the document check.");
      return null;
    }
    log.debug("Leaving VcApi.readBody().");
    return body;
  }

  // ---------------------------------------------------------------------------
  // THE OFF SWITCH (#598): `vcApi.enabled`, per realm, off by default. Off,
  // the request is answered 501 BEFORE anything else is looked at — no token
  // is read, nothing is counted — with the VC API's error shape and
  // `STS-VC-0120`: `scim.enabled`'s answer, for its reason (the header).
  // Answers true when the realm serves the VC API; otherwise it has answered.
  // ---------------------------------------------------------------------------
  /**
   * The off switch: whether the ambient realm serves the VC API
   * (`vcApi.enabled`), answering 501 when it does not.
   *
   * @param res - the response
   * @returns true when the request may go on; otherwise it has been answered
   */
  served(res: any): boolean {
    const { log, enabled } = this.deps;
    log.debug("Entering VcApi.served().");
    if (enabled()) {
      log.debug("Leaving VcApi.served(). On.");
      return true;
    }
    this.refuse(res, 501, 'STS-VC-0120', 'The W3C VC API is turned off in ' +
                'this realm (vcApi.enabled).');
    log.debug("Leaving VcApi.served(). Off.");
    return false;
  }

  // ---------------------------------------------------------------------------
  // THE GATE: the access token, in every mode, and then the rate limit.
  // Answers true when the request may go on; otherwise it has answered.
  //
  // THE LIMIT IS COUNTED AFTER THE TOKEN, keyed by the client the token was
  // issued to, and that order is the point: an identity bucket keyed by
  // anything a caller could choose before it was authenticated would let it
  // mint a fresh bucket per request (`xacml.ts`'s PIP argues the same). The
  // address bucket beside it bounds the unauthenticated ones too, since
  // `presentedAccessToken()` is cheap and a refusal costs nothing more. Both
  // are counted PER REALM — the realm is in the bucket's name — because the
  // ceiling is the realm's own setting.
  // ---------------------------------------------------------------------------
  /**
   * The gate: an access token this realm issued, carrying the scope, and then
   * the rate limit, per client and per address.
   *
   * @param req - the request
   * @param res - the response
   * @param scope - the scope required
   * @returns a promise of true when the request may go on; otherwise it has
   *   been answered
   */
  async admitted(req: any, res: any, scope: string): Promise<boolean> {
    const { log, presentedAccessToken, isRevoked, declares, attemptShared,
            maxPerWindow, realmId } = this.deps;
    log.debug("Entering VcApi.admitted(). " + scope);
    const presented = presentedAccessToken(req, res, 'the W3C VC API',
                                           { requireVerified: true });
    if (!presented) {
      log.debug("Leaving VcApi.admitted(). The token check answered.");
      return false;
    }
    const claims = presented.claims || {};
    const scopes = String(claims.scope || '').split(/\s+/);
    let why = '';
    if (!presented.verified) {
      why = 'this access token was not issued by this realm';
    } else if (claims.typ && claims.typ !== 'Bearer') {
      why = 'this is a "' + claims.typ + '" token, not an access token';
    } else if (isRevoked(claims.jti)) {
      why = 'this access token was revoked';
    } else if (scopes.indexOf(scope) < 0) {
      why = 'this access token does not carry the ' + scope + ' scope';
    } else if (!declares(claims.client_id, scope)) {
      why = 'the client this token was issued to no longer declares ' +
            scope + ' (oauthAllowedScope)';
    }
    if (why) {
      res.set('WWW-Authenticate', 'Bearer error="' +
              (scopes.indexOf(scope) < 0 ? 'insufficient_scope' :
               'invalid_token') + '", scope="' + scope + '"');
      this.refuse(res, scopes.indexOf(scope) < 0 ? 403 : 401, 'STS-VC-0101',
                  'Refused: ' + why + '.');
      log.debug("Leaving VcApi.admitted(). " + why);
      return false;
    }
    const within = await attemptShared('vc-api:' + realmId(), req,
                                       String(claims.client_id || ''),
                                       maxPerWindow());
    if (!within.ok) {
      res.set('Retry-After', String(within.retryAfterS));
      this.refuse(res, 429, 'STS-VC-0121', 'Too many VC API calls. ' +
                  within.detail + ' The limit is ' + within.limit + ' per ' +
                  'rate-limit window on the ' + within.kind + ' bucket ' +
                  '(vcApi.maxPerWindow).');
      log.debug("Leaving VcApi.admitted(). Rate limited.");
      return false;
    }
    log.debug("Leaving VcApi.admitted(). Admitted.");
    return true;
  }

  // ---------------------------------------------------------------------------
  // THE OPTIONS A REQUEST MAY CARRY (#598). VCALM: "Implementations MUST
  // throw an error on options or values they do not understand." Each
  // endpoint names the options it reads and a check of each one's shape; an
  // option it does not name, or a value of the wrong shape, is refused 400
  // (`STS-VC-0122`) naming it. Absent `options` is `{}`.
  // ---------------------------------------------------------------------------
  /**
   * Reads a request's `options`, refusing one this endpoint does not
   * understand or whose value has the wrong shape.
   *
   * @param res - the response
   * @param body - the request body
   * @param allowed - the option names this endpoint reads
   * @returns the options, or null when the request has been answered
   */
  optionsOf(res: any, body: any, allowed: string[]): any {
    const { log } = this.deps;
    log.debug("Entering VcApi.optionsOf(). " + allowed.join(','));
    const options = body.options === undefined ? {} : body.options;
    let why = '';
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
      why = 'options must be a JSON object';
    } else {
      Object.keys(options).some(function (name: string): boolean {
        if (allowed.indexOf(name) < 0) {
          why = 'this endpoint does not understand the option ' +
                JSON.stringify(name) + '; it reads ' +
                (allowed.length ? allowed.join(', ') : 'none');
        } else if (!OPTION_SHAPES[name](options[name])) {
          why = 'options.' + name + ' must be ' + OPTION_WORDS[name];
        }
        return !!why;
      });
    }
    if (why) {
      this.refuse(res, 400, 'STS-VC-0122', 'Refused: ' + why + '.');
      log.debug("Leaving VcApi.optionsOf(). " + why);
      return null;
    }
    log.debug("Leaving VcApi.optionsOf().");
    return options;
  }

  // The issuer a name selects, with its key, or null.
  /**
   * Returns the issuer a name selects, with its key.
   *
   * @param name - the issuer's name
   * @returns the issuer, or null
   */
  issuerFor(name: string): any {
    const { log, di } = this.deps;
    log.debug("Entering VcApi.issuerFor(). " + name);
    const row = Object.prototype.hasOwnProperty.call(ISSUERS, name)
      ? ISSUERS[name] : null;
    if (!row) {
      log.debug("Leaving VcApi.issuerFor(). Unknown.");
      return null;
    }
    // THE VC API'S OWN KEY (#598), never the realm's token keys — see the
    // header.
    const key = di.vcApiKeyFor(row.curve);
    log.debug("Leaving VcApi.issuerFor().");
    return Object.assign({ name: name, key: key, id: key.did }, row);
  }

  // Every issuer, as the job's implementation manifest wants them.
  /**
   * Returns every issuer, as the suites' implementation manifest wants them.
   *
   * @param req - the request, for the issuers' URLs
   * @returns the issuers
   */
  issuers(req: any): any[] {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering VcApi.issuers().");
    const base = baseUrlOf(req);
    const out = Object.keys(ISSUERS).map((name) => {
      const one = this.issuerFor(name);
      return { name: name, id: one.id, kind: one.kind,
               cryptosuite: one.cryptosuite || '', curve: one.curve,
               endpoint: base + BASE + '/issuers/' + name +
                         '/credentials/issue' };
    });
    log.debug("Leaving VcApi.issuers().");
    return out;
  }

  // The credential's issuer id, from a string or an object.
  private issuerIdOf(credential: any): string {
    const { log } = this.deps;
    log.debug("Entering VcApi.issuerIdOf().");
    log.debug("Leaving VcApi.issuerIdOf().");
    return typeof credential.issuer === 'string' ? credential.issuer
      : (credential.issuer && typeof credential.issuer.id === 'string'
         ? credential.issuer.id : '');
  }

  // JSON-LD safe mode over the document: '' when it expands cleanly, the
  // reason otherwise.
  private async jsonLdProblem(document: any): Promise<string> {
    const { log, jsonld } = this.deps;
    log.debug("Entering VcApi.jsonLdProblem().");
    try {
      await jsonld.expand(document);
    } catch (e) {
      log.debug("Caught in VcApi.jsonLdProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcApi.jsonLdProblem(). Refused.");
      return 'JSON-LD processing in safe mode refused it: ' +
        String((e && e.message) || e) +
        (e && e.details && e.details.event && e.details.event.code
          ? ' (' + e.details.event.code + ')' : '');
    }
    log.debug("Leaving VcApi.jsonLdProblem(). Clean.");
    return '';
  }

  // ---------------------------------------------------------------------------
  // ISSUE.
  // ---------------------------------------------------------------------------
  /**
   * Handles `/credentials/issue`: secures the credential it is handed with the
   * named issuer.
   *
   * @param req - the request
   * @param res - the response
   */
  async issue(req: any, res: any): Promise<void> {
    const { log, model, di, status, baseUrlOf, now } = this.deps;
    log.debug("Entering VcApi.issue().");
    const issuer = this.issuerFor(String(req.params.issuer || ''));
    if (!issuer) {
      this.refuse(res, 404, 'STS-VC-0104', 'No issuer "' + req.params.issuer +
                  '" here; there are ' + Object.keys(ISSUERS).join(', ') +
                  '.');
      log.debug("Leaving VcApi.issue(). Unknown issuer.");
      return;
    }
    const body = this.readBody(req, res);
    if (!body) {
      log.debug("Leaving VcApi.issue(). The body was refused.");
      return;
    }
    const credential = body.credential;
    const options = this.optionsOf(res, body, ISSUE_OPTIONS);
    if (!options) {
      log.debug("Leaving VcApi.issue(). An option was refused.");
      return;
    }
    if (!credential || typeof credential !== 'object' ||
        Array.isArray(credential)) {
      this.refuse(res, 400, 'STS-VC-0102', 'The request names no ' +
                  'credential object ({ "credential": {…} }).');
      log.debug("Leaving VcApi.issue(). No credential.");
      return;
    }
    const checked = model.checkCredential(credential, {});
    if (!checked.ok) {
      this.refuse(res, 400, 'STS-VC-0102', 'This credential does not ' +
        'conform to the data model: ' + checked.problems.map(function (p) {
          return p.where + ': ' + p.message;
        }).join(' '), { problems: checked.problems });
      log.debug("Leaving VcApi.issue(). Data model.");
      return;
    }
    if (this.issuerIdOf(credential) !== issuer.id) {
      this.refuse(res, 400, 'STS-VC-0102', 'This issuer signs as ' +
                  issuer.id + '; the credential names ' +
                  JSON.stringify(credential.issuer) + ' as its issuer.');
      log.debug("Leaving VcApi.issue(). Another issuer.");
      return;
    }
    const document = JSON.parse(JSON.stringify(credential));
    // A 1.1 credential's context defines no DataIntegrityProof: the Data
    // Integrity context goes on the end, as the cryptosuites' examples do.
    const contexts = [].concat(document['@context']);
    if (issuer.kind === 'di' && model.versionOf(document) === '1.1' &&
        contexts.indexOf(DATA_INTEGRITY_V2) < 0) {
      document['@context'] = contexts.concat([DATA_INTEGRITY_V2]);
    }
    let idx = '';
    const wantsStatus = options.credentialStatus &&
      typeof options.credentialStatus === 'object' &&
      options.credentialStatus.type === 'BitstringStatusListEntry';
    if (wantsStatus && document.credentialStatus === undefined) {
      if (document.id === undefined) {
        document.id = 'urn:uuid:' + crypto.randomUuid();
      }
      const until = Date.parse(document.validUntil || '') || 0;
      const allocated = await status.allocate({ base: baseUrlOf(req),
        format: 'ldp_vc', configId: 'vc-api',
        expiresAt: until > now() ? until : now() + DEFAULT_STATUS_MS });
      idx = allocated.key;
      const purpose = options.credentialStatus.statusPurpose;
      document.credentialStatus = allocated.credentialStatus
        .filter(function (entry: any) {
          return !purpose || entry.statusPurpose === purpose;
        });
      if (document.credentialStatus.length === 1) {
        document.credentialStatus = document.credentialStatus[0];
      }
    }
    const problem = await this.jsonLdProblem(document);
    if (problem) {
      this.refuse(res, 400, 'STS-VC-0103', problem);
      log.debug("Leaving VcApi.issue(). JSON-LD.");
      return;
    }
    let mandatoryPointers: string[] = undefined;
    if (issuer.cryptosuite === 'ecdsa-sd-2023') {
      if (options.mandatoryPointers !== undefined &&
          (!Array.isArray(options.mandatoryPointers) ||
           options.mandatoryPointers.some(function (p: any) {
             return typeof p !== 'string';
           }))) {
        this.refuse(res, 400, 'STS-VC-0103', 'options.mandatoryPointers is ' +
                    'an array of JSON pointers.');
        log.debug("Leaving VcApi.issue(). Bad pointers.");
        return;
      }
      mandatoryPointers = options.mandatoryPointers !== undefined
        ? options.mandatoryPointers
        : DEFAULT_MANDATORY.filter(function (p) {
            return document[p.slice(1)] !== undefined;
          });
    }
    if (issuer.kind === 'jose') {
      await this.issueEnvelope(res, issuer, document, options, idx);
      log.debug("Leaving VcApi.issue(). An envelope.");
      return;
    }
    let secured: any;
    try {
      secured = await di.signDocument(document, {
        mandatoryPointers: mandatoryPointers,
        cryptosuite: issuer.cryptosuite, publicJwk: issuer.key.publicJwk,
        privateKey: issuer.key.privateKey,
        verificationMethod: issuer.key.verificationMethod,
        proofPurpose: 'assertionMethod',
        created: typeof options.created === 'string' ? options.created
                                                     : undefined });
    } catch (e) {
      log.debug("Caught in VcApi.issue(): " + ((e && e.message) || e));
      this.refuse(res, 400, 'STS-VC-0103', 'The credential could not be ' +
                  'secured: ' + String((e && e.message) || e));
      log.debug("Leaving VcApi.issue(). Signing failed.");
      return;
    }
    if (idx) {
      this.remember(secured.id, idx,
                    Date.parse(secured.validUntil || '') || 0);
    }
    this.send(res, 201, { verifiableCredential: secured });
    log.debug("Leaving VcApi.issue(). Issued by " + issuer.name + ".");
  }

  // The signer a VC-JOSE-COSE issuer or holder uses: the realm key, its
  // did:key verification method as the kid.
  private joseSigner(issuer: any): any {
    const { log } = this.deps;
    log.debug("Entering VcApi.joseSigner().");
    log.debug("Leaving VcApi.joseSigner().");
    return { privateKey: issuer.key.privateKey,
             publicJwk: issuer.key.publicJwk,
             kid: issuer.key.verificationMethod };
  }

  // A credential or presentation secured by an ENVELOPE (#198), in the
  // issuer's form. `options.disclosurePaths` names what an SD-JWT makes
  // selectively disclosable (`a.b[0]`, the VC-JOSE-COSE suite's syntax).
  private async secureEnvelope(issuer: any, document: any,
                               kind: 'vc' | 'vp', options: any):
    Promise<any> {
    const { log, jose } = this.deps;
    log.debug("Entering VcApi.secureEnvelope(). " + issuer.form);
    const signer = this.joseSigner(issuer);
    let secured: any;
    if (issuer.form === 'jwt') {
      secured = await jose.secureJwt(document, kind, signer);
    } else if (issuer.form === 'sdjwt') {
      const paths = Array.isArray(options.disclosurePaths)
        ? options.disclosurePaths.map(String) : [];
      secured = await jose.secureSdJwt(document, kind, signer, paths);
    } else {
      secured = await jose.secureCose(document, kind, signer);
    }
    log.debug("Leaving VcApi.secureEnvelope().");
    return jose.envelope(issuer.form, kind, secured);
  }

  private async issueEnvelope(res: any, issuer: any, document: any,
                              options: any, idx: string): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering VcApi.issueEnvelope().");
    let envelope: any;
    try {
      envelope = await this.secureEnvelope(issuer, document, 'vc', options);
    } catch (e) {
      log.debug("Caught in VcApi.issueEnvelope(): " + ((e && e.message) ||
                                                        e));
      this.refuse(res, 400, 'STS-VC-0103', 'The credential could not be ' +
                  'secured: ' + String((e && e.message) || e));
      log.debug("Leaving VcApi.issueEnvelope(). Refused.");
      return;
    }
    if (idx) {
      this.remember(document.id, idx,
                    Date.parse(document.validUntil || '') || 0);
    }
    this.send(res, 201, { verifiableCredential: envelope });
    log.debug("Leaving VcApi.issueEnvelope().");
  }

  // ---------------------------------------------------------------------------
  // PROVE (VC-API `/presentations/prove`): a presentation secured by one of
  // the holders — the same names as the issuers, and the same keys. The
  // presentation's `holder`, if it names one, must be that key's did:key;
  // `options.challenge` and `options.domain` go on a Data Integrity proof,
  // and on an envelope as its `nonce` and `aud`.
  // ---------------------------------------------------------------------------
  /**
   * Handles `/presentations/prove`: a presentation secured by the named holder,
   * with `challenge` and `domain` on its proof.
   *
   * @param req - the request
   * @param res - the response
   */
  async prove(req: any, res: any): Promise<void> {
    const { log, model, di } = this.deps;
    log.debug("Entering VcApi.prove().");
    const holder = this.issuerFor(String(req.params.holder || ''));
    if (!holder) {
      this.refuse(res, 404, 'STS-VC-0104', 'No holder "' + req.params.holder +
                  '" here; there are ' + Object.keys(ISSUERS).join(', ') +
                  '.');
      log.debug("Leaving VcApi.prove(). Unknown holder.");
      return;
    }
    const body = this.readBody(req, res);
    if (!body) {
      log.debug("Leaving VcApi.prove(). The body was refused.");
      return;
    }
    const presentation = body.presentation;
    const options = this.optionsOf(res, body, PROVE_OPTIONS);
    if (!options) {
      log.debug("Leaving VcApi.prove(). An option was refused.");
      return;
    }
    const checked = model.checkPresentation(presentation, {});
    if (!checked.ok) {
      this.refuse(res, 400, 'STS-VC-0102', 'This presentation does not ' +
        'conform to the data model: ' + checked.problems.map(function (p) {
          return p.where + ': ' + p.message;
        }).join(' '), { problems: checked.problems });
      log.debug("Leaving VcApi.prove(). Data model.");
      return;
    }
    const named = typeof presentation.holder === 'string'
      ? presentation.holder
      : (presentation.holder && presentation.holder.id) || '';
    if (named && named !== holder.id) {
      this.refuse(res, 400, 'STS-VC-0102', 'This holder presents as ' +
                  holder.id + '; the presentation names ' +
                  JSON.stringify(presentation.holder) + '.');
      log.debug("Leaving VcApi.prove(). Another holder.");
      return;
    }
    const document = JSON.parse(JSON.stringify(presentation));
    let out: any;
    try {
      if (holder.kind === 'jose') {
        if (typeof options.challenge === 'string') {
          document.nonce = options.challenge;
        }
        if (typeof options.domain === 'string') {
          document.aud = options.domain;
        }
        out = await this.secureEnvelope(holder, document, 'vp', options);
      } else {
        const problem = await this.jsonLdProblem(document);
        if (problem) {
          throw new Error(problem);
        }
        out = await di.signDocument(document, {
          cryptosuite: holder.cryptosuite, publicJwk: holder.key.publicJwk,
          privateKey: holder.key.privateKey,
          verificationMethod: holder.key.verificationMethod,
          proofPurpose: 'authentication',
          challenge: typeof options.challenge === 'string'
            ? options.challenge : undefined,
          domain: typeof options.domain === 'string' ? options.domain
                                                     : undefined });
      }
    } catch (e) {
      log.debug("Caught in VcApi.prove(): " + ((e && e.message) || e));
      this.refuse(res, 400, 'STS-VC-0103', 'The presentation could not be ' +
                  'secured: ' + String((e && e.message) || e));
      log.debug("Leaving VcApi.prove(). Refused.");
      return;
    }
    this.send(res, 201, { verifiablePresentation: out });
    log.debug("Leaving VcApi.prove(). By " + holder.name + ".");
  }

  // The status index an issued credential took, for a status change.
  private remember(id: string, idx: string, until: number): void {
    const { log, issued, now } = this.deps;
    log.debug("Entering VcApi.remember().");
    if (!issued.has(String(id))) {
      cacheRegistry.makeRoom(issued, MAX_ISSUED, { counter: issuedCount });
    }
    issued.set(String(id), { idx: idx,
      expiresAt: until > now() ? until : now() + DEFAULT_STATUS_MS });
    log.debug("Leaving VcApi.remember().");
  }

  // ---------------------------------------------------------------------------
  // VERIFY. Answers `{ verified, checks, warnings, errors }` — errors naming
  // what failed, each with a `message`.
  // ---------------------------------------------------------------------------
  /**
   * Verifies a credential: its data model, its proofs or envelope, and its
   * status.
   *
   * @param vc - the credential
   * @param options - the verification options
   * @param enveloped - true when an envelope this function opened already
   *   verified it; an ARGUMENT and never an option, since a caller who could
   *   set it would skip the proof check (#598)
   * @returns `{ verified, checks, warnings, errors }`
   */
  async verifyCredentialDocument(vc: any, options: any,
                                 enveloped?: boolean): Promise<any> {
    const { log, model, di, status, now, jose } = this.deps;
    log.debug("Entering VcApi.verifyCredentialDocument().");
    const errors: any[] = [];
    const warnings: any[] = [];
    const checks: string[] = [];
    const o = options || {};
    // AN ENVELOPE (#198): its shape, then what it secures, verified; the
    // credential inside is then held to everything below but a proof,
    // which it does not carry — the envelope is its securing mechanism.
    const types = vc && typeof vc === 'object' && vc.type !== undefined
      ? [].concat(vc.type) : [];
    if (types.indexOf('EnvelopedVerifiableCredential') >= 0 &&
        !enveloped) {
      const shape = model.checkCredential(vc, { enveloped: true });
      if (!shape.ok) {
        shape.problems.forEach(function (p: any) {
          errors.push({ type: 'MALFORMED_VALUE_ERROR', where: p.where,
                        message: p.message });
        });
        log.debug("Leaving VcApi.verifyCredentialDocument(). Envelope " +
                  "shape.");
        return { verified: false, checks: checks, warnings: warnings,
                 errors: errors };
      }
      const opened = await jose.verifyEnvelope(vc, 'vc',
        { verificationMethod: o.verificationMethod });
      checks.push('envelope');
      opened.warnings.forEach(function (w: string) {
        warnings.push({ message: w });
      });
      if (!opened.ok) {
        opened.errors.forEach(function (e: string) {
          errors.push({ type: 'PROOF_VERIFICATION_ERROR', message: e });
        });
        log.debug("Leaving VcApi.verifyCredentialDocument(). Envelope.");
        return { verified: false, checks: checks, warnings: warnings,
                 errors: errors };
      }
      const inner = await this.verifyCredentialDocument(opened.document, o,
                                                        true);
      log.debug("Leaving VcApi.verifyCredentialDocument(). Enveloped: " +
                inner.verified);
      return { verified: inner.verified, checks: checks.concat(inner.checks),
               warnings: warnings.concat(inner.warnings),
               errors: inner.errors };
    }
    const checked = model.checkCredential(vc, { atTime: now() });
    checked.problems.forEach(function (p: any) {
      errors.push({ type: 'MALFORMED_VALUE_ERROR', where: p.where,
                    message: p.message });
    });
    checked.warnings.forEach(function (w: string) {
      warnings.push({ message: w });
    });
    if (!checked.ok) {
      log.debug("Leaving VcApi.verifyCredentialDocument(). Data model.");
      return { verified: false, checks: checks, warnings: warnings,
               errors: errors };
    }
    const problem = await this.jsonLdProblem(vc);
    if (problem) {
      errors.push({ type: 'PARSING_ERROR', message: problem });
      log.debug("Leaving VcApi.verifyCredentialDocument(). JSON-LD.");
      return { verified: false, checks: checks, warnings: warnings,
               errors: errors };
    }
    const proofs = enveloped ? { ok: true, results: [] }
      : await di.verifyAllProofs(vc, {
        allowedCryptosuites: VERIFIABLE_SUITES,
        expectedPurpose: 'assertionMethod', expectedChallenge: null,
        expectedDomain: null, createdRequired: false });
    if (!enveloped) {
      checks.push('proof');
    }
    if (enveloped) {
      if (vc.proof !== undefined) {
        warnings.push({ message: 'an enveloped credential carries an ' +
                        'embedded proof as well; the envelope is what was ' +
                        'verified.' });
      }
    } else if (!proofs.ok) {
      errors.push({ type: 'PROOF_VERIFICATION_ERROR',
                    message: proofs.reason || this.proofFailures(proofs) });
    } else {
      // WHO SIGNED IT IS VALIDATION, NOT VERIFICATION (VCDM 2.0 section
      // 7.1 against 7.2): verification is that every proof verifies against
      // a key its verification method's controller authorizes for the
      // purpose, which is what `verifyAllProofs()` answered. Whether that
      // controller is one the verifier accepts as the issuer is a business
      // rule — the specifications' own test vectors name an https issuer
      // and sign with a did:key — so a credential no proof of which is by
      // a key its `issuer` identifier controls is VERIFIED with a warning
      // that says so, and the sign-in door (`vc_verifier.ts`) keeps its
      // own, stricter rule.
      const issuerId = this.issuerIdOf(vc);
      const byIssuer = proofs.results.some(function (r: any) {
        return r.controller === issuerId;
      });
      if (!byIssuer) {
        warnings.push({ message: 'no proof was made by a key the ' +
          'credential\'s issuer ' + issuerId + ' controls (they were made ' +
          'by ' + proofs.results.map(function (r: any) {
            return r.controller;
          }).join(', ') + '); whether that is the issuer is for the ' +
          'relying party to decide.' });
      }
    }
    const entries = vc.credentialStatus === undefined ? []
      : [].concat(vc.credentialStatus);
    const wantStatus = Array.isArray(o.checks)
      ? o.checks.indexOf('credentialStatus') >= 0 : entries.length > 0;
    if (wantStatus && !errors.length && entries.length) {
      checks.push('credentialStatus');
      const bitstrings = entries.filter(function (e: any) {
        return e && e.type === 'BitstringStatusListEntry';
      });
      if (bitstrings.length !== entries.length) {
        warnings.push({ message: 'a credentialStatus entry of a type other ' +
                        'than BitstringStatusListEntry was not checked.' });
      }
      if (bitstrings.length) {
        const answer = await status.checkPresented({ own: true,
          format: 'ldp_vc', credentialStatus: bitstrings, policy: 'all' });
        if (!answer.ok) {
          errors.push({ type: 'STATUS_VERIFICATION_ERROR',
                        message: answer.detail || answer.status });
        }
      }
    }
    log.debug("Leaving VcApi.verifyCredentialDocument(). " +
              errors.length + " error(s).");
    return { verified: !errors.length, checks: checks, warnings: warnings,
             errors: errors };
  }

  // The failed checks of a proof-set verification, as one sentence.
  private proofFailures(proofs: any): string {
    const { log } = this.deps;
    log.debug("Entering VcApi.proofFailures().");
    const failed: string[] = [];
    (proofs.results || []).forEach(function (r: any, i: number) {
      (r.checks || []).forEach(function (c: any) {
        if (!c.ok) {
          failed.push('proof ' + i + ', ' + c.name + ': ' + c.detail);
        }
      });
    });
    log.debug("Leaving VcApi.proofFailures().");
    return failed.join(' ') || 'the proof did not verify.';
  }

  /**
   * Verifies a presentation and every credential in it.
   *
   * @param vp - the presentation
   * @param options - the verification options, `challenge` and `domain` among
   *   them
   * @param enveloped - true when an envelope this function opened already
   *   verified it (an argument, never an option, #598)
   * @returns `{ verified, checks, warnings, errors }`
   */
  async verifyPresentationDocument(vp: any, options: any,
                                   enveloped?: boolean): Promise<any> {
    const { log, model, di, now, jose } = this.deps;
    log.debug("Entering VcApi.verifyPresentationDocument().");
    const o = options || {};
    const errors: any[] = [];
    const warnings: any[] = [];
    const checks: string[] = [];
    const types = vp && typeof vp === 'object' && vp.type !== undefined
      ? [].concat(vp.type) : [];
    if (types.indexOf('EnvelopedVerifiablePresentation') >= 0 &&
        !enveloped) {
      const shape = model.checkPresentation(vp, {});
      const opened = shape.ok ? await jose.verifyEnvelope(vp, 'vp',
        { verificationMethod: o.verificationMethod })
        : { ok: false, errors: shape.problems.map(function (p: any) {
              return p.where + ': ' + p.message;
            }), warnings: [], document: null };
      checks.push('envelope');
      opened.warnings.forEach(function (w: string) {
        warnings.push({ message: w });
      });
      if (opened.ok) {
        // The challenge and domain an enveloped presentation answers are
        // its `nonce` and `aud` claims.
        const d = opened.document;
        if (typeof o.challenge === 'string' && d.nonce !== o.challenge) {
          opened.errors.push('its nonce is ' + JSON.stringify(d.nonce) +
                             '; the challenge was "' + o.challenge + '".');
        }
        if (typeof o.domain === 'string' &&
            [].concat(d.aud === undefined ? [] : d.aud)
              .indexOf(o.domain) < 0) {
          opened.errors.push('its aud is ' + JSON.stringify(d.aud) +
                             '; the domain was "' + o.domain + '".');
        }
      }
      if (opened.errors.length) {
        opened.errors.forEach(function (e: string) {
          errors.push({ type: 'PROOF_VERIFICATION_ERROR', message: e });
        });
        log.debug("Leaving VcApi.verifyPresentationDocument(). Envelope.");
        return { verified: false, checks: checks, warnings: warnings,
                 errors: errors };
      }
      const inner = await this.verifyPresentationDocument(opened.document,
                                                          o, true);
      log.debug("Leaving VcApi.verifyPresentationDocument(). Enveloped: " +
                inner.verified);
      return { verified: inner.verified, checks: checks.concat(inner.checks),
               warnings: warnings.concat(inner.warnings),
               errors: inner.errors };
    }
    const checked = model.checkPresentation(vp, { atTime: now() });
    checked.problems.forEach(function (p: any) {
      errors.push({ type: 'MALFORMED_VALUE_ERROR', where: p.where,
                    message: p.message });
    });
    if (!checked.ok) {
      log.debug("Leaving VcApi.verifyPresentationDocument(). Data model.");
      return { verified: false, checks: checks, warnings: warnings,
               errors: errors };
    }
    const problem = await this.jsonLdProblem(vp);
    if (problem) {
      errors.push({ type: 'PARSING_ERROR', message: problem });
      log.debug("Leaving VcApi.verifyPresentationDocument(). JSON-LD.");
      return { verified: false, checks: checks, warnings: warnings,
               errors: errors };
    }
    const challenge = typeof o.challenge === 'string' ? o.challenge : null;
    const domain = typeof o.domain === 'string' ? o.domain : null;
    if (enveloped) {
      // Answered by the envelope, above.
    } else if (vp.proof === undefined) {
      if (challenge !== null || domain !== null) {
        errors.push({ type: 'PROOF_VERIFICATION_ERROR', message: 'the ' +
          'presentation carries no proof, so the challenge or domain asked ' +
          'for cannot have been answered.' });
      } else {
        warnings.push({ message: 'the presentation carries no proof: its ' +
                        'credentials were verified, and nothing about who ' +
                        'presented them.' });
      }
    } else {
      checks.push('proof');
      const proofs = await di.verifyAllProofs(vp, {
        allowedCryptosuites: VERIFIABLE_SUITES,
        expectedPurpose: 'authentication', expectedChallenge: challenge,
        expectedDomain: domain, createdRequired: false });
      if (!proofs.ok) {
        errors.push({ type: 'PROOF_VERIFICATION_ERROR',
                      message: proofs.reason || this.proofFailures(proofs) });
      }
    }
    const credentials = vp.verifiableCredential === undefined ? []
      : [].concat(vp.verifiableCredential);
    for (let i = 0; i < credentials.length; i++) {
      const one = await this.verifyCredentialDocument(credentials[i],
        { checks: o.checks, verificationMethod: o.verificationMethod });
      one.errors.forEach(function (e: any) {
        errors.push(Object.assign({}, e, { message: 'verifiableCredential[' +
          i + ']: ' + e.message }));
      });
      one.warnings.forEach(function (w: any) {
        warnings.push(w);
      });
    }
    log.debug("Leaving VcApi.verifyPresentationDocument(). " +
              errors.length + " error(s).");
    return { verified: !errors.length, checks: checks, warnings: warnings,
             errors: errors };
  }

  // ---------------------------------------------------------------------------
  // A STATUS CHANGE: `{ credentialId, credentialStatus: { type,
  // statusPurpose }, status? }` — `status` true (the default) sets the bit
  // for the purpose, false clears a suspension. Revocation is final
  // (`vc_status.setStatus()`).
  // ---------------------------------------------------------------------------
  /**
   * Handles `/credentials/status`: sets or clears a credential's status bit for
   * a purpose. Revocation is final.
   *
   * @param req - the request
   * @param res - the response
   */
  changeStatus(req: any, res: any): void {
    const { log, issued, status, now } = this.deps;
    log.debug("Entering VcApi.changeStatus().");
    const body = this.readBody(req, res);
    if (!body) {
      log.debug("Leaving VcApi.changeStatus(). The body was refused.");
      return;
    }
    const cs = body.credentialStatus || {};
    const row = typeof body.credentialId === 'string'
      ? issued.get(body.credentialId) : null;
    if (row) {
      issuedCount.hit();
    } else {
      issuedCount.miss();
    }
    if (!row || (row.expiresAt && row.expiresAt < now())) {
      this.refuse(res, 404, 'STS-VC-0107', 'No credential ' +
                  JSON.stringify(body.credentialId) + ' was issued here ' +
                  'with a status.');
      log.debug("Leaving VcApi.changeStatus(). Unknown credential.");
      return;
    }
    if (cs.type !== 'BitstringStatusListEntry' ||
        (cs.statusPurpose !== 'revocation' &&
         cs.statusPurpose !== 'suspension')) {
      this.refuse(res, 400, 'STS-VC-0107', 'credentialStatus must be ' +
                  '{ "type": "BitstringStatusListEntry", "statusPurpose": ' +
                  '"revocation" | "suspension" }.');
      log.debug("Leaving VcApi.changeStatus(). Bad request.");
      return;
    }
    const set = body.status === undefined ? true : body.status === true;
    const wanted = !set ? vcStatus.VcStatus.VALID
      : (cs.statusPurpose === 'suspension' ? vcStatus.VcStatus.SUSPENDED
                                           : vcStatus.VcStatus.INVALID);
    const current = status.statusOf(row.idx);
    if (current !== wanted) {
      if (!set && current === vcStatus.VcStatus.INVALID) {
        this.refuse(res, 400, 'STS-VC-0107', 'A revoked credential stays ' +
                    'revoked.');
        log.debug("Leaving VcApi.changeStatus(). Revocation is final.");
        return;
      }
      status.setStatus(row.idx, wanted, 'the VC-API status endpoint');
    }
    this.send(res, 200, { credentialId: body.credentialId,
      credentialStatus: cs, status: set });
    log.debug("Leaving VcApi.changeStatus().");
  }

  // ---------------------------------------------------------------------------
  // DERIVE (VC-API `/credentials/derive`): an ecdsa-sd-2023 derived proof
  // revealing the mandatory statements and `options.selectivePointers` —
  // the holder's act, offered so that a base proof issued here can be taken
  // to a verifier. 201 `{ verifiableCredential }`.
  // ---------------------------------------------------------------------------
  /**
   * Handles `/credentials/derive`: an ecdsa-sd-2023 derived proof revealing the
   * mandatory statements and the selective pointers.
   *
   * @param req - the request
   * @param res - the response
   */
  async derive(req: any, res: any): Promise<void> {
    const { log, di } = this.deps;
    log.debug("Entering VcApi.derive().");
    const body = this.readBody(req, res);
    if (!body) {
      log.debug("Leaving VcApi.derive(). The body was refused.");
      return;
    }
    const vc = body.verifiableCredential;
    const options = this.optionsOf(res, body, DERIVE_OPTIONS);
    if (!options) {
      log.debug("Leaving VcApi.derive(). An option was refused.");
      return;
    }
    const pointers = options.selectivePointers;
    if (!vc || typeof vc !== 'object' || Array.isArray(vc)) {
      this.refuse(res, 400, 'STS-VC-0103', 'A derive request is { ' +
                  '"verifiableCredential": {…}, "options": { ' +
                  '"selectivePointers": [ JSON pointers ] } }.');
      log.debug("Leaving VcApi.derive(). Malformed.");
      return;
    }
    let derived: any;
    try {
      derived = await di.deriveProof(vc, pointers || []);
    } catch (e) {
      log.debug("Caught in VcApi.derive(): " + ((e && e.message) || e));
      this.refuse(res, 400, 'STS-VC-0103', 'No proof could be derived: ' +
                  String((e && e.message) || e));
      log.debug("Leaving VcApi.derive(). Refused.");
      return;
    }
    this.send(res, 201, { verifiableCredential: derived });
    log.debug("Leaving VcApi.derive().");
  }

  // A query parameter as one string, or undefined (a repeated one refused
  // by treating it as absent — the caller then gets the error it earned).
  private queryString(req: any, name: string): string {
    const { log } = this.deps;
    log.debug("Entering VcApi.queryString(). " + name);
    const v = req.query ? req.query[name] : undefined;
    log.debug("Leaving VcApi.queryString().");
    return typeof v === 'string' ? v : undefined;
  }

  /**
   * Handles `/resolve`: DID resolution through `vc_did_resolver.ts`.
   *
   * @param req - the request
   * @param res - the response
   */
  async resolveDid(req: any, res: any): Promise<void> {
    const { log, resolver, errorCodes } = this.deps;
    log.debug("Entering VcApi.resolveDid().");
    const query = validation.check(req, 'query', RESOLVE_QUERY);
    if (!query.ok) {
      this.refuse(res, 400, 'STS-VC-0108', 'Refused: ' + query.detail);
      log.debug("Leaving VcApi.resolveDid(). The query was refused.");
      return;
    }
    const did = this.queryString(req, 'did') || '';
    const fn = this.queryString(req, 'function') || 'resolve';
    const accept = this.queryString(req, 'accept');
    const options = accept === undefined ? {} : { accept: accept };
    const out = fn === 'resolveRepresentation'
      ? await resolver.resolveRepresentation(did, options, req)
      : await resolver.resolve(did, options, req);
    const error = out.didResolutionMetadata.error;
    if (error) {
      errorCodes.mark(res, 'STS-VC-0109');
    }
    // error-code: none — marked above when it is a refusal.
    this.send(res, !error ? 200 : (error === 'notFound' ? 404
      : (error === 'methodNotSupported' ||
         error === 'representationNotSupported' ? 501 : 400)), out);
    log.debug("Leaving VcApi.resolveDid(). " + (error || 'resolved'));
  }

  /**
   * Handles `/dereference`: DID URL dereferencing through `vc_did_resolver.ts`.
   *
   * @param req - the request
   * @param res - the response
   */
  async dereferenceDidUrl(req: any, res: any): Promise<void> {
    const { log, resolver, errorCodes } = this.deps;
    log.debug("Entering VcApi.dereferenceDidUrl().");
    const query = validation.check(req, 'query', DEREFERENCE_QUERY);
    if (!query.ok) {
      this.refuse(res, 400, 'STS-VC-0108', 'Refused: ' + query.detail);
      log.debug("Leaving VcApi.dereferenceDidUrl(). The query was refused.");
      return;
    }
    const accept = this.queryString(req, 'accept');
    const out = await resolver.dereference(
      this.queryString(req, 'didUrl') || '',
      accept === undefined ? {} : { accept: accept }, req);
    const error = out.dereferencingMetadata.error;
    if (error) {
      errorCodes.mark(res, 'STS-VC-0109');
    }
    // error-code: none — marked above when it is a refusal.
    this.send(res, !error ? 200 : (error === 'notFound' ? 404
      : (error === 'methodNotSupported' ? 501 : 400)), out);
    log.debug("Leaving VcApi.dereferenceDidUrl(). " + (error || 'found'));
  }

  // A verification's answer, as an HTTP response: 200 when verified, 400
  // with the errors when not.
  private answerVerification(res: any, result: any, code: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcApi.answerVerification(). " + result.verified);
    if (!result.verified) {
      errorCodes.mark(res, code);
    }
    // error-code: none — marked above when it is a refusal.
    this.send(res, result.verified ? 200 : 400, result);
    log.debug("Leaving VcApi.answerVerification().");
  }

  // A route's promise, with a failure answered rather than left hanging.
  private run(res: any, work: Promise<void>): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcApi.run().");
    const self = this;
    work.catch(function (e: any) {
      log.debug("Caught in VcApi.run(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-VC-0105') + 'vc_api: a request failed: ' +
                ((e && (e.stack || e.message)) || e));
      if (!res.headersSent) {
        self.refuse(res, 500, 'STS-VC-0105', 'The request could not be ' +
                    'completed.');
      }
    });
    log.debug("Leaving VcApi.run().");
  }

  // ---------------------------------------------------------------------------
  // ONE ROUTE'S HANDLER: the off switch, then the gate, then the work — each
  // answering the request itself when it stops it, and a failure in any of
  // them answered by `run()` rather than left hanging.
  // ---------------------------------------------------------------------------
  /**
   * Builds a route's handler: the off switch (`served()`), the gate
   * (`admitted()`) for the scope, then the work.
   *
   * @param name - the route, for the log
   * @param scope - the scope the route requires
   * @param work - what the route does once admitted
   * @returns the express handler
   */
  handler(name: string, scope: string,
          work: (req: any, res: any) => Promise<void> | void):
    (req: any, res: any) => void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering VcApi.handler(). " + name);
    log.debug("Leaving VcApi.handler().");
    return function vcApiRoute(req: any, res: any): void {
      log.debug("Entering " + name + ".");
      if (self.served(res)) {
        self.run(res, self.admitted(req, res, scope)
          .then(function (admitted: boolean): Promise<void> | void {
            return admitted ? work(req, res) : undefined;
          }));
      }
      log.debug("Leaving " + name + ".");
    };
  }

  // A verification route's work: the body, its options, the verification.
  private verifyWork(member: string, allowed: string[],
                     verify: (doc: any, options: any) => Promise<any>):
    (req: any, res: any) => Promise<void> | void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering VcApi.verifyWork(). " + member);
    log.debug("Leaving VcApi.verifyWork().");
    return function verifyRoute(req: any, res: any): Promise<void> | void {
      log.debug("Entering verifyRoute(). " + member);
      const body = self.readBody(req, res);
      const options = body && self.optionsOf(res, body, allowed);
      if (!options) {
        log.debug("Leaving verifyRoute(). Answered.");
        return undefined;
      }
      log.debug("Leaving verifyRoute().");
      return verify(body[member], options).then(function (result: any) {
        self.answerVerification(res, result, 'STS-VC-0106');
      });
    };
  }

  /**
   * Registers the VC API's routes under `/vc-api`. Each is registered in
   * every realm and answers 501 where `vcApi.enabled` is off (#598).
   *
   * Called by `common/protocol_stack.ts`.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: RouteApp): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering VcApi.registerRoutes().");
    app.post(BASE + '/issuers/:issuer/credentials/issue',
      this.handler('POST ' + BASE + '/issuers/:issuer/credentials/issue',
                   SCOPE_ISSUE, function (req, res) {
        return self.issue(req, res);
      }));
    app.get(BASE + '/issuers',
      this.handler('GET ' + BASE + '/issuers', SCOPE_ISSUE,
                   function (req, res) {
        self.send(res, 200, { issuers: self.issuers(req) });
      }));
    app.post(BASE + '/credentials/verify',
      this.handler('POST ' + BASE + '/credentials/verify', SCOPE_VERIFY,
        this.verifyWork('verifiableCredential', VERIFY_CREDENTIAL_OPTIONS,
          function (doc: any, options: any): Promise<any> {
            return self.verifyCredentialDocument(doc, options);
          })));
    app.post(BASE + '/presentations/verify',
      this.handler('POST ' + BASE + '/presentations/verify', SCOPE_VERIFY,
        this.verifyWork('verifiablePresentation', VERIFY_PRESENTATION_OPTIONS,
          function (doc: any, options: any): Promise<any> {
            return self.verifyPresentationDocument(doc, options);
          })));
    app.post(BASE + '/holders/:holder/presentations/prove',
      this.handler('POST ' + BASE + '/holders/:holder/presentations/prove',
                   SCOPE_ISSUE, function (req, res) {
        return self.prove(req, res);
      }));
    app.post(BASE + '/credentials/derive',
      this.handler('POST ' + BASE + '/credentials/derive', SCOPE_ISSUE,
                   function (req, res) {
        return self.derive(req, res);
      }));
    app.post(BASE + '/credentials/status',
      this.handler('POST ' + BASE + '/credentials/status', SCOPE_ISSUE,
                   function (req, res) {
        self.changeStatus(req, res);
      }));
    // DID RESOLUTION AND DEREFERENCING (#199): DID Core section 7's two
    // functions over `vc_did_resolver.ts`, answering its result structures
    // as JSON. `function` is resolve (the default) or resolveRepresentation.
    // Nothing is fetched: did:key, did:jwk and this realm's own did:web.
    app.get(BASE + '/resolve',
      this.handler('GET ' + BASE + '/resolve', SCOPE_VERIFY,
                   function (req, res) {
        return self.resolveDid(req, res);
      }));
    app.get(BASE + '/dereference',
      this.handler('GET ' + BASE + '/dereference', SCOPE_VERIFY,
                   function (req, res) {
        return self.dereferenceDidUrl(req, res);
      }));
    log.debug("Leaving VcApi.registerRoutes().");
  }
}

const slot = new InstanceSlot<VcApi>(
  'oid4vc/vc_api',
  () => new VcApi(VcApi.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The W3C VC API over this service's own issuer and verifier machinery, off
 * until a realm turns it on (`vcApi.enabled`, #598).
 *
 * @namespace
 */
export = {
  VcApi: VcApi,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: VcApi): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  ISSUERS: ISSUERS,
  SCOPE_ISSUE: SCOPE_ISSUE,
  SCOPE_VERIFY: SCOPE_VERIFY,
  issuers: slot.forward('issuers'),
  verifyCredentialDocument: slot.forward('verifyCredentialDocument'),
  verifyPresentationDocument: slot.forward('verifyPresentationDocument')
};
