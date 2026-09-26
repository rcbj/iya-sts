'use strict';
//
// File: vc_api.ts
//
// ---------------------------------------------------------------------------
// THE W3C VC-API TEST ENDPOINTS, OVER THIS SERVICE'S OWN ISSUER AND VERIFIER
// (#194-#199, 2026-09-26). A TEST CONTROL.
//
// The W3C Verifiable Credentials Working Group's interoperability suites —
// the VC Data Model 2.0, Data Integrity EdDSA and ECDSA, Bitstring Status
// List and VC-JOSE-COSE suites — drive an implementation through the
// endpoints the W3C CCG's VC-API defines: an issuer that secures a
// credential it is HANDED (`/credentials/issue`), a verifier that checks
// one (`/credentials/verify`, `/presentations/verify`), and a status change
// (`/credentials/status`). This service issues through OpenID4VCI and
// verifies through OpenID4VP, and neither protocol secures a document a
// caller wrote: the issuer builds a credential from a directory entry and
// the Verifier judges a presentation against the query it asked. So this
// file is an ADAPTER, and what it adapts to is this service's own machinery,
// not a second copy of it:
//
//   * the signing is `vc_data_integrity.ts`'s (every cryptosuite the suites
//     ask for, held to the specifications' own vectors in `tests/`), with the
//     realm's own keys (`realmKeyFor()` — the key set's Ed25519, P-256 and
//     P-384 members, made at run time, sealed in product, agreed across
//     processes) named by their did:key;
//   * a credential's status is an index `vc_status.ts` allocates in the
//     realm's own Bitstring Status Lists, and a status change is
//     `setStatus()` — the act `/admin/vc-status` performs, one of the three
//     ways a credential is DISOWNED (`CLAUDE.md` 3ar);
//   * the data model's MUSTs are `vc_data_model.ts`, and the JSON-LD safe
//     mode that refuses an undefined term or a redefined protected one is
//     `vc_jsonld.ts`'s closed loader, which fetches nothing.
//
// **A TEST CONTROL, SO NEVER IN PRODUCT** (`mode.opensTestControls()`): an
// endpoint that signs, with a realm's key, any document its caller writes is
// what a test suite needs and what no deployment should expose. In a realm
// whose mode is product every route here answers 404 (`STS-VC-0100`), as
// though it did not exist.
//
// **AUTHENTICATED ALL THE SAME**, the way the suites allow
// (`vc-test-suite-implementations`: none, a zcap, or an OAuth 2.0 client
// credentials token): an access token THIS realm issued, verified, not
// revoked, carrying `vc-api:issue` (issue, status) or `vc-api:verify`
// (verify) — this service's own protected scopes (`common/scope_policy.ts`),
// issued only to a client whose `oauthAllowedScope` declares them and
// re-checked on every call (`STS-VC-0101`). A development realm is still no
// reason for a signing oracle anybody on the network can reach.
//
// THE ROUTES, under a realm's prefix:
//
//   POST /vc-api/issuers/{issuer}/credentials/issue
//        {issuer} names the securing mechanism and the key (`ISSUERS`); the
//        credential's `issuer` must be that key's did:key. 201
//        `{ verifiableCredential }`.
//   POST /vc-api/credentials/verify         200/400 `{ verified, … }`
//   POST /vc-api/presentations/verify       200/400 `{ verified, … }`
//   POST /vc-api/credentials/status         a status change, 200
//   POST /oid4vci/status-lists/bitstring/{purpose}/publish
//        the suites' "publish the list now"; a list here is computed on every
//        read, so 204 and nothing else.
//
// A ROUTE MODULE: `common/protocol_stack.ts` registers it after the
// verifier, whose libraries it reads. It requires only libraries.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import app = require('../common/app');
import helpers = require('../common/helpers');
import mode = require('../common/mode');
import errorCodes = require('../common/error_codes');
import stats = require('../common/admin_stats');
import realms = require('../common/realms');
import scopePolicy = require('../common/scope_policy');
import InstanceSlot = require('../common/instance_slot');
import validation = require('../common/validation');
import dpop = require('../oauth-oidc/dpop');
import vcDataIntegrity = require('./vc_data_integrity');
import vcDataModel = require('./vc_data_model');
import vcJsonLd = require('./vc_jsonld');
import vcStatus = require('./vc_status');
import vcJoseCose = require('./vc_jose_cose');

type RouteApp = typeof app;

interface VcApiDeps {
  log: typeof helpers.log;
  baseUrlOf: typeof helpers.baseUrlOf;
  opensTestControls: () => boolean;
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
  issued: any;
  now: () => number;
  checkDocument: (value: any, where: string, opts?: any) => any;
}

// The two scopes, protected in both modes (`common/scope_policy.ts`).
const SCOPE_ISSUE = 'vc-api:issue';
const SCOPE_VERIFY = 'vc-api:verify';

const BASE = '/vc-api';
const PUBLISH_PATH = '/oid4vci/status-lists/bitstring/:purpose/publish';

// THE ISSUERS: a securing mechanism and the realm key it signs with.
// `kind` 'di' is an embedded Data Integrity proof; 'jose' an ENVELOPE of
// VC-JOSE-COSE (#198), `form` saying which.
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
const issued = realms.map({ persist: 'vc_api.issued' });

class VcApi {
  static readonly ISSUERS = ISSUERS;
  static readonly SCOPE_ISSUE = SCOPE_ISSUE;
  static readonly SCOPE_VERIFY = SCOPE_VERIFY;

  constructor(private readonly deps: VcApiDeps) {
    deps.log.debug("Entering VcApi.constructor().");
    deps.log.debug("Leaving VcApi.constructor().");
  }

  static defaultDeps(): VcApiDeps {
    helpers.log.debug("Entering VcApi.defaultDeps().");
    helpers.log.debug("Leaving VcApi.defaultDeps().");
    return {
      log: helpers.log,
      baseUrlOf: helpers.baseUrlOf,
      opensTestControls: mode.opensTestControls,
      errorCodes: errorCodes,
      isRevoked: stats.isRevoked,
      declares: scopePolicy.declares,
      presentedAccessToken: dpop.presentedAccessToken,
      di: vcDataIntegrity,
      model: vcDataModel,
      jsonld: vcJsonLd,
      status: vcStatus,
      jose: vcJoseCose,
      issued: issued,
      checkDocument: validation.checkDocument,
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
  // THE GATE: a test control (404 outside one), then the access token.
  // Answers true when the request may go on; otherwise it has answered.
  // ---------------------------------------------------------------------------
  admitted(req: any, res: any, scope: string): boolean {
    const { log, opensTestControls, presentedAccessToken, isRevoked,
            declares } = this.deps;
    log.debug("Entering VcApi.admitted(). " + scope);
    if (!opensTestControls()) {
      this.refuse(res, 404, 'STS-VC-0100', 'Not found.');
      log.debug("Leaving VcApi.admitted(). Test controls are closed.");
      return false;
    }
    const presented = presentedAccessToken(req, res, 'the VC-API ' +
      'test endpoints', { requireVerified: true });
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
    log.debug("Leaving VcApi.admitted(). Admitted.");
    return true;
  }

  // The issuer a name selects, with its key, or null.
  issuerFor(name: string): any {
    const { log, di } = this.deps;
    log.debug("Entering VcApi.issuerFor(). " + name);
    const row = Object.prototype.hasOwnProperty.call(ISSUERS, name)
      ? ISSUERS[name] : null;
    if (!row) {
      log.debug("Leaving VcApi.issuerFor(). Unknown.");
      return null;
    }
    const key = di.realmKeyFor(row.curve);
    log.debug("Leaving VcApi.issuerFor().");
    return Object.assign({ name: name, key: key, id: key.did }, row);
  }

  // Every issuer, as the job's implementation manifest wants them.
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
    const options = (body && body.options && typeof body.options ===
                     'object') ? body.options : {};
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
        document.id = 'urn:uuid:' + crypto.randomUUID();
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
    const options = (body.options && typeof body.options === 'object')
      ? body.options : {};
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
    if (issued.size >= MAX_ISSUED) {
      issued.delete(issued.keys().next().value);
    }
    issued.set(String(id), { idx: idx,
      expiresAt: until > now() ? until : now() + DEFAULT_STATUS_MS });
    log.debug("Leaving VcApi.remember().");
  }

  // ---------------------------------------------------------------------------
  // VERIFY. Answers `{ verified, checks, warnings, errors }` — errors naming
  // what failed, each with a `message`.
  // ---------------------------------------------------------------------------
  async verifyCredentialDocument(vc: any, options: any): Promise<any> {
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
        !o.securedByEnvelope) {
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
      const inner = await this.verifyCredentialDocument(opened.document,
        Object.assign({}, o, { securedByEnvelope: true }));
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
    const proofs = o.securedByEnvelope ? { ok: true, results: [] }
      : await di.verifyAllProofs(vc, {
        allowedCryptosuites: VERIFIABLE_SUITES,
        expectedPurpose: 'assertionMethod', expectedChallenge: null,
        expectedDomain: null, createdRequired: false });
    if (!o.securedByEnvelope) {
      checks.push('proof');
    }
    if (o.securedByEnvelope) {
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

  async verifyPresentationDocument(vp: any, options: any): Promise<any> {
    const { log, model, di, now, jose } = this.deps;
    log.debug("Entering VcApi.verifyPresentationDocument().");
    const o = options || {};
    const errors: any[] = [];
    const warnings: any[] = [];
    const checks: string[] = [];
    const types = vp && typeof vp === 'object' && vp.type !== undefined
      ? [].concat(vp.type) : [];
    if (types.indexOf('EnvelopedVerifiablePresentation') >= 0 &&
        !o.securedByEnvelope) {
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
        Object.assign({}, o, { securedByEnvelope: true }));
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
    if (o.securedByEnvelope) {
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
  async derive(req: any, res: any): Promise<void> {
    const { log, di } = this.deps;
    log.debug("Entering VcApi.derive().");
    const body = this.readBody(req, res);
    if (!body) {
      log.debug("Leaving VcApi.derive(). The body was refused.");
      return;
    }
    const vc = body.verifiableCredential;
    const pointers = body.options && body.options.selectivePointers;
    if (!vc || typeof vc !== 'object' || (pointers !== undefined &&
        (!Array.isArray(pointers) || pointers.some(function (p: any) {
          return typeof p !== 'string';
        })))) {
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

  registerRoutes(app: RouteApp): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering VcApi.registerRoutes().");
    app.post(BASE + '/issuers/:issuer/credentials/issue', function (req, res) {
      log.debug("Entering POST " + BASE + "/issuers/:issuer/credentials/" +
                "issue.");
      if (self.admitted(req, res, SCOPE_ISSUE)) {
        self.run(res, self.issue(req, res));
      }
      log.debug("Leaving POST " + BASE + "/issuers/:issuer/credentials/" +
                "issue.");
    });
    app.get(BASE + '/issuers', function (req, res) {
      log.debug("Entering GET " + BASE + "/issuers.");
      if (self.admitted(req, res, SCOPE_ISSUE)) {
        self.send(res, 200, { issuers: self.issuers(req) });
      }
      log.debug("Leaving GET " + BASE + "/issuers.");
    });
    app.post(BASE + '/credentials/verify', function (req, res) {
      log.debug("Entering POST " + BASE + "/credentials/verify.");
      const body = self.admitted(req, res, SCOPE_VERIFY) &&
        self.readBody(req, res);
      if (body) {
        self.run(res, self.verifyCredentialDocument(body.verifiableCredential,
          body.options).then(function (result: any) {
          self.answerVerification(res, result, 'STS-VC-0106');
        }));
      }
      log.debug("Leaving POST " + BASE + "/credentials/verify.");
    });
    app.post(BASE + '/presentations/verify', function (req, res) {
      log.debug("Entering POST " + BASE + "/presentations/verify.");
      const body = self.admitted(req, res, SCOPE_VERIFY) &&
        self.readBody(req, res);
      if (body) {
        self.run(res, self.verifyPresentationDocument(
          body.verifiablePresentation, body.options)
          .then(function (result: any) {
            self.answerVerification(res, result, 'STS-VC-0106');
          }));
      }
      log.debug("Leaving POST " + BASE + "/presentations/verify.");
    });
    app.post(BASE + '/holders/:holder/presentations/prove',
             function (req, res) {
      log.debug("Entering POST " + BASE + "/holders/:holder/presentations/" +
                "prove.");
      if (self.admitted(req, res, SCOPE_ISSUE)) {
        self.run(res, self.prove(req, res));
      }
      log.debug("Leaving POST " + BASE + "/holders/:holder/presentations/" +
                "prove.");
    });
    app.post(BASE + '/credentials/derive', function (req, res) {
      log.debug("Entering POST " + BASE + "/credentials/derive.");
      if (self.admitted(req, res, SCOPE_ISSUE)) {
        self.run(res, self.derive(req, res));
      }
      log.debug("Leaving POST " + BASE + "/credentials/derive.");
    });
    app.post(BASE + '/credentials/status', function (req, res) {
      log.debug("Entering POST " + BASE + "/credentials/status.");
      if (self.admitted(req, res, SCOPE_ISSUE)) {
        self.changeStatus(req, res);
      }
      log.debug("Leaving POST " + BASE + "/credentials/status.");
    });
    app.post(PUBLISH_PATH, function (req, res) {
      log.debug("Entering POST " + PUBLISH_PATH + ".");
      if (self.admitted(req, res, SCOPE_ISSUE)) {
        self.send(res, 204, null);
      }
      log.debug("Leaving POST " + PUBLISH_PATH + ".");
    });
    log.debug("Leaving VcApi.registerRoutes().");
  }
}

const slot = new InstanceSlot<VcApi>(
  'oid4vc/vc_api',
  () => new VcApi(VcApi.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  VcApi: VcApi,
  installInstance: (instance: VcApi): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  ISSUERS: ISSUERS,
  SCOPE_ISSUE: SCOPE_ISSUE,
  SCOPE_VERIFY: SCOPE_VERIFY,
  issuers: slot.forward('issuers'),
  verifyCredentialDocument: slot.forward('verifyCredentialDocument'),
  verifyPresentationDocument: slot.forward('verifyPresentationDocument')
};
