'use strict';
//
// File: gnap_rs.ts
//
// ---------------------------------------------------------------------------
// THE RESOURCE SERVER'S SIDE OF GNAP: WHAT RFC 9767 LETS AN RS ASK THE AS, AND
// HOW A PRESENTED TOKEN IS JUDGED.
//
// Three callers, one module, route-free:
//
//   * `POST /gnap/introspect` and `POST /gnap/resource` (RFC 9767 sections 3.3
//     and 3.4), whose logic is `introspect()` and `register()`.
//   * the DEMONSTRATION RS at `/gnap/rs/resource` — the one place a client can
//     present a GNAP token to something and see it judged the way a real RS
//     would: the token read in its own format, its key proof checked, its
//     rights compared with what the request needs.
//   * the SHARED SIGNALS endpoints, which accept a GNAP access token as their
//     third authorization scheme since 2026-09-12, so that a GNAP web
//     application can own a stream (gnap_signals.ts). They take
//     `presentation()` only, the synchronous half — see below.
//
// **A TOKEN IS JUDGED BY ITS RECORD AND BY ITS FORMAT, AND BOTH MUST AGREE.**
// This AS holds every token it issued (gnap_store.ts), which is what makes
// introspection possible for all five formats — including the three whose
// value a verifier could read alone. The demonstration RS does BOTH: it looks
// the value up (revocation, which no self-contained format can carry) AND
// verifies it in its own format (signature, expiry, audience, binding, rights),
// because an RS that only did the first would be an introspection client
// pretending to be a verifier, and one that only did the second would accept a
// revoked token until it expired — RFC 9767 section 6.3's trade-off, shown
// rather than chosen.
//
// **AN AS-SPECIFIC TOKEN IS NEVER ACTIVE HERE** (RFC 9767 section 2.1.14): a
// continuation or management access token is not in the token store at all —
// it is an index onto a grant — so it introspects as inactive and is refused
// by the demonstration RS by construction rather than by a check someone could
// forget.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapRs` takes every module it reads through its constructor, as
// `GnapRsDeps`, and the module still exports `introspect`, `register`,
// `authenticate`, `presentation` and `liveProblem` from a TRANSITIONAL
// instance for `gnap.ts`, `ssf/ssf_auth.ts` and `ssf/ssf_cluster.ts`, which
// require it by those names. `tests/cluster_signout_signals.js` replaces the
// whole module in `require.cache`, which is unaffected.
// ---------------------------------------------------------------------------

import config = require('../common/config');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import applications = require('../common/applications');
import keystore = require('../common/keystore');
import store = require('./gnap_store');
import keys = require('./gnap_keys');
import proof = require('./gnap_proof');
import request = require('./gnap_request');
import tokens = require('./gnap_tokens');
import monitor = require('./gnap_monitor');
import grants = require('./gnap_grants');
import accessRights = require('./gnap_access');

interface GnapRsDeps {
  config: typeof config;
  log: typeof helpers.log;
  nowSec(): number;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  applications: typeof applications;
  keystore: typeof keystore;
  store: typeof store;
  keys: typeof keys;
  proof: typeof proof;
  request: typeof request;
  tokens: typeof tokens;
  monitor: typeof monitor;
  grants: typeof grants;
  accessRights: typeof accessRights;
}

// What `authenticate()` is told about the resource being asked for.
interface AuthenticateOptions {
  audience?: string | null;
  requiredAccess?: unknown;
  base?: string;
}

class GnapRs {
  constructor(private readonly deps: GnapRsDeps) {
    deps.log.debug("Entering GnapRs.constructor().");
    deps.log.debug("Leaving GnapRs.constructor().");
  }

  private refusal(code: string, why: string, gnapError?: string,
                  status?: number): any {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapRs.refusal().");
    const out = { ok: false, errorCode: code, why: why,
                  gnapError: gnapError || 'invalid_request',
                  status: status || 400 };
    log.debug("Leaving GnapRs.refusal().");
    return errorCodes.mark(out, code);
  }

  // Whether a token record is live — the checks introspection and the RS
  // share.
  liveProblem(record: any): string {
    const { log, tokens, nowSec, store } = this.deps;
    log.debug("Entering GnapRs.liveProblem().");
    if (!record) {
      log.debug("Leaving GnapRs.liveProblem().");
      return 'unknown';
    }
    if (record.revoked || tokens.isRevokedJti(record.jti)) {
      log.debug("Leaving GnapRs.liveProblem().");
      return 'revoked';
    }
    if (record.exp && record.exp < nowSec()) {
      log.debug("Leaving GnapRs.liveProblem().");
      return 'expired';
    }
    const grant = store.getGrant(record.grantId);
    if (grant && grant.state === store.STATE.FINALIZED) {
      log.debug("Leaving GnapRs.liveProblem().");
      return 'grant finalized';
    }
    log.debug("Leaving GnapRs.liveProblem().");
    return '';
  }

  private rsNamesOf(app: any, extra?: string[]): string[] {
    const { log, grants } = this.deps;
    log.debug("Entering GnapRs.rsNamesOf().");
    log.debug("Leaving GnapRs.rsNamesOf().");
    return [app.identifier].concat(grants.fieldValues(app,
                                                      'gnapResourceServerUri'),
                                   extra || []);
  }

  // -------------------------------------------------------------------------
  // RFC 9767 SECTION 3.3.
  // -------------------------------------------------------------------------
  async introspect(req: any): Promise<any> {
    const { log, config, proof, request, grants, monitor, store,
            accessRights, audit } = this.deps;
    log.debug("Entering GnapRs.introspect().");
    if (config.value('gnap.introspection') === false) {
      log.debug("Leaving GnapRs.introspect(). Off.");
      return this.refusal('STS-GNAP-0520', 'introspection is not offered by ' +
                                           'this authorization server.',
                          'invalid_request', 404);
    }
    const body: any = proof.readBody(req);
    if (!body.ok) {
      log.debug("Leaving GnapRs.introspect(). Body refused.");
      return body;
    }
    const parsed: any = request.parseIntrospection(body.json);
    if (!parsed.ok) {
      log.debug("Leaving GnapRs.introspect(). Request refused.");
      return parsed;
    }
    const caller: any = await grants.identifyCaller(
        req, body, parsed.request.resourceServer, grants.KIND_RS);
    if (!caller.ok) {
      log.debug("Leaving GnapRs.introspect(). Resource server refused.");
      return Object.assign(caller,
                           { gnapError: 'invalid_resource_server',
                             status: 400 });
    }
    const rs = caller.app;
    monitor.record(rs.identifier, 'rs.introspection', {});
    const record: any = store.tokenByValue(parsed.request.accessToken);
    const problem = this.liveProblem(record);
    let inactiveWhy = problem;
    if (!inactiveWhy) {
      const names = this.rsNamesOf(rs);
      if (record.aud && record.aud.length &&
          !record.aud.some(function (aud) {
            return names.indexOf(aud) >= 0 ||
                   /\/gnap\/rs\/resource$/.test(aud) &&
                   rs.identifier === aud;
          })) {
        inactiveWhy = 'not for this resource server';
      } else if (parsed.request.proof) {
        const bearer = (record.flags || []).indexOf('bearer') >= 0;
        const method = record.proof ? record.proof.method : null;
        if (bearer || method !== parsed.request.proof) {
          inactiveWhy = 'not bound using the proof method indicated';
        }
      }
      if (!inactiveWhy && parsed.request.access &&
          !accessRights.accessCovers(record.access, parsed.request.access)) {
        inactiveWhy = 'not appropriate for the access indicated';
      }
    }
    audit.audit({ action: 'gnap.rs.introspect', category: 'protocol',
      protocol: 'GNAP',
      channel: 'http', outcome: 'success', actor: rs.identifier,
      target: rs.identifier,
      summary: 'A resource server introspected a GNAP access token',
      detail: { active: !inactiveWhy, why: inactiveWhy || '' } });
    if (inactiveWhy) {
      // RFC 9767 section 3.3: "the value is set to false and other fields are
      // omitted". The reason is logged for the operator and never sent.
      log.info('gnap: introspection by ' + rs.identifier +
               ' answered inactive: ' + inactiveWhy);
      log.debug("Leaving GnapRs.introspect(). Inactive.");
      return { ok: true, status: 200, body: { active: false } };
    }
    monitor.record(rs.identifier, 'rs.introspection_active', {});
    const answer: any = { active: true, access: record.access,
                          iss: record.iss };
    if (record.key && (record.flags || []).indexOf('bearer') < 0) {
      answer.key = record.key;
    }
    ['flags', 'exp', 'iat', 'nbf', 'sub', 'label'].forEach(function (name) {
      if (record[name] !== undefined && record[name] !== null &&
          !(Array.isArray(record[name]) && !record[name].length)) {
        answer[name] = record[name];
      }
    });
    if (record.aud && record.aud.length) {
      answer.aud = record.aud.length === 1 ? record.aud[0] : record.aud;
    }
    answer.instance_id = record.instanceId;
    // RFC 9767 section 2.2: "The AS can return the token's format in an
    // introspection response". The registry names no member for it; `format`
    // is the obvious spelling and is what this AS uses.
    answer.format = record.format;
    log.debug("Leaving GnapRs.introspect(). Active.");
    return { ok: true, status: 200, body: answer };
  }

  // -------------------------------------------------------------------------
  // RFC 9767 SECTION 3.4.
  // -------------------------------------------------------------------------
  async register(req: any): Promise<any> {
    const { log, config, proof, request, grants, tokens, store, monitor,
            audit } = this.deps;
    log.debug("Entering GnapRs.register().");
    if (config.value('gnap.resourceRegistration') === false) {
      log.debug("Leaving GnapRs.register(). Off.");
      return this.refusal('STS-GNAP-0530', 'resource registration is not ' +
                          'offered by this authorization server.',
                          'invalid_request', 404);
    }
    const body: any = proof.readBody(req);
    if (!body.ok) {
      log.debug("Leaving GnapRs.register(). Body refused.");
      return body;
    }
    const parsed: any = request.parseRegistration(body.json);
    if (!parsed.ok) {
      log.debug("Leaving GnapRs.register(). Request refused.");
      return parsed;
    }
    const asked = parsed.request;
    const caller: any = await grants.identifyCaller(req, body,
                                                    asked.resourceServer,
                                                    grants.KIND_RS);
    if (!caller.ok) {
      log.debug("Leaving GnapRs.register(). Resource server refused.");
      return Object.assign(caller,
                           { gnapError: 'invalid_resource_server',
                             status: 400 });
    }
    const rs = caller.app;
    const enabled = grants.capabilityList(req, null,
                                          'token_formats_supported') ||
                    tokens.FORMATS;
    let formats = null;
    if (asked.tokenFormats) {
      formats = asked.tokenFormats.filter(function (format) {
        return enabled.indexOf(format) >= 0;
      });
      if (!formats.length) {
        log.debug("Leaving GnapRs.register(). No shared token format.");
        return this.refusal('STS-GNAP-0531', 'this authorization server ' +
                            'supports none of the requested token formats ' +
                            '(it ' +
                            'issues ' + enabled.join(', ') + '; ' +
                            'RFC 9767 section 3.4).',
                            'invalid_request');
      }
    }
    if (asked.introspectionRequired &&
        config.value('gnap.introspection') === false) {
      log.debug("Leaving GnapRs.register(). Introspection required and off.");
      return this.refusal('STS-GNAP-0532', 'the resource server requires ' +
                          'introspection and this authorization server does ' +
                          'not offer it (RFC 9767 section 3.4).',
                          'invalid_request');
    }
    const allowed = grants.fieldValues(rs, 'gnapAllowedAccess');
    const denied = asked.access.filter(function (right) {
      const name = typeof right === 'string' ? right : right.type;
      return allowed.length && allowed.indexOf(name) < 0;
    });
    if (denied.length) {
      log.debug("Leaving GnapRs.register(). Access not permitted for this " +
                "RS.");
      return this.refusal('STS-GNAP-0533', 'this resource server may not ' +
                          'register access to "' +
                          (typeof denied[0] === 'string' ? denied[0] :
                           denied[0].type) + '".',
                          'invalid_access');
    }
    const canonical = grants.canonicalJson({ access: asked.access,
                                             formats: formats });
    let row: any = store.resourceByCanonical(canonical, rs.identifier);
    if (!row) {
      row = store.putResource(store.mint(12), {
        canonical: canonical, rsIdentity: rs.identifier,
        rsIdentifier: rs.identifier,
        access: asked.access, tokenFormats: formats,
        introspectionRequired: asked.introspectionRequired
      });
      monitor.record(rs.identifier, 'rs.registration', {});
    }
    this.ensureMacaroonKey(rs);
    const response: any = { resource_reference: row.reference };
    if (config.value('gnap.introspection') !== false) {
      response.introspection_endpoint = grants.realmBase(req) +
                                        '/gnap/introspect';
    }
    if (!caller.instanceId && config.value('gnap.instanceIds') !== false &&
        caller.descriptor.format !== 'reference') {
      const instanceId = store.mint(18);
      store.putInstance(instanceId,
                        { identifier: rs.identifier,
                          key: caller.descriptor.value });
      response.instance_id = instanceId;
    }
    audit.audit({ action: 'gnap.rs.register', category: 'protocol',
      protocol: 'GNAP', channel: 'http',
      outcome: 'success', actor: rs.identifier, target: rs.identifier,
      summary: 'A resource server registered a GNAP resource set',
      detail: { reference: row.reference, rights: asked.access.length,
                formats: (formats || []).join(',') } });
    log.debug("Leaving GnapRs.register(). reference=" + row.reference);
    return { ok: true, status: 200, body: response };
  }

  // -------------------------------------------------------------------------
  // THE MACAROON ROOT KEY AN RS VERIFIES WITH, ON ITS OWN ENTRY.
  //
  // A macaroon is verified with its root key, and each RS gets its own
  // (gnap_tokens.ts's header). The key is DERIVED, so it never has to be
  // stored to be correct — but an RS has to be able to READ it, and the place
  // an RS operator reads a credential for their application is that
  // application's entry (the console's drill-down, `/admin-api/applications`).
  // So it is written there once, as `gnapMacaroonKey`: a credential attribute,
  // sealed with the process key-encryption key when keys persist (the user's
  // choice, 2026-09-12) and withheld from LDAP readers in product mode.
  // -------------------------------------------------------------------------
  private ensureMacaroonKey(rs: any): void {
    const { log, grants, tokens, applications, errorCodes,
            keystore } = this.deps;
    log.debug("Entering GnapRs.ensureMacaroonKey().");
    if (grants.field(rs, 'gnapMacaroonKey')) {
      log.debug("Leaving GnapRs.ensureMacaroonKey(). Present.");
      return;
    }
    const value = tokens.macaroonKeyFor(rs.identifier).toString('base64url');
    // THROUGH seen() AND NOT updateApplication(), which refuses it: the key is
    // DERIVED — what this service did, not what an operator may set — and
    // `updateApplication()` is the door that keeps derived attributes out of
    // an operator's hands. A sighting is the door this service writes what it
    // did through, and the registry's own save seals the value
    // (SEALED_FIELDS).
    try {
      applications.seen({ identifier: rs.identifier, kind: grants.KIND_RS,
                          protocol: grants.PROTOCOL,
                          counts: false,
                          fields: { gnapMacaroonKey: value } });
    } catch (e) {
      log.debug("Caught in GnapRs.ensureMacaroonKey(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-GNAP-0655') + 'gnap: the macaroon root ' +
               'key could not be written onto "' + rs.identifier + '": ' +
               e.message);
    }
    if (!grants.field(applications.get(rs.identifier), 'gnapMacaroonKey')) {
      log.warn(errorCodes.tag('STS-GNAP-0655') + 'gnap: the macaroon root ' +
               'key was not recorded on "' +
               rs.identifier + '"; a resource server verifying macaroons ' +
                               'itself will not find it.');
    }
    log.debug("Leaving GnapRs.ensureMacaroonKey(). sealed=" +
              keystore.persists());
  }

  // -------------------------------------------------------------------------
  // A PRESENTED TOKEN (RFC 9635 section 7.2), judged as an RS judges it.
  //
  // TWO HALVES, AND THE SPLIT IS FOR A CALLER RATHER THAN FOR TIDINESS.
  // `presentation()` is everything this authorization server can decide out of
  // its OWN RECORD of the token — that it issued it, that it is live, that it
  // was presented under the right scheme, and that the request carries a
  // proof by the key it is bound to — and it is SYNCHRONOUS. `authenticate()`
  // adds the format's own verification, which is what a resource server that
  // is not this process would be doing, and is async because a zcap signature
  // check is.
  //
  // `ssf/ssf_auth.ts` takes the first half only. Its gate is synchronous
  // across twelve endpoints, and for a token this process minted and still
  // holds the record of, the record IS the answer: the format check re-derives
  // facts the store already holds.
  // -------------------------------------------------------------------------
  presentation(req: any): any {
    const { log, store, keys, grants, proof, monitor,
            errorCodes } = this.deps;
    log.debug("Entering GnapRs.presentation().");
    const header = String(req.headers.authorization || '');
    const gnapMatch = header.match(/^GNAP\s+(\S+)\s*$/);
    const bearerMatch = header.match(/^Bearer\s+(\S+)\s*$/i);
    if (!gnapMatch && !bearerMatch) {
      log.debug("Leaving GnapRs.presentation(). No token.");
      return this.refusal('STS-GNAP-0540', 'no GNAP access token was ' +
                          'presented.',
                          'invalid_token', 401);
    }
    const value = (gnapMatch || bearerMatch)[1];
    const record: any = store.tokenByValue(value);
    const problem = this.liveProblem(record);
    if (problem) {
      log.debug("Leaving GnapRs.presentation(). " + problem);
      return this.refusal('STS-GNAP-0541',
                          'the access token is ' + (problem === 'unknown'
        ? 'not one this authorization server issued' : problem) + '.',
                          'invalid_token', 401);
    }
    const bearer = (record.flags || []).indexOf('bearer') >= 0;
    // Section 7.2: a bearer token "MUST be sent using the Authorization
    // request header field method defined in [RFC6750]", and a bound token
    // with the GNAP scheme and a proof. Either the other way round is a
    // presentation error.
    if (bearer && !bearerMatch) {
      log.debug("Leaving GnapRs.presentation(). Bearer token under the GNAP " +
                "scheme.");
      return this.refusal('STS-GNAP-0542', 'a bearer GNAP token is presented ' +
                          'with the Bearer scheme (RFC 9635 section ' +
                          '7.2).', 'invalid_request', 401);
    }
    if (!bearer && !gnapMatch) {
      log.debug("Leaving GnapRs.presentation(). Bound token under the " +
                "Bearer scheme.");
      return this.refusal('STS-GNAP-0543', 'this access token is bound to a ' +
                          'key and is presented with the GNAP scheme and ' +
                          'proof of that key ' +
                          '(RFC 9635 section 7.2).', 'invalid_request', 401);
    }
    let presentedKey = null;
    let method = 'bearer';
    let replayKeys = [];
    if (!bearer) {
      const descriptor: any = keys.describe(record.key,
                                            { resolveReference:
                                                grants.resolveKeyReference });
      const body: any = proof.readBody(req);
      if (!descriptor.ok || !body.ok) {
        log.debug("Leaving GnapRs.presentation(). Key or body unusable.");
        return this.refusal('STS-GNAP-0544', 'the token\'s key or the ' +
                            'request content cannot be read.',
                            'invalid_request', 401);
      }
      const verified: any = proof.verifyRequest(req, body, descriptor,
                                                { accessToken: value });
      if (!verified.ok) {
        monitor.record(record.instanceId, 'proof.failed',
                       { gnapError: 'invalid_token' });
        log.debug("Leaving GnapRs.presentation(). Proof refused: " +
                  verified.why);
        return this.refusal(errorCodes.codeOf(verified) || 'STS-GNAP-0545',
                            'the ' +
                            'key proof does not verify: ' +
                            verified.why, 'invalid_token', 401);
      }
      presentedKey = keys.confirmationOf(descriptor);
      method = descriptor.proof.method;
      replayKeys = verified.replayKeys || [];
    }
    log.debug("Leaving GnapRs.presentation(). " + record.format + " via " +
              method);
    // `replayKeys` are what the replay cache remembered for this proof, for an
    // asynchronous caller to spend across the cluster (#46) — see
    // authenticate().
    return { ok: true, record: record, value: value,
             presentedKey: presentedKey,
             method: method, replayKeys: replayKeys };
  }

  // `options`: `{ audience, requiredAccess, base }`. Answers `{ ok, record,
  // model, method }` or a refusal carrying the WWW-Authenticate reason.
  async authenticate(req: any, options?: AuthenticateOptions): Promise<any> {
    const { log, proof, monitor, errorCodes, tokens, nowSec } = this.deps;
    log.debug("Entering GnapRs.authenticate().");
    const opts = options || {};
    const presented = this.presentation(req);
    if (!presented.ok) {
      log.debug("Leaving GnapRs.authenticate(). The presentation was " +
                "refused.");
      return presented;
    }
    // THE PROOF, SPENT ACROSS THE CLUSTER (2026-09-14, #46). `presentation()`
    // stays synchronous because ssf/ssf_auth.ts calls it synchronously, so the
    // cluster half of its replay check is made here, at the first asynchronous
    // caller, before the token is honoured — gnap_proof.ts's spendProof()
    // argues it.
    const once: any = await proof.spendProof(presented);
    if (!once.ok) {
      monitor.record(presented.record.instanceId, 'proof.failed',
                     { gnapError: 'invalid_token' });
      log.debug("Leaving GnapRs.authenticate(). The proof was refused at " +
                "its spend.");
      return this.refusal(errorCodes.codeOf(once) || 'STS-GNAP-0716',
                          'the key ' +
                          'proof does not verify: ' + once.why,
                          'invalid_token', 401);
    }
    const record = presented.record;
    const value = presented.value;
    const presentedKey = presented.presentedKey;
    const method = presented.method;
    // The format's own verification, in the format's own terms.
    const checked: any = await tokens.verify(record.format, value, {
      now: nowSec(), audience: opts.audience || null,
      presentedKey: presentedKey,
      requiredAccess: opts.requiredAccess || null, base: opts.base,
      rsIdentity: record.rsIdentifiers && record.rsIdentifiers.length === 1 ?
                  record.rsIdentifiers[0] : ''
    });
    if (!checked.ok) {
      log.debug("Leaving GnapRs.authenticate(). Format verification " +
                "refused: " + checked.why);
      // ONLY A RIGHTS SHORTFALL IS 403 insufficient_scope; every other format
      // refusal is the token itself and 401 invalid_token. Decided on the CODE
      // gnap_access.checkAccess() raises, not on the sentence — nearly every
      // refusal sentence begins "the access token …".
      const shortfall = errorCodes.codeOf(checked) === 'STS-GNAP-0308';
      log.debug("Leaving GnapRs.authenticate().");
      return this.refusal(errorCodes.codeOf(checked) || 'STS-GNAP-0546',
                          checked.why,
                          shortfall ? 'insufficient_scope' : 'invalid_token',
                          shortfall ? 403 : 401);
    }
    log.debug("Leaving GnapRs.authenticate(). " + record.format + " via " +
              method);
    return { ok: true, record: record, model: checked.model, method: method,
             format: record.format };
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, as the composition root will build one.
const judge = new GnapRs({
  config: config,
  log: helpers.log,
  nowSec: helpers.nowSec,
  errorCodes: errorCodes,
  audit: audit,
  applications: applications,
  keystore: keystore,
  store: store,
  keys: keys,
  proof: proof,
  request: request,
  tokens: tokens,
  monitor: monitor,
  grants: grants,
  accessRights: accessRights
});

export = {
  GnapRs: GnapRs,
  introspect: judge.introspect.bind(judge) as GnapRs['introspect'],
  register: judge.register.bind(judge) as GnapRs['register'],
  authenticate: judge.authenticate.bind(judge) as GnapRs['authenticate'],
  presentation: judge.presentation.bind(judge) as GnapRs['presentation'],
  liveProblem: judge.liveProblem.bind(judge) as GnapRs['liveProblem']
};
