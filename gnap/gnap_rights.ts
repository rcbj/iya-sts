// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_rights.ts
//
// ===========================================================================
// EACH GNAP ACCESS RIGHT IS A POLICY QUESTION, READ AGAINST ONE CATALOGUE
// (#432 phases 3 and 4, 2026-10-03).
//
// Until #432 the grant engine decided who may be granted what in code: a
// bearer flag against `gnap.bearerTokens` and `gnapBearerTokens`, the
// protected scopes against `oauthAllowedScope` (#110), the client's
// `gnapAllowedAccess`, an unknown reference against
// `gnap.unknownAccessReferences` — and the issuance gate was asked "an access
// token for application X" without ever seeing a right. This module is the
// replacement, in two halves:
//
// **PHASE 4 — THE ACCESS-TYPE CATALOGUE.** RFC 9396's authorization detail
// grew out of RFC 9635's access right and they share five common fields, so
// the types a resource application declares for rich authorization requests
// (`oauthAuthorizationDetailsType`, rule 3am) ARE the catalogue GNAP reads —
// extended, not twinned (`common/applications.js` owns the grammar,
// `oauth-oidc/authorization_details.ts` reads it). Here the catalogue is
// asked three things about a GNAP right:
//
//   * WELL-FORMEDNESS (`conformanceRefusal()`): a right of a catalogued type
//     must meet its definition — the actions, datatypes and privileges it
//     may name, the members it must carry, its JSON Schema, its limits
//     schema (none declared refuses `limits`), the locations its owner
//     answers to. `authorization_details.conformance()` is the one reading,
//     shared with RFC 9396. Not an authorization decision, so not policy:
//     a malformed request is `invalid_request`.
//   * DERIVATION (`derivable()`): `gnap_delegation.ts`'s one extension point,
//     filled here — rcbj's decision 3.
//   * INTROSPECTION (`introspection()`): what a resource server is told,
//     filtered per resource server.
//
// **PHASE 3 — ONE QUESTION PER RIGHT.** `judge()` gathers each right's facts
// — the right, the token it is for, the client, who approved it and how, the
// session's acr and amr, its risk (#62) and registered device (#164), and
// what the catalogue declares for its type — and asks the issuance policy
// `issue-gnap-right` through `common/issuance_gate.js`'s
// `checkGnapRights()`, #304's per-scope arrangement exactly. The verdict is
// keep, narrow (values taken off a dimension) or refuse with a code, and a
// lifetime the token honours. The built-in policy's rules ARE the code they
// replaced (`xacml_templates.ts`), so nothing here decides; `gate.check()`
// is still asked for the token as a whole.
//
// **TWO STAGES.** `request`: at grant creation, modification and derivation,
// before anybody is asked — a refusal answers the client, a narrowing
// changes what the approval page shows (and the page says so). `issue`: in
// `release()`, when the approval is known — a refusal drops the right from
// its token, a narrowing narrows it, and the lifetime caps the token. The
// approval facts exist only at the second.
//
// **NARROWING NEVER WIDENS.** A dimension a right does not list is
// unrestricted (`gnap_access.ts`'s header), so taking a value off an absent
// dimension needs the catalogue's list of what the type allows to subtract
// it from; without one, or where nothing would be left, or for a reference
// string (which has no dimensions), the narrowing is a refusal
// (STS-GNAP-0817). A narrowed right is checked against the catalogue again.
//
// **WHO MUST BE ASKED, AND HOW STRONGLY (#432 phase 6).** The catalogue's
// `interaction`, `consentActions` and `acr` are rules of the built-in
// policy (`xacml_templates.ts`), whose verdicts carry `interaction` (none,
// skippable, always) and `acr`. `judge()` aggregates them over the rights it
// keeps into the grant's `requirement` — the most demanding interaction,
// every acr — which `gnap_grants.ts` acts on before anybody is asked: a
// trusted client skips only where every right is skippable, a `never` right
// needs nobody, the approval page steps the person up. At the ISSUE stage the
// verdicts are held against what actually happened, as defence in depth: a
// right whose verdict says `always` is dropped from a token approved by
// skipping or by a remembered approval (STS-GNAP-0890), and one whose acr
// the approving session did not meet is dropped (STS-GNAP-0891). Nothing
// here decides; it holds the engine to what the policy said.
//
// A LIBRARY (rule 3): no route and no store. It requires the catalogue
// reader, the store's reference lookup, the scope policy and the gate, none
// of which reaches `gnap/`, so it closes no cycle and needs no slot.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import mode = require('../common/mode');
import audit = require('../common/audit');
import applications = require('../common/applications');
import gate = require('../common/issuance_gate');
import scopePolicy = require('../common/scope_policy');
import InstanceSlot = require('../common/instance_slot');
import catalogue = require('../oauth-oidc/authorization_details');
// RFC 9470's ordered acr levels (#432 phase 6): whether a session meets a
// right's acr. A library that requires nothing of `gnap/`.
import stepUp = require('../oauth-oidc/step_up');
import store = require('./gnap_store');

type Json = any;

interface GnapRightsDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  errorCodes: typeof errorCodes;
  mode: typeof mode;
  audit: typeof audit;
  applications: Json;
  gate: Json;
  scopePolicy: Json;
  catalogue: Json;
  store: Json;
  stepUp: Json;
}

// THE DEMONSTRATION RESOURCE SERVER'S TYPE (`gnap.ts`'s `/gnap/rs/resource`),
// defined here so the route module and the catalogue read one spelling. It is
// THIS SERVICE'S OWN API, so it is catalogued by this service — the way RFC
// 9396's `openid_credential` is built in — while `gnap.demoResourceServer` is
// on: product mode's uncatalogued rule would otherwise refuse the one API
// every GNAP client here can be pointed at. It declares nothing beyond its
// existence and owns no audience (a token for it is audienced as before).
const DEMO_TYPE = 'urn:iya-sts:gnap:demo';

// The array dimensions of a right (RFC 9635 section 8) a narrowing may take
// values off, by the obligation's name for them.
const DIMENSIONS = ['actions', 'locations', 'datatypes', 'privileges'];

// The GNAP error and status each refusal code is answered with. A code the
// table does not hold — an operator's own, from a realm's policy — is a
// refusal of the request (section 3.6's request_denied, 403).
const ANSWERS: Record<string, { gnapError: string; status: number }> = {
  'STS-GNAP-0111': { gnapError: 'invalid_flag', status: 400 },
  'STS-GNAP-0812': { gnapError: 'invalid_request', status: 400 },
  'STS-GNAP-0813': { gnapError: 'invalid_request', status: 400 },
  'STS-GNAP-0814': { gnapError: 'invalid_request', status: 400 }
};

// Who must be asked, least to most demanding (#432 phase 6). No verdict
// stating one is `skippable`, the rule before #432.
const INTERACTIONS = ['none', 'skippable', 'always'];

// conformance()'s kinds, as this protocol's codes.
const CONFORMANCE_CODES: Record<string, string> = {
  definition: 'STS-GNAP-0812',
  location: 'STS-GNAP-0812',
  'limits-undeclared': 'STS-GNAP-0813',
  limits: 'STS-GNAP-0814'
};

/**
 * GNAP access rights against the access-type catalogue and the issuance
 * policy (#432 phases 3 and 4).
 */
class GnapRights {
  /** The two stages a right is judged at. */
  static readonly STAGES = Object.freeze({ REQUEST: 'request',
                                           ISSUE: 'issue' });

  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the modules it reads
   */
  constructor(private readonly deps: GnapRightsDeps) {
    deps.log.debug("Entering GnapRights.constructor().");
    deps.log.debug("Leaving GnapRights.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): GnapRightsDeps {
    helpers.log.debug("Entering GnapRights.defaultDeps().");
    helpers.log.debug("Leaving GnapRights.defaultDeps().");
    return { log: helpers.log, config: config, errorCodes: errorCodes,
             mode: mode, audit: audit, applications: applications,
             gate: gate, scopePolicy: scopePolicy, catalogue: catalogue,
             store: store, stepUp: stepUp };
  }

  // The values of one attribute of an application entry, as strings.
  private fieldValues(app: Json, name: string): string[] {
    const { log } = this.deps;
    log.debug("Entering GnapRights.fieldValues(). " + name);
    const value = app && app.fields ? app.fields[name] : undefined;
    log.debug("Leaving GnapRights.fieldValues().");
    if (value === undefined || value === null || value === '') {
      return [];
    }
    return (Array.isArray(value) ? value : [value]).map(String);
  }

  /**
   * Returns the catalogue entry of a right's type: null for a reference
   * string or a type nobody declares.
   *
   * @param right - the access right
   * @returns the entry, or null
   */
  entryOf(right: Json): Json {
    const { log, catalogue } = this.deps;
    log.debug("Entering GnapRights.entryOf().");
    if (right && typeof right === 'object' && right.type === DEMO_TYPE &&
        this.deps.config.value('gnap.demoResourceServer') !== false) {
      log.debug("Leaving GnapRights.entryOf(). The demonstration type.");
      return { type: DEMO_TYPE, builtIn: true, identifier: '', clientId: '',
               identifiers: [], actions: null, datatypes: null,
               privileges: null, required: [], interaction: 'default',
               consentActions: [], bearer: null, maxLifetimeS: null, acr: '',
               derivableFrom: [], introspectionClaims: [], limits: null,
               validateLimits: null, validate: null };
    }
    const found = right && typeof right === 'object'
      ? catalogue.typeOf(right.type) : null;
    log.debug("Leaving GnapRights.entryOf(). " + !!found);
    return found;
  }

  // A refusal in the grant engine's shape, the code marked on it.
  private refusal(code: string, why: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapRights.refusal(). " + code);
    const answer = ANSWERS[code] || { gnapError: 'request_denied',
                                      status: 403 };
    log.debug("Leaving GnapRights.refusal().");
    return errorCodes.mark({ ok: false, why: why,
                             gnapError: answer.gnapError,
                             status: answer.status }, code);
  }

  // -------------------------------------------------------------------------
  // WELL-FORMEDNESS AGAINST THE CATALOGUE: the first right of a catalogued
  // type that does not meet its definition, as a refusal, or null.
  // -------------------------------------------------------------------------
  /**
   * Checks every right of every requested token against its catalogue entry.
   *
   * @param tokens - `[{ label, access }]`
   * @returns a refusal (STS-GNAP-0812..0814), or null
   */
  conformanceRefusal(tokens: Json[]): Json {
    const { log, catalogue } = this.deps;
    log.debug("Entering GnapRights.conformanceRefusal().");
    for (let t = 0; t < (tokens || []).length; t++) {
      const access = tokens[t].access || [];
      for (let r = 0; r < access.length; r++) {
        const entry = this.entryOf(access[r]);
        if (!entry || entry.builtIn) {
          continue;
        }
        const found = catalogue.conformance(access[r], entry,
          'access_token' + (tokens.length > 1 ? '[' + t + ']' : '') +
          '.access[' + r + ']');
        if (found.kind) {
          log.debug("Leaving GnapRights.conformanceRefusal(). " +
                    found.kind);
          return this.refusal(CONFORMANCE_CODES[found.kind] ||
                              'STS-GNAP-0812', found.problem + ' (RFC 9635 ' +
                              'section 8: an access right is read as its ' +
                              'API defines it).');
        }
      }
    }
    log.debug("Leaving GnapRights.conformanceRefusal(). None.");
    return null;
  }

  // -------------------------------------------------------------------------
  // THIS SERVICE'S PROTECTED SCOPES IN A RIGHT (#110): `ssf:read`/`ssf:write`
  // as reference strings, or an object of type `ssf` with those actions (no
  // actions means both) — the Shared Signals scopes by another spelling — and
  // whether the client's entry declares every one it asks for. The facts the
  // `gnap-protected-undeclared` rule reads; the scope policy's own test of
  // what is protected and what is declared.
  // -------------------------------------------------------------------------
  private protectedFacts(app: Json, right: Json): Json {
    const { log, config, scopePolicy } = this.deps;
    log.debug("Entering GnapRights.protectedFacts().");
    const identifier = String((app && app.identifier) || '');
    const read = String(config.value('ssf.authScopeRead') || 'ssf:read');
    const write = String(config.value('ssf.authScopeWrite') || 'ssf:write');
    const name = typeof right === 'string' ? right :
      String((right && right.type) || '');
    const wanted: string[] = [];
    if (scopePolicy.isProtected(name)) {
      wanted.push(name);
    } else if (typeof right !== 'string' && name === 'ssf') {
      const actions = Array.isArray(right.actions) && right.actions.length
        ? right.actions.map(String) : ['read', 'write'];
      if (actions.indexOf('read') >= 0) {
        wanted.push(read);
      }
      if (actions.indexOf('write') >= 0) {
        wanted.push(write);
      }
    }
    const undeclared = wanted.filter(function (one: string): boolean {
      return !scopePolicy.declares(identifier, one);
    });
    log.debug("Leaving GnapRights.protectedFacts(). " + wanted.length);
    return { protected: wanted.length > 0,
             declared: undeclared.length === 0, undeclared: undeclared };
  }

  // -------------------------------------------------------------------------
  // THE FACTS OF ONE RIGHT, in `xacml_request.js`'s gnapRight() shape.
  //   ctx { app, token: { label, bearer, format, targets }, approver,
  //         approval, session, risk, device }
  // -------------------------------------------------------------------------
  private factsOf(ctx: Json, right: Json): Json {
    const { log, store } = this.deps;
    log.debug("Entering GnapRights.factsOf().");
    const app = ctx.app;
    const allowed = this.fieldValues(app, 'gnapAllowedAccess');
    const isRef = typeof right === 'string';
    const name = isRef ? right : String(right.type || '');
    const entry = this.entryOf(right);
    const prot = this.protectedFacts(app, right);
    const session = ctx.session || null;
    const device = ctx.device || null;
    const facts: Json = {
      right: isRef
        ? { id: name, kind: 'reference', listed: allowed.indexOf(name) >= 0,
            referenceRegistered: !!store.resourceByReference(name),
            protected: prot.protected, protectedDeclared: prot.declared }
        : { id: name, kind: 'object', actions: right.actions,
            locations: right.locations, datatypes: right.datatypes,
            identifier: right.identifier, privileges: right.privileges,
            listed: allowed.indexOf(name) >= 0, protected: prot.protected,
            protectedDeclared: prot.declared },
      catalogue: isRef ? {} : (entry
        ? { catalogued: true, owner: entry.identifier,
            bearer: typeof entry.bearer === 'boolean' ? entry.bearer : null,
            maxLifetimeS: entry.maxLifetimeS, acr: entry.acr,
            interaction: entry.interaction,
            consentActions: entry.consentActions,
            derivableFrom: entry.derivableFrom,
            introspectionClaims: entry.introspectionClaims }
        : { catalogued: false }),
      token: ctx.token || {},
      client: { id: String((app && app.identifier) || ''),
                // The REGISTERED class only: a declared class_id never
                // raises trust (#432 phase 7).
                class: this.fieldValues(app, 'gnapClassId')[0] || '',
                hasAllowedAccess: allowed.length > 0,
                bearerRefused:
                  this.fieldValues(app, 'gnapBearerTokens')[0] === 'FALSE' },
      approver: ctx.approver || '',
      approval: ctx.approval || 'pending',
      session: session ? { acr: session.acr || '',
                           amr: Array.isArray(session.amr) ? session.amr
                                                           : [] } : {},
      risk: ctx.risk ? { level: ctx.risk.level,
                         signals: ctx.risk.signals || [] } : {},
      device: device
        ? { recognized: true, status: device.status || 'active',
            compliance: device.compliance || 'unknown',
            attestation: device.attestation || 'self-asserted',
            ownerMatches: !!ctx.approver && device.ownerKind === 'person' &&
              String(device.ownerName || '') === String(ctx.approver) }
        : (ctx.approver ? { recognized: false } : {})
    };
    log.debug("Leaving GnapRights.factsOf(). " + name);
    return facts;
  }

  // -------------------------------------------------------------------------
  // A NARROWED RIGHT, or null where the narrowing cannot be carried out
  // without widening or leaving nothing (the header).
  // -------------------------------------------------------------------------
  /**
   * Applies a policy's narrowing to one right.
   *
   * @param right - the access right
   * @param drop - `{ actions, locations, datatypes, privileges }` to take off
   * @returns the narrowed right, or null when it cannot be narrowed
   */
  narrowed(right: Json, drop: Json): Json {
    const { log } = this.deps;
    log.debug("Entering GnapRights.narrowed().");
    if (typeof right === 'string' || !right) {
      log.debug("Leaving GnapRights.narrowed(). A reference.");
      return null;
    }
    const entry = this.entryOf(right);
    const out = Object.assign({}, right);
    for (let i = 0; i < DIMENSIONS.length; i++) {
      const dim = DIMENSIONS[i];
      const off: string[] = (drop && drop[dim]) || [];
      if (!off.length) {
        continue;
      }
      // An absent dimension is unrestricted: what the type allows is what
      // there is to take a value off, and a type that lists nothing leaves
      // nothing to subtract from (`locations`: the owner's addresses).
      const from = Array.isArray(right[dim]) ? right[dim]
        : (entry ? (dim === 'locations' ? entry.identifiers : entry[dim])
                 : null);
      if (!Array.isArray(from)) {
        log.debug("Leaving GnapRights.narrowed(). " + dim + " is " +
                  "unrestricted with nothing to subtract from.");
        return null;
      }
      const left = from.filter(function (one: string): boolean {
        return off.indexOf(one) < 0;
      });
      if (!left.length) {
        log.debug("Leaving GnapRights.narrowed(). Nothing left of " + dim +
                  ".");
        return null;
      }
      out[dim] = left;
    }
    log.debug("Leaving GnapRights.narrowed().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE SENTENCE A REFUSAL IS ANSWERED WITH, by its code.
  // -------------------------------------------------------------------------
  private explain(code: string, right: Json, app: Json): string {
    const { log } = this.deps;
    log.debug("Entering GnapRights.explain(). " + code);
    const name = typeof right === 'string' ? right :
      String((right && right.type) || '');
    const identifier = String((app && app.identifier) || '');
    let out: string;
    switch (code) {
      case 'STS-GNAP-0111':
        out = 'this client instance may not be issued bearer tokens (RFC ' +
          '9635 section 2.1.1).';
        break;
      case 'STS-GNAP-0719':
        out = 'the access ' + this.protectedFacts(app, right).undeclared
          .map(function (one: string): string {
            return '"' + one + '"';
          }).join(', ') + ' is this service\'s own protected scope, and ' +
          'the application "' + identifier + '" does not declare it in ' +
          'its oauthAllowedScope — an administrator declares it on the ' +
          'application (POST /admin-api/applications/add).';
        break;
      case 'STS-GNAP-0112':
        out = typeof right === 'string' &&
              this.fieldValues(app, 'gnapAllowedAccess').indexOf(right) < 0 &&
              !this.fieldValues(app, 'gnapAllowedAccess').length
          ? 'the access reference "' + right + '" names nothing ' +
            'registered with this authorization server.'
          : 'the right "' + name + '" is not one this client instance may ' +
            'request.';
        break;
      case 'STS-GNAP-0810':
        out = 'the right "' + name + '" is of a type no resource server ' +
          'here declares (the access-type catalogue, ' +
          'oauthAuthorizationDetailsType), and in product mode only a ' +
          'catalogued type is granted.';
        break;
      case 'STS-GNAP-0811':
        out = 'a right of type "' + name + '" may be carried only by a ' +
          'key-bound token: the resource server that declares the type ' +
          'refuses a bearer token for it (RFC 9635 section 2.1.1).';
        break;
      case 'STS-GNAP-0817':
        out = 'the issuance policy narrowed the right "' + name + '" to ' +
          'nothing it could still grant.';
        break;
      default:
        out = 'the issuance policy refused the right "' + name + '"' +
          (code ? ' (' + code + ')' : '') + '.';
    }
    log.debug("Leaving GnapRights.explain().");
    return out;
  }

  // -------------------------------------------------------------------------
  // judge(tokens, ctx, stage)
  //
  // `tokens` `[{ label, bearer, access }]`; `ctx` `{ app, approver,
  // approval, session, risk, device, targetsOf(access), formatOf(access,
  // targets) }`. One question per right, every token's together.
  //
  // At `request` it answers a REFUSAL (the first right refused, in request
  // order) or `{ ok: true, tokens, narrowed }`. At `issue` it never refuses
  // the request: a refused right is taken out of its token, and each token
  // gains `maxLifetimeS` where a verdict capped it; `dropped` lists what was
  // taken out. `narrowed` lists `{ token, type, before, after }` either way.
  // -------------------------------------------------------------------------
  /**
   * Puts every right of a request to the issuance policy and applies the
   * verdicts.
   *
   * @param tokens - the requested tokens, `[{ label, bearer, access }]`
   * @param ctx - the client entry, the approval and its session, and how a
   *   token's targets and format are found
   * @param stage - `request` or `issue`
   * @returns a refusal (request stage only), or `{ ok: true, tokens,
   *   narrowed, dropped }`
   */
  judge(tokens: Json[], ctx: Json, stage: string): Json {
    const { log, config, mode, gate, audit } = this.deps;
    const self = this;
    log.debug("Entering GnapRights.judge(). stage=" + stage);
    const asked = (tokens || []).map(function (token: Json): Json {
      const targets = typeof ctx.targetsOf === 'function'
        ? ctx.targetsOf(token.access || []) : [];
      return {
        token: token,
        about: { label: token.label || '', bearer: !!token.bearer,
                 format: typeof ctx.formatOf === 'function'
                   ? String(ctx.formatOf(token.access || [], targets) || '')
                   : '',
                 targets: targets }
      };
    });
    const rights: Json[] = [];
    asked.forEach(function (one: Json): void {
      (one.token.access || []).forEach(function (right: Json): void {
        rights.push(self.factsOf(Object.assign({}, ctx, { token: one.about }),
                                 right));
      });
    });
    const answer = gate.checkGnapRights({
      subject: ctx.approver
        ? { kind: 'user', name: String(ctx.approver) }
        : { kind: 'application',
            name: String((ctx.app && ctx.app.identifier) || '') },
      protocol: 'GNAP',
      mode: mode.current(),
      stage: stage,
      settings: {
        'gnap.bearerTokens': config.value('gnap.bearerTokens') !== false,
        'gnap.unknownAccessReferences':
          String(config.value('gnap.unknownAccessReferences') || 'accept')
      },
      rights: rights
    });
    const verdicts: Json[] = answer.verdicts || [];
    const narrowedList: Json[] = [];
    const dropped: Json[] = [];
    let n = 0;
    const out: Json[] = [];
    // #432 phase 6: what the kept rights need, aggregated. `none` until a
    // right says more, so a request of `never` rights alone needs nobody.
    const requirement: Json = { interaction: 'none', acr: [], always: [],
                                byRight: {} };
    for (let t = 0; t < asked.length; t++) {
      const token = asked[t].token;
      const kept: Json[] = [];
      let cap: number | null = null;
      const access = token.access || [];
      for (let r = 0; r < access.length; r++) {
        const right = access[r];
        const verdict = verdicts[n++] ||
          { verdict: 'refuse', code: 'STS-GNAP-0816', drop: {} };
        let result = right;
        let code = verdict.code || '';
        let refused = verdict.verdict === 'refuse';
        if (!refused && verdict.verdict === 'narrow') {
          result = self.narrowed(right, verdict.drop);
          const entry = result ? self.entryOf(result) : null;
          if (!result || (entry && !entry.builtIn &&
              self.deps.catalogue.conformance(result,
              entry, 'the narrowed right').kind)) {
            refused = true;
            code = 'STS-GNAP-0817';
          } else {
            narrowedList.push({ token: token.label || String(t + 1),
                                type: typeof right === 'string' ? right
                                                                : right.type,
                                before: right, after: result,
                                code: code });
          }
        }
        if (refused) {
          const why = self.explain(code, right, ctx.app);
          if (stage === GnapRights.STAGES.REQUEST) {
            log.debug("Leaving GnapRights.judge(). Refused: " + code);
            return self.refusal(code || 'STS-GNAP-0816', why);
          }
          dropped.push({ token: token.label || String(t + 1), right: right,
                         code: code });
          audit.failure(code || 'STS-GNAP-0816', {
            protocol: 'GNAP', channel: 'http',
            target: String((ctx.app && ctx.app.identifier) || ''),
            summary: 'The issuance policy refused a GNAP access right at ' +
                     'issuance; it was left out of its token',
            detail: { right: typeof right === 'string' ? right : right.type,
                      why: why } });
          continue;
        }
        const asking = INTERACTIONS.indexOf(verdict.interaction) >= 0
          ? verdict.interaction : 'skippable';
        const acrs: string[] = Array.isArray(verdict.acr) ? verdict.acr
                                                          : [];
        if (stage === GnapRights.STAGES.ISSUE) {
          const unmet = self.unmetAtIssue(asking, acrs, ctx);
          if (unmet) {
            dropped.push({ token: token.label || String(t + 1),
                           right: right, code: unmet.code });
            audit.failure(unmet.code, {
              protocol: 'GNAP', channel: 'http',
              target: String((ctx.app && ctx.app.identifier) || ''),
              summary: 'A GNAP access right was left out of its token: ' +
                       unmet.why,
              detail: { right: typeof right === 'string' ? right
                                                         : right.type,
                        approval: String(ctx.approval || ''),
                        acr: acrs.join(' ') } });
            continue;
          }
        }
        if (INTERACTIONS.indexOf(asking) >
            INTERACTIONS.indexOf(requirement.interaction)) {
          requirement.interaction = asking;
        }
        if (asking === 'always') {
          requirement.always.push(typeof right === 'string' ? right
                                                            : right.type);
        }
        acrs.forEach(function (one: string): void {
          if (requirement.acr.indexOf(one) < 0) {
            requirement.acr.push(one);
          }
        });
        if (typeof verdict.maxLifetimeS === 'number' &&
            (cap === null || verdict.maxLifetimeS < cap)) {
          cap = verdict.maxLifetimeS;
        }
        kept.push(result);
        // Per right, as the approval page numbers its checkboxes
        // (`t<token>r<right>`), so the step-up can be held to what the
        // person left ticked (`gnap_approval.ts`).
        if (acrs.length) {
          requirement.byRight['t' + t + 'r' + (kept.length - 1)] =
            acrs.slice();
        }
      }
      const next = Object.assign({}, token, { access: kept });
      if (cap !== null) {
        next.maxLifetimeS = cap;
      }
      out.push(next);
    }
    log.debug("Leaving GnapRights.judge(). " + narrowedList.length +
              " narrowed, " + dropped.length + " dropped.");
    if (!rights.length) {
      // Nothing asked of anybody: the rule before #432 for an empty request.
      requirement.interaction = 'skippable';
    }
    return { ok: true, tokens: out, narrowed: narrowedList,
             dropped: dropped, requirement: requirement };
  }

  // -------------------------------------------------------------------------
  // THE ISSUE STAGE'S CHECK OF ONE RIGHT AGAINST HOW IT WAS APPROVED (#432
  // phase 6): `always` approved without the page drawn (skipped, or a
  // remembered approval), or an acr the approving session does not meet.
  // Null when it stands. A derived right was approved on the original's page
  // and inherits its interaction; its acr is held to the original's session.
  // -------------------------------------------------------------------------
  private unmetAtIssue(asking: string, acrs: string[], ctx: Json): Json {
    const { log } = this.deps;
    log.debug("Entering GnapRights.unmetAtIssue().");
    const approval = String(ctx.approval || '');
    if (asking === 'always' &&
        (approval === 'skipped' || approval === 'remembered')) {
      log.debug("Leaving GnapRights.unmetAtIssue(). Not asked.");
      return { code: 'STS-GNAP-0890',
               why: 'its type requires its resource owner to approve it ' +
                    'on the page, and this approval was ' + approval };
    }
    const session = ctx.session || {};
    const missing = this.unmetAcr(acrs, session);
    if (missing.length) {
      log.debug("Leaving GnapRights.unmetAtIssue(). acr.");
      return { code: 'STS-GNAP-0891',
               why: 'its type requires authentication level ' +
                    missing.join(' ') + ', which the approving session (' +
                    String(session.acr || 'none') + ') does not meet' };
    }
    log.debug("Leaving GnapRights.unmetAtIssue(). Stands.");
    return null;
  }

  /**
   * Returns the required acr values a session does not meet (RFC 9470's
   * ordered levels, `step_up.ts`): every value is required, so one unmet is
   * enough to refuse.
   *
   * @param acrs - the values every right requires
   * @param session - the session's `acr` and `amr` (or a sign-on session)
   * @returns the values not met
   */
  unmetAcr(acrs: string[], session: Json): string[] {
    const { log, stepUp } = this.deps;
    log.debug("Entering GnapRights.unmetAcr().");
    const facts = session || {};
    const out = (acrs || []).filter(function (one: string): boolean {
      return !!one && !stepUp.meets(one, facts);
    });
    log.debug("Leaving GnapRights.unmetAcr(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE RESOURCE SERVERS THE CATALOGUE SAYS A SET OF RIGHTS IS FOR (#432
  // phase 4): the owner of each right of a catalogued type. Beside
  // `gnap_grants.ts`'s reference and location reading, so a right that names
  // no location is still audienced to the API that defines it.
  // -------------------------------------------------------------------------
  /**
   * Returns the owning resource servers of the catalogued rights in a set.
   *
   * @param access - the access rights
   * @returns application identifiers
   */
  ownersOf(access: Json[]): string[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering GnapRights.ownersOf().");
    const out: string[] = [];
    (access || []).forEach(function (right: Json): void {
      const entry = self.entryOf(right);
      if (entry && entry.identifier && out.indexOf(entry.identifier) < 0) {
        out.push(entry.identifier);
      }
    });
    log.debug("Leaving GnapRights.ownersOf(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // DERIVATION BEYOND THE ORIGINAL (rcbj's decision 3 on #432): a right of a
  // catalogued type whose `derivableFrom` names a type the original token
  // carries. Object rights only — a reference string has no type to declare
  // anything about.
  // -------------------------------------------------------------------------
  /**
   * Tells whether a right the original token does not cover may be derived,
   * by the catalogue's `derivableFrom`.
   *
   * @param original - the original token's rights
   * @param right - the right asked for
   * @returns the original type it is derivable from, or ''
   */
  derivable(original: Json[], right: Json): string {
    const { log, catalogue } = this.deps;
    log.debug("Entering GnapRights.derivable().");
    if (!right || typeof right !== 'object') {
      log.debug("Leaving GnapRights.derivable(). A reference.");
      return '';
    }
    const types = (original || []).filter(function (one: Json): boolean {
      return !!one && typeof one === 'object';
    }).map(function (one: Json): string {
      return String(one.type);
    });
    const from = catalogue.derivableFrom(right.type, types);
    log.debug("Leaving GnapRights.derivable(). " + (from || 'No.'));
    return from;
  }

  // -------------------------------------------------------------------------
  // WHAT A RESOURCE SERVER IS TOLD AT INTROSPECTION (RFC 9767 section 3.3):
  // the token's rights of types ANOTHER resource server owns withheld, and
  // the person's claims this one's types declare (`introspectionClaims`).
  // `authorization_details.ts`'s `introspectionView()` is the one reading,
  // shared with `/oauth2/introspect`.
  // -------------------------------------------------------------------------
  /**
   * Filters a token's access for the resource server introspecting it.
   *
   * @param record - the token record
   * @param rs - the resource server's application entry
   * @returns `{ rights, claims }`
   */
  introspection(record: Json, rs: Json): Json {
    const { log, catalogue } = this.deps;
    log.debug("Entering GnapRights.introspection().");
    const view = catalogue.introspectionView(record.access || [],
                                             String((rs && rs.identifier) ||
                                                    ''),
                                             record.username || '');
    log.debug("Leaving GnapRights.introspection().");
    return { rights: view.rights, claims: view.claims };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2): see
// `common/instance_slot.ts`. A process that loads this module without the
// root builds the default when it loads.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapRights>(
  'gnap/gnap_rights',
  () => new GnapRights(GnapRights.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * GNAP access rights against the access-type catalogue and the issuance
 * policy (#432 phases 3 and 4). A library that registers no route.
 *
 * @namespace
 */
export = {
  GnapRights: GnapRights,
  installInstance: (instance: GnapRights): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  STAGES: GnapRights.STAGES,
  DEMO_TYPE: DEMO_TYPE,
  entryOf: slot.forward('entryOf'),
  conformanceRefusal: slot.forward('conformanceRefusal'),
  narrowed: slot.forward('narrowed'),
  judge: slot.forward('judge'),
  ownersOf: slot.forward('ownersOf'),
  derivable: slot.forward('derivable'),
  unmetAcr: slot.forward('unmetAcr'),
  introspection: slot.forward('introspection')
};
