// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen.ts
//
// ===========================================================================
// THE AUTHZEN AUTHORIZATION API (#563): THE ROUTES.
//
//   POST /access/v1/evaluation    one access evaluation (section 6) — #1161
//   GET  /.well-known/authzen-configuration[/realm/<id>]
//                                 the PDP's metadata (section 9) — #1163
//   POST /access/v1/evaluations   a batch of evaluations (section 7) — #1164
//   POST /access/v1/search/{subject,resource,action}
//                                 the three searches (section 8) — #1175
//
// per realm, under the realm's prefix. Deliberately thin, as `xacml/xacml.ts`
// is: it reads a request, asks `authzen_caller.ts` who is asking and whether
// they may, asks `authzen_map.ts` what the question is, hands the XACML
// request to the XACML surface's own `decide()` against the realm's ROOT
// policy and `enforce()`s the answer deny-biased, and writes what comes back.
// No decision logic lives here. **An application that enforces fine-grained
// authorization is the one exception (#564, P4)**: its evaluations are
// decided against ITS OWN policy, through `xacml/fga_pep.ts`'s
// `decideAccess()`, with the same result rules — `evaluateOne()` argues it.
//
// **A DENIAL IS A 200, AN ERROR IS NOT.** Section 5.5: `decision: false` is
// an answer. A request that could not be evaluated is 400 (its shape or a
// value), 401 (no caller), 403 (a caller that may not ask, or not about that
// application) or 500 (a fault the PDP reached), and never `false` — a PEP
// told `false` about a broken policy enforces its bias over somebody else's
// outage.
//
// **`X-Request-ID` IS ECHOED** whenever it was sent (section 10.1's MUST), on
// every answer including a refusal, and only when it is a printable token of
// at most 128 characters: a header value this service reflects is never
// arbitrary text.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50): `AuthzenSurface` takes what it uses through
// its constructor, `registerRoutes(app)` holds every route and requiring this
// module registers none — `common/protocol_stack.ts` calls it at 23c-ii,
// right after the XACML family's two. The exports are facades over the
// instance the root builds (`common/instance_slot.ts`).
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import catalogue = require('./authzen_catalogue');
import map = require('./authzen_map');
import callers = require('./authzen_caller');
import search = require('./authzen_search');

const { log } = helpers;

type Req = import('express').Request;
type Res = import('express').Response;
type Handler = (req: Req, res: Res, next?: () => void) => unknown;

// The routes' own table of what an express app offers.
interface RouteTable {
  get(path: string, ...handlers: Handler[]): unknown;
  post(path: string, ...handlers: Handler[]): unknown;
}

// The identifier of the API's own resource object, which carries the
// catalogue and whose absence turns the API off (#1140's rule).
const API_OBJECT = 'sts-authzen-api';

// The paths.
const EVALUATION_PATH = '/access/v1/evaluation';
const EVALUATIONS_PATH = '/access/v1/evaluations';
const METADATA_PATH = '/.well-known/authzen-configuration';
// The three searches (#1175), at the specification's default paths.
const SEARCH_PATH = '/access/v1/search/';

// The three batch semantics (section 7.1.2), the first the default.
const SEMANTICS = Object.freeze(['execute_all', 'deny_on_first_deny',
                                 'permit_on_first_permit']);

// The members a batch request may carry.
const BATCH_MEMBERS = Object.freeze(['subject', 'action', 'resource',
                                     'context', 'evaluations', 'options']);

// A request id this service will echo.
const REQUEST_ID = /^[\x21-\x7e]{1,128}$/;

// What a PEP is told when an application that enforces fine-grained
// authorization has no usable policy (#564, STS-AUTHZEN-0046): that it is an
// error, and nothing about the policy, which is the deployment's business.
const UNUSABLE_MESSAGE = 'The application\'s fine-grained authorization ' +
  'policy cannot be used, so the request could not be evaluated.';

// One evaluation's result: a decision, or an error, with what was recorded.
interface ItemResult {
  status: number;
  decision: boolean;
  context?: any;
  error?: { status: number; message: string };
  code?: string;
}

interface SurfaceDeps {
  log: typeof log;
  helpers: any;
  config: any;
  audit: any;
  errorCodes: any;
  realms: any;
  applications: any;
  caller: any;
  search: any;
  loadXacml(): any;
  loadMonitor(): any;
  // The embedded FGA PEP (#564, P4), for an application that enforces
  // fine-grained authorization: lazily, as the XACML surface is.
  loadFgaPep(): any;
  // The authorization server's published-document signer, for
  // `signed_metadata` (#1178): required when a document is signed.
  loadOauth2(): any;
}

/**
 * The AuthZEN Authorization API's routes over the XACML engine.
 */
class AuthzenSurface {
  /**
   * Builds the surface over its dependencies.
   *
   * @param deps - the logger, settings, audit log, error codes, realms, the
   *   application registry, the caller checks, and lazy loaders for the
   *   XACML surface and its monitor
   */
  constructor(private readonly deps: SurfaceDeps) {
    deps.log.debug("Entering AuthzenSurface.constructor().");
    deps.log.debug("Leaving AuthzenSurface.constructor().");
  }

  /**
   * The dependencies built from the real modules, as the composition root
   * passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): SurfaceDeps {
    log.debug("Entering AuthzenSurface.defaultDeps().");
    log.debug("Leaving AuthzenSurface.defaultDeps().");
    return {
      log: log,
      helpers: helpers,
      config: require('../common/config'),
      audit: require('../common/audit'),
      errorCodes: require('../common/error_codes'),
      realms: require('../common/realms'),
      applications: require('../common/applications'),
      caller: new callers.AuthzenCaller(callers.AuthzenCaller.defaultDeps()),
      search: new search.AuthzenSearch(search.AuthzenSearch.defaultDeps()),
      loadXacml: function (): any {
        log.debug("Entering loadXacml().");
        log.debug("Leaving loadXacml().");
        return require('../xacml/xacml');
      },
      loadMonitor: function (): any {
        log.debug("Entering loadMonitor().");
        log.debug("Leaving loadMonitor().");
        return require('../xacml/xacml_monitor');
      },
      loadFgaPep: function (): any {
        log.debug("Entering loadFgaPep().");
        log.debug("Leaving loadFgaPep().");
        return require('../xacml/fga_pep');
      },
      loadOauth2: function (): any {
        log.debug("Entering loadOauth2().");
        log.debug("Leaving loadOauth2().");
        return require('../oauth-oidc/oauth2');
      }
    };
  }

  /**
   * Whether the API answers in this realm: `authzen.enabled`, and the XACML
   * engine it decides with (`xacml.enabled`).
   *
   * @returns true when both are on
   */
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AuthzenSurface.enabled().");
    log.debug("Leaving AuthzenSurface.enabled().");
    return config.value('authzen.enabled') !== false &&
           config.value('xacml.enabled') !== false;
  }

  /**
   * The realm's resource object for this API, or null when an operator
   * removed it — which turns the API off.
   *
   * @returns the registry's view of `sts-authzen-api`, or null
   */
  apiObject(): any {
    const { log, applications } = this.deps;
    log.debug("Entering AuthzenSurface.apiObject().");
    let found = null;
    try {
      found = applications.get(API_OBJECT);
    } catch (e) {
      log.debug("Caught in AuthzenSurface.apiObject(): " +
                ((e && e.message) || e));
      found = null;
    }
    log.debug("Leaving AuthzenSurface.apiObject(). " + !!found);
    return found;
  }

  // THE ROUTES STAY REGISTERED AND ANSWER 501 when the API is off, as
  // XACML's do: the feature being off and the URL being wrong are different
  // sentences to a PEP.
  private offCheck(res: Res): boolean {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering AuthzenSurface.offCheck().");
    if (!self.enabled()) {
      errorCodes.mark(res, 'STS-AUTHZEN-0013');
      callers.send(res, 501, 'The AuthZEN API is turned off in this realm ' +
                   '(authzen.enabled, or xacml.enabled, whose engine it ' +
                   'decides with).');
      log.debug("Leaving AuthzenSurface.offCheck(). Off.");
      return true;
    }
    if (!self.apiObject()) {
      errorCodes.mark(res, 'STS-AUTHZEN-0014');
      callers.send(res, 501, 'This realm has no ' + API_OBJECT + ' ' +
                   'application, the AuthZEN API\'s resource object, so the ' +
                   'API is off here.');
      log.debug("Leaving AuthzenSurface.offCheck(). No object.");
      return true;
    }
    log.debug("Leaving AuthzenSurface.offCheck(). On.");
    return false;
  }

  /**
   * Echoes the caller's `X-Request-ID`, when it is one this service will
   * reflect.
   *
   * @param req - the request
   * @param res - the response
   * @returns the id, or ''
   */
  requestId(req: Req, res: Res): string {
    const { log } = this.deps;
    log.debug("Entering AuthzenSurface.requestId().");
    const sent = String(req.headers['x-request-id'] || '');
    if (!REQUEST_ID.test(sent)) {
      log.debug("Leaving AuthzenSurface.requestId(). None to echo.");
      return '';
    }
    res.set('X-Request-ID', sent);
    log.debug("Leaving AuthzenSurface.requestId().");
    return sent;
  }

  /**
   * The realm's catalogue rows, read off its resource object.
   *
   * @returns the rows
   */
  rows(): any[] {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering AuthzenSurface.rows().");
    const object = self.apiObject();
    const values = object && object.fields
      ? object.fields.authzenAttribute : null;
    const read = catalogue.rowsOf(values);
    if (read.problems.length) {
      log.warn(errorCodes.tag('STS-AUTHZEN-0010') + 'authzen: ' +
               read.problems.length + ' value(s) of authzenAttribute on ' +
               API_OBJECT + ' are not used: ' +
               read.problems.slice(0, 3).join('; '));
    }
    log.debug("Leaving AuthzenSurface.rows(). " + read.rows.length);
    return read.rows;
  }

  /**
   * Parses a request body as JSON, or null when it is not JSON.
   *
   * @param req - the request
   * @returns the parsed value, or undefined when it does not parse
   */
  static bodyOf(req: Req): unknown {
    log.debug("Entering AuthzenSurface.bodyOf().");
    const raw = typeof req.body === 'string' ? req.body
      : (Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');
    try {
      log.debug("Leaving AuthzenSurface.bodyOf().");
      return JSON.parse(raw);
    } catch (e) {
      log.debug("Caught in AuthzenSurface.bodyOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving AuthzenSurface.bodyOf(). Not JSON.");
      return undefined;
    }
  }

  /**
   * Whether a subject type names a directory person in this realm
   * (`authzen.resolveSubjectTypes`).
   *
   * @param type - `subject.type`
   * @returns true when the PIP is to answer for it
   */
  resolves(type: string): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AuthzenSurface.resolves().");
    const raw = config.value('authzen.resolveSubjectTypes');
    const list = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one: unknown) {
        return String(one).trim();
      }).filter(Boolean);
    log.debug("Leaving AuthzenSurface.resolves().");
    return list.indexOf(String(type)) >= 0;
  }

  /**
   * Evaluates one access evaluation request for an admitted caller, and
   * records it: the audit row and the monitor's count.
   *
   * @param body - the evaluation, as JSON
   * @param caller - the authenticated, admitted caller
   * @param rows - the realm's catalogue
   * @param batchId - the request id, or the batch's, for the audit row
   * @param where - the endpoint, for the audit row
   * @returns the item's result
   */
  evaluateOne(body: unknown, caller: any, rows: any[], batchId: string,
              where: string): ItemResult {
    const self = this;
    const { log, config, audit, errorCodes, realms } = this.deps;
    log.debug("Entering AuthzenSurface.evaluateOne().");
    const failed = function (status: number, code: string,
                             message: string): ItemResult {
      log.debug("Entering failed(). " + code);
      log.debug("Leaving failed().");
      return { status: status, decision: false, code: code,
               error: { status: status, message: message } };
    };
    const read = map.read(body, rows);
    if (read.refusal) {
      log.debug("Leaving AuthzenSurface.evaluateOne(). " +
                read.refusal.code);
      return failed(read.refusal.status, read.refusal.code,
                    read.refusal.message);
    }
    const evaluation = read.evaluation;
    const scoped = self.deps.caller.applicationOf(caller,
                                                  evaluation.application);
    if (!scoped.application) {
      log.debug("Leaving AuthzenSurface.evaluateOne(). " + scoped.code);
      return failed(scoped.status, scoped.code, scoped.message);
    }
    const decided = self.decideEvaluation(evaluation, caller.name,
                                          scoped.application);
    if (decided.unusable) {
      // AN ERROR, NEVER `false` (#564, decision 8): the application enforces
      // fine-grained authorization and there is nothing to decide with — no
      // reference, a policy that is missing, not its own, disabled or will
      // not parse (STS-FGA-0003 to 0007), no such application (0009), or a
      // throw or an unreadable registry (0015). Not counted on the monitor:
      // no engine decided anything.
      self.recordUnusable(caller, evaluation, scoped.application, batchId,
                          where, decided.unusable.code,
                          decided.unusable.policy);
      log.debug("Leaving AuthzenSurface.evaluateOne(). " +
                decided.unusable.code);
      return failed(500, 'STS-AUTHZEN-0046', UNUSABLE_MESSAGE);
    }
    const outcome = decided.outcome;
    const faultCode = decided.faultCode;
    const decidedBy = decided.decidedBy;
    const recorded = outcome.fault
      ? (faultCode || 'STS-AUTHZEN-0028')
      : (outcome.obligationProblems.length ? 'STS-AUTHZEN-0041'
        : (outcome.undischargeable.length ? 'STS-AUTHZEN-0029' : ''));
    // WHAT THE ROW CARRIES: who asked, about which application, the two
    // types and the action, the request id, the decision — and NO property
    // value and no credential (decision 9). Since #564, the application's
    // fine-grained policy, its PolicyId and version, when it decided.
    audit.audit({
      action: 'authzen.decision',
      actor: caller.name,
      protocol: 'AuthZEN',
      errorCode: recorded || undefined,
      detail: where + ' decided ' + (outcome.fault ? 'nothing (a fault)'
        : String(outcome.decision) + ' (XACML ' + outcome.xacmlDecision +
          ')') + ' for a ' + evaluation.subject.type + ' to ' +
        evaluation.action.name + ' a ' + evaluation.resource.type +
        ', application "' + scoped.application + '"' +
        AuthzenSurface.decidedByText(decidedBy) +
        (batchId ? ', request ' + batchId : '') +
        (outcome.discharged.length ? '; discharged ' +
          outcome.discharged.join(', ') : '') +
        (outcome.undischargeable.length ? '; refused for the obligation ' +
          outcome.undischargeable.join(', ') : '') +
        (outcome.obligations.length ? '; handed the obligation type(s) ' +
          outcome.obligations.map(function (one: any) {
            return one.type;
          }).join(', ') : '') +
        (outcome.obligationProblems.length ? '; ' +
          outcome.obligationProblems.join('; ') : '') + '.'
    });
    if (outcome.fault) {
      log.error(errorCodes.tag('STS-AUTHZEN-0028') + 'authzen: the PDP ' +
                'could not evaluate a request: ' + outcome.why);
      log.debug("Leaving AuthzenSurface.evaluateOne(). A fault.");
      return failed(500, 'STS-AUTHZEN-0028',
                    'The PDP could not evaluate the request.');
    }
    const out: ItemResult = { status: 200, decision: outcome.decision };
    if (config.value('authzen.returnReasons') === true) {
      out.context = map.reasons(outcome);
    }
    // `context.obligations` (#1177): the reserved key the profile names, in
    // the same context as any reasons.
    if (outcome.obligations.length) {
      out.context = Object.assign(out.context || {},
                                  { obligations: outcome.obligations });
    }
    log.debug("Leaving AuthzenSurface.evaluateOne(). " + outcome.decision);
    return out;
  }

  /**
   * Decides one evaluation that has been read and scoped: the XACML request
   * built, the policy asked, the answer enforced and mapped back, and the
   * decision counted. The one place a question is put to a policy, for an
   * evaluation, a batch item and every candidate of a search.
   *
   * WHICH POLICY DECIDES (#564, P4; rcbj's decision 4, which amends #563's
   * decision 7). An application that ENFORCES fine-grained authorization
   * (`appFgaEnforced`, read from the registry — no XACML is needed to ask)
   * is decided against ITS OWN policy alone, through the embedded FGA PEP's
   * `decideAccess()`: the same resolve and the same `decidePolicy()` an
   * issuance question uses, so the two can never disagree about which
   * policy is the application's. Every other application — FGA off, or no
   * such entry — is decided against the realm ROOT exactly as before. Being
   * here, the routing holds for a search's candidates as for an evaluation
   * (#1175 decides each candidate through this method).
   *
   * A registry that cannot be read is NOT read as "not enforced": that
   * would route an enforcing application's question to the root, which is
   * the restriction silently not applying. It is `unusable`, as a policy
   * that cannot be used is, and the caller answers an error.
   *
   * @param evaluation - the evaluation `authzen_map.ts` read
   * @param callerName - the trusted caller
   * @param application - the trusted application
   * @returns `{ outcome, faultCode, decidedBy, unusable }`: `unusable` is
   *   `{ code, policy }` (nothing else set) when the application enforces
   *   and its policy cannot be used; `decidedBy` is `decideAccess()`'s
   *   answer when the application's policy decided, else null
   */
  decideEvaluation(evaluation: any, callerName: string,
                   application: string): any {
    const self = this;
    const { log, config, errorCodes, realms } = this.deps;
    log.debug("Entering AuthzenSurface.decideEvaluation().");
    let fgaEnforced = false;
    try {
      fgaEnforced = !!self.deps.applications.fgaStateOf(
        application).enforced;
    } catch (e) {
      log.debug("Caught in AuthzenSurface.decideEvaluation(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-AUTHZEN-0046') + 'authzen: whether "' +
                application + '" enforces fine-grained ' +
                'authorization could not be read: ' +
                ((e && e.message) || e));
      log.debug("Leaving AuthzenSurface.decideEvaluation(). FGA unreadable.");
      return { unusable: { code: 'STS-FGA-0015', policy: '' } };
    }
    const request = map.request(evaluation, {
      realm: String(realms.currentId() || ''),
      caller: callerName,
      application: application,
      fga: fgaEnforced
    });
    const xacml = self.deps.loadXacml();
    const resolve = self.resolves(evaluation.subject.type);
    let answer: any;
    let decidedBy: any = null;
    if (fgaEnforced) {
      const routed = self.deps.loadFgaPep().decideAccess(
        application, request, { resolve: resolve });
      if (!routed || !routed.ok) {
        const code = String((routed && routed.code) || 'STS-FGA-0015');
        log.warn(errorCodes.tag('STS-AUTHZEN-0046') + 'authzen: "' +
                 application + '" enforces fine-grained ' +
                 'authorization and its policy cannot be used (' + code +
                 '); the evaluation is an error.');
        log.debug("Leaving AuthzenSurface.decideEvaluation(). " + code);
        return { unusable: { code: code,
                             policy: String((routed && routed.policy) ||
                                            '') } };
      }
      answer = routed.answer;
      decidedBy = routed;
    } else {
      answer = xacml.decide(request, { resolve: resolve });
    }
    const faultCode = String(errorCodes.codeOf(answer) || '');
    const enforcement = xacml.enforce(answer, 'deny-biased');
    // THE OBLIGATIONS PROFILE (#1177), while `authzen.obligationsProfile`
    // is on: the PEP's declaration decides what is handed (`outcome()`),
    // whichever policy decided.
    const profile = config.value('authzen.obligationsProfile') !== false;
    const outcome = map.outcome(answer, enforcement, faultCode,
      profile ? evaluation.supportedObligations : null);
    // COUNTED AS A DECISION AND NOT AN ENFORCEMENT, the PDP endpoint's
    // reason: the caller enforced it, in its own process. ON THIS ROW
    // WHICHEVER POLICY DECIDED (#564): the monitor's rows are per ASKER, and
    // the asker is an AuthZEN PEP; the `fga` row counts what this process
    // ENFORCES at issuance, and counting this there would claim an
    // enforcement nobody here made — and counting it on both, one decision
    // twice. The audit row says which policy decided.
    self.deps.loadMonitor().record('authzen', { decision: answer.decision });
    log.debug("Leaving AuthzenSurface.decideEvaluation().");
    return { outcome: outcome, faultCode: faultCode, decidedBy: decidedBy,
             unusable: null };
  }

  /**
   * Whether the search endpoints answer in this realm
   * (`authzen.searchEnabled`).
   *
   * @returns true unless switched off
   */
  searchEnabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AuthzenSurface.searchEnabled().");
    log.debug("Leaving AuthzenSurface.searchEnabled().");
    return config.value('authzen.searchEnabled') !== false;
  }

  /**
   * Runs one search (section 8) for a caller: the request read, its
   * candidates each decided as an evaluation, the permitted ones paged.
   * One audit row per search. Shared by the three routes and the reports
   * application's sources (#1176), whose caller is the signed-in person.
   *
   * @param kind - subject, resource or action
   * @param given - the request
   * @param caller - the caller, `{ name }` with the scope checks applied by
   *   `applicationOf()` when `checkScope` is true
   * @param options - `checkScope` (false for a caller whose application is
   *   given), `application` (the application then), `where` and `id`
   * @returns `{ status, body }` or `{ status, code, error }`
   */
  runSearch(kind: string, given: unknown, caller: any, options: any): any {
    const self = this;
    const { log, config, audit, errorCodes } = this.deps;
    log.debug("Entering AuthzenSurface.runSearch(). " + kind);
    const opts = options || {};
    const failed = function (status: number, code: string,
                             message: string): any {
      log.debug("Entering failed(). " + code);
      log.debug("Leaving failed().");
      return { status: status, code: code,
               error: { status: status, message: message } };
    };
    const asked = self.deps.search.read(kind, given);
    if (asked.refusal) {
      log.debug("Leaving AuthzenSurface.runSearch(). " + asked.refusal.code);
      return failed(asked.refusal.status, asked.refusal.code,
                    asked.refusal.message);
    }
    const read = map.read(asked.body, self.rows());
    if (read.refusal) {
      log.debug("Leaving AuthzenSurface.runSearch(). " + read.refusal.code);
      return failed(read.refusal.status, read.refusal.code,
                    read.refusal.message);
    }
    const evaluation = read.evaluation;
    let application = String(opts.application || '');
    if (opts.checkScope !== false) {
      const scoped = self.deps.caller.applicationOf(caller,
                                                    evaluation.application);
      if (!scoped.application) {
        log.debug("Leaving AuthzenSurface.runSearch(). " + scoped.code);
        return failed(scoped.status, scoped.code, scoped.message);
      }
      application = scoped.application;
    }
    const offset = self.deps.search.offsetOf(asked.page.token,
                                             asked.fingerprint);
    if (offset < 0) {
      log.debug("Leaving AuthzenSurface.runSearch(). A foreign token.");
      return failed(400, 'STS-AUTHZEN-0043', 'page.token is not one this ' +
                    'search issued, or the request changed since it was ' +
                    'issued; a continued request must repeat every entity ' +
                    'and the limit unchanged (section 8.2).');
    }
    const most = Number(config.value('authzen.searchMaxCandidates'));
    const named = self.deps.search.candidates(kind, evaluation,
      self.resolves(evaluation.subject.type), most);
    const permitted: string[] = [];
    let faults = 0;
    let unusable: any = null;
    named.values.forEach(function (candidate: string) {
      if (unusable) {
        return;
      }
      const one = JSON.parse(JSON.stringify(evaluation));
      if (kind === 'subject') {
        one.subject.id = candidate;
      } else if (kind === 'resource') {
        one.resource.id = candidate;
      } else {
        one.action.name = candidate;
      }
      const decided = self.decideEvaluation(one, caller.name, application);
      if (decided.unusable) {
        unusable = decided.unusable;
      } else if (decided.outcome.fault) {
        faults += 1;
      } else if (decided.outcome.decision === true) {
        permitted.push(candidate);
      }
    });
    // AN APPLICATION WHOSE FINE-GRAINED POLICY CANNOT BE USED (#564): the
    // whole search is an error, never an empty or partial answer and never
    // the root's — every candidate would meet the same policy, so a result
    // without them would be the restriction answering "nobody" by accident.
    // The row carries the STS-FGA code that says why.
    if (unusable) {
      audit.audit({
        action: 'authzen.search',
        actor: caller.name,
        protocol: 'AuthZEN',
        errorCode: unusable.code,
        detail: String(opts.where || 'search') + ' searched ' + kind +
          's and decided nothing (the fine-grained authorization policy' +
          (unusable.policy ? ' "' + unusable.policy + '"' : '') +
          ' of application "' + application + '" cannot be used, ' +
          unusable.code + ')' + (opts.id ? ', request ' + opts.id : '') + '.'
      });
      log.debug("Leaving AuthzenSurface.runSearch(). " + unusable.code);
      return failed(500, 'STS-AUTHZEN-0046', UNUSABLE_MESSAGE);
    }
    const limit = asked.page.limit === null
      ? Number(config.value('authzen.searchPageSize')) : asked.page.limit;
    const shown = permitted.slice(offset, offset + limit);
    const results = shown.map(function (candidate: string) {
      return kind === 'action' ? { name: candidate }
        : { type: kind === 'subject' ? evaluation.subject.type
                                     : evaluation.resource.type,
            id: candidate };
    });
    const out: any = {};
    // THE PAGE FIRST, as section 8.3 RECOMMENDS, so a PEP reads the count
    // before the results.
    out.page = { next_token: search.nextToken(offset + shown.length,
                                              permitted.length,
                                              asked.fingerprint),
                 count: shown.length, total: permitted.length };
    out.results = results;
    // AN INCOMPLETE RESULT IS SAID SO: candidates past the cap were not
    // decided, and a candidate the PDP could not decide is not a result.
    if (named.truncated || faults) {
      out.context = { incomplete: true,
        reason_admin: { en: (named.truncated
          ? 'More than authzen.searchMaxCandidates (' + most + ') ' +
            'candidates; only the first were decided. ' : '') +
          (faults ? faults + ' candidate(s) could not be decided.' : '') } };
    }
    audit.audit({
      action: 'authzen.search',
      actor: caller.name,
      protocol: 'AuthZEN',
      errorCode: named.truncated ? 'STS-AUTHZEN-0045'
        : (faults ? 'STS-AUTHZEN-0028' : undefined),
      detail: String(opts.where || 'search') + ' searched ' + kind +
        's: ' + named.values.length + ' candidate(s) decided, ' +
        permitted.length + ' permitted' + (named.truncated
          ? ', more not decided' : '') + ', application "' + application +
        '"' + (opts.id ? ', request ' + opts.id : '') + '.'
    });
    log.debug("Leaving AuthzenSurface.runSearch(). " + permitted.length +
              " permitted.");
    return { status: 200, body: out };
  }

  /**
   * The audit row's words naming the fine-grained policy that decided, or
   * '' when the realm root did.
   *
   * @param decidedBy - `decideAccess()`'s answer, or null
   * @returns the words
   */
  static decidedByText(decidedBy: any): string {
    log.debug("Entering AuthzenSurface.decidedByText().");
    if (!decidedBy) {
      log.debug("Leaving AuthzenSurface.decidedByText(). The root.");
      return '';
    }
    log.debug("Leaving AuthzenSurface.decidedByText().");
    return ', decided by its fine-grained authorization policy "' +
      String(decidedBy.policy || '') + '" (PolicyId ' +
      String(decidedBy.policyId || '-') + ', version ' +
      String(decidedBy.version || '-') + ')';
  }

  // THE ROW OF AN EVALUATION NO POLICY COULD DECIDE (#564, P4): an
  // application that enforces fine-grained authorization whose policy
  // cannot be used. The row carries the STS-FGA code that says WHY — the
  // response is marked STS-AUTHZEN-0046, which says only that it happened —
  // and the policy entry when one was named. No property value (decision 9).
  private recordUnusable(caller: any, evaluation: any, application: string,
                         batchId: string, where: string, code: string,
                         policy: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering AuthzenSurface.recordUnusable(). " + code);
    audit.audit({
      action: 'authzen.decision',
      actor: caller.name,
      protocol: 'AuthZEN',
      errorCode: code,
      detail: where + ' decided nothing (the fine-grained authorization ' +
        'policy' + (policy ? ' "' + policy + '"' : '') + ' of application "' +
        application + '" cannot be used, ' + code + ') for a ' +
        evaluation.subject.type + ' to ' + evaluation.action.name + ' a ' +
        evaluation.resource.type + (batchId ? ', request ' + batchId : '') +
        '.'
    });
    log.debug("Leaving AuthzenSurface.recordUnusable().");
  }

  /**
   * Admits a caller: authentication by the realm's door, then the policy.
   *
   * @param req - the request
   * @param res - the response, written on a refusal
   * @returns the caller, or null when a refusal was written
   */
  admit(req: Req, res: Res): any {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AuthzenSurface.admit().");
    const caller = self.deps.caller.authenticate(req, res);
    if (!caller) {
      log.debug("Leaving AuthzenSurface.admit(). Not authenticated.");
      return null;
    }
    if (!self.deps.caller.mayAsk(req, res, caller)) {
      log.debug("Leaving AuthzenSurface.admit(). The policy refused.");
      return null;
    }
    log.debug("Leaving AuthzenSurface.admit().");
    return caller;
  }

  /**
   * Whether the batch endpoint answers in this realm
   * (`authzen.batchEnabled`).
   *
   * @returns true unless switched off
   */
  batchEnabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering AuthzenSurface.batchEnabled().");
    log.debug("Leaving AuthzenSurface.batchEnabled().");
    return config.value('authzen.batchEnabled') !== false;
  }

  /**
   * The PDP's metadata document (section 9), for the realm the request is
   * answered in. It names ONLY what answers here: the single endpoint, and
   * the batch one while `authzen.batchEnabled` is on, the three searches
   * while `authzen.searchEnabled` is on (#1175), no `capabilities` — and,
   * while
   * `authzen.signedMetadata` is on, `signed_metadata` (#1178).
   *
   * @param req - the request
   * @returns the document
   */
  metadata(req: Req): any {
    const self = this;
    const { log, helpers } = this.deps;
    log.debug("Entering AuthzenSurface.metadata().");
    // THE IDENTIFIER IS THE BASE THE API IS ADVERTISED UNDER, realm prefix
    // included: section 9.2.3 has a PEP refuse a document whose
    // `policy_decision_point` is not the one it built the URL from.
    const base = String(helpers.baseUrlOf(req, 'authzen') || '');
    const out: any = {
      policy_decision_point: base,
      access_evaluation_endpoint: base + EVALUATION_PATH
    };
    if (self.batchEnabled()) {
      out.access_evaluations_endpoint = base + EVALUATIONS_PATH;
    }
    if (self.searchEnabled()) {
      out.search_subject_endpoint = base + SEARCH_PATH + 'subject';
      out.search_resource_endpoint = base + SEARCH_PATH + 'resource';
      out.search_action_endpoint = base + SEARCH_PATH + 'action';
    }
    // The Obligations Profile's member (its section 6), while it is on.
    if (self.deps.config.value('authzen.obligationsProfile') !== false) {
      out.supported_obligations = map.supportedObligationTypes();
    }
    const signed = self.signedMetadata(out);
    if (signed) {
      out.signed_metadata = signed;
    }
    log.debug("Leaving AuthzenSurface.metadata().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // `signed_metadata` (section 9.1, #1178): a JWT whose claims are the
  // document's own members and whose `iss` is the PDP identifier, signed by
  // the realm the way RFC 8414's document is — `oauth2.ts`'s
  // `signPublishedDocument()`, the one signer of a published document here,
  // under the `oauth-signed-metadata` use case, so `oauth2.signedMetadata*`'s
  // algorithm and certificate header apply and the realm's JWKS verifies it.
  // A PEP that supports it takes ITS values over the plain ones, so it is
  // signed from the very object it is answered beside, and the two cannot
  // disagree. Signed per fetch: the document is fetched once per PEP start,
  // and a cache would be a store of its own to make per realm.
  // ---------------------------------------------------------------------------
  /**
   * Signs the metadata document as its own `signed_metadata`, while
   * `authzen.signedMetadata` is on.
   *
   * @param document - the document's members
   * @returns the JWT, or '' when it is off or the signing failed
   */
  signedMetadata(document: any): string {
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering AuthzenSurface.signedMetadata().");
    if (config.value('authzen.signedMetadata') === false) {
      log.debug("Leaving AuthzenSurface.signedMetadata(). Off.");
      return '';
    }
    try {
      const signed = String(this.deps.loadOauth2().signPublishedDocument(
        Object.assign({}, document, { sub: document.policy_decision_point }),
        document.policy_decision_point, 3600, 'oauth-signed-metadata') || '');
      log.debug("Leaving AuthzenSurface.signedMetadata().");
      return signed;
    } catch (e) {
      // Left out rather than failing the document: the plain members are
      // the metadata, and signed_metadata is OPTIONAL.
      log.error(errorCodes.tag('STS-AUTHZEN-0040') + 'authzen: the ' +
                'metadata could not be signed: ' + ((e && e.message) || e));
      log.debug("Leaving AuthzenSurface.signedMetadata(). Not signed.");
      return '';
    }
  }

  // Answers the metadata in the realm the request is in, or 501 while the
  // API is off there (the document would advertise an endpoint that does
  // not answer).
  private sendMetadata(req: Req, res: Res): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering AuthzenSurface.sendMetadata().");
    if (self.offCheck(res)) {
      log.debug("Leaving AuthzenSurface.sendMetadata(). Off.");
      return;
    }
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(self.metadata(req), null, 2));
    log.debug("Leaving AuthzenSurface.sendMetadata().");
  }

  /**
   * One batch item's request: the top-level defaults, each overridden whole
   * by the item's own member (section 7.1.1).
   *
   * @param defaults - the batch request
   * @param item - one member of `evaluations`
   * @returns the evaluation request, or null when the item is not an object
   */
  static merged(defaults: any, item: unknown): any {
    log.debug("Entering AuthzenSurface.merged().");
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      log.debug("Leaving AuthzenSurface.merged(). Not an object.");
      return null;
    }
    const given: any = item;
    const out: any = {};
    ['subject', 'action', 'resource', 'context'].forEach(function (key) {
      const value = given[key] !== undefined ? given[key] : defaults[key];
      if (value !== undefined) {
        out[key] = value;
      }
    });
    // A member the item carries beyond the four is the item's own mistake,
    // and the mapping refuses it for that item alone.
    Object.keys(given).forEach(function (key: string) {
      if (out[key] === undefined && ['subject', 'action', 'resource',
                                     'context'].indexOf(key) < 0) {
        out[key] = given[key];
      }
    });
    log.debug("Leaving AuthzenSurface.merged().");
    return out;
  }

  /**
   * Answers one batch (section 7): its bounds, its semantic, each item
   * evaluated in order and answered in order.
   *
   * @param req - the request
   * @param res - the response
   * @param caller - the admitted caller
   * @param id - the request id, or ''
   */
  batch(req: Req, res: Res, caller: any, id: string): void {
    const self = this;
    const { log, config, errorCodes } = this.deps;
    log.debug("Entering AuthzenSurface.batch().");
    const refuse = function (code: string, message: string): void {
      log.debug("Entering refuse(). " + code);
      errorCodes.mark(res, code);
      // error-code: none — marked on the line above.
      callers.send(res, 400, message);
      log.debug("Leaving refuse().");
    };
    // THE BODY'S SIZE FIRST: a bound has to hold before the body is read.
    // The bytes on the wire where body-parser kept them (`app.js`), else
    // the body as it was read.
    const raw: any = (req as any).rawBody || req.body || '';
    const size = Buffer.isBuffer(raw) ? raw.length
      : Buffer.byteLength(String(raw));
    const cap = Number(config.value('authzen.maxBodyBytes'));
    if (size > cap) {
      refuse('STS-AUTHZEN-0037', 'The request is larger than this realm\'s ' +
             'authzen.maxBodyBytes (' + cap + ' bytes).');
      log.debug("Leaving AuthzenSurface.batch(). Too large.");
      return;
    }
    const body: any = AuthzenSurface.bodyOf(req);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      refuse('STS-AUTHZEN-0001', 'An access evaluations request is a JSON ' +
             'object.');
      log.debug("Leaving AuthzenSurface.batch(). Not an object.");
      return;
    }
    const stray = Object.keys(body).filter(function (key: string) {
      return BATCH_MEMBERS.indexOf(key) < 0;
    })[0];
    if (stray) {
      refuse('STS-AUTHZEN-0009', 'An access evaluations request has no ' +
             'member "' + stray.slice(0, 64) + '"; it takes ' +
             BATCH_MEMBERS.join(', ') + '.');
      log.debug("Leaving AuthzenSurface.batch(). An unknown member.");
      return;
    }
    if (body.evaluations !== undefined && !Array.isArray(body.evaluations)) {
      refuse('STS-AUTHZEN-0003', 'evaluations must be an array.');
      log.debug("Leaving AuthzenSurface.batch(). Not an array.");
      return;
    }
    if (body.options !== undefined && (!body.options ||
        typeof body.options !== 'object' || Array.isArray(body.options))) {
      refuse('STS-AUTHZEN-0003', 'options must be a JSON object.');
      log.debug("Leaving AuthzenSurface.batch(). Bad options.");
      return;
    }
    const options = body.options || {};
    const semantic = options.evaluations_semantic === undefined
      ? SEMANTICS[0] : String(options.evaluations_semantic);
    if (SEMANTICS.indexOf(semantic) < 0) {
      refuse('STS-AUTHZEN-0036', 'options.evaluations_semantic must be one ' +
             'of ' + SEMANTICS.join(', ') + '.');
      log.debug("Leaving AuthzenSurface.batch(). Unknown semantic.");
      return;
    }
    const items = body.evaluations || [];
    const most = Number(config.value('authzen.maxEvaluations'));
    if (items.length > most) {
      refuse('STS-AUTHZEN-0038', 'The request carries ' + items.length +
             ' evaluations, and this realm answers at most ' + most +
             ' in one (authzen.maxEvaluations).');
      log.debug("Leaving AuthzenSurface.batch(). Too many.");
      return;
    }
    const rows = self.rows();
    const where = 'POST ' + EVALUATIONS_PATH;
    // NO ITEMS IS ONE EVALUATION, answered as `/access/v1/evaluation` would
    // answer it (section 7.1: "backwards-compatible").
    if (!items.length) {
      const single = AuthzenSurface.merged(body, {});
      const one = self.evaluateOne(single, caller, rows, id, where);
      if (one.error) {
        errorCodes.mark(res, one.code);
        // error-code: none — marked on the line above with the item's code.
        callers.send(res, one.status, one.error.message);
        log.debug("Leaving AuthzenSurface.batch(). One, refused.");
        return;
      }
      res.status(200).type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(one.context
           ? { decision: one.decision, context: one.context }
           : { decision: one.decision }));
      log.debug("Leaving AuthzenSurface.batch(). One.");
      return;
    }
    // THE BATCH ID ON EVERY ROW: the caller's, or one made here, so the rows
    // of one batch are found together (decision 9).
    const batchId = id || ('authzen-' +
                           self.deps.helpers.randomId(12));
    const out: any[] = [];
    for (let i = 0; i < items.length; i += 1) {
      const request = AuthzenSurface.merged(body, items[i]);
      const one = request === null
        ? { status: 400, decision: false, code: 'STS-AUTHZEN-0001',
            error: { status: 400, message: 'An evaluation is a JSON ' +
                                           'object.' } }
        : self.evaluateOne(request, caller, rows,
                           batchId + '#' + i, where);
      // AN ITEM'S FAILURE IS ITS OWN, said in its own context.error and
      // never hidden by the batch's 200 (section 7.2). It is still false,
      // which is the fail-closed reading of an item nobody could decide.
      if (one.error) {
        out.push({ decision: false, context: { error: one.error } });
      } else {
        out.push(one.context ? { decision: one.decision,
                                 context: one.context }
                             : { decision: one.decision });
      }
      const denied = !!one.error || one.decision === false;
      if ((semantic === 'deny_on_first_deny' && denied) ||
          (semantic === 'permit_on_first_permit' && !one.error &&
           one.decision === true)) {
        break;
      }
    }
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ evaluations: out }));
    log.debug("Leaving AuthzenSurface.batch(). " + out.length + " of " +
              items.length + " answered.");
  }

  /**
   * Registers the routes on the shared app.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering AuthzenSurface.registerRoutes().");

    // -----------------------------------------------------------------------
    // POST /access/v1/evaluation — one access evaluation (section 6).
    // -----------------------------------------------------------------------
    app.post(EVALUATION_PATH, function (req, res) {
      log.debug('Entering POST ' + EVALUATION_PATH + '.');
      const id = self.requestId(req, res);
      if (self.offCheck(res)) {
        log.debug('Leaving POST ' + EVALUATION_PATH + '. Off.');
        return;
      }
      const caller = self.admit(req, res);
      if (!caller) {
        log.debug('Leaving POST ' + EVALUATION_PATH + '. Not admitted.');
        return;
      }
      const body = AuthzenSurface.bodyOf(req);
      const result = self.evaluateOne(body === undefined ? null : body,
                                      caller, self.rows(), id,
                                      'POST ' + EVALUATION_PATH);
      if (result.error) {
        errorCodes.mark(res, result.code);
        callers.send(res, result.status, result.error.message);
        log.debug('Leaving POST ' + EVALUATION_PATH + '. ' + result.code);
        return;
      }
      const answer: any = { decision: result.decision };
      if (result.context) {
        answer.context = result.context;
      }
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify(answer));
      log.debug('Leaving POST ' + EVALUATION_PATH + '. ' + result.decision);
    });

    // -----------------------------------------------------------------------
    // POST /access/v1/evaluations — a batch (section 7).
    // -----------------------------------------------------------------------
    app.post(EVALUATIONS_PATH, function (req, res) {
      log.debug('Entering POST ' + EVALUATIONS_PATH + '.');
      const id = self.requestId(req, res);
      if (self.offCheck(res)) {
        log.debug('Leaving POST ' + EVALUATIONS_PATH + '. Off.');
        return;
      }
      if (!self.batchEnabled()) {
        errorCodes.mark(res, 'STS-AUTHZEN-0039');
        callers.send(res, 501, 'The batch endpoint is turned off in this ' +
                     'realm (authzen.batchEnabled); ' + EVALUATION_PATH +
                     ' still answers.');
        log.debug('Leaving POST ' + EVALUATIONS_PATH + '. Batch off.');
        return;
      }
      const caller = self.admit(req, res);
      if (!caller) {
        log.debug('Leaving POST ' + EVALUATIONS_PATH + '. Not admitted.');
        return;
      }
      self.batch(req, res, caller, id);
      log.debug('Leaving POST ' + EVALUATIONS_PATH + '.');
    });

    // -----------------------------------------------------------------------
    // POST /access/v1/search/{subject,resource,action} — section 8 (#1175).
    // -----------------------------------------------------------------------
    search.KINDS.forEach(function (kind: string) {
      const path = SEARCH_PATH + kind;
      app.post(path, function (req, res) {
        log.debug('Entering POST ' + path + '.');
        const id = self.requestId(req, res);
        if (self.offCheck(res)) {
          log.debug('Leaving POST ' + path + '. Off.');
          return;
        }
        if (!self.searchEnabled()) {
          errorCodes.mark(res, 'STS-AUTHZEN-0044');
          callers.send(res, 501, 'The search endpoints are turned off in ' +
                       'this realm (authzen.searchEnabled).');
          log.debug('Leaving POST ' + path + '. Search off.');
          return;
        }
        const caller = self.admit(req, res);
        if (!caller) {
          log.debug('Leaving POST ' + path + '. Not admitted.');
          return;
        }
        const body = AuthzenSurface.bodyOf(req);
        const result = self.runSearch(kind, body === undefined ? null : body,
                                      caller, { where: 'POST ' + path,
                                                id: id });
        if (result.error) {
          errorCodes.mark(res, result.code);
          // error-code: none — marked on the line above with its code.
          callers.send(res, result.status, result.error.message);
          log.debug('Leaving POST ' + path + '. ' + result.code);
          return;
        }
        res.status(200).type('application/json')
           .set('Cache-Control', 'no-store')
           .send(JSON.stringify(result.body));
        log.debug('Leaving POST ' + path + '.');
      });
    });

    // -----------------------------------------------------------------------
    // GET /.well-known/authzen-configuration — the metadata (section 9).
    //
    // SECTION 9.2 INSERTS the well-known segment between the host and the
    // PDP identifier's path, so a realm's document is
    // `/.well-known/authzen-configuration/realm/<id>`, which arrives at the
    // host root with the realm after it — RFC 8414's shape, read the way
    // `oauth2.ts`'s `issuerPathTarget()` reads it. The appended form
    // (`/realm/<id>/.well-known/...`) is answered too, already in its realm,
    // with the same identifier, since it names the same PDP. Anything else
    // after the segment names no PDP and is Express's 404.
    // -----------------------------------------------------------------------
    app.get(METADATA_PATH, function (req, res) {
      log.debug('Entering GET ' + METADATA_PATH + '.');
      self.sendMetadata(req, res);
      log.debug('Leaving GET ' + METADATA_PATH + '.');
    });
    app.get(METADATA_PATH + '/*', function (req, res, next) {
      log.debug('Entering GET ' + METADATA_PATH + '/*.');
      const { realms } = self.deps;
      const segments = String((req.params as any)[0] || '').split('/')
        .filter(Boolean);
      const named = segments.length === 2 && segments[0] === 'realm' &&
                    realms.isDefault() && segments[1] !== realms.DEFAULT_ID
        ? realms.get(segments[1]) : null;
      if (!named) {
        errorCodes.mark(res, 'STS-AUTHZEN-0035');
        log.debug('Leaving GET ' + METADATA_PATH + '/*. Names no PDP.');
        next();
        return;
      }
      realms.run(named, function () {
        self.sendMetadata(req, res);
      });
      log.debug('Leaving GET ' + METADATA_PATH + '/*.');
    });

    log.debug("Leaving AuthzenSurface.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), as `xacml.ts`'s is.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AuthzenSurface>(
  'authzen/authzen',
  () => new AuthzenSurface(AuthzenSurface.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The AuthZEN Authorization API, registered by `common/protocol_stack.ts`.
 * @namespace
 */
export = {
  registerRoutes: (target: any): void => slot.get().registerRoutes(target),
  AuthzenSurface: AuthzenSurface,
  installInstance: (instance: AuthzenSurface): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  enabled: slot.forward('enabled'),
  metadata: slot.forward('metadata'),
  runSearch: slot.forward('runSearch'),
  searchEnabled: slot.forward('searchEnabled'),
  API_OBJECT: API_OBJECT,
  EVALUATION_PATH: EVALUATION_PATH,
  EVALUATIONS_PATH: EVALUATIONS_PATH,
  METADATA_PATH: METADATA_PATH,
  SEMANTICS: SEMANTICS
};
