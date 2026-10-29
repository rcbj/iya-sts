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
//
// per realm, under the realm's prefix. Deliberately thin, as `xacml/xacml.ts`
// is: it reads a request, asks `authzen_caller.ts` who is asking and whether
// they may, asks `authzen_map.ts` what the question is, hands the XACML
// request to the XACML surface's own `decide()` against the realm's ROOT
// policy and `enforce()`s the answer deny-biased, and writes what comes back.
// No decision logic lives here.
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

// A request id this service will echo.
const REQUEST_ID = /^[\x21-\x7e]{1,128}$/;

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
  config: any;
  audit: any;
  errorCodes: any;
  realms: any;
  applications: any;
  caller: any;
  loadXacml(): any;
  loadMonitor(): any;
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
      config: require('../common/config'),
      audit: require('../common/audit'),
      errorCodes: require('../common/error_codes'),
      realms: require('../common/realms'),
      applications: require('../common/applications'),
      caller: new callers.AuthzenCaller(callers.AuthzenCaller.defaultDeps()),
      loadXacml: function (): any {
        log.debug("Entering loadXacml().");
        log.debug("Leaving loadXacml().");
        return require('../xacml/xacml');
      },
      loadMonitor: function (): any {
        log.debug("Entering loadMonitor().");
        log.debug("Leaving loadMonitor().");
        return require('../xacml/xacml_monitor');
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
    const request = map.request(evaluation, {
      realm: String(realms.currentId() || ''),
      caller: caller.name,
      application: scoped.application
    });
    const xacml = self.deps.loadXacml();
    const answer = xacml.decide(request,
      { resolve: self.resolves(evaluation.subject.type) });
    const faultCode = String(errorCodes.codeOf(answer) || '');
    const enforcement = xacml.enforce(answer, 'deny-biased');
    const outcome = map.outcome(answer, enforcement, faultCode);
    // COUNTED AS A DECISION AND NOT AN ENFORCEMENT, the PDP endpoint's
    // reason: the caller enforced it, in its own process.
    self.deps.loadMonitor().record('authzen', { decision: answer.decision });
    const recorded = outcome.fault
      ? (faultCode || 'STS-AUTHZEN-0028')
      : (outcome.undischargeable.length ? 'STS-AUTHZEN-0029' : '');
    // WHAT THE ROW CARRIES: who asked, about which application, the two
    // types and the action, the request id, the decision — and NO property
    // value and no credential (decision 9).
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
        (batchId ? ', request ' + batchId : '') +
        (outcome.discharged.length ? '; discharged ' +
          outcome.discharged.join(', ') : '') +
        (outcome.undischargeable.length ? '; refused for the obligation ' +
          outcome.undischargeable.join(', ') : '') + '.'
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
    log.debug("Leaving AuthzenSurface.evaluateOne(). " + outcome.decision);
    return out;
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
  API_OBJECT: API_OBJECT,
  EVALUATION_PATH: EVALUATION_PATH
};
