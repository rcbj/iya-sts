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
const EVALUATIONS_PATH = '/access/v1/evaluations';
const METADATA_PATH = '/.well-known/authzen-configuration';

// The three batch semantics (section 7.1.2), the first the default.
const SEMANTICS = Object.freeze(['execute_all', 'deny_on_first_deny',
                                 'permit_on_first_permit']);

// The members a batch request may carry.
const BATCH_MEMBERS = Object.freeze(['subject', 'action', 'resource',
                                     'context', 'evaluations', 'options']);

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
  helpers: any;
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
      helpers: helpers,
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
   * the batch one while `authzen.batchEnabled` is on — no search endpoint
   * and no `capabilities` until one is implemented end to end, and no
   * `signed_metadata` (section 9.1 lets a PDP omit it).
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
    log.debug("Leaving AuthzenSurface.metadata().");
    return out;
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
  API_OBJECT: API_OBJECT,
  EVALUATION_PATH: EVALUATION_PATH,
  EVALUATIONS_PATH: EVALUATIONS_PATH,
  METADATA_PATH: METADATA_PATH,
  SEMANTICS: SEMANTICS
};
