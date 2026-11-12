// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models.ts
//
// ---------------------------------------------------------------------------
// EVERY RESPONSE OF AN API THIS SERVICE PUBLISHES A DOCUMENT FOR IS HELD TO
// THAT DOCUMENT (#1353, rcbj's decision, 2026-11-05).
//
// `/admin-api`, `/account-api`, `/authn-api` and `/report-api` each publish an
// OpenAPI document, and each model in it is closed. This module checks the
// answer about to leave against the model its operation declares for its
// status. **There is no setting**: it runs in every mode, on every request.
//
// **ONE DOOR, NOT ONE CALL PER SENDER.** These APIs answer through several
// hundred call sites (`sendJson()`, `AccountApi.json()`, `reportJson()`, a
// handler's own `res.status(200).send()`), and a gate refuses before any of
// them. A check at each is a check somebody forgets. Each API calls `install()`
// first in its `registerRoutes()`, which wraps `res.send` for its prefix, so a
// refusal from the gate meets the same check as a handler's answer.
//
// **WHAT A VIOLATION DOES: THE ANSWER IS NOT SENT.** The caller gets a 500
// `server_error` saying nothing of the shape, and the operator gets
// `STS-API-0139`, naming the operation, the status and where in the body it
// failed, once per distinct failure (a failure on a busy path must not become
// one line per request). Log lines carry key names and schema keywords, never
// a value: these bodies hold tokens, keys and personal data, which is why this
// validator is not `verbose`.
//
// **THE THREE THINGS IT DOES NOT CHECK.** `res.end()` and a piped stream have no
// `res.send` to pass through; `tests/openapi_response_models.js` holds that none
// of these APIs answers JSON that way, and the one stream there is, a finished
// report job's file (`report/report_api.ts`), is bytes under a declared type. An unrouted path answers Express's own
// `Cannot GET /path`, which `tests/protocol/sts_metadata.js` depends on and
// which does not use `res.send`. And a request a cell relays is checked by the
// cell that answers it.
//
// **THE VALIDATORS ARE COMPILED ON FIRST USE AND SHARE ONE COPY OF THE
// COMPONENTS** (`mgmt-api/CLAUDE.md`, #365 and #617): compiling every model at
// start, or wrapping each in its own copy, costs every process for operations
// it mostly never reaches.
//
// **A COMPILE THAT FAILS IS CONTAINED TO THE MODEL THAT FAILED (2026-11-12).**
// The ajv instance that threw is discarded, so nothing half-built inside it —
// its schema cache, the root it was compiling, the scope names it had
// reserved — is reachable from any later compile; every validator already
// compiled is a closure of its own and keeps working. The failure is
// REMEMBERED for that one model for `RETRY_MS`, and its answers are refused
// from the memory, because a compile that failed once usually fails again and
// a fresh compile on every request would make each of them expensive; after
// that, one request tries again, so a cause that has gone (a transient one, or
// a process that was repaired) costs one window and not the process's life.
// The check is the time at the read, not a timer (`cluster/CLAUDE.md`).
//
// **AND A REFUSAL ASKS WHETHER THE PROCESS IS POLLUTED** (`STS-API-0146`). On
// 2026-11-12 one write gave `Object.prototype` an enumerable `rules`
// (`xacml/xacml_editor.ts`, `nodeAt()`), and every answer of every operation
// was then refused for a member nobody had sent, because ajv reads an
// object's members with `for…in`; the compile of a new model recursed without
// end through the same member. The cause was invisible from these lines. Now
// the first refusal that sees an inherited enumerable member on a plain object
// or an array says so, by name, once: it costs a `for…in` over an empty object
// on the refusal path only.
//
// A LIBRARY (rule 3): it registers no route of its own, and requires `helpers`
// and `error_codes`, both already loaded by anything that installs it.
// ---------------------------------------------------------------------------

import AjvModule = require('ajv');
import addFormatsModule = require('ajv-formats');
import helpers = require('./helpers');
import errorCodes = require('./error_codes');

type Json = any;

// `any` for the type checker (#50): CommonJS modules whose declared types are
// ES default exports, as `mgmt-api/admin_api.ts` says of the same two.
const Ajv: any = AjvModule;
const addFormats: any = addFormatsModule;

const CODE = 'STS-API-0139';

const POLLUTED = 'STS-API-0146';

// How long a model that would not compile is answered from the memory of
// that failure before one request compiles it again.
const RETRY_MS = 60 * 1000;

// A distinct failure is logged once; the bound keeps a shape that varies by
// request from growing this set without limit.
const MAX_LOGGED = 2000;

const FAILED_BODY = JSON.stringify({
  error: 'server_error',
  error_description: 'The service could not produce a valid answer.'
});

interface Deps {
  log: Json;
  mark: (res: Json, code: string) => unknown;
  tag: (code: string) => string;
  // The clock the retry window is read on; a test passes its own.
  now?: () => number;
}

interface Unbuildable {
  at: number;
  message: string;
}

interface Installed {
  documentOf: () => Json;
  refusal: Json;
  built: Json;
  exact: Map<string, Json>;
  templated: { method: string; pattern: RegExp; operation: Json }[];
  components: Json;
}

class ResponseModels {
  private readonly deps: Deps;

  private ajv: Json;

  private readonly validators = new Map<Json, Json>();

  private readonly unbuildable = new Map<Json, Unbuildable>();

  private pollutionSaid = '';

  private prefixes: string[] = [];
  private readonly logged = new Set<string>();

  private failures = 0;

  constructor(deps: Deps) {
    this.deps = deps;
    this.ajv = this.freshAjv();
  }

  private freshAjv(): Json {
    this.deps.log.debug("Entering ResponseModels.freshAjv().");
    // `coerceTypes` off and no defaults: a validator must not change what it
    // is reading. `strict: false` for `examples` and the `x-` members.
    const ajv = new Ajv({ strict: false, allErrors: true,
                          coerceTypes: false, useDefaults: false });
    addFormats(ajv);
    this.deps.log.debug("Leaving ResponseModels.freshAjv().");
    return ajv;
  }

  /**
   * Holds every answer under `prefix` to the document `documentOf()` builds.
   * Called first in an API's `registerRoutes()`: express applies middleware
   * only to the routes added after it.
   *
   * @param app - the express app
   * @param prefix - the API's base path
   * @param documentOf - builds the OpenAPI document; asked once, at the first
   *   answer, because some operation tables are complete only by then
   * @param refusal - the model of this API's refusal, for a path no operation
   *   documents: an action nobody defined, which its `:action` route refuses
   */
  install(app: Json, prefix: string, documentOf: () => Json,
          refusal: Json): void {
    const self = this;
    this.deps.log.debug("Entering ResponseModels.install(). " + prefix);
    const installed = this.installed(documentOf, refusal);
    this.prefixes.push(prefix);
    app.use(prefix, function (req: Json, res: Json, next: Json) {
      self.wrap(installed, req, res);
      next();
    });
    this.deps.log.debug("Leaving ResponseModels.install().");
  }

  /**
   * An exception no handler caught, on a published API, answered as that API
   * answers: JSON and the same sentence, where Express's own would be an HTML
   * page no model declares. Called once, after every route is registered,
   * because Express reaches an error handler only if it comes after the route
   * that threw. A status below 500 is somebody else's and passes.
   *
   * @param app - the express app
   */
  answerExceptions(app: Json): void {
    const self = this;
    this.deps.log.debug("Entering ResponseModels.answerExceptions().");
    this.prefixes.forEach(function (prefix: string) {
      app.use(prefix, function (err: Json, req: Json, res: Json, next: Json) {
        if (res.headersSent || Number(err && err.status) < 500) {
          return next(err);
        }
        self.reportException(req, res, err);
        // error-code: none — `reportException()` marked STS-API-0140.
        res.status(500).set('Cache-Control', 'no-store')
           .type('application/json');
        return res.send(FAILED_BODY);
      });
    });
    this.deps.log.debug("Leaving ResponseModels.answerExceptions().");
  }

  private reportException(req: Json, res: Json, err: Json): void {
    const { log, mark, tag } = this.deps;
    log.debug("Entering ResponseModels.reportException().");
    mark(res, 'STS-API-0140');
    const line = req.method + ' ' + String(req.baseUrl || '') +
      String(req.path || '') + ': ' + String((err && err.message) || err);
    if (!this.logged.has(line) && this.logged.size < MAX_LOGGED) {
      this.logged.add(line);
      log.error(tag('STS-API-0140') + 'A handler threw and nothing caught ' +
                'it: ' + line);
    }
    log.debug("Leaving ResponseModels.reportException().");
  }

  /**
   * The record `install()` keeps for one document. Separate so that a test can
   * check one answer with no express app.
   *
   * @param documentOf - builds the document
   * @param refusal - the API's refusal model
   * @returns the record
   */
  installed(documentOf: () => Json, refusal?: Json): Installed {
    this.deps.log.debug("Entering ResponseModels.installed().");
    this.deps.log.debug("Leaving ResponseModels.installed().");
    return { documentOf: documentOf,
             refusal: refusal ? { schema: refusal } : null,
             built: null, exact: new Map(),
             templated: [], components: null };
  }

  // Runs per request: a handler answering pays for one closure here and for
  // the check in `send`, so no Entering/Leaving pair, which would drown the
  // log at debug on a path this hot.
  private wrap(installed: Installed, req: Json, res: Json): void {
    const self = this;
    const send = res.send;
    // THE REQUEST AS IT ARRIVED, read now and not at the send: a handler can
    // change `req.url` on the way (a sign-in ticket removed from the query, or
    // through an accessor on HTTP/2), and the answer is still to what was asked.
    const arrived = {
      method: req.method, baseUrl: '',
      path: String(req.baseUrl || '') + String(req.path || '')
    };
    res.send = function (body: Json) {
      // Express's `send(object)` calls `json()`, which calls `send(string)`.
      // Only the last of those is the answer, so an object goes round again.
      if (body !== null && typeof body === 'object' &&
          !Buffer.isBuffer(body)) {
        return send.call(this, body);
      }
      res.send = send;
      const problem = self.problemOf(installed, arrived, res, body);
      if (!problem) {
        return send.call(this, body);
      }
      self.report(req, res, problem);
      res.removeHeader('Content-Disposition');
      res.removeHeader('ETag');
      // error-code: none — `report()` above marked STS-API-0139.
      res.status(500).set('Cache-Control', 'no-store')
         .type('application/json');
      return send.call(this, FAILED_BODY);
    };
  }

  /**
   * What is wrong with an answer, or null where it is what the document says.
   *
   * @param installed - the document's record
   * @param req - the request
   * @param res - the response, carrying its status and media type
   * @param body - the string or Buffer about to be sent
   * @returns `{ operation, status, where }`, or null
   */
  problemOf(installed: Installed, req: Json, res: Json, body: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ResponseModels.problemOf().");
    const status = String(res.statusCode);
    const media = String(res.get('Content-Type') || '').split(';')[0].trim()
      .toLowerCase();
    const path = String(req.baseUrl || '') + String(req.path || '');
    let operation: Json;
    try {
      operation = this.operationFor(installed, req.method, path);
    } catch (e: Json) {
      log.debug("Caught in ResponseModels.problemOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving ResponseModels.problemOf(). No document.");
      return { operation: req.method + ' ' + path, status: status,
               where: 'the document could not be built' };
    }
    const name = req.method + ' ' + path;
    if (!operation) {
      log.debug("Leaving ResponseModels.problemOf(). Undocumented.");
      return this.undocumentedProblem(installed, name, status, media, body);
    }
    const opName = operation.operationId || name;
    const declared = operation.responses[status] ||
      operation.responses.default;
    if (!declared) {
      log.debug("Leaving ResponseModels.problemOf(). Undeclared status.");
      return { operation: opName, status: status,
               where: 'a status the operation does not declare' };
    }
    const hasBody = body !== undefined && body !== null &&
      (Buffer.isBuffer(body) ? body.length > 0 : String(body).length > 0);
    const content = declared.content || null;
    if (!hasBody) {
      log.debug("Leaving ResponseModels.problemOf(). No body.");
      return null;
    }
    if (!content || !content[media]) {
      log.debug("Leaving ResponseModels.problemOf(). Undeclared media type.");
      return { operation: opName, status: status,
               where: 'a media type the status does not declare: ' + media };
    }
    if (!/json/.test(media)) {
      log.debug("Leaving ResponseModels.problemOf(). Not JSON.");
      return null;
    }
    let parsed: Json;
    try {
      parsed = JSON.parse(Buffer.isBuffer(body) ? body.toString('utf8') :
        String(body));
    } catch (e: Json) {
      log.debug("Caught in ResponseModels.problemOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving ResponseModels.problemOf(). Not parsable.");
      return { operation: opName, status: status,
               where: 'the body is not JSON' };
    }
    // A model that will not compile is a problem with this answer, never an
    // exception: thrown from `res.send`, a handler's catch would put ajv's
    // sentence about the schema in the caller's answer (the first live run).
    let validate: Json;
    try {
      validate = this.validatorFor(installed, content[media]);
    } catch (e: Json) {
      log.debug("Caught in ResponseModels.problemOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving ResponseModels.problemOf(). Will not compile.");
      return { operation: opName, status: status,
               where: 'the model does not compile: ' +
                      String((e && e.message) || e) };
    }
    if (validate(parsed)) {
      log.debug("Leaving ResponseModels.problemOf(). Valid.");
      return null;
    }
    log.debug("Leaving ResponseModels.problemOf(). Invalid.");
    return { operation: opName, status: status,
             where: this.describeErrors(validate.errors) };
  }

  // A path no operation documents may refuse: the document lists each action
  // at its concrete URL, and `/x/nonsense` reaches the `:action` route, whose
  // refusal is the right answer. It may not answer anything else in JSON. A
  // body that is not JSON is left alone: Express's own 404 is `Cannot GET`.
  private undocumentedProblem(installed: Installed, name: string,
                              status: string, media: string,
                              body: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ResponseModels.undocumentedProblem().");
    if (!/json/.test(media)) {
      log.debug("Leaving ResponseModels.undocumentedProblem(). Not JSON.");
      return null;
    }
    const nothing = { operation: name, status: status,
                      where: 'no operation in the document' };
    if (Number(status) < 400 || !installed.refusal) {
      log.debug("Leaving ResponseModels.undocumentedProblem(). No operation.");
      return nothing;
    }
    let parsed: Json;
    try {
      parsed = JSON.parse(Buffer.isBuffer(body) ? body.toString('utf8') :
        String(body));
    } catch (e: Json) {
      log.debug("Caught in ResponseModels.undocumentedProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving ResponseModels.undocumentedProblem(). Unparsable.");
      return nothing;
    }
    let validate: Json;
    try {
      validate = this.validatorFor(installed, installed.refusal);
    } catch (e: Json) {
      log.debug("Caught in ResponseModels.undocumentedProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving ResponseModels.undocumentedProblem(). No model.");
      return { operation: name, status: status,
               where: 'the refusal model does not compile' };
    }
    const valid = validate(parsed);
    log.debug("Leaving ResponseModels.undocumentedProblem(). " + valid);
    return valid ? null : { operation: name, status: status,
                            where: this.describeErrors(validate.errors) };
  }

  /**
   * How many answers this process has refused to send.
   *
   * @returns the count
   */
  failureCount(): number {
    this.deps.log.debug("Entering ResponseModels.failureCount().");
    this.deps.log.debug("Leaving ResponseModels.failureCount().");
    return this.failures;
  }

  private build(installed: Installed): void {
    const { log } = this.deps;
    log.debug("Entering ResponseModels.build().");
    const doc = installed.documentOf();
    installed.components = doc.components || {};
    Object.keys(doc.paths || {}).forEach(function (path) {
      const template = /[{:]/.test(path);
      const pattern = template ? new RegExp('^' + path
        .replace(/[.*+?^$()|[\]\\]/g, '\\$&')
        .replace(/\{[^}]+\}|:[A-Za-z_]+/g, '[^/]+') + '/?$') : null;
      Object.keys(doc.paths[path]).forEach(function (method) {
        const operation = doc.paths[path][method];
        if (!operation || !operation.responses) {
          return;
        }
        const verb = method.toUpperCase();
        if (template) {
          installed.templated.push({ method: verb, pattern: pattern as RegExp,
                                     operation: operation });
        } else {
          installed.exact.set(verb + ' ' + path, operation);
        }
      });
    });
    installed.built = doc;
    log.debug("Leaving ResponseModels.build().");
  }

  private operationFor(installed: Installed, method: string,
                       path: string): Json {
    const { log } = this.deps;
    log.debug("Entering ResponseModels.operationFor().");
    if (!installed.built) {
      this.build(installed);
    }
    const verb = method === 'HEAD' ? 'GET' : method;
    const trimmed = path.length > 1 ? path.replace(/\/$/, '') : path;
    const exact = installed.exact.get(verb + ' ' + trimmed);
    if (exact) {
      log.debug("Leaving ResponseModels.operationFor(). Exact.");
      return exact;
    }
    const found = installed.templated.find(function (row) {
      return row.method === verb && row.pattern.test(trimmed);
    });
    log.debug("Leaving ResponseModels.operationFor().");
    return found ? found.operation : null;
  }

  private validatorFor(installed: Installed, media: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ResponseModels.validatorFor().");
    let validate = this.validators.get(media);
    if (validate) {
      log.debug("Leaving ResponseModels.validatorFor(). Compiled.");
      return validate;
    }
    const now = this.deps.now ? this.deps.now() : Date.now();
    const failed = this.unbuildable.get(media);
    if (failed && now - failed.at < RETRY_MS) {
      log.debug("Leaving ResponseModels.validatorFor(). Failed lately.");
      throw new Error(failed.message);
    }
    try {
      // `allOf` rather than a spread: a model that is only a `$ref` keeps its
      // target's meaning beside `components`, and this is one shared
      // `components` object behind every validator of the document.
      validate = this.ajv.compile({ allOf: [media.schema || {}],
                                    components: installed.components });
    } catch (e: Json) {
      log.debug("Caught in ResponseModels.validatorFor(): " +
                ((e && e.message) || e));
      // Contained: see the header. The instance is replaced and the failure
      // remembered for this model alone, then thrown on to `problemOf()`,
      // which answers it as this answer's problem.
      this.ajv = this.freshAjv();
      this.unbuildable.set(media, { at: now,
                                    message: String((e && e.message) || e) });
      log.debug("Leaving ResponseModels.validatorFor(). Will not compile.");
      throw e;
    }
    this.unbuildable.delete(media);
    this.validators.set(media, validate);
    log.debug("Leaving ResponseModels.validatorFor().");
    return validate;
  }

  /**
   * The members every plain object and array of this process inherits and a
   * `for…in` would list: none, unless something wrote to `Object.prototype`
   * or `Array.prototype`.
   *
   * @returns their names, sorted
   */
  static inheritedMembers(): string[] {
    helpers.log.debug("Entering ResponseModels.inheritedMembers().");
    const found: string[] = [];
    const probes: Json[] = [{}, []];
    probes.forEach(function (probe: Json) {
      for (const name in probe) {
        if (!Object.prototype.hasOwnProperty.call(probe, name) &&
            found.indexOf(name) < 0) {
          found.push(name);
        }
      }
    });
    helpers.log.debug("Leaving ResponseModels.inheritedMembers().");
    return found.sort();
  }

  // On a refusal only: a polluted prototype refuses EVERY answer, and the line
  // that says so is the one an operator needs first. Said once per set of
  // names, so a process that stays polluted does not repeat it per request.
  private notePollution(): void {
    const { log, tag } = this.deps;
    log.debug("Entering ResponseModels.notePollution().");
    const names = ResponseModels.inheritedMembers();
    const said = names.join(',');
    if (names.length > 0 && said !== this.pollutionSaid) {
      this.pollutionSaid = said;
      log.error(tag('STS-API-0146') + 'Every object in this process inherits ' +
                'members a closed model does not declare, so every answer ' +
                'is refused: ' + names.map(function (n: string) {
                  return '"' + n + '"';
                }).join(', ') + '. Something wrote to Object.prototype or ' +
                'Array.prototype; restart the process.');
    }
    log.debug("Leaving ResponseModels.notePollution().");
  }

  // Names and keywords only: an error's `data` is off (not `verbose`), and a
  // `const` or `enum` value is the document's rather than the answer's.
  private describeErrors(errors: Json[]): string {
    const { log } = this.deps;
    log.debug("Entering ResponseModels.describeErrors().");
    // THE DEEPEST FIRST, EACH SAID ONCE. Where a model is a union, ajv reports
    // every branch: `getUsers`, a list or one person's detail, answered a bad
    // member of the detail as dozens of "additionalProperties" of the list
    // branch at `/`, and the eight this line keeps never reached the member
    // that was wrong. The branch the answer really is goes deepest.
    const depth = function (e: Json): number {
      return String(e.instancePath || '').split('/').length;
    };
    const said = new Set<string>();
    (errors || []).slice().sort(function (a: Json, b: Json) {
      return depth(b) - depth(a);
    }).forEach(function (e: Json) {
      const member = e.params && e.params.additionalProperty
        ? ' "' + e.params.additionalProperty + '"' : '';
      said.add((e.instancePath || '/') + ' ' + e.keyword + member);
    });
    log.debug("Leaving ResponseModels.describeErrors().");
    return Array.from(said).slice(0, 8).join('; ');
  }

  private report(req: Json, res: Json, problem: Json): void {
    const { log, mark, tag } = this.deps;
    log.debug("Entering ResponseModels.report().");
    this.failures += 1;
    mark(res, 'STS-API-0139');
    this.notePollution();
    const line = problem.operation + ' answered ' + problem.status + ': ' +
      problem.where;
    if (!this.logged.has(line) && this.logged.size < MAX_LOGGED) {
      this.logged.add(line);
      log.error(tag('STS-API-0139') + 'An answer does not match its model and was not ' +
                'sent: ' + line);
    }
    log.debug("Leaving ResponseModels.report().");
  }
}

const shared = new ResponseModels({
  log: helpers.log,
  mark: errorCodes.mark,
  tag: errorCodes.tag
});

export = {
  ResponseModels: ResponseModels,
  CODE: CODE,
  POLLUTED: POLLUTED,
  RETRY_MS: RETRY_MS,
  install: function (app: Json, prefix: string, documentOf: () => Json,
                     refusal: Json): void {
    shared.install(app, prefix, documentOf, refusal);
  },
  answerExceptions(app: Json): void {
    shared.answerExceptions(app);
  },
  failureCount: function (): number {
    return shared.failureCount();
  }
};
