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
}

interface Installed {
  documentOf: () => Json;
  built: Json;
  exact: Map<string, Json>;
  templated: { method: string; pattern: RegExp; operation: Json }[];
  components: Json;
}

class ResponseModels {
  private readonly deps: Deps;

  private readonly ajv: Json;

  private readonly validators = new Map<Json, Json>();

  private readonly logged = new Set<string>();

  private failures = 0;

  constructor(deps: Deps) {
    this.deps = deps;
    // `coerceTypes` off and no defaults: a validator must not change what it
    // is reading. `strict: false` for `examples` and the `x-` members.
    this.ajv = new Ajv({ strict: false, allErrors: true,
                         coerceTypes: false, useDefaults: false });
    addFormats(this.ajv);
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
   */
  install(app: Json, prefix: string, documentOf: () => Json): void {
    const self = this;
    this.deps.log.debug("Entering ResponseModels.install(). " + prefix);
    const installed = this.installed(documentOf);
    app.use(prefix, function (req: Json, res: Json, next: Json) {
      self.wrap(installed, req, res);
      next();
    });
    this.deps.log.debug("Leaving ResponseModels.install().");
  }

  /**
   * The record `install()` keeps for one document. Separate so that a test can
   * check one answer with no express app.
   *
   * @param documentOf - builds the document
   * @returns the record
   */
  installed(documentOf: () => Json): Installed {
    this.deps.log.debug("Entering ResponseModels.installed().");
    this.deps.log.debug("Leaving ResponseModels.installed().");
    return { documentOf: documentOf, built: null, exact: new Map(),
             templated: [], components: null };
  }

  // Runs per request: a handler answering pays for one closure here and for
  // the check in `send`, so no Entering/Leaving pair, which would drown the
  // log at debug on a path this hot.
  private wrap(installed: Installed, req: Json, res: Json): void {
    const self = this;
    const send = res.send;
    res.send = function (body: Json) {
      // Express's `send(object)` calls `json()`, which calls `send(string)`.
      // Only the last of those is the answer, so an object goes round again.
      if (body !== null && typeof body === 'object' &&
          !Buffer.isBuffer(body)) {
        return send.call(this, body);
      }
      res.send = send;
      const problem = self.problemOf(installed, req, res, body);
      if (!problem) {
        return send.call(this, body);
      }
      self.report(req, res, problem);
      res.removeHeader('Content-Disposition');
      res.removeHeader('ETag');
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
      const isJson = /json/.test(media);
      log.debug("Leaving ResponseModels.problemOf(). Undocumented.");
      return isJson ? { operation: name, status: status,
                        where: 'no operation in the document' } : null;
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
    const validate = this.validatorFor(installed, content[media]);
    if (validate(parsed)) {
      log.debug("Leaving ResponseModels.problemOf(). Valid.");
      return null;
    }
    log.debug("Leaving ResponseModels.problemOf(). Invalid.");
    return { operation: opName, status: status,
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
    if (!validate) {
      // `allOf` rather than a spread: a model that is only a `$ref` keeps its
      // target's meaning beside `components`, and this is one shared
      // `components` object behind every validator of the document.
      validate = this.ajv.compile({ allOf: [media.schema || {}],
                                    components: installed.components });
      this.validators.set(media, validate);
    }
    log.debug("Leaving ResponseModels.validatorFor().");
    return validate;
  }

  // Names and keywords only: an error's `data` is off (not `verbose`), and a
  // `const` or `enum` value is the document's rather than the answer's.
  private describeErrors(errors: Json[]): string {
    const { log } = this.deps;
    log.debug("Entering ResponseModels.describeErrors().");
    const said = (errors || []).slice(0, 8).map(function (e: Json) {
      const member = e.params && e.params.additionalProperty
        ? ' "' + e.params.additionalProperty + '"' : '';
      return (e.instancePath || '/') + ' ' + e.keyword + member;
    });
    log.debug("Leaving ResponseModels.describeErrors().");
    return said.join('; ');
  }

  private report(req: Json, res: Json, problem: Json): void {
    const { log, mark, tag } = this.deps;
    log.debug("Entering ResponseModels.report().");
    this.failures += 1;
    mark(res, CODE);
    const line = problem.operation + ' answered ' + problem.status + ': ' +
      problem.where;
    if (!this.logged.has(line) && this.logged.size < MAX_LOGGED) {
      this.logged.add(line);
      log.error(tag(CODE) + 'An answer does not match its model and was not ' +
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
  install: function (app: Json, prefix: string,
                     documentOf: () => Json): void {
    shared.install(app, prefix, documentOf);
  },
  failureCount: function (): number {
    return shared.failureCount();
  }
};
