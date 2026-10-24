// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: passkey_report_api.ts
// ---------------------------------------------------------------------------
// THE /admin-api/passkey-report OPERATIONS (#942), mirroring Monitoring →
// Passkeys (rule 7): the report as the page draws it — with a page of one
// list when the query names one — the export of a list, and the page's one
// control, Recount now. Each is `common/passkey_report.ts`'s and nothing
// else: the page and the operation cannot report different numbers because
// they are one call.
//
// **NOTHING HERE COUNTS.** The report's counts are the aggregate the
// recount job and the directory's key-writing doors keep; a filter by group
// or profile reads that population's members, bounded; a list reads holders
// after a key cursor, bounded. The module's header argues each bound.
//
// **A STORE THAT CANNOT BE READ IS A 503** (`STS-AUTHN-0415`), as every
// windowed console read answers one (`ldap_server.js`'s `storeAsked()`
// marks the store's rejections `STS-LDAP-0139`); anything else is a 500.
//
// It registers no route: `mgmt-api/admin_api.ts` spreads `ROUTES` into its
// table, as it does the secret destinations'.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface PasskeyReportApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // The report, lazily: this module is built with the other API modules,
  // and the report is only asked inside a handler.
  loadReport(): Json;
}

const BASE = '/admin-api';

/**
 * The `/admin-api/passkey-report` operations: the report, its export and
 * its recount.
 */
class PasskeyReportApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes and a loader of the
   *   report
   */
  constructor(private readonly deps: PasskeyReportApiDeps) {
    deps.log.debug("Entering PasskeyReportApi.constructor().");
    deps.log.debug("Leaving PasskeyReportApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports, with the
   * report loaded lazily.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): PasskeyReportApiDeps {
    helpers.log.debug("Entering PasskeyReportApi.defaultDeps().");
    helpers.log.debug("Leaving PasskeyReportApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadReport: function (): Json {
        return require('../common/passkey_report');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: PasskeyReportApi): void {
    helpers.log.debug("Entering PasskeyReportApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving PasskeyReportApi.wire().");
  }

  /**
   * Sends a JSON body with `Cache-Control: no-store`.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the body, serialised with indentation
   */
  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering PasskeyReportApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving PasskeyReportApi.sendJson().");
  }

  // A refusal the report answered: 400, with its own code.
  private refused(res: Res, answer: Json): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PasskeyReportApi.refused().");
    // error-code: none — the report's own code, read off its answer
    errorCodes.mark(res, errorCodes.codeOf(answer) || 'STS-AUTHN-0416');
    this.sendJson(res, 400, { ok: false, errors: answer.errors || [] });
    log.debug("Leaving PasskeyReportApi.refused().");
  }

  // A read that failed: 503 when the store could not be asked, 500 else.
  private failed(res: Res, e: any, what: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PasskeyReportApi.failed().");
    const store = errorCodes.codeOf(e) === 'STS-LDAP-0139';
    log.error(errorCodes.tag('STS-AUTHN-0415') + 'passkey report: ' + what +
              ' could not be read' + (store ? ' (the store refused)' : '') +
              ': ' + ((e && e.message) || e));
    errorCodes.mark(res, 'STS-AUTHN-0415');
    this.sendJson(res, store ? 503 : 500, { ok: false, errors: [
      store ? 'The directory could not be asked just now; try again.'
            : 'The passkey report could not be read.'] });
    log.debug("Leaving PasskeyReportApi.failed().");
  }

  /**
   * Builds the operations' route table, each row carrying its OpenAPI
   * description and its handler.
   *
   * @returns the route rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadReport } = this.deps;
    const self = this;
    log.debug("Entering PasskeyReportApi.buildRoutes().");
    const report = loadReport();
    // THE FILTER AND THE LIST, declared once for the report and its export.
    const FILTER: Json[] = [
      { name: 'group', in: 'query', required: false,
        schema: { type: 'string', maxLength: 1024 },
        description: 'Count the members of this group only (its cn or its ' +
                     'DN). At most ' + report.POPULATION_LIMIT + ' members ' +
                     'are read; `population.complete` says whether that was ' +
                     'all of them.' },
      { name: 'profile', in: 'query', required: false,
        schema: { type: 'string', maxLength: 128 },
        description: 'Count the people a NAMED passkey profile selects by ' +
                     'group (#535: the members of its ' +
                     '`stsPasskeySelectGroup` groups), bounded as `group` ' +
                     'is. `default` is refused: it selects nobody by group.' },
      { name: 'application', in: 'query', required: false,
        schema: { type: 'string', maxLength: 512 },
        description: 'An application\'s population: anybody may sign in to ' +
                     'it, so the counts are the realm\'s, with ' +
                     '`application` saying which passkey profile governs ' +
                     'its sign-ins and how many group-selected profiles ' +
                     'could still win for a person.' }
    ];
    const LIST: Json[] = [
      { name: 'list', in: 'query', required: false,
        schema: { type: 'string', enum: report.LISTS.slice() },
        description: 'The people behind one count: a kind ' +
                     '(`post-quantum-only`, `classical-only`, `both`, ' +
                     '`none`), everybody `holding` a passkey, one ' +
                     '`algorithm` (with `algorithm` and, optionally, ' +
                     '`lane`) or one `model` (with `aaguid`).' },
      { name: 'algorithm', in: 'query', required: false,
        schema: { type: 'string', maxLength: 64 },
        description: 'With `list=algorithm`: the JOSE name, `ML-DSA-65`, ' +
                     '`ES256` and the like.' },
      { name: 'lane', in: 'query', required: false,
        schema: { type: 'string', enum: ['classical', 'pqc'] },
        description: 'With `list=algorithm`: only keys made in this lane ' +
                     '(#643).' },
      { name: 'aaguid', in: 'query', required: false,
        schema: { type: 'string', maxLength: 64 },
        description: 'With `list=model`: the AAGUID, or `unreported` for ' +
                     'keys whose authenticator named none.' }
    ];
    const ROUTES = [
      { method: 'GET', path: BASE + '/passkey-report',
        tag: 'Monitoring', operationId: 'getPasskeyReport',
        summary: 'Who holds which passkey algorithm, across the realm (#942)',
        description: 'Everything Monitoring → Passkeys draws. `people`: ' +
          '`total`, `holding`, `postQuantumOnly`, `classicalOnly`, `both`, ' +
          '`none` and `withPostQuantum` — a person\'s kind is the ' +
          'ALGORITHM of their keys (ML-DSA is post-quantum), never the ' +
          'lane. `keys`: `total`, `postQuantum`, `classical`, `byLane` and ' +
          '`byAlgorithm` (each `algorithm`, `coseAlg`, `lane`, ' +
          '`postQuantum`, `count`). `models`: each AAGUID with its name and ' +
          'the algorithms its keys use. `attestation`: the attestation ' +
          'certificates\' algorithms, `recorded: false` until the key rows ' +
          'carry them (#941). `profiles`: each passkey profile\'s ' +
          '`postQuantumRequired` and selectors. `counted`: where the ' +
          'numbers came from — the recount\'s `baseline` (when, how long, ' +
          'how many holders) plus the `changesSince` noted as keys were ' +
          'written, or the `population` a filter read; null before the ' +
          'first recount. With `list`, a page of the people behind one ' +
          'count, paged by `page`, `per` and `from` (the cursor ' +
          '`list.paging.nextFrom` hands back); a realm list reads at most ' +
          report.LIST_SCAN + ' entries a request and says ' +
          '`complete: false` when that stopped it. NO COUNT IS A SCAN OF ' +
          'THE DIRECTORY: the realm\'s are a maintained aggregate.',
        mirrors: 'GET /admin/passkey-report',
        parameters: FILTER.concat(LIST).concat([
          { name: 'page', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `list.rows`.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1,
                      maximum: report.PER_MAX },
            description: 'Rows per page.' },
          { name: 'from', in: 'query', required: false,
            schema: { type: 'string', maxLength: 2048 },
            description: 'Where `page` starts: the `nextFrom` the page ' +
                         'before answered. Without it a page is found by ' +
                         'reading from the start.' }
        ]),
        responseDescription: 'The report.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`counted`, `people`, `keys`, ' +
                                       '`models`, `attestation`, ' +
                                       '`profiles`, `filter`, ' +
                                       '`population`, `application`, ' +
                                       '`list`, `limits`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API passkey report endpoint.");
          Promise.resolve().then(function (): Json {
            return loadReport().reportAsync(req.query || {});
          }).then(function (view: Json): void {
            if (!view.ok) {
              self.refused(res, view);
              log.debug("Leaving the management API passkey report " +
                        "endpoint. Refused.");
              return;
            }
            self.sendJson(res, 200, view);
            log.debug("Leaving the management API passkey report " +
                      "endpoint.");
          }, function (e: any): void {
            log.debug("Caught in the management API passkey report " +
                      "endpoint: " + ((e && e.message) || e));
            self.failed(res, e, 'the report');
          });
        } },

      { method: 'GET', path: BASE + '/passkey-report/export',
        tag: 'Monitoring', operationId: 'exportPasskeyReport',
        summary: 'Every person behind one passkey count, as CSV or JSON',
        description: 'The people `list` names (every passkey holder when ' +
          'it is absent), in the filter the report takes, as a file: CSV ' +
          '(`username`, `dn`, `kind`, `passkeys`, `algorithms`, `lanes`, ' +
          '`aaguids`, `models`; a cell a spreadsheet would read as a ' +
          'formula is prefixed with an apostrophe) or JSON (`rows`, each ' +
          'with its `keys`). At most ' + report.EXPORT_LIMIT + ' rows; ' +
          'the JSON says `truncated`, and so does the header ' +
          '`X-Passkey-Report-Truncated`. Read asynchronously, holders ' +
          'only, as the lists are. No secret is in it: a public key is not ' +
          'exported.',
        mirrors: 'GET /admin/passkey-report',
        parameters: FILTER.concat(LIST).concat([
          { name: 'format', in: 'query', required: false,
            schema: { type: 'string', enum: ['csv', 'json'] },
            description: '`csv` (the default) or `json`.' }
        ]),
        responseDescription: 'The file, as an attachment.',
        responseSchema: { type: 'string',
                          description: 'text/csv or application/json.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API passkey export endpoint.");
          Promise.resolve().then(function (): Json {
            return loadReport().exportAsync(req.query || {});
          }).then(function (file: Json): void {
            if (!file.ok) {
              self.refused(res, file);
              log.debug("Leaving the management API passkey export " +
                        "endpoint. Refused.");
              return;
            }
            res.status(200)
               .set('Content-Type', file.contentType)
               .set('Cache-Control', 'no-store')
               .set('X-Passkey-Report-Truncated',
                    file.truncated ? 'true' : 'false')
               .set('Content-Disposition', 'attachment; filename="' +
                    file.filename + '"')
               .send(file.body);
            log.debug("Leaving the management API passkey export " +
                      "endpoint. " + file.rows + " row(s).");
          }, function (e: any): void {
            log.debug("Caught in the management API passkey export " +
                      "endpoint: " + ((e && e.message) || e));
            self.failed(res, e, 'the export');
          });
        } },

      { method: 'POST', route: BASE + '/passkey-report/:action',
        tag: 'Monitoring', mirrors: 'POST /admin/passkey-report',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API passkey report action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          // THE CALLER, which the route wrapper put in the body's `actor`
          // after its schema passed (`nameActor()`, #446).
          const result = loadReport().act(body, {
            via: 'api', actor: String(body.actor || ''), channel: 'api' });
          if (!result.ok) {
            // error-code: none — the act's own code, read off the result
            errorCodes.mark(res, errorCodes.codeOf(result) ||
                                 'STS-AUTHN-0418');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API passkey report action. " +
                    "ok=" + result.ok);
        },
        actions: [
          { action: 'recount', operationId: 'recountPasskeyReport',
            summary: 'Count the realm\'s passkeys again, now',
            description: 'Queues a run of the `passkeys.report-recount` ' +
              'job for this realm on the scheduler\'s leader (#49), which ' +
              'reads every passkey holder a page at a time and makes the ' +
              'result the new baseline — putting right whatever the ' +
              'changes noted since could not see (a bulk import, a ' +
              'restore). It runs where every job runs, never on this ' +
              'request: the answer is the queued run (`runId`, ' +
              '`alreadyQueued`), and Monitoring → Scheduler shows it. ' +
              'Audited by the scheduler.',
            requestBodyRequired: false,
            requestBody: {
              type: 'object', properties: {},
              examples: [{}],
              additionalProperties: false
            },
            responseDescription: 'The queued run.' }
        ] }
    ];
    log.debug("Leaving PasskeyReportApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<PasskeyReportApi>(
  'mgmt-api/passkey_report_api',
  () => new PasskeyReportApi(PasskeyReportApi.defaultDeps()),
  PasskeyReportApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The passkey report's operations of `/admin-api` (#942), mirroring
 * Monitoring → Passkeys.
 *
 * It registers no route: the management API spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  PasskeyReportApi: PasskeyReportApi,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: PasskeyReportApi): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  /**
   * The installed instance's route table, which `mgmt-api/admin_api.ts`
   * spreads into its own.
   */
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
