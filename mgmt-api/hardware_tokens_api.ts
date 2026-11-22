// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: hardware_tokens_api.ts
//
// ---------------------------------------------------------------------------
// `/admin-api/hardware-tokens` (#1955 P1): Directory → Hardware tokens, for a
// machine (rule 7, the console/API parity rule) — and, since the console is
// a static application over `/admin-api` (#446), the operations the page is
// drawn from and posts to.
//
//   * `GET /admin-api/hardware-tokens` — the realm's tokens, paged (`page`,
//     `per`), filtered by `status` and searched by `q` (a serial, exactly,
//     or a username for that person's tokens). On an on-demand store the
//     unsearched list is the newest thousand rows and says so (`capped`).
//   * `POST /admin-api/hardware-tokens/lost` — reports one lost: the token
//     is marked and every credential on it, whoever registered it, is
//     retired by its kind's retirer (`common/hardware_tokens.ts`). A
//     credential that could not be retired is on the answer.
//
// **THE ACTOR IS THE TOKEN'S SUBJECT, NEVER THE BODY'S**, as every act of
// this API is (#1579). Nothing here records a serial: a token reaches the
// register only from attestation.
// ---------------------------------------------------------------------------

import ApiRows = require('../common/api_rows');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import adminViews = require('../admin-core/admin_views');

type Json = any;

interface HardwareTokensApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  adminViews: typeof adminViews;
  // The register, lazily: it is only asked inside a handler.
  loadTokens(): Json;
  // #1955 P4: the imported OATH token inventory, the same way.
  loadOath(): Json;
  // #1955 P5: the YubiKey OTP inventory and the YK-VAL clients.
  loadYubi(): Json;
}

const BASE = '/admin-api';

/**
 * The `/admin-api/hardware-tokens` operations: the list and the lost-key
 * act.
 */
class HardwareTokensApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes, the paging helper
   *   and a loader of the register
   */
  constructor(private readonly deps: HardwareTokensApiDeps) {
    deps.log.debug("Entering HardwareTokensApi.constructor().");
    deps.log.debug("Leaving HardwareTokensApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): HardwareTokensApiDeps {
    helpers.log.debug("Entering HardwareTokensApi.defaultDeps().");
    helpers.log.debug("Leaving HardwareTokensApi.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody,
      errorCodes: errorCodes, adminViews: adminViews,
      loadTokens: function (): Json {
        return require('../common/hardware_tokens');
      },
      loadOath: function (): Json {
        return require('../common/oath_tokens');
      },
      loadYubi: function (): Json {
        return require('../common/yubiotp_store');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: HardwareTokensApi): void {
    helpers.log.debug("Entering HardwareTokensApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving HardwareTokensApi.wire().");
  }

  /**
   * Sends a JSON body with `Cache-Control: no-store`.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the body, serialised with indentation
   */
  sendJson<R, S extends number>(res: R, status: S,
           body: IyaApi.AnswerOf<R, S>): void;
  sendJson(res: any, status: number, body: any): void {
    const { log } = this.deps;
    log.debug("Entering HardwareTokensApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving HardwareTokensApi.sendJson().");
  }

  // The list as the page draws it: the register's page, with the paging
  // the console's pager reads (`admin_views.pagingOf()`).
  /**
   * The realm's tokens, one page.
   *
   * @param query - `q`, `status`, `page`, `per`
   * @returns `{ tokens, paging, capped, q, status }`
   */
  async view(query: Json): Promise<Json> {
    const { log, adminViews: views } = this.deps;
    log.debug("Entering HardwareTokensApi.view().");
    const q = String((query && query.q) || '').slice(0, 256);
    const status = String((query && query.status) || '');
    const tokens = this.deps.loadTokens();
    const per = Math.max(1, Math.min(300,
      parseInt(String((query && query.per) || ''), 10) || 50));
    const asked = Math.max(1, parseInt(String((query && query.page) || ''),
                                       10) || 1);
    let page: Json = await tokens.list({ q: q, status: status,
      offset: (asked - 1) * per, limit: per });
    const paging = views.pagingOf({ page: asked, per: per }, page.total,
                                  { noun: 'tokens' });
    if (paging.offset !== (asked - 1) * per) {
      // A page past the end: the last one, as every paged list answers.
      page = await tokens.list({ q: q, status: status,
                                 offset: paging.offset, limit: per });
    }
    log.debug("Leaving HardwareTokensApi.view(). " + page.tokens.length);
    // The pager's members, the offset left out (the page says which rows).
    return { tokens: page.tokens,
             paging: { page: paging.page, pages: paging.pages,
                       perPage: paging.perPage, firstRow: paging.firstRow,
                       lastRow: paging.lastRow, total: paging.total,
                       param: paging.param, noun: paging.noun },
             capped: !!page.capped, q: q, status: status };
  }

  /**
   * The OATH token inventory, one page.
   *
   * @param query - `q`, `status`, `page`, `per`
   * @returns `{ tokens, paging, capped, q, status }`
   */
  async oathView(query: Json): Promise<Json> {
    const { log, adminViews: views } = this.deps;
    log.debug("Entering HardwareTokensApi.oathView().");
    const q = String((query && query.q) || '').slice(0, 256);
    const status = String((query && query.status) || '');
    const oath = this.deps.loadOath();
    const per = Math.max(1, Math.min(300,
      parseInt(String((query && query.per) || ''), 10) || 50));
    const asked = Math.max(1, parseInt(String((query && query.page) || ''),
                                       10) || 1);
    let page: Json = await oath.list({ q: q, status: status,
      offset: (asked - 1) * per, limit: per });
    const paging = views.pagingOf({ page: asked, per: per }, page.total,
                                  { noun: 'tokens' });
    if (paging.offset !== (asked - 1) * per) {
      page = await oath.list({ q: q, status: status,
                               offset: paging.offset, limit: per });
    }
    log.debug("Leaving HardwareTokensApi.oathView().");
    return { tokens: page.tokens,
             paging: { page: paging.page, pages: paging.pages,
                       perPage: paging.perPage, firstRow: paging.firstRow,
                       lastRow: paging.lastRow, total: paging.total,
                       param: paging.param, noun: paging.noun },
             capped: !!page.capped, q: q, status: status };
  }

  /** The OATH inventory's acts on `/hardware-tokens/:action` (#1955 P4). */
  static readonly OATH_ACTIONS = ['import-pskc', 'assign-oath',
                                  'remove-oath'];

  /** The YubiKey OTP acts on the same route (#1955 P5). */
  static readonly YUBI_ACTIONS = ['import-yubiotp', 'assign-yubiotp',
                                  'remove-yubiotp', 'ykval-client-add',
                                  'ykval-client-remove'];

  // -------------------------------------------------------------------------
  // THE OATH ACTS (#1955 P4). `import-pskc` takes the seed file's XML text
  // and its pre-shared key or password, which reach `pskc.open()` and
  // nothing else — no audit row, no log line, no answer names them.
  // `assign-oath` gives an unassigned token to a named person;
  // `remove-oath` removes one imported by mistake.
  // -------------------------------------------------------------------------
  /**
   * Carries out one OATH inventory act and answers it.
   *
   * @param req - the request
   * @param res - the response
   * @param action - one of OATH_ACTIONS
   * @param body - the parsed body
   * @param actor - the token's subject
   */
  oathAction(req: Json, res: Json, action: string, body: Json,
             actor: string): void {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering HardwareTokensApi.oathAction(). " + action);
    const self = this;
    const oath = this.deps.loadOath();
    Promise.resolve().then(function (): Json {
      if (action === 'import-pskc') {
        return oath.importPskc({ pskc: String(body.pskc || ''),
                                 preSharedKey: body.preSharedKey,
                                 password: body.password,
                                 actor: actor, via: 'api' });
      }
      if (action === 'assign-oath') {
        return oath.assign({ key: String(body.key || ''),
                             username: String(body.username || ''),
                             actor: actor, via: 'api' });
      }
      return oath.remove({ key: String(body.key || ''), actor: actor,
                           via: 'api' });
    }).then(function (result: Json): void {
      if (!result.ok) {
        // error-code: none — the act's own code, read off the result
        const code = codes.codeOf(result) || 'STS-OATH-0040';
        codes.mark(res, code);
        self.sendJson(res, code === 'STS-OATH-0040' ? 404
          : (code === 'STS-OATH-0041' || code === 'STS-OATH-0049' ? 409
                                                                   : 400),
          { ok: false, errors: result.errors ||
                               [String(result.error || '')] });
        log.debug("Leaving HardwareTokensApi.oathAction(). Refused.");
        return;
      }
      if (action === 'import-pskc') {
        // NO ERROR CODE IN THE ANSWER (the root CLAUDE.md's rule): a key
        // skipped says why in English; its code is on the audit row.
        self.sendJson(res, 200, { ok: true,
          message: result.imported.length + ' token(s) imported, ' +
                   result.skipped.length + ' skipped.',
          protection: String(result.protection || ''),
          imported: result.imported,
          skipped: (result.skipped || []).map(function (r: Json): Json {
            return { index: Number(r.index || 0),
                     serial: String(r.serial || ''),
                     keyId: String(r.keyId || ''),
                     why: String(r.why || '') };
          }) });
      } else if (action === 'assign-oath') {
        self.sendJson(res, 200, { ok: true,
          message: 'Token ' + result.token.key + ' is assigned to ' +
                   result.token.holder + '.', token: result.token });
      } else {
        self.sendJson(res, 200, { ok: true,
          message: 'Token ' + result.key + ' is removed from the ' +
                   'inventory.', key: String(result.key) });
      }
      log.debug("Leaving HardwareTokensApi.oathAction(). Done.");
    }, function (e: any): void {
      log.error(codes.tag('STS-OATH-0045') + 'an OATH token act (' + action +
                ') failed: ' + ((e && e.message) || e));
      codes.mark(res, 'STS-OATH-0045');
      self.sendJson(res, 500, { ok: false, errors: [
        'The OATH token inventory could not be changed.'] });
      log.debug("Leaving HardwareTokensApi.oathAction(). Threw.");
    });
  }

  // -------------------------------------------------------------------------
  // THE YUBIKEY OTP ACTS (#1955 P5). The CSV and the OTP reach the store
  // and nothing else: no log line names them. A YK-VAL client's HMAC key
  // is answered once, on create, and is not logged.
  // -------------------------------------------------------------------------
  /**
   * Carries out one YubiKey OTP act and answers it.
   *
   * @param req - the request
   * @param res - the response
   * @param action - one of YUBI_ACTIONS
   * @param body - the parsed body
   * @param actor - the token's subject
   */
  yubiAction(req: Json, res: Json, action: string, body: Json,
             actor: string): void {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering HardwareTokensApi.yubiAction(). " + action);
    const self = this;
    const yubi = this.deps.loadYubi();
    Promise.resolve().then(function (): Json {
      if (action === 'import-yubiotp') {
        return yubi.importCsv({ csv: String(body.csv || ''),
                                actor: actor, via: 'api' });
      }
      if (action === 'assign-yubiotp') {
        return yubi.assign({ serial: String(body.serial || ''),
                             username: String(body.username || ''),
                             otp: String(body.otp || ''),
                             actor: actor, via: 'api' });
      }
      if (action === 'remove-yubiotp') {
        return yubi.remove({ serial: String(body.serial || ''),
                             actor: actor, via: 'api' });
      }
      if (action === 'ykval-client-add') {
        return yubi.addClient({ id: String(body.id || ''), actor: actor });
      }
      return yubi.removeClient({ id: String(body.id || ''), actor: actor });
    }).then(function (result: Json): void {
      if (!result || !result.ok) {
        // error-code: none — the act's own code, read off the result
        const code = codes.codeOf(result) || 'STS-YUBIOTP-0027';
        const missing = code === 'STS-YUBIOTP-0023' ||
                        code === 'STS-YUBIOTP-0015';
        const conflict = code === 'STS-YUBIOTP-0022';
        codes.mark(res, code);
        self.sendJson(res, missing ? 404 : (conflict ? 409 : 400),
          { ok: false, errors: (result && result.errors) ||
                               [String((result && result.error) || '')] });
        log.debug("Leaving HardwareTokensApi.yubiAction(). Refused.");
        return;
      }
      if (action === 'import-yubiotp') {
        self.sendJson(res, 200, { ok: true,
          message: result.imported.length + ' YubiKey OTP row(s) ' +
                   'imported, ' + result.skipped.length + ' skipped.',
          imported: result.imported,
          skipped: (result.skipped || []).map(function (r: Json): Json {
            return { serial: String(r.serial || ''),
                     why: String(r.why || '') };
          }) });
      } else if (action === 'assign-yubiotp') {
        self.sendJson(res, 200, { ok: true,
          message: 'YubiKey OTP ' + result.token.serial +
                   ' is assigned to ' + result.token.holder + '.',
          token: result.token });
      } else if (action === 'remove-yubiotp') {
        self.sendJson(res, 200, { ok: true,
          message: 'YubiKey OTP ' + result.serial +
                   ' is removed from the inventory.',
          serial: String(result.serial) });
      } else if (action === 'ykval-client-add') {
        self.sendJson(res, 200, { ok: true,
          message: 'YK-VAL client ' + result.id +
                   ' is created. Its key is shown once.',
          id: String(result.id), key: String(result.key) });
      } else {
        self.sendJson(res, 200, { ok: true,
          message: 'YK-VAL client ' + result.id + ' is removed.',
          id: String(result.id) });
      }
      log.debug("Leaving HardwareTokensApi.yubiAction(). Done.");
    }, function (e: any): void {
      log.error(codes.tag('STS-YUBIOTP-0027') + 'a YubiKey OTP act (' +
                action + ') failed: ' + ((e && e.message) || e));
      codes.mark(res, 'STS-YUBIOTP-0027');
      self.sendJson(res, 500, { ok: false, errors: [
        'The YubiKey OTP inventory could not be changed.'] });
      log.debug("Leaving HardwareTokensApi.yubiAction(). Threw.");
    });
  }

  /**
   * The retired rows of a lost-key act, each without its error code.
   *
   * @param rows - the act's rows
   * @returns the rows an answer carries
   */
  static withoutCodes(rows: Json[]): Json[] {
    helpers.log.debug("Entering HardwareTokensApi.withoutCodes().");
    helpers.log.debug("Leaving HardwareTokensApi.withoutCodes().");
    return (rows || []).map(function (r: Json): Json {
      return { kind: String(r.kind), ref: String(r.ref),
               label: String(r.label || ''), ok: !!r.ok,
               why: String(r.why || ''),
               sessionsEnded: Number(r.sessionsEnded || 0) };
    });
  }

  /**
   * Builds the operations' route table.
   *
   * @returns the route rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes: codes } = this.deps;
    const self = this;
    log.debug("Entering HardwareTokensApi.buildRoutes().");
    const ROUTES: IyaApi.AdminRow[] = [
      { method: 'GET', path: BASE + '/hardware-tokens',
        tag: 'Directory', operationId: 'getHardwareTokens',
        mirrors: 'GET /admin/hardware-tokens',
        parameters: [
          { name: 'q', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256,
                      examples: ['12345678'] },
            description: 'A serial, matched exactly, or a username for ' +
                         'that person\'s tokens; empty for every token.' },
          { name: 'status', in: 'query', required: false,
            schema: { type: 'string', enum: ['', 'active', 'lost'] },
            description: '`active` or `lost`; empty for both.' },
          { name: 'page', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'Which page; a page past the end answers the ' +
                         'last one.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 300,
                      examples: [50] },
            description: 'Rows per page, 50 by default and at most 300.' }
        ],
        handler: function (req, res): void {
          log.debug("Entering the management API hardware tokens " +
                    "endpoint.");
          self.view(req.query || {}).then(function (view: Json): void {
            self.sendJson(res, 200, view);
            log.debug("Leaving the management API hardware tokens " +
                      "endpoint.");
          }, function (e: any): void {
            log.error(codes.tag('STS-HWTOKEN-0013') + 'hardware tokens ' +
                      'could not be listed: ' + ((e && e.message) || e));
            codes.mark(res, 'STS-HWTOKEN-0013');
            self.sendJson(res, 500, { ok: false, errors: [
              'The hardware tokens could not be read.'] });
            log.debug("Leaving the management API hardware tokens " +
                      "endpoint. Threw.");
          });
        } },

      // #1955 P4: THE IMPORTED OATH TOKEN INVENTORY, Directory → Hardware
      // tokens' second tab. Never a secret, never a seed file's key.
      { method: 'GET', path: BASE + '/hardware-tokens/oath',
        tag: 'Directory', operationId: 'getOathTokens',
        mirrors: 'GET /admin/hardware-tokens',
        parameters: [
          { name: 'q', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256,
                      examples: ['987654321'] },
            description: 'A serial, matched exactly, or a username for ' +
                         'the tokens assigned to that person; empty for ' +
                         'every token.' },
          { name: 'status', in: 'query', required: false,
            schema: { type: 'string',
                      enum: ['', 'unassigned', 'assigned', 'retired'] },
            description: '`unassigned`, `assigned` or `retired`; empty ' +
                         'for all three.' },
          { name: 'page', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'Which page; a page past the end answers the ' +
                         'last one.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 300,
                      examples: [50] },
            description: 'Rows per page, 50 by default and at most 300.' }
        ],
        handler: function (req, res): void {
          log.debug("Entering the management API OATH tokens endpoint.");
          self.oathView(req.query || {}).then(function (view: Json): void {
            self.sendJson(res, 200, view);
            log.debug("Leaving the management API OATH tokens endpoint.");
          }, function (e: any): void {
            log.error(codes.tag('STS-OATH-0045') + 'the OATH token ' +
                      'inventory could not be listed: ' +
                      ((e && e.message) || e));
            codes.mark(res, 'STS-OATH-0045');
            self.sendJson(res, 500, { ok: false, errors: [
              'The OATH token inventory could not be read.'] });
            log.debug("Leaving the management API OATH tokens endpoint. " +
                      "Threw.");
          });
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/hardware-tokens/:action',
        tag: 'Directory', mirrors: 'POST /admin/hardware-tokens',
        handler: function (req, res): void {
          log.debug("Entering the management API hardware tokens action.");
          const body = parseBody(req) || {};
          const action = String(req.params.action || '');
          // THE CALLER is the subject of the token the gate verified, never
          // the body's (#1579).
          const caller = res.locals && res.locals.apiCaller;
          const actor = String((caller && caller.name) || '');
          if (HardwareTokensApi.OATH_ACTIONS.indexOf(action) >= 0) {
            self.oathAction(req, res, action, body, actor);
            log.debug("Leaving the management API hardware tokens " +
                      "action. An OATH act.");
            return;
          }
          if (HardwareTokensApi.YUBI_ACTIONS.indexOf(action) >= 0) {
            self.yubiAction(req, res, action, body, actor);
            log.debug("Leaving the management API hardware tokens " +
                      "action. A YubiKey OTP act.");
            return;
          }
          if (action !== 'lost') {
            codes.mark(res, 'STS-HWTOKEN-0012');
            self.sendJson(res, 400, { ok: false, errors: [
              'Unknown action "' + action.slice(0, 64) + '". The ' +
              'actions are: lost, ' + HardwareTokensApi.OATH_ACTIONS
                .concat(HardwareTokensApi.YUBI_ACTIONS).join(', ') +
              '.'] });
            log.debug("Leaving the management API hardware tokens " +
                      "action. Unknown.");
            return;
          }
          Promise.resolve().then(function (): Json {
            return self.deps.loadTokens().markLost({
              key: String(body.key || ''), actor: actor, via: 'api',
              initiatingEntity: 'admin' });
          }).then(function (result: Json): void {
            if (!result.ok) {
              // error-code: none — the act's own code, read off the result
              codes.mark(res, codes.codeOf(result) || 'STS-HWTOKEN-0005');
              self.sendJson(res, codes.codeOf(result) === 'STS-HWTOKEN-0006'
                ? 409 : 404, { ok: false, errors: result.errors ||
                               [String(result.error || '')] });
              log.debug("Leaving the management API hardware tokens " +
                        "action. Refused.");
              return;
            }
            self.sendJson(res, 200, {
              ok: true,
              message: 'Hardware token ' + result.token.key + ' is ' +
                'reported lost: ' + result.retired.length + ' ' +
                'credential(s) retired, ' + result.notRetired.length +
                ' not.' + ((result.recoveryNoted || []).length
                  ? ' A recovery is now pending for ' +
                    result.recoveryNoted.join(', ') + ': their next ' +
                    'sign-in a passkey does not answer is held to the ' +
                    'passkey policy\'s recoveryAssurance.' : ''),
              token: result.token,
              // NO ERROR CODE IN THE ANSWER (the root CLAUDE.md's rule): a
              // credential not retired says why in English; its code is on
              // the audit row.
              retired: HardwareTokensApi.withoutCodes(result.retired),
              notRetired: HardwareTokensApi.withoutCodes(result.notRetired)
            });
            log.debug("Leaving the management API hardware tokens " +
                      "action. Lost.");
          }, function (e: any): void {
            log.error(codes.tag('STS-HWTOKEN-0013') + 'the lost-key act ' +
                      'failed: ' + ((e && e.message) || e));
            codes.mark(res, 'STS-HWTOKEN-0013');
            self.sendJson(res, 500, { ok: false, errors: [
              'The hardware token could not be reported lost.'] });
            log.debug("Leaving the management API hardware tokens " +
                      "action. Threw.");
          });
        },
        actions: [
          { action: 'lost', operationId: 'reportHardwareTokenLost' },
          // #1955 P4: the imported OATH token inventory.
          { action: 'import-pskc', operationId: 'importPskcSeedFile' },
          { action: 'assign-oath', operationId: 'assignOathToken' },
          { action: 'remove-oath', operationId: 'removeOathToken' },
          { action: 'import-yubiotp', operationId: 'importYubiOtpCsv' },
          { action: 'assign-yubiotp', operationId: 'assignYubiOtp' },
          { action: 'remove-yubiotp', operationId: 'removeYubiOtp' },
          { action: 'ykval-client-add', operationId: 'addYkvalClient' },
          { action: 'ykval-client-remove',
            operationId: 'removeYkvalClient' }
        ] })
    ];
    log.debug("Leaving HardwareTokensApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<HardwareTokensApi>(
  'mgmt-api/hardware_tokens_api',
  () => new HardwareTokensApi(HardwareTokensApi.defaultDeps()),
  HardwareTokensApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The hardware token operations of `/admin-api` (#1955 P1), mirroring
 * Directory → Hardware tokens. It registers no route: the management API
 * spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  HardwareTokensApi: HardwareTokensApi,
  installInstance: (instance: HardwareTokensApi): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
