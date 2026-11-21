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
//   * `POST /admin-api/hardware-tokens/enrol-piv` (#1955 P2) — issues a PIV
//     slot certificate to the person `username` names, from a certificate
//     request and, optionally, its YubiKey PIV attestation: the console's
//     enrolment form, for a machine (`common/piv_enrolment.ts`).
//   * `GET /admin-api/hardware-tokens/escrowed` and `POST
//     /admin-api/hardware-tokens/recover-key` (#1955 P2, D7) — a person's
//     escrowed piv-key-management certificates, and the recovery of one's
//     key, which the access-control policy decides on PIV_KEY_RECOVERY
//     beside Admin Write, and audits.
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
  // The PIV enrolment form and escrow (#1955 P2), lazily, for the same
  // reason.
  loadPivEnrolment(): Json;
}

// The acts, in the order the unknown-action sentence names them.
const ACTIONS = ['lost', 'enrol-piv', 'recover-key'];

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
      loadPivEnrolment: function (): Json {
        return require('../common/piv_enrolment');
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
    // #1955 P2: the enrolment form's rules, and the escrowed certificates
    // of the person a search names (none for a serial or nobody).
    return { piv: this.pivRules(),
             escrowed: q ? this.deps.loadPivEnrolment().escrowedOf(q) : [],
             tokens: page.tokens,
             paging: { page: paging.page, pages: paging.pages,
                       perPage: paging.perPage, firstRow: paging.firstRow,
                       lastRow: paging.lastRow, total: paging.total,
                       param: paging.param, noun: paging.noun },
             capped: !!page.capped, q: q, status: status };
  }

  // What the enrolment form may issue here: the PIV profiles EST's list
  // holds, and the two switches.
  private pivRules(): Json {
    const { log } = this.deps;
    log.debug("Entering HardwareTokensApi.pivRules().");
    const cfg = require('../common/config');
    const raw = cfg.value('est.allowedProfiles');
    const allowed = (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one: unknown): string {
        return String(one).trim();
      });
    log.debug("Leaving HardwareTokensApi.pivRules().");
    return { profiles: ['piv-auth', 'piv-sign', 'piv-key-management',
                        'piv-card-auth'].filter(function (one) {
               return allowed.indexOf(one) >= 0;
             }),
             requireAttestation: cfg.value('piv.requireAttestation') === true,
             keyEscrow: cfg.value('piv.keyEscrow') === true };
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

  // A refusal's status, held to the ones the model gives these acts.
  static statusOf(answer: Json, allowed: number[]): number {
    helpers.log.debug("Entering HardwareTokensApi.statusOf().");
    const status = Number((answer && answer.status) || 400);
    helpers.log.debug("Leaving HardwareTokensApi.statusOf().");
    return allowed.indexOf(status) >= 0 ? status : 400;
  }

  // THE TWO PIV ACTS (header): `enrol-piv` for the person `username`
  // names, and `recover-key`, which the access-control policy decides.
  /**
   * Answers `enrol-piv` or `recover-key`.
   *
   * @param res - the response
   * @param action - the act
   * @param actor - the token's subject
   * @param body - the request body
   * @param roles - the roles the caller's token carries
   */
  pivAct(res: Json, action: string, actor: string, body: Json,
         roles: string[]): void {
    const { log, errorCodes: codes } = this.deps;
    const self = this;
    log.debug("Entering HardwareTokensApi.pivAct(). " + action);
    const piv = this.deps.loadPivEnrolment();
    const username = String(body.username || '').slice(0, 256);
    Promise.resolve().then(function (): Json {
      return action === 'enrol-piv'
        ? piv.enrol({ username: username, actor: actor, admin: true,
                      profile: String(body.profile || ''),
                      csr: String(body.csr || ''),
                      slotPem: String(body.attestationCertificate || ''),
                      attestationPem: String(body.attestationIssuer || ''),
                      via: 'api:piv' })
        : piv.recover({ username: username, actor: actor, door: 'admin-api',
                        serialHex: String(body.serial || ''),
                        roles: roles });
    }).then(function (done: Json): void {
      if (!done || !done.ok) {
        // error-code: none — the act's own code, read off the result
        codes.mark(res, codes.codeOf(done) || 'STS-PIV-0016');
        self.sendJson(res, HardwareTokensApi.statusOf(done,
          action === 'enrol-piv' ? [400, 404, 409, 503]
                                 : [403, 404, 503]),
          { ok: false, errors: (done && done.errors) || ['refused'] });
        log.debug("Leaving HardwareTokensApi.pivAct(). Refused.");
        return;
      }
      if (action === 'enrol-piv') {
        self.sendJson(res, 200, { ok: true,
          message: 'Certificate ' + done.serialHex + ' (' + done.profile +
            ') was issued to ' + username + (done.attested
              ? ' from a verified PIV attestation, on token ' + done.token
              : ', with no attestation') + '.',
          serialHex: done.serialHex, profile: done.profile,
          certificatePem: done.certificatePem, chainPem: done.chainPem,
          attested: !!done.attested, token: String(done.token || '') });
      } else {
        self.sendJson(res, 200, { ok: true,
          message: 'The escrowed key of certificate ' +
            done.record.serialHex + ' of ' + username + ' was recovered.',
          serialHex: done.record.serialHex,
          privateKeyPem: done.privateKeyPem,
          certificatePem: done.certificatePem, chainPem: done.chainPem });
      }
      log.debug("Leaving HardwareTokensApi.pivAct(). Done.");
    }, function (e: any): void {
      log.error(codes.tag('STS-PIV-0016') + 'the ' + action + ' act ' +
                'failed: ' + ((e && e.stack) || e));
      codes.mark(res, 'STS-PIV-0016');
      self.sendJson(res, 500, { ok: false, errors: [
        'The ' + action + ' act could not be completed.'] });
      log.debug("Leaving HardwareTokensApi.pivAct(). Threw.");
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
          if (ACTIONS.indexOf(action) < 0) {
            codes.mark(res, 'STS-HWTOKEN-0012');
            self.sendJson(res, 400, { ok: false, errors: [
              'Unknown action "' + action.slice(0, 64) + '". The actions ' +
              'are: ' + ACTIONS.join(', ') + '.'] });
            log.debug("Leaving the management API hardware tokens " +
                      "action. Unknown.");
            return;
          }
          if (action !== 'lost') {
            self.pivAct(res, action, actor, body,
                        (caller && Array.isArray(caller.roles))
                          ? caller.roles : []);
            log.debug("Leaving the management API hardware tokens " +
                      "action. A PIV act.");
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
                ' not.',
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
          { action: 'enrol-piv', operationId: 'enrolPivCertificate' },
          { action: 'recover-key', operationId: 'recoverEscrowedPivKey' }
        ] }),

      // A PERSON'S ESCROWED KEY-MANAGEMENT CERTIFICATES (#1955 P2, D7):
      // which there are, never a key.
      { method: 'GET', path: BASE + '/hardware-tokens/escrowed',
        tag: 'Directory', operationId: 'getEscrowedPivKeys',
        mirrors: 'GET /admin/hardware-tokens',
        parameters: [
          { name: 'username', in: 'query', required: true,
            schema: { type: 'string', maxLength: 256,
                      examples: ['alice'] },
            description: 'The person whose escrowed certificates to list.' }
        ],
        handler: function (req, res): void {
          log.debug("Entering the management API escrowed keys endpoint.");
          const username = String((req.query && req.query.username) || '')
            .slice(0, 256);
          let rows: Json[] = [];
          try {
            rows = self.deps.loadPivEnrolment().escrowedOf(username);
          } catch (e) {
            log.error(codes.tag('STS-PIV-0016') + 'escrowed keys could not ' +
                      'be listed: ' + ((e && e.message) || e));
            codes.mark(res, 'STS-PIV-0016');
            self.sendJson(res, 500, { ok: false, errors: [
              'The escrowed keys could not be read.'] });
            log.debug("Leaving the management API escrowed keys endpoint. " +
                      "Threw.");
            return;
          }
          self.sendJson(res, 200, { username: username, escrowed: rows });
          log.debug("Leaving the management API escrowed keys endpoint.");
        } }
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
