// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: audit_export_api.ts
// ---------------------------------------------------------------------------
// THE /admin-api/audit-export OPERATIONS (#641), mirroring Monitoring →
// Audit export (rule 7). The view is what the page draws, and the six acts
// are `common/audit_export.ts`'s `act()`. The action names are the last
// path segment (`add`, `update`, `remove`, `enable`, `disable`, `test`),
// which is what a console form's hidden `action` resolves to.
//
// NO ANSWER CARRIES A SECRET. A token and a secret header are write-only:
// the view says they are set, and an empty value on a change keeps them.
//
// It registers no route. `mgmt-api/admin_api.ts` spreads `ROUTES`.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface AuditExportApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // The register, lazily. Built with the other API modules, and asked
  // only inside a handler, after the composition root has installed it.
  loadExport(): Json;
  // The console, lazily, for this page's settings block. Requiring it
  // here at load would be a cycle through the management API.
  loadAdmin(): Json;
}

const BASE = '/admin-api';
const PAGE = '/admin/audit-export';

/**
 * The `/admin-api/audit-export` operations: the register and its six acts.
 */
class AuditExportApi {
  /**
   * @param deps - the logger, the body parser, and the two loaders
   */
  constructor(private readonly deps: AuditExportApiDeps) {
    deps.log.debug("Entering AuditExportApi.constructor().");
    deps.log.debug("Leaving AuditExportApi.constructor().");
  }

  /**
   * The dependencies the composition root builds this with.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): AuditExportApiDeps {
    helpers.log.debug("Entering AuditExportApi.defaultDeps().");
    helpers.log.debug("Leaving AuditExportApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadExport: function (): Json {
        return require('../common/audit_export');
      },
      loadAdmin: function (): Json {
        return require('../admin-ui/admin');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: AuditExportApi): void {
    helpers.log.debug("Entering AuditExportApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving AuditExportApi.wire().");
  }

  /**
   * Sends JSON with `Cache-Control: no-store`.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the body
   */
  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering AuditExportApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving AuditExportApi.sendJson().");
  }

  /**
   * The fields an add or an update may carry. Secrets are write-only.
   *
   * @returns the JSON Schema properties
   */
  static properties(): Json {
    helpers.log.debug("Entering AuditExportApi.properties().");
    const text = function (max: number, description: string): Json {
      helpers.log.debug("Entering text().");
      helpers.log.debug("Leaving text().");
      return { type: 'string', maxLength: max, description: description };
    };
    const fields = {
      id: { type: 'string', minLength: 1, maxLength: 63,
            pattern: '^[a-z0-9][a-z0-9-]{0,62}$',
            description: 'The destination id. A letter or a digit, then ' +
                         'lower-case letters, digits and hyphens. It does ' +
                         'not change.' },
      name: text(128, 'What to call it on the page.'),
      type: { type: 'string',
              enum: ['syslog', 'file', 'webhook', 'splunk', 'logrhythm'],
              description: 'syslog, file, webhook, splunk, or logrhythm. ' +
                           'LogRhythm is the syslog adapter.' },
      enabled: { type: 'boolean',
                 description: 'Whether the job delivers to it.' },
      excludeAttributes: text(1000, 'More detail names to remove, ' +
                                    'separated by commas.'),
      host: text(255, 'syslog and logrhythm: the host.'),
      port: { type: 'integer', minimum: 0, maximum: 65535,
              description: 'syslog and logrhythm: the port. 0 or omitted ' +
                           'is 6514 for TLS and 514 otherwise.' },
      transport: { type: 'string', enum: ['tcp', 'udp', 'tls'],
                   description: 'syslog and logrhythm. TCP when omitted. ' +
                                'UDP is fire-and-forget.' },
      facility: { type: 'integer', minimum: 0, maximum: 23,
                  description: 'syslog and logrhythm. 16 is local0.' },
      appName: text(48, 'syslog and logrhythm: the APP-NAME. iya-sts when ' +
                        'empty.'),
      path: text(1024, 'file: an absolute path.'),
      mode: text(4, 'file: three octal digits, such as 640.'),
      rotateBytes: { type: 'integer', minimum: 0,
                     description: 'file: rotate at this size. 0 is off.' },
      url: text(2048, 'webhook or Splunk HEC: an https URL.'),
      template: text(4000, 'webhook: one line with {timestamp} and the ' +
                           'other placeholders. Empty sends the canonical ' +
                           'event as JSON.'),
      contentType: text(200, 'webhook: the content type. Empty is JSON, ' +
                             'or text when a template is set.'),
      headers: text(8000, 'webhook: plain headers, one "Name: value" a ' +
                          'line. Sent back on a change. Empty replaces ' +
                          'them. A name that looks like a credential is ' +
                          'sealed instead.'),
      secretHeaders: { type: 'string', maxLength: 8000, writeOnly: true,
                       description: 'webhook: sealed headers, one ' +
                                    '"Name: value" a line. Never returned. ' +
                                    'Empty keeps every one. A blank value ' +
                                    'keeps that one name.' },
      token: { type: 'string', maxLength: 4096, writeOnly: true,
               description: 'Splunk HEC: the collector token. Never ' +
                            'returned. Empty on a change keeps it.' },
      index: text(128, 'Splunk HEC: the index. Empty uses the token\'s.'),
      sourcetype: text(128, 'Splunk HEC: the sourcetype. iya:audit when ' +
                            'empty.'),
      source: text(128, 'Splunk HEC: the source. iya-sts when empty.'),
      ack: { type: 'boolean',
             description: 'Splunk HEC: wait for the indexer ack before ' +
                          'the cursor moves. One event is in flight.' }
    };
    helpers.log.debug("Leaving AuditExportApi.properties().");
    return fields;
  }

  /**
   * The route table.
   *
   * @returns the rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes: codes, loadExport,
            loadAdmin } = this.deps;
    const self = this;
    log.debug("Entering AuditExportApi.buildRoutes().");
    const p = AuditExportApi.properties();
    const fields = {
      id: p.id, name: p.name, type: p.type, enabled: p.enabled,
      excludeAttributes: p.excludeAttributes, host: p.host, port: p.port,
      transport: p.transport, facility: p.facility, appName: p.appName,
      path: p.path, mode: p.mode, rotateBytes: p.rotateBytes, url: p.url,
      template: p.template, contentType: p.contentType, headers: p.headers,
      secretHeaders: p.secretHeaders, token: p.token, index: p.index,
      sourcetype: p.sourcetype, source: p.source, ack: p.ack
    };
    const idOnly = {
      type: 'object', properties: { id: p.id }, required: ['id'],
      examples: [{ id: 'siem' }], additionalProperties: false
    };
    const ROUTES = [
      { method: 'GET', path: BASE + '/audit-export',
        tag: 'Monitoring', operationId: 'getAuditExport',
        mirrors: 'GET ' + PAGE,
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API audit export endpoint.");
          const view = loadExport().view();
          view.settings = loadAdmin().configSettingsJson(PAGE);
          self.sendJson(res, 200, view);
          log.debug("Leaving the management API audit export endpoint.");
        } },

      { method: 'POST', route: BASE + '/audit-export/:action',
        tag: 'Monitoring', mirrors: 'POST ' + PAGE,
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API audit export action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          Promise.resolve().then(function (): Json {
            return loadExport().act(body);
          }).then(function (result: Json): void {
            if (!result.ok) {
              // The act's own code, read off the marked result.
              codes.mark(res, codes.codeOf(result) ||
                              'STS-AUDIT-0001');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API audit export action. " +
                      "ok=" + result.ok);
          }, function (e: any): void {
            log.error(codes.tag('STS-AUDIT-0001') +
                      'audit export: an /admin-api action failed: ' +
                      ((e && e.message) || e));
            codes.mark(res, 'STS-AUDIT-0001');
            self.sendJson(res, 500, { ok: false, errors:
              ['The action could not be completed.'] });
            log.debug("Leaving the management API audit export action. " +
                      "Threw.");
          });
        },
        actions: [
          { action: 'add', operationId: 'addAuditExportDestination'
             },
          { action: 'update', operationId: 'updateAuditExportDestination'
             },
          { action: 'remove', operationId: 'removeAuditExportDestination'
             },
          { action: 'enable', operationId: 'enableAuditExportDestination'
             },
          { action: 'disable',
            operationId: 'disableAuditExportDestination'
             },
          { action: 'test', operationId: 'testAuditExportDestination'
             }
        ] }
    ];
    log.debug("Leaving AuditExportApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<AuditExportApi>(
  'mgmt-api/audit_export_api',
  () => new AuditExportApi(AuditExportApi.defaultDeps()),
  AuditExportApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The audit export operations of `/admin-api` (#641).
 *
 * It registers no route: the management API spreads `ROUTES`.
 *
 * @namespace
 */
export = {
  AuditExportApi: AuditExportApi,
  /**
   * Installs the instance the composition root built.
   *
   * @param instance - the instance every facade forwards to
   */
  installInstance: (instance: AuditExportApi): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  /**
   * The installed instance's route table.
   */
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
