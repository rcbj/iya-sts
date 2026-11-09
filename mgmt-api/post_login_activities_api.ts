// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: post_login_activities_api.ts
// ---------------------------------------------------------------------------
// THE /admin-api/post-login-activities OPERATIONS (#1111, #1123), mirroring
// Directory → Post-login activities (rule 7): the started activities as the
// page draws them, with the start form's group chooser, and the page's four
// acts — start, pause, resume, end. Each is
// `common/post_login_activities.ts`'s and nothing else, so the page and the
// operation cannot disagree: they are one call.
//
// **NOTHING HERE MAILS.** Starting an activity writes a row; the scheduler
// job `post-login.activity-mail` mails, on the leader's schedule, a slice
// at a time. And nothing here REPORTS: who was mailed and where each person
// stands is the reports application's `postLoginProgress` source (#1110),
// as rcbj asked — this operation answers each started activity's own counts
// only.
//
// It registers no route: `mgmt-api/admin_api.ts` spreads `ROUTES` into its
// table, as it does the passkey report's.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface ActivitiesApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // The started activities, lazily: this module is built with the other
  // API modules, and they are only asked inside a handler.
  loadActivities(): Json;
}

const BASE = '/admin-api';

/**
 * The `/admin-api/post-login-activities` operations: the list and the four
 * acts.
 */
class PostLoginActivitiesApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes and a loader of the
   *   started activities
   */
  constructor(private readonly deps: ActivitiesApiDeps) {
    deps.log.debug("Entering PostLoginActivitiesApi.constructor().");
    deps.log.debug("Leaving PostLoginActivitiesApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports, with the
   * started activities loaded lazily.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): ActivitiesApiDeps {
    helpers.log.debug("Entering PostLoginActivitiesApi.defaultDeps().");
    helpers.log.debug("Leaving PostLoginActivitiesApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadActivities: function (): Json {
        return require('../common/post_login_activities');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: PostLoginActivitiesApi): void {
    helpers.log.debug("Entering PostLoginActivitiesApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving PostLoginActivitiesApi.wire().");
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
    log.debug("Entering PostLoginActivitiesApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving PostLoginActivitiesApi.sendJson().");
  }

  /**
   * Builds the operations' route table, each row carrying its OpenAPI
   * description and its handler.
   *
   * @returns the route rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadActivities } = this.deps;
    const self = this;
    log.debug("Entering PostLoginActivitiesApi.buildRoutes().");
    const activities = loadActivities();
    const L = activities.LIMITS;
    const idBody = function (what: string): Json {
      return {
        type: 'object',
        properties: { id: { type: 'string', maxLength: 64,
                            description: what } },
        required: ['id'], examples: [{ id: 'pla-AbCdEfGhIjKl' }],
        additionalProperties: false
      };
    };
    const ROUTES = [
      { method: 'GET', path: BASE + '/post-login-activities',
        tag: 'Directory', operationId: 'getPostLoginActivities',
        mirrors: 'GET /admin/post-login-activities',
        parameters: [
          { name: 'groupq', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256, examples: ['staff'] },
            description: 'The group search: a substring of a group\'s cn ' +
                         'or DN, case-insensitive; empty for every group.' },
          { name: 'groupfrom', in: 'query', required: false,
            schema: { type: 'string', maxLength: 16 },
            description: 'Where the page of the group search starts.' },
          { name: 'groups', in: 'query', required: false,
            schema: { type: 'string',
                      maxLength: activities.GROUPS_QUERY_MAX },
            description: 'The groups chosen so far, cns or DNs separated ' +
                         'by `;` (a DN\'s commas stay intact; a `;` inside ' +
                         'a DN value is escaped, `\\;`); ' +
                         'resolved into `groupChooser.chosen` and left out ' +
                         'of the search. At most ' +
                         activities.GROUPS_QUERY_MAX + ' characters, which ' +
                         'is as much as one request line can carry; fifty ' +
                         'ordinary group names fit.' }
        ],
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API post-login activities " +
                    "endpoint.");
          const problem = activities.groupsQueryProblem(req.query || {});
          if (problem) {
            errorCodes.mark(res, 'STS-AUTHN-0496');
            self.sendJson(res, 400, problem);
            log.debug("Leaving the management API post-login activities " +
                      "endpoint.");
            return;
          }
          try {
            self.sendJson(res, 200, loadActivities().view(req.query || {}));
          } catch (e) {
            log.error(errorCodes.tag('STS-AUTHN-0493') + 'post-login ' +
                      'activities could not be read: ' +
                      ((e && e.message) || e));
            errorCodes.mark(res, 'STS-AUTHN-0493');
            self.sendJson(res, 500, { ok: false, errors: [
              'The post-login activities could not be read.'] });
          }
          log.debug("Leaving the management API post-login activities " +
                    "endpoint.");
        } },

      { method: 'POST', route: BASE + '/post-login-activities/:action',
        tag: 'Directory', mirrors: 'POST /admin/post-login-activities',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API post-login activities " +
                    "action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          // THE CALLER, which the route wrapper put in the body's `actor`
          // after its schema passed (`nameActor()`, #446).
          Promise.resolve().then(function (): Json {
            return loadActivities().act(body, {
              actor: String(body.actor || ''), via: 'api' });
          }).then(function (result: Json): void {
            if (!result.ok) {
              // error-code: none — the act's own code, read off the result
              errorCodes.mark(res, errorCodes.codeOf(result) ||
                                   'STS-AUTHN-0491');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API post-login activities " +
                      "action. ok=" + result.ok);
          }, function (e: any): void {
            log.error(errorCodes.tag('STS-AUTHN-0493') + 'post-login ' +
                      'activity act failed: ' + ((e && e.message) || e));
            errorCodes.mark(res, 'STS-AUTHN-0493');
            self.sendJson(res, 500, { ok: false, errors: [
              'The post-login activity could not be changed.'] });
            log.debug("Leaving the management API post-login activities " +
                      "action. Threw.");
          });
        },
        actions: [
          { action: 'start', operationId: 'startPostLoginActivity'
             },
          { action: 'pause', operationId: 'pausePostLoginActivity'
             },
          { action: 'resume', operationId: 'resumePostLoginActivity'
             },
          { action: 'end', operationId: 'endPostLoginActivity'
             }
        ] }
    ];
    log.debug("Leaving PostLoginActivitiesApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<PostLoginActivitiesApi>(
  'mgmt-api/post_login_activities_api',
  () => new PostLoginActivitiesApi(PostLoginActivitiesApi.defaultDeps()),
  PostLoginActivitiesApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The started post-login activities' operations of `/admin-api` (#1111,
 * #1123), mirroring Directory → Post-login activities.
 *
 * It registers no route: the management API spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  PostLoginActivitiesApi: PostLoginActivitiesApi,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: PostLoginActivitiesApi): void =>
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
