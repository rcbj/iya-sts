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
        summary: 'Started post-login activities in this realm (#1111)',
        description: 'Everything Directory → Post-login activities draws: ' +
          '`started`, every post-login activity started in the realm, ' +
          'newest first — `id`, `activity`, `groups` (their DNs; empty for ' +
          'the whole realm), `intervalDays`, `maxMails`, `perRun`, `state` ' +
          '(`running`, `paused`, `ended`), who started and last changed it ' +
          'and when — each with `run`, what its scheduler job has done ' +
          '(`passes` over the population, `read`, `mailed`, `notDue`, ' +
          '`heldBack`, `refused`, `lastRunAt`, `lastSummary`); the ' +
          '`activities` an administrator may start, the `limits` of the ' +
          'numbers and of `groups`, whether a mail transport is ' +
          '`mailAvailable`, whether any post-login profile is ' +
          '`activityEnabled`, the job and how often it runs; and ' +
          '`groupChooser`, the start form\'s group search (#1123): ' +
          '`chosen` (the `groups` asked, each resolved — `found` false for ' +
          'a name this realm does not have) and `pane`, one page of the ' +
          'groups whose cn or DN contains `groupq`, ' +
          activities.CHOOSER_HITS + ' from `groupfrom` (a stale offset is ' +
          'clamped to the first page), the chosen ones left out ' +
          '(`total`, `matched`, `from`, `shown`: each `dn` and `cn`). The ' +
          'search reads the directory\'s group index, never its people. ' +
          'Who was mailed and where each person stands is the reports ' +
          'application\'s postLoginProgress source, not this operation.',
        mirrors: 'GET /admin/post-login-activities',
        parameters: [
          { name: 'groupq', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256 },
            description: 'The group search: a substring of a group\'s cn ' +
                         'or DN, case-insensitive; empty for every group.' },
          { name: 'groupfrom', in: 'query', required: false,
            schema: { type: 'string', maxLength: 16 },
            description: 'Where the page of the group search starts.' },
          { name: 'groups', in: 'query', required: false,
            schema: { type: 'string', maxLength: 65536 },
            description: 'The groups chosen so far, cns or DNs separated ' +
                         'by `;` (a DN\'s commas stay intact; a `;` inside ' +
                         'a DN value is escaped, `\\;`); ' +
                         'resolved into `groupChooser.chosen` and left out ' +
                         'of the search.' }
        ],
        responseDescription: 'The started activities and the chooser.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`realm`, `job`, `everyMinutes`, ' +
                                       '`activities`, `limits`, ' +
                                       '`mailAvailable`, ' +
                                       '`activityEnabled`, ' +
                                       '`groupChooser`, `started`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API post-login activities " +
                    "endpoint.");
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
              errorCodes.mark(res, String(result.errorCode ||
                                          'STS-AUTHN-0491'));
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
          { action: 'start', operationId: 'startPostLoginActivity',
            summary: 'Start a post-login activity',
            description: 'Starts a post-login activity in this realm. From ' +
              'the next run of the scheduler job ' +
              '`post-login.activity-mail` (every few minutes, or Run now ' +
              'on Monitoring → Scheduler) each person the activity is DUE ' +
              'for — the post-login policy reaches them, the realm can make ' +
              'the passkey, they have not done it — is mailed at the ' +
              'address on their entry a reminder to sign in, at most ' +
              '`maxMails` times and never twice inside `intervalDays`. ' +
              'The mail\'s one link opens the sign-in page; it carries no ' +
              'credential, and the post-login activity does the ' +
              'registration. `groups` narrows the people to the members of ' +
              'those groups: their UNION, a person in two of them read and ' +
              'mailed once; none means everybody in the realm. A group this ' +
              'realm does not have is refused (STS-AUTHN-0530); a second ' +
              'started activity for the same activity and the same groups ' +
              'is refused (STS-AUTHN-0492); bad values are STS-AUTHN-0490.',
            requestBodyRequired: false,
            requestBody: {
              type: 'object',
              properties: {
                activity: { type: 'string',
                            enum: activities.ACTIVITIES.slice(),
                            description: 'The post-login activity.' },
                groups: { type: 'array', maxItems: activities.MAX_GROUPS,
                          items: { type: 'string', maxLength: 1024 },
                          description: 'Groups\' cns or DNs, the people ' +
                                       'being the union of their members; ' +
                                       'empty or absent for everybody in ' +
                                       'the realm.' },
                intervalDays: { type: 'integer',
                  minimum: L.intervalDays.min, maximum: L.intervalDays.max,
                  description: 'Days between two mails to one person ' +
                               '(default ' + L.intervalDays.dflt + ').' },
                maxMails: { type: 'integer',
                  minimum: L.maxMails.min, maximum: L.maxMails.max,
                  description: 'The most mails one person is sent ' +
                               '(default ' + L.maxMails.dflt + ').' },
                perRun: { type: 'integer',
                  minimum: L.perRun.min, maximum: L.perRun.max,
                  description: 'People read per run of the job (default ' +
                               L.perRun.dflt + ').' }
              },
              examples: [{ activity: 'pqc-passkey-migration',
                           groups: ['engineering', 'finance'],
                           intervalDays: 7, maxMails: 3 }],
              additionalProperties: false
            },
            responseDescription: 'The post-login activity started.' },
          { action: 'pause', operationId: 'pausePostLoginActivity',
            summary: 'Pause a started post-login activity',
            description: 'A running post-login activity stops mailing, ' +
              'within the slice a run is in; its cursor is kept. ' +
              'STS-AUTHN-0491 for no such started activity or one that is ' +
              'not running.',
            requestBodyRequired: true,
            requestBody: idBody('The started activity.'),
            responseDescription: 'The post-login activity paused.' },
          { action: 'resume', operationId: 'resumePostLoginActivity',
            summary: 'Resume a paused post-login activity',
            description: 'A paused post-login activity mails again from ' +
              'where its cursor stopped. STS-AUTHN-0491 for no such ' +
              'started activity or one that is not paused.',
            requestBodyRequired: true,
            requestBody: idBody('The started activity.'),
            responseDescription: 'The post-login activity running again.' },
          { action: 'end', operationId: 'endPostLoginActivity',
            summary: 'End a started post-login activity',
            description: 'A running or paused post-login activity ends for ' +
              'good: it mails nobody again, and what it did stays on the ' +
              'page and on each person\'s progress row. STS-AUTHN-0491 for ' +
              'no such started activity or one already ended.',
            requestBodyRequired: true,
            requestBody: idBody('The started activity.'),
            responseDescription: 'The post-login activity ended.' }
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
