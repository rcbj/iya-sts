// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: post_login_campaigns_api.ts
// ---------------------------------------------------------------------------
// THE /admin-api/post-login-campaigns OPERATIONS (#1111), mirroring
// Directory → Post-login campaigns (rule 7): the campaigns as the page draws
// them, and the page's four acts — start, pause, resume, end. Each is
// `common/post_login_campaigns.ts`'s and nothing else, so the page and the
// operation cannot disagree: they are one call.
//
// **NOTHING HERE MAILS.** Starting a campaign writes a row; the scheduler
// job `post-login.campaign-mail` mails, on the leader's schedule, a slice
// at a time. And nothing here REPORTS: who was mailed and where each person
// stands is the reports application's `postLoginProgress` source (#1110),
// as rcbj asked — this operation answers each campaign's own counts only.
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

interface CampaignsApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // The campaigns, lazily: this module is built with the other API
  // modules, and the campaigns are only asked inside a handler.
  loadCampaigns(): Json;
}

const BASE = '/admin-api';

/**
 * The `/admin-api/post-login-campaigns` operations: the list and the four
 * acts.
 */
class PostLoginCampaignsApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes and a loader of the
   *   campaigns
   */
  constructor(private readonly deps: CampaignsApiDeps) {
    deps.log.debug("Entering PostLoginCampaignsApi.constructor().");
    deps.log.debug("Leaving PostLoginCampaignsApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports, with the
   * campaigns loaded lazily.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): CampaignsApiDeps {
    helpers.log.debug("Entering PostLoginCampaignsApi.defaultDeps().");
    helpers.log.debug("Leaving PostLoginCampaignsApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadCampaigns: function (): Json {
        return require('../common/post_login_campaigns');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: PostLoginCampaignsApi): void {
    helpers.log.debug("Entering PostLoginCampaignsApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving PostLoginCampaignsApi.wire().");
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
    log.debug("Entering PostLoginCampaignsApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving PostLoginCampaignsApi.sendJson().");
  }

  /**
   * Builds the operations' route table, each row carrying its OpenAPI
   * description and its handler.
   *
   * @returns the route rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadCampaigns } = this.deps;
    const self = this;
    log.debug("Entering PostLoginCampaignsApi.buildRoutes().");
    const campaigns = loadCampaigns();
    const L = campaigns.LIMITS;
    const ROUTES = [
      { method: 'GET', path: BASE + '/post-login-campaigns',
        tag: 'Directory', operationId: 'getPostLoginCampaigns',
        summary: 'Post-login mail campaigns in this realm (#1111)',
        description: 'Everything Directory → Post-login campaigns draws: ' +
          'every campaign of the realm, newest first — `id`, `activity`, ' +
          '`group` (a DN, or empty for the whole realm), `intervalDays`, ' +
          '`maxMails`, `perRun`, `state` (`running`, `paused`, `ended`), ' +
          'who started and last changed it and when — each with `run`, what ' +
          'its scheduler job has done (`passes` over the population, ' +
          '`read`, `mailed`, `notDue`, `heldBack`, `refused`, `lastRunAt`, ' +
          '`lastSummary`); the `activities` a campaign may be for, the ' +
          '`limits` of its numbers, whether a mail transport is ' +
          '`mailAvailable`, whether any post-login profile is ' +
          '`activityEnabled`, and the job and how often it runs. Who was ' +
          'mailed and where each person stands is the reports ' +
          'application\'s postLoginProgress source, not this operation.',
        mirrors: 'GET /admin/post-login-campaigns',
        responseDescription: 'The campaigns.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`realm`, `job`, `everyMinutes`, ' +
                                       '`activities`, `limits`, ' +
                                       '`mailAvailable`, ' +
                                       '`activityEnabled`, `campaigns`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API campaigns endpoint.");
          try {
            self.sendJson(res, 200, loadCampaigns().view());
          } catch (e) {
            log.error(errorCodes.tag('STS-AUTHN-0480') + 'post-login ' +
                      'campaigns could not be read: ' +
                      ((e && e.message) || e));
            errorCodes.mark(res, 'STS-AUTHN-0480');
            self.sendJson(res, 500, { ok: false, errors: [
              'The campaigns could not be read.'] });
          }
          log.debug("Leaving the management API campaigns endpoint.");
        } },

      { method: 'POST', route: BASE + '/post-login-campaigns/:action',
        tag: 'Directory', mirrors: 'POST /admin/post-login-campaigns',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API campaigns action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          // THE CALLER, which the route wrapper put in the body's `actor`
          // after its schema passed (`nameActor()`, #446).
          Promise.resolve().then(function (): Json {
            return loadCampaigns().act(body, {
              actor: String(body.actor || ''), via: 'api' });
          }).then(function (result: Json): void {
            if (!result.ok) {
              // error-code: none — the act's own code, read off the result
              errorCodes.mark(res, String(result.errorCode ||
                                          'STS-AUTHN-0478'));
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API campaigns action. " +
                      "ok=" + result.ok);
          }, function (e: any): void {
            log.error(errorCodes.tag('STS-AUTHN-0480') + 'post-login ' +
                      'campaign act failed: ' + ((e && e.message) || e));
            errorCodes.mark(res, 'STS-AUTHN-0480');
            self.sendJson(res, 500, { ok: false, errors: [
              'The campaign could not be changed.'] });
            log.debug("Leaving the management API campaigns action. " +
                      "Threw.");
          });
        },
        actions: [
          { action: 'start', operationId: 'startPostLoginCampaign',
            summary: 'Start a post-login mail campaign',
            description: 'Starts a campaign for one post-login activity in ' +
              'this realm. From the next run of the scheduler job ' +
              '`post-login.campaign-mail` (every few minutes, or Run now ' +
              'on Monitoring → Scheduler) each person the activity is DUE ' +
              'for — the post-login policy reaches them, the realm can make ' +
              'the passkey, they have not done it — is mailed at the ' +
              'address on their entry a reminder to sign in, at most ' +
              '`maxMails` times and never twice inside `intervalDays`. ' +
              'The mail\'s one link opens the sign-in page; it carries no ' +
              'credential, and the post-login activity does the ' +
              'registration. `group` narrows the people to one group\'s ' +
              'members. A second campaign for the same activity and people ' +
              'is refused (STS-AUTHN-0479); bad values are STS-AUTHN-0477.',
            requestBodyRequired: false,
            requestBody: {
              type: 'object',
              properties: {
                activity: { type: 'string',
                            enum: campaigns.ACTIVITIES.slice(),
                            description: 'The post-login activity.' },
                group: { type: 'string', maxLength: 1024,
                         description: 'A group\'s cn or DN; empty for ' +
                                      'everybody in the realm.' },
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
                           intervalDays: 7, maxMails: 3 }],
              additionalProperties: false
            },
            responseDescription: 'The campaign started.' },
          { action: 'pause', operationId: 'pausePostLoginCampaign',
            summary: 'Pause a post-login mail campaign',
            description: 'A running campaign stops mailing, within the ' +
              'slice a run is in; its cursor is kept. STS-AUTHN-0478 for ' +
              'no such campaign or one that is not running.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { id: { type: 'string', maxLength: 64,
                                  description: 'The campaign.' } },
              required: ['id'], examples: [{ id: 'plc-AbCdEfGhIjKl' }],
              additionalProperties: false
            },
            responseDescription: 'The campaign paused.' },
          { action: 'resume', operationId: 'resumePostLoginCampaign',
            summary: 'Resume a paused post-login mail campaign',
            description: 'A paused campaign mails again from where its ' +
              'cursor stopped. STS-AUTHN-0478 for no such campaign or one ' +
              'that is not paused.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { id: { type: 'string', maxLength: 64,
                                  description: 'The campaign.' } },
              required: ['id'], examples: [{ id: 'plc-AbCdEfGhIjKl' }],
              additionalProperties: false
            },
            responseDescription: 'The campaign running again.' },
          { action: 'end', operationId: 'endPostLoginCampaign',
            summary: 'End a post-login mail campaign',
            description: 'A running or paused campaign ends for good: it ' +
              'mails nobody again, and what it did stays on the page and ' +
              'on each person\'s progress row. STS-AUTHN-0478 for no such ' +
              'campaign or one already ended.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { id: { type: 'string', maxLength: 64,
                                  description: 'The campaign.' } },
              required: ['id'], examples: [{ id: 'plc-AbCdEfGhIjKl' }],
              additionalProperties: false
            },
            responseDescription: 'The campaign ended.' }
        ] }
    ];
    log.debug("Leaving PostLoginCampaignsApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<PostLoginCampaignsApi>(
  'mgmt-api/post_login_campaigns_api',
  () => new PostLoginCampaignsApi(PostLoginCampaignsApi.defaultDeps()),
  PostLoginCampaignsApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The post-login mail campaigns' operations of `/admin-api` (#1111),
 * mirroring Directory → Post-login campaigns.
 *
 * It registers no route: the management API spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  PostLoginCampaignsApi: PostLoginCampaignsApi,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: PostLoginCampaignsApi): void =>
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
