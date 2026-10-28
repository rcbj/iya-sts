// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_campaigns.ts
//
// ---------------------------------------------------------------------------
// MAIL CAMPAIGNS FOR A POST-LOGIN ACTIVITY (#1111, 2026-10-28).
//
// A post-login activity (#1096) reaches a person only when they sign in, so
// somebody who rarely signs in is never asked to register an ML-DSA passkey
// before a deadline. rcbj's decisions on #1111:
//
//   * AN ADMINISTRATOR STARTS A CAMPAIGN for one post-login activity in a
//     realm — optionally narrowed to one group — from the console and from
//     `/admin-api` (rule 7: `mgmt-api/post_login_campaigns_api.ts`, drawn by
//     `admin-ui/web_post_login_campaigns.ts`): the reminder interval in days,
//     the most mails one person is sent, and how many people one run reads.
//     It can be paused, resumed and ended.
//   * A CLUSTER SCHEDULER JOB (`post-login.campaign-mail`) walks the
//     campaign's population after a KEY CURSOR, a bounded slice per run —
//     the realm's people through `ldap_server.js`'s `passkeyScanAsync()`, a
//     group's through `groupMembersAfterAsync()` — and mails each person the
//     activity is due for (`post_login.dueFor()`, which already says nobody
//     who has done it and nobody the realm cannot ask, `canRegister()`). No
//     second mail inside the interval, none past the maximum. At the end of
//     the population the cursor starts again: the next pass is the reminders.
//   * THE MAIL SENDS THE PERSON TO SIGN IN, and the post-login activity does
//     the registration. The one link is the portal's own path on this
//     service's pinned origin (`common/mail.ts`, point 6); it carries no
//     token, no code and nothing about the person. The address is the one on
//     the person's entry (`mail_uses.ts`'s `postLoginReminder()`), never one a
//     request names.
//   * Progress per person — the campaign, how many mails, the first and the
//     last — is written on the person's progress row
//     (`post_login.noteMailed()`), and the reports application reads it as
//     the `postLoginProgress` source (#1110). Nothing here draws a report.
//
// TWO STORES, AND WHY TWO. `post_login.campaigns` holds what an
// administrator decided — the activity, the group, the numbers, the state —
// and is written only by the console and the API. `post_login.campaignRuns`
// holds what the job did — the cursor, the passes, the counts — and is
// written only by the job. A job runs on a request worker (#408) while an
// administrator's Pause is answered by whichever process served it; with one
// row each would write back the other's stale half. Both are cell-tier: the
// cursor is a person's DN and a campaign names the administrator who started
// it. Neither is on demand: a realm runs a handful of campaigns.
//
// AUDIT: one row per start, pause, resume and end, and ONE ROW PER CAMPAIGN
// PER RUN summarising it (how many read, mailed, not due, held back, refused)
// — never a row per person, which a population of a million would turn into
// a million rows a pass.
//
// A LIBRARY (rule 3): it registers no route, and its job when it is built.
// The directory, the mail uses, the scheduler and the post-login modules are
// required LAZILY, at the moment of use — `ldap/ldap_server.js` is a
// JavaScript route module (root CLAUDE.md, rule 1) and must not be dragged
// forward by a require from here.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import InstanceSlot = require('./instance_slot');

type Json = any;

const { log } = helpers;

const DAY_MS = 24 * 60 * 60 * 1000;

/** The scheduler job that mails a running campaign's population. */
const JOB = 'post-login.campaign-mail';
/** How often it runs, in every realm with a campaign running. */
const EVERY_MS = 10 * 60 * 1000;

// The activities a campaign may be for: the post-login activities there are
// (`post_login.ts`), one today.
const ACTIVITIES = ['pqc-passkey-migration'];

// The numbers a campaign is started with, and their bounds.
const LIMITS = {
  intervalDays: { min: 1, max: 365, dflt: 7 },
  maxMails: { min: 1, max: 20, dflt: 3 },
  perRun: { min: 1, max: 20000, dflt: 1000 }
};

// The states, and which act moves a campaign from which.
const STATES = ['running', 'paused', 'ended'];
const MOVES: Record<string, { from: string[]; to: string }> = {
  pause: { from: ['running'], to: 'paused' },
  resume: { from: ['paused'], to: 'running' },
  end: { from: ['running', 'paused'], to: 'ended' }
};

// Every campaign a realm keeps, ended ones included, at most: past it the
// oldest ENDED campaign is forgotten when one is started.
const KEEP = 50;

// THE STORES — see the header. Declared here, per realm, and nowhere else.
const campaignStore = realms.map({ persist: 'post_login.campaigns' });
const runStore = realms.map({ persist: 'post_login.campaignRuns' });

interface Campaign {
  id: string;
  activity: string;
  group: string;
  intervalDays: number;
  maxMails: number;
  perRun: number;
  state: string;
  startedAt: number;
  startedBy: string;
  changedAt: number;
  changedBy: string;
  endedAt: number;
}

interface CampaignRun {
  cursor: string;
  passes: number;
  read: number;
  mailed: number;
  notDue: number;
  heldBack: number;
  refused: number;
  lastRunAt: number;
  lastSummary: string;
}

interface Store {
  get(key: string): any;
  set(key: string, value: any): unknown;
  delete(key: string): unknown;
  has(key: string): boolean;
  forEach(fn: (value: any, key: string) => void): void;
  realmMap?(id?: string): Map<string, any>;
}

interface CampaignDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  audit: { audit(event: Json): unknown };
  realms: Json;
  campaigns: Store;
  runs: Store;
  // Lazily: see the header.
  directory(): Json;
  postLogin(): Json;
  mailUses(): Json;
  mail(): Json;
  scheduler(): Json;
  randomId(): string;
  now(): number;
}

/**
 * Mail campaigns for a post-login activity (#1111): started, paused,
 * resumed and ended by an administrator; run by a cluster scheduler job.
 */
class PostLoginCampaigns {
  /** The scheduler job that mails a running campaign's population. */
  static readonly JOB = JOB;
  /** The activities a campaign may be for. */
  static readonly ACTIVITIES = ACTIVITIES;
  /** The bounds of a campaign's numbers. */
  static readonly LIMITS = LIMITS;
  /** The states a campaign is in. */
  static readonly STATES = STATES;
  /** The acts after a start. */
  static readonly ACTS = Object.keys(MOVES);

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, the stores, lazy readers of the directory,
   *   the post-login module, the mail uses and the scheduler, and a clock
   */
  constructor(private readonly deps: CampaignDeps) {
    deps.log.debug("Entering PostLoginCampaigns.constructor().");
    deps.log.debug("Leaving PostLoginCampaigns.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules
   */
  static defaultDeps(): CampaignDeps {
    log.debug("Entering PostLoginCampaigns.defaultDeps().");
    log.debug("Leaving PostLoginCampaigns.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      audit: audit,
      realms: realms,
      campaigns: campaignStore as unknown as Store,
      runs: runStore as unknown as Store,
      directory: function (): Json {
        return require('../ldap/ldap_server');
      },
      postLogin: function (): Json {
        return require('./post_login');
      },
      mailUses: function (): Json {
        return require('./mail_uses');
      },
      mail: function (): Json {
        return require('./mail');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      randomId: function (): string {
        return require('./crypto').randomBytes(9).toString('base64url');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // A campaign row as the store holds it, with every field it should have.
  private campaignOf(value: any): Campaign | null {
    const { log } = this.deps;
    log.debug("Entering PostLoginCampaigns.campaignOf().");
    if (!value || typeof value !== 'object' || !value.id) {
      log.debug("Leaving PostLoginCampaigns.campaignOf(). None.");
      return null;
    }
    const out: Campaign = {
      id: String(value.id), activity: String(value.activity || ''),
      group: String(value.group || ''),
      intervalDays: Number(value.intervalDays) || LIMITS.intervalDays.dflt,
      maxMails: Number(value.maxMails) || LIMITS.maxMails.dflt,
      perRun: Number(value.perRun) || LIMITS.perRun.dflt,
      state: STATES.indexOf(value.state) >= 0 ? value.state : 'ended',
      startedAt: Number(value.startedAt) || 0,
      startedBy: String(value.startedBy || ''),
      changedAt: Number(value.changedAt) || 0,
      changedBy: String(value.changedBy || ''),
      endedAt: Number(value.endedAt) || 0
    };
    log.debug("Leaving PostLoginCampaigns.campaignOf().");
    return out;
  }

  private runOf(id: string): CampaignRun {
    const { log, runs } = this.deps;
    log.debug("Entering PostLoginCampaigns.runOf().");
    const held = runs.get(id) || {};
    const out: CampaignRun = {
      cursor: String(held.cursor || ''), passes: Number(held.passes) || 0,
      read: Number(held.read) || 0, mailed: Number(held.mailed) || 0,
      notDue: Number(held.notDue) || 0, heldBack: Number(held.heldBack) || 0,
      refused: Number(held.refused) || 0,
      lastRunAt: Number(held.lastRunAt) || 0,
      lastSummary: String(held.lastSummary || '')
    };
    log.debug("Leaving PostLoginCampaigns.runOf().");
    return out;
  }

  /**
   * Every campaign of the ambient realm, newest first.
   *
   * @returns the campaigns
   */
  list(): Campaign[] {
    const { log, campaigns } = this.deps;
    log.debug("Entering PostLoginCampaigns.list().");
    const out: Campaign[] = [];
    const self = this;
    campaigns.forEach(function (value: any): void {
      const one = self.campaignOf(value);
      if (one) {
        out.push(one);
      }
    });
    out.sort(function (a, b) {
      return b.startedAt - a.startedAt || (a.id < b.id ? -1 : 1);
    });
    log.debug("Leaving PostLoginCampaigns.list(). " + out.length);
    return out;
  }

  /**
   * One campaign of the ambient realm.
   *
   * @param id - its id
   * @returns the campaign, or null
   */
  get(id: string): Campaign | null {
    const { log, campaigns } = this.deps;
    log.debug("Entering PostLoginCampaigns.get().");
    const out = this.campaignOf(campaigns.get(String(id || '')));
    log.debug("Leaving PostLoginCampaigns.get(). " + (out ? 'Found.'
                                                         : 'None.'));
    return out;
  }

  /**
   * What the console page and `GET /admin-api/post-login-campaigns` draw:
   * every campaign with what its runs did, the activities, the bounds, and
   * whether anything can be sent.
   *
   * @returns the view
   */
  view(): Json {
    const { log, realms } = this.deps;
    log.debug("Entering PostLoginCampaigns.view().");
    const self = this;
    let mailOn = false;
    let activityOn = false;
    try {
      mailOn = this.deps.mail().available() === true;
    } catch (e) {
      // A channel that cannot be asked sends nothing; the page says so.
      log.debug("Caught in PostLoginCampaigns.view(): " +
                ((e && e.message) || e));
      mailOn = false;
    }
    try {
      activityOn = require('./post_login_policy').anyEnabled() === true;
    } catch (e) {
      // A policy that cannot be read asks nobody; the page says so.
      log.debug("Caught in PostLoginCampaigns.view(): " +
                ((e && e.message) || e));
      activityOn = false;
    }
    const iso = function (ms: number): string | null {
      return ms > 0 ? new Date(ms).toISOString() : null;
    };
    const out = {
      realm: String(realms.currentId()),
      job: JOB,
      everyMinutes: Math.round(EVERY_MS / 60000),
      activities: ACTIVITIES.slice(),
      limits: JSON.parse(JSON.stringify(LIMITS)),
      mailAvailable: mailOn,
      activityEnabled: activityOn,
      campaigns: this.list().map(function (one: Campaign): Json {
        const run = self.runOf(one.id);
        return Object.assign({}, one, {
          startedAt: iso(one.startedAt), changedAt: iso(one.changedAt),
          endedAt: iso(one.endedAt),
          run: Object.assign({}, run, { lastRunAt: iso(run.lastRunAt),
                                        cursor: run.cursor ? 'held' : '' })
        });
      })
    };
    log.debug("Leaving PostLoginCampaigns.view(). " + out.campaigns.length);
    return out;
  }

  // A whole number between the bounds, or the default when absent; null
  // when given and out of bounds or not a number.
  private numberOf(given: any, bound: { min: number; max: number;
                                        dflt: number }): number | null {
    const { log } = this.deps;
    log.debug("Entering PostLoginCampaigns.numberOf().");
    if (given === undefined || given === null || given === '') {
      log.debug("Leaving PostLoginCampaigns.numberOf(). Default.");
      return bound.dflt;
    }
    const n = Number(given);
    const out = Number.isInteger(n) && n >= bound.min && n <= bound.max
      ? n : null;
    log.debug("Leaving PostLoginCampaigns.numberOf(). " + out);
    return out;
  }

  private refused(code: string, errors: string[]): Json {
    const { log } = this.deps;
    log.debug("Entering PostLoginCampaigns.refused(). " + code);
    log.debug("Leaving PostLoginCampaigns.refused().");
    return { ok: false, errorCode: code, errors: errors };
  }

  /**
   * Starts a campaign in the ambient realm.
   *
   * @param body - `activity`, `group` (optional: a group's cn or DN),
   *   `intervalDays`, `maxMails`, `perRun`
   * @param ctx - `{ actor, via }`: who started it, and through which door
   * @returns `{ ok, campaign }`, or `{ ok: false, errorCode, errors }`
   */
  async start(body: Json, ctx: Json): Promise<Json> {
    const { log, campaigns, runs, randomId, now, realms } = this.deps;
    log.debug("Entering PostLoginCampaigns.start().");
    const b = body || {};
    const errors: string[] = [];
    const activity = String(b.activity || ACTIVITIES[0]);
    if (ACTIVITIES.indexOf(activity) < 0) {
      errors.push('activity is one of: ' + ACTIVITIES.join(', ') + '.');
    }
    const numbers: Record<string, number> = {};
    (Object.keys(LIMITS) as Array<keyof typeof LIMITS>)
      .forEach((key) => {
        const n = this.numberOf(b[key], LIMITS[key]);
        if (n === null) {
          errors.push(key + ' is a whole number from ' + LIMITS[key].min +
                      ' to ' + LIMITS[key].max + '.');
        } else {
          numbers[key] = n;
        }
      });
    let group = String(b.group || '').trim();
    if (!errors.length && group) {
      let found: Json = null;
      try {
        found = await this.deps.directory()
          .groupMembersAfterAsync(group, '', 1);
      } catch (e) {
        log.debug("Caught in PostLoginCampaigns.start(): " +
                  ((e && e.message) || e));
        found = null;
      }
      if (!found || !found.found) {
        errors.push('There is no group "' + group + '" in this realm.');
      } else {
        group = String(found.dn);
      }
    }
    if (errors.length) {
      log.debug("Leaving PostLoginCampaigns.start(). Refused.");
      return this.refused('STS-AUTHN-0477', errors);
    }
    const same = this.list().filter(function (one: Campaign): boolean {
      return one.state !== 'ended' && one.activity === activity &&
             one.group.toLowerCase() === group.toLowerCase();
    })[0];
    if (same) {
      log.debug("Leaving PostLoginCampaigns.start(). One is running.");
      return this.refused('STS-AUTHN-0479', [
        'Campaign ' + same.id + ' is already ' + same.state + ' for ' +
        activity + (group ? ' in ' + group : ' across the realm') +
        '. End it before starting another for the same people.']);
    }
    // THE BOUND ON WHAT IS KEPT: the oldest ended campaigns go first.
    const ended = this.list().filter(function (one: Campaign): boolean {
      return one.state === 'ended';
    });
    while (ended.length && this.list().length >= KEEP) {
      const old = ended.pop() as Campaign;
      campaigns.delete(old.id);
      runs.delete(old.id);
    }
    const at = now();
    const actor = String((ctx && ctx.actor) || '');
    const campaign: Campaign = {
      id: 'plc-' + randomId(), activity: activity, group: group,
      intervalDays: numbers.intervalDays, maxMails: numbers.maxMails,
      perRun: numbers.perRun, state: 'running', startedAt: at,
      startedBy: actor, changedAt: at, changedBy: actor, endedAt: 0
    };
    campaigns.set(campaign.id, campaign);
    this.deps.audit.audit({
      action: 'admin.post-login-campaign.change', outcome: 'success',
      actor: actor, target: campaign.id,
      channel: String((ctx && ctx.via) || 'console'),
      summary: actor + ' started post-login mail campaign ' + campaign.id +
               ' for ' + activity + (group ? ' in ' + group
                                            : ' across the realm'),
      detail: { act: 'start', campaign: campaign.id, activity: activity,
                group: group, intervalDays: campaign.intervalDays,
                maxMails: campaign.maxMails, perRun: campaign.perRun,
                realm: String(realms.currentId()) }
    });
    log.info('post-login: campaign ' + campaign.id + ' started in realm "' +
             realms.currentId() + '" by ' + (actor || 'nobody named') + '.');
    log.debug("Leaving PostLoginCampaigns.start().");
    return { ok: true, campaign: campaign };
  }

  /**
   * Pauses, resumes or ends a campaign of the ambient realm.
   *
   * @param act - `pause`, `resume` or `end`
   * @param id - the campaign
   * @param ctx - `{ actor, via }`
   * @returns `{ ok, campaign }`, or `{ ok: false, errorCode, errors }`
   */
  move(act: string, id: string, ctx: Json): Json {
    const { log, campaigns, now, realms } = this.deps;
    log.debug("Entering PostLoginCampaigns.move(). " + act);
    const move = MOVES[String(act || '')];
    if (!move) {
      log.debug("Leaving PostLoginCampaigns.move(). Unknown act.");
      return this.refused('STS-AUTHN-0478', ['Unknown action "' +
        String(act || '') + '". The actions are start, ' +
        Object.keys(MOVES).join(', ') + '.']);
    }
    const campaign = this.get(id);
    if (!campaign) {
      log.debug("Leaving PostLoginCampaigns.move(). No campaign.");
      return this.refused('STS-AUTHN-0478', ['There is no campaign "' +
        String(id || '') + '" in this realm.']);
    }
    if (move.from.indexOf(campaign.state) < 0) {
      log.debug("Leaving PostLoginCampaigns.move(). Wrong state.");
      return this.refused('STS-AUTHN-0478', ['Campaign ' + campaign.id +
        ' is ' + campaign.state + '; ' + act + ' needs one that is ' +
        move.from.join(' or ') + '.']);
    }
    const at = now();
    const actor = String((ctx && ctx.actor) || '');
    campaign.state = move.to;
    campaign.changedAt = at;
    campaign.changedBy = actor;
    if (move.to === 'ended') {
      campaign.endedAt = at;
    }
    campaigns.set(campaign.id, campaign);
    this.deps.audit.audit({
      action: 'admin.post-login-campaign.change', outcome: 'success',
      actor: actor, target: campaign.id,
      channel: String((ctx && ctx.via) || 'console'),
      summary: actor + ' ' + (act === 'end' ? 'ended'
                                            : act + 'd') +
               ' post-login mail campaign ' + campaign.id,
      detail: { act: act, campaign: campaign.id, state: campaign.state,
                realm: String(realms.currentId()) }
    });
    log.debug("Leaving PostLoginCampaigns.move(). " + campaign.state);
    return { ok: true, campaign: campaign };
  }

  /**
   * The console's and the API's one door: `start`, `pause`, `resume` or
   * `end`, named by `body.action`.
   *
   * @param body - the act and its fields (`id` for all but a start)
   * @param ctx - `{ actor, via }`
   * @returns a promise of the act's answer
   */
  async act(body: Json, ctx: Json): Promise<Json> {
    const { log } = this.deps;
    const b = body || {};
    const action = String(b.action || '');
    log.debug("Entering PostLoginCampaigns.act(). " + action);
    const out = action === 'start' ? await this.start(b, ctx)
                                   : this.move(action, String(b.id || ''),
                                               ctx);
    log.debug("Leaving PostLoginCampaigns.act(). ok=" + out.ok);
    return out;
  }

  // ONE SLICE OF A CAMPAIGN'S POPULATION after its cursor: usernames, the
  // next cursor, and whether the population ended there.
  private async sliceOf(campaign: Campaign, cursor: string):
      Promise<{ names: string[]; next: string; done: boolean;
                found: boolean }> {
    const { log } = this.deps;
    log.debug("Entering PostLoginCampaigns.sliceOf().");
    const directory = this.deps.directory();
    if (campaign.group) {
      const answer = await directory.groupMembersAfterAsync(campaign.group,
        cursor, campaign.perRun);
      log.debug("Leaving PostLoginCampaigns.sliceOf(). A group's.");
      return { names: (answer.rows || []).map(function (row: Json): string {
        return String(row.id);
      }), next: String(answer.next || ''), done: answer.done === true,
               found: answer.found === true };
    }
    const names: string[] = [];
    const answer = await directory.passkeyScanAsync({
      attribute: '', after: cursor, readLimit: campaign.perRun,
      wanted: Number.MAX_SAFE_INTEGER,
      accept: function (row: Json): boolean {
        names.push(String(row.id));
        return true;
      }
    });
    log.debug("Leaving PostLoginCampaigns.sliceOf(). The realm's.");
    return { names: names, next: String(answer.next || ''),
             done: answer.done === true || answer.next === cursor,
             found: true };
  }

  /**
   * Whether one person is mailed now, and why not: `due` (mail them),
   * `not-due` (nothing is due, or another activity), `interval` (the last
   * mail is too recent) or `max` (this campaign sent its most).
   *
   * @param campaign - the campaign
   * @param username - the person
   * @returns `{ verdict, due }`
   */
  decide(campaign: Campaign, username: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering PostLoginCampaigns.decide().");
    const postLogin = this.deps.postLogin();
    const due = postLogin.dueFor(username);
    if (!due || due.activity !== campaign.activity) {
      log.debug("Leaving PostLoginCampaigns.decide(). Not due.");
      return { verdict: 'not-due', due: null };
    }
    const state = postLogin.stateOf(username, campaign.activity);
    // Never two mails inside the interval, whichever campaign sent the last.
    const last = Number(state.lastMailedAt) || 0;
    if (last > 0 && now() - last < campaign.intervalDays * DAY_MS) {
      log.debug("Leaving PostLoginCampaigns.decide(). Too soon.");
      return { verdict: 'interval', due: due };
    }
    // The maximum is THIS campaign's: `mails` counts the mails of the
    // campaign the row names.
    const sent = state.campaign === campaign.id ? Number(state.mails) || 0
                                                : 0;
    if (sent >= campaign.maxMails) {
      log.debug("Leaving PostLoginCampaigns.decide(). At the maximum.");
      return { verdict: 'max', due: due };
    }
    log.debug("Leaving PostLoginCampaigns.decide(). Due.");
    return { verdict: 'due', due: due };
  }

  // One campaign's run: a slice of its population, each person decided and
  // mailed or not, the run row written once, one audit row.
  private async runOne(campaign: Campaign, ctx: Json): Promise<Json> {
    const { log, errorCodes, runs, now, realms } = this.deps;
    log.debug("Entering PostLoginCampaigns.runOne(). " + campaign.id);
    const run = this.runOf(campaign.id);
    const counts = { read: 0, mailed: 0, notDue: 0, heldBack: 0,
                     refused: 0 };
    let slice: Json = null;
    try {
      slice = await this.sliceOf(campaign, run.cursor);
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0480') + 'post-login: campaign ' +
                campaign.id + ' in realm "' + realms.currentId() + '" could ' +
                'not read its population: ' + ((e && e.message) || e));
      log.debug("Leaving PostLoginCampaigns.runOne(). No population.");
      return { campaign: campaign.id, error: 'STS-AUTHN-0480' };
    }
    if (!slice.found) {
      log.warn(errorCodes.tag('STS-AUTHN-0480') + 'post-login: campaign ' +
               campaign.id + '\'s group ' + campaign.group + ' is gone; ' +
               'nobody was mailed.');
    }
    const uses = this.deps.mailUses();
    const postLogin = this.deps.postLogin();
    let stopped = false;
    for (const username of slice.names as string[]) {
      if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
        stopped = true;
        break;
      }
      // An administrator's Pause or End takes effect within the slice.
      const fresh = this.get(campaign.id);
      if (!fresh || fresh.state !== 'running') {
        stopped = true;
        break;
      }
      counts.read += 1;
      const decided = this.decide(campaign, username);
      if (decided.verdict === 'not-due') {
        counts.notDue += 1;
        continue;
      }
      if (decided.verdict !== 'due') {
        counts.heldBack += 1;
        continue;
      }
      const before = postLogin.stateOf(username, campaign.activity);
      const sent = uses.postLoginReminder(username, {
        campaign: campaign.id,
        mails: before.campaign === campaign.id ? Number(before.mails) || 0
                                               : 0,
        actor: campaign.startedBy
      });
      if (sent && sent.ok && Array.isArray(sent.queued) &&
          sent.queued.length) {
        postLogin.noteMailed(username, decided.due, campaign.id);
        counts.mailed += 1;
      } else {
        counts.refused += 1;
      }
    }
    // THE CURSOR: past what was read, or back to the start at the end of
    // the population — the next pass is the reminders. A run stopped part
    // way keeps the cursor where it was, so nobody is skipped.
    const atEnd = !stopped && slice.done;
    const next: CampaignRun = {
      cursor: stopped ? run.cursor : (atEnd ? '' : slice.next),
      passes: run.passes + (atEnd ? 1 : 0),
      read: run.read + counts.read, mailed: run.mailed + counts.mailed,
      notDue: run.notDue + counts.notDue,
      heldBack: run.heldBack + counts.heldBack,
      refused: run.refused + counts.refused,
      lastRunAt: now(),
      lastSummary: counts.read + ' read, ' + counts.mailed + ' mailed, ' +
                   counts.notDue + ' not due, ' + counts.heldBack +
                   ' held back, ' + counts.refused + ' refused' +
                   (atEnd ? '; the pass ended' : '') +
                   (stopped ? '; stopped part way' : '')
    };
    runs.set(campaign.id, next);
    if (counts.refused > 0) {
      log.warn(errorCodes.tag('STS-AUTHN-0481') + 'post-login: campaign ' +
               campaign.id + ': the mail channel refused ' + counts.refused +
               ' reminder(s) this run (no address, a declined notification ' +
               'or a ceiling); Monitoring → Mail says which.');
    }
    this.deps.audit.audit({
      action: 'authn.post-login.campaign-run',
      outcome: counts.refused && !counts.mailed ? 'refused' : 'success',
      errorCode: counts.refused ? 'STS-AUTHN-0481' : '',
      actor: 'scheduler', target: campaign.id, channel: 'scheduler',
      summary: 'Post-login mail campaign ' + campaign.id + ': ' +
               next.lastSummary,
      detail: { campaign: campaign.id, activity: campaign.activity,
                read: counts.read, mailed: counts.mailed,
                notDue: counts.notDue, heldBack: counts.heldBack,
                refused: counts.refused, passEnded: atEnd,
                passes: next.passes, run: String((ctx && ctx.runId) || '') }
    });
    log.debug("Leaving PostLoginCampaigns.runOne(). " + next.lastSummary);
    return Object.assign({ campaign: campaign.id }, counts,
                         { passEnded: atEnd, stopped: stopped });
  }

  /**
   * The job's body in the realm it runs for: one slice of every running
   * campaign. Never throws for one campaign's failure.
   *
   * @param ctx - the scheduler's run context
   * @returns a promise of the run's summary
   */
  async runAsync(ctx?: Json): Promise<Json> {
    const { log, errorCodes, realms } = this.deps;
    log.debug("Entering PostLoginCampaigns.runAsync().");
    const running = this.list().filter(function (one: Campaign): boolean {
      return one.state === 'running';
    });
    if (!running.length) {
      log.debug("Leaving PostLoginCampaigns.runAsync(). None running.");
      return { summary: 'No campaign is running in this realm.' };
    }
    let available = false;
    try {
      available = this.deps.mail().available() === true;
    } catch (e) {
      log.debug("Caught in PostLoginCampaigns.runAsync(): " +
                ((e && e.message) || e));
      available = false;
    }
    if (!available) {
      log.warn(errorCodes.tag('STS-AUTHN-0482') + 'post-login: ' +
               running.length + ' campaign(s) running in realm "' +
               realms.currentId() + '" and no mail transport: nobody was ' +
               'mailed, and no cursor moved.');
      log.debug("Leaving PostLoginCampaigns.runAsync(). No transport.");
      return { summary: 'No mail transport in this realm; nobody was ' +
                        'mailed.', errorCode: 'STS-AUTHN-0482' };
    }
    const results: Json[] = [];
    for (const campaign of running) {
      if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
        break;
      }
      try {
        results.push(await this.runOne(campaign, ctx));
      } catch (e) {
        log.error(errorCodes.tag('STS-AUTHN-0480') + 'post-login: campaign ' +
                  campaign.id + ' failed this run: ' +
                  ((e && e.message) || e));
        results.push({ campaign: campaign.id, error: 'STS-AUTHN-0480' });
      }
    }
    const mailed = results.reduce(function (n: number, r: Json): number {
      return n + (Number(r.mailed) || 0);
    }, 0);
    log.debug("Leaving PostLoginCampaigns.runAsync(). " + mailed +
              " mailed.");
    return { summary: results.length + ' campaign(s), ' + mailed +
                      ' mailed.', campaigns: results };
  }

  /**
   * Whether the job has anything to do in a realm: '' when a campaign is
   * running there, else why it is off.
   *
   * @param realmId - the realm
   * @returns '' or the reason
   */
  offIn(realmId: string): string {
    const { log, campaigns } = this.deps;
    log.debug("Entering PostLoginCampaigns.offIn().");
    let any = false;
    const held = typeof campaigns.realmMap === 'function'
      ? campaigns.realmMap(realmId) : null;
    (held || campaigns).forEach(function (value: any): void {
      if (value && value.state === 'running') {
        any = true;
      }
    });
    log.debug("Leaving PostLoginCampaigns.offIn(). " + any);
    return any ? '' : 'No post-login mail campaign is running in this realm.';
  }

  /**
   * Registers the job with the scheduler, once per process.
   *
   * @returns true when registered, false when it already was
   */
  registerJobs(): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginCampaigns.registerJobs().");
    const s = this.deps.scheduler();
    if (s.job(JOB)) {
      log.debug("Leaving PostLoginCampaigns.registerJobs(). Already there.");
      return false;
    }
    const self = this;
    s.register({
      id: JOB,
      title: 'Post-login mail campaigns',
      describe: 'Mails the people a running post-login mail campaign ' +
                'reaches (#1111) a reminder to sign in, where the ' +
                'post-login activity then asks them to register a ' +
                'post-quantum passkey. Reads one slice of each campaign\'s ' +
                'population after a cursor per run, mails only the people ' +
                'the activity is due for, never inside the reminder ' +
                'interval or past the campaign\'s maximum, and writes one ' +
                'audit row per campaign per run.',
      owner: 'common/post_login_campaigns.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return EVERY_MS;
      },
      off: function (realmId: string): string {
        return self.offIn(realmId);
      },
      manual: true,
      timeoutS: 900,
      run: function (ctx: Json): Promise<Json> {
        return self.runAsync(ctx);
      }
    });
    log.debug("Leaving PostLoginCampaigns.registerJobs().");
    return true;
  }

  /**
   * Forgets every campaign of the ambient realm and what its runs did. For
   * a test.
   */
  resetForTests(): void {
    const { log, campaigns, runs } = this.deps;
    log.debug("Entering PostLoginCampaigns.resetForTests().");
    const ids: string[] = [];
    campaigns.forEach(function (value: any, key: string): void {
      ids.push(key);
    });
    ids.forEach(function (id: string): void {
      campaigns.delete(id);
      runs.delete(id);
    });
    log.debug("Leaving PostLoginCampaigns.resetForTests().");
  }
}

const slot = new InstanceSlot<PostLoginCampaigns>(
  'common/post_login_campaigns',
  () => new PostLoginCampaigns(PostLoginCampaigns.defaultDeps()),
  function (instance: PostLoginCampaigns): void {
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

/**
 * Mail campaigns for a post-login activity (#1111). The exports forward to
 * the instance the composition root installs.
 *
 * @namespace
 */
export = {
  PostLoginCampaigns: PostLoginCampaigns,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: PostLoginCampaigns): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  JOB: JOB,
  ACTIVITIES: ACTIVITIES,
  LIMITS: LIMITS,
  STATES: STATES,
  ACTS: PostLoginCampaigns.ACTS,
  list: slot.forward('list'),
  get: slot.forward('get'),
  view: slot.forward('view'),
  start: slot.forward('start'),
  move: slot.forward('move'),
  act: slot.forward('act'),
  decide: slot.forward('decide'),
  runAsync: slot.forward('runAsync'),
  offIn: slot.forward('offIn'),
  registerJobs: slot.forward('registerJobs'),
  resetForTests: slot.forward('resetForTests')
};
