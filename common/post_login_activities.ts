// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_activities.ts
//
// ---------------------------------------------------------------------------
// STARTED POST-LOGIN ACTIVITIES: THE MAIL THAT BRINGS PEOPLE TO ONE (#1111,
// 2026-10-28; one concept since #1123).
//
// A post-login activity (#1096) reaches a person only when they sign in, so
// somebody who rarely signs in is never asked to register an ML-DSA passkey
// before a deadline. rcbj's decisions on #1111:
//
//   * AN ADMINISTRATOR STARTS A POST-LOGIN ACTIVITY in a realm — optionally
//     narrowed to groups — from the console and from `/admin-api` (rule 7:
//     `mgmt-api/post_login_activities_api.ts`, drawn by
//     `admin-ui/web_post_login_activities.ts`): the reminder interval in
//     days, the most mails one person is sent, and how many people one run
//     reads. It can be paused, resumed and ended.
//   * A CLUSTER SCHEDULER JOB (`post-login.activity-mail`) walks the started
//     activity's population after a KEY CURSOR, a bounded slice per run —
//     the realm's people through `ldap_server.js`'s `passkeyScanAsync()`,
//     its groups' members through `groupMembersAfterAsync()` — and mails
//     each person the activity is due for (`post_login.dueFor()`, which
//     already says nobody who has done it and nobody the realm cannot ask,
//     `canRegister()`). No second mail inside the interval, none past the
//     maximum. At the end of the population the cursor starts again: the
//     next pass is the reminders.
//   * THE MAIL SENDS THE PERSON TO SIGN IN, and the post-login activity does
//     the registration. The one link is the portal's own path on this
//     service's pinned origin (`common/mail.ts`, point 6); it carries no
//     token, no code and nothing about the person. The address is the one on
//     the person's entry (`mail_uses.ts`'s `postLoginReminder()`), never one a
//     request names.
//   * Progress per person — which started activity mailed them, how many
//     mails, the first and the last — is written on the person's progress
//     row (`post_login.noteMailed()`, its `mailedBy`), and the reports
//     application reads it as the `postLoginProgress` source (#1110).
//     Nothing here draws a report.
//
// ONE CONCEPT (#1123, rcbj): what the page starts IS a post-login activity.
// The post-login activity policy kind on Directory → Policies
// (`post_login_policy.ts`) stays what it was — the rules a started activity
// follows: who it reaches, the allotted time, the role. Where the two must
// be told apart in prose, this one is the STARTED activity and its record is
// a `StartedActivity`; its `activity` field names which activity (today
// `pqc-passkey-migration`).
//
// GROUPS, SEVERAL, CHOSEN BY SEARCH (#1123). A started activity names a list
// of groups (`groups`, their DNs, at most `MAX_GROUPS`), and its population
// is their UNION: `groupMembersAfterAsync()` puts every member key of every
// group into one sorted set and walks it with one cursor, so a person in two
// groups is read once and mailed once. No group is the whole realm. The
// console's chooser asks `groupChoices()` (the group index, never the
// directory's entries) for a page of twenty — `chooserPane()`'s `slice`, cut
// here by `view()` from the page's own query: `groupq` (the search),
// `groupfrom` (the offset, clamped) and `groups` (the list being built, its
// groups left out of the results). THE LIST IS ONE PARAMETER, ITS NAMES
// SEPARATED BY `;`: a DN's commas would split a comma list, the console's
// `pageParamsOf()` keeps only the first of a repeated parameter, and a query
// value may hold no control character (`common/validation.js`), so a line
// break is refused at the gate. RFC 4514 escapes a `;` inside a DN value
// (`\;`), so an unescaped one is never part of a DN.
//
// TWO STORES, AND WHY TWO. `post_login.activities` holds what an
// administrator decided — the activity, the groups, the numbers, the state —
// and is written only by the console and the API. `post_login.activityRuns`
// holds what the job did — the cursor, the passes, the counts — and is
// written only by the job. A job runs on a request worker (#408) while an
// administrator's Pause is answered by whichever process served it; with one
// row each would write back the other's stale half. Both are cell-tier: the
// cursor is a person's DN and a started activity names the administrator
// who started it. Neither is on demand: a realm runs a handful of them. The
// stores were renamed by #1123 with no migration (no released data held a
// row of either).
//
// AUDIT: one row per start, pause, resume and end, and ONE ROW PER STARTED
// ACTIVITY PER RUN summarising it (how many read, mailed, not due, held
// back, refused) — never a row per person, which a population of a million
// would turn into a million rows a pass.
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

/** The scheduler job that mails a running started activity's population. */
const JOB = 'post-login.activity-mail';
/** How often it runs, in every realm with a started activity running. */
const EVERY_MS = 10 * 60 * 1000;

// The activities an administrator may start: the post-login activities
// there are (`post_login.ts`), one today.
const ACTIVITIES = ['pqc-passkey-migration'];

// The numbers a started activity is given, and their bounds.
const LIMITS = {
  intervalDays: { min: 1, max: 365, dflt: 7 },
  maxMails: { min: 1, max: 20, dflt: 3 },
  perRun: { min: 1, max: 20000, dflt: 1000 }
};

// The most groups one started activity names. A bound on what one start
// resolves and what one run unions, not a design limit anybody has met.
const MAX_GROUPS = 50;

// The group chooser's page: `WebKit.CHOOSER_HITS`, which the console's
// `chooserPane()` draws twenty of at a time. Written here because this
// library is not bundled with the console and cannot require it.
const CHOOSER_HITS = 20;

// The states, and which act moves a started activity from which.
const STATES = ['running', 'paused', 'ended'];
const MOVES: Record<string, { from: string[]; to: string }> = {
  pause: { from: ['running'], to: 'paused' },
  resume: { from: ['paused'], to: 'running' },
  end: { from: ['running', 'paused'], to: 'ended' }
};

// Every started activity a realm keeps, ended ones included, at most: past
// it the oldest ENDED one is forgotten when another is started.
const KEEP = 50;

// THE STORES — see the header. Declared here, per realm, and nowhere else.
const startedStore = realms.map({ persist: 'post_login.activities' });
const runStore = realms.map({ persist: 'post_login.activityRuns' });

interface StartedActivity {
  id: string;
  activity: string;
  groups: string[];
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

interface ActivityRun {
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

interface ActivityDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  audit: { audit(event: Json): unknown };
  realms: Json;
  started: Store;
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
 * Started post-login activities (#1111, #1123): started, paused, resumed
 * and ended by an administrator; their reminders mailed by a cluster
 * scheduler job.
 */
class PostLoginActivities {
  /** The scheduler job that mails a running started activity's people. */
  static readonly JOB = JOB;
  /** The activities an administrator may start. */
  static readonly ACTIVITIES = ACTIVITIES;
  /** The bounds of a started activity's numbers. */
  static readonly LIMITS = LIMITS;
  /** The most groups one started activity names. */
  static readonly MAX_GROUPS = MAX_GROUPS;
  /** The group chooser's page size. */
  static readonly CHOOSER_HITS = CHOOSER_HITS;
  /** The states a started activity is in. */
  static readonly STATES = STATES;
  /** The acts after a start. */
  static readonly ACTS = Object.keys(MOVES);

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, the stores, lazy readers of the directory,
   *   the post-login module, the mail uses and the scheduler, and a clock
   */
  constructor(private readonly deps: ActivityDeps) {
    deps.log.debug("Entering PostLoginActivities.constructor().");
    deps.log.debug("Leaving PostLoginActivities.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules
   */
  static defaultDeps(): ActivityDeps {
    log.debug("Entering PostLoginActivities.defaultDeps().");
    log.debug("Leaving PostLoginActivities.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      audit: audit,
      realms: realms,
      started: startedStore as unknown as Store,
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

  /**
   * The group names a request carries, as a list: an array, or strings
   * holding several separated by `;` (the console's `groups` query
   * parameter — see the header), each trimmed, the empty ones dropped. A
   * `;` escaped with a backslash, as RFC 4514 writes one inside a DN value,
   * does not separate.
   *
   * @param given - what the request carried
   * @returns the names
   */
  static groupNamesOf(given: any): string[] {
    log.debug("Entering PostLoginActivities.groupNamesOf().");
    const out: string[] = [];
    const keep = function (name: string): void {
      const trimmed = name.trim();
      if (trimmed) {
        out.push(trimmed);
      }
    };
    ([] as any[]).concat(given === undefined || given === null ? []
                                                               : given)
      .forEach(function (one: any): void {
        const text = String(one == null ? '' : one);
        let name = '';
        for (let i = 0; i < text.length; i++) {
          const c = text.charAt(i);
          if (c === '\\' && i + 1 < text.length) {
            name += c + text.charAt(i + 1);
            i += 1;
          } else if (c === ';') {
            keep(name);
            name = '';
          } else {
            name += c;
          }
        }
        keep(name);
      });
    log.debug("Leaving PostLoginActivities.groupNamesOf(). " + out.length);
    return out;
  }

  // A started activity's row as the store holds it, with every field it
  // should have.
  private startedOf(value: any): StartedActivity | null {
    const { log } = this.deps;
    log.debug("Entering PostLoginActivities.startedOf().");
    if (!value || typeof value !== 'object' || !value.id) {
      log.debug("Leaving PostLoginActivities.startedOf(). None.");
      return null;
    }
    const out: StartedActivity = {
      id: String(value.id), activity: String(value.activity || ''),
      groups: Array.isArray(value.groups)
        ? value.groups.map(function (one: any): string {
          return String(one);
        }) : [],
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
    log.debug("Leaving PostLoginActivities.startedOf().");
    return out;
  }

  private runOf(id: string): ActivityRun {
    const { log, runs } = this.deps;
    log.debug("Entering PostLoginActivities.runOf().");
    const held = runs.get(id) || {};
    const out: ActivityRun = {
      cursor: String(held.cursor || ''), passes: Number(held.passes) || 0,
      read: Number(held.read) || 0, mailed: Number(held.mailed) || 0,
      notDue: Number(held.notDue) || 0, heldBack: Number(held.heldBack) || 0,
      refused: Number(held.refused) || 0,
      lastRunAt: Number(held.lastRunAt) || 0,
      lastSummary: String(held.lastSummary || '')
    };
    log.debug("Leaving PostLoginActivities.runOf().");
    return out;
  }

  /**
   * Every started activity of the ambient realm, newest first.
   *
   * @returns the started activities
   */
  list(): StartedActivity[] {
    const { log, started } = this.deps;
    log.debug("Entering PostLoginActivities.list().");
    const out: StartedActivity[] = [];
    const self = this;
    started.forEach(function (value: any): void {
      const one = self.startedOf(value);
      if (one) {
        out.push(one);
      }
    });
    out.sort(function (a, b) {
      return b.startedAt - a.startedAt || (a.id < b.id ? -1 : 1);
    });
    log.debug("Leaving PostLoginActivities.list(). " + out.length);
    return out;
  }

  /**
   * The RUNNING started activities of the ambient realm for one activity,
   * oldest first (#1126): what `post_login.dueFor()` asks at every sign-in,
   * since a running started activity turns the sign-in invitation on for
   * its population. Each is `{ id, groups }`, its group DNs lower-cased for
   * comparing with the person's.
   *
   * THE COST IS AN IN-MEMORY READ, AND NO CACHE IS KEPT. `started` is a
   * persisted `realms.map()` that is NOT on demand: every process holds the
   * realm's rows whole and the change log brings another process's writes
   * (a Pause answered elsewhere) within its convergence, as the job's own
   * `get()` before each person already relies on. A realm keeps at most
   * `KEEP` (fifty) rows, ended ones included, so this is a walk of at most
   * fifty objects already in this process — a cache over it would be a
   * second copy to keep in step for nothing.
   *
   * @param activity - the activity, e.g. `pqc-passkey-migration`
   * @returns the running ones, oldest first
   */
  runningOf(activity: string): { id: string; groups: string[];
                                 startedAt: number }[] {
    const { log, started } = this.deps;
    log.debug("Entering PostLoginActivities.runningOf().");
    const out: { id: string; groups: string[]; startedAt: number }[] = [];
    started.forEach(function (value: any): void {
      if (!value || value.state !== 'running' || !value.id ||
          String(value.activity || '') !== String(activity || '')) {
        return;
      }
      out.push({
        id: String(value.id),
        groups: (Array.isArray(value.groups) ? value.groups : [])
          .map(function (one: any): string {
            return String(one).toLowerCase();
          }),
        startedAt: Number(value.startedAt) || 0
      });
    });
    out.sort(function (a, b) {
      return a.startedAt - b.startedAt || (a.id < b.id ? -1 : 1);
    });
    log.debug("Leaving PostLoginActivities.runningOf(). " + out.length);
    return out;
  }

  /**
   * One started activity of the ambient realm.
   *
   * @param id - its id
   * @returns the started activity, or null
   */
  get(id: string): StartedActivity | null {
    const { log, started } = this.deps;
    log.debug("Entering PostLoginActivities.get().");
    const out = this.startedOf(started.get(String(id || '')));
    log.debug("Leaving PostLoginActivities.get(). " + (out ? 'Found.'
                                                          : 'None.'));
    return out;
  }

  /**
   * The start form's group chooser (#1123), from the page's query: the
   * groups chosen so far (`groups`, resolved — a name the realm does not
   * have comes back `found: false`, for the page to offer its removal) and
   * one page of the search (`groupq`, from `groupfrom`, `CHOOSER_HITS` at a
   * time, the chosen ones left out), cut here because the console's
   * `chooserPane()` takes a `slice` for a catalogue too big to send whole.
   *
   * @param query - the page's query, or none
   * @returns `{ search, chosen, pane: { total, matched, from, shown } }`
   */
  groupChooser(query?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering PostLoginActivities.groupChooser().");
    const q = query || {};
    const one = function (name: string): string {
      const raw = q[name];
      const value = Array.isArray(raw) ? raw[0] : raw;
      return value === undefined || value === null ? '' : String(value);
    };
    const search = one('groupq').trim();
    const names = PostLoginActivities.groupNamesOf(q.groups)
      .slice(0, MAX_GROUPS);
    const out: Json = { search: search, chosen: [],
                        pane: { total: 0, matched: 0, from: 0, shown: [] } };
    let directory: Json = null;
    try {
      directory = this.deps.directory();
    } catch (e) {
      // No directory in this process: no group to offer, and the page says
      // nothing matched.
      log.debug("Caught in PostLoginActivities.groupChooser(): " +
                ((e && e.message) || e));
      directory = null;
    }
    if (!directory || typeof directory.groupChoices !== 'function') {
      log.debug("Leaving PostLoginActivities.groupChooser(). No directory.");
      return out;
    }
    out.chosen = directory.groupsNamed(names);
    const found = directory.groupChoices(search, one('groupfrom'),
      CHOOSER_HITS, out.chosen.map(function (g: Json): string {
        return String(g.dn);
      }));
    out.pane = { total: found.total, matched: found.matched,
                 from: found.from, shown: found.rows };
    log.debug("Leaving PostLoginActivities.groupChooser(). " +
              out.pane.shown.length + " shown, " + out.chosen.length +
              " chosen.");
    return out;
  }

  /**
   * What the console page and `GET /admin-api/post-login-activities` draw:
   * every started activity with what its runs did, the activities, the
   * bounds, whether anything can be sent, and the start form's group
   * chooser for the query given.
   *
   * @param query - optional; the page's query (`groupq`, `groupfrom`,
   *   `groups`)
   * @returns the view
   */
  view(query?: Json): Json {
    const { log, realms } = this.deps;
    log.debug("Entering PostLoginActivities.view().");
    const self = this;
    let mailOn = false;
    let activityOn = false;
    try {
      mailOn = this.deps.mail().available() === true;
    } catch (e) {
      // A channel that cannot be asked sends nothing; the page says so.
      log.debug("Caught in PostLoginActivities.view(): " +
                ((e && e.message) || e));
      mailOn = false;
    }
    try {
      activityOn = require('./post_login_policy').anyEnabled() === true;
    } catch (e) {
      // A policy that cannot be read asks nobody; the page says so.
      log.debug("Caught in PostLoginActivities.view(): " +
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
      limits: Object.assign(JSON.parse(JSON.stringify(LIMITS)),
                            { groups: { max: MAX_GROUPS } }),
      mailAvailable: mailOn,
      activityEnabled: activityOn,
      groupChooser: this.groupChooser(query),
      started: this.list().map(function (one: StartedActivity): Json {
        const run = self.runOf(one.id);
        return Object.assign({}, one, {
          startedAt: iso(one.startedAt), changedAt: iso(one.changedAt),
          endedAt: iso(one.endedAt),
          run: Object.assign({}, run, { lastRunAt: iso(run.lastRunAt),
                                        cursor: run.cursor ? 'held' : '' })
        });
      })
    };
    log.debug("Leaving PostLoginActivities.view(). " + out.started.length);
    return out;
  }

  // A whole number between the bounds, or the default when absent; null
  // when given and out of bounds or not a number.
  private numberOf(given: any, bound: { min: number; max: number;
                                        dflt: number }): number | null {
    const { log } = this.deps;
    log.debug("Entering PostLoginActivities.numberOf().");
    if (given === undefined || given === null || given === '') {
      log.debug("Leaving PostLoginActivities.numberOf(). Default.");
      return bound.dflt;
    }
    const n = Number(given);
    const out = Number.isInteger(n) && n >= bound.min && n <= bound.max
      ? n : null;
    log.debug("Leaving PostLoginActivities.numberOf(). " + out);
    return out;
  }

  private refused(code: string, errors: string[]): Json {
    const { log } = this.deps;
    log.debug("Entering PostLoginActivities.refused(). " + code);
    log.debug("Leaving PostLoginActivities.refused().");
    return { ok: false, errorCode: code, errors: errors };
  }

  // The same people, as a duplicate start is judged: the same set of group
  // DNs, compared as LDAP compares a DN (case and the spaces after a comma
  // do not matter), or both the whole realm.
  private static sameGroups(a: string[], b: string[]): boolean {
    log.debug("Entering PostLoginActivities.sameGroups().");
    const key = function (list: string[]): string {
      return list.map(function (one: string): string {
        return one.toLowerCase().replace(/\s*,\s*/g, ',');
      }).sort().join('\n');
    };
    const out = key(a) === key(b);
    log.debug("Leaving PostLoginActivities.sameGroups(). " + out);
    return out;
  }

  /**
   * Starts a post-login activity in the ambient realm.
   *
   * @param body - `activity`, `groups` (optional: groups' cns or DNs, a list
   *   or `;`-separated; none for everybody in the realm), `intervalDays`,
   *   `maxMails`, `perRun`
   * @param ctx - `{ actor, via }`: who started it, and through which door
   * @returns `{ ok, started }`, or `{ ok: false, errorCode, errors }`
   */
  async start(body: Json, ctx: Json): Promise<Json> {
    const { log, started, runs, randomId, now, realms } = this.deps;
    log.debug("Entering PostLoginActivities.start().");
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
    const names = PostLoginActivities.groupNamesOf(b.groups);
    if (names.length > MAX_GROUPS) {
      errors.push('groups names at most ' + MAX_GROUPS + ' groups.');
    }
    if (errors.length) {
      log.debug("Leaving PostLoginActivities.start(). Refused.");
      return this.refused('STS-AUTHN-0490', errors);
    }
    // EACH GROUP RESOLVED TO ITS DN, and a name the realm does not have
    // refused by name (STS-AUTHN-0530): a started activity that silently
    // dropped one of its groups would mail fewer people than the
    // administrator chose.
    let groups: string[] = [];
    if (names.length) {
      let resolved: Json[] = [];
      try {
        resolved = this.deps.directory().groupsNamed(names);
      } catch (e) {
        // No directory to ask: every name is one this realm does not have.
        log.debug("Caught in PostLoginActivities.start(): " +
                  ((e && e.message) || e));
        resolved = names.map(function (name: string): Json {
          return { asked: name, dn: name, found: false };
        });
      }
      const missing = resolved.filter(function (one: Json): boolean {
        return !one.found;
      });
      if (missing.length) {
        log.debug("Leaving PostLoginActivities.start(). No such group.");
        return this.refused('STS-AUTHN-0530', missing.map(
          function (one: Json): string {
            return 'There is no group "' + String(one.asked) +
                   '" in this realm.';
          }));
      }
      groups = resolved.map(function (one: Json): string {
        return String(one.dn);
      });
    }
    const same = this.list().filter(function (one: StartedActivity):
        boolean {
      return one.state !== 'ended' && one.activity === activity &&
             PostLoginActivities.sameGroups(one.groups, groups);
    })[0];
    if (same) {
      log.debug("Leaving PostLoginActivities.start(). One is running.");
      return this.refused('STS-AUTHN-0492', [
        'Post-login activity ' + same.id + ' is already ' + same.state +
        ' for ' + activity + (groups.length ? ' in ' + groups.join('; ')
                                            : ' across the realm') +
        '. End it before starting another for the same people.']);
    }
    // THE BOUND ON WHAT IS KEPT: the oldest ended ones go first.
    const ended = this.list().filter(function (one: StartedActivity):
        boolean {
      return one.state === 'ended';
    });
    while (ended.length && this.list().length >= KEEP) {
      const old = ended.pop() as StartedActivity;
      started.delete(old.id);
      runs.delete(old.id);
    }
    const at = now();
    const actor = String((ctx && ctx.actor) || '');
    const record: StartedActivity = {
      id: 'pla-' + randomId(), activity: activity, groups: groups,
      intervalDays: numbers.intervalDays, maxMails: numbers.maxMails,
      perRun: numbers.perRun, state: 'running', startedAt: at,
      startedBy: actor, changedAt: at, changedBy: actor, endedAt: 0
    };
    started.set(record.id, record);
    this.deps.audit.audit({
      action: 'admin.post-login-activity.change', outcome: 'success',
      actor: actor, target: record.id,
      channel: String((ctx && ctx.via) || 'console'),
      summary: actor + ' started post-login activity ' + record.id +
               ' (' + activity + ')' +
               (groups.length ? ' in ' + groups.length + ' group(s)'
                              : ' across the realm'),
      detail: { act: 'start', started: record.id, activity: activity,
                groups: groups, intervalDays: record.intervalDays,
                maxMails: record.maxMails, perRun: record.perRun,
                realm: String(realms.currentId()) }
    });
    log.info('post-login: activity ' + record.id + ' started in realm "' +
             realms.currentId() + '" by ' + (actor || 'nobody named') + '.');
    log.debug("Leaving PostLoginActivities.start().");
    return { ok: true, started: record };
  }

  /**
   * Pauses, resumes or ends a started activity of the ambient realm.
   *
   * @param act - `pause`, `resume` or `end`
   * @param id - the started activity
   * @param ctx - `{ actor, via }`
   * @returns `{ ok, started }`, or `{ ok: false, errorCode, errors }`
   */
  move(act: string, id: string, ctx: Json): Json {
    const { log, started, now, realms } = this.deps;
    log.debug("Entering PostLoginActivities.move(). " + act);
    const move = MOVES[String(act || '')];
    if (!move) {
      log.debug("Leaving PostLoginActivities.move(). Unknown act.");
      return this.refused('STS-AUTHN-0491', ['Unknown action "' +
        String(act || '') + '". The actions are: start, ' +
        Object.keys(MOVES).join(', ') + '.']);
    }
    const record = this.get(id);
    if (!record) {
      log.debug("Leaving PostLoginActivities.move(). None.");
      return this.refused('STS-AUTHN-0491', ['There is no started ' +
        'post-login activity "' + String(id || '') + '" in this realm.']);
    }
    if (move.from.indexOf(record.state) < 0) {
      log.debug("Leaving PostLoginActivities.move(). Wrong state.");
      return this.refused('STS-AUTHN-0491', ['Post-login activity ' +
        record.id + ' is ' + record.state + '; ' + act + ' needs one ' +
        'that is ' + move.from.join(' or ') + '.']);
    }
    const at = now();
    const actor = String((ctx && ctx.actor) || '');
    record.state = move.to;
    record.changedAt = at;
    record.changedBy = actor;
    if (move.to === 'ended') {
      record.endedAt = at;
    }
    started.set(record.id, record);
    this.deps.audit.audit({
      action: 'admin.post-login-activity.change', outcome: 'success',
      actor: actor, target: record.id,
      channel: String((ctx && ctx.via) || 'console'),
      summary: actor + ' ' + (act === 'end' ? 'ended'
                                            : act + 'd') +
               ' post-login activity ' + record.id,
      detail: { act: act, started: record.id, state: record.state,
                realm: String(realms.currentId()) }
    });
    log.debug("Leaving PostLoginActivities.move(). " + record.state);
    return { ok: true, started: record };
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
    log.debug("Entering PostLoginActivities.act(). " + action);
    const out = action === 'start' ? await this.start(b, ctx)
                                   : this.move(action, String(b.id || ''),
                                               ctx);
    log.debug("Leaving PostLoginActivities.act(). ok=" + out.ok);
    return out;
  }

  // ONE SLICE OF A STARTED ACTIVITY'S POPULATION after its cursor:
  // usernames, the next cursor, whether the population ended there, and
  // which of its groups are gone.
  private async sliceOf(record: StartedActivity, cursor: string):
      Promise<{ names: string[]; next: string; done: boolean;
                found: boolean; missing: string[] }> {
    const { log } = this.deps;
    log.debug("Entering PostLoginActivities.sliceOf().");
    const directory = this.deps.directory();
    if (record.groups.length) {
      // THE UNION: one sorted set of every group's member keys, one cursor.
      const answer = await directory.groupMembersAfterAsync(record.groups,
        cursor, record.perRun);
      const missing = (answer.groups || []).filter(function (g: Json):
          boolean {
        return !g.found;
      }).map(function (g: Json): string {
        return String(g.dn || g.asked);
      });
      log.debug("Leaving PostLoginActivities.sliceOf(). Its groups'.");
      return { names: (answer.rows || []).map(function (row: Json): string {
        return String(row.id);
      }), next: String(answer.next || ''), done: answer.done === true,
               found: answer.found === true, missing: missing };
    }
    const names: string[] = [];
    const answer = await directory.passkeyScanAsync({
      attribute: '', after: cursor, readLimit: record.perRun,
      wanted: Number.MAX_SAFE_INTEGER,
      accept: function (row: Json): boolean {
        names.push(String(row.id));
        return true;
      }
    });
    log.debug("Leaving PostLoginActivities.sliceOf(). The realm's.");
    return { names: names, next: String(answer.next || ''),
             done: answer.done === true || answer.next === cursor,
             found: true, missing: [] };
  }

  /**
   * Whether one person is mailed now, and why not: `due` (mail them),
   * `not-due` (nothing is due, or another activity), `interval` (the last
   * mail is too recent) or `max` (this started activity sent its most).
   *
   * @param record - the started activity
   * @param username - the person
   * @returns `{ verdict, due }`
   */
  decide(record: StartedActivity, username: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering PostLoginActivities.decide().");
    const postLogin = this.deps.postLogin();
    const due = postLogin.dueFor(username);
    if (!due || due.activity !== record.activity) {
      log.debug("Leaving PostLoginActivities.decide(). Not due.");
      return { verdict: 'not-due', due: null };
    }
    const state = postLogin.stateOf(username, record.activity);
    // Never two mails inside the interval, whichever started activity sent
    // the last.
    const last = Number(state.lastMailedAt) || 0;
    if (last > 0 && now() - last < record.intervalDays * DAY_MS) {
      log.debug("Leaving PostLoginActivities.decide(). Too soon.");
      return { verdict: 'interval', due: due };
    }
    // The maximum is THIS started activity's: `mails` counts the mails of
    // the one the row's `mailedBy` names.
    const sent = state.mailedBy === record.id ? Number(state.mails) || 0
                                              : 0;
    if (sent >= record.maxMails) {
      log.debug("Leaving PostLoginActivities.decide(). At the maximum.");
      return { verdict: 'max', due: due };
    }
    log.debug("Leaving PostLoginActivities.decide(). Due.");
    return { verdict: 'due', due: due };
  }

  // One started activity's run: a slice of its population, each person
  // decided and mailed or not, the run row written once, one audit row.
  private async runOne(record: StartedActivity, ctx: Json): Promise<Json> {
    const { log, errorCodes, runs, now, realms } = this.deps;
    log.debug("Entering PostLoginActivities.runOne(). " + record.id);
    const run = this.runOf(record.id);
    const counts = { read: 0, mailed: 0, notDue: 0, heldBack: 0,
                     refused: 0 };
    let slice: Json = null;
    try {
      slice = await this.sliceOf(record, run.cursor);
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0493') + 'post-login: activity ' +
                record.id + ' in realm "' + realms.currentId() + '" could ' +
                'not read its population: ' + ((e && e.message) || e));
      log.debug("Leaving PostLoginActivities.runOne(). No population.");
      return { started: record.id, error: 'STS-AUTHN-0493' };
    }
    if (slice.missing.length) {
      log.warn(errorCodes.tag('STS-AUTHN-0493') + 'post-login: activity ' +
               record.id + '\'s group(s) ' + slice.missing.join('; ') +
               (slice.found ? ' are gone; their members are not read.'
                            : ' are gone; nobody was mailed.'));
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
      const fresh = this.get(record.id);
      if (!fresh || fresh.state !== 'running') {
        stopped = true;
        break;
      }
      counts.read += 1;
      const decided = this.decide(record, username);
      if (decided.verdict === 'not-due') {
        counts.notDue += 1;
        continue;
      }
      if (decided.verdict !== 'due') {
        counts.heldBack += 1;
        continue;
      }
      const before = postLogin.stateOf(username, record.activity);
      const sent = uses.postLoginReminder(username, {
        started: record.id,
        mails: before.mailedBy === record.id ? Number(before.mails) || 0
                                             : 0,
        actor: record.startedBy
      });
      if (sent && sent.ok && Array.isArray(sent.queued) &&
          sent.queued.length) {
        postLogin.noteMailed(username, decided.due, record.id);
        counts.mailed += 1;
      } else {
        counts.refused += 1;
      }
    }
    // THE CURSOR: past what was read, or back to the start at the end of
    // the population — the next pass is the reminders. A run stopped part
    // way keeps the cursor where it was, so nobody is skipped.
    const atEnd = !stopped && slice.done;
    const next: ActivityRun = {
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
    runs.set(record.id, next);
    if (counts.refused > 0) {
      log.warn(errorCodes.tag('STS-AUTHN-0494') + 'post-login: activity ' +
               record.id + ': the mail channel refused ' + counts.refused +
               ' reminder(s) this run (no address, a declined notification ' +
               'or a ceiling); Monitoring → Mail says which.');
    }
    this.deps.audit.audit({
      action: 'authn.post-login.activity-run',
      outcome: counts.refused && !counts.mailed ? 'refused' : 'success',
      errorCode: counts.refused ? 'STS-AUTHN-0494' : '',
      actor: 'scheduler', target: record.id, channel: 'scheduler',
      summary: 'Post-login activity ' + record.id + ': ' +
               next.lastSummary,
      detail: { started: record.id, activity: record.activity,
                read: counts.read, mailed: counts.mailed,
                notDue: counts.notDue, heldBack: counts.heldBack,
                refused: counts.refused, passEnded: atEnd,
                passes: next.passes, run: String((ctx && ctx.runId) || '') }
    });
    log.debug("Leaving PostLoginActivities.runOne(). " + next.lastSummary);
    return Object.assign({ started: record.id }, counts,
                         { passEnded: atEnd, stopped: stopped });
  }

  /**
   * The job's body in the realm it runs for: one slice of every running
   * started activity. Never throws for one's failure.
   *
   * @param ctx - the scheduler's run context
   * @returns a promise of the run's summary
   */
  async runAsync(ctx?: Json): Promise<Json> {
    const { log, errorCodes, realms } = this.deps;
    log.debug("Entering PostLoginActivities.runAsync().");
    const running = this.list().filter(function (one: StartedActivity):
        boolean {
      return one.state === 'running';
    });
    if (!running.length) {
      log.debug("Leaving PostLoginActivities.runAsync(). None running.");
      return { summary: 'No post-login activity is running in this realm.' };
    }
    let available = false;
    try {
      available = this.deps.mail().available() === true;
    } catch (e) {
      log.debug("Caught in PostLoginActivities.runAsync(): " +
                ((e && e.message) || e));
      available = false;
    }
    if (!available) {
      log.warn(errorCodes.tag('STS-AUTHN-0495') + 'post-login: ' +
               running.length + ' activity(ies) running in realm "' +
               realms.currentId() + '" and no mail transport: nobody was ' +
               'mailed, and no cursor moved.');
      log.debug("Leaving PostLoginActivities.runAsync(). No transport.");
      return { summary: 'No mail transport in this realm; nobody was ' +
                        'mailed.', errorCode: 'STS-AUTHN-0495' };
    }
    const results: Json[] = [];
    for (const record of running) {
      if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
        break;
      }
      try {
        results.push(await this.runOne(record, ctx));
      } catch (e) {
        log.error(errorCodes.tag('STS-AUTHN-0493') + 'post-login: activity ' +
                  record.id + ' failed this run: ' +
                  ((e && e.message) || e));
        results.push({ started: record.id, error: 'STS-AUTHN-0493' });
      }
    }
    const mailed = results.reduce(function (n: number, r: Json): number {
      return n + (Number(r.mailed) || 0);
    }, 0);
    log.debug("Leaving PostLoginActivities.runAsync(). " + mailed +
              " mailed.");
    return { summary: results.length + ' activity(ies), ' + mailed +
                      ' mailed.', started: results };
  }

  /**
   * Whether the job has anything to do in a realm: '' when a started
   * activity is running there, else why it is off.
   *
   * @param realmId - the realm
   * @returns '' or the reason
   */
  offIn(realmId: string): string {
    const { log, started } = this.deps;
    log.debug("Entering PostLoginActivities.offIn().");
    let any = false;
    const held = typeof started.realmMap === 'function'
      ? started.realmMap(realmId) : null;
    (held || started).forEach(function (value: any): void {
      if (value && value.state === 'running') {
        any = true;
      }
    });
    log.debug("Leaving PostLoginActivities.offIn(). " + any);
    return any ? '' : 'No post-login activity is running in this realm.';
  }

  /**
   * Registers the job with the scheduler, once per process.
   *
   * @returns true when registered, false when it already was
   */
  registerJobs(): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginActivities.registerJobs().");
    const s = this.deps.scheduler();
    if (s.job(JOB)) {
      log.debug("Leaving PostLoginActivities.registerJobs(). Already there.");
      return false;
    }
    const self = this;
    s.register({
      id: JOB,
      title: 'Post-login activity mail',
      describe: 'Mails the people a running post-login activity reaches ' +
                '(#1111) a reminder to sign in, where the activity then ' +
                'asks them to register a post-quantum passkey. Reads one ' +
                'slice of each started activity\'s population (the realm, ' +
                'or the union of its groups) after a cursor per run, mails ' +
                'only the people the activity is due for, never inside the ' +
                'reminder interval or past its maximum, and writes one ' +
                'audit row per started activity per run.',
      owner: 'common/post_login_activities.ts',
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
    log.debug("Leaving PostLoginActivities.registerJobs().");
    return true;
  }

  /**
   * Forgets every started activity of the ambient realm and what its runs
   * did. For a test.
   */
  resetForTests(): void {
    const { log, started, runs } = this.deps;
    log.debug("Entering PostLoginActivities.resetForTests().");
    const ids: string[] = [];
    started.forEach(function (value: any, key: string): void {
      ids.push(key);
    });
    ids.forEach(function (id: string): void {
      started.delete(id);
      runs.delete(id);
    });
    log.debug("Leaving PostLoginActivities.resetForTests().");
  }
}

const slot = new InstanceSlot<PostLoginActivities>(
  'common/post_login_activities',
  () => new PostLoginActivities(PostLoginActivities.defaultDeps()),
  function (instance: PostLoginActivities): void {
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

/**
 * Started post-login activities (#1111, #1123). The exports forward to the
 * instance the composition root installs.
 *
 * @namespace
 */
export = {
  PostLoginActivities: PostLoginActivities,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: PostLoginActivities): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  JOB: JOB,
  ACTIVITIES: ACTIVITIES,
  LIMITS: LIMITS,
  MAX_GROUPS: MAX_GROUPS,
  CHOOSER_HITS: CHOOSER_HITS,
  STATES: STATES,
  ACTS: PostLoginActivities.ACTS,
  groupNamesOf: PostLoginActivities.groupNamesOf,
  list: slot.forward('list'),
  get: slot.forward('get'),
  runningOf: slot.forward('runningOf'),
  groupChooser: slot.forward('groupChooser'),
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
