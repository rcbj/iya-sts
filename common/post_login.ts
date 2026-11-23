// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login.ts
//
// ---------------------------------------------------------------------------
// WHO IS DUE A POST-LOGIN ACTIVITY, AND WHAT THEY DID ABOUT IT (#1096).
//
// `common/post_login_policy.ts` says what a realm asks and of whom; this
// module answers the per-person question at a sign-in — is THIS person due
// it now, and may they still skip it — and keeps the one
// thing the question needs that the directory does not hold: when the person
// was first asked, until when they put it off, and when they did it.
// `authn/authn.ts` asks `dueFor()` as a session is about to start, holds the
// session while the person is asked, and reports back through
// `noteAsked()`, `noteSkipped()` and `noteDone()`.
//
// SEVERAL ACTIVITIES SINCE #2009 (P1, design X1 and X3). The activities are
// `common/post_login_kinds.ts`'s table, each answering the same four
// questions (is it on in this profile, its rules with it turned on, Skip
// and the allotted time, and why this person is due it); everything below
// that is not about passkeys — who asks, the snooze, the allotted time,
// the progress row — is the same for each. `dueListFor()` answers every
// activity due, required first and then by exposure; `nextDue()` is what a
// sign-in asks next (every required one, at most one that may be skipped);
// `dueFor()` is the first, or the one named.
//
// THE FIRST ACTIVITY, `pqc-passkey-migration` (`passkeyKind()`):
//
//   * A person holding a CLASSICAL passkey and NO post-quantum one is due a
//     post-quantum passkey. (Until #1135 this was asked per role, `primary`
//     first; a key has no role now.) Post-quantum is the key's algorithm
//     (`credentials.keyAlgorithm().postQuantum`, ML-DSA), not its lane: a
//     realm with one lane makes ML-DSA keys in the classical lane.
//   * A person holding NO passkey is due one only as the profile's
//     `noPasskey` says (`invite` or `require`).
//   * A person holding a post-quantum key is due nothing.
//
// IT IS DUE ONLY WHERE IT CAN BE DONE: passkeys on (`webauthn.enabled`), the
// a new key enrollable (`enrolmentAllowed()`), an ML-DSA algorithm offered at
// registration in this realm (`offersPostQuantum()`), and — with both lanes
// on — the post-quantum lane not refused. A realm that cannot make an ML-DSA
// passkey asks nobody to make one, and holds nobody's sign-in for it.
//
// SKIP AND THE ALLOTTED TIME (rcbj's answer 2). Skip puts the activity off
// for `snoozeDays`; while it is put off the person is not asked. The
// allotted time (`graceDays`, 0 = none) is counted from the person's FIRST
// invitation to this activity, which is recorded the first time they are
// asked; once it has passed the activity is REQUIRED — Skip is gone, a
// snooze no longer counts, and (answer 3) the sign-in is held until it is
// done. `noPasskey: invite` is never required.
//
// THE STATE IS A MINTED STORE, `post_login.progress`, one row per person and
// activity, per realm. It is somebody's (it says when they were asked), so it
// is cell-tier (`persistence/tiers.js`), and ON DEMAND (#820): it grows with
// the people asked, and a start must not read it whole.
//
// WHAT A ROW SAYS (#1110, #1111): the first invitation, the snooze, how many
// times the person was asked and skipped, and when they did it — and, since
// the reports application reads it back (`report/sources.ts`, the
// `postLoginProgress` source), the profile and the allotted time
// that applied when it was last written, so a report says which profile
// asked a person without asking the directory again for every row. A
// started activity's mail (`common/post_login_activities.ts`) adds which
// started activity mailed them (`mailedBy`), how many mails went and when
// the first and the last did. A mail is NOT an
// invitation: the allotted time still starts at the first time the person
// is asked at a sign-in, because that is the first time they can act on it.
//
// WHO ASKS (#1126, rcbj's option (a)). Two sources turn the invitation on
// for a person: the POLICY (the profile `selectionFor()` picks for them,
// with `enabled` on) and a RUNNING STARTED activity
// (`common/post_login_activities.ts`) whose population — the union of its
// groups by DN, or the whole realm where it names none — holds them. The
// RULES are the selected profile's either way (method, snoozeDays,
// graceDays, noPasskey, noPasskeyRole, attestation, noPasskeyFallback);
// a started activity overrides only `enabled`. EXCLUSION STILL HOLDS: the
// selected profile is the named profile of lowest precedence among those the
// application signed in to and the person's groups name (#1239), so when it is
// a NAMED profile with `enabled` off the person is excluded from every started
// activity too — the policy's one way to exclude a group, or a sign-in to an
// application. `default` off excludes nobody: off is its built-in state, and a
// started activity that `default` could veto would ask nobody in every realm
// that never saved a policy. Paused or ended, the activity asks nobody; a
// person the policy itself enables is still asked. Membership is the person's
// own groups (`postLoginPolicy.personGroups()`, the passkey policy's hook),
// asked once a sign-in and only where a running activity names groups or a
// named profile exists — never a member walk. Which source asked is `askedBy`
// on the progress row: `policy`, or the started activity's id.
//
// A LIBRARY (rule 3): it registers no route. It requires the credential
// store, the WebAuthn and passkey policies and the post-login policy, none of
// which requires it, so it closes no cycle. The started activities are
// reached LAZILY (`started()`): that module reaches this one lazily too,
// and neither is loaded by the other's require.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import credentials = require('./credentials');
import passkeyPolicy = require('./passkey_policy');
import postLoginPolicy = require('./post_login_policy');
import webauthnPolicy = require('../authn/webauthn_policy');
import InstanceSlot = require('./instance_slot');
import errorCodes = require('./error_codes');
// The activities there are (#2009): a leaf.
import PostLoginKinds = require('./post_login_kinds');

const { log } = helpers;

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * The passkey migration's id (#1096), the first activity.
 */
const PQC_MIGRATION = PostLoginKinds.PQC_PASSKEY_MIGRATION;

/**
 * What one post-login activity answers (#2009 P1): the shape
 * `common/post_login_kinds.ts` describes, which every module its table
 * names exports as `kind`.
 */
interface Kind {
  id: string;
  exposure: string;
  enabledIn(profile: Record<string, any>): boolean;
  turnedOn(profile: Record<string, any>): Record<string, any>;
  timing(rules: Record<string, any>): { snoozeDays: number;
                                        graceDays: number };
  due(username: string, rules: Record<string, any>,
      application: string): { reason: string; enforceable: boolean;
                              method: string; fallback: string;
                              [fact: string]: any } | null;
}

// ---------------------------------------------------------------------------
// THE STORE: `<username>|<activity>` → `{ invitedAt, snoozedUntil, asks,
// skips, doneAt, profile, graceDays, askedBy, mailedBy, mails,
// firstMailedAt, lastMailedAt }`, times in milliseconds. Declared here, per
// realm, and nowhere else (rule: a store becomes per realm at its
// declaration).
// ---------------------------------------------------------------------------
const progress = realms.map({ persist: 'post_login.progress',
                              onDemand: { maxEntries: 20000 } });

/**
 * What a person is due, as `dueFor()` answers it.
 */
interface Due {
  activity: string;
  // Why they are due it, in the activity's own words. The passkey
  // migration's: `classical`: they hold a classical passkey and no
  // post-quantum one; `attestation`: their ML-DSA passkeys all
  // fall short of a required post-quantum attestation (#1102); `none`:
  // they hold no passkey at all.
  reason: string;
  // Past the allotted time: Skip is gone and the sign-in is held.
  required: boolean;
  // Whether it can ever be required: a classical passkey to migrate, or a
  // person with none under `noPasskey: require`; never `invite`.
  enforceable: boolean;
  // HOW it is done (#1100): `upgrade` (#939's ceremony: prove the
  // classical passkey, then an ML-DSA one replaces it in place),
  // `alongside` (an ML-DSA passkey beside it) or `register` (a person with
  // no passkey registers one).
  method: string;
  // For a person with no passkey (#1103): `none` or `classical`.
  fallback: string;
  snoozeDays: number;
  graceDays: number;
  // When the person was first asked (0 when they never were), and when the
  // allotted time ends (0 when there is none).
  invitedAt: number;
  deadline: number;
  profile: string;
  // WHO ASKED (#1126): `policy`, or the id (`pla-…`) of the running
  // started activity whose population holds the person.
  askedBy: string;
}

/**
 * One person's progress on one activity, as the store's walk hands it out
 * (#1110): the row, with the person and the activity split out of its key.
 */
interface ProgressEntry {
  username: string;
  activity: string;
  row: Record<string, any>;
}

interface PostLoginDeps {
  log: typeof helpers.log;
  credentials: any;
  passkeyPolicy: any;
  postLoginPolicy: any;
  webauthnPolicy: any;
  progress: any;
  now: () => number;
  // The started activities (#1126), lazily; absent in a test's deps, when
  // no started activity asks anybody.
  started?: () => any;
  // The activities asked (#2009), for a test; absent, the table's.
  kinds?: (self: PostLogin) => Kind[];
}

/**
 * Who is due a post-login activity, and what they did about it (#1096).
 */
class PostLogin {
  /**
   * The activity a profile names today.
   */
  static readonly PQC_MIGRATION = PQC_MIGRATION;

  // The table's activities that loaded, by id (`kindsAsked()`); a row that
  // failed is not kept, and is tried again.
  private loadedKinds: Record<string, Kind> = {};

  // What was already logged at error level once in this process: a module
  // that did not load (`load:<id>`), an activity whose answer threw
  // (`due:<id>`).
  private warnedKinds: Set<string> = new Set();

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, the stores and policies, and the clock
   */
  constructor(private readonly deps: PostLoginDeps) {
    deps.log.debug("Entering PostLogin.constructor().");
    deps.log.debug("Leaving PostLogin.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules
   */
  static defaultDeps(): PostLoginDeps {
    log.debug("Entering PostLogin.defaultDeps().");
    log.debug("Leaving PostLogin.defaultDeps().");
    return { log: log, credentials: credentials,
             passkeyPolicy: passkeyPolicy, postLoginPolicy: postLoginPolicy,
             webauthnPolicy: webauthnPolicy, progress: progress,
             now: function () {
               return Date.now();
             },
             started: function () {
               return require('./post_login_activities');
             } };
  }

  // The row's key: one per person and activity.
  private keyOf(username: string, activity: string): string {
    const { log } = this.deps;
    log.debug("Entering PostLogin.keyOf().");
    log.debug("Leaving PostLogin.keyOf().");
    return String(username || '').trim().toLowerCase() + '|' +
           String(activity || PQC_MIGRATION);
  }

  /**
   * Reads a person's progress on an activity.
   *
   * @param username - the person
   * @param activity - the activity; the PQC migration when omitted
   * @returns the row, or an empty one
   */
  stateOf(username: string, activity?: string): Record<string, any> {
    const { log, progress } = this.deps;
    log.debug("Entering PostLogin.stateOf().");
    const row = progress.get(this.keyOf(username, activity || PQC_MIGRATION));
    log.debug("Leaving PostLogin.stateOf(). " + (row ? 'Held.' : 'None.'));
    return Object.assign({ invitedAt: 0, snoozedUntil: 0, asks: 0, skips: 0,
                           doneAt: 0, mails: 0, firstMailedAt: 0,
                           lastMailedAt: 0, askedBy: '' }, row || {});
  }

  // WHAT APPLIED WHEN THE ROW WAS WRITTEN (#1110): the profile and
  // the allotted time of the due that wrote it, kept beside the counts so
  // the report reads them off the row.
  private stamp(row: Record<string, any>, due: Due, asked: boolean): void {
    const { log } = this.deps;
    log.debug("Entering PostLogin.stamp().");
    row.profile = String(due.profile || '');
    // No role since #1135; a row written before keeps the one it has.
    row.graceDays = due.enforceable ? Number(due.graceDays) || 0 : 0;
    // Who asked at a sign-in (#1126). A mail is not an ask, so
    // `noteMailed()` leaves it as it was.
    if (asked) {
      row.askedBy = String(due.askedBy || '');
    }
    log.debug("Leaving PostLogin.stamp().");
  }

  private write(username: string, activity: string,
                row: Record<string, any>): void {
    const { log, progress } = this.deps;
    log.debug("Entering PostLogin.write().");
    progress.set(this.keyOf(username, activity), row);
    log.debug("Leaving PostLogin.write().");
  }

  /**
   * Says whether this realm can make the passkey the activity asks for, in a
   * new key enrollable (no role since #1135), an ML-DSA algorithm offered
   * at registration, and the post-quantum lane not refused where both are
   * on.
   *
   * @param method - the due's `method`
   * @returns true where it can
   */
  canRegister(method?: string): boolean {
    const { log, webauthnPolicy } = this.deps;
    log.debug("Entering PostLogin.canRegister(). " + (method || ''));
    let out = false;
    try {
      out = webauthnPolicy.offered() === true &&
        (method !== 'upgrade' || webauthnPolicy.upgradeRefusal().ok === true) &&
        webauthnPolicy.enrolmentAllowed().ok === true &&
        webauthnPolicy.offersPostQuantum() === true &&
        webauthnPolicy.upgradeAlgorithms().length > 0 &&
        (!webauthnPolicy.alongsideClassical() ||
         webauthnPolicy.laneRefusal('pqc').ok === true);
    } catch (e) {
      // A policy that cannot be asked asks nobody anything.
      log.debug("Caught in PostLogin.canRegister(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving PostLogin.canRegister(). " + out);
    return out;
  }

  /**
   * The lane the activity's passkey is made in: an upgrade's replaces the
   * classical key in ITS lane; otherwise the post-quantum lane where both
   * are offered, the one lane where they are not (made with an ML-DSA
   * algorithm there).
   *
   * @param method - the due's `method`
   * @returns `pqc` or `classical`
   */
  lane(method?: string): string {
    const { log, webauthnPolicy } = this.deps;
    log.debug("Entering PostLogin.lane().");
    const out = method !== 'upgrade' && webauthnPolicy.alongsideClassical()
      ? 'pqc' : 'classical';
    log.debug("Leaving PostLogin.lane(). " + out);
    return out;
  }

  // THE METHOD FOR ONE PERSON (#1100): the profile's, `automatic` resolved
  // by the lanes the person's passkey policy offers; `register` for a
  // person with no passkey to migrate.
  private methodFor(rules: Record<string, any>, reason: string): string {
    const { log, webauthnPolicy } = this.deps;
    log.debug("Entering PostLogin.methodFor().");
    const asked = String(rules.method || 'automatic');
    const out = reason === 'none' ? 'register'
      : reason === 'attestation' ? 'alongside'
      : (asked === 'upgrade' || asked === 'alongside' ? asked
        : (webauthnPolicy.alongsideClassical() ? 'alongside' : 'upgrade'));
    log.debug("Leaving PostLogin.methodFor(). " + out);
    return out;
  }

  /**
   * The classical passkey an upgrade replaces (#1100): of the person's
   * classical passkeys, the one named (the passkey this
   * sign-in used, where it is one), else the one used last.
   *
   * @param username - the person
   * @param prefer - a credential id to prefer, or ''
   * @returns the stored key, or null
   */
  keyToUpgrade(username: string, prefer?: string): any {
    const { log, credentials } = this.deps;
    log.debug("Entering PostLogin.keyToUpgrade().");
    const classical = ((credentials.keysOf(username) || []) as any[])
      .filter(function (one) {
        return credentials.keyAlgorithm(one).postQuantum !== true;
      });
    const named = classical.filter(function (one) {
      return prefer && String(one.credentialId) === String(prefer);
    })[0];
    const out = named || classical.slice().sort(function (a, b) {
      return Number(b.lastUsedAt || b.createdAt || 0) -
             Number(a.lastUsedAt || a.createdAt || 0);
    })[0] || null;
    log.debug("Leaving PostLogin.keyToUpgrade(). " + (out ? 'Found.'
                                                         : 'None.'));
    return out;
  }

  // Why a person's keys make them due, or null where they do not (#1135:
  // every key at once, a key having no role).
  private reasonFor(username: string,
                    rules: Record<string, any>):
      { reason: 'classical' | 'none' | 'attestation' } | null {
    const { log, credentials } = this.deps;
    log.debug("Entering PostLogin.reasonFor().");
    const keys = (credentials.keysOf(username) || []) as any[];
    if (!keys.length) {
      const out = rules.noPasskey === 'invite' ||
                  rules.noPasskey === 'require'
        ? (this.canRegister() ? { reason: 'none' as const } : null)
        : null;
      log.debug("Leaving PostLogin.reasonFor(). No passkey: " +
                (out ? 'due' : 'nothing'));
      return out;
    }
    // WHAT COUNTS (#1102): the key's algorithm, and — where the profile
    // says so — its recorded attestation's too.
    const counts = function (one: any): boolean {
      if (credentials.keyAlgorithm(one).postQuantum !== true) {
        return false;
      }
      if (rules.attestation !== 'post-quantum') {
        return true;
      }
      const att = credentials.attestationAlgorithms(one) || {};
      return att.recorded === true && att.postQuantum === true;
    };
    const pq = keys.filter(counts);
    // `attestation` where every key is ML-DSA and only its attestation
    // falls short: nothing classical to upgrade, so the new passkey goes
    // beside it.
    const reason = keys.some(function (one) {
      return credentials.keyAlgorithm(one).postQuantum !== true;
    }) ? 'classical' as const : 'attestation' as const;
    if (!pq.length && this.canRegister(this.methodFor(rules, reason))) {
      log.debug("Leaving PostLogin.reasonFor(). " + reason);
      return { reason: reason };
    }
    log.debug("Leaving PostLogin.reasonFor(). Nothing due.");
    return null;
  }

  // THE PASSKEY MIGRATION AS AN ACTIVITY (#2009 P1): what this module
  // answered alone until #2009, behind the shape every activity answers
  // (`common/post_login_kinds.ts`). Nothing in it changed: the switch is
  // `enabled` with `activity` naming it, Skip and the allotted time are the
  // profile's own rows, and who is due is `reasonFor()` after the passkey
  // policy is selected for the person and the application (#535, #940).
  /**
   * The passkey migration, as the activity `dueListFor()` asks.
   *
   * @returns its answers
   */
  passkeyKind(): Kind {
    const { log } = this.deps;
    log.debug("Entering PostLogin.passkeyKind().");
    const self = this;
    const out: Kind = {
      id: PQC_MIGRATION,
      exposure: 'forgery',
      enabledIn: function enabledIn(profile: Record<string, any>): boolean {
        log.debug("Entering PostLogin.passkeyKind().enabledIn().");
        log.debug("Leaving PostLogin.passkeyKind().enabledIn().");
        return profile.enabled === true &&
               String(profile.activity || '') === PQC_MIGRATION;
      },
      turnedOn: function turnedOn(profile: Record<string, any>):
          Record<string, any> {
        log.debug("Entering PostLogin.passkeyKind().turnedOn().");
        log.debug("Leaving PostLogin.passkeyKind().turnedOn().");
        return Object.assign({}, profile, { enabled: true,
                                            activity: PQC_MIGRATION });
      },
      timing: function timing(rules: Record<string, any>):
          { snoozeDays: number; graceDays: number } {
        log.debug("Entering PostLogin.passkeyKind().timing().");
        log.debug("Leaving PostLogin.passkeyKind().timing().");
        return { snoozeDays: Number(rules.snoozeDays) || 1,
                 graceDays: Number(rules.graceDays) || 0 };
      },
      due: function due(username: string, rules: Record<string, any>,
                        application: string): any {
        log.debug("Entering PostLogin.passkeyKind().due().");
        // The WebAuthn policy reads the passkey profile selected for this
        // person and application (#535, #940).
        self.deps.passkeyPolicy.select(username, application || '');
        const found = self.reasonFor(username, rules);
        if (!found) {
          log.debug("Leaving PostLogin.passkeyKind().due(). Not due.");
          return null;
        }
        log.debug("Leaving PostLogin.passkeyKind().due(). " + found.reason);
        return {
          reason: found.reason,
          enforceable: found.reason !== 'none' ||
                       rules.noPasskey === 'require',
          method: self.methodFor(rules, found.reason),
          fallback: found.reason === 'none' &&
                    rules.noPasskeyFallback === 'classical' ? 'classical'
                                                            : 'none'
        };
      }
    };
    log.debug("Leaving PostLogin.passkeyKind().");
    return out;
  }

  // THE ACTIVITIES ASKED (#2009 P1): `post_login_kinds.ts`'s table, in its
  // order — the passkey migration answered here, every other row by the
  // module it names, required the first time it is asked (the table's
  // header argues why lazily). A module that is not whole is not asked, and
  // is logged under STS-AUTHN-0581 the first time in this process (a line
  // per sign-in would bury the log): the other activities are still
  // asked, because one activity that cannot answer must not stop a person
  // being asked another. ONLY WHAT LOADED IS KEPT: a row that failed is
  // tried again at the next question, so a failure that passes (a module
  // that threw while something it reads was not yet loaded — node keeps no
  // module that threw) does not leave the activity unasked for the life of
  // the process. A test's deps may hand its own list.
  private kindsAsked(): Kind[] {
    const { log } = this.deps;
    log.debug("Entering PostLogin.kindsAsked().");
    if (typeof this.deps.kinds === 'function') {
      const given = this.deps.kinds(this) || [];
      log.debug("Leaving PostLogin.kindsAsked(). " + given.length +
                " given.");
      return given;
    }
    const loaded = this.loadedKinds;
    const out: Kind[] = [];
    PostLoginKinds.KINDS.forEach((row) => {
      if (loaded[row.id]) {
        out.push(loaded[row.id]);
        return;
      }
      if (!row.module) {
        if (row.id === PQC_MIGRATION) {
          loaded[row.id] = this.passkeyKind();
          out.push(loaded[row.id]);
        }
        return;
      }
      let kind: any = null;
      try {
        // A lazy require of a module the table names (its header).
        kind = require(row.module).kind;
      } catch (e) {
        log.debug("Caught in PostLogin.kindsAsked(): " +
                  ((e && e.message) || e));
        kind = null;
      }
      const problem = PostLoginKinds.problemWith(row, kind);
      if (problem) {
        const why = 'post-login: the activity "' + row.id + '" is not ' +
          'asked: its module (' + row.module + ') ' + problem + '.';
        if (this.warnedKinds.has('load:' + row.id)) {
          log.debug(why);
        } else {
          this.warnedKinds.add('load:' + row.id);
          log.error(errorCodes.tag('STS-AUTHN-0581') + why +
                    ' Tried again at every sign-in; logged once.');
        }
        return;
      }
      loaded[row.id] = kind as Kind;
      out.push(kind as Kind);
    });
    log.debug("Leaving PostLogin.kindsAsked(). " + out.length + ".");
    return out;
  }

  // THE RUNNING STARTED ACTIVITIES of one activity in this realm (#1126),
  // oldest first; none where the module cannot be asked — a started
  // activity that cannot be read asks nobody, and the policy still does.
  private runningActivities(activity: string):
      { id: string; groups: string[] }[] {
    const { log } = this.deps;
    log.debug("Entering PostLogin.runningActivities().");
    let out: { id: string; groups: string[] }[] = [];
    try {
      const started = typeof this.deps.started === 'function'
        ? this.deps.started() : null;
      out = started && typeof started.runningOf === 'function'
        ? (started.runningOf(activity) || []) : [];
    } catch (e) {
      log.debug("Caught in PostLogin.runningActivities(): " +
                ((e && e.message) || e));
      out = [];
    }
    log.debug("Leaving PostLogin.runningActivities(). " + out.length);
    return out;
  }

  // THE FIRST RUNNING STARTED ACTIVITY WHOSE POPULATION HOLDS THE PERSON
  // (#1126): one naming no group holds everybody; otherwise one of its
  // group DNs is one of the person's. Oldest first, so the answer does not
  // move when another is started. null where none does.
  private startedReaching(running: { id: string; groups: string[] }[],
                          groupsOf: () => { cn?: string; dn?: string }[]):
      { id: string } | null {
    const { log } = this.deps;
    log.debug("Entering PostLogin.startedReaching().");
    let dns: string[] | null = null;
    for (const one of running) {
      if (!one.groups.length) {
        log.debug("Leaving PostLogin.startedReaching(). " + one.id +
                  ", the realm.");
        return one;
      }
      if (dns === null) {
        dns = (groupsOf() || []).map(function (g: any): string {
          return String((g && g.dn) || '').toLowerCase();
        }).filter(Boolean);
      }
      const mine = dns;
      if (one.groups.some(function (dn: string): boolean {
        return mine.indexOf(dn) >= 0;
      })) {
        log.debug("Leaving PostLogin.startedReaching(). " + one.id + ".");
        return one;
      }
    }
    log.debug("Leaving PostLogin.startedReaching(). None.");
    return null;
  }

  // ONE ACTIVITY'S DUE FOR ONE PERSON (#2009 P1: the body `dueFor()` was
  // until then, for every activity). Who asks: the selected profile with
  // this activity on (`policy`); else, where the selected profile is a
  // NAMED one, nobody — a named profile with the activity off is how the
  // policy excludes a group or an application, from a started activity too
  // (#1126); else the oldest running started activity whose population
  // holds them, under the selected profile's rules with only the switch
  // the activity's. Then the activity's own reason, then the snooze and the
  // allotted time, which are the same for every activity.
  private dueOf(kind: Kind, username: string, application: string,
                selected: Record<string, any>,
                running: { id: string; groups: string[] }[],
                groupsOf: () => { cn?: string; dn?: string }[]):
      Due | null {
    const { log, postLoginPolicy, now } = this.deps;
    log.debug("Entering PostLogin.dueOf(). " + kind.id);
    let rules = selected;
    let askedBy = '';
    if (kind.enabledIn(selected)) {
      askedBy = 'policy';
    } else if (String(selected.name) !==
               String(postLoginPolicy.DEFAULT_PROFILE || 'default')) {
      log.debug("Leaving PostLogin.dueOf(). Excluded by the named " +
                "profile " + selected.name + ".");
      return null;
    } else {
      const by = this.startedReaching(running, groupsOf);
      if (!by) {
        log.debug("Leaving PostLogin.dueOf(). The policy does not ask " +
                  "this person, and no started activity reaches them.");
        return null;
      }
      // The selected profile's rules; only the switch is the activity's.
      rules = kind.turnedOn(selected);
      askedBy = by.id;
    }
    const found = kind.due(username, rules, application);
    if (!found) {
      log.debug("Leaving PostLogin.dueOf(). Not due.");
      return null;
    }
    const timing = kind.timing(rules);
    const state = this.stateOf(username, kind.id);
    const at = now();
    const graceDays = Number(timing.graceDays) || 0;
    const deadline = graceDays > 0 && state.invitedAt
      ? Number(state.invitedAt) + graceDays * DAY_MS : 0;
    const enforceable = found.enforceable === true;
    const required = enforceable && deadline > 0 && at >= deadline;
    if (!required && Number(state.snoozedUntil) > at) {
      log.debug("Leaving PostLogin.dueOf(). Put off until " +
                new Date(Number(state.snoozedUntil)).toISOString() + ".");
      return null;
    }
    const out: Due = Object.assign({}, found, {
      activity: kind.id, reason: found.reason,
      required: required, enforceable: enforceable,
      method: String(found.method || ''),
      fallback: String(found.fallback || 'none'),
      snoozeDays: Number(timing.snoozeDays) || 1,
      graceDays: graceDays, invitedAt: Number(state.invitedAt) || 0,
      deadline: enforceable ? deadline : 0, profile: String(rules.name),
      askedBy: askedBy
    }) as Due;
    log.debug("Leaving PostLogin.dueOf(). " + out.reason +
              (out.required ? ', required' : ', skippable') +
              ', asked by ' + askedBy + '.');
    return out;
  }

  /**
   * Answers which post-login activities a person is due at this sign-in
   * (#2009 P1), in the order they are asked: the required ones first, then
   * by their credential's exposure (`post_login_kinds.ts`), then by the
   * table's order. Each is due as `dueFor()` always said: the profile that
   * reaches them with it on — or a running started activity of it whose
   * population holds them and no named profile off excluding them
   * (#1126); their credentials making them due; and not put off — unless
   * the allotted time has passed, when it is due and REQUIRED whatever was
   * put off.
   *
   * Never throws: a question that cannot be answered asks nothing, and an
   * activity that cannot be answered leaves the others asked.
   *
   * @param username - the person
   * @param application - the application signed in to, for the post-login
   *   and passkey policies' selections; omitted outside a sign-in (the
   *   started activities' walk), where the groups alone select
   * @returns what is due, possibly nothing
   */
  dueListFor(username: string, application?: string): Due[] {
    const { log, postLoginPolicy } = this.deps;
    log.debug("Entering PostLogin.dueListFor().");
    if (!username) {
      log.debug("Leaving PostLogin.dueListFor(). No person.");
      return [];
    }
    const out: Due[] = [];
    try {
      const kinds = this.kindsAsked();
      const running: Record<string, { id: string; groups: string[] }[]> =
        {};
      kinds.forEach((kind) => {
        running[kind.id] = this.runningActivities(kind.id);
      });
      // THE CHEAP QUESTION FIRST: a realm with every profile off and no
      // started activity running — every realm, by default — reads no
      // keys, no group and no row.
      const anyRunning = kinds.some(function (kind) {
        return running[kind.id].length > 0;
      });
      if (!anyRunning && !postLoginPolicy.anyEnabled(
            function (profile: Record<string, any>): boolean {
              return kinds.some(function (kind) {
                return kind.enabledIn(profile);
              });
            })) {
        log.debug("Leaving PostLogin.dueListFor(). Nothing is on.");
        return [];
      }
      // The person's groups — each with the post-login profile it names
      // (#1239) — asked of the directory at most once for the profile's
      // selection and every activity's started activities.
      let held: { cn?: string; dn?: string; value?: string }[] | null = null;
      const groupsOf = function ():
          { cn?: string; dn?: string; value?: string }[] {
        if (held === null) {
          held = postLoginPolicy.personGroups(username) || [];
        }
        return held as { cn?: string; dn?: string; value?: string }[];
      };
      // THE APPLICATION IS A CANDIDATE TOO (#1239): the profile it names
      // ranks with the groups' where the sign-in names one. The started
      // activities' walk and the report ask without one, and select by the
      // groups alone (`post_login_policy.ts`'s header argues it).
      const selected = postLoginPolicy.forPerson(username, groupsOf,
                                                 application || '');
      kinds.forEach((kind, at) => {
        try {
          const due = this.dueOf(kind, username, String(application || ''),
                                 selected, running[kind.id], groupsOf);
          if (due) {
            (due as any).order = at;
            out.push(due);
          }
        } catch (e) {
          // One activity that cannot be answered asks nothing, and leaves
          // the others asked — but NOT QUIETLY: an activity that throws is
          // one that may be REQUIRED of this person and is not being asked,
          // so it is an error with its code, the first time in this process
          // (once a sign-in would bury the log), and a debug line after.
          const why = 'post-login: the activity "' + kind.id + '" could ' +
            'not say whether "' + username + '" is due it, so it is not ' +
            'asked: ' + ((e && e.message) || e);
          log.debug("Caught in PostLogin.dueListFor(): " + why);
          if (!this.warnedKinds.has('due:' + kind.id)) {
            this.warnedKinds.add('due:' + kind.id);
            log.error(errorCodes.tag('STS-AUTHN-0582') + why +
                      '. Logged once in this process.');
          }
        }
      });
    } catch (e) {
      // A question that cannot be answered holds nobody's sign-in.
      log.debug("Caught in PostLogin.dueListFor(): " +
                ((e && e.message) || e));
      log.debug("Leaving PostLogin.dueListFor(). Unanswerable.");
      return [];
    }
    const kinds = this.kindsAsked();
    const exposureOf = function (id: string): number {
      log.debug("Entering PostLogin.dueListFor().exposureOf().");
      const kind = kinds.filter(function (one) {
        return one.id === id;
      })[0];
      log.debug("Leaving PostLogin.dueListFor().exposureOf().");
      return PostLoginKinds.exposureRank(kind ? kind.exposure : '');
    };
    out.sort(function (a, b) {
      return (Number(b.required) - Number(a.required)) ||
             (exposureOf(a.activity) - exposureOf(b.activity)) ||
             (Number((a as any).order) - Number((b as any).order));
    });
    out.forEach(function (one) {
      delete (one as any).order;
    });
    log.debug("Leaving PostLogin.dueListFor(). " + out.length + " due.");
    return out;
  }

  /**
   * Answers whether a person is due a post-login activity at this sign-in:
   * the first `dueListFor()` answers, or — naming an activity — that one.
   *
   * Never throws: a question that cannot be answered asks nothing.
   *
   * @param username - the person
   * @param application - the application signed in to; omitted outside a
   *   sign-in (the started activities' walk), where the groups alone select
   * @param activity - the one activity asked about (a started activity's
   *   mail, #1111); omitted for the first due
   * @returns what is due, or null
   */
  dueFor(username: string, application?: string,
         activity?: string): Due | null {
    const { log } = this.deps;
    log.debug("Entering PostLogin.dueFor().");
    const list = this.dueListFor(username, application);
    const out = (activity
      ? list.filter(function (one) {
        return one.activity === String(activity);
      })
      : list)[0] || null;
    log.debug("Leaving PostLogin.dueFor(). " +
              (out ? out.activity : 'Nothing.'));
    return out;
  }

  /**
   * The next activity a sign-in asks (#2009 P1, design X3): of what is
   * due, the first not already asked at this sign-in — every REQUIRED one,
   * and at most ONE that may be skipped, so a sign-in does not become a
   * questionnaire (rcbj's decision D2 on #2009, 2026-11-23). The others are
   * asked at a later sign-in.
   *
   * @param username - the person
   * @param application - the application signed in to
   * @param asked - the activities already asked at this sign-in
   * @param skippableAsked - whether one that could be skipped was
   * @returns what to ask next, or null
   */
  nextDue(username: string, application: string, asked: string[],
          skippableAsked: boolean): Due | null {
    const { log } = this.deps;
    log.debug("Entering PostLogin.nextDue().");
    const done = (asked || []).map(String);
    const out = this.dueListFor(username, application).filter(function (one) {
      return done.indexOf(one.activity) < 0 &&
             (one.required || !skippableAsked);
    })[0] || null;
    log.debug("Leaving PostLogin.nextDue(). " +
              (out ? out.activity : 'Nothing.'));
    return out;
  }

  /**
   * Records that a person was asked: the first invitation, which starts the
   * allotted time, and the count.
   *
   * @param username - the person
   * @param due - what they were asked
   * @returns the row now held
   */
  noteAsked(username: string, due: Due): Record<string, any> {
    const { log, now } = this.deps;
    log.debug("Entering PostLogin.noteAsked().");
    const row = this.stateOf(username, due.activity);
    if (!row.invitedAt) {
      row.invitedAt = now();
    }
    row.asks = (Number(row.asks) || 0) + 1;
    this.stamp(row, due, true);
    this.write(username, due.activity, row);
    log.debug("Leaving PostLogin.noteAsked().");
    return row;
  }

  /**
   * Records Skip: the activity is put off for the profile's `snoozeDays`.
   * Refused where it is required.
   *
   * @param username - the person
   * @param due - what they were asked
   * @returns `{ ok, snoozedUntil }`, or `{ ok: false }` where it is required
   */
  noteSkipped(username: string, due: Due): { ok: boolean;
                                             snoozedUntil?: number } {
    const { log, now } = this.deps;
    log.debug("Entering PostLogin.noteSkipped().");
    if (due.required) {
      log.debug("Leaving PostLogin.noteSkipped(). Required.");
      return { ok: false };
    }
    const row = this.stateOf(username, due.activity);
    if (!row.invitedAt) {
      row.invitedAt = now();
    }
    row.skips = (Number(row.skips) || 0) + 1;
    row.snoozedUntil = now() + (Number(due.snoozeDays) || 1) * DAY_MS;
    this.stamp(row, due, true);
    this.write(username, due.activity, row);
    log.debug("Leaving PostLogin.noteSkipped().");
    return { ok: true, snoozedUntil: row.snoozedUntil };
  }

  /**
   * Records that a person did the activity. Whether they are due it again
   * is their keys' to say (a passkey removed later makes them due again,
   * with the allotted time counted from the first invitation still).
   *
   * @param username - the person
   * @param due - what they did
   * @returns the row now held
   */
  noteDone(username: string, due: Due): Record<string, any> {
    const { log, now } = this.deps;
    log.debug("Entering PostLogin.noteDone().");
    const row = this.stateOf(username, due.activity);
    row.doneAt = now();
    row.snoozedUntil = 0;
    this.stamp(row, due, true);
    this.write(username, due.activity, row);
    log.debug("Leaving PostLogin.noteDone().");
    return row;
  }

  /**
   * Records that a started activity mailed a person about it (#1111): which
   * started activity, how many mails went, and when the first and the last
   * did. It is not an invitation — the allotted time starts at a sign-in.
   *
   * @param username - the person
   * @param due - what they are due, as `dueFor()` answered
   * @param mailedBy - the started activity's id
   * @returns the row now held
   */
  noteMailed(username: string, due: Due, mailedBy: string):
      Record<string, any> {
    const { log, now } = this.deps;
    log.debug("Entering PostLogin.noteMailed().");
    const row = this.stateOf(username, due.activity);
    const at = now();
    // THE COUNTS ARE THE NAMED STARTED ACTIVITY'S: a later one mailing the
    // same person starts its own count, so its maximum is its own.
    // `lastMailedAt` is still the last mail of any of them — the interval is
    // the person's.
    if (String(row.mailedBy || '') !== String(mailedBy || '')) {
      row.mails = 0;
      row.firstMailedAt = 0;
    }
    row.mailedBy = String(mailedBy || '');
    row.mails = (Number(row.mails) || 0) + 1;
    if (!row.firstMailedAt) {
      row.firstMailedAt = at;
    }
    row.lastMailedAt = at;
    this.stamp(row, due, false);
    this.write(username, due.activity, row);
    log.debug("Leaving PostLogin.noteMailed(). " + row.mails + '.');
    return row;
  }

  /**
   * Walks the ambient realm's progress rows (#1110), every person and
   * activity once, in no promised order: the rows this process holds, then
   * the store a page at a time, the event loop given back between pages
   * (`realms.map()`'s `scanAsync()`). `fn` answering `false` ends the walk,
   * which is how a report stops at its limit or its time budget.
   *
   * @param fn - called with each row, the person and the activity split out
   *   of its key
   * @returns a promise settled when the walk ends
   */
  async eachProgressAsync(fn: (entry: ProgressEntry) => boolean | void):
      Promise<void> {
    const { log, progress } = this.deps;
    log.debug("Entering PostLogin.eachProgressAsync().");
    let seen = 0;
    const walk = function (value: any, key: any): boolean | void {
      const text = String(key || '');
      const bar = text.lastIndexOf('|');
      if (bar <= 0 || !value || typeof value !== 'object') {
        return true;
      }
      seen += 1;
      return fn({ username: text.slice(0, bar),
                  activity: text.slice(bar + 1), row: value });
    };
    if (typeof progress.scanAsync === 'function') {
      await progress.scanAsync(walk);
    } else {
      // A plain Map (a test's): walked here, stopping the same way.
      for (const entry of Array.from(progress.entries()) as any[]) {
        if (walk(entry[1], entry[0]) === false) {
          break;
        }
      }
    }
    log.debug("Leaving PostLogin.eachProgressAsync(). " + seen + " row(s).");
  }

  /**
   * When a row's allotted time ends, and whether it has (#1110): its
   * recorded `graceDays` counted from the first invitation, 0 where there is
   * no deadline — no allotted time, never invited, or nothing that can be
   * required. Done is never past its grace.
   *
   * @param row - a progress row
   * @param graceDays - the allotted time to use where the row recorded none
   *   (a row written before #1110)
   * @returns `{ deadline, ended, snoozed }`, the deadline in milliseconds
   *   and `snoozed` whether a Skip still puts it off, on this module's clock
   */
  graceOf(row: Record<string, any>, graceDays?: number):
      { deadline: number; ended: boolean; snoozed: boolean } {
    const { log, now } = this.deps;
    log.debug("Entering PostLogin.graceOf().");
    const days = row && row.graceDays != null ? Number(row.graceDays) || 0
                                               : Number(graceDays) || 0;
    const invited = Number(row && row.invitedAt) || 0;
    const deadline = days > 0 && invited ? invited + days * DAY_MS : 0;
    const ended = deadline > 0 && !(Number(row && row.doneAt) > 0) &&
                  now() >= deadline;
    const snoozed = Number(row && row.snoozedUntil) > now();
    log.debug("Leaving PostLogin.graceOf(). " + ended);
    return { deadline: deadline, ended: ended, snoozed: snoozed };
  }

  /**
   * Forgets a person's progress on an activity: the allotted time starts
   * again at the next invitation. For a test, and an operator's reset.
   *
   * @param username - the person
   * @param activity - the activity; the PQC migration when omitted
   * @returns true where a row was held
   */
  forget(username: string, activity?: string): boolean {
    const { log, progress } = this.deps;
    log.debug("Entering PostLogin.forget().");
    const key = this.keyOf(username, activity || PQC_MIGRATION);
    const held = progress.has(key);
    progress.delete(key);
    log.debug("Leaving PostLogin.forget(). " + held);
    return held;
  }

  // A DELETED PERSON'S PROGRESS GOES WITH THEM (2026-11-16, rcbj's rule on
  // #1612). The row is keyed by the NAME, so a person made again under it
  // started with the deleted one's activity done, put off or past its
  // deadline. The directory's one person delete (`removePersonEntry()`)
  // calls this for every activity there is (`post_login_kinds.ts`'s
  // table, #2009): a key per activity, never a walk of the store. A
  // re-homing keeps it.
  /**
   * Forgets a deleted person's progress on every activity.
   *
   * @param username - the deleted person's name
   * @returns how many rows were held
   */
  forgetPerson(username: string): number {
    const { log } = this.deps;
    log.debug("Entering PostLogin.forgetPerson().");
    let held = 0;
    PostLoginKinds.ids()
      .forEach((activity: string) => {
        if (this.forget(username, activity)) {
          held += 1;
        }
      });
    log.debug("Leaving PostLogin.forgetPerson(). " + held);
    return held;
  }
}

const slot = new InstanceSlot<PostLogin>(
  'common/post_login',
  () => new PostLogin(PostLogin.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * Who is due a post-login activity, and what they did about it (#1096). The
 * exports forward to the instance the composition root installs.
 *
 * @namespace
 */
export = {
  PostLogin: PostLogin,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: PostLogin): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  PQC_MIGRATION: PostLogin.PQC_MIGRATION,
  stateOf: slot.forward('stateOf'),
  canRegister: slot.forward('canRegister'),
  lane: slot.forward('lane'),
  keyToUpgrade: slot.forward('keyToUpgrade'),
  dueFor: slot.forward('dueFor'),
  dueListFor: slot.forward('dueListFor'),
  nextDue: slot.forward('nextDue'),
  noteAsked: slot.forward('noteAsked'),
  noteSkipped: slot.forward('noteSkipped'),
  noteDone: slot.forward('noteDone'),
  noteMailed: slot.forward('noteMailed'),
  eachProgressAsync: slot.forward('eachProgressAsync'),
  graceOf: slot.forward('graceOf'),
  forget: slot.forward('forget'),
  forgetPerson: slot.forward('forgetPerson')
};
