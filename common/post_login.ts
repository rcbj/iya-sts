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
// it now, in which role, and may they still skip it — and keeps the one
// thing the question needs that the directory does not hold: when the person
// was first asked, until when they put it off, and when they did it.
// `authn/authn.ts` asks `dueFor()` as a session is about to start, holds the
// session while the person is asked, and reports back through
// `noteAsked()`, `noteSkipped()` and `noteDone()`.
//
// THE ONE ACTIVITY TODAY, `pqc-passkey-migration`:
//
//   * A person holding a CLASSICAL passkey in a role (`primary`, the
//     passwordless sign-in; `mfa`, the second factor) and NO post-quantum
//     one in that role is due a post-quantum passkey in that role —
//     `primary` first. Post-quantum is the key's algorithm
//     (`credentials.keyAlgorithm().postQuantum`, ML-DSA), not its lane: a
//     realm with one lane makes ML-DSA keys in the classical lane.
//   * A person holding NO passkey is due one only as the profile's
//     `noPasskey` says (`invite` or `require`), in `noPasskeyRole`.
//   * A person holding only post-quantum keys, or a post-quantum key in
//     every role they hold a classical one in, is due nothing.
//
// IT IS DUE ONLY WHERE IT CAN BE DONE: passkeys on (`webauthn.enabled`), the
// role allowed (`roleAllowed()`), an ML-DSA algorithm offered at
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
// A LIBRARY (rule 3): it registers no route. It requires the credential
// store, the WebAuthn and passkey policies and the post-login policy, none of
// which requires it, so it closes no cycle.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import credentials = require('./credentials');
import passkeyPolicy = require('./passkey_policy');
import postLoginPolicy = require('./post_login_policy');
import webauthnPolicy = require('../authn/webauthn_policy');
import InstanceSlot = require('./instance_slot');

const { log } = helpers;

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * The activity a profile names today.
 */
const PQC_MIGRATION = 'pqc-passkey-migration';

/**
 * The roles a passkey is held in, in the order they are asked about.
 */
const ROLES = ['primary', 'mfa'];

// ---------------------------------------------------------------------------
// THE STORE: `<username>|<activity>` → `{ invitedAt, snoozedUntil, asks,
// skips, doneAt }`, times in milliseconds. Declared here, per realm, and
// nowhere else (rule: a store becomes per realm at its declaration).
// ---------------------------------------------------------------------------
const progress = realms.map({ persist: 'post_login.progress',
                              onDemand: { maxEntries: 20000 } });

/**
 * What a person is due, as `dueFor()` answers it.
 */
interface Due {
  activity: string;
  // The role the passkey is registered in.
  role: string;
  // `classical`: they hold a classical passkey in the role and no
  // post-quantum one; `none`: they hold no passkey at all.
  reason: 'classical' | 'none';
  // Past the allotted time: Skip is gone and the sign-in is held.
  required: boolean;
  // Whether it can ever be required: a classical passkey to migrate, or a
  // person with none under `noPasskey: require`; never `invite`.
  enforceable: boolean;
  snoozeDays: number;
  graceDays: number;
  // When the person was first asked (0 when they never were), and when the
  // allotted time ends (0 when there is none).
  invitedAt: number;
  deadline: number;
  profile: string;
}

interface PostLoginDeps {
  log: typeof helpers.log;
  credentials: any;
  passkeyPolicy: any;
  postLoginPolicy: any;
  webauthnPolicy: any;
  progress: any;
  now: () => number;
}

/**
 * Who is due a post-login activity, and what they did about it (#1096).
 */
class PostLogin {
  /**
   * The activity a profile names today.
   */
  static readonly PQC_MIGRATION = PQC_MIGRATION;
  /**
   * The roles, in the order they are asked about.
   */
  static readonly ROLES = ROLES;

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
  stateOf(username: string, activity?: string): Record<string, number> {
    const { log, progress } = this.deps;
    log.debug("Entering PostLogin.stateOf().");
    const row = progress.get(this.keyOf(username, activity || PQC_MIGRATION));
    log.debug("Leaving PostLogin.stateOf(). " + (row ? 'Held.' : 'None.'));
    return Object.assign({ invitedAt: 0, snoozedUntil: 0, asks: 0, skips: 0,
                           doneAt: 0 }, row || {});
  }

  private write(username: string, activity: string,
                row: Record<string, number>): void {
    const { log, progress } = this.deps;
    log.debug("Entering PostLogin.write().");
    progress.set(this.keyOf(username, activity), row);
    log.debug("Leaving PostLogin.write().");
  }

  /**
   * Says whether this realm can make the passkey the activity asks for, in a
   * role: passkeys on, the role allowed, an ML-DSA algorithm offered at
   * registration, and the post-quantum lane not refused where both are on.
   *
   * @param role - `primary` or `mfa`
   * @returns true where it can
   */
  canRegister(role: string): boolean {
    const { log, webauthnPolicy } = this.deps;
    log.debug("Entering PostLogin.canRegister(). " + role);
    let out = false;
    try {
      out = webauthnPolicy.offered() === true &&
        webauthnPolicy.roleAllowed(role).ok === true &&
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
   * The lane the activity's passkey is made in: the post-quantum lane where
   * both are offered, the one lane otherwise (where it is made with an
   * ML-DSA algorithm).
   *
   * @returns `pqc` or `classical`
   */
  lane(): string {
    const { log, webauthnPolicy } = this.deps;
    log.debug("Entering PostLogin.lane().");
    const out = webauthnPolicy.alongsideClassical() ? 'pqc' : 'classical';
    log.debug("Leaving PostLogin.lane(). " + out);
    return out;
  }

  // The role a person's keys make them due, and why; null where none.
  private roleFor(username: string,
                  rules: Record<string, any>):
      { role: string; reason: 'classical' | 'none' } | null {
    const { log, credentials } = this.deps;
    log.debug("Entering PostLogin.roleFor().");
    const keys = (credentials.keysOf(username) || []) as any[];
    if (!keys.length) {
      const role = String(rules.noPasskeyRole || 'primary');
      const out = rules.noPasskey === 'invite' ||
                  rules.noPasskey === 'require'
        ? (this.canRegister(role) ? { role: role, reason: 'none' as const }
                                  : null)
        : null;
      log.debug("Leaving PostLogin.roleFor(). No passkey: " +
                (out ? out.role : 'nothing'));
      return out;
    }
    for (const role of ROLES) {
      const inRole = keys.filter(function (one) {
        return one.role === role;
      });
      const pq = inRole.filter(function (one) {
        return credentials.keyAlgorithm(one).postQuantum === true;
      });
      if (inRole.length && !pq.length && this.canRegister(role)) {
        log.debug("Leaving PostLogin.roleFor(). " + role);
        return { role: role, reason: 'classical' };
      }
    }
    log.debug("Leaving PostLogin.roleFor(). Nothing due.");
    return null;
  }

  /**
   * Answers whether a person is due a post-login activity at this sign-in:
   * the profile that reaches them, on; a role their passkeys make them due;
   * and not put off — unless the allotted time has passed, when it is due
   * and REQUIRED whatever was put off.
   *
   * Never throws: a question that cannot be answered asks nothing.
   *
   * @param username - the person
   * @param application - the application signed in to, for the passkey
   *   policy's selection
   * @returns what is due, or null
   */
  dueFor(username: string, application?: string): Due | null {
    const { log, postLoginPolicy, passkeyPolicy, now } = this.deps;
    log.debug("Entering PostLogin.dueFor(). username=" + username);
    if (!username) {
      log.debug("Leaving PostLogin.dueFor(). Nobody.");
      return null;
    }
    try {
      // THE CHEAP QUESTION FIRST: a realm with every profile off — every
      // realm, by default — reads no keys and no row.
      if (!postLoginPolicy.anyEnabled()) {
        log.debug("Leaving PostLogin.dueFor(). Off in this realm.");
        return null;
      }
      const rules = postLoginPolicy.forPerson(username);
      if (rules.enabled !== true || rules.activity !== PQC_MIGRATION) {
        log.debug("Leaving PostLogin.dueFor(). Off for " + rules.name + ".");
        return null;
      }
      // The WebAuthn policy reads the passkey profile selected for this
      // person and application (#535, #940).
      passkeyPolicy.select(username, application || '');
      const found = this.roleFor(username, rules);
      if (!found) {
        log.debug("Leaving PostLogin.dueFor(). Nothing due.");
        return null;
      }
      const state = this.stateOf(username, PQC_MIGRATION);
      const at = now();
      const graceDays = Number(rules.graceDays) || 0;
      const deadline = graceDays > 0 && state.invitedAt
        ? Number(state.invitedAt) + graceDays * DAY_MS : 0;
      const enforceable = found.reason === 'classical' ||
                          rules.noPasskey === 'require';
      const required = enforceable && deadline > 0 && at >= deadline;
      if (!required && Number(state.snoozedUntil) > at) {
        log.debug("Leaving PostLogin.dueFor(). Put off until " +
                  new Date(Number(state.snoozedUntil)).toISOString() + ".");
        return null;
      }
      const out: Due = {
        activity: PQC_MIGRATION, role: found.role, reason: found.reason,
        required: required, enforceable: enforceable,
        snoozeDays: Number(rules.snoozeDays) || 1,
        graceDays: graceDays, invitedAt: Number(state.invitedAt) || 0,
        deadline: enforceable ? deadline : 0, profile: String(rules.name)
      };
      log.debug("Leaving PostLogin.dueFor(). " + out.role +
                (out.required ? ', required.' : ', skippable.'));
      return out;
    } catch (e) {
      // A question that cannot be answered holds nobody's sign-in.
      log.debug("Caught in PostLogin.dueFor(): " + ((e && e.message) || e));
      log.debug("Leaving PostLogin.dueFor(). Unanswerable.");
      return null;
    }
  }

  /**
   * Records that a person was asked: the first invitation, which starts the
   * allotted time, and the count.
   *
   * @param username - the person
   * @param due - what they were asked
   * @returns the row now held
   */
  noteAsked(username: string, due: Due): Record<string, number> {
    const { log, now } = this.deps;
    log.debug("Entering PostLogin.noteAsked().");
    const row = this.stateOf(username, due.activity);
    if (!row.invitedAt) {
      row.invitedAt = now();
    }
    row.asks = (Number(row.asks) || 0) + 1;
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
  noteDone(username: string, due: Due): Record<string, number> {
    const { log, now } = this.deps;
    log.debug("Entering PostLogin.noteDone().");
    const row = this.stateOf(username, due.activity);
    row.doneAt = now();
    row.snoozedUntil = 0;
    this.write(username, due.activity, row);
    log.debug("Leaving PostLogin.noteDone().");
    return row;
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
  ROLES: PostLogin.ROLES,
  stateOf: slot.forward('stateOf'),
  canRegister: slot.forward('canRegister'),
  lane: slot.forward('lane'),
  dueFor: slot.forward('dueFor'),
  noteAsked: slot.forward('noteAsked'),
  noteSkipped: slot.forward('noteSkipped'),
  noteDone: slot.forward('noteDone'),
  forget: slot.forward('forget')
};
