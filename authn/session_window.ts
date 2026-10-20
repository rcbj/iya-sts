// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: session_window.ts
//
// The sign-on sessions one process holds when authn.sessionWindow is on
// (#350). `auto` is the same window once minted persistence is enabled, the
// process is one cell, and the minted key is a digest; otherwise the realm
// Map stays the whole store. Eviction forgets a memory copy only after its
// upsert has committed, and it does not end the session. A miss reads the
// sealed row by its keyed digest. This is not the authn.sessions partition
// and not a directory window.

import bunyan = require('bunyan');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import keystore = require('../common/keystore');
import cells = require('../common/cells');
import minted = require('../persistence/persistence_minted');
import BoundedLru = require('../common/bounded_lru');
import cacheRegistry = require('../common/cache_registry');
import SyncQuery = require('../common/sync_query');

const log = bunyan.createLogger({ name: 'sts-session-window' });

const HANDLE = 'authn.sessions';
const NAME_LABEL = 'minted-key';
const TOMBSTONE = '$tombstone$1';
const NEGATIVE_CAP = 1024;
const NEGATIVE_MS = 60000;
const PAGE = 200;
const SUBJECT_PAGE = 500;
// How long a realm's count may answer an admission that is far from the cap
// (#754), and how far "far" is: the larger of these two.
const COUNT_FRESH_MS = 10000;
const COUNT_MARGIN_MIN = 1000;
const COUNT_MARGIN_SHARE = 0.01;

const NOT_ENABLED = 'authn.sessionWindow cannot be on: minted persistence ' +
  'is not enabled.';
const SEVERAL_CELLS = 'authn.sessionWindow cannot be on: this process is ' +
  'one of several cells.';
const NOT_A_DIGEST = 'authn.sessionWindow cannot be on: the minted key is ' +
  'not a digest.';

interface RecentCount {
  n: number;
  at: number;
  admitted: number;
}

interface Slot {
  session: any;
  dirty: boolean;
  pendingTouch: boolean;
  writtenAt: number;
}

type SessionRead =
  { ok: true; session: any; error?: undefined; absent?: undefined } |
  { ok: false; absent: true; error?: undefined; session?: undefined } |
  { ok: false; error: true; absent?: undefined; session?: undefined };

type Membership = 'present' | 'absent' | 'error';

type ApplyDecision = 'remove' | 'restore' | 'keep' | 'admit' | 'skip';

interface TouchFlusher {
  (realmId: string, sid: string, session: any): void;
}

interface QueryFn {
  (name: string, args: unknown[]): unknown;
}

let autoWarned = false;

/**
 * The bounded window over sealed sign-on sessions.
 */
class SessionWindow {
  private readonly lru: BoundedLru<string, Slot>;
  private readonly negative = new Map<string, number>();
  private readonly byDigest = new Map<string, string>();
  private readonly digestBySid = new Map<string, string>();
  private readonly recentCounts = new Map<string, RecentCount>();
  private cooldownUntil = 0;
  private queryFn: QueryFn | null = null;
  private connectionOf: (() => any) | null = null;
  private bridge: SyncQuery | null = null;
  private touchFlusher: TouchFlusher | null = null;

  /**
   * Builds the window and registers it. It asks the store nothing until a
   * miss, and nothing at all while the setting is off.
   */
  constructor() {
    log.debug("Entering SessionWindow.constructor().");
    const self = this;
    this.lru = new BoundedLru<string, Slot>({
      name: 'authn.session-window',
      title: 'Sign-on session window',
      description: 'The sign-on sessions one process holds when ' +
        'authn.sessionWindow is on (#350). A miss is read from the ' +
        'sealed row. Eviction forgets the memory copy after the upsert ' +
        'has committed and does not end the session.',
      owner: 'authn/session_window.ts',
      scope: 'process',
      settings: ['authn.sessionWindow', 'authn.sessionCacheEntries'],
      registry: cacheRegistry,
      maxEntries: function () {
        return self.cacheBound();
      },
      rowOf: function (key: string) {
        const cut = key.indexOf('\n');
        return { realm: key.slice(0, cut), key: key.slice(cut + 1) };
      },
      onEvict: function (key: string, value: unknown) {
        self.onEvict(key, value as Slot);
      }
    });
    log.debug("Leaving SessionWindow.constructor().");
  }

  // Hot path: every membership test. No Entering/Leaving pair.
  /**
   * Whether the window replaces the full map. `on` and `auto` both require
   * minted persistence, one cell, and a digest key. `digestHeld` is the
   * same fact as `keyColumnOf` returning a digest; that function logs, so
   * this probe does not call it. A null digest is not `enabled()` false.
   *
   * @returns true only when the window may replace the full map
   */
  active(): boolean {
    const setting = String(config.processValue('authn.sessionWindow'));
    if (setting !== 'on' && setting !== 'auto') {
      return false;
    }
    if (!minted.enabled()) {
      return false;
    }
    if (cells.isMulti()) {
      return false;
    }
    return this.digestHeld();
  }

  /**
   * Refuses to start when `on` lacks minted persistence, a single cell, or
   * a digest key. `auto` in that state is logged once and does not throw.
   */
  assertConfigured(): void {
    log.debug("Entering SessionWindow.assertConfigured().");
    const setting = String(config.processValue('authn.sessionWindow'));
    if (setting !== 'on' && setting !== 'auto') {
      log.debug("Leaving SessionWindow.assertConfigured().");
      return;
    }
    const why = this.refusal();
    if (!why) {
      log.debug("Leaving SessionWindow.assertConfigured().");
      return;
    }
    if (setting === 'auto') {
      if (!autoWarned) {
        autoWarned = true;
        log.error(errorCodes.tag('STS-AUTHN-0339') + why);
      }
      log.debug("Leaving SessionWindow.assertConfigured(). Logged.");
      return;
    }
    log.error(errorCodes.tag('STS-AUTHN-0339') + why);
    log.debug("Leaving SessionWindow.assertConfigured().");
    throw new Error(errorCodes.tag('STS-AUTHN-0339') + why);
  }

  /**
   * Keeps the function that can hand the bridge a connection. It does not
   * start a thread: a miss does, and only while the window is on.
   *
   * @param fn - returns the driver's bridge connection, or null
   */
  offerConnection(fn: (() => any) | null): void {
    log.debug("Entering SessionWindow.offerConnection().");
    this.connectionOf = typeof fn === 'function' ? fn : null;
    log.debug("Leaving SessionWindow.offerConnection().");
  }

  /**
   * Installs the answer a test gives instead of the bridge.
   *
   * @param fn - answers a named query, or null to clear it
   */
  setQuery(fn: QueryFn | null): void {
    log.debug("Entering SessionWindow.setQuery().");
    this.queryFn = typeof fn === 'function' ? fn : null;
    log.debug("Leaving SessionWindow.setQuery().");
  }

  /**
   * Installs the write a coalesced touch flushes through. Cleared nowhere:
   * authn registers it once, when the session map exists.
   *
   * @param fn - `sessions.set` inside the session's realm
   */
  setTouchFlusher(fn: TouchFlusher | null): void {
    log.debug("Entering SessionWindow.setTouchFlusher().");
    this.touchFlusher = typeof fn === 'function' ? fn : null;
    log.debug("Leaving SessionWindow.setTouchFlusher().");
  }

  /**
   * Drops what a test planted. The touch flusher and the offered connection
   * stay: both are installed once for the process.
   */
  resetForTests(): void {
    log.debug("Entering SessionWindow.resetForTests().");
    autoWarned = false;
    this.cooldownUntil = 0;
    this.negative.clear();
    this.byDigest.clear();
    this.digestBySid.clear();
    this.recentCounts.clear();
    this.lru.clear();
    this.queryFn = null;
    const bridge = this.bridge;
    this.bridge = null;
    if (bridge) {
      Promise.resolve(bridge.stop()).catch(function (e) {
        log.debug("Caught in SessionWindow.resetForTests(): " +
                  ((e && e.message) || e));
      });
    }
    log.debug("Leaving SessionWindow.resetForTests().");
  }

  // Hot path: every cookie and every cap check. No Entering/Leaving pair.
  /**
   * The session, its absence, or a read that failed. A failure is not
   * absence.
   *
   * @param realmId - the realm
   * @param sid - the session id
   * @returns `{ ok, session }`, `{ absent: true }`, or `{ error: true }`
   */
  get(realmId: string, sid: string): SessionRead {
    const realm = String(realmId || '');
    const id = String(sid || '');
    const key = this.cacheKey(realm, id);
    const hit = this.lru.get(key);
    if (hit && hit.session) {
      return { ok: true, session: hit.session };
    }
    if (this.freshNegative(key)) {
      return { ok: false, absent: true };
    }
    const mapped = this.mapRead(realm, id);
    if (mapped.present && mapped.value != null) {
      this.admit(realm, id, mapped.value, true);
      return { ok: true, session: mapped.value };
    }
    if (Date.now() < this.cooldownUntil) {
      log.debug('session window: a miss is not retried yet.');
      return { ok: false, error: true };
    }
    const digest = this.digestOf(realm, id);
    if (!digest) {
      this.failRead('the minted key is not a digest');
      return { ok: false, error: true };
    }
    return this.opened(realm, id, digest);
  }

  // Hot path: the cap's membership test. No Entering/Leaving pair. It does
  // not admit: a flood of unknown ids must not fill the live cache.
  /**
   * Whether the id is a live session. A read that failed is `'error'`, not
   * absence.
   *
   * @param realmId - the realm
   * @param sid - the session id
   * @returns `'present'`, `'absent'`, or `'error'`
   */
  has(realmId: string, sid: string): Membership {
    const realm = String(realmId || '');
    const id = String(sid || '');
    const key = this.cacheKey(realm, id);
    if (this.lru.has(key)) {
      return 'present';
    }
    const mapped = this.mapRead(realm, id);
    if (mapped.present && mapped.value != null) {
      return 'present';
    }
    if (this.freshNegative(key)) {
      return 'absent';
    }
    // Fail closed before any bridge call. A held or negatively cached id
    // has already answered above. The sweep does not come through here.
    if (Date.now() < this.cooldownUntil) {
      log.debug('session window: a membership read is not retried yet.');
      return 'error';
    }
    const digest = this.digestOf(realm, id);
    if (!digest) {
      this.failRead('the minted key is not a digest');
      return 'error';
    }
    const exists = this.indexAnswer('session.exists', [realm, digest]);
    if (exists === null) {
      return 'error';
    }
    if ((exists as { hit?: boolean }).hit) {
      return 'present';
    }
    let row: any = null;
    try {
      row = this.readBody(realm, digest);
    } catch (e) {
      this.noteReadFailure(e);
      return 'error';
    }
    if (row == null || row.body === TOMBSTONE) {
      this.rememberAbsent(realm, id);
      return 'absent';
    }
    return 'present';
  }

  // Hot path: every sessions.set while the window is on. No
  // Entering/Leaving pair. A throw here must not fail the write.
  /**
   * Pins the row a local write just journalled, or drops it when that write
   * removed the body. It does not call `remove`: the facade already
   * journalled a delete.
   *
   * @param realmId - the realm
   * @param sid - the session id
   */
  noteLocal(realmId: string, sid: string): void {
    if (!this.active()) {
      return;
    }
    try {
      const realm = String(realmId || '');
      const id = String(sid || '');
      const key = this.cacheKey(realm, id);
      const mapped = this.mapRead(realm, id);
      if (!mapped.present || mapped.value == null) {
        this.lru.delete(key);
        this.forgetDigest(realm, id);
        this.rememberAbsent(realm, id);
        return;
      }
      const session = mapped.value;
      this.negative.delete(key);
      this.rememberDigest(realm, id, session);
      const writtenAt = Number(session.lastSeenAt) || Date.now();
      const existing = this.lru.peek(key);
      if (existing && this.lru.isPinned(key)) {
        existing.session = session;
        existing.dirty = true;
        existing.pendingTouch = false;
        existing.writtenAt = writtenAt;
        return;
      }
      if (!this.lru.isPinned(key)) {
        this.lru.pin(key);
      }
      this.lru.set(key, {
        session: session,
        dirty: true,
        pendingTouch: false,
        writtenAt: writtenAt
      });
    } catch (e) {
      log.debug("Caught in SessionWindow.noteLocal(): " +
                ((e && (e as Error).message) || e));
    }
  }

  /**
   * Releases the pin on each upsert that committed and is not journalled
   * again. A coalesced touch is written first and stays pinned.
   *
   * @param upserts - the rows the flush wrote
   */
  onCommitted(upserts: any[]): void {
    log.debug("Entering SessionWindow.onCommitted().");
    try {
      (upserts || []).forEach((row) => {
        this.committedOne(row);
      });
    } catch (e) {
      log.debug("Caught in SessionWindow.onCommitted(): " +
                ((e && (e as Error).message) || e));
    }
    log.debug("Leaving SessionWindow.onCommitted().");
  }

  /**
   * What a replicated row may do to this process's window. A tombstone
   * outranks a pin. A key in neither cache is not admitted.
   *
   * @param realmId - the realm
   * @param sid - the session id
   * @param value - the opened body, or null
   * @param remove - true when the row is a tombstone
   * @returns `'remove'`, `'restore'`, `'keep'`, `'admit'`, or `'skip'`
   */
  considerApply(realmId: string, sid: string, value: any,
                remove: boolean): ApplyDecision {
    log.debug("Entering SessionWindow.considerApply().");
    const realm = String(realmId || '');
    const id = String(sid || '');
    const key = this.cacheKey(realm, id);
    if (remove || value == null) {
      this.lru.delete(key);
      this.forgetDigest(realm, id);
      this.rememberAbsent(realm, id);
      log.debug("Leaving SessionWindow.considerApply(). Removed.");
      return 'remove';
    }
    const slot = this.lru.peek(key);
    if ((slot && slot.dirty) || this.journalledSafe(realm, id)) {
      log.debug("Leaving SessionWindow.considerApply(). Kept.");
      return 'keep';
    }
    const inMap = this.mapRead(realm, id).present;
    if (slot || inMap || this.freshNegative(key)) {
      this.negative.delete(key);
      this.admit(realm, id, value, false);
      const decision: ApplyDecision = inMap ? 'restore' : 'admit';
      log.debug("Leaving SessionWindow.considerApply(). " + decision);
      return decision;
    }
    log.debug("Leaving SessionWindow.considerApply(). Skipped.");
    return 'skip';
  }

  // Hot path: a lastSeenAt touch. No Entering/Leaving pair.
  /**
   * Keeps a touch that is already dirty and less than a second newer than
   * the journalled copy. False means the caller must `sessions.set`.
   *
   * @param realmId - the realm
   * @param sid - the session id
   * @param session - the row, already stamped
   * @returns true when the write was held
   */
  holdTouch(realmId: string, sid: string, session: any): boolean {
    if (!session) {
      return false;
    }
    const key = this.cacheKey(String(realmId || ''), String(sid || ''));
    const slot = this.lru.peek(key);
    if (!slot || !slot.dirty) {
      return false;
    }
    const seen = Number(session.lastSeenAt) || 0;
    const written = Number(slot.writtenAt) || 0;
    if (seen - written >= 1000) {
      return false;
    }
    slot.session = session;
    slot.pendingTouch = true;
    if (!this.lru.isPinned(key)) {
      this.lru.pin(key);
    }
    return true;
  }

  /**
   * How many index rows this realm has, or null when the index could not
   * be read.
   *
   * @param realmId - the realm
   * @returns the count, or null
   */
  count(realmId: string): number | null {
    log.debug("Entering SessionWindow.count().");
    if (Date.now() < this.cooldownUntil) {
      log.debug("Leaving SessionWindow.count(). Cooling.");
      return null;
    }
    const answer = this.indexAnswer('session.count', [String(realmId)]);
    if (answer === null) {
      log.debug("Leaving SessionWindow.count(). Unread.");
      return null;
    }
    const n = Number((answer as { n?: unknown }).n);
    log.debug("Leaving SessionWindow.count().");
    return Number.isFinite(n) ? n : 0;
  }

  /**
   * The realm's count as an admission against `cap` needs it (#754): exact
   * near the cap, and far from it the store's count at most COUNT_FRESH_MS
   * old plus what this process admitted since. `session.count` is a scan of
   * the realm's index rows, so asking it on every sign-in made a sign-in
   * cost O(sessions) — 0.6 ms at 4,500 sessions, about 130 ms at a million.
   *
   * What a cached answer can miss is what OTHER processes admitted within
   * the window, and it is used only while the count plus this process's
   * admissions is more than a margin (the larger of COUNT_MARGIN_MIN and
   * COUNT_MARGIN_SHARE of the cap) below it; within the margin every
   * admission asks again, as it always did. A session ended since is not
   * subtracted, so the cached answer only ever overstates. The overshoot
   * this allows is the other processes' admissions in one window past the
   * margin — the cap was never locked (`makeRoomForSession()`).
   *
   * @param realmId - the realm
   * @param cap - authn.maxSessions, at least 1
   * @returns the count to compare with the cap, or null when unread
   */
  countForAdmission(realmId: string, cap: number): number | null {
    log.debug("Entering SessionWindow.countForAdmission().");
    const realm = String(realmId || '');
    const now = Date.now();
    const margin = Math.max(COUNT_MARGIN_MIN,
                            Math.ceil(cap * COUNT_MARGIN_SHARE));
    const recent = this.recentCounts.get(realm);
    if (recent && now - recent.at < COUNT_FRESH_MS &&
        recent.n + recent.admitted + margin < cap) {
      log.debug("Leaving SessionWindow.countForAdmission(). Recent.");
      return recent.n + recent.admitted;
    }
    const n = this.count(realm);
    if (n === null) {
      log.debug("Leaving SessionWindow.countForAdmission(). Unread.");
      return null;
    }
    this.recentCounts.set(realm, { n: n, at: now, admitted: 0 });
    log.debug("Leaving SessionWindow.countForAdmission(). Asked.");
    return n;
  }

  /**
   * One session admitted in this realm, for `countForAdmission()`.
   *
   * @param realmId - the realm
   */
  noteAdmitted(realmId: string): void {
    log.debug("Entering SessionWindow.noteAdmitted().");
    const recent = this.recentCounts.get(String(realmId || ''));
    if (recent) {
      recent.admitted += 1;
    }
    log.debug("Leaving SessionWindow.noteAdmitted().");
  }

  /**
   * Chosen rows of one subject, oldest first, or null when unread.
   *
   * @param realmId - the realm
   * @param subjectKey - the subject digest
   * @returns the rows, or null
   */
  oldest(realmId: string, subjectKey: string): any[] | null {
    log.debug("Entering SessionWindow.oldest().");
    if (Date.now() < this.cooldownUntil) {
      log.debug("Leaving SessionWindow.oldest(). Cooling.");
      return null;
    }
    const answer = this.indexAnswer('session.oldest',
      [String(realmId), String(subjectKey)]);
    if (answer === null) {
      log.debug("Leaving SessionWindow.oldest(). Unread.");
      return null;
    }
    log.debug("Leaving SessionWindow.oldest().");
    return Array.isArray(answer) ? answer : [];
  }

  /**
   * Digests from one named index query, or null when unread. A request
   * query fails closed while the miss cooldown is in the future and does
   * not call the bridge. `session.expired` is the sweep: it still asks on
   * its own interval.
   *
   * @param name - the query (`session.children` and the same shape)
   * @param args - that query's arguments
   * @returns the digests, or null
   */
  indexKeys(name: string, args: unknown[]): string[] | null {
    log.debug("Entering SessionWindow.indexKeys().");
    if (name !== 'session.expired' && Date.now() < this.cooldownUntil) {
      log.debug("Leaving SessionWindow.indexKeys(). Cooling.");
      return null;
    }
    const answer = this.asKeys(this.indexAnswer(String(name),
      Array.isArray(args) ? args : []));
    log.debug("Leaving SessionWindow.indexKeys().");
    return answer;
  }

  /**
   * Every session digest in the realm, in pages, or null when unread.
   *
   * @param realmId - the realm
   * @returns the digests, or null
   */
  keysOf(realmId: string): string[] | null {
    log.debug("Entering SessionWindow.keysOf().");
    if (Date.now() < this.cooldownUntil) {
      log.debug("Leaving SessionWindow.keysOf(). Cooling.");
      return null;
    }
    const out: string[] = [];
    let after = '';
    for (;;) {
      const page = this.asKeys(this.indexAnswer('session.page',
        [String(realmId), after, PAGE]));
      if (page === null) {
        log.debug("Leaving SessionWindow.keysOf(). Unread.");
        return null;
      }
      page.forEach(function (key) {
        out.push(key);
      });
      if (page.length < PAGE) {
        break;
      }
      const next = page[page.length - 1];
      if (!next || next === after) {
        break;
      }
      after = next;
    }
    log.debug("Leaving SessionWindow.keysOf().");
    return out;
  }

  /**
   * Chosen rows grouped by subject, oldest within each group left to the
   * caller. Null when any page failed.
   *
   * @param realmId - the realm
   * @returns the groups, or null
   */
  chosenBySubject(realmId: string): Array<{ subjectKey: string;
      rows: any[] }> | null {
    log.debug("Entering SessionWindow.chosenBySubject().");
    const all: any[] = [];
    let subject = '';
    let key = '';
    for (;;) {
      const page = this.indexAnswer('session.subjectRows',
        [String(realmId), subject, key]);
      if (page === null) {
        log.debug("Leaving SessionWindow.chosenBySubject(). Unread.");
        return null;
      }
      const rows = Array.isArray(page) ? page : [];
      rows.forEach(function (row) {
        all.push(row);
      });
      if (rows.length < SUBJECT_PAGE) {
        break;
      }
      const last = rows[rows.length - 1] || {};
      const nextSubject = String(last.subjectKey || '');
      const nextKey = String(last.key || '');
      if (nextSubject === subject && nextKey === key) {
        break;
      }
      subject = nextSubject;
      key = nextKey;
    }
    const groups = new Map<string, any[]>();
    all.forEach(function (row) {
      const sk = String(row.subjectKey || '');
      let list = groups.get(sk);
      if (!list) {
        list = [];
        groups.set(sk, list);
      }
      list.push(row);
    });
    const out: Array<{ subjectKey: string; rows: any[] }> = [];
    groups.forEach(function (rows, subjectKey) {
      out.push({ subjectKey: subjectKey, rows: rows });
    });
    log.debug("Leaving SessionWindow.chosenBySubject().");
    return out;
  }

  /**
   * The keyed digest a session id is filed under, or null.
   *
   * @param realmId - the realm
   * @param sid - the session id
   * @returns the digest, or null
   */
  sessionDigest(realmId: string, sid: string): string | null {
    log.debug("Entering SessionWindow.sessionDigest().");
    const out = this.digestOf(String(realmId || ''), String(sid || ''));
    log.debug("Leaving SessionWindow.sessionDigest().");
    return out;
  }

  /**
   * The session filed under a digest. An absent row is not cached: the
   * digest does not name an id to remember.
   *
   * @param realmId - the realm
   * @param digest - the keyed digest
   * @returns the same shape as `get`
   */
  loadByDigest(realmId: string, digest: string): SessionRead {
    log.debug("Entering SessionWindow.loadByDigest().");
    const realm = String(realmId || '');
    const dig = String(digest || '');
    const known = this.byDigest.get(realm + '\n' + dig);
    if (known) {
      const found = this.get(realm, known);
      log.debug("Leaving SessionWindow.loadByDigest().");
      return found;
    }
    if (Date.now() < this.cooldownUntil) {
      log.debug('session window: a digest read is not retried yet.');
      log.debug("Leaving SessionWindow.loadByDigest(). Cooling.");
      return { ok: false, error: true };
    }
    let row: any = null;
    try {
      row = this.readBody(realm, dig);
    } catch (e) {
      this.noteReadFailure(e);
      log.debug("Leaving SessionWindow.loadByDigest(). Unread.");
      return { ok: false, error: true };
    }
    const opened = this.sessionFrom(row);
    if (opened === null) {
      log.debug("Leaving SessionWindow.loadByDigest(). Absent.");
      return { ok: false, absent: true };
    }
    if (!opened || !opened.id) {
      this.failRead('the sealed session would not open');
      log.debug("Leaving SessionWindow.loadByDigest(). Unopened.");
      return { ok: false, error: true };
    }
    const sid = String(opened.id);
    this.admit(realm, sid, opened, false);
    this.byDigest.set(realm + '\n' + dig, sid);
    this.digestBySid.set(this.cacheKey(realm, sid), dig);
    log.debug("Leaving SessionWindow.loadByDigest().");
    return { ok: true, session: opened };
  }

  /**
   * What a test asserts about one slot.
   *
   * @param realmId - the realm
   * @param sid - the session id
   * @returns cached, pinned, dirty, and a fresh negative
   */
  slotState(realmId: string, sid: string): { cached: boolean;
      pinned: boolean; dirty: boolean; negative: boolean } {
    log.debug("Entering SessionWindow.slotState().");
    const key = this.cacheKey(String(realmId || ''), String(sid || ''));
    const slot = this.lru.peek(key);
    const out = {
      cached: !!slot,
      pinned: this.lru.isPinned(key),
      dirty: !!(slot && slot.dirty),
      negative: this.freshNegative(key)
    };
    log.debug("Leaving SessionWindow.slotState().");
    return out;
  }

  // Hot path: active() on every request while the setting is on.
  // No Entering/Leaving pair. keyColumnOf logs, so this probes the digest
  // directly and does not call it.
  private digestHeld(): boolean {
    if (!keystore.sealed() || typeof keystore.keyedDigest !== 'function') {
      return false;
    }
    const realmId = realms.currentId() || 'default';
    const digest = keystore.keyedDigest(NAME_LABEL,
      HANDLE + '\n' + realmId + '\nprobe-sid');
    return !!digest && digest !== 'probe-sid';
  }

  private refusal(): string {
    log.debug("Entering SessionWindow.refusal().");
    if (!minted.enabled()) {
      log.debug("Leaving SessionWindow.refusal().");
      return NOT_ENABLED;
    }
    if (cells.isMulti()) {
      log.debug("Leaving SessionWindow.refusal().");
      return SEVERAL_CELLS;
    }
    const realmId = realms.currentId() || 'default';
    const column = minted.keyColumnOf(HANDLE, realmId, 'probe-sid');
    if (!column || column === 'probe-sid') {
      log.debug("Leaving SessionWindow.refusal().");
      return NOT_A_DIGEST;
    }
    log.debug("Leaving SessionWindow.refusal().");
    return '';
  }

  // Hot path: the bound is asked on every insert. No Entering/Leaving pair.
  private cacheBound(): number {
    return Number(config.processValue('authn.sessionCacheEntries'));
  }

  // Hot path. 0 is legal: the process does not wait and does not cool
  // the next miss down. No Entering/Leaving pair.
  private readTimeout(): number {
    const n = Number(config.processValue('authn.sessionReadTimeoutMs'));
    if (!isFinite(n) || n < 0) {
      return 2000;
    }
    return Math.floor(n);
  }

  // Hot path. No Entering/Leaving pair.
  private cacheKey(realmId: string, sid: string): string {
    return realmId + '\n' + sid;
  }

  // Hot path. No Entering/Leaving pair.
  private splitKey(key: string): { realm: string; sid: string } | null {
    const cut = String(key).indexOf('\n');
    if (cut < 0) {
      return null;
    }
    return { realm: key.slice(0, cut), sid: key.slice(cut + 1) };
  }

  // Hot path. No Entering/Leaving pair.
  private mapRead(realmId: string, sid: string): { present: boolean;
      value: any } {
    try {
      const store = realms.handleFor(HANDLE);
      if (!store || typeof store.read !== 'function') {
        return { present: false, value: null };
      }
      const row = store.read(realmId, sid);
      if (!row || !row.present || row.value == null) {
        return { present: false, value: null };
      }
      return { present: true, value: row.value };
    } catch (e) {
      log.debug("Caught in SessionWindow.mapRead(): " +
                ((e && (e as Error).message) || e));
      return { present: false, value: null };
    }
  }

  // Hot path. No Entering/Leaving pair.
  private freshNegative(key: string): boolean {
    const until = this.negative.get(key);
    if (until === undefined) {
      return false;
    }
    if (until <= Date.now()) {
      this.negative.delete(key);
      return false;
    }
    return true;
  }

  // Hot path. A live session is a different map, so this cannot evict one.
  // No Entering/Leaving pair.
  private rememberAbsent(realmId: string, sid: string): void {
    const key = this.cacheKey(realmId, sid);
    if (this.negative.size >= NEGATIVE_CAP && !this.negative.has(key)) {
      const oldest = this.negative.keys().next().value;
      if (oldest !== undefined) {
        this.negative.delete(oldest);
      }
    }
    this.negative.set(key, Date.now() + NEGATIVE_MS);
  }

  // Hot path. No Entering/Leaving pair. The raw id is not a digest.
  private digestOf(realmId: string, sid: string): string | null {
    if (!sid) {
      return null;
    }
    if (!keystore.sealed() || typeof keystore.keyedDigest !== 'function') {
      return null;
    }
    const digest = keystore.keyedDigest(NAME_LABEL,
      HANDLE + '\n' + realmId + '\n' + sid);
    if (!digest || digest === sid) {
      return null;
    }
    return String(digest);
  }

  // Hot path. No Entering/Leaving pair.
  private rememberDigest(realmId: string, sid: string, session: any): void {
    const digest = this.digestOf(realmId, sid);
    if (!digest) {
      return;
    }
    this.byDigest.set(realmId + '\n' + digest, sid);
    this.digestBySid.set(this.cacheKey(realmId, sid), digest);
    if (session && session.id && String(session.id) !== sid) {
      this.digestBySid.set(this.cacheKey(realmId, String(session.id)),
                           digest);
    }
  }

  // Hot path. No Entering/Leaving pair.
  private forgetDigest(realmId: string, sid: string): void {
    const key = this.cacheKey(realmId, sid);
    const digest = this.digestBySid.get(key);
    this.digestBySid.delete(key);
    if (digest) {
      this.byDigest.delete(realmId + '\n' + digest);
    }
  }

  // Hot path. Pin before set, and only when the row is unwritten: a pin
  // counted twice would outlive the commit. No Entering/Leaving pair.
  private admit(realmId: string, sid: string, session: any,
                fromMap: boolean): void {
    const key = this.cacheKey(realmId, sid);
    const existing = this.lru.peek(key);
    const journalled = this.journalledSafe(realmId, sid);
    let slot: Slot;
    if (existing && (existing.dirty || journalled)) {
      slot = existing;
      if (fromMap) {
        slot.session = session;
      }
    } else if (existing) {
      slot = existing;
      slot.session = session;
      slot.dirty = false;
      slot.pendingTouch = false;
      slot.writtenAt = Number(session && session.lastSeenAt) || 0;
    } else {
      slot = {
        session: session,
        dirty: journalled,
        pendingTouch: false,
        writtenAt: Number(session && session.lastSeenAt) || 0
      };
    }
    if ((journalled || (existing && existing.dirty)) &&
        !this.lru.isPinned(key)) {
      this.lru.pin(key);
    }
    this.negative.delete(key);
    this.rememberDigest(realmId, sid, slot.session);
    this.lru.set(key, slot);
  }

  // Hot path: every eviction and every apply. No Entering/Leaving pair.
  // A throw from the journal is "still journalled": removing would write a
  // tombstone for a row this process still means to keep.
  private journalledSafe(realmId: string, sid: string): boolean {
    try {
      return !!minted.journalled(HANDLE, realmId, sid);
    } catch (e) {
      log.debug("Caught in SessionWindow.journalledSafe(): " +
                ((e && (e as Error).message) || e));
      return true;
    }
  }

  // Hot path: one call per committed upsert. No Entering/Leaving pair.
  private committedOne(row: any): void {
    if (!row || row.handle !== HANDLE) {
      return;
    }
    const sid = String(row.journalKey);
    const realmId = String(row.realm);
    const key = this.cacheKey(realmId, sid);
    const slot = this.lru.peek(key);
    if (!slot) {
      return;
    }
    if (this.journalledSafe(realmId, sid)) {
      return;
    }
    if (slot.pendingTouch) {
      slot.pendingTouch = false;
      if (!this.touchFlusher) {
        slot.pendingTouch = true;
        return;
      }
      try {
        this.touchFlusher(realmId, sid, slot.session);
      } catch (e) {
        log.debug("Caught in SessionWindow.committedOne(): " +
                  ((e && (e as Error).message) || e));
        slot.pendingTouch = true;
      }
      return;
    }
    slot.dirty = false;
    if (this.lru.isPinned(key)) {
      this.lru.unpin(key);
    }
  }

  // Hot path: the bound's eviction. No Entering/Leaving pair. remove() is
  // safe only once the upsert has committed and the key is not journalled;
  // earlier, the flush would seal a tombstone.
  private onEvict(key: string, slot: Slot): void {
    const parts = this.splitKey(key);
    if (!parts) {
      return;
    }
    const realmId = parts.realm;
    const sid = parts.sid;
    if (this.journalledSafe(realmId, sid) ||
        (slot && (slot.dirty || slot.pendingTouch))) {
      this.putBack(key, slot, realmId, sid);
      return;
    }
    try {
      const store = realms.handleFor(HANDLE);
      if (store && typeof store.remove === 'function') {
        store.remove(realmId, sid);
      }
      this.forgetDigest(realmId, sid);
    } catch (e) {
      log.debug("Caught in SessionWindow.onEvict(): " +
                ((e && (e as Error).message) || e));
      this.putBack(key, slot, realmId, sid);
    }
  }

  // Hot path. No Entering/Leaving pair.
  private putBack(key: string, slot: Slot, realmId: string,
                  sid: string): void {
    if (slot && slot.pendingTouch && this.touchFlusher) {
      slot.pendingTouch = false;
      try {
        this.touchFlusher(realmId, sid, slot.session);
        return;
      } catch (e) {
        log.debug("Caught in SessionWindow.putBack(): " +
                  ((e && (e as Error).message) || e));
        slot.pendingTouch = true;
      }
    }
    if (!this.lru.isPinned(key)) {
      this.lru.pin(key);
    }
    this.lru.set(key, slot);
  }

  // Hot path: every miss. No Entering/Leaving pair.
  private opened(realm: string, id: string, digest: string): SessionRead {
    let row: any = null;
    try {
      row = this.readBody(realm, digest);
    } catch (e) {
      this.noteReadFailure(e);
      return { ok: false, error: true };
    }
    const session = this.sessionFrom(row);
    if (session === null) {
      this.rememberAbsent(realm, id);
      return { ok: false, absent: true };
    }
    if (!session) {
      this.failRead('the sealed session would not open');
      return { ok: false, error: true };
    }
    const heldId = String(session.id || id);
    this.admit(realm, heldId, session, false);
    return { ok: true, session: session };
  }

  // Hot path: every miss. No Entering/Leaving pair. null is absence.
  // undefined is a body that would not open: not absence, and not a
  // negative entry.
  private sessionFrom(row: any): any {
    if (row == null || row.body === TOMBSTONE) {
      return null;
    }
    if (row.session && typeof row.session === 'object') {
      return row.session;
    }
    if (row.body == null) {
      return null;
    }
    let text: any = null;
    try {
      text = keystore.open(row.body, 'minted-rows');
    } catch (e) {
      log.debug("Caught in SessionWindow.sessionFrom(): " +
                ((e && (e as Error).message) || e));
      return undefined;
    }
    if (text == null) {
      return undefined;
    }
    try {
      const parsed = JSON.parse(String(text));
      if (!parsed || typeof parsed !== 'object') {
        return undefined;
      }
      return parsed;
    } catch (e) {
      log.debug("Caught in SessionWindow.sessionFrom(): " +
                ((e && (e as Error).message) || e));
      return undefined;
    }
  }

  // Hot path. No Entering/Leaving pair. A missing bridge is a read failure
  // and does not arm the cooldown: there is nothing to cool down from.
  private readBody(realm: string, digest: string): unknown {
    if (this.queryFn) {
      return this.queryFn('session.read', [realm, digest]);
    }
    this.ensureBridge();
    if (!this.bridge) {
      const err: any = new Error('no session bridge');
      err.noBridge = true;
      throw err;
    }
    return this.bridge.query('session.read', [realm, digest]);
  }

  // Hot path: a failed miss. No Entering/Leaving pair.
  private noteReadFailure(e: any): void {
    const why = (e && e.message) || e;
    if (!(e && e.noBridge)) {
      this.cooldownUntil = Date.now() + this.readTimeout();
    }
    this.failRead(String(why));
  }

  // Hot path: a failed read. No Entering/Leaving pair. The code is logged
  // and is not returned to a client.
  private failRead(why: string): void {
    log.error(errorCodes.tag('STS-AUTHN-0338') +
      'authn: a session could not be read: ' + why);
  }

  // Hot path: has() and every index walk. No Entering/Leaving pair. A
  // driver or timeout failure arms the same cooldown as a body read. A
  // missing bridge does not: there is nothing to cool down from. The
  // sweep does not consult the timestamp, so it still asks on its interval.
  private indexAnswer(name: string, args: unknown[]): unknown {
    try {
      if (this.queryFn) {
        return this.queryFn(name, args);
      }
      this.ensureBridge();
      if (!this.bridge) {
        this.failRead('no session bridge');
        return null;
      }
      return this.bridge.query(name, args);
    } catch (e) {
      log.debug("Caught in SessionWindow.indexAnswer(): " +
                ((e && (e as Error).message) || e));
      this.noteReadFailure(e);
      return null;
    }
  }

  // Hot path: every index page. No Entering/Leaving pair.
  private asKeys(answer: unknown): string[] | null {
    if (answer === null || answer === undefined) {
      return null;
    }
    return Array.isArray(answer) ? answer.map(function (key) {
      return String(key);
    }) : [];
  }

  // Hot path. No Entering/Leaving pair. The thread starts on the first miss.
  private ensureBridge(): void {
    if (this.bridge || this.queryFn || !this.connectionOf) {
      return;
    }
    let connection: any = null;
    try {
      connection = this.connectionOf();
    } catch (e) {
      log.debug("Caught in SessionWindow.ensureBridge(): " +
                ((e && (e as Error).message) || e));
      return;
    }
    if (!connection) {
      return;
    }
    const self = this;
    this.bridge = new SyncQuery({
      connection: connection,
      timeoutMs: function () {
        return self.readTimeout();
      },
      queries: '../persistence/session_queries.js',
      timeoutCode: 'STS-AUTHN-0338',
      refusedCode: 'STS-AUTHN-0338',
      threadErrorCode: 'STS-AUTHN-0338'
    });
  }
}

const sessionWindow = new SessionWindow();
export = sessionWindow;
