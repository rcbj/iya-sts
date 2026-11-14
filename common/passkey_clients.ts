// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_clients.ts
//
// ---------------------------------------------------------------------------
// THE CLIENTS A PASSKEY REGISTRATION OFFERS NO ML-DSA (#1112, 2026-10-28).
//
// The offered list is ML-DSA first, and some platforms fail the WHOLE
// registration when offered an algorithm the authenticator cannot do,
// rather than taking the next one. #944 offers a classical retry after such
// a failure; this avoids the failure where the client is known to fail. A
// registration from such a client is offered the list less ML-DSA — #944's
// classical retry, armed from the start — and the ceremony row says so.
// rcbj's decision: BOTH halves.
//
//   * CONFIGURED: the passkey policy's `clientRules` row, on the default and
//     named profiles, empty by default (`passkey_policy.ts`'s
//     `clientRuleFor()`, which matches a rule against the client name).
//   * LEARNED: a per-realm switch, `webauthn.clientLearning`, OFF by
//     default. After `webauthn.clientLearningFailures` different people's
//     registrations from one client asked for ML-DSA and failed with
//     NotSupportedError within `webauthn.clientLearningWindowHours`, and
//     none from it succeeded, the realm stops offering ML-DSA to that
//     client. The entries are this module's store; Directory → Policies →
//     Passkey policy lists them, paged, and `GET /admin-api/policies`
//     answers the same page; each can be cleared, or all.
//
// THE CLIENT IS THE CEREMONY ROW'S CLIENT NAME, AND THERE IS ONE READING OF
// THE HEADER. `authn/webauthn_ceremonies.ts`'s `clientOf()` turns a
// User-Agent into `Chrome 141 on macOS 15` — family and major version of
// the browser and the system, nothing finer — for every ceremony row; this
// module asks it for the request's name, keys the learned entries by it,
// and `passkey_policy.ts` matches the configured rules against it. So what
// was learned, what was configured and what the rows show name a client the
// same way, and a second parser that could disagree does not exist. A name
// whose browser AND system could not be read (`a browser on another
// system`) is never learned and never matched except by `* on *`.
//
// ---------------------------------------------------------------------------
// WHERE A FAILURE IS COUNTED: WHERE THE CEREMONY ROW IS WRITTEN, ONCE.
//
// `webauthn_ceremonies.record()` is the one funnel every registration door
// reaches — the passkey step, `/portal/keys`, an activation link, an
// administrator's enrolment, the upgrade — and it already holds what the
// count needs: the ceremony, the outcome, the browser's error name, the
// algorithms offered and the client. So it hands them here (`observe()`)
// as it writes the row, and the count is an INCREMENT to one small entry
// per client. The alternatives were worse:
//
//   * reading the audit rows at a registration would be a scan per
//     request, of a log that is per process and capped;
//   * a scheduler job over the rows would see only the rows of the process
//     it ran in (the audit log is not a shared store), would learn late by
//     its period, and would still be a scan.
//
// The increment is cheap (one get and one set of a bounded entry), is made
// only while the switch is on, only for a registration that asked for
// ML-DSA, and only for its two interesting outcomes: NotSupportedError
// (counted) and success (the entry removed — the way back). Everything else
// — NotAllowedError, a cancel, a timeout — says nothing about the
// algorithm and is ignored. The periodic half is a scheduler job,
// `passkeys.client-learning-sweep` (cluster, per realm, hourly), which
// removes the entries whose failures have all aged out of the window; the
// window is also applied at every count, which is the correctness half.
//
// ---------------------------------------------------------------------------
// WHAT IS COUNTED, AND WHY PEOPLE AND NOT ATTEMPTS. A failure is recorded
// with a digest of the person, and a person counts once in the window
// however often they try: a registration is a ceremony any signed-in
// person can start, so counting attempts would let one account teach the
// realm to stop offering ML-DSA to everybody on that browser. The digest
// (16 hex digits of SHA-256, `crypto.js`) keeps the name out of the entry.
// The entry is still an observation of this cell's own traffic, so the
// store is CELL-tier (`persistence/tiers.js`), as `attribute_sources.status`
// is. A success removes the entry, so "and none succeeded" holds by
// construction: a success between two failures starts the count again.
//
// SEVERAL NODES. The entry is a row of a minted store, so every node reads
// what any node learned. Two nodes counting the same client within the
// replication lag may each write the entry they read, and the later write
// wins: a failure can be lost, which delays learning by one failure, and
// nothing can be learned that was not observed.
//
// THE STORE IS BOUNDED (`MAX_ENTRIES` per realm): a client name comes from a
// header anybody sets. A new client at the bound displaces the entry not yet
// learned that failed longest ago; with every entry learned, the new one is
// not counted (STS-AUTHN-0478, logged once per realm per process).
//
// ---------------------------------------------------------------------------
// NEVER WHERE A CLASSICAL KEY IS NOT ALLOWED. `offerFor()` asks
// `webauthn_policy.ts`'s `classicalRetryRefusal()` — the one statement of
// where a classical passkey may be made: `registrationMode: pq-only`,
// `webauthn.pqcOnly`, `postQuantumRequired: registration-and-sign-in`, and
// at the sign-in step `postQuantumRequired: sign-in` (whose new classical
// key would be refused at the session's start). There, and for the
// post-quantum lane (whose list less ML-DSA is nothing), the offer is
// unchanged and the row records the rule as NOT APPLIED and why. A
// registration that asks for no ML-DSA anyway is nothing to narrow and
// records nothing. The upgrade and the post-login migration never ask:
// their point is ML-DSA; their failures still count.
//
// A LIBRARY (rule 3): it registers no route. It requires `helpers`,
// `realms`, `config`, `audit`, `error_codes`, `passkey_policy` and
// `instance_slot`, none of which requires it; the ceremonies module (which
// requires this one), the WebAuthn policy, `crypto.js` and the scheduler
// are reached lazily.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import config = require('./config');
import audit = require('./audit');
import errorCodes = require('./error_codes');
import passkeyPolicy = require('./passkey_policy');
import InstanceSlot = require('./instance_slot');

const { log } = helpers;

type Json = any;

/** The store's handle. */
const STORE_HANDLE = 'passkey_clients.learned';
/** The scheduler job that removes entries whose failures aged out. */
const SWEEP_JOB = 'passkeys.client-learning-sweep';
/** The most entries one realm holds. */
const MAX_ENTRIES = 500;
/** The most failures one entry keeps (the threshold's own bound). */
const MAX_FAILURES = 50;
/** The page sizes the list offers. */
const PER_DEFAULT = 25;
const PER_MAX = 200;
const HOUR_MS = 60 * 60 * 1000;
/** The browser's error name that counts. */
const COUNTED_ERROR = 'NotSupportedError';
/** The acts this module answers, as the passkey policy's kind names them. */
const CLEAR_ONE = 'clear-passkey-client';
const CLEAR_ALL = 'clear-passkey-clients';

// ---------------------------------------------------------------------------
// THE STORE: client name → `{ failures: [{ at, who }], firstAt, lastAt,
// learnedAt, learnedFailures }`, times in milliseconds, `who` a digest.
// Declared here, per realm, and nowhere else. Every write is a NEW object,
// never the held one changed in place: a row changed in place is never
// journalled (#999).
// ---------------------------------------------------------------------------
// The handle is written out, not STORE_HANDLE: `tests/cell_tiers.js` reads
// every `persist:` literal in the tree.
const learned = realms.map({ persist: 'passkey_clients.learned' });

interface Store {
  get(key: string): Json;
  set(key: string, value: Json): unknown;
  delete(key: string): boolean;
  has(key: string): boolean;
  clear(): void;
  forEach(fn: (value: Json, key: string) => void): void;
  readonly size: number;
}

/**
 * What `offerFor()` decided for one registration.
 */
interface Decision {
  // Whether ML-DSA is left out of this registration's offer.
  narrowed: boolean;
  // `configured` or `learned`: which half named the client; '' for none.
  by: string;
  // The configured rule's text, or the learned client's name.
  rule: string;
  // Why a rule that named the client was not applied, or ''.
  notApplied: string;
  // The client name of the request.
  client: string;
  // What the ceremony row records (`webauthn_ceremonies.record()`'s
  // `narrowed`): '' where no rule named the client.
  record: string;
}

interface PasskeyClientsDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  realms: Json;
  config: Json;
  audit: Json;
  passkeyPolicy: Json;
  store: Store;
  // The ceremony row's client name for a User-Agent (lazily: that module
  // requires this one).
  clientOf(userAgent: unknown): string;
  // The WebAuthn policy (lazily: it is built after this module's load).
  webauthnPolicy(): Json;
  digest(text: string): string;
  scheduler(): Json;
  now(): number;
}

/**
 * The clients a passkey registration offers no ML-DSA (#1112): the
 * configured rules' answer, the learned register and its counting.
 */
class PasskeyClients {
  /** The store's handle. */
  static readonly STORE_HANDLE = STORE_HANDLE;
  /** The sweep job. */
  static readonly SWEEP_JOB = SWEEP_JOB;
  /** The most entries one realm holds. */
  static readonly MAX_ENTRIES = MAX_ENTRIES;
  /** The largest page the list answers. */
  static readonly PER_MAX = PER_MAX;

  // Realms whose full register was already said once in this process.
  private readonly fullSaid = new Set<string>();

  /**
   * Builds the register over its dependencies.
   *
   * @param deps - the logger, the error codes, the realms, the settings,
   *   the audit log, the passkey policy, the store and the lazy loaders
   */
  constructor(private readonly deps: PasskeyClientsDeps) {
    deps.log.debug("Entering PasskeyClients.constructor().");
    deps.log.debug("Leaving PasskeyClients.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): PasskeyClientsDeps {
    log.debug("Entering PasskeyClients.defaultDeps().");
    log.debug("Leaving PasskeyClients.defaultDeps().");
    return {
      log: log, errorCodes: errorCodes, realms: realms, config: config,
      audit: audit, passkeyPolicy: passkeyPolicy,
      store: learned as unknown as Store,
      clientOf: function (userAgent: unknown): string {
        return require('../authn/webauthn_ceremonies').clientOf(userAgent);
      },
      webauthnPolicy: function (): Json {
        return require('../authn/webauthn_policy');
      },
      // crypto.js is the one place that hashes (#453); lazily, so loading
      // this module does not load it before the composition root built it.
      digest: function (text: string): string {
        return require('./crypto').digest('sha256', text, 'hex')
          .slice(0, 16);
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE SETTINGS, read where they are used (runtime, per realm).
  // -------------------------------------------------------------------------
  /**
   * Says whether this realm learns which clients cannot make an ML-DSA
   * passkey (`webauthn.clientLearning`).
   *
   * @returns true while the switch is on
   */
  learning(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering PasskeyClients.learning().");
    const out = config.value('webauthn.clientLearning') === true;
    log.debug("Leaving PasskeyClients.learning(). " + out);
    return out;
  }

  private threshold(): number {
    const { log, config } = this.deps;
    log.debug("Entering PasskeyClients.threshold().");
    const raw = Number(config.value('webauthn.clientLearningFailures'));
    log.debug("Leaving PasskeyClients.threshold().");
    return Number.isFinite(raw) && raw >= 1
      ? Math.min(Math.floor(raw), MAX_FAILURES) : 3;
  }

  private windowMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering PasskeyClients.windowMs().");
    const raw = Number(config.value('webauthn.clientLearningWindowHours'));
    log.debug("Leaving PasskeyClients.windowMs().");
    return (Number.isFinite(raw) && raw >= 1 ? raw : 168) * HOUR_MS;
  }

  // Whether a client name names anything a rule could be about: its
  // browser or its system was read.
  private identifiable(client: string): boolean {
    const { log, passkeyPolicy } = this.deps;
    log.debug("Entering PasskeyClients.identifiable().");
    const parts = passkeyPolicy.clientParts(client);
    log.debug("Leaving PasskeyClients.identifiable().");
    return !!parts && !!(parts.browser || parts.system);
  }

  /**
   * The ceremony row's client name for a request: the given one, or the
   * request this code runs for (`audit.currentRequest()`).
   *
   * @param req - the request, where the caller holds it
   * @returns the client name, or '' with no User-Agent
   */
  clientOfRequest(req?: Json): string {
    const { log, audit, clientOf } = this.deps;
    log.debug("Entering PasskeyClients.clientOfRequest().");
    const r = req || audit.currentRequest() || null;
    const out = String(clientOf(r && r.headers
      ? r.headers['user-agent'] : '') || '');
    log.debug("Leaving PasskeyClients.clientOfRequest().");
    return out;
  }

  /**
   * Whether a learned entry stops ML-DSA being offered now: the switch is
   * on and the entry was learned.
   *
   * @param client - the client name
   * @returns true where it does
   */
  learnedFor(client: string): boolean {
    const { log, store } = this.deps;
    log.debug("Entering PasskeyClients.learnedFor().");
    const entry = client && this.learning() ? store.get(client) : null;
    const out = !!(entry && entry.learnedAt);
    log.debug("Leaving PasskeyClients.learnedFor(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE DECISION, at the door that arms a registration: the passkey step's
  // options (`authn.ts`'s `mfaWebauthnOptions()`), `beginKeyEnrolment()`
  // (`/portal/keys`, an activation link) and an administrator's enrolment.
  // The caller selected the person's passkey profile first, so the
  // configured rules and the refusal below are that profile's.
  // -------------------------------------------------------------------------
  /**
   * Decides whether a registration about to be armed leaves ML-DSA out of
   * its offer (#1112).
   *
   * @param input - `{ at, lane, req }`: `sign-in` for the passkey step
   *   (whose registration signs the person in at once), anything else for
   *   the other doors; the lane asked for; the request
   * @returns the decision, `record` the ceremony row's words
   */
  offerFor(input?: { at?: string; lane?: string; req?: Json }): Decision {
    const { log, passkeyPolicy } = this.deps;
    log.debug("Entering PasskeyClients.offerFor().");
    const given = input || {};
    const none: Decision = { narrowed: false, by: '', rule: '',
                             notApplied: '', client: '', record: '' };
    try {
      const client = this.clientOfRequest(given.req);
      none.client = client;
      if (!client) {
        log.debug("Leaving PasskeyClients.offerFor(). No client.");
        return none;
      }
      const configured = String(passkeyPolicy.clientRuleFor(client) || '');
      const by = configured ? 'configured'
        : (this.learnedFor(client) ? 'learned' : '');
      if (!by) {
        log.debug("Leaving PasskeyClients.offerFor(). No rule.");
        return none;
      }
      const rule = configured || client;
      const policy = this.deps.webauthnPolicy();
      const lane = String(given.lane || '');
      // NOTHING TO NARROW: the offer names no ML-DSA already.
      if (!policy.asksPostQuantum(lane)) {
        log.debug("Leaving PasskeyClients.offerFor(). No ML-DSA offered.");
        return none;
      }
      const refusal = policy.classicalRetryRefusal(
        given.at === 'sign-in' ? 'sign-in' : undefined);
      const notApplied = lane === 'pqc' && policy.alongsideClassical()
        ? 'the post-quantum lane'
        : (refusal && refusal.ok === false
          ? String(refusal.reason || 'a classical passkey is not allowed')
          : '');
      const out: Decision = {
        narrowed: !notApplied, by: by, rule: rule, notApplied: notApplied,
        client: client,
        record: (notApplied ? 'not applied (' + notApplied + '): ' : '') +
                by + ': ' + rule };
      log.debug("Leaving PasskeyClients.offerFor(). " + out.record);
      return out;
    } catch (e) {
      // The offer as it stands is always safe: a rule that cannot be asked
      // narrows nothing, and the registration goes on as before #1112.
      log.debug("Caught in PasskeyClients.offerFor(): " +
                ((e && e.message) || e));
      log.debug("Leaving PasskeyClients.offerFor(). Not decided.");
      return none;
    }
  }

  // -------------------------------------------------------------------------
  // THE COUNT, from `webauthn_ceremonies.record()` (see the header).
  // -------------------------------------------------------------------------
  /**
   * Counts one registration towards its client's entry (#1112): a
   * NotSupportedError from a registration that asked for ML-DSA is a
   * failure; a success that asked for it removes the entry. Never throws.
   *
   * @param event - `{ ceremony, outcome, clientError, offered (names),
   *   client, username }`
   * @returns `counted`, `learned`, `cleared` or `ignored`
   */
  observe(event: { ceremony?: string; outcome?: string;
                   clientError?: string; offered?: string[];
                   client?: string; username?: string }): string {
    const { log, passkeyPolicy, store } = this.deps;
    log.debug("Entering PasskeyClients.observe().");
    try {
      const e = event || {};
      const client = String(e.client || '');
      const asked = (Array.isArray(e.offered) ? e.offered : [])
        .some(function (name: string): boolean {
          return passkeyPolicy.isPostQuantum(String(name));
        });
      if (!this.learning() || e.ceremony !== 'registration' || !asked ||
          !this.identifiable(client)) {
        log.debug("Leaving PasskeyClients.observe(). Ignored.");
        return 'ignored';
      }
      if (e.outcome === 'success') {
        const held = store.get(client);
        if (!held) {
          log.debug("Leaving PasskeyClients.observe(). Nothing held.");
          return 'ignored';
        }
        store.delete(client);
        if (held.learnedAt) {
          // A STATE CHANGE, so a line: the client is offered ML-DSA again.
          log.info('passkey clients: a registration from ' + client +
                   ' made a passkey after being offered ML-DSA, so this ' +
                   'realm offers it ML-DSA again.');
        }
        log.debug("Leaving PasskeyClients.observe(). Cleared.");
        return 'cleared';
      }
      const who = String(e.username || '').trim().toLowerCase();
      if (String(e.clientError || '') !== COUNTED_ERROR || !who) {
        log.debug("Leaving PasskeyClients.observe(). Not counted.");
        return 'ignored';
      }
      const out = this.countFailure(client, this.deps.digest(who));
      log.debug("Leaving PasskeyClients.observe(). " + out);
      return out;
    } catch (err) {
      // Evidence, never the ceremony: a count that could not be made leaves
      // the registration as it was.
      log.debug("Caught in PasskeyClients.observe(): " +
                ((err && err.message) || err));
      log.debug("Leaving PasskeyClients.observe(). Not counted.");
      return 'ignored';
    }
  }

  // One failure from one person, against one client.
  private countFailure(client: string, who: string): string {
    const { log, store, realms, audit, errorCodes } = this.deps;
    log.debug("Entering PasskeyClients.countFailure().");
    const now = this.deps.now();
    const since = now - this.windowMs();
    let held = store.get(client);
    if (!held && store.size >= MAX_ENTRIES && !this.makeRoom(since)) {
      const realmId = String(realms.currentId() || '');
      if (!this.fullSaid.has(realmId)) {
        this.fullSaid.add(realmId);
        log.warn(errorCodes.tag('STS-AUTHN-0478') + 'passkey clients: the ' +
                 'learned clients of this realm are at their bound of ' +
                 MAX_ENTRIES + ', every one learned; ' + client + ' and ' +
                 'any other new client are not counted until one is ' +
                 'cleared.');
      }
      log.debug("Leaving PasskeyClients.countFailure(). Full.");
      return 'ignored';
    }
    held = held || {};
    const failures = (Array.isArray(held.failures) ? held.failures : [])
      .filter(function (one: Json): boolean {
        return one && Number(one.at) >= since && one.who !== who;
      }).concat([{ at: now, who: who }]).slice(-MAX_FAILURES);
    const entry = {
      failures: failures,
      firstAt: Number(held.firstAt) || now,
      lastAt: now,
      learnedAt: Number(held.learnedAt) || 0,
      learnedFailures: Number(held.learnedFailures) || 0
    };
    let out = 'counted';
    if (!entry.learnedAt && failures.length >= this.threshold()) {
      entry.learnedAt = now;
      entry.learnedFailures = failures.length;
      out = 'learned';
    }
    store.set(client, entry);
    if (out === 'learned') {
      // A STATE CHANGE: one row and one line per client learned, never one
      // per failure (those are the ceremony rows).
      audit.audit({
        action: 'webauthn.client.learned', category: 'authentication',
        outcome: 'success', actor: '', target: client, channel: 'http',
        protocol: 'WebAuthn',
        summary: 'this realm stopped offering ML-DSA at passkey ' +
                 'registration to ' + client + ': ' + failures.length +
                 ' people\'s registrations from it failed with ' +
                 'NotSupportedError, and none succeeded, within the window',
        detail: { client: client, failures: failures.length,
                  windowHours: Math.round(this.windowMs() / HOUR_MS) }
      });
      log.info('passkey clients: this realm stopped offering ML-DSA to ' +
               client + ' after ' + failures.length + ' people\'s ' +
               'registrations from it failed with NotSupportedError.');
    }
    log.debug("Leaving PasskeyClients.countFailure(). " + out);
    return out;
  }

  // At the bound: drop the entry not yet learned that failed longest ago.
  private makeRoom(since: number): boolean {
    const { log, store } = this.deps;
    log.debug("Entering PasskeyClients.makeRoom().");
    let oldest = '';
    let oldestAt = Infinity;
    store.forEach(function (value: Json, key: string): void {
      if (value && !value.learnedAt) {
        const at = Number(value.lastAt) || 0;
        if (at < oldestAt) {
          oldestAt = at;
          oldest = key;
        }
      }
    });
    if (oldest) {
      store.delete(oldest);
    }
    log.debug("Leaving PasskeyClients.makeRoom(). " +
              (oldest ? 'Dropped one' + (oldestAt < since ? ', aged out.'
                                                         : '.')
                      : 'Nothing to drop.'));
    return !!oldest;
  }

  // -------------------------------------------------------------------------
  // THE LIST, for Directory → Policies → Passkey policy and its operation.
  // -------------------------------------------------------------------------
  /**
   * This realm's learned clients, a page at a time: learned first (newest
   * first), then the clients still being counted (latest failure first).
   *
   * @param query - `clientsPage` and `clientsPer`
   * @returns `{ learning, threshold, windowHours, bound, rows, paging }`
   */
  view(query?: Json): Json {
    const { log, store } = this.deps;
    log.debug("Entering PasskeyClients.view().");
    const q = query || {};
    const one = function (value: unknown): string {
      return String(Array.isArray(value) ? value[0] : (value || ''));
    };
    const since = this.deps.now() - this.windowMs();
    const rows: Json[] = [];
    store.forEach(function (value: Json, key: string): void {
      const inWindow = (Array.isArray(value && value.failures)
        ? value.failures : []).filter(function (f: Json): boolean {
          return f && Number(f.at) >= since;
        }).length;
      rows.push({
        client: key,
        learned: !!(value && value.learnedAt),
        learnedAt: value && value.learnedAt
          ? new Date(Number(value.learnedAt)).toISOString() : '',
        learnedFailures: Number(value && value.learnedFailures) || 0,
        failures: inWindow,
        firstAt: value && value.firstAt
          ? new Date(Number(value.firstAt)).toISOString() : '',
        lastAt: value && value.lastAt
          ? new Date(Number(value.lastAt)).toISOString() : '' });
    });
    rows.sort(function (a: Json, b: Json): number {
      if (a.learned !== b.learned) {
        return a.learned ? -1 : 1;
      }
      const ak = a.learned ? a.learnedAt : a.lastAt;
      const bk = b.learned ? b.learnedAt : b.lastAt;
      return ak < bk ? 1 : (ak > bk ? -1 : (a.client < b.client ? -1 : 1));
    });
    const perRaw = parseInt(one(q.clientsPer), 10);
    const per = perRaw >= 1 ? Math.min(perRaw, PER_MAX) : PER_DEFAULT;
    const pages = Math.max(1, Math.ceil(rows.length / per));
    const pageRaw = parseInt(one(q.clientsPage), 10);
    const page = pageRaw >= 1 ? Math.min(pageRaw, pages) : 1;
    const out = {
      learning: this.learning(),
      threshold: this.threshold(),
      windowHours: Math.round(this.windowMs() / HOUR_MS),
      bound: MAX_ENTRIES,
      learnedCount: rows.filter(function (r: Json): boolean {
        return r.learned;
      }).length,
      rows: rows.slice((page - 1) * per, page * per),
      paging: { page: page, per: per, pages: pages, total: rows.length },
      actions: { clear: CLEAR_ONE, clearAll: CLEAR_ALL }
    };
    log.debug("Leaving PasskeyClients.view(). " + rows.length + " row(s).");
    return out;
  }

  /**
   * Clears one learned client, or all (#1112): the passkey policy kind's
   * acts, which Directory → Policies and `POST /admin-api/policies/{action}`
   * reach through `policiesAction()`.
   *
   * @param action - `clear-passkey-client` or `clear-passkey-clients`
   * @param body - `{ client }` for the first
   * @returns `{ ok, removed, message }`, or a refusal with STS-AUTHN-0477
   */
  act(action: string, body: Json): Json {
    const { log, store, errorCodes } = this.deps;
    log.debug("Entering PasskeyClients.act(). " + action);
    const b = body || {};
    if (action === CLEAR_ALL) {
      const removed = store.size;
      store.clear();
      log.info('passkey clients: every learned client of this realm was ' +
               'cleared (' + removed + ').');
      log.debug("Leaving PasskeyClients.act(). All cleared.");
      return { ok: true, action: action, removed: removed, dn: '',
               message: removed + ' learned client(s) cleared: every client ' +
                        'is offered the list as it stands.' };
    }
    const client = String(b.client || '').trim();
    if (action !== CLEAR_ONE || !client || !store.has(client)) {
      log.debug("Leaving PasskeyClients.act(). Not listed.");
      return errorCodes.mark({ ok: false, errors: [client
        ? '"' + client.slice(0, 80) + '" is not one of this realm\'s ' +
          'learned passkey clients; name it exactly as the list shows it.'
        : 'Name the learned client to clear (`client`).'] },
        'STS-AUTHN-0477');
    }
    store.delete(client);
    log.info('passkey clients: ' + client + ' was cleared, and is offered ' +
             'ML-DSA again where the list names it.');
    log.debug("Leaving PasskeyClients.act(). Cleared.");
    return { ok: true, action: action, client: client, removed: 1, dn: '',
             message: client + ' was cleared: its next registration is ' +
                      'offered the list as it stands.' };
  }

  // -------------------------------------------------------------------------
  // THE SWEEP: the scheduler job's body, in the realm it runs for.
  // -------------------------------------------------------------------------
  /**
   * Removes this realm's entries not learned whose failures have all aged
   * out of the window (#1112). A learned entry is kept: it ends with a
   * success or a clear.
   *
   * @returns `{ removed, kept }`
   */
  sweep(): Json {
    const { log, store } = this.deps;
    log.debug("Entering PasskeyClients.sweep().");
    const since = this.deps.now() - this.windowMs();
    const stale: string[] = [];
    store.forEach(function (value: Json, key: string): void {
      if (!value || (!value.learnedAt &&
                     !(Number(value.lastAt) >= since))) {
        stale.push(key);
      }
    });
    stale.forEach(function (key: string): void {
      store.delete(key);
    });
    const out = { removed: stale.length, kept: store.size };
    log.debug("Leaving PasskeyClients.sweep(). " + stale.length +
              " removed.");
    return out;
  }

  /**
   * Registers the sweep job with the scheduler, once per process.
   *
   * @returns true when registered, false when it already was
   */
  registerJobs(): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyClients.registerJobs().");
    const s = this.deps.scheduler();
    if (s.job(SWEEP_JOB)) {
      log.debug("Leaving PasskeyClients.registerJobs(). Already there.");
      return false;
    }
    const self = this;
    s.register({
      id: SWEEP_JOB,
      title: 'Learned passkey clients sweep',
      describe: 'Removes the learned passkey clients (#1112) whose ' +
                'failures have all aged out of ' +
                'webauthn.clientLearningWindowHours and that were never ' +
                'learned. A client already learned is kept until a ' +
                'registration from it succeeds or it is cleared.',
      owner: 'common/passkey_clients.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return HOUR_MS;
      },
      manual: true,
      timeoutS: 300,
      run: function (): Json {
        return self.sweep();
      }
    });
    log.debug("Leaving PasskeyClients.registerJobs().");
    return true;
  }
}

const slot = new InstanceSlot<PasskeyClients>(
  'common/passkey_clients',
  () => new PasskeyClients(PasskeyClients.defaultDeps()),
  function (instance: PasskeyClients): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The clients a passkey registration offers no ML-DSA (#1112). The exports
 * forward to the instance the composition root installs.
 *
 * @namespace
 */
export = {
  PasskeyClients: PasskeyClients,
  installInstance: (instance: PasskeyClients): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  STORE_HANDLE: STORE_HANDLE,
  SWEEP_JOB: SWEEP_JOB,
  MAX_ENTRIES: MAX_ENTRIES,
  PER_MAX: PER_MAX,
  learning: slot.forward('learning'),
  learnedFor: slot.forward('learnedFor'),
  clientOfRequest: slot.forward('clientOfRequest'),
  offerFor: slot.forward('offerFor'),
  observe: slot.forward('observe'),
  view: slot.forward('view'),
  act: slot.forward('act'),
  sweep: slot.forward('sweep'),
  registerJobs: slot.forward('registerJobs')
};
