'use strict';
//
// File: enrollment_monitor.ts
//
// common/enrollment_monitor.ts — WHAT THE THREE ENROLLMENT PROTOCOLS HAVE DONE
// (2026-09-13).
//
// The counters behind `/admin/acme/monitor`, `/admin/est/monitor` and
// `/admin/scep/monitor`, and behind their three `/admin-api` operations. One
// module and one vocabulary for all three, because the question each page
// answers is the same question — how many requests, of what kind, from whom,
// for which profile, how many were refused and why — and three copies of a
// counter are three places for "refused" to start meaning different things.
//
// **PER REALM AND MERGED ACROSS PROCESSES**, in `gnap/gnap_monitor.ts`'s shape:
// a `realms.map({ persist, merge: 'own' })` whose rows are this process's own
// counts, and `snapshot()` adds every other process's rows read through
// `persistence_replication.remoteRows()`. A number drawn on the page is
// therefore what the SERVICE did, not what the worker that drew it did.
//
// **A COUNTER NEVER THROWS INTO THE REQUEST IT COUNTS.** `record()` catches
// everything and logs `STS-ENROLL-0090`: a certificate that was issued must
// not turn into a 500 because a map could not be written.
//
// **WHAT IS NOT COUNTED IS A SECRET.** A principal is a username, a client_id
// or an EAB key id; a challenge password, an EAB MAC key and a private key
// never reach this module.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `EnrollmentMonitor` takes the logger, the error-code table, the three
// family stores, the replication reader and the realm reader through its
// constructor. The stores are still declared at module scope, as
// `realms.map()`, because a store becomes per realm at its declaration. The
// module still exports `FAMILIES`, `RECENT`, `record`, `snapshot` and
// `resetForTests`. Since #50's R2 the composition root builds the instance
// (`EnrollmentMonitor.defaultDeps()`) and installs it; the module's old export
// names are FACADES that forward to it, for the JavaScript callers, and a
// process without the root builds a default when this module finishes loading.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import errorCodes = require('./error_codes');
import realms = require('./realms');
import replication = require('../persistence/persistence_replication');
import InstanceSlot = require('./instance_slot');

// One family's counters in one realm. `any` on the tables so a reader can add
// them, as the page and the API do.
interface CounterRow {
  requests: number;
  issued: number;
  refused: number;
  revoked: number;
  credentialsCreated: number;
  credentialsRedeemed: number;
  operations: Record<string, number>;
  profiles: Record<string, number>;
  principals: Record<string, number>;
  codes: Record<string, number>;
  statuses: Record<string, number>;
  failInfos: Record<string, number>;
  recent: any[];
  lastAt: string | null;
  [field: string]: any;
}

// What a caller may say about a request — see `record()`.
interface RecordDetail {
  operation?: string;
  outcome?: string;
  status?: number | string;
  profile?: string;
  principal?: string;
  target?: string;
  errorCode?: string;
  serialHex?: string;
  failInfo?: string;
}

// The parts of a `realms.map()` store this module uses.
interface CounterStore {
  has(key: string): boolean;
  get(key: string): CounterRow;
  set(key: string, row: CounterRow): unknown;
  delete(key: string): unknown;
}

interface EnrollmentMonitorDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  errorCodes: { tag(code: string): string };
  stores: Record<string, CounterStore>;
  remoteRows(handle: string, realmId: undefined, key: string): any[];
  currentRealmId(): string;
  startedAt: string;
}

const FAMILIES = ['acme', 'est', 'scep'];

// The number of recent rows each family keeps per realm. Enough for a person
// watching a client try something; a history is the audit log's job.
const RECENT = 50;

// The largest number of distinct principals, profiles or codes one table
// keeps before it folds the rest into "(other)". A table keyed by a value a
// caller chooses is a table a caller can grow without bound.
const MAX_KEYS = 200;

const stores = {};
FAMILIES.forEach(function (family) {
  stores[family] = realms.map({ persist: 'enrollment_monitor.' + family,
                                merge: 'own' });
});

const startedAt = new Date().toISOString();

class EnrollmentMonitor {
  static readonly FAMILIES = FAMILIES;
  static readonly RECENT = RECENT;
  static readonly MAX_KEYS = MAX_KEYS;

  constructor(private readonly deps: EnrollmentMonitorDeps) {
    deps.log.debug("Entering EnrollmentMonitor.constructor().");
    deps.log.debug("Leaving EnrollmentMonitor.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): EnrollmentMonitorDeps {
    helpers.log.debug("Entering EnrollmentMonitor.defaultDeps().");
    helpers.log.debug("Leaving EnrollmentMonitor.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      stores: stores,
      remoteRows: function (handle, realmId, key) {
        return replication.remoteRows(handle, realmId, key);
      },
      currentRealmId: function () {
        return realms.currentId();
      },
      startedAt: startedAt
    };
  }

  private emptyRow(): CounterRow {
    const { log } = this.deps;
    log.debug("Entering EnrollmentMonitor.emptyRow().");
    log.debug("Leaving EnrollmentMonitor.emptyRow().");
    return { requests: 0, issued: 0, refused: 0, revoked: 0,
             credentialsCreated: 0, credentialsRedeemed: 0,
             operations: {}, profiles: {}, principals: {}, codes: {},
             statuses: {}, failInfos: {}, recent: [], lastAt: null };
  }

  private bump(table: Record<string, number>, key: unknown): void {
    const { log } = this.deps;
    log.debug("Entering EnrollmentMonitor.bump().");
    const name = String(key == null || key === '' ? '(none)' : key)
      .slice(0, 120);
    if (table[name] === undefined &&
        Object.keys(table).length >= MAX_KEYS) {
      table['(other)'] = (table['(other)'] || 0) + 1;
      log.debug("Leaving EnrollmentMonitor.bump(). Folded.");
      return;
    }
    table[name] = (table[name] || 0) + 1;
    log.debug("Leaving EnrollmentMonitor.bump().");
  }

  // -------------------------------------------------------------------------
  // record(family, detail)
  //
  //   detail.operation   the protocol operation (new-order, simpleenroll,
  //                      PKIOperation, create-eab, …)
  //   detail.outcome     'issued' | 'refused' | 'revoked' | 'credential' |
  //                      'redeemed' | 'answered'
  //   detail.status      the HTTP status sent
  //   detail.profile     the certificate profile, when there was one
  //   detail.principal   who asked (username, client_id, EAB kid, challenge
  //                      id)
  //   detail.target      whom it was for, when that differs
  //   detail.errorCode   the STS code of a refusal
  //   detail.serialHex   the serial of an issued or revoked certificate
  //   detail.failInfo    SCEP only: the RFC 8894 failInfo name a CertRep
  //                      FAILURE carried (badAlg, badMessageCheck,
  //                      badRequest, badTime, badCertId) — a separate table
  //                      because a SCEP refusal is an HTTP 200 whose status
  //                      says nothing
  // -------------------------------------------------------------------------
  record(family: string, detail?: RecordDetail | null): void {
    const { log, errorCodes, stores } = this.deps;
    log.debug("Entering EnrollmentMonitor.record(). family=" + family);
    try {
      const store = stores[family];
      if (!store) {
        log.warn(errorCodes.tag('STS-ENROLL-0090') + 'enrollment monitor: "' +
                 family + '" is not an enrollment family; nothing counted.');
        log.debug("Leaving EnrollmentMonitor.record(). Unknown family.");
        return;
      }
      const said: RecordDetail = detail || {};
      const key = 'counters';
      const row = store.has(key) ? store.get(key) : this.emptyRow();
      const outcome = String(said.outcome || 'answered');
      row.requests += 1;
      if (outcome === 'issued') {
        row.issued += 1;
      } else if (outcome === 'refused') {
        row.refused += 1;
      } else if (outcome === 'revoked') {
        row.revoked += 1;
      } else if (outcome === 'credential') {
        row.credentialsCreated += 1;
      } else if (outcome === 'redeemed') {
        row.credentialsRedeemed += 1;
      }
      this.bump(row.operations, said.operation);
      if (said.profile) {
        this.bump(row.profiles, said.profile);
      }
      if (said.principal) {
        this.bump(row.principals, said.principal);
      }
      if (said.errorCode) {
        this.bump(row.codes, said.errorCode);
      }
      if (said.status) {
        this.bump(row.statuses, said.status);
      }
      if (said.failInfo) {
        // A row written before this table existed has none.
        row.failInfos = row.failInfos || {};
        this.bump(row.failInfos, said.failInfo);
      }
      const now = new Date().toISOString();
      row.recent = [{
        at: now, operation: String(said.operation || '').slice(0, 60),
        outcome: outcome, status: Number(said.status) || null,
        profile: said.profile ? String(said.profile).slice(0, 40) : null,
        principal: said.principal
          ? String(said.principal).slice(0, 120) : null,
        target: said.target ? String(said.target).slice(0, 120) : null,
        errorCode: said.errorCode
          ? String(said.errorCode).slice(0, 40) : null,
        failInfo: said.failInfo ? String(said.failInfo).slice(0, 40) : null,
        serialHex: said.serialHex
          ? String(said.serialHex).slice(0, 80) : null
      }].concat(row.recent || []).slice(0, RECENT);
      row.lastAt = now;
      store.set(key, row);
    } catch (e) {
      log.error(errorCodes.tag('STS-ENROLL-0090') + 'enrollment monitor: a ' +
                'counter threw and was ignored; the request it counted is ' +
                'unaffected: ' + ((e && e.message) || e));
    }
    log.debug("Leaving EnrollmentMonitor.record().");
  }

  private mergeTable(into: Record<string, number>,
                     from: Record<string, unknown> | undefined): void {
    const { log } = this.deps;
    log.debug("Entering EnrollmentMonitor.mergeTable().");
    Object.keys(from || {}).forEach(function (name) {
      into[name] = (into[name] || 0) + Number(from[name] || 0);
    });
    log.debug("Leaving EnrollmentMonitor.mergeTable().");
  }

  // The family's counters in the ambient realm, this process's and every
  // other process's added together.
  snapshot(family: string): any {
    const { log, stores, remoteRows, currentRealmId } = this.deps;
    log.debug("Entering EnrollmentMonitor.snapshot(). family=" + family);
    const store = stores[family];
    if (!store) {
      log.debug("Leaving EnrollmentMonitor.snapshot(). Unknown family.");
      return null;
    }
    const mine = store.has('counters') ? store.get('counters')
      : this.emptyRow();
    const out = JSON.parse(JSON.stringify(mine));
    out.failInfos = out.failInfos || {};
    let theirs = [];
    try {
      theirs = remoteRows('enrollment_monitor.' + family, undefined,
                          'counters') || [];
    } catch (e) {
      log.debug("Caught in EnrollmentMonitor.snapshot(): " +
                ((e && e.message) || e));
      // No coordination in this process: its own counts are the whole
      // answer.
      theirs = [];
    }
    const self = this;
    theirs.forEach(function (row) {
      if (!row) {
        return;
      }
      ['requests', 'issued', 'refused', 'revoked', 'credentialsCreated',
       'credentialsRedeemed'].forEach(function (field) {
        out[field] += Number(row[field] || 0);
      });
      ['operations', 'profiles', 'principals', 'codes', 'statuses',
       'failInfos']
        .forEach(function (table) {
          self.mergeTable(out[table], row[table]);
        });
      out.recent = out.recent.concat(row.recent || []);
      if (row.lastAt && (!out.lastAt || row.lastAt > out.lastAt)) {
        out.lastAt = row.lastAt;
      }
    });
    out.recent = out.recent.sort(function (a, b) {
      return String(b.at).localeCompare(String(a.at));
    }).slice(0, RECENT);
    out.startedAt = this.deps.startedAt;
    out.realm = currentRealmId();
    out.family = family;
    out.processes = 1 + theirs.length;
    log.debug("Leaving EnrollmentMonitor.snapshot().");
    return out;
  }

  // Tests only: forget this realm's counts for one family.
  resetForTests(family: string): void {
    const { log, stores } = this.deps;
    log.debug("Entering EnrollmentMonitor.resetForTests().");
    if (stores[family]) {
      stores[family].delete('counters');
    }
    log.debug("Leaving EnrollmentMonitor.resetForTests().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<EnrollmentMonitor>(
  'common/enrollment_monitor',
  () => new EnrollmentMonitor(EnrollmentMonitor.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  EnrollmentMonitor: EnrollmentMonitor,
  installInstance: (instance: EnrollmentMonitor): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  FAMILIES: FAMILIES,
  RECENT: RECENT,
  record: slot.forward('record'),
  snapshot: slot.forward('snapshot'),
  resetForTests: slot.forward('resetForTests')
};
