'use strict';
//
// File: gnap_monitor.ts
//
// ---------------------------------------------------------------------------
// WHAT GNAP IS DOING, COUNTED PER APPLICATION.
//
// `/admin/gnap/monitor` answers the question somebody has when a GNAP
// integration misbehaves: which client instances and resource servers are
// using this authorization server, and what have they been doing — how many
// grants, how many approved and denied, which interaction modes, which token
// formats, how many rotations and revocations, how many proofs failed. None of
// that is in the grant store, which holds CURRENT state and forgets a finalized
// grant after a day; these are COUNTS since the process started.
//
// It is `xacml/xacml_monitor.js`'s shape, deliberately, and for its reasons:
//
//   * **a LEAF** — it requires config, realms, helpers and the replication
//     reader, and nothing it requires requires it back, so the grant engine can
//     call it on every request and the console can read it without either
//     dragging the other's routes forward (rule 1);
//   * **one call per event, and it NEVER throws into its caller** — every call
//     site is on the path of a grant or a token, and a counter that could fail
//     one would be monitoring causing the outage it exists to show;
//   * **per realm, `merge: 'own'`** — a count is an INCREMENT, so each process
//     writes its own row and `merge()` folds in the others' rows when it is
//     READ, which is what keeps dispatch mode from under-reporting (the defect
//     common/CLAUDE.md records against SCIM's counters, not repeated here).
//
// EVENTS ARE A CLOSED VOCABULARY, and an unknown event is logged and not
// counted — a page whose columns are the vocabulary cannot show a count nobody
// described.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapMonitor` takes the logger, the error-code table, the counter
// store and the replication reader through its constructor. The store is
// still declared at module scope, as `realms.map()`, because a store becomes
// per realm at its declaration. The module still exports `EVENTS`, `record`,
// `snapshot` and `emptyRow` from a TRANSITIONAL instance for the unconverted
// modules that require it.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import replication = require('../persistence/persistence_replication');

// One application's counters: a number per event counter, plus these.
interface CounterRow {
  lastAt: string | null;
  lastEvent: string | null;
  formats: Record<string, number>;
  errors: Record<string, number>;
  // Each event's counter, a number; `any` so a reader can add them.
  [counter: string]: any;
}

// What a caller may say about an event.
interface EventDetail {
  format?: string;
  gnapError?: string;
}

// The parts of a `realms.map()` store this module uses.
interface CounterStore {
  has(id: string): boolean;
  get(id: string): CounterRow;
  set(id: string, row: CounterRow): unknown;
  forEach(fn: (row: CounterRow, id: string) => void): void;
}

interface GnapMonitorDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  errorCodes: { tag(code: string): string };
  counters: CounterStore;
  replication: {
    remoteRows(handle: string, realmId?: string, key?: string): any[];
    remoteKeys(handle: string): string[] | null | undefined;
  };
}

// event -> [counter path, label]. The page draws these labels.
const EVENTS: Record<string, [string, string]> = {
  'grant.requested': ['grants', 'grant requests'],
  'grant.approved': ['approved', 'grants approved'],
  'grant.denied': ['denied', 'grants denied by the resource owner'],
  'grant.refused': ['refused', 'grant requests refused'],
  'grant.revoked': ['revoked', 'grants revoked by the client'],
  'grant.modified': ['modified', 'grant modifications'],
  'grant.immediate': ['immediate', 'grants approved with no interaction'],
  'continue.poll': ['polls', 'continuation polls'],
  'continue.interact_ref': ['finishedContinuations', 'continuations after ' +
                                                     'interaction'],
  'continue.too_fast': ['tooFast', 'continuations refused as too fast'],
  'interaction.redirect': ['startRedirect', 'redirect interactions'],
  'interaction.app': ['startApp', 'app interactions'],
  'interaction.user_code': ['startUserCode', 'user code interactions'],
  'interaction.user_code_uri': ['startUserCodeUri',
                                'user code URI interactions'],
  'finish.redirect': ['finishRedirect', 'redirect finishes'],
  'finish.push': ['finishPush', 'push finishes delivered'],
  'finish.push_failed': ['finishPushFailed', 'push finishes that failed'],
  'token.issued': ['tokens', 'access tokens issued'],
  'token.rotated': ['rotations', 'access token rotations'],
  'token.key_rotated': ['keyRotations', 'key rotations'],
  'token.revoked': ['tokenRevocations', 'access tokens revoked by the client'],
  'subject.released': ['subjects', 'subject information releases'],
  'proof.failed': ['proofFailures', 'key proofs that failed'],
  'rs.introspection': ['introspections', 'introspection calls'],
  'rs.introspection_active': ['introspectionsActive', 'introspections ' +
                                                      'answered active'],
  'rs.registration': ['registrations', 'resource sets registered'],
  'rs.derivation': ['derivations', 'downstream tokens derived'],
  'rs.presented': ['presented', 'tokens presented at the demonstration RS']
};

const FORMATS = ['jwt-signed', 'jwt-encrypted', 'macaroon', 'biscuit', 'zcap'];

// The store stays a module-scope declaration (see the header).
const counters = realms.map({ persist: 'gnap_monitor.counters',
                              merge: 'own' });

class GnapMonitor {
  static readonly EVENTS = EVENTS;
  static readonly FORMATS = FORMATS;

  private readonly startedAt = new Date().toISOString();

  constructor(private readonly deps: GnapMonitorDeps) {
    deps.log.debug("Entering GnapMonitor.constructor().");
    deps.log.debug("Leaving GnapMonitor.constructor().");
  }

  emptyRow(): CounterRow {
    const { log } = this.deps;
    log.debug("Entering GnapMonitor.emptyRow().");
    const row: CounterRow = { lastAt: null, lastEvent: null, formats: {},
                              errors: {} };
    Object.keys(EVENTS).forEach(function (event) {
      row[EVENTS[event][0]] = 0;
    });
    FORMATS.forEach(function (format) {
      row.formats[format] = 0;
    });
    log.debug("Leaving GnapMonitor.emptyRow().");
    return row;
  }

  // `detail.format` counts a token format; `detail.gnapError` counts the RFC
  // error a refusal returned, which is the column a client developer reads
  // first.
  record(identifier: unknown, event: string, detail?: EventDetail): void {
    const { log, errorCodes, counters } = this.deps;
    log.debug("Entering GnapMonitor.record().");
    try {
      if (!EVENTS[event]) {
        log.warn(errorCodes.tag('STS-GNAP-0650') + 'gnap: the event "' +
                 event + '" ' +
                 'is not in gnap_monitor.js\'s vocabulary and was not ' +
                 'counted. Add it to EVENTS.');
        log.debug("Leaving GnapMonitor.record().");
        return;
      }
      const id = String(identifier || '(unidentified)');
      const said = detail || {};
      const format = FORMATS.indexOf(said.format) >= 0 ? said.format : null;
      const gnapError = said.gnapError ?
        String(said.gnapError).slice(0, 40) : null;
      const row = counters.has(id) ? counters.get(id) : this.emptyRow();
      row[EVENTS[event][0]] += 1;
      if (format) {
        row.formats[format] = (row.formats[format] || 0) + 1;
      }
      if (gnapError) {
        row.errors[gnapError] = (row.errors[gnapError] || 0) + 1;
      }
      row.lastAt = new Date().toISOString();
      row.lastEvent = event;
      // Re-set, because the persistence journal sees a set and not an edit.
      counters.set(id, row);
    } catch (error) {
      log.debug("Caught in GnapMonitor.record(): " +
                ((error && error.message) || error));
      // SWALLOWED, for the header's reason: this is on the path of every
      // grant.
      log.error(errorCodes.tag('STS-GNAP-0651') + 'gnap: a counter threw and ' +
                'was ignored; the grant itself is unaffected: ' +
                error.message);
    }
    log.debug("Leaving GnapMonitor.record().");
  }

  // This process's row plus every other process's (merge: 'own').
  private merge(id: string): CounterRow {
    const { log, counters, replication } = this.deps;
    log.debug("Entering GnapMonitor.merge().");
    const mine = counters.has(id) ? counters.get(id) : this.emptyRow();
    const theirs = replication.remoteRows('gnap_monitor.counters', undefined,
                                          id);
    if (!theirs.length) {
      log.debug("Leaving GnapMonitor.merge().");
      return mine;
    }
    const out: CounterRow = JSON.parse(JSON.stringify(mine));
    theirs.forEach(function (row) {
      if (!row) {
        return;
      }
      Object.keys(out).forEach(function (field) {
        if (typeof out[field] === 'number' &&
            typeof row[field] === 'number') {
          out[field] += row[field];
        }
      });
      ['formats', 'errors'].forEach(function (table) {
        Object.keys(row[table] || {}).forEach(function (key) {
          out[table][key] = (out[table][key] || 0) + row[table][key];
        });
      });
      if (row.lastAt && (!out.lastAt || row.lastAt > out.lastAt)) {
        out.lastAt = row.lastAt;
        out.lastEvent = row.lastEvent;
      }
    });
    log.debug("Leaving GnapMonitor.merge().");
    return out;
  }

  // Every identifier with a row, in this process or another.
  private identifiers(): string[] {
    const { log, counters, replication } = this.deps;
    log.debug("Entering GnapMonitor.identifiers().");
    const out: string[] = [];
    counters.forEach(function (row, id) {
      out.push(id);
    });
    // Another process may be counting an application this one has never
    // served.
    (replication.remoteKeys('gnap_monitor.counters') || []).forEach(
        function (key) {
      if (key && out.indexOf(key) < 0) {
        out.push(key);
      }
    });
    log.debug("Leaving GnapMonitor.identifiers().");
    return out;
  }

  snapshot() {
    const { log } = this.deps;
    log.debug("Entering GnapMonitor.snapshot().");
    const rows: Record<string, CounterRow> = {};
    this.identifiers().forEach((id) => {
      rows[id] = this.merge(id);
    });
    log.debug("Leaving GnapMonitor.snapshot(). " + Object.keys(rows).length +
              " row(s).");
    return {
      startedAt: this.startedAt,
      events: Object.keys(EVENTS).map(function (event) {
        return { event: event, counter: EVENTS[event][0],
                 label: EVENTS[event][1] };
      }),
      formats: FORMATS.slice(),
      rows: rows,
      blank: this.emptyRow()
    };
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, as the composition root will build one.
const monitor = new GnapMonitor({
  log: helpers.log,
  errorCodes: errorCodes,
  counters: counters,
  replication: replication
});

export = {
  GnapMonitor: GnapMonitor,
  EVENTS: GnapMonitor.EVENTS,
  record: monitor.record.bind(monitor) as GnapMonitor['record'],
  snapshot: monitor.snapshot.bind(monitor) as GnapMonitor['snapshot'],
  emptyRow: monitor.emptyRow.bind(monitor) as GnapMonitor['emptyRow']
};
