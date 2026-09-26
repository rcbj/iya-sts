'use strict';
//
// File: risk/risk_store.ts
//
// ===========================================================================
// WHERE RISK SCORING KEEPS WHAT IT KEEPS (#62 P1, 2026-09-22).
//
// Two things live here, and the plan (#62, §7) says where each belongs:
//
//   * THE EXTERNAL DATASETS, by version — GeoIP and ASN ranges and IP lists,
//     with the provenance of every version loaded. On postgres they are rows
//     (`sts_risk_*`, schema version 7); rcbj's rule is that everything a
//     score takes from an external source is kept in the database.
//   * THE ATTRIBUTABLE FAILURE HISTORY — every refused password at every
//     door, with who it was about and where it came from — which the rate
//     limiter's buckets cannot supply, because a bucket is a count that is
//     cleared on success.
//
// **THE DRIVER'S RISK METHODS ARE THE DATABASE; THIS FILE IS EVERYTHING
// ELSE.** `persistence.js` hands the open driver over (`setDriver()`), and a
// driver that carries every name in RISK_GROUP — the postgres one — is used
// as it stands. Otherwise (the `memory` store, and `ldif`, whose unit of
// writing is a whole file) the same methods are answered from maps in this
// process, with the same shapes, so nothing above this file asks which. The
// guarantee that the data is in the database is therefore a postgres
// guarantee, and `describe()` says which store is in use — the page draws it.
//
// **A FAILURE ROW IS PERSONAL DATA, SO IT IS WRITTEN TO THE DATABASE ONLY
// WHERE IT CAN BE SEALED** — where the key-encryption key exists, which
// product mode requires. The address goes in sealed and as a network prefix;
// a name that matched nobody goes in as a keyed digest (`keystore.
// keyedDigest()`), because people type their password into the username
// field and a failure log is where that would otherwise be kept. With no key
// the history is held in this process and says so.
//
// A LIBRARY (rule 3): it registers no route and requires only libraries.
// ===========================================================================

import bunyan = require('bunyan');
import net = require('net');
import config = require('../common/config');
import InstanceSlot = require('../common/instance_slot');

const log = bunyan.createLogger({ name: 'sts-risk-store' });
config.registerLogger(log);

type Json = any;

// The driver methods that make a store the risk database.
const RISK_GROUP = ['riskListDatasets', 'riskListVersions', 'riskBeginVersion',
                    'riskInsertRows', 'riskFinishVersion', 'riskActivate',
                    'riskDeleteRows', 'riskMarkRowsDeleted', 'riskLookupRange',
                    'riskRecordFailure', 'riskListFailures',
                    'riskPurgeFailures', 'riskFeatureCounts',
                    'riskDistinctValues', 'riskIncrementCounts',
                    'riskRecordAssessment', 'riskListAssessments',
                    'riskUpsertSubject', 'riskListSubjects',
                    'riskUpsertSessionContext', 'riskPurgeHistory',
                    'riskRecordAcceptance', 'riskListAcceptances',
                    // #62 P3 and P4.
                    'riskSettleAssessment', 'riskSubjectOf',
                    'riskClaimAction', 'riskLookupFido',
                    'riskSetFeedback',
                    // Monitoring → Risk Scoring.
                    'riskAssessmentMetrics', 'riskSubjectLevels',
                    // Monitoring → Geolocation (#255).
                    'riskGeography',
                    // #215: an import's progress, and the ones a stopped
                    // process left loading.
                    'riskTouchVersion', 'riskAbandonStalled'];

// The most assessments one realm holds in memory, as for failures.
const MAX_MEMORY_ASSESSMENTS = 50000;

// The most failures one realm holds in memory; the oldest go first. A bound
// on a process, not a retention policy — `risk.failureRetentionDays` is that.
const MAX_MEMORY_FAILURES = 50000;

// IPv6 sorts after IPv4, as `inet` does, by lifting it above every IPv4
// value.
const V6_OFFSET = BigInt(1) << BigInt(129);

interface RiskStoreDeps {
  log: { debug(message: string): void; info(message: string): void };
}

// One range held in memory, with its bounds as numbers for the search.
interface HeldRange {
  lo: bigint;
  hi: bigint;
  row: Json;
}

class RiskStore {
  static readonly RISK_GROUP = RISK_GROUP;

  private driver: Json = null;
  private mode = 'memory';
  // Held in this process when there is no database: the four tables above.
  private readonly datasets = new Map<string, Json>();
  private readonly versions = new Map<string, Json>();
  private readonly ranges = new Map<string, HeldRange[]>();
  private readonly unsorted = new Set<string>();
  // FIDO MDS3 authenticator models by version (#62 P5): key -> model.
  private readonly fido = new Map<string, Map<string, Json>>();
  private readonly failures = new Map<string, Json[]>();
  private failureSeq = 0;
  // The model's history, held here when it is not in the database:
  // realm -> subject -> feature\0value -> { count, firstAt, lastAt }.
  private readonly counts = new Map<string, Map<string, Map<string, Json>>>();
  private readonly assessments = new Map<string, Json[]>();
  private readonly subjectStates = new Map<string, Map<string, Json>>();
  private readonly sessionContexts = new Map<string, Map<string, Json>>();
  // Terms acceptances held here when there is no database.
  private readonly acceptances: Json[] = [];
  private readonly listeners: Array<(realm: string, dataset: string) => void> =
    [];

  constructor(private readonly deps: RiskStoreDeps) {
    deps.log.debug("Entering RiskStore.constructor().");
    deps.log.debug("Leaving RiskStore.constructor().");
  }

  static defaultDeps(): RiskStoreDeps {
    log.debug("Entering RiskStore.defaultDeps().");
    log.debug("Leaving RiskStore.defaultDeps().");
    return { log: log };
  }

  // -------------------------------------------------------------------------
  // AN ADDRESS AS A NUMBER, for the in-memory search: IPv4 as its 32 bits,
  // IPv6 as its 128 lifted above every IPv4. null for a string that is not
  // an address. `::ffff:a.b.c.d` is read as the IPv4 address it carries,
  // which is how `client_address.js` normalises a dual-stack socket's.
  // -------------------------------------------------------------------------
  static addressNumber(text: string): bigint | null {
    log.debug("Entering RiskStore.addressNumber().");
    let address = String(text || '').trim();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped) {
      address = mapped[1];
    }
    const family = net.isIP(address);
    if (family === 4) {
      let value = BigInt(0);
      address.split('.').forEach(function (part) {
        value = (value << BigInt(8)) + BigInt(Number(part));
      });
      log.debug("Leaving RiskStore.addressNumber(). IPv4.");
      return value;
    }
    if (family !== 6) {
      log.debug("Leaving RiskStore.addressNumber(). Not an address.");
      return null;
    }
    // An embedded IPv4 tail becomes two groups.
    const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(address);
    if (tail) {
      const v4 = tail[1].split('.').map(Number);
      address = address.slice(0, tail.index) +
        ((v4[0] << 8) | v4[1]).toString(16) + ':' +
        ((v4[2] << 8) | v4[3]).toString(16);
    }
    const halves = address.split('::');
    const head = halves[0] ? halves[0].split(':') : [];
    const rest = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
    const fill = halves.length > 1 ? 8 - head.length - rest.length : 0;
    const groups = head.concat(new Array(fill).fill('0'), rest);
    let value = BigInt(0);
    groups.forEach(function (group) {
      value = (value << BigInt(16)) + BigInt(parseInt(group || '0', 16));
    });
    log.debug("Leaving RiskStore.addressNumber(). IPv6.");
    return value + V6_OFFSET;
  }

  // A number from addressNumber() back to the address it is, in the form
  // `inet` prints: dotted IPv4, or IPv6 with its longest run of zero groups
  // written `::`.
  static addressText(value: bigint): string {
    log.debug("Entering RiskStore.addressText().");
    if (value < V6_OFFSET) {
      const parts = [];
      for (let i = 3; i >= 0; i--) {
        parts.push(Number((value >> BigInt(8 * i)) & BigInt(255)));
      }
      log.debug("Leaving RiskStore.addressText(). IPv4.");
      return parts.join('.');
    }
    const v6 = value - V6_OFFSET;
    const groups = [];
    for (let i = 7; i >= 0; i--) {
      groups.push(Number((v6 >> BigInt(16 * i)) & BigInt(0xffff)));
    }
    let bestAt = -1;
    let bestLength = 0;
    for (let i = 0; i < 8; i++) {
      let j = i;
      while (j < 8 && groups[j] === 0) {
        j++;
      }
      if (j - i > bestLength && j - i > 1) {
        bestAt = i;
        bestLength = j - i;
      }
    }
    const hex = groups.map(function (g) {
      return g.toString(16);
    });
    log.debug("Leaving RiskStore.addressText(). IPv6.");
    if (bestAt < 0) {
      return hex.join(':');
    }
    return hex.slice(0, bestAt).join(':') + '::' +
      hex.slice(bestAt + bestLength).join(':');
  }

  // -------------------------------------------------------------------------
  // A RANGE FROM WHAT A LIST OR A DATASET WRITES: one address, a CIDR block,
  // or `first - last`. `{ start, end }` in `inet`'s form, or null for text
  // that is none of the three — a CIDR whose host bits are set is read as the
  // block it names, which is how every list this service reads writes them.
  // -------------------------------------------------------------------------
  static rangeOf(text: string): { start: string; end: string } | null {
    log.debug("Entering RiskStore.rangeOf().");
    const raw = String(text || '').trim();
    const dash = /^(\S+)\s*-\s*(\S+)$/.exec(raw);
    if (dash) {
      const lo = RiskStore.addressNumber(dash[1]);
      const hi = RiskStore.addressNumber(dash[2]);
      const sameFamily = lo !== null && hi !== null &&
        ((lo < V6_OFFSET) === (hi < V6_OFFSET));
      log.debug("Leaving RiskStore.rangeOf(). A dashed range.");
      return sameFamily && lo <= hi
        ? { start: RiskStore.addressText(lo), end: RiskStore.addressText(hi) }
        : null;
    }
    const slash = raw.indexOf('/');
    const base = RiskStore.addressNumber(slash >= 0 ? raw.slice(0, slash)
                                                    : raw);
    if (base === null) {
      log.debug("Leaving RiskStore.rangeOf(). Not an address.");
      return null;
    }
    const v6 = base >= V6_OFFSET;
    const width = v6 ? 128 : 32;
    const bits = slash >= 0 ? Number(raw.slice(slash + 1)) : width;
    if (!/^\d+$/.test(slash >= 0 ? raw.slice(slash + 1) : String(width)) ||
        bits < 0 || bits > width) {
      log.debug("Leaving RiskStore.rangeOf(). A bad prefix length.");
      return null;
    }
    const host = (BigInt(1) << BigInt(width - bits)) - BigInt(1);
    const plain = v6 ? base - V6_OFFSET : base;
    const lo = plain & ~host;
    const hi = lo | host;
    log.debug("Leaving RiskStore.rangeOf().");
    return { start: RiskStore.addressText(v6 ? lo + V6_OFFSET : lo),
             end: RiskStore.addressText(v6 ? hi + V6_OFFSET : hi) };
  }

  // -------------------------------------------------------------------------
  // THE NETWORK PREFIX AN ADDRESS IS KEPT AS, beside its sealed form: the /24
  // an IPv4 address is in, or the /48 an IPv6 one is in — a network rather
  // than a person, and still what SQL groups a spray by. '' for a string
  // that is not an address.
  // -------------------------------------------------------------------------
  static prefixOf(text: string): string {
    log.debug("Entering RiskStore.prefixOf().");
    const value = RiskStore.addressNumber(text);
    if (value === null) {
      log.debug("Leaving RiskStore.prefixOf(). Not an address.");
      return '';
    }
    // The network, written as `inet` writes it, so the text kept in memory
    // is the text postgres prints for the same `cidr`.
    if (value < V6_OFFSET) {
      const net24 = (value >> BigInt(8)) << BigInt(8);
      log.debug("Leaving RiskStore.prefixOf(). IPv4.");
      return RiskStore.addressText(net24) + '/24';
    }
    const net48 = ((value - V6_OFFSET) >> BigInt(80)) << BigInt(80);
    log.debug("Leaving RiskStore.prefixOf(). IPv6.");
    return RiskStore.addressText(net48 + V6_OFFSET) + '/48';
  }

  // -------------------------------------------------------------------------
  // THE STORE, handed over by `persistence.js` when it opens one, and taken
  // back when it closes. A driver without every RISK_GROUP method leaves this
  // process answering from its own maps.
  // -------------------------------------------------------------------------
  setDriver(theDriver: Json, activeMode: string): void {
    const { log } = this.deps;
    log.debug("Entering RiskStore.setDriver(). mode=" + activeMode);
    const complete = !!theDriver && RISK_GROUP.every(function (name) {
      return typeof theDriver[name] === 'function';
    });
    this.driver = complete ? theDriver : null;
    this.mode = String(activeMode || 'memory');
    log.info('risk: ' + (complete
      ? 'the ' + this.mode + ' store holds the risk datasets and history.'
      : 'the ' + this.mode + ' store has no risk tables; datasets and ' +
        'history are held in this process.'));
    log.debug("Leaving RiskStore.setDriver().");
  }

  clearDriver(): void {
    const { log } = this.deps;
    log.debug("Entering RiskStore.clearDriver().");
    this.driver = null;
    this.mode = 'memory';
    log.debug("Leaving RiskStore.clearDriver().");
  }

  // Whether the datasets are rows in a database every node reads.
  inDatabase(): boolean {
    const { log } = this.deps;
    log.debug("Entering RiskStore.inDatabase().");
    log.debug("Leaving RiskStore.inDatabase().");
    return !!this.driver;
  }

  describe(): Json {
    const { log } = this.deps;
    log.debug("Entering RiskStore.describe().");
    log.debug("Leaving RiskStore.describe().");
    return {
      mode: this.mode,
      database: !!this.driver,
      why: this.driver
        ? 'The ' + this.mode + ' store holds every dataset version and the ' +
          'failure history in its sts_risk_* tables; every node reads the ' +
          'same rows.'
        : 'The ' + this.mode + ' store has no risk tables, so datasets and ' +
          'the failure history are held in this process and are gone at ' +
          'the next restart. Postgres is where they are kept.'
    };
  }

  // A version activated anywhere — here, or by another process through the
  // change log — so a reader can drop what it cached.
  onActivated(fn: (realm: string, dataset: string) => void): void {
    const { log } = this.deps;
    log.debug("Entering RiskStore.onActivated().");
    this.listeners.push(fn);
    log.debug("Leaving RiskStore.onActivated().");
  }

  noteActivated(realm: string, dataset: string): void {
    const { log } = this.deps;
    log.debug("Entering RiskStore.noteActivated(). " + dataset);
    this.listeners.forEach(function (fn) {
      try {
        fn(String(realm || ''), String(dataset || ''));
      } catch (e) {
        log.debug("Caught in RiskStore.noteActivated(): " +
                  ((e && e.message) || e));
        // A reader that cannot drop its cache keeps it until its own bound
        // evicts it; the next activation is not affected.
      }
    });
    log.debug("Leaving RiskStore.noteActivated().");
  }

  // A map key from its parts. Called for every row a load inserts, so no
  // Entering/Leaving pair: a hot path, which the code style allows when it
  // says so.
  private static key(...parts: string[]): string {
    return parts.map(function (p) {
      return String(p || '');
    }).join('\u0000');
  }

  // ===== DATASETS ==========================================================

  listDatasets(): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.listDatasets().");
    if (this.driver) {
      log.debug("Leaving RiskStore.listDatasets(). Database.");
      return Promise.resolve(this.driver.riskListDatasets());
    }
    const out = [];
    this.datasets.forEach(function (row) {
      out.push(Object.assign({}, row));
    });
    log.debug("Leaving RiskStore.listDatasets(). Memory.");
    return Promise.resolve(out);
  }

  listVersions(realm: string, dataset: string): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.listVersions(). " + dataset);
    if (this.driver) {
      log.debug("Leaving RiskStore.listVersions(). Database.");
      return Promise.resolve(this.driver.riskListVersions(realm, dataset));
    }
    const out = [];
    this.versions.forEach(function (row) {
      if (row.realm === String(realm || '') &&
          (!dataset || row.dataset === dataset)) {
        out.push(Object.assign({}, row));
      }
    });
    out.sort(function (a, b) {
      return (b.fetchedAt - a.fetchedAt) ||
             (a.version < b.version ? 1 : a.version > b.version ? -1 : 0);
    });
    log.debug("Leaving RiskStore.listVersions(). Memory.");
    return Promise.resolve(out);
  }

  beginVersion(v: Json): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.beginVersion(). " + v.dataset + " " +
              v.version);
    if (this.driver) {
      log.debug("Leaving RiskStore.beginVersion(). Database.");
      return Promise.resolve(this.driver.riskBeginVersion(v));
    }
    const k = RiskStore.key(v.realm, v.dataset, v.version);
    if (this.versions.has(k)) {
      log.debug("Leaving RiskStore.beginVersion(). Already recorded.");
      return Promise.resolve(false);
    }
    this.versions.set(k, Object.assign({
      realm: String(v.realm || ''), attribution: '', sourceUri: '',
      rowCount: 0, parameters: {}, nextUpdateAt: 0, loadedAt: 0,
      activatedAt: 0, supersededAt: 0, rowsDeletedAt: 0, refusal: '',
      errorCode: '', origin: String(process.pid)
    }, v, { realm: String(v.realm || ''), state: 'loading' }));
    log.debug("Leaving RiskStore.beginVersion(). Begun.");
    return Promise.resolve(true);
  }

  insertRows(kind: string, realm: string, dataset: string, version: string,
             rows: Json[]): Promise<number> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.insertRows(). kind=" + kind + " rows=" +
              rows.length);
    if (this.driver) {
      log.debug("Leaving RiskStore.insertRows(). Database.");
      return Promise.resolve(this.driver.riskInsertRows(kind, realm, dataset,
                                                         version, rows));
    }
    const k = RiskStore.key(kind, kind === 'iplist' ? realm : '', dataset,
                            version);
    if (kind === 'fido') {
      // Authenticator models (#62 P5) are keyed, not ranged.
      const models = this.fido.get(k) || new Map();
      rows.forEach(function (row) {
        models.set(String(row.keyKind) + '\u0000' +
                   String(row.key || '').toLowerCase(),
                   Object.assign({}, row));
      });
      this.fido.set(k, models);
      log.debug("Leaving RiskStore.insertRows(). " + rows.length +
                " model(s).");
      return Promise.resolve(rows.length);
    }
    const held = this.ranges.get(k) || [];
    let added = 0;
    rows.forEach(function (row) {
      const lo = RiskStore.addressNumber(row.start);
      const hi = RiskStore.addressNumber(row.end);
      if (lo !== null && hi !== null && lo <= hi) {
        held.push({ lo: lo, hi: hi, row: Object.assign({}, row) });
        added += 1;
      }
    });
    this.ranges.set(k, held);
    this.unsorted.add(k);
    log.debug("Leaving RiskStore.insertRows(). " + added + " added.");
    return Promise.resolve(added);
  }

  finishVersion(realm: string, dataset: string, version: string,
                patch: Json): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.finishVersion(). " + dataset + " " +
              version + " " + patch.state);
    if (this.driver) {
      log.debug("Leaving RiskStore.finishVersion(). Database.");
      return Promise.resolve(this.driver.riskFinishVersion(realm, dataset,
                                                            version, patch));
    }
    const row = this.versions.get(RiskStore.key(realm, dataset, version));
    if (!row) {
      log.debug("Leaving RiskStore.finishVersion(). No such version.");
      return Promise.resolve(false);
    }
    Object.assign(row, { state: patch.state,
                         rowCount: Number(patch.rowCount) || 0,
                         loadedAt: Number(patch.loadedAt) || 0,
                         refusal: String(patch.refusal || ''),
                         errorCode: String(patch.errorCode || '') });
    if (patch.parameters) {
      row.parameters = Object.assign({}, row.parameters, patch.parameters);
    }
    log.debug("Leaving RiskStore.finishVersion().");
    return Promise.resolve(true);
  }

  // -------------------------------------------------------------------------
  // AN IMPORT'S PROGRESS (#215): the version's `progressAt` and row count so
  // far, written only while it is still `loading`. False when it is not —
  // the stalled-import job refused it — which is the importer's signal to
  // stop.
  // -------------------------------------------------------------------------
  touchVersion(realm: string, dataset: string, version: string, at: number,
               rows: number): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.touchVersion(). " + dataset + " " +
              version);
    if (this.driver) {
      log.debug("Leaving RiskStore.touchVersion(). Database.");
      return Promise.resolve(this.driver.riskTouchVersion(realm, dataset,
                                                           version, at,
                                                           rows));
    }
    const row = this.versions.get(RiskStore.key(realm, dataset, version));
    if (!row || row.state !== 'loading') {
      log.debug("Leaving RiskStore.touchVersion(). Not loading.");
      return Promise.resolve(false);
    }
    row.parameters = Object.assign({}, row.parameters,
                                   { progressAt: Number(at) || 0,
                                     progressRows: Number(rows) || 0 });
    log.debug("Leaving RiskStore.touchVersion().");
    return Promise.resolve(true);
  }

  // -------------------------------------------------------------------------
  // EVERY VERSION STILL `loading` WHOSE START AND LAST PROGRESS ARE BOTH
  // OLDER THAN `before`, marked refused with `why` and `code`, in one
  // conditional write per store; answers the versions it refused, as
  // `{ realm, dataset, version }`.
  // -------------------------------------------------------------------------
  abandonStalled(before: number, at: number, why: string,
                 code: string): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.abandonStalled().");
    if (this.driver) {
      log.debug("Leaving RiskStore.abandonStalled(). Database.");
      return Promise.resolve(this.driver.riskAbandonStalled(before, at, why,
                                                             code));
    }
    const out: Json[] = [];
    this.versions.forEach(function (row) {
      const last = Math.max(Number(row.fetchedAt) || 0,
                            Number(row.parameters &&
                                   row.parameters.progressAt) || 0);
      if (row.state === 'loading' && last < before) {
        Object.assign(row, { state: 'refused', loadedAt: Number(at) || 0,
                             refusal: String(why || ''),
                             errorCode: String(code || '') });
        out.push({ realm: row.realm, dataset: row.dataset,
                   version: row.version });
      }
    });
    log.debug("Leaving RiskStore.abandonStalled(). " + out.length + ".");
    return Promise.resolve(out);
  }

  activate(realm: string, dataset: string, kind: string, version: string,
           now: number): Promise<Json> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering RiskStore.activate(). " + dataset + " " + version);
    const done = function (answer: Json): Json {
      if (answer && answer.activated && !answer.unchanged) {
        self.noteActivated(realm, dataset);
      }
      return answer;
    };
    if (this.driver) {
      log.debug("Leaving RiskStore.activate(). Database.");
      return Promise.resolve(this.driver.riskActivate(realm, dataset, kind,
                                                       version, now))
        .then(done);
    }
    const wanted = this.versions.get(RiskStore.key(realm, dataset, version));
    const state = wanted ? wanted.state : '';
    if (state !== 'ready' && state !== 'superseded' && state !== 'active') {
      log.debug("Leaving RiskStore.activate(). Not activatable: " + state);
      return Promise.resolve({ activated: false, state: state });
    }
    const dk = RiskStore.key(realm, dataset);
    const current = this.datasets.get(dk);
    const previous = current ? current.activeVersion : '';
    if (previous === version) {
      log.debug("Leaving RiskStore.activate(). Unchanged.");
      return Promise.resolve({ activated: true, previous: previous,
                               unchanged: true });
    }
    this.versions.forEach(function (row) {
      if (row.realm === String(realm || '') && row.dataset === dataset &&
          row.state === 'active') {
        row.state = 'superseded';
        row.supersededAt = now;
      }
    });
    wanted.state = 'active';
    wanted.activatedAt = now;
    wanted.supersededAt = 0;
    this.datasets.set(dk, { realm: String(realm || ''), dataset: dataset,
                            kind: kind, activeVersion: version,
                            previousVersion: previous, state: 'active',
                            updatedAt: now });
    log.debug("Leaving RiskStore.activate(). Memory.");
    return Promise.resolve(done({ activated: true, previous: previous }));
  }

  deleteRows(kind: string, realm: string, dataset: string, version: string,
             limit: number): Promise<number> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.deleteRows(). " + dataset + " " + version);
    if (this.driver) {
      log.debug("Leaving RiskStore.deleteRows(). Database.");
      return Promise.resolve(this.driver.riskDeleteRows(kind, realm, dataset,
                                                         version, limit));
    }
    const k = RiskStore.key(kind, kind === 'iplist' ? realm : '', dataset,
                            version);
    if (kind === 'fido') {
      const models = this.fido.get(k);
      this.fido.delete(k);
      log.debug("Leaving RiskStore.deleteRows(). Memory, models.");
      return Promise.resolve(models ? models.size : 0);
    }
    const held = this.ranges.get(k) || [];
    this.ranges.delete(k);
    this.unsorted.delete(k);
    log.debug("Leaving RiskStore.deleteRows(). Memory.");
    return Promise.resolve(held.length);
  }

  markRowsDeleted(realm: string, dataset: string, version: string,
                  now: number): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.markRowsDeleted(). " + dataset);
    if (this.driver) {
      log.debug("Leaving RiskStore.markRowsDeleted(). Database.");
      return Promise.resolve(this.driver.riskMarkRowsDeleted(realm, dataset,
                                                              version, now));
    }
    const row = this.versions.get(RiskStore.key(realm, dataset, version));
    if (!row || row.state === 'active') {
      log.debug("Leaving RiskStore.markRowsDeleted(). Not marked.");
      return Promise.resolve(false);
    }
    row.state = 'deleted';
    row.rowsDeletedAt = now;
    log.debug("Leaving RiskStore.markRowsDeleted(). Marked.");
    return Promise.resolve(true);
  }

  // -------------------------------------------------------------------------
  // ONE ADDRESS IN ONE VERSION: the in-memory half of the driver's one
  // descending probe — the greatest start not above the address, kept only
  // if its end is not below it. The ranges are sorted once after a load.
  // -------------------------------------------------------------------------
  // One authenticator model of a FIDO MDS3 version (#62 P5), or null.
  lookupFido(dataset: string, version: string, keyKind: string,
             key: string): Promise<Json | null> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.lookupFido(). " + keyKind);
    if (this.driver) {
      log.debug("Leaving RiskStore.lookupFido(). Database.");
      return Promise.resolve(this.driver.riskLookupFido(dataset, version,
                                                         keyKind, key));
    }
    const models = this.fido.get(RiskStore.key('fido', '', dataset,
                                               version));
    const hit = models ? models.get(String(keyKind) + '\u0000' +
                                    String(key || '').toLowerCase()) : null;
    log.debug("Leaving RiskStore.lookupFido(). " + (hit ? 'Hit.' : 'Miss.'));
    return Promise.resolve(hit ? Object.assign({}, hit) : null);
  }

  lookupRange(kind: string, realm: string, dataset: string, version: string,
              address: string): Promise<Json | null> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.lookupRange(). kind=" + kind);
    if (this.driver) {
      log.debug("Leaving RiskStore.lookupRange(). Database.");
      return Promise.resolve(this.driver.riskLookupRange(kind, realm, dataset,
                                                          version, address));
    }
    const value = RiskStore.addressNumber(address);
    const k = RiskStore.key(kind, kind === 'iplist' ? realm : '', dataset,
                            version);
    const held = this.ranges.get(k) || [];
    if (this.unsorted.has(k)) {
      held.sort(function (a, b) {
        return a.lo < b.lo ? -1 : a.lo > b.lo ? 1 : 0;
      });
      this.unsorted.delete(k);
    }
    if (value === null || !held.length) {
      log.debug("Leaving RiskStore.lookupRange(). Nothing to search.");
      return Promise.resolve(null);
    }
    let lo = 0;
    let hi = held.length - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (held[mid].lo <= value) {
        found = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    const hit = found >= 0 && held[found].hi >= value
      ? Object.assign({}, held[found].row) : null;
    log.debug("Leaving RiskStore.lookupRange(). " + (hit ? 'Hit.' : 'Miss.'));
    return Promise.resolve(hit);
  }

  // ===== FAILURES ==========================================================

  // Whether failure rows go to the database: a database store AND a
  // key-encryption key to seal the address under. See the header.
  failuresInDatabase(sealing: boolean): boolean {
    const { log } = this.deps;
    log.debug("Entering RiskStore.failuresInDatabase().");
    log.debug("Leaving RiskStore.failuresInDatabase().");
    return !!this.driver && !!sealing;
  }

  recordFailure(row: Json, sealing: boolean): Promise<string> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.recordFailure(). door=" + row.door);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.recordFailure(). Database.");
      return Promise.resolve(this.driver.riskRecordFailure(row));
    }
    const realm = String(row.realm || '');
    const held = this.failures.get(realm) || [];
    this.failureSeq += 1;
    held.push(Object.assign({ id: String(this.failureSeq),
                              origin: String(process.pid) }, row,
                            { realm: realm }));
    if (held.length > MAX_MEMORY_FAILURES) {
      held.splice(0, held.length - MAX_MEMORY_FAILURES);
    }
    this.failures.set(realm, held);
    log.debug("Leaving RiskStore.recordFailure(). Memory.");
    return Promise.resolve(String(this.failureSeq));
  }

  listFailures(realm: string, opts: Json, sealing: boolean): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.listFailures(). realm=" + realm);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.listFailures(). Database.");
      return Promise.resolve(this.driver.riskListFailures(realm, opts));
    }
    const o = opts || {};
    const matched = (this.failures.get(String(realm || '')) || [])
      .filter(function (row) {
        return row.at >= (Number(o.since) || 0) &&
          (!o.subject || row.subject === o.subject) &&
          (!o.nameHmac || row.nameHmac === o.nameHmac) &&
          (!o.prefix || row.addressPrefix === o.prefix) &&
          (!o.door || row.door === o.door) &&
          (!o.excludeDoor || row.door !== o.excludeDoor);
      }).reverse();
    const offset = Number(o.offset) || 0;
    const limit = Number(o.limit) || 50;
    log.debug("Leaving RiskStore.listFailures(). Memory.");
    return Promise.resolve({ rows: matched.slice(offset, offset + limit)
                               .map(function (row) {
                                 return Object.assign({}, row);
                               }),
                             total: matched.length });
  }

  purgeFailures(beforeMs: number, limit: number,
                sealing: boolean): Promise<number> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.purgeFailures().");
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.purgeFailures(). Database.");
      return Promise.resolve(this.driver.riskPurgeFailures(beforeMs, limit));
    }
    let removed = 0;
    this.failures.forEach(function (held, realm, all) {
      const kept = held.filter(function (row) {
        return row.at >= beforeMs;
      });
      removed += held.length - kept.length;
      all.set(realm, kept);
    });
    log.debug("Leaving RiskStore.purgeFailures(). " + removed + ".");
    return Promise.resolve(removed);
  }

  // ===== THE MODEL'S HISTORY (#62 P2) ======================================
  //
  // Personal data like a failure row — an address digest, a device, a
  // person's habits — so the same rule: in the database only where it can
  // be sealed (`failuresInDatabase()`), and in this process otherwise.

  private countsOf(realm: string, subject: string): Map<string, Json> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.countsOf().");
    const r = String(realm || '');
    if (!this.counts.has(r)) {
      this.counts.set(r, new Map());
    }
    const bySubject = this.counts.get(r);
    if (!bySubject.has(subject)) {
      bySubject.set(subject, new Map());
    }
    log.debug("Leaving RiskStore.countsOf().");
    return bySubject.get(subject);
  }

  featureCounts(realm: string, subject: string, pairs: Json[],
                sealing: boolean): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.featureCounts(). " + pairs.length);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.featureCounts(). Database.");
      return Promise.resolve(this.driver.riskFeatureCounts(realm, subject,
                                                            pairs));
    }
    const held = this.countsOf(realm, subject);
    const out = [];
    pairs.forEach(function (p: Json): void {
      const row = held.get(RiskStore.key(p.feature, p.value));
      if (row) {
        out.push({ feature: p.feature, value: p.value, count: row.count });
      }
    });
    log.debug("Leaving RiskStore.featureCounts(). Memory.");
    return Promise.resolve(out);
  }

  distinctValues(realm: string, subject: string, feature: string,
                 prefix: string, sealing: boolean): Promise<number> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.distinctValues(). " + feature);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.distinctValues(). Database.");
      return Promise.resolve(this.driver.riskDistinctValues(realm, subject,
                                                             feature,
                                                             prefix));
    }
    const lead = RiskStore.key(feature, '');
    let n = 0;
    this.countsOf(realm, subject).forEach(function (row: Json,
                                                     k: string): void {
      if (k.indexOf(lead) === 0 &&
          (!prefix || k.slice(lead.length).indexOf(prefix) === 0)) {
        n += 1;
      }
    });
    log.debug("Leaving RiskStore.distinctValues(). Memory.");
    return Promise.resolve(n);
  }

  incrementCounts(realm: string, rows: Json[], at: number,
                  sealing: boolean): Promise<number> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.incrementCounts(). " + rows.length);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.incrementCounts(). Database.");
      return Promise.resolve(this.driver.riskIncrementCounts(realm, rows,
                                                              at));
    }
    const self = this;
    rows.forEach(function (r: Json): void {
      const held = self.countsOf(realm, r.subject);
      const k = RiskStore.key(r.feature, r.value);
      const row = held.get(k);
      if (row) {
        row.count += 1;
        row.lastAt = at;
      } else {
        held.set(k, { count: 1, firstAt: at, lastAt: at });
      }
    });
    log.debug("Leaving RiskStore.incrementCounts(). Memory.");
    return Promise.resolve(rows.length);
  }

  recordAssessment(a: Json, sealing: boolean): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.recordAssessment().");
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.recordAssessment(). Database.");
      return Promise.resolve(this.driver.riskRecordAssessment(a));
    }
    const realm = String(a.realm || '');
    const held = this.assessments.get(realm) || [];
    held.push(Object.assign({}, a, { realm: realm }));
    if (held.length > MAX_MEMORY_ASSESSMENTS) {
      held.splice(0, held.length - MAX_MEMORY_ASSESSMENTS);
    }
    this.assessments.set(realm, held);
    log.debug("Leaving RiskStore.recordAssessment(). Memory.");
    return Promise.resolve(true);
  }

  listAssessments(realm: string, opts: Json,
                  sealing: boolean): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.listAssessments().");
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.listAssessments(). Database.");
      return Promise.resolve(this.driver.riskListAssessments(realm, opts));
    }
    const o = opts || {};
    const matched = (this.assessments.get(String(realm || '')) || [])
      .filter(function (a: Json): boolean {
        return a.at >= (Number(o.since) || 0) &&
          (!o.subject || a.subject === o.subject) &&
          (!o.level || a.level === o.level);
      }).reverse();
    const offset = Number(o.offset) || 0;
    const limit = Number(o.limit) || 50;
    log.debug("Leaving RiskStore.listAssessments(). Memory.");
    return Promise.resolve({
      total: matched.length,
      rows: matched.slice(offset, offset + limit).map(function (a: Json) {
        const copy = Object.assign({}, a);
        delete copy.addressSealed;
        return copy;
      }) });
  }

  // -------------------------------------------------------------------------
  // THE ASSESSMENTS OF A WINDOW, COUNTED (#62), for Monitoring → Risk
  // Scoring: by level, door, decision, phase, signal, country and score
  // band; the answers people gave; and a series of levels per `bucketMs`.
  // The database counts with GROUP BY and this process counts its own rows,
  // and both hand `metricsOf()` the same grouped rows, so the two stores
  // cannot answer in different shapes.
  // -------------------------------------------------------------------------
  assessmentMetrics(realm: string, opts: Json,
                    sealing: boolean): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.assessmentMetrics().");
    const o = opts || {};
    const bucketMs = Math.max(60000, Number(o.bucketMs) || 3600000);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.assessmentMetrics(). Database.");
      return Promise.resolve(this.driver.riskAssessmentMetrics(realm, {
        since: Number(o.since) || 0, bucketMs: bucketMs,
        quantiles: (o.quantiles || []).filter(function (f: number) {
          return f > 0 && f <= 1;
        }) }))
        .then(function (grouped: Json): Json {
          return RiskStore.metricsOf(grouped);
        });
    }
    const since = Number(o.since) || 0;
    const rows = (this.assessments.get(String(realm || '')) || [])
      .filter(function (a: Json): boolean {
        return a.at >= since;
      });
    const groups = new Map<string, Json>();
    const series = new Map<string, Json>();
    const subjects = new Set<string>();
    const scores: number[] = [];
    const totals = { total: 0, bots: 0, scoreSum: 0, scoreMax: 0 };
    const count = function (k: string, v: string): void {
      const key = k + '\u0000' + v;
      const held = groups.get(key);
      if (held) {
        held.n++;
      } else {
        groups.set(key, { k: k, v: v, n: 1 });
      }
    };
    rows.forEach(function (a: Json): void {
      totals.total++;
      totals.bots += a.bot ? 1 : 0;
      totals.scoreSum += Number(a.score) || 0;
      totals.scoreMax = Math.max(totals.scoreMax, Number(a.score) || 0);
      subjects.add(String(a.subject || ''));
      scores.push(Number(a.score) || 0);
      count('level', String(a.level || ''));
      count('door', String(a.door || ''));
      count('decision', String(a.decision || ''));
      count('phase', String(a.phase || ''));
      count('country', String(a.country || ''));
      count('band', RiskStore.bandOf(Number(a.score) || 0));
      if (a.feedback) {
        count('feedback', String(a.feedback));
      }
      (a.signals || []).forEach(function (s: Json): void {
        const id = String((s && s.signal) || '');
        count('signal', id);
        // For calibration: the level a signal's sign-ins ended at, and
        // what their people said.
        count('signal-level', id + '\u0001' + String(a.level || ''));
        if (a.feedback) {
          count('signal-feedback', id + '\u0001' + String(a.feedback));
        }
      });
      const bucket = Math.floor(Number(a.at) / bucketMs) * bucketMs;
      const key = bucket + '\u0000' + String(a.level || '');
      const held = series.get(key);
      if (held) {
        held.n++;
      } else {
        series.set(key, { bucket: bucket, level: String(a.level || ''),
                          n: 1 });
      }
    });
    // PostgreSQL's percentile_disc: the first score whose cumulative share
    // reaches the fraction.
    scores.sort(function (x: number, y: number): number {
      return x - y;
    });
    const quantiles: Record<string, number> = {};
    (o.quantiles || []).forEach(function (f: number): void {
      if (scores.length && f > 0 && f <= 1) {
        quantiles[String(f)] =
          scores[Math.max(0, Math.ceil(f * scores.length) - 1)];
      }
    });
    log.debug("Leaving RiskStore.assessmentMetrics(). Memory.");
    return Promise.resolve(RiskStore.metricsOf({
      quantiles: quantiles,
      totals: { total: totals.total, subjects: subjects.size,
                bots: totals.bots,
                meanScore: totals.total ? totals.scoreSum / totals.total : 0,
                maxScore: totals.scoreMax },
      groups: Array.from(groups.values()),
      series: Array.from(series.values()) }));
  }

  // -------------------------------------------------------------------------
  // WHERE A WINDOW'S PEOPLE WERE (#255), for Monitoring → Geolocation: the
  // assessments since `since`, counted at four levels — the world, each
  // continent, each country, each city — as DISTINCT PEOPLE (subjects),
  // sign-ins (the `user` phase) and assessments, with a city's coordinates
  // and the last time it was seen. People are counted at every level rather
  // than summed from the one below, because a person seen in two cities is
  // one person in their country.
  //
  // `continents` maps an ISO 3166-1 code to its continent (the page's
  // Natural Earth table): the store holds a country and no continent, and a
  // country missing from the map is counted under the continent ''.
  // `sessionIds`, when given, is LIVE SESSIONS mode: only assessments of
  // those sessions, and only each session's LATEST — where the person is
  // now, not everywhere the session has been. An assessment with no subject
  // counts nowhere.
  //
  // The database counts with GROUPING SETS and this process counts its own
  // rows; both answer `{ rows: [{ level, continent, country, subdivision,
  // city, people, signIns, assessments, latitude, longitude, lastAt }] }`.
  // -------------------------------------------------------------------------
  geography(realm: string, opts: Json, sealing: boolean): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.geography().");
    const o = opts || {};
    const continents: Record<string, string> = o.continents || {};
    const sessionIds: string[] | null = Array.isArray(o.sessionIds)
      ? o.sessionIds.map(String) : null;
    if (this.failuresInDatabase(sealing)) {
      const codes = Object.keys(continents);
      log.debug("Leaving RiskStore.geography(). Database.");
      return Promise.resolve(this.driver.riskGeography(realm, {
        since: Number(o.since) || 0, sessionIds: sessionIds,
        countries: codes,
        continents: codes.map(function (c: string): string {
          return continents[c];
        }) }));
    }
    const since = Number(o.since) || 0;
    let rows = (this.assessments.get(String(realm || '')) || [])
      .filter(function (a: Json): boolean {
        return a.at >= since && !!a.subject;
      });
    if (sessionIds) {
      const wanted = new Set(sessionIds);
      const latest = new Map<string, Json>();
      rows.forEach(function (a: Json): void {
        const sid = String(a.sessionId || '');
        const held = latest.get(sid);
        if (wanted.has(sid) && (!held || a.at >= held.at)) {
          latest.set(sid, a);
        }
      });
      rows = Array.from(latest.values());
    }
    const groups = new Map<string, Json>();
    const count = function (level: string, key: string[], a: Json): void {
      const id = level + '\u0000' + key.join('\u0000');
      let g = groups.get(id);
      if (!g) {
        g = { level: level, continent: key[0] || '', country: key[1] || '',
              subdivision: key[2] || '', city: key[3] || '',
              people: new Set<string>(), signIns: 0, assessments: 0,
              latSum: 0, lonSum: 0, located: 0, lastAt: 0 };
        groups.set(id, g);
      }
      g.people.add(String(a.subject));
      g.assessments++;
      g.signIns += a.phase === 'user' ? 1 : 0;
      if (typeof a.latitude === 'number' && typeof a.longitude === 'number') {
        g.latSum += a.latitude;
        g.lonSum += a.longitude;
        g.located++;
      }
      g.lastAt = Math.max(g.lastAt, Number(a.at) || 0);
    };
    rows.forEach(function (a: Json): void {
      const country = String(a.country || '');
      const continent = continents[country] || '';
      count('world', [], a);
      count('continent', [continent], a);
      count('country', [continent, country], a);
      count('city', [continent, country, String(a.subdivision || ''),
                     String(a.city || '')], a);
    });
    log.debug("Leaving RiskStore.geography(). Memory.");
    return Promise.resolve({
      rows: Array.from(groups.values()).map(function (g: Json): Json {
        return { level: g.level, continent: g.continent, country: g.country,
                 subdivision: g.subdivision, city: g.city,
                 people: g.people.size, signIns: g.signIns,
                 assessments: g.assessments,
                 latitude: g.located ? g.latSum / g.located : null,
                 longitude: g.located ? g.lonSum / g.located : null,
                 lastAt: g.lastAt };
      }) });
  }

  // A score's band, a decade each, for the histogram. The score is a
  // likelihood ratio — 1 is as likely an attacker as the person — and the
  // levels begin at 1 (MEDIUM) and 10 (HIGH) by default, so those are two
  // of the edges. A hot path — once per assessment
  // counted — so no Entering or Leaving pair would add anything but volume.
  static bandOf(score: number): string {
    if (score < 0.01) {
      return '< 0.01';
    }
    if (score < 0.1) {
      return '0.01 – 0.1';
    }
    if (score < 1) {
      return '0.1 – 1';
    }
    if (score < 10) {
      return '1 – 10';
    }
    if (score < 100) {
      return '10 – 100';
    }
    return '≥ 100';
  }

  // The bands, lowest first, for a page that draws them in order.
  static readonly BANDS = ['< 0.01', '0.01 – 0.1', '0.1 – 1', '1 – 10',
                           '10 – 100', '≥ 100'];

  // The grouped rows, from either store, as the page and the API read them.
  static metricsOf(grouped: Json): Json {
    log.debug("Entering RiskStore.metricsOf().");
    const g = grouped || {};
    const by: Record<string, Record<string, number>> = {
      level: {}, door: {}, decision: {}, phase: {}, country: {}, band: {},
      feedback: {}, signal: {} };
    // Per signal, by level and by answer: `signal\u0001LEVEL` apart.
    const pairs: Record<string, Record<string, Record<string, number>>> = {
      'signal-level': {}, 'signal-feedback': {} };
    (g.groups || []).forEach(function (row: Json): void {
      if (pairs[row.k]) {
        const cut = String(row.v).indexOf('\u0001');
        const id = String(row.v).slice(0, cut);
        const of = String(row.v).slice(cut + 1);
        const table = pairs[row.k][id] || (pairs[row.k][id] = {});
        table[of] = (table[of] || 0) + Number(row.n);
      } else if (by[row.k] && row.v !== '') {
        by[row.k][row.v] = (by[row.k][row.v] || 0) + Number(row.n);
      }
    });
    const buckets = new Map<number, Json>();
    (g.series || []).forEach(function (row: Json): void {
      const at = Number(row.bucket);
      const held = buckets.get(at) || { at: at, total: 0 };
      held[String(row.level || 'UNSCORED')] =
        (held[String(row.level || 'UNSCORED')] || 0) + Number(row.n);
      held.total += Number(row.n);
      buckets.set(at, held);
    });
    const t = g.totals || {};
    log.debug("Leaving RiskStore.metricsOf().");
    return {
      total: Number(t.total) || 0,
      subjects: Number(t.subjects) || 0,
      bots: Number(t.bots) || 0,
      meanScore: Number(t.meanScore) || 0,
      maxScore: Number(t.maxScore) || 0,
      byLevel: by.level, byDoor: by.door, byDecision: by.decision,
      byPhase: by.phase, byCountry: by.country, byBand: by.band,
      bySignal: by.signal,
      bySignalLevel: pairs['signal-level'],
      bySignalFeedback: pairs['signal-feedback'],
      scoreQuantiles: Object.assign({}, g.quantiles || {}),
      feedback: { confirmed: by.feedback.confirmed || 0,
                  denied: by.feedback.denied || 0 },
      series: Array.from(buckets.values()).sort(function (a: Json,
                                                          b: Json): number {
        return a.at - b.at;
      })
    };
  }

  // How many people stand at each level now, and the reactions their
  // standings record as taken.
  subjectLevels(realm: string, sealing: boolean): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.subjectLevels().");
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.subjectLevels(). Database.");
      return Promise.resolve(this.driver.riskSubjectLevels(realm));
    }
    const out: Record<string, number> = {};
    const held = this.subjectStates.get(String(realm || ''));
    if (held) {
      held.forEach(function (row: Json): void {
        const level = String(row.level || 'UNSCORED');
        out[level] = (out[level] || 0) + 1;
      });
    }
    log.debug("Leaving RiskStore.subjectLevels(). Memory.");
    return Promise.resolve(out);
  }

  // What was decided on an assessment (#62 P3) — see the driver's
  // `riskSettleAssessment()`. In memory the row is found and amended.
  settleAssessment(a: Json, sealing: boolean): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.settleAssessment(). " + a.id);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.settleAssessment(). Database.");
      return Promise.resolve(this.driver.riskSettleAssessment(a));
    }
    const held = this.assessments.get(String(a.realm || '')) || [];
    for (let i = held.length - 1; i >= 0; i--) {
      if (held[i].id === a.id) {
        held[i].decision = a.decision || '';
        held[i].policyId = a.policyId || '';
        held[i].errorCode = a.errorCode || '';
        if (a.sessionId) {
          held[i].sessionId = a.sessionId;
        }
        log.debug("Leaving RiskStore.settleAssessment(). Memory.");
        return Promise.resolve(true);
      }
    }
    log.debug("Leaving RiskStore.settleAssessment(). Not held.");
    return Promise.resolve(false);
  }

  // A reaction to a change of risk, claimed once per assessment (#62 P4) —
  // see the driver's `riskClaimAction()`. True when this caller may take it.
  claimAction(realm: string, subject: string, reaction: string,
              assessmentId: string, sealing: boolean): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.claimAction(). " + reaction);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.claimAction(). Database.");
      return Promise.resolve(this.driver.riskClaimAction(realm, subject,
                                                         reaction,
                                                         assessmentId));
    }
    const held = this.subjectStates.get(String(realm || ''));
    const row = held ? held.get(subject) : null;
    if (!row) {
      log.debug("Leaving RiskStore.claimAction(). Nobody to claim on.");
      return Promise.resolve(false);
    }
    row.actions = row.actions || {};
    if (row.actions[reaction] === assessmentId) {
      log.debug("Leaving RiskStore.claimAction(). Already taken.");
      return Promise.resolve(false);
    }
    row.actions[reaction] = assessmentId;
    log.debug("Leaving RiskStore.claimAction(). Claimed.");
    return Promise.resolve(true);
  }

  // What the person said about one of their own sign-ins (#62 P6): only an
  // assessment of that subject, and only once. True when it was recorded.
  setFeedback(realm: string, id: string, subject: string, feedback: string,
              at: number, sealing: boolean): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.setFeedback(). " + id);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.setFeedback(). Database.");
      return Promise.resolve(this.driver.riskSetFeedback(realm, id, subject,
                                                          feedback, at));
    }
    const held = this.assessments.get(String(realm || '')) || [];
    for (let i = held.length - 1; i >= 0; i--) {
      if (held[i].id === id && held[i].subject === subject &&
          !held[i].feedback) {
        held[i].feedback = feedback;
        held[i].feedbackAt = at;
        log.debug("Leaving RiskStore.setFeedback(). Memory.");
        return Promise.resolve(true);
      }
    }
    log.debug("Leaving RiskStore.setFeedback(). Not recorded.");
    return Promise.resolve(false);
  }

  // One person's standing, or null.
  subjectOf(realm: string, subject: string,
            sealing: boolean): Promise<Json | null> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.subjectOf().");
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.subjectOf(). Database.");
      return Promise.resolve(this.driver.riskSubjectOf(realm, subject));
    }
    const held = this.subjectStates.get(String(realm || ''));
    const row = held ? held.get(subject) : null;
    log.debug("Leaving RiskStore.subjectOf(). Memory.");
    return Promise.resolve(row ? Object.assign({}, row) : null);
  }

  upsertSubject(s: Json, sealing: boolean): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.upsertSubject().");
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.upsertSubject(). Database.");
      return Promise.resolve(this.driver.riskUpsertSubject(s));
    }
    const realm = String(s.realm || '');
    if (!this.subjectStates.has(realm)) {
      this.subjectStates.set(realm, new Map());
    }
    const held = this.subjectStates.get(realm);
    const before = held.get(s.subject);
    held.set(s.subject, {
      subject: s.subject, score: Number(s.score), level: s.level,
      previousLevel: before ? before.level : '', reason: s.reason || '',
      lastAssessment: s.lastAssessment || '',
      crossedAt: !before || before.level !== s.level ? s.updatedAt
        : before.crossedAt,
      // The reactions already taken (#62 P4) survive a new standing, as
      // the database's ON CONFLICT leaves `actions` alone.
      actions: before && before.actions ? before.actions : {},
      updatedAt: s.updatedAt });
    log.debug("Leaving RiskStore.upsertSubject(). Memory.");
    return Promise.resolve(true);
  }

  // A page of the realm's people by current standing, with the count of
  // them all (`{ total, rows }`, as `listAssessments()` answers).
  listSubjects(realm: string, opts: Json, sealing: boolean): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.listSubjects().");
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.listSubjects(). Database.");
      return Promise.resolve(this.driver.riskListSubjects(realm, opts));
    }
    const out = [];
    (this.subjectStates.get(String(realm || '')) || new Map())
      .forEach(function (row: Json): void {
        out.push(Object.assign({}, row));
      });
    out.sort(function (a: Json, b: Json): number {
      return (b.score - a.score) || (b.updatedAt - a.updatedAt) ||
        (a.subject < b.subject ? -1 : a.subject > b.subject ? 1 : 0);
    });
    const offset = Number((opts || {}).offset) || 0;
    const limit = Number((opts || {}).limit) || 50;
    log.debug("Leaving RiskStore.listSubjects(). Memory.");
    return Promise.resolve({ total: out.length,
                             rows: out.slice(offset, offset + limit) });
  }

  upsertSessionContext(c: Json, sealing: boolean): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.upsertSessionContext().");
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.upsertSessionContext(). Database.");
      return Promise.resolve(this.driver.riskUpsertSessionContext(c));
    }
    const realm = String(c.realm || '');
    if (!this.sessionContexts.has(realm)) {
      this.sessionContexts.set(realm, new Map());
    }
    this.sessionContexts.get(realm).set(c.sessionId, Object.assign({}, c));
    log.debug("Leaving RiskStore.upsertSessionContext(). Memory.");
    return Promise.resolve(true);
  }

  // The session context held in this process, for the tests; the database
  // one is read by P4.
  sessionContextOf(realm: string, sessionId: string): Json | null {
    const { log } = this.deps;
    log.debug("Entering RiskStore.sessionContextOf().");
    const held = this.sessionContexts.get(String(realm || ''));
    log.debug("Leaving RiskStore.sessionContextOf().");
    return held && held.has(sessionId)
      ? Object.assign({}, held.get(sessionId)) : null;
  }

  purgeHistory(table: string, beforeMs: number, limit: number,
               sealing: boolean): Promise<number> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.purgeHistory(). " + table);
    if (this.failuresInDatabase(sealing)) {
      log.debug("Leaving RiskStore.purgeHistory(). Database.");
      return Promise.resolve(this.driver.riskPurgeHistory(table, beforeMs,
                                                           limit));
    }
    let removed = 0;
    if (table === 'assessments') {
      this.assessments.forEach(function (held: Json[], realm: string,
                                         all: Map<string, Json[]>): void {
        const kept = held.filter(function (a: Json): boolean {
          return a.at >= beforeMs;
        });
        removed += held.length - kept.length;
        all.set(realm, kept);
      });
    } else if (table === 'counts') {
      this.counts.forEach(function (bySubject): void {
        bySubject.forEach(function (held): void {
          held.forEach(function (row: Json, k: string): void {
            if (row.lastAt < beforeMs) {
              held.delete(k);
              removed += 1;
            }
          });
        });
      });
    } else if (table === 'sessions') {
      this.sessionContexts.forEach(function (held): void {
        held.forEach(function (row: Json, k: string): void {
          if (row.updatedAt < beforeMs) {
            held.delete(k);
            removed += 1;
          }
        });
      });
    }
    log.debug("Leaving RiskStore.purgeHistory(). Memory, " + removed + ".");
    return Promise.resolve(removed);
  }

  // ===== TERMS ACCEPTANCES (#62, schema 8) =================================
  //
  // Not personal data about the people who sign in — the operator's own name
  // for their own act — so in the database whenever there is one, sealing or
  // not.

  recordAcceptance(a: Json): Promise<string> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.recordAcceptance(). " + a.provider);
    if (this.driver) {
      log.debug("Leaving RiskStore.recordAcceptance(). Database.");
      return Promise.resolve(this.driver.riskRecordAcceptance(a));
    }
    const id = String(this.acceptances.length + 1);
    this.acceptances.unshift(Object.assign({ id: id }, a));
    log.debug("Leaving RiskStore.recordAcceptance(). Memory.");
    return Promise.resolve(id);
  }

  listAcceptances(): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering RiskStore.listAcceptances().");
    if (this.driver) {
      log.debug("Leaving RiskStore.listAcceptances(). Database.");
      return Promise.resolve(this.driver.riskListAcceptances());
    }
    log.debug("Leaving RiskStore.listAcceptances(). Memory.");
    return Promise.resolve(this.acceptances.map(function (a: Json): Json {
      return Object.assign({}, a);
    }));
  }

  // For tests: forget everything held in this process.
  reset(): void {
    const { log } = this.deps;
    log.debug("Entering RiskStore.reset().");
    this.datasets.clear();
    this.versions.clear();
    this.ranges.clear();
    this.unsorted.clear();
    this.fido.clear();
    this.failures.clear();
    this.failureSeq = 0;
    this.counts.clear();
    this.assessments.clear();
    this.subjectStates.clear();
    this.sessionContexts.clear();
    this.acceptances.length = 0;
    log.debug("Leaving RiskStore.reset().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), with facades.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<RiskStore>(
  'risk/risk_store',
  () => new RiskStore(RiskStore.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

export = {
  RiskStore: RiskStore,
  installInstance: (instance: RiskStore): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  RISK_GROUP: RiskStore.RISK_GROUP,
  addressNumber: RiskStore.addressNumber,
  addressText: RiskStore.addressText,
  rangeOf: RiskStore.rangeOf,
  prefixOf: RiskStore.prefixOf,
  setDriver: slot.forward('setDriver'),
  clearDriver: slot.forward('clearDriver'),
  inDatabase: slot.forward('inDatabase'),
  describe: slot.forward('describe'),
  onActivated: slot.forward('onActivated'),
  noteActivated: slot.forward('noteActivated'),
  listDatasets: slot.forward('listDatasets'),
  listVersions: slot.forward('listVersions'),
  beginVersion: slot.forward('beginVersion'),
  insertRows: slot.forward('insertRows'),
  finishVersion: slot.forward('finishVersion'),
  touchVersion: slot.forward('touchVersion'),
  abandonStalled: slot.forward('abandonStalled'),
  activate: slot.forward('activate'),
  deleteRows: slot.forward('deleteRows'),
  markRowsDeleted: slot.forward('markRowsDeleted'),
  lookupRange: slot.forward('lookupRange'),
  lookupFido: slot.forward('lookupFido'),
  failuresInDatabase: slot.forward('failuresInDatabase'),
  recordFailure: slot.forward('recordFailure'),
  listFailures: slot.forward('listFailures'),
  purgeFailures: slot.forward('purgeFailures'),
  featureCounts: slot.forward('featureCounts'),
  distinctValues: slot.forward('distinctValues'),
  incrementCounts: slot.forward('incrementCounts'),
  recordAssessment: slot.forward('recordAssessment'),
  listAssessments: slot.forward('listAssessments'),
  upsertSubject: slot.forward('upsertSubject'),
  assessmentMetrics: slot.forward('assessmentMetrics'),
  subjectLevels: slot.forward('subjectLevels'),
  geography: slot.forward('geography'),
  bandOf: RiskStore.bandOf,
  BANDS: RiskStore.BANDS,
  settleAssessment: slot.forward('settleAssessment'),
  subjectOf: slot.forward('subjectOf'),
  claimAction: slot.forward('claimAction'),
  setFeedback: slot.forward('setFeedback'),
  listSubjects: slot.forward('listSubjects'),
  upsertSessionContext: slot.forward('upsertSessionContext'),
  sessionContextOf: slot.forward('sessionContextOf'),
  purgeHistory: slot.forward('purgeHistory'),
  recordAcceptance: slot.forward('recordAcceptance'),
  listAcceptances: slot.forward('listAcceptances'),
  reset: slot.forward('reset')
};
