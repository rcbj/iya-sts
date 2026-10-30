// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_report.ts
//
// ---------------------------------------------------------------------------
// WHO HOLDS WHICH KIND OF PASSKEY, ACROSS A REALM (#942, 2026-10-23).
//
// A passkey's algorithm showed per person — on `/admin/users`, in the MFA
// roster and on the portal — and nowhere for a realm: no count of the people
// holding an ML-DSA passkey, a classical one only, both, or none, so a move
// to post-quantum keys (RFC 9964's ML-DSA, the two lanes of #643,
// `postQuantumRequired` of #718) could not be measured. This module is the
// report behind Monitoring → Passkeys and `GET /admin-api/passkey-report`:
//
//   * passkeys by ALGORITHM (the JOSE name and the COSE id `keyAlgorithm()`
//     reads off each stored key) and by LANE (`keyLane()`, #643);
//   * people by KIND — post-quantum only, classical only, both, none — and
//     the kind is the ALGORITHM, never the lane, #718's rule: with the lanes
//     off an authenticator that makes ML-DSA does so in the one lane;
//   * which AAGUIDs (authenticator models) hold which algorithms;
//   * each passkey profile's `postQuantumRequired`, beside the counts, so a
//     reader sees what the realm asks of the people counted.
//
// **THE COUNTS ARE A MAINTAINED AGGREGATE, NEVER A SCAN PER REQUEST** (rcbj
// on #942: "it must hold at the directory's large scale (#820)"). The
// directory holds millions of people on 8081; a page that read every
// person's keys to draw four numbers would be the walk #615, #616 and #820
// spent a month removing. So:
//
//   1. **A BASELINE**, counted by the scheduler job `passkeys.report-recount`
//      (daily, in every realm, and on Recount now) from the HOLDERS of
//      `stsWebauthnCredential` a page at a time, asynchronously, after a key
//      cursor — the asked names' index (`persistence/directory_queries.js`),
//      never `ou=users` walked. It is one row of `passkey_report.baseline`
//      (per realm, persisted, whole-valued: the latest count is the truth)
//      under a fresh EPOCH.
//   2. **THE CHANGES SINCE**, noted where the keys are written. The directory
//      has exactly two doors that write `stsWebauthnCredential`
//      (`ldap_server.js`'s `writeWebauthnValue()` and
//      `replaceWebauthnValues()` — every enrolment, removal, rename, counter
//      update and attestation rewrite goes through one of them, and a socket
//      write of the attribute is refused, #237) and ONE door that deletes a
//      person (`removePersonEntry()`: SCIM's, the LDAP delete handler's, a
//      re-homing's). Each hands this module the values before and after,
//      and the DIFFERENCE of the two sets of facets is added to this
//      process's own row of `passkey_report.changes` — `merge: 'own'`,
//      because a delta is an INCREMENT and two processes' increments must
//      add, not replace (`common/realms.js`, *How two processes' copies of
//      this store combine*). A counter update changes no facet and writes
//      nothing.
//   3. **THE REPORT IS THE SUM**: the baseline plus every process's changes
//      noted under the baseline's epoch. A row noted under an older epoch is
//      the recount's to have counted, and is ignored.
//
// **WHAT THE AGGREGATE CANNOT SEE, SAID RATHER THAN HIDDEN.** A write that
// reaches the store without passing those three doors — `persistence/
// bulk_import.js` writing rows straight into the database, an LDIF restore,
// a person arriving in this cell by `putEntry()` from another — is not
// noted, and nor is a change made to a person the recount had already read
// while it was running (its delta was noted under the old epoch). Both are
// put right by the next recount, and the page says when the baseline was
// counted and how many changes have been noted since. That is the price of
// not walking the directory per request, and it is the right one: the
// alternative, a count the database keeps in its own triggers (#618's
// `sts_ldap_counts`), cannot see an algorithm — the entry's attributes are
// one sealed blob (#391) — and would need a new indexed column and a schema
// version for each dimension.
//
// **THE FILTERS ARE NOT THE AGGREGATE'S, AND THEY ARE BOUNDED.** By GROUP
// (a cn or a DN) and by PASSKEY PROFILE (#535's populations: the members of
// the groups naming the profile, `stsPasskeyPolicy` since #1235), the report
// is counted from the population's own members — read asynchronously, at
// most `POPULATION_LIMIT` of them, and said when the population is larger.
// An APPLICATION selects sign-ins, not people — it names its profile in
// `appPasskeyPolicy` since #1235 — and anybody may sign in to it, so an
// application's population is the whole realm and `application=` answers
// the realm's counts with which profile governs that application's sign-ins
// (`passkeyPolicy.forApplication()`), and how many group-selected profiles
// could still win for a person.
//
// **THE LISTS BEHIND THE COUNTS ARE PAGED BY A KEY CURSOR.** A filtered list
// (post-quantum only, one algorithm, one model) has no index of its own, so a
// page reads the holders in key order from where the page before stopped
// (`from`, which every answer hands back as `paging.nextFrom`), at most
// `LIST_SCAN` holders a request, and says so when it stopped before the page
// was full. The export reads on to `EXPORT_LIMIT` rows.
//
// **THE ATTESTATION CERTIFICATE (#941).** `attestationFacetOf()` reads the
// leaf certificate's signature algorithm off `attestation.algorithms` (the
// record #941 stores; a compound statement's members are walked the same
// way, and the anchor is used only when the statement carried no
// certificate). A key from before that record, or one whose attestation
// had no certificate, answers null, so it is not a `t|` facet and the
// Attestation tab says nothing was recorded. The facet is
// `t|<algorithm>|<coseAlg>|<1|0>`: the COSE identifier when the
// certificate algorithm is also a COSE name (ML-DSA-44/65/87), empty
// otherwise, and `1` when that certificate's signature is post-quantum.
//
// **THE HISTORY (#1109).** The baseline is the latest count and nothing
// kept yesterday's, so a migration to ML-DSA passkeys could be read for
// today and never as a trend. The RECOUNT itself now writes one row of
// `passkey_report.history` per realm per UTC day, keyed by the day, right
// after it writes the baseline: people by kind, passkeys by algorithm, by
// lane and by attestation algorithm, and each named passkey profile's
// population (bounded, as the filter is). In the same job and not a
// sibling one, for three reasons: the snapshot is then EXACTLY the count
// just made, with no changes noted under the new epoch yet; the scheduler
// orders no job after another, so a sibling would have to find out whether
// a recount had run since its last run; and a Recount now that the
// operator asks for updates the day's row with the rest. A later recount on
// the same day replaces that day's row: the latest count is the truth, as
// it is for the baseline. The same run then removes the rows older than
// `webauthn.passkeyHistoryDays` — the store holds a few hundred small rows
// per realm, so the prune is a walk of keys already in memory, and nothing
// periodic runs outside the scheduler. A failure to write or prune is
// logged (`STS-AUTHN-0520`, `0521`) and never fails the recount: the
// baseline it exists for is already written. The reports application reads
// the rows as its `passkeyHistory` source (`report/passkey_history.ts`).
//
// A LIBRARY (rule 3): it registers no route. It requires `helpers`,
// `error_codes`, `realms`, `credentials` (a leaf), `instance_slot` and the
// replication fan-in, none of which requires it back; the scheduler, the
// passkey policy and the application registry are reached lazily. THE
// DIRECTORY ARRIVES THROUGH `setDirectory()`, filled by `ldap/ldap_server.js`
// at require time, and it is a slot for rule 3e's two reasons at once:
// `ldap_server.js` requires this module (its write doors note here), so a
// require back would close a cycle; and the composition root builds this at
// 18j-iii, before the directory at 21, where a require of that JavaScript
// route module would drag its `/admin/ldap/*` routes ahead of the console's.
// It is validated whole.
//
// TYPESCRIPT, AS A CLASS (#50): `PasskeyReport` takes its dependencies
// through its constructor; the two stores are declared at module scope,
// because a store becomes per realm at its declaration; the composition root
// builds the instance (`common/protocol_stack.ts`), and the exports are
// facades that forward to it.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import errorCodes = require('./error_codes');
import realms = require('./realms');
import credentials = require('./credentials');
import config = require('./config');
import replication = require('../persistence/persistence_replication');
import InstanceSlot = require('./instance_slot');

type Json = any;

// One person as the directory hands them over: their name, their entry's DN
// and their `stsWebauthnCredential` values, raw. What the values MEAN is
// `credentials.ts`'s (`keysOfValues()`, `keyAlgorithm()`, `keyLane()`).
interface HolderRow {
  id: string;
  dn: string;
  values: string[];
}

// What `scanAsync()` is asked: holders (`attribute` set) or every person
// (`attribute` ''), after a cursor, reading at most `readLimit` entries and
// stopping once `accept()` has said yes `wanted` times.
interface ScanAsk {
  attribute: string;
  after: string;
  readLimit: number;
  wanted: number;
  accept(row: HolderRow): boolean;
}

interface ScanAnswer {
  next: string;
  read: number;
  done: boolean;
}

interface PopulationAnswer {
  groups: Array<{ asked: string; dn: string; found: boolean;
                  members: number }>;
  rows: HolderRow[];
  members: number;
  complete: boolean;
}

// THE DIRECTORY'S HALF, filled by `ldap/ldap_server.js` (rule 3e).
interface PasskeyDirectory {
  scanAsync(ask: ScanAsk): Promise<ScanAnswer>;
  populationAsync(selectors: string[], limit: number):
    Promise<PopulationAnswer>;
  personCount(): number;
}

interface Store {
  has(key: string): boolean;
  get(key: string): any;
  set(key: string, value: any): unknown;
  delete(key: string): unknown;
}

// The history store also hands out its keys, for the prune and the read.
interface HistoryStore extends Store {
  keys(): Iterable<string>;
}

interface PasskeyReportDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  realms: Json;
  credentials: Json;
  baseline: Store;
  changes: Store;
  history: HistoryStore;
  historyDays(): number;
  remoteRows(handle: string, realmId: undefined, key: string): any[];
  refreshContributions(handles: string[]): Promise<unknown>;
  scheduler(): Json;
  passkeyPolicy(): Json;
  applications(): Json;
  randomId(): string;
  now(): number;
}

const BASELINE_HANDLE = 'passkey_report.baseline';
const CHANGES_HANDLE = 'passkey_report.changes';
const BASELINE_KEY = 'baseline';
const CHANGES_KEY = 'changes';
const HISTORY_HANDLE = 'passkey_report.history';

/** The scheduler job that counts the baseline. */
const RECOUNT_JOB = 'passkeys.report-recount';

// The attribute the keys are held in, lower-cased as the directory stores it.
const ATTRIBUTE = 'stswebauthncredential';

// THE FOUR KINDS OF PERSON, in the order a page offers them.
const KINDS = ['post-quantum-only', 'classical-only', 'both', 'none'];

// The lists behind the counts: the four kinds, everybody holding a passkey,
// one algorithm (in one lane or both), one model.
const LISTS = KINDS.concat(['holding', 'algorithm', 'model']);

// How many holders the recount reads between two `stillOwner()` questions.
const RECOUNT_SLICE = 5000;
// How many entries one list request may read before it stops and says so.
const LIST_SCAN = 20000;
// How many members a group or profile filter reads.
const POPULATION_LIMIT = 50000;
// How many rows an export carries at most.
const EXPORT_LIMIT = 100000;
// THE MODEL TABLE IS BOUNDED. An AAGUID is what an authenticator says it
// is, so a table keyed by it is a table a client can grow: past this many
// distinct AAGUIDs a row folds the rest into `(other)`.
const MAX_MODELS = 1000;
// The page sizes a list offers, the first the default.
const PER_DEFAULT = 50;
const PER_MAX = 500;
const DAY_MS = 24 * 60 * 60 * 1000;
// How many named passkey profiles a history row counts the population of
// (#1109). Each is a bounded read of up to POPULATION_LIMIT members, once a
// day; past this many profiles the rest are named in the row as skipped,
// so a realm with hundreds of profiles does not turn the daily recount
// into hundreds of population reads.
const HISTORY_PROFILES = 25;
// The retention when the setting cannot be read: `config.js`'s default.
const HISTORY_DAYS_DEFAULT = 400;

// The baseline is the latest count, whole: an ASSIGNMENT.
const baselineStore = realms.map({ persist: BASELINE_HANDLE });
// The changes since are INCREMENTS: each process's own row, added where
// they are reported (`merge: 'own'`), and read from the other processes
// only when the page is drawn (`contributionsOnRead`, #820). A note rides
// the write of the keys it describes, so it is an `observation`: it does not
// by itself make a request one that wrote.
const changesStore = realms.map({ persist: CHANGES_HANDLE, merge: 'own',
                                  contributionsOnRead: true,
                                  observation: true });
// THE HISTORY (#1109): one row per UTC day, keyed `yyyy-mm-dd`, whole-valued
// as the baseline is (a later recount the same day replaces the day's row).
// The handle is written out rather than named by the constant above, so
// `tests/cell_tiers.js`, which reads every `persist:` literal, sees it.
const historyStore = realms.map({ persist: 'passkey_report.history' });

/**
 * The passkey report (#942): passkeys by algorithm and lane, people by kind,
 * models by algorithm, per realm — a maintained aggregate, never a scan per
 * request — with bounded filters, cursor-paged lists and an export.
 */
class PasskeyReport {
  /** The scheduler job that counts the baseline. */
  static readonly RECOUNT_JOB = RECOUNT_JOB;
  /** The four kinds of person. */
  static readonly KINDS = KINDS;
  /** The lists a count opens. */
  static readonly LISTS = LISTS;
  /** How many entries one list request may read. */
  static readonly LIST_SCAN = LIST_SCAN;
  /** How many members a group or profile filter reads. */
  static readonly POPULATION_LIMIT = POPULATION_LIMIT;
  /** How many rows an export carries at most. */
  static readonly EXPORT_LIMIT = EXPORT_LIMIT;
  /** The largest page a list answers. */
  static readonly PER_MAX = PER_MAX;

  private directory: PasskeyDirectory | null = null;

  /**
   * Builds the report over its dependencies.
   *
   * @param deps - the logger, the error codes, the realms, the credential
   *   store's static readers, the two stores and the lazy loaders
   */
  constructor(private readonly deps: PasskeyReportDeps) {
    deps.log.debug("Entering PasskeyReport.constructor().");
    deps.log.debug("Leaving PasskeyReport.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): PasskeyReportDeps {
    helpers.log.debug("Entering PasskeyReport.defaultDeps().");
    helpers.log.debug("Leaving PasskeyReport.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      realms: realms,
      credentials: credentials,
      baseline: baselineStore as Store,
      changes: changesStore as Store,
      history: historyStore as HistoryStore,
      historyDays: function (): number {
        const days = Number(config.value('webauthn.passkeyHistoryDays'));
        return Number.isFinite(days) && days >= 1 ? Math.floor(days)
                                                  : HISTORY_DAYS_DEFAULT;
      },
      remoteRows: function (handle, realmId, key) {
        return replication.remoteRows(handle, realmId, key);
      },
      refreshContributions: function (handles) {
        return typeof replication.refreshContributions === 'function'
          ? replication.refreshContributions(handles) : Promise.resolve(0);
      },
      // Lazily: the scheduler, the passkey policy and the registry are no
      // business of this file's load.
      scheduler: function () {
        return require('../cluster/scheduler');
      },
      passkeyPolicy: function () {
        return require('./passkey_policy');
      },
      applications: function () {
        return require('./applications');
      },
      // crypto.js is the one place that reads node's CSPRNG (#453).
      // Lazy, so loading this report does not load the crypto module
      // before the composition root has built it.
      randomId: function () {
        return require('./crypto').randomBytes(9).toString('base64url');
      },
      now: function () {
        return Date.now();
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE DIRECTORY SLOT (rule 3e), validated whole: a filler that installed
  // the scan and not the population would leave a page that counts the
  // realm and refuses every filter, with nothing saying why.
  // -------------------------------------------------------------------------
  /**
   * Installs the directory's half: the scan, the population and the count.
   *
   * @param directory - `{ scanAsync, populationAsync, personCount }`
   * @returns true when installed; false (and logged) for a partial object
   */
  setDirectory(directory: Json): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PasskeyReport.setDirectory().");
    const missing = ['scanAsync', 'populationAsync', 'personCount']
      .filter(function (name) {
        return !directory || typeof directory[name] !== 'function';
      });
    if (missing.length) {
      log.error(errorCodes.tag('STS-AUTHN-0417') + 'passkey report: the ' +
                'directory offered no ' + missing.join(', ') + ', so ' +
                'nothing was installed; the report counts nothing until it ' +
                'is.');
      log.debug("Leaving PasskeyReport.setDirectory(). Partial.");
      return false;
    }
    this.directory = directory as PasskeyDirectory;
    log.debug("Leaving PasskeyReport.setDirectory().");
    return true;
  }

  // -------------------------------------------------------------------------
  // WHAT ONE PERSON'S KEYS COUNT FOR. A flat map of facet → count, so a
  // difference and a sum are one loop each:
  //
  //   p|<kind>                        the person, once (no row for `none`)
  //   k|<algorithm>|<coseAlg>|<lane>  each key
  //   m|<aaguid>|<algorithm>|<coseAlg> each key, by model ('' unreported)
  //   t|<algorithm>|<coseAlg>|<pq>    each key's attestation certificate
  //                                   (#941), see `attestationFacetOf()`
  //
  // `names` carries the model name recorded on a key, by AAGUID, for the
  // page; it is not a count.
  // -------------------------------------------------------------------------
  // Hot path (once per person a recount, a list or an export reads, which
  // is every holder of a realm): no Entering/Leaving pair, the exception the
  // code style allows, stated as it requires.
  /**
   * The attestation certificate's signature algorithm of one stored key
   * (#941). The leaf of `attestation.algorithms`, which is what #941
   * recorded; null when that record is absent or names no certificate, so
   * a key from before #941 is not counted under `t|`.
   *
   * Hot path (once per key a recount, a list or an export reads): no
   * Entering/Leaving pair, the exception the code style allows. It does
   * not call `credentials.attestationAlgorithms()`, whose debug lines
   * would run once per key of every holder.
   *
   * @param key - one stored key
   * @returns `{ algorithm, coseAlg, postQuantum }`, or null where no
   *   certificate algorithm is recorded. `coseAlg` is the COSE identifier
   *   when the certificate algorithm is also a COSE name, and null
   *   otherwise (a certificate signature is not a COSE algorithm).
   */
  static attestationFacetOf(key: Json): { algorithm: string;
      coseAlg: number | null; postQuantum: boolean } | null {
    const algorithms = key && key.attestation &&
      key.attestation.algorithms;
    if (!algorithms || typeof algorithms !== 'object') {
      return null;
    }
    const parts = [algorithms].concat(Array.isArray(algorithms.members)
      ? algorithms.members : []);
    let leaf: Json = null;
    for (let i = 0; i < parts.length && !leaf; i += 1) {
      const certs = parts[i] && Array.isArray(parts[i].certificates)
        ? parts[i].certificates : [];
      const first = certs.length ? certs[0] : null;
      if (first && first.algorithm &&
          String(first.algorithm) !== 'unreadable') {
        leaf = first;
      }
    }
    if (!leaf && algorithms.anchor && algorithms.anchor.algorithm &&
        String(algorithms.anchor.algorithm) !== 'unreadable') {
      leaf = algorithms.anchor;
    }
    if (!leaf) {
      return null;
    }
    // A `|` would split the facet. No algorithm this service names has
    // one; one it does not is still one row.
    const name = String(leaf.algorithm).split('|').join('/');
    const coseAlg = name === 'ML-DSA-44' ? -48
      : (name === 'ML-DSA-65' ? -49
         : (name === 'ML-DSA-87' ? -50 : null));
    return { algorithm: name, coseAlg: coseAlg,
             postQuantum: leaf.postQuantum === true };
  }

  // Hot path (once per person a recount, a list or an export reads, which
  // is every holder of a realm): no Entering/Leaving pair, the exception the
  // code style allows, stated as it requires.
  /**
   * What one person's stored values count for.
   *
   * @param values - their `stsWebauthnCredential` values, raw
   * @param who - their name, for a warning about a value that is not a key
   * @returns `{ kind, counts, names, keys }`: `keys` each key's algorithm,
   *   lane, AAGUID and model, for a list row
   */
  facetsOfValues(values: unknown, who: string): Json {
    const { log, credentials } = this.deps;
    const parsed = credentials.keysOfValues(values, who) || [];
    const counts: Record<string, number> = {};
    const names: Record<string, string> = {};
    const add = function (facet: string): void {
      counts[facet] = (counts[facet] || 0) + 1;
    };
    let pq = 0;
    let classical = 0;
    const keys = parsed.map(function (key: Json): Json {
      const alg = credentials.keyAlgorithm(key);
      const aaguid = credentials.aaguidString(key.aaguid);
      let model = '';
      try {
        model = String(credentials.keyProvider(key) || '');
      } catch (e) {
        log.debug("Caught in PasskeyReport.facetsOfValues(): " +
                  ((e && e.message) || e));
        // A name nobody can give is no name; the AAGUID still counts.
        model = '';
      }
      if (alg.postQuantum) {
        pq += 1;
      } else {
        classical += 1;
      }
      add('k|' + alg.name + '|' + alg.coseAlg + '|' + alg.lane);
      add('m|' + aaguid + '|' + alg.name + '|' + alg.coseAlg);
      const attested = PasskeyReport.attestationFacetOf(key);
      if (attested) {
        add('t|' + attested.algorithm + '|' +
            (attested.coseAlg === null ? '' : String(attested.coseAlg)) +
            '|' + (attested.postQuantum ? '1' : '0'));
      }
      if (aaguid && model) {
        names[aaguid] = model.slice(0, 120);
      }
      // No `role` since #1135: a key carries none, and the list row that
      // echoed the stored one (it was never a facet) would now be empty.
      return { algorithm: alg.name, coseAlg: alg.coseAlg,
               postQuantum: alg.postQuantum, lane: alg.lane,
               aaguid: aaguid, model: model };
    });
    const kind = pq && classical ? 'both'
      : (pq ? 'post-quantum-only' : (classical ? 'classical-only' : 'none'));
    if (kind !== 'none') {
      add('p|' + kind);
    }
    return { kind: kind, counts: counts, names: names, keys: keys };
  }

  // Hot path (once per person a recount, a list or an export reads, which
  // is every holder of a realm): no Entering/Leaving pair, the exception the
  // code style allows, stated as it requires.
  // Adds `from` into `into`, times `sign`; a zero is dropped. A model past
  // MAX_MODELS distinct AAGUIDs is folded into `(other)`.
  private static addCounts(into: Record<string, number>,
                           from: Record<string, number>, sign: number): void {
    let models = Object.keys(into).filter(function (k) {
      return k.indexOf('m|') === 0;
    }).length;
    Object.keys(from || {}).forEach(function (facet) {
      let key = facet;
      if (facet.indexOf('m|') === 0 && into[facet] === undefined) {
        if (models >= MAX_MODELS) {
          const parts = facet.split('|');
          key = 'm|(other)|' + parts[2] + '|' + parts[3];
        } else {
          models += 1;
        }
      }
      const n = (into[key] || 0) + sign * Number(from[facet] || 0);
      if (n === 0) {
        delete into[key];
      } else {
        into[key] = n;
      }
    });
  }

  // Hot path (once per person a recount, a list or an export reads, which
  // is every holder of a realm): no Entering/Leaving pair, the exception the
  // code style allows, stated as it requires.
  // The model names, bounded as the counts are.
  private static addNames(into: Record<string, string>,
                          from: Record<string, string>): void {
    Object.keys(from || {}).forEach(function (aaguid) {
      if (into[aaguid] !== undefined ||
          Object.keys(into).length < MAX_MODELS) {
        into[aaguid] = String(from[aaguid]);
      }
    });
  }

  // -------------------------------------------------------------------------
  // THE CHANGES, NOTED WHERE THE KEYS ARE WRITTEN.
  //
  // Called by the directory's two key-writing doors and its person delete,
  // synchronously, inside the write. **IT NEVER THROWS INTO THE WRITE**: a
  // passkey that was enrolled must not fail because a tally could not be
  // kept (`STS-AUTHN-0413`, and the next recount is right again). Called
  // once per write of somebody's keys — a sign-in's counter update at most —
  // so the pair is kept.
  // -------------------------------------------------------------------------
  /**
   * Notes the difference between a person's keys before and after a write.
   *
   * @param before - their `stsWebauthnCredential` values before
   * @param after - the values after ([] for a person deleted)
   * @param who - their name
   * @returns true when a change was noted, false when nothing moved
   */
  noteKeysChanged(before: unknown, after: unknown, who: string): boolean {
    const { log, errorCodes, baseline, changes, now } = this.deps;
    log.debug("Entering PasskeyReport.noteKeysChanged().");
    try {
      const was = this.facetsOfValues(before, who);
      const is = this.facetsOfValues(after, who);
      const delta: Record<string, number> = {};
      PasskeyReport.addCounts(delta, is.counts, 1);
      PasskeyReport.addCounts(delta, was.counts, -1);
      if (!Object.keys(delta).length) {
        log.debug("Leaving PasskeyReport.noteKeysChanged(). Nothing moved.");
        return false;
      }
      const base = baseline.has(BASELINE_KEY) ? baseline.get(BASELINE_KEY)
                                              : null;
      const epoch = base ? String(base.epoch || '') : '';
      let row = changes.has(CHANGES_KEY) ? changes.get(CHANGES_KEY) : null;
      if (!row || String(row.epoch || '') !== epoch) {
        // A row of an older epoch is the recount's to have counted.
        row = { epoch: epoch, counts: {}, names: {}, notes: 0, lastAt: '' };
      }
      PasskeyReport.addCounts(row.counts, delta, 1);
      PasskeyReport.addNames(row.names, is.names);
      row.notes = Number(row.notes || 0) + 1;
      row.lastAt = new Date(now()).toISOString();
      changes.set(CHANGES_KEY, row);
      log.debug("Leaving PasskeyReport.noteKeysChanged(). Noted.");
      return true;
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0413') + 'passkey report: a ' +
                'change to ' + String(who) + '\'s passkeys could not be ' +
                'noted, and the write it describes is unaffected; the next ' +
                'recount counts it: ' + ((e && e.message) || e));
      log.debug("Leaving PasskeyReport.noteKeysChanged(). Threw.");
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // THE RECOUNT: the scheduler job's body, in the realm it runs for.
  // -------------------------------------------------------------------------
  /**
   * Counts the realm's passkeys from the holders of `stsWebauthnCredential`,
   * a slice at a time, and writes the result as the new baseline.
   *
   * @param ctx - the scheduler's run context (`stillOwner()` is asked
   *   between slices); optional for a caller outside the scheduler
   * @returns a promise of the run's summary
   */
  async recountAsync(ctx?: Json): Promise<Json> {
    const { log, errorCodes, realms, baseline, randomId, now } = this.deps;
    log.debug("Entering PasskeyReport.recountAsync().");
    const directory = this.directory;
    if (!directory) {
      log.debug("Leaving PasskeyReport.recountAsync(). No directory.");
      return { summary: 'No directory is installed; nothing was counted.' };
    }
    const startedAt = now();
    const counts: Record<string, number> = {};
    const names: Record<string, string> = {};
    let holders = 0;
    let evidenceRenewed = 0;
    let evidenceFailures = 0;
    let after = '';
    const self = this;
    try {
      for (;;) {
        if (ctx && typeof ctx.stillOwner === 'function' &&
            !ctx.stillOwner()) {
          log.info('passkey report: the recount of realm ' +
                   realms.currentId() + ' stopped after ' + holders +
                   ' holder(s): the run is no longer this process\'s. The ' +
                   'baseline is unchanged.');
          log.debug("Leaving PasskeyReport.recountAsync(). Fenced.");
          return { summary: 'Stopped after ' + holders + ' holder(s); the ' +
                            'baseline is unchanged.' };
        }
        const renewalCandidates: string[] = [];
        const answer = await directory.scanAsync({
          attribute: ATTRIBUTE, after: after, readLimit: RECOUNT_SLICE,
          wanted: Number.MAX_SAFE_INTEGER,
          accept: function (row: HolderRow): boolean {
            const f = self.facetsOfValues(row.values, row.id);
            PasskeyReport.addCounts(counts, f.counts, 1);
            PasskeyReport.addNames(names, f.names);
            holders += 1;
            if (row.values.some(function (value: string): boolean {
              try {
                const key = JSON.parse(value);
                const evidence = key && key.attestation &&
                  key.attestation.evidence;
                const target = String(config.value(
                  'webauthn.attestationEvidenceHashAlgorithm') || 'sha256');
                const rank: { [key: string]: number } = {
                  sha256: 1, sha384: 2, sha512: 3
                };
                return !!evidence && (Number(evidence.renewAfter || 0) <=
                  Date.now() || ((rank[target] || 0) >
                    (rank[evidence.hashAlgorithm || 'sha256'] || 1)));
              } catch (e) {
                return false;
              }
            })) {
              renewalCandidates.push(row.id);
            }
            return true;
          }
        });
        // RFC 4998 timestamp renewal (#947) piggybacks on this daily,
        // cursor-paged scheduler walk. Only holders with due evidence reach
        // the TSA, and each write happens after the scan slice has closed.
        for (let i = 0; i < renewalCandidates.length; i += 1) {
          try {
            evidenceRenewed += await this.deps.credentials
              .renewAttestationEvidence(renewalCandidates[i], String(
                config.value('webauthn.attestationEvidenceHashAlgorithm') ||
                'sha256'));
          } catch (e) {
            evidenceFailures += 1;
            log.error(errorCodes.tag('STS-AUTHN-0419') +
              'passkey evidence renewal failed for a holder in realm ' +
              realms.currentId() + ': ' + ((e && e.message) || e));
          }
        }
        // The end, or a cursor that did not move (a slice of nothing but
        // entries that are not people), ends the count; never the number
        // of people a slice happened to hold.
        if (answer.done || answer.next === after) {
          break;
        }
        after = answer.next;
      }
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0414') + 'passkey report: the ' +
                'recount of realm ' + realms.currentId() + ' failed after ' +
                holders + ' holder(s), and the baseline is unchanged: ' +
                ((e && e.message) || e));
      log.debug("Leaving PasskeyReport.recountAsync(). Threw.");
      throw e;
    }
    const finishedAt = now();
    const row = { epoch: randomId(), counts: counts, names: names,
                  holders: holders,
                  startedAt: new Date(startedAt).toISOString(),
                  countedAt: new Date(finishedAt).toISOString(),
                  durationMs: finishedAt - startedAt,
                  trigger: String((ctx && ctx.trigger) || 'direct') };
    baseline.set(BASELINE_KEY, row);
    log.info('passkey report: realm ' + realms.currentId() + ' counted ' +
             holders + ' passkey holder(s) in ' + row.durationMs + ' ms.');
    // THE DAY'S HISTORY ROW (#1109), from the count just made. It never
    // throws: the baseline is written, and that is what the run is for.
    const kept = await this.writeHistoryAsync(row, ctx);
    log.debug("Leaving PasskeyReport.recountAsync().");
    return { summary: 'Counted ' + holders + ' passkey holder(s) in ' +
                      row.durationMs + ' ms' + (kept.written
                        ? '; the history row for ' + kept.day +
                          ' was written'
                        : '; no history row was written') +
                      (kept.pruned ? ' and ' + kept.pruned +
                       ' older one(s) removed.' : '.'),
             history: kept,
             holders: holders, durationMs: row.durationMs,
             evidenceRenewed: evidenceRenewed,
             evidenceFailures: evidenceFailures };
  }

  // -------------------------------------------------------------------------
  // THE HISTORY (#1109): the day's row, written by the recount, and the
  // rows older than the retention removed by the same run.
  // -------------------------------------------------------------------------
  /**
   * The UTC calendar day of an instant, `yyyy-mm-dd`: a history row's key.
   *
   * @param ms - the instant, in milliseconds
   * @returns the day
   */
  static dayOf(ms: number): string {
    helpers.log.debug("Entering PasskeyReport.dayOf().");
    helpers.log.debug("Leaving PasskeyReport.dayOf().");
    return new Date(ms).toISOString().slice(0, 10);
  }

  // A count with the model facets left out. A history row keeps no model
  // table (#1109 asks for kinds, algorithms, lanes and attestation; the
  // model table is up to MAX_MODELS rows a day), and `tablesOf()` given no
  // `m|` facet looks no model name up.
  private static withoutModels(counts: Record<string, number>):
      Record<string, number> {
    helpers.log.debug("Entering PasskeyReport.withoutModels().");
    const out: Record<string, number> = {};
    Object.keys(counts || {}).forEach(function (facet: string): void {
      if (facet.indexOf('m|') !== 0) {
        out[facet] = counts[facet];
      }
    });
    helpers.log.debug("Leaving PasskeyReport.withoutModels().");
    return out;
  }

  // Each named profile's population, counted as the profile filter counts
  // it (`populationAsync()`, at most POPULATION_LIMIT members, `complete`
  // false past it), for at most HISTORY_PROFILES profiles. The default
  // profile selects nobody by group, and a profile with no group selects
  // nobody either, so neither is a population. Null when the run stopped
  // being this process's between two profiles: the caller then writes no
  // row, rather than one that silently lacks the later profiles.
  private async historyProfilesAsync(ctx?: Json): Promise<Json[] | null> {
    const { log, errorCodes, realms } = this.deps;
    log.debug("Entering PasskeyReport.historyProfilesAsync().");
    const named = this.profiles().filter(function (p: Json): boolean {
      return p.name !== 'default' && p.selectGroups.length > 0;
    });
    const out: Json[] = [];
    for (let i = 0; i < named.length; i += 1) {
      const p = named[i];
      const head = { name: p.name, postQuantumRequired: p.postQuantumRequired,
                     selectGroups: p.selectGroups.slice() };
      if (i >= HISTORY_PROFILES) {
        out.push(Object.assign(head, { counted: false,
          why: 'past the ' + HISTORY_PROFILES + ' profiles a history row ' +
               'counts' }));
        continue;
      }
      if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
        log.debug("Leaving PasskeyReport.historyProfilesAsync(). Fenced.");
        return null;
      }
      try {
        const pop = await this.populationAsync(p.selectGroups);
        const t = this.tablesOf(PasskeyReport.withoutModels(pop.counts), {},
                                pop.rows.length);
        out.push(Object.assign(head, {
          counted: true, members: pop.members, read: pop.rows.length,
          complete: pop.complete, people: t.people,
          keys: { total: t.keys.total, postQuantum: t.keys.postQuantum,
                  classical: t.keys.classical } }));
      } catch (e) {
        log.error(errorCodes.tag('STS-AUTHN-0522') + 'passkey history: ' +
                  'the population of passkey profile ' + p.name + ' in ' +
                  'realm ' + realms.currentId() + ' could not be read; the ' +
                  'day\'s row is written without it: ' +
                  ((e && e.message) || e));
        out.push(Object.assign(head, { counted: false,
          why: 'its population could not be read' }));
      }
    }
    log.debug("Leaving PasskeyReport.historyProfilesAsync(). " + out.length);
    return out;
  }

  /**
   * Writes the day's history row from the baseline a recount just wrote,
   * and removes the rows older than `webauthn.passkeyHistoryDays` (#1109).
   * It never throws: a failure is logged and said in the answer.
   *
   * @param base - the baseline row the recount wrote
   * @param ctx - the scheduler's run context, for `stillOwner()`
   * @returns `{ written, day, pruned, profiles }`
   */
  async writeHistoryAsync(base: Json, ctx?: Json): Promise<Json> {
    const { log, errorCodes, realms, history, now } = this.deps;
    log.debug("Entering PasskeyReport.writeHistoryAsync().");
    const day = PasskeyReport.dayOf(Date.parse(base.countedAt) || now());
    let written = false;
    let profiles: Json[] | null = [];
    try {
      let people: number | null = null;
      try {
        people = Number((this.directory as PasskeyDirectory)
          .personCount()) || 0;
      } catch (e) {
        log.debug("Caught in PasskeyReport.writeHistoryAsync(): " +
                  ((e && e.message) || e));
        // Unknown, not zero: the row's `none` and `total` are then null.
        people = null;
      }
      const t = this.tablesOf(PasskeyReport.withoutModels(base.counts), {},
                              people);
      profiles = await this.historyProfilesAsync(ctx);
      if (profiles === null) {
        log.info('passkey history: realm ' + realms.currentId() + '\'s ' +
                 'row for ' + day + ' was not written: the run stopped ' +
                 'being this process\'s while it counted the profiles.');
        log.debug("Leaving PasskeyReport.writeHistoryAsync(). Fenced.");
        return { written: false, day: day, pruned: 0, profiles: 0 };
      }
      history.set(day, {
        day: day, countedAt: base.countedAt, epoch: base.epoch,
        trigger: base.trigger, holders: base.holders,
        durationMs: base.durationMs,
        people: t.people,
        keys: { total: t.keys.total, postQuantum: t.keys.postQuantum,
                classical: t.keys.classical, byLane: t.keys.byLane,
                byAlgorithm: t.keys.byAlgorithm },
        attestation: t.attestation.rows,
        profiles: profiles
      });
      written = true;
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0520') + 'passkey history: ' +
                'realm ' + realms.currentId() + '\'s row for ' + day +
                ' could not be written, and the baseline stands: ' +
                ((e && e.message) || e));
    }
    const pruned = this.pruneHistory(now());
    log.debug("Leaving PasskeyReport.writeHistoryAsync().");
    return { written: written, day: day, pruned: pruned,
             profiles: profiles ? profiles.length : 0 };
  }

  /**
   * Removes this realm's history rows older than
   * `webauthn.passkeyHistoryDays` days before `at` (#1109); the day of `at`
   * is the first of those days. Never throws.
   *
   * @param at - the instant the retention counts back from
   * @returns how many rows were removed
   */
  pruneHistory(at: number): number {
    const { log, errorCodes, realms, history, historyDays } = this.deps;
    log.debug("Entering PasskeyReport.pruneHistory().");
    let removed = 0;
    try {
      const first = PasskeyReport.dayOf(at - (historyDays() - 1) * DAY_MS);
      // Collected, then deleted: a delete inside the keys' own iteration
      // is legal for a Map and still harder to read.
      const old = Array.from(history.keys()).filter(function (k: string) {
        return String(k) < first;
      });
      old.forEach(function (k: string): void {
        history.delete(k);
      });
      removed = old.length;
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0521') + 'passkey history: ' +
                'realm ' + realms.currentId() + '\'s rows past the ' +
                'retention could not be removed; the next recount tries ' +
                'again: ' + ((e && e.message) || e));
    }
    log.debug("Leaving PasskeyReport.pruneHistory(). " + removed);
    return removed;
  }

  /**
   * This realm's history rows, oldest day first (#1109): what the reports
   * application's `passkeyHistory` source reads. At most
   * `webauthn.passkeyHistoryDays` (plus a day) rows, held in memory.
   *
   * @returns the rows, as written
   */
  historyRows(): Json[] {
    const { log, history } = this.deps;
    log.debug("Entering PasskeyReport.historyRows().");
    const keys = Array.from(history.keys()).map(String).sort();
    const rows = keys.map(function (k: string): Json {
      return history.get(k);
    }).filter(function (row: Json): boolean {
      return !!row && typeof row === 'object';
    });
    log.debug("Leaving PasskeyReport.historyRows(). " + rows.length);
    return rows;
  }

  // The baseline and every process's changes under its epoch, added.
  private async aggregateAsync(): Promise<Json> {
    const { log, baseline, changes, remoteRows,
            refreshContributions } = this.deps;
    log.debug("Entering PasskeyReport.aggregateAsync().");
    try {
      await refreshContributions([CHANGES_HANDLE]);
    } catch (e) {
      log.debug("Caught in PasskeyReport.aggregateAsync(): " +
                ((e && e.message) || e));
      // Never rejects by contract; drawn from what is held.
    }
    const base = baseline.has(BASELINE_KEY) ? baseline.get(BASELINE_KEY)
                                            : null;
    const counts: Record<string, number> = {};
    const names: Record<string, string> = {};
    let notes = 0;
    let lastNoteAt = '';
    if (base) {
      PasskeyReport.addCounts(counts, base.counts || {}, 1);
      PasskeyReport.addNames(names, base.names || {});
      const mine = changes.has(CHANGES_KEY) ? changes.get(CHANGES_KEY) : null;
      let theirs: Json[] = [];
      try {
        theirs = remoteRows(CHANGES_HANDLE, undefined, CHANGES_KEY) || [];
      } catch (e) {
        log.debug("Caught in PasskeyReport.aggregateAsync(): " +
                  ((e && e.message) || e));
        // No coordination in this process: its own changes are the whole.
        theirs = [];
      }
      [mine].concat(theirs).forEach(function (row: Json): void {
        if (!row || String(row.epoch || '') !== String(base.epoch || '')) {
          return;
        }
        PasskeyReport.addCounts(counts, row.counts || {}, 1);
        PasskeyReport.addNames(names, row.names || {});
        notes += Number(row.notes || 0);
        if (row.lastAt && row.lastAt > lastNoteAt) {
          lastNoteAt = String(row.lastAt);
        }
      });
    }
    log.debug("Leaving PasskeyReport.aggregateAsync().");
    return { base: base, counts: counts, names: names, notes: notes,
             lastNoteAt: lastNoteAt };
  }

  // The four tables the page draws, from one flat count.
  private tablesOf(counts: Record<string, number>,
                   names: Record<string, string>, people: number | null):
      Json {
    const { log, credentials } = this.deps;
    log.debug("Entering PasskeyReport.tablesOf().");
    const n = function (facet: string): number {
      return Math.max(0, Number(counts[facet] || 0));
    };
    const pqOnly = n('p|post-quantum-only');
    const clOnly = n('p|classical-only');
    const both = n('p|both');
    const holding = pqOnly + clOnly + both;
    const byAlgorithm: Json[] = [];
    const models: Record<string, Json> = {};
    const attestation: Json[] = [];
    let keys = 0;
    let pqKeys = 0;
    const lanes: Record<string, number> = { classical: 0, pqc: 0 };
    Object.keys(counts).forEach(function (facet: string): void {
      const value = Math.max(0, Number(counts[facet] || 0));
      if (!value) {
        return;
      }
      const parts = facet.split('|');
      if (parts[0] === 'k') {
        const postQuantum = /^ML-DSA-/.test(parts[1]);
        byAlgorithm.push({ algorithm: parts[1], coseAlg: Number(parts[2]),
                           lane: parts[3], postQuantum: postQuantum,
                           count: value });
        keys += value;
        pqKeys += postQuantum ? value : 0;
        lanes[parts[3]] = (lanes[parts[3]] || 0) + value;
      } else if (parts[0] === 'm') {
        const aaguid = parts[1];
        const model = models[aaguid] || (models[aaguid] = {
          aaguid: aaguid,
          name: aaguid === '(other)' ? '' : (names[aaguid] ||
            (aaguid ? String(credentials.keyProvider({ aaguid: aaguid }) ||
                             '') : '')),
          total: 0, algorithms: [] });
        model.total += value;
        model.algorithms.push({ algorithm: parts[2],
                                coseAlg: Number(parts[3]),
                                postQuantum: /^ML-DSA-/.test(parts[2]),
                                count: value });
      } else if (parts[0] === 't') {
        // `coseAlg` is empty when the certificate algorithm is not a COSE
        // name. `pq` is the certificate's own flag; a facet written before
        // that field existed is post-quantum only by an ML-DSA name.
        const coseAlg = parts[2] === '' || parts[2] === undefined
          ? null : Number(parts[2]);
        const postQuantum = parts.length > 3 ? parts[3] === '1'
          : /^ML-DSA-/.test(parts[1]);
        attestation.push({ algorithm: parts[1], coseAlg: coseAlg,
                           postQuantum: postQuantum, count: value });
      }
    });
    byAlgorithm.sort(function (a, b) {
      return b.count - a.count || (a.algorithm < b.algorithm ? -1 : 1) ||
        (a.lane < b.lane ? -1 : 1);
    });
    const modelRows = Object.keys(models).map(function (k) {
      const m = models[k];
      m.algorithms.sort(function (a: Json, b: Json) {
        return b.count - a.count;
      });
      m.postQuantum = m.algorithms.some(function (a: Json) {
        return a.postQuantum;
      });
      return m;
    }).sort(function (a, b) {
      return b.total - a.total || (a.aaguid < b.aaguid ? -1 : 1);
    });
    const total = people === null ? null : Math.max(people, holding);
    log.debug("Leaving PasskeyReport.tablesOf().");
    return {
      people: { total: total, holding: holding,
                postQuantumOnly: pqOnly, classicalOnly: clOnly, both: both,
                none: total === null ? null : total - holding,
                withPostQuantum: pqOnly + both },
      keys: { total: keys, postQuantum: pqKeys, classical: keys - pqKeys,
              byLane: lanes, byAlgorithm: byAlgorithm },
      models: modelRows,
      // What `attestationFacetOf()` counted (#941). `recorded` is false
      // when no counted passkey stored a certificate algorithm.
      attestation: { recorded: attestation.length > 0, rows: attestation }
    };
  }

  // -------------------------------------------------------------------------
  // THE FILTER. One of `group`, `profile` and `application`; none is the
  // realm. A filter naming nothing here is refused (STS-AUTHN-0416).
  // -------------------------------------------------------------------------
  /**
   * Reads the report's filter from a query.
   *
   * @param query - the request's query
   * @returns `{ ok, scope, group, profile, application, selectors,
   *   profileRow, applicationRow, errors }`
   */
  filterOf(query: Json): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PasskeyReport.filterOf().");
    const q = query || {};
    const group = String(q.group || '').trim();
    const profile = String(q.profile || '').trim().toLowerCase();
    const application = String(q.application || '').trim();
    const given = [group, profile, application].filter(Boolean).length;
    // The code rides the refusal, non-enumerably, as `credentials.ts`'s
    // `coded()` attaches one: the API's handler reads it with `codeOf()`.
    const refuse = function (why: string): Json {
      return errorCodes.mark({ ok: false, errors: [why] }, 'STS-AUTHN-0416');
    };
    if (given > 1) {
      log.debug("Leaving PasskeyReport.filterOf(). Two filters.");
      return refuse('Filter by one of group, profile and application at a ' +
                    'time.');
    }
    if (group) {
      log.debug("Leaving PasskeyReport.filterOf(). A group.");
      return { ok: true, scope: 'group', group: group,
               selectors: [group] };
    }
    if (profile) {
      const rows = this.profiles();
      const row = rows.filter(function (one: Json) {
        return one.name === profile;
      })[0];
      if (!row || profile === 'default') {
        log.debug("Leaving PasskeyReport.filterOf(). No such profile.");
        return refuse(profile === 'default'
          ? 'The default passkey profile selects nobody by group: it is ' +
            'what applies where no named profile does. The realm\'s own ' +
            'counts, with no filter, are its population.'
          : 'This realm has no named passkey profile "' + profile + '". ' +
            'Directory → Policies → Passkey policy lists them.');
      }
      log.debug("Leaving PasskeyReport.filterOf(). A profile.");
      return { ok: true, scope: 'profile', profile: profile,
               profileRow: row, selectors: row.selectGroups };
    }
    if (application) {
      let found: Json = null;
      try {
        found = this.deps.applications().get(application);
      } catch (e) {
        log.debug("Caught in PasskeyReport.filterOf(): " +
                  ((e && e.message) || e));
        found = null;
      }
      if (!found) {
        log.debug("Leaving PasskeyReport.filterOf(). No such application.");
        return refuse('This realm has no application "' + application +
                      '". Directory → Applications lists them.');
      }
      log.debug("Leaving PasskeyReport.filterOf(). An application.");
      return { ok: true, scope: 'application', application: application,
               applicationRow: found, selectors: null };
    }
    log.debug("Leaving PasskeyReport.filterOf(). The realm.");
    return { ok: true, scope: 'realm', selectors: null };
  }

  // This realm's passkey profiles, as the report shows them: each one's
  // `postQuantumRequired` and its selectors. A policy that cannot be asked
  // answers none, so the report still draws.
  private profiles(): Json[] {
    const { log } = this.deps;
    log.debug("Entering PasskeyReport.profiles().");
    let rows: Json[] = [];
    try {
      const policy = this.deps.passkeyPolicy();
      rows = (policy.list() || []).map(function (p: Json) {
        const name = String(p.name || '');
        // The applications naming it (#1235): the listing's index, never a
        // walk of the applications.
        const by = name !== 'default' && typeof policy.namedBy === 'function'
          ? policy.namedBy(name) : { applications: [], groups: [] };
        // `selectGroups` is the groups NAMING it (`stsPasskeyPolicy`,
        // #1235): its population, as the profile's own list was before.
        return { name: name,
                 postQuantumRequired: String(p.postQuantumRequired || 'off'),
                 precedence: Number(p.precedence || 0),
                 selectGroups: (by.groups || []).map(String),
                 namedByApplications: (by.applications || []).map(String) };
      });
    } catch (e) {
      log.debug("Caught in PasskeyReport.profiles(): " +
                ((e && e.message) || e));
      rows = [];
    }
    log.debug("Leaving PasskeyReport.profiles(). " + rows.length);
    return rows;
  }

  // Which profile governs an application's sign-ins (#609's answer, the
  // profile its `appPasskeyPolicy` names since #1235).
  private applicationFacts(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering PasskeyReport.applicationFacts().");
    const fields = (row && row.fields) || {};
    const reference = [].concat(fields.appPasskeyPolicy || [])[0] || '';
    let answer: Json = { named: 'default', missing: false,
                         applies: 'default', groupPolicies: 0 };
    try {
      answer = this.deps.passkeyPolicy().forApplication(reference);
    } catch (e) {
      log.debug("Caught in PasskeyReport.applicationFacts(): " +
                ((e && e.message) || e));
      // Drawn as the default, which is what a sign-in would get.
    }
    log.debug("Leaving PasskeyReport.applicationFacts().");
    return { identifier: String((row && row.identifier) || ''),
             named: String(answer.named || 'default'),
             missing: !!answer.missing, applies: answer.applies,
             groupPolicies: Number(answer.groupPolicies || 0) };
  }

  // A population's members, read and counted (a group or a profile).
  private async populationAsync(selectors: string[]): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering PasskeyReport.populationAsync().");
    const answer = await (this.directory as PasskeyDirectory)
      .populationAsync(selectors || [], POPULATION_LIMIT);
    const counts: Record<string, number> = {};
    const names: Record<string, string> = {};
    const rows = (answer.rows || []).map((row: HolderRow) => {
      const f = this.facetsOfValues(row.values, row.id);
      PasskeyReport.addCounts(counts, f.counts, 1);
      PasskeyReport.addNames(names, f.names);
      return { row: row, facets: f };
    });
    log.debug("Leaving PasskeyReport.populationAsync(). " + rows.length);
    return { groups: answer.groups || [], members: answer.members || 0,
             complete: answer.complete !== false, counts: counts,
             names: names, rows: rows };
  }

  // -------------------------------------------------------------------------
  // THE REPORT.
  // -------------------------------------------------------------------------
  /**
   * The report for the ambient realm, filtered as the query says, with a
   * page of one list when the query names one.
   *
   * @param query - `group`, `profile` or `application`; `list` (one of
   *   `LISTS`) with `algorithm`, `lane` or `aaguid`; `page`, `per`, `from`
   * @returns a promise of the view, or a refusal `{ ok: false, errors }`
   */
  async reportAsync(query: Json): Promise<Json> {
    const { log, realms, now } = this.deps;
    log.debug("Entering PasskeyReport.reportAsync().");
    const filter = this.filterOf(query);
    if (!filter.ok) {
      log.debug("Leaving PasskeyReport.reportAsync(). Refused.");
      return filter;
    }
    const profiles = this.profiles();
    const out: Json = {
      ok: true,
      realm: realms.currentId(),
      generatedAt: new Date(now()).toISOString(),
      filter: { scope: filter.scope, group: filter.group || '',
                profile: filter.profile || '',
                application: filter.application || '' },
      profiles: profiles,
      lists: LISTS.slice(),
      kinds: KINDS.slice(),
      limits: { listScan: LIST_SCAN, population: POPULATION_LIMIT,
                export: EXPORT_LIMIT, perMax: PER_MAX },
      recount: { job: RECOUNT_JOB, every: 'daily' },
      installed: !!this.directory
    };
    if (!this.directory) {
      out.counted = null;
      Object.assign(out, this.tablesOf({}, {}, null));
      log.debug("Leaving PasskeyReport.reportAsync(). No directory.");
      return out;
    }
    let population: Json = null;
    if (filter.scope === 'group' || filter.scope === 'profile') {
      population = await this.populationAsync(filter.selectors || []);
      out.population = { groups: population.groups,
                         members: population.members,
                         read: population.rows.length,
                         complete: population.complete };
      out.counted = { from: 'population', at: out.generatedAt };
      Object.assign(out, this.tablesOf(population.counts, population.names,
                                       population.rows.length));
      if (filter.scope === 'profile') {
        out.profile = filter.profileRow;
      }
    } else {
      const agg = await this.aggregateAsync();
      out.counted = agg.base
        ? { from: 'baseline', at: agg.base.countedAt,
            startedAt: agg.base.startedAt, durationMs: agg.base.durationMs,
            holders: agg.base.holders, changesSince: agg.notes,
            lastChangeAt: agg.lastNoteAt || null }
        : null;
      let people: number | null = null;
      try {
        people = Number(this.directory.personCount()) || 0;
      } catch (e) {
        log.debug("Caught in PasskeyReport.reportAsync(): " +
                  ((e && e.message) || e));
        // Unknown, not zero: `none` is then not drawn.
        people = null;
      }
      Object.assign(out, this.tablesOf(agg.counts, agg.names,
                                       agg.base ? people : null));
      if (filter.scope === 'application') {
        out.application = this.applicationFacts(filter.applicationRow);
      }
    }
    if (query && query.list) {
      out.list = await this.listAsync(query, population);
    }
    log.debug("Leaving PasskeyReport.reportAsync().");
    return out;
  }

  // Hot path (once per person a recount, a list or an export reads, which
  // is every holder of a realm): no Entering/Leaving pair, the exception the
  // code style allows, stated as it requires.
  // Whether one person's facets match the list asked for.
  private static matches(list: Json, f: Json): boolean {
    let yes = false;
    if (KINDS.indexOf(list.list) >= 0) {
      yes = f.kind === list.list;
    } else if (list.list === 'holding') {
      yes = f.kind !== 'none';
    } else if (list.list === 'algorithm') {
      yes = f.keys.some(function (k: Json) {
        return k.algorithm === list.algorithm &&
               (!list.lane || k.lane === list.lane);
      });
    } else if (list.list === 'model') {
      yes = f.keys.some(function (k: Json) {
        return k.aaguid === list.aaguid;
      });
    }
    return yes;
  }

  // The list asked for, as `matches()` reads it.
  private static listOf(query: Json): Json {
    helpers.log.debug("Entering PasskeyReport.listOf().");
    const q = query || {};
    const name = String(q.list || '');
    const aaguid = String(q.aaguid || '').trim().toLowerCase();
    const per = Math.max(1, Math.min(PER_MAX,
      Math.floor(Number(q.per) || PER_DEFAULT)));
    helpers.log.debug("Leaving PasskeyReport.listOf().");
    return { list: LISTS.indexOf(name) >= 0 ? name : 'holding',
             algorithm: String(q.algorithm || '').trim(),
             lane: q.lane === 'pqc' || q.lane === 'classical'
               ? String(q.lane) : '',
             // `unreported` is the list of keys whose authenticator named
             // no model.
             aaguid: aaguid === 'unreported' ? '' : aaguid,
             page: Math.max(1, Math.floor(Number(q.page) || 1)),
             per: per,
             from: String(q.from || '') };
  }

  // Hot path (once per person a recount, a list or an export reads, which
  // is every holder of a realm): no Entering/Leaving pair, the exception the
  // code style allows, stated as it requires.
  // One person, as a list row and an export row.
  private static personRow(row: HolderRow, f: Json): Json {
    return { username: row.id, dn: row.dn, kind: f.kind,
             passkeys: f.keys.length, keys: f.keys };
  }

  // -------------------------------------------------------------------------
  // A PAGE OF ONE LIST. In a population (a group, a profile) the members are
  // already read and the page is a slice of them. For the realm the holders
  // are read in key order from `from` — the cursor the page before handed
  // back — or from the start, skipping the pages before; at most LIST_SCAN
  // entries a request, and `complete: false` when that stopped the page.
  // -------------------------------------------------------------------------
  /**
   * One page of the people behind a count.
   *
   * @param query - the list's parameters (`list`, `algorithm`, `lane`,
   *   `aaguid`, `page`, `per`, `from`)
   * @param population - a filter's members, already read, or null
   * @returns a promise of `{ list, rows, paging }`
   */
  async listAsync(query: Json, population?: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering PasskeyReport.listAsync().");
    const want = PasskeyReport.listOf(query);
    const skip = want.from ? 0 : (want.page - 1) * want.per;
    const rows: Json[] = [];
    let read = 0;
    let next = '';
    let complete = true;
    let exhausted = true;
    let total: number | null = null;
    if (population) {
      const hits = population.rows.filter(function (one: Json) {
        return PasskeyReport.matches(want, one.facets);
      });
      total = hits.length;
      const start = (want.page - 1) * want.per;
      hits.slice(start, start + want.per).forEach(function (one: Json) {
        rows.push(PasskeyReport.personRow(one.row, one.facets));
      });
      read = population.rows.length;
      exhausted = start + want.per >= hits.length;
      complete = population.complete !== false;
    } else {
      let skipped = 0;
      const self = this;
      const answer = await (this.directory as PasskeyDirectory).scanAsync({
        attribute: want.list === 'none' ? '' : ATTRIBUTE,
        after: want.from, readLimit: LIST_SCAN, wanted: skip + want.per,
        accept: function (row: HolderRow): boolean {
          const f = self.facetsOfValues(row.values, row.id);
          if (!PasskeyReport.matches(want, f)) {
            return false;
          }
          if (skipped < skip) {
            skipped += 1;
            return true;
          }
          rows.push(PasskeyReport.personRow(row, f));
          return true;
        }
      });
      read = answer.read;
      next = answer.done ? '' : answer.next;
      exhausted = answer.done;
      // Stopped by the scan's bound, not by a full page or the end.
      complete = answer.done || rows.length >= want.per;
    }
    const firstRow = rows.length ? (want.page - 1) * want.per + 1 : 0;
    log.debug("Leaving PasskeyReport.listAsync(). " + rows.length +
              ' row(s), ' + read + ' read.');
    return {
      list: want.list, algorithm: want.algorithm, lane: want.lane,
      aaguid: want.list === 'model' ? (want.aaguid || 'unreported') : '',
      rows: rows,
      paging: {
        page: want.page, perPage: want.per, param: 'page', noun: 'people',
        total: total,
        pages: total === null ? null : Math.max(1, Math.ceil(total / want.per)),
        firstRow: firstRow,
        lastRow: rows.length ? firstRow + rows.length - 1 : 0,
        // The cursor for the next page (realm lists), '' at the end.
        nextFrom: exhausted ? '' : next,
        hasNext: !exhausted,
        scanned: read,
        complete: complete
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE EXPORT: one list, every page, to EXPORT_LIMIT rows, as CSV or JSON.
  // -------------------------------------------------------------------------
  /**
   * Every person behind a count, as a file.
   *
   * @param query - the report's filter, the list and `format` (`csv` or
   *   `json`)
   * @returns a promise of `{ ok, contentType, filename, body, rows,
   *   truncated }`, or a refusal
   */
  async exportAsync(query: Json): Promise<Json> {
    const { log, realms } = this.deps;
    log.debug("Entering PasskeyReport.exportAsync().");
    const filter = this.filterOf(query);
    if (!filter.ok) {
      log.debug("Leaving PasskeyReport.exportAsync(). Refused.");
      return filter;
    }
    const want = PasskeyReport.listOf(query);
    const out: Json[] = [];
    let truncated = false;
    if (this.directory &&
        (filter.scope === 'group' || filter.scope === 'profile')) {
      const population = await this.populationAsync(filter.selectors || []);
      population.rows.forEach(function (one: Json) {
        if (out.length >= EXPORT_LIMIT) {
          truncated = true;
          return;
        }
        if (PasskeyReport.matches(want, one.facets)) {
          out.push(PasskeyReport.personRow(one.row, one.facets));
        }
      });
      truncated = truncated || population.complete === false;
    } else if (this.directory) {
      let after = '';
      const self = this;
      for (;;) {
        const answer = await this.directory.scanAsync({
          attribute: want.list === 'none' ? '' : ATTRIBUTE,
          after: after, readLimit: RECOUNT_SLICE,
          wanted: EXPORT_LIMIT - out.length,
          accept: function (row: HolderRow): boolean {
            const f = self.facetsOfValues(row.values, row.id);
            if (!PasskeyReport.matches(want, f)) {
              return false;
            }
            out.push(PasskeyReport.personRow(row, f));
            return true;
          }
        });
        if (answer.done || answer.next === after) {
          break;
        }
        after = answer.next;
        if (out.length >= EXPORT_LIMIT) {
          truncated = true;
          break;
        }
      }
    }
    const format = String((query || {}).format || 'csv') === 'json'
      ? 'json' : 'csv';
    const stem = 'passkeys-' + realms.currentId() + '-' + want.list +
      (want.algorithm ? '-' + want.algorithm : '') +
      (want.list === 'model' ? '-' + (want.aaguid || 'unreported') : '');
    const filename = stem.replace(/[^A-Za-z0-9._-]/g, '_') + '.' + format;
    const body = format === 'json'
      ? JSON.stringify({ realm: realms.currentId(), list: want.list,
                         filter: { scope: filter.scope,
                                   group: filter.group || '',
                                   profile: filter.profile || '',
                                   application: filter.application || '' },
                         truncated: truncated, rows: out }, null, 2)
      : PasskeyReport.csvOf(out);
    log.debug("Leaving PasskeyReport.exportAsync(). " + out.length +
              ' row(s).');
    return { ok: true, format: format, filename: filename,
             contentType: format === 'json' ? 'application/json'
                                            : 'text/csv; charset=utf-8',
             body: body, rows: out.length, truncated: truncated };
  }

  // Hot path (once per person a recount, a list or an export reads, which
  // is every holder of a realm): no Entering/Leaving pair, the exception the
  // code style allows, stated as it requires.
  // A CSV cell. A value a spreadsheet would read as a formula (=, +, -, @,
  // a tab or a carriage return first) is quoted with an apostrophe in front:
  // a username is chosen by whoever registered it.
  private static csvCell(value: unknown): string {
    const text = String(value === null || value === undefined ? '' : value);
    const safe = /^[=+\-@\t\r]/.test(text) ? '\'' + text : text;
    return /[",\r\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"'
                                 : safe;
  }

  // The export as CSV: one row per person.
  private static csvOf(rows: Json[]): string {
    helpers.log.debug("Entering PasskeyReport.csvOf().");
    const cell = PasskeyReport.csvCell;
    const lines = ['username,dn,kind,passkeys,algorithms,lanes,aaguids,' +
                   'models'];
    rows.forEach(function (r: Json) {
      const keys = r.keys || [];
      const join = function (pick: (k: Json) => string): string {
        return keys.map(pick).join(' ');
      };
      lines.push([cell(r.username), cell(r.dn), cell(r.kind),
                  cell(r.passkeys),
                  cell(join(function (k) {
                    return k.algorithm + '(' + k.coseAlg + ')';
                  })),
                  cell(join(function (k) { return k.lane; })),
                  cell(join(function (k) { return k.aaguid || '-'; })),
                  cell(keys.map(function (k: Json) {
                    return k.model || '-';
                  }).join('; '))].join(','));
    });
    helpers.log.debug("Leaving PasskeyReport.csvOf().");
    return lines.join('\r\n') + '\r\n';
  }

  // -------------------------------------------------------------------------
  // THE CONSOLE'S ONE CONTROL: Recount now, which QUEUES the job on the
  // scheduler's leader — the count runs where every job runs (#408), never
  // on the request that asked.
  // -------------------------------------------------------------------------
  /**
   * Performs an action of Monitoring → Passkeys: `recount`.
   *
   * @param body - `{ action }`
   * @param opts - `{ actor, via }`
   * @returns `{ ok, runId, ... }` or a refusal `{ ok: false, errors }`
   */
  act(body: Json, opts?: Json): Json {
    const { log, realms, errorCodes } = this.deps;
    log.debug("Entering PasskeyReport.act().");
    const action = String((body || {}).action || '');
    const o = opts || {};
    if (action !== 'recount') {
      log.debug("Leaving PasskeyReport.act(). Unknown action.");
      return errorCodes.mark({ ok: false, errors: ['Unknown action "' +
        action + '". Monitoring → Passkeys has one action: recount.'] },
        'STS-AUTHN-0418');
    }
    let answer: Json;
    try {
      answer = this.deps.scheduler().requestRun(RECOUNT_JOB, {
        realm: realms.currentId(), requestedBy: String(o.actor || ''),
        via: String(o.via || '/admin/passkey-report'),
        channel: o.channel || 'console' });
    } catch (e) {
      log.debug("Caught in PasskeyReport.act(): " + ((e && e.message) || e));
      answer = { ok: false, errorCode: 'STS-AUTHN-0418',
                 why: 'The recount could not be queued: ' +
                      ((e && e.message) || e) };
    }
    if (!answer || !answer.ok) {
      log.debug("Leaving PasskeyReport.act(). Not queued.");
      // The scheduler's own code where it gave one (STS-SCHED-0006, a job
      // that is off, and the like).
      return errorCodes.mark({ ok: false,
        errors: [String((answer && answer.why) ||
                        'The recount could not be queued.')] },
        String((answer && answer.errorCode) || 'STS-AUTHN-0418'));
    }
    log.debug("Leaving PasskeyReport.act(). Queued.");
    return { ok: true, action: 'recount', runId: answer.runId,
             alreadyQueued: !!answer.alreadyQueued,
             message: answer.alreadyQueued
               ? 'A recount was already queued; it runs at the scheduler\'s ' +
                 'next tick.'
               : 'A recount was queued; it runs at the scheduler\'s next ' +
                 'tick. Monitoring → Scheduler shows it.' };
  }

  /**
   * Registers the recount job with the scheduler, once per process.
   *
   * @returns true when registered, false when it already was
   */
  registerJobs(): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyReport.registerJobs().");
    const s = this.deps.scheduler();
    if (s.job(RECOUNT_JOB)) {
      log.debug("Leaving PasskeyReport.registerJobs(). Already there.");
      return false;
    }
    const self = this;
    s.register({
      id: RECOUNT_JOB,
      title: 'Passkey report recount',
      describe: 'Counts the realm\'s passkeys for Monitoring → Passkeys ' +
                '(#942): by algorithm and lane, the people holding ' +
                'post-quantum only, classical only or both, and which ' +
                'authenticator models hold which algorithms. Reads only ' +
                'the people holding a passkey, a page at a time; the ' +
                'changes made after it are added as they are written.',
      owner: 'common/passkey_report.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return DAY_MS;
      },
      manual: true,
      timeoutS: 3600,
      run: function (ctx: Json): Promise<Json> {
        return self.recountAsync(ctx);
      }
    });
    log.debug("Leaving PasskeyReport.registerJobs().");
    return true;
  }

  // Tests only: forget this realm's baseline, this process's changes and
  // the realm's history (#1109).
  /**
   * Forgets this realm's baseline, this process's changes and the realm's
   * history rows. Tests only.
   */
  resetForTests(): void {
    const { log, baseline, changes } = this.deps;
    log.debug("Entering PasskeyReport.resetForTests().");
    baseline.delete(BASELINE_KEY);
    changes.delete(CHANGES_KEY);
    Array.from(this.deps.history.keys()).forEach((k: string): void => {
      this.deps.history.delete(k);
    });
    log.debug("Leaving PasskeyReport.resetForTests().");
  }
}

const slot = new InstanceSlot<PasskeyReport>(
  'common/passkey_report',
  () => new PasskeyReport(PasskeyReport.defaultDeps()),
  function (instance: PasskeyReport): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The passkey report (#942). The exports forward to the instance the
 * composition root installs.
 *
 * @namespace
 */
export = {
  PasskeyReport: PasskeyReport,
  /**
   * Installs the instance the module-level functions forward to.
   *
   * @param instance - the instance the composition root built
   */
  installInstance: (instance: PasskeyReport): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  RECOUNT_JOB: RECOUNT_JOB,
  HISTORY_HANDLE: HISTORY_HANDLE,
  HISTORY_PROFILES: HISTORY_PROFILES,
  dayOf: PasskeyReport.dayOf,
  KINDS: KINDS,
  LISTS: LISTS,
  LIST_SCAN: LIST_SCAN,
  POPULATION_LIMIT: POPULATION_LIMIT,
  EXPORT_LIMIT: EXPORT_LIMIT,
  PER_MAX: PER_MAX,
  attestationFacetOf: PasskeyReport.attestationFacetOf,
  setDirectory: slot.forward('setDirectory'),
  facetsOfValues: slot.forward('facetsOfValues'),
  noteKeysChanged: slot.forward('noteKeysChanged'),
  recountAsync: slot.forward('recountAsync'),
  writeHistoryAsync: slot.forward('writeHistoryAsync'),
  pruneHistory: slot.forward('pruneHistory'),
  historyRows: slot.forward('historyRows'),
  filterOf: slot.forward('filterOf'),
  reportAsync: slot.forward('reportAsync'),
  listAsync: slot.forward('listAsync'),
  exportAsync: slot.forward('exportAsync'),
  act: slot.forward('act'),
  registerJobs: slot.forward('registerJobs'),
  resetForTests: slot.forward('resetForTests')
};
