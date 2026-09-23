'use strict';
//
// File: signing_history.ts
//
// ===========================================================================
// EVERY SIGNING KEY A REALM HAS EVER HELD (2026-09-22, #42's follow-up).
//
// The key GENERATIONS are `common/helpers.js`'s: a unit — (realm, use case,
// algorithm) — has a CURRENT key, a `next` published ahead of it, and RETIRED
// ones verifying through their grace. `signing.retire` then DROPS a retired
// key past that grace and supersedes its certificate, and until this file
// existed that was the end of it: nothing anywhere recorded that the key had
// ever existed. A question an operator actually asks — *which key signed the
// token in this log line, and when was it live?* — had no answer a minute
// after the grace elapsed.
//
// **WHAT IS KEPT IS METADATA AND THE CERTIFICATE. THE PRIVATE KEY IS STILL
// THROWN AWAY AT THE GRACE, AND THAT IS THE SECURITY RULE THIS FILE MAY NOT
// BEND** (rcbj's choice of option B, 2026-09-22). A row here says a key
// existed, which unit it belonged to, when it was minted, promoted, retired
// and dropped, and — because a certificate is a PUBLIC document — the
// certificate that vouched for it, with its serial, subject and validity
// window, so a signature or a chain captured months ago can still be read
// back against the key that made it. Nothing in a row can produce a
// signature.
//
// **THE HISTORY IS APPEND-ONLY AND IS NEVER DROPPED.** It is the one store
// here whose whole point is to outlive what it describes, so it declares no
// `retain: 'age'` (the default is `keep`) and no sweep touches it. A row is
// small — no key material and one certificate — and a unit gains one per
// rotation, so a realm rotating every thirty days writes twelve rows a year
// per unit. That is why the pages that draw it are PAGED (rcbj, 2026-09-22:
// *a cluster would have to run for a long time for this to be an issue, but
// we still need to be able to address it*).
//
// **A ROW IS DERIVED FROM THE KEY SET, NEVER FROM AN EVENT**, and that is the
// decision the rest of the file follows from. The obvious implementation
// records at each site that changes a key — mint, promote, retire, drop —
// which is four call sites in two files and a fifth the day somebody adds a
// rotation path; a site that forgets leaves a hole nothing can see, because a
// missing row looks exactly like a key that never existed. So `observe()`
// walks the realm's CURRENT set and its standby entries, writes what it finds
// and marks DROPPED every row of that realm whose key the set no longer
// holds. It is idempotent, it is cheap (a map lookup per unit), and a caller
// that forgets to call it loses only the PROMPTNESS of the record: the next
// call puts the row back, because the set is the truth and this is a
// projection of it.
//
// What that costs is stated rather than hidden: a key MINTED and DROPPED
// between two observations is recorded once, at its drop, with its
// intermediate roles unknown. Only an emergency rotation does that (#48 drops
// a unit's `next` with the key presumed compromised), and `signing_rotation`
// observes on either side of one, so the window is closed where it exists.
//
// A LIBRARY (rule 3): it registers no route, and it requires `realms` and
// `error_codes` — both leaves — with `helpers` and `pki` reached LAZILY,
// because `helpers.js` is in the parent project's Kerberos COPY closure
// (`kerberos/CLAUDE.md`) and a require from it to here would owe that project
// a COPY line. Nothing in `helpers.js` mentions this file, deliberately.
// ===========================================================================

import realms = require('./realms');
import errorCodes = require('./error_codes');

type Json = any;

// The rows, per realm, keyed `<unit>#<kid>`. Persisted and KEPT — see the
// header: this store outlives the keys it describes, which is its whole
// purpose, so it takes `retain`'s default rather than the `age` every
// short-lived store declares.
const history = realms.map({ persist: 'signing.history' });

interface SigningHistoryDeps {
  log: Json;
  errorCodes: typeof errorCodes;
  // Lazily, both: `helpers` for the key set and the unit table, `pki` for the
  // certificate a key was issued. Neither may be required at load — see the
  // COPY-closure note in the header, and `pki` requires the keystore.
  helpers: () => Json;
  pki: () => Json;
  now: () => number;
}

class SigningHistory {
  constructor(private readonly deps: SigningHistoryDeps) {
    deps.log.debug("Entering SigningHistory.constructor().");
    deps.log.debug("Leaving SigningHistory.constructor().");
  }

  static defaultDeps(): SigningHistoryDeps {
    const log = require('bunyan').createLogger({
      name: 'signing_history',
      level: process.env.STS_LOG_LEVEL || 'info' });
    log.debug("Entering SigningHistory.defaultDeps().");
    log.debug("Leaving SigningHistory.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      helpers: function (): Json {
        return require('./helpers');
      },
      pki: function (): Json {
        return require('./pki');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // The realm's own partition of the history. `realmMap(id)` rather than the
  // ambient view, because two of the three callers are a page drawn for a
  // realm named in the request and a job running on a scheduler that has no
  // realm ambient — and a store read ambiently answers the DEFAULT realm's
  // rows when somebody forgets, which is `realms.map()`'s own warning.
  private storeFor(realmId: string): Json {
    this.deps.log.debug("Entering SigningHistory.storeFor().");
    this.deps.log.debug("Leaving SigningHistory.storeFor().");
    return history.realmMap(String(realmId || ''));
  }

  // The key a row is stored under. The kid alone would do for every unit this
  // service has today — a kid is derived from the key material — but the unit
  // is in it so that a reader of the store can tell which unit a row belongs
  // to without parsing a key identifier whose shape is each algorithm's own.
  private rowKey(unit: string, kid: string): string {
    this.deps.log.debug("Entering SigningHistory.rowKey().");
    this.deps.log.debug("Leaving SigningHistory.rowKey().");
    return String(unit) + '#' + String(kid);
  }

  // ---------------------------------------------------------------------------
  // OBSERVE — the one writer. Walks the realm's key set and writes a row per
  // key it holds (current, `next` and retired), then marks DROPPED every row
  // of that realm whose key the set no longer holds. Answers what changed.
  //
  // `reason` is carried onto rows whose role MOVED in this call, so that a
  // rotation asked for by hand and a scheduled one are told apart afterwards.
  // A row that did not move keeps the reason it was written with.
  //
  // It never throws: it is called from the rotation jobs, which have already
  // rotated by the time they reach it, and from the pages that draw the
  // history. A failure here must not fail either.
  // ---------------------------------------------------------------------------
  observe(realmId: string, options?: Json): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering SigningHistory.observe(). realm=" + realmId);
    const o = options || {};
    const id = String(realmId || '');
    const out = { recorded: 0, updated: 0, dropped: 0 };
    let keys: Json = null;
    try {
      keys = this.heldKeysFor(id);
    } catch (e) {
      log.debug("Caught in SigningHistory.observe(): " + ((e && e.message) ||
                                                          e));
      keys = null;
    }
    if (!keys) {
      // This process holds no key set for the realm. That is the ordinary
      // state of a node that has never answered a request in it, and it is
      // NOT evidence that the keys are gone — so nothing is marked dropped.
      log.debug("Leaving SigningHistory.observe(). No key set held here.");
      return out;
    }
    try {
      this.writeRows(id, keys, o, out);
    } catch (e) {
      log.error(codes.tag('STS-KEYS-0067') + 'the "' + id + '" realm\'s ' +
                'signing-key history could not be recorded: ' +
                ((e && e.message) || e));
    }
    log.debug("Leaving SigningHistory.observe(). " + out.recorded +
              " recorded, " + out.updated + " updated, " + out.dropped +
              " dropped.");
    return out;
  }

  // The key set this process ALREADY holds for a realm, or null. It asks
  // `existing()` and never `.of()`, which GENERATES — the key-agreement storm
  // of 2026-09-12 (`common/CLAUDE.md`, THE REALM WATCHER ASKS AND DOES NOT
  // TAKE) was one caller reading keys through a factory that makes them, and
  // a history page must never be the thing that mints a realm's signing keys.
  private heldKeysFor(realmId: string): Json {
    const { log, helpers } = this.deps;
    log.debug("Entering SigningHistory.heldKeysFor().");
    const held = helpers().stsKeysFor.existing();
    const keys = held && held.get ? held.get(String(realmId || '')) : null;
    log.debug("Leaving SigningHistory.heldKeysFor(). " + (keys ? "Held." :
                                                          "Not held."));
    return keys || null;
  }

  // Every key the set holds now, as `{ unit, useCase, slot, alg, crv, kind,
  // kid, role, … }` — the current key of each unit, then its standby entries.
  private keysOfSet(keys: Json): Json[] {
    const { log, helpers } = this.deps;
    log.debug("Entering SigningHistory.keysOfSet().");
    const h = helpers();
    const out: Json[] = [];
    h.signingUnitsOf(keys).forEach(function (u: Json): void {
      out.push({ unit: u.unit, useCase: u.useCase, slot: u.slot, alg: u.alg,
                 crv: u.crv || '', kind: u.kind, kid: u.kid,
                 role: 'current' });
    });
    h.standbyOf(keys).forEach(function (one: Json): void {
      out.push({ unit: one.unit, useCase: one.useCase, slot: one.slot,
                 alg: one.alg, crv: one.crv || '', kind: one.kind,
                 kid: one.kid, role: one.role,
                 createdAt: Number(one.createdAt) || 0,
                 retiredAt: Number(one.retiredAt) || 0,
                 retiredUntil: Number(one.retiredUntil) || 0,
                 reason: String(one.reason || '') });
    });
    log.debug("Leaving SigningHistory.keysOfSet(). " + out.length + " key(s).");
    return out;
  }

  // The write half of observe(), kept apart so the caller's catch covers one
  // statement rather than a body with a store write in the middle of it.
  private writeRows(realmId: string, keys: Json, o: Json, out: Json): void {
    const { log, now } = this.deps;
    log.debug("Entering SigningHistory.writeRows().");
    const store = this.storeFor(realmId);
    const at = now();
    const seen: Json = {};
    const self = this;
    this.keysOfSet(keys).forEach(function (one: Json): void {
      const key = self.rowKey(one.unit, one.kid);
      seen[key] = true;
      const before = store.get(key) || null;
      const row = self.rowFor(realmId, before, one, o, at);
      if (!before) {
        out.recorded += 1;
      } else if (JSON.stringify(row) !== JSON.stringify(before)) {
        out.updated += 1;
      } else {
        return;
      }
      store.set(key, row);
    });
    // AND WHAT THE SET NO LONGER HOLDS. A row without `droppedAt` whose key
    // is not in the set was dropped — by `signing.retire` past its grace, or
    // by an emergency rotation. The private half is gone; the row stays.
    store.forEach(function (row: Json, key: string): void {
      if (seen[key] || !row || Number(row.droppedAt) > 0) {
        return;
      }
      const dropped = Object.assign({}, row, {
        role: 'dropped', droppedAt: at,
        reason: String(o.reason || row.reason || 'dropped past its grace') });
      store.set(key, dropped);
      out.dropped += 1;
    });
    log.debug("Leaving SigningHistory.writeRows().");
  }

  // One row, built from what is already stored and what the set says now. The
  // timestamps only ever move FORWARD from absent to set: a row records when
  // something first became true, and an observation that sees a key in a role
  // it was already in must not restamp it.
  private rowFor(realmId: string, before: Json, one: Json, o: Json,
                 at: number): Json {
    const { log } = this.deps;
    log.debug("Entering SigningHistory.rowFor().");
    const row: Json = Object.assign({
      realm: String(realmId || ''), unit: one.unit, useCase: one.useCase,
      slot: one.slot, alg: one.alg, crv: one.crv || '', kind: one.kind,
      kid: one.kid, role: 'next', firstSeenAt: at, createdAt: 0,
      promotedAt: 0, retiredAt: 0, retiredUntil: 0, droppedAt: 0,
      reason: '', certificate: null
    }, before || {});
    row.role = one.role;
    row.createdAt = Number(row.createdAt) || Number(one.createdAt) || 0;
    if (one.role === 'current' && !(Number(row.promotedAt) > 0)) {
      // A key that is current the first time it is seen was promoted at a
      // moment this process did not observe — the set is the only record and
      // it does not keep one, so the row says when it was first seen current
      // rather than inventing a promotion instant.
      row.promotedAt = before ? at : Number(row.createdAt) || at;
    }
    if (one.role === 'retired') {
      row.retiredAt = Number(one.retiredAt) || Number(row.retiredAt) || at;
      row.retiredUntil = Number(one.retiredUntil) || Number(row.retiredUntil) ||
                         0;
    }
    if (one.reason && !row.reason) {
      row.reason = String(one.reason);
    }
    if (o.reason && before && before.role !== one.role) {
      row.reason = String(o.reason);
    }
    // THE CERTIFICATE, ONCE. It is captured the first time the authority has
    // one for this key and never replaced afterwards: a re-certification
    // issues a NEW certificate over the same key, and the point of the row is
    // what vouched for that key while it was live.
    if (!row.certificate) {
      row.certificate = this.certificateOf(realmId, one);
    }
    log.debug("Leaving SigningHistory.rowFor().");
    return row;
  }

  // The PUBLIC half of the certificate the authority issued over this key —
  // never a private key, which `pki.certificateFor()` does not hold for a
  // signing key anyway, and never a chain longer than the record carries.
  // A unit with no certificate (the BBS key: bbs-2023 keys are not X.509
  // subjects) answers null, which the pages draw as *no certificate*.
  private certificateOf(realmId: string, one: Json): Json {
    const { log, pki } = this.deps;
    log.debug("Entering SigningHistory.certificateOf().");
    let held: Json = null;
    try {
      held = pki().certificateFor(String(realmId || ''), one.useCase, one.slot,
                                  one.kid);
    } catch (e) {
      // No certificate authority in this process, or none for this key yet.
      // Either is ordinary and the row is written without one; the next
      // observation captures it.
      log.debug("Caught in SigningHistory.certificateOf(): " +
                ((e && e.message) || e));
      held = null;
    }
    if (!held || !held.certificatePem) {
      log.debug("Leaving SigningHistory.certificateOf(). None held.");
      return null;
    }
    log.debug("Leaving SigningHistory.certificateOf(). Captured.");
    return {
      serialHex: String(held.serialHex || ''),
      subject: String(held.subject || ''),
      notBefore: String(held.notBefore || ''),
      notAfter: String(held.notAfter || ''),
      thumbprint: String(held.thumbprint || ''),
      keyAlg: String(held.keyAlg || ''),
      signatureAlg: String(held.signatureAlg || ''),
      certificatePem: String(held.certificatePem || ''),
      chainPem: (held.chainPem || []).map(String)
    };
  }

  // ---------------------------------------------------------------------------
  // THE READ SIDE.
  //
  // `unitsOf()` is the summary the Key pairs page draws beside each unit — how
  // many generations it has had, and the newest. `rowsOf()` is one unit's
  // whole history, newest first, which the sub-page PAGES.
  // ---------------------------------------------------------------------------
  private allRows(realmId: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering SigningHistory.allRows().");
    const store = this.storeFor(realmId);
    const out: Json[] = [];
    store.forEach(function (row: Json): void {
      if (row) {
        out.push(row);
      }
    });
    log.debug("Leaving SigningHistory.allRows(). " + out.length + " row(s).");
    return out;
  }

  // Newest first, by the moment the row's key last moved — a dropped key by
  // its drop, a retired one by its retirement, a live one by its promotion or
  // its minting. Ties break on the kid so a page is stable between reads.
  private sortRows(rows: Json[]): Json[] {
    const { log } = this.deps;
    log.debug("Entering SigningHistory.sortRows().");
    const when = function (row: Json): number {
      return Number(row.droppedAt) || Number(row.retiredAt) ||
             Number(row.promotedAt) || Number(row.createdAt) ||
             Number(row.firstSeenAt) || 0;
    };
    const out = rows.slice().sort(function (a: Json, b: Json): number {
      const d = when(b) - when(a);
      return d !== 0 ? d : String(a.kid).localeCompare(String(b.kid));
    });
    log.debug("Leaving SigningHistory.sortRows().");
    return out;
  }

  // Every unit this realm has a history for, with its counts. A unit the set
  // holds today and has never rotated has one row, which is the answer the
  // page wants: *one generation, this one*.
  unitsOf(realmId: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering SigningHistory.unitsOf(). realm=" + realmId);
    const by: Json = {};
    this.allRows(realmId).forEach(function (row: Json): void {
      const u = String(row.unit || '');
      const seen = by[u] || (by[u] = { unit: u, useCase: row.useCase,
                                       slot: row.slot, alg: row.alg,
                                       generations: 0, live: 0, dropped: 0,
                                       withCertificate: 0, newestAt: 0 });
      seen.generations += 1;
      if (Number(row.droppedAt) > 0) {
        seen.dropped += 1;
      } else {
        seen.live += 1;
      }
      if (row.certificate) {
        seen.withCertificate += 1;
      }
      const at = Number(row.firstSeenAt) || 0;
      if (at > seen.newestAt) {
        seen.newestAt = at;
      }
    });
    const out = Object.keys(by).sort().map(function (u: string): Json {
      return by[u];
    });
    log.debug("Leaving SigningHistory.unitsOf(). " + out.length + " unit(s).");
    return out;
  }

  // One unit's history, newest first. `unit` is required and a unit with no
  // rows answers an EMPTY list rather than a refusal: a realm whose keys have
  // never been observed has a history of nothing, which is a true answer and
  // not an error.
  rowsOf(realmId: string, unit: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering SigningHistory.rowsOf(). unit=" + unit);
    const wanted = String(unit || '');
    const rows = this.allRows(realmId).filter(function (row: Json): boolean {
      return String(row.unit || '') === wanted;
    });
    log.debug("Leaving SigningHistory.rowsOf(). " + rows.length + " row(s).");
    return this.sortRows(rows);
  }

  // The view model both doors answer with — the console's sub-page and
  // `GET /admin-api/keys/history`. It carries the rows for ONE unit where one
  // is named and the unit summary otherwise, so a caller with no unit in hand
  // can find one. The CERTIFICATE PEM is carried only for a single unit's
  // rows: a summary listing every certificate of every unit would be a page
  // of PEM nobody asked for.
  historyView(realmId: string, options?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering SigningHistory.historyView(). realm=" + realmId);
    const o = options || {};
    const unit = String(o.unit || '');
    const view: Json = { realm: String(realmId || ''), unit: unit,
                         units: this.unitsOf(realmId), rows: [], total: 0 };
    if (unit) {
      const rows = this.rowsOf(realmId, unit);
      view.total = rows.length;
      view.rows = rows.map(this.publicRow.bind(this));
      view.found = view.units.some(function (one: Json): boolean {
        return one.unit === unit;
      });
    }
    log.debug("Leaving SigningHistory.historyView(). " + view.rows.length +
              " row(s) of " + view.total + ".");
    return view;
  }

  // What leaves this module. It is the stored row with nothing added and
  // nothing hidden — there is no private material in a row to hide, which is
  // the property this whole file rests on — with the timestamps as ISO
  // strings, because every other view model here answers in ISO and a page
  // that had to format epoch milliseconds would be the only one.
  private publicRow(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering SigningHistory.publicRow().");
    const iso = function (ms: Json): string | null {
      return Number(ms) > 0 ? new Date(Number(ms)).toISOString() : null;
    };
    log.debug("Leaving SigningHistory.publicRow().");
    return {
      unit: row.unit, useCase: row.useCase, slot: row.slot, alg: row.alg,
      crv: row.crv || '', kind: row.kind, kid: row.kid, role: row.role,
      createdAt: iso(row.createdAt), firstSeenAt: iso(row.firstSeenAt),
      promotedAt: iso(row.promotedAt), retiredAt: iso(row.retiredAt),
      verifiesUntil: iso(row.retiredUntil), droppedAt: iso(row.droppedAt),
      reason: String(row.reason || ''),
      certificate: row.certificate ? Object.assign({}, row.certificate) : null
    };
  }

  // For the tests, and for nothing in the service: the store this module
  // writes, so a test can assert what was recorded rather than what a view
  // reported about it. `helpers.resetStsKeys()`'s note applies — nothing in
  // the service calls it, and nothing should.
  forgetForTests(realmId: string): void {
    const { log } = this.deps;
    log.debug("Entering SigningHistory.forgetForTests().");
    const store = this.storeFor(realmId);
    store.clear();
    log.debug("Leaving SigningHistory.forgetForTests().");
  }
}

// TRANSITIONAL (#50's R2): the instance the unconverted callers use, and the
// names they require. `common/protocol_stack.ts` does not build this module —
// it registers no route and holds no socket — so the instance is built here,
// once, at load.
const instance = new SigningHistory(SigningHistory.defaultDeps());

export = {
  SigningHistory: SigningHistory,
  observe: instance.observe.bind(instance),
  historyView: instance.historyView.bind(instance),
  unitsOf: instance.unitsOf.bind(instance),
  rowsOf: instance.rowsOf.bind(instance),
  forgetForTests: instance.forgetForTests.bind(instance)
};
