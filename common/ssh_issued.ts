// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssh_issued.ts
//
// ===========================================================================
// THE SSH USER CERTIFICATES A REALM ISSUED (the #1955 review of P3).
//
// One row per certificate, keyed by its serial in lower-case hex with no
// leading zeros:
//
//   { serialHex, keyType, keyFingerprint, ownerSubject, principals,
//     issuedAt, notAfter, hardwareBound, evidence, caMember,
//     revokedAt? }
//
// **WHY A STORE OF ITS OWN.** Until the review every issued serial was a
// member of the realm's PKI row (`sshIssued`), and the row is rewritten
// whole on every change: each issuance rewrote every serial issued before
// it, so what one issuance cost grew with how many the realm had issued, and
// the row grew without a bound but expiry. Here an issuance is one row, a
// revocation rewrites one row, and a person's certificates, a key's, and the
// revoked ones the KRL needs are each one indexed question (`o:`, `k:`,
// `r:1`), never a walk.
//
// **WHAT WAS ON THE PKI ROW IS STILL READ** (backwards compatibility):
// `common/pki.js` asks this store first and the row second, for a serial,
// for a key's certificates and for the KRL, so a certificate issued before
// the review is listed, revocable and on the KRL exactly as it was. Nothing
// new is written to the row.
//
// **WHERE IT IS KEPT.** A per-realm store at its declaration
// (`realms.map()`, `persist: 'ssh_user_ca.issued'`), ON DEMAND (#820) with
// its index, in the GLOBAL tier (`persistence/tiers.js`: one KRL per realm,
// published by every cell, as the PKI row was). A row expires with its
// certificate (`expiresAt` is its `notAfter`): an expired certificate
// authenticates nobody and need not be on the KRL, so the store's own
// expiry purge is its bound and no job of this module's sweeps it. A write
// is flushed before the issuance or revocation answers, so a certificate is
// never handed out, nor a revocation reported, that the store did not keep.
//
// A LIBRARY (rule 3): it registers no route. It requires `realms`,
// `helpers` and `cache_registry`; the persistence layer is reached at the
// moment of use.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import realms = require('./realms');
import cacheRegistry = require('./cache_registry');

type Json = any;

// The rows one console or account page lists at most.
const MAX_LIST = 500;
const HELD = 5000;

// ---------------------------------------------------------------------------
// THE STORE, per realm at its declaration. `indexBy`, `sortBy` and
// `expiresAt` run on every row a flush writes, so none has an
// Entering/Leaving pair (a hot path).
// ---------------------------------------------------------------------------
const issued = realms.map({
  persist: 'ssh_user_ca.issued',
  onDemand: { maxEntries: HELD },
  indexBy: function (row: Json): string[] {
    const out: string[] = [];
    if (!row) {
      return out;
    }
    if (row.ownerSubject) {
      out.push('o:' + String(row.ownerSubject));
    }
    if (row.keyFingerprint) {
      out.push('k:' + String(row.keyFingerprint));
    }
    if (row.revokedAt) {
      out.push('r:1');
    }
    return out;
  },
  sortBy: function (row: Json): number | null {
    const at = row ? Date.parse(String(row.issuedAt || '')) : NaN;
    return at > 0 ? at : null;
  },
  expiresAt: function (row: Json): number | null {
    const at = row ? Date.parse(String(row.notAfter || '')) : NaN;
    return at > 0 ? at : null;
  }
});

cacheRegistry.register({
  name: 'ssh_user_ca.issued',
  title: 'SSH user certificates issued',
  description: 'One row per OpenSSH user certificate this realm\'s SSH ' +
    'user CA issued, keyed by serial: whose it is (urn:uuid), the key ' +
    'fingerprint, its principals, its lifetime and whether it was revoked. ' +
    'Never a key.',
  owner: 'common/ssh_issued.ts',
  scope: 'realm',
  kind: 'cache',
  persisted: true,
  settings: [],
  maxEntries: function (): number {
    return HELD;
  },
  bound: 'The rows a process holds are a cache of 5,000 per realm; a row ' +
    'leaves the store when its certificate expires.',
  lifetime: function (): string {
    return 'Until the certificate expires.';
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, issued,
      function (row: Json, key: unknown): object {
        const until = Date.parse(String((row && row.notAfter) || ''));
        return { key: String(key) + ((row && row.revokedAt) ? ' (revoked)'
                                                            : ''),
                 validUntil: Number.isFinite(until) ? until : null };
      });
  }
});

interface SshIssuedDeps {
  log: typeof helpers.log;
  realms: typeof realms;
  // Reached at the moment of use: the persistence layer requires half of
  // this service.
  loadPersistence: () => Json;
}

/**
 * The register of the SSH user certificates a realm issued.
 */
class SshIssued {
  static readonly MAX_LIST = MAX_LIST;

  /**
   * Builds the register over its dependencies.
   *
   * @param deps - the logger, the realms and the persistence loader
   */
  constructor(private readonly deps: SshIssuedDeps) {
    deps.log.debug("Entering SshIssued.constructor().");
    deps.log.debug("Leaving SshIssued.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): SshIssuedDeps {
    helpers.log.debug("Entering SshIssued.defaultDeps().");
    helpers.log.debug("Leaving SshIssued.defaultDeps().");
    return {
      log: helpers.log, realms: realms,
      loadPersistence: function (): Json {
        return require('../persistence/persistence');
      }
    };
  }

  /**
   * A serial as the register keys it: lower-case hex, no leading zeros.
   *
   * @param serialHex - the serial
   * @returns the key, or '' for one that is not a serial
   */
  static keyOf(serialHex: unknown): string {
    helpers.log.debug("Entering SshIssued.keyOf().");
    const text = String(serialHex === undefined || serialHex === null
      ? '' : serialHex).toLowerCase().replace(/^0+(?=.)/, '');
    helpers.log.debug("Leaving SshIssued.keyOf().");
    return /^[0-9a-f]{1,16}$/.test(text) && text !== '0' ? text : '';
  }

  // Runs `fn` with the realm ambient: the store answers the ambient realm.
  private within<T>(realmId: string, fn: () => Promise<T>): Promise<T> {
    const { log, realms: r } = this.deps;
    log.debug("Entering SshIssued.within().");
    const id = String(realmId || '');
    const current = String(r.currentId() || '');
    log.debug("Leaving SshIssued.within().");
    return id === current ? fn() : r.run(id, fn);
  }

  // A store write made durable before the caller answers (header). Answers
  // false when it could not be.
  private async settle(): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.settle().");
    try {
      const persistence = this.deps.loadPersistence();
      if (persistence && typeof persistence.flushMinted === 'function') {
        await persistence.flushMinted();
      }
    } catch (e) {
      log.debug("Caught in SshIssued.settle(): " + ((e && e.message) || e));
      log.debug("Leaving SshIssued.settle(). Not flushed.");
      return false;
    }
    log.debug("Leaving SshIssued.settle().");
    return true;
  }

  // The rows an index key names, read from the store where this process
  // does not hold them all; a stale index row is dropped by `keep`.
  private async rowsOf(indexKey: string,
                       keep: (row: Json) => boolean): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.rowsOf().");
    let rows: Json[] = [];
    try {
      rows = await issued.lookupEntriesAsync(indexKey);
    } catch (e) {
      log.debug("Caught in SshIssued.rowsOf(): " + ((e && e.message) || e));
      // The read pool cannot be asked: what this process holds.
      rows = issued.lookup(indexKey).map(function (k: Json): Json {
        return { key: k, value: issued.get(k) };
      });
    }
    const seen: Record<string, boolean> = {};
    const out = rows.filter(function (r: Json): boolean {
      const ok = !!(r && r.value && !seen[String(r.key)] && keep(r.value));
      seen[String(r && r.key)] = true;
      return ok;
    }).map(function (r: Json): Json {
      return r.value;
    });
    log.debug("Leaving SshIssued.rowsOf(). " + out.length);
    return out;
  }

  /**
   * Records issued certificates, durably.
   *
   * @param realmId - the realm
   * @param rows - one row per certificate (header)
   * @returns a promise of true when they were kept
   */
  record(realmId: string, rows: Json[]): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.record(). " + (rows || []).length);
    return this.within(realmId, async (): Promise<boolean> => {
      (rows || []).forEach(function (row: Json): void {
        const key = SshIssued.keyOf(row && row.serialHex);
        if (key) {
          issued.set(key, Object.assign({}, row, { serialHex: key }));
        }
      });
      const kept = await this.settle();
      log.debug("Leaving SshIssued.record(). " + kept);
      return kept;
    });
  }

  /**
   * One certificate by its serial.
   *
   * @param realmId - the realm
   * @param serialHex - the serial
   * @returns a promise of its row, or null
   */
  get(realmId: string, serialHex: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.get().");
    const key = SshIssued.keyOf(serialHex);
    return this.within(realmId, async (): Promise<Json> => {
      if (!key) {
        log.debug("Leaving SshIssued.get(). Not a serial.");
        return null;
      }
      if (!issued.get(key)) {
        try {
          await issued.warm([key]);
        } catch (e) {
          log.debug("Caught in SshIssued.get(): " + ((e && e.message) || e));
          // The store cannot be asked: what this process holds decides.
        }
      }
      const row = issued.get(key) || null;
      log.debug("Leaving SshIssued.get(). " + !!row);
      return row;
    });
  }

  /**
   * Marks a certificate revoked, durably; a revoked one stays revoked.
   *
   * @param realmId - the realm
   * @param serialHex - the serial
   * @param at - when, ISO 8601
   * @returns a promise of `{ ok, found, changed }`
   */
  async markRevoked(realmId: string, serialHex: string,
                    at: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.markRevoked().");
    const row = await this.get(realmId, serialHex);
    if (!row) {
      log.debug("Leaving SshIssued.markRevoked(). Not here.");
      return { ok: true, found: false, changed: false };
    }
    if (row.revokedAt) {
      log.debug("Leaving SshIssued.markRevoked(). Already.");
      return { ok: true, found: true, changed: false };
    }
    const kept = await this.within(realmId, async (): Promise<boolean> => {
      issued.set(SshIssued.keyOf(serialHex),
                 Object.assign({}, row, { revokedAt: String(at) }));
      return this.settle();
    });
    log.debug("Leaving SshIssued.markRevoked(). " + kept);
    return { ok: kept, found: true, changed: true };
  }

  /**
   * A person's certificates, newest first, expired ones left out.
   *
   * @param realmId - the realm
   * @param ownerSubject - the person's subject (`urn:uuid:...`)
   * @param nowMs - the instant expiry is judged at
   * @returns a promise of the rows
   */
  ofOwner(realmId: string, ownerSubject: string,
          nowMs: number): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.ofOwner().");
    const owner = String(ownerSubject || '');
    return this.within(realmId, async (): Promise<Json[]> => {
      if (!owner) {
        log.debug("Leaving SshIssued.ofOwner(). Nobody.");
        return [];
      }
      const rows = await this.rowsOf('o:' + owner, function (row) {
        return String(row.ownerSubject) === owner &&
               SshIssued.live(row, nowMs);
      });
      log.debug("Leaving SshIssued.ofOwner(). " + rows.length);
      return rows.sort(SshIssued.newestFirst).slice(0, MAX_LIST);
    });
  }

  /**
   * The live certificates of one key.
   *
   * @param realmId - the realm
   * @param fingerprint - the key's `sshFingerprint()`
   * @param nowMs - the instant expiry is judged at
   * @returns a promise of the rows
   */
  ofKey(realmId: string, fingerprint: string, nowMs: number): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.ofKey().");
    const wanted = String(fingerprint || '');
    return this.within(realmId, async (): Promise<Json[]> => {
      const rows = wanted ? await this.rowsOf('k:' + wanted, function (row) {
        return String(row.keyFingerprint) === wanted &&
               SshIssued.live(row, nowMs);
      }) : [];
      log.debug("Leaving SshIssued.ofKey(). " + rows.length);
      return rows;
    });
  }

  /**
   * The revoked certificates that have not expired: what the KRL lists.
   *
   * @param realmId - the realm
   * @param nowMs - the instant expiry is judged at
   * @returns a promise of the rows
   */
  revoked(realmId: string, nowMs: number): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.revoked().");
    return this.within(realmId, async (): Promise<Json[]> => {
      const rows = await this.rowsOf('r:1', function (row) {
        return !!row.revokedAt && SshIssued.live(row, nowMs);
      });
      log.debug("Leaving SshIssued.revoked(). " + rows.length);
      return rows;
    });
  }

  // Not expired at `nowMs` (a row with no expiry is live).
  private static live(row: Json, nowMs: number): boolean {
    const at = Date.parse(String((row && row.notAfter) || ''));
    return !Number.isFinite(at) || at > nowMs;
  }

  private static newestFirst(a: Json, b: Json): number {
    return String(b.issuedAt || '').localeCompare(String(a.issuedAt || ''));
  }

  // For the tests: the ambient realm's register cleared.
  /**
   * Clears the ambient realm's register; for tests only.
   */
  forgetForTests(): void {
    const { log } = this.deps;
    log.debug("Entering SshIssued.forgetForTests().");
    issued.clear();
    log.debug("Leaving SshIssued.forgetForTests().");
  }
}

const slot = new InstanceSlot<SshIssued>(
  'common/ssh_issued',
  () => new SshIssued(SshIssued.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The register of issued SSH user certificates (the #1955 review). A
 * library (rule 3).
 * @namespace
 */
export = {
  SshIssued: SshIssued,
  keyOf: SshIssued.keyOf,
  installInstance: (instance: SshIssued): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  record: slot.forward('record'),
  get: slot.forward('get'),
  markRevoked: slot.forward('markRevoked'),
  ofOwner: slot.forward('ofOwner'),
  ofKey: slot.forward('ofKey'),
  revoked: slot.forward('revoked'),
  forgetForTests: slot.forward('forgetForTests')
};
