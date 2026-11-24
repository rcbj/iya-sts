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
//     certificate?, entry?, revokedAt? }
//
// (`certificate`, the certificate in OpenSSH text form, and `entry`, where
// the row stands on its holder's entry, since #2050; below.)
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
// **AND ON THE HOLDER'S ENTRY (#2050, rcbj 2026-11-23: "I want
// userSMIMECertificates and SSH user certificates to be mapped to Directory
// user objects").** A person's live certificates are on their entry in
// `stsSshUserCertificate` (OID 1000), one JSON value each — its serial, the
// certificate in OpenSSH text form, the key's type and fingerprint, its
// principals, when it was issued and expires, and which authority signed it
// — as their `userCertificate` and `userSMIMECertificate` are. JSON rather
// than the bare text so that a value can be removed by its serial and
// judged expired without parsing a wire-format certificate, and so that a
// certificate issued before #2050, whose text this store never kept, is
// still on its holder's entry.
//
// **THE STORE IS AUTHORITATIVE; THE ENTRY IS ITS PROJECTION.** The entry is
// what a person HOLDS, the store is what the CA must PUBLISH: the KRL, a
// key's certificates (`ofKey()`, the lost-key retirement) and revocation
// all ask the store, never the entry. On a conflict the store wins: a value
// whose serial the store holds revoked, expired, for somebody else or not at
// all is removed, and a live certificate the store holds for the person and
// the entry lacks is written back. So a value written to the attribute by
// hand, through LDAP or the attribute editor, is dropped at the next
// reconcile of that person, and deleting one revokes nothing (a revocation
// is the CA's act: `/account-api/ssh/certificates/revoke`, the console,
// `/admin-api/hardware-tokens/revoke-ssh`, a lost key).
//
// `entry` on the row is where that projection stands: `held` (on the entry,
// or owed there), `gone` (off it, for good), or absent (a row written
// before #2050). A row `held` is indexed `e:1`, and its store expiry is
// ENTRY_GRACE_MS past its `notAfter`, so the job below sees it expire and
// takes it off the entry before the store's purge takes the row; once
// `gone` it expires with its certificate, as every row did.
//
//   * **ISSUANCE** (`record()`): the rows are kept `held`, made durable, and
//     only then written onto the holder's entry. A write that fails leaves
//     the row `held`, and the job writes it.
//   * **REVOCATION** (`markRevoked()`: a person's own, an administrator's,
//     every certificate of a lost key through `pki.revokeSshUserKeyAsync()`)
//     takes the value off the entry first, then rewrites the row revoked
//     and `gone` — or still `held` where the entry could not be written, so
//     the job takes it off. A revoked row stays in the store until its
//     certificate expires, as it always did, because the KRL lists it.
//   * **EXPIRY**: the job below.
//
// **THE JOB, `ssh-user-ca.entries`**: a CLUSTER job per realm every five
// minutes (`cluster/CLAUDE.md`, *The scheduler*), its body in a request
// worker (#408). Each run reconciles every person the `e:1` index names —
// a bounded question: a certificate lives an hour at most
// (`pki.sshHardwareLifetimeSeconds`' ceiling), so the index holds about an
// hour's issuance — and marks `gone` what it took off. Its first run in a
// process also BACKFILLS (backwards compatibility from 1.0.0 on): every
// live row written before #2050 (no `entry`) and every live certificate
// still on the realm's PKI row from before the #1955 review (`sshIssued`,
// copied into this store with its revocation, so the KRL's union is
// unchanged) is marked `held`, and the reconcile that follows writes it
// onto its holder's entry. Idempotent: a row already marked is skipped, a
// serial already here is not copied twice, and a value already on the
// entry is not written again. The walk is of this store, never of the
// directory, and the store holds an hour of certificates; after an hour of
// this build nothing it would find is live, so a later process's walk finds
// nothing to do. No SQL schema change: the marker is a field of the row.
//
// **THE DIRECTORY IS A SLOT, `setDirectory()`, filled by
// `ldap/ldap_server.js` (rule 3e).** This module is built at the
// composition root's credential libraries, long before the directory (21),
// and is reached by `pki.js`; a require of `ldap_server.js` from here at
// load would register its `/admin/ldap/*` pages there, ahead of the console
// and the authorization server, and a lazy one would need the store's whole
// writer exported for one attribute. The directory requiring this library
// is a cache hit that moves nothing. The slot is `{ locate(subject), write
// (dn, values) }`: one person's values found by subject off the event loop,
// and that one attribute replaced in place — and is validated whole
// (STS-SSHCA-0006). Empty, nothing is written onto an entry and every row
// stays `held`, so the first run after it is filled writes them.
//
// **IN CELLS** the register is the global tier's and a person's entry is in
// their home cell, so the job runs in every cell (it is not one of
// `persistence/tiers.js`' GLOBAL_JOBS) and each cell brings in step only
// the entries it holds; a row is marked `gone` only by a process that saw
// the entry (`project()`).
//
// A LIBRARY (rule 3): it registers no route. It requires `realms`,
// `helpers`, `cache_registry` and `error_codes`; the persistence layer, the
// PKI row (`pki.js`) and the scheduler are reached at the moment of use.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import realms = require('./realms');
import cacheRegistry = require('./cache_registry');
import errorCodes = require('./error_codes');

type Json = any;

// The rows one console or account page lists at most.
const MAX_LIST = 500;
const HELD = 5000;

// How long past its expiry a row still on its holder's entry is kept, so the
// job sees it expire (header). A day: a job that has not run for a day has a
// problem the console's scheduler page says, and an expired certificate on
// an entry signs nobody in meanwhile.
const ENTRY_GRACE_MS = 24 * 60 * 60 * 1000;
// The entries job (header) and how often it runs.
const ENTRIES_JOB = 'ssh-user-ca.entries';
const ENTRIES_EVERY_MS = 5 * 60 * 1000;
// The attribute on the person.
const ATTRIBUTE = 'stsSshUserCertificate';

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
    if (row.entry === 'held') {
      out.push('e:1');
    }
    return out;
  },
  sortBy: function (row: Json): number | null {
    const at = row ? Date.parse(String(row.issuedAt || '')) : NaN;
    return at > 0 ? at : null;
  },
  expiresAt: function (row: Json): number | null {
    const at = row ? Date.parse(String(row.notAfter || '')) : NaN;
    if (!(at > 0)) {
      return null;
    }
    // Still on its holder's entry: kept until the job takes it off (header).
    return row.entry === 'held' ? at + ENTRY_GRACE_MS : at;
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
  errorCodes: typeof errorCodes;
  // Reached at the moment of use: the persistence layer requires half of
  // this service.
  loadPersistence: () => Json;
  // The certificates the realm's PKI row recorded before the #1955 review,
  // reached at the moment of use (`pki.js` reaches this module).
  legacyRows?: (realmId: string) => Promise<Json[]>;
}

// The directory's half (header): one person's values by subject, and that
// one attribute written.
interface SshEntryDirectory {
  locate(subject: string): Promise<{ dn: string; values: string[] } | null>;
  write(dn: string, values: string[]): boolean;
}

/**
 * The register of the SSH user certificates a realm issued.
 */
class SshIssued {
  static readonly MAX_LIST = MAX_LIST;
  static readonly ATTRIBUTE = ATTRIBUTE;
  static readonly ENTRY_GRACE_MS = ENTRY_GRACE_MS;

  // The directory's half (`setDirectory()`), or null until it is filled.
  private directory: SshEntryDirectory | null = null;
  // The realms whose backfill this process has finished (header).
  private backfilled: Record<string, boolean> = {};

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
      log: helpers.log, realms: realms, errorCodes: errorCodes,
      loadPersistence: function (): Json {
        return require('../persistence/persistence');
      },
      legacyRows: function (realmId: string): Promise<Json[]> {
        return require('./pki').legacySshUserCertificatesAsync(realmId);
      }
    };
  }

  /**
   * Installs the directory's half (header, rule 3e), validated whole.
   *
   * @param directory - `{ locate(subject), write(dn, values) }`, or null
   * @returns true when it was installed (or cleared)
   */
  setDirectory(directory: Json): boolean {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering SshIssued.setDirectory().");
    if (directory === null) {
      this.directory = null;
      log.debug("Leaving SshIssued.setDirectory(). Cleared.");
      return true;
    }
    const missing = ['locate', 'write'].filter(function (name) {
      return !directory || typeof directory[name] !== 'function';
    });
    if (missing.length) {
      log.error(codes.tag('STS-SSHCA-0006') + 'ssh user CA: the directory ' +
                'offered no ' + missing.join(', ') + ', so nothing was ' +
                'installed; no SSH user certificate is written onto its ' +
                'holder\'s entry until one is.');
      log.debug("Leaving SshIssued.setDirectory(). Partial.");
      return false;
    }
    this.directory = directory;
    log.debug("Leaving SshIssued.setDirectory().");
    return true;
  }

  /**
   * The directory installed, so a test can put it back.
   *
   * @returns the directory's half, or null
   */
  installedDirectory(): Json {
    this.deps.log.debug("Entering SshIssued.installedDirectory().");
    this.deps.log.debug("Leaving SshIssued.installedDirectory().");
    return this.directory;
  }

  /**
   * One row as its holder's entry carries it (header): a JSON value, never
   * a key.
   *
   * @param row - the register's row
   * @returns the value
   */
  static entryValueOf(row: Json): string {
    helpers.log.debug("Entering SshIssued.entryValueOf().");
    const r = row || {};
    const value: Json = {
      serialHex: SshIssued.keyOf(r.serialHex),
      keyType: String(r.keyType || ''),
      keyFingerprint: String(r.keyFingerprint || ''),
      principals: Array.isArray(r.principals) ? r.principals.map(String) : [],
      issuedAt: String(r.issuedAt || ''),
      notAfter: String(r.notAfter || ''),
      authority: r.caMember === 'sshUserCaPqc' ? 'ssh-mldsa-65' : 'classical'
    };
    if (r.certificate) {
      value.certificate = String(r.certificate);
    }
    helpers.log.debug("Leaving SshIssued.entryValueOf().");
    return JSON.stringify(value);
  }

  /**
   * One value of the attribute read back: its serial, its expiry and the
   * rest as written, or null for a value this module did not write.
   *
   * @param value - one value of `stsSshUserCertificate`
   * @returns the value read, or null
   */
  static readEntryValue(value: unknown): Json {
    helpers.log.debug("Entering SshIssued.readEntryValue().");
    let parsed: Json = null;
    try {
      parsed = JSON.parse(String(value === undefined || value === null
        ? '' : value));
    } catch (e) {
      helpers.log.debug("Caught in SshIssued.readEntryValue(): " +
                        ((e && e.message) || e));
      // Not ours: a value written by hand, which the reconcile drops.
      parsed = null;
    }
    const serial = parsed && typeof parsed === 'object'
      ? SshIssued.keyOf(parsed.serialHex) : '';
    helpers.log.debug("Leaving SshIssued.readEntryValue(). " + !!serial);
    return serial ? Object.assign({}, parsed, { serialHex: serial }) : null;
  }

  // BRINGS ONE PERSON'S ENTRY IN STEP (header): every value whose serial is
  // in `keep` is kept (rewritten from its row), every row of `keep` the
  // entry lacks is added, and everything else — a serial in `drop`, one the
  // caller did not name, a value not ours — goes. With `onlyDrop` the values
  // the caller did not name are left alone (a revocation, which knows of
  // one certificate). Answers `done` when the entry holds what was asked
  // (or there is no owner), `absent` when this directory has no entry for
  // the person, and `failed`. ABSENT IS NOT DONE: in a service deployed as
  // cells the register is the global tier's and a person's entry is in
  // their home cell only, so a cell that does not hold the entry must not
  // mark the row `gone` and leave the home cell's entry holding it; a
  // person deleted outright leaves their rows `held` until the store's
  // purge takes them, a day past their expiry. The realm is ambient.
  private async project(ownerSubject: string, keep: Json[], drop: string[],
                        onlyDrop: boolean): Promise<string> {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering SshIssued.project().");
    const dir = this.directory;
    const owner = String(ownerSubject || '');
    if (!owner) {
      log.debug("Leaving SshIssued.project(). Nobody.");
      return 'done';
    }
    if (!dir) {
      log.debug("Leaving SshIssued.project(). No directory.");
      return 'failed';
    }
    let found: Json = null;
    try {
      found = await dir.locate(owner);
    } catch (e) {
      log.debug("Caught in SshIssued.project(): " + ((e && e.message) || e));
      log.warn(codes.tag('STS-SSHCA-0007') + 'ssh user CA: the entry of ' +
               owner + ' could not be read; the register holds its SSH ' +
               'user certificates and the entries job tries again.');
      log.debug("Leaving SshIssued.project(). Not read.");
      return 'failed';
    }
    if (!found || !found.dn) {
      // Deleted, or another cell's (above).
      log.debug("Leaving SshIssued.project(). No entry here.");
      return 'absent';
    }
    const keepBy: Record<string, Json> = {};
    keep.forEach(function (row: Json): void {
      const key = SshIssued.keyOf(row && row.serialHex);
      if (key) {
        keepBy[key] = row;
      }
    });
    const dropped: Record<string, boolean> = {};
    drop.forEach(function (one: string): void {
      dropped[SshIssued.keyOf(one)] = true;
    });
    const before = (found.values || []).map(String);
    const seen: Record<string, boolean> = {};
    const after: string[] = [];
    before.forEach(function (value: string): void {
      const read = SshIssued.readEntryValue(value);
      const key = read ? read.serialHex : '';
      if (!key || seen[key] || dropped[key]) {
        return;
      }
      if (keepBy[key]) {
        seen[key] = true;
        after.push(SshIssued.entryValueOf(keepBy[key]));
      } else if (onlyDrop) {
        seen[key] = true;
        after.push(value);
      }
    });
    Object.keys(keepBy).forEach(function (key: string): void {
      if (!seen[key]) {
        seen[key] = true;
        after.push(SshIssued.entryValueOf(keepBy[key]));
      }
    });
    if (after.length === before.length &&
        after.every(function (one: string, i: number): boolean {
          return one === before[i];
        })) {
      log.debug("Leaving SshIssued.project(). Already in step.");
      return 'done';
    }
    let written = false;
    try {
      written = dir.write(String(found.dn), after) === true;
    } catch (e) {
      log.debug("Caught in SshIssued.project(): " + ((e && e.message) || e));
      written = false;
    }
    if (!written) {
      log.warn(codes.tag('STS-SSHCA-0007') + 'ssh user CA: the entry ' +
               found.dn + ' could not be written with its SSH user ' +
               'certificates; the register holds them and the entries job ' +
               'tries again.');
    }
    log.debug("Leaving SshIssued.project(). " + written + ", " +
              after.length + " value(s).");
    return written ? 'done' : 'failed';
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
      const byOwner: Record<string, Json[]> = {};
      (rows || []).forEach(function (row: Json): void {
        const key = SshIssued.keyOf(row && row.serialHex);
        if (key) {
          // HELD until it is on the entry, then for as long as it is
          // (header): the job writes it where the write below cannot.
          const kept = Object.assign({}, row, { serialHex: key,
                                                entry: 'held' });
          issued.set(key, kept);
          const owner = String(row.ownerSubject || '');
          if (owner) {
            (byOwner[owner] = byOwner[owner] || []).push(kept);
          }
        }
      });
      const kept = await this.settle();
      // ON THE HOLDER'S ENTRY ONLY ONCE THE STORE KEPT IT (header): an entry
      // never names a certificate the CA could not revoke.
      if (kept) {
        for (const owner of Object.keys(byOwner)) {
          await this.project(owner, byOwner[owner], [], true);
        }
      }
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
      // OFF THE HOLDER'S ENTRY FIRST (header), and the row says whether it
      // went: still `held` where it did not, so the job takes it off.
      const off = await this.project(String(row.ownerSubject || ''), [],
                                     [String(serialHex)], true);
      const entry = row.entry === 'held' && off !== 'done' ? 'held'
                                                           : 'gone';
      issued.set(SshIssued.keyOf(serialHex),
                 Object.assign({}, row, { revokedAt: String(at),
                                          entry: entry }));
      return this.settle();
    });
    log.debug("Leaving SshIssued.markRevoked(). " + kept);
    return { ok: kept, found: true, changed: true };
  }

  /**
   * Takes a certificate the register does not hold off its holder's entry:
   * one revoked on the realm's PKI row, from before the #1955 review, which
   * the backfill had not yet copied here.
   *
   * @param realmId - the realm
   * @param ownerSubject - whose it is
   * @param serialHex - the serial
   * @returns a promise of true when the entry no longer names it
   */
  leaveEntry(realmId: string, ownerSubject: string,
             serialHex: string): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.leaveEntry().");
    return this.within(realmId, async (): Promise<boolean> => {
      const off = await this.project(String(ownerSubject || ''), [],
                                     [String(serialHex || '')], true);
      log.debug("Leaving SshIssued.leaveEntry(). " + off);
      return off === 'done';
    });
  }

  // THE BACKFILL (header): the live rows written before #2050 and the live
  // certificates on the PKI row from before the #1955 review, marked `held`
  // (or `gone`, revoked) so the reconcile writes them. Answers false when
  // something could not be read or kept; the next run tries again. The
  // realm is ambient.
  private async backfill(realmId: string, nowMs: number): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering SshIssued.backfill().");
    let marked = 0;
    let copied = 0;
    // The PKI row's, copied with their revocation (the KRL's union keeps
    // either revocation, so nothing on the KRL changes).
    let legacy: Json[] = [];
    if (this.deps.legacyRows) {
      legacy = await this.deps.legacyRows(realmId);
    }
    for (const one of legacy || []) {
      const key = SshIssued.keyOf(one && one.serialHex);
      if (!key || !SshIssued.live(one, nowMs)) {
        continue;
      }
      if (!issued.get(key)) {
        await issued.warm([key]);
      }
      if (issued.get(key)) {
        continue;
      }
      issued.set(key, Object.assign({}, one, {
        serialHex: key, entry: one.revokedAt ? 'gone' : 'held'
      }));
      copied += 1;
    }
    // This store's own, written before the marker existed.
    const unmarked: Json[] = [];
    await issued.scanAsync(function (row: Json): void {
      if (row && row.entry === undefined && SshIssued.live(row, nowMs)) {
        unmarked.push(row);
      }
    });
    unmarked.forEach(function (row: Json): void {
      const key = SshIssued.keyOf(row.serialHex);
      if (key) {
        issued.set(key, Object.assign({}, row, {
          entry: row.revokedAt ? 'gone' : 'held'
        }));
        marked += 1;
      }
    });
    const kept = copied + marked ? await this.settle() : true;
    log.debug("Leaving SshIssued.backfill(). " + copied + " copied, " +
              marked + " marked, " + kept);
    return { ok: kept, copied: copied, marked: marked };
  }

  /**
   * One run of the entries job (header) in one realm: the backfill, once a
   * process, then every person the `e:1` index names brought in step and
   * what was taken off marked `gone`.
   *
   * @param realmId - the realm
   * @param nowMs - the instant expiry is judged at
   * @returns a promise of `{ ok, copied, marked, people, removed }`
   */
  reconcileEntries(realmId: string, nowMs?: number): Promise<Json> {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering SshIssued.reconcileEntries().");
    const now = Number(nowMs) > 0 ? Number(nowMs) : Date.now();
    const id = String(realmId || '');
    return this.within(id, async (): Promise<Json> => {
      if (!this.directory) {
        log.debug("Leaving SshIssued.reconcileEntries(). No directory.");
        return { ok: true, skipped: true };
      }
      const out: Json = { ok: true, copied: 0, marked: 0, people: 0,
                          removed: 0 };
      try {
        if (!this.backfilled[id]) {
          const filled = await this.backfill(id, now);
          out.copied = filled.copied;
          out.marked = filled.marked;
          if (filled.ok) {
            this.backfilled[id] = true;
          }
        }
        const held = await this.rowsOf('e:1', function (row: Json): boolean {
          return row.entry === 'held';
        });
        const byOwner: Record<string, Json[]> = {};
        held.forEach(function (row: Json): void {
          const owner = String(row.ownerSubject || '');
          (byOwner[owner] = byOwner[owner] || []).push(row);
        });
        const done: Json[] = [];
        for (const owner of Object.keys(byOwner)) {
          const rows = byOwner[owner];
          const live = rows.filter(function (row: Json): boolean {
            return !row.revokedAt && SshIssued.live(row, now);
          });
          const dead = rows.filter(function (row: Json): boolean {
            return live.indexOf(row) < 0;
          });
          out.people += 1;
          // Everything this person holds that the store does not name live
          // goes (header): the reconcile is the whole of their values.
          const state = await this.project(owner, live,
            dead.map(function (row: Json): string {
              return String(row.serialHex);
            }), false);
          if (state === 'done') {
            Array.prototype.push.apply(done, dead);
          }
        }
        done.forEach(function (row: Json): void {
          issued.set(SshIssued.keyOf(row.serialHex),
                     Object.assign({}, row, { entry: 'gone' }));
        });
        out.removed = done.length;
        out.ok = done.length ? await this.settle() : true;
      } catch (e) {
        log.error(codes.tag('STS-SSHCA-0008') + 'ssh user CA: the entries ' +
                  'job could not bring the entries of realm "' +
                  (id || 'default') + '" in step: ' +
                  ((e && e.message) || e));
        log.debug("Leaving SshIssued.reconcileEntries(). Failed.");
        return codes.mark({ ok: false, errors: [
          'The SSH user certificates on entries could not be reconciled.'
        ] }, 'STS-SSHCA-0008');
      }
      log.debug("Leaving SshIssued.reconcileEntries(). " + out.people +
                " person(s), " + out.removed + " taken off.");
      return out;
    });
  }

  /**
   * Registers the entries job (header) with the scheduler.
   *
   * @param schedulerInstance - the cluster scheduler
   * @returns true when registered, false when it already was
   */
  static installScheduler(schedulerInstance?: Json): boolean {
    helpers.log.debug("Entering SshIssued.installScheduler().");
    const scheduler = schedulerInstance || require('../cluster/scheduler');
    if (scheduler.job(ENTRIES_JOB)) {
      helpers.log.debug("Leaving SshIssued.installScheduler(). Already.");
      return false;
    }
    scheduler.register({
      id: ENTRIES_JOB, title: 'SSH user certificates on entries',
      describe: 'Takes each realm\'s expired and revoked SSH user ' +
        'certificates off their holders\' entries (stsSshUserCertificate), ' +
        'writes back a live one an entry lacks, and on its first run in a ' +
        'process copies the certificates issued before they were kept on ' +
        'entries onto their holders.',
      owner: 'common/ssh_issued.ts', kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return ENTRIES_EVERY_MS;
      },
      manual: true, timeoutS: 120,
      run: async function (ctx: Json): Promise<Json> {
        const answer = await slot.get().reconcileEntries(
          String((ctx && ctx.realm) || ''));
        return answer && answer.ok
          ? Object.assign({ ok: true }, answer) : answer;
      }
    });
    helpers.log.debug("Leaving SshIssued.installScheduler().");
    return true;
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
    this.backfilled = {};
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
  ATTRIBUTE: ATTRIBUTE,
  entryValueOf: SshIssued.entryValueOf,
  readEntryValue: SshIssued.readEntryValue,
  installScheduler: SshIssued.installScheduler,
  setDirectory: slot.forward('setDirectory'),
  installedDirectory: slot.forward('installedDirectory'),
  leaveEntry: slot.forward('leaveEntry'),
  reconcileEntries: slot.forward('reconcileEntries'),
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
