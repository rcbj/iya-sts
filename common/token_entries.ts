// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: token_entries.ts
//
// ===========================================================================
// HARDWARE TOKENS ON THE PERSON'S ENTRY (#2051, rcbj 2026-11-23: "Hardware
// tokens, OATH and YubiKey OTP inventories also need to be stored in user
// objects, but maintain the appropriate data structures needed to make
// functionality work. but, the master data elements are user object
// attributes.").
//
// Three person attributes, each one JSON value per token:
//
//   * `stsHardwareToken` (OID 1001): a token the person holds, or holds a
//     credential on — its key (`<vendor>/<serial>`), vendor, serial, model,
//     firmware, form factor, whether it is FIPS, its status and loss, the
//     evidence, whether this person is its holder, and THEIR credentials on
//     it (`common/hardware_tokens.ts`).
//   * `stsOathToken` (1002): an imported OATH token assigned to the person —
//     its inventory key, kind, vendor, serial, model, key id, status and
//     who assigned it when and how (`common/oath_tokens.ts`). Never its
//     secret, which is the person's `stsHotpCredential` or TOTP credential.
//   * `stsYubiOtpToken` (1003): an imported YubiKey OTP assigned to the
//     person — serial, public identity, credential id, status, when it was
//     imported and assigned (`common/yubiotp_store.ts`). Never its AES key,
//     which is the person's `stsYubiOtpCredential`.
//
// **THE ENTRY IS THE MASTER; THE STORES ARE INDEXES** (rcbj, 2026-11-23:
// "Be consistent. The user objects need to contain the master copy of the
// credential data."), under the one rule every credential kind follows
// (`common/entry_observer.ts`, which `ssh_issued.ts` and `openpgp_keys.ts`
// share). The stores stay because the questions that need them are not a
// person's: a credential's token at a sign-in (`c:<kind>:<ref>`), a serial
// typed at a claim, a YK-VAL public identity, the console's paged lists, a
// lost token's retirement.
//
//   * **THE ENTRY FIRST, THEN THE INDEX.** Each module writes the holder's
//     entry and then its row (`put()`); while this library writes an entry
//     its handler is told the write is its own and does nothing.
//   * **CHANGE-DRIVEN.** Every write of a person's entry by another door —
//     the console, `/admin-api`, SCIM, an `ldapmodify` — reaches this
//     library's handler through `noteAccountChange()` for that one entry
//     (`entryChanged()`). A value REMOVED is the token given up, and the
//     module updates its index row for that entry (`entryRemoved()`): a
//     hardware token's credentials of that person dropped from its row, so
//     they are no longer evidence at a sign-in; an OATH or YubiKey OTP token
//     retired, its credential removed and, for a YubiKey, its public
//     identity dropped. A value ADDED or CHANGED is put back to what the
//     index holds for that person (`entryValueFor()`), or taken off, and
//     audited (STS-HWTOKEN-0017): a serial is recorded only from
//     attestation, and a token is assigned only by its inventory.
//   * **THE REBUILD IS RECOVERY, NOT UPKEEP.** The manual job
//     `hardware-tokens.rebuild-index` rewrites every index row from the
//     entries holding these attributes (each module's
//     `rebuildFromEntries()`), so an index can be made again whole after a
//     restore. It is an administrator's tool and never what keeps the
//     indexes right day to day: it reads the holders page by page
//     (`holdersAsync()`, the store's paged holder question in a windowed
//     process, the realm's map in slices with the event loop given back
//     between them), never on a request's path.
//
// **AN UNASSIGNED IMPORT HAS NO PERSON**, so its sealed seed stays in the
// staging inventory until it is assigned or claimed; from then on the
// person's entry is the master and the inventory row keeps no secret.
//
// **A WRITE THAT DID NOT REACH THE ENTRY** leaves its index row marked
// `entrySync: 'pending'` (indexed `e:pending`), and the cluster job
// `hardware-tokens.entries` (per realm, every ten minutes, in every cell,
// since a token and its holder are the cell's) writes it again. Its first
// run in a process is also the BACKFILL (backwards compatibility from 1.0.0
// on): every register and inventory row with a holder is projected onto
// that holder's entry. Idempotent — a value already there is not written
// again — and a walk of the three stores, which are bounded by the tokens
// they describe; later runs read the `e:pending` index only. No SQL schema
// change: the attributes and the marker are values.
//
// **THE DIRECTORY IS A SLOT, `setDirectory()`, filled by
// `ldap/ldap_server.js` (rule 3e).** This module is built beside the
// credential libraries, long before the directory (21); requiring
// `ldap_server.js` from here at load would register its `/admin/ldap/*`
// pages there, and a lazy require would need the store's whole writer
// exported for three attributes. The directory requiring this library is a
// cache hit that moves nothing. The slot is `{ locate(who), locateAsync
// (who), write(dn, attribute, values), holdersAsync(attribute) }` — a person
// found by username or subject, one of the three attributes replaced in
// place, and the holders of one — validated whole (STS-HWTOKEN-0014).
//
// A LIBRARY (rule 3): it registers no route. It requires `helpers`,
// `realms` and `error_codes`; the three token modules and the scheduler are
// reached at the moment of use, since each of them requires this one.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import entryObserver = require('./entry_observer');

type Json = any;

const ATTRIBUTES = {
  hardware: 'stsHardwareToken',
  oath: 'stsOathToken',
  yubiotp: 'stsYubiOtpToken'
};
const ATTRIBUTE_NAMES = [ATTRIBUTES.hardware, ATTRIBUTES.oath,
                         ATTRIBUTES.yubiotp];
const ENTRIES_JOB = 'hardware-tokens.entries';
const REBUILD_JOB = 'hardware-tokens.rebuild-index';
const ENTRIES_EVERY_MS = 10 * 60 * 1000;
// The value field each attribute's values are keyed by.
const KEY_FIELD: Record<string, string> = {
  stsHardwareToken: 'key', stsOathToken: 'key', stsYubiOtpToken: 'serial'
};

interface TokenEntriesDeps {
  log: typeof helpers.log;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  // The three token modules, reached at the moment of use (header).
  loadModules: () => Json[];
}

interface TokenDirectory {
  locate(who: string): Json;
  locateAsync(who: string): Promise<Json>;
  write(dn: string, attribute: string, values: string[]): boolean;
  holdersAsync(attribute: string): Promise<Json[]>;
}

/**
 * A person's hardware, OATH and YubiKey OTP tokens on their entry (#2051).
 */
class TokenEntries {
  static readonly ATTRIBUTES = ATTRIBUTES;

  private directory: TokenDirectory | null = null;
  // The realms whose backfill this process has finished (header).
  private backfilled: Record<string, boolean> = {};
  // How many entry writes of this library's own are in progress: the
  // observer is told of them inside the write, and ignores them (header).
  private selfWrites = 0;

  /**
   * Builds the library over its dependencies.
   *
   * @param deps - the logger, the realms, the codes and the module loader
   */
  constructor(private readonly deps: TokenEntriesDeps) {
    deps.log.debug("Entering TokenEntries.constructor().");
    deps.log.debug("Leaving TokenEntries.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): TokenEntriesDeps {
    helpers.log.debug("Entering TokenEntries.defaultDeps().");
    helpers.log.debug("Leaving TokenEntries.defaultDeps().");
    return {
      log: helpers.log, realms: realms, errorCodes: errorCodes,
      loadModules: function (): Json[] {
        return [require('./hardware_tokens'), require('./oath_tokens'),
                require('./yubiotp_store')];
      }
    };
  }

  /**
   * Installs the directory's half (header, rule 3e), validated whole.
   *
   * @param directory - the four functions, or null to clear
   * @returns true when installed or cleared
   */
  setDirectory(directory: Json): boolean {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering TokenEntries.setDirectory().");
    if (directory === null) {
      this.directory = null;
      log.debug("Leaving TokenEntries.setDirectory(). Cleared.");
      return true;
    }
    const missing = ['locate', 'locateAsync', 'write', 'holdersAsync']
      .filter(function (name) {
        return !directory || typeof directory[name] !== 'function';
      });
    if (missing.length) {
      log.error(codes.tag('STS-HWTOKEN-0014') + 'hardware tokens: the ' +
                'directory offered no ' + missing.join(', ') + ', so ' +
                'nothing was installed; no token is written onto its ' +
                'holder\'s entry until one is.');
      log.debug("Leaving TokenEntries.setDirectory(). Partial.");
      return false;
    }
    this.directory = directory;
    log.debug("Leaving TokenEntries.setDirectory().");
    return true;
  }

  /**
   * The directory installed, so a test can put it back.
   *
   * @returns the directory's half, or null
   */
  installedDirectory(): Json {
    this.deps.log.debug("Entering TokenEntries.installedDirectory().");
    this.deps.log.debug("Leaving TokenEntries.installedDirectory().");
    return this.directory;
  }

  /**
   * A value as it is stored: JSON with its keys in a stable order, so an
   * unchanged token compares equal and is not written again.
   *
   * @param value - the token's value
   * @returns the stored text
   */
  static stored(value: Json): string {
    helpers.log.debug("Entering TokenEntries.stored().");
    const sort = function sortKeys(v: Json): Json {
      if (Array.isArray(v)) {
        return v.map(sortKeys);
      }
      if (v && typeof v === 'object') {
        const out: Json = {};
        Object.keys(v).sort().forEach(function (k: string): void {
          if (v[k] !== undefined) {
            out[k] = sortKeys(v[k]);
          }
        });
        return out;
      }
      return v;
    };
    helpers.log.debug("Leaving TokenEntries.stored().");
    return JSON.stringify(sort(value));
  }

  /**
   * One stored value read back, or null for one that is not JSON.
   *
   * @param value - a stored value
   * @returns the value, or null
   */
  static read(value: unknown): Json {
    helpers.log.debug("Entering TokenEntries.read().");
    let out: Json = null;
    try {
      out = JSON.parse(String(value === undefined || value === null
        ? '' : value));
    } catch (e) {
      helpers.log.debug("Caught in TokenEntries.read(): " +
                        ((e && e.message) || e));
      // Not ours: a value written by hand.
      out = null;
    }
    helpers.log.debug("Leaving TokenEntries.read().");
    return out && typeof out === 'object' && !Array.isArray(out) ? out
                                                                 : null;
  }

  // The field an attribute's values are keyed by; a name that is not one
  // of the three is a programming error.
  private static check(attribute: string): string {
    helpers.log.debug("Entering TokenEntries.check().");
    if (ATTRIBUTE_NAMES.indexOf(attribute) < 0) {
      helpers.log.debug("Leaving TokenEntries.check(). Not ours.");
      throw new TypeError('token_entries: not one of the token ' +
                          'attributes: ' + attribute);
    }
    helpers.log.debug("Leaving TokenEntries.check().");
    return KEY_FIELD[attribute];
  }

  // The values with `key` replaced by `value` (or dropped, for null), or
  // null when nothing changes.
  private static replaced(before: string[], field: string, key: string,
                          value: Json): string[] | null {
    helpers.log.debug("Entering TokenEntries.replaced().");
    const text = value === null ? '' : TokenEntries.stored(value);
    let found = false;
    const after: string[] = [];
    before.forEach(function (one: string): void {
      const read = TokenEntries.read(one);
      // A value that is not ours goes with any write of the attribute.
      if (!read) {
        return;
      }
      if (String(read[field]) === key) {
        if (!found && text) {
          after.push(text);
        }
        found = true;
        return;
      }
      after.push(one);
    });
    if (!found && text) {
      after.push(text);
    }
    const same = after.length === before.length &&
      after.every(function (one: string, i: number): boolean {
        return one === before[i];
      });
    helpers.log.debug("Leaving TokenEntries.replaced(). " + !same);
    return same ? null : after;
  }

  // Writes the change onto a located person. `done`, `absent` or `failed`.
  private apply(found: Json, attribute: string, key: string,
                value: Json): string {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering TokenEntries.apply().");
    if (!found || !found.dn) {
      log.debug("Leaving TokenEntries.apply(). No entry here.");
      return 'absent';
    }
    const field = TokenEntries.check(attribute);
    const before = ((found.values || {})[attribute.toLowerCase()] || [])
      .map(String);
    const after = TokenEntries.replaced(before, field, key, value);
    if (!after) {
      log.debug("Leaving TokenEntries.apply(). In step.");
      return 'done';
    }
    let written = false;
    this.selfWrites += 1;
    try {
      written = this.directory !== null &&
        this.directory.write(String(found.dn), attribute, after) === true;
    } catch (e) {
      log.debug("Caught in TokenEntries.apply(): " + ((e && e.message) || e));
      written = false;
    } finally {
      this.selfWrites -= 1;
    }
    if (!written) {
      log.warn(codes.tag('STS-HWTOKEN-0015') + 'hardware tokens: ' +
               attribute + ' of ' + found.dn + ' could not be written for ' +
               key + '; the index row is marked pending and the entries ' +
               'job writes it again.');
    }
    log.debug("Leaving TokenEntries.apply(). " + written);
    return written ? 'done' : 'failed';
  }

  /**
   * Puts one token's value on a person's entry, or takes it off (`null`),
   * in the ambient realm, synchronously: the person a request is about is
   * held by then. `absent` is a person this directory does not hold.
   *
   * @param who - a username, a subject or a bare entryUUID
   * @param attribute - one of ATTRIBUTES
   * @param key - the token's key in that attribute
   * @param value - the value, or null to take it off
   * @returns `done`, `absent` or `failed`
   */
  project(who: string, attribute: string, key: string, value: Json): string {
    const { log } = this.deps;
    log.debug("Entering TokenEntries.project(). " + attribute);
    if (!this.directory || !who) {
      log.debug("Leaving TokenEntries.project(). " +
                (who ? 'No directory.' : 'Nobody.'));
      return who ? 'failed' : 'done';
    }
    let found: Json = null;
    try {
      found = this.directory.locate(String(who));
    } catch (e) {
      log.debug("Caught in TokenEntries.project(): " +
                ((e && e.message) || e));
      log.debug("Leaving TokenEntries.project(). Not read.");
      return 'failed';
    }
    const out = this.apply(found, attribute, String(key), value);
    log.debug("Leaving TokenEntries.project(). " + out);
    return out;
  }

  /**
   * `project()` off the event loop: the person is found asynchronously
   * first, for a background job.
   *
   * @param who - a username, a subject or a bare entryUUID
   * @param attribute - one of ATTRIBUTES
   * @param key - the token's key in that attribute
   * @param value - the value, or null to take it off
   * @returns a promise of `done`, `absent` or `failed`
   */
  async projectAsync(who: string, attribute: string, key: string,
                     value: Json): Promise<string> {
    const { log } = this.deps;
    log.debug("Entering TokenEntries.projectAsync(). " + attribute);
    if (!this.directory || !who) {
      log.debug("Leaving TokenEntries.projectAsync().");
      return who ? 'failed' : 'done';
    }
    let found: Json = null;
    try {
      found = await this.directory.locateAsync(String(who));
    } catch (e) {
      log.debug("Caught in TokenEntries.projectAsync(): " +
                ((e && e.message) || e));
      log.debug("Leaving TokenEntries.projectAsync(). Not read.");
      return 'failed';
    }
    const out = this.apply(found, attribute, String(key), value);
    log.debug("Leaving TokenEntries.projectAsync(). " + out);
    return out;
  }

  /**
   * A person's values of one attribute, read back.
   *
   * @param who - a username, a subject or a bare entryUUID
   * @param attribute - one of ATTRIBUTES
   * @returns the values, [] for nobody
   */
  valuesOf(who: string, attribute: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering TokenEntries.valuesOf().");
    TokenEntries.check(attribute);
    let found: Json = null;
    try {
      found = this.directory && who ? this.directory.locate(String(who))
                                    : null;
    } catch (e) {
      log.debug("Caught in TokenEntries.valuesOf(): " +
                ((e && e.message) || e));
      found = null;
    }
    const out = (((found && found.values) || {})[attribute.toLowerCase()] ||
                 []).map(TokenEntries.read).filter(Boolean);
    log.debug("Leaving TokenEntries.valuesOf(). " + out.length);
    return out;
  }

  /**
   * Every person holding one attribute, with its values read back: what a
   * rebuild of an index reads (header).
   *
   * @param attribute - one of ATTRIBUTES
   * @returns a promise of `[{ username, dn, values }]`
   */
  async holdersOf(attribute: string): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering TokenEntries.holdersOf().");
    TokenEntries.check(attribute);
    if (!this.directory) {
      log.debug("Leaving TokenEntries.holdersOf(). No directory.");
      return [];
    }
    const rows = await this.directory.holdersAsync(attribute);
    const out = (rows || []).map(function (row: Json): Json {
      return { username: String(row.username || row.id || ''),
               dn: String(row.dn || ''),
               values: (row.values || []).map(TokenEntries.read)
                 .filter(Boolean) };
    });
    log.debug("Leaving TokenEntries.holdersOf(). " + out.length);
    return out;
  }

  /**
   * One run of the entries job in one realm: the backfill once a process,
   * then every pending index row written again (header).
   *
   * @param realmId - the realm
   * @returns a promise of `{ ok, backfilled, pending }`
   */
  syncEntries(realmId: string): Promise<Json> {
    const { log, realms: r, errorCodes: codes } = this.deps;
    log.debug("Entering TokenEntries.syncEntries().");
    const id = String(realmId || '');
    const run = async (): Promise<Json> => {
      if (!this.directory) {
        log.debug("Leaving TokenEntries.syncEntries(). No directory.");
        return { ok: true, skipped: true };
      }
      const backfill = !this.backfilled[id];
      const out: Json = { ok: true, backfill: backfill, written: 0,
                          pending: 0 };
      try {
        for (const mod of this.deps.loadModules()) {
          const one = await mod.syncEntries({ backfill: backfill });
          out.written += Number((one && one.written) || 0);
          out.pending += Number((one && one.pending) || 0);
          out.ok = out.ok && !!(one && one.ok);
        }
      } catch (e) {
        log.error(codes.tag('STS-HWTOKEN-0016') + 'hardware tokens: the ' +
                  'entries job could not bring the entries of realm "' +
                  (id || 'default') + '" in step: ' +
                  ((e && e.message) || e));
        log.debug("Leaving TokenEntries.syncEntries(). Failed.");
        return codes.mark({ ok: false, errors: [
          'The tokens on entries could not be brought in step.'
        ] }, 'STS-HWTOKEN-0016');
      }
      if (backfill && out.ok) {
        this.backfilled[id] = true;
      }
      log.debug("Leaving TokenEntries.syncEntries(). " + out.written +
                " written, " + out.pending + " still pending.");
      return out;
    };
    return id === String(r.currentId() || '') ? run() : r.run(id, run);
  }

  /**
   * The rebuild (header): every index row rewritten from the entries.
   *
   * @param realmId - the realm
   * @returns a promise of `{ ok, rebuilt }`
   */
  rebuildIndexes(realmId: string): Promise<Json> {
    const { log, realms: r, errorCodes: codes } = this.deps;
    log.debug("Entering TokenEntries.rebuildIndexes().");
    const id = String(realmId || '');
    const run = async (): Promise<Json> => {
      const out: Json = { ok: true, rebuilt: 0 };
      try {
        for (const mod of this.deps.loadModules()) {
          const one = await mod.rebuildFromEntries();
          out.rebuilt += Number((one && one.rebuilt) || 0);
        }
      } catch (e) {
        log.error(codes.tag('STS-HWTOKEN-0016') + 'hardware tokens: the ' +
                  'indexes of realm "' + (id || 'default') + '" could not ' +
                  'be rebuilt from the entries: ' + ((e && e.message) || e));
        log.debug("Leaving TokenEntries.rebuildIndexes(). Failed.");
        return codes.mark({ ok: false, errors: [
          'The token indexes could not be rebuilt from the entries.'
        ] }, 'STS-HWTOKEN-0016');
      }
      log.debug("Leaving TokenEntries.rebuildIndexes(). " + out.rebuilt);
      return out;
    };
    return id === String(r.currentId() || '') ? run() : r.run(id, run);
  }

  /**
   * Registers the two jobs (header).
   *
   * @param schedulerInstance - the cluster scheduler
   * @returns true when registered, false when they already were
   */
  static installScheduler(schedulerInstance?: Json): boolean {
    helpers.log.debug("Entering TokenEntries.installScheduler().");
    const scheduler = schedulerInstance || require('../cluster/scheduler');
    if (scheduler.job(ENTRIES_JOB)) {
      helpers.log.debug("Leaving TokenEntries.installScheduler(). Already.");
      return false;
    }
    scheduler.register({
      id: ENTRIES_JOB, title: 'Hardware tokens on entries',
      describe: 'Writes onto their holders\' entries the hardware, OATH ' +
        'and YubiKey OTP tokens whose entry write did not happen, and on ' +
        'its first run in a process copies every token recorded before ' +
        'they were kept on entries onto its holder.',
      owner: 'common/token_entries.ts', kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return ENTRIES_EVERY_MS;
      },
      manual: true, timeoutS: 300,
      run: async function (ctx: Json): Promise<Json> {
        return slot.get().syncEntries(String((ctx && ctx.realm) || ''));
      }
    });
    scheduler.register({
      id: REBUILD_JOB, title: 'Hardware token indexes rebuilt',
      describe: 'Rewrites the hardware token register and the OATH and ' +
        'YubiKey OTP inventories from the tokens on people\'s entries, ' +
        'which are the master: run by hand after a restore or when an ' +
        'index disagrees with an entry.',
      owner: 'common/token_entries.ts', kind: 'cluster', scope: 'realm',
      manualOnly: true, manual: true, timeoutS: 900,
      run: async function (ctx: Json): Promise<Json> {
        return slot.get().rebuildIndexes(String((ctx && ctx.realm) || ''));
      }
    });
    helpers.log.debug("Leaving TokenEntries.installScheduler().");
    return true;
  }

  // THE MODULE WHOSE INDEX AN ATTRIBUTE IS.
  private moduleFor(attribute: string): Json {
    const { log } = this.deps;
    log.debug("Entering TokenEntries.moduleFor(). " + attribute);
    const mods = this.deps.loadModules();
    log.debug("Leaving TokenEntries.moduleFor().");
    return attribute === ATTRIBUTES.hardware ? mods[0]
      : (attribute === ATTRIBUTES.oath ? mods[1] : mods[2]);
  }

  /**
   * THE ENTRY OBSERVER'S HANDLER (header, `common/entry_observer.ts`): a
   * person's token attribute changed by a write of their entry. A write of
   * this library's own is ignored. Of any other door's, a value removed is
   * the token given up — the index row updated for this one entry by its
   * module (`entryRemoved()`: a hardware token's credentials of this person
   * dropped, an OATH or YubiKey OTP token retired) — and a value added or
   * changed is put back to what the index holds for this person, or taken
   * off, and audited: a serial is recorded only from attestation, and a
   * token is assigned only by its inventory. In a promise job, after the
   * write has returned.
   *
   * @param change - the observer's change
   * @returns the promise of the work, or null when there was none
   */
  entryChanged(change: Json): Promise<Json> | null {
    const { log } = this.deps;
    log.debug("Entering TokenEntries.entryChanged().");
    if (this.selfWrites > 0) {
      log.debug("Leaving TokenEntries.entryChanged(). Our own write.");
      return null;
    }
    const c = change || {};
    const attribute = String(c.attribute || '');
    const field = TokenEntries.check(attribute);
    const index = function byKey(values: string[]): Record<string, string> {
      log.debug("Entering byKey().");
      const out: Record<string, string> = {};
      (values || []).forEach(function (one: string): void {
        const read = TokenEntries.read(one);
        if (read && read[field]) {
          out[String(read[field])] = String(one);
        }
      });
      log.debug("Leaving byKey().");
      return out;
    };
    const before = index(c.before);
    const after = index(c.after);
    const removed = Object.keys(before).filter(function (k: string) {
      return after[k] === undefined;
    });
    const added = Object.keys(after).filter(function (k: string) {
      return before[k] !== after[k];
    });
    if (!removed.length && !added.length) {
      log.debug("Leaving TokenEntries.entryChanged(). Nothing moved.");
      return null;
    }
    const mod = this.moduleFor(attribute);
    const work = this.inRealm(String(c.realm || ''), async (): Promise<Json> => {
      let given = 0;
      let refused = 0;
      for (const key of removed) {
        const answer = await mod.entryRemoved(key, c);
        given += answer && answer.changed ? 1 : 0;
      }
      if (!c.deleted) {
        for (const key of added) {
          const wanted = await mod.entryValueFor(key, c);
          if (wanted && TokenEntries.stored(wanted) === after[key]) {
            continue;
          }
          refused += 1;
          this.project(String(c.subject || c.username || ''), attribute, key,
                       wanted || null);
          require('./audit').record({
            category: 'authentication', action: 'hardware-token.entry-refused',
            actor: String(c.actor || c.door || 'directory'),
            target: String(c.username || ''), outcome: 'refused',
            errorCode: 'STS-HWTOKEN-0017',
            summary: 'A token written onto the entry of ' +
                     String(c.username || '') + ' (' + attribute + ') was ' +
                     (wanted ? 'put back as recorded' : 'taken off') +
                     ': a token is recorded only from attestation or an ' +
                     'assignment',
            detail: { key: key, door: String(c.door || '') }
          });
        }
      }
      if (refused) {
        log.warn(this.deps.errorCodes.tag('STS-HWTOKEN-0017') + 'hardware ' +
                 'tokens: ' + refused + ' ' + attribute + ' value(s) written ' +
                 'onto ' + c.dn + ' were not what was recorded; put back.');
      }
      return { given: given, refused: refused };
    }).catch((e: Json): Json => {
      log.error(this.deps.errorCodes.tag('STS-HWTOKEN-0016') + 'hardware ' +
                'tokens: a write of ' + String(c.dn || '') + ' could not be ' +
                'applied to the index: ' + ((e && e.message) || e));
      return { given: 0, refused: 0, failed: true };
    });
    log.debug("Leaving TokenEntries.entryChanged(). " + removed.length +
              " removed, " + added.length + " added.");
    return work;
  }

  // Runs `fn` in a realm, in a promise job.
  private inRealm<T>(realmId: string, fn: () => Promise<T>): Promise<T> {
    const { log, realms: r } = this.deps;
    log.debug("Entering TokenEntries.inRealm().");
    log.debug("Leaving TokenEntries.inRealm().");
    return Promise.resolve().then(function (): Promise<T> {
      return realmId === String(r.currentId() || '') ? fn()
                                                     : r.run(realmId, fn);
    });
  }

  /**
   * Forgets the backfill marks; for tests only.
   */
  forgetForTests(): void {
    this.deps.log.debug("Entering TokenEntries.forgetForTests().");
    this.backfilled = {};
    this.deps.log.debug("Leaving TokenEntries.forgetForTests().");
  }
}

const slot = new InstanceSlot<TokenEntries>(
  'common/token_entries',
  () => new TokenEntries(TokenEntries.defaultDeps()),
  // THE OBSERVER'S HANDLERS (header): the one mechanism every credential
  // kind shares, `ssh_issued.ts`'s and `openpgp_keys.ts`'s beside these.
  function (instance: TokenEntries): void {
    ATTRIBUTE_NAMES.forEach(function (attribute: string): void {
      entryObserver.register(attribute, {
        changed: function (change: Json): void {
          instance.entryChanged(change);
        }
      });
    });
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * A person's tokens on their entry (#2051). A library (rule 3).
 * @namespace
 */
export = {
  TokenEntries: TokenEntries,
  ATTRIBUTES: ATTRIBUTES,
  stored: TokenEntries.stored,
  read: TokenEntries.read,
  installScheduler: TokenEntries.installScheduler,
  installInstance: (instance: TokenEntries): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  setDirectory: slot.forward('setDirectory'),
  installedDirectory: slot.forward('installedDirectory'),
  project: slot.forward('project'),
  projectAsync: slot.forward('projectAsync'),
  valuesOf: slot.forward('valuesOf'),
  holdersOf: slot.forward('holdersOf'),
  syncEntries: slot.forward('syncEntries'),
  rebuildIndexes: slot.forward('rebuildIndexes'),
  entryChanged: slot.forward('entryChanged'),
  forgetForTests: slot.forward('forgetForTests')
};
