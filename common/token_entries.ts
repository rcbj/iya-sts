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
// **THE ENTRY IS THE MASTER; THE STORES ARE INDEXES.** Each module writes
// the holder's entry FIRST and then its store (`hardware_tokens.register`,
// `oath_tokens.inventory`, `yubiotp.inventory` and `yubiotp.publicIds`),
// which stay because the questions that need them are not a person's: a
// credential's token at a sign-in (`c:<kind>:<ref>`), a serial typed at a
// claim, a YK-VAL public identity, the console's paged lists, a lost token's
// retirement. On a conflict the entry wins: the manual job
// `hardware-tokens.rebuild-index` rewrites every index row from the
// entries holding these attributes (each module's `rebuildFromEntries()`),
// so an index can be rebuilt whole from the directory. It is manual,
// because the holders of an attribute no holder index names are a walk of
// the realm's people (`holdersAsync()`), which no schedule should repeat.
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
      if (read && String(read[field]) === key) {
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
    try {
      written = this.directory !== null &&
        this.directory.write(String(found.dn), attribute, after) === true;
    } catch (e) {
      log.debug("Caught in TokenEntries.apply(): " + ((e && e.message) || e));
      written = false;
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
  null,
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
  forgetForTests: slot.forward('forgetForTests')
};
