// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: yubiotp_store.ts
//
// ===========================================================================
// YUBICO OTP'S INVENTORY, PUBLIC IDENTITIES AND YK-VAL CLIENTS (#1955 P5).
//
// An administrator uploads a CSV — serial, modhex public identity, hex
// private identity, hex AES key — and each row is kept here UNASSIGNED,
// keyed by serial. A token then reaches a person because an administrator
// assigns it, or because the person claims it, in either case by presenting
// one OTP the token types. The secret moves onto the person's entry
// (`credentials.installImportedYubi()`), sealed, and the inventory row drops
// it. The public identity is indexed beside that, because YK-VAL names an
// OTP and no person: `/wsapi/2.0/verify` looks the prefix up here.
//
// A secret the portal minted is NOT in this inventory. It has no serial the
// register could key, the same way a QR-enrolled HOTP secret has none. Its
// public identity is still indexed, or YK-VAL could not find it.
//
// **A CSV IS PLAINTEXT.** Product mode refuses one unless
// `yubiotp.allowPlaintextImport` is on (`mode.refusesPlaintextYubiCsv()`).
// Development mode accepts one. The file's secrets are sealed as they are
// stored and are never written to an audit row or a log line.
//
// **THE LOST KEY.** This module registers the `yubico-otp` retirer. A token
// reported lost has its credential removed when it is still that serial's,
// its public identity dropped, and its inventory row retired. A retired
// token is not assigned again.
//
// **YK-VAL CLIENTS** are operator configuration: an id and an HMAC-SHA1 key,
// sealed, the same in every cell. **A NONCE IS SPENT BY A CLUSTER CLAIM**
// (`cluster/cluster_claims`, scope `yubiotp.ykval-nonce`, five minutes),
// since the #1955 review: a compare-and-set in the store, so two nodes or
// two workers given one request cannot both accept it. It was a
// read-then-write of a per-process map until then, and a replay sent to a
// second process was answered OK. The claim's own purge job drops the
// spent ones. `yubiotp.nonces` is no longer written; the cluster job
// `yubiotp.nonce-sweep` — a per-REALM job (`scope: 'realm'`), not one in
// `GLOBAL_JOBS` as this header said until the review — still drops the
// rows a service before the review wrote there, the expired ones and the
// oldest past ten thousand, so an upgraded store drains.
//
// No table is added. Each store is a `realms.map()` at its declaration.
// A LIBRARY (rule 3): it registers no route.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import realms = require('./realms');
import audit = require('./audit');
import errorCodes = require('./error_codes');
import cacheRegistry = require('./cache_registry');

type Json = any;

const NONCE_MS = 5 * 60 * 1000;
const NONCE_CAP = 10000;
const NONCE_JOB = 'yubiotp.nonce-sweep';
// The cluster claim a YK-VAL nonce is spent under (header).
const NONCE_SCOPE = 'yubiotp.ykval-nonce';

const inventory = realms.map({
  persist: 'yubiotp.inventory',
  onDemand: { maxEntries: 5000 },
  indexBy: function (row: Json): string[] {
    const out: string[] = [];
    if (row && row.publicId) {
      out.push('p:' + String(row.publicId));
    }
    if (row && row.status) {
      out.push('st:' + String(row.status));
    }
    return out;
  },
  sortBy: function (row: Json): number | null {
    const at = row ? Date.parse(String(row.importedAt || '')) : NaN;
    return at > 0 ? at : null;
  }
});

const publicIds = realms.map({
  persist: 'yubiotp.publicIds',
  onDemand: { maxEntries: 20000 }
});

const clients = realms.map({
  persist: 'yubiotp.ykvalClients',
  onDemand: { maxEntries: 1000 }
});

const nonces = realms.map({
  persist: 'yubiotp.nonces',
  onDemand: { maxEntries: NONCE_CAP }
});

cacheRegistry.register({
  name: 'yubiotp.inventory',
  title: 'Yubico OTP inventory',
  description: 'One row per YubiKey OTP an administrator imported from a ' +
    'CSV, keyed by serial: unassigned (its AES key sealed), assigned to a ' +
    'person (the secret dropped, now on their entry) or retired.',
  owner: 'common/yubiotp_store.ts',
  scope: 'realm',
  kind: 'cache',
  persisted: true,
  settings: ['yubiotp.offered', 'yubiotp.allowPlaintextImport'],
  maxEntries: function (): number {
    return 5000;
  },
  bound: 'Enforced: the rows a process holds are a cache of 5,000 per ' +
    'realm, the oldest dropped and read from the store again when next ' +
    'asked.',
  lifetime: function (): string {
    return 'Until an unassigned token is removed; an assigned or retired ' +
      'token is kept.';
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, inventory,
      function (row: Json, key: unknown): object {
        return { key: String(key) + ' (' + String((row && row.status) ||
                      '?') + ')', basis: 'none' };
      });
  }
});

interface YubiStoreDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  realms: typeof realms;
  now: () => number;
  loadCredentials: () => Json;
  loadHardwareTokens: () => Json;
  loadYubi: () => Json;
  loadKeystore: () => Json;
  loadClaims: () => Json;
}

/**
 * The Yubico OTP inventory, the public-identity index, the YK-VAL clients
 * and the nonce map (#1955 P5).
 */
class YubiOtpStore {
  static readonly NONCE_JOB = NONCE_JOB;
  static readonly NONCE_MS = NONCE_MS;

  /**
   * Builds the store over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: YubiStoreDeps) {
    deps.log.debug("Entering YubiOtpStore.constructor().");
    deps.log.debug("Leaving YubiOtpStore.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): YubiStoreDeps {
    helpers.log.debug("Entering YubiOtpStore.defaultDeps().");
    helpers.log.debug("Leaving YubiOtpStore.defaultDeps().");
    return {
      log: helpers.log, helpers: helpers, audit: audit,
      errorCodes: errorCodes, realms: realms, now: Date.now,
      loadCredentials: function (): Json {
        return require('./credentials');
      },
      loadHardwareTokens: function (): Json {
        return require('./hardware_tokens');
      },
      loadYubi: function (): Json {
        return require('./yubiotp');
      },
      loadKeystore: function (): Json {
        return require('./keystore');
      },
      loadClaims: function (): Json {
        return require('../cluster/cluster_claims');
      }
    };
  }

  /**
   * Registers the `yubico-otp` retirer. The nonce sweep is registered later,
   * once the scheduler is in hand (`installScheduler()`).
   *
   * @param instance - the installed instance
   */
  static wire(instance: YubiOtpStore): void {
    helpers.log.debug("Entering YubiOtpStore.wire().");
    instance.installRetirer();
    helpers.log.debug("Leaving YubiOtpStore.wire().");
  }

  /**
   * Registers `yubiotp.nonce-sweep` on the scheduler already loaded.
   *
   * @param schedulerInstance - the scheduler; the service's where omitted
   * @returns true when this call registered the job
   */
  static installScheduler(schedulerInstance?: Json): boolean {
    helpers.log.debug("Entering YubiOtpStore.installScheduler().");
    const scheduler = schedulerInstance || require('../cluster/scheduler');
    if (scheduler.job(NONCE_JOB)) {
      helpers.log.debug("Leaving YubiOtpStore.installScheduler(). Already.");
      return false;
    }
    scheduler.register({
      id: NONCE_JOB,
      title: 'Yubico OTP nonce sweep',
      describe: 'Drops YK-VAL nonces older than five minutes, and the ' +
        'oldest past ten thousand, so the nonce map does not grow.',
      owner: 'common/yubiotp_store.ts',
      kind: 'cluster',
      scope: 'realm',
      everyMs: function (): number {
        return 60000;
      },
      manual: true,
      timeoutS: 60,
      run: function (): Promise<Json> {
        return Promise.resolve(require('./yubiotp_store').sweepNonces());
      }
    });
    helpers.log.debug("Leaving YubiOtpStore.installScheduler().");
    return true;
  }

  private installRetirer(): void {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.installRetirer().");
    const self = this;
    try {
      this.deps.loadHardwareTokens().registerRetirer('yubico-otp', {
        label: 'Yubico OTP secret',
        retire: function (token: Json, c: Json, ctx: Json): Promise<Json> {
          return self.retire(token, c, ctx);
        }
      });
    } catch (e) {
      log.error(this.deps.errorCodes.tag('STS-YUBIOTP-0028') +
                'yubiotp: the retirer could not be registered: ' +
                ((e && e.message) || e));
    }
    log.debug("Leaving YubiOtpStore.installRetirer().");
  }

  private nowIso(): string {
    return new Date(this.deps.now()).toISOString();
  }

  private refuse(code: string, why: string, extra?: Json): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering YubiOtpStore.refuse(). " + code);
    log.debug("Leaving YubiOtpStore.refuse().");
    return codes.mark(Object.assign({ ok: false, error: why, errors: [why] },
                                    extra || {}), code);
  }

  private recordAudit(action: string, actor: string, target: string,
                      summary: string, detail: Json, code?: string): void {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.recordAudit().");
    this.deps.audit.audit(Object.assign({
      action: action, actor: String(actor || ''),
      target: String(target || ''), outcome: code ? 'failure' : 'success',
      summary: summary, detail: detail || {}
    }, code ? { errorCode: code } : {}));
    log.debug("Leaving YubiOtpStore.recordAudit().");
  }

  private seal(json: string): { secret: string; sealed: boolean } | null {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.seal().");
    const keystore = this.deps.loadKeystore();
    if (!keystore.persists()) {
      log.debug("Leaving YubiOtpStore.seal(). In the clear.");
      return { secret: json, sealed: false };
    }
    const sealed = keystore.seal(json, 'yubiotp-secret', 'cell');
    log.debug("Leaving YubiOtpStore.seal(). " + !!sealed);
    return sealed ? { secret: sealed, sealed: true } : null;
  }

  private openSealed(secret: string, sealed: boolean): string {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.openSealed().");
    if (!secret) {
      log.debug("Leaving YubiOtpStore.openSealed(). None.");
      return '';
    }
    if (!sealed) {
      log.debug("Leaving YubiOtpStore.openSealed(). Clear.");
      return secret;
    }
    const opened = this.deps.loadKeystore().open(secret, 'yubiotp-secret');
    log.debug("Leaving YubiOtpStore.openSealed(). " + !!opened);
    return opened || '';
  }

  /**
   * The person a public identity is enrolled for, if any.
   *
   * @param publicId - the modhex prefix
   * @returns `{ username, credentialId, serial }`, or null
   */
  lookupPublicId(publicId: string): Json | null {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.lookupPublicId().");
    const row = publicIds.get(String(publicId || '')) || null;
    log.debug("Leaving YubiOtpStore.lookupPublicId(). " + !!row);
    return row;
  }

  /**
   * Records a public identity. Refuses one already held by somebody else.
   *
   * @param publicId - the modhex prefix
   * @param spec - `{ username, credentialId, serial }`
   * @returns `{ ok }`, or a refusal
   */
  indexPublicId(publicId: string, spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.indexPublicId().");
    const id = String(publicId || '');
    const held = publicIds.get(id);
    const username = String((spec && spec.username) || '');
    if (held && held.username && held.username !== username) {
      log.debug("Leaving YubiOtpStore.indexPublicId(). Taken.");
      return this.refuse('STS-YUBIOTP-0026',
        'That YubiKey public identity is already enrolled for somebody ' +
        'else.');
    }
    publicIds.set(id, {
      username: username,
      credentialId: String((spec && spec.credentialId) || ''),
      serial: String((spec && spec.serial) || '')
    });
    log.debug("Leaving YubiOtpStore.indexPublicId(). Indexed.");
    return { ok: true };
  }

  /**
   * Drops a public identity when it still names this credential.
   *
   * @param publicId - the modhex prefix
   * @param credentialId - the credential, or '' for any
   */
  dropPublicId(publicId: string, credentialId?: string): void {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.dropPublicId().");
    const id = String(publicId || '');
    const held = id ? publicIds.get(id) : null;
    if (held && (!credentialId || held.credentialId === credentialId)) {
      publicIds.delete(id);
    }
    log.debug("Leaving YubiOtpStore.dropPublicId().");
  }

  /**
   * Imports a plaintext CSV. Product mode refuses it unless the setting
   * allows one.
   *
   * @param spec - `{ csv, actor, via }`
   * @returns `{ ok, imported, skipped }`, or a refusal
   */
  importCsv(spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.importCsv().");
    const s = spec || {};
    const yubi = this.deps.loadYubi();
    if (yubi.refusesPlaintextCsv()) {
      this.recordAudit('yubiotp.import', s.actor, '',
        'A plaintext YubiKey CSV was refused', {}, 'STS-YUBIOTP-0019');
      log.debug("Leaving YubiOtpStore.importCsv(). Plaintext refused.");
      return this.refuse('STS-YUBIOTP-0019',
        'A CSV of YubiKey secrets in the clear is refused in product ' +
        'mode unless yubiotp.allowPlaintextImport is on.');
    }
    const parsed = yubi.parseCsv(s.csv);
    if (!parsed.rows.length) {
      log.debug("Leaving YubiOtpStore.importCsv(). No rows.");
      return this.refuse('STS-YUBIOTP-0020',
        parsed.errors[0] || 'The CSV has no YubiKey rows.',
        { errors: parsed.errors.length ? parsed.errors
          : ['The CSV has no YubiKey rows.'] });
    }
    const imported: Json[] = [];
    const skipped: Json[] = parsed.errors.map(function (why: string) {
      return { serial: '', why: why };
    });
    parsed.rows.forEach((row: Json) => {
      if (inventory.get(row.serial)) {
        skipped.push({ serial: row.serial, why: 'That serial is already ' +
          'in this realm\'s inventory.' });
        return;
      }
      if (publicIds.get(row.publicId) ||
          inventory.lookup('p:' + row.publicId).length) {
        skipped.push({ serial: row.serial, why: 'That public identity is ' +
          'already in this realm.' });
        return;
      }
      const sealed = this.seal(JSON.stringify({ k: row.k, p: row.p }));
      if (!sealed) {
        skipped.push({ serial: row.serial,
                       why: 'The secret could not be sealed.' });
        return;
      }
      inventory.set(row.serial, {
        serial: row.serial, publicId: row.publicId,
        secret: sealed.secret, sealed: sealed.sealed,
        status: 'unassigned', holder: '', credentialId: '',
        importedAt: this.nowIso()
      });
      imported.push({ serial: row.serial, publicId: row.publicId });
    });
    this.recordAudit('yubiotp.import', s.actor, '',
      imported.length + ' YubiKey OTP row(s) imported, ' + skipped.length +
      ' skipped', { imported: imported.length, skipped: skipped.length });
    log.info('yubiotp: imported ' + imported.length + ' row(s), skipped ' +
             skipped.length + '.');
    log.debug("Leaving YubiOtpStore.importCsv().");
    return { ok: true, imported: imported, skipped: skipped };
  }

  private secretOf(row: Json): Json | null {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.secretOf().");
    const raw = this.openSealed(row && row.secret, !!(row && row.sealed));
    if (!raw) {
      log.debug("Leaving YubiOtpStore.secretOf(). None.");
      return null;
    }
    let parsed: Json = null;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      log.debug("Caught in YubiOtpStore.secretOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving YubiOtpStore.secretOf(). Not JSON.");
      return null;
    }
    parsed.publicId = row.publicId;
    log.debug("Leaving YubiOtpStore.secretOf().");
    return parsed;
  }

  /**
   * Assigns an unassigned token to a person, spending the OTP they present.
   *
   * @param spec - `{ serial, username, otp, actor, via }`
   * @returns a promise of `{ ok, token }`, or a refusal
   */
  async assign(spec: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.assign().");
    const s = spec || {};
    const serial = String(s.serial || '').trim();
    const username = String(s.username || '').trim();
    const yubi = this.deps.loadYubi();
    if (!yubi.offered()) {
      log.debug("Leaving YubiOtpStore.assign(). Off.");
      return this.refuse('STS-YUBIOTP-0007',
        'YubiKey OTP enrolment is turned off on this service ' +
        '(yubiotp.offered, or the authentication policy).');
    }
    const row = inventory.get(serial) || null;
    if (!row) {
      log.debug("Leaving YubiOtpStore.assign(). No token.");
      return this.refuse('STS-YUBIOTP-0023',
        'No YubiKey OTP with that serial is in this realm\'s inventory.');
    }
    if (row.status !== 'unassigned') {
      log.debug("Leaving YubiOtpStore.assign(). Not unassigned.");
      return this.refuse('STS-YUBIOTP-0022',
        'That YubiKey OTP is already ' + row.status + '.');
    }
    const secret = this.secretOf(row);
    if (!secret) {
      log.debug("Leaving YubiOtpStore.assign(). Secret.");
      return this.refuse('STS-YUBIOTP-0021',
        'That token\'s secret cannot be read by this service.');
    }
    const opened = yubi.open(secret, s.otp);
    if (!opened.ok) {
      log.debug("Leaving YubiOtpStore.assign(). OTP.");
      return opened;
    }
    const installed = await this.deps.loadCredentials().installImportedYubi(
      username, {
        serial: serial, publicId: row.publicId, k: secret.k, p: secret.p,
        composite: opened.fields.composite, use: opened.fields.use,
        session: opened.fields.session });
    if (!installed || !installed.ok) {
      log.debug("Leaving YubiOtpStore.assign(). Not installed.");
      return installed;
    }
    const recorded = this.deps.loadHardwareTokens().recordAttested({
      username: username, vendor: 'Yubico', serial: serial,
      credential: { kind: 'yubico-otp', ref: installed.id,
                    label: 'Yubico OTP' },
      evidence: { source: 'yubiotp-import',
                  detail: 'imported ' + String(row.importedAt || '') },
      actor: s.actor || username, via: s.via || '' });
    if (!recorded || !recorded.ok) {
      log.warn('yubiotp: token ' + serial + ' was assigned to ' + username +
               ' and the hardware token register did not record it.');
    }
    inventory.set(serial, Object.assign({}, row, {
      status: 'assigned', holder: username, secret: '', sealed: false,
      credentialId: installed.id, assignedAt: this.nowIso() }));
    const verb = s.via === 'claim' ? 'claimed by ' : 'assigned to ';
    this.recordAudit(s.via === 'claim' ? 'yubiotp.claim' : 'yubiotp.assign',
      s.actor || username, username,
      'YubiKey OTP ' + serial + ' was ' + verb + username,
      { serial: serial });
    log.info('yubiotp: ' + serial + ' assigned to ' + username + '.');
    log.debug("Leaving YubiOtpStore.assign(). Assigned.");
    return { ok: true, token: { serial: serial, publicId: row.publicId,
                                holder: username, status: 'assigned' } };
  }

  /**
   * A person claims an unassigned token by its serial and one OTP.
   *
   * @param spec - `{ username, serial, otp }`
   * @returns a promise of `{ ok, token }`, or a refusal
   */
  async claim(spec: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.claim().");
    const s = spec || {};
    const out = await this.assign({
      serial: s.serial, username: s.username, otp: s.otp,
      actor: s.username, via: 'claim' });
    if (!out.ok && out.reason !== 'mismatch' && out.reason !== 'shape') {
      log.debug("Leaving YubiOtpStore.claim(). Refused as itself.");
      return out;
    }
    if (!out.ok) {
      this.recordAudit('yubiotp.claim', s.username, s.username,
        'A claim of a YubiKey OTP was refused',
        { serial: String(s.serial || '') }, 'STS-YUBIOTP-0024');
      log.debug("Leaving YubiOtpStore.claim(). No match.");
      return this.refuse('STS-YUBIOTP-0024',
        'No token waiting to be claimed has that serial and types that ' +
        'OTP. Check the serial and touch the key again.');
    }
    log.debug("Leaving YubiOtpStore.claim(). Claimed.");
    return out;
  }

  /**
   * Removes an unassigned token. An assigned one is retired by reporting
   * the hardware token lost.
   *
   * @param spec - `{ serial, actor }`
   * @returns `{ ok, serial }`, or a refusal
   */
  remove(spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.remove().");
    const serial = String((spec && spec.serial) || '').trim();
    const row = inventory.get(serial) || null;
    if (!row) {
      log.debug("Leaving YubiOtpStore.remove(). None.");
      return this.refuse('STS-YUBIOTP-0023',
        'No YubiKey OTP with that serial is in this realm\'s inventory.');
    }
    if (row.status === 'assigned') {
      log.debug("Leaving YubiOtpStore.remove(). Assigned.");
      return this.refuse('STS-YUBIOTP-0022',
        'That YubiKey OTP is assigned. Report the token lost to retire it.');
    }
    inventory.delete(serial);
    this.recordAudit('yubiotp.remove', spec && spec.actor, '',
      'YubiKey OTP ' + serial + ' was removed from the inventory',
      { serial: serial });
    log.debug("Leaving YubiOtpStore.remove(). Removed.");
    return { ok: true, serial: serial };
  }

  /**
   * The lost-key retirer: drops the credential when it is still this
   * serial's, and retires the inventory row.
   *
   * @param token - the register's token
   * @param credential - the credential row
   * @param ctx - who asked
   * @returns `{ ok }`
   */
  async retire(token: Json, credential: Json, ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.retire().");
    const serial = String((token && token.serial) || '');
    const username = String((ctx && ctx.username) || '');
    try {
      const removed = this.deps.loadCredentials().removeYubiOtp(username, {
        onlySerial: serial });
      if (removed && removed.publicId) {
        this.dropPublicId(removed.publicId, removed.id);
      }
    } catch (e) {
      log.error(this.deps.errorCodes.tag('STS-YUBIOTP-0028') +
                'yubiotp: retiring ' + serial + ' threw: ' +
                ((e && e.message) || e));
      log.debug("Leaving YubiOtpStore.retire(). It threw.");
      return this.refuse('STS-YUBIOTP-0028',
        'The YubiKey OTP credential could not be retired.');
    }
    const row = inventory.get(serial);
    if (row) {
      inventory.set(serial, Object.assign({}, row, {
        status: 'retired', secret: '', sealed: false }));
    }
    log.debug("Leaving YubiOtpStore.retire().");
    return { ok: true };
  }

  /**
   * Creates a YK-VAL client and returns its HMAC key once.
   *
   * @param spec - `{ id, actor }`
   * @returns `{ ok, id, key }`, or a refusal
   */
  addClient(spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.addClient().");
    const id = String((spec && spec.id) || '').trim();
    if (!/^[0-9]{1,16}$/.test(id)) {
      log.debug("Leaving YubiOtpStore.addClient(). Id.");
      return this.refuse('STS-YUBIOTP-0029',
        'A YK-VAL client id is 1 to 16 digits.');
    }
    if (clients.get(id)) {
      log.debug("Leaving YubiOtpStore.addClient(). Exists.");
      return this.refuse('STS-YUBIOTP-0029',
        'A YK-VAL client with that id already exists.');
    }
    const key = require('./crypto').randomBytes(20).toString('base64');
    const sealed = this.seal(key);
    if (!sealed) {
      log.debug("Leaving YubiOtpStore.addClient(). Seal.");
      return this.refuse('STS-YUBIOTP-0009',
        'The client key could not be sealed, so the client was not kept.');
    }
    clients.set(id, { id: id, secret: sealed.secret, sealed: sealed.sealed,
                      createdAt: this.nowIso() });
    this.recordAudit('yubiotp.client-add', spec && spec.actor, id,
      'YK-VAL client ' + id + ' was created', { id: id });
    log.debug("Leaving YubiOtpStore.addClient(). Created.");
    return { ok: true, id: id, key: key };
  }

  /**
   * The client's HMAC key, opened. Empty when there is no such client.
   *
   * @param id - the client id
   * @returns the base64 key, or ''
   */
  clientKey(id: string): string {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.clientKey().");
    const row = clients.get(String(id || ''));
    if (!row) {
      log.debug("Leaving YubiOtpStore.clientKey(). None.");
      return '';
    }
    const key = this.openSealed(row.secret, !!row.sealed);
    log.debug("Leaving YubiOtpStore.clientKey(). " + !!key);
    return key;
  }

  /**
   * Removes a YK-VAL client.
   *
   * @param spec - `{ id, actor }`
   * @returns `{ ok }`, or a refusal
   */
  removeClient(spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.removeClient().");
    const id = String((spec && spec.id) || '');
    if (!clients.get(id)) {
      log.debug("Leaving YubiOtpStore.removeClient(). None.");
      return this.refuse('STS-YUBIOTP-0015', 'No YK-VAL client has that id.');
    }
    clients.delete(id);
    this.recordAudit('yubiotp.client-remove', spec && spec.actor, id,
      'YK-VAL client ' + id + ' was removed', { id: id });
    log.debug("Leaving YubiOtpStore.removeClient().");
    return { ok: true, id: id };
  }

  /**
   * Spends a nonce for the whole cluster (header). A repeat inside five
   * minutes is a replay; a store that cannot say is a refusal too.
   *
   * @param clientId - the client
   * @param nonce - the nonce
   * @returns a promise of `{ ok: true }`, or a refusal with `reason`
   *   `replay` or `store`
   */
  async rememberNonceAsync(clientId: string, nonce: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering YubiOtpStore.rememberNonceAsync().");
    const key = String(clientId) + '\n' + String(nonce);
    // A nonce a service before the review remembered in the map is still a
    // replay until it would have expired.
    const held = nonces.get(key);
    if (held && (this.deps.now() - Number(held.at || 0)) < NONCE_MS) {
      log.debug("Leaving YubiOtpStore.rememberNonceAsync(). Replay (map).");
      return this.refuse('STS-YUBIOTP-0016', 'That nonce was used recently.',
                         { reason: 'replay' });
    }
    const spent = await this.deps.loadClaims().claim({
      scope: NONCE_SCOPE, value: key, ttlMs: NONCE_MS });
    if (spent && spent.ok) {
      log.debug("Leaving YubiOtpStore.rememberNonceAsync(). Spent.");
      return { ok: true };
    }
    if (spent && spent.reason === 'used') {
      log.debug("Leaving YubiOtpStore.rememberNonceAsync(). Replay.");
      return this.refuse('STS-YUBIOTP-0016', 'That nonce was used recently.',
                         { reason: 'replay' });
    }
    log.error(this.deps.errorCodes.tag('STS-YUBIOTP-0031') + 'yubiotp: a ' +
              'YK-VAL nonce could not be proved unused: ' +
              String((spent && spent.why) || 'no answer'));
    log.debug("Leaving YubiOtpStore.rememberNonceAsync(). No store.");
    return this.refuse('STS-YUBIOTP-0031', 'The nonce could not be proved ' +
                       'unused just now.', { reason: 'store' });
  }

  /**
   * Drops expired nonces, and the oldest past the cap. Does not delete
   * during the walk.
   *
   * @returns `{ ok, removed }`
   */
  sweepNonces(): Json {
    const { log, realms: r } = this.deps;
    log.debug("Entering YubiOtpStore.sweepNonces().");
    const now = this.deps.now();
    const expired: string[] = [];
    const live: Array<{ key: string; at: number }> = [];
    nonces.scan(function (row: Json, key: unknown): void {
      const at = Number(row && row.at || 0);
      const id = String(key);
      if (!at || (now - at) >= NONCE_MS) {
        expired.push(id);
      } else {
        live.push({ key: id, at: at });
      }
    });
    expired.forEach(function (key) {
      nonces.delete(key);
    });
    let trimmed = 0;
    if (live.length > NONCE_CAP) {
      live.sort(function (a, b) {
        return a.at - b.at;
      });
      live.slice(0, live.length - NONCE_CAP).forEach(function (one) {
        nonces.delete(one.key);
        trimmed += 1;
      });
    }
    log.debug("Leaving YubiOtpStore.sweepNonces(). " +
              (expired.length + trimmed) + " removed. Realm " +
              r.currentId() + ".");
    return { ok: true, removed: expired.length + trimmed };
  }
}

const slot = new InstanceSlot<YubiOtpStore>(
  'common/yubiotp_store',
  () => new YubiOtpStore(YubiOtpStore.defaultDeps()),
  YubiOtpStore.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The Yubico OTP inventory and YK-VAL clients (#1955 P5).
 * @namespace
 */
export = {
  YubiOtpStore: YubiOtpStore,
  installInstance: (instance: YubiOtpStore): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  installScheduler: (scheduler?: Json): boolean =>
    YubiOtpStore.installScheduler(scheduler),
  lookupPublicId: slot.forward('lookupPublicId'),
  indexPublicId: slot.forward('indexPublicId'),
  dropPublicId: slot.forward('dropPublicId'),
  importCsv: slot.forward('importCsv'),
  assign: slot.forward('assign'),
  claim: slot.forward('claim'),
  remove: slot.forward('remove'),
  addClient: slot.forward('addClient'),
  clientKey: slot.forward('clientKey'),
  removeClient: slot.forward('removeClient'),
  rememberNonceAsync: slot.forward('rememberNonceAsync'),
  sweepNonces: slot.forward('sweepNonces')
};
