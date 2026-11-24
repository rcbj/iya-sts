// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oath_tokens.ts
//
// ===========================================================================
// PRE-PROVISIONED OATH TOKENS: THE INVENTORY (#1955 P4, design S3 and X3).
//
// An enterprise that buys hardware OATH tokens gets their secrets from the
// vendor in a PSKC seed file (RFC 6030, `common/pskc.ts`). An administrator
// uploads it on Directory → Hardware tokens (or `POST /admin-api/
// hardware-tokens/import-pskc`, rule 7) with the file's pre-shared key or
// password, and every HOTP or TOTP key in it is kept here, UNASSIGNED, keyed
// by `<vendor>/<serial>/<key id>` — the device serial the vendor's
// DeviceInfo names, which is what is printed on the token. A token then
// reaches a person one of two ways:
//
//   * an ADMINISTRATOR ASSIGNS it by serial to a named person; or
//   * the PERSON CLAIMS it on the portal (`/portal/tokens`) by typing the
//     serial on the back of the token they were handed AND a code it shows
//     now, which proves they hold that token and not merely know its
//     number. A claim spends that code.
//
// Either way the secret becomes the person's credential of the token's kind
// (`credentials.installImportedOath()`: an HOTP token is their
// `stsHotpCredential`, a TOTP token their authenticator), the token is
// recorded in the hardware token register with evidence `pskc-import`
// (`hardware_tokens.recordAttested()`), and the inventory row keeps the
// token's description and drops its secret — the person's entry holds it
// now, sealed, and nothing else should.
//
// **WHY AN IMPORTED TOKEN MAY EARN `hwk` AND A QR-ENROLLED SECRET NEVER
// DOES (X3).** A secret this service minted and showed in a QR code has been
// on a screen, in a camera, perhaps in a phone backup: nothing says where it
// lives now. A vendor's seeded token's secret was generated for the device
// and existed only inside it and in the vendor's encrypted file, which this
// service opened with a key given with the upload and kept nowhere. That is
// as good as the evidence a FIDO attestation gives, and only while the
// register holds the token ACTIVE: a token reported lost proves nothing.
// `credentials.oathHardware()` asks `hardware_tokens.evidenceFor()` at each
// sign-in, and `authn.ts`'s `finishTotp()` puts `hwk` beside `otp`. Never
// `phr`: a typed code is phishable.
//
// **THE LOST KEY (X2).** This module registers the `hotp` and `totp`
// RETIRERS with the register (`registerRetirer()`, rule 3e's hook): a token
// reported lost has its credential removed from the person's entry (only if
// it is still that token's — a person who replaced it since keeps the
// replacement) and its inventory row marked retired. A retired token is not
// assigned again: its secret may be with whoever found it.
//
// **WHERE IT IS KEPT.** A per-realm store at its declaration
// (`realms.map()`, `persist: 'oath_tokens.inventory'`), cell tier
// (`persistence/tiers.js`), on demand with an index by serial (`s:`), by
// holder (`h:`) and by status (`st:`), sealed in `sts_minted` like every
// minted row — and the secret of an unassigned token sealed AGAIN under the
// key-encryption key (`oath-token-secret`), as a TOTP secret on an entry is,
// so a store dump prints ciphertext twice over. No table is added, so no
// schema version. **Like every minted store it is not kept across a restart
// in DEVELOPMENT mode** (`persistence/CLAUDE.md`); in product mode it is.
//
// A LIBRARY (rule 3): it registers no route. `credentials`, the register,
// `hotp`, `totp`, `pskc` and the keystore are reached at the moment of use.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import realms = require('./realms');
import audit = require('./audit');
import errorCodes = require('./error_codes');
import cacheRegistry = require('./cache_registry');

type Json = any;

const STATUSES = ['unassigned', 'assigned', 'retired'];
const KINDS = ['hotp', 'totp'];
const MAX_PAGE = 500;
const NEWEST_CAP = 1000;
const MAX_TEXT = 128;

// ---------------------------------------------------------------------------
// THE INVENTORY, per realm at its declaration. `indexBy` and `sortBy` run on
// every row a flush writes, so neither has an Entering/Leaving pair (a hot
// path).
// ---------------------------------------------------------------------------
const inventory = realms.map({
  persist: 'oath_tokens.inventory',
  onDemand: { maxEntries: 5000 },
  indexBy: function (row: Json): string[] {
    const out: string[] = [];
    if (!row) {
      return out;
    }
    if (row.serial) {
      out.push('s:' + String(row.serial));
    }
    if (row.holder) {
      out.push('h:' + String(row.holder));
    }
    if (row.status) {
      out.push('st:' + String(row.status));
    }
    // A row whose holder's entry was not written (#2051).
    if (row.entrySync === 'pending') {
      out.push('e:pending');
    }
    return out;
  },
  sortBy: function (row: Json): number | null {
    const at = row ? Date.parse(String(row.importedAt || '')) : NaN;
    return at > 0 ? at : null;
  }
});

cacheRegistry.register({
  name: 'oath_tokens.inventory',
  title: 'OATH token inventory',
  description: 'One row per HOTP or TOTP key an administrator imported ' +
    'from a vendor\'s PSKC seed file (RFC 6030), keyed by vendor, serial ' +
    'and key id: unassigned (its secret sealed), assigned to a person (the ' +
    'secret dropped, now on their entry) or retired.',
  owner: 'common/oath_tokens.ts',
  scope: 'realm',
  kind: 'cache',
  persisted: true,
  settings: [],
  maxEntries: function (): number {
    return 5000;
  },
  bound: 'Enforced: the rows a process holds are a cache of 5,000 per ' +
    'realm, the oldest dropped and read from the store again when next ' +
    'asked; the inventory is bounded by what administrators import, at ' +
    'most 2,000 keys a file.',
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

// THE ASSIGNMENT'S COMPARE-AND-SET (`assign()`): a cluster claim per row,
// held for a day — long past any assignment, and the row's own status says
// `assigned` from then on.
const ASSIGN_SCOPE = 'oath_tokens.assign';
const ASSIGN_TTL_MS = 24 * 60 * 60 * 1000;

interface OathTokensDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  now: () => number;
  // Reached at the moment of use (header).
  loadCredentials: () => Json;
  loadHardwareTokens: () => Json;
  loadClaims: () => Json;
  loadPskc: () => Json;
  loadHotp: () => Json;
  loadTotp: () => Json;
  loadKeystore: () => Json;
}

/**
 * The inventory of OATH tokens imported from PSKC seed files (#1955 P4):
 * import, assignment by an administrator, a person's claim, and the
 * lost-key retirers.
 */
class OathTokens {
  static readonly STATUSES = STATUSES;
  static readonly KINDS = KINDS;
  static readonly MAX_PAGE = MAX_PAGE;

  /**
   * Builds the inventory over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: OathTokensDeps) {
    deps.log.debug("Entering OathTokens.constructor().");
    deps.log.debug("Leaving OathTokens.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): OathTokensDeps {
    helpers.log.debug("Entering OathTokens.defaultDeps().");
    helpers.log.debug("Leaving OathTokens.defaultDeps().");
    return {
      log: helpers.log, helpers: helpers, audit: audit,
      errorCodes: errorCodes, now: Date.now,
      loadCredentials: function (): Json {
        return require('./credentials');
      },
      loadHardwareTokens: function (): Json {
        return require('./hardware_tokens');
      },
      loadClaims: function (): Json {
        return require('../cluster/cluster_claims');
      },
      loadPskc: function (): Json {
        return require('./pskc');
      },
      loadHotp: function (): Json {
        return require('./hotp');
      },
      loadTotp: function (): Json {
        return require('./totp');
      },
      loadKeystore: function (): Json {
        return require('./keystore');
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE RETIRERS (header), installed when the instance is: the register's
  // hook, rule 3e. A retirer that cannot reach the register logs and leaves
  // the kind unretired, which the lost-key act reports as such.
  // -------------------------------------------------------------------------
  /**
   * Registers the `hotp` and `totp` retirers with the hardware token
   * register.
   *
   * @param instance - the installed instance
   */
  static wire(instance: OathTokens): void {
    helpers.log.debug("Entering OathTokens.wire().");
    instance.installRetirers();
    helpers.log.debug("Leaving OathTokens.wire().");
  }

  private installRetirers(): void {
    const { log } = this.deps;
    log.debug("Entering OathTokens.installRetirers().");
    const self = this;
    try {
      const register = this.deps.loadHardwareTokens();
      KINDS.forEach(function (kind) {
        register.registerRetirer(kind, {
          label: kind === 'hotp' ? 'HOTP token secret' : 'TOTP token secret',
          retire: function (token: Json, c: Json, ctx: Json): Promise<Json> {
            return self.retire(kind, c, ctx);
          }
        });
      });
    } catch (e) {
      log.error(this.deps.errorCodes.tag('STS-OATH-0047') + 'oath tokens: ' +
                'the retirers could not be registered: ' +
                ((e && e.message) || e));
    }
    log.debug("Leaving OathTokens.installRetirers().");
  }

  private nowIso(): string {
    return new Date(this.deps.now()).toISOString();
  }

  private refuse(code: string, why: string, extra?: Json): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering OathTokens.refuse(). " + code);
    log.debug("Leaving OathTokens.refuse().");
    return codes.mark(Object.assign({ ok: false, error: why, errors: [why] },
                                    extra || {}), code);
  }

  // HOT PATH: text() cleans every field of every key of an import of up to
  // two thousand, so no Entering/Leaving pair.
  private static text(value: unknown): string {
    return String(value === undefined || value === null ? '' : value)
      .replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, MAX_TEXT);
  }

  /**
   * An inventory row's key.
   *
   * @param vendor - the vendor slug
   * @param serial - the device serial
   * @param keyId - the key's id in the seed file
   * @returns `<vendor>/<serial>/<key id>`
   */
  static keyOf(vendor: string, serial: string, keyId: string): string {
    helpers.log.debug("Entering OathTokens.keyOf().");
    const slug = require('./hardware_tokens').HardwareTokens
      .vendorSlug(vendor) || 'unknown';
    helpers.log.debug("Leaving OathTokens.keyOf().");
    return slug + '/' + OathTokens.text(serial) + '/' +
      (OathTokens.text(keyId).replace(/\//g, '-') || '1');
  }

  private holderOf(username: string): string {
    const { log, helpers: h } = this.deps;
    log.debug("Entering OathTokens.holderOf().");
    const sub = String(h.subjectForName(username) || '');
    log.debug("Leaving OathTokens.holderOf().");
    return sub.indexOf('urn:uuid:') === 0 ? sub.slice(9) : '';
  }

  private nameOfHolder(holder: string): string {
    const { log, helpers: h } = this.deps;
    log.debug("Entering OathTokens.nameOfHolder().");
    const name = holder ? String(h.nameForSubject('urn:uuid:' + holder) ||
                                 '') : '';
    log.debug("Leaving OathTokens.nameOfHolder().");
    return name;
  }

  private recordAudit(action: string, actor: string, target: string,
                      summary: string, detail: Json, code?: string): void {
    const { log } = this.deps;
    log.debug("Entering OathTokens.recordAudit().");
    this.deps.audit.audit(Object.assign({
      action: action, actor: String(actor || ''),
      target: String(target || ''), outcome: code ? 'failure' : 'success',
      summary: summary, detail: detail || {}
    }, code ? { errorCode: code } : {}));
    log.debug("Leaving OathTokens.recordAudit().");
  }

  // The secret as an unassigned row keeps it: sealed where the key outlives
  // the process, base32 in the clear in development (`credentials.ts`'s
  // `writeTotpRecord()` rule, and its reason). Null when it cannot be
  // sealed.
  private sealSecret(base32: string): { secret: string; sealed: boolean } |
      null {
    const { log } = this.deps;
    log.debug("Entering OathTokens.sealSecret().");
    const keystore = this.deps.loadKeystore();
    if (!keystore.persists()) {
      log.debug("Leaving OathTokens.sealSecret(). In the clear.");
      return { secret: base32, sealed: false };
    }
    const sealed = keystore.seal(base32, 'oath-token-secret', 'cell');
    log.debug("Leaving OathTokens.sealSecret(). " + !!sealed);
    return sealed ? { secret: sealed, sealed: true } : null;
  }

  private openSecret(row: Json): string {
    const { log } = this.deps;
    log.debug("Entering OathTokens.openSecret().");
    if (!row || !row.secret) {
      log.debug("Leaving OathTokens.openSecret(). None.");
      return '';
    }
    if (!row.sealed) {
      log.debug("Leaving OathTokens.openSecret(). Clear.");
      return String(row.secret);
    }
    const opened = this.deps.loadKeystore().open(String(row.secret),
                                                 'oath-token-secret');
    log.debug("Leaving OathTokens.openSecret(). " + !!opened);
    return opened ? String(opened) : '';
  }

  // -------------------------------------------------------------------------
  // IMPORT. `spec`: { pskc (the XML text), preSharedKey?, password?, actor,
  // via }. The key and password are handed to `pskc.open()` and to nothing
  // else (`pskc.ts`'s header); the audit row names the file's protection,
  // never them.
  // -------------------------------------------------------------------------
  /**
   * Imports every HOTP and TOTP key of a PSKC seed file as an unassigned
   * token.
   *
   * @param spec - the file, its key or password, who and through which door
   * @returns a promise of `{ ok, imported, skipped, protection }`, or a
   *   refusal
   */
  async importPskc(spec: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.importPskc().");
    const s = spec || {};
    const pskc = this.deps.loadPskc();
    const totp = this.deps.loadTotp();
    const parsed = pskc.parse(s.pskc);
    if (!parsed.ok) {
      this.recordAudit('oath-token.import', s.actor, '', 'A PSKC seed file ' +
        'was refused', { via: s.via || '' },
        this.deps.errorCodes.codeOf(parsed) || 'STS-OATH-0020');
      log.debug("Leaving OathTokens.importPskc(). Not parsed.");
      return parsed;
    }
    const opened = await pskc.open(parsed, { preSharedKey: s.preSharedKey,
                                             password: s.password });
    if (!opened.ok) {
      this.recordAudit('oath-token.import', s.actor, '', 'A PSKC seed file ' +
        'did not open', { via: s.via || '', protection: parsed.protection },
        this.deps.errorCodes.codeOf(opened) || 'STS-OATH-0026');
      log.debug("Leaving OathTokens.importPskc(). Not opened.");
      return opened;
    }
    const now = this.nowIso();
    const imported: Json[] = [];
    const skipped: Json[] = (opened.skipped || []).slice(0);
    for (const k of opened.keys) {
      const key = OathTokens.keyOf(k.vendor, k.serial, k.keyId);
      if (inventory.get(key) || await this.heldElsewhere(key)) {
        skipped.push({ index: k.index, serial: k.serial, keyId: k.keyId,
                       errorCode: 'STS-OATH-0030',
                       why: 'Token ' + key + ' is already in this realm\'s ' +
                            'inventory.' });
        continue;
      }
      const held = this.sealSecret(totp.base32Encode(k.secret));
      if (!held) {
        log.error(this.deps.errorCodes.tag('STS-OATH-0046') + 'oath ' +
                  'tokens: the secret of ' + key + ' could not be sealed, ' +
                  'so the import stopped.');
        this.recordAudit('oath-token.import', s.actor, '', 'A PSKC import ' +
          'stopped: a secret could not be sealed',
          { via: s.via || '', imported: imported.length }, 'STS-OATH-0046');
        log.debug("Leaving OathTokens.importPskc(). Not sealed.");
        return this.refuse('STS-OATH-0046', 'A token\'s secret could not be ' +
          'encrypted, so the import stopped after ' + imported.length +
          ' token(s).', { imported: imported, skipped: skipped });
      }
      const row = {
        key: key,
        vendor: OathTokens.text(k.vendor), serial: OathTokens.text(k.serial),
        model: OathTokens.text(k.model), issueNo: OathTokens.text(k.issueNo),
        keyId: OathTokens.text(k.keyId), issuer: OathTokens.text(k.issuer),
        kind: k.kind, digits: k.digits, algorithm: k.algorithm,
        counter: k.counter, period: k.period,
        secret: held.secret, sealed: held.sealed,
        status: 'unassigned', holder: '',
        importedAt: now, importedBy: OathTokens.text(s.actor),
        protection: opened.protection,
        assignedAt: '', assignedBy: '', assignedVia: '', retiredAt: ''
      };
      inventory.set(key, row);
      imported.push(this.view(key, row));
    }
    this.recordAudit('oath-token.import', s.actor, '', 'A PSKC seed file ' +
      'was imported: ' + imported.length + ' token(s), ' + skipped.length +
      ' skipped', { via: s.via || '', protection: opened.protection,
                    imported: imported.map(function (r: Json): string {
                      return r.key;
                    }),
                    skipped: skipped.length });
    log.info('oath tokens: a PSKC seed file was imported: ' +
             imported.length + ' token(s), ' + skipped.length + ' skipped.');
    log.debug("Leaving OathTokens.importPskc().");
    return { ok: true, protection: opened.protection, imported: imported,
             skipped: skipped.map(function (r: Json): Json {
               return { index: r.index, serial: r.serial, keyId: r.keyId,
                        errorCode: r.errorCode || '', why: r.why };
             }) };
  }

  // A row this process does not hold may still be in the store (on demand):
  // `warm()` reads it in, then the Map answers.
  private async heldElsewhere(key: string): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.heldElsewhere().");
    const found = !!(await this.rowOf(key));
    log.debug("Leaving OathTokens.heldElsewhere(). " + found);
    return found;
  }

  private async rowOf(key: string): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.rowOf().");
    const k = String(key || '');
    if (!inventory.get(k)) {
      try {
        await inventory.warm([k]);
      } catch (e) {
        log.debug("Caught in OathTokens.rowOf(): " + ((e && e.message) || e));
        // The store cannot be asked: what this process holds decides.
      }
    }
    const row = inventory.get(k) || null;
    log.debug("Leaving OathTokens.rowOf(). " + !!row);
    return row;
  }

  private async rowsBySerial(serial: string): Promise<Json[]> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.rowsBySerial().");
    let rows: Json[] = [];
    try {
      rows = await inventory.lookupEntriesAsync('s:' + serial);
    } catch (e) {
      log.debug("Caught in OathTokens.rowsBySerial(): " +
                ((e && e.message) || e));
      // The read pool cannot be asked: what this process holds.
      rows = inventory.lookup('s:' + serial).map(function (k: Json): Json {
        return { key: k, value: inventory.get(k) };
      });
    }
    const seen: Record<string, boolean> = {};
    const out = rows.filter(function (r: Json): boolean {
      const ok = !!(r && r.value && String(r.value.serial) === serial &&
                    !seen[String(r.key)]);
      seen[String(r && r.key)] = true;
      return ok;
    });
    log.debug("Leaving OathTokens.rowsBySerial(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // ASSIGNMENT: the one writer of a person's imported credential. `spec`:
  // { key, username, actor, via, counter?, lastCounter? } — the two counters
  // set by a claim, whose code is then spent.
  // -------------------------------------------------------------------------
  /**
   * Assigns an unassigned token to a person: their credential of its kind,
   * the register's `pskc-import` evidence, the row's secret dropped.
   *
   * @param spec - the token, the person, who and through which door
   * @returns a promise of `{ ok, token }`, or a refusal
   */
  async assign(spec: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.assign().");
    const s = spec || {};
    const key = String(s.key || '');
    const username = String(s.username || '').trim();
    const row = await this.rowOf(key);
    if (!row) {
      log.debug("Leaving OathTokens.assign(). No token.");
      return this.refuse('STS-OATH-0040', 'No token "' +
        OathTokens.text(key) + '" is in this realm\'s inventory.');
    }
    if (row.status !== 'unassigned') {
      log.debug("Leaving OathTokens.assign(). Not unassigned.");
      return this.refuse('STS-OATH-0041', 'Token ' + key + ' is ' +
        String(row.status) + (row.status === 'assigned'
          ? ' to ' + (this.nameOfHolder(row.holder) || 'somebody') : '') +
        ', so it cannot be assigned.');
    }
    const holder = this.holderOf(username);
    if (!holder) {
      log.debug("Leaving OathTokens.assign(). No person.");
      return this.refuse('STS-OATH-0042', 'There is nobody called "' +
        OathTokens.text(username) + '" in this realm\'s directory.');
    }
    const lib = row.kind === 'totp' ? this.deps.loadTotp()
                                    : this.deps.loadHotp();
    if (!lib.offered()) {
      log.debug("Leaving OathTokens.assign(). The policy has it off.");
      return this.refuse('STS-OATH-0044', 'The authentication policy has ' +
        (row.kind === 'totp' ? 'authenticator apps (totp)'
                             : 'one-time code tokens (hotp)') + ' off, so ' +
        'this token cannot be given to anybody.');
    }
    const secret = this.openSecret(row);
    if (!secret) {
      log.error(this.deps.errorCodes.tag('STS-OATH-0045') + 'oath tokens: ' +
                'the secret of ' + key + ' will not open under this ' +
                'process\'s key-encryption key.');
      log.debug("Leaving OathTokens.assign(). The secret will not open.");
      return this.refuse('STS-OATH-0045', 'The token\'s secret cannot be ' +
        'read by this service, so it cannot be assigned.');
    }
    // THE ROW IS TAKEN BY COMPARE-AND-SET FIRST (the #1955 review): a claim
    // in the store, once for the cluster, before anything is installed, so
    // two assignments — two administrators, an administrator and a claim,
    // two nodes — cannot both install the token's secret on two people. The
    // row's `unassigned` above was a read; this is the write that decides.
    // A loser is told the token is taken; a winner that fails to install
    // releases the claim so the token can be assigned again.
    const taken = await this.deps.loadClaims().claim({
      scope: ASSIGN_SCOPE, value: key, ttlMs: ASSIGN_TTL_MS });
    if (!taken || !taken.ok) {
      const store = !!taken && taken.reason === 'store';
      log.debug("Leaving OathTokens.assign(). " +
                (store ? 'No store.' : 'Taken by another assignment.'));
      return store
        ? this.refuse('STS-OATH-0006', 'The token could not be reserved ' +
            'just now. Try again.')
        : this.refuse('STS-OATH-0041', 'Token ' + key + ' is being ' +
            'assigned to somebody else, so it cannot be assigned.');
    }
    const fresh = await this.rowOf(key);
    if (!fresh || fresh.status !== 'unassigned') {
      log.debug("Leaving OathTokens.assign(). Assigned since the read.");
      return this.refuse('STS-OATH-0041', 'Token ' + key + ' was assigned ' +
        'by another request just now, so it cannot be assigned.');
    }
    const installed = await this.deps.loadCredentials().installImportedOath(
      username, { key: key, kind: row.kind, secret: secret,
                  algorithm: row.algorithm, digits: row.digits,
                  counter: s.counter === undefined ? row.counter : s.counter,
                  lastCounter: s.lastCounter, period: row.period,
                  vendor: row.vendor, serial: row.serial, model: row.model,
                  // A claim's code must be the one that is spent: a store
                  // already past it means another request spent it.
                  claim: s.via === 'claim' });
    if (!installed || !installed.ok) {
      try {
        await this.deps.loadClaims().release(taken.handle);
      } catch (e) {
        log.debug("Caught in OathTokens.assign(): " + ((e && e.message) || e));
        // The reservation expires on its own (ASSIGN_TTL_MS).
      }
      log.debug("Leaving OathTokens.assign(). Not installed.");
      return installed;
    }
    const recorded = this.deps.loadHardwareTokens().recordAttested({
      username: username, vendor: row.vendor || 'unknown',
      serial: row.serial, model: row.model,
      credential: { kind: row.kind, ref: key,
                    label: (row.kind === 'hotp' ? 'HOTP' : 'TOTP') +
                           ' key ' + (row.keyId || '1') },
      evidence: { source: 'pskc-import', keyId: row.keyId,
                  detail: 'imported ' + String(row.importedAt || '') },
      actor: s.actor || username, via: s.via || '' });
    if (!recorded || !recorded.ok) {
      // The credential stands, as a QR-enrolled one would: without the
      // register row it simply earns no `hwk`. Logged under the register's
      // own code.
      log.warn('oath tokens: token ' + key + ' was assigned to ' + username +
               ' and the hardware token register did not record it (' +
               String((recorded && recorded.error) || 'no answer') + ').');
    }
    const next = Object.assign({}, row, {
      status: 'assigned', holder: holder, secret: '', sealed: false,
      assignedAt: this.nowIso(), assignedBy: OathTokens.text(s.actor),
      assignedVia: OathTokens.text(s.via) });
    this.put(key, next);
    this.recordAudit('oath-token.assign', s.actor || username, username,
      'OATH token ' + key + ' was ' + (s.via === 'claim' ? 'claimed by '
                                                          : 'assigned to ') +
      username, { key: key, kind: row.kind, via: s.via || '' });
    log.info('oath tokens: ' + key + ' was ' + (s.via === 'claim'
      ? 'claimed by ' : 'assigned to ') + username + '.');
    log.debug("Leaving OathTokens.assign(). Assigned.");
    return { ok: true, token: this.view(key, next) };
  }

  // -------------------------------------------------------------------------
  // THE CLAIM: a serial and a code the token shows now. Every unassigned
  // token of that serial is tried (a device may carry two keys, the way a
  // YubiKey has two OTP slots), and the first whose code matches is
  // assigned with that code SPENT — an HOTP token's counter past it, a TOTP
  // token's step recorded. A wrong serial and a wrong code are one refusal,
  // so a claim cannot be used to learn which serials are in stock. The door
  // throttles it (`websecurity.attemptShared('mfa-code')`).
  // -------------------------------------------------------------------------
  /**
   * A person claims an unassigned token by its serial and a current code.
   *
   * @param spec - `{ username, serial, code }`
   * @returns a promise of `{ ok, token }`, or a refusal
   */
  async claim(spec: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.claim().");
    const s = spec || {};
    const username = String(s.username || '').trim();
    const serial = OathTokens.text(s.serial).replace(/\s+/g, '');
    if (!serial || !username) {
      log.debug("Leaving OathTokens.claim(). Nothing given.");
      return this.noClaim();
    }
    const rows = (await this.rowsBySerial(serial)).filter(function (r: Json) {
      return r.value.status === 'unassigned';
    });
    for (const r of rows) {
      const row = r.value;
      const secret = this.openSecret(row);
      if (!secret) {
        continue;
      }
      const record = { secret: secret, digits: row.digits,
                       algorithm: row.algorithm, counter: row.counter,
                       period: row.period };
      const verdict = row.kind === 'totp'
        ? this.deps.loadTotp().verify(record, s.code)
        : this.deps.loadHotp().verify(record, s.code);
      if (!verdict.ok) {
        continue;
      }
      const out = await this.assign({
        key: String(r.key), username: username, actor: username,
        via: 'claim',
        counter: row.kind === 'hotp' ? verdict.next : undefined,
        lastCounter: row.kind === 'totp' ? verdict.counter : undefined });
      log.debug("Leaving OathTokens.claim(). " + (out.ok ? 'Claimed.'
                                                         : 'Refused.'));
      return out;
    }
    this.recordAudit('oath-token.claim', username, username, 'A claim of ' +
      'an OATH token was refused', { serial: serial }, 'STS-OATH-0043');
    log.debug("Leaving OathTokens.claim(). No match.");
    return this.noClaim();
  }

  // ONE refusal for a wrong serial and a wrong code (the claim's header).
  private noClaim(): Json {
    const { log } = this.deps;
    log.debug("Entering OathTokens.noClaim().");
    log.debug("Leaving OathTokens.noClaim().");
    return this.refuse('STS-OATH-0043', 'No token waiting to be claimed ' +
      'has that serial and shows that code. Check the serial on the token, ' +
      'and press it (or wait) for a new code.');
  }

  /**
   * Removes an unassigned token (a mistaken import); an assigned one is
   * retired by reporting its hardware token lost instead.
   *
   * @param spec - `{ key, actor, via }`
   * @returns a promise of `{ ok, key }`, or a refusal
   */
  async remove(spec: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.remove().");
    const s = spec || {};
    const key = String(s.key || '');
    const row = await this.rowOf(key);
    if (!row) {
      log.debug("Leaving OathTokens.remove(). No token.");
      return this.refuse('STS-OATH-0040', 'No token "' +
        OathTokens.text(key) + '" is in this realm\'s inventory.');
    }
    if (row.status === 'assigned') {
      log.debug("Leaving OathTokens.remove(). Assigned.");
      return this.refuse('STS-OATH-0049', 'Token ' + key + ' is assigned. ' +
        'Report its hardware token lost to retire it.');
    }
    inventory.delete(key);
    this.recordAudit('oath-token.remove', s.actor, '', 'OATH token ' + key +
      ' was removed from the inventory', { key: key, via: s.via || '' });
    log.debug("Leaving OathTokens.remove(). Removed.");
    return { ok: true, key: key };
  }

  // The lost-key retirer of one kind (header): the person's credential goes
  // only if it is still this token's.
  private async retire(kind: string, c: Json, ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.retire(). " + kind);
    const key = String((c && c.ref) || '');
    const username = String((ctx && ctx.username) || '');
    const credentials = this.deps.loadCredentials();
    let removed: Json = { ok: true, already: true };
    if (kind === 'hotp') {
      const held = credentials.mechanismsFor(username).hotpDetail;
      if (held && held.token === key) {
        removed = credentials.removeHotp(username, { onlyToken: key });
      }
    } else {
      const record = credentials.totpOf(username);
      if (record && !record.unusable && record.token === key) {
        removed = credentials.removeTotp(username);
      }
    }
    const row = await this.rowOf(key);
    if (row) {
      this.put(key, Object.assign({}, row, {
        status: 'retired', secret: '', sealed: false,
        retiredAt: this.nowIso() }));
    }
    if (!removed || !removed.ok) {
      log.debug("Leaving OathTokens.retire(). Not removed.");
      return { ok: false, errorCode: 'STS-OATH-0047',
               why: String(((removed && removed.errors) || ['not removed'])[0])
      };
    }
    log.debug("Leaving OathTokens.retire(). Retired.");
    return { ok: true };
  }

  // -------------------------------------------------------------------------
  // THE LIST, PAGED: P1's register's shape. `q` is a serial (exact) or a
  // username (that person's tokens).
  // -------------------------------------------------------------------------
  /**
   * A page of the realm's OATH token inventory.
   *
   * @param opts - `offset`, `limit`, `status`, `q`
   * @returns a promise of `{ ok, tokens, total, offset, limit, capped }`
   */
  async list(opts?: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.list().");
    const o = opts || {};
    const limit = Math.max(1, Math.min(MAX_PAGE, Number(o.limit) || 25));
    const offset = Math.max(0, Number(o.offset) || 0);
    const status = STATUSES.indexOf(String(o.status || '')) >= 0
      ? String(o.status) : '';
    const q = OathTokens.text(o.q);
    let rows: Json[] = [];
    let capped = false;
    let total: number | null = null;
    if (q) {
      const bySerial = await this.rowsBySerial(q);
      const holder = this.holderOf(q);
      let byHolder: Json[] = [];
      if (holder) {
        try {
          byHolder = await inventory.lookupEntriesAsync('h:' + holder);
        } catch (e) {
          log.debug("Caught in OathTokens.list(): " + ((e && e.message) || e));
          byHolder = inventory.lookup('h:' + holder).map(function (k: Json) {
            return { key: k, value: inventory.get(k) };
          });
        }
      }
      const seen: Record<string, boolean> = {};
      rows = bySerial.concat(byHolder).filter(function (r: Json): boolean {
        const ok = !!(r && r.value) && !seen[String(r.key)];
        seen[String(r && r.key)] = true;
        return ok;
      }).map((r: Json) => {
        return this.view(String(r.key), r.value);
      });
    } else if (inventory.onDemandLive()) {
      const newest = await inventory.newestAsync(NEWEST_CAP);
      rows = (newest || []).map((r: Json) => {
        return this.view(String(r.key), r.value);
      });
      total = await inventory.countAsync();
      capped = total !== null && total > rows.length;
    } else {
      inventory.forEach((value: Json, key: Json) => {
        rows.push(this.view(String(key), value));
      });
      rows.sort(function (a: Json, b: Json): number {
        return String(b.importedAt).localeCompare(String(a.importedAt));
      });
    }
    if (status) {
      rows = rows.filter(function (r) {
        return r.status === status;
      });
    }
    log.debug("Leaving OathTokens.list(). " + rows.length + " row(s).");
    return { ok: true, tokens: rows.slice(offset, offset + limit),
             total: total !== null && !status && !q ? total : rows.length,
             offset: offset, limit: limit, capped: capped };
  }

  // What a page draws: never the secret, never the file's key.
  private view(key: string, row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OathTokens.view().");
    const r = row || {};
    const out = {
      key: key, kind: String(r.kind || ''), vendor: String(r.vendor || ''),
      serial: String(r.serial || ''), model: String(r.model || ''),
      keyId: String(r.keyId || ''), issuer: String(r.issuer || ''),
      digits: Number(r.digits || 0), algorithm: String(r.algorithm || ''),
      period: r.kind === 'totp' ? Number(r.period || 30) : 0,
      status: String(r.status || 'unassigned'),
      holder: this.nameOfHolder(String(r.holder || '')),
      importedAt: String(r.importedAt || ''),
      importedBy: String(r.importedBy || ''),
      protection: String(r.protection || ''),
      assignedAt: String(r.assignedAt || ''),
      assignedVia: String(r.assignedVia || ''),
      retiredAt: String(r.retiredAt || '')
    };
    log.debug("Leaving OathTokens.view().");
    return out;
  }

  /**
   * Clears the ambient realm's inventory; for tests only.
   */
  forgetForTests(): void {
    const { log } = this.deps;
    log.debug("Entering OathTokens.forgetForTests().");
    inventory.clear();
    log.debug("Leaving OathTokens.forgetForTests().");
  }

  // -------------------------------------------------------------------------
  // AN ASSIGNED TOKEN ON ITS HOLDER'S ENTRY (#2051, `common/token_entries.ts`):
  // the entry's `stsOathToken` is the master once the token is assigned, and
  // this row its index. An unassigned row has no person, so it is the
  // staging inventory and holds the sealed secret until then.
  // -------------------------------------------------------------------------

  /**
   * A row's value of `stsOathToken`: what the inventory knows of the token,
   * never its secret.
   *
   * @param key - the inventory key
   * @param row - the inventory row
   * @returns the value
   */
  static entryValueOf(key: string, row: Json): Json {
    helpers.log.debug("Entering OathTokens.entryValueOf().");
    const r = row || {};
    const value: Json = {
      key: String(key), kind: String(r.kind || ''),
      vendor: String(r.vendor || ''), serial: String(r.serial || ''),
      model: String(r.model || ''), keyId: String(r.keyId || ''),
      issuer: String(r.issuer || ''), status: String(r.status || ''),
      importedAt: String(r.importedAt || ''),
      assignedAt: String(r.assignedAt || ''),
      assignedBy: String(r.assignedBy || ''),
      assignedVia: String(r.assignedVia || ''),
      retiredAt: String(r.retiredAt || '')
    };
    helpers.log.debug("Leaving OathTokens.entryValueOf().");
    return value;
  }

  // THE ENTRY FIRST, THEN THE INDEX (above): a row with a holder is
  // written onto their entry, and marked pending where it could not be.
  private put(key: string, row: Json): void {
    const { log } = this.deps;
    log.debug("Entering OathTokens.put().");
    const entries = require('./token_entries');
    const state = row.holder
      ? entries.project('urn:uuid:' + String(row.holder),
                        entries.ATTRIBUTES.oath, key,
                        OathTokens.entryValueOf(key, row))
      : 'done';
    const next = Object.assign({}, row);
    if (state === 'failed') {
      next.entrySync = 'pending';
    } else {
      delete next.entrySync;
    }
    inventory.set(key, next);
    log.debug("Leaving OathTokens.put(). " + state);
  }

  /**
   * The entries job's part: every pending row written again, and with
   * `backfill` every row with a holder, in the ambient realm.
   *
   * @param opts - `{ backfill }`
   * @returns a promise of `{ ok, written, pending }`
   */
  async syncEntries(opts?: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.syncEntries().");
    const rows: Json[] = [];
    if (opts && opts.backfill) {
      await inventory.scanAsync(function (value: Json, key: unknown) {
        if (value && value.holder) {
          rows.push({ key: String(key), value: value });
        }
      });
    } else {
      rows.push.apply(rows, await inventory.lookupEntriesAsync('e:pending'));
    }
    const entries = require('./token_entries');
    let written = 0;
    let pending = 0;
    for (const one of rows) {
      if (!one || !one.value || !one.value.holder) {
        continue;
      }
      const state = await entries.projectAsync(
        'urn:uuid:' + String(one.value.holder), entries.ATTRIBUTES.oath,
        String(one.key), OathTokens.entryValueOf(String(one.key), one.value));
      const failed = state === 'failed';
      if (failed) {
        pending += 1;
      } else {
        written += 1;
      }
      if (failed !== (one.value.entrySync === 'pending')) {
        const next = Object.assign({}, one.value);
        if (failed) {
          next.entrySync = 'pending';
        } else {
          delete next.entrySync;
        }
        inventory.set(String(one.key), next);
      }
    }
    log.debug("Leaving OathTokens.syncEntries(). " + written + "/" +
              pending);
    return { ok: true, written: written, pending: pending };
  }

  /**
   * What the inventory holds for one person's value of a token (the entry
   * observer's check, `token_entries.ts`), or null.
   *
   * @param key - the inventory key
   * @param change - the observer's change (`subject` the person)
   * @returns a promise of the value, or null
   */
  async entryValueFor(key: string, change: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.entryValueFor().");
    const person = String((change && change.subject) || '')
      .replace(/^urn:uuid:/i, '');
    const row = await this.rowOf(String(key));
    log.debug("Leaving OathTokens.entryValueFor().");
    return row && person && String(row.holder || '') === person
      ? OathTokens.entryValueOf(String(key), row) : null;
  }

  /**
   * A token's value removed from its holder's entry by another door (the
   * entry observer): the entry is the master, so the token is RETIRED — its
   * credential removed when it is still this token's, as a lost report
   * would — and the row no longer names a holder. The entry first: it is
   * kept off, then the row is written.
   *
   * @param key - the inventory key
   * @param change - the observer's change
   * @returns a promise of `{ ok, changed }`
   */
  async entryRemoved(key: string, change: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.entryRemoved().");
    const c = change || {};
    const person = String(c.subject || '').replace(/^urn:uuid:/i, '');
    const row = await this.rowOf(String(key));
    if (!row || !person || String(row.holder || '') !== person) {
      log.debug("Leaving OathTokens.entryRemoved(). Not theirs.");
      return { ok: true, changed: false };
    }
    if (row.status === 'assigned') {
      await this.retire(String(row.kind || ''), { ref: String(key) },
                        { username: String(c.username || '') });
    }
    const entries = require('./token_entries');
    entries.project(String(c.subject), entries.ATTRIBUTES.oath, String(key),
                    null);
    const fresh = (await this.rowOf(String(key))) || row;
    const next = Object.assign({}, fresh, {
      status: 'retired', holder: '', retiredFrom: person,
      retiredAt: String(fresh.retiredAt || this.nowIso()) });
    delete next.entrySync;
    inventory.set(String(key), next);
    this.recordAudit('oath-token.retire', String(c.actor || c.door ||
      'directory'), String(c.username || ''), 'OATH token ' + key + ' was ' +
      'retired: it was removed from the entry of ' + String(c.username || ''),
      { key: String(key), door: String(c.door || '') });
    log.debug("Leaving OathTokens.entryRemoved(). Retired.");
    return { ok: true, changed: true };
  }

  /**
   * The inventory's assigned and retired rows rebuilt from the entries,
   * which are the master; a row the entries name and the inventory lost is
   * made again, without a secret.
   *
   * @returns a promise of `{ ok, rebuilt }`
   */
  async rebuildFromEntries(): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OathTokens.rebuildFromEntries().");
    const entries = require('./token_entries');
    const holders = await entries.holdersOf(entries.ATTRIBUTES.oath);
    let rebuilt = 0;
    for (const person of holders) {
      const holder = this.holderOf(person.username);
      for (const value of person.values || []) {
        const key = String((value && value.key) || '');
        if (!key || !holder) {
          continue;
        }
        const held = (await this.rowOf(key)) || {};
        const next = Object.assign({}, held, {
          key: key, kind: value.kind, vendor: value.vendor,
          serial: value.serial, model: value.model, keyId: value.keyId,
          issuer: value.issuer, status: value.status, holder: holder,
          importedAt: value.importedAt, assignedAt: value.assignedAt,
          assignedBy: value.assignedBy, assignedVia: value.assignedVia,
          retiredAt: value.retiredAt, secret: '', sealed: false });
        delete next.entrySync;
        const before = Object.assign({}, held);
        delete before.entrySync;
        if (entries.stored(before) !== entries.stored(next)) {
          inventory.set(key, next);
          rebuilt += 1;
        }
      }
    }
    log.debug("Leaving OathTokens.rebuildFromEntries(). " + rebuilt);
    return { ok: true, rebuilt: rebuilt };
  }
}

const slot = new InstanceSlot<OathTokens>(
  'common/oath_tokens',
  () => new OathTokens(OathTokens.defaultDeps()),
  OathTokens.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The OATH token inventory (#1955 P4). A library (rule 3).
 * @namespace
 */
export = {
  OathTokens: OathTokens,
  STATUSES: STATUSES,
  KINDS: KINDS,
  installInstance: (instance: OathTokens): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  importPskc: slot.forward('importPskc'),
  assign: slot.forward('assign'),
  claim: slot.forward('claim'),
  remove: slot.forward('remove'),
  list: slot.forward('list'),
  entryValueOf: OathTokens.entryValueOf,
  syncEntries: slot.forward('syncEntries'),
  rebuildFromEntries: slot.forward('rebuildFromEntries'),
  entryValueFor: slot.forward('entryValueFor'),
  entryRemoved: slot.forward('entryRemoved'),
  forgetForTests: slot.forward('forgetForTests')
};
