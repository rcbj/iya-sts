'use strict';
//
// File: federation_keys.ts
//
// ===========================================================================
// A REALM'S FEDERATION ENTITY KEYS (OpenID Federation 1.1 sections 3.1.1,
// 8.7 and 11; #132, #133, 2026-09-23).
//
// Every statement a realm makes as a federation entity — its Entity
// Configuration, the Subordinate Statements it issues, its Trust Marks, its
// resolve and status responses, its historical key list — is signed with a
// FEDERATION ENTITY KEY, published in the `jwks` of its Entity Configuration.
// rcbj's answer 3 on #132: a key per realm, SEPARATE from the protocol
// signing keys (3.1.1: "These Federation Entity Keys SHOULD NOT be used in
// other protocols"), rotated with overlap, and every key it has retired kept
// for good, with why it was retired, for the Historical Keys endpoint (8.7).
//
// ---------------------------------------------------------------------------
// WHY IT IS A TABLE OF ITS OWN AND NOT A UNIT OF THE KEY GENERATIONS.
//
// `common/helpers.js`'s key generations hold the realm's PROTOCOL keys, and
// almost every reader of them publishes what they hold: the JWKS, the SAML
// metadata, the crypto metadata document, the "is this one of ours" check
// every token presented back is verified by. A federation key among them
// would have had to be filtered out of each, now and in every reader written
// later — and a reader that forgot would publish the federation key as a
// protocol key, which is precisely what 3.1.1 asks not to happen. And the
// generations DROP a retired key at its grace, where 8.7 wants the public
// half kept for ever. So the key is kept the way #168 keeps a federation
// relationship's encryption key: a table on a directory entry
// (`oidfed/oidfed_store.ts`, the realm's `ou=oidfed` `keys` entry), its
// private halves sealed under the key-encryption key wherever keys persist
// (`keystore.seal()`, label `oidfed-key`), rotated by a scheduler job of its
// own. **NOTHING HERE MAKES OR USES A KEY A NEW WAY** (rcbj's rule of
// 2026-09-21): a key is made by `helpers.makeFederationKey()` — the curve
// and post-quantum recipes a signing unit's next key is made by — and
// everything is signed and verified by `common/crypto.js`.
//
// ---------------------------------------------------------------------------
// THE LIFE OF A KEY (11.1, 11.2).
//
//   next      minted AHEAD and PUBLISHED at once, so every entity that
//             refreshes the Entity Configuration holds it before it signs
//             anything; it signs nothing.
//   current   signs everything. Exactly one.
//   retired   signs nothing; still PUBLISHED until `publishedUntil` (the
//             overlap after it stopped signing, so a statement it signed a
//             moment before still verifies against a freshly fetched
//             configuration), and in the Historical Keys list for ever. Its
//             PRIVATE KEY IS DROPPED THE MOMENT IT IS RETIRED — nothing may
//             sign with it again, so nothing needs to hold it.
//
// A REVOKED key (by hand, with a reason, or by an emergency rotation, which
// revokes as `compromised`) leaves the published `jwks` at once, keeps its
// row, and is listed in Historical Keys with `revoked` (8.7.2). Revoking the
// current key rotates in an emergency: the `next` key is revoked with it,
// because it was stored beside the key presumed compromised (#48's rule).
//
// THE SCHEDULE runs in product mode only (`mode.rotatesSigningKeys()`, the
// protocol keys' predicate): a development process's directory is its own
// and its keys are new at every start. A rotation by hand works in every
// mode, and is how one is exercised there.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import keystore = require('../common/keystore');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import nodeCrypto = require('crypto');
import OidfedStore = require('./oidfed_store');

type Json = any;

const SEAL_LABEL = 'oidfed-key';
const ROW_VERSION = 1;
const ROTATE_JOB = 'oidfed.key-rotate';
const ROTATE_NOW_JOB = 'oidfed.key-rotate-now';
const MINT_SCOPE = 'oidfed.key-mint';
const DAY_MS = 86400000;
// The revocation reasons 8.7.3 defines.
const REASONS = Object.freeze(['unspecified', 'compromised', 'superseded']);

interface Signer {
  key: Json;
  alg: string;
  kid: string;
}

interface FederationKeysDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  keystore: typeof keystore;
  errorCodes: typeof errorCodes;
  store: typeof OidfedStore;
  makeKey: (alg: string) => Promise<Json>;
  // Lazily: the scheduler, the mode, the audit log and the claims.
  scheduler: () => Json;
  mode: () => Json;
  audit: () => Json;
  claims: () => Json;
  now: () => number;
}

class FederationKeys {
  static readonly SEAL_LABEL = SEAL_LABEL;
  static readonly ROTATE_JOB = ROTATE_JOB;
  static readonly ROTATE_NOW_JOB = ROTATE_NOW_JOB;
  static readonly REASONS = REASONS;

  constructor(private readonly deps: FederationKeysDeps) {
    deps.log.debug("Entering FederationKeys.constructor().");
    deps.log.debug("Leaving FederationKeys.constructor().");
  }

  static defaultDeps(): FederationKeysDeps {
    helpers.log.debug("Entering FederationKeys.defaultDeps().");
    helpers.log.debug("Leaving FederationKeys.defaultDeps().");
    return {
      log: helpers.log, config: config, realms: realms, keystore: keystore,
      errorCodes: errorCodes, store: OidfedStore,
      makeKey: function (alg: string): Promise<Json> {
        return helpers.makeFederationKey(alg);
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      mode: function (): Json {
        return require('../common/mode');
      },
      audit: function (): Json {
        return require('../common/audit');
      },
      claims: function (): Json {
        return require('../cluster/cluster_claims');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // The algorithm a NEW key is made for: `oidfed.signingAlg`, one of
  // `helpers.FEDERATION_KEY_ALGS`. A change takes effect at the next key
  // minted — a rotation by hand makes it at once.
  algorithm(): string {
    const { log, config } = this.deps;
    log.debug("Entering FederationKeys.algorithm().");
    const alg = String(config.value('oidfed.signingAlg') || 'ES256');
    log.debug("Leaving FederationKeys.algorithm(). " + alg);
    return helpers.FEDERATION_KEY_ALGS.indexOf(alg) >= 0 ? alg : 'ES256';
  }

  private overlapMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering FederationKeys.overlapMs().");
    log.debug("Leaving FederationKeys.overlapMs().");
    return Math.max(0, Number(config.value('oidfed.keyOverlapDays'))) * DAY_MS;
  }

  private rows(): Json[] {
    const { log, store } = this.deps;
    log.debug("Entering FederationKeys.rows().");
    const out = store.keyRows().filter(function (row: Json): boolean {
      return row && Number(row.v) === ROW_VERSION &&
             typeof row.kid === 'string';
    });
    log.debug("Leaving FederationKeys.rows(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // A PRIVATE KEY AT REST: its PKCS#8 PEM (curve) or its bytes (ML-DSA) as
  // JSON, sealed under the key-encryption key where there is one — which is
  // every product deployment — and in the clear in a development process,
  // whose directory is its own and dies with it. `federation_encryption.ts`'s
  // arrangement, and for its reason.
  // -------------------------------------------------------------------------
  private sealed(privateKey: Json): { privateKey: string; sealed: boolean } {
    const { log, keystore } = this.deps;
    log.debug("Entering FederationKeys.sealed().");
    const text = JSON.stringify(Buffer.isBuffer(privateKey)
      ? { b64: privateKey.toString('base64') }
      : { pem: privateKey.export({ type: 'pkcs8', format: 'pem' }) });
    if (!keystore.sealed()) {
      log.debug("Leaving FederationKeys.sealed(). No key-encryption key.");
      return { privateKey: text, sealed: false };
    }
    const closed = keystore.seal(text, SEAL_LABEL);
    if (!closed) {
      log.debug("Leaving FederationKeys.sealed(). It would not seal.");
      throw new Error('a Federation Entity Key could not be sealed; see the ' +
                      'keystore errors above.');
    }
    log.debug("Leaving FederationKeys.sealed().");
    return { privateKey: closed, sealed: true };
  }

  // The private key of a row, ready to sign with, or null — a key sealed
  // under a key-encryption key this process does not hold.
  private opened(row: Json): Json {
    const { log, keystore, errorCodes } = this.deps;
    log.debug("Entering FederationKeys.opened(). kid=" + row.kid);
    const text = row.sealed ? keystore.open(String(row.privateKey),
                                            SEAL_LABEL)
                            : String(row.privateKey || '');
    if (!text) {
      log.error(errorCodes.tag('STS-OIDFED-0040') + 'oidfed: the Federation ' +
                'Entity Key ' + row.kid + ' is sealed under a key-encryption ' +
                'key this process does not hold, so this realm signs no ' +
                'federation statement. Rotate the key.');
      log.debug("Leaving FederationKeys.opened(). Not opened.");
      return null;
    }
    try {
      const held = JSON.parse(text);
      const out = held.b64 ? Buffer.from(held.b64, 'base64')
                           : nodeCrypto.createPrivateKey(String(held.pem));
      log.debug("Leaving FederationKeys.opened().");
      return out;
    } catch (e: any) {
      log.debug("Caught in FederationKeys.opened(): " +
                ((e && e.message) || e));
      log.debug("Leaving FederationKeys.opened(). Unreadable.");
      return null;
    }
  }

  private async mint(state: string): Promise<Json> {
    const { log, makeKey, now } = this.deps;
    const alg = this.algorithm();
    log.debug("Entering FederationKeys.mint(). " + state + ", " + alg);
    const made = await makeKey(alg);
    const closed = this.sealed(made.privateKey);
    const at = now();
    const row = { v: ROW_VERSION, kid: made.publicJwk.kid, alg: alg,
                  publicJwk: made.publicJwk, privateKey: closed.privateKey,
                  sealed: closed.sealed, state: state, createdAt: at,
                  activatedAt: state === 'current' ? at : 0, retiredAt: 0,
                  publishedUntil: 0, revokedAt: 0, revokedReason: '' };
    log.debug("Leaving FederationKeys.mint(). kid=" + row.kid);
    return row;
  }

  // -------------------------------------------------------------------------
  // THERE IS A CURRENT KEY — minting one where there is none, once for the
  // cluster: the minting is a claim, and a node that loses it reads back the
  // winner's row. Resolves the rows as they now stand.
  // -------------------------------------------------------------------------
  async ensure(): Promise<Json[]> {
    const { log, store, claims, realms } = this.deps;
    log.debug("Entering FederationKeys.ensure().");
    let rows = this.rows();
    if (rows.some(function (r: Json): boolean {
      return r.state === 'current';
    })) {
      log.debug("Leaving FederationKeys.ensure(). Held.");
      return rows;
    }
    const realmId = String(realms.current().id || '');
    const claimed: Json = await claims().claim({ scope: MINT_SCOPE,
      value: realmId + ':' + rows.length, ttlMs: 60000 });
    if (!claimed.ok) {
      // Another node is minting it. Its row arrives with the directory's
      // next change; until then this realm has no key to sign with.
      rows = this.rows();
      log.debug("Leaving FederationKeys.ensure(). Minted elsewhere.");
      return rows;
    }
    const made = await this.mint('current');
    rows = this.rows().concat([made]);
    store.writeKeyRows(rows);
    this.record('oidfed.key-minted', { kid: made.kid, alg: made.alg });
    log.debug("Leaving FederationKeys.ensure(). Minted " + made.kid + ".");
    return rows;
  }

  // The signer of the CURRENT key: `{ key, alg, kid }`, or null when there is
  // none or it will not open.
  async signer(): Promise<Signer | null> {
    const { log } = this.deps;
    log.debug("Entering FederationKeys.signer().");
    const rows = await this.ensure();
    const current = rows.filter(function (r: Json): boolean {
      return r.state === 'current';
    })[0];
    if (!current) {
      log.debug("Leaving FederationKeys.signer(). No current key.");
      return null;
    }
    const key = this.opened(current);
    log.debug("Leaving FederationKeys.signer(). " + (key ? current.kid : ''));
    return key ? { key: key, alg: current.alg, kid: current.kid } : null;
  }

  // -------------------------------------------------------------------------
  // THE KEYS THE ENTITY CONFIGURATION PUBLISHES (3.1.1): the current one, the
  // `next` one, and each retired one inside its overlap — never a revoked
  // one. Public halves only, each with its `kid`.
  // -------------------------------------------------------------------------
  jwks(rowsIn?: Json[]): Json {
    const { log, now } = this.deps;
    log.debug("Entering FederationKeys.jwks().");
    const at = now();
    const keys = (rowsIn || this.rows()).filter(function (r: Json): boolean {
      if (r.revokedAt) {
        return false;
      }
      return r.state === 'current' || r.state === 'next' ||
             (r.state === 'retired' && Number(r.publishedUntil) > at);
    }).map(function (r: Json): Json {
      return Object.assign({}, r.publicJwk);
    });
    log.debug("Leaving FederationKeys.jwks(). " + keys.length);
    return { keys: keys };
  }

  // -------------------------------------------------------------------------
  // THE HISTORICAL KEYS (8.7.2): every key that has STOPPED being usable —
  // retired or revoked — with `iat` when it was made, `exp` when it stopped
  // being valid, and `revoked` with its reason where it was revoked. A
  // current or next key is not historical and is not listed.
  // -------------------------------------------------------------------------
  historical(): Json[] {
    const { log } = this.deps;
    log.debug("Entering FederationKeys.historical().");
    const out = this.rows().filter(function (r: Json): boolean {
      return r.state === 'retired' || !!r.revokedAt;
    }).map(function (r: Json): Json {
      const jwk: Json = Object.assign({}, r.publicJwk);
      jwk.iat = Math.floor(Number(r.createdAt) / 1000);
      // When it stopped being valid: the end of its overlap, or its
      // revocation if that came first. A key revoked AFTER its overlap ended
      // keeps the earlier `exp` and gains `revoked` (8.7: "an expired key can
      // be later additionally marked as revoked").
      const published = Number(r.publishedUntil || r.retiredAt) ||
                        Number(r.revokedAt);
      const ended = r.revokedAt ? Math.min(Number(r.revokedAt), published)
                                : published;
      jwk.exp = Math.floor(ended / 1000);
      if (r.revokedAt) {
        jwk.revoked = { revoked_at: Math.floor(Number(r.revokedAt) / 1000) };
        if (r.revokedReason && r.revokedReason !== 'unspecified') {
          jwk.revoked.reason = r.revokedReason;
        }
      }
      return jwk;
    }).sort(function (a: Json, b: Json): number {
      return b.iat - a.iat;
    });
    log.debug("Leaving FederationKeys.historical(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // ROTATE (11.2): the `next` key becomes current (one is minted where there
  // is none), the current one is RETIRED — its private key dropped, its
  // public half published through the overlap — and a fresh `next` is made
  // so the published set is one rotation ahead again. With `emergency`, the
  // current and next keys are REVOKED as `compromised` rather than retired,
  // and leave the published set at once.
  // -------------------------------------------------------------------------
  async rotate(options?: Json): Promise<Json> {
    const { log, store, now } = this.deps;
    const o = options || {};
    log.debug("Entering FederationKeys.rotate(). emergency=" + !!o.emergency);
    const at = now();
    let rows = this.rows();
    const current = rows.filter(function (r: Json): boolean {
      return r.state === 'current';
    })[0];
    let next = rows.filter(function (r: Json): boolean {
      return r.state === 'next';
    })[0];
    if (o.emergency && next) {
      next.state = 'retired';
      next.privateKey = '';
      next.sealed = false;
      next.retiredAt = at;
      next.publishedUntil = at;
      next.revokedAt = at;
      next.revokedReason = 'compromised';
      next = null;
    }
    const promoted = next || await this.mint('next');
    promoted.state = 'current';
    promoted.activatedAt = at;
    if (!next) {
      rows = rows.concat([promoted]);
    }
    if (current) {
      current.state = 'retired';
      current.privateKey = '';
      current.sealed = false;
      current.retiredAt = at;
      current.publishedUntil = o.emergency ? at : at + this.overlapMs();
      if (o.emergency) {
        current.revokedAt = at;
        current.revokedReason = 'compromised';
      }
    }
    const fresh = await this.mint('next');
    rows = rows.concat([fresh]);
    store.writeKeyRows(rows);
    this.record(o.emergency ? 'oidfed.key-revoked' : 'oidfed.key-rotated',
                { from: current ? current.kid : '', to: promoted.kid,
                  next: fresh.kid, reason: o.reason || '' });
    log.debug("Leaving FederationKeys.rotate(). " + promoted.kid +
              " is current.");
    return { ok: true, from: current ? current.kid : '', to: promoted.kid,
             next: fresh.kid, emergency: !!o.emergency };
  }

  // -------------------------------------------------------------------------
  // REVOKE ONE KEY BY HAND (8.7.3), with a reason. A retired key is marked;
  // the current or next key cannot be revoked without an emergency
  // rotation, so it is refused here and the caller is told which to use.
  // -------------------------------------------------------------------------
  revoke(kid: string, reason: string): Json {
    const { log, store, now } = this.deps;
    log.debug("Entering FederationKeys.revoke(). kid=" + kid);
    const why = REASONS.indexOf(String(reason)) >= 0 ? String(reason)
                                                      : 'unspecified';
    const rows = this.rows();
    const row = rows.filter(function (r: Json): boolean {
      return r.kid === kid;
    })[0];
    if (!row) {
      log.debug("Leaving FederationKeys.revoke(). No such key.");
      return { ok: false, code: 'STS-OIDFED-0041', status: 404,
               why: 'this realm holds no Federation Entity Key "' + kid +
                    '".' };
    }
    if (row.state !== 'retired') {
      log.debug("Leaving FederationKeys.revoke(). Not retired.");
      return { ok: false, code: 'STS-OIDFED-0042', status: 409,
               why: 'the ' + row.state + ' key is revoked by an EMERGENCY ' +
                    'rotation, which replaces it at once; a retired key is ' +
                    'revoked here.' };
    }
    const at = now();
    row.revokedAt = row.revokedAt || at;
    row.revokedReason = why;
    row.publishedUntil = Math.min(Number(row.publishedUntil) || at, at);
    store.writeKeyRows(rows);
    this.record('oidfed.key-revoked', { kid: kid, reason: why });
    log.debug("Leaving FederationKeys.revoke().");
    return { ok: true, kid: kid, reason: why };
  }

  // The table as a page or the API shows it: never a private key.
  view(): Json[] {
    const { log } = this.deps;
    log.debug("Entering FederationKeys.view().");
    const iso = function (ms: Json): string | null {
      log.debug("Entering iso().");
      log.debug("Leaving iso().");
      return Number(ms) > 0 ? new Date(Number(ms)).toISOString() : null;
    };
    const out = this.rows().map(function (r: Json): Json {
      return { kid: r.kid, alg: r.alg, state: r.state, sealed: !!r.sealed,
               createdAt: iso(r.createdAt), activatedAt: iso(r.activatedAt),
               retiredAt: iso(r.retiredAt),
               publishedUntil: iso(r.publishedUntil),
               revokedAt: iso(r.revokedAt),
               revokedReason: r.revokedReason || null,
               publicJwk: r.publicJwk };
    });
    log.debug("Leaving FederationKeys.view(). " + out.length);
    return out;
  }

  private record(event: string, detail: Json): void {
    const { log, realms } = this.deps;
    log.debug("Entering FederationKeys.record(). " + event);
    try {
      this.deps.audit().record({
        category: 'service', action: event, actor: '',
        target: String(detail.kid || detail.to || ''),
        outcome: 'success',
        summary: 'Federation Entity Key ' + event.replace('oidfed.key-', '') +
                 ' in the "' + String(realms.current().id || '') +
                 '" realm: ' + JSON.stringify(detail) });
    } catch (e: any) {
      log.debug("Caught in FederationKeys.record(): " +
                ((e && e.message) || e));
    }
    log.info('oidfed: ' + event + ' ' + JSON.stringify(detail));
    log.debug("Leaving FederationKeys.record().");
  }

  // -------------------------------------------------------------------------
  // THE SCHEDULED STEP, per realm: a key where there is none, a `next` key
  // where there is none, and a rotation once the current key is older than
  // `oidfed.keyRotationDays` AND the next one has been published for the
  // whole overlap — so a key is never promoted that entities may not have
  // fetched yet.
  // -------------------------------------------------------------------------
  async scheduledStep(): Promise<Json> {
    const { log, store, config, now } = this.deps;
    log.debug("Entering FederationKeys.scheduledStep().");
    let rows = await this.ensure();
    const at = now();
    const current = rows.filter(function (r: Json): boolean {
      return r.state === 'current';
    })[0];
    const next = rows.filter(function (r: Json): boolean {
      return r.state === 'next';
    })[0];
    if (!next) {
      const made = await this.mint('next');
      rows = rows.concat([made]);
      store.writeKeyRows(rows);
      log.debug("Leaving FederationKeys.scheduledStep(). A next key.");
      return { minted: made.kid };
    }
    const ageMs = current ? at - Number(current.activatedAt ||
                                        current.createdAt) : 0;
    const dueMs = Math.max(1, Number(config.value('oidfed.keyRotationDays'))) *
                  DAY_MS;
    if (current && ageMs >= dueMs &&
        at - Number(next.createdAt) >= this.overlapMs()) {
      const out = await this.rotate({ reason: 'scheduled' });
      log.debug("Leaving FederationKeys.scheduledStep(). Rotated.");
      return out;
    }
    log.debug("Leaving FederationKeys.scheduledStep(). Nothing due.");
    return { due: false };
  }

  // The two jobs (#49): the schedule, product only, and the rotation by
  // hand, in every mode.
  scheduleJobs(): void {
    const { log, scheduler, mode } = this.deps;
    const self = this;
    log.debug("Entering FederationKeys.scheduleJobs().");
    const s = scheduler();
    if (s.job(ROTATE_JOB)) {
      log.debug("Leaving FederationKeys.scheduleJobs(). Registered.");
      return;
    }
    s.register({
      id: ROTATE_JOB,
      title: 'OpenID Federation key rotation',
      describe: 'Keeps each realm\'s Federation Entity Keys one rotation ' +
                'ahead — a next key published before it signs — and ' +
                'rotates once the current key is older than ' +
                'oidfed.keyRotationDays and the next has been published for ' +
                'the whole oidfed.keyOverlapDays.',
      owner: 'oidfed/federation_keys.ts',
      kind: 'cluster', scope: 'realm', everyMs: function (): number {
        return 3600000;
      },
      off: function (): string {
        return mode().rotatesSigningKeys() ? ''
          : 'development mode: a development process\'s keys are new at ' +
            'every start';
      },
      manual: true,
      run: function (): Promise<Json> {
        return self.scheduledStep();
      }
    });
    s.register({
      id: ROTATE_NOW_JOB,
      title: 'OpenID Federation key rotation, by hand',
      describe: 'Rotates the realm\'s Federation Entity Key now — or, as an ' +
                'emergency, revokes the current and next keys as ' +
                'compromised and replaces them.',
      owner: 'oidfed/federation_keys.ts',
      kind: 'cluster', scope: 'realm', manualOnly: true, manual: true,
      run: function (ctx: Json): Promise<Json> {
        const p = (ctx && ctx.params) || {};
        return self.rotate({ emergency: !!p.emergency,
                             reason: String(p.reason || 'by hand') });
      }
    });
    log.debug("Leaving FederationKeys.scheduleJobs(). On the scheduler.");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). The wire step
// registers the two scheduler jobs (#49).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<FederationKeys>(
  'oidfed/federation_keys',
  () => new FederationKeys(FederationKeys.defaultDeps()),
  function (instance: FederationKeys): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  FederationKeys: FederationKeys,
  installInstance: (instance: FederationKeys): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SEAL_LABEL: SEAL_LABEL,
  ROTATE_JOB: ROTATE_JOB,
  ROTATE_NOW_JOB: ROTATE_NOW_JOB,
  REASONS: REASONS,
  algorithm: slot.forward('algorithm'),
  ensure: slot.forward('ensure'),
  signer: slot.forward('signer'),
  jwks: slot.forward('jwks'),
  historical: slot.forward('historical'),
  rotate: slot.forward('rotate'),
  revoke: slot.forward('revoke'),
  view: slot.forward('view')
};
