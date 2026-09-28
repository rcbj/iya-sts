// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: signing_rotation.ts
//
// ===========================================================================
// SIGNING KEY ROTATION, ON THE SCHEDULER (2026-09-22, #42 P3; #48's emergency
// form in P4).
//
// The key GENERATIONS are `common/helpers.js`'s (KEY GENERATIONS): a unit —
// (realm, use case, algorithm) — has a CURRENT key, a NEXT one published
// before it signs anything, and RETIRED ones verifying through their grace.
// This module decides WHEN a unit moves on, and does nothing to a key itself:
// every change goes through `helpers.ensureNextGenerations()`,
// `promoteGenerations()` and `retireExpiredGenerations()`, so there is still
// one place keys are made and one door (`keystore.replaceKeySet()`) by which
// a realm's set changes while in use.
//
// THREE JOBS, ALL PER REALM, ALL CLUSTER JOBS (run once, on the leader):
//
//   `signing.rotate`   every hour. A unit with no next key is given one; a
//                      unit whose next key has been PUBLISHED FOR A WHOLE
//                      INTERVAL is promoted. So a key's working life is one
//                      interval and the key after it was in every published
//                      document for the whole of that — which is the overlap
//                      a relying party that refreshes its JWKS, or its SAML
//                      metadata, less often than daily depends on. Hourly
//                      because the decision is per unit and cheap, and a
//                      schedule at the interval itself would make the first
//                      rotation of a fresh install land at an arbitrary slot
//                      boundary rather than one interval after its keys were
//                      published.
//   `signing.retire`   every hour. Drops each retired key past its grace and
//                      supersedes its certificate on its Issuing CA's CRL.
//   `signing.rotate-now`  manual only, in EVERY mode: the rotation an
//                      administrator asks for (`/admin/keys`,
//                      `POST /admin-api/keys/rotate`).
//
// **THE SCHEDULE IS OFF IN DEVELOPMENT MODE** (`mode.rotatesSigningKeys()`):
// its keys are made anew at every start. `signing.rotate-now` is not, because
// a rotation by hand is how a person exercises one there.
//
// THE GRACE is `signing.retiredKeyGraceDays` or the longest lifetime of
// anything the key could have signed, whichever is longer — the tokens and
// assertions of every family, and for the VERIFIABLE CREDENTIAL signer (D3)
// every credential lifetime as well, so a credential issued the minute before
// a rotation still verifies until it expires. That signer rotates on
// `signing.credentialRotationIntervalDays` when it is a unit of its own
// (`oid4vci.credentialSigningAlgorithm` naming an algorithm tokens are not
// signed with) and on the token interval when it shares one — the shorter of
// the two is kept, never the longer, and the grace is what protects the
// credentials.
//
// AFTER EACH ROTATION a Shared Signals event of this service's own vocabulary
// is transmitted (D4, `ssf.signingKeyRotated()`), and one audit row is
// written per act.
//
// A LIBRARY THAT REGISTERS JOBS AND NO ROUTE, built by
// `common/protocol_stack.ts` after `ssf/ssf` (23b-ii). Its console controls
// are `/admin/keys`'s and its API is `/admin-api/keys/rotate`, both of which
// queue a run of `signing.rotate-now` rather than rotating in the request.
// ===========================================================================

import helpers = require('./helpers');
import config = require('./config');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

type Json = any;

/**
 * The hourly scheduled rotation job's id.
 */
const ROTATE_JOB = 'signing.rotate';
/**
 * The id of the manual rotation job the console and the API queue.
 */
const ROTATE_NOW_JOB = 'signing.rotate-now';
/**
 * The hourly job's id that drops retired keys past their grace.
 */
const RETIRE_JOB = 'signing.retire';
const SECRET_EXPIRY_JOB = 'oauth2.client-secret-expiry';
const CHECK_EVERY_MS = 3600000;
const DAY_MS = 86400000;
// The clock skew every verifier here allows, added to the grace so that a
// token minted in the last second of a key's life still verifies at its `exp`
// on a clock running slightly behind.
const SKEW_MS = 300000;

// Every lifetime a signed thing can have, and the unit of the setting.
const TOKEN_LIFETIMES: [string, number][] = [
  ['oauth2.accessTokenTtlS', 1000], ['oauth2.idTokenTtlS', 1000],
  ['oauth2.refreshTokenTtlS', 1000], ['gnap.accessTokenLifetimeS', 1000],
  ['saml2.assertionLifetimeMin', 60000], ['saml11.assertionLifetimeMin', 60000],
  ['wsfed.assertionLifetimeMin', 60000], ['wstrust.maxTokenLifetimeMin', 60000],
  ['oauth2.softwareStatementLifetimeS', 1000]
];
const CREDENTIAL_LIFETIMES: [string, number][] = [
  ['oid4vci.credentialLifetimeS', 1000],
  ['oid4vci.generatedDidCredentialLifetimeS', 1000],
  ['oid4vci.domainLinkageLifetimeS', 1000],
  ['oid4vci.statusListLifetimeS', 1000]
];

interface SigningRotationDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  // Lazily, each: the scheduler requires `helpers`, the mode module is a
  // leaf, and the audit log, the PKI and Shared Signals load later than this
  // module is built only in a test.
  scheduler: () => Json;
  mode: () => Json;
  audit: () => Json;
  pki: () => Json;
  revocation: () => Json;
  ssf: () => Json;
  applications: () => Json;
  authn: () => Json;
  // The signing-key history (#42's follow-up). Lazy like the rest, and
  // OBSERVED rather than told: it derives its rows from the key set, so
  // every path that changes a key is covered by a call at the end of it.
  history: () => Json;
  now: () => number;
}

/**
 * Decides when a realm's signing-key units move on, and runs the rotation
 * and retirement jobs on the scheduler.
 *
 * It changes no key itself: every change goes through `helpers`' generation
 * functions. The schedule is off in development mode; a rotation asked for
 * by hand runs in every mode.
 */
class SigningRotation {
  // The pinned keys warned about today (#263), `scope|kid` to the day number,
  // so the hourly `signing.retire` says it once a day. As many entries as
  // there are pinned keys near their end.
  private readonly pinWarned = new Map<string, number>();
  /**
   * The module's `ROTATE_JOB`.
   */
  static readonly ROTATE_JOB = ROTATE_JOB;
  /**
   * The module's `ROTATE_NOW_JOB`.
   */
  static readonly ROTATE_NOW_JOB = ROTATE_NOW_JOB;
  /**
   * The module's `RETIRE_JOB`.
   */
  static readonly RETIRE_JOB = RETIRE_JOB;

  /**
   * Builds the instance over its dependencies.
   *
   * @param deps - the modules it uses, most of them reached lazily, and a clock
   */
  constructor(private readonly deps: SigningRotationDeps) {
    deps.log.debug("Entering SigningRotation.constructor().");
    deps.log.debug("Leaving SigningRotation.constructor().");
  }

  /**
   * Returns the dependencies the composition root builds the instance with.
   *
   * @returns the real modules and `Date.now`
   */
  static defaultDeps(): SigningRotationDeps {
    helpers.log.debug("Entering SigningRotation.defaultDeps().");
    helpers.log.debug("Leaving SigningRotation.defaultDeps().");
    return {
      log: helpers.log,
      helpers: helpers,
      config: config,
      realms: realms,
      errorCodes: errorCodes,
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      mode: function (): Json {
        return require('./mode');
      },
      audit: function (): Json {
        return require('./audit');
      },
      pki: function (): Json {
        return require('./pki');
      },
      revocation: function (): Json {
        return require('./pki_revocation');
      },
      ssf: function (): Json {
        return require('../ssf/ssf');
      },
      applications: function (): Json {
        return require('./applications');
      },
      authn: function (): Json {
        return require('../authn/authn');
      },
      history: function (): Json {
        return require('./signing_history');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // The longest of a list of lifetime settings, in milliseconds.
  private longest(rows: [string, number][]): number {
    const { log, config, applications } = this.deps;
    log.debug("Entering SigningRotation.longest().");
    let most = 0;
    rows.forEach(function (row: [string, number]): void {
      let v = 0;
      try {
        // The largest a client's own entry sets it to, where the setting is
        // per-application — a key signs every client's tokens.
        v = Number(applications().largestSetting(row[0], config)) * row[1];
      } catch (e) {
        // A setting this build does not have is no lifetime at all.
        log.debug("Caught in SigningRotation.longest(): " +
                  ((e && e.message) || e));
        v = 0;
      }
      if (v > most) {
        most = v;
      }
    });
    log.debug("Leaving SigningRotation.longest(). " + most + "ms.");
    return most;
  }

  // The unit an algorithm signs with in this realm, or ''.
  /**
   * Returns the signing unit a JWS algorithm signs with in this realm; any RSA
   * algorithm signs with `jose:RS256`.
   *
   * @param alg - a JWS algorithm
   * @param keys - optional key set; the ambient realm's by default
   * @returns the unit, or '' when none signs it
   */
  unitForAlg(alg: string, keys?: Json): string {
    const { log, helpers } = this.deps;
    log.debug("Entering SigningRotation.unitForAlg(). " + alg);
    if (/^(RS|PS)\d+$/.test(alg)) {
      log.debug("Leaving SigningRotation.unitForAlg(). RSA.");
      return 'jose:RS256';
    }
    const set = keys || helpers.stsKeysFor();
    const units = helpers.signingUnitsOf(set);
    const byAlg = units.filter(function (u: Json): boolean {
      return u.kind === 'pq' && u.alg === alg;
    })[0];
    if (byAlg) {
      log.debug("Leaving SigningRotation.unitForAlg(). " + byAlg.unit);
      return byAlg.unit;
    }
    let kid = '';
    try {
      kid = String((helpers.signingKeyFor(alg) || {}).kid || '');
    } catch (e) {
      log.debug("Caught in SigningRotation.unitForAlg(): " +
                ((e && e.message) || e));
      kid = '';
    }
    // A PINNED key (#263) is no unit of the set; the unit is its slot's.
    if (kid.indexOf('sts-pinned-') === 0) {
      log.debug("Leaving SigningRotation.unitForAlg(). A pinned key.");
      return 'jose:' + helpers.joseSlotForAlg(alg);
    }
    const byKid = units.filter(function (u: Json): boolean {
      return !!kid && u.kid === kid;
    })[0];
    log.debug("Leaving SigningRotation.unitForAlg(). " +
              (byKid ? byKid.unit : 'none'));
    return byKid ? byKid.unit : '';
  }

  // The unit `oid4vci.credentialSigningAlgorithm` signs with, or ''.
  /**
   * Returns the unit `oid4vci.credentialSigningAlgorithm` signs with.
   *
   * @param keys - optional key set; the ambient realm's by default
   * @returns the unit, or ''
   */
  credentialUnit(keys?: Json): string {
    const { log, config } = this.deps;
    log.debug("Entering SigningRotation.credentialUnit().");
    const unit = this.unitForAlg(String(config.value(
      'oid4vci.credentialSigningAlgorithm') || 'RS256'), keys);
    log.debug("Leaving SigningRotation.credentialUnit(). " + unit);
    return unit;
  }

  // Does a TOKEN setting sign with this unit? The RSA unit always does (every
  // token family's default); another does when one of the service-wide
  // algorithm settings names it. A client's own registered algorithm is not
  // asked — a token signed that way on a unit rotating on the credential
  // interval still verifies through the same grace.
  private sharedWithTokens(unit: string, keys?: Json): boolean {
    const { log, config } = this.deps;
    log.debug("Entering SigningRotation.sharedWithTokens(). " + unit);
    if (unit === 'jose:RS256') {
      log.debug("Leaving SigningRotation.sharedWithTokens(). The RSA signer.");
      return true;
    }
    const self = this;
    const shared = ['oauth2.signedMetadataAlgorithm', 'ssf.signingAlgorithm',
                    'wstrust.jwtAlgorithm'].some(function (key: string) {
      return self.unitForAlg(String(config.value(key) || 'RS256'), keys) ===
             unit;
    });
    log.debug("Leaving SigningRotation.sharedWithTokens(). " + shared);
    return shared;
  }

  // How long a unit's key works before its next one is promoted.
  /**
   * Returns how long a unit's key works before its next key is promoted.
   *
   * A credential-only signer uses `signing.credentialRotationIntervalDays`; a
   * unit tokens also sign with keeps the shorter of the two intervals.
   * @param unit - the signing unit
   * @param keys - optional key set
   * @returns the interval in milliseconds (0 means off)
   */
  intervalMs(unit: string, keys?: Json): number {
    const { log, config } = this.deps;
    log.debug("Entering SigningRotation.intervalMs(). " + unit);
    const tokens = Number(config.value('signing.rotationIntervalDays')) *
                   DAY_MS;
    // The BBS key signs ldp_vc credentials and nothing else (#49 P5): the
    // credential interval, never shared with a token signer. So does the
    // CREDENTIALS signer group's every unit (#68), which signs credentials,
    // status lists and nothing a token uses — that is what a group is.
    if (unit === 'bbs:BBS' || this.isCredentialGroupUnit(unit)) {
      const bbsEvery = Number(config.value(
        'signing.credentialRotationIntervalDays')) * DAY_MS;
      log.debug("Leaving SigningRotation.intervalMs(). " + bbsEvery +
                "ms (the BBS credential signer).");
      return bbsEvery;
    }
    if (unit !== this.credentialUnit(keys)) {
      log.debug("Leaving SigningRotation.intervalMs(). " + tokens + "ms.");
      return tokens;
    }
    const credentials = Number(config.value(
      'signing.credentialRotationIntervalDays')) * DAY_MS;
    // A unit tokens also sign with keeps the TOKEN interval — the shorter,
    // never the longer (0 meaning off, in either).
    const answer = this.sharedWithTokens(unit, keys)
      ? (tokens > 0 && credentials > 0 ? Math.min(tokens, credentials)
                                       : tokens)
      : credentials;
    log.debug("Leaving SigningRotation.intervalMs(). " + answer +
              "ms (the credential signer).");
    return answer;
  }

  // Is this one of the credentials signer group's units (#68)? `jose:` then
  // the group's slot prefix — `common/signer_groups.js` names the group.
  private isCredentialGroupUnit(unit: string): boolean {
    const { log } = this.deps;
    log.debug("Entering SigningRotation.isCredentialGroupUnit(). " + unit);
    log.debug("Leaving SigningRotation.isCredentialGroupUnit().");
    return String(unit || '').indexOf('jose:credentials/') === 0;
  }

  // How long a key goes on verifying after it is retired.
  /**
   * Returns how long a retired key goes on verifying: the setting, or the
   * longest lifetime of anything it could have signed (credentials included for
   * a credential signer) plus clock skew, whichever is longer.
   *
   * @param unit - the signing unit
   * @param keys - optional key set
   * @returns the grace in milliseconds
   */
  graceMs(unit: string, keys?: Json): number {
    const { log, config } = this.deps;
    log.debug("Entering SigningRotation.graceMs(). " + unit);
    const setting = Number(config.value('signing.retiredKeyGraceDays')) *
                    DAY_MS;
    let derived = this.longest(TOKEN_LIFETIMES);
    if (unit === this.credentialUnit(keys) || unit === 'bbs:BBS' ||
        this.isCredentialGroupUnit(unit)) {
      // Plus an hour: an issued credential's `exp` is rounded UP to the hour
      // (`oid4vc/vc_issuer.ts` unlinkableTimes(), #187), so it may outlive
      // its lifetime by as much.
      derived = Math.max(derived, this.longest(CREDENTIAL_LIFETIMES) +
                                  3600000);
    }
    const answer = Math.max(setting, derived + SKEW_MS);
    log.debug("Leaving SigningRotation.graceMs(). " + answer + "ms.");
    return answer;
  }

  // How long a retired refresh-token key set goes on OPENING tokens (D7): the
  // longest refresh token any client is issued, or the setting if longer.
  /**
   * Returns how long a retired refresh-token key set goes on opening tokens:
   * the longest refresh-token lifetime plus skew, or the setting if longer.
   *
   * @returns the grace in milliseconds
   */
  refreshGraceMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering SigningRotation.refreshGraceMs().");
    const setting = Number(config.value('signing.retiredKeyGraceDays')) *
                    DAY_MS;
    const answer = Math.max(setting,
      this.longest([['oauth2.refreshTokenTtlS', 1000]]) + SKEW_MS);
    log.debug("Leaving SigningRotation.refreshGraceMs(). " + answer + "ms.");
    return answer;
  }

  // Is the refresh-token key set due? Once it has been in use for a whole
  // token interval: from its last rotation, or — never rotated — from when
  // this realm's first next key was published, which is when rotation began.
  private refreshDue(keys: Json, now: number): boolean {
    const { log, helpers, config } = this.deps;
    log.debug("Entering SigningRotation.refreshDue().");
    const every = Number(config.value('signing.rotationIntervalDays')) *
                  DAY_MS;
    const g = keys.generations || {};
    let since = Number((g.rotated || {})['refresh:enc']) || 0;
    if (!since) {
      since = helpers.standbyOf(keys).reduce(function (min: number,
                                                       one: Json): number {
        const at = Number(one.createdAt) || 0;
        return at && (!min || at < min) ? at : min;
      }, 0);
    }
    const due = every > 0 && since > 0 && now - since >= every;
    log.debug("Leaving SigningRotation.refreshDue(). " + due);
    return due;
  }

  // Why rotation is off for a realm right now, or ''.
  /**
   * Says why scheduled rotation is off for the ambient realm.
   *
   * @returns the reason, or '' when rotation is on
   */
  offReason(): string {
    const { log, config, mode } = this.deps;
    log.debug("Entering SigningRotation.offReason().");
    if (!mode().rotatesSigningKeys()) {
      log.debug("Leaving SigningRotation.offReason(). Development.");
      return 'development mode, whose keys are made anew at every start';
    }
    if (!(Number(config.value('signing.rotationIntervalDays')) > 0)) {
      log.debug("Leaving SigningRotation.offReason(). Interval 0.");
      return 'signing.rotationIntervalDays is 0';
    }
    log.debug("Leaving SigningRotation.offReason(). On.");
    return '';
  }

  // ---------------------------------------------------------------------------
  // THE SCHEDULED ROTATION of one realm: a next key for every unit lacking
  // one, and every unit whose next key has been published for a whole
  // interval promoted. Resolves `{ minted, rotated, generation }`.
  // ---------------------------------------------------------------------------
  // THE HISTORY (#42's follow-up, 2026-09-22). Every path that changes a key
  // ends here, and what is written is DERIVED from the key set rather than
  // from the act — see `common/signing_history.ts`'s header for why, and why
  // a caller that forgot would lose only the promptness of the record.
  //
  // It never throws and its answer is not read: a rotation that has already
  // happened must not be reported as failed because a record of it could not
  // be written, and the module logs STS-KEYS-0067 where it could not.
  // ---------------------------------------------------------------------------
  private noteHistory(realmId: string, reason: string): void {
    const { log, history } = this.deps;
    log.debug("Entering SigningRotation.noteHistory(). realm=" + realmId);
    try {
      history().observe(realmId, { reason: reason });
    } catch (e) {
      // No history module in this process, or a store that refused: the keys
      // are what they are either way.
      log.debug("Caught in SigningRotation.noteHistory(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving SigningRotation.noteHistory().");
  }

  // ---------------------------------------------------------------------------
  /**
   * Runs the scheduled rotation of one realm: a next key for every unit
   * lacking one, and every unit whose next key has been published for a whole
   * interval promoted. A pinned unit is left alone.
   *
   * @param realmId - the realm id
   * @param ctx - optional scheduler context: `nowMs`, `stillOwner`, `trigger`
   * @returns a promise of `{ minted, rotated, generation }`, with `abandoned`
   *   when the node stopped owning the job midway
   */
  async rotateDue(realmId: string, ctx?: Json): Promise<Json> {
    const { log, helpers } = this.deps;
    log.debug("Entering SigningRotation.rotateDue(). realm=" + realmId);
    const keys = helpers.stsKeysFor.of(realmId);
    const now = ctx && ctx.nowMs ? ctx.nowMs() : this.deps.now();
    const lacking: string[] = [];
    const due: string[] = [];
    const self = this;
    // A UNIT AN OPERATOR PINNED (#263) is exempt while the pin signs or is
    // about to: its lifecycle is theirs, and a promotion under it would
    // announce a rotation of a key the realm is not signing with.
    const pinned = this.pinnedUnits(String(keys.realm || realmId));
    helpers.signingUnitsOf(keys).forEach(function (u: Json): void {
      if (pinned.indexOf(u.unit) >= 0) {
        return;
      }
      const next = helpers.standbyOf(keys, u.unit)
        .filter(function (one: Json): boolean {
          return one.role === 'next';
        })[0];
      const every = self.intervalMs(u.unit, keys);
      if (!next) {
        lacking.push(u.unit);
      } else if (every > 0 && now - Number(next.createdAt) >= every) {
        due.push(u.unit);
      }
    });
    let minted: Json = { minted: [] };
    if (lacking.length) {
      minted = await helpers.ensureNextGenerations(realmId,
                                                   { units: lacking });
    }
    if (ctx && ctx.stillOwner && !ctx.stillOwner()) {
      log.debug("Leaving SigningRotation.rotateDue(). No longer the owner.");
      return { minted: minted.minted, rotated: [], abandoned: true };
    }
    if (this.refreshDue(helpers.stsKeysFor.of(realmId), now)) {
      due.push('refresh:enc');
    }
    if (!due.length) {
      // The next keys minted above are new generations even though nothing
      // rotated, so they are recorded here rather than only at a promotion.
      this.noteHistory(realmId, 'a next key minted');
      log.debug("Leaving SigningRotation.rotateDue(). Nothing due.");
      return { minted: minted.minted, rotated: [],
               generation: minted.generation };
    }
    const done = await this.rotate(realmId, { units: due,
      reason: 'scheduled', trigger: (ctx && ctx.trigger) || 'schedule' });
    log.debug("Leaving SigningRotation.rotateDue().");
    return { minted: minted.minted, rotated: done.rotated,
             generation: done.generation };
  }

  // ---------------------------------------------------------------------------
  // ROTATE NOW — the named units (or every unit), each by its OWN grace, then
  // the audit row and the Shared Signals event. What P4's controls queue.
  // ---------------------------------------------------------------------------
  /**
   * Rotates the named units (or every unit and the refresh-token keys) now,
   * each retired key keeping its own grace, then writes the audit row and sends
   * the Shared Signals event.
   *
   * An emergency rotation drops the retired keys at once, revokes the units'
   * certificates for keyCompromise and ends every session in the realm.
   * @param realmId - the realm id
   * @param options - optional `{ units, emergency, reason, trigger,
   *   requestedBy }`
   * @returns a promise of `{ rotated, generation, revoked, sessionsEnded }`
   */
  async rotate(realmId: string, options?: Json): Promise<Json> {
    const { log, helpers, audit, errorCodes } = this.deps;
    const o = options || {};
    log.debug("Entering SigningRotation.rotate(). realm=" + realmId);
    const keys = helpers.stsKeysFor.of(realmId);
    const wanted = helpers.signingUnitsOf(keys).filter(function (u: Json) {
      return !o.units || !o.units.length || o.units.indexOf(u.unit) >= 0 ||
             o.units.indexOf(u.useCase) >= 0;
    });
    // AN EMERGENCY (#48): every key of every unit named is presumed
    // compromised. Its certificates are revoked FIRST, as keyCompromise —
    // a certificate already revoked keeps its first reason, and the
    // promotion's own certification would otherwise supersede them — then
    // the units rotate with no grace, and every session of the realm ends.
    let compromised: Json[] = [];
    if (o.emergency) {
      // BEFORE the keys go. An emergency drops a unit's retired keys and its
      // `next` outright (#48), so a history written only afterwards would
      // have no row for them at all — the one window `observe()`'s
      // derive-from-the-set rule cannot close by itself.
      this.noteHistory(realmId, 'an emergency rotation');
      compromised = this.revokeCompromised(realmId, keys, wanted);
    }
    // One promotion per distinct grace, so each unit keeps its own; almost
    // always one call, two when the credential signer is a unit of its own.
    const byGrace: Json = {};
    const self = this;
    wanted.forEach(function (u: Json): void {
      const g = String(o.emergency ? 0 : self.graceMs(u.unit, keys));
      (byGrace[g] = byGrace[g] || []).push(u.unit);
    });
    let rotated: Json[] = [];
    let generation = 0;
    // THE REFRESH-TOKEN ENCRYPTION KEYS (D7), when named — or with every unit.
    if (!o.units || !o.units.length || o.units.indexOf('refresh:enc') >= 0 ||
        o.units.indexOf('refresh') >= 0) {
      const r = helpers.rotateRefreshTokenKeys(realmId,
        o.emergency ? 0 : this.refreshGraceMs(),
        'a rotation of the refresh-token keys (' +
        String(o.reason || 'scheduled') + ')');
      if (!r.ok) {
        log.error(errorCodes.tag('STS-KEYS-0063') + 'signing rotation: the "' +
                  realmId + '" realm\'s refresh-token keys could not be ' +
                  'rotated: ' + r.why);
        log.debug("Leaving SigningRotation.rotate(). Refused.");
        throw errorCodes.mark(new Error('the rotation was refused: ' + r.why),
                              'STS-KEYS-0063');
      }
      rotated.push({ unit: 'refresh:enc', from: r.from, to: r.to });
      generation = r.generation;
    }
    const graces = Object.keys(byGrace);
    for (let i = 0; i < graces.length; i++) {
      const done = await helpers.promoteGenerations(realmId, {
        units: byGrace[graces[i]], graceMs: Number(graces[i]),
        emergency: !!o.emergency });
      if (!done.ok) {
        log.error(errorCodes.tag('STS-KEYS-0063') + 'signing rotation: the "' +
                  realmId + '" realm\'s ' + byGrace[graces[i]].join(', ') +
                  ' could not be rotated: ' + done.why);
        log.debug("Leaving SigningRotation.rotate(). Refused.");
        throw errorCodes.mark(new Error('the rotation was refused: ' +
                                        done.why), 'STS-KEYS-0063');
      }
      rotated = rotated.concat(done.rotated);
      generation = done.generation;
    }
    let signedOut: Json[] = [];
    if (o.emergency) {
      signedOut = this.endSessions(realmId, String(o.requestedBy || ''));
    }
    audit().record({
      action: o.emergency ? 'keys.rotate.emergency' : 'keys.rotate',
      protocol: 'Keys', channel: 'scheduler',
      outcome: 'success', realm: realmId,
      summary: rotated.length + ' signing key(s) of the "' + realmId +
               '" realm rotated (' + String(o.reason || 'scheduled') + ')' +
               (o.emergency ? '; ' + compromised.length + ' certificate(s) ' +
                'revoked for keyCompromise and ' + signedOut.length +
                ' session(s) ended' : ''),
      detail: { rotated: rotated, trigger: String(o.trigger || ''),
                generation: generation,
                compromised: compromised, sessionsEnded: signedOut.length }
    });
    // The refresh-token keys are this service's alone and published nowhere,
    // so a receiver is told only of the signing keys it can fetch.
    this.announce(realmId, rotated.filter(function (r: Json): boolean {
      return r.unit !== 'refresh:enc';
    }), String(o.reason || 'scheduled'));
    log.info('signing rotation: the "' + realmId + '" realm rotated ' +
             rotated.map(function (r: Json): string {
               return r.unit + ' ' + r.from + ' -> ' + r.to;
             }).join(', ') + ' (generation ' + generation + ').');
    this.noteHistory(realmId, o.emergency ? 'an emergency rotation'
      : 'a rotation (' + String(o.reason || 'scheduled') + ')');
    log.debug("Leaving SigningRotation.rotate(). " + rotated.length + ".");
    return { rotated: rotated, generation: generation,
             revoked: compromised.length, sessionsEnded: signedOut.length };
  }

  // Revoke, for keyCompromise, the certificate of every key of every unit
  // named — current, next and retired. Answers what was revoked.
  private revokeCompromised(realmId: string, keys: Json,
                            wanted: Json[]): Json[] {
    const { log, helpers, pki, revocation } = this.deps;
    log.debug("Entering SigningRotation.revokeCompromised().");
    const scope = String(keys.realm || realmId);
    const out: Json[] = [];
    wanted.forEach(function (u: Json): void {
      const kids = [u.kid].concat(helpers.standbyOf(keys, u.unit)
        .map(function (one: Json): string {
          return one.kid;
        }));
      kids.forEach(function (kid: string): void {
        let held: Json = null;
        try {
          held = pki().certificateFor(scope, u.useCase, u.slot, kid);
        } catch (e) {
          log.debug("Caught in a callback in " +
                    "SigningRotation.revokeCompromised(): " +
                    ((e && e.message) || e));
          held = null;
        }
        if (!held || !held.serialHex) {
          return;
        }
        try {
          const done = revocation().revoke(scope, u.useCase, {
            serialHex: held.serialHex, reason: 'keyCompromise',
            subject: held.subject || '',
            note: 'an emergency rotation of ' + u.unit + ' (key ' + kid + ')'
          });
          if (done && done.ok) {
            out.push({ unit: u.unit, kid: kid, serialHex: held.serialHex,
                       already: !!done.already });
          }
        } catch (e) {
          // The key is dropped whatever happens here; the audit row says how
          // many certificates were revoked, so a shortfall is visible.
          log.debug("Caught in a callback in " +
                    "SigningRotation.revokeCompromised(): " +
                    ((e && e.message) || e));
        }
      });
    });
    log.debug("Leaving SigningRotation.revokeCompromised(). " + out.length +
              ".");
    return out;
  }

  // Every session of the realm ended (a CAEP session-revoked each, through
  // authn), and a RISC sessions-revoked for every account that had one — the
  // two SSF notices D4 reserves for an emergency.
  // `requestedBy` names the administrator who asked for the rotation, if
  // one did: CAEP's `initiating_entity` is then `admin`, and `system`
  // otherwise — a maintenance act nobody in particular initiated (#242).
  private endSessions(realmId: string, requestedBy?: string): Json[] {
    const { log, authn, ssf, realms } = this.deps;
    log.debug("Entering SigningRotation.endSessions().");
    let ended: Json[] = [];
    try {
      ended = authn().endEverySessionIn(realmId, 'an emergency key rotation',
                                        requestedBy ? 'admin' : 'system');
    } catch (e) {
      log.error(errorCodes.tag('STS-KEYS-0064') + 'signing rotation: the ' +
                'sessions of the "' + realmId + '" realm could not be ended ' +
                'after an emergency rotation: ' + ((e && e.message) || e));
      ended = [];
    }
    const accounts: string[] = [];
    ended.forEach(function (one: Json): void {
      if (one.username && accounts.indexOf(one.username) < 0) {
        accounts.push(one.username);
      }
    });
    const realm = realms.get(realmId) || realms.get(realms.DEFAULT_ID);
    accounts.forEach(function (username: string): void {
      try {
        Promise.resolve(realms.run(realm, function (): Json {
          return ssf().riscAction('emit', { type: 'sessions-revoked',
                                            account_id: username });
        })).catch(function (e: Json): void {
          log.debug("Caught in a callback in SigningRotation.endSessions(): " +
                    ((e && e.message) || e));
        });
      } catch (e) {
        // No Shared Signals in this process: the sessions are ended anyway.
        log.debug("Caught in a callback in SigningRotation.endSessions(): " +
                  ((e && e.message) || e));
      }
    });
    log.debug("Leaving SigningRotation.endSessions(). " + ended.length +
              " session(s), " + accounts.length + " account(s).");
    return ended;
  }

  // ---------------------------------------------------------------------------
  // WHAT THE CONSOLE AND THE API ASK FOR (#48): a run of `signing.rotate-now`
  // queued, never a rotation in the request — so it runs once, on the
  // scheduler's leader, wherever it was asked. `units` empty means every unit
  // and the refresh-token keys. An emergency needs `confirm` to be the word
  // `compromised`, because it signs everybody out and cannot be undone.
  // ---------------------------------------------------------------------------
  /**
   * Queues a run of `signing.rotate-now` for the console or the API; nothing
   * rotates in the request.
   *
   * An emergency must carry `confirm: 'compromised'`.
   * @param realmId - the realm id
   * @param options - `{ units, emergency, confirm, requestedBy, via,
   *   channel }`; no units means every unit
   * @returns `{ ok: true, runId, alreadyQueued, emergency, units }`, or
   *   `{ ok: false, errorCode, status, why }` for an unknown unit, an
   *   unconfirmed emergency or a scheduler refusal
   */
  requestRotation(realmId: string, options?: Json): Json {
    const { log, scheduler, helpers } = this.deps;
    const o = options || {};
    log.debug("Entering SigningRotation.requestRotation(). realm=" + realmId);
    const keys = helpers.stsKeysFor.of(realmId);
    const known = helpers.signingUnitsOf(keys).map(function (u: Json) {
      return u.unit;
    }).concat(['refresh:enc']);
    const units = (Array.isArray(o.units) ? o.units
      : (o.units ? [o.units] : [])).map(String).filter(Boolean);
    const unknown = units.filter(function (u: string): boolean {
      return known.indexOf(u) < 0;
    });
    if (unknown.length) {
      log.debug("Leaving SigningRotation.requestRotation(). Unknown unit.");
      return { ok: false, errorCode: 'STS-KEYS-0065', status: 400,
               why: 'Unknown signing unit(s): ' + unknown.join(', ') +
                    '. The units of this realm are ' + known.join(', ') +
                    '.' };
    }
    if (o.emergency && String(o.confirm || '') !== 'compromised') {
      log.debug("Leaving SigningRotation.requestRotation(). Unconfirmed.");
      return { ok: false, errorCode: 'STS-KEYS-0066', status: 400,
               why: 'An emergency rotation revokes the keys\' certificates ' +
                    'for keyCompromise and signs everybody in the realm out; ' +
                    'confirm it by sending confirm: "compromised".' };
    }
    const answer = scheduler().requestRun(ROTATE_NOW_JOB, {
      realm: realmId,
      params: { units: units, emergency: !!o.emergency },
      requestedBy: String(o.requestedBy || ''), via: String(o.via || ''),
      channel: String(o.channel || 'console') });
    log.debug("Leaving SigningRotation.requestRotation(). " +
              (answer.ok ? answer.runId : answer.why));
    return answer.ok
      ? { ok: true, runId: answer.runId, alreadyQueued: !!answer.alreadyQueued,
          emergency: !!o.emergency, units: units }
      : { ok: false, errorCode: answer.errorCode, status: answer.status || 400,
          why: answer.why };
  }

  // THE ROTATION STATE of a realm, for `/admin/keys` and `GET /admin-api/keys`:
  // every unit with its current, next and retired kids, when it last rotated,
  // its interval and grace, and whether the schedule is on.
  /**
   * Builds the rotation state of a realm for `/admin/keys` and
   * `GET /admin-api/keys`.
   *
   * @param realmId - the realm id
   * @returns `{ scheduled, offReason, units, refresh }`: each unit's current,
   *   next and retired kids, last rotation, interval and grace
   */
  rotationView(realmId: string): Json {
    const { log, helpers } = this.deps;
    log.debug("Entering SigningRotation.rotationView(). realm=" + realmId);
    const keys = helpers.stsKeysFor.of(realmId);
    const self = this;
    const iso = function (ms: Json): string | null {
      return Number(ms) > 0 ? new Date(Number(ms)).toISOString() : null;
    };
    const rotated = (keys.generations && keys.generations.rotated) || {};
    const units = helpers.signingUnitsOf(keys).map(function (u: Json) {
      const standby = helpers.standbyOf(keys, u.unit);
      const next = standby.filter(function (one: Json): boolean {
        return one.role === 'next';
      })[0];
      return {
        unit: u.unit, current: u.kid,
        next: next ? { kid: next.kid, since: iso(next.createdAt) } : null,
        retired: standby.filter(function (one: Json): boolean {
          return one.role === 'retired';
        }).map(function (one: Json): Json {
          return { kid: one.kid, retiredAt: iso(one.retiredAt),
                   verifiesUntil: iso(one.retiredUntil) };
        }),
        lastRotated: iso(rotated[u.unit]),
        intervalDays: self.intervalMs(u.unit, keys) / DAY_MS,
        graceDays: Math.round(self.graceMs(u.unit, keys) / DAY_MS * 100) / 100,
        credentialSigner: u.unit === self.credentialUnit(keys)
      };
    });
    const out = {
      scheduled: this.offReason() === '',
      offReason: this.offReason(),
      units: units,
      refresh: { lastRotated: iso(rotated['refresh:enc']),
                 retired: helpers.retiredRefreshTokenKeysFor(keys).length,
                 graceDays: Math.round(this.refreshGraceMs() / DAY_MS * 100) /
                            100 }
    };
    log.debug("Leaving SigningRotation.rotationView(). " + units.length +
              " unit(s).");
    return out;
  }

  // The Shared Signals event (D4). Never lets a failure reach the rotation,
  // which has already happened.
  private announce(realmId: string, rotated: Json[], reason: string): void {
    const { log, ssf, realms } = this.deps;
    log.debug("Entering SigningRotation.announce().");
    if (!rotated.length) {
      log.debug("Leaving SigningRotation.announce(). Nothing rotated.");
      return;
    }
    try {
      const realm = realms.get(realmId) || realms.get(realms.DEFAULT_ID);
      Promise.resolve(realms.run(realm, function (): Json {
        return ssf().signingKeyRotated({ realm: realmId, rotated: rotated,
                                         reason: reason });
      })).catch(function (e: Json): void {
        log.debug("Caught in a callback in SigningRotation.announce(): " +
                  ((e && e.message) || e));
      });
    } catch (e) {
      // No Shared Signals in this process: the rotation stands, and the
      // audit row is its record.
      log.debug("Caught in SigningRotation.announce(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving SigningRotation.announce().");
  }

  // ---------------------------------------------------------------------------
  // RETIRE — every retired key past its grace dropped, and its certificate
  // superseded on its Issuing CA's list: the key it vouched for signs and
  // verifies nothing here any more.
  // ---------------------------------------------------------------------------
  /**
   * Drops every retired key past its grace and supersedes its certificate on
   * its Issuing CA's list; also drops unpinned keys past their grace and warns
   * about pinned certificates near their end.
   *
   * @param realmId - the realm id
   * @param ctx - optional scheduler context carrying `nowMs`
   * @returns `{ dropped, superseded, generation, pinnedDropped, pinnedWarned }`
   */
  retireDue(realmId: string, ctx?: Json): Json {
    const { log, helpers, pki, revocation, audit } = this.deps;
    log.debug("Entering SigningRotation.retireDue(). realm=" + realmId);
    const now = ctx && ctx.nowMs ? ctx.nowMs() : this.deps.now();
    const keys = helpers.stsKeysFor.of(realmId);
    const scope = String(keys.realm || realmId);
    const done = helpers.retireExpiredGenerations(realmId, now);
    let superseded = 0;
    (done.dropped || []).forEach(function (one: Json): void {
      let held: Json = null;
      try {
        held = pki().certificateFor(scope, one.useCase, one.slot, one.kid);
      } catch (e) {
        log.debug("Caught in a callback in SigningRotation.retireDue(): " +
                  ((e && e.message) || e));
        held = null;
      }
      if (!held || !held.serialHex) {
        return;
      }
      try {
        const out = revocation().revoke(scope, one.useCase, {
          serialHex: held.serialHex, reason: 'superseded',
          subject: held.subject || '',
          note: 'the retired ' + one.unit + ' key ' + one.kid + ' passed ' +
                'its grace and was dropped'
        });
        if (out && out.ok) {
          superseded++;
        }
      } catch (e) {
        // The key is gone either way; a certificate left off the list is
        // what `pki.js`'s supersede() also tolerates.
        log.debug("Caught in a callback in SigningRotation.retireDue(): " +
                  ((e && e.message) || e));
      }
    });
    if ((done.dropped || []).length) {
      audit().record({
        action: 'keys.retire', protocol: 'Keys', channel: 'scheduler',
        outcome: 'success', realm: realmId,
        summary: done.dropped.length + ' retired signing key(s) of the "' +
                 realmId + '" realm dropped after their grace',
        detail: { dropped: done.dropped, superseded: superseded }
      });
    }
    if ((done.dropped || []).length) {
      this.noteHistory(realmId, 'dropped past its grace');
    }
    const pins = this.retirePinned(realmId, scope, now);
    log.debug("Leaving SigningRotation.retireDue(). " +
              (done.dropped || []).length + " dropped.");
    return { dropped: (done.dropped || []).length, superseded: superseded,
             generation: done.generation, pinnedDropped: pins.dropped,
             pinnedWarned: pins.warned };
  }

  // ---------------------------------------------------------------------------
  // PINNED SIGNING KEYS (2026-09-27, #263). An operator's key pinned into a
  // `jose` or `xml` slot signs for the realm where `pki.pinnedSigners` is on;
  // the record and every check on it are `pki.js`'s (`pinSigner()`). What is
  // here is what a rotation has: the grace an unpinned key verifies through
  // (`graceMs()` of its unit, as a retired generated key), the audit row, the
  // `signing-key-rotated` event, and — in `signing.retire` — the drop of an
  // unpinned key past its grace and the warning as a pinned certificate
  // nears its end. A pinned key is NEVER rotated: its lifecycle is the
  // operator's.
  // ---------------------------------------------------------------------------
  private pinnedUnits(scope: string): string[] {
    const { log, pki } = this.deps;
    log.debug("Entering SigningRotation.pinnedUnits().");
    let out: string[] = [];
    try {
      if (pki().pinnedSignersOn(scope)) {
        out = pki().pinnedSignersFor(scope)
          .filter(function (one: Json): boolean {
            return one.role !== 'retired';
          }).map(function (one: Json): string {
            return one.unit;
          });
      }
    } catch (e) {
      // No certificate authority here: nothing is pinned.
      log.debug("Caught in SigningRotation.pinnedUnits(): " +
                ((e && e.message) || e));
      out = [];
    }
    log.debug("Leaving SigningRotation.pinnedUnits(). " + out.length + ".");
    return out;
  }

  // The kid a unit signs with now: its active pin, or the generated key.
  private signerKidOf(scope: string, unit: string): string {
    const { log, helpers, pki } = this.deps;
    log.debug("Entering SigningRotation.signerKidOf(). " + unit);
    const pinned = pki().pinnedSignersFor(scope)
      .filter(function (one: Json): boolean {
        return one.unit === unit && one.role === 'active';
      })[0];
    if (pinned && pki().pinnedSignersOn(scope)) {
      log.debug("Leaving SigningRotation.signerKidOf(). Pinned.");
      return pinned.kid;
    }
    const generated = helpers.signingUnitsOf(helpers.stsKeysFor.of(scope))
      .filter(function (u: Json): boolean {
        return u.unit === unit;
      })[0];
    log.debug("Leaving SigningRotation.signerKidOf().");
    return generated ? String(generated.kid) : '';
  }

  // PIN — `/admin/pki`'s and `POST /admin-api/pki/pin-key`'s act. With the
  // realm's setting off this is `pki.pinKeyPair()` as it always was; on,
  // a pin into a signer slot is announced as a rotation `requested`.
  /**
   * Pins an operator's key pair into a slot through `pki.pinKeyPair()`; where
   * the realm's pinned signers are on and the slot signs, the pin is audited
   * and announced as a requested rotation.
   *
   * @param scopeId - the realm id ('' for the ambient realm)
   * @param useCaseId - the certificate use case (`jose`, `xml`, ...)
   * @param slot - the slot within it
   * @param material - the key pair and certificate to pin
   * @param requestedBy - optional username for the audit row
   * @returns a promise of `pki.pinKeyPair()`'s answer
   */
  async pinSigningKey(scopeId: string, useCaseId: string, slot: string,
                      material: Json, requestedBy?: string): Promise<Json> {
    const { log, pki, audit, realms } = this.deps;
    log.debug("Entering SigningRotation.pinSigningKey(). " + useCaseId + ':' +
              slot);
    const unit = String(useCaseId) + ':' + String(slot);
    const scope = String(scopeId || '') ||
                  String((realms.current() || {}).id || '');
    let from = '';
    let graceMs = 0;
    const signer = pki().PINNED_SIGNER_USE_CASES.indexOf(useCaseId) >= 0 &&
                   pki().pinnedSignersOn(scope);
    if (signer) {
      from = this.signerKidOf(scope, unit);
      graceMs = this.graceMs(unit);
    }
    const done = await pki().pinKeyPair(scope, useCaseId, slot, material,
                                        { graceMs: graceMs });
    if (!done.ok || !done.signer || done.unchanged) {
      log.debug("Leaving SigningRotation.pinSigningKey(). " +
                (done.ok ? 'Nothing to announce.' : 'Refused.'));
      return done;
    }
    audit().record({
      action: 'keys.pin', protocol: 'Keys', channel: 'admin',
      outcome: 'success', realm: scope, username: requestedBy || '',
      summary: 'A key pair was pinned as the "' + scope + '" realm\'s ' +
               unit + ' signing key (' + done.signer.kid + '), signing from ' +
               done.signer.activatesAt,
      detail: { unit: unit, kid: done.signer.kid, from: from,
                replaced: done.signer.replaced,
                activatesAt: done.signer.activatesAt }
    });
    // ANNOUNCED AT THE PIN, which is when the key is PUBLISHED — ahead of
    // its use by `pki.pinnedSignerLeadMinutes`, #42's order for a next key.
    this.announce(scope, [{ unit: unit, from: from, to: done.signer.kid }],
                  'requested');
    log.debug("Leaving SigningRotation.pinSigningKey(). Pinned.");
    return done;
  }

  // UNPIN — the generated key signs again (it was published all along), and
  // the pinned key verifies through its unit's grace.
  /**
   * Unpins a slot's key: the generated key signs again and the pinned one
   * verifies through its unit's grace; audited and announced when it signed.
   *
   * @param scopeId - the realm id ('' for the ambient realm)
   * @param useCaseId - the certificate use case
   * @param slot - the slot within it
   * @param requestedBy - optional username for the audit row
   * @returns `pki.unpinKeyPair()`'s answer
   */
  unpinSigningKey(scopeId: string, useCaseId: string, slot: string,
                  requestedBy?: string): Json {
    const { log, pki, audit, realms } = this.deps;
    log.debug("Entering SigningRotation.unpinSigningKey(). " + useCaseId +
              ':' + slot);
    const unit = String(useCaseId) + ':' + String(slot);
    const scope = String(scopeId || '') ||
                  String((realms.current() || {}).id || '');
    const done = pki().unpinKeyPair(scope, useCaseId, slot,
                                    { graceMs: this.graceMs(unit) });
    if (!done.ok || !(done.unpinned || []).length) {
      log.debug("Leaving SigningRotation.unpinSigningKey(). " +
                (done.ok ? 'An old-style pin.' : 'Refused.'));
      return done;
    }
    audit().record({
      action: 'keys.unpin', protocol: 'Keys', channel: 'admin',
      outcome: 'success', realm: scope, username: requestedBy || '',
      summary: 'The pinned ' + unit + ' signing key of the "' + scope +
               '" realm (' + done.unpinned.join(', ') + ') was unpinned',
      detail: { unit: unit, unpinned: done.unpinned, signed: done.signed }
    });
    if (done.signed && pki().pinnedSignersOn(scope)) {
      this.announce(scope, [{ unit: unit, from: done.unpinned[0],
                              to: this.signerKidOf(scope, unit) }],
                    'requested');
    }
    log.debug("Leaving SigningRotation.unpinSigningKey(). Unpinned.");
    return done;
  }

  // In `signing.retire`: drop each unpinned key past its grace (superseding
  // the certificate this service issued it, as for a generated key), and
  // warn — once a day per key — about a pinned certificate near or past its
  // notAfter (STS-PKI-0212, STS-PKI-0213).
  private retirePinned(realmId: string, scope: string, now: number): Json {
    const { log, pki, revocation, audit, config, realms, errorCodes } =
      this.deps;
    log.debug("Entering SigningRotation.retirePinned().");
    let dropped: Json[] = [];
    let warned = 0;
    try {
      dropped = pki().dropRetiredPinnedSigners(scope, now);
    } catch (e) {
      log.debug("Caught in SigningRotation.retirePinned(): " +
                ((e && e.message) || e));
      dropped = [];
    }
    dropped.filter(function (one: Json): boolean {
      return !one.operatorCertificate && !!one.serialHex;
    }).forEach(function (one: Json): void {
      try {
        revocation().revoke(scope, one.useCase, {
          serialHex: one.serialHex, reason: 'superseded',
          subject: one.subject || '',
          note: 'the unpinned ' + one.useCase + ':' + one.slot + ' key ' +
                one.kid + ' passed its grace and was dropped'
        });
      } catch (e) {
        log.debug("Caught in a callback in SigningRotation.retirePinned(): " +
                  ((e && e.message) || e));
      }
    });
    if (dropped.length) {
      audit().record({
        action: 'keys.retire', protocol: 'Keys', channel: 'scheduler',
        outcome: 'success', realm: realmId,
        summary: dropped.length + ' unpinned signing key(s) of the "' +
                 realmId + '" realm dropped after their grace',
        detail: { pinnedDropped: dropped }
      });
    }
    const realm = realms.get(realmId) || realms.get(realms.DEFAULT_ID);
    const days = Number(realms.run(realm, function (): Json {
      return config.value('pki.pinnedSignerExpiryWarningDays');
    }));
    const today = Math.floor(now / DAY_MS);
    const self = this;
    let views: Json[] = [];
    try {
      views = pki().pinnedSignersFor(scope, now);
    } catch (e) {
      log.debug("Caught in SigningRotation.retirePinned(): " +
                ((e && e.message) || e));
      views = [];
    }
    views.filter(function (one: Json): boolean {
      return one.role !== 'retired' && one.daysLeft < days;
    }).forEach(function (one: Json): void {
      const said = scope + '|' + one.kid;
      if (self.pinWarned.get(said) === today) {
        return;
      }
      self.pinWarned.set(said, today);
      warned++;
      if (one.expired) {
        log.error(errorCodes.tag('STS-PKI-0213') + 'signing rotation: the ' +
                  'certificate of the pinned ' + one.unit + ' signing key ' +
                  one.kid + ' of the "' + scope + '" realm EXPIRED at ' +
                  one.notAfter + ', and the key still signs. Relying ' +
                  'parties that check it refuse what it signs. Its ' +
                  'lifecycle is yours: pin a renewed key, or unpin it on ' +
                  '/admin/pki.');
      } else {
        log.warn(errorCodes.tag('STS-PKI-0212') + 'signing rotation: the ' +
                 'certificate of the pinned ' + one.unit + ' signing key ' +
                 one.kid + ' of the "' + scope + '" realm expires at ' +
                 one.notAfter + ' (' + one.daysLeft + ' day(s)). It is ' +
                 'never rotated: pin a renewed key before then, or unpin ' +
                 'it on /admin/pki.');
      }
    });
    log.debug("Leaving SigningRotation.retirePinned(). " + dropped.length +
              " dropped, " + warned + " warned.");
    return { dropped: dropped.length, warned: warned };
  }

  // The two jobs, registered once per process.
  /**
   * Registers `signing.rotate`, `signing.rotate-now`, `signing.retire` and the
   * client-secret expiry job with the scheduler, once per process.
   *
   * @returns true when registered, false when they already were
   */
  registerJobs(): boolean {
    const { log, scheduler } = this.deps;
    log.debug("Entering SigningRotation.registerJobs().");
    const s = scheduler();
    if (s.job(ROTATE_JOB)) {
      log.debug("Leaving SigningRotation.registerJobs(). Already there.");
      return false;
    }
    const self = this;
    s.register({
      id: ROTATE_JOB,
      title: 'Signing key rotation',
      describe: 'Gives every signing unit of the realm a next key, published ' +
                'before it signs anything, and promotes each next key once ' +
                'it has been published for a whole interval ' +
                '(signing.rotationIntervalDays); the key it replaces goes on ' +
                'verifying through its grace.',
      owner: 'common/signing_rotation.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return CHECK_EVERY_MS;
      },
      off: function (): string {
        return self.offReason();
      },
      manual: true,
      run: function (ctx: Json): Promise<Json> {
        return self.rotateDue(ctx.realm, ctx);
      }
    });
    // ROTATE NOW — what `/admin/keys` and `POST /admin-api/keys/rotate`
    // queue (#48). A job of its own rather than a manual run of the one
    // above, because that one is OFF in development mode and this must not
    // be: a rotation by hand is how a development service is made to show
    // one. Manual only; `params` names the units (none meaning every one,
    // the refresh-token keys included).
    s.register({
      id: ROTATE_NOW_JOB,
      title: 'Signing key rotation, by hand',
      describe: 'Rotates the named signing units of the realm — or every ' +
                'one — now: each next key becomes current and the key it ' +
                'replaces is retired, verifying through its grace.',
      owner: 'common/signing_rotation.ts',
      kind: 'cluster', scope: 'realm', manualOnly: true, manual: true,
      run: function (ctx: Json): Promise<Json> {
        const p = ctx.params || {};
        return self.rotate(ctx.realm, {
          units: Array.isArray(p.units) && p.units.length ? p.units : null,
          emergency: !!p.emergency,
          reason: p.emergency ? 'emergency' : 'requested',
          requestedBy: ctx.requestedBy || '',
          trigger: ctx.trigger });
      }
    });
    s.register({
      id: RETIRE_JOB,
      title: 'Retired signing key clean-up',
      describe: 'Drops every retired signing key whose grace has passed and ' +
                'supersedes its certificate on its Issuing CA\'s list.',
      owner: 'common/signing_rotation.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return CHECK_EVERY_MS;
      },
      // Retirement follows whatever rotated, so it runs wherever rotation
      // could have — including a development-mode rotation made by hand.
      manual: true,
      run: function (ctx: Json): Json {
        return self.retireDue(ctx.realm, ctx);
      }
    });
    // CLIENT SECRETS (#49 P5, rcbj's answer): the daily warning of secrets
    // expiring within oauth2.clientSecretExpiryWarningDays and of those that
    // have, and the clearing of every rotated-out secret whose overlap has
    // passed. The act is `applications.sweepClientSecrets()`'s; this is when.
    s.register({
      id: SECRET_EXPIRY_JOB,
      title: 'Client secret expiry',
      describe: 'Warns, with an audit row, about every client secret that ' +
                'expires within oauth2.clientSecretExpiryWarningDays or has ' +
                'expired, and clears the secret a rotation replaced once ' +
                'oauth2.clientSecretOverlapS has passed.',
      owner: 'common/signing_rotation.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return DAY_MS;
      },
      manual: true,
      run: function (ctx: Json): Json {
        const done = self.deps.applications().sweepClientSecrets(ctx.nowMs());
        return { expiring: done.expiring.length,
                 expired: done.expired.length,
                 cleared: done.cleared.length };
      }
    });
    log.debug("Leaving SigningRotation.registerJobs().");
    return true;
  }
}

const slot = new InstanceSlot<SigningRotation>(
  'common/signing_rotation',
  () => new SigningRotation(SigningRotation.defaultDeps()),
  function (instance: SigningRotation): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Signing-key rotation on the scheduler (#42), and its emergency form (#48).
 *
 * A library that registers jobs and no route. The method names below forward
 * to the instance the composition root installs.
 * @namespace
 */
export = {
  SigningRotation: SigningRotation,
  /**
   * Installs the instance the composition root built.
   */
  installInstance: (instance: SigningRotation): void => slot.install(instance),
  /**
   * Names where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  ROTATE_JOB: ROTATE_JOB,
  ROTATE_NOW_JOB: ROTATE_NOW_JOB,
  RETIRE_JOB: RETIRE_JOB,
  rotate: slot.forward('rotate'),
  rotateDue: slot.forward('rotateDue'),
  retireDue: slot.forward('retireDue'),
  intervalMs: slot.forward('intervalMs'),
  graceMs: slot.forward('graceMs'),
  credentialUnit: slot.forward('credentialUnit'),
  unitForAlg: slot.forward('unitForAlg'),
  offReason: slot.forward('offReason'),
  refreshGraceMs: slot.forward('refreshGraceMs'),
  requestRotation: slot.forward('requestRotation'),
  rotationView: slot.forward('rotationView'),
  pinSigningKey: slot.forward('pinSigningKey'),
  unpinSigningKey: slot.forward('unpinSigningKey')
};
