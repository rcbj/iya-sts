// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: device_authorization.ts
//
// ===========================================================================
// RFC 8628, THE OAUTH 2.0 DEVICE AUTHORIZATION GRANT (#150, 2026-09-26).
//
// Built inside #150 by rcbj's answer, because OpenID Connect Key Binding
// section 3 binds the device flow's tokens through `c_s256` over the device
// code. A device with no browser (a television, a CLI) asks
// `/oauth2/device_authorization` for a DEVICE CODE and a short USER CODE;
// the person opens `/portal/device` on another device, signs in there, types
// the user code and approves or denies; the device polls the token endpoint
// with the `urn:ietf:params:oauth:grant-type:device_code` grant until it has
// tokens (section 3.4/3.5).
//
// OFF BY DEFAULT (`oauth2.deviceAuthorization`, per realm), for CIBA's
// reason and one of its own: a new way in is something a realm turns on, and
// RFC 8628 section 5.4 describes the phishing a device flow invites — a
// person typing somebody else's user code approves THAT device. The approval
// page names the client and the scopes and requires a click; it never
// approves on the code alone.
//
// THE STORE is `oauth2.deviceCodes`, per realm and persisted: the device
// polls whichever node the balancer picks. `d|<device_code>` holds the
// record and `u|<user_code>` the index a person's typing is looked up by.
// Section 6.1: the user code is eight characters from twenty consonants
// (BCDFGHJKLMNPQRSTVWXZ, about 34.6 bits), shown `XXXX-XXXX` and compared
// with case and hyphens ignored; it lives `oauth2.deviceCodeLifetimeS`, and
// guessing is bounded by that and by the sign-in the page demands. The
// device code is 256 bits. A redemption is claimed once for the cluster.
// The `oauth2.device-code-sweep` job removes what expired or finished.
// ===========================================================================

import nodeCrypto = require('crypto');
// WHICH CELL MINTED AN ARTIFACT (#98 D10): a keyed tag appended to what
// this module mints and read where it is presented. A leaf library.
import cellLocator = require('../common/cell_locator');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import clusterClaims = require('../cluster/cluster_claims');

type Json = any;

/**
 * The device code grant type the token endpoint accepts.
 */
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';
/**
 * The scheduler job id that expires and drops device codes.
 */
const SWEEP_JOB = 'oauth2.device-code-sweep';
const REDEEM_SCOPE = 'oauth.device';
const RETENTION_MS = 60 * 60 * 1000;
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

const codes = realms.map({ persist: 'oauth2.deviceCodes', retain: 'age' });

interface DeviceDeps {
  log: typeof helpers.log;
  config: typeof config;
  claims: typeof clusterClaims;
  scheduler: () => Json;
  now: () => number;
}

/**
 * RFC 8628, the OAuth 2.0 Device Authorization Grant (#150): device codes, user
 * codes, the person's answer on `/portal/device`, and the polling.
 */
class DeviceAuthorization {
  /**
   * The device code grant type the token endpoint accepts.
   */
  static readonly GRANT_TYPE = GRANT_TYPE;
  /**
   * The scheduler job id that expires and drops device codes.
   */
  static readonly SWEEP_JOB = SWEEP_JOB;

  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, settings, cluster claims, scheduler and clock
   */
  constructor(private readonly deps: DeviceDeps) {
    deps.log.debug("Entering DeviceAuthorization.constructor().");
    deps.log.debug("Leaving DeviceAuthorization.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): DeviceDeps {
    helpers.log.debug("Entering DeviceAuthorization.defaultDeps().");
    helpers.log.debug("Leaving DeviceAuthorization.defaultDeps().");
    return {
      log: helpers.log, config: config, claims: clusterClaims,
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  /**
   * Tells whether the device flow is on in the realm
   * (`oauth2.deviceAuthorization`, off by default).
   *
   * @returns true when it is on
   */
  enabled(): boolean {
    this.deps.log.debug("Entering DeviceAuthorization.enabled().");
    this.deps.log.debug("Leaving DeviceAuthorization.enabled().");
    return !!this.deps.config.value('oauth2.deviceAuthorization');
  }

  // `abcd-efgh`, `ABCDEFGH` and ` abcdefgh ` are one code (section 6.1).
  /**
   * Normalises a typed user code: case, spaces and hyphens ignored (section
   * 6.1).
   *
   * @param userCode - the code as typed
   * @returns the normalised code
   */
  static normalize(userCode: Json): string {
    helpers.log.debug("Entering DeviceAuthorization.normalize().");
    helpers.log.debug("Leaving DeviceAuthorization.normalize().");
    return String(userCode || '').toUpperCase().replace(/[^A-Z]/g, '');
  }

  private newUserCode(): string {
    this.deps.log.debug("Entering DeviceAuthorization.newUserCode().");
    let out = '';
    for (let i = 0; i < 8; i++) {
      out += USER_CODE_ALPHABET.charAt(
        nodeCrypto.randomInt(USER_CODE_ALPHABET.length));
    }
    this.deps.log.debug("Leaving DeviceAuthorization.newUserCode().");
    return out;
  }

  private save(record: Json): void {
    this.deps.log.debug("Entering DeviceAuthorization.save().");
    codes.set('d|' + record.deviceCode, record);
    this.deps.log.debug("Leaving DeviceAuthorization.save().");
  }

  // Section 3.1/3.2: a new device authorization for `clientId`.
  /**
   * Creates a device authorization for a client: a 256-bit device code and an
   * eight-character user code (sections 3.1 and 3.2).
   *
   * @param clientId - the client asking
   * @param clientName - its name, shown on the approval page
   * @param scope - the scope requested
   * @param dpopJkt - the DPoP key thumbprint the request was bound to, or ''
   * @returns the new record
   */
  create(clientId: string, clientName: string, scope: string,
         dpopJkt: string): Json {
    const { log, config, now } = this.deps;
    log.debug("Entering DeviceAuthorization.create(). " + clientId);
    let userCode = this.newUserCode();
    for (let i = 0; i < 5 && codes.get('u|' + userCode); i++) {
      userCode = this.newUserCode();
    }
    const lifetime = Number(config.value('oauth2.deviceCodeLifetimeS'));
    const record = {
      // Stamped with the minting cell (#98 D10): a device polls the cell
      // nearest IT, which relays to this one.
      deviceCode: cellLocator.stamp(nodeCrypto.randomBytes(32)
                                      .toString('base64url')),
      userCode: userCode, clientId: clientId,
      clientName: clientName || clientId, scope: scope,
      dpopJkt: dpopJkt || '', state: 'pending', createdAt: now(),
      expiresAt: now() + lifetime * 1000,
      interval: Number(config.value('oauth2.deviceCodeIntervalS')),
      lastPolledAt: 0, username: '', approval: null
    };
    this.save(record);
    codes.set('u|' + userCode, record.deviceCode);
    log.debug("Leaving DeviceAuthorization.create().");
    return record;
  }

  // The pending request a person's typed user code names, or null.
  /**
   * Finds the pending request a typed user code names.
   *
   * @param typed - the user code as typed
   * @returns the pending record, or null
   */
  byUserCode(typed: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering DeviceAuthorization.byUserCode().");
    const deviceCode = codes.get('u|' + DeviceAuthorization.normalize(typed));
    const record = deviceCode ? codes.get('d|' + deviceCode) : null;
    const live = record && record.state === 'pending' &&
                 record.expiresAt > now() ? record : null;
    log.debug("Leaving DeviceAuthorization.byUserCode(). " +
              (live ? 'Found.' : 'None.'));
    return live;
  }

  // The person's answer on /portal/device, with what their session proved.
  /**
   * Records a person's approval or denial on `/portal/device`.
   *
   * @param typed - the user code as typed
   * @param username - the person answering
   * @param approve - true to approve, false to deny
   * @param approval - what the person's session proved
   * @returns `{ ok: true, record }`, or `{ ok: false, why }`
   */
  answer(typed: Json, username: string, approve: boolean,
         approval: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering DeviceAuthorization.answer().");
    const record = this.byUserCode(typed);
    if (!record) {
      log.debug("Leaving DeviceAuthorization.answer(). None.");
      return { ok: false, why: 'no pending sign-in has that code; it may ' +
               'have expired — start again on the device' };
    }
    record.state = approve ? 'approved' : 'denied';
    record.username = String(username);
    record.approval = approve ? approval : null;
    record.finishedAt = now();
    this.save(record);
    codes.delete('u|' + record.userCode);
    log.debug("Leaving DeviceAuthorization.answer(). " + record.state);
    return { ok: true, record: record };
  }

  // Section 3.5: what a poll finds — pending, slow_down, approved, denied,
  // expired, redeemed or unknown — with the interval enforced.
  /**
   * Tells a polling device the state of its request, with the interval enforced
   * (section 3.5).
   *
   * @param deviceCode - the device code
   * @param clientId - the client polling
   * @returns the state (`pending`, `slow_down`, `approved`, `denied`,
   *   `expired`, `redeemed` or `unknown`) and the record
   */
  poll(deviceCode: Json, clientId: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering DeviceAuthorization.poll().");
    const record = codes.get('d|' + String(deviceCode || ''));
    if (!record || record.clientId !== String(clientId || '')) {
      log.debug("Leaving DeviceAuthorization.poll(). Unknown.");
      return { state: 'unknown', record: null };
    }
    if (record.state === 'pending' && record.expiresAt <= now()) {
      record.state = 'expired';
      record.finishedAt = now();
      this.save(record);
    }
    if (record.state !== 'pending') {
      log.debug("Leaving DeviceAuthorization.poll(). " + record.state);
      return { state: record.state, record: record };
    }
    const tooSoon = record.lastPolledAt &&
      now() - Number(record.lastPolledAt) < Number(record.interval) * 1000;
    if (tooSoon) {
      // Section 3.5: "the interval MUST be increased by 5 seconds for this
      // and all subsequent requests".
      record.interval = Number(record.interval) + 5;
    }
    record.lastPolledAt = now();
    this.save(record);
    log.debug("Leaving DeviceAuthorization.poll(). " +
              (tooSoon ? 'slow_down' : 'pending'));
    return { state: tooSoon ? 'slow_down' : 'pending', record: record };
  }

  // One token response per approval, cluster-wide.
  /**
   * Claims an approved request's one token response, cluster-wide, and marks it
   * redeemed.
   *
   * @param record - the approved record
   * @returns a promise of true when this caller won the claim
   */
  async redeem(record: Json): Promise<boolean> {
    const { log, claims, now } = this.deps;
    log.debug("Entering DeviceAuthorization.redeem().");
    const claimed: Json = await claims.claim({
      scope: REDEEM_SCOPE, value: record.deviceCode,
      ttlMs: Math.max(0, record.expiresAt - now()) + RETENTION_MS });
    if (!claimed.ok) {
      log.debug("Leaving DeviceAuthorization.redeem(). " + claimed.reason);
      return false;
    }
    record.state = 'redeemed';
    record.redeemedAt = now();
    this.save(record);
    log.debug("Leaving DeviceAuthorization.redeem().");
    return true;
  }

  // The scheduler job (#49): expire what nobody answered and drop what
  // finished an hour ago.
  /**
   * Expires what nobody answered and drops what finished an hour ago. The
   * scheduler job's body.
   *
   * @returns `{ summary }` for the scheduler
   */
  sweep(): Json {
    const { log, now } = this.deps;
    log.debug("Entering DeviceAuthorization.sweep().");
    const gone: string[] = [];
    let expired = 0;
    const self = this;
    codes.forEach(function (row: Json, key: string): void {
      if (key.indexOf('d|') !== 0 || !row) {
        return;
      }
      if (row.state === 'pending' && row.expiresAt <= now()) {
        row.state = 'expired';
        row.finishedAt = now();
        self.save(row);
        gone.push('u|' + row.userCode);
        expired++;
      } else if (row.state !== 'pending' &&
                 Number(row.finishedAt || row.redeemedAt || row.expiresAt) <
                   now() - RETENTION_MS) {
        gone.push(key);
        gone.push('u|' + row.userCode);
      }
    });
    gone.forEach(function (key: string): void {
      codes.delete(key);
    });
    log.debug("Leaving DeviceAuthorization.sweep().");
    return { summary: expired + ' device code(s) expired, ' + gone.length +
             ' row(s) removed' };
  }

  /**
   * Registers the sweep job on the scheduler, once.
   */
  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering DeviceAuthorization.scheduleJobs().");
    const s = scheduler();
    if (s.job(SWEEP_JOB)) {
      log.debug("Leaving DeviceAuthorization.scheduleJobs(). Registered.");
      return;
    }
    s.register({
      id: SWEEP_JOB,
      title: 'Device authorization: expired codes',
      describe: 'Expires RFC 8628 device codes nobody approved in time, and ' +
                'removes those that finished more than an hour ago (#150).',
      owner: 'oauth-oidc/device_authorization.ts',
      kind: 'cluster', scope: 'realm', everyMs: function (): number {
        return 300000;
      },
      manual: true,
      run: function (): Json {
        return self.sweep();
      }
    });
    log.debug("Leaving DeviceAuthorization.scheduleJobs(). Registered now.");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DeviceAuthorization>(
  'oauth-oidc/device_authorization',
  () => new DeviceAuthorization(DeviceAuthorization.defaultDeps()),
  function (instance: DeviceAuthorization): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * RFC 8628, the OAuth 2.0 Device Authorization Grant.
 *
 * A library that registers no route. The composition root builds the instance;
 * each function here forwards to it.
 *
 * @namespace
 */
export = {
  DeviceAuthorization: DeviceAuthorization,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   * Refused once an instance is installed or a default built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: DeviceAuthorization): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  GRANT_TYPE: GRANT_TYPE,
  SWEEP_JOB: SWEEP_JOB,
  normalize: DeviceAuthorization.normalize,
  enabled: slot.forward('enabled'),
  create: slot.forward('create'),
  byUserCode: slot.forward('byUserCode'),
  answer: slot.forward('answer'),
  poll: slot.forward('poll'),
  redeem: slot.forward('redeem'),
  sweep: slot.forward('sweep')
};
