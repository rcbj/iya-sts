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
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import clusterClaims = require('../cluster/cluster_claims');

type Json = any;

const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';
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

class DeviceAuthorization {
  static readonly GRANT_TYPE = GRANT_TYPE;
  static readonly SWEEP_JOB = SWEEP_JOB;

  constructor(private readonly deps: DeviceDeps) {
    deps.log.debug("Entering DeviceAuthorization.constructor().");
    deps.log.debug("Leaving DeviceAuthorization.constructor().");
  }

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

  enabled(): boolean {
    this.deps.log.debug("Entering DeviceAuthorization.enabled().");
    this.deps.log.debug("Leaving DeviceAuthorization.enabled().");
    return !!this.deps.config.value('oauth2.deviceAuthorization');
  }

  // `abcd-efgh`, `ABCDEFGH` and ` abcdefgh ` are one code (section 6.1).
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
      deviceCode: nodeCrypto.randomBytes(32).toString('base64url'),
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

export = {
  DeviceAuthorization: DeviceAuthorization,
  installInstance: (instance: DeviceAuthorization): void =>
    slot.install(instance),
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
