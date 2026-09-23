'use strict';
//
// File: devices.ts
//
// ===========================================================================
// THE DEVICE REGISTER (#130, 2026-09-23 — the foundation of #164).
//
// rcbj: "Devices should be tracked as first-class objects in embedded LDAP,
// linked to the current user and one or more applications." So a device is an
// ENTRY under `ou=devices`, not a field on the person:
//
//   objectClass           top, device (RFC 4519 section 3.4), stsDevice
//   cn                    the device's id, a UUID this service assigned
//   owner                 the DN of the person whose device it is (RFC 4519)
//   description           what to call it on a page
//   stsDeviceApplication  the DN of every application that has used it
//   stsDeviceSecretHash   SHA-256 of its Native SSO device_secret (withheld
//                         from every LDAP read, like any verifier)
//   stsDeviceSession      the sign-on session that secret is good for
//   stsDeviceLastUsed     when it was last used, ISO 8601
//
// **WHAT PUTS ONE HERE TODAY is OpenID Connect Native SSO for Mobile Apps 1.0
// (`oauth-oidc/oauth2.ts`)**: the first app's authorization-code grant with
// the `device_sso` scope mints a device_secret, and the device it names is
// this entry. #164 adds the rest of what a device is — its keys, its
// compliance state, CAEP device-compliance-change — on these same entries.
//
// **THE SECRET IS GOOD FOR ONE SIGN-ON SESSION, AND THE DEVICE OUTLIVES IT**
// (rcbj, #130). The entry is the record of a device; the secret on it is
// accepted only while `stsDeviceSession` names a live session of its owner,
// so a sign-out, an expiry, a disabled account or SSF session-revoked ends it
// with nothing to sweep. A later sign-in whose code grant PRESENTS that old
// secret (Native SSO section 3.3 lets the app send it) re-binds the SAME
// device to the new session, and the secret is NEVER ROTATED (rcbj): every
// app on the device shares the value, and a rotation handed to one would
// strand the others. A secret presented by anybody but its owner, or naming
// nothing, is ignored and a new device is made.
//
// **ONE PERSON HOLDS AT MOST `oauth2.maxDevicesPerPerson`.** At the bound a
// new device replaces the person's least recently used one whose session
// has ended — an entry per sign-in is what a register nobody bounds becomes.
//
// A LIBRARY (rule 3): it registers nothing. The directory is reached through
// `credentials.deviceStore()`, the hooks `ldap_server.js` passes in, as every
// other per-person store in `common/` is.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import credentials = require('./credentials');
import stsCrypto = require('./crypto');

type Json = any;

interface Device {
  id: string;
  dn: string;
  owner: string;
  label: string;
  applications: string[];
  secretHash: string;
  session: string;
  lastUsed: string;
  created: string;
}

interface DevicesDeps {
  log: typeof helpers.log;
  config: typeof config;
  credentials: typeof credentials;
  stsCrypto: typeof stsCrypto;
  now: () => number;
}

class Devices {
  constructor(private readonly deps: DevicesDeps) {
    deps.log.debug("Entering Devices.constructor().");
    deps.log.debug("Leaving Devices.constructor().");
  }

  static defaultDeps(): DevicesDeps {
    helpers.log.debug("Entering Devices.defaultDeps().");
    helpers.log.debug("Leaving Devices.defaultDeps().");
    return { log: helpers.log, config: config, credentials: credentials,
             stsCrypto: stsCrypto, now: Date.now };
  }

  // The SHA-256 a secret is kept as. A device_secret is 256 random bits, so
  // a fast hash is enough — there is nothing to guess.
  static hashOf(secret: unknown): string {
    helpers.log.debug("Entering Devices.hashOf().");
    helpers.log.debug("Leaving Devices.hashOf().");
    return nodeCrypto.createHash('sha256').update(String(secret || ''), 'utf8')
      .digest('base64url');
  }

  private store(operation: string, ...args: any[]): any {
    const { log, credentials } = this.deps;
    log.debug("Entering Devices.store(). " + operation);
    log.debug("Leaving Devices.store().");
    return credentials.deviceStore(operation, args);
  }

  private static fromEntry(entry: Json): Device {
    helpers.log.debug("Entering Devices.fromEntry().");
    const a = (entry && entry.attributes) || {};
    const one = function (name: string): string {
      return String((a[name] || [])[0] || '');
    };
    helpers.log.debug("Leaving Devices.fromEntry().");
    return { id: one('cn'), dn: String(entry.dn || ''), owner: one('owner'),
             label: one('description'),
             applications: (a.stsdeviceapplication || []).map(String),
             secretHash: one('stsdevicesecrethash'),
             session: one('stsdevicesession'),
             lastUsed: one('stsdevicelastused'),
             created: one('createtimestamp') };
  }

  private write(device: Device): boolean {
    const { log } = this.deps;
    log.debug("Entering Devices.write(). id=" + device.id);
    const attributes: Json = {
      objectClass: ['top', 'device', 'stsDevice'],
      cn: [device.id],
      owner: [device.owner],
      description: [device.label || 'a device'],
      stsDeviceLastUsed: [device.lastUsed || new Date(this.deps.now())
        .toISOString()]
    };
    if (device.applications.length) {
      attributes.stsDeviceApplication = device.applications.slice(0);
    }
    if (device.secretHash) {
      attributes.stsDeviceSecretHash = [device.secretHash];
    }
    if (device.session) {
      attributes.stsDeviceSession = [device.session];
    }
    const written = !!this.store('writeDeviceEntry', device.id, attributes);
    log.debug("Leaving Devices.write(). " + written);
    return written;
  }

  // Every device in the realm.
  all(): Device[] {
    const { log } = this.deps;
    log.debug("Entering Devices.all().");
    const out = (this.store('listDeviceEntries') || [])
      .map(Devices.fromEntry);
    log.debug("Leaving Devices.all(). " + out.length + ".");
    return out;
  }

  static sameDn(a: string, b: string): boolean {
    helpers.log.debug("Entering Devices.sameDn().");
    const norm = function (dn: string): string {
      return String(dn || '').replace(/\s*,\s*/g, ',').toLowerCase();
    };
    helpers.log.debug("Leaving Devices.sameDn().");
    return !!a && norm(a) === norm(b);
  }

  // A person's devices, most recently used first. [] for nobody.
  listFor(username: unknown): Device[] {
    const { log } = this.deps;
    log.debug("Entering Devices.listFor(). user=" + username);
    const ownerDn = String(this.store('personDnOf', String(username || '')) ||
                           '');
    if (!ownerDn) {
      log.debug("Leaving Devices.listFor(). No entry.");
      return [];
    }
    const out = this.all().filter(function (one) {
      return Devices.sameDn(one.owner, ownerDn);
    }).sort(function (a, b) {
      return String(b.lastUsed).localeCompare(String(a.lastUsed));
    });
    log.debug("Leaving Devices.listFor(). " + out.length + ".");
    return out;
  }

  byId(id: unknown): Device | null {
    const { log } = this.deps;
    log.debug("Entering Devices.byId().");
    const wanted = String(id || '');
    const found = this.all().filter(function (one) {
      return one.id === wanted;
    })[0] || null;
    log.debug("Leaving Devices.byId(). " + !!found);
    return found;
  }

  // The device a secret belongs to, or null — compared in constant time.
  bySecret(secret: unknown): Device | null {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering Devices.bySecret().");
    const text = String(secret || '');
    if (!text) {
      log.debug("Leaving Devices.bySecret(). None given.");
      return null;
    }
    const hash = Devices.hashOf(text);
    const found = this.all().filter(function (one) {
      return !!one.secretHash &&
             stsCrypto.constantTimeEquals(one.secretHash, hash);
    })[0] || null;
    log.debug("Leaving Devices.bySecret(). " + !!found);
    return found;
  }

  // The application DN a client id is linked by, added to a device.
  private linkApplication(device: Device, clientId: unknown): void {
    const { log } = this.deps;
    log.debug("Entering Devices.linkApplication().");
    const dn = String(this.store('applicationDnOf', String(clientId || '')) ||
                      '');
    if (dn && !device.applications.some(function (one) {
      return Devices.sameDn(one, dn);
    })) {
      device.applications.push(dn);
    }
    log.debug("Leaving Devices.linkApplication(). " + (dn ? 'Linked.' :
                                                        'No entry.'));
  }

  // -------------------------------------------------------------------------
  // THE FIRST APP'S GRANT (Native SSO section 3.3). `spec` is { username,
  // clientId, sessionId, presented, label, isLive(sessionId) }. Returns
  // { ok, secret, device, reused } or { ok: false, error }.
  // -------------------------------------------------------------------------
  issueForSession(spec: Json): Json {
    const { log, config } = this.deps;
    log.debug("Entering Devices.issueForSession(). user=" + spec.username);
    const ownerDn = String(this.store('personDnOf',
                                      String(spec.username || '')) || '');
    if (!ownerDn || !spec.sessionId) {
      log.debug("Leaving Devices.issueForSession(). No person or session.");
      return { ok: false, error: !ownerDn
        ? 'there is no directory entry for "' + spec.username + '"'
        : 'the grant names no sign-on session' };
    }
    const now = new Date(this.deps.now()).toISOString();
    const presented = String(spec.presented || '');
    const known = presented ? this.bySecret(presented) : null;
    if (known && Devices.sameDn(known.owner, ownerDn)) {
      // THE SAME DEVICE, SIGNED IN AGAIN: re-bound to this session, and the
      // secret it already holds stays the secret (never rotated).
      known.session = String(spec.sessionId);
      known.lastUsed = now;
      this.linkApplication(known, spec.clientId);
      if (!this.write(known)) {
        log.debug("Leaving Devices.issueForSession(). Not stored.");
        return { ok: false, error: 'the directory did not store the device' };
      }
      log.debug("Leaving Devices.issueForSession(). Re-bound " + known.id);
      return { ok: true, secret: presented, device: known, reused: true };
    }
    // A NEW DEVICE, after making room: the person's least recently used
    // device whose session has ended, and failing that their least recently
    // used one.
    const max = Number(config.value('oauth2.maxDevicesPerPerson'));
    const held = this.listFor(spec.username);
    if (held.length >= max) {
      const isLive = typeof spec.isLive === 'function' ? spec.isLive :
        function (): boolean {
          return false;
        };
      const byAge = held.slice(0).reverse();
      const victim = byAge.filter(function (one) {
        return !one.session || !isLive(one.session);
      })[0] || byAge[0];
      this.store('deleteDeviceEntry', victim.id);
      log.info('devices: ' + spec.username + ' holds ' + held.length +
               ' devices (oauth2.maxDevicesPerPerson); ' + victim.id +
               ', last used ' + victim.lastUsed + ', was removed to make ' +
               'room for a new one.');
    }
    const secret = nodeCrypto.randomBytes(32).toString('base64url');
    const device: Device = {
      id: nodeCrypto.randomUUID(), dn: '', owner: ownerDn,
      label: String(spec.label || '').slice(0, 128) || 'a device',
      applications: [], secretHash: Devices.hashOf(secret),
      session: String(spec.sessionId), lastUsed: now, created: now
    };
    this.linkApplication(device, spec.clientId);
    if (!this.write(device)) {
      log.debug("Leaving Devices.issueForSession(). Not stored.");
      return { ok: false, error: 'the directory did not store the device' };
    }
    log.debug("Leaving Devices.issueForSession(). New " + device.id);
    return { ok: true, secret: secret, device: device, reused: false };
  }

  // A device a second app has used (the Native SSO exchange).
  noteUse(device: Device, clientId: unknown): void {
    const { log } = this.deps;
    log.debug("Entering Devices.noteUse().");
    device.lastUsed = new Date(this.deps.now()).toISOString();
    this.linkApplication(device, clientId);
    this.write(device);
    log.debug("Leaving Devices.noteUse().");
  }

  // RFC 7009 for a device_secret (#130): the secret stops being accepted;
  // the device stays. True when there was one to revoke.
  revokeSecret(secret: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering Devices.revokeSecret().");
    const device = this.bySecret(secret);
    if (!device) {
      log.debug("Leaving Devices.revokeSecret(). No such secret.");
      return false;
    }
    device.secretHash = '';
    device.session = '';
    const written = this.write(device);
    log.debug("Leaving Devices.revokeSecret(). " + written);
    return written;
  }

  // Removes a device — the person's own, where `username` is given.
  remove(id: unknown, username?: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.remove(). id=" + id);
    const device = this.byId(id);
    const ownerDn = username === undefined ? '' :
      String(this.store('personDnOf', String(username || '')) || '');
    if (!device || (username !== undefined &&
                    !Devices.sameDn(device.owner, ownerDn))) {
      log.debug("Leaving Devices.remove(). Not found.");
      return { ok: false, error: 'no device with that id' +
               (username !== undefined ? ' is yours' : '') + '.' };
    }
    const gone = !!this.store('deleteDeviceEntry', device.id);
    log.debug("Leaving Devices.remove(). " + gone);
    return gone ? { ok: true, removed: device.id } :
      { ok: false, error: 'the directory did not remove it.' };
  }

  // What a page or the API shows of a device: never the hash.
  static view(device: Device, isLive?: (session: string) => boolean): Json {
    helpers.log.debug("Entering Devices.view().");
    helpers.log.debug("Leaving Devices.view().");
    return { id: device.id, dn: device.dn, owner: device.owner,
             label: device.label, applications: device.applications.slice(0),
             nativeSso: !!device.secretHash,
             sessionLive: !!(device.secretHash && device.session && isLive &&
                             isLive(device.session)),
             lastUsed: device.lastUsed, created: device.created };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Devices>(
  'common/devices',
  () => new Devices(Devices.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  Devices: Devices,
  installInstance: (instance: Devices): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  hashOf: Devices.hashOf,
  view: Devices.view,
  all: slot.forward('all'),
  listFor: slot.forward('listFor'),
  byId: slot.forward('byId'),
  bySecret: slot.forward('bySecret'),
  issueForSession: slot.forward('issueForSession'),
  noteUse: slot.forward('noteUse'),
  revokeSecret: slot.forward('revokeSecret'),
  remove: slot.forward('remove')
};
