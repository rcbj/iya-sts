'use strict';
//
// File: devices.ts
//
// ===========================================================================
// THE DEVICE REGISTER (#130, 2026-09-23 — the foundation; #164 and #218,
// 2026-09-26 — the whole model).
//
// rcbj: "Devices should be tracked as first-class objects in embedded LDAP,
// linked to the current user and one or more applications." So a device is an
// ENTRY under `ou=devices`, not a field on its owner. #164 is built in six
// phases on one branch (register and views; recognition; compliance and the
// MDM feed; CAEP and RISC; risk scoring; policy, acr and token claims), and
// **this file's model was designed in phase one for all six**, so that no
// later phase has to reshape an entry that is already in somebody's
// directory. What each phase FILLS is said beside each attribute.
//
//   objectClass                 top, device (RFC 4519 section 3.4), stsDevice
//   cn                          the device's id, a UUID this service assigned
//   owner                       the DN of its ONE owner (RFC 4519): a person
//                               or an application entry (#164 decision 5)
//   stsDeviceOwnerKind          `person` or `application`
//   description                 what to call it on a page (RFC 4519)
//   stsDeviceApplication        the DN of every application that used it
//   stsDeviceKey                ONE JSON VALUE PER KEY the device holds —
//                               below, "THE KEYS"
//   stsDeviceKeyThumbprint      `<kind>:<thumbprint>` per key: an index an
//                               LDAP filter can match, derived on every write
//   stsDeviceAttestation        `attested` or `self-asserted`, derived from
//                               the keys on every write (decision 7)
//   stsDeviceCompliance         `compliant` or `not-compliant`; ABSENT is
//                               `unknown` (CAEP's vocabulary; phase 3)
//   stsDeviceComplianceChange   JSON: the last change — status, previous,
//                               at, source (admin, mdm, test-control, caep),
//                               actor, reason
//   stsDeviceStatus             `compromised`; ABSENT is `active` (phase 4's
//                               RISC credential-compromise)
//   stsDeviceStatusChange       JSON: the last change, the same shape
//   stsDevicePlatform           ios, ipados, android, macos, windows, linux,
//                               chromeos or other — a closed list, because
//                               phase 6's policy will compare it
//   stsDeviceModel, stsDeviceOs free text, descriptive only
//   stsDeviceEnrolment          JSON: how it was registered — method
//                               (native-sso, admin, portal, est, scep), at,
//                               actor (decision 6)
//   stsDeviceSecretHash         SHA-256 of its Native SSO device_secret
//                               (withheld from every LDAP read)
//   stsDeviceSession            the sign-on session that secret is good for
//   stsDeviceLastUsed           when it was last used, ISO 8601
//
// **THE KEYS ARE ONE JSON VALUE EACH, NOT A SET OF PARALLEL ATTRIBUTES.** A
// key is several facts that are true only together — its kind, its
// thumbprint, the public material, when it was added and by whom, how it was
// PROVEN and what its attestation showed — and a directory holding them as
// five multi-valued attributes would hold five lists whose Nth members are
// related by nothing but their position, which no LDAP server preserves. It
// is the shape `stsAppPassword`, `stsSelfIssuedSubject` and
// `stsIdaVerification` already chose, for this reason. Each value is:
//
//   { id, kind, thumbprint, label, added, addedBy, proof,
//     attestation: { level, format, summary, verifiedAt },
//     material: { … } }
//
//   * `kind` is `x509`, `jwk` or `webauthn` (decision 1). The Native SSO
//     device_secret is NOT a key here and stays exactly where #130 put it: it
//     is a shared secret, kept as a hash in a withheld attribute, where every
//     key here is PUBLIC material.
//   * `thumbprint` is base64url SHA-256, one digest per key whatever its
//     kind, so recognition (phase 2) asks one question: RFC 7638 over the JWK
//     for `jwk` — which is DPoP's `jkt`, so a DPoP proof names its device
//     with no conversion — and over the credential's public key for
//     `webauthn`; the SubjectPublicKeyInfo for `x509`
//     (`crypto.certificateSpkiThumbprint()`), so a renewed certificate over
//     the same key is the same key. **A thumbprint belongs to one device in
//     the realm**: a key that identified two devices would identify neither.
//   * `proof` is how possession was shown: `admin` (an administrator typed it
//     and NOTHING was proven), `webauthn`, `jwk-proof`, `dpop`, `est`,
//     `scep`, `mtls`.
//   * `attestation.level` is `attested` only where a verifier checked an
//     attestation statement (WebAuthn against FIDO MDS3, TPM key attestation
//     on EST and SCEP, Android Key Attestation, Apple App Attest — phase 2);
//     anything else is `self-asserted`. The DEVICE's level is `attested` when
//     any of its keys is, and is written beside the keys so a filter and a
//     policy read one attribute.
//   * **A key's value never changes once written.** Anything that moves on
//     every use (a last-used time) is on the DEVICE. Two nodes rewriting one
//     key's JSON at once would leave both versions in the multi-valued
//     attribute after `directory_merge.js` merged them by value — two keys
//     with one id.
//   * **No secret is ever in one**, which is why `stsDeviceKey` is NOT in
//     SECRET_ATTRIBUTES: a certificate, a public JWK and a credential id are
//     published by their holder. A JWK carrying a private member, or any
//     `oct` key, is refused (`STS-DEVICE-0004`).
//
// **WHAT PUTS ONE HERE.** Native SSO (`oauth-oidc/oauth2.ts`) since #130: the
// first app's authorization-code grant with `device_sso` mints a
// device_secret, and the device it names is this entry. An ADMINISTRATOR
// since #164 phase 1 — the console's Directory → Devices and `/admin-api/
// devices`, owned by a person or by an application (a workload host). The
// person's own portal proving a key, and EST and SCEP issuing a device
// certificate, are phase 2 and pass `method` here.
//
// **THE SECRET IS GOOD FOR ONE SIGN-ON SESSION, AND THE DEVICE OUTLIVES IT**
// (rcbj, #130). The secret is accepted only while `stsDeviceSession` names a
// live session of its owner, so a sign-out, an expiry, a disabled account or
// SSF session-revoked ends it with nothing to sweep. A later sign-in whose
// code grant PRESENTS that old secret (Native SSO section 3.3) re-binds the
// SAME device to the new session, and the secret is NEVER ROTATED (rcbj):
// every app on the device shares the value, and a rotation handed to one
// would strand the others. A secret presented by anybody but its owner, or
// naming nothing, is ignored and a new device is made. **A device given to
// another owner loses its secret** — it was bound to the first owner's
// session — and keeps its keys, which belong to the hardware.
//
// **BOUNDS.** A person holds at most `devices.maxPerPerson` (it was
// `oauth2.maxDevicesPerPerson` until #218 moved every device setting into a
// group of its own); at the bound a NATIVE SSO sign-in replaces their least
// recently used device whose session has ended — an entry per sign-in is what
// a register nobody bounds becomes — and an ADMINISTRATOR's create is
// refused instead (`STS-DEVICE-0002`), because an act a person chose must not
// silently delete something else. An application holds at most
// `devices.maxPerApplication`, and a device at most `devices.maxKeysPerDevice`
// keys.
//
// **THE EVENTS** (Monitoring → Devices): every creation, removal and eviction
// is a row in `devices.events`, per realm at its declaration, persisted, and
// bounded at the insert by `devices.eventsKept` (the oldest goes). A removal
// by an `ldapdelete` on the socket is not one of them — this file never sees
// it — and the page says so.
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
import realms = require('./realms');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import cacheRegistry = require('./cache_registry');

type Json = any;

// ---------------------------------------------------------------------------
// THE VOCABULARY. Closed lists, each read by a later phase's policy or
// signal, so a value outside one is refused rather than stored.
// ---------------------------------------------------------------------------
const OWNER_KINDS = ['person', 'application'];
const KEY_KINDS = ['x509', 'jwk', 'webauthn'];
// What a key-kind FILTER may name: the three kinds, and the Native SSO
// secret, which is not a key but is the fourth way a device is recognised.
const KEY_KIND_FILTERS = KEY_KINDS.concat(['native-sso']);
const KEY_PROOFS = ['admin', 'webauthn', 'jwk-proof', 'dpop', 'est', 'scep',
                    'mtls'];
const ATTESTATION_LEVELS = ['attested', 'self-asserted'];
// The WebAuthn attestation statement formats (the IANA registry of WebAuthn
// Level 3 section 8), and the three key attestations decision 7 names for
// EST/SCEP (TCG TPM 2.0 key attestation) and JWK proofs (Android Key
// Attestation, Apple App Attest).
const ATTESTATION_FORMATS = ['none', 'packed', 'tpm', 'android-key',
                             'android-safetynet', 'fido-u2f', 'apple',
                             'compound', 'tcg-tpm2-key',
                             'android-key-attestation', 'apple-app-attest'];
const COMPLIANCE_STATES = ['compliant', 'not-compliant', 'unknown'];
const COMPLIANCE_SOURCES = ['admin', 'mdm', 'test-control', 'caep'];
const ENROLMENT_METHODS = ['native-sso', 'admin', 'portal', 'est', 'scep'];
const STATUSES = ['active', 'compromised'];
const PLATFORMS = ['ios', 'ipados', 'android', 'macos', 'windows', 'linux',
                   'chromeos', 'other'];
const EVENT_KINDS = ['created', 'removed', 'evicted'];
// JWK members that make a key PRIVATE (RFC 7518 section 6, RFC 8037, and
// the ML-DSA JOSE draft's `priv` and `seed`): a device key here is public.
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k',
                             'priv', 'seed'];
const MAX_LABEL = 128;

interface Attestation {
  level: string;
  format: string;
  summary: string;
  verifiedAt: string;
}

interface DeviceKey {
  id: string;
  kind: string;
  thumbprint: string;
  label: string;
  added: string;
  addedBy: string;
  proof: string;
  attestation: Attestation;
  material: Json;
}

interface Change {
  status: string;
  previous: string;
  at: string;
  source?: string;
  actor: string;
  reason: string;
}

interface Enrolment {
  method: string;
  at: string;
  actor: string;
}

interface Device {
  id: string;
  dn: string;
  owner: string;
  ownerKind: string;
  label: string;
  applications: string[];
  keys: DeviceKey[];
  attestation: string;
  compliance: string;
  complianceChange: Change | null;
  status: string;
  statusChange: Change | null;
  platform: string;
  model: string;
  os: string;
  enrolment: Enrolment;
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
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  now: () => number;
}

// ---------------------------------------------------------------------------
// THE EVENTS, per realm at the declaration (common/CLAUDE.md, "A store
// becomes per realm at its DECLARATION"), persisted and tombstoned — a random
// id is never legitimately written again once the bound removed it. Keyed by
// a random id rather than counted per day, because two nodes incrementing one
// day's counter would each write their own total over the other's; a row per
// event merges by key with nothing lost.
// ---------------------------------------------------------------------------
const events = realms.map({ persist: 'devices.events', tombstone: true });

const eventsCounter = cacheRegistry.register({
  name: 'devices.events',
  title: 'Device register events',
  description: 'One row per device created, removed or evicted at a ' +
    'person\'s bound in this realm — what Monitoring → Devices draws over ' +
    'time. Never a key, a secret or an owner\'s name.',
  owner: 'common/devices.ts',
  scope: 'realm',
  kind: 'cache',
  persisted: true,
  settings: ['devices.eventsKept'],
  maxEntries: function (): number {
    return Number(config.value('devices.eventsKept'));
  },
  bound: 'Enforced: devices.eventsKept per realm, the oldest event dropped ' +
    'at the insert.',
  lifetime: function (): string {
    return 'Until devices.eventsKept newer events push it out.';
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, events,
      function (row: Json, key: unknown): object {
        return { key: String(key) + ' (' + String((row && row.kind) || '?') +
                      ')', basis: 'none' };
      });
  }
});

class Devices {
  static readonly OWNER_KINDS = OWNER_KINDS;
  static readonly KEY_KINDS = KEY_KINDS;
  static readonly KEY_KIND_FILTERS = KEY_KIND_FILTERS;
  static readonly KEY_PROOFS = KEY_PROOFS;
  static readonly ATTESTATION_LEVELS = ATTESTATION_LEVELS;
  static readonly ATTESTATION_FORMATS = ATTESTATION_FORMATS;
  static readonly COMPLIANCE_STATES = COMPLIANCE_STATES;
  static readonly COMPLIANCE_SOURCES = COMPLIANCE_SOURCES;
  static readonly ENROLMENT_METHODS = ENROLMENT_METHODS;
  static readonly STATUSES = STATUSES;
  static readonly PLATFORMS = PLATFORMS;
  static readonly EVENT_KINDS = EVENT_KINDS;

  constructor(private readonly deps: DevicesDeps) {
    deps.log.debug("Entering Devices.constructor().");
    deps.log.debug("Leaving Devices.constructor().");
  }

  static defaultDeps(): DevicesDeps {
    helpers.log.debug("Entering Devices.defaultDeps().");
    helpers.log.debug("Leaving Devices.defaultDeps().");
    return { log: helpers.log, config: config, credentials: credentials,
             stsCrypto: stsCrypto, errorCodes: errorCodes, audit: audit,
             now: Date.now };
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

  private nowIso(): string {
    this.deps.log.debug("Entering Devices.nowIso().");
    this.deps.log.debug("Leaving Devices.nowIso().");
    return new Date(this.deps.now()).toISOString();
  }

  // A refusal, marked with its code and carrying the sentence both as
  // `error` (what the #130 callers read) and `errors` (what the console and
  // the API answer with).
  private refuse(code: string, why: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Devices.refuse(). " + code);
    log.debug("Leaving Devices.refuse().");
    return errorCodes.mark({ ok: false, error: why, errors: [why] }, code);
  }

  // One JSON value of an attribute, or null for one this service did not
  // write — skipped rather than thrown, so one malformed value written over
  // the socket cannot hide the device it is on.
  private static parsed(value: unknown): Json {
    helpers.log.debug("Entering Devices.parsed().");
    if (!value) {
      helpers.log.debug("Leaving Devices.parsed(). Empty.");
      return null;
    }
    try {
      const out = JSON.parse(String(value));
      helpers.log.debug("Leaving Devices.parsed().");
      return out && typeof out === 'object' ? out : null;
    } catch (e) {
      helpers.log.debug("Caught in Devices.parsed(): " +
                        ((e && e.message) || e));
      helpers.log.debug("Leaving Devices.parsed(). Not JSON.");
      return null;
    }
  }

  private static fromEntry(entry: Json): Device {
    helpers.log.debug("Entering Devices.fromEntry().");
    const a = (entry && entry.attributes) || {};
    // A HOT PATH: once per attribute of every device on every read of the
    // register, so no Entering/Leaving pair — it would drown the log.
    const one = function (name: string): string {
      return String((a[name] || [])[0] || '');
    };
    const keys = (a.stsdevicekey || []).map(Devices.parsed)
      .filter(function (k: Json) {
        return k && typeof k.id === 'string' && KEY_KINDS.indexOf(k.kind) >= 0;
      });
    const enrolment = Devices.parsed(one('stsdeviceenrolment')) || {};
    helpers.log.debug("Leaving Devices.fromEntry().");
    return {
      id: one('cn'), dn: String(entry.dn || ''), owner: one('owner'),
      // Every entry #130 wrote was a Native SSO device of a PERSON and
      // carries neither attribute; that is what an absent one says.
      ownerKind: one('stsdeviceownerkind') || 'person',
      label: one('description'),
      applications: (a.stsdeviceapplication || []).map(String),
      keys: keys,
      attestation: Devices.levelOf(keys),
      compliance: COMPLIANCE_STATES.indexOf(one('stsdevicecompliance')) >= 0
        ? one('stsdevicecompliance') : 'unknown',
      complianceChange: Devices.parsed(one('stsdevicecompliancechange')),
      status: one('stsdevicestatus') === 'compromised' ? 'compromised'
                                                       : 'active',
      statusChange: Devices.parsed(one('stsdevicestatuschange')),
      platform: one('stsdeviceplatform'),
      model: one('stsdevicemodel'),
      os: one('stsdeviceos'),
      enrolment: {
        method: String(enrolment.method || 'native-sso'),
        at: String(enrolment.at || ''),
        actor: String(enrolment.actor || '')
      },
      secretHash: one('stsdevicesecrethash'),
      session: one('stsdevicesession'),
      lastUsed: one('stsdevicelastused'),
      created: one('createtimestamp')
    };
  }

  // The device's attestation level, from its keys: attested when any key's
  // attestation was verified, self-asserted otherwise (decision 7).
  static levelOf(keys: DeviceKey[]): string {
    helpers.log.debug("Entering Devices.levelOf().");
    const attested = (keys || []).some(function (k) {
      return !!k.attestation && k.attestation.level === 'attested';
    });
    helpers.log.debug("Leaving Devices.levelOf().");
    return attested ? 'attested' : 'self-asserted';
  }

  private write(device: Device): boolean {
    const { log } = this.deps;
    log.debug("Entering Devices.write(). id=" + device.id);
    const attributes: Json = {
      objectClass: ['top', 'device', 'stsDevice'],
      cn: [device.id],
      owner: [device.owner],
      stsDeviceOwnerKind: [device.ownerKind || 'person'],
      description: [device.label || 'a device'],
      stsDeviceAttestation: [Devices.levelOf(device.keys)],
      stsDeviceEnrolment: [JSON.stringify(device.enrolment)],
      stsDeviceLastUsed: [device.lastUsed || this.nowIso()]
    };
    const optional: Array<[string, string]> = [
      ['stsDevicePlatform', device.platform],
      ['stsDeviceModel', device.model],
      ['stsDeviceOs', device.os],
      ['stsDeviceSecretHash', device.secretHash],
      ['stsDeviceSession', device.session]
    ];
    optional.forEach(function (pair) {
      if (pair[1]) {
        attributes[pair[0]] = [pair[1]];
      }
    });
    if (device.applications.length) {
      attributes.stsDeviceApplication = device.applications.slice(0);
    }
    if (device.keys.length) {
      attributes.stsDeviceKey = device.keys.map(function (k) {
        return JSON.stringify(k);
      });
      attributes.stsDeviceKeyThumbprint = device.keys.map(function (k) {
        return k.kind + ':' + k.thumbprint;
      });
    }
    if (device.compliance && device.compliance !== 'unknown') {
      attributes.stsDeviceCompliance = [device.compliance];
    }
    if (device.complianceChange) {
      attributes.stsDeviceComplianceChange =
        [JSON.stringify(device.complianceChange)];
    }
    if (device.status === 'compromised') {
      attributes.stsDeviceStatus = ['compromised'];
    }
    if (device.statusChange) {
      attributes.stsDeviceStatusChange = [JSON.stringify(device.statusChange)];
    }
    const written = !!this.store('writeDeviceEntry', device.id, attributes);
    log.debug("Leaving Devices.write(). " + written);
    return written;
  }

  // -------------------------------------------------------------------------
  // THE EVENTS. One row per creation, removal and eviction, bounded at the
  // insert (cache_registry.makeRoom()), never a sweep (root CLAUDE.md,
  // "Anything periodic is a scheduler job": a bound cannot wait for a timer).
  // -------------------------------------------------------------------------
  private noteEvent(kind: string, device: Device, reason?: string): void {
    const { log, config } = this.deps;
    log.debug("Entering Devices.noteEvent(). " + kind);
    cacheRegistry.makeRoom(events, Number(config.value('devices.eventsKept')),
                           { name: 'devices.events',
                             counter: eventsCounter,
                             setting: 'devices.eventsKept' });
    events.set(nodeCrypto.randomUUID(), {
      at: this.deps.now(), kind: kind, device: device.id,
      ownerKind: device.ownerKind, method: device.enrolment.method,
      reason: String(reason || '')
    });
    log.debug("Leaving Devices.noteEvent().");
  }

  // This realm's events, oldest first.
  events(): Json[] {
    const { log } = this.deps;
    log.debug("Entering Devices.events().");
    const out: Json[] = [];
    events.forEach(function (row: Json) {
      out.push(Object.assign({}, row));
    });
    out.sort(function (a: Json, b: Json) {
      return Number(a.at) - Number(b.at);
    });
    log.debug("Leaving Devices.events(). " + out.length + ".");
    return out;
  }

  // The events of the last `days` UTC days, one row per day oldest first,
  // and the totals over every event this realm still holds.
  timeline(days?: number): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.timeline().");
    const span = Math.max(1, Math.min(366, Number(days) || 30));
    const today = Math.floor(this.deps.now() / 86400000);
    const rows: Json[] = [];
    const byDay: Record<string, Json> = {};
    for (let d = today - span + 1; d <= today; d += 1) {
      const day = new Date(d * 86400000).toISOString().slice(0, 10);
      const row: Json = { day: day, created: 0, removed: 0, evicted: 0 };
      rows.push(row);
      byDay[day] = row;
    }
    const totals: Json = { created: 0, removed: 0, evicted: 0 };
    let since = '';
    this.events().forEach(function (e: Json) {
      if (EVENT_KINDS.indexOf(e.kind) < 0) {
        return;
      }
      totals[e.kind] += 1;
      if (!since) {
        since = new Date(Number(e.at)).toISOString();
      }
      const day = new Date(Number(e.at)).toISOString().slice(0, 10);
      if (byDay[day]) {
        byDay[day][e.kind] += 1;
      }
    });
    log.debug("Leaving Devices.timeline().");
    return { days: span, rows: rows, totals: totals, since: since };
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

  private static byRecency(a: Device, b: Device): number {
    helpers.log.debug("Entering Devices.byRecency().");
    helpers.log.debug("Leaving Devices.byRecency().");
    return String(b.lastUsed).localeCompare(String(a.lastUsed));
  }

  // An owner's devices, most recently used first. [] for no owner.
  listForOwner(ownerDn: unknown): Device[] {
    const { log } = this.deps;
    log.debug("Entering Devices.listForOwner().");
    const dn = String(ownerDn || '');
    const out = dn ? this.all().filter(function (one) {
      return Devices.sameDn(one.owner, dn);
    }).sort(Devices.byRecency) : [];
    log.debug("Leaving Devices.listForOwner(). " + out.length + ".");
    return out;
  }

  // A person's devices, most recently used first. [] for nobody.
  listFor(username: unknown): Device[] {
    const { log } = this.deps;
    log.debug("Entering Devices.listFor(). user=" + username);
    const ownerDn = String(this.store('personDnOf', String(username || '')) ||
                           '');
    log.debug("Leaving Devices.listFor().");
    return ownerDn ? this.listForOwner(ownerDn) : [];
  }

  // -------------------------------------------------------------------------
  // THE REALM'S DEVICES, FILTERED, most recently used first. Every member of
  // `filter` is optional and they are ANDed:
  //
  //   ownerKind    person | application
  //   owner        a DN, a username or an application identifier
  //   application  a DN or an application identifier the device was used by
  //   compliance   compliant | not-compliant | unknown
  //   attestation  attested | self-asserted
  //   keyKind      x509 | jwk | webauthn | native-sso
  //   status       active | compromised
  //   q            a substring of the id, the label, the owner's DN, a key's
  //                thumbprint or label, the platform, the model or the OS
  //
  // A value outside a closed list matches nothing rather than everything: a
  // misspelt `compliance=complaint` answering the whole register would read
  // as "every device is complaint".
  // -------------------------------------------------------------------------
  list(filter?: Json): Device[] {
    const { log } = this.deps;
    log.debug("Entering Devices.list().");
    const f = filter || {};
    // A HOT PATH: several times per device in the filter below, so no
    // Entering/Leaving pair — it would drown the log.
    const text = function (v: unknown): string {
      return String(v === undefined || v === null ? '' : v).trim();
    };
    const ownerDn = text(f.owner) ? this.ownerDnFor(text(f.owner),
                                                   text(f.ownerKind)) : '';
    const appDn = text(f.application)
      ? (text(f.application).indexOf('=') >= 0 ? text(f.application)
        : String(this.store('applicationDnOf', text(f.application)) || ''))
      : '';
    const needle = text(f.q).toLowerCase();
    const out = this.all().filter(function (d) {
      if (text(f.ownerKind) && d.ownerKind !== text(f.ownerKind)) {
        return false;
      }
      if (text(f.owner) && !Devices.sameDn(d.owner, ownerDn)) {
        return false;
      }
      if (text(f.application) && !d.applications.some(function (dn) {
        return Devices.sameDn(dn, appDn);
      })) {
        return false;
      }
      if (text(f.compliance) && d.compliance !== text(f.compliance)) {
        return false;
      }
      if (text(f.attestation) && d.attestation !== text(f.attestation)) {
        return false;
      }
      if (text(f.status) && d.status !== text(f.status)) {
        return false;
      }
      if (text(f.keyKind) && Devices.keyKindsOf(d)
            .indexOf(text(f.keyKind)) < 0) {
        return false;
      }
      if (needle) {
        const hay = [d.id, d.label, d.owner, d.platform, d.model, d.os]
          .concat(d.keys.map(function (k) {
            return k.thumbprint + ' ' + k.label;
          })).join('\n').toLowerCase();
        if (hay.indexOf(needle) < 0) {
          return false;
        }
      }
      return true;
    }).sort(Devices.byRecency);
    log.debug("Leaving Devices.list(). " + out.length + ".");
    return out;
  }

  // One page of `list(filter)`: `page` from 1, `per` rows, the page clamped
  // to the last one — the console's `pagingOf()` rule, for a caller without
  // the console (a test, a later phase's job).
  page(filter: Json, page?: unknown, per?: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.page().");
    const rows = this.list(filter);
    const perPage = Math.max(1, Math.min(500, Number(per) || 50));
    const pages = Math.max(1, Math.ceil(rows.length / perPage));
    const at = Math.max(1, Math.min(pages, Number(page) || 1));
    log.debug("Leaving Devices.page().");
    return { rows: rows.slice((at - 1) * perPage, at * perPage),
             total: rows.length, page: at, pages: pages, perPage: perPage };
  }

  // The kinds of key a device can be recognised by — its keys' kinds, and
  // `native-sso` while it holds a secret.
  static keyKindsOf(device: Device): string[] {
    helpers.log.debug("Entering Devices.keyKindsOf().");
    const out: string[] = [];
    device.keys.forEach(function (k) {
      if (out.indexOf(k.kind) < 0) {
        out.push(k.kind);
      }
    });
    if (device.secretHash) {
      out.push('native-sso');
    }
    helpers.log.debug("Leaving Devices.keyKindsOf().");
    return out;
  }

  byId(id: unknown): Device | null {
    const { log } = this.deps;
    log.debug("Entering Devices.byId().");
    const wanted = String(id || '');
    const found = wanted ? this.all().filter(function (one) {
      return one.id === wanted;
    })[0] || null : null;
    log.debug("Leaving Devices.byId(). " + !!found);
    return found;
  }

  // The device a key thumbprint belongs to, or null — what phase 2's
  // recognition asks. `kind` narrows it where the caller knows it.
  byKeyThumbprint(thumbprint: unknown, kind?: unknown): Device | null {
    const { log } = this.deps;
    log.debug("Entering Devices.byKeyThumbprint().");
    const wanted = String(thumbprint || '');
    const wantedKind = String(kind || '');
    const found = wanted ? this.all().filter(function (one) {
      return one.keys.some(function (k) {
        return k.thumbprint === wanted &&
               (!wantedKind || k.kind === wantedKind);
      });
    })[0] || null : null;
    log.debug("Leaving Devices.byKeyThumbprint(). " + !!found);
    return found;
  }

  // The device a linked WebAuthn credential id belongs to, or null — what
  // recognition asks at a sign-in, where the assertion names its credential
  // by id (phase 2).
  byCredentialId(credentialId: unknown): Device | null {
    const { log } = this.deps;
    log.debug("Entering Devices.byCredentialId().");
    const wanted = String(credentialId || '');
    const found = wanted ? this.all().filter(function (one) {
      return one.keys.some(function (k) {
        return k.kind === 'webauthn' && k.material &&
               String(k.material.credentialId || '') === wanted;
      });
    })[0] || null : null;
    log.debug("Leaving Devices.byCredentialId(). " + !!found);
    return found;
  }

  // A RECOGNISED device (phase 2): its last use moves, and the application
  // it was recognised for is linked. Written at most once per
  // `devices.lastUsedResolutionSeconds` unless an application is new to it,
  // so a busy device is not a directory write on every token request.
  // Answers whether anything was written.
  noteRecognized(device: Device, clientId?: unknown): boolean {
    const { log, config } = this.deps;
    log.debug("Entering Devices.noteRecognized(). id=" + device.id);
    const before = device.applications.length;
    this.linkApplication(device, clientId);
    const resolution = Number(config.value(
      'devices.lastUsedResolutionSeconds')) * 1000;
    const last = Date.parse(device.lastUsed || '') || 0;
    const stale = this.deps.now() - last >= resolution;
    if (!stale && device.applications.length === before) {
      log.debug("Leaving Devices.noteRecognized(). Recent enough.");
      return false;
    }
    device.lastUsed = this.nowIso();
    const written = this.write(device);
    log.debug("Leaving Devices.noteRecognized(). " + written);
    return written;
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

  // Who owns a DN: { kind, name, dn }, or null where the directory holds no
  // person or application entry there.
  ownerOf(dn: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.ownerOf().");
    const found = dn ? this.store('ownerOf', String(dn)) : null;
    log.debug("Leaving Devices.ownerOf(). " + !!found);
    return found || null;
  }

  // An owner's DN from what a caller typed: a DN (checked against the
  // directory), a username, or an application identifier. '' for nobody.
  private ownerDnFor(name: string, kind: string): string {
    const { log } = this.deps;
    log.debug("Entering Devices.ownerDnFor(). kind=" + kind);
    let dn = '';
    if (name.indexOf('=') >= 0) {
      const found = this.ownerOf(name);
      dn = found && (!kind || found.kind === kind) ? String(found.dn) : '';
    } else if (kind === 'application') {
      dn = String(this.store('applicationDnOf', name) || '');
    } else {
      dn = String(this.store('personDnOf', name) || '');
    }
    log.debug("Leaving Devices.ownerDnFor(). " + (dn ? 'Found.' : 'None.'));
    return dn;
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

  private capFor(kind: string): number {
    const { log, config } = this.deps;
    log.debug("Entering Devices.capFor(). " + kind);
    log.debug("Leaving Devices.capFor().");
    return Number(config.value(kind === 'application'
      ? 'devices.maxPerApplication' : 'devices.maxPerPerson'));
  }

  private recordAudit(action: string, actor: string, device: Device,
                      summary: string, detail?: Json): void {
    const { log, audit } = this.deps;
    log.debug("Entering Devices.recordAudit(). " + action);
    audit.audit({ action: action, actor: actor || '', target: device.owner,
                  outcome: 'success', summary: summary,
                  detail: Object.assign({ id: device.id,
                                          ownerKind: device.ownerKind },
                                        detail || {}) });
    log.debug("Leaving Devices.recordAudit().");
  }

  // -------------------------------------------------------------------------
  // THE FIRST APP'S GRANT (Native SSO section 3.3). `spec` is { username,
  // clientId, sessionId, presented, label, isLive(sessionId) }. Returns
  // { ok, secret, device, reused } or { ok: false, error }.
  // -------------------------------------------------------------------------
  issueForSession(spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.issueForSession(). user=" + spec.username);
    const ownerDn = String(this.store('personDnOf',
                                      String(spec.username || '')) || '');
    if (!ownerDn || !spec.sessionId) {
      log.debug("Leaving Devices.issueForSession(). No person or session.");
      return { ok: false, error: !ownerDn
        ? 'there is no directory entry for "' + spec.username + '"'
        : 'the grant names no sign-on session' };
    }
    const now = this.nowIso();
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
    const max = this.capFor('person');
    const held = this.listForOwner(ownerDn);
    if (held.length >= max) {
      const isLive = typeof spec.isLive === 'function' ? spec.isLive :
        function (): boolean {
          return false;
        };
      const byAge = held.slice(0).reverse();
      const victim = byAge.filter(function (one) {
        return !one.session || !isLive(one.session);
      })[0] || byAge[0];
      if (this.store('deleteDeviceEntry', victim.id)) {
        this.noteEvent('evicted', victim, 'devices.maxPerPerson');
        this.recordAudit('device.evict', String(spec.username || ''), victim,
                         'device ' + victim.id + ' removed at ' +
                         'devices.maxPerPerson to make room for a new one');
      }
      log.info('devices: ' + spec.username + ' holds ' + held.length +
               ' devices (devices.maxPerPerson); ' + victim.id +
               ', last used ' + victim.lastUsed + ', was removed to make ' +
               'room for a new one.');
    }
    const secret = nodeCrypto.randomBytes(32).toString('base64url');
    const device = Devices.blank(ownerDn, 'person',
      String(spec.label || '').slice(0, MAX_LABEL) || 'a device',
      { method: 'native-sso', at: now, actor: String(spec.username || '') });
    device.secretHash = Devices.hashOf(secret);
    device.session = String(spec.sessionId);
    this.linkApplication(device, spec.clientId);
    if (!this.write(device)) {
      log.debug("Leaving Devices.issueForSession(). Not stored.");
      return { ok: false, error: 'the directory did not store the device' };
    }
    this.noteEvent('created', device);
    log.debug("Leaving Devices.issueForSession(). New " + device.id);
    return { ok: true, secret: secret, device: device, reused: false };
  }

  private static blank(ownerDn: string, ownerKind: string, label: string,
                       enrolment: Enrolment): Device {
    helpers.log.debug("Entering Devices.blank().");
    helpers.log.debug("Leaving Devices.blank().");
    return {
      id: nodeCrypto.randomUUID(), dn: '', owner: ownerDn,
      ownerKind: ownerKind, label: label, applications: [], keys: [],
      attestation: 'self-asserted', compliance: 'unknown',
      complianceChange: null, status: 'active', statusChange: null,
      platform: '', model: '', os: '', enrolment: enrolment,
      secretHash: '', session: '', lastUsed: enrolment.at,
      created: enrolment.at
    };
  }

  // A device a second app has used (the Native SSO exchange).
  noteUse(device: Device, clientId: unknown): void {
    const { log } = this.deps;
    log.debug("Entering Devices.noteUse().");
    device.lastUsed = this.nowIso();
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

  // One line of text of at most `max` characters, or a refusal.
  private checkedText(name: string, value: unknown, max: number): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.checkedText(). " + name);
    const text = String(value === undefined || value === null ? ''
                                                            : value).trim();
    if (text.length > max || /[\u0000-\u001f\u007f]/.test(text)) {
      log.debug("Leaving Devices.checkedText(). Refused.");
      return this.refuse('STS-DEVICE-0010', 'A device\'s ' + name + ' is at ' +
                         'most ' + max + ' characters of text on one line.');
    }
    log.debug("Leaving Devices.checkedText().");
    return { ok: true, value: text };
  }

  // The descriptive fields a spec carries, applied to `device`. Answers null
  // when every one was acceptable, or the refusal.
  private applyDescription(device: Device, spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.applyDescription().");
    if (spec.label !== undefined) {
      const label = this.checkedText('label', spec.label, MAX_LABEL);
      if (!label.ok) {
        log.debug("Leaving Devices.applyDescription(). label.");
        return label;
      }
      device.label = label.value || 'a device';
    }
    if (spec.platform !== undefined) {
      const platform = String(spec.platform || '').trim().toLowerCase();
      if (platform && PLATFORMS.indexOf(platform) < 0) {
        log.debug("Leaving Devices.applyDescription(). platform.");
        return this.refuse('STS-DEVICE-0010', 'Unknown platform "' +
          platform + '". The ' + PLATFORMS.length + ' are: ' +
          Devices.sentence(PLATFORMS) + ' — or none.');
      }
      device.platform = platform;
    }
    const fields: Array<[string, string]> = [['model', 'model'],
                                             ['os', 'operating system']];
    for (const pair of fields) {
      if (spec[pair[0]] !== undefined) {
        const checked = this.checkedText(pair[1], spec[pair[0]], MAX_LABEL);
        if (!checked.ok) {
          log.debug("Leaving Devices.applyDescription(). " + pair[0]);
          return checked;
        }
        (device as Json)[pair[0]] = checked.value;
      }
    }
    log.debug("Leaving Devices.applyDescription().");
    return null;
  }

  // "a, b and c" — the list shape the parity tests read out of a refusal.
  static sentence(list: string[]): string {
    helpers.log.debug("Entering Devices.sentence().");
    helpers.log.debug("Leaving Devices.sentence().");
    return list.length < 2 ? list.join('')
      : list.slice(0, -1).join(', ') + ' and ' + list[list.length - 1];
  }

  // The applications a spec names (client ids, identifiers or DNs), as DNs.
  private applicationDns(names: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.applicationDns().");
    const list = (Array.isArray(names) ? names : String(names || '')
      .split(/[\s,]+/)).map(function (n) {
        return String(n || '').trim();
      }).filter(Boolean);
    const out: string[] = [];
    for (const name of list) {
      const found = name.indexOf('=') >= 0 ? this.ownerOf(name) : null;
      const dn = name.indexOf('=') >= 0
        ? (found && found.kind === 'application' ? String(found.dn) : '')
        : String(this.store('applicationDnOf', name) || '');
      if (!dn) {
        log.debug("Leaving Devices.applicationDns(). Unknown " + name);
        return this.refuse('STS-DEVICE-0012', 'There is no application "' +
                           name + '" in this realm\'s directory.');
      }
      if (!out.some(function (one) {
        return Devices.sameDn(one, dn);
      })) {
        out.push(dn);
      }
    }
    log.debug("Leaving Devices.applicationDns(). " + out.length + ".");
    return { ok: true, value: out };
  }

  // The owner a spec names, resolved: { ok, dn, kind } or a refusal.
  private resolveOwner(spec: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.resolveOwner().");
    const kind = String(spec.ownerKind || 'person').trim();
    const name = String(spec.owner || '').trim();
    if (OWNER_KINDS.indexOf(kind) < 0) {
      log.debug("Leaving Devices.resolveOwner(). Kind.");
      return this.refuse('STS-DEVICE-0001', 'Unknown owner kind "' + kind +
        '". The two are: person and application.');
    }
    if (!name) {
      log.debug("Leaving Devices.resolveOwner(). Nobody.");
      return this.refuse('STS-DEVICE-0001', 'Name the device\'s owner in ' +
        '`owner` — a username, or with `ownerKind` application an ' +
        'application\'s identifier.');
    }
    const dn = this.ownerDnFor(name, kind);
    if (!dn) {
      log.debug("Leaving Devices.resolveOwner(). Not found.");
      return this.refuse('STS-DEVICE-0001', 'There is no ' + kind + ' "' +
                         name + '" in this realm\'s directory to own a ' +
                         'device.');
    }
    log.debug("Leaving Devices.resolveOwner().");
    return { ok: true, dn: dn, kind: kind };
  }

  private underCap(ownerDn: string, kind: string, except?: string): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.underCap().");
    const cap = this.capFor(kind);
    const held = this.listForOwner(ownerDn).filter(function (d) {
      return d.id !== except;
    }).length;
    if (held >= cap) {
      const code = kind === 'application' ? 'STS-DEVICE-0003'
                                          : 'STS-DEVICE-0002';
      log.debug("Leaving Devices.underCap(). Full.");
      return this.refuse(code, 'That ' + kind + ' already owns ' + held +
        ' device(s), which is the most this realm allows (' +
        (kind === 'application' ? 'devices.maxPerApplication'
                                : 'devices.maxPerPerson') +
        '). Remove one first.');
    }
    log.debug("Leaving Devices.underCap().");
    return null;
  }

  // The x509 half of prepareKey(): the SPKI thumbprint and the names.
  private x509Material(pem: string): Json {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering Devices.x509Material().");
    const thumbprint = stsCrypto.certificateSpkiThumbprint(pem);
    const ids = stsCrypto.certificateIdentifiers(pem);
    let notAfter = '';
    try {
      notAfter = new Date(new nodeCrypto.X509Certificate(pem).validTo)
        .toISOString();
    } catch (e) {
      // A post-quantum certificate node cannot load: its key and its names
      // were still read above; only the expiry goes unreported.
      log.debug("Caught in Devices.x509Material(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving Devices.x509Material().");
    return { thumbprint: thumbprint,
             material: { certificate: pem, subject: ids.subject,
                         issuer: ids.issuer, serial: ids.serial,
                         notAfter: notAfter } };
  }

  // The jwk half: public members only, and never a symmetric key.
  private jwkMaterial(value: unknown): Json {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering Devices.jwkMaterial().");
    const jwk: Json = typeof value === 'string' ? JSON.parse(value) : value;
    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) {
      log.debug("Leaving Devices.jwkMaterial(). Not an object.");
      throw new Error('a JWK is a JSON object');
    }
    const secretMembers = PRIVATE_JWK_MEMBERS.filter(function (m) {
      return jwk[m] !== undefined;
    });
    if (jwk.kty === 'oct' || secretMembers.length) {
      log.debug("Leaving Devices.jwkMaterial(). Private.");
      return this.refuse('STS-DEVICE-0004', 'A device key is PUBLIC ' +
        'material: this JWK ' + (jwk.kty === 'oct'
          ? 'is a symmetric key' : 'carries the private member(s) ' +
            secretMembers.join(', ')) + ', and nothing was stored.');
    }
    const thumbprint = stsCrypto.jwkThumbprint(jwk);
    const pub: Json = {};
    Object.keys(jwk).sort().forEach(function (m) {
      pub[m] = jwk[m];
    });
    log.debug("Leaving Devices.jwkMaterial().");
    return { thumbprint: thumbprint, material: { jwk: pub } };
  }

  // The webauthn half: a credential the OWNER already enrolled, linked to
  // the device by its id; its public key is the one the registration
  // ceremony verified.
  private webauthnMaterial(credentialId: string,
                           owner: { dn: string; kind: string }): Json {
    const { log, stsCrypto, credentials } = this.deps;
    log.debug("Entering Devices.webauthnMaterial().");
    const username = owner.kind === 'person'
      ? String((this.ownerOf(owner.dn) || {}).name || '') : '';
    const held: Json = username ? (credentials.keysOf(username) || [])
      .filter(function (k: Json) {
        return String(k.credentialId) === credentialId;
      })[0] : null;
    if (!held) {
      log.debug("Leaving Devices.webauthnMaterial(). Not the owner's.");
      return this.refuse('STS-DEVICE-0015', 'No security key with ' +
        'credential id "' + credentialId + '" is enrolled by this device\'s ' +
        'owner' + (owner.kind === 'person' ? '' : ' — a WebAuthn ' +
          'credential belongs to a person, and this device\'s owner is an ' +
          'application') + '.');
    }
    log.debug("Leaving Devices.webauthnMaterial().");
    return { thumbprint: stsCrypto.jwkThumbprint(held.publicKeyJwk),
             material: { credentialId: credentialId,
                         aaguid: String(held.aaguid || ''),
                         attachment: String(held.attachment || '') } };
  }

  // -------------------------------------------------------------------------
  // A KEY, CHECKED AND MADE INTO THE VALUE THAT IS STORED. `spec` is
  // { kind, certificate | jwk | credentialId (or `value`), label, proof,
  // attestation }.
  //
  // `proof` and `attestation` are what the CALLER proved and verified: the
  // console and the API pass `admin` and nothing, which is recorded as
  // self-asserted — they must never forward a body's claim to either. Phase
  // 2's enrolment doors pass what their ceremony established.
  // -------------------------------------------------------------------------
  private prepareKey(spec: Json, owner: { dn: string; kind: string },
                     actor: string): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.prepareKey().");
    const s = spec || {};
    const kind = String(s.kind || '').trim();
    if (KEY_KINDS.indexOf(kind) < 0) {
      log.debug("Leaving Devices.prepareKey(). Kind.");
      return this.refuse('STS-DEVICE-0004', 'Unknown key kind "' + kind +
        '". The three are: ' + Devices.sentence(KEY_KINDS) + '.');
    }
    const label = this.checkedText('key label', s.label, MAX_LABEL);
    if (!label.ok) {
      log.debug("Leaving Devices.prepareKey(). Label.");
      return label;
    }
    const proof = String(s.proof || 'admin');
    const att = s.attestation || {};
    const format = String(att.format || 'none');
    if (KEY_PROOFS.indexOf(proof) < 0 ||
        ATTESTATION_FORMATS.indexOf(format) < 0) {
      log.debug("Leaving Devices.prepareKey(). Proof or format.");
      return this.refuse('STS-DEVICE-0004', 'Unknown proof "' + proof +
                         '" or attestation format "' + format + '".');
    }
    const level = att.level === 'attested' ? 'attested' : 'self-asserted';
    let read: Json = null;
    try {
      if (kind === 'x509') {
        read = this.x509Material(String(s.certificate || s.value || '')
          .trim());
      } else if (kind === 'jwk') {
        read = this.jwkMaterial(s.jwk !== undefined ? s.jwk : s.value);
      } else {
        read = this.webauthnMaterial(String(s.credentialId || s.value || '')
          .trim(), owner);
      }
    } catch (e) {
      log.debug("Caught in Devices.prepareKey(): " + ((e && e.message) || e));
      log.debug("Leaving Devices.prepareKey(). Unreadable.");
      return this.refuse('STS-DEVICE-0004', 'That ' + kind + ' key could ' +
        'not be read: ' + String((e && e.message) || e));
    }
    if (read.ok === false) {
      log.debug("Leaving Devices.prepareKey(). Refused.");
      return read;
    }
    const now = this.nowIso();
    const key: DeviceKey = {
      id: 'k-' + nodeCrypto.randomBytes(9).toString('base64url'),
      kind: kind, thumbprint: read.thumbprint,
      label: label.value || kind + ' key', added: now,
      addedBy: String(actor || ''), proof: proof,
      attestation: { level: level, format: format,
                     summary: String(att.summary || '').slice(0, 500),
                     verifiedAt: level === 'attested'
                       ? String(att.verifiedAt || now) : '' },
      material: read.material
    };
    log.debug("Leaving Devices.prepareKey(). " + kind);
    return { ok: true, key: key };
  }

  // A key another device already holds cannot be added (header, THE KEYS).
  private keyTaken(key: DeviceKey, exceptDevice: string): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.keyTaken().");
    const holder = this.byKeyThumbprint(key.thumbprint);
    if (holder && holder.id !== exceptDevice) {
      log.debug("Leaving Devices.keyTaken(). Taken.");
      return this.refuse('STS-DEVICE-0005', 'That key (' + key.kind + ' ' +
        key.thumbprint + ') is already registered to device ' + holder.id +
        ': a key identifies ONE device.');
    }
    log.debug("Leaving Devices.keyTaken().");
    return null;
  }

  // -------------------------------------------------------------------------
  // CREATE (decision 6a, and phase 2's portal and EST/SCEP through `method`).
  // `spec` is { label, ownerKind, owner, platform, model, os, applications,
  // keys: [keySpec], method }. Answers { ok, device } or a refusal.
  // -------------------------------------------------------------------------
  create(spec: Json, actor?: unknown): Json {
    const { log, config } = this.deps;
    log.debug("Entering Devices.create().");
    const s = spec || {};
    const who = String(actor || '');
    const method = String(s.method || 'admin');
    if (ENROLMENT_METHODS.indexOf(method) < 0 || method === 'native-sso') {
      log.debug("Leaving Devices.create(). Method.");
      return this.refuse('STS-DEVICE-0010', 'Unknown enrolment method "' +
                         method + '".');
    }
    const owner = this.resolveOwner(s);
    if (!owner.ok) {
      log.debug("Leaving Devices.create(). Owner.");
      return owner;
    }
    const full = this.underCap(owner.dn, owner.kind);
    if (full) {
      log.debug("Leaving Devices.create(). Full.");
      return full;
    }
    const now = this.nowIso();
    const device = Devices.blank(owner.dn, owner.kind, 'a device',
                                 { method: method, at: now, actor: who });
    const described = this.applyDescription(device, s);
    if (described) {
      log.debug("Leaving Devices.create(). Description.");
      return described;
    }
    if (s.applications !== undefined) {
      const apps = this.applicationDns(s.applications);
      if (!apps.ok) {
        log.debug("Leaving Devices.create(). Applications.");
        return apps;
      }
      device.applications = apps.value;
    }
    const specs = Array.isArray(s.keys) ? s.keys : [];
    const maxKeys = Number(config.value('devices.maxKeysPerDevice'));
    if (specs.length > maxKeys) {
      log.debug("Leaving Devices.create(). Too many keys.");
      return this.refuse('STS-DEVICE-0006', 'A device holds at most ' +
        maxKeys + ' keys (devices.maxKeysPerDevice).');
    }
    for (const one of specs) {
      const prepared = this.prepareKey(one, owner, who);
      if (!prepared.ok) {
        log.debug("Leaving Devices.create(). Key.");
        return prepared;
      }
      const twice = device.keys.some(function (k) {
        return k.thumbprint === prepared.key.thumbprint;
      });
      const taken = twice
        ? this.refuse('STS-DEVICE-0005', 'The same key is named twice.')
        : this.keyTaken(prepared.key, '');
      if (taken) {
        log.debug("Leaving Devices.create(). Key taken.");
        return taken;
      }
      device.keys.push(prepared.key);
    }
    if (!this.write(device)) {
      log.debug("Leaving Devices.create(). Not stored.");
      return this.refuse('STS-DEVICE-0009', 'The directory did not store ' +
                         'the device (it may hold its maximum of entries).');
    }
    this.noteEvent('created', device);
    this.recordAudit('device.create', who, device, 'device ' + device.id +
                     ' registered (' + method + ') for ' + device.owner,
                     { method: method, keys: device.keys.length });
    log.debug("Leaving Devices.create(). " + device.id);
    return { ok: true, device: this.byId(device.id) || device,
             message: 'Device ' + device.id + ' is registered.' };
  }

  // -------------------------------------------------------------------------
  // UPDATE: label, owner (and its kind), platform, model, OS, applications.
  // A new owner is held to its own bound, and takes the device WITHOUT its
  // Native SSO secret (header).
  // -------------------------------------------------------------------------
  update(id: unknown, changes: Json, actor?: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.update().");
    const c = changes || {};
    const device = this.byId(id);
    if (!device) {
      log.debug("Leaving Devices.update(). No device.");
      return this.refuse('STS-DEVICE-0007', 'There is no device "' +
                         String(id || '') + '" in this realm.');
    }
    const changed: string[] = [];
    if (c.owner !== undefined && String(c.owner).trim() !== '') {
      const owner = this.resolveOwner({ owner: c.owner,
        ownerKind: c.ownerKind || device.ownerKind });
      if (!owner.ok) {
        log.debug("Leaving Devices.update(). Owner.");
        return owner;
      }
      if (!Devices.sameDn(owner.dn, device.owner)) {
        const full = this.underCap(owner.dn, owner.kind, device.id);
        if (full) {
          log.debug("Leaving Devices.update(). Full.");
          return full;
        }
        device.owner = owner.dn;
        device.ownerKind = owner.kind;
        device.secretHash = '';
        device.session = '';
        changed.push('owner');
      }
    }
    const before = JSON.stringify([device.label, device.platform,
                                   device.model, device.os]);
    const described = this.applyDescription(device, c);
    if (described) {
      log.debug("Leaving Devices.update(). Description.");
      return described;
    }
    if (before !== JSON.stringify([device.label, device.platform,
                                   device.model, device.os])) {
      changed.push('description');
    }
    if (c.applications !== undefined) {
      const apps = this.applicationDns(c.applications);
      if (!apps.ok) {
        log.debug("Leaving Devices.update(). Applications.");
        return apps;
      }
      device.applications = apps.value;
      changed.push('applications');
    }
    if (!this.write(device)) {
      log.debug("Leaving Devices.update(). Not stored.");
      return this.refuse('STS-DEVICE-0009', 'The directory did not store ' +
                         'the change.');
    }
    this.recordAudit('device.update', String(actor || ''), device,
                     'device ' + device.id + ' changed: ' +
                     (changed.join(', ') || 'nothing'), { changed: changed });
    log.debug("Leaving Devices.update().");
    return { ok: true, device: this.byId(device.id) || device,
             changed: changed,
             message: 'Device ' + device.id + ' is saved' +
               (changed.indexOf('owner') >= 0 ? ' under its new owner, ' +
                'without the Native SSO secret the old owner\'s session ' +
                'held' : '') + '.' };
  }

  // Removes a device — the person's own, where `username` is given.
  remove(id: unknown, username?: unknown, actor?: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.remove(). id=" + id);
    const device = this.byId(id);
    const ownerDn = username === undefined ? '' :
      String(this.store('personDnOf', String(username || '')) || '');
    if (!device || (username !== undefined &&
                    !Devices.sameDn(device.owner, ownerDn))) {
      log.debug("Leaving Devices.remove(). Not found.");
      return this.refuse('STS-DEVICE-0007', 'no device with that id' +
                         (username !== undefined ? ' is yours' : '') + '.');
    }
    if (!this.store('deleteDeviceEntry', device.id)) {
      log.debug("Leaving Devices.remove(). Not removed.");
      return this.refuse('STS-DEVICE-0009', 'the directory did not remove ' +
                         'it.');
    }
    this.noteEvent('removed', device);
    this.recordAudit('device.delete', String(actor || username || ''), device,
                     'device ' + device.id + ' removed');
    log.debug("Leaving Devices.remove().");
    return { ok: true, removed: device.id,
             message: 'Device ' + device.id + ' is removed.' };
  }

  // Adds one key to a device.
  addKey(id: unknown, spec: Json, actor?: unknown): Json {
    const { log, config } = this.deps;
    log.debug("Entering Devices.addKey().");
    const device = this.byId(id);
    if (!device) {
      log.debug("Leaving Devices.addKey(). No device.");
      return this.refuse('STS-DEVICE-0007', 'There is no device "' +
                         String(id || '') + '" in this realm.');
    }
    const max = Number(config.value('devices.maxKeysPerDevice'));
    if (device.keys.length >= max) {
      log.debug("Leaving Devices.addKey(). Full.");
      return this.refuse('STS-DEVICE-0006', 'This device already holds ' +
        device.keys.length + ' keys, the most this realm allows ' +
        '(devices.maxKeysPerDevice). Remove one first.');
    }
    const prepared = this.prepareKey(spec, { dn: device.owner,
                                             kind: device.ownerKind },
                                     String(actor || ''));
    if (!prepared.ok) {
      log.debug("Leaving Devices.addKey(). Refused.");
      return prepared;
    }
    const taken = this.keyTaken(prepared.key, '');
    if (taken) {
      log.debug("Leaving Devices.addKey(). Taken.");
      return taken;
    }
    device.keys.push(prepared.key);
    if (!this.write(device)) {
      log.debug("Leaving Devices.addKey(). Not stored.");
      return this.refuse('STS-DEVICE-0009', 'The directory did not store ' +
                         'the key.');
    }
    this.recordAudit('device.key-add', String(actor || ''), device,
                     'a ' + prepared.key.kind + ' key was added to device ' +
                     device.id, { key: prepared.key.id,
                                  thumbprint: prepared.key.thumbprint,
                                  proof: prepared.key.proof });
    log.debug("Leaving Devices.addKey().");
    return { ok: true, key: prepared.key, device: device,
             message: 'The ' + prepared.key.kind + ' key is added.' };
  }

  // Removes one key from a device, by its id or its thumbprint.
  removeKey(id: unknown, keyId: unknown, actor?: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.removeKey().");
    const device = this.byId(id);
    if (!device) {
      log.debug("Leaving Devices.removeKey(). No device.");
      return this.refuse('STS-DEVICE-0007', 'There is no device "' +
                         String(id || '') + '" in this realm.');
    }
    const wanted = String(keyId || '');
    const key = device.keys.filter(function (k) {
      return k.id === wanted || k.thumbprint === wanted;
    })[0];
    if (!key) {
      log.debug("Leaving Devices.removeKey(). No key.");
      return this.refuse('STS-DEVICE-0008', 'Device ' + device.id +
                         ' holds no key "' + wanted + '".');
    }
    device.keys = device.keys.filter(function (k) {
      return k !== key;
    });
    if (!this.write(device)) {
      log.debug("Leaving Devices.removeKey(). Not stored.");
      return this.refuse('STS-DEVICE-0009', 'The directory did not store ' +
                         'the change.');
    }
    this.recordAudit('device.key-remove', String(actor || ''), device,
                     'a ' + key.kind + ' key was removed from device ' +
                     device.id, { key: key.id, thumbprint: key.thumbprint });
    log.debug("Leaving Devices.removeKey().");
    return { ok: true, device: device, removed: key.id,
             message: 'The ' + key.kind + ' key is removed.' };
  }

  // -------------------------------------------------------------------------
  // COMPLIANCE (decision 2; phase 3 adds the doors — the console, the MDM
  // feed under its protected scope, development's test control and a
  // received CAEP event). The register records the change and its previous
  // value, which is what CAEP's device-compliance-change carries (phase 4).
  // -------------------------------------------------------------------------
  setCompliance(id: unknown, status: unknown, source: unknown,
                actor?: unknown, reason?: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.setCompliance().");
    const wanted = String(status || '');
    const from = String(source || '');
    if (COMPLIANCE_STATES.indexOf(wanted) < 0 ||
        COMPLIANCE_SOURCES.indexOf(from) < 0) {
      log.debug("Leaving Devices.setCompliance(). Vocabulary.");
      return this.refuse('STS-DEVICE-0011', 'A compliance status is one of ' +
        Devices.sentence(COMPLIANCE_STATES) + ', set by one of ' +
        Devices.sentence(COMPLIANCE_SOURCES) + '.');
    }
    const device = this.byId(id);
    if (!device) {
      log.debug("Leaving Devices.setCompliance(). No device.");
      return this.refuse('STS-DEVICE-0007', 'There is no device "' +
                         String(id || '') + '" in this realm.');
    }
    const previous = device.compliance;
    device.compliance = wanted;
    device.complianceChange = { status: wanted, previous: previous,
      at: this.nowIso(), source: from, actor: String(actor || ''),
      reason: String(reason || '').slice(0, 500) };
    if (!this.write(device)) {
      log.debug("Leaving Devices.setCompliance(). Not stored.");
      return this.refuse('STS-DEVICE-0009', 'The directory did not store ' +
                         'the change.');
    }
    this.recordAudit('device.compliance', String(actor || ''), device,
                     'device ' + device.id + ' is ' + wanted + ' (was ' +
                     previous + ', by ' + from + ')',
                     { previous: previous, status: wanted, source: from });
    log.debug("Leaving Devices.setCompliance().");
    return { ok: true, device: device, previous: previous, status: wanted,
             changed: previous !== wanted };
  }

  // The device's status (phase 4: a compromised device is what RISC's
  // credential-compromise reports on its owner).
  setStatus(id: unknown, status: unknown, actor?: unknown,
            reason?: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.setStatus().");
    const wanted = String(status || '');
    if (STATUSES.indexOf(wanted) < 0) {
      log.debug("Leaving Devices.setStatus(). Vocabulary.");
      return this.refuse('STS-DEVICE-0011', 'A device\'s status is ' +
                         Devices.sentence(STATUSES) + '.');
    }
    const device = this.byId(id);
    if (!device) {
      log.debug("Leaving Devices.setStatus(). No device.");
      return this.refuse('STS-DEVICE-0007', 'There is no device "' +
                         String(id || '') + '" in this realm.');
    }
    const previous = device.status;
    device.status = wanted;
    device.statusChange = { status: wanted, previous: previous,
      at: this.nowIso(), actor: String(actor || ''),
      reason: String(reason || '').slice(0, 500) };
    if (!this.write(device)) {
      log.debug("Leaving Devices.setStatus(). Not stored.");
      return this.refuse('STS-DEVICE-0009', 'The directory did not store ' +
                         'the change.');
    }
    this.recordAudit('device.update', String(actor || ''), device,
                     'device ' + device.id + ' is ' + wanted + ' (was ' +
                     previous + ')', { previous: previous, status: wanted });
    log.debug("Leaving Devices.setStatus().");
    return { ok: true, device: device, previous: previous, status: wanted };
  }

  // -------------------------------------------------------------------------
  // THE COUNTS Monitoring → Devices draws. `isLive(device)` says whether a
  // device's Native SSO secret is bound to a live session.
  // -------------------------------------------------------------------------
  counts(isLive?: (device: Device) => boolean): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.counts().");
    const zero = function (list: string[]): Json {
      log.debug("Entering zero().");
      const out: Json = {};
      list.forEach(function (k) {
        out[k] = 0;
      });
      log.debug("Leaving zero().");
      return out;
    };
    const out: Json = {
      total: 0,
      byOwnerKind: zero(OWNER_KINDS),
      byCompliance: zero(COMPLIANCE_STATES),
      byAttestation: zero(ATTESTATION_LEVELS),
      byKeyKind: zero(KEY_KIND_FILTERS),
      byEnrolment: zero(ENROLMENT_METHODS),
      byStatus: zero(STATUSES),
      // Keys by what verified them (#164 phase 2): the attestation format
      // of each key, `none` for an unattested one.
      byKeyAttestationFormat: {},
      keys: 0,
      nativeSso: { live: 0, ended: 0, none: 0 }
    };
    // A HOT PATH: several times per device, so no Entering/Leaving pair.
    const bump = function (table: Json, key: string): void {
      table[key] = (table[key] || 0) + 1;
    };
    this.all().forEach(function (d) {
      out.total += 1;
      bump(out.byOwnerKind, d.ownerKind);
      bump(out.byCompliance, d.compliance);
      bump(out.byAttestation, d.attestation);
      bump(out.byStatus, d.status);
      bump(out.byEnrolment, d.enrolment.method);
      out.keys += d.keys.length;
      d.keys.forEach(function (k) {
        bump(out.byKeyAttestationFormat,
             (k.attestation && k.attestation.format) || 'none');
      });
      Devices.keyKindsOf(d).forEach(function (k) {
        bump(out.byKeyKind, k);
      });
      if (!d.secretHash) {
        out.nativeSso.none += 1;
      } else if (d.session && isLive && isLive(d)) {
        out.nativeSso.live += 1;
      } else {
        out.nativeSso.ended += 1;
      }
    });
    log.debug("Leaving Devices.counts(). " + out.total + ".");
    return out;
  }

  // What a page or the API shows of a device: never the hash, never the
  // session id. `isLive(session)` is asked about the secret's session.
  static view(device: Device, isLive?: (session: string) => boolean): Json {
    helpers.log.debug("Entering Devices.view().");
    const attestedBy = device.keys.filter(function (k) {
      return k.attestation && k.attestation.level === 'attested';
    })[0];
    helpers.log.debug("Leaving Devices.view().");
    return {
      id: device.id, dn: device.dn, owner: device.owner,
      ownerKind: device.ownerKind, label: device.label,
      applications: device.applications.slice(0),
      keys: device.keys.map(function (k) {
        return JSON.parse(JSON.stringify(k));
      }),
      keyKinds: Devices.keyKindsOf(device),
      attestation: {
        level: device.attestation,
        format: attestedBy ? attestedBy.attestation.format : 'none',
        summary: attestedBy ? attestedBy.attestation.summary : '',
        keyId: attestedBy ? attestedBy.id : ''
      },
      compliance: device.compliance,
      complianceChange: device.complianceChange,
      status: device.status,
      statusChange: device.statusChange,
      platform: device.platform, model: device.model, os: device.os,
      enrolment: Object.assign({}, device.enrolment),
      nativeSso: !!device.secretHash,
      sessionLive: !!(device.secretHash && device.session && isLive &&
                      isLive(device.session)),
      lastUsed: device.lastUsed, created: device.created
    };
  }

  // -------------------------------------------------------------------------
  // THE SCHEMA, for `/admin/ldap/devices` — the object classes and every
  // attribute, as the other container pages publish theirs.
  // -------------------------------------------------------------------------
  static readonly SCHEMA = {
    objectClasses: [
      { name: 'device', where: 'RFC 4519 section 3.4', standard: true,
        what: 'cn, and the standard owner and description.' },
      { name: 'stsDevice', where: 'this service (#130, #164)',
        standard: false,
        what: 'Every stsDevice* attribute below: the owner\'s kind, the ' +
              'applications, the keys, attestation, compliance, status, ' +
              'the descriptive labels, the enrolment and Native SSO.' }
    ],
    attributes: [
      { name: 'cn', kind: 'single', what: 'The device id, a UUID.' },
      { name: 'owner', kind: 'single',
        what: 'The DN of its one owner: a person or an application.' },
      { name: 'stsDeviceOwnerKind', kind: 'single',
        what: 'person or application.' },
      { name: 'description', kind: 'single', what: 'Its label.' },
      { name: 'stsDeviceApplication', kind: 'multi',
        what: 'The DN of every application that used it.' },
      { name: 'stsDeviceKey', kind: 'multi',
        what: 'One JSON value per key: id, kind (x509, jwk, webauthn), ' +
              'thumbprint, label, added, addedBy, proof, attestation and ' +
              'the public material. Never a secret.' },
      { name: 'stsDeviceKeyThumbprint', kind: 'multi',
        what: '<kind>:<thumbprint> per key, derived from stsDeviceKey on ' +
              'every write so an LDAP filter can find a device by its key.' },
      { name: 'stsDeviceAttestation', kind: 'single',
        what: 'attested when any key\'s attestation was verified, else ' +
              'self-asserted. Derived on every write.' },
      { name: 'stsDeviceCompliance', kind: 'single',
        what: 'compliant or not-compliant; absent is unknown.' },
      { name: 'stsDeviceComplianceChange', kind: 'single',
        what: 'JSON: the last compliance change — status, previous, at, ' +
              'source (admin, mdm, test-control, caep), actor, reason.' },
      { name: 'stsDeviceStatus', kind: 'single',
        what: 'compromised; absent is active.' },
      { name: 'stsDeviceStatusChange', kind: 'single',
        what: 'JSON: the last status change.' },
      { name: 'stsDevicePlatform', kind: 'single',
        what: 'ios, ipados, android, macos, windows, linux, chromeos or ' +
              'other.' },
      { name: 'stsDeviceModel', kind: 'single', what: 'Descriptive.' },
      { name: 'stsDeviceOs', kind: 'single', what: 'Descriptive.' },
      { name: 'stsDeviceEnrolment', kind: 'single',
        what: 'JSON: method (native-sso, admin, portal, est, scep), at, ' +
              'actor.' },
      { name: 'stsDeviceSecretHash', kind: 'single', sensitive: true,
        what: 'SHA-256 of its Native SSO device_secret. Withheld from ' +
              'every LDAP read.' },
      { name: 'stsDeviceSession', kind: 'single',
        what: 'The sign-on session the secret is good for.' },
      { name: 'stsDeviceLastUsed', kind: 'single',
        what: 'When it was last used, ISO 8601.' }
    ]
  };
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
  levelOf: Devices.levelOf,
  keyKindsOf: Devices.keyKindsOf,
  sentence: Devices.sentence,
  SCHEMA: Devices.SCHEMA,
  OWNER_KINDS: OWNER_KINDS,
  KEY_KINDS: KEY_KINDS,
  KEY_KIND_FILTERS: KEY_KIND_FILTERS,
  KEY_PROOFS: KEY_PROOFS,
  ATTESTATION_LEVELS: ATTESTATION_LEVELS,
  ATTESTATION_FORMATS: ATTESTATION_FORMATS,
  COMPLIANCE_STATES: COMPLIANCE_STATES,
  COMPLIANCE_SOURCES: COMPLIANCE_SOURCES,
  ENROLMENT_METHODS: ENROLMENT_METHODS,
  STATUSES: STATUSES,
  PLATFORMS: PLATFORMS,
  EVENT_KINDS: EVENT_KINDS,
  all: slot.forward('all'),
  list: slot.forward('list'),
  page: slot.forward('page'),
  listFor: slot.forward('listFor'),
  listForOwner: slot.forward('listForOwner'),
  byId: slot.forward('byId'),
  bySecret: slot.forward('bySecret'),
  byCredentialId: slot.forward('byCredentialId'),
  noteRecognized: slot.forward('noteRecognized'),
  byKeyThumbprint: slot.forward('byKeyThumbprint'),
  ownerOf: slot.forward('ownerOf'),
  issueForSession: slot.forward('issueForSession'),
  noteUse: slot.forward('noteUse'),
  revokeSecret: slot.forward('revokeSecret'),
  create: slot.forward('create'),
  update: slot.forward('update'),
  remove: slot.forward('remove'),
  addKey: slot.forward('addKey'),
  removeKey: slot.forward('removeKey'),
  setCompliance: slot.forward('setCompliance'),
  setStatus: slot.forward('setStatus'),
  counts: slot.forward('counts'),
  events: slot.forward('events'),
  timeline: slot.forward('timeline')
};
