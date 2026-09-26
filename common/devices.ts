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
//   stsDeviceRiskLevel          LOW, MEDIUM or HIGH (CAEP's three); ABSENT
//                               is unassessed (phase 4 stores it, phase 5's
//                               risk scoring sets it through setRiskLevel())
//   stsDeviceRiskChange         JSON: the last change — level, previous, at,
//                               source, actor, reason
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
// **WHAT AN ACT HERE CAUSES (#164 phases 3 and 4, 2026-09-26).** This file
// is the FUNNEL for every change to a device — the console, `/admin-api`,
// the MDM feed, the portal, EST and SCEP, Native SSO — so what a change owes
// the rest of the service is sent from here, where no door can miss it (the
// #145 rule: send at the funnel where one exists):
//
//   * Shared Signals, through `ssf/account_signals.ts` (a library that finds
//     a loaded `ssf/ssf.ts` in `require.cache`, so nothing here waits on a
//     receiver or requires SSF): CAEP `device-compliance-change` when
//     compliance actually moves, `risk-level-change` (principal DEVICE) when
//     the risk level does, `credential-change` for every device key and
//     Native SSO secret created, re-issued, revoked or deleted, and RISC
//     `credential-compromise` and `sessions-revoked` when a person's device
//     is compromised or removed. `ssf/CLAUDE.md` argues each event's shape
//     and subject; `docs/devices.md` lists them.
//   * **A COMPROMISED DEVICE LOSES EVERYTHING IT WAS TRUSTED WITH**: every
//     sign-on session one of its keys authenticated is ended (each a CAEP
//     session-revoked and its back-channel Logout Tokens, through
//     `authn.endSessionById()`), its Native SSO secret is revoked, and every
//     certificate this service's EST or SCEP Issuing CA issued it is revoked
//     for keyCompromise (`cert_enrollment.revokeDeviceCertificates()`), so
//     the CRL and OCSP say so. **A REMOVED device** loses the same sessions
//     and its certificates for cessationOfOperation (keyCompromise when it
//     was compromised). The device's own record keeps its keys: they belong
//     to the hardware, and a restored device is still that hardware.
//   * `authn` is found in `require.cache` rather than required, for the
//     reason `account_signals.ts` finds SSF that way — `authn` requires
//     `device_recognition`, which requires this file — and the enrolment
//     core is required lazily at the moment of use for the same cycle.
//
// **THE REGISTER IS LOOKED UP BY INDEX, NOT BY WALK** (the performance fix
// phase 2 owed). `byId()`, `byKeyThumbprint()` and `bySecret()` ask the
// directory's `deviceEntryByIndex()` for the ONE entry carrying `cn`, the
// derived `stsDeviceKeyThumbprint` or `stsDeviceSecretHash`, and parse only
// that entry. Phase 6 added the two it had left walking: `byCredentialId()`
// (a WebAuthn sign-in's, by the derived `stsDeviceCredentialId`) and
// `holdsAny()` (risk scoring's "does this person own a device", by `owner`,
// which several entries share — so the index answers ONE of them, which is
// all that question needs). `listForOwner()` still walks: it wants every
// device of an owner, the index keeps one entry per value, and its callers
// are pages and a Native SSO grant, not a per-request path.
// `ldap_server.js` argues why the index is safe across processes and nodes:
// it holds nothing the directory does not, and is validated against the
// directory on every hit.
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
// What a change says over Shared Signals (#164 phase 4). A library that
// requires only the logger and `common/crypto`, and finds SSF in
// `require.cache` at the moment an event is due: the require moves nothing
// and closes no cycle — `cert_enrollment.ts` requires it the same way.
import accountSignals = require('../ssf/account_signals');

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
// CAEP's risk-level vocabulary (section 3.8.1): a device's level is one of
// the three, or absent (never assessed).
const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH'];
// Who set a device's risk level: phase 5's risk scoring, a compromise, an
// administrator.
const RISK_SOURCES = ['risk', 'compromise', 'admin'];
// Where a compliance source's act comes from, in CAEP section 2's
// `initiating_entity` words: an administrator is `admin`; an MDM or posture
// feed is "a system or platform assertion" (`system`), and so is
// development's test control, which stands in for one; a received CAEP event
// (#153) is the transmitter's system asserting it.
const COMPLIANCE_INITIATORS: Record<string, string> = {
  admin: 'admin', mdm: 'system', 'test-control': 'system', caep: 'system'
};
// The credential types a device credential goes out as in CAEP's
// credential-change and RISC's credential-compromise (CAEP section 3.3.1:
// "one of the following strings, or any other credential type supported
// mutually by the Transmitter and the Receiver"). A certificate is `x509`
// and a linked WebAuthn credential `fido2-platform` or `fido2-roaming` by
// its recorded attachment — both registered values. A device's JWK key and
// its Native SSO secret fit NO registered value — a JWK proven by a JWS is
// not an app authenticator, and a bearer secret is not a password a person
// chose — so each is a URN in this service's own namespace, the approach
// #236 suggested, which a receiver that does not know it still reads as "a
// credential changed" (the member is an open enumeration).
const DEVICE_KEY_CREDENTIAL_TYPE = 'urn:iya:sts:credential-type:device-key';
const DEVICE_SECRET_CREDENTIAL_TYPE =
  'urn:iya:sts:credential-type:device-secret';
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

interface RiskChange {
  level: string;
  previous: string;
  at: string;
  source: string;
  actor: string;
  reason: string;
  // The level before a COMPROMISE raised it, so restoring the device can put
  // it back (`setStatus()`).
  beforeCompromise?: string;
}

// What a door says about who acted, for CAEP's `initiating_entity` and the
// sessions a removal ends. Every member optional.
interface ActOptions {
  initiatingEntity?: string;
  via?: string;
  // Nothing is signalled or ended: a device `cert_enrollment.ts` created for
  // an issuance the authority then refused, removed again in the same act.
  quiet?: boolean;
  // A certificate re-issued over the key the device already holds (EST
  // simplereenroll): the old key's removal and the new one's addition are
  // ONE credential-change `update`, and the old certificate is revoked as
  // superseded.
  renewal?: boolean;
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
  riskLevel: string;
  riskChange: RiskChange | null;
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
  // What a change says over Shared Signals (header).
  signals: typeof accountSignals;
  // `authn/authn` as it is loaded in this process, or null (header).
  findAuthn: () => Json;
  // `common/cert_enrollment`, required at the moment of use (header).
  loadEnrollment: () => Json;
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
  static readonly RISK_LEVELS = RISK_LEVELS;
  static readonly RISK_SOURCES = RISK_SOURCES;
  static readonly DEVICE_KEY_CREDENTIAL_TYPE = DEVICE_KEY_CREDENTIAL_TYPE;
  static readonly DEVICE_SECRET_CREDENTIAL_TYPE =
    DEVICE_SECRET_CREDENTIAL_TYPE;

  constructor(private readonly deps: DevicesDeps) {
    deps.log.debug("Entering Devices.constructor().");
    deps.log.debug("Leaving Devices.constructor().");
  }

  static defaultDeps(): DevicesDeps {
    helpers.log.debug("Entering Devices.defaultDeps().");
    helpers.log.debug("Leaving Devices.defaultDeps().");
    return { log: helpers.log, config: config, credentials: credentials,
             stsCrypto: stsCrypto, errorCodes: errorCodes, audit: audit,
             now: Date.now, signals: accountSignals,
             findAuthn: Devices.loadedAuthn,
             loadEnrollment: function (): Json {
               return require('./cert_enrollment');
             } };
  }

  // `authn/authn` as it is loaded in THIS process, found in `require.cache`,
  // or null — never required (header).
  static loadedAuthn(): Json {
    helpers.log.debug("Entering Devices.loadedAuthn().");
    let id = '';
    try {
      id = require.resolve('../authn/authn');
    } catch (e) {
      helpers.log.debug("Caught in Devices.loadedAuthn(): " +
                        ((e && e.message) || e));
      helpers.log.debug("Leaving Devices.loadedAuthn(). Not resolvable.");
      return null;
    }
    const cached = require.cache[id];
    helpers.log.debug("Leaving Devices.loadedAuthn(). " +
                      (cached ? 'Loaded.' : 'Not loaded.'));
    return cached && cached.exports ? cached.exports : null;
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
      riskLevel: RISK_LEVELS.indexOf(one('stsdevicerisklevel')) >= 0
        ? one('stsdevicerisklevel') : '',
      riskChange: Devices.parsed(one('stsdeviceriskchange')),
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
      // A LINKED WEBAUTHN CREDENTIAL'S ID, derived as the thumbprint is
      // (#164 phase 6): what a sign-in's assertion names its credential by,
      // so `byCredentialId()` is an index lookup rather than a walk.
      const credentialIds = device.keys.filter(function (k) {
        return k.kind === 'webauthn' && k.material &&
               !!k.material.credentialId;
      }).map(function (k) {
        return String(k.material.credentialId);
      });
      if (credentialIds.length) {
        attributes.stsDeviceCredentialId = credentialIds;
      }
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
    if (device.riskLevel) {
      attributes.stsDeviceRiskLevel = [device.riskLevel];
    }
    if (device.riskChange) {
      attributes.stsDeviceRiskChange = [JSON.stringify(device.riskChange)];
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
  private noteEvent(kind: string, device: Device, reason?: string,
                    extra?: Json): void {
    const { log, config } = this.deps;
    log.debug("Entering Devices.noteEvent(). " + kind);
    cacheRegistry.makeRoom(events, Number(config.value('devices.eventsKept')),
                           { name: 'devices.events',
                             counter: eventsCounter,
                             setting: 'devices.eventsKept' });
    events.set(nodeCrypto.randomUUID(), Object.assign({
      at: this.deps.now(), kind: kind, device: device.id,
      ownerKind: device.ownerKind, method: device.enrolment.method,
      reason: String(reason || '')
    }, extra || {}));
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
  // and the totals over every event this realm still holds. A COMPLIANCE
  // change (#164 phase 3) is counted by its SOURCE — admin, mdm,
  // test-control, caep — in each row's `compliance` and in the totals', which
  // is what "compliance changes over time by source" reads.
  timeline(days?: number): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.timeline().");
    const span = Math.max(1, Math.min(366, Number(days) || 30));
    const today = Math.floor(this.deps.now() / 86400000);
    const rows: Json[] = [];
    const byDay: Record<string, Json> = {};
    for (let d = today - span + 1; d <= today; d += 1) {
      const day = new Date(d * 86400000).toISOString().slice(0, 10);
      const row: Json = { day: day, created: 0, removed: 0, evicted: 0,
                          compliance: Devices.zeroSources() };
      rows.push(row);
      byDay[day] = row;
    }
    const totals: Json = { created: 0, removed: 0, evicted: 0,
                           compliance: Devices.zeroSources() };
    let since = '';
    this.events().forEach(function (e: Json) {
      const compliance = e.kind === 'compliance' &&
                         COMPLIANCE_SOURCES.indexOf(String(e.source)) >= 0;
      if (EVENT_KINDS.indexOf(e.kind) < 0 && !compliance) {
        return;
      }
      if (!since) {
        since = new Date(Number(e.at)).toISOString();
      }
      const day = new Date(Number(e.at)).toISOString().slice(0, 10);
      if (compliance) {
        totals.compliance[e.source] += 1;
        if (byDay[day]) {
          byDay[day].compliance[e.source] += 1;
        }
        return;
      }
      totals[e.kind] += 1;
      if (byDay[day]) {
        byDay[day][e.kind] += 1;
      }
    });
    log.debug("Leaving Devices.timeline().");
    return { days: span, rows: rows, totals: totals, since: since };
  }

  // One counter per compliance source, at zero.
  static zeroSources(): Json {
    helpers.log.debug("Entering Devices.zeroSources().");
    const out: Json = {};
    COMPLIANCE_SOURCES.forEach(function (source) {
      out[source] = 0;
    });
    helpers.log.debug("Leaving Devices.zeroSources().");
    return out;
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

  // ONE DEVICE BY AN INDEXED ATTRIBUTE (header): the directory's
  // `deviceEntryByIndex()`, parsed — or null. A directory too old to offer
  // the hook (an in-process test's stand-in) answers from the walk it
  // replaced, so the answer never depends on which one ran.
  private byIndex(attribute: string, value: string,
                  test: (one: Device) => boolean): Device | null {
    const { log, credentials } = this.deps;
    log.debug("Entering Devices.byIndex(). " + attribute);
    if (!value) {
      log.debug("Leaving Devices.byIndex(). Nothing asked.");
      return null;
    }
    const indexed = typeof credentials.deviceStore === 'function' &&
      credentials.deviceStore('hasHook', ['deviceEntryByIndex']);
    if (!indexed) {
      const walked = this.all().filter(test)[0] || null;
      log.debug("Leaving Devices.byIndex(). Walked: " + !!walked);
      return walked;
    }
    const entry = this.store('deviceEntryByIndex', attribute, value);
    const found = entry ? Devices.fromEntry(entry) : null;
    log.debug("Leaving Devices.byIndex(). " + !!found);
    return found && test(found) ? found : null;
  }

  byId(id: unknown): Device | null {
    const { log } = this.deps;
    log.debug("Entering Devices.byId().");
    const wanted = String(id || '');
    const found = this.byIndex('cn', wanted, function (one) {
      return one.id === wanted;
    });
    log.debug("Leaving Devices.byId(). " + !!found);
    return found;
  }

  // The device a key thumbprint belongs to, or null — what phase 2's
  // recognition asks. `kind` narrows it where the caller knows it; without
  // it each kind's index value is asked in turn.
  byKeyThumbprint(thumbprint: unknown, kind?: unknown): Device | null {
    const { log } = this.deps;
    log.debug("Entering Devices.byKeyThumbprint().");
    const wanted = String(thumbprint || '');
    const wantedKind = String(kind || '');
    const kinds = wantedKind ? [wantedKind] : KEY_KINDS;
    let found: Device | null = null;
    for (const one of kinds) {
      found = this.byIndex('stsDeviceKeyThumbprint', wanted ? one + ':' +
                           wanted : '', function (d) {
        return d.keys.some(function (k) {
          return k.thumbprint === wanted && k.kind === one;
        });
      });
      if (found) {
        break;
      }
    }
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
    // BY INDEX since phase 6 (it was the one lookup phase 3 left walking,
    // and it is asked at every WebAuthn sign-in): the derived
    // `stsDeviceCredentialId`, validated against the keys it came from.
    const found = this.byIndex('stsDeviceCredentialId', wanted,
      function (one) {
        return one.keys.some(function (k) {
          return k.kind === 'webauthn' && k.material &&
                 String(k.material.credentialId || '') === wanted;
        });
      });
    log.debug("Leaving Devices.byCredentialId(). " + !!found);
    return found;
  }

  // -------------------------------------------------------------------------
  // WHETHER A PERSON OWNS ANY DEVICE AT ALL (#164 phase 5) — what risk
  // scoring's `unregistered-device` signal asks at every sign-in, so it is
  // the owner index's ONE entry rather than `listFor()`'s walk: the question
  // is "at least one", and the index answers it with the first device that
  // still names this owner. A compromised device counts — the person still
  // registered one, and a sign-in from elsewhere is still not from it.
  // -------------------------------------------------------------------------
  holdsAny(username: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering Devices.holdsAny().");
    const ownerDn = String(this.store('personDnOf', String(username || '')) ||
                           '');
    const found = ownerDn ? this.byIndex('owner', ownerDn, function (one) {
      return Devices.sameDn(one.owner, ownerDn);
    }) : null;
    log.debug("Leaving Devices.holdsAny(). " + !!found);
    return !!found;
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
    // Looked up by the HASH, which is what the entry holds: the index is a
    // Map keyed by it, so no secret is compared in the lookup, and the one
    // entry found is compared in constant time as before.
    const hash = Devices.hashOf(text);
    const found = this.byIndex('stsDeviceSecretHash', hash, function (one) {
      return !!one.secretHash &&
             stsCrypto.constantTimeEquals(one.secretHash, hash);
    });
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

  // =========================================================================
  // WHAT A CHANGE SAYS AND CAUSES (header, "WHAT AN ACT HERE CAUSES").
  // =========================================================================

  // CAEP section 2's four words; anything else is the fallback.
  private static entityOf(opts: ActOptions | undefined,
                          fallback: string): string {
    helpers.log.debug("Entering Devices.entityOf().");
    const asked = String((opts && opts.initiatingEntity) || '');
    helpers.log.debug("Leaving Devices.entityOf().");
    return ['admin', 'user', 'policy', 'system'].indexOf(asked) >= 0
      ? asked : fallback;
  }

  // The owner's username where the owner is a PERSON, else '' — an
  // application has no CAEP user subject and no RISC account here.
  private personOf(device: Device): string {
    const { log } = this.deps;
    log.debug("Entering Devices.personOf().");
    const owner = device.ownerKind === 'person' ? this.ownerOf(device.owner)
                                                : null;
    log.debug("Leaving Devices.personOf().");
    return owner && owner.kind === 'person' ? String(owner.name || '') : '';
  }

  // One call to `ssf/account_signals.ts`, fired and forgotten: it never
  // throws and never rejects by contract, and this is belt and braces so a
  // defect there cannot undo a change already written here.
  private signal(method: string, notice: Json): void {
    const { log, signals, errorCodes } = this.deps;
    log.debug("Entering Devices.signal(). " + method);
    try {
      const emit = (signals as Json)[method];
      const answer = typeof emit === 'function' ? emit(notice) : null;
      if (answer && typeof answer.catch === 'function') {
        answer.catch(function (e: Json): void {
          log.debug("Caught in a callback in Devices.signal(): " +
                    ((e && e.message) || e));
        });
      }
    } catch (e) {
      log.warn(errorCodes.tag('STS-DEVICE-0030') + 'devices: the ' + method +
               ' signal for device ' + String(notice.deviceId || '') +
               ' could not be sent: ' + ((e && e.message) || e));
    }
    log.debug("Leaving Devices.signal().");
  }

  // The members every device signal carries: the device, and its owner.
  private deviceNotice(device: Device, extra: Json): Json {
    this.deps.log.debug("Entering Devices.deviceNotice().");
    this.deps.log.debug("Leaving Devices.deviceNotice().");
    return Object.assign({ deviceId: device.id, username: this.personOf(device),
                           ownerKind: device.ownerKind,
                           deviceLabel: device.label }, extra);
  }

  // A key's CAEP credential-change members: its type and what identifies it.
  static credentialOf(key: DeviceKey): Json {
    helpers.log.debug("Entering Devices.credentialOf(). " + key.kind);
    const m = key.material || {};
    const out: Json = { credentialType: DEVICE_KEY_CREDENTIAL_TYPE,
                        friendlyName: key.label || key.kind + ' key' };
    if (key.kind === 'x509') {
      out.credentialType = 'x509';
      out.x509Issuer = String(m.issuer || '');
      out.x509Serial = String(m.serial || '');
    } else if (key.kind === 'webauthn') {
      out.credentialType = accountSignals.keyCredentialType({
        attachment: String(m.attachment || '') });
      out.fido2Aaguid = /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(String(m.aaguid))
        ? '' : String(m.aaguid || '');
    }
    helpers.log.debug("Leaving Devices.credentialOf().");
    return out;
  }

  // CAEP credential-change about one of a device's credentials — a key
  // (`key`) or, with none, its Native SSO secret.
  private credentialChanged(device: Device, changeType: string,
                            key: DeviceKey | null, opts: ActOptions | undefined,
                            fallback: string, why: string): void {
    const { log } = this.deps;
    log.debug("Entering Devices.credentialChanged(). " + changeType);
    const cred: Json = key ? Devices.credentialOf(key)
      : { credentialType: DEVICE_SECRET_CREDENTIAL_TYPE,
          friendlyName: 'Native SSO device_secret' };
    this.signal('deviceEvent', this.deviceNotice(device, {
      type: 'credential-change', act: 'credential',
      values: { credential_type: cred.credentialType,
                change_type: changeType,
                friendly_name: String(cred.friendlyName || ''),
                x509_issuer: String(cred.x509Issuer || ''),
                x509_serial: String(cred.x509Serial || ''),
                fido2_aaguid: String(cred.fido2Aaguid || '') },
      initiatingEntity: Devices.entityOf(opts, fallback),
      via: String((opts && opts.via) || ''),
      reasonAdmin: why,
      reasonUser: 'A credential of your device "' + device.label + '" ' +
                  (changeType === 'create' ? 'was added'
                    : changeType === 'update' ? 'was renewed'
                      : changeType === 'revoke' ? 'was revoked'
                        : 'was removed') + '.' }));
    log.debug("Leaving Devices.credentialChanged().");
  }

  // EVERY SIGN-ON SESSION ONE OF THIS DEVICE'S KEYS AUTHENTICATED, ENDED:
  // those whose authentication events name the device as `registeredDevice`
  // (`authn.authenticationEvent()`). Each goes through `dropSession()`, so
  // it is an audit row, a CAEP session-revoked (with the device in its
  // subject) and its relying parties' back-channel Logout Tokens, with the
  // caller's `entity` as CAEP's `initiating_entity` (#242). Answers how many
  // ended.
  private endSessionsFrom(device: Device, via: string,
                          entity: string): number {
    const { log, findAuthn, errorCodes } = this.deps;
    log.debug("Entering Devices.endSessionsFrom(). " + device.id);
    const authn = findAuthn();
    if (!authn || typeof authn.sessionsMatching !== 'function') {
      log.debug("Leaving Devices.endSessionsFrom(). No sessions here.");
      return 0;
    }
    let ended = 0;
    try {
      const ids = authn.sessionsMatching(function (session: Json): boolean {
        return Array.isArray(session && session.events) &&
          session.events.some(function (e: Json): boolean {
            return !!(e && e.registeredDevice &&
                      e.registeredDevice.id === device.id);
          });
      }).map(function (session: Json): string {
        return String(session.id || '');
      }).filter(Boolean);
      ids.forEach(function (id: string): void {
        if (authn.endSessionById(id, via, entity)) {
          ended += 1;
        }
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-DEVICE-0031') + 'devices: the sessions ' +
                'device ' + device.id + ' authenticated could not all be ' +
                'ended: ' + ((e && e.message) || e));
    }
    log.info('devices: ' + ended + ' sign-on session(s) device ' +
             device.id + ' authenticated were ended (' + via + ').');
    log.debug("Leaving Devices.endSessionsFrom(). " + ended);
    return ended;
  }

  // EVERY CERTIFICATE THIS SERVICE ISSUED THE DEVICE, REVOKED for `reason`
  // (an RFC 5280 reason) by the Issuing CA that issued it —
  // `cert_enrollment.revokeDeviceCertificates()`, the enrolment core, which
  // owns what EST and SCEP issue. Answers what was revoked.
  private revokeCertificates(device: Device, reason: string,
                             actor: string, keys?: DeviceKey[]): Json[] {
    const { log, loadEnrollment, errorCodes } = this.deps;
    log.debug("Entering Devices.revokeCertificates(). " + reason);
    let out: Json[] = [];
    try {
      out = loadEnrollment().revokeDeviceCertificates(
        { id: device.id, keys: keys || device.keys }, reason, actor) || [];
    } catch (e) {
      log.error(errorCodes.tag('STS-DEVICE-0032') + 'devices: the ' +
                'certificates of device ' + device.id + ' could not be ' +
                'revoked (' + reason + '): ' + ((e && e.message) || e));
      out = [];
    }
    log.debug("Leaving Devices.revokeCertificates(). " + out.length);
    return out;
  }

  // WHAT A REMOVAL (or an eviction) CAUSES, after the entry is gone: its
  // certificates revoked, the sessions it authenticated ended, a CAEP
  // credential-change `delete` for each key and its secret, and — for a
  // person's device — RISC sessions-revoked naming the person and the
  // device. `ended` is what a compromise already ended, so it is not asked
  // twice.
  private afterRemoval(device: Device, opts: ActOptions | undefined,
                       fallback: string, actor: string, why: string): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.afterRemoval(). " + device.id);
    const entity = Devices.entityOf(opts, fallback);
    const revoked = this.revokeCertificates(device,
      device.status === 'compromised' ? 'keyCompromise'
                                      : 'cessationOfOperation', actor);
    const ended = this.endSessionsFrom(device, entity === 'admin'
      ? 'an administrator removed device ' + device.id
      : (entity === 'user' ? 'the owner removed device ' + device.id
                           : 'device ' + device.id + ' was removed'), entity);
    device.keys.forEach((key) => {
      this.credentialChanged(device, 'delete', key, opts, fallback, why);
    });
    if (device.secretHash) {
      this.credentialChanged(device, 'delete', null, opts, fallback, why);
    }
    this.sessionsRevoked(device, entity, why);
    log.debug("Leaving Devices.afterRemoval().");
    return { revoked: revoked.length, sessionsEnded: ended };
  }

  // RISC sessions-revoked for a PERSON's device: every session of theirs ON
  // THIS DEVICE — the complex subject's `device` member is what makes the
  // deprecated event's "all the sessions for the account" true of what was
  // done (ssf/CLAUDE.md argues it).
  private sessionsRevoked(device: Device, entity: string, why: string): void {
    const { log } = this.deps;
    log.debug("Entering Devices.sessionsRevoked().");
    const username = this.personOf(device);
    if (username) {
      this.signal('sessionsRevoked', this.deviceNotice(device, {
        initiatingEntity: entity, reasonAdmin: why,
        reasonUser: 'Your sessions on the device "' + device.label +
                    '" were ended.' }));
    }
    log.debug("Leaving Devices.sessionsRevoked(). " + (username || 'none'));
  }

  // =========================================================================
  // THE RISK LEVEL (#164 decision 4, phase 4) — what phase 5's risk scoring
  // calls with its assessment of a device, and what a compromise raises.
  //
  //   setRiskLevel(id, level, reason, options?)
  //     level    LOW | MEDIUM | HIGH (CAEP section 3.8.1), or '' to forget
  //              the assessment (sends nothing: CAEP has no "unknown" level)
  //     reason   CAEP's risk_reason — the signal that moved it
  //     options  { source: risk (default) | compromise | admin, actor,
  //                initiatingEntity (system by default) }
  //
  // It answers `{ ok, device, previous, level, changed }` or a refusal, and
  // sends CAEP risk-level-change with principal DEVICE when the level MOVED
  // — `previous_level` the stored one where there was one, omitted where
  // there was none ("the Receiver MUST assume that the previous risk level
  // is unknown").
  // =========================================================================
  setRiskLevel(id: unknown, level: unknown, reason?: unknown,
               options?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.setRiskLevel().");
    const o = options || {};
    const wanted = String(level || '').toUpperCase();
    const source = String(o.source || 'risk');
    if ((wanted && RISK_LEVELS.indexOf(wanted) < 0) ||
        RISK_SOURCES.indexOf(source) < 0) {
      log.debug("Leaving Devices.setRiskLevel(). Vocabulary.");
      return this.refuse('STS-DEVICE-0033', 'A device\'s risk level is one ' +
        'of ' + Devices.sentence(RISK_LEVELS) + ' (or empty, to forget ' +
        'it), set by one of ' + Devices.sentence(RISK_SOURCES) + '.');
    }
    const device = this.byId(id);
    if (!device) {
      log.debug("Leaving Devices.setRiskLevel(). No device.");
      return this.refuse('STS-DEVICE-0007', 'There is no device "' +
                         String(id || '') + '" in this realm.');
    }
    // RISK SCORING NEVER MOVES A COMPROMISED DEVICE (#164 phase 5): the
    // compromise raised it to HIGH and only a restore puts the level back
    // (`setStatus()`). An assessment of a sign-in the device took part in
    // is evidence about that sign-in; it cannot say the device is no longer
    // compromised.
    if (source === 'risk' && device.status === 'compromised') {
      log.debug("Leaving Devices.setRiskLevel(). Compromised: held.");
      return { ok: true, device: device, previous: device.riskLevel,
               level: device.riskLevel, changed: false, held: true };
    }
    const previous = device.riskLevel;
    const changed = previous !== wanted;
    if (changed) {
      device.riskLevel = wanted;
      device.riskChange = { level: wanted, previous: previous,
        at: this.nowIso(), source: source, actor: String(o.actor || ''),
        reason: String(reason || '').slice(0, 500) };
      if (o.beforeCompromise !== undefined) {
        device.riskChange.beforeCompromise = String(o.beforeCompromise);
      }
      if (!this.write(device)) {
        log.debug("Leaving Devices.setRiskLevel(). Not stored.");
        return this.refuse('STS-DEVICE-0009', 'The directory did not store ' +
                           'the change.');
      }
      this.recordAudit('device.risk', String(o.actor || source), device,
                       'device ' + device.id + '\'s risk level is ' +
                       (wanted || 'unassessed') + ' (was ' +
                       (previous || 'unassessed') + ', by ' + source + ')',
                       { previous: previous, level: wanted, source: source });
    }
    if (changed && wanted) {
      const values: Json = { principal: 'DEVICE', current_level: wanted };
      if (previous) {
        values.previous_level = previous;
      }
      if (reason) {
        values.risk_reason = String(reason).slice(0, 500);
      }
      this.signal('deviceEvent', this.deviceNotice(device, {
        type: 'risk-level-change', act: 'risk', values: values,
        initiatingEntity: Devices.entityOf(o, source === 'admin' ? 'admin'
                                                                 : 'system'),
        reasonAdmin: 'Device ' + device.id + '\'s risk level went from ' +
                     (previous || 'unassessed') + ' to ' + wanted +
                     (reason ? ' (' + String(reason) + ')' : '') + '.',
        reasonUser: 'The risk this service sees in your device "' +
                    device.label + '" changed.' }));
    }
    log.debug("Leaving Devices.setRiskLevel(). " + (changed ? 'Changed.'
                                                           : 'Unchanged.'));
    return { ok: true, device: device, previous: previous, level: wanted,
             changed: changed };
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
        // An eviction is a removal a POLICY made (#164 phase 4).
        this.afterRemoval(victim, { initiatingEntity: 'policy' }, 'policy',
                          String(spec.username || ''), 'Device ' + victim.id +
                          ' was removed at devices.maxPerPerson to make room ' +
                          'for a new one.');
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
    this.credentialChanged(device, 'create', null,
                           { initiatingEntity: 'user' }, 'user',
                           'A Native SSO device_secret was issued for new ' +
                           'device ' + device.id + ' to ' +
                           String(spec.clientId || 'a client') + '.');
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
      riskLevel: '', riskChange: null, platform: '', model: '', os: '',
      enrolment: enrolment,
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
  revokeSecret(secret: unknown, options?: ActOptions): boolean {
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
    if (written) {
      this.credentialChanged(device, 'revoke', null, options, 'user',
                             'The Native SSO device_secret of device ' +
                             device.id + ' was revoked (RFC 7009).');
    }
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
  create(spec: Json, actor?: unknown, options?: ActOptions): Json {
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
    if (!(options && options.quiet)) {
      device.keys.forEach((key) => {
        this.credentialChanged(device, 'create', key, options,
                               method === 'portal' ? 'user' : 'admin',
                               'Device ' + device.id + ' was registered (' +
                               method + ') holding this key.');
      });
    }
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
        // The secret the OLD owner's session held is revoked, and said to
        // that owner's receivers before the device changes hands.
        if (device.secretHash) {
          this.credentialChanged(Object.assign({}, device), 'revoke', null,
            { initiatingEntity: 'admin' }, 'admin', 'Device ' + device.id +
            ' was given to another owner, and its Native SSO device_secret ' +
            'went with the old owner\'s session.');
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

  // Removes a device — the person's own, where `username` is given — and
  // everything that follows from it (`afterRemoval()`): its certificates
  // revoked, the sessions it authenticated ended, its credentials' CAEP
  // credential-change and, for a person's device, RISC sessions-revoked.
  // `options.quiet` removes it and nothing else (a device `cert_enrollment`
  // created for an issuance that then failed).
  remove(id: unknown, username?: unknown, actor?: unknown,
         options?: ActOptions): Json {
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
    const after = options && options.quiet ? null
      : this.afterRemoval(device, options,
                          username !== undefined ? 'user' : 'admin',
                          String(actor || username || ''),
                          'Device ' + device.id + ' was removed from the ' +
                          'register.');
    log.debug("Leaving Devices.remove().");
    return { ok: true, removed: device.id,
             certificatesRevoked: after ? after.revoked : 0,
             sessionsEnded: after ? after.sessionsEnded : 0,
             message: 'Device ' + device.id + ' is removed' +
               (after && (after.revoked || after.sessionsEnded)
                 ? ': ' + after.sessionsEnded + ' sign-on session(s) it ' +
                   'authenticated were ended and ' + after.revoked +
                   ' certificate(s) issued to it were revoked' : '') + '.' };
  }

  // Adds one key to a device. `options.renewal` says the key replaces one
  // `removeKey()` just took off for a certificate re-issue, which is a
  // credential-change `update` rather than a `create`.
  addKey(id: unknown, spec: Json, actor?: unknown,
         options?: ActOptions): Json {
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
    const renewal = !!(options && options.renewal);
    this.credentialChanged(device, renewal ? 'update' : 'create',
                           prepared.key, options, 'admin',
                           'A ' + prepared.key.kind + ' key was ' +
                           (renewal ? 're-issued for' : 'added to') +
                           ' device ' + device.id + ' (' +
                           prepared.key.proof + ').');
    log.debug("Leaving Devices.addKey().");
    return { ok: true, key: prepared.key, device: device,
             message: 'The ' + prepared.key.kind + ' key is added.' };
  }

  // Removes one key from a device, by its id or its thumbprint. A
  // certificate this service issued for the key is revoked with it —
  // `superseded` for a re-issue (`options.renewal`, which also sends no
  // signal: `addKey()` sends the one `update`), cessationOfOperation
  // otherwise.
  removeKey(id: unknown, keyId: unknown, actor?: unknown,
            options?: ActOptions): Json {
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
    const renewal = !!(options && options.renewal);
    this.revokeCertificates(device, renewal ? 'superseded'
      : (device.status === 'compromised' ? 'keyCompromise'
                                         : 'cessationOfOperation'),
      String(actor || ''), [key]);
    if (!renewal) {
      this.credentialChanged(device, 'delete', key, options, 'admin',
                             'A ' + key.kind + ' key was removed from ' +
                             'device ' + device.id + '.');
    }
    log.debug("Leaving Devices.removeKey().");
    return { ok: true, device: device, removed: key.id,
             message: 'The ' + key.kind + ' key is removed.' };
  }

  // -------------------------------------------------------------------------
  // COMPLIANCE (decision 2, phase 3). The doors that call this: the console
  // and `/admin-api` (`admin`), the MDM feed under `device:compliance`
  // (`mdm`), development's test control (`test-control`); a received CAEP
  // event (`caep`) from a registered foreign transmitter
  // (`ssf/ssf_transmitters.ts`, #153). The register records the change and
  // its previous value, and a change counts in Monitoring → Devices by its
  // source.
  //
  // **WHAT GOES OUT IS CAEP's `device-compliance-change`, WHEN THE STATUS A
  // RECEIVER CAN BE TOLD ACTUALLY MOVED (phase 4).** CAEP section 3.5.1 makes
  // `previous_status` and `current_status` REQUIRED and allows exactly two
  // values, `compliant` and `not-compliant` — there is no `unknown` on the
  // wire. So `unknown` is sent as what it means to a relying party enforcing
  // compliance, `not-compliant`: a device nobody has vouched for is not one
  // anybody may treat as compliant, which is also what phase 6's policy will
  // read. Hence unknown → compliant goes out as not-compliant → compliant,
  // compliant → unknown (an administrator withdrawing a vouch) as compliant →
  // not-compliant, and unknown ↔ not-compliant sends NOTHING — a receiver
  // told not-compliant then not-compliant would read a change that did not
  // happen. `initiating_entity` is the source's (COMPLIANCE_INITIATORS);
  // `reason_admin` is the reason given, or a sentence naming the source.
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
    const why = String(reason || '').slice(0, 500);
    device.compliance = wanted;
    device.complianceChange = { status: wanted, previous: previous,
      at: this.nowIso(), source: from, actor: String(actor || ''),
      reason: why };
    if (!this.write(device)) {
      log.debug("Leaving Devices.setCompliance(). Not stored.");
      return this.refuse('STS-DEVICE-0009', 'The directory did not store ' +
                         'the change.');
    }
    this.recordAudit('device.compliance', String(actor || ''), device,
                     'device ' + device.id + ' is ' + wanted + ' (was ' +
                     previous + ', by ' + from + ')',
                     { previous: previous, status: wanted, source: from });
    const changed = previous !== wanted;
    if (changed) {
      this.noteEvent('compliance', device, why, { source: from,
                     previous: previous, status: wanted });
    }
    const wire = function (state: string): string {
      log.debug("Entering wire().");
      log.debug("Leaving wire().");
      return state === 'compliant' ? 'compliant' : 'not-compliant';
    };
    const signalled = wire(previous) !== wire(wanted);
    if (signalled) {
      this.signal('deviceEvent', this.deviceNotice(device, {
        type: 'device-compliance-change', act: 'compliance',
        values: { previous_status: wire(previous),
                  current_status: wire(wanted) },
        initiatingEntity: COMPLIANCE_INITIATORS[from],
        reasonAdmin: why || ('Device ' + device.id + ' was reported ' +
                             wanted + ' by ' + (from === 'mdm'
                               ? 'the MDM feed' : from === 'test-control'
                                 ? 'the development test control'
                                 : from === 'caep' ? 'a received CAEP event'
                                                   : 'an administrator') +
                             '.'),
        reasonUser: wire(wanted) === 'compliant'
          ? 'Your device "' + device.label + '" meets this service\'s ' +
            'requirements.'
          : 'Your device "' + device.label + '" no longer meets this ' +
            'service\'s requirements.' }));
    }
    log.debug("Leaving Devices.setCompliance().");
    return { ok: true, device: device, previous: previous, status: wanted,
             changed: changed, signalled: signalled };
  }

  // -------------------------------------------------------------------------
  // THE DEVICE'S STATUS (decision 4, phase 4). `options` is ActOptions.
  //
  // **MARKING IT COMPROMISED IS THE STRONGEST ACT ON A DEVICE**, and what it
  // does is argued in the header: its Native SSO secret revoked (in the same
  // write), every certificate this service issued it revoked for
  // keyCompromise, every sign-on session one of its keys authenticated
  // ended, its risk level raised to HIGH (CAEP risk-level-change, principal
  // DEVICE: CAEP section 3.8 names exactly this — "Device's risk has
  // changed"), and for a person's device RISC credential-compromise for each
  // kind of credential it held and sessions-revoked, naming the person AND
  // the device. The device stays in the register, recognised and saying
  // `compromised` (`device_recognition.ts`), because the requests it makes
  // afterwards are the ones somebody needs to see.
  //
  // **RESTORING IT TO ACTIVE UNDOES ONLY THE RISK LEVEL**, and only when the
  // compromise set it: back to what it was, which goes out as a
  // risk-level-change, or — where it had never been assessed — forgotten
  // silently, because CAEP has no level for "unassessed" and inventing LOW
  // would tell receivers something nobody assessed. Nothing revoked comes
  // back: a revoked certificate is re-issued, a secret re-minted at the next
  // sign-in.
  // -------------------------------------------------------------------------
  setStatus(id: unknown, status: unknown, actor?: unknown,
            reason?: unknown, options?: ActOptions): Json {
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
    const why = String(reason || '').slice(0, 500);
    const compromising = wanted === 'compromised' && previous !== 'compromised';
    const hadSecret = !!device.secretHash;
    device.status = wanted;
    device.statusChange = { status: wanted, previous: previous,
      at: this.nowIso(), actor: String(actor || ''), reason: why };
    if (compromising) {
      device.secretHash = '';
      device.session = '';
    }
    if (!this.write(device)) {
      log.debug("Leaving Devices.setStatus(). Not stored.");
      return this.refuse('STS-DEVICE-0009', 'The directory did not store ' +
                         'the change.');
    }
    this.recordAudit('device.update', String(actor || ''), device,
                     'device ' + device.id + ' is ' + wanted + ' (was ' +
                     previous + ')', { previous: previous, status: wanted });
    let after: Json = null;
    if (compromising) {
      after = this.compromised(device, hadSecret, String(actor || ''), why,
                               options);
    } else if (wanted === 'active' && previous === 'compromised' &&
               device.riskChange && device.riskChange.source === 'compromise') {
      this.setRiskLevel(device.id, device.riskChange.beforeCompromise || '',
                        'the device was restored to active',
                        { source: 'compromise', actor: String(actor || ''),
                          initiatingEntity: Devices.entityOf(options,
                                                             'admin') });
    }
    log.debug("Leaving Devices.setStatus().");
    return Object.assign({ ok: true, device: this.byId(device.id) || device,
                           previous: previous, status: wanted },
                         after || {});
  }

  // What a compromise causes, after the write (setStatus()'s header).
  private compromised(device: Device, hadSecret: boolean, actor: string,
                      why: string, options?: ActOptions): Json {
    const { log } = this.deps;
    log.debug("Entering Devices.compromised(). " + device.id);
    const entity = Devices.entityOf(options, 'admin');
    const reasonAdmin = 'Device ' + device.id + ' was marked compromised' +
                        (why ? ': ' + why : '') + '.';
    if (hadSecret) {
      this.credentialChanged(device, 'revoke', null, options, 'admin',
                             reasonAdmin);
    }
    const revoked = this.revokeCertificates(device, 'keyCompromise', actor);
    const ended = this.endSessionsFrom(device, entity === 'admin'
      ? 'an administrator marked device ' + device.id + ' compromised'
      : 'device ' + device.id + ' was marked compromised', entity);
    this.setRiskLevel(device.id, 'HIGH', 'DEVICE_COMPROMISED',
                      { source: 'compromise', actor: actor,
                        initiatingEntity: entity,
                        beforeCompromise: device.riskLevel });
    const username = this.personOf(device);
    if (username) {
      const types: string[] = [];
      device.keys.forEach(function (key) {
        const type = Devices.credentialOf(key).credentialType;
        if (types.indexOf(type) < 0) {
          types.push(type);
        }
      });
      if (hadSecret) {
        types.push(DEVICE_SECRET_CREDENTIAL_TYPE);
      }
      types.forEach((type) => {
        this.signal('credentialCompromised', this.deviceNotice(device, {
          credentialType: type, initiatingEntity: entity,
          reasonAdmin: reasonAdmin,
          reasonUser: 'A credential held by your device "' + device.label +
                      '" is no longer trusted.' }));
      });
      this.sessionsRevoked(device, entity, reasonAdmin);
    }
    log.warn('devices: device ' + device.id + ' was marked COMPROMISED by ' +
             (actor || 'an administrator') + '; ' + ended + ' session(s) ' +
             'ended, ' + revoked.length + ' certificate(s) revoked' +
             (hadSecret ? ', its Native SSO secret revoked' : '') + '.');
    log.debug("Leaving Devices.compromised().");
    return { sessionsEnded: ended, certificatesRevoked: revoked.length,
             secretRevoked: hadSecret };
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
      byRiskLevel: zero(RISK_LEVELS.concat(['unassessed'])),
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
      bump(out.byRiskLevel, d.riskLevel || 'unassessed');
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
      riskLevel: device.riskLevel || 'unassessed',
      riskChange: device.riskChange,
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
      { name: 'stsDeviceCredentialId', kind: 'multi',
        what: 'The credential id of each linked WebAuthn key, derived from ' +
              'stsDeviceKey on every write so a sign-in finds its device ' +
              'by index.' },
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
      { name: 'stsDeviceRiskLevel', kind: 'single',
        what: 'LOW, MEDIUM or HIGH (CAEP\'s risk levels); absent is ' +
              'unassessed. Set by risk scoring and by a compromise.' },
      { name: 'stsDeviceRiskChange', kind: 'single',
        what: 'JSON: the last risk level change — level, previous, at, ' +
              'source (risk, compromise, admin), actor, reason.' },
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
  RISK_LEVELS: RISK_LEVELS,
  RISK_SOURCES: RISK_SOURCES,
  DEVICE_KEY_CREDENTIAL_TYPE: DEVICE_KEY_CREDENTIAL_TYPE,
  DEVICE_SECRET_CREDENTIAL_TYPE: DEVICE_SECRET_CREDENTIAL_TYPE,
  credentialOf: Devices.credentialOf,
  all: slot.forward('all'),
  list: slot.forward('list'),
  page: slot.forward('page'),
  listFor: slot.forward('listFor'),
  listForOwner: slot.forward('listForOwner'),
  byId: slot.forward('byId'),
  bySecret: slot.forward('bySecret'),
  byCredentialId: slot.forward('byCredentialId'),
  holdsAny: slot.forward('holdsAny'),
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
  // THE RISK LEVEL PHASE 5 SETS (#164): setRiskLevel(id, level, reason,
  // { source, actor, initiatingEntity }).
  setRiskLevel: slot.forward('setRiskLevel'),
  counts: slot.forward('counts'),
  events: slot.forward('events'),
  timeline: slot.forward('timeline')
};
