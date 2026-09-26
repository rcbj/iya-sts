'use strict';
//
// File: device_recognition.ts
//
// ===========================================================================
// WHICH REGISTERED DEVICE A REQUEST CAME FROM, AND BY WHICH KEY (#164
// decision 1, phase 2, 2026-09-26).
//
// "A device holds keys proven at enrolment, and presenting any one of them
// identifies the device" (rcbj). So recognition is one question asked of the
// evidence a request already carries, and `recognize()` is the one place it
// is answered:
//
//   via         evidence                                   device key
//   ---------   ----------------------------------------   ---------------
//   x509        the client certificate on this TLS         an x509 key with
//               connection (the main port asks every       that certificate's
//               connection for one, `tls/CLAUDE.md`)       SPKI thumbprint
//   webauthn    the credential id a verified WebAuthn      a linked webauthn
//               assertion named                            key with that id
//   jwk         a verified DPoP proof's key (`jkt`)        a jwk key with
//                                                          that RFC 7638
//                                                          thumbprint
//   native-sso  a Native SSO device_secret                 the device the
//                                                          secret's hash is on
//
// It answers a FACT — `{ id, via, keyId, owner, ownerKind, ownerName,
// status, attestation, compliance, chainVerified, at }` — or null, and it
// decides NOTHING: phases 3 to 6 (compliance, CAEP and RISC, risk, policy
// and token claims) read the fact where it is recorded:
//
//   * at a SIGN-IN, on the authentication event: `event.registeredDevice`
//     (`authn/authn.ts`'s `authenticationEvent()`), so every event of a
//     session says which device proved it, and `authn.registeredDeviceOf(
//     session)` answers the latest;
//   * at the TOKEN ENDPOINT, on the issuance request: `opts.registered_device`
//     (`oauth-oidc/oauth2.ts`'s `issue()`, before `checkIssuance()`, and
//     `tokenSet()` for a door that did not pass one).
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS.
//
//   * **THE REGISTER IS THE AUTHORITY, NOT THE CHAIN.** A certificate is
//     recognised by its KEY: the TLS handshake's CertificateVerify proves the
//     client holds the private key, and the register says that key was
//     proven at enrolment to this device. Whether the chain built to this
//     service's truststore is recorded (`chainVerified`) and does not decide
//     — RFC 8705 section 3 binds a token to a self-signed certificate on the
//     same reading. **A certificate refused on REVOCATION is not recognised**
//     (`req.certificateRevocation`, `common/app.js`): the key is the same,
//     and somebody said it should no longer be believed.
//   * **ONE DEVICE, CHOSEN IN ORDER OF STRENGTH**: x509 (a handshake), then
//     webauthn (a signature over a challenge this service chose), then jwk (a
//     proof the client made), then native-sso (a bearer secret). Evidence
//     naming a SECOND device is kept as `conflict: [ids]` rather than
//     dropped: two of one person's devices in one request is odd, and a
//     later phase's policy is where odd is judged.
//   * **A COMPROMISED DEVICE IS STILL RECOGNISED** (`status: 'compromised'`
//     on the fact). Recognising is saying which device it was; refusing it is
//     phase 4's RISC and phase 6's policy, and a recognition that went quiet
//     for a compromised device would hide exactly the requests somebody needs
//     to see.
//   * **ITS LAST USE MOVES** (`devices.noteRecognized()`, at most every
//     `devices.lastUsedResolutionSeconds`), and the recognitions are counted
//     per realm IN THIS PROCESS for Monitoring → Devices — a count, not a
//     log, so it is not persisted, and a page served by one node says so.
//
// The enrolment and attestation counters beside them (`noteEnrolment()`,
// `noteAttestationRefused()`) are here for the same page.
//
// A LIBRARY (rule 3): it registers nothing. It requires `common/devices`
// and `oauth-oidc/mtls.js` (a library), and nothing that requires it back.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import realms = require('./realms');
import stsCrypto = require('./crypto');
import devices = require('./devices');
import mtls = require('../oauth-oidc/mtls');

type Json = any;

const VIAS = ['x509', 'webauthn', 'jwk', 'native-sso'];

// Per realm at the declaration (common/CLAUDE.md), NOT persisted: counters
// of this process — recognitions by via, enrolments by method, attestation
// outcomes by level and by format. A count that two nodes each incremented
// would have to be merged by key to be right, and what this page wants is
// "is recognition happening", which one node's count answers.
const activity = realms.map();

interface DeviceRecognitionDeps {
  log: typeof helpers.log;
  devices: typeof devices;
  mtls: typeof mtls;
  stsCrypto: typeof stsCrypto;
  now: () => number;
}

class DeviceRecognition {
  static readonly VIAS = VIAS;

  constructor(private readonly deps: DeviceRecognitionDeps) {
    deps.log.debug("Entering DeviceRecognition.constructor().");
    deps.log.debug("Leaving DeviceRecognition.constructor().");
  }

  static defaultDeps(): DeviceRecognitionDeps {
    helpers.log.debug("Entering DeviceRecognition.defaultDeps().");
    helpers.log.debug("Leaving DeviceRecognition.defaultDeps().");
    return { log: helpers.log, devices: devices, mtls: mtls,
             stsCrypto: stsCrypto, now: Date.now };
  }

  // One counter, `table` then `key`, bumped in this realm.
  private bump(table: string, key: string): void {
    this.deps.log.debug("Entering DeviceRecognition.bump(). " + table);
    const row = activity.get(table) || {};
    row[key] = (Number(row[key]) || 0) + 1;
    activity.set(table, row);
    this.deps.log.debug("Leaving DeviceRecognition.bump().");
  }

  // The device a certificate on this connection names, or null — with
  // whether its chain verified.
  private byCertificate(req: Json): Json {
    const { log, mtls, stsCrypto, devices } = this.deps;
    log.debug("Entering DeviceRecognition.byCertificate().");
    const cert = req ? mtls.peerCertificate(req) : null;
    if (!cert) {
      log.debug("Leaving DeviceRecognition.byCertificate(). None.");
      return null;
    }
    const revocation = req.certificateRevocation || null;
    if (revocation && revocation.refused) {
      log.debug("Leaving DeviceRecognition.byCertificate(). Revoked.");
      return null;
    }
    let thumbprint = '';
    try {
      thumbprint = stsCrypto.certificateSpkiThumbprint(
        Buffer.from(cert.raw).toString('base64'));
    } catch (e) {
      log.debug("Caught in DeviceRecognition.byCertificate(): " +
                ((e && e.message) || e));
      thumbprint = '';
    }
    const device = thumbprint ? devices.byKeyThumbprint(thumbprint, 'x509')
                              : null;
    log.debug("Leaving DeviceRecognition.byCertificate(). " + !!device);
    return device ? { device: device, thumbprint: thumbprint,
                      chainVerified: !!mtls.peerVerified(req).verified }
                  : null;
  }

  // The key of `kind` on `device` matching `test`, or null.
  private static keyOf(device: Json, kind: string,
                       test: (k: Json) => boolean): Json {
    helpers.log.debug("Entering DeviceRecognition.keyOf(). " + kind);
    helpers.log.debug("Leaving DeviceRecognition.keyOf().");
    return (device.keys || []).filter(function (k: Json): boolean {
      return k.kind === kind && test(k);
    })[0] || null;
  }

  // =========================================================================
  // RECOGNISE. `evidence` is any of { request, webauthnCredentialId,
  // dpopJkt, deviceSecret, clientId, subject } — `subject` the username
  // the request is for, which sets `ownerMatches`, `clientId` the
  // application the device is linked to. Answers the fact or null.
  // =========================================================================
  recognize(evidence: Json): Json {
    const { log, devices } = this.deps;
    log.debug("Entering DeviceRecognition.recognize().");
    const e = evidence || {};
    const found: Json[] = [];
    const cert = this.byCertificate(e.request);
    if (cert) {
      const key = DeviceRecognition.keyOf(cert.device, 'x509',
        function (k: Json): boolean {
          return k.thumbprint === cert.thumbprint;
        });
      found.push({ device: cert.device, via: 'x509', key: key,
                   chainVerified: cert.chainVerified });
    }
    if (e.webauthnCredentialId) {
      const device = devices.byCredentialId(e.webauthnCredentialId);
      if (device) {
        found.push({ device: device, via: 'webauthn',
          key: DeviceRecognition.keyOf(device, 'webauthn',
            function (k: Json): boolean {
              return String((k.material || {}).credentialId || '') ===
                     String(e.webauthnCredentialId);
            }) });
      }
    }
    if (e.dpopJkt) {
      const device = devices.byKeyThumbprint(e.dpopJkt, 'jwk');
      if (device) {
        found.push({ device: device, via: 'jwk',
          key: DeviceRecognition.keyOf(device, 'jwk',
            function (k: Json): boolean {
              return k.thumbprint === String(e.dpopJkt);
            }) });
      }
    }
    if (e.deviceSecret) {
      const device = devices.bySecret(e.deviceSecret);
      if (device) {
        found.push({ device: device, via: 'native-sso', key: null });
      }
    }
    if (!found.length) {
      log.debug("Leaving DeviceRecognition.recognize(). No device.");
      return null;
    }
    const first = found[0];
    const conflict = found.filter(function (one: Json): boolean {
      return one.device.id !== first.device.id;
    }).map(function (one: Json): string {
      return one.device.id;
    });
    devices.noteRecognized(first.device, e.clientId);
    this.bump('recognitions', first.via);
    const owner = devices.ownerOf(first.device.owner) || {};
    const fact: Json = {
      id: first.device.id, via: first.via,
      keyId: first.key ? String(first.key.id) : '',
      owner: first.device.owner, ownerKind: first.device.ownerKind,
      ownerName: String(owner.name || ''),
      status: first.device.status, attestation: first.device.attestation,
      keyAttestation: first.key && first.key.attestation
        ? String(first.key.attestation.level) : '',
      compliance: first.device.compliance,
      riskLevel: first.device.riskLevel || '',
      chainVerified: first.via === 'x509' ? !!first.chainVerified : undefined,
      at: new Date(this.deps.now()).toISOString()
    };
    if (e.subject !== undefined) {
      fact.ownerMatches = first.device.ownerKind === 'person' &&
        String(owner.name || '') === String(e.subject || '');
    }
    if (conflict.length) {
      fact.conflict = conflict;
    }
    log.info('devices: device ' + fact.id + ' (' + fact.status + ') ' +
             'recognised by ' + fact.via + (fact.keyId ? ' key ' + fact.keyId
                                                       : '') + '.');
    log.debug("Leaving DeviceRecognition.recognize(). " + fact.id);
    return fact;
  }

  // =========================================================================
  // A RECORDED FACT, BROUGHT UP TO DATE (#164 phase 6). A session's event
  // recorded the device as it stood at the sign-in; an issuance an hour
  // later is decided on the device as it stands NOW — an MDM that has since
  // reported it not-compliant, an administrator who marked it compromised —
  // because compliance is exactly the fact that moves under a live session.
  // So the register is asked again by id (an index lookup) and the four
  // things that can move are overlaid; the evidence (`via`, the key) is the
  // sign-in's and stays. Null for a device since removed: a device no
  // longer registered is not a registered device. A fact with no id, or no
  // fact, is answered as given.
  // =========================================================================
  current(fact: Json): Json {
    const { log, devices } = this.deps;
    log.debug("Entering DeviceRecognition.current().");
    if (!fact || !fact.id) {
      log.debug("Leaving DeviceRecognition.current(). Nothing to refresh.");
      return fact || null;
    }
    const device = devices.byId(fact.id);
    if (!device) {
      log.debug("Leaving DeviceRecognition.current(). Removed since.");
      return null;
    }
    const out = Object.assign({}, fact, {
      status: device.status, compliance: device.compliance,
      attestation: device.attestation, riskLevel: device.riskLevel || ''
    });
    // GIVEN TO SOMEBODY ELSE SINCE: the owner's name is looked up again,
    // and the sign-in's `ownerMatches` no longer speaks for it.
    if (String(device.owner || '').toLowerCase() !==
        String(fact.owner || '').toLowerCase()) {
      const owner = devices.ownerOf(device.owner) || {};
      out.owner = device.owner;
      out.ownerKind = device.ownerKind;
      out.ownerName = String(owner.name || '');
      delete out.ownerMatches;
    }
    log.debug("Leaving DeviceRecognition.current().");
    return out;
  }

  // -------------------------------------------------------------------------
  // WHETHER A FACT'S DEVICE BELONGS TO THE PARTY AN ISSUANCE IS ABOUT —
  // `subject` is `{ kind: user | application, name }`, the issuance gate's
  // shape. A person's own device, or an application's own device for that
  // application — by the owner's kind and name, which recognition names
  // and `current()` looks up again for a device given away since.
  // -------------------------------------------------------------------------
  static ownedBy(fact: Json, subject: Json): boolean {
    helpers.log.debug("Entering DeviceRecognition.ownedBy().");
    const who = subject || {};
    if (!fact || !who.name) {
      helpers.log.debug("Leaving DeviceRecognition.ownedBy(). No.");
      return false;
    }
    const kind = who.kind === 'application' ? 'application' : 'person';
    const owned = fact.ownerKind === kind &&
      String(fact.ownerName || '') === String(who.name);
    helpers.log.debug("Leaving DeviceRecognition.ownedBy(). " + owned);
    return owned;
  }

  // An enrolment through `method` whose key was `level` in `format`.
  noteEnrolment(method: string, level: string, format: string): void {
    this.deps.log.debug("Entering DeviceRecognition.noteEnrolment().");
    this.bump('enrolments', String(method));
    this.bump('attestationLevels', String(level));
    this.bump('attestationFormats', String(format || 'none'));
    this.deps.log.debug("Leaving DeviceRecognition.noteEnrolment().");
  }

  // A statement in `format` that did not verify, or a key product refused
  // for having none (`format` 'unattested').
  noteAttestationRefused(format: string): void {
    this.deps.log.debug("Entering DeviceRecognition." +
                        "noteAttestationRefused().");
    this.bump('attestationRefusals', String(format || 'none'));
    this.deps.log.debug("Leaving DeviceRecognition.noteAttestationRefused().");
  }

  // What Monitoring → Devices draws: this realm's counters in this process.
  activity(): Json {
    this.deps.log.debug("Entering DeviceRecognition.activity().");
    const read = function (table: string, keys: string[]): Json {
      helpers.log.debug("Entering read().");
      const row = activity.get(table) || {};
      const out: Json = {};
      keys.concat(Object.keys(row)).forEach(function (k: string) {
        out[k] = Number(row[k]) || 0;
      });
      helpers.log.debug("Leaving read().");
      return out;
    };
    this.deps.log.debug("Leaving DeviceRecognition.activity().");
    return {
      scope: 'this process, since it started',
      recognitions: read('recognitions', VIAS),
      enrolments: read('enrolments', ['portal', 'est', 'scep']),
      attestationLevels: read('attestationLevels',
                              ['attested', 'self-asserted']),
      attestationFormats: read('attestationFormats', []),
      attestationRefusals: read('attestationRefusals', [])
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DeviceRecognition>(
  'common/device_recognition',
  () => new DeviceRecognition(DeviceRecognition.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  DeviceRecognition: DeviceRecognition,
  installInstance: (instance: DeviceRecognition): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  VIAS: VIAS,
  recognize: slot.forward('recognize'),
  current: slot.forward('current'),
  ownedBy: DeviceRecognition.ownedBy,
  noteEnrolment: slot.forward('noteEnrolment'),
  noteAttestationRefused: slot.forward('noteAttestationRefused'),
  activity: slot.forward('activity')
};
