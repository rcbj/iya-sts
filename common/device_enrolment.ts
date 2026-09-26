'use strict';
//
// File: device_enrolment.ts
//
// ===========================================================================
// A PERSON REGISTERING THEIR OWN DEVICE BY PROVING ONE OF ITS KEYS (#164
// decision 6b, phase 2, 2026-09-26).
//
// `/portal/devices` (and its two JSON doors, for a native app) lets the
// signed-in person register a device they own — a new one, or another key on
// one they already have — in one of two ways:
//
//   * **A JWK PROOF.** This file issues a CHALLENGE; the device signs a
//     `device-key-proof+jwt` JWS over it with the key it wants registered,
//     the public key in the header — or, on an iPhone, answers with an Apple
//     App Attest attestation object whose clientDataHash is the challenge's
//     SHA-256. `common/device_attestation.ts` verifies either, and an
//     Android Key Attestation in the JWS's `x5c`.
//   * **A LINKED WEBAUTHN PLATFORM CREDENTIAL** the person already enrolled
//     on `/portal/keys`, proven again NOW by a fresh assertion over a
//     challenge from here — the ceremony `/authn/webauthn` and `/portal/keys`
//     already run, in the same script. Its attestation is the one #105
//     verified when the credential was REGISTERED
//     (`authn/webauthn_attestation.ts`'s record on the key): trusted, it is
//     `attested`; anything else is `self-asserted`. A ROAMING key
//     (`cross-platform`) is refused: it is carried between devices and
//     identifies none of them.
//
// ---------------------------------------------------------------------------
// THE CHALLENGE STORE.
//
// `devices.challenges`, **per realm at its declaration** (common/CLAUDE.md,
// "A store becomes per realm at its DECLARATION") and persisted, so a
// challenge issued by one node is answered at another. A row is
// `{ sessionId, username, purpose, issuedAt, expiresAt, detail }`, keyed by
// the challenge itself (32 random bytes). It is:
//
//   * **BOUND TO THE SESSION AND THE PERSON it was issued to**, and answered
//     by nobody else — the portal rule that no identity comes from a request;
//   * **ONE PER SESSION AND PURPOSE**: a new one replaces the old, so a page
//     reloaded ten times holds one;
//   * **ANSWERED ONCE, ACROSS THE CLUSTER**: spent through
//     `cluster/cluster_claims.js` (`claim()`, the atomic "once"), or, for a
//     WebAuthn assertion, through `credentials.spendAssertion()`, which is
//     that same claim plus the signature counter — so the challenge is the
//     one the ceremony answered and the counter the one sign-in advances;
//   * **SHORT-LIVED** (`devices.challengeTtlSeconds`), and **BOUNDED AT THE
//     INSERT** (`devices.maxChallenges` per realm, the oldest dropped); an
//     expired row is refused where it is read and ejected by the
//     `caches.eject-expired` job (#49 P5, `tests/cache_eject.js`).
//
// **THE CHALLENGE IS ALSO THE JSON DOORS' ANTI-FORGERY TOKEN.** The HTML
// form carries the portal's CSRF field as every portal form does; the JSON
// proof door cannot, because a native app never drew the page. It does not
// need one: a forged request cannot know the challenge (it is returned only
// to the session's own caller, and read cross-origin by nobody — `cors.js`)
// and cannot sign over it with a key it does not hold. The JSON challenge
// door only MINTS, which a forgery gains nothing by; it takes
// `application/json` only, so a plain cross-site form cannot reach it.
//
// ---------------------------------------------------------------------------
// THE MODE SPLIT (decision 9). A key whose attestation is not `attested` is
// registered `self-asserted` in development and REFUSED in product
// (`mode.acceptsUnattestedDeviceKeys()`, STS-DEVICE-0024) — here, before
// anything is written. An administrator's by-value key is not this file's
// and is not asked (`common/mode.js` argues why).
//
// A LIBRARY (rule 3): it registers no route; `portal/portal_devices.ts` is
// the door. It requires `common/devices`, `device_attestation`,
// `device_recognition` (for the counters), `credentials`, the WebAuthn
// verifier and policy (libraries), and `cluster/cluster_claims`.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import realms = require('./realms');
import mode = require('./mode');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import cacheRegistry = require('./cache_registry');
import credentials = require('./credentials');
import devices = require('./devices');
import deviceAttestation = require('./device_attestation');
import deviceRecognition = require('./device_recognition');
import claims = require('../cluster/cluster_claims');
import webauthnVerifier = require('../authn/webauthn');
import webauthnPolicy = require('../authn/webauthn_policy');

type Json = any;

const PURPOSES = ['key', 'webauthn'];
const CLAIM_SCOPE = 'devices.challenge';
const MAX_LABEL = 128;

const challenges = realms.map({ persist: 'devices.challenges',
                                tombstone: true });

function challengeTtlMs(): number {
  helpers.log.debug("Entering challengeTtlMs().");
  helpers.log.debug("Leaving challengeTtlMs().");
  return Math.max(30, Number(config.value('devices.challengeTtlSeconds'))) *
         1000;
}

const challengesCount = cacheRegistry.register({
  name: 'devices.challenges',
  title: 'Device enrolment challenges',
  description: 'The challenges /portal/devices has issued for a key proof, ' +
    'an App Attest statement or a WebAuthn link, each bound to the ' +
    'session it was issued to and answered once.',
  owner: 'common/device_enrolment.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a challenge this realm issued, so the proof was checked',
  settings: ['devices.challengeTtlSeconds', 'devices.maxChallenges'],
  maxEntries: function (): number {
    return Number(config.value('devices.maxChallenges'));
  },
  bound: 'Enforced: devices.maxChallenges per realm, the oldest dropped at ' +
    'the insert; one per session and purpose.',
  lifetime: function (): string {
    return 'devices.challengeTtlSeconds (' +
      Number(config.value('devices.challengeTtlSeconds')) + ' s), or until ' +
      'it is answered.';
  },
  eject: cacheRegistry.realmMapEjector(realms, challenges,
    function (row: Json, key: unknown, now: number): boolean {
      return !row || Number(row.expiresAt) <= now;
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, challenges,
      function (row: Json, key: unknown): object {
        return { key: cacheRegistry.digestKey(key) + ' (' +
                   String((row && row.purpose) || '?') + ')',
                 validUntil: row ? Number(row.expiresAt) : null };
      });
  }
});

interface DeviceEnrolmentDeps {
  log: typeof helpers.log;
  config: typeof config;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  credentials: typeof credentials;
  devices: typeof devices;
  deviceAttestation: typeof deviceAttestation;
  deviceRecognition: typeof deviceRecognition;
  claims: typeof claims;
  webauthnVerifier: typeof webauthnVerifier;
  webauthnPolicy: typeof webauthnPolicy;
  realmId: () => string;
  now: () => number;
}

class DeviceEnrolment {
  static readonly PURPOSES = PURPOSES;

  constructor(private readonly deps: DeviceEnrolmentDeps) {
    deps.log.debug("Entering DeviceEnrolment.constructor().");
    deps.log.debug("Leaving DeviceEnrolment.constructor().");
  }

  static defaultDeps(): DeviceEnrolmentDeps {
    helpers.log.debug("Entering DeviceEnrolment.defaultDeps().");
    helpers.log.debug("Leaving DeviceEnrolment.defaultDeps().");
    return { log: helpers.log, config: config, mode: mode,
             errorCodes: errorCodes, audit: audit, credentials: credentials,
             devices: devices, deviceAttestation: deviceAttestation,
             deviceRecognition: deviceRecognition, claims: claims,
             webauthnVerifier: webauthnVerifier,
             webauthnPolicy: webauthnPolicy,
             realmId: function (): string {
               return realms.currentId();
             },
             now: Date.now };
  }

  private refuse(code: string, why: string, status?: number): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering DeviceEnrolment.refuse(). " + code);
    log.debug("Leaving DeviceEnrolment.refuse().");
    return errorCodes.mark({ ok: false, status: status || 400, error: why,
                             errors: [why] }, code);
  }

  // =========================================================================
  // ISSUE A CHALLENGE for `purpose`, bound to the session and the person.
  // `detail` rides along (a WebAuthn link's credential and target). Answers
  // { ok, challenge, purpose, expiresAt }.
  // =========================================================================
  issueChallenge(spec: Json): Json {
    const { log, config } = this.deps;
    log.debug("Entering DeviceEnrolment.issueChallenge().");
    const s = spec || {};
    const purpose = String(s.purpose || 'key');
    if (PURPOSES.indexOf(purpose) < 0 || !s.sessionId || !s.username) {
      log.debug("Leaving DeviceEnrolment.issueChallenge(). Malformed.");
      return this.refuse('STS-DEVICE-0016', 'A challenge is issued to a ' +
                         'signed-in session, for a key proof or a WebAuthn ' +
                         'link.');
    }
    const stale: string[] = [];
    challenges.forEach(function (row: Json, key: string) {
      if (row && row.sessionId === s.sessionId && row.purpose === purpose) {
        stale.push(key);
      }
    });
    stale.forEach(function (key: string) {
      challenges.delete(key);
    });
    cacheRegistry.makeRoom(challenges,
                           Number(config.value('devices.maxChallenges')),
                           { name: 'devices.challenges',
                             counter: challengesCount,
                             setting: 'devices.maxChallenges' });
    const now = this.deps.now();
    const challenge = nodeCrypto.randomBytes(32).toString('base64url');
    const row = { sessionId: String(s.sessionId), username: String(s.username),
                  purpose: purpose, issuedAt: now,
                  expiresAt: now + challengeTtlMs(),
                  detail: s.detail || null };
    challenges.set(challenge, row);
    log.debug("Leaving DeviceEnrolment.issueChallenge(). " + purpose);
    return { ok: true, challenge: challenge, purpose: purpose,
             expiresAt: new Date(row.expiresAt).toISOString(),
             detail: row.detail };
  }

  // The live challenge this session holds for `purpose`, or null — what the
  // page draws while a ceremony or a proof is awaited.
  pendingFor(sessionId: unknown, purpose: string): Json {
    const { log } = this.deps;
    log.debug("Entering DeviceEnrolment.pendingFor(). " + purpose);
    const now = this.deps.now();
    let out: Json = null;
    challenges.forEach(function (row: Json, key: string) {
      if (row && row.sessionId === String(sessionId || '') &&
          row.purpose === purpose && Number(row.expiresAt) > now) {
        out = Object.assign({ challenge: key }, row);
      }
    });
    log.debug("Leaving DeviceEnrolment.pendingFor(). " + !!out);
    return out;
  }

  // Forgets this session's challenge for `purpose` (the page's Cancel).
  abandon(sessionId: unknown, purpose: string): void {
    const { log } = this.deps;
    log.debug("Entering DeviceEnrolment.abandon(). " + purpose);
    const held = this.pendingFor(sessionId, purpose);
    if (held) {
      challenges.delete(held.challenge);
    }
    log.debug("Leaving DeviceEnrolment.abandon().");
  }

  // A challenge's row if `s` (sessionId, username, purpose) may answer it,
  // or the refusal. Spends nothing.
  private checkChallenge(challenge: string, s: Json): Json {
    const { log } = this.deps;
    log.debug("Entering DeviceEnrolment.checkChallenge().");
    const row = challenge ? challenges.get(challenge) : null;
    let why = '';
    if (!row) {
      why = 'There is no such challenge — it was never issued, was already ' +
            'answered, or was replaced by a newer one.';
    } else if (Number(row.expiresAt) <= this.deps.now()) {
      why = 'That challenge has expired (devices.challengeTtlSeconds). Ask ' +
            'for a new one.';
    } else if (row.sessionId !== String(s.sessionId || '') ||
               row.username !== String(s.username || '')) {
      why = 'That challenge was issued to another session.';
    } else if (row.purpose !== s.purpose) {
      why = 'That challenge was issued for something else.';
    }
    if (why) {
      log.debug("Leaving DeviceEnrolment.checkChallenge(). Refused.");
      return this.refuse('STS-DEVICE-0016', why);
    }
    log.debug("Leaving DeviceEnrolment.checkChallenge().");
    return { ok: true, row: row };
  }

  // Spends a key challenge ONCE across the cluster. { ok, row } or refusal.
  private async spendKeyChallenge(challenge: string, s: Json): Promise<Json> {
    const { log, claims } = this.deps;
    log.debug("Entering DeviceEnrolment.spendKeyChallenge().");
    const checked = this.checkChallenge(challenge, s);
    if (!checked.ok) {
      log.debug("Leaving DeviceEnrolment.spendKeyChallenge(). Refused.");
      return checked;
    }
    const claimed = await claims.claim({ scope: CLAIM_SCOPE,
      value: challenge, ttlMs: challengeTtlMs() + 60000,
      realm: this.deps.realmId() });
    challenges.delete(challenge);
    if (!claimed.ok) {
      log.debug("Leaving DeviceEnrolment.spendKeyChallenge(). " +
                claimed.reason);
      return claimed.reason === 'used'
        ? this.refuse('STS-DEVICE-0016', 'That challenge has already been ' +
                      'answered.')
        : this.refuse('STS-DEVICE-0028', 'The challenge could not be ' +
                      'proved unanswered just now. Try again.', 503);
    }
    log.debug("Leaving DeviceEnrolment.spendKeyChallenge().");
    return checked;
  }

  // The descriptive fields a request may set, clipped: label, platform,
  // model, os. `devices.create()` refuses a platform outside its list.
  private described(s: Json): Json {
    this.deps.log.debug("Entering DeviceEnrolment.described().");
    const out: Json = {};
    ['label', 'platform', 'model', 'os'].forEach(function (k: string) {
      if (s[k] !== undefined && s[k] !== null && String(s[k]).trim()) {
        out[k] = String(s[k]).trim().slice(0, MAX_LABEL);
      }
    });
    this.deps.log.debug("Leaving DeviceEnrolment.described().");
    return out;
  }

  // =========================================================================
  // THE KEY, REGISTERED: a new device owned by `username`, or a key added to
  // `deviceId`, which must be theirs. The mode split is asked first.
  // =========================================================================
  private register(username: string, keySpec: Json, s: Json,
                   via: string): Json {
    const { log, mode, devices, deviceRecognition, audit } = this.deps;
    log.debug("Entering DeviceEnrolment.register(). " + via);
    const level = keySpec.attestation && keySpec.attestation.level;
    const format = String((keySpec.attestation &&
                           keySpec.attestation.format) || 'none');
    if (level !== 'attested' && !mode.acceptsUnattestedDeviceKeys()) {
      deviceRecognition.noteAttestationRefused('unattested');
      audit.record({ category: 'authentication',
        action: 'device.enrol.refused', errorCode: 'STS-DEVICE-0024',
        actor: username, target: username, outcome: 'failure',
        summary: 'a ' + keySpec.kind + ' device key with no verified ' +
                 'attestation was refused (product mode)',
        detail: { via: via, format: format } });
      log.debug("Leaving DeviceEnrolment.register(). Unattested, product.");
      return this.refuse('STS-DEVICE-0024', 'This realm registers a device ' +
        'key only with an attestation that verified and chained to a ' +
        'trusted root, and this one ' + (format === 'none'
          ? 'carried none' : 'did not chain to one: ' +
            String((keySpec.attestation || {}).summary || '')) + '.');
    }
    let result: Json = null;
    if (s.deviceId) {
      const mine = devices.listFor(username).some(function (d: Json) {
        return d.id === String(s.deviceId);
      });
      result = mine ? devices.addKey(String(s.deviceId), keySpec, username,
                                     { initiatingEntity: 'user' })
        : this.refuse('STS-DEVICE-0007', 'No device "' +
                      String(s.deviceId).slice(0, 64) + '" is yours.');
    } else {
      result = devices.create(Object.assign({ owner: username,
        ownerKind: 'person', method: 'portal', keys: [keySpec] },
        this.described(s)), username, { initiatingEntity: 'user' });
    }
    if (result.ok) {
      deviceRecognition.noteEnrolment('portal', String(level ||
                                      'self-asserted'), format);
    }
    log.debug("Leaving DeviceEnrolment.register(). ok=" + result.ok);
    return result;
  }

  // =========================================================================
  // A JWK PROOF or an APP ATTEST statement answering a `key` challenge.
  // `spec` is { username, sessionId, challenge, audience, proof (a compact
  // JWS) | appAttest: { keyId, attestation }, deviceId?, label, platform,
  // model, os, keyLabel }.
  // =========================================================================
  async proveKey(spec: Json): Promise<Json> {
    const { log, deviceAttestation, deviceRecognition } = this.deps;
    log.debug("Entering DeviceEnrolment.proveKey().");
    const s = spec || {};
    const username = String(s.username || '');
    const spent = await this.spendKeyChallenge(String(s.challenge || ''),
      { sessionId: s.sessionId, username: username, purpose: 'key' });
    if (!spent.ok) {
      log.debug("Leaving DeviceEnrolment.proveKey(). Challenge.");
      return spent;
    }
    let verified: Json = null;
    if (s.appAttest && typeof s.appAttest === 'object') {
      verified = await deviceAttestation.appAttest({
        keyId: s.appAttest.keyId, attestation: s.appAttest.attestation,
        nonce: String(s.challenge) });
    } else if (s.proof) {
      verified = await deviceAttestation.verifyJwkProof({
        token: String(s.proof), nonce: String(s.challenge),
        audience: String(s.audience || '') });
    } else {
      verified = this.refuse('STS-DEVICE-0017', 'Send a key proof (a JWS ' +
                             'over the challenge) or an App Attest ' +
                             'statement.');
    }
    if (!verified.ok) {
      deviceRecognition.noteAttestationRefused(s.appAttest
        ? 'apple-app-attest' : 'jwk-proof');
      log.debug("Leaving DeviceEnrolment.proveKey(). Not verified.");
      return verified;
    }
    const out = this.register(username, {
      kind: 'jwk', jwk: verified.jwk, proof: 'jwk-proof',
      label: String(s.keyLabel || '').slice(0, MAX_LABEL) ||
             (s.appAttest ? 'App Attest key' : verified.alg + ' key'),
      attestation: verified.attestation }, s, 'jwk-proof');
    log.debug("Leaving DeviceEnrolment.proveKey(). ok=" + out.ok);
    return out;
  }

  // =========================================================================
  // A WEBAUTHN LINK, begun: the person names one of their credentials, and
  // a `webauthn` challenge carrying it is issued. { ok, challenge, … } or a
  // refusal.
  // =========================================================================
  beginLink(spec: Json): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering DeviceEnrolment.beginLink().");
    const s = spec || {};
    const username = String(s.username || '');
    const key = (credentials.keysOf(username) || []).filter(function (k: Json) {
      return String(k.credentialId) === String(s.credentialId || '');
    })[0];
    if (!key) {
      log.debug("Leaving DeviceEnrolment.beginLink(). Not theirs.");
      return this.refuse('STS-DEVICE-0022', 'That is not a security key ' +
                         'you enrolled.');
    }
    if (String(key.attachment || '') === 'cross-platform') {
      log.debug("Leaving DeviceEnrolment.beginLink(). Roaming.");
      return this.refuse('STS-DEVICE-0022', 'That security key is a ' +
        'roaming authenticator (cross-platform): it is carried between ' +
        'devices and identifies none of them. Link a key built into this ' +
        'device (a platform authenticator).');
    }
    const out = this.issueChallenge({ sessionId: s.sessionId,
      username: username, purpose: 'webauthn',
      detail: Object.assign({ credentialId: String(key.credentialId),
                              deviceId: String(s.deviceId || '') },
                            this.described(s)) });
    log.debug("Leaving DeviceEnrolment.beginLink(). ok=" + out.ok);
    return out;
  }

  // =========================================================================
  // A WEBAUTHN LINK, finished: `spec` is { username, sessionId, challenge,
  // credential (what /authn/webauthn.js posted in `get` mode), origin,
  // rpId }. The assertion is verified with the stored key and spent through
  // `credentials.spendAssertion()`; the key's REGISTRATION attestation
  // decides its level.
  // =========================================================================
  async finishLink(spec: Json): Promise<Json> {
    const { log, credentials, webauthnVerifier, webauthnPolicy } = this.deps;
    log.debug("Entering DeviceEnrolment.finishLink().");
    const s = spec || {};
    const username = String(s.username || '');
    const challenge = String(s.challenge || '');
    const checked = this.checkChallenge(challenge, { sessionId: s.sessionId,
      username: username, purpose: 'webauthn' });
    if (!checked.ok) {
      log.debug("Leaving DeviceEnrolment.finishLink(). Challenge.");
      return checked;
    }
    const detail = checked.row.detail || {};
    const credential = s.credential || {};
    const key = (credentials.keysOf(username) || []).filter(function (k: Json) {
      return String(k.credentialId) === String(detail.credentialId);
    })[0];
    const named = String(credential.rawId || credential.id || '');
    if (!key || named !== String(detail.credentialId) ||
        !credential.response) {
      challenges.delete(challenge);
      log.debug("Leaving DeviceEnrolment.finishLink(). Wrong credential.");
      return this.refuse('STS-DEVICE-0022', 'The browser answered with ' +
        (credential.response ? 'a different security key from the one ' +
          'you chose' : 'no assertion — it ran no ceremony') + '.');
    }
    let verdict: Json = null;
    try {
      verdict = webauthnVerifier.verifyAssertion({
        authenticatorData: credential.response.authenticatorData,
        clientDataJSON: credential.response.clientDataJSON,
        signature: credential.response.signature,
        publicKeyJwk: key.publicKeyJwk,
        expectedChallenge: challenge,
        expectedOrigin: String(s.origin || ''),
        expectedRpId: String(s.rpId || ''),
        requireUserVerification: webauthnPolicy.requireUserVerification(),
        previousSignCount: key.signCount });
    } catch (e) {
      log.debug("Caught in DeviceEnrolment.finishLink(): " +
                ((e && e.message) || e));
      verdict = { ok: false, failed: [String((e && e.message) || e)] };
    }
    if (credentials.Credentials.clonedKeyVerdict(verdict)) {
      // A CLONE, BY THE ENTRY'S COUNTER (#231): see noteKeyCloned().
      credentials.noteKeyCloned(username, key.credentialId, 'signature ' +
        'counter ' + verdict.signCount + ', last recorded ' + key.signCount);
    }
    if (!verdict.ok) {
      challenges.delete(challenge);
      log.debug("Leaving DeviceEnrolment.finishLink(). Assertion.");
      return this.refuse('STS-DEVICE-0022', 'The security key\'s assertion ' +
        'does not verify: ' + ((verdict.failed || []).map(function (f: Json) {
          return typeof f === 'string' ? f : String(f && f.name);
        }).join('; ') || 'unknown') + '.');
    }
    const spent = await credentials.spendAssertion({ username: username,
      credentialId: key.credentialId, signCount: verdict.signCount,
      challenge: challenge, ttlMs: challengeTtlMs() });
    challenges.delete(challenge);
    if (!spent.ok) {
      log.debug("Leaving DeviceEnrolment.finishLink(). Not spent.");
      return this.refuse(spent.reason === 'store' ? 'STS-DEVICE-0028'
                                                  : 'STS-DEVICE-0016',
                         'The assertion could not be accepted: ' +
                         String(spent.detail || spent.reason) + '.');
    }
    const att = key.attestation || {};
    const trusted = !!(att.verified && att.trusted);
    const out = this.register(username, {
      kind: 'webauthn', credentialId: String(key.credentialId),
      proof: 'webauthn', label: String(detail.label || key.label ||
                                       'security key'),
      attestation: { level: trusted ? 'attested' : 'self-asserted',
        format: String(att.format || 'none'),
        summary: trusted
          ? 'WebAuthn attestation (' + String(att.format) + ', ' +
            String(att.type || '') + ') verified at registration and ' +
            'trusted through ' + String(att.anchor || '') +
            (att.model ? ', ' + String(att.model) : '') + '.'
          : 'WebAuthn credential whose registration attestation was ' +
            (att.verified ? 'verified and not trusted' : 'not verified') +
            ' (format ' + String(att.format || 'unrecorded') + ').',
        verifiedAt: trusted
          ? new Date(Number(att.checkedAt) || this.deps.now()).toISOString()
          : '' } }, { deviceId: detail.deviceId, label: detail.label,
                      platform: detail.platform, model: detail.model,
                      os: detail.os }, 'webauthn');
    log.debug("Leaving DeviceEnrolment.finishLink(). ok=" + out.ok);
    return out;
  }

  // What Protocols → Device registration says about the store.
  describeChallenges(): Json {
    this.deps.log.debug("Entering DeviceEnrolment.describeChallenges().");
    let live = 0;
    const now = this.deps.now();
    challenges.forEach(function (row: Json) {
      if (row && Number(row.expiresAt) > now) {
        live += 1;
      }
    });
    this.deps.log.debug("Leaving DeviceEnrolment.describeChallenges().");
    return { store: 'devices.challenges', perRealm: true, persisted: true,
             live: live,
             ttlSeconds: Number(config.value('devices.challengeTtlSeconds')),
             max: Number(config.value('devices.maxChallenges')),
             purposes: PURPOSES.slice(0) };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DeviceEnrolment>(
  'common/device_enrolment',
  () => new DeviceEnrolment(DeviceEnrolment.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  DeviceEnrolment: DeviceEnrolment,
  installInstance: (instance: DeviceEnrolment): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PURPOSES: PURPOSES,
  issueChallenge: slot.forward('issueChallenge'),
  pendingFor: slot.forward('pendingFor'),
  abandon: slot.forward('abandon'),
  proveKey: slot.forward('proveKey'),
  beginLink: slot.forward('beginLink'),
  finishLink: slot.forward('finishLink'),
  describeChallenges: slot.forward('describeChallenges')
};
