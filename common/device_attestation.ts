'use strict';
//
// File: device_attestation.ts
//
// ===========================================================================
// WHAT A DEVICE KEY'S ATTESTATION PROVES, VERIFIED (#164 decision 7, phase 2,
// 2026-09-26).
//
// A device key is registered by PROVING it (`common/device_enrolment.ts`),
// and a proof of possession says only that the presenter holds the private
// key. Decision 7 asks for the other question — WHERE the key lives — and
// names the statements that answer it:
//
//   * **ANDROID KEY ATTESTATION** on a JWK proof: the proof's JWS header
//     carries `x5c`, a chain whose leaf certifies the proven key and carries
//     the key attestation extension (1.3.6.1.4.1.11129.2.1.17). Its
//     `attestationChallenge` must be this realm's enrolment challenge, its
//     `attestationSecurityLevel` a TEE or StrongBox — never Software — and
//     the chain must end at a Google hardware attestation root
//     (`devices.androidAttestationTrustAnchors`, or the two shipped and
//     pinned in `common/pki_device_anchors.json`).
//   * **APPLE APP ATTEST**: the attestation object `DCAppAttestService`
//     returns, with the enrolment challenge's SHA-256 as its clientDataHash.
//     Apple's validation steps 1-9 ("Validating apps that connect to your
//     server"): the chain to the Apple App Attestation Root CA; the nonce
//     SHA-256(authData ‖ clientDataHash) in the credential certificate's
//     1.2.840.113635.100.8.2; the key id as the SHA-256 of the certificate's
//     uncompressed EC point; the RP ID hash as the SHA-256 of a configured
//     TEAMID.bundle.id (`devices.appleAppAttestAppIds`); the counter 0; the
//     AAGUID `appattest` (or `appattestdevelop` where
//     `devices.appleAppAttestAllowDevelopment` says); the credential id the
//     key id. The RECEIPT is kept by the app for Apple's fraud-risk service
//     and is not read here: nothing here dials Apple.
//   * **TPM KEY ATTESTATION** on EST and SCEP:
//     draft-ietf-lamps-csr-attestation's id-aa-attestation attribute (the
//     codec is `crypto.csrAttestationBundle()`), with a TCG
//     `tcg-attest-tpm-certify` statement: TPM2_Certify's TPMS_ATTEST, signed
//     by an Attestation Key whose certificate (tcg-kp-AIKCertificate) is in
//     the bundle and chains to `devices.tpmTrustAnchors`; the certified Name
//     is nameAlg ‖ H(TPMT_PUBLIC) of the public area carried beside it; that
//     public area is the request's key; and its objectAttributes say fixedTPM,
//     fixedParent and sensitiveDataOrigin — generated inside the TPM and never
//     to leave it.
//   * WebAuthn's own statement is #105's (`authn/webauthn_attestation.ts`),
//     verified when the credential was REGISTERED; a device linking the
//     credential reads that record (`device_enrolment.ts`).
//
// ---------------------------------------------------------------------------
// THREE OUTCOMES, AND WHICH IS WHICH IS THE WHOLE DESIGN.
//
//   * **A statement that does not verify is REFUSED**, in both modes, under
//     its own code (STS-DEVICE-0018, 0019, 0020): a signature that fails, a
//     challenge that is not ours, a certified key that is not the one
//     presented. That is a claim that is FALSE, and registering the key
//     anyway would record a lie beside it.
//   * **A statement that verifies and chains to NO anchor this realm holds
//     is `self-asserted`**, with the reason in its summary. Cryptographically
//     it proves no more than a self-signed statement does — WebAuthn Level 3
//     section 7.1 step 25's reading, which #105 follows. Product refuses it
//     through `mode.acceptsUnattestedDeviceKeys()`, as it refuses no
//     statement at all.
//   * **A statement that verifies and chains to an anchor is `attested`.**
//
// ---------------------------------------------------------------------------
// WHAT IS NOT DONE, AND WHY.
//
//   * **Google's attestation revocation list** (android.googleapis.com/
//     attestation/status) is not consulted: it is a URL somebody else
//     serves, and this service dials such a URL only as a scheduler job
//     with the operator's say-so (root CLAUDE.md, the dialling row). A
//     compromised Android batch key is what the list reports; until a job
//     imports it, an operator removes such devices by hand.
//   * **Freshness of a TPM statement**: draft-ietf-lamps-csr-attestation
//     section 6.2 leaves it to the CA ("may choose to ignore attestations
//     that are stale"), and EST and SCEP give the attester no nonce without
//     draft-ietf-lamps-attestation-freshness. What a key attestation states —
//     that the key was made in, and cannot leave, a TPM — does not go stale,
//     and the request's own signature proves possession NOW; so the
//     statement's `extraData` is recorded and not required to be anything.
//   * **Post-quantum**: every format here is fixed by its vendor — Android's
//     and Apple's chains are RSA and ECDSA, a TPM 2.0 AK signs RSA or ECDSA —
//     so none of them can be post-quantum, and the summary records the
//     algorithm each used. A JWK proof WITHOUT an attestation may be ML-DSA:
//     the proof's algorithm list is `crypto.JWS_ASYMMETRIC_ALGS`, post-quantum
//     included.
//
// A LIBRARY (rule 3): it registers nothing and holds nothing. Every codec it
// uses is `crypto.js`'s (section 10, and the CSR attestation codec beside
// it) and every certificate question `pki.js`'s (rcbj, 2026-09-21); the CBOR
// and authenticator-data readers are `authn/webauthn.js`'s, the one copy.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import stsCrypto = require('./crypto');
import pki = require('./pki');
import errorCodes = require('./error_codes');
import webauthnCodec = require('../authn/webauthn');

type Json = any;

// The Android key attestation extension, and Apple's nonce extension.
const OID_ANDROID_KEY = '1.3.6.1.4.1.11129.2.1.17';
const OID_APPLE_NONCE = '1.2.840.113635.100.8.2';
// TCG's Attestation Key certificate purpose (TCG EK Credential Profile).
const OID_TCG_AIK = '2.23.133.8.3';

// KeyMint's SecurityLevel (Android's key attestation schema).
const SECURITY_LEVELS = ['software', 'trusted-environment', 'strongbox'];

// App Attest's two AAGUIDs: "appattestdevelop", and "appattest" padded
// with seven NULs.
const APP_ATTEST_PRODUCTION = Buffer.concat([Buffer.from('appattest'),
                                             Buffer.alloc(7)]);
const APP_ATTEST_DEVELOPMENT = Buffer.from('appattestdevelop');

// TPMA_OBJECT (TPM 2.0 Library Part 2, table 31): the three bits that say a
// key was generated inside the TPM and can never be duplicated out of it.
const TPMA_FIXED_TPM = 0x00000002;
const TPMA_FIXED_PARENT = 0x00000010;
const TPMA_SENSITIVE_DATA_ORIGIN = 0x00000020;

// The typ a device key proof carries, so a DPoP proof or any other JWS
// signed by the same key cannot be replayed as one (RFC 8725 section 3.11).
const PROOF_TYP = 'device-key-proof+jwt';

interface DeviceAttestationDeps {
  log: typeof helpers.log;
  config: typeof config;
  stsCrypto: typeof stsCrypto;
  pki: typeof pki;
  errorCodes: typeof errorCodes;
  webauthnCodec: typeof webauthnCodec;
  now: () => number;
}

class DeviceAttestation {
  static readonly PROOF_TYP = PROOF_TYP;
  static readonly SECURITY_LEVELS = SECURITY_LEVELS;
  static readonly OID_ANDROID_KEY = OID_ANDROID_KEY;
  static readonly OID_APPLE_NONCE = OID_APPLE_NONCE;
  static readonly OID_TCG_AIK = OID_TCG_AIK;

  constructor(private readonly deps: DeviceAttestationDeps) {
    deps.log.debug("Entering DeviceAttestation.constructor().");
    deps.log.debug("Leaving DeviceAttestation.constructor().");
  }

  static defaultDeps(): DeviceAttestationDeps {
    helpers.log.debug("Entering DeviceAttestation.defaultDeps().");
    helpers.log.debug("Leaving DeviceAttestation.defaultDeps().");
    return { log: helpers.log, config: config, stsCrypto: stsCrypto,
             pki: pki, errorCodes: errorCodes, webauthnCodec: webauthnCodec,
             now: Date.now };
  }

  // A refusal with its code and the sentence.
  private refuse(code: string, why: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering DeviceAttestation.refuse(). " + code);
    log.debug("Leaving DeviceAttestation.refuse().");
    return errorCodes.mark({ ok: false, error: why, errors: [why] }, code);
  }

  private nowIso(): string {
    this.deps.log.debug("Entering DeviceAttestation.nowIso().");
    this.deps.log.debug("Leaving DeviceAttestation.nowIso().");
    return new Date(this.deps.now()).toISOString();
  }

  // The record a key carries: `{ level, format, summary, verifiedAt }`.
  private record(level: string, format: string, summary: string): Json {
    this.deps.log.debug("Entering DeviceAttestation.record(). " + level);
    this.deps.log.debug("Leaving DeviceAttestation.record().");
    return { level: level, format: format,
             summary: String(summary || '').slice(0, 500),
             verifiedAt: level === 'attested' ? this.nowIso() : '' };
  }

  // The RFC 7638 thumbprint of a JWK, or '' for one that cannot be read.
  private thumbprintOf(jwk: Json): string {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering DeviceAttestation.thumbprintOf().");
    try {
      log.debug("Leaving DeviceAttestation.thumbprintOf().");
      return stsCrypto.jwkThumbprint(jwk);
    } catch (e) {
      log.debug("Caught in DeviceAttestation.thumbprintOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving DeviceAttestation.thumbprintOf(). Unreadable.");
      return '';
    }
  }

  // The chain `leaf` then `rest` against `anchors` (`pki.deviceAttestation-
  // Anchors()`'s answer). `{ ok, anchor }` or `{ ok: false, why }`.
  private async chainOf(leaf: Buffer, rest: Buffer[],
                        anchors: Json): Promise<Json> {
    const { log, pki } = this.deps;
    log.debug("Entering DeviceAttestation.chainOf().");
    if (!anchors.anchors.length) {
      log.debug("Leaving DeviceAttestation.chainOf(). No anchor.");
      return { ok: false, why: 'no trust anchor is configured for it' };
    }
    const path = await pki.verifyPathToAnchors(leaf, rest, anchors.anchors,
                                               { now: this.deps.now() });
    if (!path.ok) {
      log.debug("Leaving DeviceAttestation.chainOf(). " + path.reason);
      return { ok: false, why: String(path.reason) };
    }
    const top = path.chain[path.chain.length - 1];
    log.debug("Leaving DeviceAttestation.chainOf(). Anchored.");
    return { ok: true, anchor: String((top.x509 && top.x509.subject) || '')
      .replace(/\n/g, ', ') + ' (' + anchors.source + ')' };
  }

  // =========================================================================
  // A JWK PROOF: a compact JWS, `typ` device-key-proof+jwt, the public key in
  // its header's `jwk`, over `{ nonce, aud, iat }`. `spec` is { token, nonce,
  // audience }. Resolves { ok, jwk, alg, attestation } or a refusal. An `x5c`
  // in the header is an Android Key Attestation, verified by android().
  // =========================================================================
  async verifyJwkProof(spec: Json): Promise<Json> {
    const { log, stsCrypto, config } = this.deps;
    log.debug("Entering DeviceAttestation.verifyJwkProof().");
    const token = String((spec && spec.token) || '').trim();
    let header: Json = null;
    try {
      header = JSON.parse(Buffer.from(token.split('.')[0] || '',
                                      'base64url').toString('utf8'));
    } catch (e) {
      log.debug("Caught in DeviceAttestation.verifyJwkProof(): " +
                ((e && e.message) || e));
      header = null;
    }
    if (!header || typeof header !== 'object' || token.split('.').length !==
        3) {
      log.debug("Leaving DeviceAttestation.verifyJwkProof(). Not a JWS.");
      return this.refuse('STS-DEVICE-0017', 'The key proof is not a compact ' +
                         'JWS.');
    }
    if (header.typ !== PROOF_TYP) {
      log.debug("Leaving DeviceAttestation.verifyJwkProof(). typ.");
      return this.refuse('STS-DEVICE-0017', 'A device key proof carries ' +
                         '"typ": "' + PROOF_TYP + '", and this one ' +
                         (header.typ ? 'says "' + String(header.typ)
                           .slice(0, 60) + '"' : 'has none') + '.');
    }
    const jwk = header.jwk;
    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk) || !jwk.kty ||
        jwk.kty === 'oct') {
      log.debug("Leaving DeviceAttestation.verifyJwkProof(). No key.");
      return this.refuse('STS-DEVICE-0017', 'A device key proof carries the ' +
                         'public key it proves in its header\'s "jwk".');
    }
    let verified: Json = null;
    try {
      verified = await stsCrypto.verifyCompactJwsAsync(token, jwk,
        { algorithms: stsCrypto.JWS_ASYMMETRIC_ALGS });
    } catch (e) {
      log.debug("Caught in DeviceAttestation.verifyJwkProof(): " +
                ((e && e.message) || e));
      log.debug("Leaving DeviceAttestation.verifyJwkProof(). Signature.");
      return this.refuse('STS-DEVICE-0017', 'The key proof does not verify ' +
                         'under the key in its own header: ' +
                         String((e && e.message) || e));
    }
    const claims = (verified && verified.claims) || {};
    const nowS = Math.floor(this.deps.now() / 1000);
    const window = Number(config.value('devices.challengeTtlSeconds'));
    const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    let why = '';
    if (!spec.nonce || claims.nonce !== spec.nonce) {
      why = 'its "nonce" is not the challenge this page issued';
    } else if (spec.audience && auds.indexOf(spec.audience) < 0) {
      why = 'its "aud" is not ' + spec.audience;
    } else if (typeof claims.iat !== 'number' || claims.iat > nowS + 60 ||
               claims.iat < nowS - window) {
      why = 'its "iat" is not a time within the challenge\'s lifetime';
    }
    if (why) {
      log.debug("Leaving DeviceAttestation.verifyJwkProof(). " + why);
      return this.refuse('STS-DEVICE-0017', 'The key proof verifies, and ' +
                         why + '.');
    }
    const pub: Json = {};
    Object.keys(jwk).forEach(function (m: string) {
      pub[m] = jwk[m];
    });
    if (header.x5c !== undefined) {
      const android = await this.android(header.x5c, pub, spec.nonce);
      if (!android.ok) {
        log.debug("Leaving DeviceAttestation.verifyJwkProof(). Android.");
        return android;
      }
      log.debug("Leaving DeviceAttestation.verifyJwkProof(). Android " +
                android.attestation.level + ".");
      return { ok: true, jwk: pub, alg: String(verified.header.alg),
               attestation: android.attestation };
    }
    log.debug("Leaving DeviceAttestation.verifyJwkProof(). Unattested.");
    return { ok: true, jwk: pub, alg: String(verified.header.alg),
             attestation: this.record('self-asserted', 'none',
               'A ' + String(verified.header.alg) + ' key proven by a ' +
               'signature over the enrolment challenge; no attestation ' +
               'statement said where it lives.') };
  }

  // =========================================================================
  // ANDROID KEY ATTESTATION: the header's `x5c` (base64 DER, leaf first).
  // =========================================================================
  async android(x5c: unknown, jwk: Json, nonce: string): Promise<Json> {
    const { log, pki, stsCrypto, config } = this.deps;
    log.debug("Entering DeviceAttestation.android().");
    const ders: Buffer[] = Array.isArray(x5c) && x5c.length &&
      x5c.every(function (one: unknown): boolean {
        return typeof one === 'string' && /^[A-Za-z0-9+/=]+$/.test(one);
      }) ? x5c.map(function (one: string): Buffer {
        return Buffer.from(one, 'base64');
      }) : [];
    if (!ders.length) {
      log.debug("Leaving DeviceAttestation.android(). No chain.");
      return this.refuse('STS-DEVICE-0018', 'An Android Key Attestation\'s ' +
                         '"x5c" is a list of base64 DER certificates, leaf ' +
                         'first.');
    }
    const facts = pki.attestationCertificateFacts(ders[0]);
    if (!facts || !facts.publicKeyJwk ||
        this.thumbprintOf(facts.publicKeyJwk) !== this.thumbprintOf(jwk)) {
      log.debug("Leaving DeviceAttestation.android(). Different key.");
      return this.refuse('STS-DEVICE-0018', 'The attestation certificate ' +
                         'does not certify the key that signed the proof.');
    }
    const ext = facts.extensions[OID_ANDROID_KEY];
    let description: Json = null;
    try {
      description = ext ? stsCrypto.androidKeyDescription(ext.value) : null;
    } catch (e) {
      log.debug("Caught in DeviceAttestation.android(): " +
                ((e && e.message) || e));
      description = null;
    }
    if (!description) {
      log.debug("Leaving DeviceAttestation.android(). No extension.");
      return this.refuse('STS-DEVICE-0018', 'The attestation certificate ' +
                         'carries no readable key attestation extension (' +
                         OID_ANDROID_KEY + ').');
    }
    if (!description.attestationChallenge.equals(
          Buffer.from(String(nonce), 'utf8'))) {
      log.debug("Leaving DeviceAttestation.android(). Challenge.");
      return this.refuse('STS-DEVICE-0018', 'The key attestation\'s ' +
                         'attestationChallenge is not the enrolment ' +
                         'challenge.');
    }
    const level = SECURITY_LEVELS[description.attestationSecurityLevel] ||
                  'unknown';
    const least = String(config.value('devices.androidMinimumSecurityLevel'));
    if (SECURITY_LEVELS.indexOf(level) < 1 ||
        SECURITY_LEVELS.indexOf(level) < SECURITY_LEVELS.indexOf(least)) {
      log.debug("Leaving DeviceAttestation.android(). Level " + level);
      return this.refuse('STS-DEVICE-0018', 'The key is attested at ' +
                         'security level "' + level + '", and this realm ' +
                         'registers ' + least + ' or better ' +
                         '(devices.androidMinimumSecurityLevel). A software ' +
                         'key is never attested.');
    }
    const chain = await this.chainOf(ders[0], ders.slice(1),
      pki.deviceAttestationAnchors('androidKeyAttestation',
        config.value('devices.androidAttestationTrustAnchors')));
    const said = 'Android Key Attestation, version ' +
      description.attestationVersion + ', security level ' + level;
    log.debug("Leaving DeviceAttestation.android(). " +
              (chain.ok ? 'Anchored.' : 'Unanchored.'));
    return { ok: true, attestation: chain.ok
      ? this.record('attested', 'android-key-attestation', said +
                    ', chained to ' + chain.anchor + '.')
      : this.record('self-asserted', 'android-key-attestation', said +
                    ', which verified and does NOT chain to a trusted ' +
                    'root: ' + chain.why + '.') };
  }

  // =========================================================================
  // APPLE APP ATTEST. `spec` is { keyId (base64 or base64url), attestation
  // (base64 or base64url CBOR), nonce (the challenge string) }. Resolves
  // { ok, jwk, alg, appId, environment, attestation } or a refusal.
  // =========================================================================
  async appAttest(spec: Json): Promise<Json> {
    const { log, pki, stsCrypto, config, webauthnCodec } = this.deps;
    log.debug("Entering DeviceAttestation.appAttest().");
    const s = spec || {};
    const falsified = (why: string): Json => {
      log.debug("Entering falsified().");
      log.debug("Leaving falsified().");
      return this.refuse('STS-DEVICE-0019', 'The App Attest statement does ' +
                         'not verify: ' + why + '.');
    };
    const listed = config.value('devices.appleAppAttestAppIds');
    const appIds = (Array.isArray(listed) ? listed
                                          : String(listed || '').split(','))
      .map(function (one: unknown): string {
        return String(one).trim();
      }).filter(Boolean);
    if (!appIds.length) {
      log.debug("Leaving DeviceAttestation.appAttest(). No app configured.");
      return this.refuse('STS-DEVICE-0019', 'This realm accepts no App ' +
                         'Attest statement: devices.appleAppAttestAppIds ' +
                         'names no app.');
    }
    const keyId = Buffer.from(String(s.keyId || ''), 'base64');
    let object: Json = null;
    try {
      object = webauthnCodec.cborDecodeFirst(
        Buffer.from(String(s.attestation || ''), 'base64'), 0)[0];
    } catch (e) {
      log.debug("Caught in DeviceAttestation.appAttest(): " +
                ((e && e.message) || e));
      object = null;
    }
    const stmt = object instanceof Map ? object.get('attStmt') : null;
    const x5c = stmt instanceof Map ? stmt.get('x5c') : null;
    const authDataRaw = object instanceof Map ? object.get('authData') : null;
    if (!(object instanceof Map) || object.get('fmt') !== 'apple-appattest' ||
        !Array.isArray(x5c) || x5c.length < 2 ||
        !Buffer.isBuffer(authDataRaw) || keyId.length !== 32) {
      log.debug("Leaving DeviceAttestation.appAttest(). Shape.");
      return falsified('it is not an apple-appattest attestation object with ' +
                  'x5c, authData and a 32-byte key id');
    }
    // Step 1: the chain.
    const chain = await this.chainOf(x5c[0], x5c.slice(1),
      pki.deviceAttestationAnchors('appleAppAttest',
        config.value('devices.appleAppAttestTrustAnchors')));
    if (!chain.ok) {
      log.debug("Leaving DeviceAttestation.appAttest(). Chain.");
      return falsified('the certificate chain does not end at the Apple App ' +
                  'Attestation root (' + chain.why + ')');
    }
    let authData: Json = null;
    try {
      authData = webauthnCodec.parseAuthenticatorData(authDataRaw);
    } catch (e) {
      log.debug("Caught in DeviceAttestation.appAttest(): " +
                ((e && e.message) || e));
      authData = null;
    }
    if (!authData || !authData.credentialPublicKey) {
      log.debug("Leaving DeviceAttestation.appAttest(). authData.");
      return falsified('the authenticator data carries no attested credential');
    }
    // Steps 2-4: the nonce in the credential certificate.
    const clientDataHash = nodeCrypto.createHash('sha256')
      .update(String(s.nonce || ''), 'utf8').digest();
    const nonce = nodeCrypto.createHash('sha256')
      .update(Buffer.concat([authDataRaw, clientDataHash])).digest();
    const facts = pki.attestationCertificateFacts(x5c[0]);
    const ext = facts ? facts.extensions[OID_APPLE_NONCE] : null;
    const certified = ext ? stsCrypto.appleAttestationNonce(ext.value) : null;
    if (!certified || !certified.equals(nonce)) {
      log.debug("Leaving DeviceAttestation.appAttest(). Nonce.");
      return falsified('the credential certificate\'s nonce is not SHA-256(' +
                  'authData ‖ SHA-256(challenge))');
    }
    // Step 5: the key id is the SHA-256 of the uncompressed point.
    const certJwk = facts.publicKeyJwk || {};
    const point = certJwk.kty === 'EC' && certJwk.crv === 'P-256'
      ? Buffer.concat([Buffer.from([4]), Buffer.from(certJwk.x, 'base64url'),
                       Buffer.from(certJwk.y, 'base64url')]) : null;
    if (!point || !nodeCrypto.createHash('sha256').update(point).digest()
          .equals(keyId)) {
      log.debug("Leaving DeviceAttestation.appAttest(). Key id.");
      return falsified('the key id is not the SHA-256 of the certified ' +
                       'P-256 key');
    }
    // Step 6: the app.
    const appId = appIds.filter(function (one: string): boolean {
      return nodeCrypto.createHash('sha256').update(one, 'utf8').digest()
        .equals(authData.rpIdHash);
    })[0];
    if (!appId) {
      log.debug("Leaving DeviceAttestation.appAttest(). App.");
      return falsified('the RP ID hash is not the SHA-256 of an app in ' +
                  'devices.appleAppAttestAppIds');
    }
    // Steps 7-9: the counter, the environment and the credential id.
    const aaguid = Buffer.from(authData.aaguid || []);
    const development = aaguid.equals(APP_ATTEST_DEVELOPMENT);
    let why = '';
    if (authData.signCount !== 0) {
      why = 'the counter is ' + authData.signCount + ', not 0';
    } else if (!aaguid.equals(APP_ATTEST_PRODUCTION) && !(development &&
               config.value('devices.appleAppAttestAllowDevelopment') ===
               true)) {
      why = 'the AAGUID is not App Attest\'s production environment' +
            (development ? ' (a development key, and ' +
              'devices.appleAppAttestAllowDevelopment is off)' : '');
    } else if (!Buffer.from(authData.credentialId || []).equals(keyId)) {
      why = 'the credential id is not the key id';
    }
    let jwk: Json = null;
    try {
      // `{ jwk, alg, coseAlg }`, the verifier's shape.
      jwk = webauthnCodec.coseKeyToJwk(authData.credentialPublicKey).jwk;
    } catch (e) {
      log.debug("Caught in DeviceAttestation.appAttest(): " +
                ((e && e.message) || e));
      jwk = null;
    }
    if (!why && (!jwk || this.thumbprintOf(jwk) !==
                 this.thumbprintOf(certJwk))) {
      why = 'the attested credential key is not the certified key';
    }
    if (why) {
      log.debug("Leaving DeviceAttestation.appAttest(). " + why);
      return falsified(why);
    }
    const pub = { kty: 'EC', crv: 'P-256', x: certJwk.x, y: certJwk.y };
    log.debug("Leaving DeviceAttestation.appAttest(). Attested.");
    return { ok: true, jwk: pub, alg: 'ES256', appId: appId,
             environment: development ? 'development' : 'production',
             attestation: this.record('attested', 'apple-app-attest',
               'Apple App Attest (' + (development ? 'development'
                 : 'production') + ') for ' + appId + ', a P-256 key in ' +
               'the Secure Enclave, chained to ' + chain.anchor + '.') };
  }

  // =========================================================================
  // TPM KEY ATTESTATION IN A CERTIFICATE REQUEST. `spec` is { bundle (the
  // id-aa-attestation value's DER, or null for none), publicKeyPem }.
  // Resolves { ok, attestation } — `none` and self-asserted when there is
  // no bundle or no statement this service verifies — or a refusal.
  // =========================================================================
  async csrAttestation(spec: Json): Promise<Json> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering DeviceAttestation.csrAttestation().");
    const s = spec || {};
    if (!s.bundle) {
      log.debug("Leaving DeviceAttestation.csrAttestation(). None.");
      return { ok: true, attestation: this.record('self-asserted', 'none',
        'A key certified over a certificate request that carried no ' +
        'attestation.') };
    }
    let bundle: Json = null;
    try {
      bundle = stsCrypto.csrAttestationBundle(s.bundle);
    } catch (e) {
      log.debug("Caught in DeviceAttestation.csrAttestation(): " +
                ((e && e.message) || e));
      log.debug("Leaving DeviceAttestation.csrAttestation(). Malformed.");
      return this.refuse('STS-DEVICE-0021', 'The request\'s attestation ' +
                         'attribute cannot be read: ' +
                         String((e && e.message) || e) + '.');
    }
    const tpm = bundle.attestations.filter(function (one: Json): boolean {
      return one.type === stsCrypto.TCG_ATTEST_TPM_CERTIFY;
    })[0];
    if (!tpm) {
      log.debug("Leaving DeviceAttestation.csrAttestation(). No TPM.");
      return { ok: true, attestation: this.record('self-asserted', 'none',
        'The request carried attestation statement(s) of type ' +
        bundle.attestations.map(function (one: Json): string {
          return one.type;
        }).join(', ') + ', none of which this service verifies (it ' +
        'verifies ' + stsCrypto.TCG_ATTEST_TPM_CERTIFY + ', ' +
        'tcg-attest-tpm-certify).') };
    }
    const out = await this.tpmCertify(tpm.stmt, bundle.certs, s.publicKeyPem);
    log.debug("Leaving DeviceAttestation.csrAttestation(). ok=" + out.ok);
    return out;
  }

  // tcg-attest-tpm-certify: TPM2_Certify's output over the request's key.
  private async tpmCertify(stmtDer: Buffer, certs: Buffer[],
                           publicKeyPem: string): Promise<Json> {
    const { log, stsCrypto, pki, config } = this.deps;
    log.debug("Entering DeviceAttestation.tpmCertify().");
    const falsified = (why: string): Json => {
      log.debug("Entering falsified().");
      log.debug("Leaving falsified().");
      return this.refuse('STS-DEVICE-0020', 'The TPM key attestation does ' +
                         'not verify: ' + why + '.');
    };
    let stmt: Json = null;
    let attest: Json = null;
    let pub: Json = null;
    try {
      stmt = stsCrypto.tcgTpmCertifyStatement(stmtDer);
      attest = stsCrypto.tpmParseAttest(stmt.tpmSAttest);
      pub = stmt.tpmTPublic ? stsCrypto.tpmParsePublic(stmt.tpmTPublic)
                            : null;
    } catch (e) {
      log.debug("Caught in DeviceAttestation.tpmCertify(): " +
                ((e && e.message) || e));
      log.debug("Leaving DeviceAttestation.tpmCertify(). Unreadable.");
      return falsified(String((e && e.message) || e));
    }
    if (!pub) {
      log.debug("Leaving DeviceAttestation.tpmCertify(). No public area.");
      return falsified('it carries no tpmTPublic, so the certified Name ' +
                       'cannot ' +
                  'be tied to the request\'s key');
    }
    let requestJwk: Json = null;
    try {
      requestJwk = nodeCrypto.createPublicKey(String(publicKeyPem || ''))
        .export({ format: 'jwk' });
    } catch (e) {
      log.debug("Caught in DeviceAttestation.tpmCertify(): " +
                ((e && e.message) || e));
      requestJwk = null;
    }
    let name: Buffer | null = null;
    try {
      name = stsCrypto.tpmName(pub);
    } catch (e) {
      log.debug("Caught in DeviceAttestation.tpmCertify(): " +
                ((e && e.message) || e));
      name = null;
    }
    const required = TPMA_FIXED_TPM | TPMA_FIXED_PARENT |
                     TPMA_SENSITIVE_DATA_ORIGIN;
    let why = '';
    if (attest.magic !== stsCrypto.TPM_GENERATED_VALUE) {
      why = 'tpmSAttest\'s magic is not TPM_GENERATED_VALUE';
    } else if (attest.type !== stsCrypto.TPM_ST_ATTEST_CERTIFY) {
      why = 'tpmSAttest is not a TPM_ST_ATTEST_CERTIFY';
    } else if (!name || !attest.name || !name.equals(attest.name)) {
      why = 'the certified Name is not nameAlg ‖ H(tpmTPublic)';
    } else if (!requestJwk || this.thumbprintOf(pub.jwk) !==
               this.thumbprintOf(requestJwk)) {
      why = 'the certified key is not the key in the certificate request';
    } else if ((pub.attributes & required) !== required) {
      why = 'the key\'s objectAttributes do not say fixedTPM, fixedParent ' +
            'and sensitiveDataOrigin, so it was not generated in the TPM ' +
            'or can leave it';
    }
    if (why) {
      log.debug("Leaving DeviceAttestation.tpmCertify(). " + why);
      return falsified(why);
    }
    // The Attestation Key: the bundle's certificate with tcg-kp-AIKCertificate
    // whose key verifies the signature.
    const signature = stsCrypto.tpmParseSignature(stmt.signature);
    if (!signature) {
      log.debug("Leaving DeviceAttestation.tpmCertify(). Signature shape.");
      return falsified('the signature is not one TPMT_SIGNATURE');
    }
    const scheme = {
      family: signature.sigAlg === stsCrypto.TPM_ALG.RSASSA ? 'rsa-pkcs1'
        : signature.sigAlg === stsCrypto.TPM_ALG.RSAPSS ? 'rsa-pss' : 'ecdsa',
      hash: '', encoding: 'der', saltLength: 'auto'
    };
    try {
      scheme.hash = stsCrypto.tpmHashName(signature.hash);
    } catch (e) {
      log.debug("Caught in DeviceAttestation.tpmCertify(): " +
                ((e && e.message) || e));
      return falsified('the signature\'s hash algorithm is not one this ' +
                       'service ' +
                  'verifies');
    }
    let ak: Buffer | null = null;
    for (const der of certs) {
      const facts = pki.attestationCertificateFacts(der);
      if (!facts || facts.eku.indexOf(OID_TCG_AIK) < 0) {
        continue;
      }
      if (await stsCrypto.verifyRawSignature(scheme,
            nodeCrypto.createPublicKey(facts.pem), stmt.tpmSAttest,
            signature.signature)) {
        ak = der;
        break;
      }
    }
    if (!ak) {
      log.debug("Leaving DeviceAttestation.tpmCertify(). No AK.");
      return falsified('no certificate in the bundle with ' +
                       'tcg-kp-AIKCertificate (' +
                  OID_TCG_AIK + ') verifies the TPMS_ATTEST signature');
    }
    const chain = await this.chainOf(ak, certs.filter(function (one) {
      return one !== ak;
    }), pki.deviceAttestationAnchors('tpm',
                                     config.value('devices.tpmTrustAnchors')));
    const said = 'TPM 2.0 key attestation (TPM2_Certify, ' + scheme.family +
      '/' + scheme.hash + '), extraData ' +
      (attest.extraData.length ? attest.extraData.toString('hex')
        .slice(0, 64) : 'empty') + ', firmware ' +
      String(attest.firmwareVersion);
    log.debug("Leaving DeviceAttestation.tpmCertify(). " +
              (chain.ok ? 'Anchored.' : 'Unanchored.'));
    return { ok: true, attestation: chain.ok
      ? this.record('attested', 'tcg-tpm2-key', said + ', its AK chained ' +
                    'to ' + chain.anchor + '.')
      : this.record('self-asserted', 'tcg-tpm2-key', said + ', which ' +
                    'verified and whose AK does NOT chain to a trusted ' +
                    'root: ' + chain.why + '.') };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DeviceAttestation>(
  'common/device_attestation',
  () => new DeviceAttestation(DeviceAttestation.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  DeviceAttestation: DeviceAttestation,
  installInstance: (instance: DeviceAttestation): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PROOF_TYP: PROOF_TYP,
  SECURITY_LEVELS: SECURITY_LEVELS,
  verifyJwkProof: slot.forward('verifyJwkProof'),
  android: slot.forward('android'),
  appAttest: slot.forward('appAttest'),
  csrAttestation: slot.forward('csrAttestation')
};
