// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: common/crypto_impl/pkcs11.js
//
// ---------------------------------------------------------------------------
// THE PKCS#11 ENGINE (#1955 P8, 2026-11-20): a token in a hardware security
// module — a YubiHSM 2 through `yubihsm_pkcs11.so` and `yubihsm-connector`,
// SoftHSM2, or any PKCS#11 v2.40 module — reached through a native binding,
// with the operations this service asks of it and nothing else:
//
//   * a key-encryption key that WRAPS AND UNWRAPS DATA KEYS INSIDE THE HSM
//     (`wrapData()` / `unwrapData()`), for `keys.kekProvider=pkcs11`
//     (`common/secrets.js`), and
//   * a realm's classical SIGNING KEYS held in the HSM (`generateKeyPair()`,
//     `publicKeyOf()`, `sign()` / `signSync()`), for
//     `keys.signingKeyStore=pkcs11` (`common/helpers.js`, `common/crypto.js`).
//     `sign()` uses `C_SignAsync`, and `decryptOaep()` / `deriveEcdh()`
//     asked asynchronously `C_DecryptAsync` / `C_DeriveKeyAsync`. A blocking
//     call — `signSync()`, a synchronous decryption or agreement, or a
//     module with no asynchronous call — is made only while
//     `keys.pkcs11SynchronousSign` is on; otherwise it refuses
//     (STS-KEYS-0209). Every door in `crypto.js` has the asynchronous road
//     (the P8 follow-up, 2026-11-23).
//
// IT IS AN ENGINE, AND `common/crypto.js` IS THE DOOR. Nothing outside
// `crypto.js` requires this file; `crypto.js` hands out a `Pkcs11Token` and
// the signing choke points ask it. The binding itself (`pkcs11js`, or a test's
// fake) is passed IN by the caller that loaded it — this file requires no
// binding, so a deployment without one loads it and never calls it, and the
// rule that a missing optional package is reported as the package to install
// stays `secrets.js`'s (`missingModule()`).
//
// THE THREE WRAPPING MECHANISMS, IN THE ORDER `auto` PREFERS THEM, and the
// stored text each produces. The text is VERSIONED by its first letters so the
// choice can change later without a migration: `unwrapData()` reads the tag,
// never the configured mechanism, so a token whose preferred mechanism changes
// still opens everything wrapped before.
//
//   g1.<iv>.<ct>  CKM_AES_GCM through C_Encrypt, a 96-bit random IV and a
//                 128-bit tag, the data key's AAD as GCM's additional data.
//                 SoftHSM2, Thales, Entrust, AWS CloudHSM and most network
//                 HSMs offer it. Preferred: the HSM binds the AAD itself.
//   k1.<wrapped>  CKM_AES_KEY_WRAP_PAD (RFC 5649) through C_WrapKey, which is
//                 what most modules (SoftHSM2 among them) offer KWP for — NOT
//                 C_Encrypt. The data key goes in as a short-lived SESSION
//                 object (CKA_TOKEN false) holding the key followed by
//                 SHA-256 of its AAD, which is wrapped and destroyed; the
//                 unwrap reverses it and refuses a digest that is not the
//                 row's. KWP is authenticated, so that is a binding.
//   y1.<blob>     CKM_YUBICO_AES_CCM_WRAP through C_Encrypt: the YubiHSM 2's
//                 own "Wrap Data" (AES-CCM under a wrap-key object), because
//                 the YubiHSM's PKCS#11 module offers neither GCM nor KWP
//                 (yubihsm-shell's util_pkcs11.c, checked 2026-11-20). The
//                 plaintext is the key and the SHA-256 of its AAD, as for KWP.
//
// SESSIONS. A PKCS#11 session runs one operation at a time — C_SignInit and
// the C_Sign that follows it must not interleave with another caller's — so a
// token holds a small POOL of sessions (`maxSessions`), each lent to one
// operation and handed back. An asynchronous operation (the binding's
// `C_SignAsync`, `C_EncryptAsync`, `C_DecryptAsync`, which compute off the
// event loop) holds its session until it settles; its session is opened and
// logged in, its key found and its operation begun off the event loop too,
// by the module's CONTROL THREAD (below, `Pkcs11Control`). A synchronous one
// borrows an idle session or the one blocking session the token keeps for
// it, never one past that. EVERY THREAD HOLDS ITS OWN: a request worker
// is a `worker_threads` Worker, the binding is loaded per thread, and so is
// this module and its sessions. C_Initialize is process-wide in a PKCS#11
// module, so a second thread's answer CKR_CRYPTOKI_ALREADY_INITIALIZED is
// expected and accepted, as is CKR_USER_ALREADY_LOGGED_IN (a login is per
// application, not per session). CKF_OS_LOCKING_OK tells the module several
// threads call it.
//
// RECONNECTING, WITHOUT A TIMER. A connector restart (yubihsm-connector) or a
// device that went away invalidates every session, and the module answers
// CKR_SESSION_HANDLE_INVALID, CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED and the
// like. An operation that meets one of those discards its session, opens a
// fresh one (logging in again) and runs ONCE more; where even that fails with
// CKR_CRYPTOKI_NOT_INITIALIZED or a device error the module is finalized and
// initialized again first — ONCE for every token on the module, after the
// operations holding its sessions drain, with every session from before
// forgotten rather than closed or lent (`reinitializeEntry()`), and ONCE for
// every thread of the process that met the outage at the same moment: a
// lock and a generation in shared memory make it single-flight, and the
// threads that waited take in the one that reconnected. Nothing
// polls: the next operation after an outage is what reconnects, and an
// operation that still fails is refused with STS-KEYS-0201 — a refusal,
// never a crash.
//
// POST-QUANTUM SIGNING COMES HERE ONLY WHEN THE MODULE OFFERS IT. PKCS#11
// 3.2 (OASIS, 3 June 2026) defines CKM_ML_DSA — pure ML-DSA, FIPS 204, no
// pre-hash — and CKM_ML_DSA_KEY_PAIR_GEN. A token that does not list
// CKM_ML_DSA with CKF_SIGN is refused (STS-KEYS-0206) and the signature
// stays in software. The pre-hash numbers some drafts used (0x23–0x26) are
// not these.
//
// AND SLH-DSA, AND THE REALM'S PUBLISHED SET (#2220). PKCS#11 3.2 also
// defines CKM_SLH_DSA — pure SLH-DSA, FIPS 205, no pre-hash — with
// CKM_SLH_DSA_KEY_PAIR_GEN and CKK_SLH_DSA, the parameter set again being
// CKA_PARAMETER_SET on the key (CKP_SLH_DSA_SHA2_128S, _SHAKE_128S, ...).
// Both SLH-DSA sets this service publishes (SLH-DSA-SHA2-128s and
// SLH-DSA-SHAKE-128s) are made here when the token lists the generation
// mechanism and CKM_SLH_DSA with CKF_SIGN, and refused (STS-KEYS-0206 at
// a signature, STS-KEYS-0207 at a generation) otherwise. The realm's
// published post-quantum set (`helpers.js`'s `pqKeysFor`) asks this file
// for each of its three ML-DSA and two SLH-DSA keys and makes in software
// only the ones the token does not offer, and the composites, which no
// PKCS#11 mechanism covers; `hsmKeyReport()` says which went where.
//
// THE NUMBERS ARE pkcs11t.h's OF PKCS#11 3.2, written out: pkcs11js 2.1.7
// carries the 3.0 headers and exposes none of them (checked 2026-11-25).
// ---------------------------------------------------------------------------

'use strict';

const nodeCrypto = require('crypto');
const bunyan = require('bunyan');
const errorCodes = require('../error_codes');

// A node consumer (a test loads this file directly) may have no CONFIG_FILE,
// so the level falls back to info rather than failing to load.
let logLevelProblem = null;
const log = bunyan.createLogger({
  name: 'pkcs11',
  level: (function () {
    try {
      return require(String(process.env.CONFIG_FILE)).logLevel || 'info';
    } catch (e) {
      // No logger exists yet; reported on the line after it does.
      logLevelProblem = (e && e.message) || String(e);
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('Caught in pkcs11 log level: ' + logLevelProblem);
}

// ---------------------------------------------------------------------------
// THE PKCS#11 v2.40 NUMBERS THIS FILE USES, written out rather than read from
// the binding: a fake module (the tests') need not carry them, and they are
// the specification's, not the binding's. The binding's own parameter-type
// tags (`CK_PARAMS_*`) ARE the binding's, and are read from it.
// ---------------------------------------------------------------------------
const CK = Object.freeze({
  CKF_RW_SESSION: 0x2, CKF_SERIAL_SESSION: 0x4, CKF_OS_LOCKING_OK: 0x2,
  CKU_USER: 1,
  CKO_PUBLIC_KEY: 2, CKO_PRIVATE_KEY: 3, CKO_SECRET_KEY: 4,
  CKK_RSA: 0x0, CKK_EC: 0x3, CKK_GENERIC_SECRET: 0x10, CKK_AES: 0x1f,
  CKK_EC_EDWARDS: 0x40, CKK_ML_DSA: 0x4a, CKK_SLH_DSA: 0x4b,
  CKA_CLASS: 0x0, CKA_TOKEN: 0x1, CKA_PRIVATE: 0x2, CKA_LABEL: 0x3,
  CKA_VALUE: 0x11, CKA_KEY_TYPE: 0x100, CKA_ID: 0x102, CKA_SENSITIVE: 0x103,
  CKA_ENCRYPT: 0x104, CKA_DECRYPT: 0x105, CKA_WRAP: 0x106, CKA_UNWRAP: 0x107,
  CKA_SIGN: 0x108, CKA_VERIFY: 0x10a, CKA_DERIVE: 0x10c, CKA_MODULUS: 0x120,
  CKA_MODULUS_BITS: 0x121, CKA_PUBLIC_EXPONENT: 0x122, CKA_VALUE_LEN: 0x161,
  CKA_EXTRACTABLE: 0x162, CKA_EC_PARAMS: 0x180, CKA_EC_POINT: 0x181,
  CKA_PARAMETER_SET: 0x61d, CKA_SEED: 0x637,
  CKM_RSA_PKCS_KEY_PAIR_GEN: 0x0, CKM_ML_DSA_KEY_PAIR_GEN: 0x1c,
  CKM_ML_DSA: 0x1d, CKM_SLH_DSA_KEY_PAIR_GEN: 0x2d, CKM_SLH_DSA: 0x2e,
  CKM_SHA256_RSA_PKCS: 0x40,
  CKM_SHA384_RSA_PKCS: 0x41, CKM_SHA512_RSA_PKCS: 0x42,
  CKM_SHA256_RSA_PKCS_PSS: 0x43, CKM_SHA384_RSA_PKCS_PSS: 0x44,
  CKM_SHA512_RSA_PKCS_PSS: 0x45, CKM_SHA256: 0x250, CKM_SHA384: 0x260,
  CKM_SHA512: 0x270, CKG_MGF1_SHA256: 0x2, CKG_MGF1_SHA384: 0x3,
  CKG_MGF1_SHA512: 0x4, CKM_EC_KEY_PAIR_GEN: 0x1040, CKM_ECDSA: 0x1041,
  CKM_EC_EDWARDS_KEY_PAIR_GEN: 0x1055, CKM_EDDSA: 0x1057,
  CKM_AES_KEY_GEN: 0x1080, CKM_AES_GCM: 0x1087, CKM_AES_KEY_WRAP_PAD: 0x210a,
  CKM_RSA_PKCS_OAEP: 0x9, CKM_ECDH1_DERIVE: 0x1050, CKM_SHA_1: 0x220,
  CKM_SHA224: 0x255, CKG_MGF1_SHA1: 0x1, CKG_MGF1_SHA224: 0x5,
  CKD_NULL: 0x1, CKZ_DATA_SPECIFIED: 0x1,
  CKP_ML_DSA_44: 0x1, CKP_ML_DSA_65: 0x2, CKP_ML_DSA_87: 0x3,
  CKP_SLH_DSA_SHA2_128S: 0x1, CKP_SLH_DSA_SHAKE_128S: 0x2,
  // CKM_VENDOR_DEFINED | YUBICO_BASE_VENDOR (0x59554200) | YH_WRAP_KEY (4),
  // yubihsm-shell's pkcs11y.h.
  CKM_YUBICO_AES_CCM_WRAP: 0xd9554204,
  CKF_ENCRYPT: 0x100, CKF_DECRYPT: 0x200, CKF_SIGN: 0x800,
  CKF_WRAP: 0x20000, CKF_UNWRAP: 0x40000,
  CKR_USER_ALREADY_LOGGED_IN: 0x100, CKR_CRYPTOKI_NOT_INITIALIZED: 0x190,
  CKR_CRYPTOKI_ALREADY_INITIALIZED: 0x191
});

// The answers after which a session is not worth keeping: the device, the
// connector or the session went away. Anything else (a bad mechanism, a
// refused PIN, a wrong tag) is the operation's own failure and is not retried.
const RECONNECT_ON = new Set([
  0x5,    // CKR_GENERAL_ERROR
  0x6,    // CKR_FUNCTION_FAILED
  0x30,   // CKR_DEVICE_ERROR
  0x31,   // CKR_DEVICE_MEMORY
  0x32,   // CKR_DEVICE_REMOVED
  0xb0,   // CKR_SESSION_CLOSED
  0xb3,   // CKR_SESSION_HANDLE_INVALID
  0xe0,   // CKR_TOKEN_NOT_PRESENT
  0x101,  // CKR_USER_NOT_LOGGED_IN
  0x190   // CKR_CRYPTOKI_NOT_INITIALIZED
]);
// Of those, the ones that say every session of this token went with it, so
// the idle ones are dropped too; the others (a general failure) cost only the
// session that met them.
const DEVICE_LOST = new Set([0x30, 0x32, 0xb0, 0xb3, 0xe0, 0x101, 0x190]);
const REINITIALIZE_ON = new Set([0x30, 0x32, 0xe0, 0x190]);
// The answers that say the module cannot do THIS (a curve, a mechanism, a
// template it does not support) rather than that it failed: STS-KEYS-0207,
// which a caller may answer by making the key elsewhere.
const UNSUPPORTED = new Set([0x70, 0x71, 0x130, 0x140, 0xd1, 0xd0]);
// The answers that say THIS KEY may not do it — a key made without
// CKA_DECRYPT or CKA_DERIVE (every HSM signing key before #1955 P8's
// follow-up): STS-KEYS-0208, whose remedy is a new key, not a retry.
const NOT_PERMITTED = new Set([0x68, 0x63]);

// The named curves a key may be made on, as the DER of their OID (what
// CKA_EC_PARAMS holds) and their JWK spelling.
const CURVES = Object.freeze({
  'P-256': { oid: '06082a8648ce3d030107', size: 32, hash: 'sha256' },
  'P-384': { oid: '06052b81040022', size: 48, hash: 'sha384' },
  'P-521': { oid: '06052b81040023', size: 66, hash: 'sha512' },
  'secp256k1': { oid: '06052b8104000a', size: 32, hash: 'sha256' },
  'Ed25519': { oid: '06032b6570', size: 32, edwards: true },
  'Ed448': { oid: '06032b6571', size: 57, edwards: true }
});

// ---------------------------------------------------------------------------
// THE JWS ALGORITHMS A KEY IN THE HSM SIGNS, AND HOW. ECDSA is CKM_ECDSA over
// a digest made here — the raw mechanism is what every module offers, the
// hashing ones (CKM_ECDSA_SHA256) are not — and its answer is r || s, which is
// already JOSE's encoding. EdDSA is CKM_EDDSA over the whole message.
// ML-DSA is CKM_ML_DSA over the whole message (PKCS#11 3.2; the parameter
// set is CKA_PARAMETER_SET on the key, not a mechanism parameter). The
// signature is the raw FIPS 204 encoding, which is already JOSE's.
// ---------------------------------------------------------------------------
const ML_DSA = Object.freeze({
  'ML-DSA-44': { set: CK.CKP_ML_DSA_44, publicBytes: 1312 },
  'ML-DSA-65': { set: CK.CKP_ML_DSA_65, publicBytes: 1952 },
  'ML-DSA-87': { set: CK.CKP_ML_DSA_87, publicBytes: 2592 }
});
// SLH-DSA is CKM_SLH_DSA over the whole message, the parameter set on the
// key in the same way (#2220). Its public key is the raw FIPS 205 encoding
// (PK.seed || PK.root), 32 octets for both 128s sets.
const SLH_DSA = Object.freeze({
  'SLH-DSA-SHA2-128s': { set: CK.CKP_SLH_DSA_SHA2_128S, publicBytes: 32 },
  'SLH-DSA-SHAKE-128s': { set: CK.CKP_SLH_DSA_SHAKE_128S, publicBytes: 32 }
});

/**
 * The row of a post-quantum JWS algorithm this file can make and sign in a
 * token, with its two mechanisms, or null.
 *
 * @param alg - the JWS algorithm
 * @returns `{ set, publicBytes, gen, sign, family }`, or null
 */
function pqRowOf(alg) {
  log.debug('Entering pqRowOf(). ' + alg);
  const ml = ML_DSA[alg];
  const slh = SLH_DSA[alg];
  const out = ml ? Object.assign({ gen: CK.CKM_ML_DSA_KEY_PAIR_GEN,
                                   sign: CK.CKM_ML_DSA,
                                   family: 'ML-DSA' }, ml)
    : slh ? Object.assign({ gen: CK.CKM_SLH_DSA_KEY_PAIR_GEN,
                            sign: CK.CKM_SLH_DSA, family: 'SLH-DSA' }, slh)
      : null;
  log.debug('Leaving pqRowOf().');
  return out;
}

// ML-DSA-87's signature is 4627 octets, SLH-DSA-128s's 7856. 1024 was the
// classical room.
const SIGN_ROOM = 16384;
const SIGNING = Object.freeze({
  RS256: { kty: 'RSA', mech: CK.CKM_SHA256_RSA_PKCS },
  RS384: { kty: 'RSA', mech: CK.CKM_SHA384_RSA_PKCS },
  RS512: { kty: 'RSA', mech: CK.CKM_SHA512_RSA_PKCS },
  PS256: { kty: 'RSA', mech: CK.CKM_SHA256_RSA_PKCS_PSS,
           pss: [CK.CKM_SHA256, CK.CKG_MGF1_SHA256, 32] },
  PS384: { kty: 'RSA', mech: CK.CKM_SHA384_RSA_PKCS_PSS,
           pss: [CK.CKM_SHA384, CK.CKG_MGF1_SHA384, 48] },
  PS512: { kty: 'RSA', mech: CK.CKM_SHA512_RSA_PKCS_PSS,
           pss: [CK.CKM_SHA512, CK.CKG_MGF1_SHA512, 64] },
  ES256: { kty: 'EC', mech: CK.CKM_ECDSA, hash: 'sha256', crv: 'P-256' },
  ES384: { kty: 'EC', mech: CK.CKM_ECDSA, hash: 'sha384', crv: 'P-384' },
  ES512: { kty: 'EC', mech: CK.CKM_ECDSA, hash: 'sha512', crv: 'P-521' },
  ES256K: { kty: 'EC', mech: CK.CKM_ECDSA, hash: 'sha256',
            crv: 'secp256k1' },
  EdDSA: { kty: 'OKP', mech: CK.CKM_EDDSA },
  'ML-DSA-44': { kty: 'AKP', mech: CK.CKM_ML_DSA,
                 parameterSet: CK.CKP_ML_DSA_44 },
  'ML-DSA-65': { kty: 'AKP', mech: CK.CKM_ML_DSA,
                 parameterSet: CK.CKP_ML_DSA_65 },
  'ML-DSA-87': { kty: 'AKP', mech: CK.CKM_ML_DSA,
                 parameterSet: CK.CKP_ML_DSA_87 },
  'SLH-DSA-SHA2-128s': { kty: 'AKP', mech: CK.CKM_SLH_DSA,
                         parameterSet: CK.CKP_SLH_DSA_SHA2_128S },
  'SLH-DSA-SHAKE-128s': { kty: 'AKP', mech: CK.CKM_SLH_DSA,
                          parameterSet: CK.CKP_SLH_DSA_SHAKE_128S }
});

// OAEP's digest and MGF1 by the digest's name.
const OAEP = Object.freeze({
  sha1: [CK.CKM_SHA_1, CK.CKG_MGF1_SHA1],
  sha224: [CK.CKM_SHA224, CK.CKG_MGF1_SHA224],
  sha256: [CK.CKM_SHA256, CK.CKG_MGF1_SHA256],
  sha384: [CK.CKM_SHA384, CK.CKG_MGF1_SHA384],
  sha512: [CK.CKM_SHA512, CK.CKG_MGF1_SHA512]
});

// The PKCS#11 return value an error carries (pkcs11js's `Pkcs11Error.code`),
// or 0 when it is not one.
function ckrOf(err) {
  log.debug('Entering ckrOf().');
  const code = err && typeof err.code === 'number' ? err.code : 0;
  log.debug('Leaving ckrOf().');
  return code;
}

// The code an operation's own failure is refused with.
function codeFor(err) {
  log.debug('Entering codeFor().');
  const ckr = ckrOf(err);
  log.debug('Leaving codeFor().');
  return NOT_PERMITTED.has(ckr) ? 'STS-KEYS-0208' :
         UNSUPPORTED.has(ckr) ? 'STS-KEYS-0207' : 'STS-KEYS-0201';
}

// Whether a blocking call with a realm's key in the token — C_Sign, and
// since the P8 follow-up (2026-11-23) C_Decrypt and C_DeriveKey too — is
// allowed. Off by default (keys.pkcs11SynchronousSign): every door has an
// asynchronous road (`crypto.js`'s `…OffLoop()` doors), so a blocking call
// is refused (STS-KEYS-0209) rather than made, which is what a door left on
// the synchronous road, or a module with no asynchronous call, gets. On, it
// is the opt-in to waiting on the token on the event loop. Read lazily.
// This file is required by crypto.js, which has already required config.js,
// so the require hits the cache; a load that is not ready is treated as off.
function synchronousSignAllowed() {
  log.debug('Entering synchronousSignAllowed().');
  let allowed = false;
  try {
    const config = require('../config');
    allowed = config.value('keys.pkcs11SynchronousSign') === true;
  } catch (e) {
    // The default is off. A half-loaded config refuses the blocking call
    // rather than waiting on the token.
    log.debug('Caught in synchronousSignAllowed(): ' +
              ((e && e.message) || e));
    allowed = false;
  }
  log.debug('Leaving synchronousSignAllowed().');
  return allowed;
}

// A refusal from the token, named, with its code; the module's own words
// (`CKR_…`) are kept, because they are what an operator searches for.
function refusal(code, what, err) {
  log.debug('Entering refusal(). ' + code);
  const said = err ? ': ' + ((err && err.message) || String(err)) : '';
  const out = errorCodes.mark(new Error(what + said), code);
  // The module's own answer travels with the refusal, for a caller that
  // reads it (`decryptOaep()`'s "this module does not do that digest").
  /** @type {any} */ (out).ckr = ckrOf(err) || ckrOf(err && err.cause);
  log.debug('Leaving refusal().');
  return out;
}

// A boolean attribute as the module answers it: one byte.
function attrTrue(buf) {
  log.debug('Entering attrTrue().');
  log.debug('Leaving attrTrue().');
  return !!(buf && buf.length && buf[0] !== 0);
}

// An unsigned integer attribute (CK_ULONG, host order) as the module answers
// it; 4 or 8 bytes.
function attrUlong(buf) {
  log.debug('Entering attrUlong().');
  if (!buf || !buf.length) {
    log.debug('Leaving attrUlong(). Empty.');
    return 0;
  }
  const b = Buffer.from(buf);
  const out = b.length >= 8 ? Number(b.readBigUInt64LE(0)) :
    b.length >= 4 ? b.readUInt32LE(0) : b[0];
  log.debug('Leaving attrUlong().');
  return out;
}

// CKA_EC_POINT is a DER OCTET STRING around the point; a few modules answer
// the bare point. Both are read.
function ecPointOf(buf) {
  log.debug('Entering ecPointOf().');
  const b = Buffer.from(buf || []);
  if (b.length > 2 && b[0] === 0x04) {
    if (b[1] < 0x80 && b[1] === b.length - 2) {
      log.debug('Leaving ecPointOf(). Short-form DER.');
      return b.subarray(2);
    }
    if (b[1] === 0x81 && b[2] === b.length - 3) {
      log.debug('Leaving ecPointOf(). Long-form DER.');
      return b.subarray(3);
    }
  }
  log.debug('Leaving ecPointOf(). Bare.');
  return b;
}

function b64u(buf) {
  log.debug('Entering b64u().');
  log.debug('Leaving b64u().');
  return Buffer.from(buf).toString('base64url');
}

// SHA-256 of a data key's AAD, appended to the key where the mechanism takes
// no additional data (KWP, the YubiHSM's CCM wrap).
function aadDigest(aad) {
  log.debug('Entering aadDigest().');
  log.debug('Leaving aadDigest().');
  return nodeCrypto.createHash('sha256').update(Buffer.from(String(aad),
                                                            'utf8')).digest();
}

// The key from a `key || SHA-256(aad)` plaintext, or a refusal when the
// digest is not this row's (the wrapped key was moved).
function splitBound(plain, aad) {
  log.debug('Entering splitBound().');
  const p = Buffer.from(plain);
  if (p.length <= 32) {
    throw refusal('STS-KEYS-0201', 'the HSM unwrapped something too short ' +
                  'to be a data key and its binding');
  }
  const key = p.subarray(0, p.length - 32);
  const digest = p.subarray(p.length - 32);
  if (!nodeCrypto.timingSafeEqual(digest, aadDigest(aad))) {
    throw refusal('STS-KEYS-0201', 'the wrapped data key is bound to ' +
                  'another key\'s id, scope, realm or class');
  }
  log.debug('Leaving splitBound().');
  return Buffer.from(key);
}

// ---------------------------------------------------------------------------
// THE CALLS PKCS11JS HAS NO ASYNCHRONOUS FORM FOR, MADE OFF THE EVENT LOOP
// (#1955 P8 follow-up, 2026-11-23; rcbj: "I do not want this activity to block
// the main event loop").
//
// pkcs11js 2.1.7 computes ten calls on libuv's pool — C_EncryptAsync,
// C_DecryptAsync, C_DigestAsync, C_SignAsync, C_VerifyAsync,
// C_GenerateKeyAsync, C_GenerateKeyPairAsync, C_WrapKeyAsync,
// C_UnwrapKeyAsync, C_DeriveKeyAsync (its index.d.ts) — and nothing else.
// C_OpenSession, C_Login, C_FindObjects*, C_GetAttributeValue,
// C_CreateObject, C_DestroyObject, C_CloseSession, every C_*Init, and
// C_Finalize / C_Initialize are blocking, and against a YubiHSM 2 each is a
// round trip to yubihsm-connector (C_Login derives the session keys). Three
// roads were open, and this is why it is the third:
//
//   * PREWARMING sessions and handles at start, and refreshing them off the
//     hot path, still makes the refresh on SOME event loop turn, and a
//     YubiHSM 2 has sixteen sessions for every process and thread of a
//     deployment: opening keys.pkcs11Sessions of them per thread eagerly
//     could exhaust the device at start where a lazy pool does not;
//   * the binding's asynchronous calls cover none of the above;
//   * so A THREAD OF ITS OWN makes them (`pkcs11_thread.js`), one per loaded
//     module per thread that loaded it, started at its first call and
//     unref'd while nothing waits on it. PKCS#11 sessions and object handles
//     belong to the APPLICATION (the process), not to the thread that opened
//     them, and with CKF_OS_LOCKING_OK the module serialises its own state —
//     so a session the control thread opened and logged in is the session
//     C_SignAsync then runs on here, and the C_SignInit the control thread
//     made on it is the one that C_SignAsync completes (one operation per
//     session still: the session is lent to one operation from its Init to
//     its answer, `run()`).
//
// The control thread runs the same functions this file runs in place
// (`CONTROL_OPS`), so the two cannot disagree. A binding this process did not
// load from a file — a test's fake (`tests/tools/fake-pkcs11.js`) — cannot be
// loaded in a thread, and its calls are made in place: a fake does not block.
// What stays on the event loop is the asynchronous call's own dispatch, and
// the start: `connect()` opens the first session, reads the mechanism list
// and finds the slot before the listener binds (`keystore.start()`,
// `secrets.js`). The blocking door (`runSync()`) is the opt-in
// (keys.pkcs11SynchronousSign), a key's first resolution in a thread
// (`keyPair()`, once per key) and the key-encryption key's lookup at start.
// ---------------------------------------------------------------------------

// Every Buffer a thread posts arrives as a Uint8Array; the binding takes
// Buffers, so handles, templates and answers are made Buffers again.
function revive(value) {
  log.debug('Entering revive().');
  let out = value;
  if (value instanceof Uint8Array && !Buffer.isBuffer(value)) {
    out = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  } else if (Array.isArray(value)) {
    out = value.map(revive);
  } else if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    out = {};
    for (const k of Object.keys(value)) {
      out[k] = revive(value[k]);
    }
  }
  log.debug('Leaving revive().');
  return out;
}

// What an error a thread posts carries back: the module's CKR, and the two
// facts a caller reads off it.
function errorFields(err) {
  log.debug('Entering errorFields().');
  log.debug('Leaving errorFields().');
  return { message: String((err && err.message) || err),
           code: ckrOf(err),
           notFound: err && err.notFound !== undefined ? err.notFound
                                                      : undefined,
           pinRefused: !!(err && err.pinRefused) };
}

// The error those fields describe, on this side.
function errorFrom(fields) {
  log.debug('Entering errorFrom().');
  const e = new Error(String(fields.message));
  /** @type {any} */ (e).code = Number(fields.code) || 0;
  if (fields.notFound !== undefined && fields.notFound !== null) {
    /** @type {any} */ (e).notFound = fields.notFound;
  }
  if (fields.pinRefused) {
    /** @type {any} */ (e).pinRefused = true;
  }
  log.debug('Leaving errorFrom().');
  return e;
}

// Every object a template names, on a session this call holds.
function findOn(lib, session, template) {
  log.debug('Entering findOn().');
  lib.C_FindObjectsInit(session, template);
  const out = [];
  try {
    for (;;) {
      const batch = lib.C_FindObjects(session, 16);
      if (!batch || !batch.length) {
        break;
      }
      for (const h of batch) {
        out.push(h);
      }
      if (out.length > 64) {
        break;
      }
    }
  } finally {
    lib.C_FindObjectsFinal(session);
  }
  log.debug('Leaving findOn(). ' + out.length + '.');
  return out;
}

// The handle a key names: the one held, or the one its template finds,
// which must be exactly one (`notFound` carries the count otherwise).
function keyHandleOn(lib, session, key) {
  log.debug('Entering keyHandleOn().');
  if (key.handle !== null && key.handle !== undefined) {
    log.debug('Leaving keyHandleOn(). Held.');
    return key.handle;
  }
  const found = findOn(lib, session, key.template);
  if (found.length !== 1) {
    const e = new Error('the key was found ' + found.length + ' times');
    /** @type {any} */ (e).notFound = found.length;
    throw e;
  }
  log.debug('Leaving keyHandleOn(). Found.');
  return found[0];
}

const BEGIN_KINDS = new Set(['Sign', 'Encrypt', 'Decrypt']);

// ---------------------------------------------------------------------------
// THE CALLS THE CONTROL THREAD MAKES, each `(lib, ...args)`, synchronous, and
// made in place for a binding that cannot be loaded in a thread. A keyed one
// takes `{ handle, template }` (the handle null when it must be found again)
// and answers `{ handle, value }`, so the caller keeps the handle it found.
// ---------------------------------------------------------------------------
const CONTROL_OPS = Object.freeze({
  // C_OpenSession and C_Login. A refused PIN closes the session it opened
  // and says so (`pinRefused`); CKR_USER_ALREADY_LOGGED_IN is expected (a
  // login is per application).
  open: function (lib, slot, pin) {
    log.debug('Entering CONTROL_OPS.open().');
    const session = lib.C_OpenSession(slot, CK.CKF_SERIAL_SESSION |
                                      CK.CKF_RW_SESSION);
    if (pin !== null && pin !== undefined) {
      try {
        lib.C_Login(session, CK.CKU_USER, String(pin));
      } catch (e) {
        log.debug('Caught in CONTROL_OPS.open(): ' + ((e && e.message) || e));
        if (ckrOf(e) !== CK.CKR_USER_ALREADY_LOGGED_IN) {
          try {
            lib.C_CloseSession(session);
          } catch (c) {
            // The session the refused login left is not worth more than the
            // refusal; the module closes it with the application anyway.
            log.debug('Caught in CONTROL_OPS.open(): ' +
                      ((c && c.message) || c));
          }
          /** @type {any} */ (e).pinRefused = true;
          throw e;
        }
      }
    }
    log.debug('Leaving CONTROL_OPS.open().');
    return session;
  },
  close: function (lib, session) {
    log.debug('Entering CONTROL_OPS.close().');
    lib.C_CloseSession(session);
    log.debug('Leaving CONTROL_OPS.close().');
    return true;
  },
  find: function (lib, session, template) {
    log.debug('Entering CONTROL_OPS.find().');
    const found = findOn(lib, session, template);
    log.debug('Leaving CONTROL_OPS.find().');
    return found;
  },
  // Each attribute asked alone: a sensitive one (CKA_VALUE of a secret key)
  // is refused by design and is absent from the answer.
  attributes: function (lib, session, handle, types) {
    log.debug('Entering CONTROL_OPS.attributes().');
    const out = [];
    for (const type of types) {
      try {
        const got = lib.C_GetAttributeValue(session, handle, [{ type: type }]);
        if (got && got[0] && got[0].value !== undefined) {
          out.push([type, Buffer.from(got[0].value)]);
        }
      } catch (e) {
        log.debug('Caught in CONTROL_OPS.attributes(): ' +
                  ((e && e.message) || e));
      }
    }
    log.debug('Leaving CONTROL_OPS.attributes().');
    return out;
  },
  // C_SignInit / C_EncryptInit / C_DecryptInit, the key found first where
  // its handle has to be found again.
  begin: function (lib, session, key, kind, mechanism) {
    log.debug('Entering CONTROL_OPS.begin(). ' + kind);
    if (!BEGIN_KINDS.has(kind)) {
      // error-code: none — a programming error: the three kinds are this
      // file's own.
      throw new Error('pkcs11: no operation of the kind "' + kind + '"');
    }
    const handle = keyHandleOn(lib, session, key);
    lib['C_' + kind + 'Init'](session, mechanism, handle);
    log.debug('Leaving CONTROL_OPS.begin().');
    return { handle: handle, value: null };
  },
  locate: function (lib, session, key) {
    log.debug('Entering CONTROL_OPS.locate().');
    const handle = keyHandleOn(lib, session, key);
    log.debug('Leaving CONTROL_OPS.locate().');
    return { handle: handle, value: handle };
  },
  // The value of a short-lived secret (an ECDH agreement's Z), read and the
  // object destroyed.
  readSecret: function (lib, session, obj) {
    log.debug('Entering CONTROL_OPS.readSecret().');
    try {
      const got = lib.C_GetAttributeValue(session, obj,
                                          [{ type: CK.CKA_VALUE }]);
      log.debug('Leaving CONTROL_OPS.readSecret().');
      return Buffer.from(got[0].value);
    } finally {
      lib.C_DestroyObject(session, obj);
    }
  },
  // `k1`: the bound data key as a session object, wrapped under the
  // key-encryption key with CKM_AES_KEY_WRAP_PAD, and destroyed.
  kwpWrap: function (lib, session, key, template, room) {
    log.debug('Entering CONTROL_OPS.kwpWrap().');
    const handle = keyHandleOn(lib, session, key);
    const obj = lib.C_CreateObject(session, template);
    try {
      const wrapped = lib.C_WrapKey(session,
        { mechanism: CK.CKM_AES_KEY_WRAP_PAD }, handle, obj,
        Buffer.alloc(Number(room)));
      log.debug('Leaving CONTROL_OPS.kwpWrap().');
      return { handle: handle, value: Buffer.from(wrapped) };
    } finally {
      lib.C_DestroyObject(session, obj);
    }
  },
  // `k1` reversed: unwrapped as a session object, its value read, destroyed.
  kwpUnwrap: function (lib, session, key, wrapped, template) {
    log.debug('Entering CONTROL_OPS.kwpUnwrap().');
    const handle = keyHandleOn(lib, session, key);
    const obj = lib.C_UnwrapKey(session,
      { mechanism: CK.CKM_AES_KEY_WRAP_PAD }, handle, wrapped, template);
    try {
      const got = lib.C_GetAttributeValue(session, obj,
                                          [{ type: CK.CKA_VALUE }]);
      log.debug('Leaving CONTROL_OPS.kwpUnwrap().');
      return { handle: handle, value: Buffer.from(got[0].value) };
    } finally {
      lib.C_DestroyObject(session, obj);
    }
  },
  // C_Finalize (unless the module already says it is not initialized) and
  // C_Initialize; CKR_CRYPTOKI_ALREADY_INITIALIZED is another thread having
  // done it first.
  reinitialize: function (lib, finalizeFirst) {
    log.debug('Entering CONTROL_OPS.reinitialize(). ' + !!finalizeFirst);
    if (finalizeFirst) {
      try {
        lib.C_Finalize();
      } catch (e) {
        // A module that lost its device may refuse to finalize too; it is
        // initialized again either way, which is the point.
        log.debug('Caught in CONTROL_OPS.reinitialize(): ' +
                  ((e && e.message) || e));
      }
    }
    try {
      lib.C_Initialize({ flags: CK.CKF_OS_LOCKING_OK });
    } catch (e) {
      log.debug('Caught in CONTROL_OPS.reinitialize(): ' +
                ((e && e.message) || e));
      if (ckrOf(e) !== CK.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        throw e;
      }
    }
    log.debug('Leaving CONTROL_OPS.reinitialize().');
    return true;
  },
  // The slots with a token, and what each token says it is.
  slots: function (lib) {
    log.debug('Entering CONTROL_OPS.slots().');
    const out = [];
    for (const slot of lib.C_GetSlotList(true) || []) {
      let info = null;
      try {
        info = lib.C_GetTokenInfo(slot);
      } catch (e) {
        // One slot that cannot describe its token is not a reason to refuse
        // the others; it simply is not the one asked for.
        log.debug('Caught in CONTROL_OPS.slots(): ' + ((e && e.message) || e));
        continue;
      }
      out.push({ slot: slot,
                 label: String((info && info.label) || '').trim(),
                 serial: String((info && info.serialNumber) || '').trim() });
    }
    log.debug('Leaving CONTROL_OPS.slots(). ' + out.length + '.');
    return out;
  }
});

// The file a binding was loaded from, which a thread can load again; null
// for one this process built itself (a test's fake).
function bindingPathOf(binding) {
  log.debug('Entering bindingPathOf().');
  const cache = require.cache || {};
  for (const id of Object.keys(cache)) {
    const m = cache[id];
    if (m && m.exports === binding && m.filename) {
      log.debug('Leaving bindingPathOf(). Loaded from a file.');
      return String(m.filename);
    }
  }
  log.debug('Leaving bindingPathOf(). Built in process.');
  return null;
}

// ---------------------------------------------------------------------------
// THE CONTROL CHANNEL of one loaded module: `call(op, args)` answers a
// promise of `CONTROL_OPS[op](lib, ...args)`, made by the control thread, or
// in place for a binding with no file. The thread is unref'd whenever no
// call waits on it, so a process with nothing else to do still exits, and
// ref'd while one does, so a call awaited alone is not abandoned. A thread
// that fails or exits refuses every call waiting on it (STS-KEYS-0211) and
// the next call starts another. No timer.
// ---------------------------------------------------------------------------
class Pkcs11Control {
  /**
   * @param entry - the loaded module (`libraryFor()`)
   * @param bindingPath - the binding's file, or null to call in place
   */
  constructor(entry, bindingPath) {
    log.debug('Entering Pkcs11Control.constructor().');
    this.entry = entry;
    this.bindingPath = bindingPath;
    /** @type {any} */
    this.worker = null;
    this.pending = new Map();
    this.nextId = 1;
    this.started = 0;
    log.debug('Leaving Pkcs11Control.constructor().');
  }

  /**
   * Makes one control call.
   *
   * @param op - a `CONTROL_OPS` name
   * @param args - its arguments after the module
   * @returns a promise of its answer
   */
  call(op, args) {
    log.debug('Entering Pkcs11Control.call(). ' + op);
    if (!this.bindingPath) {
      // In place, and at once, so a fake behaves exactly as it did when
      // these calls were made inline.
      try {
        const out = CONTROL_OPS[op].apply(null, [this.entry.lib].concat(args));
        log.debug('Leaving Pkcs11Control.call(). In place.');
        return Promise.resolve(out);
      } catch (e) {
        log.debug('Caught in Pkcs11Control.call(): ' + ((e && e.message) || e));
        log.debug('Leaving Pkcs11Control.call(). Refused in place.');
        return Promise.reject(e);
      }
    }
    const self = this;
    let worker;
    try {
      worker = this.thread();
    } catch (e) {
      log.debug('Caught in Pkcs11Control.call(): ' + ((e && e.message) || e));
      log.debug('Leaving Pkcs11Control.call(). No thread.');
      return Promise.reject(refusal('STS-KEYS-0211', 'the PKCS#11 control ' +
        'thread for "' + this.entry.modulePath + '" could not start', e));
    }
    const id = this.nextId++;
    log.debug('Leaving Pkcs11Control.call(). Posted.');
    return new Promise(function (resolve, reject) {
      self.pending.set(id, { resolve: resolve, reject: reject });
      if (self.pending.size === 1) {
        worker.ref();
      }
      worker.postMessage({ id: id, op: op, args: args });
    });
  }

  // The thread, started when there is none.
  thread() {
    log.debug('Entering Pkcs11Control.thread().');
    if (this.worker) {
      log.debug('Leaving Pkcs11Control.thread(). Running.');
      return this.worker;
    }
    const self = this;
    const workerThreads = require('worker_threads');
    const worker = new workerThreads.Worker(
      require('path').join(__dirname, 'pkcs11_thread.js'),
      { workerData: { bindingPath: this.bindingPath,
                      modulePath: this.entry.modulePath } });
    worker.unref();
    worker.on('message', function (m) {
      self.settle(worker, m);
    });
    worker.on('error', function (e) {
      self.lost(worker, e);
    });
    worker.on('exit', function (code) {
      self.lost(worker, new Error('the thread exited (' + code + ')'));
    });
    this.worker = worker;
    this.started++;
    log.debug('Leaving Pkcs11Control.thread(). Started.');
    return worker;
  }

  // One answer from the thread.
  settle(worker, m) {
    log.debug('Entering Pkcs11Control.settle().');
    const waiting = m && this.pending.get(m.id);
    if (!waiting) {
      log.debug('Leaving Pkcs11Control.settle(). Nobody waits.');
      return;
    }
    this.pending.delete(m.id);
    if (!this.pending.size && this.worker === worker) {
      worker.unref();
    }
    if (m.error) {
      waiting.reject(errorFrom(m.error));
    } else {
      waiting.resolve(revive(m.value));
    }
    log.debug('Leaving Pkcs11Control.settle().');
  }

  // The thread failed or exited: every call waiting on it is refused.
  lost(worker, err) {
    log.debug('Entering Pkcs11Control.lost().');
    if (this.worker !== worker) {
      log.debug('Leaving Pkcs11Control.lost(). Not the current thread.');
      return;
    }
    this.worker = null;
    const waiting = Array.from(this.pending.values());
    this.pending.clear();
    if (waiting.length) {
      log.error(errorCodes.tag('STS-KEYS-0211') + 'pkcs11: the control ' +
                'thread for "' + this.entry.modulePath + '" stopped (' +
                ((err && err.message) || err) + '); ' + waiting.length +
                ' call(s) waiting on it are refused, and the next call ' +
                'starts a new thread.');
    }
    for (const w of waiting) {
      w.reject(refusal('STS-KEYS-0211', 'the PKCS#11 control thread for "' +
                       this.entry.modulePath + '" stopped', err));
    }
    log.debug('Leaving Pkcs11Control.lost().');
  }

  /**
   * Stops the thread, for a test that forgets its modules.
   */
  stop() {
    log.debug('Entering Pkcs11Control.stop().');
    const worker = this.worker;
    if (worker) {
      this.lost(worker, new Error('stopped'));
      Promise.resolve(worker.terminate()).catch(function (e) {
        log.debug('Caught in Pkcs11Control.stop(): ' +
                  ((e && e.message) || e));
      });
    }
    log.debug('Leaving Pkcs11Control.stop().');
  }
}

// ---------------------------------------------------------------------------
// ONE LOADED MODULE PER PATH, PER THREAD. `lib.load()` dlopens the module and
// C_Initialize is called once; a second token on the same module shares it.
//
// THE ENTRY IS WHAT EVERY TOKEN ON THE MODULE SHARES, and so it is what a
// recovery acts on (`recover()`): C_Finalize ends every session of the
// module, not only the session that met the outage. `inflight` counts the
// operations of this thread holding a session on it, `epoch` the times it
// was initialised again (a session remembers its epoch, and one from before
// is never closed — its handle may since name somebody else's session — nor
// lent again), `recovering` the one re-initialisation in progress that
// every token meeting the outage joins, and `tokens` the tokens to tell.
// ---------------------------------------------------------------------------
const LIBRARIES = new Map();

/**
 * The shared state of one loaded module, for `libraryFor()` and a test that
 * builds a token by hand.
 *
 * @param binding - the binding
 * @param lib - its loaded module (`new binding.PKCS11()`)
 * @param modulePath - the module's path
 * @returns the entry
 */
function newEntry(binding, lib, modulePath) {
  log.debug('Entering newEntry().');
  const entry = { binding: binding, lib: lib, initialized: false,
                  modulePath: String(modulePath || ''), tokens: new Set(),
                  inflight: 0, drainWaiters: [], recovering: null, epoch: 0,
                  control: null };
  entry.control = new Pkcs11Control(entry, bindingPathOf(binding));
  entry.channel = outageChannel(entry);
  log.debug('Leaving newEntry().');
  return entry;
}

function libraryFor(binding, modulePath) {
  log.debug('Entering libraryFor(). ' + modulePath);
  const held = LIBRARIES.get(modulePath);
  if (held && held.binding === binding) {
    log.debug('Leaving libraryFor(). Held.');
    return held;
  }
  let lib;
  try {
    lib = new binding.PKCS11();
    lib.load(modulePath);
  } catch (e) {
    throw refusal('STS-KEYS-0202', 'the PKCS#11 module "' + modulePath +
                  '" could not be loaded', e);
  }
  const entry = newEntry(binding, lib, modulePath);
  initialize(entry);
  LIBRARIES.set(modulePath, entry);
  log.debug('Leaving libraryFor(). Loaded.');
  return entry;
}

function initialize(entry) {
  log.debug('Entering initialize().');
  try {
    entry.lib.C_Initialize({ flags: CK.CKF_OS_LOCKING_OK });
  } catch (e) {
    if (ckrOf(e) !== CK.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
      throw refusal('STS-KEYS-0202', 'the PKCS#11 module would not ' +
                    'initialize', e);
    }
    // Another thread of this process initialized it, which is expected:
    // C_Initialize is process-wide.
    log.debug('Caught in initialize(): already initialized by another ' +
              'thread: ' + ((e && e.message) || e));
  }
  entry.initialized = true;
  log.debug('Leaving initialize().');
}

// One operation of this thread took or gave back a session on the module.
function inflightMoved(entry, by) {
  log.debug('Entering inflightMoved(). ' + by);
  entry.inflight = Math.max(0, (Number(entry.inflight) || 0) + by);
  if (entry.inflight === 0 && entry.drainWaiters &&
      entry.drainWaiters.length) {
    const waiting = entry.drainWaiters.splice(0);
    for (const w of waiting) {
      w();
    }
  }
  log.debug('Leaving inflightMoved(). ' + entry.inflight + ' in flight.');
}

// A promise that settles once no operation of this thread holds a session
// on the module.
function drained(entry) {
  log.debug('Entering drained(). ' + entry.inflight + ' in flight.');
  if (!entry.inflight) {
    log.debug('Leaving drained(). Already.');
    return Promise.resolve();
  }
  log.debug('Leaving drained(). Waiting.');
  return new Promise(function (resolve) {
    entry.drainWaiters.push(resolve);
  });
}

// ---------------------------------------------------------------------------
// ONE RE-INITIALISATION AT A TIME IN THE PROCESS: A SINGLE FLIGHT (#1955 P8,
// rcbj 2026-11-23: "fix it").
//
// WHERE THE RACE WAS. Every thread that loaded a module — the front and
// each request worker, `worker_threads` Workers that each load the binding
// and this file — holds its own entry, its own session pool and its own
// control thread, while C_Finalize and C_Initialize are the PROCESS's. A
// thread's own operations already joined one re-initialisation
// (`entry.recovering`), and the outage channel below tells the other
// threads after the fact. What that left was the channel's flight time:
// two threads that met the outage in the same instant each finalized the
// module, the second after the first had initialised it again and opened
// its sessions, so the first thread's retry met a dead session and was
// refused (STS-KEYS-0201) — a spurious failed signature or decryption
// during an outage. It was never libuv's pool: C_SignAsync and its kin run
// there, but a re-initialisation is asked by a JavaScript thread (through
// its control thread), and two JavaScript threads were the two that raced.
//
// THE FIX IS A LOCK AND A GENERATION IN SHARED MEMORY. One
// SharedArrayBuffer for the process, made by the first thread that loads
// this file — the front, at `crypto.js`'s require, long before a request
// worker is started — and handed to every Worker made after it through
// `worker_threads.setEnvironmentData()`, which a new Worker inherits from
// the thread that made it (a request worker from the front, a control
// thread from its owner); a structured clone of a SharedArrayBuffer shares
// its memory, so nothing is plumbed through the pool. It holds a SLOT of
// three int32s per module path: the path's hash, the lock (0 free, else the
// holder's threadId + 1) and the module's GENERATION, the number of times
// any thread of the process has initialised it again. A session remembers
// the generation it was opened under (`gen`). A thread that must
// re-initialise takes the lock (`Atomics.compareExchange`, waiting with
// `Atomics.waitAsync`, which arms no timer of ours), and holding it looks at
// the generation: MOVED since its session was opened (or since it noticed
// the outage) means another thread re-initialised in between, so it does
// not finalize — it ADOPTS that result (its sessions from before are
// forgotten, its slots found again) and its one retry runs on the module the
// other thread reconnected. UNMOVED means it is the one: it re-initialises,
// moves the generation and lets go. However many threads notice at once,
// the module is finalized once, and every one of them retries against that
// one result (`tests/pkcs11_reconnect.js`).
//
// A HOLDER THAT NEVER LETS GO (a worker terminated mid-way) is waited out
// for REINIT_LOCK_WAIT_MS and then taken over, logged under STS-KEYS-0213;
// the blocking door (`recoverSync()`) waits at most REINIT_LOCK_WAIT_SYNC_MS
// with `Atomics.wait` and is refused STS-KEYS-0212 past it. Neither is
// periodic: a wait ends when the holder lets go. A runtime with no
// SharedArrayBuffer (none this service runs on) gets a private table, a lock
// for its own thread only; the outage channel still tells the others.
// ---------------------------------------------------------------------------
const REINIT_ENV_KEY = 'iya-sts-pkcs11-reinit:v1';
const REINIT_SLOTS = 32;
const REINIT_SLOT_INTS = 3;
const REINIT_LOCK_WAIT_MS = 30000;
const REINIT_LOCK_WAIT_SYNC_MS = 2000;

const REINIT_TABLE = (function () {
  let table = null;
  let problem = null;
  try {
    const workerThreads = require('worker_threads');
    const held = workerThreads.getEnvironmentData(REINIT_ENV_KEY);
    if (held instanceof SharedArrayBuffer) {
      table = new Int32Array(held);
    } else {
      const made = new SharedArrayBuffer(4 * REINIT_SLOTS * REINIT_SLOT_INTS);
      workerThreads.setEnvironmentData(REINIT_ENV_KEY, made);
      table = new Int32Array(made);
    }
  } catch (e) {
    // Reported on the line below: a private table serves this thread.
    problem = (e && e.message) || String(e);
    table = new Int32Array(REINIT_SLOTS * REINIT_SLOT_INTS);
  }
  if (problem) {
    log.debug('Caught in REINIT_TABLE: ' + problem);
  }
  return table;
})();

// This thread's name in the lock: its threadId plus one, so 0 is free.
function reinitHolder() {
  log.debug('Entering reinitHolder().');
  const id = Number(require('worker_threads').threadId) || 0;
  log.debug('Leaving reinitHolder().');
  return id + 1;
}

// A module path's slot in the table, claimed on first use: FNV-1a over the
// path, never 0. Not a cryptographic use; two paths that collided would only
// share a lock and a generation, which costs a reconnect, never a crash.
function reinitSlotOf(entry) {
  log.debug('Entering reinitSlotOf().');
  if (typeof entry.reinitSlot === 'number') {
    log.debug('Leaving reinitSlotOf(). Held.');
    return entry.reinitSlot;
  }
  let h = 0x811c9dc5;
  const text = String(entry.modulePath || '');
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  h = (h | 0) || 1;
  let slot = ((h >>> 0) % REINIT_SLOTS) * REINIT_SLOT_INTS;
  for (let n = 0; n < REINIT_SLOTS; n++) {
    const at = (((h >>> 0) + n) % REINIT_SLOTS) * REINIT_SLOT_INTS;
    const was = Atomics.compareExchange(REINIT_TABLE, at, 0, h);
    if (was === 0 || was === h) {
      slot = at;
      break;
    }
  }
  entry.reinitSlot = slot;
  log.debug('Leaving reinitSlotOf(). ' + slot);
  return slot;
}

// The module's generation: how many times a thread of this process has
// initialised it again.
function sharedGeneration(entry) {
  log.debug('Entering sharedGeneration().');
  const out = Atomics.load(REINIT_TABLE, reinitSlotOf(entry) + 2);
  log.debug('Leaving sharedGeneration(). ' + out);
  return out;
}

// One attempt at the lock: 0 when this thread took it, else its holder.
function tryReinitLock(entry) {
  log.debug('Entering tryReinitLock().');
  const was = Atomics.compareExchange(REINIT_TABLE, reinitSlotOf(entry) + 1,
                                      0, reinitHolder());
  log.debug('Leaving tryReinitLock(). ' + was);
  return was;
}

/**
 * Takes the module's lock, waiting for its holder to let go; a holder that
 * has not let go after REINIT_LOCK_WAIT_MS is taken over (STS-KEYS-0213).
 *
 * @param entry - the module
 * @returns a promise settled once this thread holds the lock
 */
async function takeReinitLock(entry) {
  log.debug('Entering takeReinitLock().');
  const at = reinitSlotOf(entry) + 1;
  const me = reinitHolder();
  const deadline = Date.now() + REINIT_LOCK_WAIT_MS;
  for (;;) {
    const was = tryReinitLock(entry);
    if (was === 0) {
      log.debug('Leaving takeReinitLock(). Taken.');
      return;
    }
    const left = deadline - Date.now();
    if (left <= 0) {
      if (Atomics.compareExchange(REINIT_TABLE, at, was, me) === was) {
        log.warn(errorCodes.tag('STS-KEYS-0213') + 'pkcs11: the ' +
                 'process-wide lock on re-initialising "' + entry.modulePath +
                 '" was held by thread ' + (was - 1) + ' for more than ' +
                 REINIT_LOCK_WAIT_MS + ' ms; this thread takes it over.');
        log.debug('Leaving takeReinitLock(). Taken over.');
        return;
      }
      continue;
    }
    // ES2024's `Atomics.waitAsync`, which node has had since 16; the cast
    // is for the type-check's library, which predates it.
    const waited = /** @type {any} */ (Atomics).waitAsync(REINIT_TABLE, at,
                                                          was, left);
    if (waited.async) {
      // A pending `Atomics.waitAsync()` does not keep a thread's event loop
      // alive (measured: a worker with nothing else to do exited mid-wait),
      // so a message port with a listener holds it open for the wait.
      const hold = new (require('worker_threads').MessageChannel)();
      hold.port1.on('message', function () {
        log.debug('takeReinitLock(): nothing is ever sent here.');
      });
      try {
        await waited.value;
      } finally {
        hold.port1.close();
      }
    }
  }
}

// The same, for the blocking door: true once held, false when the holder
// did not let go within REINIT_LOCK_WAIT_SYNC_MS.
function takeReinitLockSync(entry) {
  log.debug('Entering takeReinitLockSync().');
  const at = reinitSlotOf(entry) + 1;
  const deadline = Date.now() + REINIT_LOCK_WAIT_SYNC_MS;
  for (;;) {
    const was = tryReinitLock(entry);
    if (was === 0) {
      log.debug('Leaving takeReinitLockSync(). Taken.');
      return true;
    }
    const left = deadline - Date.now();
    if (left <= 0) {
      log.debug('Leaving takeReinitLockSync(). Held elsewhere.');
      return false;
    }
    Atomics.wait(REINIT_TABLE, at, was, left);
  }
}

// Lets the lock go and wakes every thread waiting on it.
function giveReinitLock(entry) {
  log.debug('Entering giveReinitLock().');
  const at = reinitSlotOf(entry) + 1;
  Atomics.compareExchange(REINIT_TABLE, at, reinitHolder(), 0);
  Atomics.notify(REINIT_TABLE, at);
  log.debug('Leaving giveReinitLock().');
}

// This thread initialised the module again: the generation moves, and this
// thread has taken in the generation it made.
function moveSharedGeneration(entry) {
  log.debug('Entering moveSharedGeneration().');
  const out = Atomics.add(REINIT_TABLE, reinitSlotOf(entry) + 2, 1) + 1;
  entry.adoptedGeneration = out;
  log.debug('Leaving moveSharedGeneration(). ' + out);
  return out;
}

// Whether this thread has yet to take in generation `gen`, which another
// thread made; when it has not, it takes it in now (the epoch moves, so its
// sessions from before are forgotten rather than closed or lent).
function adoptSharedGeneration(entry, gen) {
  log.debug('Entering adoptSharedGeneration(). ' + gen);
  const fresh = !(Number(entry.adoptedGeneration) >= gen);
  if (fresh) {
    entry.adoptedGeneration = gen;
    entry.epoch++;
  }
  log.debug('Leaving adoptSharedGeneration(). ' + fresh);
  return fresh;
}

/**
 * Initialises a module again, ONCE for every token on it that met the
 * outage — and, through the lock above, once for every THREAD of the
 * process that met it at the same moment. The operations of this thread
 * holding its sessions drain first (they complete or meet the outage and
 * join this); then the process-wide lock is taken, and either another
 * thread has initialised the module again since `seenGeneration` (it is
 * adopted, nothing is finalized) or C_Finalize and C_Initialize are made off
 * the event loop and the generation moves. Either way the epoch moves — so
 * every session from before is forgotten rather than closed or lent — and
 * every token on the module drops its idle sessions and finds its slot
 * again. New operations wait for it in `acquire()`.
 *
 * CKR_CRYPTOKI_NOT_INITIALIZED is answered without C_Finalize: somebody
 * finalized it already, and finalizing again would end the sessions they
 * have just opened.
 *
 * @param entry - the module
 * @param finalizeFirst - false when the module is already not initialized
 * @param seenEpoch - this thread's epoch the failed session was opened
 *   under, or undefined
 * @param seenGeneration - the process's generation it was opened under,
 *   or undefined for the generation when the outage was noticed
 * @returns a promise settled once it is done
 */
function reinitializeEntry(entry, finalizeFirst, seenEpoch, seenGeneration) {
  log.debug('Entering reinitializeEntry().');
  if (entry.recovering) {
    log.debug('Leaving reinitializeEntry(). Joined.');
    return entry.recovering;
  }
  const seenGen = typeof seenGeneration === 'number' ? seenGeneration :
                  sharedGeneration(entry);
  const done = function () {
    entry.recovering = null;
  };
  // Whether the module was initialised again — by another thread, which
  // said so on the outage channel — since the session that met the outage
  // was opened: then that is what ended it, and finalizing again would end
  // the sessions the other thread has just opened.
  const since = function () {
    return seenEpoch !== undefined && seenEpoch !== null &&
           entry.epoch !== seenEpoch;
  };
  let skipped = false;
  entry.recovering = drained(entry).then(async function () {
    if (since()) {
      skipped = true;
      return true;
    }
    await takeReinitLock(entry);
    try {
      const now = sharedGeneration(entry);
      if (now !== seenGen) {
        // Another thread reconnected while this one waited: its result
        // is this one's too.
        skipped = true;
        adoptSharedGeneration(entry, now);
        return true;
      }
      await entry.control.call('reinitialize', [!!finalizeFirst]);
      moveSharedGeneration(entry);
      entry.epoch++;
      announceReinitialized(entry);
    } finally {
      giveReinitLock(entry);
    }
    return true;
  }).then(function () {
    if (skipped) {
      log.info('pkcs11: "' + entry.modulePath + '" was initialised again ' +
               'by another thread since the session that met the outage ' +
               'was opened; it is not finalized again.');
    }
    return Promise.all(Array.from(entry.tokens).map(function (t) {
      return t.afterReinitialize();
    }));
  }).then(function () {
    done();
  }, function (e) {
    log.debug('Caught in reinitializeEntry(): ' + ((e && e.message) || e));
    done();
    throw e;
  });
  log.debug('Leaving reinitializeEntry(). Started.');
  return entry.recovering;
}

// ---------------------------------------------------------------------------
// THE OUTAGE CHANNEL: ONE RE-INITIALISATION FOR THE PROCESS, NOT ONE PER
// THREAD (#1955 P8 follow-up). C_Finalize is process-wide, and each thread
// that loaded a module (the front, every request worker) counts only its own
// operations. Without this, a device that really went away was met by
// several threads at once, each finalized the module after the others had
// initialised it again, and an operation another thread had just retried
// lost its one retry (STS-KEYS-0201). So a thread that has initialised a
// module again says so on a BroadcastChannel of that module's path — every
// thread of the process hears it with no plumbing through the pool — and
// each other thread moves its epoch (its sessions from before are forgotten,
// not closed: their handles may now name the announcer's), finds its slots
// again, and — the point — does not finalize for an outage met on a session
// opened before the announcement (`reinitializeEntry()`'s `seenEpoch`). The
// time a message takes to arrive is NOT what keeps two threads from both
// finalizing — that is the process-wide lock and generation above, which
// make a re-initialisation single-flight; the channel only lets a thread
// that met no outage of its own drop its idle sessions early. A message
// carries the generation it made, and one this thread has already taken in
// (through the lock) is not taken in twice.
// ---------------------------------------------------------------------------
function outageChannel(entry) {
  log.debug('Entering outageChannel().');
  let channel = null;
  try {
    const workerThreads = require('worker_threads');
    channel = new workerThreads.BroadcastChannel('iya-sts-pkcs11:' +
                                                 entry.modulePath);
    channel.onmessage = function (event) {
      if (event && event.data && event.data.reinitialized) {
        foreignReinitialized(entry, Number(event.data.generation) || 0);
      }
    };
    if (typeof channel.unref === 'function') {
      channel.unref();
    }
  } catch (e) {
    // A runtime with no BroadcastChannel recovers each thread on its own,
    // as before it existed.
    log.debug('Caught in outageChannel(): ' + ((e && e.message) || e));
    channel = null;
  }
  log.debug('Leaving outageChannel().');
  return channel;
}

// Tells the other threads this one initialised the module again.
function announceReinitialized(entry) {
  log.debug('Entering announceReinitialized().');
  if (entry.channel) {
    try {
      entry.channel.postMessage({ reinitialized: true,
                                  generation: entry.adoptedGeneration });
    } catch (e) {
      log.debug('Caught in announceReinitialized(): ' +
                ((e && e.message) || e));
    }
  }
  log.debug('Leaving announceReinitialized().');
}

// Another thread initialised the module again: every session of this thread
// from before is gone with it — unless this thread took that generation in
// already, through the lock (`adoptSharedGeneration()`).
function foreignReinitialized(entry, generation) {
  log.debug('Entering foreignReinitialized(). ' + entry.modulePath);
  if (generation > 0) {
    if (!adoptSharedGeneration(entry, generation)) {
      log.debug('Leaving foreignReinitialized(). Taken in already.');
      return;
    }
  } else {
    entry.epoch++;
  }
  const tokens = Array.from(entry.tokens);
  for (const t of tokens) {
    t.generation++;
    t.dropIdle();
  }
  if (!entry.recovering) {
    const done = function () {
      entry.recovering = null;
    };
    entry.recovering = Promise.all(tokens.map(function (t) {
      return t.findSlotAsync().then(function (slot) {
        t.slot = slot;
      }, function (e) {
        // The next operation meets the module as it is.
        log.debug('Caught in foreignReinitialized(): ' +
                  ((e && e.message) || e));
      });
    })).then(done, done);
  }
  log.debug('Leaving foreignReinitialized().');
}

// ---------------------------------------------------------------------------
// A TOKEN: one slot of one module, logged in as the user, with its pool of
// sessions. Built by `common/crypto.js`'s `openPkcs11Token()`.
//
// A SESSION is held as `{ h, epoch, gen }`: the binding's handle, the
// module's epoch it was opened under in this thread (`newEntry()`) and the
// process's generation of the module then (`sharedGeneration()`). `open`
// counts this token's sessions that exist — idle, lent, and the one blocking session — and is
// only ever moved one session at a time, never reset while sessions are
// lent: a session from an earlier epoch is forgotten when it comes back.
// ---------------------------------------------------------------------------
class Pkcs11Token {
  /**
   * @param binding - the loaded binding (`require('pkcs11js')`) or a fake
   * @param options - `{ modulePath, tokenLabel, serial, slotId, pin,
   *   maxSessions, timeoutMs, queueLimit }`
   */
  constructor(binding, options) {
    log.debug('Entering Pkcs11Token.constructor().');
    const o = options || {};
    this.binding = binding;
    this.modulePath = String(o.modulePath || '');
    this.tokenLabel = String(o.tokenLabel || '');
    this.serial = String(o.serial || '');
    this.slotId = o.slotId === undefined || o.slotId === null ||
                  o.slotId === '' ? null : String(o.slotId);
    this.pin = o.pin === undefined || o.pin === null ? null : String(o.pin);
    this.maxSessions = Math.max(1, Math.min(64, Number(o.maxSessions) || 4));
    // THE WAIT AND THE QUEUE (#2220, ASVS 5.0.0 13.1.2 and 13.1.3). An
    // asynchronous operation (and the wait for a session to run it on) is
    // given up after `timeoutMs` (`keys.pkcs11TimeoutMs`, 60 s; 0 for
    // none), and at most `queueLimit` operations (`keys.pkcs11QueueLimit`,
    // 1000) wait for a session of this token in this thread; past it an
    // operation is refused at once (STS-KEYS-0215). See `acquire()` and
    // `run()`.
    this.timeoutMs = Math.max(0, Number(o.timeoutMs) || 0);
    this.queueLimit = Number(o.queueLimit) > 0 ? Number(o.queueLimit)
      : Infinity;
    /** @type {any} */
    this.entry = null;
    this.slot = null;
    this.idle = [];
    this.open = 0;
    this.lent = 0;
    this.waiters = [];
    this.loggedIn = false;
    this.mechanisms = null;
    this.reconnects = 0;
    // THE BLOCKING SESSION. A synchronous call (`runSync()`) cannot wait for
    // a session an asynchronous one holds, so where none is idle it takes
    // this one, opened once and kept: synchronous calls on one thread never
    // overlap, so one is enough, and the pool never grows past
    // `maxSessions` lent plus this one. Until the P8 follow-up it opened a
    // session past the cap for each such call and closed it after.
    /** @type {any} */
    this.blocking = null;
    // OBJECT HANDLES DO NOT OUTLIVE THE LOGIN. When the last session closes
    // the module logs the application out, and SoftHSM2 then answers
    // CKR_OBJECT_HANDLE_INVALID for a handle found before (2026-11-20, the
    // first run against it); a connector restart does the same. So a key is
    // held as the TEMPLATE that finds it, and its handle is found again
    // whenever this counter has moved since — off the event loop, on the
    // session the operation holds, by the control thread (`keyed()`).
    this.generation = 0;
    log.debug('Leaving Pkcs11Token.constructor().');
  }

  /**
   * Loads the module, finds the slot, reads the mechanism list and opens
   * (and logs in) one session, so that a wrong label or PIN is refused at
   * start rather than at the first operation. Synchronous, at start: it is
   * called before the listener binds (`keystore.start()`), and what it
   * reads is what every later operation would otherwise read on its first
   * call.
   *
   * @returns this token
   */
  connect() {
    log.debug('Entering Pkcs11Token.connect().');
    this.entry = libraryFor(this.binding, this.modulePath);
    this.entry.tokens.add(this);
    this.slot = this.findSlot();
    const session = this.openSessionSync();
    this.idle.push(session);
    try {
      this.mechanismFlags();
    } catch (e) {
      // Read again by the first caller that needs it, which refuses with
      // the module's answer (STS-KEYS-0204).
      log.debug('Caught in Pkcs11Token.connect(): ' + ((e && e.message) || e));
    }
    log.debug('Leaving Pkcs11Token.connect().');
    return this;
  }

  // The one slot this token's label, serial and slot-id name, of the module's
  // answer (`CONTROL_OPS.slots()`).
  chooseSlot(listed) {
    log.debug('Entering Pkcs11Token.chooseSlot().');
    const matches = [];
    for (const one of listed) {
      const slot = one.slot;
      const id = Buffer.isBuffer(slot) ? String(attrUlong(slot)) :
                 String(slot);
      if (this.tokenLabel && one.label !== this.tokenLabel) {
        continue;
      }
      if (this.serial && one.serial !== this.serial) {
        continue;
      }
      if (this.slotId !== null && id !== this.slotId) {
        continue;
      }
      matches.push(slot);
    }
    if (matches.length !== 1) {
      throw refusal('STS-KEYS-0202', (matches.length ? 'more than one ' :
        'no ') + 'PKCS#11 token in "' + this.modulePath + '" matches ' +
        this.describe() + (matches.length ? '; name its serial or slot-id ' +
        'as well' : ''));
    }
    log.debug('Leaving Pkcs11Token.chooseSlot().');
    return matches[0];
  }

  findSlot() {
    log.debug('Entering Pkcs11Token.findSlot().');
    let listed;
    try {
      listed = CONTROL_OPS.slots(this.entry.lib);
    } catch (e) {
      throw refusal('STS-KEYS-0202', 'the PKCS#11 module listed no slots', e);
    }
    log.debug('Leaving Pkcs11Token.findSlot().');
    return this.chooseSlot(listed);
  }

  async findSlotAsync() {
    log.debug('Entering Pkcs11Token.findSlotAsync().');
    let listed;
    try {
      listed = await this.entry.control.call('slots', []);
    } catch (e) {
      throw refusal('STS-KEYS-0202', 'the PKCS#11 module listed no slots', e);
    }
    log.debug('Leaving Pkcs11Token.findSlotAsync().');
    return this.chooseSlot(listed);
  }

  /**
   * Says which token this is, for a sentence: its label, serial and slot,
   * whichever were asked for. Never the PIN.
   *
   * @returns the description
   */
  describe() {
    log.debug('Entering Pkcs11Token.describe().');
    const parts = [];
    if (this.tokenLabel) {
      parts.push('token "' + this.tokenLabel + '"');
    }
    if (this.serial) {
      parts.push('serial ' + this.serial);
    }
    if (this.slotId !== null) {
      parts.push('slot ' + this.slotId);
    }
    log.debug('Leaving Pkcs11Token.describe().');
    return parts.join(', ') || 'the only token';
  }

  // The refusal a failed C_OpenSession or C_Login is.
  openRefusal(e) {
    log.debug('Entering Pkcs11Token.openRefusal().');
    log.debug('Leaving Pkcs11Token.openRefusal().');
    return e && e.pinRefused
      ? refusal('STS-KEYS-0205', 'the PIN was refused by ' + this.describe(),
                e)
      : refusal('STS-KEYS-0201', 'no session could be opened on ' +
                this.describe(), e);
  }

  // A session opened in place: at start, and for the blocking door.
  openSessionSync() {
    log.debug('Entering Pkcs11Token.openSessionSync().');
    const epoch = this.entry.epoch;
    const gen = sharedGeneration(this.entry);
    let h;
    try {
      h = CONTROL_OPS.open(this.entry.lib, this.slot, this.pin);
    } catch (e) {
      throw this.openRefusal(e);
    }
    this.open++;
    this.loggedIn = this.pin !== null;
    log.debug('Leaving Pkcs11Token.openSessionSync().');
    return { h: h, epoch: epoch, gen: gen };
  }

  // A session opened off the event loop, counted from the moment it is
  // asked for, so two callers cannot both pass the cap.
  async openSessionAsync() {
    log.debug('Entering Pkcs11Token.openSessionAsync().');
    const epoch = this.entry.epoch;
    const gen = sharedGeneration(this.entry);
    this.open++;
    let h;
    try {
      h = await this.entry.control.call('open', [this.slot, this.pin]);
    } catch (e) {
      this.open = Math.max(0, this.open - 1);
      throw this.openRefusal(e);
    }
    this.loggedIn = this.pin !== null;
    log.debug('Leaving Pkcs11Token.openSessionAsync().');
    return { h: h, epoch: epoch, gen: gen };
  }

  // Whether a session is from the module's current epoch.
  current(session) {
    log.debug('Entering Pkcs11Token.current().');
    const out = !!session && session.epoch === this.entry.epoch;
    log.debug('Leaving Pkcs11Token.current(). ' + out);
    return out;
  }

  // A session that no longer exists in the module (an earlier epoch's)
  // leaves the count without C_CloseSession: its handle may since have been
  // given to another session.
  forgetSession(session) {
    log.debug('Entering Pkcs11Token.forgetSession().');
    this.open = Math.max(0, this.open - 1);
    if (this.open === 0) {
      this.generation++;
    }
    log.debug('Leaving Pkcs11Token.forgetSession().');
  }

  // Closes a session off the event loop, or forgets it when it is from an
  // earlier epoch.
  closeSession(session) {
    log.debug('Entering Pkcs11Token.closeSession().');
    const live = this.current(session);
    this.forgetSession(session);
    if (live) {
      this.entry.control.call('close', [session.h]).catch(function (e) {
        // A session the device already lost cannot be closed, and does not
        // need to be.
        log.debug('Caught in Pkcs11Token.closeSession(): ' +
                  ((e && e.message) || e));
      });
    }
    log.debug('Leaving Pkcs11Token.closeSession().');
  }

  /**
   * Closes every idle session, for a test that forgets its tokens (the
   * module logs the application out with the last one). A session lent to a
   * running operation is closed when it is handed back.
   */
  close() {
    log.debug('Entering Pkcs11Token.close().');
    const idle = this.idle.splice(0);
    for (const s of idle) {
      this.closeSession(s);
    }
    if (this.blocking) {
      const b = this.blocking;
      this.blocking = null;
      this.closeSession(b);
    }
    this.maxSessions = 0;
    if (this.entry && this.entry.tokens) {
      this.entry.tokens.delete(this);
    }
    log.debug('Leaving Pkcs11Token.close().');
  }

  // An idle session of the current epoch, or null; an earlier epoch's is
  // forgotten on the way.
  takeIdle() {
    log.debug('Entering Pkcs11Token.takeIdle().');
    while (this.idle.length) {
      const s = this.idle.pop();
      if (this.current(s)) {
        log.debug('Leaving Pkcs11Token.takeIdle(). One.');
        return s;
      }
      this.forgetSession(s);
    }
    log.debug('Leaving Pkcs11Token.takeIdle(). None.');
    return null;
  }

  // How many sessions the pool may lend: every open one but the blocking
  // session.
  pooled() {
    log.debug('Entering Pkcs11Token.pooled().');
    log.debug('Leaving Pkcs11Token.pooled().');
    return this.open - (this.blocking ? 1 : 0);
  }

  lend(session) {
    log.debug('Entering Pkcs11Token.lend().');
    this.lent++;
    inflightMoved(this.entry, 1);
    log.debug('Leaving Pkcs11Token.lend().');
  }

  unlend(session) {
    log.debug('Entering Pkcs11Token.unlend().');
    this.lent = Math.max(0, this.lent - 1);
    inflightMoved(this.entry, -1);
    log.debug('Leaving Pkcs11Token.unlend().');
  }

  // Wakes one waiter to try again (`null`), when a session left the pool.
  wakeOne() {
    log.debug('Entering Pkcs11Token.wakeOne().');
    const next = this.waiters.shift();
    if (next) {
      next(null);
    }
    log.debug('Leaving Pkcs11Token.wakeOne().');
  }

  // Lends a session: an idle one, a new one under the cap (opened off the
  // event loop), or the next one handed back. Waits first for a
  // re-initialisation of the module in progress.
  async acquire() {
    log.debug('Entering Pkcs11Token.acquire().');
    for (;;) {
      if (this.entry.recovering) {
        try {
          await this.entry.recovering;
        } catch (e) {
          // The recovery's own refusal is the operation that started it;
          // this one opens a session and meets the module as it now is.
          log.debug('Caught in Pkcs11Token.acquire(): ' +
                    ((e && e.message) || e));
        }
        continue;
      }
      const idle = this.takeIdle();
      if (idle) {
        this.lend(idle);
        log.debug('Leaving Pkcs11Token.acquire(). Idle.');
        return idle;
      }
      if (this.pooled() < this.maxSessions) {
        const opened = await this.openSessionAsync();
        if (!this.current(opened)) {
          // The module was initialised again while it opened.
          this.forgetSession(opened);
          continue;
        }
        this.lend(opened);
        log.debug('Leaving Pkcs11Token.acquire(). Opened.');
        return opened;
      }
      const waiters = this.waiters;
      if (waiters.length >= this.queueLimit) {
        log.warn(errorCodes.tag('STS-KEYS-0215') + 'pkcs11: ' +
                 waiters.length + ' operations are already waiting for a ' +
                 'session of ' + this.describe() +
                 ' (keys.pkcs11QueueLimit); this one is refused.');
        log.debug('Leaving Pkcs11Token.acquire(). The queue is full.');
        throw refusal('STS-KEYS-0215', 'too many operations are waiting ' +
                      'for a session of ' + this.describe());
      }
      const timeoutMs = this.timeoutMs;
      const what = this.describe();
      const handed = await new Promise(function (resolve, reject) {
        let timer = null;
        const waiter = function (session) {
          if (timer) {
            clearTimeout(timer);
          }
          resolve(session);
        };
        waiters.push(waiter);
        if (timeoutMs > 0) {
          // A wait inside one operation, cleared when a session comes.
          timer = setTimeout(function () {
            const at = waiters.indexOf(waiter);
            if (at >= 0) {
              waiters.splice(at, 1);
            }
            reject(refusal('STS-KEYS-0216', 'no session of ' + what +
                           ' came free within ' + timeoutMs + ' ms ' +
                           '(keys.pkcs11TimeoutMs)'));
          }, timeoutMs);
          if (timer && typeof timer.unref === 'function') {
            timer.unref();
          }
        }
      });
      if (handed) {
        log.debug('Leaving Pkcs11Token.acquire(). Handed on.');
        return handed;
      }
    }
  }

  release(session) {
    log.debug('Entering Pkcs11Token.release().');
    this.unlend(session);
    if (!this.current(session)) {
      this.forgetSession(session);
      this.wakeOne();
      log.debug('Leaving Pkcs11Token.release(). From before.');
      return;
    }
    const next = this.waiters.shift();
    if (next) {
      this.lend(session);
      next(session);
    } else if (this.pooled() > this.maxSessions) {
      this.closeSession(session);
    } else {
      this.idle.push(session);
    }
    log.debug('Leaving Pkcs11Token.release().');
  }

  // A lost session is not handed back; a waiter is woken to open another.
  discard(session) {
    log.debug('Entering Pkcs11Token.discard().');
    this.unlend(session);
    this.closeSession(session);
    this.wakeOne();
    log.debug('Leaving Pkcs11Token.discard().');
  }

  // Every idle session of this token, closed (or forgotten): they were lost
  // with the one that failed.
  dropIdle() {
    log.debug('Entering Pkcs11Token.dropIdle().');
    const idle = this.idle.splice(0);
    for (const s of idle) {
      this.closeSession(s);
    }
    if (this.blocking) {
      const b = this.blocking;
      this.blocking = null;
      this.closeSession(b);
    }
    log.debug('Leaving Pkcs11Token.dropIdle().');
  }

  /**
   * After the module was initialised again (`reinitializeEntry()`): the
   * handles found before are found again, every session from before is
   * forgotten (the module ended them), and the slot is found again.
   *
   * @returns a promise settled once the slot is found
   */
  async afterReinitialize() {
    log.debug('Entering Pkcs11Token.afterReinitialize().');
    this.generation++;
    this.dropIdle();
    this.slot = await this.findSlotAsync();
    log.debug('Leaving Pkcs11Token.afterReinitialize().');
  }

  // After an outage met off the event loop: every idle session is dropped
  // (they were lost with the one that failed), and the module is initialised
  // again, once, where the error says the library itself lost the device.
  async recover(err, seenEpoch, seenGeneration) {
    log.debug('Entering Pkcs11Token.recover().');
    this.reconnects++;
    this.generation++;
    const ckr = ckrOf(err);
    if (!DEVICE_LOST.has(ckr)) {
      log.debug('Leaving Pkcs11Token.recover(). Only that session.');
      return;
    }
    this.dropIdle();
    if (REINITIALIZE_ON.has(ckr)) {
      await reinitializeEntry(this.entry,
                              ckr !== CK.CKR_CRYPTOKI_NOT_INITIALIZED,
                              seenEpoch, seenGeneration);
    }
    log.warn(errorCodes.tag('STS-KEYS-0201') + 'pkcs11: ' + this.describe() +
             ' answered ' + ((err && err.message) || err) + '; the session ' +
             'was dropped and the operation is tried once more.');
    log.debug('Leaving Pkcs11Token.recover().');
  }

  // The same, met on the blocking door. Initialising the module again in
  // place is safe only while no asynchronous operation of this thread holds
  // a session on it; otherwise it is started off the event loop, where it
  // waits for them, and this call is refused (STS-KEYS-0212).
  recoverSync(err, what, seenEpoch, seenGeneration) {
    log.debug('Entering Pkcs11Token.recoverSync().');
    const seenGen = typeof seenGeneration === 'number' ? seenGeneration :
                    sharedGeneration(this.entry);
    this.reconnects++;
    this.generation++;
    const ckr = ckrOf(err);
    if (!DEVICE_LOST.has(ckr)) {
      log.debug('Leaving Pkcs11Token.recoverSync(). Only that session.');
      return;
    }
    this.dropIdle();
    // Initialised again by another thread since that session was opened:
    // nothing to finalize (`reinitializeEntry()`).
    const since = seenEpoch !== undefined && seenEpoch !== this.entry.epoch;
    if (REINITIALIZE_ON.has(ckr) && !since) {
      if (this.entry.inflight > 0 || this.entry.recovering) {
        reinitializeEntry(this.entry, ckr !== CK.CKR_CRYPTOKI_NOT_INITIALIZED,
                          seenEpoch, seenGen)
          .catch(function (e) {
            // The next operation meets the module as it is, and refuses
            // with its own answer.
            log.debug('Caught in Pkcs11Token.recoverSync(): ' +
                      ((e && e.message) || e));
          });
        log.debug('Leaving Pkcs11Token.recoverSync(). Off the loop.');
        throw refusal('STS-KEYS-0212', what + ' on ' + this.describe() +
          ' met a lost device while asynchronous calls hold sessions on ' +
          'the module; it is initialised again off the event loop once ' +
          'they drain', err);
      }
      // The process-wide lock (`takeReinitLock()`), waited for in place —
      // this is the door where the event loop waits for the module — and
      // at most REINIT_LOCK_WAIT_SYNC_MS.
      if (!takeReinitLockSync(this.entry)) {
        log.debug('Leaving Pkcs11Token.recoverSync(). Locked elsewhere.');
        throw refusal('STS-KEYS-0212', what + ' on ' + this.describe() +
          ' met a lost device while another thread of this process is ' +
          'initialising the module again', err);
      }
      try {
        const now = sharedGeneration(this.entry);
        if (now !== seenGen) {
          // Another thread reconnected it: this thread takes that in.
          adoptSharedGeneration(this.entry, now);
        } else {
          CONTROL_OPS.reinitialize(this.entry.lib,
                                   ckr !== CK.CKR_CRYPTOKI_NOT_INITIALIZED);
          moveSharedGeneration(this.entry);
          this.entry.epoch++;
          announceReinitialized(this.entry);
        }
      } finally {
        giveReinitLock(this.entry);
      }
      for (const t of Array.from(this.entry.tokens)) {
        t.generation++;
        t.dropIdle();
        t.slot = t.findSlot();
      }
    }
    log.warn(errorCodes.tag('STS-KEYS-0201') + 'pkcs11: ' + this.describe() +
             ' answered ' + ((err && err.message) || err) + '; the session ' +
             'was dropped and the operation is tried once more.');
    log.debug('Leaving Pkcs11Token.recoverSync().');
  }

  /**
   * Runs one operation on a lent session, asynchronously, reconnecting once
   * after an outage.
   *
   * @param what - what the operation is, for a refusal
   * @param fn - `(lib, session) => value | Promise<value>`, `session` the
   *   binding's handle
   * @returns a promise of what `fn` answered
   */
  async run(what, fn) {
    log.debug('Entering Pkcs11Token.run(). ' + what);
    for (let attempt = 0; attempt < 2; attempt++) {
      let session;
      try {
        session = await this.acquire();
      } catch (e) {
        // A session that could not be opened for the same reason an
        // operation fails (the device went away) is the same outage, and
        // reconnects the same way; a refused PIN is not.
        const ckr = ckrOf(e) || Number(/** @type {any} */ (e).ckr) || 0;
        log.debug('Caught in Pkcs11Token.run(): ' + ((e && e.message) || e));
        if (attempt === 0 && RECONNECT_ON.has(ckr)) {
          try {
            await this.recover({ code: ckr, message: e.message });
          } catch (r) {
            throw refusal('STS-KEYS-0201', what + ' failed on ' +
                          this.describe() + ', and reconnecting failed', r);
          }
          continue;
        }
        log.debug('Leaving Pkcs11Token.run(). No session.');
        throw e;
      }
      try {
        const out = await this.bounded(what, session, fn(this.entry.lib,
                                                        session.h));
        this.release(session);
        log.debug('Leaving Pkcs11Token.run().');
        return out;
      } catch (e) {
        if (e && e.stsTimedOut) {
          // The session is still the module's: `bounded()` discards it
          // when the late answer comes.
          log.debug('Leaving Pkcs11Token.run(). Timed out.');
          throw e;
        }
        if (attempt === 0 && RECONNECT_ON.has(ckrOf(e))) {
          log.debug('Caught in Pkcs11Token.run(): ' + ((e && e.message) || e) +
                    '; reconnecting once.');
          this.discard(session);
          try {
            await this.recover(e, session.epoch, session.gen);
          } catch (r) {
            // The device is still away: the reconnect itself failed, which
            // is this operation's refusal, not a different one.
            throw refusal('STS-KEYS-0201', what + ' failed on ' +
                          this.describe() + ', and reconnecting failed', r);
          }
          continue;
        }
        this.release(session);
        log.debug('Leaving Pkcs11Token.run(). Refused.');
        throw errorCodes.codeOf(e) ? e : refusal(codeFor(e),
          what + ' failed on ' + this.describe(), e);
      }
    }
    log.debug('Leaving Pkcs11Token.run(). Unreachable.');
    throw refusal('STS-KEYS-0201', what + ' failed on ' + this.describe());
  }

  // -------------------------------------------------------------------------
  // AN OPERATION THAT DOES NOT ANSWER (#2220). The call itself runs in the
  // module, on libuv's pool, and nothing can stop it there; what can stop is
  // the WAITING. After `timeoutMs` the operation is refused (STS-KEYS-0216)
  // and its caller goes on, and the session it holds is not lent again: when
  // the module does answer, the session is discarded (closed, and a waiter
  // woken to open another), because a session whose operation outlived its
  // caller is in no known state. A synchronous call cannot be timed.
  // -------------------------------------------------------------------------
  bounded(what, session, pending) {
    log.debug('Entering Pkcs11Token.bounded().');
    const timeoutMs = this.timeoutMs;
    if (!timeoutMs || !pending || typeof pending.then !== 'function') {
      log.debug('Leaving Pkcs11Token.bounded(). Not timed.');
      return Promise.resolve(pending);
    }
    const self = this;
    log.debug('Leaving Pkcs11Token.bounded().');
    return new Promise(function (resolve, reject) {
      let late = false;
      const timer = setTimeout(function () {
        late = true;
        log.warn(errorCodes.tag('STS-KEYS-0216') + 'pkcs11: ' + what +
                 ' on ' + self.describe() + ' did not answer within ' +
                 timeoutMs + ' ms (keys.pkcs11TimeoutMs); it is refused, ' +
                 'and its session is discarded when the module answers.');
        const out = refusal('STS-KEYS-0216', what + ' on ' + self.describe() +
                            ' did not answer within ' + timeoutMs + ' ms');
        /** @type {any} */ (out).stsTimedOut = true;
        reject(out);
      }, timeoutMs);
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
      const settle = function () {
        if (late) {
          self.discard(session);
        }
      };
      pending.then(function (value) {
        clearTimeout(timer);
        settle();
        resolve(value);
      }, function (err) {
        clearTimeout(timer);
        settle();
        reject(err);
      });
    });
  }

  // The blocking session, opened once where it is not.
  blockingSession() {
    log.debug('Entering Pkcs11Token.blockingSession().');
    if (this.blocking && this.current(this.blocking)) {
      log.debug('Leaving Pkcs11Token.blockingSession(). Held.');
      return this.blocking;
    }
    if (this.blocking) {
      this.forgetSession(this.blocking);
      this.blocking = null;
    }
    this.blocking = this.openSessionSync();
    log.debug('Leaving Pkcs11Token.blockingSession(). Opened.');
    return this.blocking;
  }

  // A session the blocking door took, given back: the blocking one is kept,
  // an idle one goes back to the pool (or to a waiter).
  giveBackSync(session) {
    log.debug('Entering Pkcs11Token.giveBackSync().');
    if (session === this.blocking) {
      log.debug('Leaving Pkcs11Token.giveBackSync(). The blocking one.');
      return;
    }
    const next = this.waiters.shift();
    if (next) {
      this.lend(session);
      next(session);
    } else {
      this.idle.push(session);
    }
    log.debug('Leaving Pkcs11Token.giveBackSync().');
  }

  // A session the blocking door lost.
  dropSync(session) {
    log.debug('Entering Pkcs11Token.dropSync().');
    if (session === this.blocking) {
      this.blocking = null;
    }
    this.closeSession(session);
    log.debug('Leaving Pkcs11Token.dropSync().');
  }

  /**
   * Runs one operation synchronously — the event loop waits for the module —
   * on an idle session or the blocking one: the opt-in blocking door
   * (`keys.pkcs11SynchronousSign`), a key's first resolution in a thread and
   * the lookups made at start. Reconnects once after an outage; refused
   * (STS-KEYS-0212) while the module is being initialised again.
   *
   * @param what - what the operation is, for a refusal
   * @param fn - `(lib, session) => value`, `session` the binding's handle
   * @returns what `fn` answered
   */
  runSync(what, fn) {
    log.debug('Entering Pkcs11Token.runSync(). ' + what);
    if (this.entry.recovering) {
      log.debug('Leaving Pkcs11Token.runSync(). Reconnecting.');
      throw refusal('STS-KEYS-0212', what + ' was asked while ' +
                    this.describe() + ' is being initialised again');
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      const session = this.takeIdle() || this.blockingSession();
      try {
        const out = fn(this.entry.lib, session.h);
        this.giveBackSync(session);
        log.debug('Leaving Pkcs11Token.runSync().');
        return out;
      } catch (e) {
        if (attempt === 0 && RECONNECT_ON.has(ckrOf(e))) {
          log.debug('Caught in Pkcs11Token.runSync(): ' +
                    ((e && e.message) || e) + '; reconnecting once.');
          this.dropSync(session);
          try {
            this.recoverSync(e, what, session.epoch, session.gen);
          } catch (r) {
            // The device is still away: the reconnect itself failed, which
            // is this operation's refusal, not a different one.
            throw errorCodes.codeOf(r) === 'STS-KEYS-0212' ? r :
              refusal('STS-KEYS-0201', what + ' failed on ' +
                      this.describe() + ', and reconnecting failed', r);
          }
          continue;
        }
        this.giveBackSync(session);
        log.debug('Leaving Pkcs11Token.runSync(). Refused.');
        throw errorCodes.codeOf(e) ? e : refusal(codeFor(e),
          what + ' failed on ' + this.describe(), e);
      }
    }
    log.debug('Leaving Pkcs11Token.runSync(). Unreachable.');
    throw refusal('STS-KEYS-0201', what + ' failed on ' + this.describe());
  }

  /**
   * The mechanisms the token offers, with their flags, read once (at
   * `connect()`).
   *
   * @returns a Map of mechanism number to flags
   */
  mechanismFlags() {
    log.debug('Entering Pkcs11Token.mechanismFlags().');
    if (this.mechanisms) {
      log.debug('Leaving Pkcs11Token.mechanismFlags(). Held.');
      return this.mechanisms;
    }
    const lib = this.entry.lib;
    const out = new Map();
    let list = [];
    try {
      list = lib.C_GetMechanismList(this.slot) || [];
    } catch (e) {
      throw refusal('STS-KEYS-0204', describeMechFailure(this), e);
    }
    for (const m of list) {
      let flags = 0;
      try {
        flags = Number(lib.C_GetMechanismInfo(this.slot, m).flags) || 0;
      } catch (e) {
        // Listed and not described: counted as offered with no flags, which
        // no choice below accepts.
        log.debug('Caught in Pkcs11Token.mechanismFlags(): ' +
                  ((e && e.message) || e));
      }
      out.set(Number(m), flags);
    }
    this.mechanisms = out;
    log.debug('Leaving Pkcs11Token.mechanismFlags(). ' + out.size + '.');
    return out;
  }

  offers(mech, flags) {
    log.debug('Entering Pkcs11Token.offers().');
    const all = this.mechanismFlags();
    const has = all.has(mech) && (all.get(mech) & flags) === flags;
    log.debug('Leaving Pkcs11Token.offers(). ' + has);
    return has;
  }

  // -------------------------------------------------------------------------
  // OBJECTS
  // -------------------------------------------------------------------------
  /**
   * The handle of a key this token found before, found again ON THE SESSION
   * GIVEN when the login it was found under has gone (see `generation`) —
   * for the blocking door, which holds that session already.
   *
   * @param key - `{ template, handle, generation, what }`
   * @param lib - the module
   * @param session - the binding's handle of the session the caller holds
   * @returns the handle
   */
  handleOf(key, lib, session) {
    log.debug('Entering Pkcs11Token.handleOf().');
    if (key.generation === this.generation && key.handle !== null) {
      log.debug('Leaving Pkcs11Token.handleOf(). Held.');
      return key.handle;
    }
    const found = findOn(lib, session, key.template);
    if (found.length !== 1) {
      throw this.keyGone(key, found.length);
    }
    key.handle = found[0];
    key.generation = this.generation;
    log.debug('Leaving Pkcs11Token.handleOf(). Found again.');
    return key.handle;
  }

  // The refusal a key that is no longer (or no longer once) on the token is.
  keyGone(key, count) {
    log.debug('Entering Pkcs11Token.keyGone().');
    log.debug('Leaving Pkcs11Token.keyGone().');
    return refusal('STS-KEYS-0203', key.what + ' is ' +
      (count ? 'no longer unique' : 'no longer') + ' on ' + this.describe());
  }

  /**
   * A keyed control call off the event loop (`CONTROL_OPS`' `begin`,
   * `locate`, `kwpWrap`, `kwpUnwrap`) on the session the operation holds:
   * the key's handle is passed where it is still good and found again by
   * the call where it is not, and kept.
   *
   * @param op - the call
   * @param session - the binding's handle of the session
   * @param key - `{ template, handle, generation, what }`
   * @param args - the call's other arguments
   * @returns a promise of the call's value
   */
  async keyed(op, session, key, args) {
    log.debug('Entering Pkcs11Token.keyed(). ' + op);
    const generation = this.generation;
    const held = key.generation === generation && key.handle !== null
      ? key.handle : null;
    let out;
    try {
      out = await this.entry.control.call(op,
        [session, { handle: held, template: key.template }].concat(args));
    } catch (e) {
      log.debug('Caught in Pkcs11Token.keyed(): ' + ((e && e.message) || e));
      if (e && e.notFound !== undefined) {
        throw this.keyGone(key, Number(e.notFound));
      }
      throw e;
    }
    if (held === null) {
      key.handle = out.handle;
      key.generation = generation;
    }
    log.debug('Leaving Pkcs11Token.keyed().');
    return out.value;
  }

  /**
   * Finds objects by a template, synchronously.
   *
   * @param template - PKCS#11 attributes
   * @returns the handles
   */
  find(template) {
    log.debug('Entering Pkcs11Token.find().');
    const found = this.runSync('a search', function (lib, session) {
      return findOn(lib, session, template);
    });
    log.debug('Leaving Pkcs11Token.find(). ' + found.length + '.');
    return found;
  }

  /**
   * Finds objects by a template, off the event loop.
   *
   * @param template - PKCS#11 attributes
   * @returns a promise of the handles
   */
  findAsync(template) {
    log.debug('Entering Pkcs11Token.findAsync().');
    const control = this.entry.control;
    log.debug('Leaving Pkcs11Token.findAsync().');
    return this.run('a search', function (lib, session) {
      return control.call('find', [session, template]);
    });
  }

  /**
   * Reads attributes of one object, synchronously.
   *
   * @param handle - the object
   * @param types - the attribute numbers
   * @returns a Map of attribute number to its bytes (absent when refused)
   */
  attributes(handle, types) {
    log.debug('Entering Pkcs11Token.attributes().');
    const got = this.runSync('an attribute read', function (lib, s) {
      return CONTROL_OPS.attributes(lib, s, handle, types);
    });
    log.debug('Leaving Pkcs11Token.attributes().');
    return new Map(got);
  }

  /**
   * Reads attributes of one object, off the event loop.
   *
   * @param handle - the object
   * @param types - the attribute numbers
   * @returns a promise of a Map of attribute number to its bytes
   */
  async attributesAsync(handle, types) {
    log.debug('Entering Pkcs11Token.attributesAsync().');
    const control = this.entry.control;
    const got = await this.run('an attribute read', function (lib, s) {
      return control.call('attributes', [s, handle, types]);
    });
    log.debug('Leaving Pkcs11Token.attributesAsync().');
    return new Map(got);
  }

  // -------------------------------------------------------------------------
  // THE KEY-ENCRYPTION KEY
  // -------------------------------------------------------------------------
  /**
   * Finds the AES (or YubiHSM wrap) key a key-encryption key is, by label
   * and/or id, and checks it is fit: a secret key, of 32 bytes where the
   * module says, and NOT extractable. With `generate`, makes it when it is
   * absent.
   *
   * @param ref - `{ label, id (Buffer|null), generate }`
   * @returns `{ key, keyType, generated }`, `key` what the operations take
   */
  secretKey(ref) {
    log.debug('Entering Pkcs11Token.secretKey().');
    /** @type {Array<{ type: number, value?: any }>} */
    const template = [{ type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY }];
    if (ref.label) {
      template.push({ type: CK.CKA_LABEL, value: String(ref.label) });
    }
    if (ref.id) {
      template.push({ type: CK.CKA_ID, value: Buffer.from(ref.id) });
    }
    let found = this.find(template);
    let generated = false;
    if (!found.length && ref.generate) {
      found = [this.generateAesKey(ref)];
      generated = true;
    }
    if (found.length !== 1) {
      throw refusal('STS-KEYS-0203', (found.length ? 'more than one' : 'no') +
        ' secret key on ' + this.describe() + ' is ' + refText(ref) +
        (found.length ? '. Give it an id (CKA_ID) and name it by that.' :
          '. Create it with the HSM\'s own tool (yubihsm-shell, ' +
          'softhsm2-util with pkcs11-tool) or turn on ' +
          'keys.pkcs11GenerateKey for a first start.'));
    }
    const handle = found[0];
    const a = this.attributes(handle, [CK.CKA_KEY_TYPE, CK.CKA_VALUE_LEN,
                                       CK.CKA_EXTRACTABLE]);
    const keyType = a.has(CK.CKA_KEY_TYPE) ? attrUlong(a.get(CK.CKA_KEY_TYPE))
                                           : -1;
    if (a.has(CK.CKA_EXTRACTABLE) && attrTrue(a.get(CK.CKA_EXTRACTABLE))) {
      throw refusal('STS-KEYS-0203', 'the key ' + refText(ref) + ' on ' +
        this.describe() + ' is EXTRACTABLE. A key-encryption key that can ' +
        'leave the HSM is not one this service will wrap under; make it ' +
        'again with CKA_EXTRACTABLE false.');
    }
    if (keyType === CK.CKK_AES && a.has(CK.CKA_VALUE_LEN) &&
        attrUlong(a.get(CK.CKA_VALUE_LEN)) !== 32) {
      throw refusal('STS-KEYS-0203', 'the key ' + refText(ref) + ' on ' +
        this.describe() + ' is AES-' +
        (attrUlong(a.get(CK.CKA_VALUE_LEN)) * 8) + '; a key-encryption key ' +
        'here is AES-256.');
    }
    log.debug('Leaving Pkcs11Token.secretKey().');
    return { key: { template: template, handle: handle,
                    generation: this.generation,
                    what: 'the key-encryption key ' + refText(ref) },
             keyType: keyType, generated: generated };
  }

  generateAesKey(ref) {
    log.debug('Entering Pkcs11Token.generateAesKey().');
    /** @type {Array<{ type: number, value?: any }>} */
    const template = [
      { type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
      { type: CK.CKA_KEY_TYPE, value: CK.CKK_AES },
      { type: CK.CKA_TOKEN, value: true },
      { type: CK.CKA_PRIVATE, value: true },
      { type: CK.CKA_SENSITIVE, value: true },
      { type: CK.CKA_EXTRACTABLE, value: false },
      { type: CK.CKA_ENCRYPT, value: true },
      { type: CK.CKA_DECRYPT, value: true },
      { type: CK.CKA_WRAP, value: true },
      { type: CK.CKA_UNWRAP, value: true },
      { type: CK.CKA_VALUE_LEN, value: 32 }
    ];
    if (ref.label) {
      template.push({ type: CK.CKA_LABEL, value: String(ref.label) });
    }
    if (ref.id) {
      template.push({ type: CK.CKA_ID, value: Buffer.from(ref.id) });
    }
    const handle = this.runSync('generating the key-encryption key',
      function (lib, session) {
        return lib.C_GenerateKey(session, { mechanism: CK.CKM_AES_KEY_GEN },
                                 template);
      });
    log.info('pkcs11: an AES-256 key-encryption key ' + refText(ref) +
             ' was generated on ' + this.describe() + ', non-extractable.');
    log.debug('Leaving Pkcs11Token.generateAesKey().');
    return handle;
  }

  /**
   * Chooses how a key-encryption key wraps: the configured mechanism if the
   * token offers it, else (for `auto`) GCM, then KWP, then the YubiHSM's
   * CCM wrap.
   *
   * @param wanted - `auto`, `aes-gcm`, `aes-key-wrap-pad` or
   *   `yubico-aes-ccm-wrap`
   * @param keyType - the key's CKA_KEY_TYPE, -1 when unknown
   * @returns the tag: `g1`, `k1` or `y1`
   */
  wrapMechanism(wanted, keyType) {
    log.debug('Entering Pkcs11Token.wrapMechanism(). ' + wanted);
    const aes = keyType === CK.CKK_AES || keyType === -1;
    const can = {
      g1: aes && this.offers(CK.CKM_AES_GCM, CK.CKF_ENCRYPT | CK.CKF_DECRYPT),
      k1: aes && this.offers(CK.CKM_AES_KEY_WRAP_PAD,
                             CK.CKF_WRAP | CK.CKF_UNWRAP),
      y1: this.mechanismFlags().has(CK.CKM_YUBICO_AES_CCM_WRAP)
    };
    const byName = { 'aes-gcm': 'g1', 'aes-key-wrap-pad': 'k1',
                     'yubico-aes-ccm-wrap': 'y1' };
    let tag = null;
    if (byName[wanted]) {
      tag = can[byName[wanted]] ? byName[wanted] : null;
    } else {
      tag = can.g1 ? 'g1' : can.k1 ? 'k1' : can.y1 ? 'y1' : null;
    }
    if (!tag) {
      throw refusal('STS-KEYS-0204', describeMechFailure(this) +
        (byName[wanted] ? ' It does not offer ' + wanted + ' for this key.'
                        : ' It offers none of CKM_AES_GCM (encrypt), ' +
                          'CKM_AES_KEY_WRAP_PAD (wrap) or ' +
                          'CKM_YUBICO_AES_CCM_WRAP for this key.'));
    }
    log.debug('Leaving Pkcs11Token.wrapMechanism(). ' + tag);
    return tag;
  }

  /**
   * Wraps a data key under a key-encryption key in the HSM.
   *
   * @param key - the key-encryption key, as `secretKey()` answered it
   * @param tag - `g1`, `k1` or `y1` (`wrapMechanism()`)
   * @param dek - the data key
   * @param aad - the data key's additional authenticated data
   * @returns a promise of the stored text (`<tag>.<…>`)
   */
  wrapData(key, tag, dek, aad) {
    log.debug('Entering Pkcs11Token.wrapData(). ' + tag);
    const binding = this.binding;
    const self = this;
    const plain = Buffer.from(dek);
    if (tag === 'g1') {
      const iv = nodeCrypto.randomBytes(12);
      log.debug('Leaving Pkcs11Token.wrapData(). GCM.');
      return this.run('a wrap', async function (lib, session) {
        await self.keyed('begin', session, key,
                         ['Encrypt', gcmMechanism(binding, iv, aad)]);
        return encryptAsync(lib, session, plain, plain.length + 64);
      }).then(function (ct) {
        return 'g1.' + b64u(iv) + '.' + b64u(ct);
      });
    }
    const bound = Buffer.concat([plain, aadDigest(aad)]);
    if (tag === 'y1') {
      log.debug('Leaving Pkcs11Token.wrapData(). YubiHSM CCM wrap.');
      return this.run('a wrap', async function (lib, session) {
        await self.keyed('begin', session, key,
          ['Encrypt', { mechanism: CK.CKM_YUBICO_AES_CCM_WRAP }]);
        return encryptAsync(lib, session, bound, bound.length + 64);
      }).then(function (blob) {
        return 'y1.' + b64u(blob);
      });
    }
    // KWP: the session object, C_WrapKey and C_DestroyObject are made
    // together by the control thread, off the event loop.
    log.debug('Leaving Pkcs11Token.wrapData(). KWP.');
    return this.run('a wrap', function (lib, session) {
      return self.keyed('kwpWrap', session, key,
                        [sessionSecret(bound), bound.length + 16]);
    }).then(function (wrapped) {
      return 'k1.' + b64u(wrapped);
    });
  }

  /**
   * Unwraps what `wrapData()` made, by the text's own tag.
   *
   * @param key - the key-encryption key, as `secretKey()` answered it
   * @param text - `<tag>.<…>`
   * @param aad - the data key's additional authenticated data
   * @returns a promise of the data key
   */
  unwrapData(key, text, aad) {
    log.debug('Entering Pkcs11Token.unwrapData().');
    const binding = this.binding;
    const self = this;
    const parts = String(text || '').split('.');
    if (parts[0] === 'g1' && parts.length === 3) {
      const iv = Buffer.from(parts[1], 'base64url');
      const ct = Buffer.from(parts[2], 'base64url');
      log.debug('Leaving Pkcs11Token.unwrapData(). GCM.');
      return this.run('an unwrap', async function (lib, session) {
        await self.keyed('begin', session, key,
                         ['Decrypt', gcmMechanism(binding, iv, aad)]);
        return decryptAsync(lib, session, ct, ct.length + 16);
      }).then(function (plain) {
        return Buffer.from(plain);
      });
    }
    if (parts[0] === 'y1' && parts.length === 2) {
      const blob = Buffer.from(parts[1], 'base64url');
      log.debug('Leaving Pkcs11Token.unwrapData(). YubiHSM CCM wrap.');
      return this.run('an unwrap', async function (lib, session) {
        await self.keyed('begin', session, key,
          ['Decrypt', { mechanism: CK.CKM_YUBICO_AES_CCM_WRAP }]);
        return decryptAsync(lib, session, blob, blob.length + 16);
      }).then(function (plain) {
        return splitBound(plain, aad);
      });
    }
    if (parts[0] === 'k1' && parts.length === 2) {
      const wrapped = Buffer.from(parts[1], 'base64url');
      log.debug('Leaving Pkcs11Token.unwrapData(). KWP.');
      return this.run('an unwrap', function (lib, session) {
        return self.keyed('kwpUnwrap', session, key,
                          [wrapped, sessionSecret(null)]);
      }).then(function (plain) {
        return splitBound(plain, aad);
      });
    }
    log.debug('Leaving Pkcs11Token.unwrapData(). Not ours.');
    return Promise.reject(refusal('STS-KEYS-0201', 'the wrapped data key ' +
      'is in no PKCS#11 format this service knows (' +
      String(parts[0]).slice(0, 4) + ')'));
  }

  // -------------------------------------------------------------------------
  // SIGNING KEYS
  // -------------------------------------------------------------------------
  /**
   * Generates a signing key pair in the token: the private half sensitive and
   * non-extractable, both halves token objects under one label and id.
   *
   * @param spec - `{ kty: 'RSA', bits }` or `{ kty: 'EC'|'OKP', crv }`
   * @param label - CKA_LABEL for both halves
   * @param id - CKA_ID for both halves (bytes)
   * @returns `{ key, publicKey }`: what `sign()` takes, and the public key
   *   as a node KeyObject
   */
  generateKeyPair(spec, label, id) {
    log.debug('Entering Pkcs11Token.generateKeyPair(). ' + spec.kty);
    const plan = this.keyPairPlan(spec, label, id);
    const pair = this.runSync('generating a signing key',
      function (lib, session) {
        return lib.C_GenerateKeyPair(session, { mechanism: plan.mech },
                                     plan.pub, plan.priv);
      });
    const publicKey = this.publicKeyOf(pair.publicKey, spec);
    log.debug('Leaving Pkcs11Token.generateKeyPair().');
    return { key: this.privateKeyRef(id, pair.privateKey),
             publicKey: publicKey };
  }

  /**
   * The same as `generateKeyPair()`, with the generation off the event loop
   * where the binding offers C_GenerateKeyPairAsync — an RSA key in a
   * YubiHSM 2 takes seconds.
   *
   * @param spec - as for `generateKeyPair()`
   * @param label - CKA_LABEL
   * @param id - CKA_ID
   * @returns a promise of `{ key, publicKey }`
   */
  async generateKeyPairAsync(spec, label, id) {
    log.debug('Entering Pkcs11Token.generateKeyPairAsync(). ' + spec.kty);
    const plan = this.keyPairPlan(spec, label, id);
    const control = this.entry.control;
    // The public half's attributes are read by the control thread on the
    // same session, so nothing of the generation waits on the event loop.
    const made = await this.run('generating a signing key',
      async function (lib, session) {
        const pair = typeof lib.C_GenerateKeyPairAsync === 'function'
          ? await lib.C_GenerateKeyPairAsync(session,
            { mechanism: plan.mech }, plan.pub, plan.priv)
          : lib.C_GenerateKeyPair(session, { mechanism: plan.mech },
                                  plan.pub, plan.priv);
        const attrs = await control.call('attributes',
          [session, pair.publicKey, publicTypes(spec)]);
        return { pair: pair, attrs: new Map(attrs) };
      });
    const pair = made.pair;
    const publicKey = this.publicKeyFrom(made.attrs, spec);
    log.debug('Leaving Pkcs11Token.generateKeyPairAsync().');
    return { key: this.privateKeyRef(id, pair.privateKey),
             publicKey: publicKey };
  }

  // The templates and mechanism a key pair is made with.
  keyPairPlan(spec, label, id) {
    log.debug('Entering Pkcs11Token.keyPairPlan(). ' + spec.kty);
    /** @type {Array<{ type: number, value?: any }>} */
    const common = [{ type: CK.CKA_TOKEN, value: true },
                    { type: CK.CKA_LABEL, value: String(label) },
                    { type: CK.CKA_ID, value: Buffer.from(id) }];
    const pub = common.concat([{ type: CK.CKA_VERIFY, value: true }]);
    const priv = common.concat([
      { type: CK.CKA_PRIVATE, value: true },
      { type: CK.CKA_SENSITIVE, value: true },
      { type: CK.CKA_EXTRACTABLE, value: false },
      { type: CK.CKA_SIGN, value: true }]);
    let mech;
    // THE REALM'S SIGNING KEYS ARE ITS DECRYPTION KEYS TOO (#1955 P8
    // follow-up): this service models one RSA key per unit that signs AND
    // opens what a partner encrypted to its certificate (`helpers.js`'s
    // `ownRsaDecryptionKeys()` — XML Encryption, a JWE assertion), and its
    // P-256/P-384/P-521 keys answer ECDH-ES. So an RSA pair is made with
    // CKA_DECRYPT (used with CKM_RSA_PKCS_OAEP only) and a NIST-curve pair
    // with CKA_DERIVE (CKM_ECDH1_DERIVE); still never extractable.
    if (spec.kty === 'RSA') {
      priv.push({ type: CK.CKA_DECRYPT, value: true });
      pub.push({ type: CK.CKA_ENCRYPT, value: true });
    } else if (spec.kty === 'EC' && /^P-/.test(String(spec.crv))) {
      priv.push({ type: CK.CKA_DERIVE, value: true });
    }
    let named = 'RSA';
    if (spec.kty === 'RSA') {
      mech = CK.CKM_RSA_PKCS_KEY_PAIR_GEN;
      pub.push({ type: CK.CKA_MODULUS_BITS, value: Number(spec.bits) || 3072 },
               { type: CK.CKA_PUBLIC_EXPONENT,
                 value: Buffer.from([1, 0, 1]) });
    } else if (spec.kty === 'AKP') {
      const row = pqRowOf(spec.alg);
      named = String(spec.alg || '');
      if (!row) {
        throw refusal('STS-KEYS-0207', 'no ML-DSA or SLH-DSA key can be ' +
                      'made in the HSM for "' + named + '"');
      }
      mech = row.gen;
      pub.push({ type: CK.CKA_PARAMETER_SET, value: row.set });
      priv.push({ type: CK.CKA_PARAMETER_SET, value: row.set });
    } else {
      const curve = CURVES[spec.crv];
      named = String(spec.crv || '');
      if (!curve) {
        throw refusal('STS-KEYS-0207', 'no key can be made in the HSM on ' +
                      'the curve "' + spec.crv + '"');
      }
      mech = curve.edwards ? CK.CKM_EC_EDWARDS_KEY_PAIR_GEN :
                             CK.CKM_EC_KEY_PAIR_GEN;
      pub.push({ type: CK.CKA_EC_PARAMS, value: Buffer.from(curve.oid,
                                                            'hex') });
    }
    if (!this.mechanismFlags().has(mech)) {
      throw refusal('STS-KEYS-0207', describeMechFailure(this) + ' It ' +
        'cannot generate a ' + named + ' key pair.');
    }
    log.debug('Leaving Pkcs11Token.keyPairPlan().');
    return { mech: mech, pub: pub, priv: priv };
  }

  /**
   * Whether this token can make a key pair of this kind.
   *
   * @param spec - `{ kty: 'RSA' }` or `{ kty, crv }`
   * @returns true where the generation mechanism is offered
   */
  canGenerate(spec) {
    log.debug('Entering Pkcs11Token.canGenerate().');
    let mech = Number(CK.CKM_RSA_PKCS_KEY_PAIR_GEN);
    if (spec.kty === 'AKP') {
      const row = pqRowOf(spec.alg);
      if (!row) {
        log.debug('Leaving Pkcs11Token.canGenerate(). No such ML-DSA or ' +
                  'SLH-DSA set.');
        return false;
      }
      // A post-quantum key is made here only where the token can also SIGN
      // with it (#2220): a key it could make and not use would leave the
      // realm's published key unable to sign anything.
      const both = this.mechanismFlags().has(row.gen) &&
        this.offers(row.sign, CK.CKF_SIGN);
      log.debug('Leaving Pkcs11Token.canGenerate(). ' + both);
      return both;
    } else if (spec.kty !== 'RSA') {
      const curve = CURVES[spec.crv];
      if (!curve) {
        log.debug('Leaving Pkcs11Token.canGenerate(). No such curve here.');
        return false;
      }
      mech = curve.edwards ? CK.CKM_EC_EDWARDS_KEY_PAIR_GEN :
                             CK.CKM_EC_KEY_PAIR_GEN;
    }
    const has = this.mechanismFlags().has(mech);
    log.debug('Leaving Pkcs11Token.canGenerate(). ' + has);
    return has;
  }

  /**
   * Finds a signing key pair by its CKA_ID: the private half, as `sign()`
   * takes it, and the public half as a node KeyObject.
   *
   * @param id - CKA_ID (bytes)
   * @param spec - what the key should be: `{ kty, crv }`
   * @returns `{ key, publicKey }`
   */
  keyPair(id, spec) {
    log.debug('Entering Pkcs11Token.keyPair().');
    const idBuf = Buffer.from(id);
    const priv = this.find([{ type: CK.CKA_CLASS, value: CK.CKO_PRIVATE_KEY },
                            { type: CK.CKA_ID, value: idBuf }]);
    const pub = this.find([{ type: CK.CKA_CLASS, value: CK.CKO_PUBLIC_KEY },
                           { type: CK.CKA_ID, value: idBuf }]);
    if (priv.length !== 1 || pub.length !== 1) {
      throw refusal('STS-KEYS-0203', 'the signing key ' + b64u(idBuf) +
        ' is not on ' + this.describe() + ' (' + priv.length + ' private, ' +
        pub.length + ' public half/halves)');
    }
    const publicKey = this.publicKeyOf(pub[0], spec);
    log.debug('Leaving Pkcs11Token.keyPair().');
    return { key: this.privateKeyRef(idBuf, priv[0]), publicKey: publicKey };
  }

  /**
   * `keyPair()`, off the event loop: both searches and the public half's
   * attributes made by the control thread, on one session.
   *
   * @param id - CKA_ID (bytes)
   * @param spec - what the key should be: `{ kty, crv }`
   * @returns a promise of `{ key, publicKey }`
   */
  async keyPairAsync(id, spec) {
    log.debug('Entering Pkcs11Token.keyPairAsync().');
    const idBuf = Buffer.from(id);
    const control = this.entry.control;
    const got = await this.run('a search', async function (lib, session) {
      const priv = await control.call('find', [session,
        [{ type: CK.CKA_CLASS, value: CK.CKO_PRIVATE_KEY },
         { type: CK.CKA_ID, value: idBuf }]]);
      const pub = await control.call('find', [session,
        [{ type: CK.CKA_CLASS, value: CK.CKO_PUBLIC_KEY },
         { type: CK.CKA_ID, value: idBuf }]]);
      const attrs = pub.length === 1
        ? await control.call('attributes', [session, pub[0],
                                            publicTypes(spec)])
        : [];
      return { priv: priv, pub: pub, attrs: new Map(attrs) };
    });
    if (got.priv.length !== 1 || got.pub.length !== 1) {
      throw refusal('STS-KEYS-0203', 'the signing key ' + b64u(idBuf) +
        ' is not on ' + this.describe() + ' (' + got.priv.length +
        ' private, ' + got.pub.length + ' public half/halves)');
    }
    const publicKey = this.publicKeyFrom(got.attrs, spec);
    log.debug('Leaving Pkcs11Token.keyPairAsync().');
    return { key: this.privateKeyRef(idBuf, got.priv[0]),
             publicKey: publicKey };
  }

  privateKeyRef(id, handle) {
    log.debug('Entering Pkcs11Token.privateKeyRef().');
    log.debug('Leaving Pkcs11Token.privateKeyRef().');
    return { template: [{ type: CK.CKA_CLASS, value: CK.CKO_PRIVATE_KEY },
                        { type: CK.CKA_ID, value: Buffer.from(id) }],
             handle: handle, generation: this.generation,
             what: 'the signing key ' + b64u(id) };
  }

  publicKeyOf(handle, spec) {
    log.debug('Entering Pkcs11Token.publicKeyOf().');
    const out = this.publicKeyFrom(this.attributes(handle, publicTypes(spec)),
                                   spec);
    log.debug('Leaving Pkcs11Token.publicKeyOf().');
    return out;
  }

  /**
   * A public key from the attributes its object answered
   * (`publicTypes()`), however they were read.
   *
   * @param a - a Map of attribute number to its bytes
   * @param spec - `{ kty, crv }` or `{ kty: 'AKP', alg }`
   * @returns the public key
   */
  publicKeyFrom(a, spec) {
    log.debug('Entering Pkcs11Token.publicKeyFrom().');
    if (spec.kty === 'AKP') {
      const made = this.mlDsaPublicKeyFrom(a.get(CK.CKA_VALUE), spec);
      log.debug('Leaving Pkcs11Token.publicKeyFrom(). ML-DSA.');
      return made;
    }
    let jwk;
    if (spec.kty === 'RSA') {
      if (!a.has(CK.CKA_MODULUS) || !a.has(CK.CKA_PUBLIC_EXPONENT)) {
        throw refusal('STS-KEYS-0207', 'the HSM did not answer an RSA ' +
                      'public key\'s modulus and exponent');
      }
      jwk = { kty: 'RSA', n: b64u(a.get(CK.CKA_MODULUS)),
              e: b64u(a.get(CK.CKA_PUBLIC_EXPONENT)) };
    } else {
      const curve = CURVES[spec.crv];
      if (!curve || !a.has(CK.CKA_EC_POINT)) {
        throw refusal('STS-KEYS-0207', 'the HSM did not answer the public ' +
                      'point of a ' + spec.crv + ' key');
      }
      const point = ecPointOf(a.get(CK.CKA_EC_POINT));
      if (curve.edwards) {
        jwk = { kty: 'OKP', crv: spec.crv, x: b64u(point) };
      } else {
        if (point[0] !== 0x04 || point.length !== 1 + 2 * curve.size) {
          throw refusal('STS-KEYS-0207', 'the HSM answered a ' + spec.crv +
                        ' point that is not uncompressed');
        }
        jwk = { kty: 'EC', crv: spec.crv,
                x: b64u(point.subarray(1, 1 + curve.size)),
                y: b64u(point.subarray(1 + curve.size)) };
      }
    }
    const key = nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' });
    log.debug('Leaving Pkcs11Token.publicKeyFrom().');
    return key;
  }

  /**
   * Signs with a private key in the token, off the event loop where the
   * binding computes asynchronously.
   *
   * @param key - the private key, as `keyPair()` answered it
   * @param alg - the JWS algorithm
   * @param data - the signing input
   * @returns a promise of the JOSE-encoded signature
   */
  sign(key, alg, data) {
    log.debug('Entering Pkcs11Token.sign(). ' + alg);
    const plan = signingPlan(this.binding, alg, data);
    const refused = this.mlDsaOfferProblem(plan);
    if (refused) {
      log.debug('Leaving Pkcs11Token.sign(). Refused.');
      throw refused;
    }
    const self = this;
    log.debug('Leaving Pkcs11Token.sign().');
    return this.run('a signature', async function (lib, session) {
      if (typeof lib.C_SignAsync !== 'function' &&
          !synchronousSignAllowed()) {
        // No asynchronous sign, and blocking C_Sign is off. Refuse before
        // C_SignInit so the session is not left mid-operation.
        throw refusal('STS-KEYS-0209', 'synchronous PKCS#11 signing is ' +
                      'off (keys.pkcs11SynchronousSign), and this module ' +
                      'has no asynchronous C_Sign');
      }
      // C_SignInit (and the key's search, where its handle went with a
      // login) by the control thread, on this session; C_SignAsync here.
      await self.keyed('begin', session, key, ['Sign', plan.mechanism]);
      if (typeof lib.C_SignAsync === 'function') {
        return lib.C_SignAsync(session, plan.input,
                               Buffer.alloc(SIGN_ROOM));
      }
      return lib.C_Sign(session, plan.input, Buffer.alloc(SIGN_ROOM));
    }).then(function (sig) {
      return Buffer.from(sig);
    });
  }

  /**
   * Signs synchronously — the event loop waits for the HSM — for the
   * synchronous signing door, only while `keys.pkcs11SynchronousSign` is
   * on. Off, this refuses (`STS-KEYS-0209`) and does not call the token.
   *
   * @param key - the private key, as `keyPair()` answered it
   * @param alg - the JWS algorithm
   * @param data - the signing input
   * @returns the JOSE-encoded signature
   */
  signSync(key, alg, data) {
    log.debug('Entering Pkcs11Token.signSync(). ' + alg);
    if (!synchronousSignAllowed()) {
      log.debug('Leaving Pkcs11Token.signSync(). Refused.');
      throw refusal('STS-KEYS-0209', 'synchronous PKCS#11 signing is ' +
                    'off (keys.pkcs11SynchronousSign)');
    }
    const plan = signingPlan(this.binding, alg, data);
    const refused = this.mlDsaOfferProblem(plan);
    if (refused) {
      log.debug('Leaving Pkcs11Token.signSync(). Refused.');
      throw refused;
    }
    const self = this;
    const sig = this.runSync('a signature', function (lib, session) {
      lib.C_SignInit(session, plan.mechanism,
                     self.handleOf(key, lib, session));
      return lib.C_Sign(session, plan.input, Buffer.alloc(SIGN_ROOM));
    });
    log.debug('Leaving Pkcs11Token.signSync().');
    return Buffer.from(sig);
  }

  /**
   * Decrypts with an RSA private key in the token, RSA-OAEP only (PKCS#1
   * v1.5 is never asked of an HSM key: the module cannot do OpenSSL's
   * implicit rejection, so its failure would be a padding oracle).
   *
   * @param key - the private key, as `keyPair()` answered it
   * @param hash - the OAEP digest (sha1, sha224, sha256, sha384, sha512);
   *   MGF1 over the same digest, as XML Encryption and JOSE use it
   * @param label - the OAEP label, or undefined
   * @param data - the ciphertext
   * @param async - true for a promise, off the event loop
   * @returns the plaintext, or a promise of it
   */
  decryptOaep(key, hash, label, data, async) {
    log.debug('Entering Pkcs11Token.decryptOaep(). ' + hash);
    const pair = OAEP[String(hash)];
    if (!pair) {
      throw refusal('STS-KEYS-0206', 'the HSM does not decrypt RSA-OAEP ' +
                    'over "' + hash + '"');
    }
    const binding = this.binding;
    const self = this;
    const mechanism = { mechanism: CK.CKM_RSA_PKCS_OAEP,
      parameter: { type: binding.CK_PARAMS_RSA_OAEP, hashAlg: pair[0],
                   mgf: pair[1], source: CK.CKZ_DATA_SPECIFIED,
                   sourceData: label && label.length ? Buffer.from(label)
                                                     : undefined } };
    const input = Buffer.from(data);
    // A BLOCKING C_Decrypt — asked synchronously, or by a module with no
    // C_DecryptAsync — only while keys.pkcs11SynchronousSign is on
    // (#1955 P8 follow-up); otherwise STS-KEYS-0209, before C_DecryptInit.
    if (!async && !synchronousSignAllowed()) {
      log.debug('Leaving Pkcs11Token.decryptOaep(). Refused.');
      throw refusal('STS-KEYS-0209', 'a blocking PKCS#11 decryption is off ' +
                    '(keys.pkcs11SynchronousSign); use the asynchronous door');
    }
    const noAsync = function (lib) {
      if (typeof lib.C_DecryptAsync !== 'function' &&
          !synchronousSignAllowed()) {
        throw refusal('STS-KEYS-0209', 'a blocking PKCS#11 decryption is ' +
                      'off (keys.pkcs11SynchronousSign), and this module ' +
                      'has no asynchronous C_Decrypt');
      }
    };
    // Off the loop: C_DecryptInit by the control thread, C_DecryptAsync
    // here. In place (the opt-in): both here.
    const op = async ? async function (lib, session) {
      noAsync(lib);
      await self.keyed('begin', session, key, ['Decrypt', mechanism]);
      return decryptAsync(lib, session, input, input.length);
    } : function (lib, session) {
      noAsync(lib);
      lib.C_DecryptInit(session, mechanism, self.handleOf(key, lib, session));
      return lib.C_Decrypt(session, input, Buffer.alloc(input.length));
    };
    // A MODULE THAT DOES NOT DO THIS DIGEST answers CKR_ARGUMENTS_BAD or
    // CKR_MECHANISM_PARAM_INVALID — SoftHSM2 2.6 offers OAEP over SHA-1
    // only (measured) — which is STS-KEYS-0207, a limit of the module, and
    // not a failure of the device.
    const describe = this.describe();
    const limited = function (e) {
      const ckr = /** @type {any} */ (e).ckr;
      if (ckr === 0x7 || ckr === 0x71) {
        return refusal('STS-KEYS-0207', 'the PKCS#11 module on ' + describe +
          ' does not decrypt RSA-OAEP over ' + hash + ' (SoftHSM2 2.6 ' +
          'offers SHA-1 only)');
      }
      return e;
    };
    log.debug('Leaving Pkcs11Token.decryptOaep().');
    if (async) {
      return this.run('an RSA-OAEP decryption', op).then(function (out) {
        return Buffer.from(out);
      }, function (e) {
        throw limited(e);
      });
    }
    try {
      return Buffer.from(this.runSync('an RSA-OAEP decryption', op));
    } catch (e) {
      log.debug('Caught in Pkcs11Token.decryptOaep(): ' +
                ((e && e.message) || e));
      throw limited(e);
    }
  }

  /**
   * ECDH with an EC private key in the token: the shared secret Z (the
   * x-coordinate), which the caller's KDF (JOSE's or XML's Concat KDF)
   * turns into a key. The secret comes back as a short-lived session object
   * that is read and destroyed.
   *
   * @param key - the private key, as `keyPair()` answered it
   * @param point - the other party's uncompressed point (0x04 || x || y)
   * @param bytes - the secret's length (the curve's field size)
   * @param async - true for a promise, off the event loop
   * @returns Z, or a promise of it
   */
  deriveEcdh(key, point, bytes, async) {
    log.debug('Entering Pkcs11Token.deriveEcdh().');
    const binding = this.binding;
    const self = this;
    const mechanism = { mechanism: CK.CKM_ECDH1_DERIVE,
      parameter: { type: binding.CK_PARAMS_EC_DH, kdf: CK.CKD_NULL,
                   publicData: Buffer.from(point) } };
    /** @type {Array<{ type: number, value?: any }>} */
    const template = [
      { type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
      { type: CK.CKA_KEY_TYPE, value: CK.CKK_GENERIC_SECRET },
      { type: CK.CKA_TOKEN, value: false },
      { type: CK.CKA_SENSITIVE, value: false },
      { type: CK.CKA_EXTRACTABLE, value: true },
      { type: CK.CKA_VALUE_LEN, value: Number(bytes) }];
    const control = this.entry.control;
    // A blocking C_DeriveKey only while keys.pkcs11SynchronousSign is on,
    // as for decryptOaep().
    if (!async && !synchronousSignAllowed()) {
      log.debug('Leaving Pkcs11Token.deriveEcdh(). Refused.');
      throw refusal('STS-KEYS-0209', 'a blocking PKCS#11 key agreement is ' +
                    'off (keys.pkcs11SynchronousSign); use the asynchronous ' +
                    'door');
    }
    const noAsync = function (lib) {
      if (typeof lib.C_DeriveKeyAsync !== 'function' &&
          !synchronousSignAllowed()) {
        throw refusal('STS-KEYS-0209', 'a blocking PKCS#11 key agreement ' +
                      'is off (keys.pkcs11SynchronousSign), and this module ' +
                      'has no asynchronous C_DeriveKey');
      }
    };
    // Off the loop: the key found and Z read (and its object destroyed) by
    // the control thread, C_DeriveKeyAsync here. In place: all here.
    const op = async ? async function (lib, session) {
      noAsync(lib);
      const handle = await self.keyed('locate', session, key, []);
      const obj = typeof lib.C_DeriveKeyAsync === 'function'
        ? await lib.C_DeriveKeyAsync(session, mechanism, handle, template)
        : lib.C_DeriveKey(session, mechanism, handle, template);
      return control.call('readSecret', [session, obj]);
    } : function (lib, session) {
      noAsync(lib);
      return CONTROL_OPS.readSecret(lib, session,
        lib.C_DeriveKey(session, mechanism, self.handleOf(key, lib, session),
                        template));
    };
    log.debug('Leaving Pkcs11Token.deriveEcdh().');
    if (async) {
      return this.run('an ECDH agreement', op);
    }
    return this.runSync('an ECDH agreement', op);
  }

  // CKM_ML_DSA is refused before C_Sign when the token does not offer it.
  // A classical mechanism is not asked here: `signingAlgorithms()` already
  // hides one the token lacks, and a missing SIGNING row is STS-KEYS-0206
  // from `signingPlan()`.
  /**
   * Refuses an ML-DSA signature when the token does not offer CKM_ML_DSA.
   *
   * @param plan - `signingPlan()`'s answer
   * @returns a STS-KEYS-0206 error, or null
   */
  mlDsaOfferProblem(plan) {
    log.debug('Entering Pkcs11Token.mlDsaOfferProblem().');
    const mech = plan && plan.mechanism ? plan.mechanism.mechanism : null;
    if (mech !== CK.CKM_ML_DSA && mech !== CK.CKM_SLH_DSA) {
      log.debug('Leaving Pkcs11Token.mlDsaOfferProblem().');
      return null;
    }
    if (this.offers(mech, CK.CKF_SIGN)) {
      log.debug('Leaving Pkcs11Token.mlDsaOfferProblem(). Offered.');
      return null;
    }
    const name = mech === CK.CKM_ML_DSA ? 'CKM_ML_DSA' : 'CKM_SLH_DSA';
    const family = mech === CK.CKM_ML_DSA ? 'An ML-DSA' : 'An SLH-DSA';
    log.debug('Leaving Pkcs11Token.mlDsaOfferProblem(). Refused.');
    return refusal('STS-KEYS-0206', 'the HSM does not offer ' + name +
      ', so ' + family.toLowerCase() + ' signature stays in software');
  }

  /**
   * Which of the published post-quantum algorithms this token can make and
   * sign with (#2220): for each, whether it lists the generation mechanism
   * and the signing one with CKF_SIGN.
   *
   * @returns `{ [alg]: { offered, family, mechanism } }`
   */
  postQuantumOffer() {
    log.debug('Entering Pkcs11Token.postQuantumOffer().');
    const self = this;
    const out = {};
    Object.keys(ML_DSA).concat(Object.keys(SLH_DSA)).forEach(function (alg) {
      const row = pqRowOf(alg);
      out[alg] = { offered: self.canGenerate({ kty: 'AKP', alg: alg }),
                   family: row.family,
                   mechanism: row.family === 'ML-DSA' ? 'CKM_ML_DSA'
                     : 'CKM_SLH_DSA' };
    });
    log.debug('Leaving Pkcs11Token.postQuantumOffer().');
    return out;
  }

  // CKA_VALUE is the raw public key (FIPS 204). It becomes a
  // SubjectPublicKeyInfo so the rest of this service can publish it. A
  // runtime that cannot import ML-DSA still returns the parameter set.
  /**
   * The public half of an ML-DSA key in the token.
   *
   * @param handle - the public object
   * @param spec - `{ kty: 'AKP', alg }`
   * @returns a public-key object whose `parameterSet` is the algorithm
   */
  mlDsaPublicKey(handle, spec) {
    log.debug('Entering Pkcs11Token.mlDsaPublicKey(). ' + spec.alg);
    const a = this.attributes(handle, [CK.CKA_VALUE]);
    log.debug('Leaving Pkcs11Token.mlDsaPublicKey().');
    return this.mlDsaPublicKeyFrom(a.get(CK.CKA_VALUE), spec);
  }

  /**
   * The public half of an ML-DSA key from its CKA_VALUE.
   *
   * @param raw - the raw FIPS 204 public key
   * @param spec - `{ kty: 'AKP', alg }`
   * @returns a public-key object whose `parameterSet` is the algorithm
   */
  mlDsaPublicKeyFrom(raw, spec) {
    log.debug('Entering Pkcs11Token.mlDsaPublicKeyFrom(). ' + spec.alg);
    // An SLH-DSA key's raw public key is read the same way (#2220).
    const row = pqRowOf(spec.alg);
    if (!row || !raw || raw.length !== row.publicBytes) {
      log.debug('Leaving Pkcs11Token.mlDsaPublicKeyFrom(). Refused.');
      throw refusal('STS-KEYS-0207', 'the HSM did not answer an ' +
        (spec.alg || 'ML-DSA') + ' public key of ' +
        (row ? row.publicBytes : '?') + ' octets');
    }
    const spki = require('./pqc_x509').encodeSpki(spec.alg, raw);
    let imported = null;
    try {
      imported = nodeCrypto.createPublicKey({ key: Buffer.from(spki),
                                              format: 'der', type: 'spki' });
    } catch (e) {
      // Node before 24 is linked to an OpenSSL with no ML-DSA. The key
      // stays in the token; the caller still gets the parameter set.
      log.debug('Caught in Pkcs11Token.mlDsaPublicKey(): ' +
                ((e && e.message) || e));
      imported = null;
    }
    const details = Object.assign({},
      (imported && imported.asymmetricKeyDetails) || {},
      { parameterSet: spec.alg });
    // The raw public key travels on the object too (#2220): the realm's
    // published set builds its AKP JWK from it.
    const rawPublic = Buffer.from(raw);
    const out = imported && imported.asymmetricKeyType ? {
      raw: rawPublic,
      type: 'public',
      asymmetricKeyType: imported.asymmetricKeyType,
      asymmetricKeyDetails: details,
      export: function (opts) {
        log.debug('Entering mldsaPublic.export().');
        const exported = imported.export(opts);
        log.debug('Leaving mldsaPublic.export().');
        return exported;
      }
    } : {
      raw: rawPublic,
      type: 'public',
      asymmetricKeyType: row.family === 'ML-DSA' ? 'ml-dsa' : 'slh-dsa',
      asymmetricKeyDetails: details,
      export: function () {
        log.debug('Entering mldsaPublic.export().');
        log.debug('Leaving mldsaPublic.export(). The SPKI.');
        return Buffer.from(spki);
      }
    };
    log.debug('Leaving Pkcs11Token.mlDsaPublicKeyFrom().');
    return out;
  }

  /**
   * What this token can sign with, of the JWS algorithms `SIGNING` lists.
   *
   * @returns the algorithm names
   */
  signingAlgorithms() {
    log.debug('Entering Pkcs11Token.signingAlgorithms().');
    const self = this;
    const out = Object.keys(SIGNING).filter(function (alg) {
      return self.offers(SIGNING[alg].mech, CK.CKF_SIGN);
    });
    log.debug('Leaving Pkcs11Token.signingAlgorithms().');
    return out;
  }
}

// The attributes a public key of this kind is read from.
function publicTypes(spec) {
  log.debug('Entering publicTypes(). ' + spec.kty);
  log.debug('Leaving publicTypes().');
  return spec.kty === 'AKP' ? [CK.CKA_VALUE]
    : spec.kty === 'RSA' ? [CK.CKA_MODULUS, CK.CKA_PUBLIC_EXPONENT]
      : [CK.CKA_EC_POINT];
}

function refText(ref) {
  log.debug('Entering refText().');
  const parts = [];
  if (ref.label) {
    parts.push('labelled "' + ref.label + '"');
  }
  if (ref.id) {
    parts.push('with id ' + Buffer.from(ref.id).toString('hex'));
  }
  log.debug('Leaving refText().');
  return parts.join(' and ') || '(unnamed)';
}

function describeMechFailure(token) {
  log.debug('Entering describeMechFailure().');
  log.debug('Leaving describeMechFailure().');
  return 'The PKCS#11 module "' + token.modulePath + '" (' +
         token.describe() + ') was asked for a mechanism it does not offer.';
}

// GCM's parameters in the binding's own shape: a 96-bit IV, a 128-bit tag,
// the data key's AAD as GCM's additional data.
function gcmMechanism(binding, iv, aad) {
  log.debug('Entering gcmMechanism().');
  log.debug('Leaving gcmMechanism().');
  return { mechanism: CK.CKM_AES_GCM,
           parameter: { type: binding.CK_PARAMS_AES_GCM, iv: iv,
                        aad: Buffer.from(String(aad), 'utf8'), ivBits: 96,
                        tagBits: 128 } };
}

// A short-lived session object holding bytes to wrap (`bound`), or the
// template an unwrap creates one with (`null`): never a token object,
// extractable so its value can be read back, and destroyed by the caller.
function sessionSecret(bound) {
  log.debug('Entering sessionSecret().');
  /** @type {Array<{ type: number, value?: any }>} */
  const t = [{ type: CK.CKA_CLASS, value: CK.CKO_SECRET_KEY },
             { type: CK.CKA_KEY_TYPE, value: CK.CKK_GENERIC_SECRET },
             { type: CK.CKA_TOKEN, value: false },
             { type: CK.CKA_SENSITIVE, value: false },
             { type: CK.CKA_EXTRACTABLE, value: true }];
  if (bound) {
    t.push({ type: CK.CKA_VALUE, value: Buffer.from(bound) });
  }
  log.debug('Leaving sessionSecret().');
  return t;
}

function encryptAsync(lib, session, data, room) {
  log.debug('Entering encryptAsync().');
  log.debug('Leaving encryptAsync().');
  return typeof lib.C_EncryptAsync === 'function'
    ? lib.C_EncryptAsync(session, data, Buffer.alloc(room))
    : lib.C_Encrypt(session, data, Buffer.alloc(room));
}

function decryptAsync(lib, session, data, room) {
  log.debug('Entering decryptAsync().');
  log.debug('Leaving decryptAsync().');
  return typeof lib.C_DecryptAsync === 'function'
    ? lib.C_DecryptAsync(session, data, Buffer.alloc(room))
    : lib.C_Decrypt(session, data, Buffer.alloc(room));
}

// The mechanism and the bytes a JWS algorithm hands C_Sign.
function signingPlan(binding, alg, data) {
  log.debug('Entering signingPlan(). ' + alg);
  const s = SIGNING[alg];
  if (!s) {
    throw refusal('STS-KEYS-0206', 'the HSM does not sign "' + alg + '"');
  }
  const input = Buffer.from(data);
  if (s.pss) {
    log.debug('Leaving signingPlan(). PSS.');
    return { mechanism: { mechanism: s.mech,
                          parameter: { type: binding.CK_PARAMS_RSA_PSS,
                                       hashAlg: s.pss[0], mgf: s.pss[1],
                                       saltLen: s.pss[2] } },
             input: input };
  }
  if (s.hash) {
    log.debug('Leaving signingPlan(). Hashed here.');
    return { mechanism: { mechanism: s.mech },
             input: nodeCrypto.createHash(s.hash).update(input).digest() };
  }
  log.debug('Leaving signingPlan().');
  return { mechanism: { mechanism: s.mech }, input: input };
}

/**
 * Opens a token: loads the module (once per path, per thread), finds the slot
 * and logs in one session.
 *
 * @param binding - the loaded binding, or a test's fake
 * @param options - as for `Pkcs11Token`
 * @returns the connected token
 */
function openToken(binding, options) {
  log.debug('Entering openToken().');
  const token = new Pkcs11Token(binding, options).connect();
  log.debug('Leaving openToken().');
  return token;
}

/**
 * Forgets every loaded module of this thread, for a test that swaps its fake
 * between cases. Nothing in the service calls it.
 */
function forgetLibraries() {
  log.debug('Entering forgetLibraries().');
  LIBRARIES.forEach(function (entry) {
    if (entry.control) {
      entry.control.stop();
    }
    if (entry.channel) {
      entry.channel.close();
    }
  });
  LIBRARIES.clear();
  log.debug('Leaving forgetLibraries().');
}

module.exports = {
  CK: CK,
  CURVES: CURVES,
  SIGNING: SIGNING,
  Pkcs11Token: Pkcs11Token,
  // The calls a control thread makes (`pkcs11_thread.js`), and how what it
  // posts back is read.
  CONTROL_OPS: CONTROL_OPS,
  revive: revive,
  errorFields: errorFields,
  newEntry: newEntry,
  // The process's generation of a module (`reinitializeEntry()`), for a
  // test that counts re-initialisations across threads.
  sharedGeneration: sharedGeneration,
  openToken: openToken,
  forgetLibraries: forgetLibraries
};
