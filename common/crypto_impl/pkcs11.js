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
//     `sign()` uses `C_SignAsync`. `signSync()`, and a module with no
//     asynchronous sign, call blocking `C_Sign` only while
//     `keys.pkcs11SynchronousSign` is on; otherwise they refuse
//     (STS-KEYS-0209).
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
// event loop) holds its session until it settles; a synchronous one borrows an
// idle session or opens one more. EVERY THREAD HOLDS ITS OWN: a request worker
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
// initialized again first. Nothing polls: the next operation after an outage
// is what reconnects, and an operation that still fails is refused with
// STS-KEYS-0201 — a refusal, never a crash.
//
// POST-QUANTUM SIGNING COMES HERE ONLY WHEN THE MODULE OFFERS IT. PKCS#11
// 3.2 (OASIS, 3 June 2026) defines CKM_ML_DSA — pure ML-DSA, FIPS 204, no
// pre-hash — and CKM_ML_DSA_KEY_PAIR_GEN. A token that does not list
// CKM_ML_DSA with CKF_SIGN is refused (STS-KEYS-0206) and the signature
// stays in software. SLH-DSA has no mechanism here. The realm's published
// post-quantum set is still made in software (`helpers.js`'s `pqKeysFor`):
// an ML-DSA key in the token is one this module generated, not that set.
// The pre-hash numbers some drafts used (0x23–0x26) are not these.
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
  CKK_EC_EDWARDS: 0x40, CKK_ML_DSA: 0x4a,
  CKA_CLASS: 0x0, CKA_TOKEN: 0x1, CKA_PRIVATE: 0x2, CKA_LABEL: 0x3,
  CKA_VALUE: 0x11, CKA_KEY_TYPE: 0x100, CKA_ID: 0x102, CKA_SENSITIVE: 0x103,
  CKA_ENCRYPT: 0x104, CKA_DECRYPT: 0x105, CKA_WRAP: 0x106, CKA_UNWRAP: 0x107,
  CKA_SIGN: 0x108, CKA_VERIFY: 0x10a, CKA_DERIVE: 0x10c, CKA_MODULUS: 0x120,
  CKA_MODULUS_BITS: 0x121, CKA_PUBLIC_EXPONENT: 0x122, CKA_VALUE_LEN: 0x161,
  CKA_EXTRACTABLE: 0x162, CKA_EC_PARAMS: 0x180, CKA_EC_POINT: 0x181,
  CKA_PARAMETER_SET: 0x61d, CKA_SEED: 0x637,
  CKM_RSA_PKCS_KEY_PAIR_GEN: 0x0, CKM_ML_DSA_KEY_PAIR_GEN: 0x1c,
  CKM_ML_DSA: 0x1d, CKM_SHA256_RSA_PKCS: 0x40,
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
// ML-DSA-87's signature is 4627 octets. 1024 was the classical room.
const SIGN_ROOM = 8192;
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
                 parameterSet: CK.CKP_ML_DSA_87 }
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

// Whether a blocking C_Sign is allowed. Off by default
// (keys.pkcs11SynchronousSign): a synchronous door refuses rather than
// holding the event loop for the token. Read lazily. This file is required
// by crypto.js, which has already required config.js, so the require hits
// the cache; a load that is not ready is treated as off.
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
// ONE LOADED MODULE PER PATH, PER THREAD. `lib.load()` dlopens the module and
// C_Initialize is called once; a second token on the same module shares it.
// ---------------------------------------------------------------------------
const LIBRARIES = new Map();

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
  const entry = { binding: binding, lib: lib, initialized: false };
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

function reinitialize(entry) {
  log.debug('Entering reinitialize().');
  try {
    entry.lib.C_Finalize();
  } catch (e) {
    // A module that lost its device may refuse to finalize too; it is
    // initialized again either way, which is the point.
    log.debug('Caught in reinitialize(): ' + ((e && e.message) || e));
  }
  initialize(entry);
  log.debug('Leaving reinitialize().');
}

// ---------------------------------------------------------------------------
// A TOKEN: one slot of one module, logged in as the user, with its pool of
// sessions. Built by `common/crypto.js`'s `openPkcs11Token()`.
// ---------------------------------------------------------------------------
class Pkcs11Token {
  /**
   * @param binding - the loaded binding (`require('pkcs11js')`) or a fake
   * @param options - `{ modulePath, tokenLabel, serial, slotId, pin,
   *   maxSessions }`
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
    this.entry = null;
    this.slot = null;
    this.idle = [];
    this.open = 0;
    this.waiters = [];
    this.loggedIn = false;
    this.mechanisms = null;
    this.reconnects = 0;
    // OBJECT HANDLES DO NOT OUTLIVE THE LOGIN. When the last session closes
    // the module logs the application out, and SoftHSM2 then answers
    // CKR_OBJECT_HANDLE_INVALID for a handle found before (2026-11-20, the
    // first run against it); a connector restart does the same. So a key is
    // held as the TEMPLATE that finds it, and its handle is found again
    // whenever this counter has moved since (`handleOf()`).
    this.generation = 0;
    log.debug('Leaving Pkcs11Token.constructor().');
  }

  /**
   * Loads the module, finds the slot and opens (and logs in) one session, so
   * that a wrong label or PIN is refused at start rather than at the first
   * operation.
   *
   * @returns this token
   */
  connect() {
    log.debug('Entering Pkcs11Token.connect().');
    this.entry = libraryFor(this.binding, this.modulePath);
    this.slot = this.findSlot();
    const session = this.openSession();
    this.idle.push(session);
    log.debug('Leaving Pkcs11Token.connect().');
    return this;
  }

  findSlot() {
    log.debug('Entering Pkcs11Token.findSlot().');
    const lib = this.entry.lib;
    let slots;
    try {
      slots = lib.C_GetSlotList(true) || [];
    } catch (e) {
      throw refusal('STS-KEYS-0202', 'the PKCS#11 module listed no slots', e);
    }
    const matches = [];
    for (const slot of slots) {
      let info;
      try {
        info = lib.C_GetTokenInfo(slot);
      } catch (e) {
        // One slot that cannot describe its token is not a reason to refuse
        // the others; it simply is not the one asked for.
        log.debug('Caught in Pkcs11Token.findSlot(): ' +
                  ((e && e.message) || e));
        continue;
      }
      const label = String((info && info.label) || '').trim();
      const serial = String((info && info.serialNumber) || '').trim();
      const id = Buffer.isBuffer(slot) ? String(attrUlong(slot)) :
                 String(slot);
      if (this.tokenLabel && label !== this.tokenLabel) {
        continue;
      }
      if (this.serial && serial !== this.serial) {
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
    log.debug('Leaving Pkcs11Token.findSlot().');
    return matches[0];
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

  openSession() {
    log.debug('Entering Pkcs11Token.openSession().');
    const lib = this.entry.lib;
    let session;
    try {
      session = lib.C_OpenSession(this.slot,
                                  CK.CKF_SERIAL_SESSION | CK.CKF_RW_SESSION);
    } catch (e) {
      throw refusal('STS-KEYS-0201', 'no session could be opened on ' +
                    this.describe(), e);
    }
    this.open++;
    if (this.pin !== null) {
      try {
        lib.C_Login(session, CK.CKU_USER, this.pin);
      } catch (e) {
        if (ckrOf(e) !== CK.CKR_USER_ALREADY_LOGGED_IN) {
          this.closeSession(session);
          throw refusal('STS-KEYS-0205', 'the PIN was refused by ' +
                        this.describe(), e);
        }
        // A login is per application: another session of this process
        // (or another thread) already holds it.
        log.debug('Caught in Pkcs11Token.openSession(): already logged in: ' +
                  ((e && e.message) || e));
      }
      this.loggedIn = true;
    }
    log.debug('Leaving Pkcs11Token.openSession().');
    return session;
  }

  closeSession(session) {
    log.debug('Entering Pkcs11Token.closeSession().');
    this.open = Math.max(0, this.open - 1);
    if (this.open === 0) {
      this.generation++;
    }
    try {
      this.entry.lib.C_CloseSession(session);
    } catch (e) {
      // A session the device already lost cannot be closed, and does not
      // need to be.
      log.debug('Caught in Pkcs11Token.closeSession(): ' +
                ((e && e.message) || e));
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
    this.maxSessions = 0;
    log.debug('Leaving Pkcs11Token.close().');
  }

  // Lends a session: an idle one, a new one under the cap, or a promise of
  // the next one handed back.
  acquire() {
    log.debug('Entering Pkcs11Token.acquire().');
    if (this.idle.length) {
      log.debug('Leaving Pkcs11Token.acquire(). Idle.');
      return Promise.resolve(this.idle.pop());
    }
    if (this.open < this.maxSessions) {
      try {
        const s = this.openSession();
        log.debug('Leaving Pkcs11Token.acquire(). Opened.');
        return Promise.resolve(s);
      } catch (e) {
        log.debug('Leaving Pkcs11Token.acquire(). Refused.');
        return Promise.reject(e);
      }
    }
    const waiters = this.waiters;
    log.debug('Leaving Pkcs11Token.acquire(). Waiting.');
    return new Promise(function (resolve) {
      waiters.push(resolve);
    });
  }

  release(session) {
    log.debug('Entering Pkcs11Token.release().');
    const next = this.waiters.shift();
    if (next) {
      next(session);
    } else if (this.open > this.maxSessions) {
      this.closeSession(session);
    } else {
      this.idle.push(session);
    }
    log.debug('Leaving Pkcs11Token.release().');
  }

  // A lost session is not handed back; a waiter is handed a fresh one.
  discard(session) {
    log.debug('Entering Pkcs11Token.discard().');
    this.closeSession(session);
    const next = this.waiters.shift();
    if (next) {
      try {
        next(this.openSession());
      } catch (e) {
        // The waiter's own operation will meet the outage and reconnect; it
        // is handed nothing better than a retry.
        log.debug('Caught in Pkcs11Token.discard(): ' +
                  ((e && e.message) || e));
        this.waiters.unshift(next);
      }
    }
    log.debug('Leaving Pkcs11Token.discard().');
  }

  // After an outage: every idle session is dropped (they were lost with the
  // one that failed), and the module is initialized again where the error
  // says the library itself lost the device.
  recover(err) {
    log.debug('Entering Pkcs11Token.recover().');
    this.reconnects++;
    this.generation++;
    if (!DEVICE_LOST.has(ckrOf(err))) {
      log.debug('Leaving Pkcs11Token.recover(). Only that session.');
      return;
    }
    const idle = this.idle.splice(0);
    for (const s of idle) {
      this.closeSession(s);
    }
    if (REINITIALIZE_ON.has(ckrOf(err))) {
      reinitialize(this.entry);
      this.open = 0;
      this.slot = this.findSlot();
    }
    log.warn(errorCodes.tag('STS-KEYS-0201') + 'pkcs11: ' + this.describe() +
             ' answered ' + ((err && err.message) || err) + '; the session ' +
             'was dropped and the operation is tried once more.');
    log.debug('Leaving Pkcs11Token.recover().');
  }

  /**
   * Runs one operation on a lent session, asynchronously, reconnecting once
   * after an outage.
   *
   * @param what - what the operation is, for a refusal
   * @param fn - `(lib, session) => value | Promise<value>`
   * @returns a promise of what `fn` answered
   */
  async run(what, fn) {
    log.debug('Entering Pkcs11Token.run(). ' + what);
    for (let attempt = 0; attempt < 2; attempt++) {
      const session = await this.acquire();
      try {
        const out = await fn(this.entry.lib, session);
        this.release(session);
        log.debug('Leaving Pkcs11Token.run().');
        return out;
      } catch (e) {
        if (attempt === 0 && RECONNECT_ON.has(ckrOf(e))) {
          log.debug('Caught in Pkcs11Token.run(): ' + ((e && e.message) || e) +
                    '; reconnecting once.');
          this.discard(session);
          try {
            this.recover(e);
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

  /**
   * Runs one operation synchronously on an idle session (or one more), for
   * a caller that cannot wait — `signJws()`'s synchronous door. Reconnects
   * once after an outage.
   *
   * @param what - what the operation is, for a refusal
   * @param fn - `(lib, session) => value`
   * @returns what `fn` answered
   */
  runSync(what, fn) {
    log.debug('Entering Pkcs11Token.runSync(). ' + what);
    for (let attempt = 0; attempt < 2; attempt++) {
      const session = this.idle.length ? this.idle.pop() : this.openSession();
      try {
        const out = fn(this.entry.lib, session);
        this.release(session);
        log.debug('Leaving Pkcs11Token.runSync().');
        return out;
      } catch (e) {
        if (attempt === 0 && RECONNECT_ON.has(ckrOf(e))) {
          log.debug('Caught in Pkcs11Token.runSync(): ' +
                    ((e && e.message) || e) + '; reconnecting once.');
          this.discard(session);
          try {
            this.recover(e);
          } catch (r) {
            // The device is still away: the reconnect itself failed, which
            // is this operation's refusal, not a different one.
            throw refusal('STS-KEYS-0201', what + ' failed on ' +
                          this.describe() + ', and reconnecting failed', r);
          }
          continue;
        }
        this.release(session);
        log.debug('Leaving Pkcs11Token.runSync(). Refused.');
        throw errorCodes.codeOf(e) ? e : refusal(codeFor(e),
          what + ' failed on ' + this.describe(), e);
      }
    }
    log.debug('Leaving Pkcs11Token.runSync(). Unreachable.');
    throw refusal('STS-KEYS-0201', what + ' failed on ' + this.describe());
  }

  /**
   * The mechanisms the token offers, with their flags, read once.
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
   * The handle of a key this token found before, found again when the login
   * it was found under has gone (see `generation`).
   *
   * @param key - `{ template, handle, generation, what }`
   * @returns the handle
   */
  handleOf(key) {
    log.debug('Entering Pkcs11Token.handleOf().');
    if (key.generation === this.generation && key.handle !== null) {
      log.debug('Leaving Pkcs11Token.handleOf(). Held.');
      return key.handle;
    }
    const found = this.find(key.template);
    if (found.length !== 1) {
      throw refusal('STS-KEYS-0203', key.what + ' is ' +
        (found.length ? 'no longer unique' : 'no longer') + ' on ' +
        this.describe());
    }
    key.handle = found[0];
    key.generation = this.generation;
    log.debug('Leaving Pkcs11Token.handleOf(). Found again.');
    return key.handle;
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
      return out;
    });
    log.debug('Leaving Pkcs11Token.find(). ' + found.length + '.');
    return found;
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
    const out = new Map();
    const self = this;
    for (const type of types) {
      try {
        const got = self.runSync('an attribute read', function (lib, s) {
          return lib.C_GetAttributeValue(s, handle, [{ type: type }]);
        });
        if (got && got[0] && got[0].value !== undefined) {
          out.set(type, Buffer.from(got[0].value));
        }
      } catch (e) {
        // A sensitive attribute (CKA_VALUE of a secret key) is refused by
        // design; it is absent from the answer, which is what a caller asks.
        log.debug('Caught in Pkcs11Token.attributes(): ' +
                  ((e && e.message) || e));
      }
    }
    log.debug('Leaving Pkcs11Token.attributes().');
    return out;
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
      return this.run('a wrap', function (lib, session) {
        lib.C_EncryptInit(session, gcmMechanism(binding, iv, aad),
                          self.handleOf(key));
        return encryptAsync(lib, session, plain, plain.length + 64);
      }).then(function (ct) {
        return 'g1.' + b64u(iv) + '.' + b64u(ct);
      });
    }
    const bound = Buffer.concat([plain, aadDigest(aad)]);
    if (tag === 'y1') {
      log.debug('Leaving Pkcs11Token.wrapData(). YubiHSM CCM wrap.');
      return this.run('a wrap', function (lib, session) {
        lib.C_EncryptInit(session, { mechanism: CK.CKM_YUBICO_AES_CCM_WRAP },
                          self.handleOf(key));
        return encryptAsync(lib, session, bound, bound.length + 64);
      }).then(function (blob) {
        return 'y1.' + b64u(blob);
      });
    }
    log.debug('Leaving Pkcs11Token.wrapData(). KWP.');
    return this.run('a wrap', function (lib, session) {
      const obj = lib.C_CreateObject(session, sessionSecret(bound));
      try {
        return lib.C_WrapKey(session, { mechanism: CK.CKM_AES_KEY_WRAP_PAD },
                             self.handleOf(key), obj,
                             Buffer.alloc(bound.length + 16));
      } finally {
        lib.C_DestroyObject(session, obj);
      }
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
      return this.run('an unwrap', function (lib, session) {
        lib.C_DecryptInit(session, gcmMechanism(binding, iv, aad),
                          self.handleOf(key));
        return decryptAsync(lib, session, ct, ct.length + 16);
      }).then(function (plain) {
        return Buffer.from(plain);
      });
    }
    if (parts[0] === 'y1' && parts.length === 2) {
      const blob = Buffer.from(parts[1], 'base64url');
      log.debug('Leaving Pkcs11Token.unwrapData(). YubiHSM CCM wrap.');
      return this.run('an unwrap', function (lib, session) {
        lib.C_DecryptInit(session, { mechanism: CK.CKM_YUBICO_AES_CCM_WRAP },
                          self.handleOf(key));
        return decryptAsync(lib, session, blob, blob.length + 16);
      }).then(function (plain) {
        return splitBound(plain, aad);
      });
    }
    if (parts[0] === 'k1' && parts.length === 2) {
      const wrapped = Buffer.from(parts[1], 'base64url');
      log.debug('Leaving Pkcs11Token.unwrapData(). KWP.');
      return this.run('an unwrap', function (lib, session) {
        const obj = lib.C_UnwrapKey(session,
          { mechanism: CK.CKM_AES_KEY_WRAP_PAD }, self.handleOf(key),
          wrapped, sessionSecret(null));
        try {
          const got = lib.C_GetAttributeValue(session, obj,
                                              [{ type: CK.CKA_VALUE }]);
          return Buffer.from(got[0].value);
        } finally {
          lib.C_DestroyObject(session, obj);
        }
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
    const pair = await this.run('generating a signing key',
      function (lib, session) {
        if (typeof lib.C_GenerateKeyPairAsync === 'function') {
          return lib.C_GenerateKeyPairAsync(session,
            { mechanism: plan.mech }, plan.pub, plan.priv);
        }
        return lib.C_GenerateKeyPair(session, { mechanism: plan.mech },
                                     plan.pub, plan.priv);
      });
    const publicKey = this.publicKeyOf(pair.publicKey, spec);
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
      const row = ML_DSA[spec.alg];
      named = String(spec.alg || '');
      if (!row) {
        throw refusal('STS-KEYS-0207', 'no ML-DSA key can be made in the ' +
                      'HSM for "' + named + '"');
      }
      mech = CK.CKM_ML_DSA_KEY_PAIR_GEN;
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
      if (!ML_DSA[spec.alg]) {
        log.debug('Leaving Pkcs11Token.canGenerate(). No such ML-DSA set.');
        return false;
      }
      mech = CK.CKM_ML_DSA_KEY_PAIR_GEN;
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
    if (spec.kty === 'AKP') {
      const made = this.mlDsaPublicKey(handle, spec);
      log.debug('Leaving Pkcs11Token.publicKeyOf(). ML-DSA.');
      return made;
    }
    let jwk;
    if (spec.kty === 'RSA') {
      const a = this.attributes(handle, [CK.CKA_MODULUS,
                                         CK.CKA_PUBLIC_EXPONENT]);
      if (!a.has(CK.CKA_MODULUS) || !a.has(CK.CKA_PUBLIC_EXPONENT)) {
        throw refusal('STS-KEYS-0207', 'the HSM did not answer an RSA ' +
                      'public key\'s modulus and exponent');
      }
      jwk = { kty: 'RSA', n: b64u(a.get(CK.CKA_MODULUS)),
              e: b64u(a.get(CK.CKA_PUBLIC_EXPONENT)) };
    } else {
      const curve = CURVES[spec.crv];
      const a = this.attributes(handle, [CK.CKA_EC_POINT]);
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
    log.debug('Leaving Pkcs11Token.publicKeyOf().');
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
    return this.run('a signature', function (lib, session) {
      if (typeof lib.C_SignAsync !== 'function' &&
          !synchronousSignAllowed()) {
        // No asynchronous sign, and blocking C_Sign is off. Refuse before
        // C_SignInit so the session is not left mid-operation.
        throw refusal('STS-KEYS-0209', 'synchronous PKCS#11 signing is ' +
                      'off (keys.pkcs11SynchronousSign), and this module ' +
                      'has no asynchronous C_Sign');
      }
      lib.C_SignInit(session, plan.mechanism, self.handleOf(key));
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
      lib.C_SignInit(session, plan.mechanism, self.handleOf(key));
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
    const op = function (lib, session) {
      lib.C_DecryptInit(session, mechanism, self.handleOf(key));
      return async ? decryptAsync(lib, session, input, input.length)
                   : lib.C_Decrypt(session, input, Buffer.alloc(input.length));
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
    const read = function (lib, session, obj) {
      try {
        const got = lib.C_GetAttributeValue(session, obj,
                                            [{ type: CK.CKA_VALUE }]);
        return Buffer.from(got[0].value);
      } finally {
        lib.C_DestroyObject(session, obj);
      }
    };
    const op = function (lib, session) {
      const handle = self.handleOf(key);
      if (async && typeof lib.C_DeriveKeyAsync === 'function') {
        return lib.C_DeriveKeyAsync(session, mechanism, handle, template)
          .then(function (obj) {
            return read(lib, session, obj);
          });
      }
      return read(lib, session,
                  lib.C_DeriveKey(session, mechanism, handle, template));
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
    if (!plan || !plan.mechanism ||
        plan.mechanism.mechanism !== CK.CKM_ML_DSA) {
      log.debug('Leaving Pkcs11Token.mlDsaOfferProblem().');
      return null;
    }
    if (this.offers(CK.CKM_ML_DSA, CK.CKF_SIGN)) {
      log.debug('Leaving Pkcs11Token.mlDsaOfferProblem(). Offered.');
      return null;
    }
    log.debug('Leaving Pkcs11Token.mlDsaOfferProblem(). Refused.');
    return refusal('STS-KEYS-0206', 'the HSM does not offer CKM_ML_DSA, ' +
      'so an ML-DSA signature stays in software');
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
    const row = ML_DSA[spec.alg];
    const a = this.attributes(handle, [CK.CKA_VALUE]);
    const raw = a.get(CK.CKA_VALUE);
    if (!row || !raw || raw.length !== row.publicBytes) {
      log.debug('Leaving Pkcs11Token.mlDsaPublicKey(). Refused.');
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
    const out = imported && imported.asymmetricKeyType ? {
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
      type: 'public',
      asymmetricKeyType: 'ml-dsa',
      asymmetricKeyDetails: details,
      export: function () {
        log.debug('Entering mldsaPublic.export().');
        log.debug('Leaving mldsaPublic.export(). The SPKI.');
        return Buffer.from(spki);
      }
    };
    log.debug('Leaving Pkcs11Token.mlDsaPublicKey().');
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
  LIBRARIES.clear();
  log.debug('Leaving forgetLibraries().');
}

module.exports = {
  CK: CK,
  CURVES: CURVES,
  SIGNING: SIGNING,
  Pkcs11Token: Pkcs11Token,
  openToken: openToken,
  forgetLibraries: forgetLibraries
};
