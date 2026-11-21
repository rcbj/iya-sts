// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// File: openpgp_engine.js
//
// ---------------------------------------------------------------------------
// THE OpenPGP ENGINE (#1955 P6, rcbj's decision D3: wrap openpgp.js).
//
// RFC 9580 (v6 keys) and RFC 4880 (v4 keys) as far as this service needs
// them: read a PUBLIC key, describe it, verify a cleartext signature by it,
// and encrypt a message to it. It is the mechanism; `common/crypto.js`
// section 19 is the policy — which algorithms are acceptable, what a
// registration challenge must say, and how fresh a signature must be — and
// is the only file that requires this one (`tests/crypto_centralised.js`).
//
// **IT NEVER HOLDS A PRIVATE KEY.** `readPublicKey()` refuses an armored or
// binary block that is a secret key, so a person who pastes the wrong export
// is told so rather than having their secret key stored on their entry.
//
// **EVERY CALL IS GIVEN ITS OWN openpgp.js CONFIG**, never the library's
// global one, so nothing here changes how another caller of the library in
// the same process behaves. The library's own minimum RSA size is left at
// its default: the service's minimum is `crypto.js`'s question, asked of
// what `describeKey()` answers, so that a refusal names the realm's rule
// rather than the library's.
//
// Requires `openpgp` and nothing of this service: a leaf, as every engine in
// this directory is.
// ---------------------------------------------------------------------------

'use strict';

const bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'openpgp_engine',
  level: process.env.STS_LOG_LEVEL || 'info'
});

// openpgp.js is about a megabyte of JavaScript, and a request worker that
// never sees an OpenPGP key has no use for it: loaded at the first call.
let library = null;

/**
 * The openpgp.js module, loaded at first use.
 *
 * @returns the module
 */
function openpgp() {
  log.debug("Entering openpgp().");
  if (!library) {
    library = require('openpgp');
  }
  log.debug("Leaving openpgp().");
  return library;
}

/**
 * The library's version, for the console's crypto metadata.
 *
 * @returns the version string, or '' when it cannot be read
 */
function libraryVersion() {
  log.debug("Entering libraryVersion().");
  let out = '';
  try {
    out = String(require('openpgp/package.json').version || '');
  } catch (e) {
    log.debug("Caught in libraryVersion(): " + ((e && e.message) || e));
    // The package does not export its manifest under every resolver; the
    // config's version string says the same.
    try {
      out = String(openpgp().config.versionString || '')
        .replace(/^OpenPGP\.js v?/, '');
    } catch (e2) {
      log.debug("Caught in libraryVersion(): " + ((e2 && e2.message) || e2));
      out = '';
    }
  }
  log.debug("Leaving libraryVersion(). " + out);
  return out;
}

/**
 * Reads ONE public key, armored or binary. Refuses a secret key and a block
 * holding more than one key.
 *
 * @param input - the armored text, or the binary packets
 * @returns `{ ok: true, key }` or `{ ok: false, reason, why }`, `reason`
 *   one of `unreadable`, `secret`, `several`
 */
async function readPublicKey(input) {
  log.debug("Entering readPublicKey().");
  const lib = openpgp();
  let keys = [];
  try {
    if (typeof input === 'string') {
      keys = await lib.readKeys({ armoredKeys: input });
    } else {
      keys = await lib.readKeys({ binaryKeys: new Uint8Array(input) });
    }
  } catch (e) {
    log.debug("Caught in readPublicKey(): " + ((e && e.message) || e));
    // A secret key's armor reads as one too; the library says which.
    const text = String((e && e.message) || e);
    log.debug("Leaving readPublicKey(). Unreadable.");
    return { ok: false, reason: /private|secret/i.test(text) ? 'secret'
                                                               : 'unreadable',
             why: text };
  }
  if (keys.length !== 1) {
    log.debug("Leaving readPublicKey(). " + keys.length + " keys.");
    return { ok: false, reason: keys.length ? 'several' : 'unreadable',
             why: keys.length + ' keys' };
  }
  if (keys[0].isPrivate()) {
    log.debug("Leaving readPublicKey(). A secret key.");
    return { ok: false, reason: 'secret', why: 'a secret key' };
  }
  log.debug("Leaving readPublicKey().");
  return { ok: true, key: keys[0] };
}

/**
 * One key packet's algorithm, as the policy reads it.
 *
 * @param packet - a key or subkey object of the library
 * @returns `{ algorithm, curve, bits }`
 */
function algorithmOf(packet) {
  log.debug("Entering algorithmOf().");
  const info = packet.getAlgorithmInfo() || {};
  log.debug("Leaving algorithmOf().");
  return { algorithm: String(info.algorithm || ''),
           curve: String(info.curve || ''),
           bits: Number(info.bits || 0) };
}

/**
 * Whether a call that may throw answered; its answer or null.
 *
 * @param fn - the call
 * @returns the answer, or null when it threw
 */
async function quietly(fn) {
  log.debug("Entering quietly().");
  try {
    const out = await fn();
    log.debug("Leaving quietly().");
    return out;
  } catch (e) {
    log.debug("Caught in quietly(): " + ((e && e.message) || e));
    // The library answers "no such key" by throwing; to a description that
    // is an absent member, not a failure.
    log.debug("Leaving quietly(). Threw.");
    return null;
  }
}

/**
 * Describes a public key as of an instant: its fingerprint and version, the
 * algorithms of the primary key and of each subkey, the key the library
 * would sign and encrypt with, the user ids and their addresses, and
 * whether it is revoked or expired.
 *
 * @param key - a key `readPublicKey()` answered
 * @param at - the instant (a Date)
 * @returns the description
 */
async function describeKey(key, at) {
  log.debug("Entering describeKey().");
  const date = at instanceof Date ? at : new Date();
  const revoked = !!(await quietly(function () {
    return key.isRevoked(null, null, date);
  }));
  const expiry = await quietly(function () {
    return key.getExpirationTime();
  });
  const expiresAt = expiry instanceof Date ? expiry.toISOString() : '';
  const signing = await quietly(function () {
    return key.getSigningKey(null, date);
  });
  const encryption = await quietly(function () {
    return key.getEncryptionKey(null, date);
  });
  const users = [];
  for (const user of key.users) {
    if (!user.userID) {
      continue;
    }
    const valid = !!(await quietly(function () {
      return user.verify(date);
    }));
    users.push({ text: String(user.userID.userID || ''),
                 email: String(user.userID.email || ''),
                 valid: valid });
  }
  const out = {
    fingerprint: key.getFingerprint().toLowerCase(),
    keyId: key.getKeyID().toHex().toLowerCase(),
    version: Number(key.keyPacket.version),
    created: key.getCreationTime().toISOString(),
    primary: algorithmOf(key),
    subkeys: key.subkeys.map(function (sub) {
      return Object.assign({ fingerprint: sub.getFingerprint().toLowerCase() },
                           algorithmOf(sub));
    }),
    signing: signing ? Object.assign({
      fingerprint: signing.getFingerprint().toLowerCase(),
      keyId: signing.getKeyID().toHex().toLowerCase() }, algorithmOf(signing))
      : null,
    encryption: encryption ? Object.assign({
      fingerprint: encryption.getFingerprint().toLowerCase(),
      keyId: encryption.getKeyID().toHex().toLowerCase() },
      algorithmOf(encryption)) : null,
    users: users,
    revoked: revoked,
    expiresAt: expiresAt,
    expired: !!(expiry instanceof Date && expiry.getTime() <= date.getTime())
  };
  log.debug("Leaving describeKey(). " + out.fingerprint);
  return out;
}

/**
 * The key's public packets, armored — what is stored and what the Web Key
 * Directory answers (as binary, `binaryOf()`).
 *
 * @param key - a public key
 * @returns the armored text
 */
function armor(key) {
  log.debug("Entering armor().");
  log.debug("Leaving armor().");
  return key.armor();
}

/**
 * The key's public packets, binary.
 *
 * @param key - a public key
 * @returns the bytes
 */
function binaryOf(key) {
  log.debug("Entering binaryOf().");
  log.debug("Leaving binaryOf().");
  return Buffer.from(key.write());
}

/**
 * Verifies a cleartext-signed message (`gpg --clearsign`) by a key: the
 * signature must be made by a signing-capable key of it, valid at `at`.
 *
 * @param signedText - the whole armored cleartext message
 * @param key - the public key
 * @param at - the instant the key's validity is judged at (a Date)
 * @returns `{ ok: true, text, signer: { fingerprint, keyId, algorithm,
 *   curve, bits }, created }` or `{ ok: false, reason, why }`, `reason` one
 *   of `unreadable`, `unsigned`, `other-key`, `bad-signature`
 */
async function verifyCleartext(signedText, key, at) {
  log.debug("Entering verifyCleartext().");
  const lib = openpgp();
  const date = at instanceof Date ? at : new Date();
  let message = null;
  try {
    message = await lib.readCleartextMessage({
      cleartextMessage: String(signedText) });
  } catch (e) {
    log.debug("Caught in verifyCleartext(): " + ((e && e.message) || e));
    log.debug("Leaving verifyCleartext(). Unreadable.");
    return { ok: false, reason: 'unreadable', why: String((e && e.message) ||
                                                          e) };
  }
  const ids = message.getSigningKeyIDs();
  if (!ids.length) {
    log.debug("Leaving verifyCleartext(). No signature.");
    return { ok: false, reason: 'unsigned', why: 'no signature' };
  }
  // THE SIGNER MUST BE A SIGNING-CAPABLE KEY OF THIS ONE, valid now: asked
  // of the key by the signature's issuer id before the signature is
  // checked, so a signature by a revoked or encryption-only subkey is
  // refused as that rather than as a bad signature.
  let signer = null;
  for (const id of ids) {
    signer = await quietly(function () {
      return key.getSigningKey(id, date);
    });
    if (signer) {
      break;
    }
  }
  if (!signer) {
    log.debug("Leaving verifyCleartext(). Not this key's signature.");
    return { ok: false, reason: 'other-key',
             why: 'signed by ' + ids.map(function (id) {
               return id.toHex();
             }).join(', ') + ', which is no signing key of this one' };
  }
  let result = null;
  try {
    result = await lib.verify({ message: message, verificationKeys: key,
                                date: date, expectSigned: true });
  } catch (e) {
    log.debug("Caught in verifyCleartext(): " + ((e && e.message) || e));
    log.debug("Leaving verifyCleartext(). Did not verify.");
    return { ok: false, reason: 'bad-signature',
             why: String((e && e.message) || e) };
  }
  const first = result.signatures[0];
  let created = '';
  try {
    const signature = await first.signature;
    const packet = signature.packets[0];
    created = packet && packet.created ? packet.created.toISOString() : '';
  } catch (e) {
    log.debug("Caught in verifyCleartext(): " + ((e && e.message) || e));
    // expectSigned has already established the signature verified; a
    // creation time it does not carry is judged by the caller as absent.
    created = '';
  }
  log.debug("Leaving verifyCleartext(). Verified.");
  return {
    ok: true,
    text: String(result.data),
    signer: Object.assign({
      fingerprint: signer.getFingerprint().toLowerCase(),
      keyId: signer.getKeyID().toHex().toLowerCase() }, algorithmOf(signer)),
    created: created
  };
}

/**
 * Encrypts bytes to a key's encryption key, as a binary OpenPGP message
 * (what RFC 3156's `application/octet-stream` part carries, armored by the
 * caller — `armorMessage()`).
 *
 * @param data - the bytes (a Buffer or Uint8Array)
 * @param key - the public key
 * @param at - the instant the key's validity is judged at (a Date)
 * @returns the armored message
 */
async function encryptTo(data, key, at) {
  log.debug("Entering encryptTo().");
  const lib = openpgp();
  const message = await lib.createMessage({ binary: new Uint8Array(data) });
  const out = await lib.encrypt({
    message: message, encryptionKeys: key,
    date: at instanceof Date ? at : new Date(), format: 'armored' });
  log.debug("Leaving encryptTo().");
  return String(out);
}

module.exports = {
  libraryVersion: libraryVersion,
  readPublicKey: readPublicKey,
  describeKey: describeKey,
  armor: armor,
  binaryOf: binaryOf,
  verifyCleartext: verifyCleartext,
  encryptTo: encryptTo
};
