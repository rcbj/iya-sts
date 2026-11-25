// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openpgp_pqc.js
//
// ---------------------------------------------------------------------------
// RFC 9980 AGAINST THE PUBLISHED APPENDIX A.3 VECTORS, AND THE REGISTRATION
// POLICY THAT SITS ON THE READER.
//
// The vectors are public domain (RFC 9980 Appendix A.3). The Ed25519 half,
// the fingerprint, the KEK and the session key match on every runtime.
// Where ML-DSA cannot be verified (node before 24, OpenSSL before 3.5) the
// key is refused as unchecked rather than stored. Where it verifies, the
// same key is accepted and both signature halves have to match. ML-KEM
// encapsulation is not attempted against the vectors. Keys made here at run
// time (section 9) test what a third party can append: an unbound subkey,
// a revocation, a direct-key signature that does not verify, and a second
// signature on a proof.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'openpgp_pqc',
  level: process.env.LOG_LEVEL || 'info' });

const DIR = path.join(__dirname, 'fixtures', 'rfc9980');
const PRIMARY = 'a3e2e14b6a493ff930fb27321f125e9a' +
  '6880338be9fb7da3ae065ea65793242f';
const SUBKEY = '7dae8fbce23022607167af72a002e774' +
  'e0ca379a2d7ae072384e1e8fde3265e4';
const MLKEM_SHARE = '0987fe72ad5ea58e73344f9a2a543f41' +
  '31d9fdb7cf07474f501430a20f705b4d';
const ECDH_SHARE = '88f3e9a8de1917127b4b758f6e83bd4c' +
  'e00faaae01bd8b6e412a43a710b26012';
const KEK = 'a4904982f7caa9c9de690afd772d8bfe' +
  '027a1ad6a5bbda00db68963fe303ae8e';
const SESSION = 'adee68618b302d4bfd7ae3d432bc63a1' +
  'c1ad7f5fd6e7fd7bdedbb0d0b14a5c9a';

function read(name) {
  log.debug("Entering read(). " + name);
  log.debug("Leaving read().");
  return fs.readFileSync(path.join(DIR, name));
}

function checkReader(t, leaf) {
  log.debug("Entering checkReader().");
  const canCheck = require('../common/crypto').mlDsaAvailable();
  const pub = read('a3-public.asc');
  const parsed = leaf.readPublicKey(pub, new Date('2026-06-01T00:00:00Z'));
  if (canCheck) {
    t.equal(parsed.ok, true,
            '1a. an RFC 9980 key is accepted when ML-DSA verifies');
    t.equal(parsed.reason, undefined,
            '1b. an accepted key carries no refusal reason');
  } else {
    t.equal(parsed.reason, 'unchecked',
            '1a. an RFC 9980 key is refused while ML-DSA cannot be ' +
            'checked');
    t.equal(parsed.ok, false, '1b. an unchecked key is not ok');
  }
  t.equal(parsed.description.fingerprint, PRIMARY,
          '1c. the primary fingerprint is Appendix A.3.2');
  t.equal(parsed.description.subkeys[0].fingerprint, SUBKEY,
          '1d. the encryption subkey fingerprint is Appendix A.3.2');
  t.equal(parsed.description.encryption &&
          parsed.description.encryption.algorithm, 'ML-KEM-768+X25519',
          '1e. the bound encryption subkey is named');
  t.check(parsed.key && parsed.key.pqc === true && parsed.binary,
          '1f. the answer carries the key and its bytes');
  const users = (parsed.description.users || []).map(function (u) {
    return u.email;
  });
  t.check(users.indexOf('pqc-test-key@example.com') >= 0,
          '1g. the user id is the appendix\'s address', users.join(','));

  const detached = leaf.verifyDetached(read('a3-signature.asc'),
                                       'Testing\n', parsed.key);
  t.equal(detached.eddsa, true,
          '2a. the Ed25519 half of Appendix A.3.4 verifies');
  if (canCheck) {
    t.equal(detached.mldsa, true,
            '2b. the ML-DSA half of Appendix A.3.4 verifies');
  } else {
    t.equal(detached.mldsa, 'unavailable',
            '2b. the ML-DSA half is unchecked on this runtime');
  }
  t.equal(detached.type, 1, '2c. the appendix signature is a text signature');
  t.equal(detached.leftMatches, true, '2d. the left-16 hash bits match');

  const clear = '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA3-256\n\n' +
    'Testing\n' + read('a3-signature.asc').toString('utf8');
  const signed = leaf.verifyCleartext(clear, parsed.key);
  if (canCheck) {
    t.equal(signed.ok, true,
            '2e. a cleartext whose both halves verify is accepted');
    t.equal(signed.text, 'Testing',
            '2f. that cleartext is the appendix message');
  } else {
    t.equal(signed.reason, 'unchecked',
            '2e. a cleartext whose ML-DSA half is unchecked says so');
    t.equal(signed.eddsa, true,
            '2f. that cleartext\'s Ed25519 half verified');
  }

  const sub = parsed.key.subkeys.filter(function (s) {
    return s.spec && s.spec.use === 'encrypt';
  })[0];
  const opened = leaf.decryptWithShares(read('a3-message.asc'),
    sub.material.subarray(0, 32),
    Buffer.from(MLKEM_SHARE, 'hex'), Buffer.from(ECDH_SHARE, 'hex'));
  t.equal(opened.kek.toString('hex'), KEK,
          '3a. the composite KEK is Appendix A.3.3');
  t.equal(opened.sessionKey.toString('hex'), SESSION,
          '3b. the unwrapped session key is Appendix A.3.3');
  t.check(opened.plaintext.indexOf(Buffer.from('Testing')) >= 0,
          '3c. the SEIPD plaintext contains the appendix message');

  const round = Buffer.from('hello pq');
  const body = leaf.encryptSeipd(round, opened.sessionKey);
  const back = leaf.decryptSeipd(body, opened.sessionKey);
  t.equal(back.toString('utf8'), 'hello pq',
          '3d. a v2 SEIPD this reader writes, it reads back');
  log.debug("Leaving checkReader().");
}

function checkPolicy(t) {
  log.debug("Entering checkPolicy().");
  const crypto = require('../common/crypto');
  const codes = require('../common/error_codes');
  ['ML-DSA-65+Ed25519', 'ML-DSA-87+Ed448'].forEach(function (name) {
    t.check(crypto.OPENPGP_SIGNING_ALGORITHMS.indexOf(name) === 0 ||
            crypto.OPENPGP_SIGNING_ALGORITHMS.indexOf(name) === 1,
            '4. ' + name + ' is a signing algorithm', name);
  });
  ['ML-KEM-768+X25519', 'ML-KEM-1024+X448'].forEach(function (name) {
    t.check(crypto.OPENPGP_ENCRYPTION_ALGORITHMS.indexOf(name) >= 0,
            '4. ' + name + ' is an encryption algorithm');
  });
  t.equal(crypto.openpgpAlgorithmProblem(
    { algorithm: 'ed25519', curve: '', bits: 0 }, 'sign', 3072,
    ['ML-DSA-65+Ed25519']), 
          'ed25519 is not an OpenPGP signing algorithm this service ' +
          'accepts (ML-DSA-65+Ed25519)',
          '5a. a name absent from the accept list is refused');
  t.equal(crypto.openpgpAlgorithmProblem(
    { algorithm: 'ed25519', curve: '', bits: 0 }, 'sign', 3072), '',
          '5b. an omitted accept list still allows a classical name');
  t.equal(crypto.openpgpAlgorithmProblem(
    { algorithm: 'SLH-DSA-128+Ed25519', curve: '', bits: 0 }, 'sign', 3072),
          'SLH-DSA-128+Ed25519 is not an OpenPGP signing algorithm this ' +
          'service accepts (' + crypto.OPENPGP_SIGNING_ALGORITHMS.join(', ') +
          ')',
          '5c. an invented composite name is not on the universe');
  const classical = {
    primary: { algorithm: 'ed25519', curve: '', bits: 0 },
    signing: { algorithm: 'ed25519', curve: '', bits: 0 },
    subkeys: [{ algorithm: 'x25519', curve: '', bits: 0 }],
    encryption: { algorithm: 'x25519', curve: '', bits: 0 }
  };
  t.equal(crypto.openpgpRegistrationProblem(classical, {
    registration: true, pqcOnly: true }), 
          'openpgp.pqcOnly is on, so a new key must use a post-quantum ' +
          'algorithm (' + crypto.OPENPGP_PQ_NAMES.join(', ') + '); ed25519 ' +
          'and x25519 are not one',
          '6a. pqcOnly refuses a classical key at registration');
  t.equal(crypto.openpgpRegistrationProblem(classical, {
    registration: false, pqcOnly: true }), '',
          '6b. pqcOnly does not apply outside registration');
  const compositeOnly = {
    primary: { algorithm: 'ML-DSA-65+Ed25519', curve: '', bits: 0 },
    signing: { algorithm: 'ML-DSA-65+Ed25519', curve: '', bits: 0 },
    subkeys: [{ algorithm: 'ML-KEM-768+X25519', curve: '', bits: 0 }],
    encryption: { algorithm: 'ML-KEM-768+X25519', curve: '', bits: 0 }
  };
  t.equal(crypto.openpgpRegistrationProblem(compositeOnly, {
    registration: true, pqcOnly: true }), '',
          '6c. pqcOnly accepts a composite signing and encryption key');
  t.check(crypto.openpgpRegistrationProblem(compositeOnly, {
    registration: true, pqcAlongsideClassical: true
  }).indexOf('separate classical') >= 0,
          '6d. a composite alone is not the classical key alongside asks for');
  const both = {
    primary: { algorithm: 'ML-DSA-65+Ed25519', curve: '', bits: 0 },
    signing: { algorithm: 'ML-DSA-65+Ed25519', curve: '', bits: 0 },
    subkeys: [
      { algorithm: 'ML-KEM-768+X25519', curve: '', bits: 0 },
      { algorithm: 'ed25519', curve: '', bits: 0 }
    ]
  };
  t.equal(crypto.openpgpRegistrationProblem(both, {
    registration: true, pqcAlongsideClassical: true }), '',
          '6e. a composite beside a separate Ed25519 key satisfies alongside');
  t.equal(crypto.openpgpRegistrationProblem(classical, {
    registration: true, pqcOnly: true, pqcAlongsideClassical: true
  }).indexOf('openpgp.pqcOnly') >= 0 ? 'pqcOnly' : 'other', 'pqcOnly',
          '6f. when both switches are set, pqcOnly wins');

  return crypto.openpgpReadKey(read('a3-public.asc'), {
    at: new Date('2026-06-01T00:00:00Z'), minRsaBits: 3072,
    registration: true
  }).then(function (answer) {
    if (crypto.mlDsaAvailable()) {
      t.equal(answer.ok, true,
              '7. registration stores the appendix key when ML-DSA ' +
              'verifies');
      t.equal(codes.codeOf(answer), '',
              '7b. a checked registration records no refusal');
    } else {
      t.equal(codes.codeOf(answer), 'STS-OPENPGP-0026',
              '7. registration of the appendix key is STS-OPENPGP-0026 ' +
              'while ML-DSA cannot be checked');
      t.equal(answer.ok, false,
              '7b. that registration does not store the key');
    }
    return crypto.openpgpBinaryKey(read('a3-public.asc').toString('utf8'));
  }).then(function (binary) {
    t.check(Buffer.isBuffer(binary) && binary.length > 0,
            '8. the Web Key Directory can still publish an unchecked key ' +
            'that was stored after a real check',
            binary ? String(binary.length) : 'null');
    log.debug("Leaving checkPolicy().");
  });
}

// ---------------------------------------------------------------------------
// SYNTHETIC RFC 9980 KEYS, made here at run time (no secret is in the
// repository), so that what a third party can APPEND to a published key —
// a subkey with no binding, a revocation, a direct-key signature it could
// not have made — can be tested against signatures that really verify.
// ---------------------------------------------------------------------------

// A new-format packet (RFC 9580 section 4.2.1).
function packet(tag, body) {
  log.debug("Entering packet(). " + tag);
  const n = body.length;
  let len;
  if (n < 192) {
    len = Buffer.from([n]);
  } else if (n < 8384) {
    len = Buffer.from([((n - 192) >> 8) + 192, (n - 192) & 0xff]);
  } else {
    len = Buffer.alloc(5);
    len[0] = 0xff;
    len.writeUInt32BE(n, 1);
  }
  log.debug("Leaving packet().");
  return Buffer.concat([Buffer.from([0xc0 | tag]), len, body]);
}

function u32(n) {
  log.debug("Entering u32().");
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  log.debug("Leaving u32().");
  return b;
}

// A v6 key packet body: version, creation, algorithm, material length.
function keyBody(created, algorithm, material) {
  log.debug("Entering keyBody().");
  log.debug("Leaving keyBody().");
  return Buffer.concat([Buffer.from([6]), u32(created),
                        Buffer.from([algorithm]), u32(material.length),
                        material]);
}

// The primary: ML-DSA-65+Ed25519 (algorithm 30), its two secret halves
// kept by the test.
function compositePrimary(created) {
  log.debug("Entering compositePrimary().");
  const ed25519 = require('@noble/curves/ed25519').ed25519;
  const pqc = require('../common/crypto_impl/pqc');
  const edPriv = require('crypto').randomBytes(32);
  const edPub = Buffer.from(ed25519.getPublicKey(edPriv));
  const ml = pqc.generateAkpKeyPair('ML-DSA-65');
  const body = keyBody(created, 30,
                       Buffer.concat([edPub, Buffer.from(ml.pub)]));
  log.debug("Leaving compositePrimary().");
  return { body: body, edPriv: edPriv, mlPriv: ml.priv, created: created };
}

// An encryption subkey: ML-KEM-768+X25519 (algorithm 35), public halves.
function compositeSubkey(created) {
  log.debug("Entering compositeSubkey().");
  const x25519 = require('@noble/curves/ed25519').x25519;
  const pqc = require('../common/crypto_impl/pqc');
  const xPub = Buffer.from(x25519.getPublicKey(
    require('crypto').randomBytes(32)));
  const kem = pqc.kemAlg('ML-KEM-768').keygen();
  log.debug("Leaving compositeSubkey().");
  return keyBody(created, 35, Buffer.concat([xPub,
                                             Buffer.from(kem.publicKey)]));
}

// A hashed subpacket.
function sub(type, data) {
  log.debug("Entering sub(). " + type);
  log.debug("Leaving sub().");
  return Buffer.concat([Buffer.from([data.length + 1, type]), data]);
}

// A v6 composite signature of `type` by the primary over `subject`, with
// the given creation time, key flags and expiry; `bogus` writes random
// signature halves instead of signing.
function signature(leaf, primary, type, subject, opts) {
  log.debug("Entering signature(). " + type);
  const o = opts || {};
  const ed25519 = require('@noble/curves/ed25519').ed25519;
  const pqc = require('../common/crypto_impl/pqc');
  const parts = [sub(2, u32(o.created || primary.created + 10))];
  if (o.flags !== undefined) {
    parts.push(sub(27, Buffer.from([o.flags])));
  }
  if (o.expires) {
    parts.push(sub(9, u32(o.expires)));
  }
  const hashed = Buffer.concat(parts);
  const signatureData = Buffer.concat([Buffer.from([6, type, 30, 10]),
                                       u32(hashed.length), hashed]);
  const salt = require('crypto').randomBytes(32);
  const over = leaf.toSign(type, primary.body, subject, 6);
  const digest = leaf.dataDigest({ version: 6, hashAlg: 10, salt: salt,
                                   signatureData: signatureData }, over);
  const params = o.bogus ? require('crypto').randomBytes(64 + 3309)
    : Buffer.concat([Buffer.from(ed25519.sign(digest, primary.edPriv)),
                     Buffer.from(pqc.signWithPriv('ML-DSA-65', digest,
                                                  primary.mlPriv))]);
  const body = Buffer.concat([signatureData, u32(0), digest.subarray(0, 2),
                              Buffer.from([salt.length]), salt, params]);
  log.debug("Leaving signature().");
  return packet(2, body);
}

// The PKESK recipient fingerprint of an armored message `encryptTo()` wrote.
function recipientOf(leaf, armored) {
  log.debug("Entering recipientOf().");
  const pkesk = leaf.readPackets(leaf.dearmor(armored)).filter(function (p) {
    return p.tag === 1;
  })[0];
  log.debug("Leaving recipientOf().");
  return pkesk ? pkesk.body.subarray(3, 3 + pkesk.body[1] - 1)
    .toString('hex') : '';
}

function checkAppended(t, leaf) {
  log.debug("Entering checkAppended().");
  t.log.info('=== 9. what a third party can append ===');
  const now = Math.floor(Date.now() / 1000);
  const at = new Date();
  const primary = compositePrimary(now - 1000);
  const uid = Buffer.from('PQ test <pq-' + now + '@example.org>');
  const cert = signature(leaf, primary, 0x13, uid,
                         { created: now - 990, flags: 0x03 });
  const bound = compositeSubkey(now - 980);
  const binding = signature(leaf, primary, 0x18, bound,
                            { created: now - 970, flags: 0x0c });
  const head = Buffer.concat([packet(6, primary.body), packet(13, uid),
                              cert]);
  const base = leaf.readPublicKey(Buffer.concat([head, packet(14, bound),
                                                 binding]), at);
  if (!base.ok) {
    t.check(base.reason === 'unchecked',
            '9. (a synthetic key reads, or ML-DSA is unchecked here)',
            base.reason + ' ' + base.why);
    log.debug("Leaving checkAppended(). Unchecked here.");
    return;
  }
  const boundFp = leaf.fingerprintOf(bound);
  t.equal(base.description.encryption &&
          base.description.encryption.fingerprint, boundFp,
          '9a. a synthetic key reads, its bound subkey chosen');

  // An unbound subkey placed AHEAD of the bound one.
  const stranger = compositeSubkey(now - 500);
  const appended = leaf.readPublicKey(Buffer.concat([head,
    packet(14, stranger), packet(14, bound), binding]), at);
  t.check(appended.ok && appended.description.encryption &&
          appended.description.encryption.fingerprint === boundFp,
          '9b. an appended subkey with no binding is not chosen',
          JSON.stringify(appended.description &&
                         appended.description.encryption));
  t.equal((leaf.encryptionSubkeyOf(appended.key) || {}).fingerprint, boundFp,
          '9c. encryptTo() selects the bound subkey, not the first one of ' +
          'an encryption algorithm');
  let to = '';
  try {
    to = recipientOf(leaf, leaf.encryptTo(Buffer.from('hi'), appended.key));
  } catch (e) {
    log.debug("Caught in checkAppended(): " + ((e && e.message) || e));
    to = 'threw: ' + ((e && e.message) || e);
  }
  t.equal(to, boundFp, '9d. the message is encrypted to the bound subkey');

  // A binding that names no encryption use.
  const signOnly = leaf.readPublicKey(Buffer.concat([head,
    packet(14, bound), signature(leaf, primary, 0x18, bound,
                                 { created: now - 970, flags: 0x02 })]), at);
  t.equal(signOnly.description.encryption, null,
          '9e. a subkey whose binding flags name no encryption use is not ' +
          'encrypted to');

  // A subkey revocation the primary made.
  const revoked = leaf.readPublicKey(Buffer.concat([head, packet(14, bound),
    binding, signature(leaf, primary, 0x28, bound, { created: now - 100 })]),
    at);
  t.check(revoked.description.encryption === null &&
          revoked.description.subkeys[0].revoked === true,
          '9f. a revoked subkey is not encrypted to',
          JSON.stringify(revoked.description.subkeys));
  let threw = false;
  try {
    leaf.encryptTo(Buffer.from('hi'), revoked.key);
  } catch (e) {
    log.debug("Caught in checkAppended(): " + ((e && e.message) || e));
    threw = true;
  }
  t.check(threw, '9g. encryptTo() refuses a key whose subkey was revoked');
  const forged = leaf.readPublicKey(Buffer.concat([head, packet(14, bound),
    binding, signature(leaf, primary, 0x28, bound,
                       { created: now - 100, bogus: true })]), at);
  t.equal(forged.description.encryption &&
          forged.description.encryption.fingerprint, boundFp,
          '9h. a subkey revocation that does not verify revokes nothing');

  // A direct-key signature with an expiry already past.
  const bogusDirect = signature(leaf, primary, 0x1f, null,
                                { created: now - 50, expires: 60,
                                  bogus: true });
  const notExpired = leaf.readPublicKey(Buffer.concat([packet(6,
    primary.body), bogusDirect, packet(13, uid), cert, packet(14, bound),
    binding]), at);
  t.check(notExpired.ok && notExpired.description.expired === false &&
          notExpired.description.expiresAt === '',
          '9i. an expiry in a direct-key signature that does not verify is ' +
          'not read', JSON.stringify([notExpired.ok,
            notExpired.description.expiresAt]));
  const realDirect = signature(leaf, primary, 0x1f, null,
                               { created: now - 50, expires: 60,
                                 flags: 0x03 });
  const expired = leaf.readPublicKey(Buffer.concat([packet(6, primary.body),
    realDirect, packet(13, uid), cert]), at);
  t.check(expired.description.expired === true,
          '9j. the same expiry in one that verifies is read',
          expired.description.expiresAt);

  // A certification revocation (0x30), newer than the certification.
  const uidRevoked = leaf.readPublicKey(Buffer.concat([head,
    signature(leaf, primary, 0x30, uid, { created: now - 10 })]), at);
  t.check(!uidRevoked.ok && uidRevoked.description.users[0].valid === false,
          '9k. a user id whose certification was revoked is not valid',
          JSON.stringify(uidRevoked.description.users));

  // A primary whose self-signature withholds the sign flag.
  const certifyOnly = leaf.readPublicKey(Buffer.concat([packet(6,
    primary.body), packet(13, uid),
    signature(leaf, primary, 0x13, uid, { created: now - 990,
                                         flags: 0x01 })]), at);
  t.equal(certifyOnly.description.signing, null,
          '9l. a primary key whose flags omit signing has no signing key');

  // Two signatures on one cleartext proof.
  const text = 'proof ' + now;
  const one = signature(leaf, primary, 0x01, text, { created: now - 5 });
  const armor = function (sigs) {
    return '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n' + text +
      '\n-----BEGIN PGP SIGNATURE-----\n\n' +
      Buffer.concat(sigs).toString('base64') +
      '\n-----END PGP SIGNATURE-----\n';
  };
  const single = leaf.verifyCleartext(armor([one]), base.key);
  t.check(single.ok && single.text === text,
          '9m. a cleartext with one signature verifies',
          JSON.stringify([single.reason, single.why]));
  const double = leaf.verifyCleartext(armor([one, one]), base.key);
  t.check(!double.ok && double.reason === 'several',
          '9n. a cleartext carrying two signatures is refused',
          JSON.stringify([double.reason, double.why]));
  log.debug("Leaving checkAppended().");
}

// ---------------------------------------------------------------------------
// 10. SLH-DSA (#2220): RFC 9980 section 7's standalone signing algorithms,
// 32 (SLH-DSA-SHAKE-128s), 33 (-128f) and 34 (-256s), v6 keys only, each
// over the digest its Table 9 binds it to. A key is made here, signed with
// node's SLH-DSA through `pqc.js`, and read back.
// ---------------------------------------------------------------------------
// A v6 SLH-DSA primary of algorithm `id`, its secret kept by the test.
function slhPrimary(created, id, name) {
  log.debug("Entering slhPrimary(). " + name);
  const pqc = require('../common/crypto_impl/pqc');
  const kp = pqc.generateAkpKeyPair(name);
  log.debug("Leaving slhPrimary().");
  return { body: keyBody(created, id, Buffer.from(kp.pub)), priv: kp.priv,
           created: created, id: id, name: name };
}

// A v6 SLH-DSA signature of `type` over `subject`, made over `hashAlg`
// (12 SHA3-256, 14 SHA3-512, 10 SHA-512 for the refusal).
function slhSignature(leaf, primary, type, subject, hashAlg, opts) {
  log.debug("Entering slhSignature(). " + type);
  const o = opts || {};
  const pqc = require('../common/crypto_impl/pqc');
  const parts = [sub(2, u32(o.created || primary.created + 10))];
  if (o.flags !== undefined) {
    parts.push(sub(27, Buffer.from([o.flags])));
  }
  const hashed = Buffer.concat(parts);
  const signatureData = Buffer.concat([
    Buffer.from([6, type, primary.id, hashAlg]), u32(hashed.length), hashed]);
  const saltLen = hashAlg === 12 ? 16 : 32;
  const salt = require('crypto').randomBytes(saltLen);
  const over = leaf.toSign(type, primary.body, subject, 6);
  const digest = leaf.dataDigest({ version: 6, hashAlg: hashAlg, salt: salt,
                                   signatureData: signatureData }, over);
  const params = Buffer.from(pqc.signWithPriv(primary.name, digest,
                                              primary.priv));
  const body = Buffer.concat([signatureData, u32(0), digest.subarray(0, 2),
                              Buffer.from([salt.length]), salt, params]);
  log.debug("Leaving slhSignature().");
  return packet(2, body);
}

async function checkSlhDsa(t, leaf) {
  log.debug("Entering checkSlhDsa().");
  t.log.info('=== 10. SLH-DSA (#2220) ===');
  const crypto = require('../common/crypto');
  const codes = require('../common/error_codes');
  const now = Math.floor(Date.now() / 1000);
  const at = new Date();
  ['SLH-DSA-SHAKE-128s', 'SLH-DSA-SHAKE-128f', 'SLH-DSA-SHAKE-256s']
    .forEach(function (name) {
      t.check(crypto.OPENPGP_SIGNING_ALGORITHMS.indexOf(name) >= 0 &&
              crypto.OPENPGP_PQ_NAMES.indexOf(name) >= 0,
              '10a. ' + name + ' is an accepted, post-quantum signing ' +
              'algorithm');
    });
  t.equal(leaf.ALGS[32].name, 'SLH-DSA-SHAKE-128s',
          '10b. algorithm 32 is SLH-DSA-SHAKE-128s (RFC 9980 Table 8)');
  const primary = slhPrimary(now - 1000, 32, 'SLH-DSA-SHAKE-128s');
  const uid = Buffer.from('SLH test <slh-' + now + '@example.org>');
  const cert = slhSignature(leaf, primary, 0x13, uid, 12,
                            { created: now - 990, flags: 0x03 });
  const bound = compositeSubkey(now - 980);
  const binding = slhSignature(leaf, primary, 0x18, bound, 12,
                               { created: now - 970, flags: 0x0c });
  const whole = Buffer.concat([packet(6, primary.body), packet(13, uid),
                               cert, packet(14, bound), binding]);
  const read = leaf.readPublicKey(whole, at);
  if (!read.ok && read.reason === 'unchecked') {
    t.check(true, '10c. (SLH-DSA cannot be verified on this runtime: ' +
            'the key is unchecked, never accepted)', read.why);
    log.debug("Leaving checkSlhDsa(). Unchecked here.");
    return;
  }
  t.check(read.ok && read.description.primary.algorithm ===
          'SLH-DSA-SHAKE-128s',
          '10c. a v6 SLH-DSA-SHAKE-128s key with an ML-KEM subkey reads',
          (read.reason || '') + ' ' + (read.why || ''));
  t.equal(read.description && read.description.encryption &&
          read.description.encryption.fingerprint, leaf.fingerprintOf(bound),
          '10d. its bound ML-KEM-768+X25519 subkey is chosen');
  const policy = await crypto.openpgpReadKey(whole, {
    at: at, registration: true, pqcOnly: true });
  t.check(policy.ok === true,
          '10e. openpgp.pqcOnly accepts it: SLH-DSA is post-quantum',
          policy.error || '');
  const narrowed = await crypto.openpgpReadKey(whole, {
    at: at, accept: 'ML-DSA-65+Ed25519,ML-KEM-768+X25519' });
  t.equal(codes.codeOf(narrowed), 'STS-OPENPGP-0004',
          '10f. a realm whose openpgp.algorithms leaves SLH-DSA out ' +
          'refuses it');
  const wrongHash = leaf.readPublicKey(Buffer.concat([
    packet(6, primary.body), packet(13, uid),
    slhSignature(leaf, primary, 0x13, uid, 10, { created: now - 990,
                                                 flags: 0x03 })]), at);
  t.check(!wrongHash.ok && wrongHash.reason === 'bad-signature',
          '10g. an SLH-DSA-SHAKE-128s self-signature over SHA-512, not ' +
          'SHA3-256, is not believed', wrongHash.reason);
  const old = leaf.readPublicKey(Buffer.concat([packet(6, Buffer.concat([
    Buffer.from([4]), u32(primary.created), Buffer.from([32]),
    primary.body.subarray(10)])), packet(13, uid), cert]), at);
  t.check(!old.ok && /v6/.test(String(old.why)),
          '10h. SLH-DSA on a v4 key is refused (RFC 9980 section 7)',
          String(old.why));
  const doc = Buffer.from('signed by SLH-DSA');
  const detached = slhSignature(leaf, primary, 0x00, doc, 12);
  t.equal(leaf.verifyDetached(detached, doc, read.key).ok, true,
          '10i. a detached SLH-DSA signature verifies');
  t.equal(leaf.verifyDetached(detached, Buffer.from('other'), read.key).ok,
          false, '10j. and not over other bytes');
  const big = slhPrimary(now - 1000, 34, 'SLH-DSA-SHAKE-256s');
  const bigUid = Buffer.from('SLH256 <slh256-' + now + '@example.org>');
  const bigRead = leaf.readPublicKey(Buffer.concat([
    packet(6, big.body), packet(13, bigUid),
    slhSignature(leaf, big, 0x13, bigUid, 14, { created: now - 990,
                                                flags: 0x03 })]), at);
  t.check(bigRead.ok === true,
          '10k. SLH-DSA-SHAKE-256s over SHA3-512 reads',
          (bigRead.reason || '') + ' ' + (bigRead.why || ''));
  log.debug("Leaving checkSlhDsa().");
}

async function run(t) {
  log.debug("Entering run().");
  const leaf = require('../common/crypto_impl/openpgp_pqc');
  checkReader(t, leaf);
  checkAppended(t, leaf);
  await checkPolicy(t);
  await checkSlhDsa(t, leaf);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'openpgp_pqc',
  describe: 'RFC 9980 OpenPGP: the Appendix A.3 vectors, and registration ' +
            'narrowed the way a passkey request is',
  run: run
};

if (require.main === module) {
  const harness = require('./harness').createHarness('openpgp_pqc');
  run(harness).then(function () {
    const failures = harness.failures();
    if (failures.length) {
      failures.forEach(function (line) {
        harness.log.error(line);
      });
      process.exit(1);
    }
    harness.log.info(harness.passed() + ' passed');
  }).catch(function (e) {
    harness.log.error(String((e && e.stack) || e));
    process.exit(1);
  });
}
