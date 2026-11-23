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
// encapsulation is not attempted here.
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
          '5c. SLH-DSA is not on the universe');
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

async function run(t) {
  log.debug("Entering run().");
  const leaf = require('../common/crypto_impl/openpgp_pqc');
  checkReader(t, leaf);
  await checkPolicy(t);
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
