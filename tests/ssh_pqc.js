// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssh_pqc.js
//
// ---------------------------------------------------------------------------
// THE SSH USER CA'S POST-QUANTUM SIBLING.
//
// OpenSSH defines no ML-DSA certificate. The published TrustedUserCAKeys
// line stays the first classical algorithm. ssh-mldsa-65 is this service's
// own wire name, and a runtime that cannot generate ML-DSA still makes the
// classical authority.
// ---------------------------------------------------------------------------

const log = require('bunyan').createLogger({ name: 'ssh_pqc',
  level: process.env.LOG_LEVEL || 'info' });

function run(t) {
  log.debug("Entering run().");
  const pki = require('../common/pki');
  const config = require('../common/config');
  const crypto = require('../common/crypto');
  t.equal(pki.sshClassicalCaAlgorithm(), 'ssh-ed25519',
          '1. the published algorithm is the first classical name');
  t.equal(pki.SSH_CA_ALGORITHMS['ssh-mldsa-65'].kind, 'pq',
          '2. ssh-mldsa-65 is the post-quantum authority algorithm');
  t.equal(pki.SSH_CA_ALGORITHMS['ssh-rsa'], undefined,
          '3. ssh-rsa is still not an authority algorithm');
  const onlyPq = config.setOverride('pki.sshUserCaAlgorithms',
                                    'ssh-mldsa-65');
  t.equal(onlyPq.ok, true, '4. a post-quantum-only list is a legal write');
  t.equal(pki.sshClassicalCaAlgorithm(), 'ssh-ed25519',
          '5. a list that names only ssh-mldsa-65 still publishes ' +
          'ssh-ed25519');
  config.clearOverride('pki.sshUserCaAlgorithms');
  const raw = Buffer.alloc(1952, 7);
  const pub = pki.sshPqPublicKey('ssh-mldsa-65', raw);
  const parsed = pki.parseSshPublicKey(pub.blob);
  t.equal(parsed.type, 'ssh-mldsa-65',
          '6. an ML-DSA public blob names ssh-mldsa-65');
  t.equal(parsed.raw.length, 1952,
          '7. the blob carries the raw 1952-octet public key');
  t.equal(Buffer.compare(parsed.raw, raw), 0,
          '8. the raw public key round-trips');
  const first = config.setOverride('pki.sshUserCaPqcOnly', true);
  t.equal(first.ok, true, '9. pqcOnly alone is a legal write');
  const second = config.setOverride('pki.sshUserCaPqcAlongsideClassical',
                                    true);
  t.equal(second.ok, false, '10. the two switches cannot both be on');
  t.equal(require('../common/error_codes').codeOf(second), 'STS-PKI-0296',
          '11. that refusal is STS-PKI-0296');
  config.clearOverride('pki.sshUserCaPqcOnly');
  config.clearOverride('pki.sshUserCaPqcAlongsideClassical');
  const krl = pki.buildSshKrl({
    version: BigInt(3), generatedAt: BigInt(9), comment: 'two',
    authorities: [
      { caBlob: Buffer.from('classical-ca'), serials: [BigInt(4)] },
      { caBlob: Buffer.from('pq-ca'), serials: [BigInt(5)] }
    ],
    keySha256: []
  });
  const read = pki.parseSshKrl(krl);
  t.equal(read.authorities.length, 2,
          '12. a KRL can name the classical authority and the sibling');
  t.equal(read.authorities[1].caBlob.toString('utf8'), 'pq-ca',
          '13. the sibling section carries the ML-DSA authority blob');
  if (!crypto.mlDsaAvailable()) {
    let message = '';
    return pki.generateSshCaKey('ssh-mldsa-65').then(function () {
      t.check(false, '14. ML-DSA key generation was refused');
    }, function (e) {
      message = String((e && e.message) || e);
      t.check(message.indexOf('ML-DSA') >= 0,
              '14. a runtime without ML-DSA refuses the sibling key',
              message);
      return pki.generateSshCaKey('ssh-ed25519');
    }).then(function (key) {
      t.check(key.publicLine.indexOf('ssh-ed25519 ') === 0,
              '15. the classical authority still generates',
              key.publicLine.slice(0, 24));
      log.debug("Leaving run().");
    });
  }
  log.debug("Leaving run(). ML-DSA is available; generation is not " +
            "asserted here.");
  return Promise.resolve();
}

module.exports = {
  name: 'ssh_pqc',
  describe: 'SSH user CA: the published line stays classical, and ' +
            'ML-DSA is a sibling authority',
  run: run
};

if (require.main === module) {
  const harness = require('./harness').createHarness('ssh_pqc');
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
