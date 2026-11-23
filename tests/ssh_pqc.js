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
// own wire name, published beside that line with ?algorithm=ssh-mldsa-65,
// and a runtime that cannot generate ML-DSA still makes the classical
// authority. pki.sshUserCaPqcOnly refuses (STS-PKI-0297) when the realm has
// no ML-DSA authority, rather than issue a classical certificate.
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
  return pqcOnlyRefuses(t, pki, config).then(function () {
    return publication(t);
  }).then(function () {
    return generation(t, pki, crypto);
  });
}

// 16-19. pki.sshUserCaPqcOnly with no ML-DSA authority REFUSES
// (STS-PKI-0297) instead of handing out a classical certificate. The
// authority is made absent the one way every runtime shares: ssh-mldsa-65
// taken off the algorithm list. With the switch off the same request is
// issued classically.
async function pqcOnlyRefuses(t, pki, config) {
  log.debug("Entering pqcOnlyRefuses().");
  const codes = require('../common/error_codes');
  const subject = await pki.generateSshCaKey('ssh-ed25519');
  const spec = { subjectBlob: subject.publicBlob, principals: ['alice'],
                 ownerSubject: 'urn:uuid:alice', lifetimeS: 300 };
  const list = config.setOverride('pki.sshUserCaAlgorithms', 'ssh-ed25519');
  t.equal(list.ok, true, '16. a classical-only algorithm list is a legal ' +
          'write');
  const only = config.setOverride('pki.sshUserCaPqcOnly', true);
  t.equal(only.ok, true, '17. pqcOnly is a legal write beside it');
  try {
    const refused = await pki.issueSshUserCertificateAsync('', spec);
    t.equal(refused.ok, false,
            '18. pqcOnly with no ML-DSA authority issues nothing');
    t.equal(codes.codeOf(refused), 'STS-PKI-0297',
            '18a. that refusal is STS-PKI-0297', JSON.stringify(refused));
  } finally {
    config.clearOverride('pki.sshUserCaPqcOnly');
  }
  try {
    const issued = await pki.issueSshUserCertificateAsync('', spec);
    t.check(issued.ok === true && String(issued.line)
      .indexOf('ssh-ed25519-cert-v01@openssh.com ') === 0,
            '19. with the switch off the certificate is classical',
            JSON.stringify(issued).slice(0, 160));
  } finally {
    config.clearOverride('pki.sshUserCaAlgorithms');
  }
  log.debug("Leaving pqcOnlyRefuses().");
}

// A response the PKI service writes into, as far as these routes use it.
function fakeResponse() {
  log.debug("Entering fakeResponse().");
  const res = { statusCode: 0, body: '', headers: {} };
  res.status = function (n) {
    res.statusCode = n;
    return res;
  };
  res.type = function () {
    return res;
  };
  res.set = function (name, value) {
    res.headers[String(name).toLowerCase()] = value;
    return res;
  };
  res.send = function (body) {
    res.body = String(body);
    return res;
  };
  res.locals = {};
  log.debug("Leaving fakeResponse().");
  return res;
}

// 20-23. The ML-DSA authority is PUBLISHED beside the classical one, at the
// same path with ?algorithm=ssh-mldsa-65, never concatenated onto it.
async function publication(t) {
  log.debug("Entering publication().");
  const PkiService = require('../pki/pki_service').PkiService;
  const codes = require('../common/error_codes');
  let pqcLine = 'ssh-mldsa-65 AAAApq';
  const stub = {
    SERVICE_SCOPE: '*service', PROCESS_SCOPE: '*process',
    sshUserCaPublicKeyAsync: async function () {
      return { ok: true, publicLine: 'ssh-ed25519 AAAAclassical',
               fingerprint: 'SHA256:c', pqcPublicLine: pqcLine,
               pqcFingerprint: pqcLine ? 'SHA256:p' : '' };
    }
  };
  const service = new PkiService(Object.assign(PkiService.defaultDeps(), {
    pki: stub,
    realms: { get: function () {
      return { id: 'acme' };
    } },
    revocation: { scopeFromSegment: function (s) {
      return s;
    } }
  }));
  const plain = fakeResponse();
  await service.sshUserCaFor(plain, 'acme', '');
  t.equal(plain.body, 'ssh-ed25519 AAAAclassical\n',
          '20. without the parameter the line is the classical one alone');
  const pq = fakeResponse();
  await service.sshUserCaFor(pq, 'acme', 'ssh-mldsa-65');
  t.check(pq.statusCode === 200 && pq.body === 'ssh-mldsa-65 AAAApq\n' &&
          pq.headers['cache-control'] === 'no-store',
          '21. algorithm=ssh-mldsa-65 answers the ML-DSA line, no-store',
          pq.statusCode + ' ' + pq.body);
  const other = fakeResponse();
  await service.sshUserCaFor(other, 'acme', 'ssh-rsa');
  t.check(other.statusCode === 400 &&
          codes.codeOf(other) === 'STS-PKI-0298',
          '22. another algorithm is refused 400 (STS-PKI-0298)',
          other.statusCode + ' ' + codes.codeOf(other));
  pqcLine = '';
  const none = fakeResponse();
  await service.sshUserCaFor(none, 'acme', 'ssh-mldsa-65');
  t.check(none.statusCode === 404 &&
          codes.codeOf(none) === 'STS-PKI-0298',
          '23. a realm with no ML-DSA authority answers 404 (STS-PKI-0298)',
          none.statusCode + ' ' + codes.codeOf(none));
  log.debug("Leaving publication().");
}

// 14-15. Generation, as the runtime allows it.
function generation(t, pki, crypto) {
  log.debug("Entering generation().");
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
      log.debug("Leaving generation().");
    });
  }
  log.debug("Leaving generation(). ML-DSA is available; generation is " +
            "not asserted here.");
  return Promise.resolve();
}

module.exports = {
  name: 'ssh_pqc',
  describe: 'SSH user CA: the published line stays classical, ML-DSA is ' +
            'a sibling authority published beside it, and pqcOnly refuses ' +
            'without it',
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
