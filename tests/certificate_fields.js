// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/certificate_fields.js — `crypto.js` SECTION 18 AND `pathRuleProblem()`'s
// `opts.leaf` (#1360).
//
// A file of its own rather than a section of `crypto_module.js`, whose `run` is
// synchronous and which mints no chain. Every check is made to fail once and
// pass once, with the extendedKeyUsage triple the design turns on: present but
// wrong, absent and required, absent and optional.
//
// MUTATION RECORD, each applied to a scratch build, seen red and put back:
//   * a keyUsage absent read as permitting nothing       — 1 red (B)
//   * anyExtendedKeyUsage answering a required EKU       — 1 red (C)
//   * the key size asking `mode` in development          — 1 red (E)
//   * `certificateNameMatches()` falling back to the CN  — 1 red (G)
//   * `pathRuleProblem()` not asking `opts.leaf`         — 3 red (I)
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const stsCrypto = require('../common/crypto');
const pki = require('../common/pki');
const kit = require('./tools/trust_kit');
const keys = require('../common/crypto_impl/key_material');

const log = require('bunyan').createLogger({ name: 'certificate_fields_test',
  level: process.env.LOG_LEVEL || 'info' });

module.exports = {
  name: 'certificate_fields',
  describe: 'the field checks of crypto.js section 18, each failing once and ' +
            'passing once, and the path rules asking them of a leaf',
  run: async function (t) {
    log.debug("Entering run().");
    const now = Date.now();
    const root = await kit.mint({ cn: 'field root', ca: true });
    const plain = await kit.mint({ cn: 'field leaf', issuer: root });
    const check = function (cert, options) {
      log.debug("Entering check().");
      const problem = stsCrypto.certificateFieldProblem(cert.pem || cert,
                                                        options);
      log.debug("Leaving check().");
      return problem ? problem.check : null;
    };

    t.log.info('A. validity');
    const old = await kit.mint({ cn: 'old', issuer: root,
      notBefore: now - 3 * kit.DAY, notAfter: now - kit.DAY });
    const soon = await kit.mint({ cn: 'soon', issuer: root,
      notBefore: now + kit.DAY, notAfter: now + 2 * kit.DAY });
    t.equal(check(plain), null, 'A. a current certificate holds');
    t.equal(check(old), 'validity', 'A. expired');
    t.equal(stsCrypto.certificateFieldProblem(old.pem).code, 'STS-KEYS-0168',
            'A. under its own code');
    t.equal(stsCrypto.certificateFieldProblem(soon.pem).code, 'STS-KEYS-0169',
            'A. not yet valid, under its own');
    t.equal(check(old, { skewMs: 2 * kit.DAY }), null, 'A. skew widens it');
    t.equal(check(old, { validityAt: now - 2 * kit.DAY }), null,
            'A. validityAt replaces now for the window alone');

    t.log.info('B. keyUsage and basicConstraints');
    const noUsage = await kit.mint({ cn: 'no ku', issuer: root,
                                     noKeyUsage: true });
    t.equal(check(plain, { keyUsage: ['digitalSignature'] }), null,
            'B. the bit asked');
    t.equal(check(plain, { keyUsage: ['keyEncipherment', 'keyAgreement'] }),
            'key-usage', 'B. none of the bits asked');
    t.equal(check(plain, { keyUsage: ['keyAgreement', 'digitalSignature'] }),
            null, 'B. any of them will do');
    t.equal(check(noUsage, { keyUsage: ['keyEncipherment'] }), null,
            'B. absent permits everything');
    t.equal(check(root), 'basic-constraints', 'B. a CA as a leaf');
    t.equal(check(root, { mayBeCa: true }), null, 'B. unless it may be one');
    t.equal(check(root, { role: 'anchor', keyUsage: ['keyCertSign'] }), null,
            'B. an anchor is a CA that may sign');
    t.equal(check(plain, { role: 'intermediate' }), 'basic-constraints',
            'B. a leaf as an intermediate');

    t.log.info('C. extendedKeyUsage: the triple');
    const client = await kit.mint({ cn: 'client', issuer: root,
                                    eku: ['clientAuth'] });
    const any = await kit.mint({ cn: 'any', issuer: root,
                                 eku: ['anyExtendedKeyUsage'] });
    const asked = { oids: [stsCrypto.EKU.serverAuth], required: false };
    const must = { oids: [stsCrypto.EKU.serverAuth], required: true };
    t.equal(check(client, { eku: asked }), 'extended-key-usage',
            'C. present but wrong');
    t.equal(check(plain, { eku: must }), 'extended-key-usage',
            'C. absent and required');
    t.equal(check(plain, { eku: asked }), null, 'C. absent and optional');
    t.equal(check(client, { eku: { oids: [stsCrypto.EKU.clientAuth],
                                   required: true } }), null,
            'C. present and named');
    t.equal(check(any, { eku: asked }), null,
            'C. anyExtendedKeyUsage answers where presence is not required');
    t.equal(check(any, { eku: must }), 'extended-key-usage',
            'C. and not where the specification names the purpose');

    t.log.info('D. the signature');
    const sha1 = await kit.mint({ cn: 'sha1', issuer: root,
                                  signatureAlg: 'sha1-rsa' });
    t.equal(check(sha1), 'signature-strength', 'D. SHA-1');
    t.equal(check(sha1, { allowSha1: true }), null,
            'D. unless the caller allows it');

    t.log.info('E. the key');
    // Node's own generator: the service's refuses to make a key this short.
    const short = { publicPem: nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 1024 }).publicKey
      .export({ type: 'spki', format: 'pem' }) };
    const small = await kit.mint({ cn: 'small key', issuer: root, pair: short });
    t.equal(check(small), 'key-strength',
            'E. a short RSA key, in development too: the check is the check');
    const ec = await keys.generateKeyPair('ec-p256');
    const named = await kit.mint({ cn: 'p256', issuer: root, pair: ec });
    t.equal(check(named), null, 'E. a named curve this service relies on');

    t.log.info('F. critical extensions');
    const critical = await kit.mint({ cn: 'critical', issuer: root,
                                      critical: '1.3.6.1.4.1.55555.7.3' });
    t.equal(check(critical), 'critical-extensions',
            'F. a critical extension nothing reads');
    t.equal(check(critical, { allowCritical: ['1.3.6.1.4.1.55555.7.3'] }), null,
            'F. unless the caller reads it');
    t.equal(stsCrypto.certificateFieldProblems(old.pem,
      { keyUsage: ['keyEncipherment'] }).length, 2,
            'F. the plural answers every check that failed');

    t.log.info('G. names');
    const host = await kit.mint({ cn: 'cn.example', issuer: root,
      san: ['DNS:san.example', 'URI:https://san.example/x',
            'EMAIL:a@san.example', 'IP:192.0.2.1'] });
    const matches = function (expected) {
      log.debug("Entering matches().");
      log.debug("Leaving matches().");
      return stsCrypto.certificateNameMatches(host.pem, expected);
    };
    t.check(matches({ dns: 'san.example' }), 'G. a dNSName', '');
    t.check(!matches({ dns: 'cn.example' }),
            'G. never the common name (RFC 9525)', '');
    t.check(matches({ uri: 'https://san.example/x' }), 'G. a URI', '');
    t.check(matches({ email: 'a@san.example' }), 'G. an email', '');
    t.check(matches({ ip: '192.0.2.1' }), 'G. an address', '');
    t.check(matches({ dns: 'san.example', ip: '192.0.2.1' }),
            'G. every member given', '');
    t.check(!matches({ dns: 'san.example', ip: '192.0.2.2' }),
            'G. one wrong refuses', '');
    t.check(!matches({}), 'G. asking nothing matches nothing', '');

    t.log.info('H. the facts');
    const facts = stsCrypto.certificateFacts(host.pem);
    t.equal(facts.subject, 'CN=cn.example', 'H. the subject');
    t.equal(facts.selfIssued, false, 'H. not self-issued');
    t.equal(facts.san.dns[0], 'san.example', 'H. the SAN');
    t.equal(facts.san.ip[0], '192.0.2.1', 'H. an address read back');
    t.equal(stsCrypto.certificateFacts(root.pem).ca, true, 'H. cA');
    t.equal(stsCrypto.certificateFacts(root.pem).pathLen, 1, 'H. pathLen');
    t.equal(stsCrypto.certificateFacts(plain.pem).eku, null,
            'H. absent is null and not empty');

    t.log.info('I. the path rules asking them of a leaf');
    const entry = function (cert) {
      log.debug("Entering entry().");
      log.debug("Leaving entry().");
      return pki.certificateFromDer(pki.pemToDer(cert.pem));
    };
    const path = [entry(client), entry(root)];
    t.equal(pki.pathRuleProblem(path, {}), null,
            'I. with no use case, the path is what it was');
    const refused = pki.pathRuleProblem(path, { leaf: {
      keyUsage: ['digitalSignature'],
      eku: { oids: [stsCrypto.EKU.serverAuth], required: true } } });
    t.equal(refused && refused.check, 'extended-key-usage',
            'I. a use case makes the leaf\'s fields a path rule');
    t.equal(refused && refused.index, 0, 'I. at the leaf');
    t.equal(refused && refused.code, 'STS-KEYS-0172', 'I. with the code');
    t.equal(pki.pathRuleProblem(path, { leaf: { keyUsage:
      ['digitalSignature'], eku: { oids: [stsCrypto.EKU.clientAuth],
                                   required: true } } }), null,
            'I. and holds when the leaf does');
    log.debug("Leaving run().");
  }
};
