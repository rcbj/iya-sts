// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/pbes2_export_iterations.js
//
// ---------------------------------------------------------------------------
// A PASSWORD-PROTECTED KEY EXPORT IS STRETCHED AS FAR AS #1512 SAYS (#1577).
//
// #1512 (ASVS 5.0.0 11.4.4) adopted 600,000 PBKDF2-HMAC-SHA256 iterations for
// PBES2 and PKCS#12 export. `common/crypto.js` and the PKCS#12 builder used it;
// `jose_jwe.js`'s `pbes2JweEncrypt()`, which password-protects a JWK the
// console's key panes download, still fixed `p2c` at 100,000. This holds:
//
//   1. an exported, password-protected JWK is a PBES2 JWE with `p2c` 600,000;
//   2. it is the figure `crypto.js` encrypts with, and the one PKCS#12 reads;
//   3. `crypto.js` opens it with the password, so the two implementations of
//      RFC 7518 section 4.8 still agree on the salt, and refuses a wrong one.
//
// WHY IN PROCESS (tests/CLAUDE.md's first question): the export is a library
// call a console pane makes and downloads in the browser; no HTTP answer
// carries the JWE's header to assert on.
// ---------------------------------------------------------------------------

const path = require('path');

delete process.env.CONFIG_FILE;

const ROOT = path.join(__dirname, '..');

function headerOf(compact) {
  return JSON.parse(Buffer.from(String(compact).split('.')[0], 'base64url')
    .toString('utf8'));
}

async function run(t) {
  t.log.debug("Entering run().");
  const keyMaterial = require(ROOT + '/common/crypto_impl/key_material');
  const jose = require(ROOT + '/common/crypto_impl/jose_jwe');
  const stsCrypto = require(ROOT + '/common/crypto');
  const secret = Buffer.from('a-secret-for-the-pbes2-export-test')
    .toString('base64url');
  const exported = await keyMaterial.exportKeyPair({
    format: 'jwk', desc: { kind: 'hmac' }, privatePem: secret,
    password: 'correct horse battery staple', alg: 'HS256', use: 'sig',
    baseName: 'pbes2-test' });
  const file = exported.files[0];
  const header = headerOf(file.data);
  t.equal(header.alg, 'PBES2-HS256+A128KW',
          '1a. a password-protected JWK export is a PBES2 JWE');
  t.equal(header.p2c, 600000,
          '1b. its p2c is 600,000, OWASP\'s PBKDF2-HMAC-SHA256 figure ' +
          '(#1512)');
  t.equal(jose.PBKDF2_EXPORT_ITERATIONS, 600000,
          '2a. the constant PKCS#12 export reads is the same figure');
  const ours = stsCrypto.encryptJweCompact('x',
    { alg: 'PBES2-HS256+A128KW', enc: 'A256GCM', secret: 'pw' });
  t.equal(headerOf(ours).p2c, header.p2c,
          '2b. and crypto.js encrypts with it too');
  const opened = stsCrypto.decryptJweCompact(file.data,
    { secret: 'correct horse battery staple' });
  const jwk = JSON.parse(String(opened.plaintext));
  t.check(jwk.kty === 'oct' && jwk.k === secret,
          '3a. crypto.js opens the export with the password', jwk.kty);
  let wrong = '';
  try {
    stsCrypto.decryptJweCompact(file.data, { secret: 'wrong password' });
    wrong = 'opened';
  } catch (e) {
    t.log.debug("Caught in run(): " + ((e && e.message) || e));
    wrong = 'refused';
  }
  t.equal(wrong, 'refused', '3b. and refuses it with a wrong one');
  t.log.debug("Leaving run().");
}

module.exports = {
  name: 'pbes2_export_iterations',
  describe: 'a password-protected key export is PBES2 at 600,000 ' +
            'iterations, the figure PKCS#12 and crypto.js use (#1512, #1577)',
  run: run
};
