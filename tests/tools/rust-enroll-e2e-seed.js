// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: rust-enroll-e2e-seed.js
//
// ---------------------------------------------------------------------------
// THE CREDENTIALS `rust-enroll-e2e.sh` HANDS THE CLIENTS (#444, phase 6):
// an ACME External Account Binding key, a SCEP challenge and a registered
// host name, written onto a person's entry in the LDIF a Node service left,
// in the form `common/cert_enrollment.ts`'s `createEab()`,
// `createScepChallenge()` and `addHostName()` write them (development
// mode, so nothing is sealed). The Rust runtime has no `/admin-api` yet
// (the management-API slice), and the enrollment vectors prove these rows
// read alike on both sides; this puts them where a real client finds them.
//
//   node rust-enroll-e2e-seed.js <realm-default.ldif> <uid> <host> <out.json>
//
// Uses only node's own modules, so it runs on the host.
// ---------------------------------------------------------------------------

const fs = require('fs');
const nodeCrypto = require('crypto');

const [FILE, UID, HOST, OUT] = process.argv.slice(2);

/**
 * A credential id as `credentialId()` makes one for a person.
 *
 * @param {string} prefix - `eab` or `scep`
 * @returns {string} the id
 */
function credentialId(prefix) {
  return prefix + '-p-' + Buffer.from(UID, 'utf8').toString('base64url') +
         '-' + nodeCrypto.randomBytes(8).toString('hex');
}

/**
 * One LDIF line, base64 (RFC 2849 `::`) so a JSON value needs no folding
 * rules.
 *
 * @param {string} name - the attribute
 * @param {string} value - its value
 * @returns {string} the line
 */
function line(name, value) {
  return name + ':: ' + Buffer.from(value, 'utf8').toString('base64');
}

/**
 * The seeding.
 */
function main() {
  const now = Date.now();
  const iso = function (ms) {
    return new Date(ms).toISOString();
  };
  const kid = credentialId('eab');
  const hmacKey = nodeCrypto.randomBytes(32).toString('base64url');
  const scepId = credentialId('scep');
  const secret = nodeCrypto.randomBytes(24).toString('base64url');
  const eab = { kid: kid, hmacKey: hmacKey, createdAt: iso(now),
                expiresAt: iso(now + 7 * 86400000), createdBy: 'e2e',
                boundAccount: null, boundAt: null };
  const challenge = { id: scepId,
                      sha256: nodeCrypto.createHash('sha256').update(secret)
                        .digest('hex'),
                      profile: 'tls-client', createdAt: iso(now),
                      expiresAt: iso(now + 3600000), createdBy: 'e2e',
                      usedAt: null };
  const added = [line('stsAcmeEabKey', JSON.stringify(eab)),
                 line('stsScepChallenge', JSON.stringify(challenge)),
                 'stsCertificateHostName: ' + HOST];
  const lines = fs.readFileSync(FILE, 'utf8').split('\n');
  const dn = new RegExp('^dn: uid=' + UID + ',ou=users,', 'i');
  const at = lines.findIndex(function (one) {
    return dn.test(one);
  });
  if (at < 0) {
    throw new Error('no entry for ' + UID + ' in ' + FILE);
  }
  let end = at;
  while (end < lines.length && lines[end] !== '') {
    end += 1;
  }
  lines.splice.apply(lines, [end, 0].concat(added));
  fs.writeFileSync(FILE, lines.join('\n'));
  fs.writeFileSync(OUT, JSON.stringify({ kid: kid, hmacKey: hmacKey,
                                         challenge: scepId + '.' + secret,
                                         host: HOST, uid: UID }));
}

main();
