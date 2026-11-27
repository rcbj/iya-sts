// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssh_krl_first_fetch.js
//
// ---------------------------------------------------------------------------
// THE FIRST GET /pki/ssh-user-krl OF A PRODUCT REALM IS ANSWERED (#2092).
//
// The KRL is derived from the issued register and the realm's PKI row, and
// `buildSshUserKrlAsync()` keeps a copy of the bytes on that row so the
// next fetch is not signed again. It refused the KRL (503, STS-PKI-0290)
// when that COPY did not reach the store, and in product on a store that
// keeps nothing no write is ever queued — so every realm's first fetch was
// refused and its second answered from the copy this process held. An sshd
// refreshing RevokedKeys at that moment kept a stale list
// (`tests/protocol/sts_ssh_client_lab.js` found it). Now the list built is
// answered and the failure is logged under STS-PKI-0299.
//
// In a child process, because it starts the process in product mode with
// no store, which no other file here should share:
//   A. the first and second fetch through PkiService.sshUserKrlFor() are
//      200 and a KRL, the first already listing a revoked certificate;
//   B. the cache failure is logged under STS-PKI-0299 and STS-PKI-0290 is
//      not;
//   C. in development (nothing persists) the first fetch is a KRL and
//      nothing is logged under either code.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'ssh_krl_first_fetch',
  level: process.env.LOG_LEVEL || 'info' });

// The child: a revoked certificate in the default realm's register, then
// two fetches through the real handler and the real PKI. It prints one
// RESULT line; everything else on stdout is the service's own log.
const CHILD = `
const pki = require('./common/pki');
const errorCodes = require('./common/error_codes');
const register = require('./common/ssh_issued');
const pkiService = require('./pki/pki_service');
function stub() {
  const res = { statusCode: 0, headers: {}, body: null,
    status: function (c) { res.statusCode = c; return res; },
    type: function (v) { res.headers['Content-Type'] = v; return res; },
    set: function (n, v) { res.headers[n] = v; return res; },
    send: function (b) { res.body = b; return res; } };
  return res;
}
(async function () {
  const service = new pkiService.PkiService({
    http: {}, stsCrypto: {}, app: function () {}, config: {},
    log: require('bunyan').createLogger({ name: 'child', level: 'fatal' }),
    pki: pki, errorCodes: errorCodes, certificateHeader: {},
    proxyProtocol: {},
    realms: { get: function () { return { id: '' }; } },
    revocation: { scopeFromSegment: function () { return ''; } }
  });
  const now = Date.now();
  await register.record('', [{ serialHex: '7a01', keyType: 'ssh-ed25519',
    keyFingerprint: 'SHA256:probe', ownerSubject: 'urn:uuid:probe',
    principals: ['probe'], issuedAt: new Date(now).toISOString(),
    notAfter: new Date(now + 600000).toISOString(),
    revokedAt: new Date(now).toISOString(), caMember: 'sshUserCa',
    certificate: 'ssh-ed25519-cert-v01 x' }]);
  const out = [];
  for (let i = 0; i < 2; i++) {
    const res = stub();
    await service.sshUserKrlFor(res, 'default');
    let serials = null;
    if (res.statusCode === 200) {
      const krl = pki.parseSshKrl(res.body);
      serials = [];
      (krl.authorities || []).forEach(function (a) {
        (a.serials || []).forEach(function (s) {
          serials.push(s.toString(16));
        });
      });
    }
    out.push({ status: res.statusCode, serials: serials });
  }
  process.stdout.write('RESULT ' + JSON.stringify(out) + '\\n');
  process.exit(0);
})().catch(function (e) {
  process.stdout.write('RESULT ' + JSON.stringify({ threw: String(e &&
    e.stack || e) }) + '\\n');
  process.exit(0);
});
`;

function inChild(env) {
  log.debug('Entering inChild().');
  const childEnv = Object.assign({}, process.env, env, { LOG_LEVEL: 'warn' });
  delete childEnv.CONFIG_FILE;
  delete childEnv.STS_KEYS_SOURCE;
  delete childEnv.STS_PERSISTENCE_MODE;
  const result = childProcess.spawnSync(process.execPath, ['-e', CHILD], {
    cwd: path.join(__dirname, '..'), env: childEnv, encoding: 'utf8',
    timeout: 120000, maxBuffer: 64 * 1024 * 1024 });
  const text = String(result.stdout || '') + String(result.stderr || '');
  const line = text.split('\n').filter(function (one) {
    return one.indexOf('RESULT ') === 0;
  })[0];
  let answers = null;
  try {
    answers = line ? JSON.parse(line.slice('RESULT '.length)) : null;
  } catch (e) {
    log.debug('Caught in inChild(): ' + ((e && e.message) || e));
    answers = null;
  }
  log.debug('Leaving inChild().');
  return { answers: answers, text: text };
}

function run(t) {
  log.debug('Entering run().');
  const product = inChild({ STS_MODE: 'product' });
  const answers = Array.isArray(product.answers) ? product.answers : [];
  t.check(answers.length === 2 && answers[0].status === 200,
          'A1. a product realm\'s FIRST KRL fetch is 200 with no store',
          JSON.stringify(product.answers) + ' ' + product.text.slice(-2000));
  t.check(answers.length === 2 && answers[1].status === 200,
          'A2. and so is the second', JSON.stringify(product.answers));
  t.check(answers.length === 2 &&
          (answers[0].serials || []).indexOf('7a01') >= 0 &&
          (answers[1].serials || []).indexOf('7a01') >= 0,
          'A3. the first answer is a KRL already listing the revoked ' +
          'certificate', JSON.stringify(product.answers));
  t.check(product.text.indexOf('STS-PKI-0299') >= 0,
          'B1. the cache that could not be persisted is logged under ' +
          'STS-PKI-0299');
  t.check(product.text.indexOf('STS-PKI-0290') < 0,
          'B2. and nothing is refused under STS-PKI-0290');
  const development = inChild({ STS_MODE: 'development' });
  const dev = Array.isArray(development.answers) ? development.answers : [];
  t.check(dev.length === 2 && dev[0].status === 200 &&
          (dev[0].serials || []).indexOf('7a01') >= 0,
          'C1. in development the first fetch is a KRL too',
          JSON.stringify(development.answers));
  t.check(development.text.indexOf('STS-PKI-0299') < 0 &&
          development.text.indexOf('STS-PKI-0290') < 0,
          'C2. and nothing persists there, so neither code is logged');
  log.debug('Leaving run().');
}

module.exports = {
  name: 'ssh_krl_first_fetch',
  describe: 'the first GET /pki/ssh-user-krl of a product realm with no ' +
            'store is a KRL, the cache failure logged (#2092)',
  run: run
};
