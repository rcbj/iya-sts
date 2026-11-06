// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/listener_path_rules.js — THE HOLD ON EVERY LISTENER (#1360, Phase 1).
//
// In a CHILD PROCESS, because `tls/tls_server.js` registers its views at require
// and the anchors are the process's. Real handshakes, on listeners this file
// builds with the main port's posture, with `holdConnectionsOn()` installed as
// LDAPS and the debugger install it: an answer of what the socket came to say.
//
// A: not in force, the hold is what it was: the rules alone, and nothing happens
//    on `holdConnectionsOn()`'s listener. B: in force, a CA presented as a client
//    is demoted, a good one is not.
//    C: revocation, off a CRL, before the first byte is read. D: resumption: the
//    demotion carried, and a session nothing remembers demoted.
//    E: a throw inside the hold fails closed in force and leaves OpenSSL's verdict
//    alone out of force. F: the row, and the master.
//
// OPENSSL ALREADY REFUSES AN EKU OR A keyUsage THE CLIENT PURPOSE CANNOT USE at a
// handshake (INVALID_PURPOSE), so a CA presented as a client is what separates
// the two states here: OpenSSL takes it and the hold does not.
//
// MUTATION RECORD, each applied to a scratch build, seen red and put back:
//   * the demotion not carried across a resumption            — 1 red (D)
//   * a throw leaving OpenSSL's answer standing in force      — 1 red (E)
//   * a revoked client not demoted                            — 2 red (C)
//   * `holdPeer()` not asking the leaf's fields               — 3 red (B, D, F)
//   * `holdConnectionsOn()` holding out of force too          — 1 red (A)
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const tls = require('tls');

const log = require('bunyan').createLogger({ name: 'listener_path_rules',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD = 'STS_LISTENER_PATH_RULES_CHILD';

// One TLS connection, and what the listener's socket came to say.
function connect(port, client, session) {
  log.debug("Entering connect().");
  log.debug("Leaving connect().");
  return new Promise(function (resolve, reject) {
    const socket = tls.connect({ host: '127.0.0.1', port: port,
      cert: client.pem, key: client.key, rejectUnauthorized: false,
      session: session, maxVersion: 'TLSv1.2', servername: 'localhost' });
    let saved = null;
    socket.once('session', function (s) {
      saved = s;
    });
    socket.once('error', reject);
    socket.once('secureConnect', function () {
      socket.write('asked\n');
    });
    socket.setEncoding('utf8');
    socket.once('data', function (line) {
      socket.destroy();
      resolve({ answer: JSON.parse(line), session: saved });
    });
  });
}

async function child() {
  log.debug("Entering child().");
  const config = require('../common/config');
  const tlsServer = require('../tls/tls_server');
  const trust = require('../common/certificate_trust');
  const kit = require('./tools/trust_kit');
  const results = {};
  const root = await kit.mint({ cn: 'listener root', ca: true });
  const crls = await kit.crlServer();
  const serverCert = await kit.mint({ cn: 'localhost', issuer: root,
    usages: ['digitalSignature', 'keyEncipherment'], eku: ['serverAuth'],
    san: ['DNS:localhost'] });
  const good = await kit.mint({ cn: 'good client', issuer: root,
                                eku: ['clientAuth'] });
  const wrongEku = await kit.mint({ cn: 'server eku client', issuer: root,
                                    eku: ['serverAuth'] });
  const caLeaf = await kit.mint({ cn: 'a CA as a client', issuer: root, ca: true,
    pathLen: 0, usages: ['digitalSignature', 'keyCertSign'],
    eku: ['clientAuth'] });
  const revoked = await kit.mint({ cn: 'revoked client', issuer: root,
                                   eku: ['clientAuth'],
                                   crls: [crls.base + '/l.crl'] });
  crls.routes['/l.crl'] = await kit.crlOf(root, [revoked.serialHex]);
  const server = tls.createServer({
    key: serverCert.key, cert: serverCert.pem + root.pem, ca: [root.pem],
    requestCert: true, rejectUnauthorized: false, maxVersion: 'TLSv1.2'
  }, function (socket) {
    socket.once('data', function () {
      socket.write(JSON.stringify({
        authorized: socket.authorized,
        error: String(socket.authorizationError || ''),
        resumed: socket.isSessionReused()
      }) + '\n');
    });
  });
  tlsServer.holdConnectionsOn(server, 'the test listener');
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const ask = function (client, session) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return connect(port, client, session);
  };

  // A. NOT IN FORCE.
  results.offGood = (await ask(good)).answer;
  results.offEku = (await ask(wrongEku)).answer;
  results.offUsage = (await ask(caLeaf)).answer;
  results.offRevoked = (await ask(revoked)).answer;
  const mockOff = { authorized: true, authorizationError: null,
                    getPeerCertificate: function () {
                      throw new Error('a defect');
                    } };
  tlsServer.holdToPathRules(mockOff, 'a socket that throws');
  results.throwOff = mockOff.authorized;

  // B-E. IN FORCE.
  config.setOverride('pki.paranoid', 'on');
  config.setOverride('pki.revocationCheck', 'soft-fail');
  results.onGood = (await ask(good)).answer;
  results.onEku = (await ask(wrongEku)).answer;
  results.onUsage = (await ask(caLeaf)).answer;
  results.onRevoked = (await ask(revoked)).answer;
  const mockOn = { authorized: true, authorizationError: null,
                   getPeerCertificate: function () {
                     throw new Error('a defect');
                   } };
  tlsServer.holdToPathRules(mockOn, 'a socket that throws');
  results.throwOn = mockOn.authorized;

  // D. RESUMPTION, through the store the hold writes, with a real session.
  const first = await ask(good);
  results.firstResumed = first.answer.resumed;
  const second = await ask(good, first.session);
  results.goodResumed = second.answer;
  const refusedFirst = await ask(caLeaf);
  const refusedAgain = await ask(caLeaf, refusedFirst.session);
  results.badResumed = refusedAgain.answer;
  require('../common/revocation_status').resetCache();
  const forgotten = await ask(good, first.session);
  results.forgotten = forgotten.answer;
  const revocationStatus = require('../common/revocation_status');
  const der = Buffer.from(good.pem.replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
  revocationStatus.rememberHold(der, false);
  results.rememberedFalse = revocationStatus.rememberedHold(der);
  revocationStatus.rememberHold(der, true);
  results.rememberedTrue = revocationStatus.rememberedHold(der);

  // F. THE ROW AND THE MASTER.
  config.setOverride('pki.paranoidTlsClient', false);
  results.rowOff = (await ask(caLeaf)).answer;
  config.clearOverride('pki.paranoidTlsClient');
  config.setOverride('pki.paranoid', 'off');
  results.masterOff = (await ask(caLeaf)).answer;
  results.applies = trust.applies('tls-client');
  await crls.close();
  server.close();
  process.stdout.write('RESULTS ' + JSON.stringify(results) + '\n');
  log.debug("Leaving child().");
}

if (process.env[CHILD]) {
  child().then(function () {
    process.exit(0);
  }, function (e) {
    process.stderr.write(String((e && e.stack) || e) + '\n');
    process.exit(2);
  });
}

module.exports = {
  name: 'listener_path_rules',
  describe: 'the hold on a listener: EKU and keyUsage, revocation, resumption ' +
            'and failing closed, in force and not, over real handshakes',
  run: function (t) {
    const out = childProcess.spawnSync(process.execPath, [__filename], {
      env: Object.assign({}, process.env, { [CHILD]: '1', LOG_LEVEL: 'fatal' }),
      encoding: 'utf8', timeout: 180000 });
    const line = /RESULTS (.*)/.exec(out.stdout || '');
    if (!line) {
      t.bad('the child answered nothing',
            String(out.stderr || out.stdout).slice(0, 800));
      return;
    }
    const r = JSON.parse(line[1]);
    t.equal(r.offGood.authorized, true, 'A. off: a good client verifies');
    t.equal(r.offEku.authorized, false,
            'A. off: OpenSSL itself refuses an EKU that omits clientAuth');
    t.check(/INVALID_PURPOSE/.test(r.offEku.error), 'A. and says so',
            r.offEku.error);
    t.equal(r.offUsage.authorized, true,
            'A. off: a CA presented as a client verifies, as it did');
    t.equal(r.offRevoked.authorized, true,
            'A. off: this listener consults no revocation, as it did');
    t.equal(r.throwOff, true,
            'A. off: a throw leaves OpenSSL\'s answer standing, as it did');
    t.equal(r.onGood.authorized, true, 'B. on: a good client verifies');
    t.equal(r.onEku.authorized, false,
            'B. on: an EKU that omits clientAuth stays refused');
    t.check(/ERR_STS_PATH_RULES/.test(r.onUsage.error), 'B. and says why',
            r.onUsage.error);
    t.equal(r.onUsage.authorized, false,
            'B. on: a CA presented as a client is demoted');
    t.equal(r.onRevoked.authorized, false,
            'C. on: a revoked client is demoted before its first byte is read');
    t.check(/ERR_STS_REVOCATION/.test(r.onRevoked.error), 'C. and says why',
            r.onRevoked.error);
    t.equal(r.throwOn, false, 'E. on: a throw fails closed');
    t.equal(r.goodResumed.resumed, true, 'D. the session did resume');
    t.equal(r.goodResumed.authorized, true,
            'D. a good client stays verified across a resumption');
    t.equal(r.badResumed.authorized, false,
            'D. a demoted client stays demoted across a resumption');
    t.equal(r.forgotten.authorized, false,
            'D. a session nothing remembers is demoted');
    t.equal(r.rememberedFalse, false, 'D. a demotion is remembered');
    t.equal(r.rememberedTrue, true, 'D. and so is its being settled');
    t.equal(r.rowOff.authorized, true, 'F. the row off restores the baseline');
    t.equal(r.masterOff.authorized, true, 'F. the master off wins');
    t.equal(r.applies, false, 'F. and the door agrees');
  }
};
