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
//    G: the main port's shape, under hard-fail: a resumed session gets its full
//    handshake's verdict after a request has written the chain, waits for a
//    verdict on its way, is refused when a refusal or nothing arrives, and is
//    refused once revoked or expired since. A session made before paranoid was
//    turned on is refused until the client's next full handshake.
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
//   * the chain's write dropping the verdict (the regression) — 1 red (G)
//   * a verdict not known here demoted at once                — 1 red (G)
//   * a verdict not known here never settled                  — 2 red (D, G)
//   * a verdict that never arrives passing                    — 2 red (D, G)
//   * a remembered refusal ignored                            — 1 red (G)
//   * the wait skipped where node completed the issuer        — 1 red (G)
//   * a row with an empty chain counting as a chain           — 1 red (G)
//   * a row with no verdict counting as held                  — 4 red (G)
//   * a client chain not stopped at the listener's anchor     — 1 red (H)
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

  // G. THE MAIN PORT'S SHAPE (the product run's sts_main_port_pooling): the
  // observer, then a request's wait and its chain, as the middleware and the
  // sign-in ask them, under hard-fail with an issuer the service does not hold.
  const answering = tls.createServer({
    key: serverCert.key, cert: serverCert.pem + root.pem, ca: [root.pem],
    requestCert: true, rejectUnauthorized: false, maxVersion: 'TLSv1.2'
  }, function (socket) {
    socket.once('data', function () {
      const revocation = require('../common/revocation_status');
      revocation.awaitResumedChain(socket).then(function () {
        const input = revocation.fromSocket(socket);
        return input ? revocation.verdictFor(input) : null;
      }).then(function (verdict) {
        socket.write(JSON.stringify({
          authorized: socket.authorized, resumed: socket.isSessionReused(),
          error: String(socket.authorizationError || ''),
          refused: !!(verdict && verdict.refused),
          why: String((verdict && verdict.why) || '')
        }) + '\n');
      });
    });
  });
  tlsServer.observeConnectionsOn(answering, 'a main-port-shaped listener');
  await new Promise(function (resolve) {
    answering.listen(0, '127.0.0.1', resolve);
  });
  const askMain = function (client, session) {
    log.debug("Entering askMain().");
    log.debug("Leaving askMain().");
    return connect(answering.address().port, client, session);
  };
  const revocationG = require('../common/revocation_status');
  const rawOf = function (one) {
    log.debug("Entering rawOf().");
    log.debug("Leaving rawOf().");
    return new (require('crypto').X509Certificate)(one.pem).raw;
  };
  config.setOverride('pki.revocationCheck', 'hard-fail');
  const waitSet = config.setOverride('tls.resumedChainWaitMs', 2000);
  if (!waitSet.ok) {
    throw new Error(waitSet.errors.join(' '));
  }
  const listed = await kit.mint({ cn: 'listed client', issuer: root,
                                  eku: ['clientAuth'],
                                  crls: [crls.base + '/g.crl'] });
  crls.routes['/g.crl'] = await kit.crlOf(root, []);
  const fullG = await askMain(listed);
  results.gFull = fullG.answer;
  results.gResumed = [];
  for (let i = 0; i < 3; i++) {
    results.gResumed.push((await askMain(listed, fullG.session)).answer);
  }
  results.gRemembered = revocationG.rememberedHold(rawOf(listed));
  // The row arrives from elsewhere while the resumed connection waits for it.
  revocationG.resetCache();
  const startedG = Date.now();
  const waiting = askMain(listed, fullG.session);
  setTimeout(function () {
    askMain(listed);
  }, 300);
  results.gArrived = (await waiting).answer;
  results.gWaitedMs = Date.now() - startedG;
  // A refusal arriving is a refusal, and nothing at all is a refusal.
  revocationG.resetCache();
  revocationG.rememberHold(rawOf(listed), false);
  results.gArrivedRefused = (await askMain(listed, fullG.session)).answer;
  config.setOverride('tls.resumedChainWaitMs', 300);
  revocationG.resetCache();
  results.gNothing = (await askMain(listed, fullG.session)).answer;
  // The row, driven directly: a chain written later keeps the verdict, and a
  // row the hold wrote with no chain yet does not count as a chain held.
  const mockSocket = function (peer) {
    log.debug("Entering mockSocket().");
    log.debug("Leaving mockSocket().");
    return { authorized: true,
             isSessionReused: function () {
               return true;
             },
             getPeerCertificate: function () {
               return peer;
             } };
  };
  const listedRaw = rawOf(listed);
  revocationG.resetCache();
  revocationG.rememberHold(listedRaw, true);
  results.gNoChainYet = await revocationG.awaitResumedChain(
    mockSocket({ raw: listedRaw }));
  const anchor = { raw: rawOf(root) };
  anchor.issuerCertificate = anchor;
  revocationG.fromSocket(mockSocket({ raw: listedRaw,
                                      issuerCertificate: anchor }));
  results.gChainKeepsVerdict = revocationG.rememberedHold(listedRaw);
  // A session that never passed does not start passing.
  const neverPassed = await askMain(caLeaf);
  results.gNeverPassed = (await askMain(caLeaf, neverPassed.session)).answer;
  // Revoked since: the session's verdict stands at the TLS layer, as it did
  // before #1360, and the request's own check refuses it.
  const revokedSince = await askMain(listed);
  crls.routes['/g.crl'] = await kit.crlOf(root, [listed.serialHex]);
  revocationG.resetCache();
  await askMain(listed);
  results.gRevokedSince = (await askMain(listed, revokedSince.session)).answer;
  // Expired since: the leaf's own window is asked on every connection.
  const shortLived = await kit.mint({ cn: 'short-lived client', issuer: root,
    eku: ['clientAuth'], notAfter: Date.now() + 2500 });
  const shortFirst = await askMain(shortLived);
  results.gShortFirst = shortFirst.answer;
  await new Promise(function (resolve) {
    setTimeout(resolve, 4500);
  });
  results.gExpiredSince = (await askMain(shortLived,
                                         shortFirst.session)).answer;
  // A session from before paranoid was turned on: nothing held it, so it is
  // refused until the client's next full handshake, and that settles it.
  config.setOverride('pki.paranoid', 'off');
  const beforeOn = await kit.mint({ cn: 'made before paranoid', issuer: root,
                                    eku: ['clientAuth'] });
  const madeOff = await askMain(beforeOn);
  results.gMadeOff = madeOff.answer;
  results.gMadeOffResumed = (await askMain(beforeOn, madeOff.session)).answer;
  config.setOverride('pki.paranoid', 'on');
  results.gMadeOffVerdict = revocationG.rememberedHold(rawOf(beforeOn));
  results.gTurnedOn = (await askMain(beforeOn, madeOff.session)).answer;
  const settledBy = await askMain(beforeOn);
  results.gNextFull = settledBy.answer;
  results.gNextResumed = (await askMain(beforeOn, settledBy.session)).answer;
  // H. A CLIENT CHAIN ENDING IN A CROSS-SIGNED ROOT, over a real handshake: the
  // leaf and a copy of the listener's anchor another root signed, whose issuer
  // is not sent. Under hard-fail the walk refused it for having no issuer.
  const keyMaterial = require('../common/crypto_impl/key_material');
  const crossPair = await keyMaterial.generateKeyPair('rsa-2048');
  const crossAnchor = await kit.mint({ cn: 'client cross root', ca: true,
                                       pair: crossPair });
  const olderAnchor = await kit.mint({ cn: 'client older root', ca: true,
    pair: await keyMaterial.generateKeyPair('rsa-2048') });
  const crossCopy = await kit.mint({ cn: 'client cross root', ca: true,
                                     issuer: olderAnchor, pair: crossPair,
                                     crls: ['http://127.0.0.1:1/older.crl'] });
  const crossClient = await kit.mint({ cn: 'cross client', issuer: crossAnchor,
    eku: ['clientAuth'], crls: [crls.base + '/h.crl'] });
  crls.routes['/h.crl'] = await kit.crlOf(crossAnchor, []);
  const revokedCross = await kit.mint({ cn: 'cross revoked',
    issuer: crossAnchor, eku: ['clientAuth'], crls: [crls.base + '/hr.crl'] });
  crls.routes['/hr.crl'] = await kit.crlOf(crossAnchor,
                                           [revokedCross.serialHex]);
  const crossListener = tls.createServer({
    key: serverCert.key, cert: serverCert.pem + root.pem,
    ca: [crossAnchor.pem], requestCert: true, rejectUnauthorized: false,
    maxVersion: 'TLSv1.2'
  }, function (socket) {
    socket.once('data', function () {
      const revocation = require('../common/revocation_status');
      revocation.verdictFor(revocation.fromSocket(socket)).then(function (v) {
        socket.write(JSON.stringify({ authorized: socket.authorized,
                                      refused: !!v.refused,
                                      status: String(v.status),
                                      why: String(v.why || '') }) + '\n');
      });
    });
  });
  await new Promise(function (resolve) {
    crossListener.listen(0, '127.0.0.1', resolve);
  });
  const crossPort = crossListener.address().port;
  const presenting = function (one) {
    log.debug("Entering presenting().");
    log.debug("Leaving presenting().");
    return { pem: one.pem + crossCopy.pem, key: one.key };
  };
  const anchored = tlsServer.truststore.add(crossAnchor.pem, {});
  results.hAdded = !!anchored;
  results.hGood = (await connect(crossPort, presenting(crossClient))).answer;
  results.hRevoked = (await connect(crossPort,
                                    presenting(revokedCross))).answer;
  answering.close();
  crossListener.close();
  config.setOverride('pki.revocationCheck', 'soft-fail');
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
    t.equal(r.gFull.authorized, true, 'G. a full handshake verifies');
    t.check(r.gResumed.every(function (one) {
      return one.resumed && one.authorized && !one.refused;
    }), 'G. and every session resuming it is verified and signs in, under ' +
        'hard-fail with the chain the full handshake showed',
    JSON.stringify(r.gResumed).slice(0, 400));
    t.equal(r.gRemembered, true,
            'G. a request writing the chain leaves the verdict on the row');
    t.check(r.gArrived.resumed && r.gArrived.authorized &&
            !r.gArrived.refused && r.gWaitedMs >= 250,
            'G. a verdict still on its way from another node is waited for',
            JSON.stringify(r.gArrived) + ' ' + r.gWaitedMs + 'ms');
    t.check(r.gArrivedRefused.resumed && !r.gArrivedRefused.authorized,
            'G. a refusal that arrives is a refusal',
            JSON.stringify(r.gArrivedRefused));
    t.check(r.gNothing.resumed && !r.gNothing.authorized,
            'G. and nothing arriving is a refusal', JSON.stringify(r.gNothing));
    t.equal(r.gNoChainYet, false,
            'G. a row with a verdict and no chain yet is still waited for');
    t.equal(r.gChainKeepsVerdict, true,
            'G. and the chain written later keeps the verdict');
    t.check(r.gNeverPassed.resumed && !r.gNeverPassed.authorized,
            'G. a session that never passed does not start passing',
            JSON.stringify(r.gNeverPassed));
    t.check(r.gRevokedSince.resumed && r.gRevokedSince.refused,
            'G. a certificate revoked since is refused by the request\'s check',
            JSON.stringify(r.gRevokedSince));
    t.equal(r.gShortFirst.authorized, true,
            'G. a certificate verifies inside its window');
    t.check(r.gExpiredSince.resumed && !r.gExpiredSince.authorized &&
            /expired/.test(r.gExpiredSince.error),
            'G. and a session of it is refused once the window has closed',
            JSON.stringify(r.gExpiredSince));
    t.check(r.gMadeOff.authorized && r.gMadeOffResumed.resumed &&
            r.gMadeOffResumed.authorized,
            'G. out of force a session is made and resumes, with no verdict',
            JSON.stringify(r.gMadeOffResumed));
    t.equal(r.gMadeOffVerdict, null, 'G. so no verdict is on its row');
    t.check(r.gTurnedOn.resumed && !r.gTurnedOn.authorized &&
            /no record/.test(r.gTurnedOn.error),
            'G. once paranoid is on, that session is refused',
            JSON.stringify(r.gTurnedOn));
    t.check(!r.gNextFull.resumed && r.gNextFull.authorized,
            'G. the client\'s next full handshake is held and passes',
            JSON.stringify(r.gNextFull));
    t.check(r.gNextResumed.resumed && r.gNextResumed.authorized,
            'G. and a session of that one resumes',
            JSON.stringify(r.gNextResumed));
    t.check(r.hGood.authorized && !r.hGood.refused,
            'H. a client chain ending in a cross-signed copy of the ' +
            'listener\'s anchor ends at the anchor, under hard-fail',
            JSON.stringify(r.hGood));
    t.check(r.hRevoked.refused && r.hRevoked.status === 'revoked',
            'H. and a client below that anchor is still asked about revocation',
            JSON.stringify(r.hRevoked));
    t.equal(r.rememberedFalse, false, 'D. a demotion is remembered');
    t.equal(r.rememberedTrue, true, 'D. and so is its being settled');
    t.equal(r.rowOff.authorized, true, 'F. the row off restores the baseline');
    t.equal(r.masterOff.authorized, true, 'F. the master off wins');
    t.equal(r.applies, false, 'F. and the door agrees');
  }
};
