// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/outbound_gate.js — THE GATE ON EVERY OUTBOUND HANDSHAKE (#1360, Phase 2).
//
// rcbj's decision: every dialer is gated, the cloud SDKs included, and the call
// fails before a request is written. The gate is at `tls.connect()`, so the claim
// is held against the transports the SDKs stand on, each pointed at a TLS server
// this file runs and which counts every byte it decrypts: https and so the AWS and
// Azure SDKs' handlers, undici's `fetch`, http2, grpc-js and so Google's clients,
// nodemailer, node-postgres, and a bare `tls.connect()`. **THE SDKs THEMSELVES ARE
// OPTIONAL PEERS, NOT INSTALLED IN THE TESTS IMAGE, AND ARE NOT DRIVEN HERE**; what
// is held is the function each of them ends in.
//
// In a child: the patch is the process's. A: out of force a revoked server is
// reached, which is what happened before. B: in force every transport is refused
// with no byte delivered. C: a good server is reached, its request whole. D: an
// EKU that omits serverAuth. E: a staple answering revoked, off a real OCSP
// response, with no fetch. F: the opt-out, the row and the master. G: the signer
// truststore beside a dialer's `ca`. H: the store's variant. I: the
// certificates the shipped stack generates, through the gate.
//
// MUTATION RECORD, each applied to a scratch build, seen red and put back:
//   * `cork()` dropped, so a stream writer's bytes go first   — 2 red (B)
//   * `secureConnect` not held                                — 1 red (B)
//   * the opt-out ignored                                     — 1 red (F)
//   * the staple not handed to the walk                       — 2 red (E)
//   * a context's `ca` not remembered                        — 1 red (H3)
//   * the store's row not softening                           — 1 red (H)
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');
const https = require('https');
const http2 = require('http2');

const log = require('bunyan').createLogger({ name: 'outbound_gate',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD = 'STS_OUTBOUND_GATE_CHILD';

// Each answers `{ reached: boolean, error }`; none may throw.
const CLIENTS = {
  https: function (port, ca) {
    log.debug("Entering the https client.");
    return new Promise(function (resolve) {
      const req = https.request({ host: 'localhost', port: port, path: '/x',
        method: 'POST', ca: ca, agent: false }, function (res) {
        res.resume();
        res.on('end', function () {
          resolve({ reached: res.statusCode === 200 });
        });
      });
      req.on('error', function (e) {
        resolve({ reached: false, error: e.code || e.message });
      });
      req.end('secret body');
    });
  },
  fetch: function (port, ca) {
    log.debug("Entering the undici client.");
    const undici = require('undici');
    return undici.request('https://localhost:' + port + '/x', {
      method: 'POST', body: 'secret body',
      dispatcher: new undici.Agent({ connect: { ca: ca } })
    }).then(function (res) {
      return res.body.text().then(function () {
        return { reached: res.statusCode === 200 };
      });
    }, function (e) {
      return { reached: false, error: e.code || e.message };
    });
  },
  http2: function (port, ca) {
    log.debug("Entering the http2 client.");
    return new Promise(function (resolve) {
      const session = http2.connect('https://localhost:' + port, { ca: ca });
      session.on('error', function (e) {
        session.destroy();
        resolve({ reached: false, error: e.code || e.message });
      });
      const req = session.request({ ':path': '/x', ':method': 'POST' });
      req.on('error', function (e) {
        session.destroy();
        resolve({ reached: false, error: e.code || e.message });
      });
      req.on('response', function (headers) {
        req.resume();
        session.close();
        resolve({ reached: headers[':status'] === 200 });
      });
      req.end('secret body');
    });
  },
  tls: function (port, ca) {
    log.debug("Entering the raw client.");
    return new Promise(function (resolve) {
      const socket = tls.connect({ host: 'localhost', port: port, ca: ca,
                                   servername: 'localhost' });
      socket.on('error', function (e) {
        resolve({ reached: false, error: e.code || e.message });
      });
      socket.write('secret body');
      socket.once('data', function () {
        socket.destroy();
        resolve({ reached: true });
      });
    });
  },
  grpc: function (port, ca) {
    log.debug("Entering the grpc client.");
    const grpc = require('@grpc/grpc-js');
    return new Promise(function (resolve) {
      const client = new grpc.Client('localhost:' + port,
        grpc.credentials.createSsl(Buffer.from(ca.join('\n'))));
      client.makeUnaryRequest('/x/y', function (b) {
        return b;
      }, function (b) {
        return b;
      }, Buffer.from('secret body'), { deadline: Date.now() + 6000 },
      function (e) {
        client.close();
        resolve({ reached: !e || e.code !== 14,
                  error: e ? String(e.details || e.message) : '' });
      });
    });
  },
  nodemailer: function (port, ca) {
    log.debug("Entering the nodemailer client.");
    const nodemailer = require('nodemailer');
    const transport = nodemailer.createTransport({ host: 'localhost',
      port: port, secure: true, tls: { ca: ca, servername: 'localhost' },
      connectionTimeout: 6000, greetingTimeout: 6000, socketTimeout: 6000 });
    return transport.verify().then(function () {
      return { reached: true };
    }, function (e) {
      // A server that speaks no SMTP is still a server that was reached.
      const refused = /refused|ERR_STS/
        .test(String(e.code) + String(e.message));
      return { reached: !refused, error: e.code || e.message };
    });
  },
  pg: function (port, ca) {
    log.debug("Entering the node-postgres client.");
    // It asks for TLS in the clear first, so it is asked of `pgServerOf()`. The
    // one door to the driver, as everything that dials the store uses.
    const client = require('../persistence/knex_store').openConnection({
      connectionString: 'postgres://x@localhost:' + port + '/x',
      connectionTimeoutMillis: 6000,
      ssl: { ca: ca, servername: 'localhost' } });
    return client.connect().then(function () {
      return { reached: true };
    }, function (e) {
      // A server that speaks no more of the protocol is still one that was
      // reached: the bytes it counted are what is read.
      return { reached: !/refused/.test(String(e.message)),
               error: e.code || e.message };
    });
  }
};

// What node-postgres dials: `S` in the clear, then TLS over the same socket,
// counting what it decrypts and answering nothing.
function pgServerOf(cert, root) {
  log.debug("Entering pgServerOf().");
  const state = { bytes: 0, port: 0 };
  const context = tls.createSecureContext({ key: cert.key,
                                            cert: cert.pem + root.pem });
  const server = net.createServer(function (socket) {
    socket.once('data', function () {
      socket.write('S');
      const secure = new tls.TLSSocket(socket, { isServer: true,
                                                 secureContext: context });
      secure.on('data', function (chunk) {
        state.bytes += chunk.length;
        secure.destroy();
      });
      secure.on('error', function (e) {
        log.debug("pg server: " + e.message);
      });
    });
    socket.on('error', function (e) {
      log.debug("pg server socket: " + e.message);
    });
  });
  log.debug("Leaving pgServerOf().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      state.port = server.address().port;
      resolve(state);
    });
  });
}

// A TLS server that counts what it decrypts, speaking both http versions.
function serverOf(cert, root) {
  log.debug("Entering serverOf().");
  const state = { bytes: 0, server: null, port: 0, ocsp: null };
  const server = http2.createSecureServer({
    key: cert.key, cert: cert.pem + root.pem, allowHTTP1: true,
    minVersion: 'TLSv1.2' }, function (req, res) {
    req.on('data', function (chunk) {
      state.bytes += chunk.length;
    });
    req.on('end', function () {
      res.writeHead(200);
      res.end('ok');
    });
  });
  server.on('OCSPRequest', function (certificate, issuer, done) {
    done(null, state.ocsp);
  });
  server.on('unknownProtocol', function (socket) {
    socket.on('data', function (chunk) {
      state.bytes += chunk.length;
      socket.write('ok');
    });
  });
  log.debug("Leaving serverOf().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      state.server = server;
      state.port = server.address().port;
      resolve(state);
    });
  });
}

// A real OCSP response, from a real `openssl ocsp`, for this file to staple.
function stapleOf(cert, root, status) {
  log.debug("Entering stapleOf().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-gate-'));
  const file = function (name, text) {
    log.debug("Entering file().");
    const at = path.join(dir, name);
    if (text !== undefined) {
      fs.writeFileSync(at, text);
    }
    log.debug("Leaving file().");
    return at;
  };
  try {
    file('ca.pem', root.pem);
    file('ca.key', root.key);
    file('leaf.pem', cert.pem);
    const stamp = '200101000000Z';
    file('index.txt', status + '\t491231235959Z\t' +
         (status === 'R' ? stamp : '') + '\t' +
         cert.serialHex.toUpperCase() + '\tunknown\t/CN=' + cert.cn + '\n');
    childProcess.execFileSync('openssl', ['ocsp', '-issuer', file('ca.pem'),
      '-cert', file('leaf.pem'), '-reqout', file('req.der'), '-no_nonce'],
    { stdio: 'pipe' });
    childProcess.execFileSync('openssl', ['ocsp', '-index', file('index.txt'),
      '-CA', file('ca.pem'), '-rsigner', file('ca.pem'),
      '-rkey', file('ca.key'),
      '-reqin', file('req.der'), '-respout', file('res.der'), '-ndays', '2'],
    { stdio: 'pipe' });
    log.debug("Leaving stapleOf().");
    return fs.readFileSync(file('res.der'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function child() {
  log.debug("Entering child().");
  const config = require('../common/config');
  const outbound = require('../common/outbound_tls');
  const signers = require('../common/signer_truststore');
  const kit = require('./tools/trust_kit');
  outbound.installProcessWide();
  signers.setDirectory(kit.signerStoreDouble());
  const results = {};
  const root = await kit.mint({ cn: 'gate root', ca: true });
  const crls = await kit.crlServer();
  const profile = { usages: ['digitalSignature', 'keyEncipherment'],
                    san: ['DNS:localhost'], issuer: root };
  const revoked = await kit.mint(Object.assign({ cn: 'revoked server',
    eku: ['serverAuth'], crls: [crls.base + '/g.crl'] }, profile));
  const good = await kit.mint(Object.assign({ cn: 'good server',
    eku: ['serverAuth'], crls: [crls.base + '/g.crl'] }, profile));
  const wrongEku = await kit.mint(Object.assign({ cn: 'client eku server',
    eku: ['emailProtection'], crls: [crls.base + '/g.crl'] }, profile));
  crls.routes['/g.crl'] = await kit.crlOf(root, [revoked.serialHex]);
  const noList = await kit.mint(Object.assign({ cn: 'dead list server',
    crls: ['http://127.0.0.1:1/dead.crl'],
    eku: ['serverAuth'] }, profile));
  const servers = {
    revoked: await serverOf(revoked, root), good: await serverOf(good, root),
    wrongEku: await serverOf(wrongEku, root),
    noList: await serverOf(noList, root)
  };
  const pgServers = { revoked: await pgServerOf(revoked, root),
                      good: await pgServerOf(good, root) };
  const ca = [root.pem];
  const drive = async function (name, which) {
    log.debug("Entering drive().");
    const server = name === 'pg' ? pgServers[which] : servers[which];
    const before = server.bytes;
    const answer = await CLIENTS[name](server.port, ca);
    log.debug("Leaving drive().");
    const bytes = server.bytes - before;
    return { reached: name === 'pg' ? bytes > 0 : answer.reached,
             error: String(answer.error || ''), bytes: bytes };
  };

  results.off = {};
  for (const name of Object.keys(CLIENTS)) {
    results.off[name] = await drive(name, 'revoked');
  }
  config.setOverride('pki.paranoid', 'on');
  config.setOverride('pki.revocationCheck', 'soft-fail');
  results.on = {};
  results.good = {};
  for (const name of Object.keys(CLIENTS)) {
    results.on[name] = await drive(name, 'revoked');
    results.good[name] = await drive(name, 'good');
  }
  results.eku = await drive('https', 'wrongEku');
  // E. A staple: this certificate names no list and no responder.
  const stapledGood = await kit.mint(Object.assign({ cn: 'stapled good',
    eku: ['serverAuth'] }, profile));
  const stapledBad = await kit.mint(Object.assign({ cn: 'stapled bad',
    eku: ['serverAuth'] }, profile));
  servers.stapledGood = await serverOf(stapledGood, root);
  servers.stapledBad = await serverOf(stapledBad, root);
  servers.stapledGood.ocsp = stapleOf(stapledGood, root, 'V');
  servers.stapledBad.ocsp = stapleOf(stapledBad, root, 'R');
  results.stapledGood = await drive('https', 'stapledGood');
  results.stapledBad = await drive('https', 'stapledBad');
  // F. The row, and the master.
  config.setOverride('pki.paranoidOutboundTls', false);
  results.rowOff = await drive('https', 'revoked');
  config.clearOverride('pki.paranoidOutboundTls');
  config.setOverride('pki.paranoid', 'off');
  results.masterOff = await drive('https', 'revoked');
  config.setOverride('pki.paranoid', 'on');
  results.optOut = await new Promise(function (resolve) {
    const req = https.request({ host: 'localhost', method: 'POST',
      port: servers.revoked.port, path: '/x', ca: ca, agent: false,
      stsOutboundGate: false }, function (res) {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', function () {
      resolve(false);
    });
    req.end('x');
  });
  // G. A CA only the signer truststore holds.
  const added = await signers.add('default', root.pem, {});
  results.signerAdded = added.added.length;
  results.signerPems = outbound.verifiedOptions(null).ca.some(function (one) {
    return String(one).trim() === root.pem.trim();
  });
  results.signerBeside = outbound.verifiedOptions(null).ca.length >
                         tls.rootCertificates.length;
  // H. The store's row: a source named and unreachable is not refused, under
  // hard-fail, for the database alone.
  config.setOverride('pki.revocationCheck', 'hard-fail');
  config.setOverride('pki.revocationRequireDistributionPoint', 'on');
  results.noListRefused = await drive('https', 'noList');
  results.noListStore = await new Promise(function (resolve) {
    const req = https.request({ host: 'localhost', method: 'POST',
      port: servers.noList.port, path: '/x', ca: ca, agent: false,
      stsOutboundVariant: 'store' }, function (res) {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', function () {
      resolve(false);
    });
    req.end('x');
  });
  results.revokedStore = await new Promise(function (resolve) {
    const req = https.request({ host: 'localhost', method: 'POST',
      port: servers.revoked.port, path: '/x', ca: ca, agent: false,
      stsOutboundVariant: 'store' }, function (res) {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', function () {
      resolve(false);
    });
    req.end('x');
  });
  // H2. A SESSION A CLIENT KEPT: undici and https's agents resume on their own,
  // and a resumed client sees no peer certificate. The gate asks for a full
  // handshake instead, so the second connection to a host is held as the first.
  config.clearOverride('pki.revocationRequireDistributionPoint');
  config.setOverride('pki.revocationCheck', 'soft-fail');
  const kept = await new Promise(function (resolve) {
    const first = tls.connect({ host: 'localhost', port: servers.good.port,
      ca: ca, servername: 'localhost', maxVersion: 'TLSv1.2',
      ALPNProtocols: ['http/1.1'] }, function () {
      const session = first.getSession();
      first.destroy();
      resolve(session);
    });
    first.on('error', function () {
      resolve(null);
    });
  });
  results.keptSession = !!kept;
  results.resumedHeld = await new Promise(function (resolve) {
    const second = tls.connect({ host: 'localhost', port: servers.good.port,
      ca: ca, servername: 'localhost', maxVersion: 'TLSv1.2', session: kept,
      ALPNProtocols: ['http/1.1'] }, function () {
      const peer = second.getPeerCertificate();
      const out = { reached: true, reused: second.isSessionReused(),
                    raw: !!peer.raw };
      second.destroy();
      resolve(out);
    });
    second.on('error', function (e) {
      resolve({ reached: false, why: String(e.message) });
    });
  });
  // I. THE CERTIFICATES THE SHIPPED STACK GENERATES (the product stack's first
  // dial, refused until a dialer's own `ca` counted as naming the server): each
  // generator's real output, over a real handshake, through the gate, under
  // hard-fail. `generate-tls` is what a new install runs, with nobody present.
  const cp = require('child_process');
  const os = require('os');
  const generated = fs.mkdtempSync(path.join(os.tmpdir(), 'outbound-gate-'));
  const baoDir = path.join(generated, 'bao');
  const pgDir = path.join(generated, 'pg');
  fs.mkdirSync(baoDir);
  cp.execFileSync(process.execPath,
    [path.join(__dirname, '..', 'openbao', 'generate-tls.js')],
    { env: Object.assign({}, process.env, { STS_BAO_TLS_DIR: baoDir,
                                            STS_BAO_RAFT_DIR: baoDir }),
      stdio: 'ignore' });
  cp.execFileSync('sh', [path.join(__dirname, '..', 'postgres',
                                   'generate-tls.sh')],
    { env: Object.assign({}, process.env, { POSTGRES_TLS_DIR: pgDir,
                                            POSTGRES_TLS_CN: 'localhost',
                                            POSTGRES_TLS_PUBLIC_DIR: '' }),
      stdio: 'ignore' });
  const selfSignedServer = function (keyFile, certFile) {
    log.debug("Entering selfSignedServer().");
    const pem = fs.readFileSync(certFile, 'utf8');
    const server = https.createServer(
      { key: fs.readFileSync(keyFile), cert: pem }, function (req, res) {
        res.end('ok');
      });
    log.debug("Leaving selfSignedServer().");
    return new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', function () {
        resolve({ server: server, pem: pem, port: server.address().port });
      });
    });
  };
  const dial = function (port, ca, extra) {
    log.debug("Entering dial().");
    log.debug("Leaving dial().");
    return new Promise(function (resolve) {
      const req = https.request(Object.assign(
        { host: 'localhost', port: port, path: '/', ca: ca, agent: false },
        extra || {}), function (res) {
        res.resume();
        resolve({ reached: res.statusCode === 200, why: '' });
      });
      req.on('error', function (e) {
        resolve({ reached: false, why: String(e.message) });
      });
      req.end();
    });
  };
  config.setOverride('pki.revocationCheck', 'hard-fail');
  config.setOverride('pki.revocationRequireDistributionPoint', 'on');
  const bao = await selfSignedServer(path.join(baoDir, 'server.key'),
                                     path.join(baoDir, 'server.crt'));
  const pg = await selfSignedServer(path.join(pgDir, 'server.key'),
                                    path.join(pgDir, 'server.crt'));
  results.generatedBao = await dial(bao.port, bao.pem);
  results.generatedPg = await dial(pg.port, pg.pem);
  // H3. A CONTEXT THE DIALER BUILT ITSELF, as mysql2 does: its `ca` is still
  // the dialer naming this server.
  results.contextNamed = await new Promise(function (resolve) {
    const socket = tls.connect({ host: 'localhost', port: bao.port,
      servername: 'localhost', ALPNProtocols: ['http/1.1'],
      secureContext: tls.createSecureContext({ ca: bao.pem }) }, function () {
      socket.destroy();
      resolve({ reached: true });
    });
    socket.on('error', function (e) {
      resolve({ reached: false, why: String(e.message) });
    });
  });
  // A pair the volume already holds is what it reads: nothing is regenerated.
  cp.execFileSync(process.execPath,
    [path.join(__dirname, '..', 'openbao', 'generate-tls.js')],
    { env: Object.assign({}, process.env, { STS_BAO_TLS_DIR: baoDir,
                                            STS_BAO_RAFT_DIR: baoDir }),
      stdio: 'ignore' });
  results.keptPair = fs.readFileSync(path.join(baoDir, 'server.crt'),
                                     'utf8') === bao.pem;
  const stranger = await kit.mint({ cn: 'localhost', san: ['DNS:localhost'],
    usages: ['digitalSignature', 'keyEncipherment'], eku: ['serverAuth'] });
  fs.writeFileSync(path.join(generated, 's.key'), stranger.key);
  fs.writeFileSync(path.join(generated, 's.crt'), stranger.pem);
  const unnamed = await selfSignedServer(path.join(generated, 's.key'),
                                         path.join(generated, 's.crt'));
  // In a truststore row of no kind this may not be: an anchor is a CA. So the
  // refusal is OpenSSL's for an unnamed server, and the gate's once accepted
  // and then expired.
  results.strangerUnnamed = await dial(unnamed.port, bao.pem);
  const aged = await kit.mint({ cn: 'localhost', san: ['DNS:localhost'],
    usages: ['digitalSignature', 'keyEncipherment'], eku: ['serverAuth'],
    notBefore: Date.now() - 3 * 86400000, notAfter: Date.now() - 86400000 });
  fs.writeFileSync(path.join(generated, 'a.key'), aged.key);
  fs.writeFileSync(path.join(generated, 'a.crt'), aged.pem);
  const agedServer = await selfSignedServer(path.join(generated, 'a.key'),
                                            path.join(generated, 'a.crt'));
  results.agedPinned = await dial(agedServer.port, aged.pem);
  [bao, pg, unnamed, agedServer].forEach(function (one) {
    one.server.close();
  });
  fs.rmSync(generated, { recursive: true, force: true });
  process.stdout.write('RESULTS ' + JSON.stringify(results) + '\n');
  await crls.close();
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
  name: 'outbound_gate',
  describe: 'every transport the dialers and the SDKs stand on is refused a ' +
            'revoked server before a byte is written, in force and only then',
  run: function (t) {
    const out = childProcess.spawnSync(process.execPath, [__filename], {
      env: Object.assign({}, process.env, { [CHILD]: '1', LOG_LEVEL: 'fatal' }),
      encoding: 'utf8', timeout: 240000 });
    const line = /RESULTS (.*)/.exec(out.stdout || '');
    if (!line) {
      t.bad('the child answered nothing',
            String(out.stderr || out.stdout).slice(0, 900));
      return;
    }
    const r = JSON.parse(line[1]);
    Object.keys(r.on).forEach(function (name) {
      t.equal(r.off[name].reached, true, 'A. off: ' + name + ' reaches a ' +
              'revoked server, as it did');
      t.equal(r.on[name].reached, false, 'B. on: ' + name + ' does not: ' +
              r.on[name].error);
      t.equal(r.on[name].bytes, 0, 'B. on: ' + name + ' delivered no byte');
      t.equal(r.good[name].reached, true, 'C. on: ' + name +
              ' reaches a good server');
    });
    t.check(r.good.https.bytes > 0, 'C. and its request arrives whole', '');
    t.check(r.good.fetch.bytes > 0, 'C. through undici too', '');
    t.equal(r.eku.reached, false, 'D. an EKU that omits serverAuth: ' +
            r.eku.error);
    t.equal(r.eku.bytes, 0, 'D. no byte');
    t.equal(r.stapledGood.reached, true, 'E. a stapled good answer is taken');
    t.equal(r.stapledBad.reached, false, 'E. a stapled revoked is refused: ' +
            r.stapledBad.error);
    t.equal(r.stapledBad.bytes, 0, 'E. no byte');
    t.equal(r.rowOff.reached, true, 'F. the row off restores the baseline');
    t.equal(r.masterOff.reached, true, 'F. the master off wins');
    t.equal(r.optOut, true, 'F. a dialer that answers itself opts out');
    t.equal(r.signerAdded, 1, 'G. a CA in the signer truststore');
    t.check(r.signerPems && r.signerBeside,
            'G. is beside a dialer\'s ca, and beside node\'s store', '');
    t.equal(r.noListRefused.reached, false,
            'H. under hard-fail a certificate naming no list is refused');
    t.equal(r.noListStore, true, 'H. the store\'s row takes it');
    t.equal(r.revokedStore, false, 'H. and still refuses what is revoked');
    t.equal(r.keptSession, true, 'H2. a client kept a session');
    t.check(r.resumedHeld.reached && !r.resumedHeld.reused && r.resumedHeld.raw,
            'H2. offering it again is a full handshake, held, and reached: a ' +
            'resumed client would have no certificate to hold',
            JSON.stringify(r.resumedHeld));
    t.check(r.contextNamed.reached,
            'H3. a context built with the server as its `ca` names it',
            JSON.stringify(r.contextNamed));
    t.check(r.generatedBao.reached,
            'I. the certificate openbao/generate-tls.js makes is reached, by ' +
            'the dialer configured with it, under hard-fail',
            r.generatedBao.why);
    t.check(r.generatedPg.reached,
            'I. and so is the one postgres/generate-tls.sh makes',
            r.generatedPg.why);
    t.equal(r.keptPair, true,
            'I. a volume already holding a pair keeps it, so an existing ' +
            'install needs nothing');
    t.equal(r.strangerUnnamed.reached, false,
            'I. another self-signed server is not reached by that pin');
    t.check(!r.agedPinned.reached && /expired/.test(r.agedPinned.why),
            'I. and a pinned certificate is still held to its window',
            r.agedPinned.why);
  }
};
