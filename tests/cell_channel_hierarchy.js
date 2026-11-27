// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cell_channel_hierarchy.js
//
// ===========================================================================
// THE INTER-CELL LISTENER FOLLOWS A HIERARCHY ANOTHER CELL REBUILT
// (2026-11-14, CI run 43642810770, the `cells` mode).
//
// Cell A rebuilt the process branch at 22:00:54 and the Root three times from
// 22:01:30. Cell B adopted every row and went on presenting the inter-cell
// leaf it had minted at 21:59 under the replaced `cell` Issuing CA, because
// nothing in B asked its leaf about the change: B dialled nobody, A's new leaf
// verified under B's own view so B refused nothing, and once the Root was
// replaced A's handshake failed in OpenSSL before any request reached B. Every
// A -> B call then failed (STS-CELL-0032 "not issued by the inter-cell Issuing
// CA", then "self-signed certificate in certificate chain"), and ten protocol
// jobs with them.
//
// What this holds, against a real listener and a real handshake:
//
//   A. A leaf minted at listen() is presented, under the `cell` Issuing CA.
//   B. The process branch rebuilt underneath the channel (as an adopted row
//      is: the channel is told nothing) — the next handshake presents a leaf
//      under the NEW Issuing CA, and accepts a peer's leaf from it.
//   C. A Root replaced whose process branch has not arrived: the handshake
//      keeps the leaf held, and neither it nor a dialler's ensureLeaf()
//      builds a process branch here (that would be a second builder of the
//      branch the other cell is building — the claim is per cell).
//   D. The branch arrives under the new Root: the next handshake presents a
//      leaf that chains to it, and verifies the peer against it.
//
// In process: the claim is about what a handshake on this process's socket
// presents, and the one way to know is to make one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const net = require('net');
const tls = require('tls');

const log = require('bunyan').createLogger({ name: 'cell_channel_hierarchy',
  level: process.env.LOG_LEVEL || 'info' });

const PEER = { id: 'b', jurisdiction: 'ca', url: 'https://localhost:1',
               self: false };
const SELF = { id: 'a', jurisdiction: 'us', url: '', self: true };

// The cell map stubbed as cell "a" with one peer "b", and restored after:
// `tests/run.js` runs every file in one process.
function stubCells() {
  log.debug("Entering stubCells().");
  const cells = require('../common/cells');
  const saved = {};
  const stubs = {
    isMulti: function () {
      return true;
    },
    id: function () {
      return 'a';
    },
    hostname: function () {
      return 'localhost';
    },
    peers: function () {
      return [PEER];
    },
    all: function () {
      return [SELF, PEER];
    },
    get: function (id) {
      return id === 'a' ? SELF : (id === 'b' ? PEER : null);
    }
  };
  Object.keys(stubs).forEach(function (name) {
    saved[name] = cells[name];
    cells[name] = stubs[name];
  });
  log.debug("Leaving stubCells().");
  return function restore() {
    Object.keys(saved).forEach(function (name) {
      cells[name] = saved[name];
    });
  };
}

function freePort() {
  log.debug("Entering freePort().");
  log.debug("Leaving freePort().");
  return new Promise(function (resolve, reject) {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', function () {
      const port = probe.address().port;
      probe.close(function () {
        resolve(port);
      });
    });
  });
}

function derB64(pem) {
  log.debug("Entering derB64().");
  log.debug("Leaving derB64().");
  return String(pem || '').replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

// The process branch's `cell` Issuing CA and Intermediate as this process
// holds them now.
function branchNow(pki) {
  log.debug("Entering branchNow().");
  const row = pki.rawRowFor(pki.PROCESS_SCOPE) || {};
  const root = pki.serviceRoot();
  log.debug("Leaving branchNow().");
  return {
    cellCa: derB64(row.issuing && row.issuing.cell &&
                   row.issuing.cell.certificatePem),
    intermediate: derB64(row.intermediate &&
                         row.intermediate.certificatePem),
    rootPem: root && root.certificatePem ? String(root.certificatePem) : ''
  };
}

// A peer cell's leaf, issued as cell "b" under the `cell` Issuing CA held now.
async function peerLeaf(t, pki, stsCrypto) {
  log.debug("Entering peerLeaf().");
  const pair = stsCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const now = Date.now();
  const issued = await pki.issueUnder(pki.PROCESS_SCOPE, 'cell', {
    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' })
      .toString(),
    subject: [{ name: 'CN', value: 'cell b test peer' }],
    profile: 'tls-server',
    notBefore: now - 60000,
    notAfter: now + 3600000,
    extensions: {
      keyUsage: { present: true, critical: true,
                  usages: ['digitalSignature'] },
      extKeyUsage: { present: true, critical: false,
                     usages: ['serverAuth', 'clientAuth'] },
      subjectAltName: { present: true, critical: false, names: [
        { kind: 'dns', value: 'localhost' },
        { kind: 'uri', value: 'urn:sts:cell:b' }
      ] }
    }
  });
  t.check(issued && issued.ok, 'a peer leaf is issued under the cell CA',
          JSON.stringify(issued && issued.errors));
  log.debug("Leaving peerLeaf().");
  return {
    keyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' })
      .toString(),
    certPem: issued.certificatePem,
    chainPem: issued.issuerChainPem || []
  };
}

// One handshake with the listener as cell "b", then one HTTP request on it,
// so the server's verdict on our certificate (TLS 1.3 sends it after the
// client's Finished) arrives as an answer or an alert.
function handshake(port, leaf, rootPem) {
  log.debug("Entering handshake().");
  log.debug("Leaving handshake().");
  return new Promise(function (resolve) {
    const out = { connected: false, authorized: false, error: '',
                  serverIssuer: '', serverRoot: '', answered: false };
    const socket = tls.connect({
      host: '127.0.0.1', port: port, servername: 'localhost',
      key: leaf.keyPem, cert: [leaf.certPem].concat(leaf.chainPem).join('\n'),
      // VERIFIED against the Root the case names: a chain that does not
      // reach it fails the handshake, and `connected` stays false with the
      // reason in `error`, which is what every case asserts against.
      ca: [rootPem], minVersion: 'TLSv1.3'
    }, function () {
      out.connected = true;
      out.authorized = socket.authorized;
      out.error = socket.authorizationError
        ? String(socket.authorizationError) : '';
      const peer = socket.getPeerCertificate(true);
      if (peer && peer.issuerCertificate && peer.issuerCertificate.raw) {
        out.serverIssuer = Buffer.from(peer.issuerCertificate.raw)
          .toString('base64');
      }
      socket.write('GET /_cell/v1/none HTTP/1.1\r\nHost: localhost\r\n' +
                   'Connection: close\r\n\r\n');
    });
    let settled = false;
    const finish = function () {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(out);
      }
    };
    socket.on('data', function () {
      out.answered = true;
      finish();
    });
    socket.on('error', function (err) {
      out.error = out.error || String((err && err.message) || err);
      finish();
    });
    socket.on('close', finish);
    socket.setTimeout(10000, function () {
      out.error = out.error || 'timed out';
      finish();
    });
  });
}

async function run(t) {
  log.debug("Entering run().");
  const restoreCells = stubCells();
  const port = await freePort();
  const savedPort = process.env.STS_CELL_PORT;
  process.env.STS_CELL_PORT = String(port);
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const stsCrypto = require('../common/crypto');
  const channelModule = require('../common/cell_channel');
  const channel = new channelModule.CellChannel();
  try {
    await keystore.start();
    const started = await pki.start({ realmIds: [] });
    t.check(started.ok, 'pki.start() builds the hierarchy',
            JSON.stringify(started && started.errors));
    const ensured = await pki.ensureScope(pki.PROCESS_SCOPE);
    t.check(ensured && ensured.ok !== false,
            'the process branch carries the cell Issuing CA');
    const listening = await channel.listen(function () {
      return null;
    }).whenReady;
    t.equal(listening.port, port, 'the inter-cell listener is bound');

    // A. The leaf minted at listen().
    const first = branchNow(pki);
    t.check(first.cellCa, 'the process branch has a cell Issuing CA');
    let leaf = await peerLeaf(t, pki, stsCrypto);
    let seen = await handshake(port, leaf, first.rootPem);
    t.check(seen.connected && seen.authorized,
            'A: the listener\'s chain verifies to the Root', seen.error);
    t.equal(seen.serverIssuer, first.cellCa,
            'A: the listener presents a leaf from the cell Issuing CA');
    t.check(seen.answered, 'A: the listener accepts a peer from that CA',
            seen.error);

    // B. The branch rebuilt underneath the channel, which is told nothing —
    // as when the row arrives from another cell.
    const rebuilt = await pki.buildScope(pki.PROCESS_SCOPE);
    t.check(rebuilt && rebuilt.ok, 'B: the process branch is rebuilt',
            JSON.stringify(rebuilt && rebuilt.errors));
    const second = branchNow(pki);
    t.check(second.cellCa && second.cellCa !== first.cellCa,
            'B: the rebuild made a new cell Issuing CA');
    leaf = await peerLeaf(t, pki, stsCrypto);
    seen = await handshake(port, leaf, second.rootPem);
    t.check(seen.connected && seen.authorized,
            'B: the chain still verifies to the (unchanged) Root',
            seen.error);
    t.equal(seen.serverIssuer, second.cellCa,
            'B: the next handshake presents a leaf from the NEW cell ' +
            'Issuing CA, not the one minted before the rebuild');
    t.check(seen.answered,
            'B: a peer holding a leaf from the new CA is accepted',
            seen.error);

    // C. A Root replaced whose branch has not arrived.
    const root = await pki.buildRoot();
    t.check(root && root.ok, 'C: the Root is replaced',
            JSON.stringify(root && root.errors));
    t.check(!pki.scopeChainsToRoot(pki.PROCESS_SCOPE),
            'C: the process branch no longer chains to the new Root');
    const context = await channel.handshakeContext();
    t.equal(context, null,
            'C: a handshake keeps the leaf held while the branch is on ' +
            'its way');
    await channel.ensureLeaf();
    const third = branchNow(pki);
    t.equal(third.intermediate, second.intermediate,
            'C: neither the handshake nor a dialler\'s ensureLeaf() built a ' +
            'process branch here');
    // B's peer leaf and B's Root: a new peer leaf would be issued through
    // `issueUnder()`, which repairs the stale branch this section is about.
    seen = await handshake(port, leaf, second.rootPem);
    t.equal(seen.serverIssuer, second.cellCa,
            'C: the leaf held is the one presented, from the branch the ' +
            'process still holds');

    // D. The branch arrives under the new Root.
    const arrived = await pki.buildScope(pki.PROCESS_SCOPE);
    t.check(arrived && arrived.ok, 'D: the process branch is rebuilt under ' +
            'the new Root', JSON.stringify(arrived && arrived.errors));
    const fourth = branchNow(pki);
    leaf = await peerLeaf(t, pki, stsCrypto);
    seen = await handshake(port, leaf, fourth.rootPem);
    t.check(seen.connected && seen.authorized,
            'D: the listener\'s chain verifies to the NEW Root', seen.error);
    t.equal(seen.serverIssuer, fourth.cellCa,
            'D: the listener presents a leaf from the newest cell CA');
    t.check(seen.answered,
            'D: the listener verifies the peer against the new Root',
            seen.error);
  } finally {
    await channel.close();
    if (savedPort === undefined) {
      delete process.env.STS_CELL_PORT;
    } else {
      process.env.STS_CELL_PORT = savedPort;
    }
    restoreCells();
    // The listener certificate back under the hierarchy this file left, for
    // the files after it in the same process.
    try {
      await require('../tls/tls_server').reconcileWithHierarchy();
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell channel hierarchy',
  describe: 'the inter-cell listener presents a leaf under the hierarchy it ' +
            'holds now, re-minted at the handshake after another cell ' +
            'rebuilt the branch, and builds no branch of its own while a ' +
            'replaced Root\'s branch is on its way (CI run 43642810770)',
  run: run
};
