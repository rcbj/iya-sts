'use strict';
//
// File: tests/tls_resumed_chain.js
//
// ===========================================================================
// A RESUMED TLS SESSION STILL HAS A CHAIN TO WALK (2026-09-21).
//
// Node hands a server the peer's LEAF and nothing above it when a session is
// RESUMED — `getPeerCertificate(true)` has no `issuerCertificate` — while
// `socket.authorized` stays true, because the session carries the verdict of
// the full handshake that made it. `common/revocation_status.js` walked that
// leaf, found its issuer "neither held here nor in the chain that was
// presented", and under hard-fail (product mode's default) refused a
// certificate that had verified. The remote XACML PEP reconnects every few
// seconds and resumes, so in the `single-node` mode it never registered —
// every request after its first connection was an unauthenticated caller —
// and the XACML jobs failed the same way in `cluster`.
//
// In process because what is under test is what a SOCKET carries on its
// second connection, which no request can ask about: over HTTP the only
// evidence is a 403 naming an access policy. A real TLS 1.2 listener on an
// ephemeral loopback port, a client that presents leaf + issuing CA and
// resumes, and `fromSocket()` asked on every connection:
//
//   1. the control — node really does give a resumed session the leaf alone,
//      so the fixture reaches the case (a client that never resumed would pass
//      every assertion below against the old code);
//   2. `fromSocket()` hands the resumed session the chain its full handshake
//      showed, and the walk then finds every link's issuer;
//   3. an UNVERIFIED leaf is remembered for nobody, so a certificate that
//      never verified cannot lend its chain to anything;
//   4. `common/request_pool.js`'s `peerOf()` reads the chain through
//      `fromSocket()` (source), which is what carries it to a request worker.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const tls = require('tls');

const log = require('bunyan').createLogger({ name: 'tls_resumed_chain',
  level: process.env.LOG_LEVEL || 'info' });

const pepCredential = require('./tools/pep-credential');
const revocation = require('../common/revocation_status');

// One listener, three connections from one client session: the first is a
// full handshake, the next two resume it. TLS 1.2 because its session-id and
// ticket resumption is immediate; a TLS 1.3 ticket arrives after the
// handshake and a short-lived client may never use it.
function connectThrice(server, clientOptions) {
  log.debug("Entering connectThrice().");
  const seen = [];
  return new Promise(function (resolve, reject) {
    let session;
    function next(i) {
      if (i >= 3) {
        resolve(seen);
        return;
      }
      const client = tls.connect(Object.assign({
        port: server.address().port, host: '127.0.0.1',
        rejectUnauthorized: false, maxVersion: 'TLSv1.2', session: session
      }, clientOptions));
      client.on('session', function (s) {
        session = s;
      });
      client.on('error', reject);
      client.on('data', function () {});
      client.on('close', function () {
        setTimeout(function () {
          next(i + 1);
        }, 30);
      });
    }
    server.on('secureConnection', function (socket) {
      const peer = socket.getPeerCertificate(true);
      seen.push({
        reused: socket.isSessionReused(),
        authorized: socket.authorized,
        nodeChain: !!(peer && peer.issuerCertificate),
        input: revocation.fromSocket(socket)
      });
      socket.end('ok');
    });
    next(0);
    log.debug("Leaving connectThrice().");
  });
}

async function run(t) {
  log.debug("Entering run().");
  revocation.resetCache();
  const client = await pepCredential.mint({ subject: 'CN=resumer,O=tests' });
  const server = await pepCredential.mint({ subject: 'CN=127.0.0.1,O=tests' });
  const stranger = await pepCredential.mint({ subject: 'CN=stranger,O=tests' });

  const listener = tls.createServer({
    key: server.keyPem, cert: server.certPem,
    requestCert: true, rejectUnauthorized: false,
    ca: [client.anchorPem]
  });
  await new Promise(function (resolve) {
    listener.listen(0, '127.0.0.1', resolve);
  });
  try {
    const seen = await connectThrice(listener, {
      key: client.keyPem, cert: client.certPem
    });

    // 1. THE CONTROL.
    t.check(seen.length === 3 && !seen[0].reused &&
            seen[1].reused && seen[2].reused,
            'the first connection is a full handshake and the next two ' +
            'resume it', JSON.stringify(seen.map(function (s) {
              return s.reused;
            })));
    t.check(seen.every(function (s) { return s.authorized === true; }),
            'every one of them is authorized — the session carries the ' +
            'verdict');
    t.check(seen[0].nodeChain && !seen[1].nodeChain,
            'and node gives the RESUMED session no issuer chain, which is ' +
            'the case this file exists for');

    // 2. THE CHAIN, HANDED BACK.
    t.equal(seen[0].input.chain.length, 2,
            'fromSocket() reads the issuing CA and the anchor off the full ' +
            'handshake');
    t.equal(seen[1].input.chain.length, 2,
            'and hands the SAME two to the resumed session');
    t.check(seen[1].input.chain.every(function (der, i) {
      return der.equals(seen[0].input.chain[i]);
    }), 'byte for byte');
    const walked = revocation.walk(seen[2].input);
    const orphan = walked.links.filter(function (link) {
      return /neither held here nor in the chain/.test(link.why || '');
    });
    t.check(orphan.length === 0,
            'so the walk finds the issuer of every link of a resumed ' +
            'session\'s leaf', walked.links.map(function (l) {
              return l.why;
            }).join(' | '));
    t.check(walked.links.some(function (link) {
      return link.source === 'anchor';
    }), 'and ends at the anchor');

    // 3. AN UNVERIFIED LEAF LENDS NOTHING.
    revocation.resetCache();
    const strangers = await connectThrice(listener, {
      key: stranger.keyPem, cert: stranger.certPem
    });
    t.check(strangers[1].reused && strangers[1].authorized === false,
            'a leaf under an authority this listener does not trust resumes ' +
            'unverified');
    t.equal(strangers[1].input.chain.length, 0,
            'and its resumed session is handed no chain, because an ' +
            'unverified handshake remembers nothing');
  } finally {
    await new Promise(function (resolve) {
      listener.close(resolve);
    });
    revocation.resetCache();
  }

  // 4. THE FRONT PROCESS FORWARDS IT.
  const pool = fs.readFileSync(path.join(__dirname, '..', 'common',
                                         'request_pool.js'), 'utf8');
  const body = /function peerOf\(req\) \{([\s\S]*?)\n\}\n/.exec(pool);
  t.check(!!body && /revocation_status'\)\.fromSocket\(socket\)/
            .test(body[1]),
          'request_pool.js\'s peerOf() reads the chain through ' +
          'fromSocket(), which is what carries it to a request worker');
  t.check(!!body && !/\.issuerCertificate\b/.test(
            body[1].replace(/\/\/.*$/gm, '')),
          'and walks no issuerCertificate of its own, which lost it');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls_resumed_chain',
  describe: 'a resumed TLS session carries the leaf alone, and the ' +
            'revocation walk is handed the chain its full handshake showed',
  run: run
};
