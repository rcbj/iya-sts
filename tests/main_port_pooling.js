// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/main_port_pooling.js
// ===========================================================================
// THE MAIN PORT'S SESSIONS RESUME ON ANY NODE, AND THE CHAIN FOLLOWS THEM
// (#406, 2026-10-02).
//
// The main port shares the cluster's session-ticket key now, so a TLS
// session one node made resumes on another — which is what stops a browser
// holding a matching client certificate asking its user on every new
// connection. A resumed session hands the server the leaf alone, so the chain
// the full handshake verified is a replicated shared store
// (`tls.presentedChains`), and a request on a session that resumed before its
// row arrived waits for it (`awaitResumedChain()`, `tls.resumedChainWaitMs`).
// `tests/vendored/sts_main_port_pooling.js` is the over-HTTP half, across a
// real cluster; what is here is what that job cannot choose — WHEN the row
// arrives:
//
//   A. the four settings and their defaults;
//   B. two "nodes" (two listeners, two SessionTickets instances over one
//      store) asking for a client certificate: a ticket from A does NOT resume
//      on B with no shared key, and does with one;
//   C. the chain is held as base64 rows, so it survives the journal, and a
//      session resumed on B finds it;
//   D. a row that is NOT held when the session resumes is waited for, and the
//      request carries the chain once it arrives — the race the shared key
//      opened;
//   E. a row that never arrives stops the wait at the setting, and 0 does
//      not wait at all;
//   F. as source: the main listener is given its session lifetime, keep-alive
//      and header timeout, joins the shared key behind its setting, and the
//      wait is mounted above the request pool.
//
// In process, for `tls_resumed_chain.js`'s reason: what is asserted is what a
// socket carries on its SECOND connection, and the order of a replicated row
// and a request, neither of which a request can ask about.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const https = require('https');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'main_port_pooling',
  level: process.env.STS_LOG_LEVEL || 'info' });

const pepCredential = require('./tools/pep-credential');

function makeDeps(store, state) {
  log.debug("Entering makeDeps().");
  const nodeCrypto = require('crypto');
  log.debug("Leaving makeDeps().");
  return {
    log: log,
    config: {
      value: function (key) {
        return key === 'tls.sessionTicketRotationS' ? state.intervalS : '';
      }
    },
    errorCodes: require('../common/error_codes'),
    store: store,
    activeActive: function () {
      return state.activeActive;
    },
    scheduler: function () {
      return null;
    },
    randomBytes: function (n) {
      return nodeCrypto.randomBytes(n);
    },
    now: function () {
      return Date.now();
    }
  };
}

// A node: an HTTPS listener with the main port's posture, answering what the
// socket carried — after the wait, as the main port's middleware does.
function node(serverPki, anchorPem, revocation) {
  log.debug("Entering node().");
  const server = https.createServer({
    key: serverPki.keyPem, cert: serverPki.certPem,
    requestCert: true, rejectUnauthorized: false, ca: [anchorPem],
    sessionTimeout: 60
  }, function (req, res) {
    const started = Date.now();
    revocation.awaitResumedChain(req.socket).then(function (arrived) {
      const input = revocation.fromSocket(req.socket);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        reused: req.socket.isSessionReused(),
        authorized: req.socket.authorized === true,
        chain: input ? input.chain.length : -1,
        arrived: arrived,
        waitedMs: Date.now() - started
      }));
    });
  });
  log.debug("Leaving node().");
  return server;
}

function listen(server) {
  log.debug("Entering listen().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      log.debug("Leaving listen().");
      resolve(server.address().port);
    });
  });
}

// One request on a NEW connection, offering `session`; resolves with the
// answer and the newest session the server issued.
function ask(port, pki, session) {
  log.debug("Entering ask(). " + port);
  return new Promise(function (resolve, reject) {
    let issued = null;
    const socket = tls.connect({
      host: '127.0.0.1', port: port, cert: pki.certPem, key: pki.keyPem,
      session: session || undefined, rejectUnauthorized: false,
      maxVersion: 'TLSv1.3'
    }, function () {
      socket.write('GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
    });
    const chunks = [];
    socket.on('session', function (s) {
      issued = s;
    });
    socket.on('data', function (d) {
      chunks.push(d);
    });
    socket.on('error', function (e) {
      log.debug("Caught in ask(): " + ((e && e.message) || e));
      reject(e);
    });
    socket.on('close', function () {
      const text = Buffer.concat(chunks).toString('utf8');
      const body = text.slice(text.indexOf('\r\n\r\n') + 4);
      let json = null;
      try {
        json = JSON.parse(body);
      } catch (e) {
        log.debug("Caught in ask(): " + e.message + ' ' + text.slice(0, 200));
      }
      log.debug("Leaving ask().");
      resolve({ answer: json, session: issued });
    });
  });
}

function settingRow(config, key) {
  log.debug("Entering settingRow(). " + key);
  log.debug("Leaving settingRow().");
  return config.SETTINGS.filter(function (r) { return r.key === key; })[0];
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const revocation = require('../common/revocation_status');
  const ticketsModule = require('../tls/session_tickets');

  // --- A. the settings ------------------------------------------------------
  const rows = {
    // Service-wide defaults every listener inherits since #429; each
    // listener has its own listener<Id>.<name> row.
    'http.keepAliveTimeoutS': [60, 'STS_HTTP_KEEP_ALIVE_TIMEOUT_S'],
    'tls.sessionTimeoutS': [300, 'STS_TLS_SESSION_TIMEOUT_S'],
    'tls.mainPortSharedTickets': [true, 'STS_TLS_MAIN_PORT_SHARED_TICKETS'],
    'tls.resumedChainWaitMs': [2000, 'STS_TLS_RESUMED_CHAIN_WAIT_MS']
  };
  Object.keys(rows).forEach(function (key) {
    const row = settingRow(config, key);
    t.check(row && row.dflt === rows[key][0] && row.env === rows[key][1],
      key + ' is a setting, ' + rows[key][1] + ', default ' + rows[key][0],
      JSON.stringify(row && { dflt: row.dflt, env: row.env }));
  });

  revocation.resetCache();
  const client = await pepCredential.mint({ subject: 'CN=pooler,O=tests',
                                            crlBase: false });
  const serverPki = await pepCredential.mint({
    subject: 'CN=127.0.0.1,O=tests', crlBase: false });
  const shared = new Map();
  const state = { intervalS: 3600, activeActive: true };
  const ticketsA = new ticketsModule.SessionTickets(makeDeps(shared, state));
  const ticketsB = new ticketsModule.SessionTickets(makeDeps(shared, state));
  const A = node(serverPki, client.anchorPem, revocation);
  const B = node(serverPki, client.anchorPem, revocation);
  const portA = await listen(A);
  const portB = await listen(B);
  ticketsA.track(A, 'node A');
  ticketsB.track(B, 'node B');
  const restore = [];
  function setWait(ms) {
    config.setOverride('tls.resumedChainWaitMs', ms);
    restore.push('tls.resumedChainWaitMs');
  }
  try {
    // --- B. the control, then one key --------------------------------------
    {
      const first = await ask(portA, client, null);
      const second = await ask(portB, client, first.session);
      t.check(first.answer && second.answer && !second.answer.reused,
        'with no shared key a session made on A does NOT resume on B, which ' +
        'is a full handshake and a certificate prompt', JSON.stringify(
          second.answer));
    }
    ticketsA.rotate('scheduled');
    const first = await ask(portA, client, null);
    t.check(first.answer && !first.answer.reused && first.answer.authorized &&
            first.answer.chain === 2,
      'a full handshake on A verifies the leaf and reads the issuing CA and ' +
      'the anchor above it', JSON.stringify(first.answer));

    // --- C. resumed on B, the row held -------------------------------------
    const second = await ask(portB, client, first.session);
    t.check(second.answer && second.answer.reused &&
            second.answer.authorized && second.answer.chain === 2 &&
            second.answer.arrived === true,
      'with the shared key the session resumes on B, and B hands the ' +
      'resumed leaf the chain A saw', JSON.stringify(second.answer));

    // --- D. resumed on B BEFORE the row arrives -----------------------------
    setWait(3000);
    const made = await ask(portA, client, null);
    revocation.resetCache();
    const late = ask(portB, client, made.session);
    await new Promise(function (r) { setTimeout(r, 300); });
    // The row arriving: another full handshake on A writes it, as the
    // replicated row would land here.
    await ask(portA, client, null);
    const waited = await late;
    t.check(waited.answer && waited.answer.reused &&
            waited.answer.arrived === true && waited.answer.chain === 2 &&
            waited.answer.waitedMs >= 250,
      'a session resumed on B before its chain arrived waits for it, and ' +
      'the request carries the chain once it does', JSON.stringify(
        waited.answer));

    // --- E. a row that never arrives, and 0 ---------------------------------
    // Each case below starts from a session made on A by a full handshake,
    // as a client's does, and B is then made to hold no row for it.
    setWait(400);
    const fresh = await ask(portA, client, null);
    revocation.resetCache();
    const never = await ask(portB, client, fresh.session);
    t.check(never.answer && never.answer.reused &&
            never.answer.arrived === false && never.answer.chain === 0 &&
            never.answer.waitedMs >= 350 && never.answer.waitedMs < 3000,
      'a chain that never arrives stops the wait at tls.resumedChainWaitMs, ' +
      'and the request goes on with the leaf alone', JSON.stringify(
        never.answer));
    setWait(0);
    const fresher = await ask(portA, client, null);
    revocation.resetCache();
    const none = await ask(portB, client, fresher.session);
    t.check(none.answer && none.answer.reused &&
            none.answer.arrived === false && none.answer.waitedMs < 200,
      'with tls.resumedChainWaitMs 0 nothing waits', JSON.stringify(
        none.answer));
  } finally {
    restore.forEach(function (key) {
      try {
        config.clearOverride(key);
      } catch (e) {
        log.debug("Caught in run(): " + e.message);
      }
    });
    revocation.resetCache();
    A.close();
    B.close();
  }

  // --- F. the wiring, as source ---------------------------------------------
  const root = path.join(__dirname, '..');
  const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
  const app = fs.readFileSync(path.join(root, 'common', 'app.js'), 'utf8');
  // Since #429 the session lifetime rides in the main port's policy
  // (protocolOptions(policyFor('main'))) and its pooling is registered.
  t.check(/protocolOptions\(tlsServer\.policyFor\('main'\)\)/.test(server),
    'the main listener is created from its own policy, which carries its ' +
    'TLS session lifetime', '');
  t.check(/registerHttpListener\(mainServer, 'main'\)/.test(server),
    'its connection pooling is registered, so its keep-alive and header ' +
    'timeout follow its settings', '');
  t.check(/config\.value\('tls\.mainPortSharedTickets'\)\s*!==\s*false\)\s*\{\s*require\('\.\/tls\/session_tickets'\)\.track\(mainServer/
            .test(server),
    'it joins the shared session-ticket key unless ' +
    'tls.mainPortSharedTickets is off', '');
  const waitAt = app.indexOf('resumedChainMiddleware()');
  const poolAt = app.indexOf('app.use(requestPool.middleware(');
  t.check(waitAt > 0 && poolAt > waitAt,
    'the wait for a resumed chain is mounted above the request pool', '');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'main_port_pooling',
  describe: 'the main port: a session resumes on any node and its client ' +
            'certificate chain follows it (#406)',
  run: run
};
