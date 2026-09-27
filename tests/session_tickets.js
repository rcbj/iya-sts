// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: tests/session_tickets.js
//
// ---------------------------------------------------------------------------
// ONE SESSION-TICKET KEY FOR EVERY NODE OF AN ACTIVE-ACTIVE CLUSTER
// (2026-09-27), `tls/session_tickets.ts`.
//
// The cluster mode found it: behind a balancer that picks a node per
// connection, a TLS ticket node A issued was sealed under a key node B had
// never seen, so tlsfuzzer's session-resumption scripts failed on the main
// port and LDAPS whenever the resumption landed on the other node.
//
// Two NODES here are two SessionTickets instances sharing one row store —
// which is what the replicated store makes them — each tracking a TLS server
// of its own over its own certificate. Every claim is asked of a REAL
// handshake, and each has its control:
//
//   A. a ticket from A resumes on B, TLS 1.3 and 1.2, and does NOT with
//      sharing off (the control that makes the positive mean something);
//   B. a context rebuilt with setSecureContext() — which puts a random key
//      back — still resumes, because the key is applied per connection;
//   C. a rotation refuses a ticket issued under the old key, and a new one
//      resumes; the old key is gone from the store;
//   D. a listener that applied the shared key and then finds sharing off
//      stops using that key;
//   E. the off reasons, a malformed stored key, and no key anywhere in the
//      report;
//   F. the scheduler job: registered once, a cluster job at the setting,
//      and its run rotates.
//
// In process: the servers are on loopback ephemeral ports, and what is
// varied is the cluster mode and the setting, which no request can choose.
// ---------------------------------------------------------------------------

const tls = require('tls');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'session_tickets',
  level: process.env.STS_LOG_LEVEL || 'info' });

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
      return state.scheduler;
    },
    randomBytes: function (n) {
      return nodeCrypto.randomBytes(n);
    },
    now: function () {
      return Date.now();
    }
  };
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

// One connection; resolves { reused, session }. `ca` is every certificate a
// node may present, since A and B present different ones.
function connect(port, ca, session, maxVersion) {
  log.debug("Entering connect(). " + port);
  return new Promise(function (resolve, reject) {
    let got = null;
    let reused = false;
    // Not verified: which certificate a node presents is not under test,
    // and resumption is decided before verification either way.
    const c = tls.connect({ host: '127.0.0.1', port: port, ca: ca,
                            rejectUnauthorized: false,
                            servername: 'localhost',
                            session: session || undefined,
                            maxVersion: maxVersion, minVersion: maxVersion },
      function () {
        reused = c.isSessionReused();
      });
    c.on('session', function (s) {
      got = s;
    });
    c.on('data', function () {});
    c.on('error', function (e) {
      log.debug("Caught in connect(): " + ((e && e.message) || e));
      reject(e);
    });
    c.on('end', function () {
      // A TLS 1.3 ticket arrives after the handshake; give it a moment.
      setTimeout(function () {
        log.debug("Leaving connect(). reused=" + reused);
        resolve({ reused: reused, session: got });
      }, 30);
    });
  });
}

async function run(t) {
  const mod = require('../tls/session_tickets');
  const stsCrypto = require('../common/crypto');
  const certA = stsCrypto.selfSignedRsaCertificate({ commonName: 'localhost' });
  const certB = stsCrypto.selfSignedRsaCertificate({ commonName: 'localhost' });
  const ca = [certA.certPem, certB.certPem];
  const shared = new Map();
  const state = { intervalS: 3600, activeActive: true, scheduler: null };
  const nodeA = new mod.SessionTickets(makeDeps(shared, state));
  const nodeB = new mod.SessionTickets(makeDeps(shared, state));
  function server(cert) {
    return tls.createServer({ key: cert.privateKeyPem, cert: cert.certPem },
      function (c) {
        c.end('hi');
      });
  }
  const A = server(certA);
  const B = server(certB);
  const portA = await listen(A);
  const portB = await listen(B);
  try {
    t.check(nodeA.track(A, 'node A') === true && nodeB.track(B, 'node B'),
      'two listeners are tracked', '');
    t.check(nodeA.track(A, 'node A') === true &&
            nodeA.report().listeners.length === 1,
      'tracking a listener twice keeps one entry', '');

    // --- E. no key until the job runs -------------------------------------
    t.check(nodeA.current() === null, 'no key is shared before the first ' +
      'rotation', '');

    // --- A. sharing off: the CONTROL ---------------------------------------
    for (const v of ['TLSv1.3', 'TLSv1.2']) {
      const first = await connect(portA, ca, null, v);
      const second = await connect(portB, ca, first.session, v);
      t.check(!!first.session && !second.reused,
        'with no shared key a ' + v + ' ticket from A does NOT resume on B',
        'reused=' + second.reused);
    }

    // --- A. one key, rotated by the job ------------------------------------
    const done = nodeA.rotate('scheduled');
    t.equal(done.generation, 1, 'the first rotation is generation 1');
    t.check(nodeB.current() && nodeB.current().length === 48,
      'the other node reads the 48-byte key from the shared store', '');
    for (const v of ['TLSv1.3', 'TLSv1.2']) {
      const first = await connect(portA, ca, null, v);
      const second = await connect(portB, ca, first.session, v);
      t.check(second.reused, 'a ' + v + ' ticket from A resumes on B', '');
      const back = await connect(portA, ca, second.session || first.session,
                                 v);
      t.check(back.reused, 'and a ' + v + ' ticket resumes back on A', '');
    }

    // --- B. a context rebuilt ---------------------------------------------
    B.setSecureContext({ key: certB.privateKeyPem, cert: certB.certPem });
    {
      const first = await connect(portA, ca, null, 'TLSv1.3');
      const second = await connect(portB, ca, first.session, 'TLSv1.3');
      t.check(second.reused, 'after setSecureContext() on B a ticket from A ' +
        'still resumes (the key is applied per connection)', '');
    }

    // --- C. rotation --------------------------------------------------------
    const before = await connect(portA, ca, null, 'TLSv1.3');
    const oldKey = shared.get('current').key;
    const again = nodeB.rotate('requested');
    t.equal(again.generation, 2, 'the second rotation is generation 2');
    t.check(shared.get('current').key !== oldKey &&
            JSON.stringify(Array.from(shared.values())).indexOf(oldKey) < 0,
      'the old key is gone from the store', '');
    const stale = await connect(portA, ca, before.session, 'TLSv1.3');
    t.check(!stale.reused, 'a ticket issued under the old key is refused ' +
      'after the rotation', '');
    const fresh = await connect(portB, ca, stale.session, 'TLSv1.3');
    t.check(fresh.reused, 'a ticket issued under the new key resumes on the ' +
      'other node', '');

    // --- D. sharing turned off ---------------------------------------------
    const lastShared = await connect(portA, ca, null, 'TLSv1.3');
    state.activeActive = false;
    // The first connection after the change carries a ticket B would have
    // taken a moment ago; each listener now has a key of its own.
    const onA = await connect(portA, ca, null, 'TLSv1.3');
    const crossed = await connect(portB, ca, lastShared.session, 'TLSv1.3');
    t.check(!crossed.reused, 'with sharing off a ticket issued under the ' +
      'shared key no longer resumes on the other node', '');
    t.check(!!onA.session, 'and the listener still hands out tickets', '');
    t.check(nodeA.report().listeners.every(function (one) {
      return one.shared === false;
    }), 'the report says the listener no longer holds the shared key', '');

    // --- E. off reasons, a malformed key, the report -----------------------
    t.check(/active-active/.test(nodeA.offReason()),
      'outside active-active the reason names the mode', nodeA.offReason());
    state.activeActive = true;
    state.intervalS = 0;
    t.check(/sessionTicketRotationS is 0/.test(nodeA.offReason()) &&
            nodeA.current() === null,
      'a rotation interval of 0 shares nothing', nodeA.offReason());
    state.intervalS = 3600;
    shared.set('current', { key: Buffer.alloc(12).toString('base64'),
                            generation: 3 });
    t.check(nodeA.current() === null,
      'a stored key that is not 48 bytes is not used (STS-TLS-0037)', '');
    nodeA.rotate('scheduled');
    const text = JSON.stringify(nodeA.report());
    t.check(text.indexOf(shared.get('current').key) < 0,
      'the report never carries the key', '');
    t.check(nodeA.report().shared === true &&
            nodeA.report().generation === 4,
      'the report says a key is shared and which generation', text);

    // --- F. the scheduler job ----------------------------------------------
    const registered = [];
    state.scheduler = {
      job: function (id) {
        return registered.find(function (one) {
          return one.id === id;
        }) || null;
      },
      register: function (spec) {
        registered.push(spec);
      }
    };
    t.check(nodeA.registerJobs() === true && nodeA.registerJobs() === false,
      'the job is registered once', '');
    const job = registered[0];
    t.check(job.id === 'tls.ticket-key-rotate' && job.kind === 'cluster' &&
            job.scope === 'service' &&
            job.everySetting === 'tls.sessionTicketRotationS',
      'a cluster job at tls.sessionTicketRotationS', JSON.stringify(job));
    t.check(job.off() === '', 'the job is on in active-active mode', '');
    const genBefore = nodeA.report().generation;
    const outcome = job.run({ trigger: 'manual' });
    t.check(nodeA.report().generation === genBefore + 1 &&
            /generation/.test(outcome.summary) &&
            shared.get('current').reason === 'requested',
      'its run rotates the key', JSON.stringify(outcome));
    state.activeActive = false;
    t.check(/active-active/.test(job.off()), 'and off outside it', '');
  } finally {
    A.close();
    B.close();
  }
}

module.exports = {
  name: 'session_tickets',
  describe: 'One TLS session-ticket key for every node of an active-active ' +
            'cluster: a ticket one node issued resumes on another, across ' +
            'a context rebuild, until a rotation deletes its key',
  run: run
};
