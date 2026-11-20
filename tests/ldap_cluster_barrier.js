// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_cluster_barrier.js
//
// ===========================================================================
// AN LDAP OPERATION WAITS FOR THE CLUSTER'S READ BARRIER BEFORE IT RUNS
// (2026-11-18, GitHub run #510).
//
// `tests/protocol/sts_second_factor_doors.js` in `cluster` mode required a
// second factor of a person through `/admin-api` (node A, answered after its
// commit) and the LDAPS simple bind it made next, balanced to node B, was
// ACCEPTED with her password alone: `cluster/cluster_barrier.js`'s rule 1 is
// HTTP middleware and an LDAP operation never passes `app.js`, so B had not
// applied the change. `ldap/ldap_server.js` now wraps every operation but
// unbind in `afterClusterCatchUp()`, inside what `LOCAL_HANDLERS` holds, so
// it runs wherever the operation runs. Driven here with a stub barrier, so
// the ORDER is what is asserted: the handler does not run until the pull
// answers, and runs in the same tick where the barrier is inactive.
//
// Mutation-checked by hand on the day: the registration without the wrapper
// turns section D red.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ldapServer = require('../ldap/ldap_server');
const clusterBarrier = require('../cluster/cluster_barrier');

const log = require('bunyan').createLogger({
  name: 'ldap_cluster_barrier',
  level: process.env.LOG_LEVEL || 'info' });

const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;

// Replaces the barrier's two members the wrapper reads, with a pull that
// finishes only when the test says so; `restore()` puts them back.
function heldBarrier(active) {
  log.debug("Entering heldBarrier().");
  const saved = { isActive: clusterBarrier.isActive,
                  catchUp: clusterBarrier.catchUp };
  let release = null;
  const barrier = {
    asked: [],
    release: function () {
      log.debug("Entering release().");
      if (release) {
        release({ caughtUp: true });
      }
      log.debug("Leaving release().");
    },
    restore: function () {
      log.debug("Entering restore().");
      clusterBarrier.isActive = saved.isActive;
      clusterBarrier.catchUp = saved.catchUp;
      log.debug("Leaving restore().");
    }
  };
  clusterBarrier.isActive = function () {
    log.debug("Entering the stub isActive().");
    log.debug("Leaving the stub isActive().");
    return active;
  };
  clusterBarrier.catchUp = function (what) {
    log.debug("Entering the stub catchUp().");
    barrier.asked.push(what);
    log.debug("Leaving the stub catchUp().");
    return new Promise(function (resolve) {
      release = resolve;
    });
  };
  log.debug("Leaving heldBarrier().");
  return barrier;
}

function tick() {
  log.debug("Entering tick().");
  log.debug("Leaving tick().");
  return new Promise(function (resolve) {
    setImmediate(resolve);
  });
}

function socketRequest(dn) {
  log.debug("Entering socketRequest().");
  const ldap = require('ldapjs');
  log.debug("Leaving socketRequest().");
  return {
    connection: { encrypted: false,
                  ldap: { bindDN: 'cn=anonymous', id: 'lcb-connection-1' },
                  remoteAddress: '127.0.0.1', remotePort: 40000 },
    dn: ldap.parseDN(dn), scope: 2,
    filter: ldap.parseFilter('(objectClass=*)')
  };
}

async function run(t) {
  log.debug("Entering run().");

  t.log.info('=== A. active: the handler runs after the pull ===');
  let barrier = heldBarrier(true);
  try {
    const ran = [];
    const req = {};
    const res = {};
    const next = function () {};
    const wrapped = ldapServer.afterClusterCatchUp('bind',
      function (q, s, n) {
        ran.push(q === req && s === res && typeof n === 'function');
      });
    wrapped(req, res, next);
    await tick();
    t.check(barrier.asked.length === 1 && /bind/.test(barrier.asked[0]),
            'the barrier is asked once, naming the operation',
            JSON.stringify(barrier.asked));
    t.check(ran.length === 0,
            'THE HANDLER HAS NOT RUN while the pull is outstanding — so a ' +
            'second-factor requirement another node committed first is ' +
            'applied before a bind decides on a password');
    t.check(req.stsAsyncOperation === true,
            'the request says it went asynchronous, so a worker\'s ' +
            'performOperation() waits for its next()');
    barrier.release();
    await tick();
    t.check(ran.length === 1 && ran[0] === true,
            'and runs once the pull answers, with the request, the response ' +
            'and a next', JSON.stringify(ran));
  } finally {
    barrier.restore();
  }

  t.log.info('=== B. inactive: no wait at all ===');
  barrier = heldBarrier(false);
  try {
    const direct = [];
    const req = {};
    ldapServer.afterClusterCatchUp('search', function () {
      direct.push(true);
    })(req, {}, function () {});
    t.check(direct.length === 1 && barrier.asked.length === 0 &&
            req.stsAsyncOperation === undefined,
            'outside active-active the handler runs in the same tick, ' +
            'nothing is pulled and the request stays synchronous',
            JSON.stringify({ ran: direct.length, asked: barrier.asked }));
  } finally {
    barrier.restore();
  }

  t.log.info('=== C. a handler that throws after the wait ===');
  barrier = heldBarrier(true);
  try {
    const answers = [];
    ldapServer.afterClusterCatchUp('modify', function () {
      throw new Error('a handler failure');
    })({}, {}, function (err) {
      answers.push(err);
    });
    barrier.release();
    await tick();
    await tick();
    t.check(answers.length === 1 && answers[0] && answers[0].code === 1,
            'is answered operationsError (1), once, rather than left open ' +
            '(STS-LDAP-0223)', JSON.stringify(answers.map(function (e) {
              return e && { code: e.code, name: e.name };
            })));
    const unreadable = [];
    ldapServer.afterClusterCatchUp('search', function () {
      const e = new Error('the store did not answer');
      require('../common/error_codes').mark(e, 'STS-LDAP-0130');
      throw e;
    })({}, {}, function (err) {
      unreadable.push(err);
    });
    barrier.release();
    await tick();
    await tick();
    t.check(unreadable.length === 1 && unreadable[0] &&
            unreadable[0].code === 52,
            'and a directory this process could not read is unavailable ' +
            '(52), as performOperation() answers it',
            JSON.stringify(unreadable.map(function (e) {
              return e && { code: e.code, name: e.name };
            })));
  } finally {
    barrier.restore();
  }

  t.log.info('=== D. the registered handler goes through it ===');
  barrier = heldBarrier(true);
  try {
    const shape = ldapServer.operationRequest('search', socketRequest(USERS));
    let outcome = null;
    Promise.resolve(ldapServer.performOperation('search',
      JSON.parse(JSON.stringify(shape)))).then(function (o) {
      outcome = o;
    });
    await tick();
    t.check(barrier.asked.length === 1 && outcome === null,
            'a search run as a worker runs it asks the barrier and has not ' +
            'answered while the pull is outstanding — the wrapper is in ' +
            'what LOCAL_HANDLERS holds',
            JSON.stringify({ asked: barrier.asked, outcome: !!outcome }));
    barrier.release();
    for (let i = 0; i < 5 && !outcome; i++) {
      await tick();
    }
    t.check(!!outcome && outcome.ok === true &&
            (outcome.entries || []).length > 0,
            'and answers the search once it does',
            JSON.stringify(outcome).slice(0, 300));
  } finally {
    barrier.restore();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ldap_cluster_barrier',
  describe: 'Every LDAP operation but unbind waits for the cluster read ' +
            'barrier where it is active, so a change another node committed ' +
            'first — a second factor required — is applied before a bind is ' +
            'decided (run #510).',
  run: run
};
