'use strict';
//
// File: spiffe_grpc_cluster_barrier.js
//
// ===========================================================================
// A gRPC CALL WAITS FOR THE CLUSTER'S READ BARRIER BEFORE IT IS ANSWERED
// (2026-09-24).
//
// `tests/vendored/sts_spiffe_broker.js` in `cluster` mode: a broker removed
// through the balancer on node B was still answered on its next call to node
// A's Broker listener, because the barrier that makes a node apply what
// another committed before serving a request (`cluster/cluster_barrier.js`,
// rule 1) is HTTP middleware and a gRPC call never passes `app.js`.
// `SpiffeGrpc.fromCaller()`, the wrapper every unary, server-streaming and
// bidi handler runs through, now asks `syncShared()` first where the barrier
// is active. Driven here with a stub barrier, so the ORDER is what is
// asserted: the handler does not run until the barrier answers, and runs at
// once where the barrier is inactive.
//
// Mutation-checked by hand on the day: `fromCaller()` running the handler
// without the wait turns section A red.
// ===========================================================================

delete process.env.CONFIG_FILE;

const rpc = require('../spiffe/spiffe_grpc');

const log = require('bunyan').createLogger({
  name: 'spiffe_grpc_cluster_barrier',
  level: process.env.LOG_LEVEL || 'info' });

function built(barrier) {
  log.debug("Entering built().");
  const deps = Object.assign(rpc.SpiffeGrpc.defaultDeps(), {
    loadClusterBarrier: function () {
      log.debug("Entering loadClusterBarrier().");
      log.debug("Leaving loadClusterBarrier().");
      return barrier;
    }
  });
  log.debug("Leaving built().");
  return new rpc.SpiffeGrpc(deps);
}

// A barrier whose pull finishes only when the test says so.
function heldBarrier(active) {
  log.debug("Entering heldBarrier().");
  let release = null;
  const barrier = {
    asked: 0,
    isActive: function () {
      log.debug("Entering isActive().");
      log.debug("Leaving isActive().");
      return active;
    },
    syncShared: function () {
      log.debug("Entering syncShared().");
      barrier.asked += 1;
      log.debug("Leaving syncShared().");
      return new Promise(function (resolve) {
        release = function () {
          resolve({ caughtUp: true });
        };
      });
    },
    release: function () {
      log.debug("Entering release().");
      if (release) {
        release();
      }
      log.debug("Leaving release().");
    }
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

async function run(t) {
  log.debug("Entering run().");
  const call = {
    getPeer: function () {
      log.debug("Entering getPeer().");
      log.debug("Leaving getPeer().");
      return 'ipv4:10.0.0.5:51234';
    }
  };

  t.log.info('=== A. active: the handler runs after the barrier ===');
  const barrier = heldBarrier(true);
  const ran = [];
  const wrapped = built(barrier).fromCaller(function (c, callback) {
    ran.push(c === call && typeof callback === 'function');
  });
  wrapped(call, function () {});
  await tick();
  t.check(barrier.asked === 1, 'the barrier is asked once for the call',
          String(barrier.asked));
  t.check(ran.length === 0,
          'THE HANDLER HAS NOT RUN while the barrier\'s pull is outstanding ' +
          '— so an allow-list change another node committed first is ' +
          'applied before the call is authorized');
  barrier.release();
  await tick();
  t.check(ran.length === 1 && ran[0] === true,
          'and runs once the barrier answers, with the call and its callback',
          JSON.stringify(ran));

  t.log.info('=== B. inactive: no wait at all ===');
  const idle = heldBarrier(false);
  const direct = [];
  built(idle).fromCaller(function () {
    direct.push(true);
  })(call, function () {});
  t.check(direct.length === 1 && idle.asked === 0,
          'where the barrier is inactive (not active-active) the handler runs ' +
          'synchronously and nothing is pulled',
          JSON.stringify({ ran: direct.length, asked: idle.asked }));

  t.log.info('=== C. a handler that throws after the wait ===');
  const late = heldBarrier(true);
  const answers = [];
  built(late).fromCaller(function () {
    throw new Error('a handler failure');
  })(call, function (err) {
    answers.push(err);
  });
  late.release();
  await tick();
  await tick();
  t.check(answers.length === 1 && answers[0] &&
          answers[0].code === rpc.grpc.status.INTERNAL,
          'is answered INTERNAL rather than left open (STS-SPIFFE-0143)',
          JSON.stringify(answers));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_grpc_cluster_barrier',
  describe: 'Every SPIFFE gRPC call waits for the cluster read barrier where ' +
            'it is active, so a change another node committed first — a ' +
            'broker removed — is applied before the call is answered.',
  run: run
};
