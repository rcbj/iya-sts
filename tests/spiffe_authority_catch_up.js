// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/spiffe_authority_catch_up.js
// ===========================================================================
// AN SVID UNDER AN AUTHORITY THAT HAS NOT REACHED THIS PROCESS YET WAITS FOR
// THE STORE ONCE (2026-10-02).
//
// A federated bundle written through /admin-api reaches the process holding
// the SPIFFE gRPC sockets on the next pull of the change log. In single-node,
// CI run 36986913696, `sts_spiffe_broker` presented an SVID under a trust
// domain it had federated a moment before and was refused as signed by nobody
// (STS-SPIFFE-0024). `SpiffeGrpc.prepareAfterCatchUp()` now pulls the store
// once for that refusal and prepares the call again. Asserted on the method
// itself, with `prepareCall()` stood in for:
//
//   A. an unknown authority is prepared again after the pull, and the second
//      answer is the one handed on;
//   B. it is prepared again once only — a bundle still missing stands;
//   C. any other refusal, and an allowed call, are handed on at once,
//      prepared once.
// ===========================================================================

const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'spiffe_authority_catch_up',
  level: process.env.STS_LOG_LEVEL || 'info' });

// A stand-in carrying just what the method reads: `deps.log` and a
// `prepareCall()` answering from a script.
function standIn(answers) {
  log.debug("Entering standIn().");
  const me = {
    deps: { log: log },
    calls: 0,
    prepareCall: function () {
      const at = Math.min(me.calls, answers.length - 1);
      me.calls += 1;
      return answers[at];
    }
  };
  log.debug("Leaving standIn().");
  return me;
}

function prepared(grpcModule, me) {
  log.debug("Entering prepared().");
  log.debug("Leaving prepared().");
  return new Promise(function (resolve) {
    grpcModule.SpiffeGrpc.prototype.prepareAfterCatchUp.call(
      me, {}, 'broker', 'FetchJWTSVID', resolve);
  });
}

const UNKNOWN = { refusal: new Error('signed by nobody'),
                  errorCode: 'STS-SPIFFE-0131',
                  caller: { refusalCode: 'STS-SPIFFE-0024' } };
const ALLOWED = { refusal: null, caller: { spiffeId: 'spiffe://x/y' } };
const OTHER = { refusal: new Error('no header'), errorCode: 'STS-SPIFFE-0132',
                caller: null };

async function run(t) {
  log.debug("Entering run().");
  const grpcModule = require('../spiffe/spiffe_grpc');

  t.log.info('=== A. an unknown authority is prepared again ===');
  const a = standIn([UNKNOWN, ALLOWED]);
  const gotA = await prepared(grpcModule, a);
  t.check(gotA === ALLOWED && a.calls === 2,
          'A1. after the pull the call is prepared again and allowed',
          'calls ' + a.calls);

  t.log.info('=== B. once only ===');
  const b = standIn([UNKNOWN, UNKNOWN, ALLOWED]);
  const gotB = await prepared(grpcModule, b);
  t.check(gotB === UNKNOWN && b.calls === 2,
          'B1. a bundle still missing after one pull stands as a refusal',
          'calls ' + b.calls);

  t.log.info('=== C. everything else at once ===');
  const c = standIn([OTHER]);
  const gotC = await prepared(grpcModule, c);
  t.check(gotC === OTHER && c.calls === 1,
          'C1. another refusal is handed on at once', 'calls ' + c.calls);
  const d = standIn([ALLOWED]);
  const gotD = await prepared(grpcModule, d);
  t.check(gotD === ALLOWED && d.calls === 1,
          'C2. an allowed call is prepared once', 'calls ' + d.calls);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_authority_catch_up',
  describe: 'an SVID whose authority has not reached this process yet waits ' +
            'for the store once, and nothing else waits',
  run: run
};
