// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: conformance_ledger.js
//
// ===========================================================================
// THE CONFORMANCE LEDGER ARGUES ONE MESSAGE WITHOUT ARGUING THE CONDITION
// (2026-10-26), AND SINCE #1292 IT ARGUES NO OKP MESSAGE AT ALL.
//
// sts_oidcc_conformance.js starts the OpenID conformance suite when it is
// loaded, so this file does not require it. It reads that driver's ledger
// as text, and asks conformance_suite.js's judge() and ledgerFor() about a
// table of its own with the shape the driver used:
//   * THE DRIVER: the classical twin's `unknown key type 'OKP'` entry on
//     oidcc-server-rotate-keys is GONE (#1292: `keys.eddsaSigning` is off by
//     default, so no realm publishes an Ed25519 or Ed448 key), and so are
//     the two `profile` scope warnings and
//     EnsureIdTokenDoesNotContainNonRequestedClaims; the AKP sentences stay
//     and PQ_ONLY still names them.
//   * THE JUDGE: an entry keyed by module and condition with a `msg`
//     argues that message only — a different message from the condition,
//     the same message from another module and a second failure beside it
//     stay findings — and a plan judged with the driver's own ledger finds
//     an OKP failure, since nothing argues it now.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'conformance_ledger',
  level: process.env.LOG_LEVEL || 'info' });
// The helper warns at load when the suite's certificate is absent. This
// file never calls the suite, so an empty stand-in keeps that warning out
// of the in-process run, and the variable is put back afterwards so a
// later file does not inherit it. A launcher that already named the
// certificate keeps its own file.
const hadSuiteCa = !!process.env.CONFORMANCE_SUITE_CA_FILE;
if (!hadSuiteCa) {
  process.env.CONFORMANCE_SUITE_CA_FILE = '/dev/null';
}
const oidf = require('./protocol/conformance_suite.js');
if (!hadSuiteCa) {
  delete process.env.CONFORMANCE_SUITE_CA_FILE;
}

const DRIVER = path.join(__dirname, 'protocol', 'sts_oidcc_conformance.js');
const OKP_KEY = '*/oidcc-server-rotate-keys/VerifyNewJwksHasNewSigningKey';
const COND = 'VerifyNewJwksHasNewSigningKey';
const MODULE = 'oidcc-server-rotate-keys';
const OKP_MSG = "unknown key type 'OKP' found";
const AKP_MSG = 'Error parsing JWK key';
const PQ_ONLY = [COND, 'WarnOnUnusableJwksKeys'];

function driverText() {
  log.debug('Entering driverText().');
  const text = fs.readFileSync(DRIVER, 'utf8');
  log.debug('Leaving driverText().');
  return text;
}

function failuresOf() {
  log.debug('Entering failuresOf().');
  const table = {};
  table[COND] = 'nimbus cannot parse kty AKP';
  table[OKP_KEY] = {
    why: 'nimbus throws on kty OKP',
    msg: /unknown key type 'OKP'/
  };
  log.debug('Leaving failuresOf().');
  return table;
}

function one(module, src, msg, status) {
  log.debug('Entering one().');
  log.debug('Leaving one().');
  return {
    result: 'FAILED',
    status: status || 'FINISHED',
    module: module,
    failures: [{ src: src, msg: msg }],
    warnings: []
  };
}

function unexplained(label, plan, result) {
  log.debug('Entering unexplained().');
  const ledger = oidf.ledgerFor(plan, failuresOf(), PQ_ONLY);
  const judged = oidf.judge(label, { results: [result] }, {}, {}, ledger);
  log.debug('Leaving unexplained(). ' + judged.unexplained.length);
  return judged.unexplained;
}

async function run(t) {
  log.debug('Entering run().');
  const src = driverText();
  t.check(src.indexOf('["' + OKP_KEY + '"]') < 0 &&
          src.indexOf("msg: /unknown key type 'OKP'/") < 0,
          'the OpenID Connect driver no longer argues the OKP message ' +
          '(#1292: no EdDSA key is published by default)');
  ['VerifyScopesReturnedInUserInfoClaims:',
   'VerifyScopesReturnedInAuthorizationEndpointIdToken:',
   'EnsureIdTokenDoesNotContainNonRequestedClaims:'].forEach(function (key) {
    t.check(src.indexOf(key) < 0,
            'the driver no longer argues ' + key.slice(0, -1) + ' (#1292)');
  });
  t.check(src.indexOf('WarnOnUnusableJwksKeys:') >= 0 &&
          src.indexOf('VerifyNewJwksHasNewSigningKey:') >= 0,
          'the two post-quantum sentences stay');
  const pq = /const PQ_ONLY = (\[[^\]]+\])/.exec(src);
  t.check(!!pq, 'the driver names the entries a twin loses');
  t.check(pq && pq[1].indexOf('"' + COND + '"') >= 0,
           'PQ_ONLY still drops the AKP condition');
  t.check(pq && pq[1].indexOf('"WarnOnUnusableJwksKeys"') >= 0,
           'PQ_ONLY still drops the AKP warning');
  // The driver's own failure ledger, as text: with the OKP entry gone, a
  // classical rotate-keys OKP failure is unexplained.
  const driverFailures = {};
  driverFailures[COND] = 'nimbus cannot parse kty AKP';
  const driverTwin = oidf.ledgerFor({ key: 'dynamic-cl', base: 'dynamic',
                                      classical: true },
                                    driverFailures, PQ_ONLY);
  t.equal(oidf.judge('dynamic-cl', { results: [one(MODULE, COND, OKP_MSG)] },
                     {}, {}, driverTwin).unexplained.length, 1,
          'with the driver\'s ledger an OKP failure on the twin is a finding');

  const classical = { key: 'dynamic-cl', base: 'dynamic', classical: true };
  const postQuantum = { key: 'dynamic' };
  const whole = failuresOf();
  const twin = oidf.ledgerFor(classical, whole, PQ_ONLY);
  t.check(!(COND in twin),
          'the twin ledger has lost the AKP condition');
  t.check(typeof twin[OKP_KEY] === 'object',
          'the twin ledger keeps the OKP message entry');
  t.check(oidf.ledgerFor(postQuantum, whole, PQ_ONLY) === whole,
          'a plan that is not a twin is judged on the whole table');

  t.equal(unexplained('dynamic-cl', classical,
                      one(MODULE, COND, OKP_MSG)).length, 0,
          'a classical rotate-keys OKP failure is argued');
  t.equal(unexplained('dynamic-cl', classical,
                      one(MODULE, COND, OKP_MSG, 'INTERRUPTED')).length, 0,
          'the same failure is argued when the module stops there');
  t.equal(unexplained('t-mtls-cl',
                      { key: 't-mtls-cl', base: 't-mtls', classical: true },
                      one(MODULE, COND, OKP_MSG)).length, 0,
          'every classical plan shares that argument');
  const other = unexplained('dynamic-cl', classical,
                            one(MODULE, COND, AKP_MSG));
  t.check(other.length === 1 && other[0].indexOf(AKP_MSG) >= 0,
          'a different message from the same condition is a finding',
          other.join(' | '));
  t.equal(unexplained('dynamic-cl', classical,
                      one('oidcc-server-other', COND, OKP_MSG)).length, 1,
          'the same OKP message from another module is a finding');
  const both = one(MODULE, COND, OKP_MSG);
  both.failures.push({ src: 'SomeOtherCondition', msg: 'no new key' });
  t.equal(unexplained('dynamic-cl', classical, both).length, 1,
          'a second failure in the same module is still a finding');
  t.equal(unexplained('dynamic', postQuantum,
                      one(MODULE, COND, AKP_MSG)).length, 0,
          'the post-quantum plan still argues any message of the condition');

  const warned = oidf.judge('dynamic-cl', {
    results: [{
      result: 'WARNING', status: 'FINISHED', module: MODULE,
      failures: [],
      warnings: [{ src: 'EnsureIdTokenDoesNotContainNonRequestedClaims',
                   msg: "non-requested claim 'email'" }]
    }]
  }, {}, {
    EnsureIdTokenDoesNotContainNonRequestedClaims: {
      why: 'only the two argued claims',
      msg: /session_expiry|tenant/
    }
  }, {});
  t.equal(warned.unexplained.length, 1,
          'a warning outside its pattern is still a finding');
  log.debug('Leaving run().');
}

module.exports = {
  name: 'conformance_ledger',
  describe: 'The conformance ledger argues one message of one module ' +
            'without arguing every failure of that condition, and the ' +
            'OpenID Connect driver argues no OKP message, profile-scope ' +
            'warning or unrequested ID Token claim since #1292',
  run: run
};
