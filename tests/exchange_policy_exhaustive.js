// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/exchange_policy_exhaustive.js
// ===========================================================================
// THE EXCHANGE POLICY (#186), EVERY COMBINATION AT ONCE.
//
// rcbj, 2026-10-03: "execute every logical combination ... and test against
// positive and negative outcomes". `tests/exchange_policy.js` enumerates each
// group of interacting dimensions in full; this file takes the PRODUCT of all
// of them, so an interaction between two groups cannot hide. Each dimension
// is cut to the classes the rules can tell apart (`tools/exchange_oracle.js`).
// The four places the semantics can come from are the one exception: they
// decide only WHICH semantics is chosen, and `exchange_policy.js` enumerates
// all of them against each other in full, so here the request names it.
//
// About two and a half million combinations; each is asked of the built-in
// policy and compared with the oracle on the verdict, the refusal, whether a
// refusal is enforced, the semantics and the audience.
// ===========================================================================

const path = require('path');
const kit = require('./tools/exchange_oracle');

const ROOT = path.join(__dirname, '..');
const log = require('bunyan').createLogger({ name: 'exchange_policy_' +
  'exhaustive', level: process.env.LOG_LEVEL || 'info' });

function run(t) {
  log.debug("Entering run().");
  const verdicts = require(ROOT + '/xacml/xacml_exchange_verdicts');
  const dims = {
    mode: ['development', 'product'],
    protect: ['', 'flag', 'group'],
    actor: ['application', 'user-role', 'user', 'unknown'],
    position: kit.POSITIONS,
    relation: ['to', 'accepts', ''],
    requested: ['delegation', 'impersonation'],
    actorAllowed: [[], ['delegation'], ['impersonation'],
                   ['delegation', 'impersonation']],
    subjectAllowed: [[], ['delegation'], ['impersonation']],
    reach: [false, true],
    groups: ['', 'member', 'outsider'],
    mayAct: ['', 'names', 'other'],
    sourceAuthority: [false, true],
    targetAuthority: [false, true],
    targets: [0, 1, 'unregistered', 2]
  };
  const fixed = { subjectKind: 'user', actorDefault: '', subjectDefault: '',
                  settingDefault: 'delegation' };
  let count = 0;
  let wrong = 0;
  let firstWrong = '';
  const outcomes = {};
  const started = Date.now();
  kit.product(dims, fixed, function (c) {
    const facts = kit.combination(c);
    const expected = kit.oracle(c, facts);
    const got = verdicts.decide({ facts: facts, mode: c.mode,
      protocol: 'OAuth 2.0',
      settings: { defaultSemantics: c.settingDefault,
                  actorRole: 'DELEGATION_ACTOR' } }, null, {});
    count += 1;
    const key = expected.verdict === 'allow'
      ? 'allow:' + expected.semantics : 'refuse:' + expected.refusal;
    outcomes[key] = (outcomes[key] || 0) + 1;
    const same = got.verdict === expected.verdict &&
      got.chosen === expected.chosen &&
      (expected.verdict === 'allow'
        ? got.semantics === expected.semantics &&
          got.audience === expected.audience
        : got.refusal === expected.refusal &&
          !!got.enforced === !!expected.enforced);
    if (!same) {
      wrong += 1;
      if (!firstWrong) {
        firstWrong = JSON.stringify({ combination: c, expected: expected,
                                      got: got });
      }
    }
  });
  t.check(wrong === 0, 'the policy agrees with the oracle on all ' + count +
          ' combinations (' + JSON.stringify(outcomes) + ', ' +
          Math.round((Date.now() - started) / 1000) + ' s)',
          wrong + ' disagree; the first: ' + firstWrong);
  const keys = Object.keys(outcomes);
  t.check(['allow:self', 'allow:delegation', 'allow:impersonation']
            .every(function (k) { return keys.indexOf(k) >= 0; }) &&
          keys.filter(function (k) { return /^refuse/.test(k); }).length >= 9,
          'every allowed outcome and every refusal is reached',
          keys.join(', '));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'exchange_policy_exhaustive',
  describe: 'the exchange policy (#186) against an oracle over every ' +
            'combination of its decision dimensions at once',
  run: run
};
