// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_regexp_bound.js
//
// ===========================================================================
// XACML'S REGEXP-MATCH IS BOUNDED, AT THE SAVE AND AT THE EVALUATION (#2220).
//
//   A. `common/pattern_safety.js` itself: the exponential shapes refused,
//      escapes and classes stepped over, and federation's check unchanged.
//   B. THE EVALUATION: `string-regexp-match` with `(a+)+`, with a
//      backreference, or on a value longer than 4096 characters is a
//      processing error (Indeterminate); an ordinary pattern still matches
//      anchored.
//   C. THE WALK: `patternProblemsIn()` finds a literal pattern in a Target's
//      Match and in a Condition's Apply, and nothing in a safe policy.
//      `validate()` does not refuse it — a stored policy must still load.
//   D. THE STORE: a new document with an unsafe pattern is refused
//      STS-XACML-0338; a safe one is written; a policy stored before the
//      rule (written straight into the directory) still parses, and an
//      unchanged rewrite of it — what enable and disable do — is accepted.
// ===========================================================================

const errorCodes = require('../common/error_codes');
const PatternSafety = require('../common/pattern_safety');
const model = require('../xacml/xacml_model');
const functions = require('../xacml/xacml_functions');
const validate = require('../xacml/xacml_validate');
const xml = require('../xacml/xacml_xml');
const store = require('../xacml/xacml_store');

require('../ldap/ldap_server');

const log = require('bunyan').createLogger({ name: 'xacml_regexp_bound',
  level: process.env.LOG_LEVEL || 'info' });

const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
const STRING = 'http://www.w3.org/2001/XMLSchema#string';
const SUBJECT = 'urn:oasis:names:tc:xacml:1.0:subject-category:' +
                'access-subject';

// A policy whose target's Match and whose rule's Condition each carry a
// string-regexp-match with the given literal patterns.
function policyWith(id, matchPattern, conditionPattern) {
  log.debug("Entering policyWith().");
  const designator = '<AttributeDesignator Category="' + SUBJECT + '" ' +
    'AttributeId="uid" DataType="' + STRING + '" MustBePresent="false"/>';
  log.debug("Leaving policyWith().");
  return [
    '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"',
    ' PolicyId="urn:test:2220:' + id + '" Version="1.0"',
    ' RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-' +
      'algorithm:deny-unless-permit">',
    '<Target><AnyOf><AllOf>',
    '<Match MatchId="' + F1 + 'string-regexp-match">',
    '<AttributeValue DataType="' + STRING + '">' + matchPattern +
      '</AttributeValue>', designator, '</Match>',
    '</AllOf></AnyOf></Target>',
    '<Rule RuleId="urn:test:2220:rule" Effect="Permit"><Condition>',
    '<Apply FunctionId="' + F1 + 'string-regexp-match">',
    '<AttributeValue DataType="' + STRING + '">' + conditionPattern +
      '</AttributeValue>',
    '<Apply FunctionId="' + F1 + 'string-one-and-only">' + designator +
      '</Apply>',
    '</Apply></Condition></Rule></Policy>'].join('\n');
}

function checkPatternSafety(t) {
  log.debug("Entering checkPatternSafety().");
  ['(a+)+', '(a|aa)*', '((ab)*c)+', '(a+){2,}', '(?:x|y)+'].forEach(
    function (p) {
      t.check(PatternSafety.nestedQuantifier(p),
              'A: "' + p + '" is the exponential shape');
    });
  ['[a-z]+', '(ab)+', '[(a+)]+', '\\(a+\\)+', 'uid=[^,]+,ou=users,.*']
    .forEach(function (p) {
      t.check(!PatternSafety.nestedQuantifier(p) &&
              PatternSafety.problem(p) === '',
              'A: "' + p + '" is accepted');
    });
  t.check(/backreference/.test(PatternSafety.problem('(a)\\1')),
          'A: a backreference is refused');
  t.check(/characters long/.test(PatternSafety.problem('a'.repeat(300))) &&
          PatternSafety.problem('a'.repeat(300), 1024) === '',
          'A: the length is the caller\'s (256 unless it names one)');
  const federation = require('../federation/federation');
  t.check(/exponential/.test(federation.subjectPatternProblem('(a+)+')) &&
          federation.subjectPatternProblem('uid=[^,]+,.*') === '',
          'A: federation\'s fedSubjectPattern check reads the shared module');
  log.debug("Leaving checkPatternSafety().");
}

function checkEvaluation(t) {
  log.debug("Entering checkEvaluation().");
  const match = functions.lookup(F1 + 'string-regexp-match');
  const answer = function (pattern, value) {
    try {
      const bag = match.apply([pattern, value]);
      return bag.values[0] === true ? 'true' : 'false';
    } catch (e) {
      log.debug("Caught in answer(): " + ((e && e.message) || e));
      return e && e.xacmlStatus === model.STATUS.PROCESSING_ERROR
        ? 'processing-error'
        : 'error:' + (e && (e.xacmlStatus || e.message));
    }
  };
  t.equal(answer('ab+', 'abbb'), 'true',
          'B: an ordinary pattern matches, anchored');
  t.equal(answer('b', 'abc'), 'false', 'B: ... and anchored');
  const started = Date.now();
  t.equal(answer('(a+)+$', 'a'.repeat(40) + '!'), 'processing-error',
          'B: (a+)+ is Indeterminate rather than evaluated');
  t.check(Date.now() - started < 1000,
          'B: ... at once (an evaluated (a+)+ on 41 characters takes ' +
          'minutes)', (Date.now() - started) + ' ms');
  t.equal(answer('(a)\\1', 'aa'), 'processing-error',
          'B: a backreference is Indeterminate');
  t.equal(answer('a+', 'a'.repeat(functions.REGEX_INPUT_MAX)), 'true',
          'B: a value of exactly REGEX_INPUT_MAX characters is matched');
  t.equal(answer('a+', 'a'.repeat(functions.REGEX_INPUT_MAX + 1)),
          'processing-error',
          'B: one character more is Indeterminate');
  t.check(typeof match.patternCheck === 'function' && !match.staticCheck,
          'B: the save\'s check is a patternCheck, not a staticCheck');
  log.debug("Leaving checkEvaluation().");
}

function checkWalk(t) {
  log.debug("Entering checkWalk().");
  const unsafe = xml.parsePolicy(policyWith('walk', '(a+)+', '(x|xy)*'));
  t.check(true, 'C: a policy with unsafe patterns still PARSES (validate() ' +
          'does not refuse it, so a stored one loads)');
  const problems = validate.patternProblemsIn(unsafe);
  t.check(problems.length === 2 &&
          /\(a\+\)\+/.test(problems.join(' ')) &&
          /\(x\|xy\)\*/.test(problems.join(' ')),
          'C: patternProblemsIn() finds the Match\'s and the Condition\'s',
          JSON.stringify(problems));
  const safe = xml.parsePolicy(policyWith('walk-safe', 'a[0-9]+', '[a-z]+'));
  t.equal(validate.patternProblemsIn(safe).length, 0,
          'C: nothing in a safe policy');
  t.check(validate.patternProblemsIn(xml.parsePolicy(
    policyWith('walk-long', 'a'.repeat(1025), 'a'))).length === 1,
          'C: a literal pattern longer than 1024 characters is found');
  log.debug("Leaving checkWalk().");
}

function checkStore(t) {
  log.debug("Entering checkStore().");
  const refused = store.write('rx2220-unsafe',
                              policyWith('unsafe', '(a+)+', '[a-z]+'));
  t.check(!refused.ok && errorCodes.codeOf(refused) === 'STS-XACML-0338' &&
          /exponential/.test(refused.why || ''),
          'D: a new policy with (a+)+ is refused STS-XACML-0338',
          JSON.stringify(refused));
  t.check(!store.read('rx2220-unsafe'), 'D: ... and nothing was written');
  const written = store.write('rx2220-safe',
                              policyWith('safe', 'a[0-9]+', '[a-z]+'));
  t.check(written.ok, 'D: a safe one is written', JSON.stringify(written));

  // A POLICY STORED BEFORE THE RULE: straight into the directory, as an
  // `ldapmodify` or a 1.1 deployment's restore would leave it.
  const directory = store.directoryInstalled();
  const legacy = policyWith('legacy', '(a+)+', '[a-z]+');
  const described = store.describe(legacy);
  directory.writePolicy('rx2220-legacy', {
    objectClass: ['top', 'xacmlPolicy'], xacmlPolicyId: described.id,
    xacmlPolicyDocument: legacy, xacmlVersion: described.version,
    xacmlKind: described.kind,
    xacmlCombiningAlgId: described.combiningAlgId,
    xacmlEnabled: 'TRUE', xacmlIsRoot: 'FALSE' });
  const row = store.read('rx2220-legacy');
  t.check(!!row && !!store.parseDocument(row.document),
          'D: a policy stored before the rule still loads');
  const toggled = store.write('rx2220-legacy', row.document,
                              { enabled: false });
  t.check(toggled.ok, 'D: an unchanged rewrite of it (disable) is accepted',
          JSON.stringify(toggled));
  const changed = store.write('rx2220-legacy',
                              policyWith('legacy', '(a+)+', '[b-z]+'));
  t.check(!changed.ok && errorCodes.codeOf(changed) === 'STS-XACML-0338',
          'D: a CHANGED document still carrying the pattern is refused',
          JSON.stringify(changed));
  ['rx2220-safe', 'rx2220-legacy'].forEach(function (name) {
    store.remove(name);
  });
  log.debug("Leaving checkStore().");
}

function run(t) {
  log.debug("Entering run().");
  checkPatternSafety(t);
  checkEvaluation(t);
  checkWalk(t);
  checkStore(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml_regexp_bound',
  describe: 'XACML: a regexp-match pattern of the exponential shape is ' +
            'refused at the save and Indeterminate at the evaluation, a ' +
            'long value is Indeterminate, and a policy stored before the ' +
            'rule still loads (#2220)',
  run: run
};
