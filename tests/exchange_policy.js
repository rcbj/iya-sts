// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/exchange_policy.js
// ===========================================================================
// WHO MAY ACT FOR WHOM, AND AS WHAT, IS THE ISSUANCE POLICY'S (#186).
//
// The built-in `role-issuance` document answers the two exchange questions an
// RFC 8693 token exchange, a WS-Trust OnBehalfOf / ActAs and a Kerberos S4U
// request ask — `choose-exchange-semantics` and `exchange-token` — from the
// facts `common/delegation_policy.ts` gathers. This file asks it directly,
// through `xacml/xacml_exchange_verdicts.js`, with facts built here, so every
// rule is held without a directory, a stack or a port:
//
//   A. the semantics, by precedence: the request, the actor's default, the
//      subject's default, delegation.defaultSemantics;
//   B. SELF — an application for itself, a client for its own token, and
//      the default audience when none was named;
//   C. DELEGATION — both chains (actor = S, actor = R), from either side of
//      the relationship (appAllowedToDelegateTo on S, appAllowedToActOn-
//      BehalfOf on R), and refused without one or with an actor outside it;
//   D. IMPERSONATION — allowed only where the actor's AND the subject's
//      semantics allow it, and only toward a target the actor may reach;
//   E. the protected subject (its own flag, a protected group), the actor's
//      subject groups and may_act standing in for them;
//   F. may_act naming somebody else — refused, ENFORCED in every mode;
//   G. a PERSON as the actor, with and without delegation.actorRole, and an
//      actor no entry backs;
//   H. the targets: exactly one, registered, and none only for self;
//   I. authority: the subject's roles against S (delegation) or R;
//   J. enforced: every other refusal in product only;
//   K. a primary policy that says nothing about exchanges is not a verdict:
//      the built-in policy answers instead;
//   L. the 14 rows of the table on #186.
// ===========================================================================

const path = require('path');

const ROOT = path.join(__dirname, '..');
const log = require('bunyan').createLogger({ name: 'exchange_policy',
  level: process.env.LOG_LEVEL || 'info' });

// A whole question, every party filled in with a plain default that the
// case then overrides: alice, a person holding `staff`, exchanged through
// `front` (S) toward `back` (R).
function question(overrides, mode) {
  log.debug("Entering question().");
  const o = overrides || {};
  const base = {
    subject: { id: 'alice', kind: 'user', roles: ['EVERYBODY', 'staff'],
               notDelegated: false, groups: [], semantics: [],
               defaultSemantics: '' },
    actor: { id: 'front', kind: 'application', registered: true,
             roles: ['EVERYBODY'], semantics: [], defaultSemantics: '',
             delegatesTo: [], subjectGroups: [] },
    source: { id: 'front', requiredRoles: ['EVERYBODY'],
              delegatesTo: ['back'] },
    target: { id: 'back', count: 1, registered: true,
              requiredRoles: ['EVERYBODY'], accepts: [] },
    requestedSemantics: '', mayActPresent: false, mayActNamesActor: false,
    protectedGroups: []
  };
  const facts = {};
  Object.keys(base).forEach(function (key) {
    const given = o[key];
    facts[key] = base[key] && typeof base[key] === 'object' &&
      !Array.isArray(base[key])
      ? Object.assign({}, base[key], given || {})
      : (given !== undefined ? given : base[key]);
  });
  log.debug("Leaving question().");
  return { facts: facts, mode: mode || 'product', protocol: 'OAuth 2.0',
           settings: { defaultSemantics: o.defaultSetting || 'delegation',
                       actorRole: 'DELEGATION_ACTOR' } };
}

async function run(t) {
  log.debug("Entering run().");
  const verdicts = require(ROOT + '/xacml/xacml_exchange_verdicts');
  const templates = require(ROOT + '/xacml/xacml_templates');
  const ask = function (overrides, mode) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return verdicts.decide(question(overrides, mode), null, {});
  };
  const show = function (answer) {
    log.debug("Entering show().");
    log.debug("Leaving show().");
    return JSON.stringify(answer);
  };

  t.log.info('=== A. the semantics, by precedence ===');
  let a = ask({ requestedSemantics: 'impersonation',
                actor: { defaultSemantics: 'delegation' } });
  t.check(a.chosen === 'impersonation', 'A1. the request\'s choice wins ' +
          'over the actor\'s default', show(a));
  a = ask({ actor: { defaultSemantics: 'impersonation' },
            subject: { defaultSemantics: 'delegation' } });
  t.check(a.chosen === 'impersonation', 'A2. else the actor\'s default ' +
          'wins over the subject\'s', show(a));
  a = ask({ subject: { defaultSemantics: 'impersonation' } });
  t.check(a.chosen === 'impersonation', 'A3. else the subject\'s default',
          show(a));
  a = ask({});
  t.check(a.chosen === 'delegation', 'A4. else delegation.defaultSemantics ' +
          '(delegation)', show(a));
  a = ask({ defaultSetting: 'impersonation' });
  t.check(a.chosen === 'impersonation', 'A5. ... and the setting is read, ' +
          'not assumed', show(a));

  t.log.info('=== B. self ===');
  a = ask({ subject: { id: 'svc', kind: 'application' },
            actor: { id: 'svc' }, source: { id: '' },
            target: { id: 'svc' } });
  t.check(a.verdict === 'allow' && a.semantics === 'self' &&
          a.audience === 'svc', 'B1. an application exchanging its own ' +
          'token is SELF, for the audience asked', show(a));
  a = ask({ actor: { id: 'front' }, target: { id: 'front' } });
  t.check(a.verdict === 'allow' && a.semantics === 'self',
          'B2. the client the subject token was issued for, asking for its ' +
          'own audience again, is SELF', show(a));
  a = ask({ target: { id: '', count: 0, registered: false } });
  t.check(a.verdict === 'allow' && a.semantics === 'self' &&
          a.audience === 'front', 'B3. a self exchange naming no target is ' +
          'for S', show(a));
  a = ask({ subject: { notDelegated: true }, target: { id: 'front' } });
  t.check(a.verdict === 'allow' && a.semantics === 'self',
          'B4. a protected subject is not refused a SELF exchange — nobody ' +
          'is acting for it', show(a));

  t.log.info('=== C. delegation ===');
  a = ask({});
  t.check(a.verdict === 'allow' && a.semantics === 'delegation' &&
          a.audience === 'back', 'C1. actor = S, S delegates to R ' +
          '(appAllowedToDelegateTo on S): allowed, for R', show(a));
  a = ask({ actor: { id: 'back' } });
  t.check(a.verdict === 'allow' && a.semantics === 'delegation',
          'C2. actor = R (S handed its token on): allowed', show(a));
  a = ask({ source: { delegatesTo: [] }, target: { accepts: ['front'] } });
  t.check(a.verdict === 'allow', 'C3. S delegates to R from R\'s side ' +
          '(appAllowedToActOnBehalfOf, resource-based): allowed', show(a));
  a = ask({ source: { delegatesTo: [] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'target',
          'C4. no relationship between S and R: refused, target', show(a));
  a = ask({ actor: { id: 'mid' } });
  t.check(a.verdict === 'refuse' && a.refusal === 'target',
          'C5. an actor that is neither S nor R, nor accepted by R: ' +
          'refused, target', show(a));
  a = ask({ actor: { id: 'mid' }, target: { accepts: ['mid'] } });
  t.check(a.verdict === 'allow', 'C5b. ... allowed once R accepts it by ' +
          'name', show(a));
  a = ask({ actor: { id: 'mid' }, target: { accepts: ['mid'] },
            source: { delegatesTo: [] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'target',
          'C5c. ... but S must still delegate to R', show(a));
  a = ask({ source: { id: '' } });
  t.check(a.verdict === 'refuse',
          'C6. S unknown: no delegation can be shown', show(a));

  t.log.info('=== D. impersonation ===');
  a = ask({ requestedSemantics: 'impersonation',
            actor: { delegatesTo: ['back'] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'semantics',
          'D1. an actor whose semantics are empty may not impersonate',
          show(a));
  a = ask({ requestedSemantics: 'impersonation',
            actor: { semantics: ['impersonation'], delegatesTo: ['back'] } });
  t.check(a.verdict === 'allow' && a.semantics === 'impersonation' &&
          a.audience === 'back', 'D2. impersonation allowed to the actor, ' +
          'toward a target on its appAllowedToDelegateTo', show(a));
  a = ask({ requestedSemantics: 'impersonation',
            actor: { id: 'back', semantics: ['impersonation'] } });
  t.check(a.verdict === 'allow' && a.semantics === 'impersonation',
          'D3. impersonation toward the actor itself (S4U2Self\'s shape)',
          show(a));
  a = ask({ requestedSemantics: 'impersonation',
            actor: { semantics: ['impersonation'] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'target',
          'D4. impersonation toward a target the actor cannot reach: ' +
          'refused, target', show(a));
  a = ask({ requestedSemantics: 'impersonation',
            actor: { semantics: ['impersonation'] },
            target: { accepts: ['front'] } });
  t.check(a.verdict === 'allow', 'D5. ... allowed when R accepts the actor',
          show(a));
  a = ask({ requestedSemantics: 'impersonation',
            subject: { semantics: ['delegation'] },
            actor: { semantics: ['impersonation'], delegatesTo: ['back'] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'semantics',
          'D6. a SUBJECT allowing delegation only may not be impersonated',
          show(a));
  a = ask({ actor: { semantics: ['impersonation'] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'semantics',
          'D7. an actor allowing impersonation ONLY may not delegate', show(a));

  t.log.info('=== E. protected subjects and subject groups ===');
  a = ask({ subject: { notDelegated: true } });
  t.check(a.verdict === 'refuse' && a.refusal === 'subject',
          'E1. a subject whose entry says NOT_DELEGATED: refused', show(a));
  a = ask({ subject: { groups: ['protected users'] },
            protectedGroups: ['protected users'] });
  t.check(a.verdict === 'refuse' && a.refusal === 'subject',
          'E2. a member of a protected group: refused', show(a));
  a = ask({ actor: { subjectGroups: ['cn=delegable,ou=groups,dc=x'] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'subject',
          'E3. a subject outside the actor\'s subject groups: refused',
          show(a));
  a = ask({ actor: { subjectGroups: ['cn=delegable,ou=groups,dc=x'] },
            subject: { groups: ['cn=delegable,ou=groups,dc=x'] } });
  t.check(a.verdict === 'allow', 'E4. ... and allowed for a member', show(a));
  a = ask({ actor: { subjectGroups: ['cn=delegable,ou=groups,dc=x'] },
            mayActPresent: true, mayActNamesActor: true });
  t.check(a.verdict === 'allow', 'E5. may_act naming the actor stands in ' +
          'for the subject groups', show(a));

  t.log.info('=== F. may_act naming somebody else ===');
  a = ask({ mayActPresent: true, mayActNamesActor: false }, 'development');
  t.check(a.verdict === 'refuse' && a.refusal === 'may-act' && a.enforced,
          'F1. refused and ENFORCED, in development too', show(a));
  a = ask({ mayActPresent: true, mayActNamesActor: true });
  t.check(a.verdict === 'allow', 'F2. may_act naming the actor is no ' +
          'refusal', show(a));

  t.log.info('=== G. the actor ===');
  a = ask({ actor: { id: 'bob', kind: 'user', roles: ['EVERYBODY'] },
            target: { id: 'front', accepts: [] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'intermediary',
          'G1. a PERSON without delegation.actorRole may not act', show(a));
  a = ask({ actor: { id: 'bob', kind: 'user',
                     roles: ['EVERYBODY', 'DELEGATION_ACTOR'] },
            target: { accepts: ['bob'] } });
  t.check(a.verdict === 'allow' && a.semantics === 'delegation',
          'G2. a PERSON holding it may, toward an R that accepts them',
          show(a));
  a = ask({ actor: { id: 'ghost', registered: false } });
  t.check(a.verdict === 'refuse' && a.refusal === 'intermediary',
          'G3. an actor no entry backs: refused', show(a));

  t.log.info('=== H. targets ===');
  a = ask({ target: { count: 2 } });
  t.check(a.verdict === 'refuse' && a.refusal === 'targets',
          'H1. two targets: refused', show(a));
  a = ask({ target: { id: 'https://nowhere', registered: false } });
  t.check(a.verdict === 'refuse' && a.refusal === 'unregistered-target',
          'H2. a target no application registers: refused', show(a));
  a = ask({ target: { id: '', count: 0, registered: false },
            actor: { id: 'mid' } });
  t.check(a.verdict === 'refuse' && a.refusal === 'no-target',
          'H3. no target, not self: refused', show(a));

  t.log.info('=== I. authority ===');
  a = ask({ source: { requiredRoles: ['payroll'] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'authority',
          'I1. delegation: the subject holds none of the roles S requires',
          show(a));
  a = ask({ source: { requiredRoles: ['staff'] } });
  t.check(a.verdict === 'allow', 'I2. ... and allowed holding one', show(a));
  a = ask({ requestedSemantics: 'impersonation',
            actor: { semantics: ['impersonation'], delegatesTo: ['back'] },
            target: { requiredRoles: ['payroll'] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'authority',
          'I3. impersonation: the subject holds none of the roles R ' +
          'requires', show(a));
  a = ask({ subject: { id: 'svc', kind: 'application', roles: [] },
            actor: { id: 'svc' }, source: { id: '' },
            target: { id: 'svc', requiredRoles: ['payroll'] } });
  t.check(a.verdict === 'refuse' && a.refusal === 'authority',
          'I4. self: authority for R is still asked', show(a));

  t.log.info('=== J. enforcement by mode ===');
  a = ask({ source: { delegatesTo: [] } }, 'development');
  t.check(a.verdict === 'refuse' && !a.enforced, 'J1. a refusal in ' +
          'development is recorded, not enforced', show(a));
  a = ask({ source: { delegatesTo: [] } }, 'product');
  t.check(a.verdict === 'refuse' && a.enforced, 'J2. ... and enforced in ' +
          'product', show(a));

  t.log.info('=== K. a policy silent on exchanges ===');
  const silent = templates.build('role-issuance', { decideExchanges: 'no' },
                                 { name: 'silent' });
  t.check(silent.ok, 'precondition: the issuance policy builds without the ' +
          'exchange rules', silent.why);
  a = verdicts.decide(question({ source: { delegatesTo: [] } }),
                      { policy: silent.policy, builtIn: false }, {});
  t.check(a.verdict === 'refuse' && a.decidedBy === 'built-in',
          'K1. a realm policy without the rules does not decide: the ' +
          'built-in policy does, and still refuses', show(a));

  t.log.info('=== L. the table on #186 ===');
  // [subject kind, actor kind, semantics, interpretation]. Every row is
  // allowed when its relationships hold (rcbj's decision on #186), user
  // actors included through delegation.actorRole.
  const ROWS = [
    ['user', 'user', 'impersonation', 'User B impersonates User A'],
    ['user', 'application', 'impersonation', 'Application impersonates User'],
    ['application', 'user', 'impersonation', 'User impersonates Application'],
    ['application', 'application', 'impersonation',
     'Application B impersonates Application A'],
    ['user', 'user', 'delegation', 'User A delegates to User B'],
    ['user', 'application', 'delegation', 'Application acts for User'],
    ['application', 'user', 'delegation', 'User acts for Application'],
    ['application', 'application', 'delegation',
     'Application A delegates to Application B']
  ];
  ROWS.forEach(function (row, i) {
    const actorIsUser = row[1] === 'user';
    const facts = {
      requestedSemantics: row[2],
      subject: row[0] === 'application'
        ? { id: 'subject-app', kind: 'application', roles: ['EVERYBODY'] }
        : {},
      actor: { id: 'actor-b', kind: actorIsUser ? 'user' : 'application',
               roles: actorIsUser ? ['EVERYBODY', 'DELEGATION_ACTOR']
                                  : ['EVERYBODY'],
               semantics: ['delegation', 'impersonation'] },
      // R accepts the actor by name, and S delegates to R: the
      // relationship every row of the table stands on.
      target: { id: 'back', accepts: ['actor-b'] },
      source: { delegatesTo: ['back'] }
    };
    const answer = ask(facts);
    t.check(answer.verdict === 'allow' && answer.semantics === row[2],
            'L' + (i + 1) + '. ' + row[3] + ' (' + row[2] + ') is allowed ' +
            'when its relationships hold', show(answer));
  });
  [['user', 'self'], ['application', 'self']].forEach(function (row, i) {
    const answer = ask(row[0] === 'application'
      ? { subject: { id: 'a', kind: 'application' }, actor: { id: 'a' },
          source: { id: '' }, target: { id: 'a' } }
      : { actor: { id: 'front' }, target: { id: 'front' } });
    t.check(answer.verdict === 'allow' && answer.semantics === 'self',
            'L' + (ROWS.length + i + 1) + '. self, ' + row[0] + ' subject',
            show(answer));
  });

  t.log.info('=== N. the third question: what may_act names ===');
  const mayAct = function (delegates, primary) {
    log.debug("Entering mayAct().");
    log.debug("Leaving mayAct().");
    return verdicts.decide({ action: 'assign-may-act',
      facts: { subject: { id: 'alice', kind: 'user', delegates: delegates } },
      mode: 'product', protocol: '', settings: {} }, primary || null, {});
  };
  a = mayAct(['urn:uuid:carol']);
  t.check(a.verdict === 'allow' && a.mayAct.join() === 'urn:uuid:carol' &&
          a.decidedBy === 'built-in', 'N1. the subject named a delegate: ' +
          'may_act names them, by the built-in rule', show(a));
  a = mayAct([]);
  t.check(a.mayAct.length === 0, 'N2. named nobody: no may_act', show(a));
  const xml = require(ROOT + '/xacml/xacml_xml');
  const denyMayAct = xml.parsePolicy(
    '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" ' +
    'PolicyId="no-may-act" Version="1.0" RuleCombiningAlgId="urn:oasis:' +
    'names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides"><Target/>' +
    '<Rule RuleId="no" Effect="Deny"><Target><AnyOf><AllOf><Match ' +
    'MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">' +
    '<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">' +
    'assign-may-act</AttributeValue><AttributeDesignator AttributeId="urn:' +
    'oasis:names:tc:xacml:1.0:action:action-id" Category="urn:oasis:names:' +
    'tc:xacml:3.0:attribute-category:action" DataType="http://www.w3.org/' +
    '2001/XMLSchema#string" MustBePresent="false"/></Match></AllOf></AnyOf>' +
    '</Target><ObligationExpressions><ObligationExpression ' +
    'ObligationId="urn:sts:xacml:obligation:may-act" FulfillOn="Deny"/>' +
    '</ObligationExpressions></Rule></Policy>');
  a = mayAct(['urn:uuid:carol'], { policy: denyMayAct, builtIn: false });
  t.check(a.mayAct.length === 0 && a.decidedBy === 'policy',
          'N3. a realm policy answering with the may_act obligation and no ' +
          'party takes the claim away', show(a));
  const bareDeny = xml.parsePolicy(
    '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" ' +
    'PolicyId="bare" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:' +
    'xacml:3.0:rule-combining-algorithm:deny-overrides"><Target/><Rule ' +
    'RuleId="no" Effect="Deny"><Target/></Rule></Policy>');
  a = mayAct(['urn:uuid:carol'], { policy: bareDeny, builtIn: false });
  t.check(a.mayAct.join() === 'urn:uuid:carol' && a.decidedBy === 'built-in',
          'N3b. a BARE Deny (a rule for every action) does not: the ' +
          'built-in answer stands', show(a));
  a = mayAct(['urn:uuid:carol'], { policy: silent.policy, builtIn: false });
  t.check(a.mayAct.join() === 'urn:uuid:carol' && a.decidedBy === 'built-in',
          'N4. one silent on it leaves the built-in answer', show(a));

  t.log.info('=== M. every combination, against an oracle ===');
  matrix(t, verdicts);
  log.debug("Leaving run().");
}

const oracleKit = require('./tools/exchange_oracle');
const POSITIONS = oracleKit.POSITIONS;
const combination = oracleKit.combination;
const oracle = oracleKit.oracle;
const product = oracleKit.product;

function matrix(t, verdicts) {
  log.debug("Entering matrix().");
  const SEMANTICS = ['', 'delegation', 'impersonation'];
  const ALLOWED = [[], ['delegation'], ['impersonation'],
                   ['delegation', 'impersonation']];
  const FIXED = { mode: 'product', subjectKind: 'user', protect: '',
                  actor: 'application', position: 'source', relation: 'to',
                  requested: '', actorDefault: '', subjectDefault: '',
                  settingDefault: 'delegation', actorAllowed: [],
                  subjectAllowed: [], reach: false, groups: '', mayAct: '',
                  sourceAuthority: true, targetAuthority: true, targets: 1 };
  // THE GROUPS OF DIMENSIONS THAT INTERACT, each enumerated in full.
  const GROUPS = [
    { name: 'the semantics, by precedence',
      dims: { requested: SEMANTICS, actorDefault: SEMANTICS,
              subjectDefault: SEMANTICS,
              settingDefault: ['delegation', 'impersonation'],
              actorAllowed: ALLOWED, subjectAllowed: ALLOWED.slice(0, 3),
              mode: ['development', 'product'] } },
    { name: 'the shape of the act',
      dims: { mode: ['development', 'product'],
              subjectKind: ['user', 'application'],
              actor: ['application', 'user-role', 'user', 'unknown'],
              position: POSITIONS, relation: ['to', 'accepts', ''],
              requested: ['delegation', 'impersonation'],
              actorAllowed: ALLOWED, reach: [false, true],
              targets: [0, 1, 'unregistered', 2] } },
    { name: 'the gates on the subject',
      dims: { mode: ['development', 'product'],
              protect: ['', 'flag', 'group'],
              groups: ['', 'member', 'outsider'],
              mayAct: ['', 'names', 'other'],
              sourceAuthority: [false, true], targetAuthority: [false, true],
              requested: ['delegation', 'impersonation'],
              actorAllowed: [['delegation', 'impersonation']],
              reach: [true], position: POSITIONS,
              targets: [0, 1] } }
  ];
  let total = 0;
  GROUPS.forEach(function (group) {
    let count = 0;
    let wrong = 0;
    let firstWrong = '';
    const outcomes = {};
    const started = Date.now();
    product(group.dims, FIXED, function (c) {
      const facts = combination(c);
      const expected = oracle(c, facts);
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
    total += count;
    t.check(wrong === 0, 'M. ' + group.name + ': the policy agrees with ' +
            'the oracle on all ' + count + ' combinations (' +
            JSON.stringify(outcomes) + ', ' + (Date.now() - started) +
            ' ms)', wrong + ' disagree; the first: ' + firstWrong);
    // Positive AND negative outcomes are both present, or the group tests
    // only one side.
    const keys = Object.keys(outcomes);
    t.check(keys.some(function (k) { return /^allow/.test(k); }) &&
            keys.some(function (k) { return /^refuse/.test(k); }),
            'M. ' + group.name + ': both allowed and refused outcomes are ' +
            'reached', keys.join(', '));
  });
  t.log.info('M. ' + total + ' combinations in all.');
  log.debug("Leaving matrix().");
}

module.exports = {
  name: 'exchange_policy',
  describe: 'who may act for whom, and as what, at a token exchange, ' +
            'WS-Trust and Kerberos S4U: the built-in issuance policy\'s ' +
            'exchange rules as a truth table (#186)',
  run: run
};
