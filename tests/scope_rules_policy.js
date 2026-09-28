// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: scope_rules_policy.js
//
// ===========================================================================
// THE SCOPE RULES ARE POLICY (#305, part D of #88, 2026-09-27).
//
// The #110 scope rules, delegated permissions, consent and the two RFC 9396
// type questions used to be code. They are rules of the issuance policy now,
// and code gathers the facts. The existing tests (scope_policy.js, the RAR and
// consent tests) hold that the BEHAVIOUR did not move; this file holds that
// the DECISION did — that each outcome follows the realm's policy document:
//
//   A. SCOPE POLICY. The built-in refuses a protected scope the client does
//      not declare (STS-OAUTH-0577) at `request` and drops it at `mint`; an
//      operator's document refusing `email` for everybody makes
//      `scopePolicy.refusal()` refuse it, with the operator's code.
//   B. MODE IS A FACT. The undeclared-scope rule reads the mode attribute:
//      the same client's undeclared scope is kept in development and refused
//      in product.
//   C. DELEGATED PERMISSIONS. An ungranted permission is refused in product
//      (STS-OAUTH-0155) — and an operator's document without the rule lets
//      it through.
//   D. CONSENT. A scope nobody agreed to is outstanding; an operator's
//      document without the consent rule needs no consent for anything.
//   E. RFC 9396. A detail of a type the client did not register is refused
//      (STS-OAUTH-0454) by the policy.
//   F. NO DECIDER. With the gate's decider removed, the built-in policy
//      still decides (the gate loads it itself).
//
// IN A THROWAWAY REALM: an operator's document is written to that realm's
// ou=policies and nowhere else.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const config = require('../common/config');
const applications = require('../common/applications');
require('../ldap/ldap_server');
const gate = require('../common/issuance_gate');
const scopePolicy = require('../common/scope_policy');
const consent = require('../common/consent');
const oauth2 = require('../oauth-oidc/oauth2');
const authorizationDetails = require('../oauth-oidc/authorization_details');
const xacmlStore = require('../xacml/xacml_store');
const xml = require('../xacml/xacml_xml');
const templates = require('../xacml/xacml_templates');
const model = require('../xacml/xacml_model');
const deciderBefore = gate.deciderInstalled();
const rolePep = require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'scope_rules_policy',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const CLIENT = 'srp-client-' + RUN;
const RESOURCE = 'srp-api-' + RUN;
const BASE = 'https://srp-api-' + RUN + '.example/';
const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';

async function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return await fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

// The built-in document, with some rules taken out and some put in first.
function operatorPolicy(without, extra) {
  log.debug("Entering operatorPolicy().");
  const built = templates.build('role-issuance', {},
                                { name: rolePep.issuancePolicyName() });
  built.policy.rules = (extra || []).concat(
    built.policy.rules.filter(function (rule) {
      return (without || []).every(function (suffix) {
        return !rule.id.endsWith(':rule:' + suffix);
      });
    }));
  const written = xacmlStore.write(rolePep.issuancePolicyName(),
                                   xml.writePolicy(built.policy),
                                   { enabled: true });
  log.debug("Leaving operatorPolicy().");
  return written;
}

function removeOperatorPolicy() {
  log.debug("Entering removeOperatorPolicy().");
  xacmlStore.remove(rolePep.issuancePolicyName());
  log.debug("Leaving removeOperatorPolicy().");
}

// An operator's rule refusing one scope for everybody, at the request stage.
function refuseEverywhere(scope, code) {
  log.debug("Entering refuseEverywhere().");
  const B = templates.PolicyBuilders;
  const S = templates.SCOPE_ATTRIBUTE;
  log.debug("Leaving refuseEverywhere().");
  return {
    id: 'urn:srp:rule:refuse-' + scope,
    effect: model.EFFECT.DENY,
    description: 'An operator refuses ' + scope + '.',
    target: B.targetOf([
      [B.match(F1 + 'string-equal', B.value(model.TYPE.STRING, S.ACTION),
               B.designator(model.CATEGORY.ACTION, model.ATTRIBUTE.ACTION_ID,
                            model.TYPE.STRING))],
      [B.match(F1 + 'string-equal', B.value(model.TYPE.STRING, scope),
               B.designator(model.CATEGORY.RESOURCE,
                            model.ATTRIBUTE.RESOURCE_ID,
                            model.TYPE.STRING))]]),
    condition: null,
    obligations: [{ id: S.OBLIGATION, on: model.EFFECT.DENY, assignments: [
      { attributeId: S.VERDICT, category: null, issuer: null,
        expression: B.value(model.TYPE.STRING, 'refuse') },
      { attributeId: S.CODE, category: null, issuer: null,
        expression: B.value(model.TYPE.STRING, code) }] }],
    advice: []
  };
}

function setUp(t) {
  log.debug("Entering setUp().");
  const made = [
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT,
                oauthAllowedScope: ['openid', 'email'] } }),
    applications.createApplication({ identifier: RESOURCE,
      protocols: ['oauth2'],
      fields: { oauthClientId: RESOURCE, oauthPermissionBaseUri: BASE,
                oauthPermission: ['read'] } })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the client and the resource were created',
          JSON.stringify(made));
  log.debug("Leaving setUp().");
}

async function scopePolicyRules(t) {
  log.debug("Entering scopePolicyRules().");
  t.log.info('=== A. scope policy ===');
  const refused = scopePolicy.refusal('openid admin:write', CLIENT);
  t.check(!!refused && refused.code === 'STS-OAUTH-0577',
          'A1. a protected scope the client does not declare is refused ' +
          '(STS-OAUTH-0577) — by the built-in rule', JSON.stringify(refused));
  t.equal(scopePolicy.narrow('openid admin:write', CLIENT,
                             { grant: 'refresh_token' }), 'openid',
          'A2. and dropped at the backstop');
  t.check(!scopePolicy.refusal('openid email', CLIENT),
          'precondition: email is issued to this client');
  t.check(operatorPolicy([], [refuseEverywhere('email', 'STS-OAUTH-0578')])
            .ok, 'precondition: an operator refuses email');
  const operated = scopePolicy.refusal('openid email', CLIENT);
  t.check(!!operated && operated.code === 'STS-OAUTH-0578' &&
          (operated.scopes || []).indexOf('email') >= 0,
          'A3. the operator\'s rule refuses it: the document decided',
          JSON.stringify(operated));
  removeOperatorPolicy();
  log.debug("Leaving scopePolicyRules().");
}

async function modeIsAFact(t) {
  log.debug("Entering modeIsAFact().");
  t.log.info('=== B. the mode is a fact ===');
  t.check(!scopePolicy.refusal('openid custom-' + RUN, CLIENT),
          'B1. in development an undeclared ordinary scope is kept');
  await withSettings({ 'global.mode': 'product' }, async function () {
    const refused = scopePolicy.refusal('openid custom-' + RUN, CLIENT);
    t.check(!!refused && refused.code === 'STS-OAUTH-0578',
            'B2. in product the same request is refused (STS-OAUTH-0578)',
            JSON.stringify(refused));
  });
  log.debug("Leaving modeIsAFact().");
}

async function delegatedPermissions(t) {
  log.debug("Entering delegatedPermissions().");
  t.log.info('=== C. delegated permissions ===');
  const asked = 'openid ' + BASE + 'read';
  t.equal(oauth2.permissionRefusal(asked, CLIENT), '',
          'C1. development, setting off: honoured');
  await withSettings({ 'global.mode': 'product' }, async function () {
    t.check(/has not been granted/.test(oauth2.permissionRefusal(asked,
                                                                 CLIENT)),
            'C2. product: an ungranted permission is refused');
    t.check(operatorPolicy(['permission-not-granted']).ok,
            'precondition: an operator\'s document without the rule');
    t.equal(oauth2.permissionRefusal(asked, CLIENT), '',
            'C3. without the rule it is honoured even in product: the ' +
            'document decided');
    removeOperatorPolicy();
  });
  log.debug("Leaving delegatedPermissions().");
}

function consentRules(t) {
  log.debug("Entering consentRules().");
  t.log.info('=== D. consent ===');
  const who = 'srp-person-' + RUN;
  const before = consent.outstanding({ username: who, clientId: CLIENT,
                                       scope: 'openid email' });
  t.equal(before.names.join(' '), 'openid email',
          'D1. two scopes nobody agreed to are both outstanding');
  t.check(operatorPolicy(['consent-outstanding']).ok,
          'precondition: an operator\'s document without the consent rule');
  const after = consent.outstanding({ username: who, clientId: CLIENT,
                                      scope: 'openid email' });
  t.equal(after.names.join(' '), '',
          'D2. without the rule nothing needs consent: the document decided');
  removeOperatorPolicy();
  log.debug("Leaving consentRules().");
}

function authorizationDetailTypes(t) {
  log.debug("Entering authorizationDetailTypes().");
  t.log.info('=== E. RFC 9396 types ===');
  const answer = authorizationDetails.parse(
    JSON.stringify([{ type: 'openid_credential' }]),
    { clientTypes: ['payment_initiation'], clientId: CLIENT });
  t.check(!answer.ok && /registered/.test(String(answer.error || '')),
          'E1. a detail of a type the client did not register is refused ' +
          'by the policy (STS-OAUTH-0454)', JSON.stringify(answer));
  log.debug("Leaving authorizationDetailTypes().");
}

function noDecider(t) {
  log.debug("Entering noDecider().");
  t.log.info('=== F. no decider ===');
  const installed = gate.deciderInstalled();
  gate.setDecider(null);
  try {
    const refused = scopePolicy.refusal('openid admin:write', CLIENT);
    t.check(!!refused && refused.code === 'STS-OAUTH-0577',
            'F1. with no decider the gate evaluates the built-in policy, and ' +
            'the protected scope is still refused', JSON.stringify(refused));
  } finally {
    gate.setDecider(installed);
  }
  log.debug("Leaving noDecider().");
}

async function run(t) {
  log.debug("Entering run().");
  const realm = realms.create({ id: 'srp-' + RUN,
                                name: 'scope rules policy ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      setUp(t);
      await scopePolicyRules(t);
      await modeIsAFact(t);
      await delegatedPermissions(t);
      consentRules(t);
      authorizationDetailTypes(t);
      noDecider(t);
    });
  } finally {
    gate.setDecider(deciderBefore);
    // THE THROWAWAY REALM GOES WITH THE FILE — `role_permissions.js` says
    // why: one directory, one entry cap, every file in the process.
    realms.remove(realm.id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scope_rules_policy',
  describe: 'the #110 scope rules, delegated permissions, consent and the ' +
            'RFC 9396 type checks are issuance-policy rules (#305)',
  run: run
};
