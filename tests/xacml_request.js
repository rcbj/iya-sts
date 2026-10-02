// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_request.js
//
// ===========================================================================
// ONE AUTHORIZATION REQUEST BUILDER FOR EVERY PEP (#306, part E of #88,
// 2026-09-27).
//
// Claims:
//
//   A. THE BUILDER. The fields of #88 section 7 land in their categories with
//      the vocabulary's spelling; `includeInResult`, `dropEmpty` and
//      `returnPolicyIdList` do what they say; a named empty category is sent.
//   B. ONE SPELLING. The templates' ROLE and SUBJECT_KIND are the builder's.
//   C. EVERY PEP BUILDS THROUGH IT, AND NOTHING ELSE BUILDS ONE. No module in
//      `xacml/` or the remote PEP but the builder (and the engine's own JSON
//      and XML readers) writes `combinedDecision: false` — a source check,
//      read by statement, so a PEP that went back to building its own is a
//      failure here rather than a drift found later.
//   D. THE REQUESTS ARE THE ONES THE PEPS SENT BEFORE — the issuance PEP's
//      categories and attributes, the access PEP's dropped empties, the risk
//      and signal PEPs' includeInResult false and no policy-id list.
//   E. THE REMOTE PEP LOADS IT: it is in `engine.js`'s MODULES and has a
//      COPY line in the Dockerfile.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const model = require('../xacml/xacml_model');
const xacmlRequest = require('../xacml/xacml_request');
const templates = require('../xacml/xacml_templates');

const log = require('bunyan').createLogger({ name: 'xacml_request',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const V = xacmlRequest.VOCABULARY;

function categoryOf(request, id) {
  log.debug("Entering categoryOf().");
  log.debug("Leaving categoryOf().");
  return request.categories.filter(function (one) {
    return one.category === id;
  })[0] || null;
}

function valuesOf(request, categoryId, attributeId) {
  log.debug("Entering valuesOf().");
  const category = categoryOf(request, categoryId);
  const found = category ? category.attributes.filter(function (one) {
    return one.attributeId === attributeId;
  })[0] : null;
  log.debug("Leaving valuesOf().");
  return found ? found.values.map(function (v) { return v.lexical; }) : null;
}

function theBuilder(t) {
  log.debug("Entering theBuilder().");
  t.log.info('=== A. the builder ===');
  const built = new xacmlRequest.AuthorizationRequest()
    .principal('alice', 'application')
    .roles(['staff'])
    .client('portal')
    .target('payroll')
    .audience(['https://payroll.example/'])
    .requestedAction('issue-access-token')
    .requestedScopes(['openid', 'payroll:read'])
    .protocol('OAuth 2.0')
    .grantType('client_credentials')
    .intermediary('broker')
    .build();
  t.equal(valuesOf(built, model.CATEGORY.ACCESS_SUBJECT,
                   model.ATTRIBUTE.SUBJECT_ID).join(), 'alice',
          'A1. principal is the access-subject subject-id');
  t.equal(valuesOf(built, model.CATEGORY.ACCESS_SUBJECT,
                   V.SUBJECT_KIND).join(), 'application',
          'A2. principal_type is subject-kind');
  t.equal(valuesOf(built, model.CATEGORY.ACCESS_SUBJECT, V.ROLE).join(),
          'staff', 'A3. roles are on the subject');
  t.equal(valuesOf(built, model.CATEGORY.RESOURCE,
                   model.ATTRIBUTE.RESOURCE_ID).join(), 'payroll',
          'A4. target is the resource-id');
  t.equal(valuesOf(built, model.CATEGORY.ACTION, V.REQUESTED_SCOPE).join(),
          'openid,payroll:read', 'A5. requested scopes are one bag');
  t.equal(valuesOf(built, model.CATEGORY.ENVIRONMENT, V.GRANT_TYPE).join(),
          'client_credentials', 'A6. the grant type is environment');
  t.equal(valuesOf(built, model.CATEGORY.INTERMEDIARY_SUBJECT,
                   model.ATTRIBUTE.SUBJECT_ID).join(), 'broker',
          'A7. the intermediary is its own category');
  const odd = new xacmlRequest.AuthorizationRequest()
    .principal('bob', 'robot').build();
  t.equal(valuesOf(odd, model.CATEGORY.ACCESS_SUBJECT, V.SUBJECT_KIND)
            .join(), 'user', 'A8. an unknown principal type is a person');
  const dropped = new xacmlRequest.AuthorizationRequest({
    includeInResult: false, dropEmpty: true, returnPolicyIdList: false })
    .resource('owner', ['']);
  dropped.category(model.CATEGORY.ENVIRONMENT);
  const shape = dropped.build();
  t.check(shape.returnPolicyIdList === false &&
          categoryOf(shape, model.CATEGORY.RESOURCE).attributes[0]
            .values.length === 0 &&
          categoryOf(shape, model.CATEGORY.RESOURCE).attributes[0]
            .includeInResult === false &&
          categoryOf(shape, model.CATEGORY.ENVIRONMENT).attributes.length ===
            0,
          'A9. dropEmpty, includeInResult, returnPolicyIdList and a named ' +
          'empty category', JSON.stringify(shape));
  log.debug("Leaving theBuilder().");
}

function oneSpelling(t) {
  log.debug("Entering oneSpelling().");
  t.log.info('=== B. one spelling ===');
  t.check(templates.ISSUANCE_ATTRIBUTE.ROLE === V.ROLE &&
          templates.ISSUANCE_ATTRIBUTE.SUBJECT_KIND === V.SUBJECT_KIND,
          'B1. the templates spell ROLE and SUBJECT_KIND as the builder does');
  log.debug("Leaving oneSpelling().");
}

// Every statement in a file, joined over line breaks, so a check reads a
// statement rather than a line (the root CLAUDE.md's rule for source tests).
function statementsOf(file) {
  log.debug("Entering statementsOf().");
  const text = fs.readFileSync(path.join(ROOT, file), 'utf8')
    .split('\n').filter(function (line) {
      return !/^\s*\/\//.test(line);
    }).join(' ').replace(/\s+/g, ' ');
  log.debug("Leaving statementsOf().");
  return text;
}

function nobodyElseBuilds(t) {
  log.debug("Entering nobodyElseBuilds().");
  t.log.info('=== C. every PEP builds through it ===');
  const allowed = ['xacml/xacml_request.js', 'xacml/xacml_json.js',
                   'xacml/xacml_xml.js'];
  const files = fs.readdirSync(path.join(ROOT, 'xacml'))
    .filter(function (one) { return /\.(js|ts)$/.test(one); })
    .map(function (one) { return 'xacml/' + one; })
    .concat(['xacml-pep/pep.js', 'xacml-pep/pip.js']);
  const building = files.filter(function (file) {
    return allowed.indexOf(file) < 0 &&
           /combinedDecision\s*:\s*false/.test(statementsOf(file));
  });
  t.equal(building.join(', '), '',
          'C1. no module but the builder writes a request of its own');
  ['xacml/xacml_role_pep.ts', 'xacml/xacml_access_pep.ts',
   'xacml/xacml_risk_pep.ts', 'xacml/xacml_signal_pep.ts', 'xacml/xacml.ts',
   'xacml/xacml_admin.ts', 'xacml-pep/pep.js'].forEach(function (file) {
    t.check(/AuthorizationRequest/.test(statementsOf(file)),
            'C2. ' + file + ' builds through AuthorizationRequest');
  });
  log.debug("Leaving nobodyElseBuilds().");
}

function samePepRequests(t) {
  log.debug("Entering samePepRequests().");
  t.log.info('=== D. the requests are the ones the PEPs sent ===');
  const rolePep = require('../xacml/xacml_role_pep');
  const issuance = rolePep.buildRequest({
    application: 'app-1', kind: 'issue-access-token',
    subject: { kind: 'user', name: 'alice', authenticated: true }
  }, ['staff'], ['from-token'], ['staff']);
  t.check(issuance.returnPolicyIdList === true &&
          valuesOf(issuance, model.CATEGORY.ACCESS_SUBJECT,
                   model.ATTRIBUTE.SUBJECT_ID).join() === 'alice' &&
          valuesOf(issuance, model.CATEGORY.ACCESS_SUBJECT,
                   templates.ISSUANCE_ATTRIBUTE.TOKEN_ROLE).join() ===
            'from-token' &&
          valuesOf(issuance, model.CATEGORY.RESOURCE,
                   templates.ISSUANCE_ATTRIBUTE.REQUIRED_ROLE).join() ===
            'staff' &&
          valuesOf(issuance, model.CATEGORY.ACTION,
                   model.ATTRIBUTE.ACTION_ID).join() ===
            'issue-access-token' &&
          !!categoryOf(issuance, model.CATEGORY.ENVIRONMENT),
          'D1. the issuance PEP: subject, roles, token roles, the ' +
          'application and its requirement, the kind, an environment',
          JSON.stringify(issuance));
  const accessPep = require('../xacml/xacml_access_pep');
  const access = accessPep.buildRequest({
    resource: 'admin-console', action: 'read',
    subject: { name: 'alice', authenticated: true } }, ['ADMIN_READ'],
    ['ADMIN_READ']);
  t.check(valuesOf(access, model.CATEGORY.RESOURCE,
                   templates.ISSUANCE_ATTRIBUTE.OWNER).length === 0,
          'D2. the access PEP still sends no owner rather than an owner ' +
          'called \'\'', JSON.stringify(access));
  const riskPep = require('../xacml/xacml_risk_pep');
  const risk = riskPep.buildRequest({ username: 'alice', level: 'high',
                                      signals: ['tor'] }, 'notify');
  const signalPep = require('../xacml/xacml_signal_pep');
  const signal = signalPep.buildRequest({ event: 'x', family: 'caep' },
                                        'notify');
  t.check(risk.returnPolicyIdList === false &&
          signal.returnPolicyIdList === false &&
          categoryOf(risk, model.CATEGORY.ENVIRONMENT).attributes
            .every(function (one) { return one.includeInResult === false; }) &&
          !categoryOf(signal, model.CATEGORY.ACCESS_SUBJECT),
          'D3. the reaction PEPs: no policy-id list, nothing asked back, and ' +
          'the signal PEP names no subject',
          JSON.stringify([risk, signal]));
  log.debug("Leaving samePepRequests().");
}

function theRemotePep(t) {
  log.debug("Entering theRemotePep().");
  t.log.info('=== E. the remote PEP loads it ===');
  const engine = fs.readFileSync(path.join(ROOT, 'xacml-pep/engine.js'),
                                 'utf8');
  const docker = fs.readFileSync(path.join(ROOT, 'xacml-pep/Dockerfile'),
                                 'utf8');
  t.check(/'xacml_request\.js'/.test(engine) &&
          /COPY xacml\/xacml_request\.js \.\/xacml\//.test(docker),
          'E1. it is in engine.js\'s MODULES and has a COPY line');
  log.debug("Leaving theRemotePep().");
}

async function run(t) {
  log.debug("Entering run().");
  theBuilder(t);
  oneSpelling(t);
  nobodyElseBuilds(t);
  samePepRequests(t);
  theRemotePep(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml_request',
  describe: 'one authorization request builder for every PEP (#306)',
  run: run
};
