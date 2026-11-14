// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/uma_templates.js
//
// ---------------------------------------------------------------------------
// THE TWO USER-MANAGED ACCESS TEMPLATES THROUGH THE REAL ENGINE (#1168
// phase 1, #1190): `uma-authorization`, the realm's layer, and
// `uma-owner-default`, the resource owner's starting document — each built,
// written as XML, parsed back (which validates it) and evaluated with
// `xacml_pdp.js` against requests `uma()` builds.
//
//   A. the realm policy: a known stranger permits, the owner permits, each
//      gate denies, and NOBODY KNOWN IS AN INDETERMINATE OVER A MISSING
//      subject-id OF THE ACCESS-SUBJECT CATEGORY — what need_info is built
//      from — while a gate's Deny wins over it
//   B. the owner document: the owner permits, a stranger is DENIED (not
//      NotApplicable: deny-unless-permit), its PolicyId names the owner,
//      and the scope is the action-id there
//   C. the catalogue lists both and the attribute vocabulary is what the
//      PEP will read
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'uma_templates',
  level: process.env.LOG_LEVEL || 'info' });

const templates = require('../xacml/xacml_templates');
const xml = require('../xacml/xacml_xml');
const pdp = require('../xacml/xacml_pdp');
const model = require('../xacml/xacml_model');
const xacmlRequest = require('../xacml/xacml_request');
const V = xacmlRequest.VOCABULARY;

function facts(over) {
  log.debug("Entering facts().");
  log.debug("Leaving facts().");
  return Object.assign({
    realm: 'acme', layer: 'realm', stage: 'assess', scope: 'read',
    resource: { id: 'res-1', type: 'photo', resourceServer: 'photos-rs',
                resourceServerDeclared: true, owner: 'urn:uuid:owner',
                ownerKind: 'user' },
    requestingParty: { id: 'urn:uuid:bob', kind: 'user', known: true,
                       isOwner: false, claimSource: 'session',
                       claimIssuerDeclared: true },
    clientId: 'viewer', clientGrantDeclared: true
  }, over || {});
}

function ask(policy, over) {
  log.debug("Entering ask().");
  const request = new xacmlRequest.AuthorizationRequest({})
    .uma(facts(over)).build();
  log.debug("Leaving ask().");
  return pdp.evaluate(policy, request, { repository: null, resolver: null });
}

function parsed(id, answers) {
  log.debug("Entering parsed().");
  const built = templates.build(id, answers || {}, { name: id });
  if (!built.ok) {
    throw new Error(built.why);
  }
  const document = xml.writePolicy(built.policy);
  log.debug("Leaving parsed().");
  return { document: document, policy: xml.parsePolicy(document) };
}

function theRealmPolicy(t) {
  log.debug("Entering theRealmPolicy().");
  t.log.info('=== A. uma-authorization ===');
  const made = parsed('uma-authorization');
  const policy = made.policy;
  t.check(policy.kind === 'Policy' &&
          policy.combiningAlgId === model.RULE_ALG.DENY_OVERRIDES &&
          policy.rules.length === 6,
          'A1. a Policy under deny-overrides with six rules, written and ' +
          'parsed back', policy.combiningAlgId);
  t.equal(ask(policy, {}).decision, model.DECISION.PERMIT,
          'A2. a known requesting party who is not the owner is permitted ' +
          'at the realm\'s layer: the owner\'s document decides next');
  t.equal(ask(policy, { requestingParty: { id: 'urn:uuid:owner',
                                           known: true, isOwner: true } })
            .decision, model.DECISION.PERMIT,
          'A3. the owner is permitted');
  const nobody = ask(policy, { requestingParty: { known: false } });
  t.check(nobody.decision === model.DECISION.INDETERMINATE &&
          nobody.status && nobody.status.code === model.STATUS.MISSING_ATTRIBUTE &&
          nobody.status.detail &&
          nobody.status.detail.attributeId === model.ATTRIBUTE.SUBJECT_ID &&
          nobody.status.detail.category === model.CATEGORY.ACCESS_SUBJECT,
          'A4. NOBODY KNOWN is Indeterminate over the missing subject-id of ' +
          'the access-subject category, which is what need_info is built ' +
          'from', JSON.stringify(nobody.status));
  t.equal(ask(policy, { clientGrantDeclared: false }).decision,
          model.DECISION.DENY,
          'A5. a client that did not register the UMA grant type is denied');
  t.equal(ask(policy, { resource: { id: 'res-1', owner: 'urn:uuid:owner',
                                    resourceServerDeclared: false } })
            .decision, model.DECISION.DENY,
          'A6. a resource server not declared for uma is denied');
  t.equal(ask(policy, { requestingParty: { id: 'urn:uuid:bob', known: true,
                                           claimSource: 'claim_token',
                                           claimIssuer: 'https://other',
                                           claimIssuerDeclared: false } })
            .decision, model.DECISION.DENY,
          'A7. a pushed claim token from an undeclared issuer is denied');
  t.equal(ask(policy, { clientGrantDeclared: false,
                        requestingParty: { known: false } }).decision,
          model.DECISION.DENY,
          'A8. a gate\'s Deny wins over nobody being known: the protocol ' +
          'gates are answered before claims are asked for');
  t.equal(ask(policy, { requestingParty: { id: 'urn:uuid:owner', known: true,
                                           isOwner: true },
                        clientGrantDeclared: false }).decision,
          model.DECISION.DENY,
          'A9. and over the owner: deny-overrides');
  const other = pdp.evaluate(policy, new xacmlRequest.AuthorizationRequest({})
    .principal('alice', 'user').requestedAction('read').target('res-1')
    .protocol('oauth2').build(), { repository: null, resolver: null });
  t.equal(other.decision, model.DECISION.NOT_APPLICABLE,
          'A10. a question that is not UMA\'s does not match its Target');
  log.debug("Leaving theRealmPolicy().");
}

function theOwnerDocument(t) {
  log.debug("Entering theOwnerDocument().");
  t.log.info('=== B. uma-owner-default ===');
  const made = parsed('uma-owner-default', { owner: 'urn:uuid:owner' });
  const policy = made.policy;
  t.check(policy.kind === 'Policy' &&
          policy.combiningAlgId === model.RULE_ALG.DENY_UNLESS_PERMIT &&
          policy.rules.length === 1 &&
          policy.rules[0].id === templates.UMA_ATTRIBUTE.OWNER_SELF_RULE,
          'B1. a Policy under deny-unless-permit with the one owner-self ' +
          'rule', JSON.stringify(policy.rules.map(function (r) {
            return r.id;
          })));
  t.equal(policy.id, templates.umaOwnerPolicyId('urn:uuid:owner'),
          'B2. its PolicyId is derived from the owner\'s key');
  t.check(templates.umaOwnerPolicyId('urn:uuid:a b') ===
            'urn:sts:xacml:uma-owner:urn%3Auuid%3Aa%20b' &&
          templates.umaOwnerPolicyId('app!') !==
            templates.umaOwnerPolicyId('app*'),
          'B3. percent-encoded as the FGA PolicyId is, and unambiguous');
  t.equal(ask(policy, { layer: 'owner',
                        requestingParty: { id: 'urn:uuid:owner', known: true,
                                           isOwner: true } }).decision,
          model.DECISION.PERMIT, 'B4. the owner reaches their own resource');
  t.equal(ask(policy, { layer: 'owner' }).decision, model.DECISION.DENY,
          'B5. a stranger is DENIED, not NotApplicable: the document ' +
          'shares nothing until a share rule is added');
  const request = new xacmlRequest.AuthorizationRequest({})
    .uma(facts({ layer: 'owner', scope: 'write' })).build();
  const action = request.categories.filter(function (one) {
    return one.category === model.CATEGORY.ACTION;
  })[0].attributes.filter(function (one) {
    return one.attributeId === model.ATTRIBUTE.ACTION_ID;
  })[0];
  t.equal(action.values[0].lexical, 'write',
          'B6. on the owner\'s layer the action-id is the scope, which is ' +
          'what a share rule targets');
  log.debug("Leaving theOwnerDocument().");
}

function theCatalogue(t) {
  log.debug("Entering theCatalogue().");
  t.log.info('=== C. the catalogue and the vocabulary ===');
  const ids = templates.catalogue().map(function (one) {
    return one.id;
  });
  t.check(ids.indexOf('uma-authorization') >= 0 &&
          ids.indexOf('uma-owner-default') >= 0,
          'C1. both templates are in the catalogue the console lists',
          ids.join(', '));
  const U = templates.UMA_ATTRIBUTE;
  t.check(U.ACTION === xacmlRequest.UMA_PERMISSION_ACTION &&
          U.FGA_ACTION === xacmlRequest.UMA_FGA_ACTION &&
          U.APPROVAL_OBLIGATION === 'urn:sts:xacml:obligation:uma-approval' &&
          U.REALM_TEMPLATE === 'uma-authorization' &&
          U.OWNER_TEMPLATE === 'uma-owner-default',
          'C2. the templates\' vocabulary is the request builder\'s');
  const owner = templates.build('uma-owner-default', {}, { name: 'x' });
  t.check(owner.ok && owner.policy.id.indexOf('urn:sts:xacml:uma-owner:') === 0,
          'C3. built with no answers, the owner template still builds');
  log.debug("Leaving theCatalogue().");
}

async function run(t) {
  log.debug("Entering run().");
  theRealmPolicy(t);
  theOwnerDocument(t);
  theCatalogue(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'uma_templates',
  describe: 'the two User-Managed Access templates through the real engine ' +
            '(#1168 phase 1): the realm\'s gates, nobody known as a missing ' +
            'subject-id, the owner\'s document denying strangers',
  run: run
};
