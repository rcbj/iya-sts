'use strict';
//
// File: delegation_policy.js
//
// ===========================================================================
// WHO MAY ACT FOR WHOM AT WS-TRUST AND THE TOKEN EXCHANGE (#108, 2026-09-23).
//
// `common/delegation_policy.ts`'s `decide()` as a truth table, in BOTH modes
// — the answer is the same and only `enforced` differs, which is the whole
// of development's "would have been refused":
//
//   A. DELEGATION by an intermediary whose appAllowedToDelegateTo names the
//      target, by identifier and by a registered audience; the row names the
//      attribute and the subject group that allowed it.
//   B. IMPERSONATION needs appTrustedToImpersonate; without it, refused.
//   C. THE SUBJECT: outside the intermediary's appDelegationSubjectGroup,
//      carrying stsNotDelegated, or a member of the console roster — each
//      refused, the last two whoever asks.
//   D. THE TARGET: an unregistered one, and none at all; the resource-based
//      attribute (appAllowedToActOnBehalfOf on the target) allowing a pair.
//   E. THE INTERMEDIARY must be an application entry.
//   F. `may_act` honoured stands in for the flag and the groups, never for the
//      target; a self-exchange needs nothing.
//   G. THE DENY-ONLY XACML LAYER: an issuance policy denying action-id
//      `delegate` refuses an act the attributes allowed; one saying nothing
//      about it changes nothing.
//   H. THE PERSON'S HALF: stsMayAct resolved to the may_act claim (a person's
//      urn:uuid, an application's client_id), refused when it names nobody or
//      the person themselves; mayActNames() compares sub and iss.
//   I. THE ATTRIBUTES' GRAMMAR (STS-REG-0194), and list() as a register.
//   J. WS-TRUST, through `handleRst()`: ActAs allowed, OnBehalfOf refused
//      without appTrustedToImpersonate and allowed with it, a PERSON
//      requester refused (STS-WSTRUST-0019), a protected subject refused
//      (0018) — each refusal a SOAP Fault carrying WS-Trust 1.4 section 11's
//      `wst:RequestFailed`, as SOAP 1.2's Subcode and SOAP 1.1's faultcode —
//      and development issuing with the act saying it would have been
//      refused.
//   K. THE CONSOLE'S DOOR: `usersAction()` as /admin/users posts it —
//      set-not-delegated and set-may-act, a refusal coded — and the paged
//      view /admin/delegation and GET /admin-api/delegation/policy share.
//
// IN PROCESS, because it is a truth table over two modes and a directory; the
// HTTP half — the refusals at /sts and /oauth2/token and the console and API
// doors — is `tests/token_exchange_product.js` and the local job
// `tests/vendored/sts_delegation_policy.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const policy = require('../common/delegation_policy');
const store = require('../xacml/xacml_store');
// Arms `issuance_gate.js`'s decider, which is what the XACML layer asks.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'delegation_policy',
  level: process.env.LOG_LEVEL || 'info' });

const STAFF = 'dp-staff';
const AUDIENCE = 'https://dp-back.example';

// The deny-only layer's fixture: Deny `delegate` when the intermediary is
// `dp-mid`, and say nothing about anything else.
const DENY_POLICY =
  '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" ' +
  'PolicyId="dp-deny-delegate" Version="1.0" RuleCombiningAlgId="' +
  'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">' +
  '<Target/><Rule RuleId="deny-dp-mid" Effect="Deny"><Target><AnyOf>' +
  '<AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:' +
  'string-equal"><AttributeValue DataType="http://www.w3.org/2001/' +
  'XMLSchema#string">delegate</AttributeValue><AttributeDesignator ' +
  'AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" ' +
  'Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" ' +
  'DataType="http://www.w3.org/2001/XMLSchema#string" ' +
  'MustBePresent="false"/></Match><Match MatchId="urn:oasis:names:tc:' +
  'xacml:1.0:function:string-equal"><AttributeValue DataType="http://' +
  'www.w3.org/2001/XMLSchema#string">dp-mid</AttributeValue>' +
  '<AttributeDesignator AttributeId="urn:oasis:names:tc:xacml:1.0:' +
  'subject:subject-id" Category="urn:oasis:names:tc:xacml:1.0:' +
  'subject-category:intermediary-subject" DataType="http://www.w3.org/' +
  '2001/XMLSchema#string" MustBePresent="false"/></Match></AllOf>' +
  '</AnyOf></Target></Rule></Policy>';

function inMode(m, fn) {
  log.debug("Entering inMode(). " + m);
  config.setOverride('global.mode', m);
  try {
    log.debug("Leaving inMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

function decide(asked) {
  log.debug("Entering decide().");
  log.debug("Leaving decide().");
  return policy.decide(Object.assign({ protocol: 'OAuth 2.0',
    mode: 'delegation', targetKind: 'audience' }, asked));
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  ['dp-alice', 'dp-bob', 'dp-carol', 'dp-dave'].forEach(function (name) {
    dir.createUser(name, { invent: false });
  });
  const staff = dir.createGroup(STAFF, { origin: 'test' });
  t.check(staff.ok, 'precondition: the subject group was created',
          JSON.stringify(staff));
  dir.addGroupMember(STAFF, 'dp-alice', { origin: 'test' });
  const roster = String(config.value('admin.writeGroup'));
  dir.createGroup(roster, { origin: 'test' });
  dir.addGroupMember(roster, 'dp-dave', { origin: 'test' });
  const made = [
    applications.createApplication({ identifier: 'dp-back',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'dp-back', oauthAudience: [AUDIENCE] } }),
    applications.createApplication({ identifier: 'dp-mid',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'dp-mid',
                appAllowedToDelegateTo: ['dp-back'],
                appDelegationSubjectGroup: [staff.dn] } }),
    applications.createApplication({ identifier: 'dp-mid-imp',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'dp-mid-imp',
                appAllowedToDelegateTo: [AUDIENCE],
                appTrustedToImpersonate: 'TRUE' } }),
    applications.createApplication({ identifier: 'dp-rbcd-back',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'dp-rbcd-back',
                appAllowedToActOnBehalfOf: ['dp-rbcd-mid'] } }),
    applications.createApplication({ identifier: 'dp-rbcd-mid',
      protocols: ['oauth2'], fields: { oauthClientId: 'dp-rbcd-mid' } })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the five applications were created',
          JSON.stringify(made.filter(function (one) { return !one.ok; })));
  const bob = credentials.setNotDelegated('dp-bob', true);
  t.check(bob.ok, 'precondition: dp-bob carries stsNotDelegated',
          JSON.stringify(bob));
  log.debug("Leaving fixtures().");
  return { staffDn: staff.dn };
}

function truthTable(t, m) {
  log.debug("Entering truthTable(). " + m);
  const enforced = m === 'product';
  t.log.info('=== the truth table in ' + m + ' ===');
  inMode(m, function () {
    // A.
    let d = decide({ intermediary: 'dp-mid', subject: 'dp-alice',
                     targets: ['dp-back'] });
    t.check(d.allowed && d.enforced === enforced,
            m + ' A1. a delegation to a target appAllowedToDelegateTo names, ' +
            'for a member of the subject group, is allowed', JSON.stringify(d));
    t.check(/appAllowedToDelegateTo/.test(policy.rowText(d)) &&
            /appDelegationSubjectGroup/.test(policy.rowText(d)),
            m + ' A2. and the row names the attribute and the group that ' +
            'allowed it, as a Kerberos row does', policy.rowText(d));
    d = decide({ intermediary: 'dp-mid', subject: 'dp-alice',
                 targets: [AUDIENCE] });
    t.check(d.allowed && d.targets[0].application === 'dp-back',
            m + ' A3. an audience is resolved to the application that ' +
            'registered it before it is compared', JSON.stringify(d.targets));
    // B.
    d = decide({ intermediary: 'dp-mid', subject: 'dp-alice',
                 mode: 'impersonation', targets: ['dp-back'] });
    t.check(!d.allowed && d.refusal === 'impersonation' &&
            d.enforced === enforced,
            m + ' B1. IMPERSONATION without appTrustedToImpersonate is ' +
            'refused', JSON.stringify(d));
    t.check(enforced ? /refused by the delegation policy/.test(
              policy.rowText(d))
                     : /WOULD HAVE BEEN REFUSED/.test(policy.rowText(d)),
            m + ' B2. the row says ' + (enforced ? 'it was refused'
              : 'it would have been refused in product'), policy.rowText(d));
    d = decide({ intermediary: 'dp-mid-imp', subject: 'dp-carol',
                 mode: 'impersonation', targets: [AUDIENCE] });
    t.check(d.allowed && /appTrustedToImpersonate/.test(d.authorizedBy),
            m + ' B3. with the flag it is allowed, and says so',
            JSON.stringify(d));
    // C.
    d = decide({ intermediary: 'dp-mid', subject: 'dp-carol',
                 targets: ['dp-back'] });
    t.check(!d.allowed && d.refusal === 'subject' &&
            d.attribute === 'appDelegationSubjectGroup',
            m + ' C1. a subject outside the intermediary\'s groups is refused',
            JSON.stringify(d));
    d = decide({ intermediary: 'dp-mid-imp', subject: 'dp-bob',
                 targets: [AUDIENCE] });
    t.check(!d.allowed && d.refusal === 'subject' &&
            /stsNotDelegated/.test(d.why),
            m + ' C2. a subject carrying stsNotDelegated is refused even to ' +
            'an intermediary that names no group', JSON.stringify(d));
    d = decide({ intermediary: 'dp-mid-imp', subject: 'dp-dave',
                 targets: [AUDIENCE] });
    t.check(!d.allowed && d.refusal === 'subject' && /roster/.test(d.why),
            m + ' C3. a member of the console roster is never delegated',
            JSON.stringify(d));
    // D.
    d = decide({ intermediary: 'dp-mid', subject: 'dp-alice',
                 targets: ['https://nowhere.example'] });
    t.check(!d.allowed && d.refusal === 'target',
            m + ' D1. a target no attribute allows is refused ' +
            '(invalid_target at the token endpoint)', JSON.stringify(d));
    d = decide({ intermediary: 'dp-mid', subject: 'dp-alice', targets: [] });
    t.check(!d.allowed && d.refusal === 'no-target',
            m + ' D2. and so is an act that names no target at all',
            JSON.stringify(d));
    d = decide({ intermediary: 'dp-rbcd-mid', subject: 'dp-alice',
                 targets: ['dp-rbcd-back'] });
    t.check(d.allowed && /appAllowedToActOnBehalfOf/.test(d.authorizedBy),
            m + ' D3. the RESOURCE-BASED attribute on the target allows a ' +
            'pair the intermediary names nothing for', JSON.stringify(d));
    d = decide({ protocol: 'WS-Trust', targetKind: 'appliesTo',
                 intermediary: 'dp-rbcd-mid', subject: 'dp-alice',
                 targets: ['dp-back'] });
    t.check(!d.allowed && d.refusal === 'target',
            m + ' D4. and names only the intermediaries it lists',
            JSON.stringify(d));
    // E.
    d = decide({ intermediary: 'dp-alice', subject: 'dp-carol',
                 targets: ['dp-back'] });
    t.check(!d.allowed && d.refusal === 'intermediary',
            m + ' E1. an intermediary with no application entry — a person — ' +
            'is refused', JSON.stringify(d));
    // F.
    d = decide({ intermediary: 'dp-mid', subject: 'dp-carol',
                 mode: 'impersonation', targets: ['dp-back'],
                 mayActHonoured: true });
    t.check(d.allowed && /may_act/.test(d.authorizedBy),
            m + ' F1. a may_act naming the actor stands in for the flag and ' +
            'the groups', JSON.stringify(d));
    d = decide({ intermediary: 'dp-mid', subject: 'dp-carol',
                 targets: ['https://nowhere.example'], mayActHonoured: true });
    t.check(!d.allowed && d.refusal === 'target',
            m + ' F2. but never for the target — the subject named who, not ' +
            'where', JSON.stringify(d));
    d = decide({ intermediary: 'dp-mid', subject: 'dp-mid', targets: [],
                 self: true });
    t.check(d.allowed, m + ' F3. a client exchanging its own token acts for ' +
            'nobody and needs nothing', JSON.stringify(d));
  });
  log.debug("Leaving truthTable().");
}

function xacmlLayer(t) {
  log.debug("Entering xacmlLayer().");
  t.log.info('=== G. the deny-only XACML layer ===');
  const written = store.write('dp-deny-delegate', DENY_POLICY,
                              { enabled: true });
  t.check(written && written.ok, 'precondition: the deny policy was written',
          JSON.stringify(written));
  config.setOverride('xacml.issuancePolicy', 'dp-deny-delegate');
  try {
    ['development', 'product'].forEach(function (m) {
      inMode(m, function () {
        let d = decide({ intermediary: 'dp-mid', subject: 'dp-alice',
                         targets: ['dp-back'] });
        t.check(!d.allowed && d.refusal === 'xacml' &&
                d.enforced === (m === 'product'),
                m + ' G1. an issuance policy denying action-id delegate ' +
                'refuses an act the attributes allowed', JSON.stringify(d));
        d = decide({ intermediary: 'dp-rbcd-mid', subject: 'dp-alice',
                     targets: ['dp-rbcd-back'] });
        t.check(d.allowed, m + ' G2. and a NotApplicable for another ' +
                'intermediary refuses nothing — only a Deny does',
                JSON.stringify(d));
      });
    });
  } finally {
    config.clearOverride('xacml.issuancePolicy');
    store.remove('dp-deny-delegate');
  }
  const d = decide({ intermediary: 'dp-mid', subject: 'dp-alice',
                     targets: ['dp-back'] });
  t.check(d.allowed, 'G3. the built-in issuance policy says nothing about ' +
          'delegate, so it changes nothing', JSON.stringify(d));
  log.debug("Leaving xacmlLayer().");
}

function personHalf(t) {
  log.debug("Entering personHalf().");
  t.log.info('=== H. the person\'s half: stsMayAct and may_act ===');
  const carol = credentials.delegationFactsFor('dp-carol');
  const alice = credentials.delegationFactsFor('dp-alice');
  let r = credentials.setMayAct('dp-alice', carol.dn);
  t.check(r.ok, 'H1. a person names another person as their delegate',
          JSON.stringify(r));
  const claim = policy.mayActClaimFor('dp-alice');
  t.check(claim && /^urn:uuid:/.test(claim.sub),
          'H2. and their access tokens\' may_act names that person by their ' +
          'urn:uuid subject', JSON.stringify(claim));
  const midDn = applications.get('dp-mid').dn;
  r = credentials.setMayAct('dp-alice', midDn);
  t.check(r.ok && policy.mayActClaimFor('dp-alice').sub === 'dp-mid',
          'H3. an application is named by its client_id', JSON.stringify(r));
  r = credentials.setMayAct('dp-alice', 'uid=nobody-here,ou=users,dc=x');
  t.check(!r.ok, 'H4. a DN naming nobody is refused', JSON.stringify(r));
  r = credentials.setMayAct('dp-alice', alice.dn);
  t.check(!r.ok, 'H5. and so is the person themselves', JSON.stringify(r));
  r = credentials.setMayAct('dp-alice', '');
  t.check(r.ok && policy.mayActClaimFor('dp-alice') === null,
          'H6. clearing it takes the claim away', JSON.stringify(r));
  t.check(policy.mayActNames({ sub: 'x' }, { sub: 'x' }) &&
          !policy.mayActNames({ sub: 'x' }, { sub: 'y' }) &&
          !policy.mayActNames({ sub: 'x', iss: 'https://a' },
                              { sub: 'x', iss: 'https://b' }) &&
          policy.mayActNames({ sub: 'c' }, { sub: 'urn:sts:client:c',
                                             aliases: ['c'] }),
          'H7. may_act matches on sub, and on iss when it carries one');
  log.debug("Leaving personHalf().");
}

function grammarAndList(t, fx) {
  log.debug("Entering grammarAndList().");
  t.log.info('=== I. the grammar and the register ===');
  let r = applications.updateApplication('dp-mid', {
    attribute: 'appTrustedToImpersonate', mode: 'set', value: 'yes' });
  t.check(!r.ok, 'I1. appTrustedToImpersonate must be TRUE or FALSE',
          JSON.stringify(r));
  r = applications.updateApplication('dp-mid', {
    attribute: 'appDelegationSubjectGroup', mode: 'add', value: STAFF });
  t.check(!r.ok, 'I2. a subject group is named by its DN', JSON.stringify(r));
  const listed = policy.list();
  t.check(listed.pairs.some(function (one) {
    return one.intermediary === 'dp-mid' && one.target === 'dp-back' &&
           one.mechanism === 'constrained';
  }) && listed.pairs.some(function (one) {
    return one.intermediary === 'dp-rbcd-mid' &&
           one.target === 'dp-rbcd-back' && one.mechanism === 'resource-based';
  }), 'I3. list() has a pair for each attribute, set on each end',
          JSON.stringify(listed.pairs));
  t.check(listed.intermediaries.some(function (one) {
    return one.application === 'dp-mid-imp' && one.trustedToImpersonate;
  }) && listed.intermediaries.some(function (one) {
    return one.application === 'dp-mid' &&
           one.subjectGroups.indexOf(fx.staffDn) >= 0;
  }), 'I4. and the intermediaries carrying a flag or a group',
          JSON.stringify(listed.intermediaries));
  t.check(listed.people.some(function (one) {
    return one.username === 'dp-bob' && one.notDelegated;
  }), 'I5. and the people carrying stsNotDelegated',
          JSON.stringify(listed.people));
  t.check(listed.protectedGroups.indexOf(
    String(config.value('admin.writeGroup'))) >= 0,
          'I6. and names the roster groups it protects');
  log.debug("Leaving grammarAndList().");
}

// An RST whose security header carries `security` and whose body delegates
// with `element` (OnBehalfOf or ActAs) the assertion `delegated`, for
// `appliesTo`. SOAP 1.2 unless `soap11`.
function rst(security, element, delegated, appliesTo, soap11) {
  log.debug("Entering rst().");
  const soapNs = soap11 ? 'http://schemas.xmlsoap.org/soap/envelope/'
                        : 'http://www.w3.org/2003/05/soap-envelope';
  const wrapped = element === 'ActAs'
    ? '<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/ws-trust/' +
      '200802">' + delegated + '</wst14:ActAs>'
    : '<wst:OnBehalfOf>' + delegated + '</wst:OnBehalfOf>';
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="' + soapNs + '" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
    'wssecurity-secext-1.0.xsd"><s:Header><wsse:Security>' + security +
    '</wsse:Security></s:Header><s:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/' +
    'Issue</wst:RequestType><wsp:AppliesTo xmlns:wsp="http://schemas.' +
    'xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="' +
    'http://www.w3.org/2005/08/addressing"><wsa:Address>' + appliesTo +
    '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' + wrapped +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function wsTrust(t) {
  log.debug("Entering wsTrust().");
  t.log.info('=== J. WS-Trust OnBehalfOf and ActAs ===');
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const delegation = require('../common/delegation');
  const as = function (name) {
    log.debug("Entering as().");
    log.debug("Leaving as().");
    return saml2.buildSamlAssertion(name, 'https://sts.test', 5);
  };
  const ask = function (m, requester, element, subject, appliesTo, soap11) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return inMode(m, function () {
      return wstrust.handleRst(rst(as(requester), element, as(subject),
                                   appliesTo, soap11),
                               soap11 ? 'text/xml' : 'application/soap+xml');
    });
  };
  let r = ask('product', 'dp-mid', 'ActAs', 'dp-alice', 'dp-back');
  t.equal(r.status, 200, 'J1. product: ActAs by an intermediary whose ' +
          'appAllowedToDelegateTo names the AppliesTo, for a member of its ' +
          'group, is issued', r.body.slice(0, 300));
  const allowedRow = delegation.list().filter(function (row) {
    return row.type === 'wstrust-actas';
  })[0];
  t.check(allowedRow && /appAllowedToDelegateTo/.test(allowedRow.authorizedBy),
          'J2. and the act names the attribute that allowed it',
          JSON.stringify(allowedRow && allowedRow.authorizedBy));
  r = ask('product', 'dp-mid', 'OnBehalfOf', 'dp-alice', 'dp-back');
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0018' &&
          /<soap:Subcode><soap:Value xmlns:wst="[^"]+">wst:RequestFailed</
            .test(r.body) && /appTrustedToImpersonate/.test(r.body),
          'J3. product: OnBehalfOf (impersonation) without ' +
          'appTrustedToImpersonate is a SOAP 1.2 Fault whose Subcode is ' +
          'wst:RequestFailed (STS-WSTRUST-0018)', r.errorCode + ' ' +
          r.body.slice(0, 500));
  r = ask('product', 'dp-mid', 'OnBehalfOf', 'dp-alice', 'dp-back', true);
  t.check(/<faultcode xmlns:wst="[^"]+">wst:RequestFailed<\/faultcode>/
            .test(r.body),
          'J4. and over SOAP 1.1 the faultcode itself is wst:RequestFailed',
          r.body.slice(0, 400));
  r = ask('product', 'dp-mid-imp', 'OnBehalfOf', 'dp-carol', AUDIENCE);
  t.equal(r.status, 200, 'J5. product: OnBehalfOf by an intermediary ' +
          'carrying appTrustedToImpersonate is issued', r.body.slice(0, 300));
  r = ask('product', 'dp-carol', 'ActAs', 'dp-alice', 'dp-back');
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0019' &&
          /only an application/.test(r.body),
          'J6. product: a PERSON requester is refused, and told why ' +
          '(STS-WSTRUST-0019)', r.errorCode + ' ' + r.body.slice(0, 400));
  r = ask('product', 'dp-mid-imp', 'ActAs', 'dp-bob', AUDIENCE);
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0018' &&
          /stsNotDelegated/.test(r.body),
          'J7. product: a subject carrying stsNotDelegated is refused',
          r.errorCode + ' ' + r.body.slice(0, 400));
  const refusedRow = delegation.list().filter(function (row) {
    return row.type === 'wstrust-actas';
  })[0];
  t.check(refusedRow && refusedRow.outcome === 'refused' &&
          /stsNotDelegated/.test(refusedRow.reason),
          'J8. and the refusal is an act on /admin/delegation',
          JSON.stringify(refusedRow && [refusedRow.outcome,
                                        refusedRow.reason]));
  r = ask('development', 'dp-mid', 'OnBehalfOf', 'dp-alice', 'dp-back');
  const devRow = delegation.list().filter(function (row) {
    return row.type === 'wstrust-onbehalfof';
  })[0];
  t.check(r.status === 200 && devRow && devRow.outcome === 'issued' &&
          /WOULD HAVE BEEN REFUSED/.test(devRow.authorizedBy),
          'J9. development issues the same OnBehalfOf and the act says it ' +
          'WOULD have been refused', r.status + ' ' +
          JSON.stringify(devRow && devRow.authorizedBy));
  log.debug("Leaving wsTrust().");
}

function consoleDoor(t) {
  log.debug("Entering consoleDoor().");
  t.log.info('=== K. the console\'s door and the paged view ===');
  const adminActions = require('../admin-core/admin_actions');
  const adminViews = require('../admin-core/admin_views');
  const errorCodes = require('../common/error_codes');
  const ctx = { via: 'console', actor: 'delegation-policy-test' };
  let r = adminActions.usersAction({ action: 'set-not-delegated',
                                     user: 'dp-carol', value: 'true' }, ctx);
  t.check(r.ok && credentials.delegationFactsFor('dp-carol').notDelegated,
          'K1. set-not-delegated, as the person page posts it, writes ' +
          'stsNotDelegated', JSON.stringify(r));
  r = adminActions.usersAction({ action: 'set-not-delegated',
                                 user: 'dp-carol', value: 'false' }, ctx);
  t.check(r.ok && !credentials.delegationFactsFor('dp-carol').notDelegated,
          'K2. and value=false clears it', JSON.stringify(r));
  const aliceDn = credentials.delegationFactsFor('dp-alice').dn;
  r = adminActions.usersAction({ action: 'set-may-act', user: 'dp-carol',
                                 delegate: aliceDn }, ctx);
  t.check(r.ok && credentials.delegationFactsFor('dp-carol').mayAct ===
          aliceDn, 'K3. set-may-act writes stsMayAct', JSON.stringify(r));
  r = adminActions.usersAction({ action: 'set-may-act', user: 'dp-carol',
                                 delegate: 'uid=nobody,ou=users,dc=x' }, ctx);
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-AUTHN-0227',
          'K4. and a delegate naming nobody is refused, the store\'s code ' +
          '(STS-AUTHN-0227) riding out rather than the action\'s',
          JSON.stringify(r) + ' ' + errorCodes.codeOf(r));
  adminActions.usersAction({ action: 'set-may-act', user: 'dp-carol',
                             delegate: '' }, ctx);
  const view = adminViews.delegationPolicyView({ per: '1' });
  t.check(view.json.pairs.length === 1 && view.json.pairsPaging.pages >= 2 &&
          view.json.peoplePaging && view.json.intermediariesPaging,
          'K5. the view is PAGED, each list on its own parameter',
          JSON.stringify(view.json.pairsPaging));
  const second = adminViews.delegationPolicyView({ per: '1',
                                                   policyPairsPage: '2' });
  t.check(second.json.pairsPaging.page === 2 &&
          JSON.stringify(second.json.pairs) !==
            JSON.stringify(view.json.pairs),
          'K6. and policyPairsPage moves that list alone',
          JSON.stringify(second.json.pairsPaging));
  log.debug("Leaving consoleDoor().");
}

// EVERYTHING IN A THROWAWAY REALM, removed afterwards: the fixtures put a
// person on the console roster's group, and `tests/run.js` runs every file in
// one process — in the default realm that membership opened the console to
// somebody in `directory_write_authorization.js`, which runs later.
function run(t) {
  log.debug("Entering run().");
  const id = 'dp-' + process.pid;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    realms.run(made.realm, function () {
      inRealm(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

function inRealm(t) {
  log.debug("Entering inRealm().");
  const fx = fixtures(t);
  truthTable(t, 'development');
  truthTable(t, 'product');
  xacmlLayer(t);
  personHalf(t);
  grammarAndList(t, fx);
  wsTrust(t);
  consoleDoor(t);
  log.debug("Leaving inRealm().");
}

module.exports = {
  name: 'delegation_policy',
  describe: 'who may act for whom at WS-Trust and the token exchange: the ' +
            'attribute rule in both modes, the deny-only XACML layer, ' +
            'stsMayAct and may_act (#108)',
  run: run
};
