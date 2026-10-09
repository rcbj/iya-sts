// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_saml11.js
//
// ===========================================================================
// SAML 1.1 AS A WS-TRUST REQUEST AND RESPONSE TOKEN TYPE (#487).
//
//   T1. an RST for `…#SAMLV1.1` — or its older name
//       `urn:oasis:names:tc:SAML:1.0:assertion` — is answered with a signed
//       SAML 1.1 assertion (MajorVersion 1, MinorVersion 1), the RSTR's
//       wst:TokenType the profile's URI. It carries the subject, the
//       AppliesTo as its AudienceRestrictionCondition, an
//       AuthenticationStatement (`am:password` for a UsernameToken), and an
//       AssertionID reference;
//   T2. it carries the AppliesTo application's SAML 1.1 attributes exactly
//       as SAML 1.1 SSO would (`stats.samlAttributes('saml11', …)` with the
//       service provider as the audience): the groups claim under the
//       application's name, the roles claim, `saml11CustomAttributes` with
//       its namespace, and the realm's own custom attribute;
//   T3. a SAML 1.1 assertion this realm signed is accepted inside
//       OnBehalfOf and ActAs, in product verified as a SAML 2.0 one is: one
//       not signed is refused (STS-WSTRUST-0004, InvalidRequest), an
//       expired one (STS-WSTRUST-0006, ExpiredData);
//   T4. an ActAs answered in SAML 1.1 names the requester in its
//       `delegates` attribute (urn:iya:sts:delegation, #522: SAML 1.1 has no
//       Delegation Restriction), and no del:Delegate; the register's row
//       says so and records a `SAML 1.1 assertion` produced, consuming the
//       presented one's AssertionID. A chain of SAML 1.1 hops keeping the
//       list is sts_wstrust_saml11_chain_delegation.js's.
//
// IN PROCESS, in a throwaway realm, in the mode each case belongs to.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const helpers = require('../common/helpers');
const stats = require('../common/admin_stats');
const roles = require('../common/roles');
// Arms the issuance gate and its claim resolvers.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'wstrust_saml11',
  level: process.env.LOG_LEVEL || 'info' });

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const SAML11 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-' +
  'profile-1.1#SAMLV1.1';
const SAML11_ALIAS = 'urn:oasis:names:tc:SAML:1.0:assertion';
const BACK = 'https://w11-back.example';
const NS = 'http://example.com/claims';

// A requester's credential is addressed to this IdP (#519): its WS-Trust
// endpoint at the base the RSTs are handed.
const IDP = 'https://sts.w11.example/sts';

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

function shifted(ms, fn) {
  log.debug("Entering shifted().");
  const real = Date.now;
  Date.now = function () {
    return real() + ms;
  };
  try {
    log.debug("Leaving shifted().");
    return fn();
  } finally {
    Date.now = real;
  }
}

function rst(security, body, tokenType) {
  log.debug("Entering rst().");
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
    'wssecurity-secext-1.0.xsd"><s:Header><wsse:Security>' + security +
    '</wsse:Security></s:Header><s:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="' + WST + '"><wst:RequestType>' + WST + '/Issue' +
    '</wst:RequestType><wst:TokenType>' + tokenType + '</wst:TokenType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
    'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/' +
    'addressing"><wsa:Address>' + BACK + '</wsa:Address>' +
    '</wsa:EndpointReference></wsp:AppliesTo>' + (body || '') +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function usernameToken(user) {
  log.debug("Entering usernameToken().");
  log.debug("Leaving usernameToken().");
  return '<wsse:UsernameToken><wsse:Username>' + user + '</wsse:Username>' +
    '<wsse:Password>any</wsse:Password></wsse:UsernameToken>';
}

function wrap(element, inner) {
  log.debug("Entering wrap().");
  log.debug("Leaving wrap().");
  return element === 'ActAs'
    ? '<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/' +
      'ws-trust/200802">' + inner + '</wst14:ActAs>'
    : '<wst:OnBehalfOf>' + inner + '</wst:OnBehalfOf>';
}

function assertionOf(r) {
  log.debug("Entering assertionOf().");
  const m = /<wst:RequestedSecurityToken>([\s\S]*?)<\/wst:RequestedSecurityToken>/
    .exec(String(r && r.body || ''));
  log.debug("Leaving assertionOf().");
  return m ? m[1] : '';
}

// SAML 1.1 attributes as { "namespace name": [values] }.
function attributesOf(xml) {
  log.debug("Entering attributesOf().");
  const out = {};
  const re = /<saml:Attribute AttributeName="([^"]+)" AttributeNamespace="([^"]*)">([\s\S]*?)<\/saml:Attribute>/g;
  for (let m = re.exec(xml); m; m = re.exec(xml)) {
    const values = [];
    const vr = /<saml:AttributeValue[^>]*>([^<]*)<\/saml:AttributeValue>/g;
    for (let v = vr.exec(m[3]); v; v = vr.exec(m[3])) {
      values.push(v[1]);
    }
    out[m[2] + ' ' + m[1]] = values;
  }
  log.debug("Leaving attributesOf().");
  return out;
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  dir.createUser('w11-alice', { invent: false });
  const group = dir.createGroup('w11-team', { members: [] });
  const member = dir.addGroupMember('w11-team', 'w11-alice');
  const role = roles.write('w11-role', { users: [], groups: ['w11-team'] });
  const realmSet = stats.setClaimSet('saml11',
    [{ name: 'realm-flag', value: 'on', namespace: NS }]);
  const made = [
    applications.createApplication({ identifier: 'w11-back',
      protocols: ['wstrust', 'saml11'],
      fields: { wstrustAppliesTo: [BACK], appGroupsClaim: 'TRUE',
                appGroupsClaimName: 'teams',
                saml11CustomAttributes: JSON.stringify(
                  [{ name: 'tier', value: 'gold-${subject}',
                     namespace: NS }]) } }),
    applications.createApplication({ identifier: 'w11-front',
      protocols: ['wstrust'],
      fields: { appAllowedToDelegateTo: ['w11-back'],
                appDelegationSemantics: ['delegation', 'impersonation'] } })
  ];
  t.check(group && group.ok && member && member.ok &&
          role && role.ok !== false && realmSet.ok &&
          made.every(function (one) { return one && one.ok; }),
          'precondition: the person, group, role and applications exist',
          JSON.stringify([group, member, role, realmSet, made])
            .slice(0, 600));
  log.debug("Leaving fixtures().");
}

function cases(t) {
  log.debug("Entering cases().");
  const wstrust = require('../ws-trust/wstrust');
  const saml11 = require('../saml/saml11');
  const delegation = require('../common/delegation');
  const ask = function (m, security, body, tokenType) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return inMode(m, function () {
      return wstrust.handleRst(rst(security, body, tokenType),
                               'application/soap+xml',
                               { base: 'https://sts.w11.example' });
    });
  };
  // T1.
  [SAML11, SAML11_ALIAS].forEach(function (asked, i) {
    const r = ask('development', usernameToken('w11-alice'), '', asked);
    const xml = assertionOf(r);
    const signed = helpers.verifyOwnXml(xml, { element: 'Assertion' });
    t.check(r.status === 200 &&
            new RegExp('<wst:TokenType>' + SAML11.replace(/[.#]/g, '\\$&') +
                       '</wst:TokenType>').test(String(r.body)) &&
            /^<saml:Assertion[^>]*MajorVersion="1" MinorVersion="1"/
              .test(xml.trim()) &&
            signed && signed.ok &&
            /<saml:NameIdentifier[^>]*>w11-alice</.test(xml) &&
            xml.indexOf('<saml:AudienceRestrictionCondition><saml:Audience>' +
                        BACK + '</saml:Audience>') >= 0 &&
            /AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password"/
              .test(xml) &&
            /oasis-wss-saml-token-profile-1.0#SAMLAssertionID/
              .test(String(r.body)),
            'T1' + 'ab'[i] + '. TokenType ' + asked + ' is answered with a ' +
            'signed SAML 1.1 assertion: the subject, the AppliesTo, ' +
            'am:password, an AssertionID reference',
            r.status + ' ' + JSON.stringify(signed) + ' ' +
            String(r.body).slice(0, 700));
  });
  // T2.
  ['development', 'product'].forEach(function (m) {
    const expected = {};
    inMode(m, function () {
      return stats.samlAttributes('saml11', { subject: 'w11-alice',
                                              audience: 'w11-back' });
    }).forEach(function (a) {
      expected[a.namespace + ' ' + a.name] = a.values || [a.value];
    });
    const subject = saml11.buildSaml11Assertion({ subject: 'w11-alice',
                                                  audience: 'w11-front',
                                                  lifetimeMin: 5 });
    const r = ask(m, saml11.buildSaml11Assertion({ subject: 'w11-front',
                                                   audience: IDP,
                                                   lifetimeMin: 5 }),
                  wrap('OnBehalfOf', subject), SAML11);
    const got = attributesOf(assertionOf(r));
    const wrong = Object.keys(expected).filter(function (k) {
      return JSON.stringify(got[k]) !== JSON.stringify(expected[k]);
    });
    t.check(r.status === 200 && wrong.length === 0 &&
            Object.keys(expected).some(function (k) {
              return / teams$/.test(k);
            }) && JSON.stringify(expected[NS + ' tier']) ===
              '["gold-w11-alice"]',
            'T2 (' + m + '). an OnBehalfOf SAML 1.1 assertion about the ' +
            'person carries the AppliesTo application\'s SAML 1.1 attributes ' +
            'as SAML 1.1 SSO does: teams, roles, tier, realm-flag',
            r.status + ' differing ' + JSON.stringify(wrong) + ' ' +
            JSON.stringify({ expected: expected, got: got }).slice(0, 900));
  });
  // T3. Product refuses an unsigned or expired SAML 1.1 assertion inside.
  const front = saml11.buildSaml11Assertion({ subject: 'w11-front',
                                              audience: IDP,
                                              lifetimeMin: 5 });
  [['T3a', saml11.buildSaml11Assertion({ subject: 'w11-alice',
                                          audience: 'w11-front',
                                          lifetimeMin: 5, sign: false }),
    'STS-WSTRUST-0004', 'InvalidRequest', 'an unsigned'],
   ['T3b', shifted(-2 * 3600 * 1000, function () {
     return saml11.buildSaml11Assertion({ subject: 'w11-alice',
                                          audience: 'w11-front',
                                          lifetimeMin: 5 });
   }), 'STS-WSTRUST-0006', 'ExpiredData', 'an expired']]
    .forEach(function (one) {
      const r = ask('product', front, wrap('ActAs', one[1]), SAML11);
      t.check(r.status === 500 && r.errorCode === one[2] &&
              new RegExp('wst:' + one[3] + '<').test(String(r.body)),
              one[0] + ' (product). ' + one[4] + ' SAML 1.1 assertion ' +
              'inside ActAs is refused: ' + one[2], r.status + ' ' +
              r.errorCode + ' ' + String(r.body).slice(0, 300));
    });
  // T4. An ActAs in SAML 1.1, in product, from a signed SAML 1.1 assertion.
  const presented = saml11.buildSaml11Assertion({ subject: 'w11-alice',
                                                  audience: 'w11-front',
                                                  lifetimeMin: 5 });
  const presentedId = (/AssertionID="([^"]+)"/.exec(presented) || [])[1];
  const r = ask('product', front, wrap('ActAs', presented), SAML11);
  const xml = assertionOf(r);
  const id = (/AssertionID="([^"]+)"/.exec(xml) || [])[1] || '';
  const act = delegation.list().filter(function (row) {
    return (row.produced || []).some(function (one) {
      return one.identifier === id;
    });
  })[0] || {};
  // #522: the requester named in the `delegates` attribute.
  const delegatesAttr = /<saml:Attribute AttributeName="delegates" AttributeNamespace="urn:iya:sts:delegation">((?:<saml:AttributeValue>[^<]*<\/saml:AttributeValue>)+)<\/saml:Attribute>/
    .exec(xml);
  t.check(r.status === 200 && /<saml:NameIdentifier[^>]*>w11-alice</
            .test(xml) && xml.indexOf('Delegate') < 0 &&
          !!delegatesAttr && delegatesAttr[1] ===
            '<saml:AttributeValue>w11-front</saml:AttributeValue>' &&
          act.type === 'wstrust-actas' &&
          /in its "delegates" attribute/.test(String(act.note)) &&
          (act.produced || [])[0].kind === 'SAML 1.1 assertion' &&
          (act.consumed || []).some(function (c) {
            return c.identifier === presentedId;
          }),
          'T4 (product). an ActAs answered in SAML 1.1 names the requester ' +
          'in its delegates attribute (#522); the register records it, ' +
          'consuming the presented AssertionID and saying so',
          r.status + ' ' + JSON.stringify({ note: act.note,
                                            produced: act.produced,
                                            consumed: act.consumed }) + ' ' +
          String(r.body).slice(0, 300));
  log.debug("Leaving cases().");
}

// EVERYTHING IN A THROWAWAY REALM, removed afterwards.
function run(t) {
  log.debug("Entering run().");
  const id = 'w11-' + process.pid;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return undefined;
  }
  try {
    realms.run(made.realm, function () {
      fixtures(t);
      cases(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
  return undefined;
}

module.exports = {
  name: 'wstrust_saml11',
  describe: 'SAML 1.1 as a WS-Trust token type: issued by the SAML 1.1 ' +
            'builder with the application\'s SAML 1.1 attributes, accepted ' +
            'inside OnBehalfOf / ActAs (verified in product), and no ' +
            'delegate chain (#487)',
  run: run
};
