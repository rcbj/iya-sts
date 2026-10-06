// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_token_claims.js
//
// ===========================================================================
// AN APPLICATION'S CLAIM SETTINGS GOVERN THE TOKENS WS-TRUST ISSUES TO IT
// (#483, #484), exactly as they govern an OAuth 2.0 access token and a SAML
// SSO assertion for the same application and person.
//
// The settings are on the AppliesTo's application:
//
//   * the groups claim: `appGroupsClaim`, `appGroupsClaimName` and
//     `appGroupsClaimValue` (`dn` here, so the per-application form is seen);
//   * the roles claim: a role whose member is a GROUP the person is in;
//   * custom claims: `oauthClaimsAccessToken` (with a `${username}`
//     placeholder) and `saml2CustomAttributes` (with `${subject}`, the
//     placeholder a SAML context has, and a NameFormat), over the realm's
//     own custom claims (`realm-flag`).
//
// What "exactly as" means is asked of the code those two doors use, with the
// context each passes:
//
//   * an OAuth access token for the application carries
//     `stats.jwtClaims('access_token', …)` with its client_id;
//   * a SAML SSO assertion carries `stats.samlAttributes('saml2', …)` with
//     its service provider's identifier as the audience.
//
// The WS-Trust JWT and SAML 2.0 assertion must carry the same names and
// values, in both modes:
//
//   C1. a person's own JWT;
//   C2. their own SAML 2.0 assertion;
//   C3. an ActAs JWT;
//   C4. an ActAs assertion. In both, the claims describe the SUBJECT: the
//       requester holds neither the group nor the role, and nothing of its
//       own appears.
//
// IN PROCESS, in a throwaway realm.
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
// Arms `issuance_gate.js`'s decider, and with it the claim resolvers.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'wstrust_token_claims',
  level: process.env.LOG_LEVEL || 'info' });

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const JWT = 'urn:ietf:params:oauth:token-type:jwt';
const BACK = 'https://wc-back.example';
const BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

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

function rst(security, body, tokenType) {
  log.debug("Entering rst().");
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
    'wssecurity-secext-1.0.xsd"><s:Header><wsse:Security>' + security +
    '</wsse:Security></s:Header><s:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="' + WST + '"><wst:RequestType>' + WST + '/Issue' +
    '</wst:RequestType>' + (tokenType ? '<wst:TokenType>' + tokenType +
    '</wst:TokenType>' : '') + '<wsp:AppliesTo xmlns:wsp="http://' +
    'schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference ' +
    'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
    BACK + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    (body || '') + '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function actAs(inner) {
  log.debug("Entering actAs().");
  log.debug("Leaving actAs().");
  return '<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/' +
    'ws-trust/200802">' + inner + '</wst14:ActAs>';
}

function claimsOf(r) {
  log.debug("Entering claimsOf().");
  const m = /<wsse:BinarySecurityToken[^>]*>([^<]+)</.exec(String(r.body));
  log.debug("Leaving claimsOf().");
  return m ? JSON.parse(Buffer.from(m[1].split('.')[1], 'base64url')
    .toString('utf8')) : {};
}

// The assertion's attributes as { name: { nameFormat, values } }.
function attributesOf(r) {
  log.debug("Entering attributesOf().");
  const out = {};
  const re = /<saml:Attribute Name="([^"]+)"([^>]*)>([\s\S]*?)<\/saml:Attribute>/g;
  const body = String(r.body);
  for (let m = re.exec(body); m; m = re.exec(body)) {
    const values = [];
    const vr = /<saml:AttributeValue[^>]*>([^<]*)<\/saml:AttributeValue>/g;
    for (let v = vr.exec(m[3]); v; v = vr.exec(m[3])) {
      values.push(v[1]);
    }
    const format = /NameFormat="([^"]+)"/.exec(m[2]);
    out[m[1]] = { nameFormat: format ? format[1] : '', values: values };
  }
  log.debug("Leaving attributesOf().");
  return out;
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  dir.createUser('wc-alice', { invent: false });
  const group = dir.createGroup('wc-team', { members: [] });
  const member = dir.addGroupMember('wc-team', 'wc-alice');
  const role = roles.write('wc-role', { users: [], groups: ['wc-team'] });
  // The realm's own custom claims, which the application's rows sit over.
  const realmJwt = stats.setClaimSet('access_token',
                                     [{ name: 'realm-flag', value: 'on' }]);
  const realmSaml = stats.setClaimSet('saml2',
                                      [{ name: 'realm-flag', value: 'on' }]);
  const app = function (identifier, fields) {
    log.debug("Entering app().");
    log.debug("Leaving app().");
    return applications.createApplication({ identifier: identifier,
      protocols: ['wstrust', 'saml2', 'oauth2'], fields: fields });
  };
  const made = [
    app('wc-back', {
      wstrustAppliesTo: [BACK], oauthClientId: 'wc-back',
      appGroupsClaim: 'TRUE', appGroupsClaimName: 'teams',
      appGroupsClaimValue: 'dn',
      oauthClaimsAccessToken: JSON.stringify(
        [{ name: 'tier', value: 'gold-${username}' }]),
      saml2CustomAttributes: JSON.stringify(
        [{ name: 'tier', value: 'gold-${subject}', nameFormat: BASIC }])
    }),
    app('wc-front', { appAllowedToDelegateTo: ['wc-back'],
                      appDelegationSemantics: ['delegation',
                                               'impersonation'] })
  ];
  t.check(group && group.ok && member && member.ok && realmJwt.ok &&
          realmSaml.ok &&
          role && role.ok !== false &&
          made.every(function (one) { return one && one.ok; }),
          'precondition: the person, group, role and applications exist',
          JSON.stringify([group, member, role, made]).slice(0, 600));
  log.debug("Leaving fixtures().");
}

function compare(t) {
  log.debug("Entering compare().");
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const signed = function (name, audience) {
    log.debug("Entering signed().");
    log.debug("Leaving signed().");
    return saml2.buildSamlAssertion(name, audience, 5);
  };
  ['development', 'product'].forEach(function (m) {
    t.log.info('=== ' + m + ' mode ===');
    const ask = function (requester, body, tokenType) {
      log.debug("Entering ask().");
      log.debug("Leaving ask().");
      return inMode(m, function () {
        return wstrust.handleRst(rst(signed(requester, 'https://sts.test'),
                                     body, tokenType),
                                 'application/soap+xml');
      });
    };
    // What the OAuth access token and the SAML SSO assertion carry.
    const oauth = inMode(m, function () {
      return stats.jwtClaims('access_token', {
        username: 'wc-alice', sub: helpers.subjectForName('wc-alice'),
        client_id: 'wc-back', audience: BACK });
    });
    const sso = {};
    inMode(m, function () {
      return stats.samlAttributes('saml2', { subject: 'wc-alice',
                                             audience: 'wc-back' });
    }).forEach(function (a) {
      sso[a.name] = { nameFormat: a.nameFormat || '',
                      values: a.values || [a.value] };
    });
    t.check(Array.isArray(oauth.teams) && /^cn=wc-team,/.test(oauth.teams[0]) &&
            JSON.stringify(oauth.roles) === '["wc-role"]' &&
            oauth.tier === 'gold-wc-alice' && oauth['realm-flag'] === 'on' &&
            sso.teams && sso.roles && sso['realm-flag'] && sso.tier &&
            sso.tier.nameFormat === BASIC &&
            JSON.stringify(sso.tier.values) === '["gold-wc-alice"]',
            'precondition (' + m + '): an OAuth access token and a SAML SSO ' +
            'assertion for wc-back carry teams (dn), roles, tier and the ' +
            'realm\'s realm-flag',
            JSON.stringify({ oauth: oauth, sso: sso }));
    const sameJwt = function (claims) {
      log.debug("Entering sameJwt().");
      const wrong = Object.keys(oauth).filter(function (k) {
        return JSON.stringify(claims[k]) !== JSON.stringify(oauth[k]);
      });
      log.debug("Leaving sameJwt().");
      return wrong;
    };
    const sameSaml = function (attrs) {
      log.debug("Entering sameSaml().");
      const wrong = Object.keys(sso).filter(function (k) {
        return !attrs[k] ||
          JSON.stringify(attrs[k].values) !== JSON.stringify(sso[k].values) ||
          attrs[k].nameFormat !== sso[k].nameFormat;
      });
      log.debug("Leaving sameSaml().");
      return wrong;
    };
    const subject = signed('wc-alice', 'wc-front');
    [['C1', 'a person\'s own JWT', ask('wc-alice', '', JWT), true],
     ['C2', 'a person\'s own SAML 2.0 assertion', ask('wc-alice', '', ''),
      false],
     ['C3', 'an ActAs JWT about the person', ask('wc-front',
                                                 actAs(subject), JWT), true],
     ['C4', 'an ActAs assertion about the person', ask('wc-front',
                                                       actAs(subject), ''),
      false]].forEach(function (one) {
      const r = one[2];
      const wrong = one[3] ? sameJwt(claimsOf(r)) : sameSaml(attributesOf(r));
      t.check(r.status === 200 && wrong.length === 0,
              one[0] + ' (' + m + '). ' + one[1] + ' carries the groups, ' +
              'roles and custom ' + (one[3] ? 'claims' : 'attributes') +
              ' as ' + (one[3] ? 'an OAuth access token' : 'SAML SSO') +
              ' does for wc-back', r.status + ' differing: ' +
              JSON.stringify(wrong) + ' ' + JSON.stringify(one[3]
                ? claimsOf(r) : attributesOf(r)).slice(0, 700));
    });
  });
  log.debug("Leaving compare().");
}

// EVERYTHING IN A THROWAWAY REALM, removed afterwards.
function run(t) {
  log.debug("Entering run().");
  const id = 'wc-' + process.pid;
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
      compare(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
  return undefined;
}

module.exports = {
  name: 'wstrust_token_claims',
  describe: 'an application\'s groups, roles and custom claim settings ' +
            'govern the JWT and SAML assertion WS-Trust issues to it, as ' +
            'they govern an OAuth access token and a SAML SSO assertion ' +
            '(#483, #484)',
  run: run
};
