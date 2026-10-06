// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust_jwt_claims.js
//
// ===========================================================================
// THE JWT A WS-TRUST RST ASKS FOR FOLLOWS RFC 9068 AND RFC 8693 IN ITS
// STRUCTURE AND CLAIMS (#476), and nothing else about WS-Trust changes.
//
// rcbj: "follow RFC-9068 and OAuth2 Token Exchange spec for claims in the
// JWT", and only for "response token JWT structure and contents". So, through
// `handleRst()` with `wst:TokenType` urn:ietf:params:oauth:token-type:jwt, in
// both modes:
//
//   J1. a person's own token: `typ: at+jwt`, iss / sub (`urn:uuid:`) / aud
//       (the AppliesTo) / iat / exp (the RSTR's wst:Lifetime) / jti, and NO
//       client_id: a person asking for themselves has no client (the
//       exception `ws-trust/CLAUDE.md` records), and no act;
//   J2. an application's own token: `client_id` its client_id;
//   J3. ActAs: `client_id` the requester, `act` naming it as RFC 8693
//       section 4.1 has it, in this service's OAuth shape (#471): `iss` this
//       token's own, the client named `urn:sts:client:<id>` in product (RFC
//       9700 mode) and bare in development;
//   J4. an ActAs of an ActAs assertion: `act` nests, the current actor
//       outermost, `iss` at every level;
//   J5. OnBehalfOf: `client_id` the requester, no `act`;
//   J6. and the SAML assertion an ActAs asks for is untouched: its
//       Delegation Restriction names the applications by their bare
//       identifiers in both modes.
//
// Every JWT verifies with this realm's own key (`helpers.verifyOwnJws()`).
// IN PROCESS, in a throwaway realm, for `wstrust_fault_codes.js`'s reason:
// the two modes' answers differ, and a job over HTTP runs in one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const helpers = require('../common/helpers');
// Arms `issuance_gate.js`'s decider, the PEP the role gate and the
// delegation questions go to.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'wstrust_jwt_claims',
  level: process.env.LOG_LEVEL || 'info' });

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const JWT = 'urn:ietf:params:oauth:token-type:jwt';
const BACK = 'https://wj-back.example';
const FINAL = 'https://wj-final.example';

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

// An Issue for `appliesTo` asking for `tokenType`, the requester's
// credential in the security header and `body` in the RST.
function rst(security, appliesTo, body, tokenType) {
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
    appliesTo + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    (body || '') + '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function actAs(inner) {
  log.debug("Entering actAs().");
  log.debug("Leaving actAs().");
  return '<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/' +
    'ws-trust/200802">' + inner + '</wst14:ActAs>';
}

function onBehalfOf(inner) {
  log.debug("Entering onBehalfOf().");
  log.debug("Leaving onBehalfOf().");
  return '<wst:OnBehalfOf>' + inner + '</wst:OnBehalfOf>';
}

// The JWT out of an RSTR, its header and claims, verified with this realm's
// own key; and the RSTR's wst:Lifetime.
function jwtOf(r) {
  log.debug("Entering jwtOf().");
  const body = String(r && r.body || '');
  const m = /<wsse:BinarySecurityToken[^>]*>([^<]+)<\/wsse:BinarySecurityToken>/
    .exec(body);
  if (!m) {
    log.debug("Leaving jwtOf(). No JWT.");
    return { token: '', header: {}, claims: {}, verified: false,
             expires: NaN, body: body };
  }
  const token = m[1].trim();
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url')
    .toString('utf8'));
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url')
    .toString('utf8'));
  let verified = false;
  try {
    verified = !!helpers.verifyOwnJws(token);
  } catch (e) {
    log.debug("Caught in jwtOf(): " + ((e && e.message) || e));
    verified = false;
  }
  const expires = /<wsu:Expires>([^<]+)<\/wsu:Expires>/.exec(body);
  log.debug("Leaving jwtOf().");
  return { token: token, header: header, claims: claims, verified: verified,
           expires: expires ? Date.parse(expires[1]) : NaN, body: body };
}

function assertionOf(r) {
  log.debug("Entering assertionOf().");
  const m = /<wst:RequestedSecurityToken>([\s\S]*?)<\/wst:RequestedSecurityToken>/
    .exec(String(r && r.body || ''));
  log.debug("Leaving assertionOf().");
  return m ? m[1] : '';
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  ['wj-alice'].forEach(function (name) {
    dir.createUser(name, { invent: false });
  });
  const app = function (identifier, fields) {
    log.debug("Entering app().");
    log.debug("Leaving app().");
    return applications.createApplication({ identifier: identifier,
      protocols: ['wstrust'], fields: fields });
  };
  const made = [
    app('wj-back', { wstrustAppliesTo: [BACK],
                     appAllowedToDelegateTo: ['wj-final'] }),
    app('wj-final', { wstrustAppliesTo: [FINAL] }),
    // A client_id unlike its identifier, so the claim is seen to be the
    // registered client_id and not the entry's name.
    app('wj-front', { oauthClientId: 'wj-front-client',
                      appAllowedToDelegateTo: ['wj-back'],
                      appDelegationSemantics: ['delegation',
                                               'impersonation'] })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the applications were created',
          JSON.stringify(made.filter(function (one) { return !one.ok; })));
  log.debug("Leaving fixtures().");
}

function inBothModes(t) {
  log.debug("Entering inBothModes().");
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const signed = function (name, audience) {
    log.debug("Entering signed().");
    log.debug("Leaving signed().");
    return saml2.buildSamlAssertion(name, audience, 5);
  };
  ['development', 'product'].forEach(function (m) {
    t.log.info('=== ' + m + ' mode ===');
    const product = m === 'product';
    const ask = function (requester, appliesTo, body, tokenType) {
      log.debug("Entering ask().");
      log.debug("Leaving ask().");
      return inMode(m, function () {
        return wstrust.handleRst(rst(signed(requester, 'https://sts.test'),
                                     appliesTo, body, tokenType),
                                 'application/soap+xml');
      });
    };
    const issuer = String(config.value('wstrust.issuer'));
    const front = product ? 'urn:sts:client:wj-front-client'
                          : 'wj-front-client';
    const back = product ? 'urn:sts:client:wj-back' : 'wj-back';
    const aliceSub = helpers.subjectForName('wj-alice');

    let r = ask('wj-alice', BACK, '', JWT);
    let j = jwtOf(r);
    t.check(r.status === 200 && j.verified && j.header.typ === 'at+jwt' &&
            j.claims.iss === issuer && j.claims.sub === aliceSub &&
            /^urn:uuid:/.test(String(j.claims.sub)) &&
            j.claims.aud === BACK && typeof j.claims.iat === 'number' &&
            typeof j.claims.jti === 'string' && j.claims.jti.length > 0 &&
            Math.abs(j.claims.exp * 1000 - j.expires) <= 2000 &&
            j.claims.client_id === undefined && j.claims.act === undefined,
            'J1 (' + m + '). a person\'s own JWT: typ at+jwt, RFC 9068\'s ' +
            'claims, exp the wst:Lifetime, no client_id (a person has no ' +
            'client) and no act', r.status + ' ' + JSON.stringify(j.header) +
            ' ' + JSON.stringify(j.claims) + ' ' + j.body.slice(0, 300));

    r = ask('wj-front', BACK, '', JWT);
    j = jwtOf(r);
    t.check(r.status === 200 && j.verified &&
            j.claims.client_id === 'wj-front-client' &&
            j.claims.act === undefined,
            'J2 (' + m + '). an application\'s own JWT: client_id its ' +
            'registered client_id', JSON.stringify(j.claims));

    r = ask('wj-front', BACK, actAs(signed('wj-alice', 'wj-front')), JWT);
    j = jwtOf(r);
    t.check(r.status === 200 && j.verified && j.header.typ === 'at+jwt' &&
            j.claims.sub === aliceSub && j.claims.aud === BACK &&
            j.claims.client_id === 'wj-front-client' &&
            JSON.stringify(j.claims.act) ===
              JSON.stringify({ sub: front, iss: issuer }),
            'J3 (' + m + '). ActAs: client_id the requester, act {sub: ' +
            front + ', iss}', JSON.stringify(j.claims) + ' ' +
            j.body.slice(0, 300));

    // The first hop as a SAML assertion, then an ActAs of it as a JWT.
    r = ask('wj-front', BACK, actAs(signed('wj-alice', 'wj-front')), '');
    const hop1 = assertionOf(r);
    const named = [];
    const re = /<del:Delegate[^>]*><saml:NameID[^>]*>([^<]+)</g;
    for (let d = re.exec(hop1); d; d = re.exec(hop1)) {
      named.push(d[1]);
    }
    t.check(r.status === 200 && JSON.stringify(named) === '["wj-front"]',
            'J6 (' + m + '). the SAML assertion an ActAs asks for is ' +
            'untouched: its Delegation Restriction names the bare ' +
            'identifier', JSON.stringify(named));
    r = ask('wj-back', FINAL, actAs(hop1), JWT);
    j = jwtOf(r);
    t.check(r.status === 200 && j.verified &&
            j.claims.client_id === 'wj-back' &&
            JSON.stringify(j.claims.act) === JSON.stringify(
              { sub: back, iss: issuer, act: { sub: front, iss: issuer } }),
            'J4 (' + m + '). an ActAs of an ActAs assertion: act nests, the ' +
            'current actor outermost, iss at every level',
            JSON.stringify(j.claims.act) + ' ' + j.body.slice(0, 300));

    r = ask('wj-front', BACK, onBehalfOf(signed('wj-alice', 'wj-front')),
            JWT);
    j = jwtOf(r);
    t.check(r.status === 200 && j.verified &&
            j.claims.sub === aliceSub &&
            j.claims.client_id === 'wj-front-client' &&
            j.claims.act === undefined,
            'J5 (' + m + '). OnBehalfOf: client_id the requester and no act',
            JSON.stringify(j.claims) + ' ' + j.body.slice(0, 300));
  });
  log.debug("Leaving inBothModes().");
}

// EVERYTHING IN A THROWAWAY REALM, removed afterwards.
function run(t) {
  log.debug("Entering run().");
  const id = 'wj-' + process.pid;
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
      inBothModes(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
  return undefined;
}

module.exports = {
  name: 'wstrust_jwt_claims',
  describe: 'the JWT a WS-Trust RST asks for: RFC 9068\'s typ and claims, ' +
            'client_id the requester\'s application, RFC 8693 act in this ' +
            'service\'s OAuth shape, and the SAML assertion untouched (#476)',
  run: run
};
