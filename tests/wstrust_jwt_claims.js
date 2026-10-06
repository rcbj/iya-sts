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
// AND A JWT THIS STS ISSUED IS ACCEPTED INSIDE OnBehalfOf / ActAs (#477):
//
//   K1. a chain in JWTs — a person's own JWT for the front end, ActAs of it
//       for the back end, ActAs of THAT for the last tier — in both modes:
//       the subject carried, `act` nesting, the register consuming each
//       JWT's `jti`; and a SAML assertion asked for with a JWT inside names
//       the JWT's actors in its Delegation Restriction;
//   K2. product refuses a JWT that does not verify, one another issuer
//       signed, an expired one (`wst:ExpiredData`) and one naming nobody,
//       each by its own code; development believes a tampered one, as it
//       believes a NameID.
//
// AND THE REGISTER'S ROW FOR EACH ACT SAYS WHAT HAPPENED (section N):
//
//   N1. an ActAs act's note says the token issued names who acted — the
//       Delegation Restriction for an assertion, the nested `act` for a
//       JWT (#478; it said no ActAs token carried that);
//   N2. an OnBehalfOf act's note says the token adds nobody;
//   N3. the consumed token's note follows the mode: VERIFIED in product
//       (an assertion's certificate and Conditions, a JWT's key, issuer and
//       exp), NOT verified in development (#479);
//   N4. the row's authorizedBy is in WS-Trust's words: the application the
//       AppliesTo names and the token inside the element, never RFC 8693's
//       "subject token" (#481).
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
const FRONT = 'https://wj-front.example';

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
                      wstrustAppliesTo: [FRONT],
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

// K. A JWT this STS issued, inside OnBehalfOf / ActAs (#477).
function jwtInside(t) {
  log.debug("Entering jwtInside().");
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const delegation = require('../common/delegation');
  const signed = function (name, audience) {
    log.debug("Entering signed().");
    log.debug("Leaving signed().");
    return saml2.buildSamlAssertion(name, audience, 5);
  };
  const bst = function (token) {
    log.debug("Entering bst().");
    log.debug("Leaving bst().");
    return '<wsse:BinarySecurityToken ValueType="' + JWT + '">' + token +
      '</wsse:BinarySecurityToken>';
  };
  ['development', 'product'].forEach(function (m) {
    t.log.info('=== K. a JWT inside ActAs, ' + m + ' mode ===');
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

    const own = jwtOf(ask('wj-alice', FRONT, '', JWT));
    let r = ask('wj-front', BACK, actAs(bst(own.token)), JWT);
    const hop1 = jwtOf(r);
    const consumed = function (jti) {
      log.debug("Entering consumed().");
      const row = (delegation.list ? delegation.list() : [])
        .filter(function (one) {
          return (one.consumed || []).some(function (c) {
            return c.identifier === jti;
          });
        });
      log.debug("Leaving consumed().");
      return row.length;
    };
    t.check(r.status === 200 && hop1.verified &&
            hop1.claims.sub === aliceSub && hop1.claims.aud === BACK &&
            JSON.stringify(hop1.claims.act) ===
              JSON.stringify({ sub: front, iss: issuer }),
            'K1a (' + m + '). ActAs of a person\'s own JWT: the subject ' +
            'carried, act naming the requester',
            r.status + ' ' + JSON.stringify(hop1.claims) + ' ' +
            hop1.body.slice(0, 400));
    r = ask('wj-back', FINAL, actAs(bst(hop1.token)), JWT);
    const hop2 = jwtOf(r);
    t.check(r.status === 200 && hop2.verified &&
            hop2.claims.sub === aliceSub &&
            JSON.stringify(hop2.claims.act) === JSON.stringify(
              { sub: back, iss: issuer, act: { sub: front, iss: issuer } }),
            'K1b (' + m + '). ActAs of an ActAs JWT: act nests, the JWT\'s ' +
            'actors read back from its act', JSON.stringify(hop2.claims.act) +
            ' ' + hop2.body.slice(0, 400));
    t.check(!delegation.list || consumed(hop1.claims.jti) >= 1,
            'K1c (' + m + '). the register records the JWT\'s jti as what ' +
            'the act consumed', String(hop1.claims.jti));
    r = ask('wj-back', FINAL, actAs(bst(hop1.token)), '');
    const named = [];
    const re = /<del:Delegate[^>]*><saml:NameID[^>]*>([^<]+)</g;
    const xml = assertionOf(r);
    for (let d = re.exec(xml); d; d = re.exec(xml)) {
      named.push(d[1]);
    }
    t.check(r.status === 200 &&
            JSON.stringify(named) === '["wj-front","wj-back"]' &&
            xml.indexOf('<saml:NameID') >= 0,
            'K1d (' + m + '). a SAML assertion asked for with a JWT inside ' +
            'names the JWT\'s actor and the requester, by bare identifier',
            JSON.stringify(named) + ' ' + r.status);

    // Refusals: a tampered JWT, another issuer, an expired one, nobody.
    const parts = own.token.split('.');
    const tamperedClaims = Object.assign({}, own.claims,
                                         { name: 'someone-else' });
    const tampered = parts[0] + '.' + Buffer.from(JSON.stringify(
      tamperedClaims)).toString('base64url') + '.' + parts[2];
    const now = Math.floor(Date.now() / 1000);
    const sign = function (claims) {
      log.debug("Entering sign().");
      log.debug("Leaving sign().");
      return helpers.signJwtAs(claims, 'RS256', null, {});
    };
    const base = { sub: aliceSub, aud: FRONT, iat: now, exp: now + 300,
                   jti: 'wj-k2-' + m, iss: issuer };
    const cases = [
      ['K2a', 'a JWT whose signature does not verify', tampered,
       'STS-WSTRUST-0026', 'InvalidRequest'],
      ['K2b', 'a JWT another issuer named',
       sign(Object.assign({}, base, { iss: 'https://elsewhere.example' })),
       'STS-WSTRUST-0026', 'InvalidRequest'],
      ['K2c', 'an expired JWT',
       sign(Object.assign({}, base, { iat: now - 7200, exp: now - 3600 })),
       'STS-WSTRUST-0027', 'ExpiredData'],
      ['K2d', 'a JWT naming nobody this directory holds',
       sign(Object.assign({}, base, {
         sub: 'urn:uuid:00000000-0000-4000-8000-000000000000' })),
       'STS-WSTRUST-0028', 'InvalidRequest']
    ];
    cases.forEach(function (one) {
      r = ask('wj-front', BACK, actAs(bst(one[2])), JWT);
      if (product) {
        t.check(r.status === 500 && r.errorCode === one[3] &&
                new RegExp('wst:' + one[4] + '<').test(String(r.body)),
                one[0] + ' (product). ' + one[1] + ' is refused: ' + one[3] +
                ', wst:' + one[4], r.status + ' ' + r.errorCode + ' ' +
                String(r.body).slice(0, 400));
      } else if (one[0] === 'K2a') {
        t.check(r.status === 200,
                'K2a (development). a tampered JWT is believed, as a NameID ' +
                'is', r.status + ' ' + String(r.body).slice(0, 300));
      }
    });
  });
  log.debug("Leaving jwtInside().");
}

// N. The register's row for each act (#478, #479, #481).
function registerRows(t) {
  log.debug("Entering registerRows().");
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const delegation = require('../common/delegation');
  const signed = function (name, audience) {
    log.debug("Entering signed().");
    log.debug("Leaving signed().");
    return saml2.buildSamlAssertion(name, audience, 5);
  };
  ['development', 'product'].forEach(function (m) {
    t.log.info('=== N. the register\'s rows, ' + m + ' mode ===');
    const ask = function (body, tokenType) {
      log.debug("Entering ask().");
      log.debug("Leaving ask().");
      return inMode(m, function () {
        return wstrust.handleRst(rst(signed('wj-front', 'https://sts.test'),
                                     BACK, body, tokenType),
                                 'application/soap+xml');
      });
    };
    // The act that produced the token in `r`: its assertion ID or jti.
    const actFor = function (r) {
      log.debug("Entering actFor().");
      const body = String(r.body || '');
      const jwt = jwtOf(r);
      const id = jwt.token ? String(jwt.claims.jti || '')
        : ((/<saml:Assertion[^>]*\bID="([^"]+)"/.exec(body) || [])[1] || '');
      const found = delegation.list().filter(function (row) {
        return (row.produced || []).some(function (one) {
          return one.identifier === id;
        });
      });
      log.debug("Leaving actFor(). " + found.length);
      return found[0] || {};
    };
    [['ActAs', '', /Delegation Restriction/],
     ['ActAs', JWT, /nested `act` claim/],
     ['OnBehalfOf', '', /the assertion names the subject and adds nobody/],
     ['OnBehalfOf', JWT, /the JWT names the subject and adds nobody/]]
      .forEach(function (one) {
        const r = ask((one[0] === 'ActAs' ? actAs : onBehalfOf)(
          signed('wj-alice', 'wj-front')), one[1]);
        const act = actFor(r);
        const consumed = String(((act.consumed || []).filter(function (c) {
          return c.kind === 'delegated token';
        })[0] || {}).note || '');
        t.check(r.status === 200 && (m === 'product'
          ? /VERIFIED against this realm's own signing certificate/
            .test(consumed)
          : /NOT verified/.test(consumed)),
                'N3 (' + m + ', ' + one[0] + '). the consumed assertion\'s ' +
                'note says whether it was verified', consumed);
        const element = one[0] === 'ActAs' ? '<wst14:ActAs>'
                                           : '<wst:OnBehalfOf>';
        const said = String(act.authorizedBy || '');
        t.check(r.status === 200 &&
                said.indexOf('", the application the AppliesTo names (the ' +
                             'token inside ' + element + ' was issued for ' +
                             '"wj-front")') > 0 &&
                said.indexOf('subject token') < 0,
                'N4 (' + m + ', ' + one[0] + '). authorizedBy names the ' +
                'AppliesTo and the token inside ' + element, said);
        t.check(r.status === 200 && one[2].test(String(act.note || '')),
                (one[0] === 'ActAs' ? 'N1' : 'N2') + ' (' + m + ', ' +
                (one[1] ? 'JWT' : 'SAML') + '). the ' + one[0] + ' act\'s ' +
                'note says what the token issued carries',
                r.status + ' ' + String(act.note));
      });
  });
  log.debug("Leaving registerRows().");
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
      jwtInside(t);
      registerRows(t);
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
            'service\'s OAuth shape, and the SAML assertion untouched ' +
            '(#476); a JWT this STS issued accepted inside OnBehalfOf / ' +
            'ActAs (#477)',
  run: run
};
