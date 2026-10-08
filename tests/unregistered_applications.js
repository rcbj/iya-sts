// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: unregistered_applications.js
//
// ===========================================================================
// IN PRODUCT, AN APPLICATION NOBODY REGISTERED GETS NOTHING (#496).
//
// rcbj, 2026-10-06: in product mode an application that is not registered
// gets nothing but a 404 or its protocol's own "unknown application" error,
// in every protocol, and nothing is learned from it. "Registered" is #494's
// word: `appRegisteredBy` on the entry (`IssuerNames.registeredApplication()`)
// — an entry a development `seen()` filed is a sighting, not a registration.
//
//   U1. the mode predicate `issuesToUnregisteredApplications()` answers per
//       mode, and the `unregistered-applications` row is in mode.report();
//   U2. WS-Trust, product, every token type (SAML 2.0, SAML 1.1, JWT): an
//       AppliesTo nobody registered, one only SEEN, and one that resolves
//       through `wstrustAppliesTo` to no registered application are
//       wst:InvalidScope (STS-WSTRUST-0030); no AppliesTo and an empty one
//       are wst:InvalidRequest (STS-WSTRUST-0031); a registered one is
//       issued;
//   U3. WS-Trust, product, OnBehalfOf and ActAs: the same refusals;
//   U4. nothing is recorded by a refusal: no /admin/users row for the
//       requester, no register entry for the AppliesTo, no new sighting on
//       a seen-only entry, no delegation act;
//   U5. Validate and Cancel issue nothing and are not asked;
//   U6. development is unchanged: an unregistered AppliesTo and none are
//       issued, and the sighting files the application;
//   U7. WS-Federation: product refuses a wsignin1.0 whose wtrealm names no
//       registered relying party, or only a seen one, with a 404 page
//       (STS-WSFED-0021) before the sign-in screen and writes nothing; a
//       registered wtrealm passes the check; development is unchanged;
//   O1. OAuth, product: an authorization request naming a client_id nobody
//       registered, one only seen, or none is a 400 that is not redirected
//       (STS-OAUTH-0947 / 0948); a registered one passes the check;
//       development asks nothing;
//   O2. OAuth, product: a token request naming an unregistered or seen-only
//       client is 401 invalid_client (STS-OAUTH-0949) and writes nothing on
//       the seen-only entry; development is not refused for it;
//   O3. RFC 8693: the delegation policy resolves a seen-only target to
//       nothing in product (its unregistered-target) and to the entry in
//       development; an exchanged assertion's audience naming a seen-only
//       entry is no relying party in product;
//   S1. SAML 2.0, product: an AuthnRequest from an unregistered or a
//       seen-only Issuer is a 403 page (STS-SAML-0103) and writes nothing on
//       the seen-only entry; a registered one passes the check; development
//       answers both;
//   S2. a LogoutRequest from an unregistered Issuer ends nothing
//       (STS-SAML-0104);
//   S3. the per-SP metadata path: a seen-only service provider is a 404
//       in product (STS-SAML-0082), a registered one is answered;
//   S4. SAML 1.1: a browser flow for an unregistered or seen-only relying
//       party is a 403 page (STS-SAML-0105);
//   S5. a Metadata Query lookup a request starts for a seen-only entityID
//       is gated as for an unknown one in product (STS-SAML-0080);
//   G1. GNAP, product: a proved key, or an instance identifier, belonging
//       to an entry development created on first sight is 401
//       invalid_client (STS-GNAP-0902) and the entry is not sighted again;
//       a registered client's key is identified; development identifies
//       the seen-only one.
//
// IN PROCESS, in a throwaway realm: the cases are product's and
// development's, and a job over HTTP runs in one mode.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const stats = require('../common/admin_stats');
const mode = require('../common/mode');
const errorCodes = require('../common/error_codes');
// Arms the issuance gate, which a WS-Trust Issue asks.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({
  name: 'unregistered_applications',
  level: process.env.LOG_LEVEL || 'info' });

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const SAML2 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-' +
  'profile-1.1#SAMLV2.0';
const SAML11 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-' +
  'profile-1.1#SAMLV1.1';
const JWT = 'urn:ietf:params:oauth:token-type:jwt';
const TOKEN_TYPES = [['SAML 2.0', SAML2], ['SAML 1.1', SAML11],
                     ['JWT', JWT]];
const REG_URL = 'https://ua-registered.example';
const BASE = 'https://sts.ua.example';

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

// An RST: `appliesTo` undefined for none, '' for an empty element.
function rst(opts) {
  log.debug("Entering rst().");
  const o = opts || {};
  let applies = '';
  if (o.appliesTo !== undefined) {
    applies = '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/' +
      '2004/09/policy">' + (o.appliesTo
        ? '<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/' +
          'addressing"><wsa:Address>' + o.appliesTo + '</wsa:Address>' +
          '</wsa:EndpointReference>'
        : '') + '</wsp:AppliesTo>';
  }
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
    'wssecurity-secext-1.0.xsd"><s:Header>' +
    (o.security ? '<wsse:Security>' + o.security + '</wsse:Security>' : '') +
    '</s:Header><s:Body><wst:RequestSecurityToken xmlns:wst="' + WST + '">' +
    '<wst:RequestType>' + WST + '/' + (o.op || 'Issue') +
    '</wst:RequestType>' + (o.tokenType ? '<wst:TokenType>' + o.tokenType +
      '</wst:TokenType>' : '') + applies + (o.body || '') +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function signed(name, audience) {
  log.debug("Entering signed().");
  const saml2 = require('../saml/saml2');
  log.debug("Leaving signed().");
  return saml2.buildSamlAssertion(name, audience || BASE + '/sts', 5);
}

function usernameToken(user) {
  log.debug("Entering usernameToken().");
  log.debug("Leaving usernameToken().");
  return '<wsse:UsernameToken><wsse:Username>' + user + '</wsse:Username>' +
    '<wsse:Password>anything</wsse:Password></wsse:UsernameToken>';
}

function ask(m, opts) {
  log.debug("Entering ask().");
  const wstrust = require('../ws-trust/wstrust');
  const r = inMode(m, function () {
    return wstrust.handleRst(rst(opts), 'application/soap+xml',
                             { base: BASE });
  });
  log.debug("Leaving ask().");
  return { status: r.status, errorCode: r.errorCode || '',
           body: String(r.body) };
}

// wst:<code> as SOAP 1.2's Subcode.
function fault(r, code) {
  log.debug("Entering fault().");
  log.debug("Leaving fault().");
  return r.status === 500 &&
    new RegExp('<soap:Subcode><soap:Value xmlns:wst="[^"]*">wst:' + code +
               '</soap:Value>').test(r.body);
}

function brief(r) {
  log.debug("Entering brief().");
  log.debug("Leaving brief().");
  return r.status + ' ' + r.errorCode + ' ' + r.body.slice(0, 300);
}

function userRow(name) {
  log.debug("Entering userRow().");
  const out = stats.userRows().some(function (one) {
    return String((one && (one.name || one.key)) || '').toLowerCase() ===
      String(name).toLowerCase();
  });
  log.debug("Leaving userRow().");
  return out;
}

function modeRow(t) {
  log.debug("Entering modeRow().");
  const row = mode.report().requirements.filter(function (one) {
    return one.id === 'unregistered-applications';
  })[0];
  const dev = inMode('development', mode.issuesToUnregisteredApplications);
  const prod = inMode('product', mode.issuesToUnregisteredApplications);
  t.check(dev === true && prod === false && !!row &&
          /STS-WSTRUST-0030/.test(row.product) &&
          /STS-WSFED-0021/.test(row.product) && !!row.development &&
          /wstrust/.test(row.where) && /wsfed/.test(row.where),
          'U1. issuesToUnregisteredApplications() is true in development, ' +
          'false in product, and its requirement row is reported',
          JSON.stringify([dev, prod, row]));
  log.debug("Leaving modeRow().");
}

function wstrustRefusals(t, seenOnly, aliased) {
  log.debug("Entering wstrustRefusals().");
  const unknown = 'https://ua-nobody-' + process.pid + '.example';
  TOKEN_TYPES.forEach(function (pair) {
    const label = pair[0];
    const tokenType = pair[1];
    const sec = signed('ua-alice');
    const cases = [
      ['an AppliesTo nobody registered', unknown, 'STS-WSTRUST-0030',
       'InvalidScope'],
      ['an AppliesTo only seen', seenOnly, 'STS-WSTRUST-0030',
       'InvalidScope'],
      ['an AppliesTo on an unregistered entry\'s wstrustAppliesTo', aliased,
       'STS-WSTRUST-0030', 'InvalidScope'],
      ['no AppliesTo', undefined, 'STS-WSTRUST-0031', 'InvalidRequest'],
      ['an empty AppliesTo', '', 'STS-WSTRUST-0031', 'InvalidRequest']
    ];
    cases.forEach(function (c) {
      const r = ask('product', { security: sec, tokenType: tokenType,
                                 appliesTo: c[1] });
      t.check(r.errorCode === c[2] && fault(r, c[3]),
              'U2. product, ' + label + ': ' + c[0] + ' is wst:' + c[3] +
              ' (' + c[2] + ')', brief(r));
    });
    const ok = ask('product', { security: sec, tokenType: tokenType,
                                appliesTo: REG_URL });
    t.check(ok.status === 200 && !ok.errorCode,
            'U2b. product, ' + label + ': a registered AppliesTo is issued',
            brief(ok));
  });
  log.debug("Leaving wstrustRefusals().");
  return unknown;
}

function delegated(t, seenOnly) {
  log.debug("Entering delegated().");
  const unknown = 'https://ua-nobody-delegated-' + process.pid + '.example';
  [['ActAs', function (inner) {
    return '<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/' +
      'ws-trust/200802">' + inner + '</wst14:ActAs>';
  }], ['OnBehalfOf', function (inner) {
    return '<wst:OnBehalfOf>' + inner + '</wst:OnBehalfOf>';
  }]].forEach(function (pair) {
    const body = pair[1](signed('ua-alice', 'ua-front'));
    TOKEN_TYPES.forEach(function (tt) {
      [[unknown, 'STS-WSTRUST-0030', 'InvalidScope'],
       [seenOnly, 'STS-WSTRUST-0030', 'InvalidScope'],
       [undefined, 'STS-WSTRUST-0031', 'InvalidRequest']]
        .forEach(function (c) {
          const r = ask('product', { security: signed('ua-front'),
                                     body: body, tokenType: tt[1],
                                     appliesTo: c[0] });
          t.check(r.errorCode === c[1] && fault(r, c[2]),
                  'U3. product, ' + pair[0] + ', ' + tt[0] + ', ' +
                  (c[0] === undefined ? 'no AppliesTo'
                    : c[0] === seenOnly ? 'a seen-only AppliesTo'
                      : 'an unregistered AppliesTo') + ': ' + c[1],
                  brief(r));
        });
    });
  });
  log.debug("Leaving delegated().");
}

function nothingRecorded(t, seenOnly) {
  log.debug("Entering nothingRecorded().");
  const delegation = require('../common/delegation');
  const requester = 'ua-requester-' + process.pid;
  const unknown = 'https://ua-unrecorded-' + process.pid + '.example';
  // A requester who WOULD authenticate — an entry, and an assertion this
  // realm signed — so a refusal asked after authenticate() would leave
  // their row; and one presenting a UsernameToken.
  dir.createUser(requester, { invent: false });
  // Creating the entry may list them already; what a refusal must not do
  // is CHANGE their row — no authentication counted, nothing seen.
  // The assertions are minted FIRST: minting one is an artifact on the
  // row, and the test's own minting is not what is being held.
  const creds = [0, 1, 2, 3, 4].map(function () {
    return signed(requester);
  });
  const rowBefore = JSON.stringify(stats.userRow(requester));
  const before = applications.get(seenOnly);
  const acts = delegation.list().length;
  const results = [
    ask('product', { security: creds[0], appliesTo: unknown }),
    ask('product', { security: creds[1] }),
    ask('product', { security: creds[2], appliesTo: seenOnly }),
    ask('product', { security: usernameToken(requester),
                     appliesTo: unknown }),
    ask('product', { security: creds[3],
                     body: '<wst:OnBehalfOf>' + signed('ua-alice') +
                       '</wst:OnBehalfOf>',
                     appliesTo: unknown })
  ];
  const after = applications.get(seenOnly);
  t.check(results.every(function (r) {
    return r.errorCode === 'STS-WSTRUST-0030' ||
      r.errorCode === 'STS-WSTRUST-0031';
  }) && JSON.stringify(stats.userRow(requester)) === rowBefore &&
          !applications.get(unknown) &&
          before && after &&
          after.authentications === before.authentications &&
          after.lastAt === before.lastAt &&
          delegation.list().length === acts,
          'U4. a refusal records nothing: no /admin/users row for the ' +
          'requester, no entry for the AppliesTo, no new sighting on the ' +
          'seen-only entry, no delegation act',
          JSON.stringify({ codes: results.map(function (r) {
            return r.errorCode;
          }), row: [rowBefore, JSON.stringify(stats.userRow(requester))],
          entry: !!applications.get(unknown),
          before: before && [before.authentications, before.lastAt],
          after: after && [after.authentications, after.lastAt],
          acts: [acts, delegation.list().length] }));
  // The control: the same requester, for a registered AppliesTo, is
  // issued and IS recorded — so the absence above is the refusal's.
  const control = ask('product', { security: creds[4],
                                   appliesTo: REG_URL });
  t.check(control.status === 200 && userRow(requester) &&
          JSON.stringify(stats.userRow(requester)) !== rowBefore,
          'U4b. the control: the same requester for a registered AppliesTo ' +
          'is issued and its /admin/users row changes', brief(control));
  log.debug("Leaving nothingRecorded().");
}

function notAsked(t) {
  log.debug("Entering notAsked().");
  const validate = ask('product', { security: signed('ua-alice'),
    op: 'Validate', body: '<wst:ValidateTarget>' + signed('ua-alice') +
      '</wst:ValidateTarget>' });
  const cancel = ask('product', { security: signed('ua-alice'),
                                  op: 'Cancel' });
  t.check(validate.status === 200 && cancel.status === 200,
          'U5. product: Validate and Cancel, which issue nothing, are not ' +
          'asked for an AppliesTo', brief(validate) + ' | ' + brief(cancel));
  log.debug("Leaving notAsked().");
}

function development(t, unknownFromProduct) {
  log.debug("Entering development().");
  const fresh = 'https://ua-dev-' + process.pid + '.example';
  const results = TOKEN_TYPES.map(function (tt) {
    return [ask('development', { security: signed('ua-alice'),
                                 tokenType: tt[1], appliesTo: fresh }),
            ask('development', { security: signed('ua-alice'),
                                 tokenType: tt[1] })];
  });
  const filed = applications.get(fresh);
  t.check(results.every(function (pair) {
    return pair[0].status === 200 && pair[1].status === 200;
  }) && !!filed && !filed.registeredBy && !applications.get(
    unknownFromProduct),
          'U6. development is unchanged: an unregistered AppliesTo and ' +
          'none are issued for every token type, and the sighting files ' +
          'the application (unregistered); product filed nothing',
          JSON.stringify(results.map(function (pair) {
            return [pair[0].status, pair[1].status];
          })) + ' ' + JSON.stringify(filed && filed.registeredBy));
  log.debug("Leaving development().");
}

// A chainable stand-in for express's response, recording what was sent.
function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { statusCode: 200, headers: {}, body: '', locals: {} };
  res.status = function (n) {
    res.statusCode = n;
    return res;
  };
  res.type = function () {
    return res;
  };
  res.set = function (k, v) {
    res.headers[String(k).toLowerCase()] = v;
    return res;
  };
  res.setHeader = res.set;
  res.getHeader = function (k) {
    return res.headers[String(k).toLowerCase()];
  };
  res.cookie = function () {
    return res;
  };
  res.redirect = function (n, where) {
    res.statusCode = typeof n === 'number' ? n : 302;
    res.headers.location = String(typeof n === 'number' ? where : n);
    return res;
  };
  res.send = function (b) {
    res.body = String(b);
    return res;
  };
  res.end = res.send;
  log.debug("Leaving fakeRes().");
  return res;
}

function wsfed(t) {
  log.debug("Entering wsfed().");
  const module = require('../ws-federation/wsfed');
  const instance = new module.WsFederation(module.WsFederation.defaultDeps());
  let handler = null;
  instance.registerRoutes({
    get: function (path, fn) {
      if (path === '/wsfed') {
        handler = fn;
      }
    },
    post: function () {},
    contentSecurityPolicy: function () {
      return '';
    }
  });
  const signIn = function (m, wtrealm) {
    log.debug("Entering signIn(). " + m + ' ' + wtrealm);
    const res = fakeRes();
    const req = { method: 'GET', path: '/wsfed', url: '/wsfed',
                  originalUrl: '/wsfed',
                  query: { wa: 'wsignin1.0', wtrealm: wtrealm },
                  headers: { host: 'sts.ua.example' }, cookies: {},
                  protocol: 'https', secure: true, ip: '127.0.0.1',
                  socket: {},
                  get: function (k) {
                    return String(k).toLowerCase() === 'host'
                      ? 'sts.ua.example' : undefined;
                  } };
    let threw = '';
    try {
      inMode(m, function () {
        return handler(req, res);
      });
    } catch (e) {
      // Development goes on to the sign-in screen, which this stand-in
      // request may not carry everything for; what matters here is only
      // that the refusal was not answered.
      log.debug("Caught in signIn(): " + ((e && e.message) || e));
      threw = String((e && e.message) || e);
    }
    log.debug("Leaving signIn().");
    return { status: res.statusCode, code: errorCodes.codeOf(res) || '',
             threw: threw, body: res.body.slice(0, 300),
             location: res.headers.location || '' };
  };
  const unknown = 'urn:ua-nobody-' + process.pid;
  const seenRealm = 'urn:ua-seen-rp-' + process.pid;
  inMode('development', function () {
    return applications.seen({ identifier: seenRealm,
                               kind: 'wsfed-relying-party',
                               protocol: 'WS-Federation',
                               note: 'filed by ' + __filename });
  });
  const seenBefore = applications.get(seenRealm);
  const refused = [signIn('product', unknown), signIn('product', seenRealm)];
  const seenAfter = applications.get(seenRealm);
  t.check(refused.every(function (r) {
    return r.status === 404 && r.code === 'STS-WSFED-0021' &&
      /not registered/.test(r.body) && !r.location;
  }) && !applications.get(unknown) && !!seenBefore && !!seenAfter &&
          seenAfter.lastAt === seenBefore.lastAt,
          'U7. product: a wtrealm nobody registered, and one only seen, is ' +
          'a 404 page (STS-WSFED-0021) before the sign-in screen, and ' +
          'nothing is written', JSON.stringify(refused));
  const registered = signIn('product', 'ua-rp');
  t.check(registered.code !== 'STS-WSFED-0021' && registered.status !== 404,
          'U7b. product: a registered wtrealm passes the check',
          JSON.stringify(registered));
  const dev = signIn('development', unknown);
  t.check(dev.code !== 'STS-WSFED-0021' && dev.status !== 404,
          'U7c. development: a wtrealm nobody registered is not refused',
          JSON.stringify(dev));
  log.debug("Leaving wsfed().");
}

// A request enough for the OAuth server's two doors: the query for the
// authorization endpoint, a form body for the token endpoint.
function oauthReq(query, form) {
  log.debug("Entering oauthReq().");
  const headers = { host: 'sts.ua.example',
                    'content-type': 'application/x-www-form-urlencoded' };
  log.debug("Leaving oauthReq().");
  return { method: form ? 'POST' : 'GET', path: '/oauth2/token',
           url: '/oauth2/token', originalUrl: '/oauth2/token',
           query: query || {}, headers: headers, cookies: {},
           body: form ? new URLSearchParams(form).toString() : '',
           protocol: 'https', secure: true, ip: '127.0.0.1',
           socket: { remoteAddress: '127.0.0.1' },
           get: function (k) {
             return headers[String(k).toLowerCase()];
           } };
}

async function oauth(t, seenOnlyClient) {
  log.debug("Entering oauth().");
  const oauth2 = require('../oauth-oidc/oauth2');
  const server = new oauth2.OAuth2Server(oauth2.OAuth2Server.defaultDeps());
  const vet = function (m, clientId) {
    log.debug("Entering vet(). " + m + ' ' + clientId);
    const query = { response_type: 'code', scope: 'openid',
                    redirect_uri: 'https://ua-client.example/cb',
                    code_challenge: 'x'.repeat(43),
                    code_challenge_method: 'S256' };
    if (clientId) {
      query.client_id = clientId;
    }
    const out = inMode(m, function () {
      return server.vetAuthorizationRequest(oauthReq(query));
    });
    log.debug("Leaving vet().");
    return out;
  };
  const unknown = 'ua-nobody-client-' + process.pid;
  const product = [vet('product', unknown), vet('product', seenOnlyClient),
                   vet('product', '')];
  t.check(product[0].code === 'STS-OAUTH-0947' &&
          product[0].error === 'invalid_client' &&
          product[0].redirect === false && product[0].status === 400 &&
          product[1].code === 'STS-OAUTH-0947' &&
          product[2].code === 'STS-OAUTH-0948' &&
          product[2].error === 'invalid_request' && !product[2].redirect,
          'O1. product: an authorization request naming an unregistered ' +
          'client, a seen-only one, or none is a 400 on this server, never ' +
          'redirected (STS-OAUTH-0947 / 0948)', JSON.stringify(product));
  const registered = vet('product', 'ua-oauth');
  const dev = vet('development', unknown);
  t.check(registered.code !== 'STS-OAUTH-0947' &&
          dev.code !== 'STS-OAUTH-0947' && dev.code !== 'STS-OAUTH-0948',
          'O1b. a registered client passes the check in product, and ' +
          'development asks nothing', JSON.stringify([registered, dev]));

  const token = async function (m, clientId) {
    log.debug("Entering token(). " + m + ' ' + clientId);
    const res = fakeRes();
    config.setOverride('global.mode', m);
    try {
      await server.tokenGrant(oauthReq({}, {
        grant_type: 'client_credentials', client_id: clientId,
        client_secret: 'not-the-secret-0123456789' }), res);
    } finally {
      config.clearOverride('global.mode');
    }
    log.debug("Leaving token().");
    return { status: res.statusCode, code: errorCodes.codeOf(res) || '',
             body: res.body.slice(0, 300) };
  };
  const before = applications.get(seenOnlyClient);
  const refused = [await token('product', unknown),
                   await token('product', seenOnlyClient)];
  const after = applications.get(seenOnlyClient);
  t.check(refused.every(function (r) {
    return r.status === 401 && r.code === 'STS-OAUTH-0949' &&
      /invalid_client/.test(r.body);
  }) && before && after &&
          // What a refused request would have written is a sighting, and a
          // sighting goes to the OBSERVED list, never the declared one (#289).
          JSON.stringify(after.fields.oauthGrantTypeObserved || null) ===
            JSON.stringify(before.fields.oauthGrantTypeObserved || null) &&
          JSON.stringify(after.fields.oauthGrantType || null) ===
            JSON.stringify(before.fields.oauthGrantType || null) &&
          after.lastAt === before.lastAt && !applications.get(unknown),
          'O2. product: a token request naming an unregistered or seen-only ' +
          'client is 401 invalid_client (STS-OAUTH-0949), and nothing is ' +
          'written', JSON.stringify(refused));
  const devToken = await token('development', unknown);
  t.check(devToken.code !== 'STS-OAUTH-0949',
          'O2b. development is not refused for an unregistered client',
          JSON.stringify(devToken));

  const policy = require('../common/delegation_policy');
  const resolved = ['product', 'development'].map(function (m) {
    return inMode(m, function () {
      return [policy.resolveTarget(seenOnlyClient, 'audience'),
              policy.resolveTarget('ua-oauth', 'audience')];
    });
  });
  const exchange = require('../oauth-oidc/exchange_assertions')
    .ExchangeAssertions;
  const named = ['product', 'development'].map(function (m) {
    return inMode(m, function () {
      return [exchange.applicationNamed(seenOnlyClient),
              exchange.applicationNamed('ua-oauth')];
    });
  });
  t.check(resolved[0][0] === '' && resolved[0][1] === 'ua-oauth' &&
          resolved[1][0] === seenOnlyClient &&
          resolved[1][1] === 'ua-oauth' &&
          named[0][0] === '' && named[0][1] === 'ua-oauth' &&
          named[1][0] === seenOnlyClient,
          'O3. RFC 8693: a seen-only target resolves to nothing in product ' +
          '(the policy\'s unregistered-target) and to its entry in ' +
          'development; an exchanged assertion\'s audience likewise',
          JSON.stringify({ resolved: resolved, named: named }));
  log.debug("Leaving oauth().");
}

// The routes a module registers, on a stand-in app: path -> handler.
function routesOf(module) {
  log.debug("Entering routesOf().");
  const routes = {};
  const add = function (method) {
    return function (path, fn) {
      routes[method + ' ' + path] = fn;
    };
  };
  module.registerRoutes({ get: add('GET'), post: add('POST'),
                          all: add('ALL'), use: function () {},
                          contentSecurityPolicy: function () {
                            return '';
                          } });
  log.debug("Leaving routesOf().");
  return routes;
}

async function ask2(handler, m, query) {
  log.debug("Entering ask2().");
  const res = fakeRes();
  const req = oauthReq(query);
  req.params = {};
  config.setOverride('global.mode', m);
  let threw = '';
  try {
    await Promise.resolve(handler(req, res));
  } catch (e) {
    // A development request goes on to the sign-in screen, which this
    // stand-in may not carry everything for; what is held here is only
    // whether the refusal answered.
    log.debug("Caught in ask2(): " + ((e && e.message) || e));
    threw = String((e && e.message) || e);
  } finally {
    config.clearOverride('global.mode');
  }
  log.debug("Leaving ask2().");
  return { status: res.statusCode, code: errorCodes.codeOf(res) || '',
           threw: threw, body: res.body.slice(0, 300) };
}

function deflated(xml) {
  log.debug("Entering deflated().");
  log.debug("Leaving deflated().");
  return require('zlib').deflateRawSync(Buffer.from(xml)).toString('base64');
}

async function saml(t, seenSp) {
  log.debug("Entering saml().");
  const routes2 = routesOf(require('../saml/saml2_sso'));
  const routes11 = routesOf(require('../saml/saml11_sso'));
  const authn = function (issuer) {
    return { SAMLRequest: deflated('<samlp:AuthnRequest ' +
      'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
      'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_ua1" ' +
      'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
      '<saml:Issuer>' + issuer + '</saml:Issuer></samlp:AuthnRequest>') };
  };
  const unknown = 'https://ua-nobody-sp-' + process.pid + '.example';
  const sso = routes2['GET /saml2/sso'];
  const before = applications.get(seenSp);
  const refused = [await ask2(sso, 'product', authn(unknown)),
                   await ask2(sso, 'product', authn(seenSp))];
  const after = applications.get(seenSp);
  t.check(refused.every(function (r) {
    return r.status === 403 && r.code === 'STS-SAML-0103' &&
      /not registered/.test(r.body);
  }) && !applications.get(unknown) && before && after &&
          after.lastAt === before.lastAt &&
          JSON.stringify(after.fields.samlAuthnRequestVerification || null) ===
            JSON.stringify(before.fields.samlAuthnRequestVerification || null),
          'S1. product: an AuthnRequest from an unregistered or seen-only ' +
          'Issuer is a 403 page (STS-SAML-0103), and nothing is written',
          JSON.stringify(refused));
  const passes = [await ask2(sso, 'product', authn('ua-sp')),
                  await ask2(sso, 'development', authn(unknown))];
  t.check(passes.every(function (r) {
    return r.code !== 'STS-SAML-0103';
  }), 'S1b. a registered service provider passes the check in product, ' +
      'and development answers an unregistered one',
          JSON.stringify(passes));

  const slo = routes2['GET /saml2/slo'];
  const logout = await ask2(slo, 'product', { SAMLRequest: deflated(
    '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:' +
    'protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
    'ID="_ua2" Version="2.0" IssueInstant="' + new Date().toISOString() +
    '"><saml:Issuer>' + unknown + '</saml:Issuer><saml:NameID>ua-alice' +
    '</saml:NameID></samlp:LogoutRequest>') });
  t.check(logout.status === 403 && logout.code === 'STS-SAML-0104',
          'S2. product: a LogoutRequest from an unregistered Issuer ends ' +
          'nothing (STS-SAML-0104)', JSON.stringify(logout));

  const metadata = routes2['GET /saml2/metadata/:sp'];
  const askMetadata = async function (sp) {
    log.debug("Entering askMetadata().");
    const res = fakeRes();
    const req = oauthReq({});
    req.params = { sp: sp };
    config.setOverride('global.mode', 'product');
    try {
      await Promise.resolve(metadata(req, res));
    } finally {
      config.clearOverride('global.mode');
    }
    log.debug("Leaving askMetadata().");
    return { status: res.statusCode, code: errorCodes.codeOf(res) || '' };
  };
  const md = [await askMetadata(seenSp), await askMetadata('ua-sp')];
  t.check(md[0].status === 404 && md[0].code === 'STS-SAML-0082' &&
          md[1].status === 200,
          'S3. product: /saml2/metadata/{sp} is a 404 for a seen-only ' +
          'service provider (STS-SAML-0082) and answered for a registered ' +
          'one', JSON.stringify(md));

  const sso11 = routes11['GET /saml11/sso'];
  const flow = function (rp) {
    return { providerId: rp, shire: 'https://ua-rp11.example/acs',
             target: 'https://ua-rp11.example/', time:
               String(Math.floor(Date.now() / 1000)) };
  };
  const refused11 = [await ask2(sso11, 'product', flow(unknown)),
                     await ask2(sso11, 'product', flow(seenSp))];
  t.check(refused11.every(function (r) {
    return r.status === 403 && r.code === 'STS-SAML-0105';
  }), 'S4. product: a SAML 1.1 flow for an unregistered or seen-only ' +
      'relying party is a 403 page (STS-SAML-0105)',
          JSON.stringify(refused11));

  const spMetadata = require('../saml/sp_metadata');
  config.setOverride('saml2.mdqBaseUrl', 'https://mdq.ua.example/');
  config.setOverride('global.mode', 'product');
  let gated;
  try {
    gated = await spMetadata.mdqImport(seenSp, { origin: 'request' });
  } finally {
    config.clearOverride('global.mode');
    config.clearOverride('saml2.mdqBaseUrl');
  }
  t.check(gated && gated.ok === false &&
          errorCodes.codeOf(gated) === 'STS-SAML-0080',
          'S5. product: a Metadata Query lookup a request starts for a ' +
          'seen-only entityID is gated as for an unknown one ' +
          '(STS-SAML-0080)', JSON.stringify(gated));
  log.debug("Leaving saml().");
}

async function gnap(t) {
  log.debug("Entering gnap().");
  const nodeCrypto = require('crypto');
  const grantsModule = require('../gnap/gnap_grants');
  const keys = require('../gnap/gnap_keys');
  // A GNAP JWK carries alg and kid (STS-GNAP-0012 otherwise).
  const jwkOf = function () {
    return Object.assign(nodeCrypto.generateKeyPairSync('ed25519').publicKey
      .export({ format: 'jwk' }), { alg: 'EdDSA',
                                    kid: nodeCrypto.randomUUID() });
  };
  const seenJwk = jwkOf();
  const regJwk = jwkOf();
  const seenKey = { proof: 'httpsig', jwk: seenJwk };
  const regKey = { proof: 'httpsig', jwk: regJwk };
  const seenId = keys.describe(seenKey).identity;
  const seenApp = 'ua-gnap-seen-' + process.pid;
  const instance = 'ua-gnap-instance-' + process.pid;
  inMode('development', function () {
    return applications.seen({ identifier: seenApp, kind: 'gnap-client',
      protocol: 'GNAP', counts: false,
      fields: { gnapKey: JSON.stringify(seenJwk), gnapKeyIdentity: seenId,
                gnapInstanceId: instance },
      note: 'filed by ' + __filename });
  });
  const reg = applications.createApplication({ identifier: 'ua-gnap',
    protocols: ['gnap'], fields: { gnapKey: JSON.stringify(regKey) } });
  t.check(reg && reg.ok && !!applications.get(seenApp) &&
          !applications.get(seenApp).registeredBy,
          'precondition: a seen-only and a registered GNAP client',
          JSON.stringify(reg));
  // THE PROOF IS STUBBED: what is held is who the key belongs to, which
  // is decided after the proof verifies.
  const deps = grantsModule.GnapGrants.defaultDeps();
  deps.proof = Object.assign({}, deps.proof, {
    verifyRequestOnce: function () {
      return Promise.resolve({ ok: true });
    } });
  const grants = new grantsModule.GnapGrants(deps);
  const identify = async function (m, member) {
    log.debug("Entering identify(). " + m);
    config.setOverride('global.mode', m);
    try {
      const out = await grants.identifyCaller(oauthReq({}), {}, member,
                                              'gnap-client');
      log.debug("Leaving identify().");
      return { ok: !!out.ok, code: out.errorCode || '',
               error: out.gnapError || '', status: out.status || 0,
               app: out.app ? out.app.identifier : '' };
    } finally {
      config.clearOverride('global.mode');
    }
  };
  const before = applications.get(seenApp);
  const refused = [await identify('product', { key: seenKey }),
                   await identify('product', { reference: instance })];
  const after = applications.get(seenApp);
  t.check(refused.every(function (r) {
    return !r.ok && r.code === 'STS-GNAP-0902' &&
      r.error === 'invalid_client' && r.status === 401;
  }) && before && after && after.lastAt === before.lastAt,
          'G1. product: a key and an instance identifier of a client ' +
          'development created on first sight are 401 invalid_client ' +
          '(STS-GNAP-0902), and the entry is not sighted again',
          JSON.stringify(refused));
  const served = [await identify('product', { key: regKey }),
                  await identify('development', { key: seenKey })];
  t.check(served[0].ok && served[0].app === 'ua-gnap' && served[1].ok &&
          served[1].app === seenApp,
          'G1b. product identifies a registered client\'s key, and ' +
          'development the seen-only one', JSON.stringify(served));
  log.debug("Leaving gnap().");
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  ['ua-alice', 'ua-front'].forEach(function (name) {
    dir.createUser(name, { invent: false });
  });
  const made = [
    applications.createApplication({ identifier: 'ua-app',
      protocols: ['wstrust'], fields: { wstrustAppliesTo: [REG_URL] } }),
    applications.createApplication({ identifier: 'ua-front',
      protocols: ['wstrust'],
      fields: { oauthClientId: 'ua-front',
                appAllowedToDelegateTo: ['ua-app'] } }),
    applications.createApplication({ identifier: 'ua-rp',
      protocols: ['wsfed'],
      fields: { wsfedReplyUrl: [BASE + '/wsfed/rp'] } }),
    applications.createApplication({ identifier: 'ua-oauth',
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: 'ua-oauth',
                oauthRedirectUri: ['https://ua-client.example/cb'],
                oauthTokenEndpointAuthMethod: 'none',
                oauthGrantType: ['authorization_code'] } }),
    applications.createApplication({ identifier: 'ua-sp',
      protocols: ['saml2', 'saml11'], fields: {} })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the applications were registered',
          JSON.stringify(made));
  // A SEEN-ONLY AppliesTo: development issues a token for it, which files an
  // entry with no appRegisteredBy.
  const seenOnly = 'https://ua-seen-' + process.pid + '.example';
  const first = ask('development', { security: signed('ua-alice'),
                                     appliesTo: seenOnly });
  const filed = applications.get(seenOnly);
  t.check(first.status === 200 && filed && !filed.registeredBy,
          'precondition: development filed ' + seenOnly + ' unregistered',
          brief(first));
  // AN UNREGISTERED ENTRY WHOSE wstrustAppliesTo NAMES ANOTHER ADDRESS — the
  // way forAppliesTo() resolves — with no appRegisteredBy: a sighting of
  // its own identifier carrying the field.
  const aliased = 'https://ua-aliased-' + process.pid + '.example';
  inMode('development', function () {
    return applications.seen({ identifier: 'ua-sighted-' + process.pid,
                               kind: 'wstrust-relying-party',
                               protocol: 'WS-Trust',
                               fields: { wstrustAppliesTo: aliased },
                               note: 'filed by ' + __filename });
  });
  // A SEEN-ONLY OAuth client: a development sighting, with the redirect URI
  // it was observed at.
  const seenClient = 'ua-seen-client-' + process.pid;
  inMode('development', function () {
    return applications.seen({ identifier: seenClient,
                               kind: 'oauth2-client',
                               protocol: 'OAuth 2.0 / OIDC',
                               // OBSERVED, as the service files it (#289).
                               fields: { oauthClientId: seenClient,
                                         oauthGrantTypeObserved:
                                           'authorization_code',
                                         oauthRedirectUri:
                                           'https://ua-client.example/cb' },
                               note: 'filed by ' + __filename });
  });
  t.check(!!applications.get(seenClient) &&
          !applications.get(seenClient).registeredBy,
          'precondition: development filed ' + seenClient + ' unregistered');
  // A SEEN-ONLY SAML service provider and relying party.
  const seenSp = 'https://ua-seen-sp-' + process.pid + '.example';
  inMode('development', function () {
    return applications.seen({ identifier: seenSp,
                               kind: ['saml2-service-provider',
                                      'saml11-relying-party'],
                               protocol: 'SAML 2.0',
                               note: 'filed by ' + __filename });
  });
  log.debug("Leaving fixtures().");
  return { seenOnly: seenOnly, aliased: aliased, seenClient: seenClient,
           seenSp: seenSp };
}

function run(t) {
  log.debug("Entering run().");
  modeRow(t);
  const id = 'ua-' + process.pid;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return undefined;
  }
  let done;
  try {
    done = realms.run(made.realm, function () {
      const f = fixtures(t);
      const unknown = wstrustRefusals(t, f.seenOnly, f.aliased);
      delegated(t, f.seenOnly);
      nothingRecorded(t, f.seenOnly);
      notAsked(t);
      development(t, unknown);
      wsfed(t);
      return oauth(t, f.seenClient).then(function () {
        return saml(t, f.seenSp);
      }).then(function () {
        return gnap(t);
      });
    });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    realms.remove(id);
    throw e;
  }
  log.debug("Leaving run().");
  return Promise.resolve(done).then(function () {
    realms.remove(id);
  }, function (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    realms.remove(id);
    throw e;
  });
}

module.exports = {
  name: 'unregistered_applications',
  describe: 'in product an application nobody registered gets nothing: ' +
            'WS-Trust refuses an unregistered or absent AppliesTo, ' +
            'WS-Federation an unregistered wtrealm, before anything is ' +
            'issued or recorded; development is unchanged (#496)',
  run: run
};
