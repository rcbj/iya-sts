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
//       registered wtrealm passes the check; development is unchanged.
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
  return saml2.buildSamlAssertion(name, audience || 'https://sts.test', 5);
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
      fields: { wsfedReplyUrl: [BASE + '/wsfed/rp'] } })
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
  log.debug("Leaving fixtures().");
  return { seenOnly: seenOnly, aliased: aliased };
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
  try {
    realms.run(made.realm, function () {
      const f = fixtures(t);
      const unknown = wstrustRefusals(t, f.seenOnly, f.aliased);
      delegated(t, f.seenOnly);
      nothingRecorded(t, f.seenOnly);
      notAsked(t);
      development(t, unknown);
      wsfed(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
  return undefined;
}

module.exports = {
  name: 'unregistered_applications',
  describe: 'in product an application nobody registered gets nothing: ' +
            'WS-Trust refuses an unregistered or absent AppliesTo, ' +
            'WS-Federation an unregistered wtrealm, before anything is ' +
            'issued or recorded; development is unchanged (#496)',
  run: run
};
