// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: issuer_names.js
//
// ===========================================================================
// ONE ISSUER PER REALM, IN EVERY PROTOCOL (#523): the realm's OAuth issuer,
// through `common/issuer_names.ts`, is every name this service issues under.
//
//   U1. `issuer(base)` is `oauth2.issuerOf(base)`, in both modes; with no
//       base and no request it is the configured base's, the realm's
//       prefix included;
//   U2. the seven settings are gone from the table and refused if named
//       (REPLACED_SETTINGS, naming global.publicBaseUrl), and the four
//       "no name" error codes are retired;
//   U3. WS-Trust, both modes: a SAML 2.0 Issuer, a SAML 1.1 Issuer and a
//       JWT's `iss` for a registered AppliesTo are the same string, the
//       OAuth issuer at the request's base; in development an AppliesTo
//       nobody registered gets the same name, and in product it is refused
//       (#496, STS-WSTRUST-0030);
//   U4. WS-Federation, both modes: the assertion (SAML 2.0 and 1.1) carries
//       the issuer, and the mock relying party's issuer check holds it to
//       that name, for a registered wtrealm and for one nobody registered;
//   U5. WS-Federation metadata, both modes: the shared document and
//       /wsfed/metadata/{rp} (by identifier and by slug) name the issuer
//       at the request's base; an unregistered segment is a 404
//       (STS-WSFED-0019);
//   U6. SAML 2.0 SSO's entityID and SAML 1.1's providerID are the issuer,
//       and the same string for every service provider;
//   U7. in a realm, the issuer carries the realm's prefix and is not the
//       default realm's.
//
// IN PROCESS: the modes and the layers are set here, which a job over HTTP
// cannot do.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const IssuerNames = require('../common/issuer_names');
// Arms the issuance gate, which a WS-Trust Issue asks.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'issuer_names',
  level: process.env.LOG_LEVEL || 'info' });

const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const SAML11 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-' +
  'profile-1.1#SAMLV1.1';
const JWT = 'urn:ietf:params:oauth:token-type:jwt';
const SP_URL = 'https://in-sp.example';
const UNREG_URL = 'https://in-unregistered.example';
const UNREG_REALM = 'urn:in-unregistered-rp';
const BASE = 'https://sts.in.example';

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

function bothModes(fn) {
  log.debug("Entering bothModes().");
  log.debug("Leaving bothModes().");
  return ['development', 'product'].map(function (m) {
    return inMode(m, fn);
  });
}

function unescapeXml(text) {
  log.debug("Entering unescapeXml().");
  log.debug("Leaving unescapeXml().");
  return String(text).replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
}

// A WS-Trust Issue for `appliesTo`, as a person on a signed assertion of
// theirs, asking for `tokenType` (SAML 2.0 when none).
function issued(appliesTo, tokenType) {
  log.debug("Entering issued().");
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const body = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-' +
    'envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-' +
    '200401-wss-wssecurity-secext-1.0.xsd"><s:Header><wsse:Security>' +
    saml2.buildSamlAssertion('in-alice', BASE + '/sts', 5) +
    '</wsse:Security></s:Header><s:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="' + WST + '"><wst:RequestType>' + WST + '/Issue' +
    '</wst:RequestType>' + (tokenType ? '<wst:TokenType>' + tokenType +
    '</wst:TokenType>' : '') + '<wsp:AppliesTo xmlns:wsp="http://' +
    'schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference ' +
    'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
    appliesTo + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
  const r = wstrust.handleRst(body, 'application/soap+xml', { base: BASE });
  const text = String(r.body);
  const s2 = /<saml:Issuer>([^<]*)<\/saml:Issuer>/.exec(text);
  const s11 = /<saml:Assertion [^>]*\bIssuer="([^"]*)"/.exec(text);
  const jwt = /<wsse:BinarySecurityToken[^>]*>([^<]+)</.exec(text);
  let iss = '';
  if (jwt) {
    iss = String(JSON.parse(Buffer.from(jwt[1].trim().split('.')[1],
                                        'base64url').toString('utf8')).iss);
  }
  log.debug("Leaving issued().");
  return { status: r.status, errorCode: r.errorCode || '',
           issuer: tokenType === SAML11 ? (s11 ? s11[1] : '')
             : (s2 ? s2[1] : ''),
           iss: iss, body: text.slice(0, 400) };
}

// A chainable stand-in for express's response, recording what was sent.
function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { statusCode: 200, headers: {}, body: '', locals: {} };
  res.status = function (n) { res.statusCode = n; return res; };
  res.type = function () { return res; };
  res.set = function (k, v) { res.headers[k] = v; return res; };
  res.setHeader = res.set;
  res.redirect = function (n, where) {
    res.statusCode = n;
    res.body = String(where);
    return res;
  };
  res.send = function (b) { res.body = String(b); return res; };
  log.debug("Leaving fakeRes().");
  return res;
}

// A WS-Federation sign-in response for `realm`, the wresult the page
// carries, and the mock relying party's verdict over it for that realm.
function wsfedIssued(realm, tokenType) {
  log.debug("Entering wsfedIssued().");
  const wsfed = require('../ws-federation/wsfed');
  const instance = new wsfed.WsFederation(wsfed.WsFederation.defaultDeps());
  const session = { id: 'in-session', authenticated: true,
                    authTime: Math.floor(Date.now() / 1000),
                    user: { username: 'in-alice' }, events: [] };
  const res = fakeRes();
  instance.issueSignInResponse({}, res, { wa: 'wsignin1.0', wtrealm: realm },
                               session, realm, BASE + '/wsfed/rp',
                               tokenType || wsfed.SAML2_TOKEN_TYPE);
  const m = /name="wresult" value="([^"]*)"/.exec(res.body);
  const wresult = m ? unescapeXml(m[1]) : '';
  const s2 = /<saml:Issuer>([^<]*)<\/saml:Issuer>/.exec(wresult);
  const s11 = /<saml:Assertion [^>]*\bIssuer="([^"]*)"/.exec(wresult);
  const verdict = wresult
    ? instance.verifySignInResponse({ wa: 'wsignin1.0', wresult: wresult },
                                    realm)
    : { checks: [] };
  const check = (verdict.checks || []).filter(function (c) {
    return c.name === 'the issuer is this service';
  })[0];
  log.debug("Leaving wsfedIssued().");
  return { status: res.statusCode,
           issuer: s2 ? s2[1] : (s11 ? s11[1] : ''),
           rpIssuerCheck: !!(check && check.ok),
           body: res.body.slice(0, 300) };
}

// The WS-Federation metadata routes, asked as express would ask them.
function metadataRoutes() {
  log.debug("Entering metadataRoutes().");
  const wsfed = require('../ws-federation/wsfed');
  const instance = new wsfed.WsFederation(wsfed.WsFederation.defaultDeps());
  const routes = {};
  instance.registerRoutes({
    get: function (path, handler) { routes[path] = handler; },
    post: function () {},
    contentSecurityPolicy: function () { return ''; }
  });
  const ask = function (path, params) {
    log.debug("Entering ask(). " + path);
    const res = fakeRes();
    routes[path]({ params: params || {}, headers: { host: 'sts.in.example' },
                   protocol: 'https',
                   get: function (k) {
                     return String(k).toLowerCase() === 'host'
                       ? 'sts.in.example' : undefined;
                   } }, res);
    const m = /<EntityDescriptor [^>]*\bentityID="([^"]*)"/.exec(res.body);
    log.debug("Leaving ask().");
    return { status: res.statusCode, entityId: m ? m[1] : '',
             cache: String(res.headers['Cache-Control'] || ''),
             code: require('../common/error_codes').codeOf(res) || '',
             body: res.body.slice(0, 300) };
  };
  log.debug("Leaving metadataRoutes().");
  return {
    shared: function () {
      return ask('/FederationMetadata/2007-06/FederationMetadata.xml');
    },
    of: function (rp) {
      return ask('/wsfed/metadata/:rp', { rp: rp });
    }
  };
}

function defaultRealm(t) {
  log.debug("Entering defaultRealm().");
  const oauth2 = require('../oauth-oidc/oauth2');
  const got = bothModes(function () {
    return [IssuerNames.issuer(BASE), oauth2.issuerOf(BASE)];
  });
  t.check(got.every(function (pair) {
    return pair[0] && pair[0] === pair[1];
  }), 'U1. issuer(base) is the realm\'s OAuth issuer at that base, in ' +
      'development AND product', JSON.stringify(got));
  const configured = String(config.managementApiBaseUrl() || '')
    .replace(/\/admin-api$/, '');
  const bare = IssuerNames.issuer();
  t.check(bare && bare === IssuerNames.issuer(configured),
          'U1b. with no base and no request: the configured base\'s (' +
          bare + ')', configured);
  const retired = ['saml.issuer', 'saml2.entityId',
                   'saml2.perApplicationEntityId', 'saml11.providerId',
                   'saml11.perApplicationProviderId', 'wstrust.issuer',
                   'wsfed.entityId'];
  const inTable = config.SETTINGS.filter(function (row) {
    return retired.indexOf(row.key) >= 0;
  }).map(function (row) { return row.key; });
  const replaced = config.REPLACED_SETTINGS.filter(function (row) {
    return retired.indexOf(row.key) >= 0 &&
           row.now.indexOf('global.publicBaseUrl') >= 0;
  }).map(function (row) { return row.key; });
  const legacy = config.REPLACED_SETTINGS.some(function (row) {
    return row.legacyEnv === 'STS_ISSUER';
  });
  t.check(!inTable.length && replaced.length === retired.length && legacy,
          'U2. the seven issuer settings are gone and refused if named, ' +
          'naming global.publicBaseUrl; STS_ISSUER with them',
          JSON.stringify({ inTable: inTable, replaced: replaced }));
  const codes = require('../common/error_codes');
  const stillLive = ['STS-SAML-0004', 'STS-SAML-0027', 'STS-WSTRUST-0029',
                     'STS-WSFED-0020'].filter(function (code) {
    const row = codes.CODES.filter(function (one) {
      return one.code === code;
    })[0];
    return !(row && row.retired);
  });
  t.check(!stillLive.length, 'U2b. the four "no name to issue under" ' +
          'codes are retired', JSON.stringify(stillLive));
  log.debug("Leaving defaultRealm().");
}

function wstrustIssuers(t, expected) {
  log.debug("Entering wstrustIssuers().");
  ['development', 'product'].forEach(function (m) {
    inMode(m, function () {
      const s2 = issued(SP_URL);
      const s11 = issued(SP_URL, SAML11);
      const jwt = issued(SP_URL, JWT);
      const first = issued(UNREG_URL);
      const second = issued(UNREG_URL);
      t.check(s2.status === 200 && s2.issuer === expected &&
              s11.status === 200 && s11.issuer === expected &&
              jwt.status === 200 && jwt.iss === expected,
              'U3. ' + m + ': WS-Trust\'s SAML 2.0 Issuer, SAML 1.1 Issuer ' +
              'and JWT iss are one string, the OAuth issuer (' + expected +
              ')', JSON.stringify([s2, s11, jwt]));
      // #496: only DEVELOPMENT issues for an AppliesTo nobody registered.
      // Product refuses it — and development, which runs first, has filed
      // an entry for it by then, so product's refusal is of a seen-only one.
      t.check(m === 'development'
        ? first.status === 200 && first.issuer === expected &&
          second.status === 200 && second.issuer === expected
        : first.status === 500 && first.errorCode === 'STS-WSTRUST-0030' &&
          second.status === 500 && second.errorCode === 'STS-WSTRUST-0030',
              'U3b. ' + m + ': an AppliesTo nobody registered gets ' +
              (m === 'development'
                ? 'the same name, before and after seen() files it'
                : 'refusal STS-WSTRUST-0030 even after a sighting (#496)'),
              JSON.stringify([first, second]));
    });
  });
  log.debug("Leaving wstrustIssuers().");
}

function wsfedIssuers(t) {
  log.debug("Entering wsfedIssuers().");
  const wsfed = require('../ws-federation/wsfed');
  ['development', 'product'].forEach(function (m) {
    inMode(m, function () {
      // No request is ambient here, so the name is the configured base's.
      const expected = IssuerNames.issuer();
      const s2 = wsfedIssued('in-app', wsfed.SAML2_TOKEN_TYPE);
      const s11 = wsfedIssued('in-app', wsfed.SAML11_TOKEN_TYPE);
      const unreg = wsfedIssued(UNREG_REALM, wsfed.SAML2_TOKEN_TYPE);
      t.check(s2.status === 200 && s2.issuer === expected &&
              s11.status === 200 && s11.issuer === expected &&
              s2.rpIssuerCheck && s11.rpIssuerCheck &&
              unreg.status === 200 && unreg.issuer === expected &&
              unreg.rpIssuerCheck,
              'U4. ' + m + ': a WS-Federation assertion (SAML 2.0 and 1.1), ' +
              'registered wtrealm or not, carries the issuer, and the mock ' +
              'relying party\'s issuer check holds it to that name',
              JSON.stringify([s2, s11, unreg]));
    });
  });
  log.debug("Leaving wsfedIssuers().");
}

function wsfedMetadata(t, prefix) {
  log.debug("Entering wsfedMetadata().");
  const sso = require('../saml/saml2_sso');
  const routes = metadataRoutes();
  const expected = IssuerNames.issuer(BASE + prefix);
  ['development', 'product'].forEach(function (m) {
    inMode(m, function () {
      const own = routes.of('in-app');
      const bySlug = routes.of(sso.slugOf('in-app'));
      const shared = routes.shared();
      const unreg = routes.of('in-nobody');
      // An entry that merely turned up (the wtrealm the sign-in above
      // filed) is not registered either.
      const seenOnly = routes.of(UNREG_REALM);
      t.check(own.status === 200 && own.entityId === expected &&
              /no-store/.test(own.cache) && bySlug.entityId === expected &&
              shared.status === 200 && shared.entityId === expected,
              'U5. ' + m + ': the shared document and /wsfed/metadata/{rp}, ' +
              'by identifier and by slug, name the issuer at the request\'s ' +
              'base (' + expected + ')', JSON.stringify([own, bySlug, shared]));
      t.check(unreg.status === 404 && seenOnly.status === 404 &&
              unreg.code === 'STS-WSFED-0019' &&
              /no-store/.test(unreg.cache),
              'U5b. ' + m + ': an unregistered segment is a 404 ' +
              '(STS-WSFED-0019)', JSON.stringify([unreg, seenOnly]));
    });
  });
  log.debug("Leaving wsfedMetadata().");
}

function browserProfiles(t) {
  log.debug("Entering browserProfiles().");
  const sso = require('../saml/saml2_sso');
  const sso11 = require('../saml/saml11_sso');
  const got = bothModes(function () {
    return [IssuerNames.issuer(), sso.idpEntityId(), sso11.providerId()];
  });
  t.check(got.every(function (three) {
    return three[0] && three[1] === three[0] && three[2] === three[0];
  }), 'U6. SAML 2.0 SSO\'s entityID and SAML 1.1\'s providerID are the ' +
      'issuer, one string for every party, in both modes',
          JSON.stringify(got));
  log.debug("Leaving browserProfiles().");
}

function inRealm(t, defaultIssuer) {
  log.debug("Entering inRealm().");
  const id = 'in-' + process.pid;
  const made = realms.create({ id: id, name: id, domain: id + '.example.net',
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving inRealm().");
    return;
  }
  try {
    realms.run(made.realm, function () {
      const prefix = String(realms.currentPrefix() || '');
      const own = IssuerNames.issuer();
      t.check(prefix && own.indexOf(prefix) >= 0 && own !== defaultIssuer,
              'U7. in a realm the issuer carries its prefix (' + own +
              ') and is not the default realm\'s', defaultIssuer);
      dir.createUser('in-alice', { invent: false });
      const app = applications.createApplication({
        identifier: 'in-app', protocols: ['wstrust', 'wsfed', 'saml2'],
        fields: { wstrustAppliesTo: [SP_URL],
                  wsfedReplyUrl: [BASE + '/wsfed/rp'] } });
      t.check(app && app.ok, 'precondition: the application was registered',
              JSON.stringify(app));
      // handleRst() is handed BASE itself, as a caller with no request.
      wstrustIssuers(t, IssuerNames.issuer(BASE));
      wsfedIssuers(t);
      wsfedMetadata(t, prefix);
      browserProfiles(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving inRealm().");
}

function run(t) {
  log.debug("Entering run().");
  defaultRealm(t);
  browserProfiles(t);
  inRealm(t, IssuerNames.issuer());
  log.debug("Leaving run().");
  return undefined;
}

module.exports = {
  name: 'issuer_names',
  describe: 'one issuer per realm (#523): every SAML Issuer, identity ' +
            'provider entityID and providerID, the WS-Trust STS name and ' +
            'every JWT iss are the realm\'s OAuth issuer, in both modes',
  run: run
};
