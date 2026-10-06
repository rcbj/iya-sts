// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: issuer_names.js
//
// ===========================================================================
// THE NAMES THIS SERVICE SIGNS UNDER (#480, #494): `saml.issuer`,
// `wstrust.issuer` and `wsfed.entityId`, through `common/issuer_names.ts`,
// in BOTH modes since #494 — and one name per application across SAML 2.0,
// WS-Trust and WS-Federation.
//
//   I1. nothing set, either mode: all three are saml2.entityId;
//   I2. a REGISTERED application, either mode: its per-application
//       entityID, `saml2_sso.idpEntityIdFor()`'s; an application nobody
//       registered (absent, or an entry that merely turned up) gets the
//       shared one; `saml2.perApplicationEntityId` off gives the shared one;
//   I3. a value somebody set wins, in either mode;
//   I4. in a realm, the SEEDED `urn:<domain>:sts` is read as a default in
//       both modes; a realm value that is not the seed wins;
//   I5. the mode predicate and its requirement row are gone (no shim);
//   I6. WS-Trust, both modes: a SAML 2.0 and a SAML 1.1 assertion for a
//       registered AppliesTo carry the application's own entityID; a JWT's
//       `iss` is still the realm's OAuth issuer; an AppliesTo nobody
//       registered gets the shared name, on the first request and on the
//       second, after `seen()` has filed an entry for it;
//   I7. WS-Federation, both modes: the assertion for a registered wtrealm
//       carries the application's own entityID, and the mock relying
//       party's issuer check holds it to that name; an unregistered wtrealm
//       gets the shared name;
//   I8. WS-Federation metadata: /wsfed/metadata/{rp} — by identifier and by
//       slug — names the registered application's entityID; the shared
//       document names the shared one; an unregistered segment is a 404
//       (STS-WSFED-0019) in both modes;
//   I9. one name per application: the SAML 2.0 SSO name, the WS-Trust SAML
//       2.0 and 1.1 Issuers, the WS-Federation Issuer and its metadata
//       entityID are the same string;
//   I10. product with saml2.entityId emptied and nothing set: no name, and
//       WS-Trust (STS-WSTRUST-0029) and the WS-Federation metadata
//       (STS-WSFED-0020) refuse rather than sign under an empty one.
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
const mode = require('../common/mode');
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

function three() {
  log.debug("Entering three().");
  log.debug("Leaving three().");
  return [IssuerNames.samlIssuer(), IssuerNames.wstrustIssuer(),
          IssuerNames.wsfedEntityId()];
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
    saml2.buildSamlAssertion('in-alice', 'https://sts.test', 5) +
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
  const entityId = String(config.value('saml2.entityId'));
  const got = bothModes(three);
  t.check(entityId && got.every(function (names) {
    return names.every(function (one) { return one === entityId; });
  }), 'I1. nothing set, in development AND product: all three are ' +
      'saml2.entityId (' + entityId + ')', JSON.stringify(got));
  config.setOverride('saml.issuer', 'urn:example:chosen');
  try {
    const set = bothModes(function () {
      return IssuerNames.samlIssuer('anything');
    });
    t.check(set.every(function (one) { return one === 'urn:example:chosen'; }),
            'I3. a value somebody set wins, in either mode',
            JSON.stringify(set));
  } finally {
    config.clearOverride('saml.issuer');
  }
  t.check(typeof mode.namesIssuersByEntityId === 'undefined' &&
          !mode.report().requirements.some(function (r) {
            return r.id === 'issuer-names';
          }),
          'I5. mode.namesIssuersByEntityId() and the issuer-names ' +
          'requirement are retired, with no shim', '');
  log.debug("Leaving defaultRealm().");
}

function names(t, seed) {
  log.debug("Entering names().");
  const sso = require('../saml/saml2_sso');
  const shared = String(config.value('saml2.entityId'));
  const own = sso.idpEntityIdFor('in-app');
  const got = bothModes(three);
  t.check(seed && got.every(function (names) {
    return names.every(function (one) { return one === shared; });
  }) && shared !== seed,
          'I4. in a realm, the seeded ' + seed + ' is a default in both ' +
          'modes: all three are the realm\'s entityID (' + shared + ')',
          JSON.stringify(got));
  const reg = bothModes(function () {
    return [IssuerNames.samlIssuer('in-app'),
            IssuerNames.wsfedEntityId('in-app')];
  });
  t.check(own === shared + ':in-app' && reg.every(function (pair) {
    return pair[0] === own && pair[1] === own;
  }), 'I2. a registered application, both modes: its own entityID (' +
      own + ')', JSON.stringify(reg));
  const unreg = bothModes(function () {
    return [IssuerNames.samlIssuer('in-nobody'),
            IssuerNames.samlIssuer(UNREG_REALM)];
  });
  t.check(unreg.every(function (pair) {
    return pair[0] === shared && pair[1] === shared;
  }), 'I2b. an application nobody registered: the shared entityID',
          JSON.stringify(unreg));
  config.setOverride('saml2.perApplicationEntityId', false);
  try {
    const off = bothModes(function () {
      return IssuerNames.samlIssuer('in-app');
    });
    t.check(off.every(function (one) { return one === shared; }),
            'I2c. saml2.perApplicationEntityId off: the shared entityID ' +
            'for a registered application too', JSON.stringify(off));
  } finally {
    config.clearOverride('saml2.perApplicationEntityId');
  }
  log.debug("Leaving names().");
  return { shared: shared, own: own };
}

function wstrustIssuers(t, n) {
  log.debug("Entering wstrustIssuers().");
  const oauth2 = require('../oauth-oidc/oauth2');
  const out = {};
  ['development', 'product'].forEach(function (m) {
    inMode(m, function () {
      const s2 = issued(SP_URL);
      const s11 = issued(SP_URL, SAML11);
      const jwt = issued(SP_URL, JWT);
      const first = issued(UNREG_URL);
      const second = issued(UNREG_URL);
      out[m] = { s2: s2.issuer, s11: s11.issuer };
      t.check(s2.status === 200 && s2.issuer === n.own &&
              s11.status === 200 && s11.issuer === n.own,
              'I6. ' + m + ': a WS-Trust SAML 2.0 and SAML 1.1 assertion ' +
              'for the registered AppliesTo carry the application\'s own ' +
              'entityID', JSON.stringify([s2, s11]));
      t.check(jwt.status === 200 && jwt.iss === oauth2.issuerOf(BASE) &&
              jwt.iss !== n.own,
              'I6b. ' + m + ': a WS-Trust JWT\'s iss is still the realm\'s ' +
              'OAuth issuer', JSON.stringify(jwt));
      t.check(first.status === 200 && first.issuer === n.shared &&
              second.status === 200 && second.issuer === n.shared,
              'I6c. ' + m + ': an AppliesTo nobody registered gets the ' +
              'shared name, before and after seen() files it',
              JSON.stringify([first, second]));
    });
  });
  log.debug("Leaving wstrustIssuers().");
  return out;
}

function wsfedIssuers(t, n) {
  log.debug("Entering wsfedIssuers().");
  const wsfed = require('../ws-federation/wsfed');
  const out = {};
  ['development', 'product'].forEach(function (m) {
    inMode(m, function () {
      const s2 = wsfedIssued('in-app', wsfed.SAML2_TOKEN_TYPE);
      const s11 = wsfedIssued('in-app', wsfed.SAML11_TOKEN_TYPE);
      const unreg = wsfedIssued(UNREG_REALM, wsfed.SAML2_TOKEN_TYPE);
      out[m] = { s2: s2.issuer, s11: s11.issuer };
      t.check(s2.status === 200 && s2.issuer === n.own &&
              s11.status === 200 && s11.issuer === n.own &&
              s2.rpIssuerCheck && s11.rpIssuerCheck,
              'I7. ' + m + ': a WS-Federation assertion (SAML 2.0 and 1.1) ' +
              'for the registered wtrealm carries its own entityID, and the ' +
              'mock relying party\'s issuer check holds it to that name',
              JSON.stringify([s2, s11]));
      t.check(unreg.status === 200 && unreg.issuer === n.shared &&
              unreg.rpIssuerCheck,
              'I7b. ' + m + ': a wtrealm nobody registered gets the shared ' +
              'name', JSON.stringify(unreg));
    });
  });
  log.debug("Leaving wsfedIssuers().");
  return out;
}

function wsfedMetadata(t, n) {
  log.debug("Entering wsfedMetadata().");
  const sso = require('../saml/saml2_sso');
  const routes = metadataRoutes();
  const out = {};
  ['development', 'product'].forEach(function (m) {
    inMode(m, function () {
      const own = routes.of('in-app');
      const bySlug = routes.of(sso.slugOf('in-app'));
      const shared = routes.shared();
      const unreg = routes.of('in-nobody');
      // An entry that merely turned up (the wtrealm the sign-in above
      // filed) is not registered either.
      const seenOnly = routes.of(UNREG_REALM);
      out[m] = own.entityId;
      t.check(own.status === 200 && own.entityId === n.own &&
              /no-store/.test(own.cache) && bySlug.entityId === n.own &&
              shared.status === 200 && shared.entityId === n.shared,
              'I8. ' + m + ': /wsfed/metadata/{rp} names the registered ' +
              'application\'s entityID, by identifier and by slug; the ' +
              'shared document names the shared one',
              JSON.stringify([own, bySlug, shared]));
      t.check(unreg.status === 404 && seenOnly.status === 404 &&
              unreg.code === 'STS-WSFED-0019' &&
              /no-store/.test(unreg.cache) &&
              /not|no WS-Federation relying party registered/.test(
                unreg.body),
              'I8b. ' + m + ': an unregistered segment is a 404 ' +
              '(STS-WSFED-0019)', JSON.stringify([unreg, seenOnly]));
    });
  });
  log.debug("Leaving wsfedMetadata().");
  return out;
}

function noName(t) {
  log.debug("Entering noName().");
  const routes = metadataRoutes();
  config.setOverride('saml2.entityId', '');
  try {
    const got = inMode('product', function () {
      return { names: three(), problem: IssuerNames.problem('saml.issuer'),
               wstrust: issued(SP_URL), jwt: issued(SP_URL, JWT),
               metadata: routes.shared() };
    });
    t.check(got.names.every(function (one) { return one === ''; }) &&
            /saml2\.entityId is empty/.test(got.problem) &&
            got.wstrust.status === 500 &&
            got.wstrust.errorCode === 'STS-WSTRUST-0029' &&
            got.jwt.status === 200 && got.metadata.status === 503 &&
            got.metadata.code === 'STS-WSFED-0020',
            'I10. product, saml2.entityId empty, nothing set: no name, and ' +
            'WS-Trust SAML and the WS-Federation metadata refuse; a JWT is ' +
            'unaffected', JSON.stringify(got));
    const dev = inMode('development', three);
    t.check(dev.every(function (one) { return one === 'urn:sts:idp'; }),
            'I10b. development, saml2.entityId empty: the SSO profile\'s ' +
            'own fallback, for all three', JSON.stringify(dev));
  } finally {
    config.clearOverride('saml2.entityId');
  }
  log.debug("Leaving noName().");
}

function inRealm(t) {
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
      const seed = 'urn:' + id + '.example.net:sts';
      dir.createUser('in-alice', { invent: false });
      const app = applications.createApplication({
        identifier: 'in-app', protocols: ['wstrust', 'wsfed', 'saml2'],
        fields: { wstrustAppliesTo: [SP_URL],
                  wsfedReplyUrl: [BASE + '/wsfed/rp'] } });
      t.check(app && app.ok, 'precondition: the application was registered',
              JSON.stringify(app));
      const n = names(t, seed);
      const ws = wstrustIssuers(t, n);
      const wf = wsfedIssuers(t, n);
      const md = wsfedMetadata(t, n);
      const sso = require('../saml/saml2_sso');
      const all = [sso.idpEntityIdFor('in-app')];
      ['development', 'product'].forEach(function (m) {
        all.push(ws[m].s2, ws[m].s11, wf[m].s2, wf[m].s11, md[m]);
      });
      t.check(all.every(function (one) { return one === all[0]; }) &&
              all[0] === n.own,
              'I9. one name per application: SAML 2.0 SSO, the WS-Trust ' +
              'SAML 2.0 and 1.1 Issuers, the WS-Federation Issuers and its ' +
              'metadata entityID agree, in both modes', JSON.stringify(all));
      noName(t);
      const wrote = realms.setOverride(id, 'wsfed.entityId',
                                       'urn:example:realm-chosen');
      const chosen = bothModes(function () {
        return IssuerNames.wsfedEntityId('in-app');
      });
      t.check(wrote && wrote.ok !== false &&
              chosen.every(function (one) {
                return one === 'urn:example:realm-chosen';
              }),
              'I4b. a realm value that is not the seed wins, in both modes ' +
              'and for every application', JSON.stringify(chosen));
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving inRealm().");
}

function run(t) {
  log.debug("Entering run().");
  defaultRealm(t);
  inRealm(t);
  log.debug("Leaving run().");
  return undefined;
}

module.exports = {
  name: 'issuer_names',
  describe: 'the SAML issuer, the WS-Trust STS name and the WS-Federation ' +
            'entityID: the SAML entityID in both modes, one per registered ' +
            'application across SAML 2.0, WS-Trust and WS-Federation, a set ' +
            'value always (#480, #494)',
  run: run
};
