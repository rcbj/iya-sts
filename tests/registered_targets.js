// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: registered_targets.js
//
// ===========================================================================
// IN PRODUCT, AN RFC 8707 RESOURCE AND A GNAP RIGHT'S LOCATIONS NAME A
// REGISTERED TARGET (#505).
//
// rcbj's follow-up to #496: a `resource` at the authorization, PAR and token
// endpoints outside a token exchange, and every location of a GNAP access
// right, must name a registered target in product — one of this service's
// own resource servers, or an application registered ahead of time
// (`appRegisteredBy`), found by its oauthAudience, permission base URI,
// client_id or identifier. `common/registered_targets.ts` is the one
// definition; development is unchanged.
//
//   T1. the `unregistered-resource-targets` row is in mode.report(), naming
//       the three codes, and the predicate is #496's;
//   T2. the definition, in product: a registered application by each of its
//       four names is a registered target; this service's own resource
//       servers (the default resource indicator, a named authorization
//       server's, the realm's /admin-api, the GNAP demonstration resource
//       server) are; an address nobody registered and one only SEEN are
//       not; in development nothing is unregistered;
//   T3. the authorization endpoint's request check (shared with PAR): in
//       product an unregistered resource is a REDIRECTED invalid_target
//       (STS-OAUTH-0950), a seen-only one too; a registered application's
//       audience and the default resource indicator pass; development
//       refuses neither;
//   T4. the token endpoint: in product an unregistered resource is a 400
//       invalid_target (STS-OAUTH-0951) before the grant is looked at; a
//       registered one and one of this service's own pass the check; a
//       token exchange is not asked (its targets are RFC 8693's);
//       development refuses none;
//   T5. GNAP's request stage: in product a right whose location names no
//       registered resource server, or a seen-only one, is refused
//       invalid_request (STS-GNAP-0903); a location at or under a
//       registered GNAP resource server's gnapResourceServerUri, a
//       registered application's audience and the demonstration resource
//       server pass; a reference string is not asked; development refuses
//       none.
//
// IN PROCESS, in a throwaway realm, because the cases are product's and
// development's both and a job over HTTP runs in one mode.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
require('../ldap/ldap_server');
const mode = require('../common/mode');
const errorCodes = require('../common/error_codes');
const RegisteredTargets = require('../common/registered_targets');

const log = require('bunyan').createLogger({
  name: 'registered_targets',
  level: process.env.LOG_LEVEL || 'info' });

const HOST = 'sts.rt.example';
const API = 'https://api.rt-registered.example';
const BASE_URI = 'https://perm.rt-registered.example/';
const GNAP_RS = 'https://rs.rt-registered.example/api';
const NOBODY = 'https://nobody.rt.example/api';
const REDIRECT = 'https://rt-client.example/cb';

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

async function inModeAsync(m, fn) {
  log.debug("Entering inModeAsync(). " + m);
  config.setOverride('global.mode', m);
  try {
    log.debug("Leaving inModeAsync().");
    return await fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

// A request on this realm's address: a query for the authorization
// endpoint, a form body for the token endpoint.
function request(query, form) {
  log.debug("Entering request().");
  const headers = { host: HOST,
                    'content-type': 'application/x-www-form-urlencoded' };
  log.debug("Leaving request().");
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
  res.json = function (b) {
    res.body = JSON.stringify(b);
    return res;
  };
  log.debug("Leaving fakeRes().");
  return res;
}

function modeRow(t) {
  log.debug("Entering modeRow().");
  const row = mode.report().requirements.filter(function (one) {
    return one.id === 'unregistered-resource-targets';
  })[0];
  t.check(!!row && /STS-OAUTH-0950/.test(row.product) &&
          /STS-OAUTH-0951/.test(row.product) &&
          /STS-GNAP-0903/.test(row.product) && !!row.development &&
          /registered_targets/.test(row.where) &&
          inMode('product', mode.issuesToUnregisteredApplications) ===
            false,
          'T1. the unregistered-resource-targets row is reported, with its ' +
          'three codes, under #496\'s predicate', JSON.stringify(row));
  log.debug("Leaving modeRow().");
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  const made = [
    applications.createApplication({ identifier: 'rt-api',
      protocols: ['oauth2'],
      fields: { oauthAudience: [API], oauthClientId: 'rt-api-client' } }),
    applications.createApplication({ identifier: 'rt-perm',
      protocols: ['oauth2'],
      fields: { oauthPermissionBaseUri: BASE_URI,
                oauthPermission: ['read|Read it'] } }),
    applications.createApplication({ identifier: 'rt-oauth',
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: 'rt-oauth',
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'none',
                // T4c's exchange is declared too, or it would be refused
                // for its grant type before the target check is reached
                // and pass for the wrong reason (#289).
                oauthGrantType: ['authorization_code',
                  'urn:ietf:params:oauth:grant-type:token-exchange'] } }),
    applications.createApplication({ identifier: 'rt-gnap-rs',
      kind: 'gnap-resource-server', protocols: ['gnap'],
      fields: { gnapResourceServerUri: GNAP_RS } })
  ];
  t.check(made.every(function (one) {
    return one && one.ok;
  }), 'precondition: the applications were registered',
          JSON.stringify(made));
  // A SEEN-ONLY target: a development sighting with an audience and a GNAP
  // resource server address, and no appRegisteredBy.
  const seen = 'https://seen-' + process.pid + '.rt.example/api';
  inMode('development', function () {
    return applications.seen({ identifier: 'rt-seen-' + process.pid,
                               kind: 'gnap-resource-server',
                               protocol: 'GNAP',
                               fields: { oauthAudience: seen,
                                         gnapResourceServerUri: seen },
                               note: 'filed by ' + __filename });
  });
  const filed = applications.get('rt-seen-' + process.pid);
  t.check(!!filed && !filed.registeredBy,
          'precondition: development filed a seen-only target');
  log.debug("Leaving fixtures().");
  return { seen: seen };
}

function definition(t, f) {
  log.debug("Entering definition().");
  const req = request({});
  const base = require('../common/helpers').baseUrlOf(req);
  const registered = [API, 'rt-api-client', 'rt-api', BASE_URI,
                      BASE_URI.slice(0, -1)];
  const own = [base + '/resource', base + '/as1/resource',
               base + '/admin-api', base + '/gnap/rs/resource'];
  const product = inMode('product', function () {
    return { registered: RegisteredTargets.unregistered(registered, req),
             own: RegisteredTargets.unregistered(own, req),
             owners: own.map(function (one) {
               return RegisteredTargets.ownResourceServer(one, req);
             }),
             strangers: RegisteredTargets.unregistered(
               [NOBODY, f.seen, base + '/other', base + '/resource/x'], req)
           };
  });
  t.check(product.registered.length === 0,
          'T2. product: a registered application is a registered target by ' +
          'its audience, client_id, identifier and permission base URI ' +
          '(normalised)', JSON.stringify(product.registered));
  t.check(product.own.length === 0 && product.owners.every(Boolean),
          'T2b. product: this service\'s own resource servers — the default ' +
          'resource indicator, a named authorization server\'s, the realm\'s ' +
          '/admin-api and the GNAP demonstration resource server — are ' +
          'registered targets', JSON.stringify(product));
  t.check(product.strangers.length === 4,
          'T2c. product: an address nobody registered, one only seen, and ' +
          'paths of this service that are no resource server are not',
          JSON.stringify(product.strangers));
  const dev = inMode('development', function () {
    return RegisteredTargets.unregistered([NOBODY, f.seen], req);
  });
  t.check(dev.length === 0,
          'T2d. development: nothing is unregistered', JSON.stringify(dev));
  log.debug("Leaving definition().");
  return base;
}

function authorize(t, f, base) {
  log.debug("Entering authorize().");
  const oauth2 = require('../oauth-oidc/oauth2');
  const server = new oauth2.OAuth2Server(oauth2.OAuth2Server.defaultDeps());
  const vet = function (m, resource) {
    log.debug("Entering vet(). " + m);
    const query = { response_type: 'code', scope: 'openid',
                    client_id: 'rt-oauth', redirect_uri: REDIRECT,
                    state: 's', nonce: 'n',
                    code_challenge: 'x'.repeat(43),
                    code_challenge_method: 'S256' };
    if (resource !== undefined) {
      query.resource = resource;
    }
    const out = inMode(m, function () {
      return server.vetAuthorizationRequest(request(query));
    });
    log.debug("Leaving vet().");
    return { ok: !!out.ok, code: out.code || '', error: out.error || '',
             redirect: !!out.redirect, description: out.description || '' };
  };
  const refused = [vet('product', NOBODY), vet('product', f.seen),
                   vet('product', [API, NOBODY])];
  t.check(refused.every(function (r) {
    return !r.ok && r.code === 'STS-OAUTH-0950' &&
      r.error === 'invalid_target' && r.redirect === true;
  }), 'T3. product: an authorization request whose resource names no ' +
          'registered target (unknown, seen-only, or one of two) is a ' +
          'redirected invalid_target (STS-OAUTH-0950)',
          JSON.stringify(refused));
  const passed = [vet('product', API), vet('product', base + '/resource'),
                  vet('product', undefined),
                  vet('development', NOBODY), vet('development', f.seen)];
  t.check(passed.every(function (r) {
    return r.code !== 'STS-OAUTH-0950';
  }), 'T3b. a registered application\'s audience and the default resource ' +
          'indicator pass in product, as does no resource; development ' +
          'refuses neither', JSON.stringify(passed));
  log.debug("Leaving authorize().");
  return server;
}

async function token(t, f, base, server) {
  log.debug("Entering token().");
  const ask = async function (m, form) {
    log.debug("Entering ask(). " + m);
    const res = fakeRes();
    await inModeAsync(m, function () {
      return server.tokenGrant(request({}, form), res);
    });
    log.debug("Leaving ask().");
    return { status: res.statusCode, code: errorCodes.codeOf(res) || '',
             body: res.body.slice(0, 300) };
  };
  const code = function (resource) {
    log.debug("Entering code().");
    log.debug("Leaving code().");
    return { grant_type: 'authorization_code', client_id: 'rt-oauth',
             code: 'not-a-code-' + process.pid, redirect_uri: REDIRECT,
             code_verifier: 'v'.repeat(43), resource: resource };
  };
  const refused = [await ask('product', code(NOBODY)),
                   await ask('product', code(f.seen))];
  t.check(refused.every(function (r) {
    return r.status === 400 && r.code === 'STS-OAUTH-0951' &&
      /invalid_target/.test(r.body);
  }), 'T4. product: a token request whose resource names no registered ' +
          'target is a 400 invalid_target (STS-OAUTH-0951)',
          JSON.stringify(refused));
  const passed = [await ask('product', code(API)),
                  await ask('product', code(base + '/admin-api')),
                  await ask('development', code(NOBODY))];
  t.check(passed.every(function (r) {
    return r.code !== 'STS-OAUTH-0951';
  }), 'T4b. a registered application and one of this service\'s own pass ' +
          'the check in product; development refuses none',
          JSON.stringify(passed));
  const exchange = await ask('product', {
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: 'rt-oauth', subject_token: 'x.y.z',
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    resource: NOBODY });
  t.check(exchange.code !== 'STS-OAUTH-0951',
          'T4c. a token exchange is not asked: its targets are RFC 8693\'s',
          JSON.stringify(exchange));
  log.debug("Leaving token().");
}

async function gnap(t, f, base) {
  log.debug("Entering gnap().");
  const grantsModule = require('../gnap/gnap_grants');
  const grants = new grantsModule.GnapGrants(
    grantsModule.GnapGrants.defaultDeps());
  const app = { identifier: 'rt-gnap-client', fields: {} };
  const judge = async function (m, access) {
    log.debug("Entering judge(). " + m);
    const out = await inModeAsync(m, function () {
      return grants.judgeRequested(request({}), { as: 'default' }, app,
                                   [{ label: '', access: access }],
                                   'pending');
    });
    log.debug("Leaving judge().");
    return { ok: !!out.ok, code: errorCodes.codeOf(out) || out.errorCode ||
             '', error: out.gnapError || '', status: out.status || 0 };
  };
  const right = function (locations) {
    log.debug("Entering right().");
    log.debug("Leaving right().");
    return { type: 'https://rt.example/photos', actions: ['read'],
             locations: locations };
  };
  const refused = [await judge('product', [right([NOBODY])]),
                   await judge('product', [right([f.seen])]),
                   await judge('product', [right([GNAP_RS, NOBODY])])];
  t.check(refused.every(function (r) {
    return !r.ok && r.code === 'STS-GNAP-0903' &&
      r.error === 'invalid_request' && r.status === 400;
  }), 'T5. product: a right whose location names no registered resource ' +
          'server (unknown, seen-only, or one of two) is refused ' +
          'invalid_request (STS-GNAP-0903)', JSON.stringify(refused));
  const passed = [await judge('product', [right([GNAP_RS])]),
                  await judge('product', [right([GNAP_RS + '/photos/1'])]),
                  await judge('product', [right([API])]),
                  await judge('product',
                              [right([base + '/gnap/rs/resource'])]),
                  await judge('product', ['rt-some-reference']),
                  await judge('development', [right([NOBODY])]),
                  await judge('development', [right([f.seen])])];
  t.check(passed.every(function (r) {
    return r.code !== 'STS-GNAP-0903';
  }), 'T5b. a location at or under a registered GNAP resource server, a ' +
          'registered application\'s audience and the demonstration ' +
          'resource server pass in product, a reference is not asked, and ' +
          'development refuses none', JSON.stringify(passed));
  log.debug("Leaving gnap().");
}

function run(t) {
  log.debug("Entering run().");
  modeRow(t);
  const id = 'rt-' + process.pid;
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
      const base = definition(t, f);
      const server = authorize(t, f, base);
      return token(t, f, base, server).then(function () {
        return gnap(t, f, base);
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
  name: 'registered_targets',
  describe: 'in product an RFC 8707 resource and a GNAP right\'s locations ' +
            'name a registered target — one of this service\'s own resource ' +
            'servers or a registered application — or are refused; ' +
            'development is unchanged (#505)',
  run: run
};
