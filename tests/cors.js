'use strict';
//
// File: cors.js
//
// ===========================================================================
// THE CORS ALLOWLIST (2026-09-13).
//
// `Access-Control-Allow-Origin: *` on every response became an allowlist on
// every path — `common/cors.js` argues the rule — and what is asserted here is
// that rule, its refusals above all, in three layers:
//
//   * the origin grammar (`common/validation.js`) — what `appCorsOrigin` may
//     hold, and the serialisation it is held in;
//   * the application register's writes — a create and an add refused for a
//     value that is not an origin, stored normalised, and a remove that finds
//     a value by either spelling;
//   * THE DECISION, over real HTTP, through the two middlewares installed in
//     the order `common/app.js` installs them: this service's own origins
//     always, a named client's own list and nothing else, the realm's union
//     only where no client is named, an unknown client refused, a navigation
//     left alone, RFC 9700 section 2.6 still honoured, and GNAP's OPTIONS
//     discovery still reaching its route.
//
// The app is a small express app built here rather than `common/app.js`
// itself, because registering probe routes on the shared app would put them in
// the router every later file in a run reads. The middlewares are the real
// ones, and the body parser is the text parser `app.js` uses.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const http = require('http');

const log = require('bunyan').createLogger({ name: 'cors',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// A. The grammar.
// Mutants: a path accepted and dropped; `*` or `null` accepted; case or the
// default port kept, so a stored value never matches the header.
// ---------------------------------------------------------------------------
function grammar(t) {
  log.debug("Entering grammar().");
  t.log.info('=== A. what an origin is ===');
  const validation = require('../common/validation');
  const NORMALISED = [
    ['https://app.example.com', 'https://app.example.com'],
    ['HTTPS://App.Example.COM:443/', 'https://app.example.com'],
    ['http://localhost:3000', 'http://localhost:3000'],
    ['http://LOCALHOST:80', 'http://localhost'],
    ['http://[::1]:5173', 'http://[::1]:5173'],
    ['https://bücher.example', 'https://xn--bcher-kva.example'],
    ['chrome-extension://abcdefghijklmnop',
     'chrome-extension://abcdefghijklmnop']
  ];
  const REFUSED = [
    ['*', 'the wildcard this rule replaces'],
    ['https://*.example.com', 'a wildcard host no browser sends'],
    ['null', 'the opaque origin every sandboxed frame shares'],
    ['https://app.example.com/spa', 'a path the comparison would drop'],
    ['https://app.example.com?x=1', 'a query'],
    ['https://app.example.com#x', 'a fragment'],
    ['https://user@app.example.com', 'a user name'],
    ['app.example.com', 'no scheme'],
    ['file:///tmp/x', 'no host'],
    ['https://app.example.com:99999', 'a port that does not parse'],
    ['', 'empty']
  ];
  NORMALISED.forEach(function (pair) {
    t.equal(validation.normaliseOrigin(pair[0]), pair[1],
            'held as the origin a browser sends: ' + pair[0]);
  });
  REFUSED.forEach(function (pair) {
    t.check(typeof validation.originProblem(pair[0]) === 'string' &&
            validation.normaliseOrigin(pair[0]) === '',
            'refused as an origin: ' + JSON.stringify(pair[0]) + ' (' +
            pair[1] + ')', validation.originProblem(pair[0]));
  });
  log.debug("Leaving grammar().");
}

// ---------------------------------------------------------------------------
// B. The register's writes.
// Mutants: normaliseFields() without the origin check; updateApplication()
// storing the value as typed; a remove that only matches the exact spelling.
// ---------------------------------------------------------------------------
function registerWrites(t, suffix) {
  log.debug("Entering registerWrites().");
  t.log.info('=== B. what the register stores ===');
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const errorCodes = require('../common/error_codes');

  const refused = applications.createApplication({
    identifier: 'cors-bad-' + suffix, kind: 'oauth2-client',
    fields: { oauthClientId: 'cors-bad-' + suffix,
              appCorsOrigin: ['https://ok.example', 'https://x.example/path'] }
  });
  t.check(refused && !refused.ok &&
          errorCodes.codeOf(refused) === 'STS-REG-0150',
          'a create carrying one value that is not an origin is refused whole',
          refused);
  t.check(!applications.get('cors-bad-' + suffix),
          'and nothing was written');

  const id = 'cors-writes-' + suffix;
  const created = applications.createApplication({
    identifier: id, kind: 'oauth2-client',
    fields: { oauthClientId: id,
              appCorsOrigin: ['HTTPS://Spa.Example:443/',
                              'https://spa.example'] }
  });
  t.check(created && created.ok, 'a create with two spellings of one origin ' +
          'is accepted', created);
  t.equal(JSON.stringify(applications.corsOriginsOf(applications.get(id))),
          JSON.stringify(['https://spa.example']),
          'and holds it ONCE, in the serialisation a browser sends');

  const bad = applications.updateApplication(id, {
    attribute: 'appCorsOrigin', mode: 'add', value: 'null' });
  t.check(!bad.ok && errorCodes.codeOf(bad) === 'STS-REG-0150',
          'an add of `null` is refused with STS-REG-0150', bad);
  const added = applications.updateApplication(id, {
    attribute: 'appCorsOrigin', mode: 'add', value: 'HTTP://LocalHost:5173/' });
  t.check(added.ok && added.changed, 'an add is accepted', added);
  const held = [].concat((applications.get(id).fields || {}).appCorsOrigin);
  t.check(held.indexOf('http://localhost:5173') >= 0 &&
          held.indexOf('HTTP://LocalHost:5173/') < 0,
          'and stored normalised', held);
  const again = applications.updateApplication(id, {
    attribute: 'appCorsOrigin', mode: 'add', value: 'http://localhost:5173' });
  t.check(again.ok && !again.changed,
          'adding the same origin in the other spelling changes nothing',
          again);
  const removed = applications.updateApplication(id, {
    attribute: 'appCorsOrigin', mode: 'remove',
    value: 'HTTP://LOCALHOST:5173' });
  t.check(removed.ok && removed.changed &&
          [].concat((applications.get(id).fields || {}).appCorsOrigin)
            .indexOf('http://localhost:5173') < 0,
          'a remove finds the value by its normalised spelling', removed);
  applications.deleteApplication(id);
  log.debug("Leaving registerWrites().");
}

// ---------------------------------------------------------------------------
// C. The decision, over HTTP.
// ---------------------------------------------------------------------------
function request(port, options) {
  log.debug("Entering request().");
  const opts = options || {};
  log.debug("Leaving request().");
  return new Promise(function (resolve, reject) {
    const body = opts.body || '';
    const req = http.request({
      host: '127.0.0.1', port: port, method: opts.method || 'GET',
      path: opts.path, headers: Object.assign({
        'Content-Length': Buffer.byteLength(body)
      }, opts.headers || {})
    }, function (res) {
      const chunks = [];
      res.on('data', function (chunk) { chunks.push(chunk); });
      res.on('end', function () {
        resolve({ status: res.statusCode, headers: res.headers,
                  body: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

function unsignedJwt(claims) {
  log.debug("Entering unsignedJwt().");
  const b64u = function (value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  };
  log.debug("Leaving unsignedJwt().");
  return b64u({ alg: 'RS256', typ: 'at+jwt' }) + '.' + b64u(claims) + '.sig';
}

function probeApp() {
  log.debug("Entering probeApp().");
  const express = require('express');
  const bodyParser = require('body-parser');
  const corsPolicy = require('../common/cors');
  const app = express();
  app.use(corsPolicy.preflight());
  app.options('*', corsPolicy.preflight());
  app.use(bodyParser.text({ type: function () { return true; } }));
  app.use(corsPolicy.response());
  const answer = function (req, res) {
    res.setHeader('DPoP-Nonce', 'n');
    res.status(200).json({ path: req.path });
  };
  app.get('/.well-known/openid-configuration', answer);
  app.post('/oauth2/token', answer);
  app.get('/oauth2/userinfo', answer);
  app.get('/oauth2/authorize', answer);
  app.get('/scim/v2/Users', answer);
  app.post('/saml2/sso', answer);
  app.options('/gnap', function (req, res) {
    res.status(200).json({ grant_request_endpoint: '/gnap' });
  });
  log.debug("Leaving probeApp().");
  return app;
}

async function decision(t, suffix) {
  log.debug("Entering decision().");
  t.log.info('=== C. the decision ===');
  const config = require('../common/config');
  const applications = require('../common/applications');
  const A = 'cors-a-' + suffix;
  const B = 'cors-b-' + suffix;
  const ORIGIN_A = 'https://a-' + suffix + '.example';
  const ORIGIN_B = 'https://b-' + suffix + '.example';
  const STRANGER = 'https://stranger-' + suffix + '.example';
  applications.createApplication({ identifier: A, kind: 'oauth2-client',
    fields: { oauthClientId: A, appCorsOrigin: [ORIGIN_A] } });
  applications.createApplication({ identifier: B, kind: 'oauth2-client',
    fields: { oauthClientId: B, scimClientId: 'scim-' + B,
              appCorsOrigin: [ORIGIN_B] } });
  const EMPTY = 'cors-empty-' + suffix;
  applications.createApplication({ identifier: EMPTY, kind: 'oauth2-client',
    fields: { oauthClientId: EMPTY } });

  const server = probeApp().listen(0, '127.0.0.1');
  await new Promise(function (resolve) { server.on('listening', resolve); });
  const port = server.address().port;
  const acao = function (r) {
    return r.headers['access-control-allow-origin'] || '';
  };
  const form = { 'Content-Type': 'application/x-www-form-urlencoded' };
  try {
    let r = await request(port, { path: '/.well-known/openid-configuration' });
    t.check(acao(r) === '' && /Origin/.test(r.headers.vary || ''),
            'a request with no Origin gets no CORS header, and Vary: Origin',
            r.headers);

    r = await request(port, { path: '/.well-known/openid-configuration',
                              headers: { Origin: ORIGIN_A } });
    t.equal(acao(r), ORIGIN_A, 'DISCOVERY names no client, so an origin ' +
            'any application in the realm lists is allowed');
    t.check(/DPoP-Nonce/.test(r.headers['access-control-expose-headers'] ||
                              ''),
            'and the DPoP nonce is exposed to it', r.headers);
    r = await request(port, { path: '/.well-known/openid-configuration',
                              headers: { Origin: STRANGER } });
    t.equal(acao(r), '', 'and an origin no application lists is not');
    t.check(r.headers['access-control-allow-origin'] !== '*',
            'and nothing anywhere answers `*`');

    r = await request(port, { method: 'POST', path: '/oauth2/token',
      headers: Object.assign({ Origin: ORIGIN_A }, form),
      body: 'grant_type=client_credentials&client_id=' + A });
    t.equal(acao(r), ORIGIN_A, 'a token request naming client A from A\'s ' +
            'origin is allowed');
    r = await request(port, { method: 'POST', path: '/oauth2/token',
      headers: Object.assign({ Origin: ORIGIN_B }, form),
      body: 'grant_type=client_credentials&client_id=' + A });
    t.equal(acao(r), '', 'PER CLIENT: naming A from B\'s origin is NOT ' +
            'allowed, though B\'s origin is in the realm\'s union');
    r = await request(port, { method: 'POST', path: '/oauth2/token',
      headers: Object.assign({ Origin: ORIGIN_A }, form),
      body: 'grant_type=client_credentials&client_id=no-such-' + suffix });
    t.equal(acao(r), '', 'AN UNKNOWN client_id gets no CORS header even from ' +
            'an origin the realm lists — a CORS error, not invalid_client');
    r = await request(port, { method: 'POST', path: '/oauth2/token',
      headers: Object.assign({ Origin: ORIGIN_A }, form),
      body: 'grant_type=client_credentials&client_id=' + EMPTY });
    t.equal(acao(r), '', 'a client with an EMPTY appCorsOrigin allows no ' +
            'third-party origin');
    r = await request(port, { method: 'POST', path: '/oauth2/token',
      headers: Object.assign({ Origin: ORIGIN_A,
        Authorization: 'Basic ' + Buffer.from(B + ':secret')
          .toString('base64') }, form),
      body: 'grant_type=client_credentials&client_id=' + A });
    t.equal(acao(r), '', 'two names on one request must BOTH allow the ' +
            'origin — a Basic credential for B beside client_id A');
    r = await request(port, { method: 'POST', path: '/oauth2/token',
      headers: Object.assign({ Origin: ORIGIN_B,
        Authorization: 'Basic ' + Buffer.from(B + ':secret')
          .toString('base64') }, form),
      body: 'grant_type=client_credentials' });
    t.equal(acao(r), ORIGIN_B, 'a Basic credential names its client');
    r = await request(port, { method: 'POST', path: '/oauth2/token',
      headers: Object.assign({ Origin: ORIGIN_A }, form),
      body: 'grant_type=client_credentials&client_assertion=' +
            unsignedJwt({ iss: B, sub: B }) });
    t.equal(acao(r), '', 'a client assertion names its sub — B, from A\'s ' +
            'origin, is refused');

    r = await request(port, { path: '/oauth2/userinfo',
      headers: { Origin: ORIGIN_B,
                 Authorization: 'Bearer ' + unsignedJwt({ client_id: B }) } });
    t.equal(acao(r), ORIGIN_B, 'an access token names the client it was ' +
            'issued to');
    r = await request(port, { path: '/oauth2/userinfo',
      headers: { Origin: ORIGIN_A,
                 Authorization: 'DPoP ' + unsignedJwt({ azp: B }) } });
    t.equal(acao(r), '', 'and `azp` stands in for client_id, under DPoP ' +
            'too — B\'s token from A\'s origin is refused');

    r = await request(port, { path: '/scim/v2/Users',
      headers: { Origin: ORIGIN_A,
                 Authorization: 'Basic ' + Buffer.from('alice:pw')
                   .toString('base64') } });
    t.equal(acao(r), ORIGIN_A, 'OFF an OAuth path a Basic user name that is ' +
            'no application is a PERSON, and the request names no client');
    r = await request(port, { path: '/scim/v2/Users',
      headers: { Origin: ORIGIN_A,
                 Authorization: 'Basic ' + Buffer.from('scim-' + B + ':pw')
                   .toString('base64') } });
    t.equal(acao(r), '', 'while one that IS an application (B\'s ' +
            'scimClientId) is judged against that application');

    r = await request(port, { method: 'OPTIONS', path: '/oauth2/token',
      headers: { Origin: ORIGIN_A, 'Access-Control-Request-Method': 'POST',
                 'Access-Control-Request-Headers': 'authorization,dpop' } });
    t.check(r.status === 204 && acao(r) === ORIGIN_A &&
            /POST/.test(r.headers['access-control-allow-methods'] || '') &&
            /dpop/i.test(r.headers['access-control-allow-headers'] || ''),
            'a PREFLIGHT from an origin the realm lists is answered with the ' +
            'method and headers it asked for', r);
    t.check(!r.headers['access-control-allow-credentials'],
            'and credentials are never allowed', r.headers);
    r = await request(port, { method: 'OPTIONS', path: '/oauth2/token',
      headers: { Origin: STRANGER, 'Access-Control-Request-Method': 'POST' } });
    t.check(r.status === 204 && acao(r) === '',
            'and one from an origin nobody lists is a 204 with no CORS ' +
            'headers, not a 404', r);

    const own = 'http://127.0.0.1:' + port;
    r = await request(port, { path: '/oauth2/userinfo',
      headers: { Origin: own,
                 Authorization: 'Bearer ' +
                   unsignedJwt({ client_id: 'no-such-' + suffix }) } });
    t.equal(acao(r), own, 'THIS SERVICE\'S OWN ORIGIN is allowed whatever ' +
            'the request names');
    config.setOverride('global.corsOrigins', STRANGER + ',not an origin');
    try {
      r = await request(port, { method: 'POST', path: '/oauth2/token',
        headers: Object.assign({ Origin: STRANGER }, form),
        body: 'client_id=' + A });
      t.equal(acao(r), STRANGER, 'and so is an origin global.corsOrigins ' +
              'names, beside a value there that is ignored');
    } finally {
      config.clearOverride('global.corsOrigins');
    }

    // From an origin the realm LISTS, so that deciding the navigation would
    // put a header on it and the assertion can tell the two apart.
    r = await request(port, { method: 'POST', path: '/saml2/sso',
      headers: Object.assign({ Origin: ORIGIN_A,
                               'Sec-Fetch-Mode': 'navigate' }, form),
      body: 'SAMLRequest=x' });
    t.check(r.status === 200 && acao(r) === '',
            'a cross-origin NAVIGATION is answered and not decided at all', r);

    // `oauth2.rfc9700` is restart-only for the process and settable only on a
    // realm, and this probe app has no realm middleware — so the mode's own
    // predicate is answered for the one request. What is asserted is that the
    // decision ASKS it, ahead of a client whose list allows the origin.
    const bcp = require('../oauth-oidc/oauth2_bcp');
    const corsForbidden = bcp.corsForbidden;
    bcp.corsForbidden = function (req) {
      return String(req.path) === '/oauth2/authorize';
    };
    try {
      r = await request(port, { path: '/oauth2/authorize?client_id=' + A,
                                headers: { Origin: ORIGIN_A } });
      t.equal(acao(r), '', 'RFC 9700 section 2.6 still withholds CORS from ' +
              'the authorization endpoint, for a client that lists the ' +
              'origin');
    } finally {
      bcp.corsForbidden = corsForbidden;
    }
    r = await request(port, { path: '/oauth2/authorize?client_id=' + A,
                              headers: { Origin: ORIGIN_A } });
    t.equal(acao(r), ORIGIN_A, 'and outside that mode the authorization ' +
            'endpoint is judged like any other, by the client it names');

    // WHICH CODE A WITHHELD HEADER IS LOGGED UNDER. Over HTTP an unknown
    // client and a client that does not list the origin look identical — no
    // header either way — and a mutant that dropped the unknown-client
    // refusal survived on exactly that, falling through to the second rule.
    // The code is what an operator searches for, so it is asserted here.
    const corsPolicy = require('../common/cors');
    const probe = function (method, path, origin, body) {
      return {
        method: method, path: path, query: {}, protocol: 'http',
        headers: Object.assign({ origin: origin, host: '127.0.0.1:' + port },
          body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
        body: body || '',
        get: function (name) {
          return this.headers[String(name).toLowerCase()];
        }
      };
    };
    t.equal(corsPolicy.decide(probe('POST', '/oauth2/token', ORIGIN_A,
                                    'client_id=no-such-' + suffix)).code,
            'STS-HTTP-0021', 'an unknown client is logged as STS-HTTP-0021');
    t.equal(corsPolicy.decide(probe('POST', '/oauth2/token', ORIGIN_B,
                                    'client_id=' + A)).code,
            'STS-HTTP-0022', 'a client not listing the origin as STS-HTTP-0022');
    t.equal(corsPolicy.decide(probe('GET', '/oauth2/jwks', STRANGER)).code,
            'STS-HTTP-0020', 'no client and no listing as STS-HTTP-0020');
    t.equal(corsPolicy.decide(probe('OPTIONS', '/oauth2/token', STRANGER),
                              { preflight: true }).code,
            'STS-HTTP-0019', 'and a refused preflight as STS-HTTP-0019');

    r = await request(port, { method: 'OPTIONS', path: '/gnap',
      headers: { Origin: STRANGER } });
    t.check(r.status === 200 && /grant_request_endpoint/.test(r.body) &&
            acao(r) === '',
            'GNAP\'s OPTIONS discovery reaches its route from a refused ' +
            'origin', r);
    r = await request(port, { method: 'OPTIONS', path: '/gnap',
      headers: { Origin: ORIGIN_A, 'Access-Control-Request-Method': 'POST' } });
    t.check(r.status === 200 && /grant_request_endpoint/.test(r.body) &&
            acao(r) === ORIGIN_A,
            'and from an allowed one, with the CORS headers on it', r);
  } finally {
    server.close();
    [A, B, EMPTY].forEach(function (one) {
      applications.deleteApplication(one);
    });
  }
  log.debug("Leaving decision().");
}

async function run(t) {
  log.debug("Entering run().");
  const suffix = crypto.randomBytes(4).toString('hex');
  grammar(t);
  registerWrites(t, suffix);
  await decision(t, suffix);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cors',
  describe: 'the CORS allowlist: origins, the register, and the decision',
  run: run
};
