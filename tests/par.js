'use strict';
//
// File: par.js
//
// ===========================================================================
// RFC 9126 — OAUTH 2.0 PUSHED AUTHORIZATION REQUESTS (2026-09-13).
//
// `oauth-oidc/par.js` argues the design. What is held here, every feature with
// the request that must work and the requests that must not:
//
//   1. THE LIBRARY: the request_uri namespace and its entropy, the binding to
//      a client and to an authorization server, reads that do not spend, a
//      spend that does, expiry, a full store refusing rather than forgetting,
//      the listing and the delete, and the counters;
//   2. THE REGISTRY'S CHECK: require_pushed_authorization_requests as a
//      registration member and as an attribute;
//   3. THE ENDPOINTS, in a child process on an ephemeral loopback port:
//        a. discovery — both members, a named authorization server's own URL,
//           and the member gone when the endpoint is switched off;
//        b. a push and the whole flow to a token, with the pushed PKCE and
//           redirect_uri the ones used, query parameters beside request_uri
//           ignored, the round trip through sign-in, and a replay refused;
//        c. what section 2.3 refuses: 405, 413, not a form, malformed, a
//           repeated parameter (and resource repeated accepted), request_uri
//           in a push, no client_id, two client_ids, 429;
//        d. the pushed request validated as an authorization request;
//        e. client authentication as at the token endpoint — observed in
//           development, refused in RFC 9700 mode, OAuth 2.1's one method,
//           product mode's public client, a client assertion with the PAR
//           endpoint, the issuer or another audience;
//        f. the request_uri at the authorization endpoint — unknown, another
//           client's, another authorization server's, expired;
//        g. section 2.4 — an authenticated client's unregistered redirect_uri
//           with the setting on, not with it off, not for a public client, and
//           refused at the authorization endpoint once the setting is turned
//           off (section 7.4);
//        h. the require policy — global, per client (and through RFC 7591
//           registration), per authorization server — and metadata;
//        i. section 3 — a request object pushed, bound to the authenticated
//           client, with no parameters beside it; a plain push where a signed
//           object is required, at the push and after it;
//        j. RFC 9449 section 10.1 — a DPoP proof at the push binding the code,
//           a dpop_jkt naming another key, a proof for another URL;
//        k. this service's own round-trip markers stripped from a push;
//        l. a push while the endpoint is off, and a request_uri issued before
//           it was switched off still usable (section 5);
//        m. a full store refusing 503;
//        n. OAuth 2.1 mode's default redirect_uri through a push;
//        o. the counters on /admin/oauth2/monitor's model.
//
// **THE CHILD IS NOT FASTIDIOUSNESS**, for `tests/rfc9068_access_tokens.js`'s
// reason: loading the protocol stack into `run.js`'s one process builds a
// certificate authority and registers every route on the shared app.
//
// **THE SIGNERS ARE WRITTEN HERE** — the request object, the client assertion
// and the DPoP proof — for `sts_dpop.js`'s reason: a JWT checked with the
// implementation that made it proves only that the implementation agrees with
// itself.
//
// **MUTATION-TESTED AGAINST TWENTY-TWO MUTANTS, ALL CAUGHT**, applied through a
// `NODE_OPTIONS` require hook rather than by editing the modules, because other
// sessions were editing `oauth2.js` and `applications.js` at the time: in
// `par.js` the client, authorization-server, expiry and capacity checks and the
// spend; in `oauth2.js` the spend's call, both require policies, both halves of
// section 2.4 (the push counting only a verified credential, the authorization
// endpoint asking the setting again), the request_uri refusal, the marker strip,
// the dpop_jkt and client_id-claim checks, the vetting of a push, product
// mode's public client, the signed-object refusal at the push and after it, the
// metadata removal, 413 and 429; and the registration write in
// `applications.js`. The fewest caught by any was one assertion — each of those
// is the one case in section 3 written for it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'par',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. THE LIBRARY.
// ---------------------------------------------------------------------------
function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 1. the store, the reference and the counters ===');
  const par = require('../oauth-oidc/par');
  const monitor = require('../oauth-oidc/oauth2_monitor');
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');

  t.check(par.isPushedRequestUri('urn:ietf:params:oauth:request_uri:abc') &&
          par.isPushedRequestUri('URN:IETF:params:oauth:request_uri:abc'),
          '1a. a request_uri in the namespace, the URN letters in any case');
  t.check(!par.isPushedRequestUri('urn:ietf:params:oauth:request_uri:') &&
          !par.isPushedRequestUri('https://rp.example/ro') &&
          !par.isPushedRequestUri(undefined),
          '1b. not an empty reference, an https request_uri or nothing');

  let r = par.push({ params: { response_type: 'code' } });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-OAUTH-0405',
          '1c. a push bound to nobody is refused', JSON.stringify(r));

  const params = { client_id: 'lib1', response_type: 'code',
                   redirect_uri: 'https://rp.example/cb', state: 's',
                   request: 'dropped', request_uri: 'dropped' };
  r = par.push({ clientId: 'lib1', authorizationServer: 'default',
                 params: params, clientAuthenticated: true,
                 method: 'client_secret_basic', source: 'form' });
  const reference = r.ok ? r.requestUri.slice(
    par.REQUEST_URI_PREFIX.length) : '';
  t.check(r.ok && r.requestUri.indexOf(par.REQUEST_URI_PREFIX) === 0 &&
          /^[A-Za-z0-9_-]{43}$/.test(reference) && r.expiresIn === 60,
          '1d. a push answers a urn:ietf:params:oauth:request_uri: with a ' +
          '256-bit base64url reference and the default 60s', JSON.stringify(r));
  const second = par.push({ clientId: 'lib1', params: params });
  t.check(second.ok && second.requestUri !== r.requestUri,
          '1e. two pushes are two references');
  const uri = r.requestUri;

  let got = par.resolve(uri, 'lib1', { authorizationServer: 'default' });
  t.check(got.ok && got.params.state === 's' &&
          got.params.request === undefined &&
          got.params.request_uri === undefined &&
          got.pushed.requestUri === uri && got.pushed.clientAuthenticated &&
          got.pushed.method === 'client_secret_basic',
          '1f. resolve answers the parameters without request or request_uri, ' +
          'and the facts of the push', JSON.stringify(got).slice(0, 300));
  got = par.resolve(uri, 'lib1', { req: { __asProfile: 'default' } });
  t.check(got.ok, '1g. read a second time — a read does not spend, and the ' +
          'authorization server may come off the request');
  t.check(par.get(uri).reads === 2, '1h. and both reads are counted',
          JSON.stringify(par.get(uri)));

  const refusedAs = function (answer, code) {
    return answer && !answer.ok && answer.error === 'invalid_request_uri' &&
           errorCodes.codeOf(answer) === code;
  };
  t.check(refusedAs(par.resolve(par.REQUEST_URI_PREFIX + 'nope', 'lib1'),
                    'STS-OAUTH-0410'),
          '1i. an unknown request_uri is invalid_request_uri, STS-OAUTH-0410');
  t.check(refusedAs(par.resolve('https://rp.example/ro', 'lib1'),
                    'STS-OAUTH-0410'),
          '1j. so is one outside the namespace');
  t.check(refusedAs(par.resolve(uri, 'somebody-else'), 'STS-OAUTH-0413'),
          '1k. another client\'s is refused, STS-OAUTH-0413');
  t.check(refusedAs(par.resolve(uri, 'lib1', { authorizationServer: 't1' }),
                    'STS-OAUTH-0414'),
          '1l. another authorization server\'s is refused, STS-OAUTH-0414');

  t.check(par.spend(uri) === true && par.spend(uri) === false,
          '1m. a spend spends once');
  t.check(refusedAs(par.resolve(uri, 'lib1'), 'STS-OAUTH-0412'),
          '1n. a spent request_uri is refused as USED, STS-OAUTH-0412');
  t.check(refusedAs(par.resolve(uri, 'somebody-else'), 'STS-OAUTH-0413'),
          '1o. and to another client it is still only "not yours"');

  // Expiry, with the clock moved rather than waited for.
  const realNow = Date.now;
  const later = par.push({ clientId: 'lib2', params: params });
  try {
    Date.now = function () { return realNow() + 61 * 1000; };
    t.check(refusedAs(par.resolve(later.requestUri, 'lib2'), 'STS-OAUTH-0411'),
            '1p. past its expires_in a request_uri is refused, STS-OAUTH-0411');
    const swept = par.sweep();
    t.check(swept >= 1 && par.get(later.requestUri) === null &&
            refusedAs(par.resolve(later.requestUri, 'lib2'), 'STS-OAUTH-0410'),
            '1q. a sweep drops it, and it is then simply unknown', swept);
  } finally {
    Date.now = realNow;
  }

  config.setOverride('oauth2.parRequestUriLifetimeS', 300);
  try {
    t.check(par.push({ clientId: 'lib3', params: params }).expiresIn === 300,
            '1r. oauth2.parRequestUriLifetimeS is the expires_in');
  } finally {
    config.clearOverride('oauth2.parRequestUriLifetimeS');
  }

  // A full store refuses; it does not forget.
  par.sweep(Date.now() + 3600 * 1000);
  config.setOverride('oauth2.parMaxRequests', 10);
  try {
    const kept = [];
    for (let i = 0; i < 10; i++) {
      kept.push(par.push({ clientId: 'lib4', params: params }));
    }
    const eleventh = par.push({ clientId: 'lib4', params: params });
    t.check(kept.every(function (one) { return one.ok; }) && !eleventh.ok &&
            eleventh.error === 'temporarily_unavailable' &&
            errorCodes.codeOf(eleventh) === 'STS-OAUTH-0408' &&
            par.resolve(kept[0].requestUri, 'lib4').ok,
            '1s. the eleventh push to a store of ten is refused and the first ' +
            'is still there', JSON.stringify(eleventh));
    const realNow2 = Date.now;
    try {
      Date.now = function () { return realNow2() + 61 * 1000; };
      t.check(par.push({ clientId: 'lib4', params: params }).ok,
              '1t. once they have expired, a push sweeps and is kept');
    } finally {
      Date.now = realNow2;
    }
  } finally {
    config.clearOverride('oauth2.parMaxRequests');
  }

  // The listing.
  par.sweep(Date.now() + 3600 * 1000);
  const rows = [];
  for (let i = 0; i < 5; i++) {
    rows.push(par.push({ clientId: i < 3 ? 'list-a' : 'list-b',
                        params: params }).requestUri);
  }
  par.spend(rows[0]);
  let page = par.list({ limit: 2 });
  t.check(page.total === 5 && page.items.length === 2 && page.limit === 2 &&
          page.offset === 0, '1u. the listing pages', JSON.stringify(page)
            .slice(0, 200));
  page = par.list({ offset: 4, limit: 2 });
  t.check(page.items.length === 1, '1v. and the last page holds the rest');
  t.check(par.list({ clientId: 'list-b' }).total === 2 &&
          par.list({ state: 'spent' }).total === 1 &&
          par.list({ state: 'live' }).total === 4,
          '1w. filtered by client and by state');
  const row = par.get(rows[1]);
  t.check(row && row.client_id === 'list-a' && row.state === 'live' &&
          row.redirect_uri === 'https://rp.example/cb' &&
          row.parameters.request === undefined,
          '1x. a row names the client, the state and the redirect_uri, and ' +
          'never a request or request_uri', JSON.stringify(row).slice(0, 200));
  t.check(par.remove(rows[1]) === true && par.remove(rows[1]) === false &&
          par.get(rows[1]) === null, '1y. a delete removes it once');

  // The counters.
  const snap = monitor.snapshot();
  const lib1 = snap.rows.lib1 || {};
  t.check(lib1.pushed === 2 && lib1.resolved === 2 && lib1.spent === 1 &&
          lib1.resolveRefused === 4 && lib1.errors.invalid_request_uri === 4 &&
          lib1.expired === 1,
          '1z. the counters saw every push, read, spend and refusal',
          JSON.stringify(lib1));
  t.check((snap.rows.lib2 || {}).expired === 1 &&
          (snap.rows['list-a'] || {}).deleted === 1 &&
          snap.totals.pushed >= 20 &&
          snap.sections[0].id === 'par',
          '1za. expiry and deletes are counted, and the totals add up',
          JSON.stringify(snap.totals));
  monitor.record('x', 'not.an.event');
  t.check(!(monitor.snapshot().rows.x), '1zb. an event outside the ' +
          'vocabulary is not counted');
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 2. THE REGISTRY'S CHECK.
// ---------------------------------------------------------------------------
function registry(t) {
  log.debug("Entering registry().");
  t.log.info('=== 2. require_pushed_authorization_requests ===');
  const applications = require('../common/applications');
  t.check(applications.pushedAuthorizationMetadataProblem({}) === null &&
          applications.pushedAuthorizationMetadataProblem(
            { require_pushed_authorization_requests: true }) === null &&
          applications.pushedAuthorizationMetadataProblem(
            { require_pushed_authorization_requests: false }) === null,
          '2a. absent, true and false are accepted at registration');
  const p = applications.pushedAuthorizationMetadataProblem(
    { require_pushed_authorization_requests: 'true' });
  t.check(p && p.errorCode === 'STS-REG-0120' &&
          p.error === 'invalid_client_metadata',
          '2b. the string "true" is refused, STS-REG-0120', JSON.stringify(p));
  t.check(applications.pushedAuthorizationAttributeProblem(
            'oauthRequirePushedAuthorizationRequests', 'true') === '' &&
          applications.pushedAuthorizationAttributeProblem(
            'oauthRequirePushedAuthorizationRequests', 'FALSE') === '' &&
          applications.pushedAuthorizationAttributeProblem(
            'oauthRequirePushedAuthorizationRequests', '') === '',
          '2c. TRUE and FALSE in any case, and a clear, are accepted');
  t.check(/not TRUE or FALSE/.test(applications
            .pushedAuthorizationAttributeProblem(
              'oauthRequirePushedAuthorizationRequests', 'yes')),
          '2d. anything else is refused on a console or API write');
  t.check(applications.pushedAuthorizationAttributeProblem('oauthScope',
                                                           'yes') === '',
          '2e. and no other attribute is asked');
  log.debug("Leaving registry().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINTS, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.PAR_ROOT;
  const OUT = process.env.PAR_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const b64 = function (value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  };
  function sign(alg, payload, key, header) {
    const head = Object.assign({ alg: alg }, header || {});
    const input = b64(head) + '.' + b64(payload);
    if (alg === 'none') {
      return input + '.';
    }
    const signature = crypto.sign('sha256', Buffer.from(input),
                                  { key: key, dsaEncoding: 'ieee-p1363' });
    return input + '.' + signature.toString('base64url');
  }
  function thumbprint(jwk) {
    return crypto.createHash('sha256').update(JSON.stringify(
      { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url');
  }

  let jar = {};
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.raw !== undefined ? o.raw
        : (o.form ? new URLSearchParams(o.form).toString() : '');
      const headers = Object.assign({}, o.headers || {});
      if (o.cookies && Object.keys(jar).length) {
        headers.cookie = Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      if (method !== 'GET') {
        if (!headers['content-type']) {
          headers['content-type'] = 'application/x-www-form-urlencoded';
        }
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        (res.headers['set-cookie'] || []).forEach(function (line) {
          const pair = line.split(';')[0];
          const eq = pair.indexOf('=');
          jar[pair.slice(0, eq)] = pair.slice(eq + 1);
        });
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const servers = require(ROOT + '/oauth-oidc/authorization_servers');
    const par = require(ROOT + '/oauth-oidc/par');
    const monitor = require(ROOT + '/oauth-oidc/oauth2_monitor');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;

    config.setOverride('oauth2.consentRequired', false);

    const SECRET = 'par-client-secret-0123456789abcdef0123456789';
    const REDIRECT = 'https://rp.par.example/cb';
    const OTHER_REDIRECT = 'https://rp.par.example/elsewhere';
    const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const ecJwk = Object.assign(ec.publicKey.export({ format: 'jwk' }),
                                { kid: 'par-ec', use: 'sig' });
    const make = function (id, fields) {
      return applications.createApplication({ identifier: id,
        protocols: ['oauth2'],
        fields: Object.assign({ oauthClientId: id, oauthClientSecret: SECRET,
          oauthRedirectUri: [REDIRECT],
          oauthTokenEndpointAuthMethod: 'client_secret_basic',
          oauthJwks: JSON.stringify({ keys: [ecJwk] }) }, fields || {}) });
    };
    const basicFor = function (id, secret) {
      return 'Basic ' + Buffer.from(id + ':' + (secret || SECRET))
        .toString('base64');
    };
    ['par-a', 'par-b', 'par-limit', 'par-ro'].forEach(function (id) {
      make(id);
    });
    make('par-jwt', { oauthTokenEndpointAuthMethod: 'private_key_jwt' });
    make('par-public', { oauthTokenEndpointAuthMethod: 'none',
                         oauthClientSecret: '' });
    applications.updateApplication('par-public', {
      attribute: 'oauthClientSecret', mode: 'set', value: '' });

    const pushForm = function (extra) {
      return Object.assign({ response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 'st-' + crypto.randomBytes(4).toString('hex'),
        nonce: 'n-' + crypto.randomBytes(4).toString('hex'),
        code_challenge: CHALLENGE, code_challenge_method: 'S256' },
        extra || {});
    };
    const push = function (client, extra, opts) {
      const o = opts || {};
      const headers = Object.assign({}, o.headers || {});
      if (o.basic !== false) {
        headers.authorization = basicFor(client, o.secret);
      }
      return request(port, 'POST', (o.prefix || '') + '/oauth2/par', {
        headers: headers,
        form: o.form || pushForm(Object.assign(
          o.basic === false ? { client_id: client } : {}, extra || {}))
      });
    };
    const authorize = function (query, prefix) {
      jar = {};
      return request(port, 'GET', (prefix || '') + '/oauth2/authorize?' +
                     new URLSearchParams(query).toString());
    };
    const refused = function (r, status, error, pattern) {
      return r.status === status && r.json && r.json.error === error &&
             (!pattern || pattern.test(r.json.error_description || ''));
    };
    const toSignIn = function (r) {
      return r.status === 302 &&
             /\/authn\/login/.test(String(r.headers.location || ''));
    };
    const signIn = async function (first, username) {
      if (!toSignIn(first)) {
        return { final: first, back: '' };
      }
      const page = await request(port, 'GET', first.headers.location,
                                 { cookies: true });
      const form = {};
      (page.text.match(/<input type="hidden"[^>]*>/g) || []).forEach(
        function (tag) {
          const name = /name="([^"]+)"/.exec(tag);
          const value = /value="([^"]*)"/.exec(tag);
          if (name) {
            form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
          }
        });
      form.username = username || 'par-alice';
      form.password = 'anything';
      form.action = 'login';
      // The screen's own path, which carries a realm's prefix in a realm.
      const screen = String(first.headers.location).split('?')[0]
        .replace(/^https?:\/\/[^/]+/, '');
      const posted = await request(port, 'POST', screen,
                                   { form: form, cookies: true });
      const back = String(posted.headers.location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      const final = back
        ? await request(port, 'GET', back, { cookies: true })
        : posted;
      return { final: final, back: back };
    };
    const codeOf = function (r, target) {
      const loc = String((r && r.headers && r.headers.location) || '');
      if (!r || r.status !== 302 || loc.indexOf(target || REDIRECT) !== 0) {
        return null;
      }
      return new URL(loc).searchParams;
    };
    const flow = async function (client, requestUri, prefix, extraQuery) {
      const first = await authorize(Object.assign(
        { client_id: client, request_uri: requestUri }, extraQuery || {}),
        prefix);
      const done = await signIn(first);
      return { first: first, final: done.final, back: done.back };
    };

    // --- a. discovery --------------------------------------------------------
    let meta = (await request(port, 'GET',
                              '/.well-known/oauth-authorization-server')).json;
    note(meta.pushed_authorization_request_endpoint === BASE + '/oauth2/par' &&
         meta.require_pushed_authorization_requests === false,
         '3a1. RFC 8414 metadata publishes the PAR endpoint and ' +
         'require_pushed_authorization_requests false',
         JSON.stringify([meta.pushed_authorization_request_endpoint,
                         meta.require_pushed_authorization_requests]));
    const oidc = (await request(port, 'GET',
                                '/.well-known/openid-configuration')).json;
    note(oidc.pushed_authorization_request_endpoint === BASE + '/oauth2/par',
         '3a2. and so does the OpenID Provider Configuration');
    const named = (await request(port, 'GET',
      '/.well-known/oauth-authorization-server/parAS')).json;
    note(named.pushed_authorization_request_endpoint ===
           BASE + '/parAS/oauth2/par',
         '3a3. a named authorization server publishes its own',
         named.pushed_authorization_request_endpoint);

    // --- b. a push, and the whole flow ---------------------------------------
    const form = pushForm();
    let r = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basicFor('par-a') }, form: form });
    note(r.status === 201 && /application\/json/.test(
           r.headers['content-type'] || '') &&
         /no-store/.test(r.headers['cache-control'] || '') &&
         /^urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]{43}$/.test(
           r.json.request_uri || '') && r.json.expires_in === 60,
         '3b1. a push is 201 { request_uri, expires_in }, JSON, no-store',
         r.status + ' ' + r.text.slice(0, 200));
    let uri = r.json.request_uri;
    let listed = par.get(uri);
    note(listed && listed.client_authenticated &&
         listed.authentication_method === 'client_secret_basic' &&
         listed.parameters.client_id === 'par-a' &&
         listed.parameters.client_secret === undefined,
         '3b2. the push is kept with the client authenticated and no ' +
         'credential in its parameters', JSON.stringify(listed).slice(0, 300));
    let run = await flow('par-a', uri, '',
                         { state: 'evil', redirect_uri: OTHER_REDIRECT,
                           scope: 'openid profile' });
    note(toSignIn(run.first), '3b3. the request_uri sends the browser to sign ' +
         'in', run.first.status + ' ' + run.first.headers.location);
    note(/request_uri=urn/.test(run.back) && !/code_challenge/.test(run.back) &&
         !/state=/.test(run.back),
         '3b4. the round trip carries the request_uri and not the pushed ' +
         'parameters', run.back);
    let params = codeOf(run.final);
    note(params && params.get('code') && params.get('state') === form.state,
         '3b5. the authorization response goes to the PUSHED redirect_uri with ' +
         'the PUSHED state — the query\'s own redirect_uri and state ignored',
         run.final.status + ' ' + run.final.headers.location);
    r = await request(port, 'POST', '/oauth2/token', {
      headers: { authorization: basicFor('par-a') },
      form: { grant_type: 'authorization_code', code: params.get('code'),
              redirect_uri: REDIRECT, code_verifier: VERIFIER } });
    note(r.status === 200 && r.json.access_token && r.json.id_token,
         '3b6. the code redeems with the pushed PKCE challenge\'s verifier',
         r.status + ' ' + r.text.slice(0, 200));
    note(par.get(uri) && par.get(uri).state === 'spent',
         '3b7. the request_uri is spent by the response');
    r = await authorize({ client_id: 'par-a', request_uri: uri });
    note(refused(r, 400, 'invalid_request_uri', /already used/),
         '3b8. a replay of a spent request_uri is refused 400 on this server',
         r.status + ' ' + r.text.slice(0, 200));

    // --- c. what section 2.3 refuses -----------------------------------------
    r = await request(port, 'GET', '/oauth2/par');
    note(r.status === 405 && r.headers.allow === 'POST',
         '3c1. GET is 405 with Allow: POST', r.status + ' ' + r.headers.allow);
    r = await request(port, 'PUT', '/oauth2/par', { form: pushForm() });
    note(r.status === 405, '3c2. and so is PUT', r.status);
    config.setOverride('oauth2.parMaxBodyBytes', 1024);
    try {
      r = await push('par-a', { state: 'x'.repeat(2000) });
      note(r.status === 413, '3c3. a push past oauth2.parMaxBodyBytes is 413',
           r.status + ' ' + r.text.slice(0, 120));
      r = await push('par-a');
      note(r.status === 201, '3c4. and one under it is not', r.status);
    } finally {
      config.clearOverride('oauth2.parMaxBodyBytes');
    }
    r = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basicFor('par-a'),
                 'content-type': 'application/json' },
      raw: JSON.stringify(pushForm()) });
    note(refused(r, 400, 'invalid_request', /x-www-form-urlencoded/),
         '3c5. a JSON body is refused', r.status + ' ' + r.text.slice(0, 160));
    r = await push('par-a', { max_age: 'not-a-number' });
    note(refused(r, 400, 'invalid_request'),
         '3c6. a malformed parameter is refused', r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basicFor('par-a') },
      raw: new URLSearchParams(pushForm()).toString() + '&state=again' });
    note(refused(r, 400, 'invalid_request', /repeats state/),
         '3c7. a repeated state is refused', r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basicFor('par-a') },
      raw: new URLSearchParams(pushForm()).toString() +
           '&resource=https%3A%2F%2Fapi1.par.example%2F' +
           '&resource=https%3A%2F%2Fapi2.par.example%2F' });
    const twoResources = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(twoResources && Array.isArray(twoResources.parameters.resource) &&
         twoResources.parameters.resource.length === 2,
         '3c8. resource may repeat (RFC 8707), and both are kept',
         r.status + ' ' + r.text.slice(0, 160));
    r = await push('par-a', { request_uri: 'urn:ietf:params:oauth:request_uri:x' });
    note(refused(r, 400, 'invalid_request', /MUST NOT be provided/),
         '3c9. request_uri in a push is refused (section 2.1)',
         r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/par', { form: pushForm() });
    note(refused(r, 400, 'invalid_request', /requires client_id/),
         '3c10. a push naming no client is refused', r.text.slice(0, 160));
    r = await push('par-a', { client_id: 'par-b' });
    note(refused(r, 400, 'invalid_request', /must\s+be the same client/),
         '3c11. a body client_id that is not the authenticated client is ' +
         'refused', r.text.slice(0, 160));
    config.setOverride('oauth2.parRequestsPerMinute', 3);
    try {
      const statuses = [];
      for (let i = 0; i < 4; i++) {
        statuses.push(await push('par-limit'));
      }
      const last = statuses[3];
      note(statuses.slice(0, 3).every(function (one) {
        return one.status === 201;
      }) && last.status === 429 && Number(last.headers['retry-after']) > 0,
           '3c12. the fourth push in the window is 429 with Retry-After',
           statuses.map(function (one) { return one.status; }).join(','));
      r = await push('par-b');
      note(r.status === 201, '3c13. and another client is not affected',
           r.status);
    } finally {
      config.clearOverride('oauth2.parRequestsPerMinute');
    }

    // --- d. validated as an authorization request ----------------------------
    r = await push('par-a', { response_type: 'bogus' });
    note(refused(r, 400, 'unsupported_response_type'),
         '3d1. an unsupported response_type is refused at the push',
         r.text.slice(0, 160));
    r = await push('par-a', { redirect_uri: '' });
    note(refused(r, 400, 'invalid_request', /redirect_uri/),
         '3d2. no redirect_uri is refused', r.text.slice(0, 160));
    r = await push('par-a', { redirect_uri: 'javascript:alert(1)' });
    note(r.status === 400 && r.json.error === 'invalid_request',
         '3d3. an unusable redirect_uri is refused for its shape',
         r.text.slice(0, 160));
    r = await push('par-a', { claims: '{not json' });
    note(refused(r, 400, 'invalid_request'),
         '3d4. a malformed claims request is refused', r.text.slice(0, 160));
    r = await push('par-a', { resource: 'https://api.par.example/#frag' });
    note(refused(r, 400, 'invalid_target'),
         '3d5. a resource with a fragment is invalid_target',
         r.text.slice(0, 160));
    r = await push('par-a', { authorization_details: '{"type": 1}' });
    note(refused(r, 400, 'invalid_authorization_details'),
         '3d6. malformed authorization_details are refused',
         r.text.slice(0, 160));
    r = await push('par-a', { response_mode: 'web_message' });
    note(r.status === 400 && r.json.error === 'invalid_request',
         '3d7. a response_mode this server does not advertise is refused',
         r.text.slice(0, 160));
    r = await push('par-a', { code_challenge_method: 'S512' });
    note(r.status === 400, '3d8. an unadvertised code_challenge_method is ' +
         'refused', r.text.slice(0, 160));

    // --- e. client authentication as at the token endpoint -------------------
    r = await push('par-a', {}, { secret: 'wrong-secret' });
    listed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(listed && listed.client_authenticated === false,
         '3e1. development: a wrong secret is observed, not refused — the ' +
         'token endpoint\'s own behaviour — and the push is not authenticated',
         r.status + ' ' + JSON.stringify(listed || {}).slice(0, 120));
    r = await push('par-public', {}, { basic: false });
    listed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(listed && listed.client_authenticated === false,
         '3e2. a public client pushes with client_id alone',
         r.status + ' ' + r.text.slice(0, 120));
    const assertion = function (aud, extra) {
      return sign('ES256', Object.assign({ iss: 'par-jwt', sub: 'par-jwt',
        aud: aud, jti: crypto.randomBytes(8).toString('hex'),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 120 }, extra || {}),
        ec.privateKey, { kid: 'par-ec' });
    };
    const assertionForm = function (aud) {
      return Object.assign(pushForm(), { client_id: 'par-jwt',
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion(aud) });
    };
    r = await push('par-jwt', {}, { basic: false,
                                    form: assertionForm(BASE + '/oauth2/par') });
    listed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(listed && listed.client_authenticated &&
         listed.authentication_method === 'private_key_jwt',
         '3e3. private_key_jwt with the PAR endpoint URL as its audience ' +
         'authenticates (section 2)', r.status + ' ' + r.text.slice(0, 160));
    r = await push('par-jwt', {}, { basic: false, form: assertionForm(BASE) });
    listed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(listed && listed.client_authenticated,
         '3e4. and with the issuer', r.status);
    r = await push('par-jwt', {}, { basic: false,
      form: assertionForm(BASE + '/oauth2/token') });
    listed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(listed && listed.client_authenticated,
         '3e5. and with the token endpoint URL', r.status);
    r = await push('par-jwt', {}, { basic: false,
      form: assertionForm('https://somebody-else.example/token') });
    listed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(listed && !listed.client_authenticated,
         '3e6. another audience does not authenticate (development observes)',
         r.status);

    realms.create({ id: 'par9700', overrides: { 'oauth2.rfc9700': true } });
    realms.run(realms.get('par9700'), function () {
      make('par-a');
      make('par-jwt', { oauthTokenEndpointAuthMethod: 'private_key_jwt' });
    });
    r = await push('par-a', {}, { prefix: '/realm/par9700',
                                  secret: 'wrong-secret' });
    note(r.status === 401 && r.json.error === 'invalid_client' &&
         /^Basic /.test(r.headers['www-authenticate'] || ''),
         '3e7. RFC 9700 mode: a wrong secret at PAR is 401 invalid_client ' +
         'with the Basic challenge', r.status + ' ' + r.text.slice(0, 160));
    r = await push('par-a', {}, { prefix: '/realm/par9700' });
    note(r.status === 201, '3e8. and the right one is accepted',
         r.status + ' ' + r.text.slice(0, 160));
    r = await request(port, 'POST', '/realm/par9700/oauth2/par', {
      form: assertionForm('https://somebody-else.example/token') });
    note(r.status === 401 && r.json.error === 'invalid_client',
         '3e9. RFC 9700 mode: a client assertion for another audience is ' +
         'refused', r.status + ' ' + r.text.slice(0, 160));

    realms.create({ id: 'par21', overrides: { 'oauth2.oauth21': true } });
    realms.run(realms.get('par21'), function () {
      make('par-a');
    });
    r = await push('par-a', { client_secret: SECRET },
                   { prefix: '/realm/par21' });
    note(r.status === 400 && r.json.error === 'invalid_request' &&
         /2\.4/.test(r.json.error_description || ''),
         '3e10. OAuth 2.1 mode: Basic and a body secret together are refused',
         r.status + ' ' + r.text.slice(0, 160));
    r = await push('par-a', { redirect_uri: undefined },
                   { prefix: '/realm/par21',
                     form: (function () {
                       const f = pushForm();
                       delete f.redirect_uri;
                       return f;
                     }()) });
    listed = r.status === 201 ? realms.run(realms.get('par21'), function () {
      return par.get(r.json.request_uri);
    }) : null;
    note(listed && listed.redirect_uri === REDIRECT,
         '3e11. OAuth 2.1 mode: a push with no redirect_uri takes the one ' +
         'registered (section 4.1.1)', r.status + ' ' + r.text.slice(0, 160));

    config.setOverride('global.mode', 'product');
    try {
      r = await push('par-public', {}, { basic: false });
      note(r.status === 401 && r.json.error === 'invalid_client',
           '3e12. product mode: an unauthenticated client is refused 401 at ' +
           'PAR', r.status + ' ' + r.text.slice(0, 160));
    } finally {
      config.clearOverride('global.mode');
    }

    // --- f. the request_uri at the authorization endpoint --------------------
    r = await authorize({ client_id: 'par-a',
      request_uri: 'urn:ietf:params:oauth:request_uri:unknown' });
    note(refused(r, 400, 'invalid_request_uri', /not one this/),
         '3f1. an unknown request_uri is refused 400, not redirected',
         r.status + ' ' + r.text.slice(0, 160));
    r = await push('par-a');
    uri = r.json.request_uri;
    r = await authorize({ client_id: 'par-b', request_uri: uri });
    note(refused(r, 400, 'invalid_request_uri', /different client/),
         '3f2. another client\'s request_uri is refused',
         r.text.slice(0, 160));
    r = await authorize({ request_uri: uri });
    note(r.status === 400, '3f3. a request_uri with no client_id is refused',
         r.status + ' ' + r.text.slice(0, 160));
    r = await authorize({ client_id: 'par-a', request_uri: uri }, '/parAS');
    note(refused(r, 400, 'invalid_request_uri', /authorization server/),
         '3f4. a request_uri pushed at the default authorization server is ' +
         'refused at a named one', r.text.slice(0, 160));
    r = await push('par-a', {}, { prefix: '/parAS' });
    const namedUri = r.json && r.json.request_uri;
    r = await authorize({ client_id: 'par-a', request_uri: namedUri }, '/parAS');
    note(toSignIn(r), '3f5. and one pushed at the named server works there',
         r.status + ' ' + r.text.slice(0, 160));
    r = await authorize({ client_id: 'par-a', request_uri: namedUri });
    note(refused(r, 400, 'invalid_request_uri'),
         '3f6. and not at the default one', r.status);
    config.setOverride('oauth2.parRequestUriLifetimeS', 5);
    try {
      r = await push('par-a');
      note(r.json && r.json.expires_in === 5,
           '3f7. expires_in follows oauth2.parRequestUriLifetimeS',
           r.text.slice(0, 100));
      const shortUri = r.json.request_uri;
      await new Promise(function (done) { setTimeout(done, 5600); });
      r = await authorize({ client_id: 'par-a', request_uri: shortUri });
      note(refused(r, 400, 'invalid_request_uri', /expired/),
           '3f8. an expired request_uri is refused', r.text.slice(0, 160));
    } finally {
      config.clearOverride('oauth2.parRequestUriLifetimeS');
    }

    // --- g. section 2.4 -------------------------------------------------------
    const UNREGISTERED = 'https://rp.par.example/per-request';
    r = await push('par-a', { redirect_uri: UNREGISTERED },
                   { prefix: '/realm/par9700' });
    note(r.status === 400 && /redirect/i.test(r.json.error_description || ''),
         '3g1. RFC 9700 mode, setting off: an unregistered redirect_uri is ' +
         'refused at the push', r.status + ' ' + r.text.slice(0, 160));
    realms.setOverride('par9700', 'oauth2.parAllowUnregisteredRedirectUris',
                       true);
    r = await push('par-a', { redirect_uri: UNREGISTERED },
                   { prefix: '/realm/par9700' });
    const relaxedUri = r.status === 201 ? r.json.request_uri : '';
    listed = relaxedUri ? realms.run(realms.get('par9700'), function () {
      return par.get(relaxedUri);
    }) : null;
    note(listed && listed.redirect_uri_unregistered === true,
         '3g2. setting on: an AUTHENTICATED client may push one, and the row ' +
         'says so', r.status + ' ' + r.text.slice(0, 160));
    run = await flow('par-a', relaxedUri, '/realm/par9700');
    params = codeOf(run.final, UNREGISTERED);
    note(params && params.get('code'),
         '3g3. and the authorization response goes to it',
         run.final.status + ' ' + String(run.final.headers.location || '') +
         run.final.text.slice(0, 160));
    r = await push('par-a', { redirect_uri: UNREGISTERED },
                   { prefix: '/realm/par9700', secret: 'wrong' });
    note(r.status === 401,
         '3g4. a client whose credential fails gets no such thing',
         r.status);
    r = await push('par-a', { redirect_uri: UNREGISTERED },
                   { prefix: '/realm/par9700' });
    const laterUri = r.json && r.json.request_uri;
    realms.setOverride('par9700', 'oauth2.parAllowUnregisteredRedirectUris',
                       false);
    r = await authorize({ client_id: 'par-a', request_uri: laterUri },
                        '/realm/par9700');
    note(r.status === 400 && !toSignIn(r),
         '3g5. turned off after the push, the authorization endpoint refuses ' +
         'the same request_uri (section 7.4)', r.status + ' ' +
         r.text.slice(0, 160));
    config.setOverride('oauth2.parAllowUnregisteredRedirectUris', true);
    try {
      realms.run(realms.get('par9700'), function () {
        make('par-public9700', { oauthTokenEndpointAuthMethod: 'none',
                                 oauthClientSecret: '' });
        applications.updateApplication('par-public9700', {
          attribute: 'oauthClientSecret', mode: 'set', value: '' });
      });
      realms.setOverride('par9700', 'oauth2.parAllowUnregisteredRedirectUris',
                         true);
      r = await push('par-public9700', { redirect_uri: UNREGISTERED },
                     { prefix: '/realm/par9700', basic: false });
      note(r.status === 400,
           '3g6. a PUBLIC client may not push an unregistered redirect_uri ' +
           'even with the setting on (section 7.2)', r.status + ' ' +
           r.text.slice(0, 160));
    } finally {
      config.clearOverride('oauth2.parAllowUnregisteredRedirectUris');
      realms.clearOverride('par9700', 'oauth2.parAllowUnregisteredRedirectUris');
    }

    // --- h. the require policy -----------------------------------------------
    config.setOverride('oauth2.requirePushedAuthorizationRequests', true);
    try {
      meta = (await request(port, 'GET',
                            '/.well-known/oauth-authorization-server')).json;
      note(meta.require_pushed_authorization_requests === true,
           '3h1. the metadata says PAR is required');
      r = await authorize(Object.assign({ client_id: 'par-a' }, pushForm()));
      note(refused(r, 400, 'invalid_request', /not pushed/),
           '3h2. a plain authorization request is refused 400 on this server',
           r.status + ' ' + r.text.slice(0, 160));
      r = await push('par-a');
      r = await authorize({ client_id: 'par-a', request_uri: r.json.request_uri });
      note(toSignIn(r), '3h3. and a pushed one goes through', r.status);
    } finally {
      config.clearOverride('oauth2.requirePushedAuthorizationRequests');
    }
    applications.updateApplication('par-b', {
      attribute: 'oauthRequirePushedAuthorizationRequests', mode: 'set',
      value: 'TRUE' });
    r = await authorize(Object.assign({ client_id: 'par-b' }, pushForm()));
    note(refused(r, 400, 'invalid_request', /par-b/),
         '3h4. a client carrying require_pushed_authorization_requests is ' +
         'refused a plain request', r.text.slice(0, 160));
    r = await authorize(Object.assign({ client_id: 'par-a' }, pushForm()));
    note(toSignIn(r), '3h5. and another client is not', r.status);
    r = await push('par-b');
    r = await authorize({ client_id: 'par-b', request_uri: r.json.request_uri });
    note(toSignIn(r), '3h6. the requiring client\'s pushed request works',
         r.status);
    const bad = applications.updateApplication('par-b', {
      attribute: 'oauthRequirePushedAuthorizationRequests', mode: 'set',
      value: 'maybe' });
    note(bad && bad.ok === false, '3h7. a console or API write of "maybe" is ' +
         'refused', JSON.stringify(bad).slice(0, 160));
    applications.updateApplication('par-b', {
      attribute: 'oauthRequirePushedAuthorizationRequests', mode: 'set',
      value: 'FALSE' });

    r = await request(port, 'POST', '/oauth2/register', {
      headers: { 'content-type': 'application/json' },
      raw: JSON.stringify({ redirect_uris: [REDIRECT], client_name: 'par reg',
                            require_pushed_authorization_requests: true }) });
    const registered = r.json || {};
    note(r.status === 201 &&
         registered.require_pushed_authorization_requests === true &&
         applications.clientConfigOf(registered.client_id)
           .require_pushed_authorization_requests === true,
         '3h8. RFC 7591 registration records require_pushed_authorization_' +
         'requests, and echoes it', r.status + ' ' + r.text.slice(0, 200));
    r = await authorize({ client_id: registered.client_id,
                          response_type: 'code', redirect_uri: REDIRECT,
                          code_challenge: CHALLENGE,
                          code_challenge_method: 'S256' });
    note(refused(r, 400, 'invalid_request', /not pushed/),
         '3h9. and the registered client is then held to it', r.status);
    r = await request(port, 'POST', '/oauth2/register', {
      headers: { 'content-type': 'application/json' },
      raw: JSON.stringify({ redirect_uris: [REDIRECT],
                            require_pushed_authorization_requests: 'yes' }) });
    note(refused(r, 400, 'invalid_client_metadata'),
         '3h10. a registration giving it as a string is refused',
         r.status + ' ' + r.text.slice(0, 160));
    await request(port, 'GET', '/.well-known/oauth-authorization-server/parReq');
    servers.setMember('parReq', 'require_pushed_authorization_requests',
                      'true');
    try {
      r = await authorize(Object.assign({ client_id: 'par-a' }, pushForm()),
                          '/parReq');
      note(refused(r, 400, 'invalid_request', /parReq/),
           '3h11. a named authorization server publishing the requirement ' +
           'refuses a plain request', r.status + ' ' + r.text.slice(0, 160));
      r = await authorize(Object.assign({ client_id: 'par-a' }, pushForm()));
      note(toSignIn(r), '3h12. and the default server does not', r.status);
    } finally {
      servers.removeMember('parReq', 'require_pushed_authorization_requests');
    }
    r = await authorize(Object.assign({ client_id: 'par-a' }, pushForm()),
                        '/parReq');
    note(toSignIn(r), '3h13. a removed member means the check does not run',
         r.status);

    // --- i. section 3: a pushed request object -------------------------------
    const object = function (claims, header) {
      return sign('ES256', Object.assign({ iss: 'par-a', aud: BASE,
        client_id: 'par-a', exp: Math.floor(Date.now() / 1000) + 300 },
        pushForm(), claims || {}),
        ec.privateKey, Object.assign({ typ: 'oauth-authz-req+jwt',
                                       kid: 'par-ec' }, header || {}));
    };
    r = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basicFor('par-a') },
      form: { request: object({ state: 'from-object' }) } });
    listed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(listed && listed.source === 'request' &&
         listed.request_object_alg === 'ES256' &&
         listed.parameters.state === 'from-object',
         '3i1. a signed request object pushed alone is verified and kept as ' +
         'its parameters', r.status + ' ' + r.text.slice(0, 200));
    run = await flow('par-a', r.json.request_uri);
    params = codeOf(run.final);
    note(params && params.get('state') === 'from-object',
         '3i2. and the flow runs on the object\'s parameters',
         run.final.status + ' ' + run.final.headers.location);
    r = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basicFor('par-a') },
      form: { request: object(), scope: 'openid email' } });
    note(refused(r, 400, 'invalid_request', /section 3/),
         '3i3. authorization parameters beside the object are refused',
         r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basicFor('par-a') },
      form: { request: object({ client_id: 'par-b' }) } });
    note(r.status === 400 && r.json.error === 'invalid_request_object',
         '3i4. an object naming another client_id is refused',
         r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basicFor('par-a') },
      form: { request: object({ client_id: undefined }) } });
    note(refused(r, 400, 'invalid_request_object', /no client_id claim/),
         '3i5. an authenticated client\'s object with no client_id claim is ' +
         'refused', r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/par', {
      headers: { authorization: basicFor('par-a') },
      form: { request: object({}, { kid: 'nobody' }).slice(0, -8) + 'AAAAAAAA' } });
    note(r.status === 400 && r.json.error === 'invalid_request_object',
         '3i6. an object whose signature does not verify is refused',
         r.text.slice(0, 160));
    applications.updateApplication('par-ro', {
      attribute: 'oauthRequireSignedRequestObject', mode: 'set',
      value: 'TRUE' });
    r = await push('par-ro');
    note(refused(r, 400, 'invalid_request', /signed request object is/),
         '3i7. a plain push from a client requiring signed objects is ' +
         'refused (section 2.3)', r.text.slice(0, 160));
    applications.updateApplication('par-ro', {
      attribute: 'oauthRequireSignedRequestObject', mode: 'set',
      value: 'FALSE' });
    r = await push('par-ro');
    const plainUri = r.json && r.json.request_uri;
    applications.updateApplication('par-ro', {
      attribute: 'oauthRequireSignedRequestObject', mode: 'set',
      value: 'TRUE' });
    r = await authorize({ client_id: 'par-ro', request_uri: plainUri });
    note(refused(r, 400, 'invalid_request', /pushed as plain/),
         '3i8. pushed plain before the requirement, refused at the ' +
         'authorization endpoint after it (section 7.4)',
         r.status + ' ' + r.text.slice(0, 160));
    applications.updateApplication('par-ro', {
      attribute: 'oauthRequireSignedRequestObject', mode: 'set',
      value: 'FALSE' });

    // --- j. RFC 9449 section 10.1 ---------------------------------------------
    const dpopKey = crypto.generateKeyPairSync('ec',
                                               { namedCurve: 'prime256v1' });
    const dpopJwk = dpopKey.publicKey.export({ format: 'jwk' });
    const proof = function (htm, htu) {
      return sign('ES256', { jti: crypto.randomBytes(8).toString('hex'),
                             htm: htm, htu: htu,
                             iat: Math.floor(Date.now() / 1000) },
                  dpopKey.privateKey, { typ: 'dpop+jwt', jwk: dpopJwk });
    };
    r = await push('par-a', {}, {
      headers: { dpop: proof('POST', BASE + '/oauth2/par') } });
    listed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(listed && listed.dpop_jkt === thumbprint(dpopJwk) &&
         listed.parameters.dpop_jkt === thumbprint(dpopJwk),
         '3j1. a DPoP proof at the push binds the request to its key',
         r.status + ' ' + r.text.slice(0, 160));
    run = await flow('par-a', r.json.request_uri);
    params = codeOf(run.final);
    const boundCode = params && params.get('code');
    r = await request(port, 'POST', '/oauth2/token', {
      headers: { authorization: basicFor('par-a') },
      form: { grant_type: 'authorization_code', code: boundCode,
              redirect_uri: REDIRECT, code_verifier: VERIFIER } });
    note(r.status === 400,
         '3j2. the code it bought is refused without a proof from that key',
         r.status + ' ' + r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/token', {
      headers: { authorization: basicFor('par-a'),
                 dpop: proof('POST', BASE + '/oauth2/token') },
      form: { grant_type: 'authorization_code', code: boundCode,
              redirect_uri: REDIRECT, code_verifier: VERIFIER } });
    note(r.status === 200 && /dpop/i.test(r.json.token_type || ''),
         '3j3. and redeemed with one', r.status + ' ' + r.text.slice(0, 160));
    r = await push('par-a', { dpop_jkt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
                   { headers: { dpop: proof('POST', BASE + '/oauth2/par') } });
    note(refused(r, 400, 'invalid_dpop_proof', /same key/),
         '3j4. a dpop_jkt naming another key than the proof is refused',
         r.text.slice(0, 160));
    r = await push('par-a', {}, {
      headers: { dpop: proof('POST', BASE + '/oauth2/token') } });
    note(refused(r, 400, 'invalid_dpop_proof'),
         '3j5. a proof made for another URL is refused', r.text.slice(0, 160));

    // --- k. this service's own markers are not the client's -------------------
    r = await push('par-a', { authn_error: 'access_denied',
                              consent_error: 'access_denied' });
    listed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(listed && listed.parameters.authn_error === undefined &&
         listed.parameters.consent_error === undefined,
         '3k1. a push cannot pre-load the sign-in or consent screens\' own ' +
         'round-trip fields', JSON.stringify(listed || {}).slice(0, 200));
    run = await flow('par-a', r.json.request_uri);
    note(codeOf(run.final) && codeOf(run.final).get('code'),
         '3k2. and the flow is not turned into a refusal by them',
         run.final.status + ' ' + run.final.headers.location);

    // --- l. switched off ------------------------------------------------------
    r = await push('par-a');
    const beforeOff = r.json.request_uri;
    config.setOverride('oauth2.pushedAuthorizationRequests', false);
    try {
      r = await push('par-a');
      note(r.status === 404 && r.json.error === 'invalid_request',
           '3l1. switched off, a push is 404', r.status);
      meta = (await request(port, 'GET',
                            '/.well-known/oauth-authorization-server')).json;
      note(!('pushed_authorization_request_endpoint' in meta),
           '3l2. and the metadata member is gone');
      r = await authorize({ client_id: 'par-a', request_uri: beforeOff });
      note(toSignIn(r), '3l3. a request_uri issued before still works ' +
           '(section 5)', r.status + ' ' + r.text.slice(0, 160));
    } finally {
      config.clearOverride('oauth2.pushedAuthorizationRequests');
    }

    // --- m. a full store ------------------------------------------------------
    realms.create({ id: 'parfull' });
    realms.run(realms.get('parfull'), function () {
      make('par-a');
    });
    realms.setOverride('parfull', 'oauth2.parMaxRequests', 10);
    const fills = [];
    for (let i = 0; i < 11; i++) {
      fills.push(await push('par-a', {}, { prefix: '/realm/parfull' }));
    }
    note(fills.slice(0, 10).every(function (one) {
      return one.status === 201;
    }) && fills[10].status === 503 &&
         fills[10].json.error === 'temporarily_unavailable',
         '3m1. the eleventh push to a realm holding ten is 503',
         fills.map(function (one) { return one.status; }).join(','));
    r = await push('par-a');
    note(r.status === 201, '3m2. and another realm is unaffected', r.status);

    // --- o. the counters ------------------------------------------------------
    const snap = monitor.snapshot();
    const a = snap.rows['par-a'] || {};
    note(a.pushed >= 10 && a.resolved >= 5 && a.spent >= 4 &&
         a.pushRefused >= 10 && a.resolveRefused >= 3 &&
         a.dpopBound >= 1 && a.pushedObjects >= 1 && a.errors.invalid_request,
         '3o1. /admin/oauth2/monitor\'s model counted pushes, reads, spends ' +
         'and refusals for the client', JSON.stringify(a));
    note((snap.rows['par-b'] || {}).requiredRefused >= 1,
         '3o2. and a plain request refused because PAR was required',
         JSON.stringify(snap.rows['par-b'] || {}));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== 3. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'par-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', PAR_ROOT: ROOT, PAR_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  library(t);
  registry(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rfc9126 pushed authorization requests',
  describe: 'PAR: the store and reference, the endpoint and its refusals, ' +
            'client authentication, the request_uri at the authorization ' +
            'endpoint, section 2.4, the require policy, request objects, ' +
            'DPoP, and the counters',
  run: run
};
