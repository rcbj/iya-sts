'use strict';
//
// File: backchannel_logout.js
//
// ===========================================================================
// OPENID CONNECT BACK-CHANNEL LOGOUT 1.0 (2026-09-17, #36).
//
// `oauth-oidc/backchannel_logout.ts` argues the design. What is held here:
//
//   1. THE LIBRARY AND THE REGISTRY, in process:
//        a. the two registration members refused when they are not an http(s)
//           address without a fragment, at registration and at a console
//           write, and read back by `clientConfigOf()` with the RFC 7591
//           default;
//        b. `plan()` with the setting off plans nothing; a stored address
//           that is not usable, and a session that recorded no issuer, are
//           planned as FAILED with their codes;
//        c. the Logout Token's claims: iss, aud, iat, exp two minutes on,
//           jti, the one `events` member, sub AND sid, and no nonce;
//        d. the outbound policy in product mode: an internal address is
//           refused before any socket opens, through `deliverForm()` and
//           through a delivery, with STS-OAUTH-0534.
//   2. THE ENDPOINTS, in a child process on ephemeral loopback ports, with a
//      relying party of the test's own listening beside the service:
//        a. discovery — the two members follow `oauth2.backchannelLogout`;
//        b. an ID Token issued on a session carries `sid`;
//        c. /oauth2/logout — the relying party receives ONE form POST whose
//           `logout_token` is a `logout+jwt` signed with the realm's key
//           (verified against /oauth2/jwks), naming the ID Token's iss, sub
//           and sid, with no nonce; the delivery ends `sent` and writes one
//           `logout.backchannel` audit row;
//        d. the console's global logout (the /admin-api door too) — its
//           result lists the deliveries as `pending`, and the three relying
//           parties then see: 503 twice then 200 (sent after three attempts),
//           400 (failed at once, one POST, STS-OAUTH-0536), 500 every time
//           (failed after three POSTs, STS-OAUTH-0537); one audit row each;
//           the recent list on /admin/logout's model shows the final states;
//        e. WS-Federation's wsignout1.0 — a door front-channel logout never
//           reached — sends one too;
//        f. a selective "forget this relying party" sends to that one client
//           and leaves the session alive;
//        g. with the setting OFF nothing is sent and the ID Token still
//           carries sid while front-channel logout is on.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'backchannel_logout',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. THE LIBRARY AND THE REGISTRY.
// ---------------------------------------------------------------------------
async function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 1. the library and the registry ===');
  const config = require('../common/config');
  // The registry lives in the embedded directory, which is loaded by
  // requiring it — `redirect_uri_schemes.js` does the same.
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const errorCodes = require('../common/error_codes');
  const backchannel = require('../oauth-oidc/backchannel_logout');
  const fedHttp = require('../federation/federation_http');

  // --- a. the registration members ---------------------------------------
  const bad = applications.registrationUriProblem({
    backchannel_logout_uri: 'javascript:alert(1)' });
  t.check(bad && bad.error === 'invalid_client_metadata' &&
          bad.errorCode === 'STS-REG-0070',
          '1a1. a registration naming a javascript: backchannel_logout_uri ' +
          'is refused invalid_client_metadata (0070)', JSON.stringify(bad));
  const fragment = applications.registrationUriProblem({
    backchannel_logout_uri: 'https://rp.example/bc#frag' });
  t.check(fragment && fragment.error === 'invalid_client_metadata',
          '1a2. and so is one with a fragment — section 2.2',
          JSON.stringify(fragment));
  t.equal(applications.registrationUriProblem({
    backchannel_logout_uri: 'https://rp.example/bc?x=1' }), null,
          '1a3. an https address with a query component is accepted');
  const made = applications.createApplication({ identifier: 'bcl-lib',
    protocols: ['oauth2'],
    fields: { oauthClientId: 'bcl-lib',
              oauthRedirectUri: ['https://rp.example/cb'] } });
  t.check(made && made.ok !== false, '1a4. (an application to write onto)',
          JSON.stringify(made).slice(0, 200));
  const refused = applications.updateApplication('bcl-lib', {
    attribute: 'oauthBackchannelLogoutUri', mode: 'set',
    value: 'ftp://rp.example/bc' });
  t.check(refused && refused.ok === false &&
          errorCodes.codeOf(refused) === 'STS-REG-0071',
          '1a5. a console write of an ftp: address is refused (0071)',
          JSON.stringify(refused).slice(0, 200));
  let config0 = applications.clientConfigOf('bcl-lib');
  t.check(config0.backchannel_logout_uri === '' &&
          config0.backchannel_logout_session_required === false,
          '1a6. an entry with neither member reads as none and FALSE',
          JSON.stringify([config0.backchannel_logout_uri,
                          config0.backchannel_logout_session_required]));
  applications.updateApplication('bcl-lib', {
    attribute: 'oauthBackchannelLogoutUri', mode: 'set',
    value: 'https://rp.example/bc' });
  applications.updateApplication('bcl-lib', {
    attribute: 'oauthBackchannelLogoutSessionRequired', mode: 'set',
    value: 'TRUE' });
  config0 = applications.clientConfigOf('bcl-lib');
  t.check(config0.backchannel_logout_uri === 'https://rp.example/bc' &&
          config0.backchannel_logout_session_required === true,
          '1a7. and the two written are read back',
          JSON.stringify([config0.backchannel_logout_uri,
                          config0.backchannel_logout_session_required]));
  t.check(applications.clientConfigOf('bcl-never-seen')
            .backchannel_logout_uri === '',
          '1a8. a client never seen has no address, not undefined');

  // --- b. plan() ------------------------------------------------------------
  const session = {
    id: 'sess-bcl-1', user: { username: 'bcl-alice', sub: 'urn:uuid:bcl' },
    oidcClients: { 'bcl-lib': { first: 1, last: 1, count: 1,
                                iss: 'https://sts.example', sub: '' } }
  };
  config.setOverride('oauth2.backchannelLogout', false);
  try {
    t.equal(backchannel.plan(session, { via: 'a test' }).length, 0,
            '1b1. with oauth2.backchannelLogout off nothing is planned');
    t.equal(backchannel.enabled(), false, '1b2. and enabled() says so');
  } finally {
    config.clearOverride('oauth2.backchannelLogout');
  }
  const mark = backchannel.mark();
  const planned = backchannel.plan(session, { via: 'a test' });
  t.check(planned.length === 1 && planned[0].state === 'pending' &&
          planned[0].sid === 'sess-bcl-1' &&
          planned[0].iss === 'https://sts.example' &&
          planned[0].sessionRequired === true,
          '1b3. one pending delivery, carrying the session and the issuer ' +
          'the client was issued under', JSON.stringify(planned[0]));
  const listed = backchannel.deliveriesFor(['sess-bcl-1'], mark);
  t.check(listed.length === 1 && listed[0].state === 'pending' &&
          !('token' in listed[0]),
          '1b4. deliveriesFor() lists it, and no token is on the row',
          JSON.stringify(listed));
  t.check(/1 back-channel Logout Token \(1 pending\)/.test(
            backchannel.summarize(listed)),
          '1b5. the summary sentence counts it as pending',
          backchannel.summarize(listed));
  backchannel.abandon(planned);
  t.equal(backchannel.deliveriesFor(['sess-bcl-1'], mark)[0].state,
          'elsewhere', '1b6. a delivery handed to another process is ' +
          '"elsewhere", not left pending');

  const noIssuer = {
    id: 'sess-bcl-2', user: { username: 'bcl-alice', sub: 'urn:uuid:bcl' },
    oidcClients: { 'bcl-lib': { first: 1, last: 1, count: 1 } }
  };
  const orphan = backchannel.plan(noIssuer, {});
  t.check(orphan.length === 1 && orphan[0].state === 'failed' &&
          orphan[0].errorCode === 'STS-OAUTH-0542',
          '1b7. a session that recorded no issuer is FAILED (0542) rather ' +
          'than sent a token naming the wrong one', JSON.stringify(orphan));
  const withFallback = backchannel.plan(noIssuer,
                                        { issuer: 'https://fallback' });
  t.check(withFallback[0].state === 'pending' &&
          withFallback[0].iss === 'https://fallback',
          '1b8. unless the caller supplies the issuer');
  backchannel.abandon(withFallback);

  // A value `ldapmodify` could write, which no door would take.
  const store = require('../common/applications');
  const entry = store.get('bcl-lib');
  const hand = Object.assign({}, entry.fields,
                             { oauthBackchannelLogoutUri: 'javascript:x' });
  const loaded = store.clientConfigOf;
  store.clientConfigOf = function (id) {
    return id === 'bcl-lib'
      ? Object.assign(loaded('bcl-lib'),
                      { backchannel_logout_uri:
                          hand.oauthBackchannelLogoutUri })
      : loaded(id);
  };
  let handWritten = null;
  try {
    handWritten = backchannel.plan(session, {});
  } finally {
    store.clientConfigOf = loaded;
  }
  t.check(handWritten.length === 1 && handWritten[0].state === 'failed' &&
          handWritten[0].errorCode === 'STS-OAUTH-0544',
          '1b9. a hand-written javascript: address is checked again when ' +
          'read, and FAILED (0544)', JSON.stringify(handWritten));

  // --- c. the token's claims -----------------------------------------------
  const claims = backchannel.claimsFor(Object.assign({}, planned[0]));
  t.check(claims.iss === 'https://sts.example' && claims.aud === 'bcl-lib' &&
          claims.sub === 'urn:uuid:bcl' && claims.sid === 'sess-bcl-1' &&
          typeof claims.jti === 'string' && claims.jti.length >= 16 &&
          claims.exp - claims.iat === 120 &&
          JSON.stringify(claims.events) ===
            JSON.stringify({ [backchannel.EVENT]: {} }) &&
          !('nonce' in claims),
          '1c1. section 2.4: iss, aud, iat, exp two minutes on, jti, the ' +
          'one events member, sub AND sid, and NO nonce',
          JSON.stringify(claims));
  t.equal(backchannel.EVENT,
          'http://schemas.openid.net/event/backchannel-logout',
          '1c2. the event member is the specification\'s');
  const signed = await backchannel.logoutToken(Object.assign({},
                                                             planned[0]));
  const header = JSON.parse(Buffer.from(signed.split('.')[0], 'base64url')
    .toString('utf8'));
  t.check(header.typ === 'logout+jwt' && header.alg === 'RS256' &&
          !!header.kid,
          '1c3. the header is typ logout+jwt, RS256 (no alg registered), ' +
          'with the kid of the realm key', JSON.stringify(header));

  // --- d. product mode refuses an internal address ------------------------
  const productHttp = new fedHttp.FederationHttp(Object.assign(
    fedHttp.FederationHttp.defaultDeps(),
    { mode: { dialsInternalAddresses: function () { return false; } } }));
  config.setOverride('federation.outboundAllowInsecure', true);
  try {
    const http = require('http');
    let hits = 0;
    const listener = http.createServer(function (req, res) {
      hits++;
      res.end('ok');
    });
    await new Promise(function (r) { listener.listen(0, '127.0.0.1', r); });
    const address = 'http://127.0.0.1:' + listener.address().port + '/bc';
    try {
      const answer = await productHttp.deliverForm(
        { id: 'bcl-lib', oauthBackchannelLogoutUri: address },
        'oauthBackchannelLogoutUri', { logout_token: 'x' });
      t.check(answer.ok === false && answer.kind === 'internal' &&
              /loopback, private/.test(answer.why),
              '1d1. product mode: deliverForm() refuses a loopback address',
              JSON.stringify(answer));
      const devAnswer = await fedHttp.deliverForm(
        { id: 'bcl-lib', oauthBackchannelLogoutUri: address },
        'oauthBackchannelLogoutUri', { logout_token: 'x' });
      t.check(devAnswer.ok === true && devAnswer.status === 200,
              '1d2. CONTROL: development mode dials the same address',
              JSON.stringify(devAnswer));
      const wrongName = await fedHttp.deliverForm(
        { id: 'bcl-lib', fedTokenUrl: address }, 'fedTokenUrl', {});
      t.check(wrongName.ok === false && wrongName.kind === 'attribute',
              '1d3. deliverForm() will not send to a DIALLABLE attribute — ' +
              'the two lists do not borrow each other\'s names',
              JSON.stringify(wrongName));
      const BL = backchannel.BackchannelLogout;
      const productBc = new BL(Object.assign(BL.defaultDeps(),
                                             { fedHttp: productHttp }));
      const productSession = {
        id: 'sess-bcl-3', user: { username: 'bcl-alice', sub: 'u' },
        oidcClients: { 'bcl-lib': { first: 1, iss: 'https://sts.example' } }
      };
      const stored = applications.clientConfigOf;
      applications.clientConfigOf = function (id) {
        return Object.assign(stored(id), { backchannel_logout_uri: address });
      };
      let rows = [];
      try {
        rows = productBc.plan(productSession, {});
        await productBc.dispatch(rows);
      } finally {
        applications.clientConfigOf = stored;
      }
      t.check(rows.length === 1 && rows[0].state === 'failed' &&
              rows[0].errorCode === 'STS-OAUTH-0534' && rows[0].attempts === 1,
              '1d4. and a delivery in product mode fails with 0534 after ONE ' +
              'attempt — a policy refusal is not retried',
              JSON.stringify(rows));
      t.equal(hits, 1, '1d5. the listener saw only the development-mode ' +
              'control, never the refused product-mode requests');
    } finally {
      listener.close();
    }
  } finally {
    config.clearOverride('federation.outboundAllowInsecure');
  }
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 2. THE ENDPOINTS, IN A CHILD PROCESS.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.BCL_ROOT;
  const OUT = process.env.BCL_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const partOf = function (jwt, n) {
    try {
      return JSON.parse(Buffer.from(String(jwt).split('.')[n], 'base64url')
        .toString('utf8'));
    } catch (e) {
      return { parseError: e.message };
    }
  };
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign({}, o.headers || {});
        if (!o.noCookies && Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
                                   path: String(urlPath).replace(
                                     /^https?:\/\/[^/]+/, ''),
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
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, json: parsed });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }
  const hiddenFields = function (html) {
    const form = {};
    (html.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
      }
    });
    return form;
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const authn = require(ROOT + '/authn/authn');
    const backchannel = require(ROOT + '/oauth-oidc/backchannel_logout');
    const adminActions = require(ROOT + '/admin-core/admin_actions');
    const adminViews = require(ROOT + '/admin-core/admin_views');
    const logout = require(ROOT + '/logout/logout');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    // THE RELYING PARTY: every POST recorded, and each path answering from a
    // script of statuses (the last one repeats).
    const received = [];
    const scripts = { '/bc/ok': [200], '/bc/flaky': [503, 503, 204],
                      '/bc/refuse': [400], '/bc/down': [500],
                      '/bc/wsfed': [200], '/bc/one': [200],
                      '/bc/off': [200] };
    const rp = http.createServer(function (req, res) {
      let text = '';
      req.on('data', function (c) { text += c; });
      req.on('end', function () {
        received.push({ path: req.url, method: req.method,
                        type: String(req.headers['content-type'] || ''),
                        body: text });
        const script = scripts[req.url] || [404];
        const status = script.length > 1 ? script.shift() : script[0];
        res.writeHead(status, { 'cache-control': 'no-store' });
        res.end();
      });
    });
    await new Promise(function (r) { rp.listen(0, '127.0.0.1', r); });
    const rpBase = 'http://127.0.0.1:' + rp.address().port;
    const postsTo = function (p) {
      return received.filter(function (one) { return one.path === p; });
    };

    config.setOverride('oauth2.consentRequired', false);
    config.setOverride('federation.outboundAllowInsecure', true);
    config.setOverride('oauth2.backchannelLogoutBackoffMs', 0);
    config.setOverride('oauth2.backchannelLogoutTimeoutMs', 2000);

    const SECRET = 'backchannel-client-secret-0123456789abcdef0123';
    const REDIRECT = 'https://rp.backchannel.example/cb';
    const client = function (id, suffix) {
      const made = applications.createApplication({ identifier: id,
        protocols: ['oauth2'],
        fields: { oauthClientId: id, oauthClientSecret: SECRET,
                  oauthRedirectUri: [REDIRECT],
                  oauthGrantType: ['authorization_code'],
                  oauthTokenEndpointAuthMethod: 'client_secret_basic',
                  oauthBackchannelLogoutUri: rpBase + suffix,
                  oauthBackchannelLogoutSessionRequired: 'TRUE' } });
      note(made && made.ok !== false, '2.0 (client ' + id + ' registered)',
           JSON.stringify(made).slice(0, 200));
    };
    client('bcl-ok', '/bc/ok');
    client('bcl-flaky', '/bc/flaky');
    client('bcl-refuse', '/bc/refuse');
    client('bcl-down', '/bc/down');
    client('bcl-wsfed', '/bc/wsfed');
    client('bcl-one', '/bc/one');
    client('bcl-off', '/bc/off');

    const authorizeQuery = function (clientId) {
      return '/oauth2/authorize?' + new URLSearchParams({
        client_id: clientId, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 'st',
        nonce: 'n-' + crypto.randomBytes(4).toString('hex') }).toString();
    };
    const codeOf = function (r) {
      const loc = String((r && r.headers && r.headers.location) || '');
      return r && r.status === 302 && loc.indexOf(REDIRECT) === 0
        ? new URL(loc).searchParams.get('code') : null;
    };
    // Authorize one client for this browser, signing in first if needed, and
    // redeem the code. Answers the token response.
    const authorize = async function (b, clientId, username) {
      let r = await b.go('GET', authorizeQuery(clientId));
      if (r.status === 302 &&
          /\/authn\/login/.test(String(r.headers.location || ''))) {
        const page = await b.go('GET', r.headers.location);
        const form = hiddenFields(page.text);
        form.username = username;
        form.password = 'anything';
        form.action = 'login';
        const screen = String(r.headers.location).split('?')[0]
          .replace(/^https?:\/\/[^/]+/, '');
        const posted = await b.go('POST', screen, { form: form });
        r = await b.go('GET', String(posted.headers.location || ''));
      }
      const code = codeOf(r);
      if (!code) {
        return { status: r.status, json: {}, text: r.text };
      }
      return b.go('POST', '/oauth2/token', {
        noCookies: true,
        headers: { authorization: 'Basic ' +
          Buffer.from(clientId + ':' + SECRET).toString('base64') },
        form: { grant_type: 'authorization_code', code: code,
                redirect_uri: REDIRECT } });
    };
    const settled = async function (sessionId, since, count) {
      for (let i = 0; i < 100; i++) {
        const rows = backchannel.deliveriesFor([sessionId], since);
        if (rows.length >= count && rows.every(function (row) {
          return row.state !== 'pending';
        })) {
          return rows;
        }
        await sleep(50);
      }
      return backchannel.deliveriesFor([sessionId], since);
    };
    const auditRows = function (clientId) {
      return audit.list().filter(function (row) {
        return row.action === 'logout.backchannel' &&
               row.target === clientId;
      });
    };

    // --- a. discovery --------------------------------------------------------
    const anon = browser(port);
    let r = await anon.go('GET', '/.well-known/openid-configuration');
    note(r.json.backchannel_logout_supported === true &&
         r.json.backchannel_logout_session_supported === true,
         '2a1. discovery advertises backchannel_logout_supported and ' +
         '_session_supported', JSON.stringify([
           r.json.backchannel_logout_supported,
           r.json.backchannel_logout_session_supported]));
    config.setOverride('oauth2.backchannelLogout', false);
    r = await anon.go('GET', '/.well-known/openid-configuration');
    note(r.json.backchannel_logout_supported === false &&
         r.json.backchannel_logout_session_supported === false,
         '2a2. and both read false with oauth2.backchannelLogout off',
         JSON.stringify([r.json.backchannel_logout_supported,
                         r.json.backchannel_logout_session_supported]));
    config.clearOverride('oauth2.backchannelLogout');
    const jwks = (await anon.go('GET', '/oauth2/jwks')).json;

    // --- b, c. /oauth2/logout ------------------------------------------------
    const alice = browser(port);
    r = await authorize(alice, 'bcl-ok', 'bcl-alice');
    const idToken = partOf(r.json.id_token, 1);
    note(r.status === 200 && !!idToken.sid,
         '2b1. the ID Token issued on the session carries sid',
         r.status + ' ' + JSON.stringify(idToken).slice(0, 200));
    let since = backchannel.mark();
    r = await alice.go('GET', '/oauth2/logout');
    note(r.status === 200, '2c0. /oauth2/logout answers at once', r.status);
    let rows = await settled(idToken.sid, since, 1);
    const okPosts = postsTo('/bc/ok');
    note(okPosts.length === 1 && okPosts[0].method === 'POST' &&
         /^application\/x-www-form-urlencoded/.test(okPosts[0].type),
         '2c1. the relying party received ONE form POST (section 2.5)',
         JSON.stringify(okPosts).slice(0, 300));
    const token = okPosts.length
      ? new URLSearchParams(okPosts[0].body).get('logout_token') : '';
    const head = partOf(token, 0);
    const body = partOf(token, 1);
    note(head.typ === 'logout+jwt' && head.alg === 'RS256',
         '2c2. the logout_token is typed logout+jwt and signed RS256',
         JSON.stringify(head));
    note(body.iss === idToken.iss && body.aud === 'bcl-ok' &&
         body.sub === idToken.sub && body.sid === idToken.sid &&
         !('nonce' in body) &&
         body.events && typeof body.events[
           'http://schemas.openid.net/event/backchannel-logout'] === 'object' &&
         body.exp > body.iat && !!body.jti,
         '2c3. it names the ID Token\'s iss, sub and sid, is addressed to the ' +
         'client, carries the event, and has no nonce',
         JSON.stringify(body));
    const jwk = (jwks.keys || []).filter(function (k) {
      return k.kid === head.kid;
    })[0];
    let verified = false;
    try {
      const parts = token.split('.');
      verified = !!jwk && crypto.verify('sha256',
        Buffer.from(parts[0] + '.' + parts[1]),
        crypto.createPublicKey({ key: jwk, format: 'jwk' }),
        Buffer.from(parts[2], 'base64url'));
    } catch (e) {
      verified = false;
    }
    note(verified, '2c4. its signature verifies against the realm JWKS ' +
         '(kid ' + head.kid + ')', JSON.stringify(jwk || {}).slice(0, 120));
    note(rows.length === 1 && rows[0].state === 'sent' &&
         rows[0].attempts === 1 && rows[0].status === 200,
         '2c5. the delivery ends sent, after one attempt',
         JSON.stringify(rows));
    note(auditRows('bcl-ok').length === 1 &&
         auditRows('bcl-ok')[0].outcome === 'success',
         '2c6. ONE logout.backchannel audit row records it',
         JSON.stringify(auditRows('bcl-ok')).slice(0, 300));
    r = await alice.go('GET', authorizeQuery('bcl-ok'));
    note(r.status === 302 && /\/authn\/login/.test(r.headers.location),
         '2c7. and the session is gone', r.status);

    // --- d. the console's global logout: retry, 400, 5xx --------------------
    const bob = browser(port);
    r = await authorize(bob, 'bcl-flaky', 'bcl-bob');
    const bobSid = partOf(r.json.id_token, 1).sid;
    await authorize(bob, 'bcl-refuse', 'bcl-bob');
    await authorize(bob, 'bcl-down', 'bcl-bob');
    since = backchannel.mark();
    const acted = adminActions.logoutAction({ action: 'global',
                                              user: 'bcl-bob' });
    const listedNow = (acted.result && acted.result.backchannel) || [];
    note(acted.ok && listedNow.length === 3 &&
         listedNow.every(function (row) { return row.state === 'pending'; }),
         '2d1. the console\'s (and /admin-api\'s) global logout lists three ' +
         'deliveries, each PENDING — they are sent after the answer',
         JSON.stringify(listedNow).slice(0, 400));
    note(/3 back-channel Logout Tokens \(3 pending\)/.test(acted.message) &&
         /BACK-CHANNEL Logout Tokens need no browser/.test(acted.message),
         '2d2. and its message says so', acted.message);
    rows = await settled(bobSid, since, 3);
    const byClient = {};
    rows.forEach(function (row) { byClient[row.clientId] = row; });
    const flaky = byClient['bcl-flaky'] || {};
    note(flaky.state === 'sent' && flaky.attempts === 3 &&
         flaky.status === 204 && postsTo('/bc/flaky').length === 3,
         '2d3. 503, 503, 204: retried and SENT on the third attempt (204 ' +
         'is success, section 2.8)', JSON.stringify(flaky));
    const refuse = byClient['bcl-refuse'] || {};
    note(refuse.state === 'failed' && refuse.attempts === 1 &&
         refuse.errorCode === 'STS-OAUTH-0536' &&
         postsTo('/bc/refuse').length === 1,
         '2d4. 400 is FINAL — one POST, failed with 0536',
         JSON.stringify(refuse) + ' posts=' + postsTo('/bc/refuse').length);
    const down = byClient['bcl-down'] || {};
    note(down.state === 'failed' && down.attempts === 3 &&
         down.errorCode === 'STS-OAUTH-0537' &&
         postsTo('/bc/down').length === 3,
         '2d5. 500 every time: three POSTs (the attempts setting), then ' +
         'failed with 0537', JSON.stringify(down) + ' posts=' +
         postsTo('/bc/down').length);
    note(auditRows('bcl-flaky').length === 1 &&
         auditRows('bcl-refuse').length === 1 &&
         auditRows('bcl-down').length === 1 &&
         auditRows('bcl-down')[0].errorCode === 'STS-OAUTH-0537' &&
         auditRows('bcl-refuse')[0].errorCode === 'STS-OAUTH-0536',
         '2d6. ONE audit row per delivery, not one per attempt, each failure ' +
         'with its code', JSON.stringify([auditRows('bcl-flaky').length,
                                          auditRows('bcl-refuse').length,
                                          auditRows('bcl-down').length]));
    const view = adminViews.logoutJson({ query: {}, headers: {} });
    const recent = (view.json && view.json.backchannelDeliveries) || [];
    note(recent.some(function (row) {
           return row.clientId === 'bcl-down' && row.state === 'failed';
         }) && recent.some(function (row) {
           return row.clientId === 'bcl-flaky' && row.state === 'sent';
         }),
         '2d7. /admin/logout\'s model (and GET /admin-api/logout) lists ' +
         'where each delivery got to', JSON.stringify(recent).slice(0, 300));

    // --- e. WS-Federation's sign-out -----------------------------------------
    const carol = browser(port);
    r = await authorize(carol, 'bcl-wsfed', 'bcl-carol');
    const carolSid = partOf(r.json.id_token, 1).sid;
    since = backchannel.mark();
    r = await carol.go('GET', '/wsfed?wa=wsignout1.0');
    rows = await settled(carolSid, since, 1);
    note(rows.length === 1 && rows[0].state === 'sent' &&
         postsTo('/bc/wsfed').length === 1 &&
         /wsignout|WS-Federation|sign-out/i.test(rows[0].via),
         '2e1. wsignout1.0 ends the session and the OIDC relying party is ' +
         'sent its Logout Token — a door front-channel never reached',
         r.status + ' ' + JSON.stringify(rows));

    // --- f. forgetting one relying party ------------------------------------
    const dave = browser(port);
    r = await authorize(dave, 'bcl-one', 'bcl-dave');
    const daveSid = partOf(r.json.id_token, 1).sid;
    since = backchannel.mark();
    const selective = logout.terminate('bcl-dave',
      ['oidc-rp:' + daveSid + '|bcl-one'], { by: 'this test' });
    rows = await settled(daveSid, since, 1);
    note(selective.terminated.length === 1 &&
         (selective.backchannel || []).length === 1 &&
         rows.length === 1 && rows[0].state === 'sent' &&
         postsTo('/bc/one').length === 1,
         '2f1. a selective "forget this relying party" sends it a Logout ' +
         'Token', JSON.stringify(selective).slice(0, 300));
    note(!!authn.sessionById(daveSid),
         '2f2. and the session itself stays');
    authn.endSessionById(daveSid, 'this test');
    await sleep(200);
    note(postsTo('/bc/one').length === 1,
         '2f3. ending the session afterwards does not tell the forgotten ' +
         'client twice', postsTo('/bc/one').length);

    // --- g. the setting off ---------------------------------------------------
    config.setOverride('oauth2.backchannelLogout', false);
    const erin = browser(port);
    r = await authorize(erin, 'bcl-off', 'bcl-erin');
    const erinId = partOf(r.json.id_token, 1);
    note(!!erinId.sid, '2g1. with it off the ID Token still carries sid, ' +
         'because front-channel logout is on and needs it',
         JSON.stringify(erinId).slice(0, 200));
    since = backchannel.mark();
    await erin.go('GET', '/oauth2/logout');
    await sleep(400);
    note(postsTo('/bc/off').length === 0 &&
         backchannel.deliveriesFor([erinId.sid], since).length === 0,
         '2g2. and a sign-out sends nothing and plans nothing',
         postsTo('/bc/off').length);
    config.setOverride('oauth2.frontchannelLogout', false);
    const frank = browser(port);
    r = await authorize(frank, 'bcl-off', 'bcl-frank');
    note(r.status === 200 && !('sid' in partOf(r.json.id_token, 1)),
         '2g3. with BOTH off the ID Token carries no sid',
         JSON.stringify(partOf(r.json.id_token, 1)).slice(0, 200));
    config.clearOverride('oauth2.frontchannelLogout');
    config.clearOverride('oauth2.backchannelLogout');

    server.close();
    rp.close();
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
  t.log.info('=== 2. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'backchannel-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', BCL_ROOT: ROOT, BCL_OUT: out }),
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
  await library(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'backchannel_logout',
  describe: 'OpenID Connect Back-Channel Logout 1.0: the registration ' +
            'members, the Logout Token, discovery and sid under the setting, ' +
            'delivery from every sign-out door with bounded retry, 400 ' +
            'final, the product-mode outbound refusal, and the audit rows',
  run: run
};
