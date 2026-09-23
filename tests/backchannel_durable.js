'use strict';
//
// File: backchannel_durable.js
//
// ===========================================================================
// BACK-CHANNEL LOGOUT, DURABLE AND COORDINATED — AND THE TOKEN SIGNED AND
// ENCRYPTED AS THE CLIENT'S ID TOKEN IS (2026-09-17, #36 follow-up).
//
// `tests/backchannel_logout.js` holds the protocol: the members, the token's
// claims, every sign-out door, retry, 400 final. This file holds what the
// follow-up changed, in a child process on ephemeral loopback ports with a
// relying party of its own. A "process" below is a `BackchannelLogout`
// instance built from the real module's class with one dependency replaced —
// the store and the claims are the real ones, which is what two processes
// against one store share.
//
//   A. a delivery whose first POST TIMES OUT is retried and sent;
//   B. a process that DIES mid-delivery (its POST never returns) has the
//      attempt taken over by another once the lease lapses, the relying party
//      is POSTed once by the survivor, and the dead process's late outcome is
//      FENCED out — plus the merge rule itself;
//   C. two processes ending the same session send ONCE; and a global logout
//      goes THROUGH the session-end claim — with the claim already held by
//      "another node" this process sends nothing, and the sweep (that node's,
//      or the safety net) sends it once;
//   D. a final failure is a DEAD LETTER, listed, and a manual retry (the
//      console's and /admin-api's action) sends a new token;
//   E. a retry survives a RESTART: a row left pending by a process that died
//      before its timer fired is sent by a fresh one, with the same token;
//   F. nothing is pending for ever, and retention removes finished rows;
//   G. the summary line counts what happened by code;
//   H. Logout Tokens signed with ES256 and ML-DSA-44 verify; one ENCRYPTED
//      (RSA-OAEP-256) and one signed ML-DSA-65 then encrypted ECDH-ES+A256KW
//      decrypt with the relying party's key and verify;
//   I. ID TOKEN ENCRYPTION end to end: discovery, registration refusals, and
//      an encrypted id_token from the token endpoint that decrypts and
//      verifies;
//   J. an EXPIRED session sends (absolute and idle), and does not with
//      `oauth2.backchannelLogoutOnExpiry` off;
//   K. the delivery list on /admin/logout and GET /admin-api/logout is the
//      SHARED store's — a row applied from "another node" is listed — and it
//      is filtered and paged.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'backchannel_durable',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.BD_ROOT;
  const OUT = process.env.BD_OUT;
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
        const body = o.json ? JSON.stringify(o.json)
          : (o.form ? new URLSearchParams(o.form).toString() : '');
        const headers = Object.assign({}, o.headers || {});
        if (!o.noCookies && Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = o.json ? 'application/json'
            : 'application/x-www-form-urlencoded';
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
    const realms = require(ROOT + '/common/realms');
    const stsCrypto = require(ROOT + '/common/crypto');
    const backchannel = require(ROOT + '/oauth-oidc/backchannel_logout');
    const adminActions = require(ROOT + '/admin-core/admin_actions');
    const adminViews = require(ROOT + '/admin-core/admin_views');
    const clusterClaims = require(ROOT + '/cluster/cluster_claims');
    const persistence = require(ROOT + '/persistence/persistence');
    const BL = backchannel.BackchannelLogout;

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;

    // THE RELYING PARTY. Each path answers from a script of statuses (the
    // last repeats); `hang` answers the first request never.
    const received = [];
    const scripts = {};
    const hangs = {};
    const held = [];
    const rp = http.createServer(function (req, res) {
      let text = '';
      req.on('data', function (c) { text += c; });
      req.on('end', function () {
        received.push({ path: req.url, body: text,
                        token: new URLSearchParams(text).get('logout_token') ||
                               '' });
        if (hangs[req.url] > 0) {
          hangs[req.url] -= 1;
          held.push(res);
          return;
        }
        const script = scripts[req.url] || [200];
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
    config.setOverride('federation.outboundAllowHttp', true);
    config.setOverride('oauth2.backchannelLogoutBackoffMs', 0);
    config.setOverride('oauth2.backchannelLogoutTimeoutMs', 2000);
    config.setOverride('oauth2.backchannelLogoutLeaseMs', 1000);
    // The sweep is driven by hand below; the timer must not race it.
    config.setOverride('oauth2.backchannelLogoutSweepS', 3600);

    const SECRET = 'backchannel-durable-secret-0123456789abcdef';
    const REDIRECT = 'https://rp.durable.example/cb';
    const client = function (id, suffix) {
      applications.createApplication({ identifier: id,
        protocols: ['oauth2'],
        fields: { oauthClientId: id, oauthClientSecret: SECRET,
                  oauthRedirectUri: [REDIRECT],
                  oauthGrantType: ['authorization_code', 'refresh_token'],
                  oauthTokenEndpointAuthMethod: 'client_secret_basic',
                  oauthBackchannelLogoutUri: rpBase + suffix } });
    };
    const authorizeQuery = function (clientId) {
      return '/oauth2/authorize?' + new URLSearchParams({
        client_id: clientId, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 'st',
        nonce: 'n-' + crypto.randomBytes(4).toString('hex') }).toString();
    };
    const authorize = async function (b, clientId, username, secret) {
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
      const loc = String(r.headers.location || '');
      const code = r.status === 302 && loc.indexOf(REDIRECT) === 0
        ? new URL(loc).searchParams.get('code') : null;
      if (!code) {
        return { status: r.status, json: {}, text: r.text };
      }
      return b.go('POST', '/oauth2/token', {
        noCookies: true,
        headers: { authorization: 'Basic ' +
          Buffer.from(clientId + ':' + (secret || SECRET))
            .toString('base64') },
        form: { grant_type: 'authorization_code', code: code,
                redirect_uri: REDIRECT } });
    };
    const settled = async function (sessionId, since, count) {
      for (let i = 0; i < 120; i++) {
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
    // A session as authn keeps one, for the library sections.
    const sessionFor = function (id, clientId) {
      const clients = {};
      clients[clientId] = { first: Date.now(), last: Date.now(), count: 1,
                            iss: base, sub: 'urn:uuid:' + id };
      return { id: id, user: { username: 'bd-' + id, sub: 'urn:uuid:' + id },
               oidcClients: clients };
    };
    // Another "process": the real class, one dependency replaced.
    const processWith = function (overrides) {
      return new BL(Object.assign(BL.defaultDeps(), overrides || {}));
    };
    const jwks = (await browser(port).go('GET', '/oauth2/jwks')).json;
    const jwkFor = function (token) {
      const kid = partOf(token, 0).kid;
      return (jwks.keys || []).filter(function (k) {
        return k.kid === kid;
      })[0] || null;
    };

    // --- A. a timeout is retried ---------------------------------------------
    config.setOverride('oauth2.backchannelLogoutTimeoutMs', 300);
    client('bd-slow', '/bc/slow');
    hangs['/bc/slow'] = 1;
    let since = backchannel.mark();
    const slowSession = sessionFor('bd-a', 'bd-slow');
    await backchannel.dispatch(backchannel.plan(slowSession, { via: 'A' }));
    let rows = await settled('bd-a', since, 1);
    note(rows.length === 1 && rows[0].state === 'sent' &&
         rows[0].attempts === 2 && postsTo('/bc/slow').length === 2,
         'A1. a POST that TIMED OUT (STS-OAUTH-0538, retryable) is tried ' +
         'again and the delivery is sent on the second attempt',
         JSON.stringify(rows) + ' posts=' + postsTo('/bc/slow').length);
    note(postsTo('/bc/slow').length === 2 &&
         postsTo('/bc/slow')[0].token === postsTo('/bc/slow')[1].token,
         'A2. and the retry resends the SAME token (the relying party ' +
         'deduplicates on jti)');
    config.setOverride('oauth2.backchannelLogoutTimeoutMs', 2000);

    // --- B. a process dies mid-delivery ----------------------------------------
    // The lease is the setting or one request timeout and a second, whichever
    // is longer: 200ms of timeout makes it the setting's 1000ms... and 1200.
    config.setOverride('oauth2.backchannelLogoutTimeoutMs', 200);
    client('bd-take', '/bc/take');
    let releaseDead = null;
    const dead = processWith({ fedHttp: { deliverForm: function () {
      return new Promise(function (resolve) {
        releaseDead = resolve;
      });
    } } });
    since = backchannel.mark();
    const takeSession = sessionFor('bd-b', 'bd-take');
    const deadRows = dead.plan(takeSession, { via: 'B' });
    const deadAttempt = dead.attempt(deadRows[0].realm, deadRows[0].id);
    await sleep(100);
    rows = backchannel.deliveriesFor(['bd-b'], since);
    note(rows.length === 1 && rows[0].state === 'pending' &&
         rows[0].inFlight === true && postsTo('/bc/take').length === 0,
         'B1. the first process claimed attempt 1, wrote it in flight, and ' +
         'its POST never returned', JSON.stringify(rows));
    let swept = await backchannel.sweep();
    note(postsTo('/bc/take').length === 0,
         'B2. a sweep inside the lease sends nothing — the attempt is not ' +
         'due, and its claim is held', JSON.stringify(swept));
    await sleep(1500);
    swept = await backchannel.sweep();
    rows = await settled('bd-b', since, 1);
    note(rows.length === 1 && rows[0].state === 'sent' &&
         rows[0].attempts === 1 && postsTo('/bc/take').length === 1,
         'B3. once the lease lapsed, the sweep in the SURVIVING process ' +
         'claimed the same attempt and sent it — the relying party was ' +
         'POSTed once', JSON.stringify(rows) + ' ' + JSON.stringify(swept));
    const afterTakeover = JSON.stringify(rows[0]);
    releaseDead({ ok: true, status: 200 });
    const deadOutcome = await deadAttempt;
    rows = backchannel.deliveriesFor(['bd-b'], since);
    note(deadOutcome === 'claimed-elsewhere' &&
         JSON.stringify(rows[0]) === afterTakeover,
         'B4. the dead process waking up to record ITS outcome is fenced ' +
         'out: the row stays as the survivor wrote it', deadOutcome);
    const older = { generation: 1, attempts: 1, inFlight: 0, fenceAt: 10,
                    state: 'sent', updatedAt: 99 };
    const newer = { generation: 1, attempts: 1, inFlight: 0, fenceAt: 20,
                    state: 'pending', updatedAt: 5 };
    const retried = { generation: 2, attempts: 0, inFlight: 0, fenceAt: 0,
                      state: 'pending', updatedAt: 1 };
    note(backchannel.compareRows(newer, older) > 0 &&
         backchannel.compareRows(retried, newer) > 0 &&
         backchannel.compareRows(older, older) === 0,
         'B5. the merge keeps the higher fence whatever its state, and an ' +
         'operator\'s new generation over both');
    config.setOverride('oauth2.backchannelLogoutTimeoutMs', 2000);
    const summaryB = backchannel.summarise(realms.currentId(), true);
    note(/1 taken over/.test(summaryB),
         'B6. and the summary counts the takeover', summaryB);

    // --- C. two processes, one session; the global logout's claim ---------------
    client('bd-twice', '/bc/twice');
    const other = processWith({});
    const twiceSession = sessionFor('bd-c', 'bd-twice');
    since = backchannel.mark();
    const p1 = backchannel.plan(twiceSession, { via: 'node 1' });
    const p2 = other.plan(twiceSession, { via: 'node 2' });
    await Promise.all([backchannel.dispatch(p1), other.dispatch(p2)]);
    rows = await settled('bd-c', since, 1);
    note(p1[0].id === p2[0].id && rows.length === 1 &&
         rows[0].state === 'sent' && postsTo('/bc/twice').length === 1,
         'C1. two processes ending the same session plan ONE row and the ' +
         'relying party is POSTed ONCE', JSON.stringify(rows) + ' posts=' +
         postsTo('/bc/twice').length);

    // A store that CAN claim — the shape postgres gives — shared by "two
    // nodes". Installed where authn and cluster_claims ask for it.
    const shared = new Map();
    const fakeStore = {
      claimOnce: function (scope, realm, key, o) {
        const k = scope + '|' + realm + '|' + key;
        const now = Date.now();
        const had = shared.get(k);
        if (had && had.expiresAt > now) {
          return Promise.resolve({ claimed: false, existing: had });
        }
        shared.set(k, { reservation: o.reservation, claimedAt: now,
                        expiresAt: now + o.ttlMs });
        return Promise.resolve({ claimed: true, claimedAt: now,
                                 expiresAt: now + o.ttlMs });
      },
      releaseClaim: function (scope, realm, key, reservation) {
        const k = scope + '|' + realm + '|' + key;
        const had = shared.get(k);
        if (had && had.reservation === reservation) {
          shared.delete(k);
          return Promise.resolve(true);
        }
        return Promise.resolve(false);
      },
      claimHeld: function (scope, realm, key) {
        const had = shared.get(scope + '|' + realm + '|' + key);
        return Promise.resolve(!!had && had.expiresAt > Date.now());
      },
      purgeClaims: function () {
        return Promise.resolve(0);
      }
    };
    const realClusterStore = persistence.clusterStore;
    persistence.clusterStore = function () { return fakeStore; };
    try {
      client('bd-held', '/bc/held');
      const bob = browser(port);
      let r = await authorize(bob, 'bd-held', 'bd-bob');
      const bobSid = partOf(r.json.id_token, 1).sid;
      // "Another node" already reported this session's end.
      const pre = await clusterClaims.claim({ scope: 'authn.session-end',
                                              value: bobSid,
                                              ttlMs: 60000 });
      since = backchannel.mark();
      const acted = adminActions.logoutAction({ action: 'global',
                                                user: 'bd-bob' });
      await sleep(400);
      rows = backchannel.deliveriesFor([bobSid], since);
      const told = ((acted.result && acted.result.terminated) || [])
        .filter(function (one) { return one.family === 'oidc-rp'; });
      note(pre.ok && acted.ok && rows.length === 1 &&
           rows[0].state === 'pending' && postsTo('/bc/held').length === 0,
           'C2. a GLOBAL logout goes through the session-end claim: with the ' +
           'claim held by another node, this process planned the delivery ' +
           'and sent NOTHING', JSON.stringify(rows) + ' posts=' +
           postsTo('/bc/held').length);
      note(told.length === 1 && /by the end of the session itself/.test(
             told[0].message),
           'C3. the relying party row did not send for itself — it was left ' +
           'for the session\'s end', JSON.stringify(told));
      await backchannel.sweep();
      rows = await settled(bobSid, since, 1);
      note(rows[0] && rows[0].state === 'sent' &&
           postsTo('/bc/held').length === 1,
           'C4. and the sweep (the winning node\'s, or the safety net) sent ' +
           'it once', JSON.stringify(rows));
      client('bd-free', '/bc/free');
      const carol = browser(port);
      r = await authorize(carol, 'bd-free', 'bd-carol');
      const carolSid = partOf(r.json.id_token, 1).sid;
      since = backchannel.mark();
      adminActions.logoutAction({ action: 'global', user: 'bd-carol' });
      rows = await settled(carolSid, since, 1);
      note(rows[0] && rows[0].state === 'sent' &&
           postsTo('/bc/free').length === 1 &&
           /admin console/.test(rows[0].via),
           'C5. with the claim free, the global logout\'s session end won it ' +
           'and sent once, through dropSession()', JSON.stringify(rows));
    } finally {
      persistence.clusterStore = realClusterStore;
    }

    // --- D. dead letters, and the manual retry --------------------------------
    client('bd-no', '/bc/no');
    scripts['/bc/no'] = [400, 200];
    since = backchannel.mark();
    const noSession = sessionFor('bd-d', 'bd-no');
    await backchannel.dispatch(backchannel.plan(noSession, { via: 'D' }));
    rows = await settled('bd-d', since, 1);
    const deadRow = rows[0] || {};
    note(deadRow.state === 'dead' && deadRow.errorCode === 'STS-OAUTH-0536',
         'D1. a 400 is a DEAD LETTER with STS-OAUTH-0536',
         JSON.stringify(deadRow));
    note(backchannel.list({ state: 'dead' }).some(function (one) {
      return one.id === deadRow.id;
    }), 'D2. and it is on the dead-letter list');
    const retriedAnswer = adminActions.logoutAction({
      action: 'retry-backchannel', delivery: deadRow.id, actor: 'a test' });
    note(retriedAnswer.ok && retriedAnswer.delivery.state === 'pending' &&
         retriedAnswer.delivery.generation === 2,
         'D3. the console\'s and /admin-api\'s retry-backchannel queues it ' +
         'again as generation 2', JSON.stringify(retriedAnswer));
    rows = await settled('bd-d', since, 1);
    const tokens = postsTo('/bc/no').map(function (one) { return one.token; });
    note(rows[0].state === 'sent' && tokens.length === 2 &&
         partOf(tokens[0], 1).jti !== partOf(tokens[1], 1).jti,
         'D4. and it is SENT, with a new Logout Token (a new jti)',
         JSON.stringify(rows[0]));
    const again = adminActions.logoutAction({
      action: 'retry-backchannel', delivery: deadRow.id });
    const unknown = adminActions.logoutAction({
      action: 'retry-backchannel', delivery: 'no-such-delivery' });
    note(!again.ok && !unknown.ok &&
         /not a dead letter/.test(again.errors.join(' ')),
         'D5. a retry of a sent delivery, or of none, is refused',
         JSON.stringify([again, unknown]));

    // --- E. a retry survives a restart -----------------------------------------
    client('bd-restart', '/bc/restart');
    config.setOverride('oauth2.backchannelLogoutBackoffMs', 300);
    const dying = processWith({
      fedHttp: { deliverForm: function () {
        return Promise.resolve({ ok: false, kind: 'status', status: 503,
                                 why: 'it answered 503' });
      } },
      // The process died before its retry timer fired.
      later: function () {}
    });
    since = backchannel.mark();
    const restartSession = sessionFor('bd-e', 'bd-restart');
    const firstTry = await dying.attempt(
      realms.currentId(), dying.plan(restartSession, { via: 'E' })[0].id);
    rows = backchannel.deliveriesFor(['bd-e'], since);
    note(firstTry === 'retry' && rows[0].state === 'pending' &&
         rows[0].attempts === 1 && rows[0].errorCode === 'STS-OAUTH-0537',
         'E1. a 503 left the row pending with its attempt recorded and a ' +
         'retry due', JSON.stringify(rows));
    await sleep(400);
    const fresh = processWith({});
    await fresh.sweep();
    rows = await settled('bd-e', since, 1);
    note(rows[0].state === 'sent' && rows[0].attempts === 2 &&
         postsTo('/bc/restart').length === 1,
         'E2. a FRESH process — the restart — found the due row and sent ' +
         'attempt 2', JSON.stringify(rows));
    config.setOverride('oauth2.backchannelLogoutBackoffMs', 0);

    // --- F. retention ---------------------------------------------------------
    config.setOverride('oauth2.backchannelLogoutRetentionS', 60);
    client('bd-old', '/bc/old');
    const past = processWith({ now: function () {
      return Date.now() - 120000;
    } });
    since = 0;
    past.plan(sessionFor('bd-f', 'bd-old'), { via: 'F' });
    const stale = await backchannel.sweep();
    rows = backchannel.deliveriesFor(['bd-f'], 0);
    note(rows.length === 1 && rows[0].state === 'dead' &&
         rows[0].errorCode === 'STS-OAUTH-0548' &&
         postsTo('/bc/old').length === 0,
         'F1. a row still pending past the retention is dead-lettered ' +
         '(0548) rather than left pending for ever', JSON.stringify(rows) +
         ' ' + JSON.stringify(stale));
    await backchannel.sweep();
    note(backchannel.deliveriesFor(['bd-f'], 0).length === 0,
         'F2. and a finished row past the retention is removed');
    config.clearOverride('oauth2.backchannelLogoutRetentionS');

    // --- G. the summary ---------------------------------------------------------
    const summaryG = backchannel.summarise(realms.currentId(), true);
    note(/dead-lettered/.test(summaryG) && /STS-OAUTH-0536 1/.test(summaryG) &&
         /STS-OAUTH-0548 1/.test(summaryG),
         'G1. one summary line counts what was dead-lettered, by code',
         summaryG);
    note(backchannel.summarise(realms.currentId(), false) === '',
         'G2. and there is no second line until something else happens');

    // --- H. signatures and encryption ------------------------------------------
    const encRsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const encEc = crypto.generateKeyPairSync('ec',
                                             { namedCurve: 'prime256v1' });
    const rsaJwk = Object.assign(encRsa.publicKey.export({ format: 'jwk' }),
                                 { use: 'enc', kid: 'rp-rsa' });
    const ecJwk = Object.assign(encEc.publicKey.export({ format: 'jwk' }),
                                { use: 'enc', kid: 'rp-ec' });
    const registered = function (id, suffix, members) {
      applications.register(id, Object.assign({
        client_name: id, redirect_uris: [REDIRECT],
        backchannel_logout_uri: rpBase + suffix,
        token_endpoint_auth_method: 'client_secret_basic',
        client_secret: SECRET, grant_types: ['authorization_code']
      }, members));
    };
    registered('bd-es256', '/bc/es256',
               { id_token_signed_response_alg: 'ES256' });
    registered('bd-mldsa', '/bc/mldsa',
               { id_token_signed_response_alg: 'ML-DSA-44' });
    registered('bd-enc', '/bc/enc',
               { jwks: { keys: [rsaJwk] },
                 id_token_encrypted_response_alg: 'RSA-OAEP-256',
                 id_token_encrypted_response_enc: 'A256GCM' });
    registered('bd-encpq', '/bc/encpq',
               { id_token_signed_response_alg: 'ML-DSA-65',
                 jwks: { keys: [ecJwk] },
                 id_token_encrypted_response_alg: 'ECDH-ES+A256KW' });
    since = backchannel.mark();
    for (const pair of [['bd-h1', 'bd-es256'], ['bd-h2', 'bd-mldsa'],
                        ['bd-h3', 'bd-enc'], ['bd-h4', 'bd-encpq']]) {
      await backchannel.dispatch(backchannel.plan(
        sessionFor(pair[0], pair[1]), { via: 'H' }));
    }
    for (const sid of ['bd-h1', 'bd-h2', 'bd-h3', 'bd-h4']) {
      await settled(sid, since, 1);
    }
    const verifyWith = async function (token, alg) {
      try {
        const jwk = jwkFor(token);
        const key = /^ML-DSA/.test(alg) ? jwk
          : crypto.createPublicKey({ key: jwk, format: 'jwk' });
        const out = await stsCrypto.verifyCompactJwsAsync(token, key,
                                                          { algorithms: [alg] });
        return out.claims;
      } catch (e) {
        return { error: e.message };
      }
    };
    const es = (postsTo('/bc/es256')[0] || {}).token;
    const esClaims = await verifyWith(es, 'ES256');
    note(partOf(es, 0).alg === 'ES256' && partOf(es, 0).typ === 'logout+jwt' &&
         esClaims.sid === 'bd-h1' && esClaims.aud === 'bd-es256',
         'H1. a client that registered id_token_signed_response_alg ES256 is ' +
         'sent a Logout Token signed ES256 that verifies against the JWKS',
         JSON.stringify(esClaims));
    const pq = (postsTo('/bc/mldsa')[0] || {}).token;
    const pqClaims = await verifyWith(pq, 'ML-DSA-44');
    note(partOf(pq, 0).alg === 'ML-DSA-44' && pqClaims.sid === 'bd-h2',
         'H2. and one that registered ML-DSA-44 — POST-QUANTUM — is sent one ' +
         'that verifies with the published AKP key', JSON.stringify(pqClaims));
    const decrypt = function (jwe, privateKey) {
      try {
        const out = stsCrypto.decryptJweCompact(jwe, {
          privateKey: privateKey,
          allowedEnc: Object.keys(stsCrypto.JWE_ENCS) });
        return String(out.plaintext || out);
      } catch (e) {
        return 'ERROR ' + e.message;
      }
    };
    const enc = (postsTo('/bc/enc')[0] || {}).token;
    const encHeader = partOf(enc, 0);
    const inner = decrypt(enc, encRsa.privateKey);
    const innerClaims = await verifyWith(inner, 'RS256');
    note(String(enc).split('.').length === 5 &&
         encHeader.alg === 'RSA-OAEP-256' && encHeader.enc === 'A256GCM' &&
         encHeader.cty === 'JWT' && encHeader.typ === 'logout+jwt' &&
         innerClaims.sid === 'bd-h3' &&
         partOf(inner, 0).typ === 'logout+jwt',
         'H3. a client that registered id_token_encrypted_response_alg is ' +
         'sent a NESTED Logout Token: RSA-OAEP-256/A256GCM around a signed ' +
         'logout+jwt, which decrypts with the relying party\'s key and ' +
         'verifies', JSON.stringify([encHeader, innerClaims]).slice(0, 400));
    const encpq = (postsTo('/bc/encpq')[0] || {}).token;
    const pqInner = decrypt(encpq, encEc.privateKey);
    const pqInnerClaims = await verifyWith(pqInner, 'ML-DSA-65');
    note(partOf(encpq, 0).alg === 'ECDH-ES+A256KW' &&
         partOf(encpq, 0).enc === 'A128CBC-HS256' &&
         partOf(pqInner, 0).alg === 'ML-DSA-65' &&
         pqInnerClaims.sid === 'bd-h4',
         'H4. and ML-DSA-65 signed then ECDH-ES+A256KW encrypted (enc ' +
         'defaulting to A128CBC-HS256) decrypts and verifies',
         JSON.stringify(pqInnerClaims).slice(0, 300));
    rows = backchannel.deliveriesFor(['bd-h3'], since);
    note(rows[0] && rows[0].encrypted === 'RSA-OAEP-256 A256GCM',
         'H5. the delivery row says it was encrypted, and with what',
         JSON.stringify(rows[0]));

    // --- I. ID Token encryption end to end ---------------------------------------
    const anon = browser(port);
    const disco = (await anon.go('GET',
                                 '/.well-known/openid-configuration')).json;
    note(Array.isArray(disco.id_token_encryption_alg_values_supported) &&
         disco.id_token_encryption_alg_values_supported.indexOf(
           'RSA-OAEP') >= 0 &&
         disco.id_token_encryption_alg_values_supported.indexOf('dir') < 0 &&
         (disco.id_token_encryption_enc_values_supported || [])
           .indexOf('A128CBC-HS256') >= 0,
         'I1. discovery advertises id_token_encryption_alg/enc_values_' +
         'supported, asymmetric families only',
         JSON.stringify([disco.id_token_encryption_alg_values_supported,
                         disco.id_token_encryption_enc_values_supported]));
    const reg = function (members) {
      return anon.go('POST', '/oauth2/register', { json: Object.assign({
        redirect_uris: [REDIRECT], grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic' }, members) });
    };
    let r = await reg({ jwks: { keys: [rsaJwk] },
                        id_token_encrypted_response_alg: 'dir' });
    note(r.status === 400 && r.json.error === 'invalid_client_metadata' &&
         /id_token_encrypted_response_alg/.test(r.json.error_description),
         'I2. a symmetric id_token_encrypted_response_alg is refused ' +
         'invalid_client_metadata', r.status + ' ' + r.text.slice(0, 200));
    r = await reg({ jwks_uri: 'https://rp.example/jwks',
                    id_token_encrypted_response_alg: 'RSA-OAEP' });
    note(r.status === 400 && r.json.error === 'invalid_client_metadata' &&
         /jwks_uri/.test(r.json.error_description),
         'I3. an algorithm with only a jwks_uri (never fetched) is refused ' +
         'by name', r.status + ' ' + r.text.slice(0, 240));
    r = await reg({ id_token_encrypted_response_enc: 'A128GCM' });
    note(r.status === 400 && /MUST also be provided/.test(
           r.json.error_description),
         'I4. an enc with no alg is refused', r.status);
    r = await reg({ jwks: { keys: [rsaJwk] },
                    id_token_encrypted_response_alg: 'RSA-OAEP' });
    const regClient = r.json.client_id;
    note(r.status === 201 && regClient &&
         r.json.id_token_encrypted_response_alg === 'RSA-OAEP',
         'I5. an RSA-OAEP registration with a key is accepted',
         r.status + ' ' + r.text.slice(0, 200));
    const erin = browser(port);
    r = await authorize(erin, regClient, 'bd-erin', r.json.client_secret);
    const idt = String(r.json.id_token || '');
    const idHeader = partOf(idt, 0);
    const idInner = decrypt(idt, encRsa.privateKey);
    const idClaims = await verifyWith(idInner, 'RS256');
    note(r.status === 200 && idt.split('.').length === 5 &&
         idHeader.alg === 'RSA-OAEP' && idHeader.enc === 'A128CBC-HS256' &&
         idHeader.cty === 'JWT' && idClaims.aud === regClient &&
         !!idClaims.sid,
         'I6. the token endpoint returns an ENCRYPTED id_token — a Nested ' +
         'JWT that decrypts with the client\'s key and verifies',
         r.status + ' ' + JSON.stringify([idHeader, idClaims]).slice(0, 400));

    // --- J. expiry ----------------------------------------------------------
    client('bd-exp', '/bc/exp');
    const dave = browser(port);
    r = await authorize(dave, 'bd-exp', 'bd-dave');
    const daveSid = partOf(r.json.id_token, 1).sid;
    authn.sessionById(daveSid).expires = Date.now() - 1000;
    since = backchannel.mark();
    await dave.go('GET', authorizeQuery('bd-exp'));
    rows = await settled(daveSid, since, 1);
    note(rows.length === 1 && rows[0].state === 'sent' &&
         rows[0].trigger === 'expiry' && postsTo('/bc/exp').length === 1,
         'J1. a session that EXPIRED is sent its Logout Tokens too',
         JSON.stringify(rows));
    config.setOverride('authn.sessionIdleTimeoutS', 60);
    client('bd-idle', '/bc/idle');
    const frank = browser(port);
    r = await authorize(frank, 'bd-idle', 'bd-frank');
    const frankSid = partOf(r.json.id_token, 1).sid;
    authn.sessionById(frankSid).lastSeenAt = Date.now() - 120000;
    since = backchannel.mark();
    await frank.go('GET', authorizeQuery('bd-idle'));
    rows = await settled(frankSid, since, 1);
    note(rows.length === 1 && rows[0].state === 'sent' &&
         /idle/.test(rows[0].via),
         'J2. and so is one that went IDLE', JSON.stringify(rows));
    config.clearOverride('authn.sessionIdleTimeoutS');
    config.setOverride('oauth2.backchannelLogoutOnExpiry', false);
    client('bd-quiet', '/bc/quiet');
    const gina = browser(port);
    r = await authorize(gina, 'bd-quiet', 'bd-gina');
    const ginaSid = partOf(r.json.id_token, 1).sid;
    authn.sessionById(ginaSid).expires = Date.now() - 1000;
    since = backchannel.mark();
    await gina.go('GET', authorizeQuery('bd-quiet'));
    await sleep(300);
    note(backchannel.deliveriesFor([ginaSid], since).length === 0 &&
         postsTo('/bc/quiet').length === 0 && !authn.sessionById(ginaSid),
         'J3. with oauth2.backchannelLogoutOnExpiry off the expiry ends the ' +
         'session and sends nothing');
    config.clearOverride('oauth2.backchannelLogoutOnExpiry');

    // --- K. the list: shared, filtered, paged -----------------------------------
    const handle = realms.handleFor('oauth2.backchannelDeliveries');
    const foreign = {
      id: 'from-node-b', realm: realms.currentId(), sessionId: 'node-b-sid',
      clientId: 'bd-remote', uri: rpBase + '/bc/remote',
      sessionRequired: false, iss: base, sub: '', sid: 'node-b-sid',
      username: 'bd-remote', via: 'node B', trigger: 'sign-out',
      state: 'dead', generation: 1, attempts: 3, inFlight: 0, fenceAt: 1,
      holder: 'node-b:1', status: 500, errorCode: 'STS-OAUTH-0537',
      why: 'it answered 500 (after 3 attempts)', jti: '', token: '',
      tokenExp: 0, encrypted: '', queuedAt: Date.now(), nextAttemptAt: 0,
      lastAttemptAt: Date.now(), finishedAt: Date.now(),
      updatedAt: Date.now()
    };
    handle.restore(realms.currentId(), foreign.id, foreign);
    const page1 = adminViews.logoutJson({ query: { per: '2' },
                                          headers: {} }).json;
    const page2 = adminViews.logoutJson({ query: {
      per: '2', backchannelDeliveriesPage: '2' }, headers: {} }).json;
    note(page1.backchannelDeliveries.length === 2 &&
         page1.backchannelDeliveriesPaging.pages >= 2 &&
         page1.backchannelDeliveriesPaging.total ===
           backchannel.list().length &&
         page2.backchannelDeliveriesPaging.page === 2 &&
         page2.backchannelDeliveries[0].id !==
           page1.backchannelDeliveries[0].id,
         'K1. GET /admin-api/logout (and /admin/logout\'s model) PAGES the ' +
         'deliveries on backchannelDeliveriesPage',
         JSON.stringify([page1.backchannelDeliveriesPaging,
                         page2.backchannelDeliveriesPaging]));
    const deadOnly = adminViews.logoutJson({ query: {
      deliveryState: 'dead', per: '100' }, headers: {} }).json;
    note(deadOnly.backchannelDeliveries.length > 0 &&
         deadOnly.backchannelDeliveries.every(function (one) {
           return one.state === 'dead';
         }) &&
         deadOnly.backchannelDeliveries.some(function (one) {
           return one.id === 'from-node-b';
         }) &&
         deadOnly.backchannelCounts.dead ===
           deadOnly.backchannelDeliveries.length,
         'K2. deliveryState=dead is the dead-letter list, and it includes a ' +
         'row ANOTHER NODE wrote — the list is the shared store\'s',
         JSON.stringify(deadOnly.backchannelCounts));
    const searched = adminViews.logoutJson({ query: {
      deliveryq: 'bd-remote' }, headers: {} }).json;
    note(searched.backchannelDeliveries.length === 1 &&
         searched.backchannelDeliveries[0].id === 'from-node-b',
         'K3. deliveryq narrows by client', searched.backchannelDeliveries
           .length);
    const consoleView = require(ROOT + '/admin-ui/admin').logoutView({
      query: { deliveryState: 'dead' }, headers: {}, cookies: {} });
    note(/Back-channel Logout Tokens/.test(consoleView.inner) &&
         /dead letter/.test(consoleView.inner),
         'K4. /admin/logout draws the same list', String(consoleView.inner)
           .slice(0, 120));

    held.forEach(function (res) {
      try {
        res.end();
      } catch (e) {
        // A socket already closed by the timeout.
      }
    });
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
  const out = path.join(os.tmpdir(), 'backchannel-durable-' + process.pid +
                        '-' + Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', BD_ROOT: ROOT, BD_OUT: out }),
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
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'backchannel_durable',
  describe: 'Back-Channel Logout deliveries as persisted rows: a timeout ' +
            'retried, a dead process taken over and fenced out, one send for ' +
            'two processes and through the session-end claim, dead letters ' +
            'and their retry, a retry across a restart, retention, the ' +
            'summary, ES256, ML-DSA and encrypted Logout Tokens, encrypted ID ' +
            'Tokens, expiry, and the shared paged list',
  run: run
};
