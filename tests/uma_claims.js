// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/uma_claims.js
//
// ---------------------------------------------------------------------------// HOW A STRANGER BECOMES KNOWN, AND HOW AN OWNER IS ASKED (#1168 phase 5,
// #1194), in a child process over a plain listener:
//
//   C. the claims interaction endpoint: an unknown client and an
//      unregistered claims_redirect_uri are told to the person, never
//      redirected; nobody signed in is sent to the sign-in; signed in, the
//      person is recorded and sent back with claims_submitted, a new ticket
//      and the state; the next grant issues an RPT and a PCT; an unusable
//      ticket goes back not_authorized
//   T. a pushed claim_token: this realm's ID Token for the client names
//      the person; one for another client names nobody (need_info)
//   A. "ask me each time": request_submitted with a rotated ticket and an
//      interval; still waiting; the owner approves on the portal's door and
//      the next poll issues — the approval a rule of the owner's document;
//      a refusal is request_denied; a full queue is request_denied

// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const http = require('http');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_UMA_CLAIMS_CHILD';
const MARK = 'UMA-CLAIMS-CHILD ';
const REALM = 'umaclaims';
const PREFIX = '/realm/' + REALM;
const SECRET = 'umaclaims-secret-0123456789abcdef';
const PROTECTION = 'urn:sts:uma-protection-api:uma_protection';

const GRANT = 'urn:ietf:params:oauth:grant-type:uma-ticket';

const log = require('bunyan').createLogger({ name: 'uma_claims',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function request(port, method, urlPath, body, headers) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const text = body === undefined ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const sent = Object.assign({ 'content-type': 'application/json',
                                 'content-length': Buffer.byteLength(text) },
                               headers || {});
    const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
      method: method, headers: sent, agent: false }, function (res) {
      let raw = '';
      res.on('data', function (chunk) {
        raw += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in request(): " + e.message);
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: raw,
                  json: json });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in request(): " + e.message);
      resolve({ status: 0, headers: {}, text: '', json: null,
                error: e.message });
    });
    req.end(text);
  });
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const applications = require(ROOT + '/common/applications');
  const errorCodes = require(ROOT + '/common/error_codes');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const store = require(ROOT + '/uma/uma_store');
  const owner = require(ROOT + '/uma/uma_owner_policy');
  const claimsModule = require(ROOT + '/uma/uma_claims');
  const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
  const screen = require(ROOT + '/tests/tools/authn_screen');

  const marks = [];
  const mark = errorCodes.mark;
  errorCodes.mark = function (res, code) {
    marks.push(code);
    return mark.apply(this, arguments);
  };
  const markedSince = function (since, code) {
    log.debug("Entering markedSince().");
    log.debug("Leaving markedSince().");
    return marks.slice(since).indexOf(code) >= 0;
  };
  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };
  const BACK = 'https://client.example/uma/back';
  let bob = '';
  inRealm(function () {
    config.setOverride('uma.enabled', true);
    ldap.createUser('uc-bob', { invent: false });
    ldap.createUser('uc-ann', { invent: false });
    bob = helpers.subjectForName('uc-bob');
    const client = function (id, fields) {
      return applications.createApplication({ identifier: id,
        protocols: ['oauth2'],
        fields: Object.assign({ oauthClientId: id, oauthClientSecret: SECRET,
          oauthTokenEndpointAuthMethod: 'client_secret_basic' },
          fields || {}) });
    };
    client('uc-rs', { appAllowedProtocol: ['oauth2', 'uma'],
      umaOwnsResources: 'TRUE', oauthGrantType: ['client_credentials'],
      oauthDelegatedPermission: [PROTECTION] });
    client('uc-client', { oauthGrantType: [GRANT],
                          oauthClaimsRedirectUri: [BACK] });
  });

  const server = http.createServer(app);
  await new Promise(function (ok) {
    server.listen(0, '127.0.0.1', ok);
  });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port + PREFIX;
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return r.status + ' ' + String(r.text || '').slice(0, 300) + ' ' +
      String((r.headers && r.headers.location) || '');
  };
  const form = function (fields) {
    log.debug("Entering form().");
    log.debug("Leaving form().");
    return Object.keys(fields).filter(function (k) {
      return fields[k] !== undefined;
    }).map(function (k) {
      return k + '=' + encodeURIComponent(fields[k]);
    }).join('&');
  };
  const token = async function (id, fields) {
    log.debug("Entering token().");
    const r = await request(port, 'POST', PREFIX + '/oauth2/token',
      form(fields), { 'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic ' + Buffer.from(id + ':' + SECRET)
          .toString('base64') });
    log.debug("Leaving token().");
    return r;
  };
  const pat = (await token('uc-rs', { grant_type: 'client_credentials',
    scope: 'uma_protection', resource: base + '/uma' })).json.access_token;
  const reg = await request(port, 'POST', PREFIX + '/uma/rreg',
    { resource_scopes: ['view', 'edit'], name: 'Album' },
    { authorization: 'Bearer ' + pat });
  const album = reg.json && reg.json._id;
  t.check(!!album, 'setup: a resource registered', brief(reg));
  const ticketFor = async function (scopes) {
    log.debug("Entering ticketFor().");
    const r = await request(port, 'POST', PREFIX + '/uma/perm',
      { resource_id: album, resource_scopes: scopes },
      { authorization: 'Bearer ' + pat });
    log.debug("Leaving ticketFor().");
    return r.json && r.json.ticket;
  };
  const ask = function (fields) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return token('uc-client', Object.assign({ grant_type: GRANT }, fields));
  };
  inRealm(function () {
    owner.share('uc-rs', { resource: album, scopes: ['view'],
                           recipientKind: 'person', recipient: 'uc-bob' });
  });

  // --- C. the claims interaction endpoint ---------------------------------
  const claimsUrl = function (q) {
    log.debug("Entering claimsUrl().");
    log.debug("Leaving claimsUrl().");
    return PREFIX + '/uma/claims?' + form(q);
  };
  let first = await ticketFor(['view']);
  let r = await ask({ ticket: first });
  const needed = r.json || {};
  t.check(r.status === 403 && needed.error === 'need_info' &&
          needed.redirect_user === true && !!needed.ticket,
          'C1. need_info advises redirect_user, with a new ticket', brief(r));
  const jar = {};
  let since = marks.length;
  r = await screen.call({ port: port, jar: {}, method: 'GET',
    path: claimsUrl({ client_id: 'nobody', ticket: needed.ticket,
                      claims_redirect_uri: BACK, state: 's' }) });
  t.check(r.status === 400 && !r.headers.location &&
          markedSince(since, 'STS-UMA-0400'),
          'C2. an unknown client is told to the person, never redirected',
          brief(r));
  r = await screen.call({ port: port, jar: {}, method: 'GET',
    path: claimsUrl({ client_id: 'uc-client', ticket: needed.ticket,
                      claims_redirect_uri: 'https://evil.example/',
                      state: 's' }) });
  t.check(r.status === 400 && !r.headers.location,
          'C3. an unregistered claims_redirect_uri is told to the person, ' +
          'never redirected', brief(r));
  const url = claimsUrl({ client_id: 'uc-client', ticket: needed.ticket,
                          claims_redirect_uri: BACK, state: 'xyz' });
  r = await screen.call({ port: port, jar: jar, method: 'GET', path: url });
  t.check(r.status === 303 && /authn/.test(String(r.headers.location)),
          'C4. nobody signed in is sent to the one sign-in', brief(r));
  const signed = await screen.submit({ port: port, jar: jar,
    at: String(r.headers.location),
    fields: { action: 'login', username: 'uc-bob', password: 'x' } });
  t.check(!!jar.sts_session, 'setup: uc-bob signs in', signed.text);
  r = await screen.call({ port: port, jar: jar, method: 'GET', path: url });
  const back = r.headers.location ? new URL(r.headers.location) : null;
  const fresh = back && back.searchParams.get('ticket');
  t.check(r.status === 302 && back && back.origin + back.pathname === BACK &&
          back.searchParams.get('authorization_state') ===
            'claims_submitted' &&
          back.searchParams.get('state') === 'xyz' && !!fresh &&
          fresh !== needed.ticket,
          'C5. signed in, the person goes back with claims_submitted, a new ' +
          'ticket and the state', brief(r));
  r = await ask({ ticket: fresh });
  const pct = r.json && r.json.pct;
  t.check(r.status === 200 && !!r.json.access_token && !!pct,
          'C6. the next grant issues the RPT, and a PCT for the claims ' +
          'gathered', brief(r));
  r = await ask({ ticket: await ticketFor(['view']), pct: pct });
  t.check(r.status === 200 && !!r.json.access_token && !r.json.pct,
          'C7. the PCT names the person next time, and is not re-issued ' +
          'when nothing grew', brief(r));
  since = marks.length;
  r = await screen.call({ port: port, jar: jar, method: 'GET',
    path: claimsUrl({ client_id: 'uc-client', ticket: 'nonsense',
                      claims_redirect_uri: BACK, state: 'q' }) });
  t.check(r.status === 302 && /authorization_state=not_authorized/.test(
            String(r.headers.location)) && markedSince(since, 'STS-UMA-0407'),
          'C8. an unusable ticket goes back not_authorized', brief(r));

  // --- T. a pushed claim_token ---------------------------------------------
  const idToken = function (aud) {
    log.debug("Entering idToken().");
    log.debug("Leaving idToken().");
    return inRealm(function () {
      const now = Math.floor(Date.now() / 1000);
      return helpers.signJwt({ iss: oauth2.issuerOf(base), sub: bob,
        aud: aud, iat: now, exp: now + 300, email: 'bob@example.com' },
        { kind: 'id_token' });
    });
  };
  r = await ask({ ticket: await ticketFor(['view']),
    claim_token: idToken('uc-client'),
    claim_token_format: 'http://openid.net/specs/openid-connect-core-1_0.' +
                        'html#IDToken' });
  t.check(r.status === 200 && !!r.json.access_token && !!r.json.pct,
          'T1. this realm\'s ID Token for the client names the person',
          brief(r));
  since = marks.length;
  r = await ask({ ticket: await ticketFor(['view']),
    claim_token: idToken('another-client'),
    claim_token_format: 'http://openid.net/specs/openid-connect-core-1_0.' +
                        'html#IDToken' });
  t.check(r.status === 403 && r.json.error === 'need_info',
          'T2. one audienced to another client names nobody: need_info',
          brief(r));

  // --- A. ask me each time ---------------------------------------------------
  inRealm(function () {
    owner.share('uc-rs', { resource: album, scopes: ['edit'],
                           recipientKind: 'person', recipient: 'uc-bob',
                           askMe: 'on' });
  });
  r = await ask({ ticket: await ticketFor(['edit']), pct: pct });
  const waiting = r.json && r.json.ticket;
  t.check(r.status === 403 && r.json.error === 'request_submitted' &&
          !!waiting && r.json.interval > 0,
          'A1. an "ask me" share answers request_submitted with a ticket ' +
          'and an interval', brief(r));
  r = await ask({ ticket: waiting, pct: pct });
  const still = r.json && r.json.ticket;
  t.check(r.status === 403 && r.json.error === 'request_submitted' &&
          !!still && still !== waiting,
          'A2. still waiting: request_submitted again, the ticket rotated',
          brief(r));
  const pendingRow = inRealm(function () {
    return store.pendingOf('uc-rs')[0];
  });
  const answered = inRealm(function () {
    return claimsModule.answer('uc-rs', pendingRow && pendingRow.id, true);
  });
  t.check(answered && answered.ok, 'A3. the owner approves',
          JSON.stringify(answered));
  r = await ask({ ticket: still, pct: pct });
  const approvedRules = inRealm(function () {
    return owner.view('uc-rs').shares.filter(function (s) {
      return s.recipient.value === bob && !s.askMe && s.expires;
    });
  });
  t.check(r.status === 200 && !!r.json.access_token &&
          approvedRules.length >= 1,
          'A4. the next poll is issued, decided by the time-bound rule the ' +
          'approval wrote into the owner\'s document', brief(r) + ' ' +
          JSON.stringify(approvedRules));
  inRealm(function () {
    owner.unshare('uc-rs', approvedRules[0].id);
  });
  r = await ask({ ticket: await ticketFor(['edit']), pct: pct });
  const second = r.json && r.json.ticket;
  const refuseRow = inRealm(function () {
    return store.pendingOf('uc-rs')[0];
  });
  inRealm(function () {
    claimsModule.answer('uc-rs', refuseRow && refuseRow.id, false);
  });
  since = marks.length;
  r = await ask({ ticket: second, pct: pct });
  t.check(r.status === 403 && r.json.error === 'request_denied' &&
          markedSince(since, 'STS-UMA-0403'),
          'A5. a refusal is request_denied at the next poll', brief(r));
  inRealm(function () {
    config.setOverride('uma.maxPendingPerOwner', 1);
  });
  await ask({ ticket: await ticketFor(['edit']), pct: pct });
  since = marks.length;
  r = await ask({ ticket: await ticketFor(['edit']), pct: pct });
  t.check(r.status === 403 && r.json.error === 'request_denied' &&
          markedSince(since, 'STS-UMA-0402'),
          'A6. past uma.maxPendingPerOwner a request is request_denied',
          brief(r));
  r = await request(port, 'GET', PREFIX + '/.well-known/uma2-configuration');
  t.check(r.json && r.json.claims_interaction_endpoint === base +
          '/uma/claims',
          'A7. the claims interaction endpoint is advertised now it answers',
          brief(r));

  await new Promise(function (ok) {
    server.close(ok);
  });
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath,
    process.execArgv.concat([__filename]), {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== UMA 2.0 claims and approval (#1168, #1194) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'uma_claims',
  describe: 'UMA 2.0 claims interaction, claim tokens and the owner\'s ' +
            'approval (#1168 phase 5)',
  run: run
};
