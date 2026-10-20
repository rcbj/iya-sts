// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/device_bound_sessions.js
// ===========================================================================
// DEVICE BOUND SESSION CREDENTIALS (#725).
//
// The whole stack in a child process, over HTTP on 127.0.0.1, with a
// browser played by this file: an ES256 key pair made here, and DBSC proofs
// (`dbsc+jwt`, the challenge as `jti`) signed with it as the W3C draft's
// section 9.10 writes them.
//
//   1. OFF, THE DEFAULT: a sign-in's answer carries no
//      Secure-Session-Registration, and the two endpoints answer 404.
//   2. ON: the answer that sets `sts_session` offers ES256 and RS256, the
//      registration path and a challenge.
//   3. REGISTRATION with an ES256 key: 200, the session instructions, the
//      bound cookie, and a challenge for the first refresh. The session is
//      honoured beside the bound cookie and NOT without it — and not ended.
//   4. THE COOKIE LAPSES (the browser drops it): a refresh without a proof
//      is a 403 with a challenge; the challenge signed with the bound key
//      renews the cookie, and the session is honoured again.
//   5. A REPLAYED CHALLENGE is refused (401) and ends the session.
//   6. A REFRESH SIGNED BY ANOTHER KEY is refused (401) and ends the
//      session, with the sign-out's audit row.
//   7. AN UNKNOWN DBSC SESSION ID is refused (401), and the sign-on session
//      behind the cookie is left as it was.
//   8. A session nobody bound is honoured without any bound cookie: a
//      browser that does not speak DBSC keeps today's behaviour.
//   9. WITH SEVERAL ACCOUNTS IN ONE BROWSER (#561): two people sign in in
//      one cookie jar and each registers; each binding is its own session's
//      (chosen by the challenge), with a bound cookie named for it, and
//      each account chosen through the set is honoured beside ITS cookie
//      only — never the other account in its place.
//  10. A refresh names its binding by Sec-Secure-Session-Id among the
//      browser's accounts, and one naming none of them ends nothing.
//  11. A refresh signed by another key ends THAT account's session only:
//      it leaves the browser's set for its remembered accounts, and the
//      default cookie, which names the other account, is not cleared.
//  12. The same person signing in again from a browser that cannot prove
//      the bound key replaces that session in the set, as with the setting
//      off: one live session per person per browser.
//
// In process, because it chooses how the process starts (the setting is
// flipped on a live stack) and asserts on the session store beside each
// answer, which no HTTP answer shows.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'device_bound_sessions',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and plays the browser.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.DB_ROOT;
  const OUT = process.env.DB_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  // The browser's key, and a proof made with it.
  function keyPair() {
    const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    return { privateKey: pair.privateKey,
             jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
  }
  function b64(obj) {
    return Buffer.from(JSON.stringify(obj)).toString('base64url');
  }
  function proof(key, challenge, withJwk) {
    const header = { alg: 'ES256', typ: 'dbsc+jwt' };
    if (withJwk) {
      header.jwk = key.jwk;
    }
    const input = b64(header) + '.' + b64({ jti: challenge });
    const sig = nodeCrypto.sign('sha256', Buffer.from(input),
      { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
    return input + '.' + sig.toString('base64url');
  }
  function quoted(text) {
    return '"' + text + '"';
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const authn = require(ROOT_DIR + '/authn/authn');
    const config = require(ROOT_DIR + '/common/config');
    const sf = require(ROOT_DIR + '/common/structured_fields');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    let n = 0;
    const signIn = async function (username, given) {
      n += 1;
      const jar = given || {};
      const at = authn.beginAuthentication({ returnTo: '/db/after?n=' + n,
        protocol: 'db-probe', application: '' });
      const r = await screen.submit({ port: port, jar: jar, at: at,
        fields: { action: 'login', username: username, password: 'right' } });
      return { jar: jar, r: r,
               sid: String(jar.sts_session || '').split('.')[0] };
    };
    const reqOf = function (jar) {
      return { headers: { cookie: Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ') }, query: {} };
    };
    const offerOf = function (r) {
      const raw = r.headers['secure-session-registration'];
      if (!raw) {
        return null;
      }
      const list = sf.parseList(Array.isArray(raw) ? raw.join(', ') : raw);
      const entry = list[0];
      return { algs: entry.value.map(function (i) {
        return i.value;
      }), path: sf.paramValue(entry.params, 'path'),
               challenge: sf.paramValue(entry.params, 'challenge') };
    };
    const challengeOf = function (r) {
      const raw = r.headers['secure-session-challenge'];
      if (!raw) {
        return null;
      }
      const item = sf.parseList(String(raw))[0];
      return { challenge: item.value,
               id: sf.paramValue(item.params, 'id') };
    };
    const post = function (jar, p, headers) {
      return screen.call({ port: port, jar: jar, method: 'POST', path: p,
                           headers: headers || {}, body: '' });
    };
    const register = async function (who, key) {
      const s = await signIn(who);
      const offer = offerOf(s.r);
      const r = await post(s.jar, offer.path, {
        'secure-session-response': quoted(proof(key, offer.challenge,
                                                true)) });
      return { s: s, offer: offer, r: r };
    };

    // --- 1. off, the default --------------------------------------------
    let s = await signIn('db-off');
    note(s.r.next === 'redirect' && !!s.sid &&
         !s.r.headers['secure-session-registration'],
         '1a. with authn.deviceBoundSessions off, a sign-in sets the session ' +
         'cookie and offers no registration',
         JSON.stringify(s.r.headers['secure-session-registration']));
    let r = await post(s.jar, '/authn/dbsc/register', {});
    const r2 = await post(s.jar, '/authn/dbsc/refresh',
                          { 'sec-secure-session-id': '"x"' });
    note(r.status === 404 && r2.status === 404,
         '1b. and both endpoints answer 404', r.status + ' ' + r2.status);

    config.setOverride('authn.deviceBoundSessions', true);

    // --- 2. the offer ------------------------------------------------------
    s = await signIn('db-ann');
    const offer = offerOf(s.r);
    note(offer && offer.algs.join(' ') === 'ES256 RS256' &&
         offer.path === '/authn/dbsc/register' && offer.challenge,
         '2. on, the answer that sets sts_session carries ' +
         'Secure-Session-Registration: (ES256 RS256), the path and a ' +
         'challenge',
         JSON.stringify(s.r.headers['secure-session-registration']));

    // --- 3. registration ---------------------------------------------------
    const key = keyPair();
    r = await post(s.jar, offer.path, {
      'secure-session-response': quoted(proof(key, offer.challenge, true)) });
    const instr = r.json || {};
    const cred = (instr.credentials || [])[0] || {};
    let next = challengeOf(r);
    note(r.status === 200 && instr.session_identifier &&
         instr.refresh_url === '/authn/dbsc/refresh' &&
         instr.scope && instr.scope.include_site === false &&
         cred.type === 'cookie' && cred.name === 'sts_session_bound' &&
         /Path=\/; .*HttpOnly; SameSite=Lax/.test(cred.attributes) &&
         !!s.jar.sts_session_bound && next &&
         next.id === instr.session_identifier &&
         /no-store/.test(String(r.headers['cache-control'])),
         '3a. registration with an ES256 key answers the session ' +
         'instructions, the bound cookie and the next challenge',
         r.status + ' ' + r.text.slice(0, 400));
    const dbscId = instr.session_identifier;
    const held = authn.sessionById(s.sid) || {};
    note(held.dbsc && held.dbsc.alg === 'ES256' && held.dbsc.jkt &&
         held.dbsc.id === dbscId,
         '3b. the session records the bound key', JSON.stringify(held.dbsc));
    note(authn.sessionOf(reqOf(s.jar)) &&
         authn.sessionOf(reqOf(s.jar)).id === s.sid,
         '3c. the session is honoured beside its bound cookie');
    const lapsed = Object.assign({}, s.jar);
    delete lapsed.sts_session_bound;
    note(authn.sessionOf(reqOf(lapsed)) === null &&
         !!authn.sessionById(s.sid),
         '3d. and without it the session is not honoured — and not ended');
    r = await post(s.jar, offer.path, {
      'secure-session-response': quoted(proof(keyPair(), offer.challenge,
                                              true)) });
    note(r.status === 409, '3e. a second registration is refused', r.status);

    // --- 4. the cookie lapses; refresh --------------------------------------
    delete s.jar.sts_session_bound;
    r = await post(s.jar, '/authn/dbsc/refresh',
                   { 'sec-secure-session-id': quoted(dbscId) });
    next = challengeOf(r);
    note(r.status === 403 && next && next.id === dbscId && next.challenge,
         '4a. a refresh without a proof is a 403 carrying ' +
         'Secure-Session-Challenge for this session', r.status + ' ' +
         JSON.stringify(r.headers['secure-session-challenge']));
    const signed = proof(key, next.challenge, false);
    r = await post(s.jar, '/authn/dbsc/refresh', {
      'sec-secure-session-id': quoted(dbscId),
      'secure-session-response': quoted(signed) });
    note(r.status === 200 && !!s.jar.sts_session_bound &&
         /sts_session_bound=/.test(String(r.headers['set-cookie'] || '')) &&
         r.json && r.json.session_identifier === dbscId && challengeOf(r),
         '4b. the challenge signed with the bound key renews the bound ' +
         'cookie', r.status + ' ' + r.text.slice(0, 300));
    note(authn.sessionOf(reqOf(s.jar)) &&
         (authn.sessionById(s.sid).dbsc || {}).refreshes === 1,
         '4c. the session is honoured again, and the refresh is counted');

    // --- 5. a replayed challenge ------------------------------------------
    r = await post(s.jar, '/authn/dbsc/refresh', {
      'sec-secure-session-id': quoted(dbscId),
      'secure-session-response': quoted(signed) });
    note(r.status === 401 && !authn.sessionById(s.sid) &&
         !/STS-[A-Z]+-\d{4}/.test(r.text),
         '5. the same proof again is refused (401) and the session ended',
         r.status + ' ' + r.text);

    // --- 6. another key ------------------------------------------------------
    const bob = await register('db-bob', keyPair());
    note(bob.r.status === 200, '6a. a second person registers', bob.r.status);
    const bobId = bob.r.json.session_identifier;
    r = await post(bob.s.jar, '/authn/dbsc/refresh',
                   { 'sec-secure-session-id': quoted(bobId) });
    next = challengeOf(r);
    r = await post(bob.s.jar, '/authn/dbsc/refresh', {
      'sec-secure-session-id': quoted(bobId),
      'secure-session-response': quoted(proof(keyPair(), next.challenge,
                                              false)) });
    note(r.status === 401 && !authn.sessionById(bob.s.sid) &&
         !bob.s.jar.sts_session && !bob.s.jar.sts_session_bound,
         '6b. a refresh signed by another key is refused (401), the session ' +
         'ended and both cookies cleared', r.status + ' ' + r.text);
    note(authn.sessionOf(reqOf({ sts_session: bob.s.sid + '.x' })) === null,
         '6c. and the session cannot be presented again');

    // --- 7. an unknown DBSC session ----------------------------------------
    const cy = await register('db-cy', keyPair());
    r = await post(cy.s.jar, '/authn/dbsc/refresh',
                   { 'sec-secure-session-id': quoted('not-this-one') });
    note(r.status === 401 && !!authn.sessionById(cy.s.sid),
         '7. a refresh naming another DBSC session is refused (401) and the ' +
         'sign-on session is left as it was', r.status);

    // --- 8. a browser without DBSC -----------------------------------------
    s = await signIn('db-dan');
    note(!!offerOf(s.r) && authn.sessionOf(reqOf(s.jar)) &&
         !s.jar.sts_session_bound,
         '8. a browser that never registers keeps an ordinary session: ' +
         'honoured with no bound cookie');

    // --- 9. several accounts in one browser (#561) -----------------------
    config.setOverride('authn.multipleAccounts', true);
    const AccountSets = require(ROOT_DIR + '/authn/account_sets');
    const hinted = function (jar, who) {
      const req = reqOf(jar);
      authn.hintAccount(req, { loginHint: who });
      return authn.sessionOf(req);
    };
    const jar = {};
    const aliceKey = keyPair();
    const bobbyKey = keyPair();
    const alice = await signIn('db-alice', jar);
    const aliceOffer = offerOf(alice.r);
    const bobby = await signIn('db-bobby', jar);
    const bobOffer = offerOf(bobby.r);
    note(!!jar.sts_accounts && alice.sid && bobby.sid && alice.sid !== bobby.sid &&
         !!authn.sessionById(alice.sid) && !!authn.sessionById(bobby.sid),
         '9a. two people sign in in one browser and both stay signed in',
         JSON.stringify(Object.keys(jar)));
    // Bob registers first, with bobby's challenge: the binding is bobby's.
    r = await post(jar, bobOffer.path, {
      'secure-session-response': quoted(proof(bobbyKey, bobOffer.challenge,
                                              true)) });
    const bobInstr = r.json || {};
    const bobCookie = ((bobInstr.credentials || [])[0] || {}).name;
    note(r.status === 200 && (authn.sessionById(bobby.sid).dbsc || {}).id ===
         bobInstr.session_identifier &&
         !(authn.sessionById(alice.sid) || {}).dbsc &&
         bobCookie === 'sts_session_bound_' + bobInstr.session_identifier &&
         !!jar[bobCookie] && !jar.sts_session_bound,
         '9b. a registration with one account\'s challenge binds that ' +
         'account, under a bound cookie named for its binding',
         r.status + ' ' + r.text.slice(0, 300));
    r = await post(jar, aliceOffer.path, {
      'secure-session-response': quoted(proof(aliceKey, aliceOffer.challenge,
                                              true)) });
    const aliceInstr = r.json || {};
    const aliceCookie = ((aliceInstr.credentials || [])[0] || {}).name;
    note(r.status === 200 && (authn.sessionById(alice.sid).dbsc || {}).id ===
         aliceInstr.session_identifier && aliceCookie !== bobCookie &&
         !!jar[aliceCookie] && !!jar[bobCookie],
         '9c. and the other account\'s challenge binds the other account, ' +
         'under a cookie of its own, both held at once',
         r.status + ' ' + r.text.slice(0, 300));
    const a1 = hinted(jar, 'db-alice');
    const b1 = hinted(jar, 'db-bobby');
    note(a1 && a1.id === alice.sid && b1 && b1.id === bobby.sid,
         '9d. each account chosen through the set is honoured beside its own ' +
         'bound cookie', (a1 && a1.id) + ' ' + (b1 && b1.id));
    const noAlice = Object.assign({}, jar);
    delete noAlice[aliceCookie];
    const a2 = hinted(noAlice, 'db-alice');
    const b2 = hinted(noAlice, 'db-bobby');
    const n2 = authn.sessionOf(reqOf(noAlice));
    note(a2 === null && b2 && b2.id === bobby.sid && n2 === null &&
         !!authn.sessionById(alice.sid),
         '9e. without its bound cookie the chosen account is not honoured ' +
         'and NOT replaced by the other; the other is still honoured',
         String(a2 && a2.id) + ' ' + String(n2 && n2.id));
    const crossed = Object.assign({}, noAlice);
    crossed[aliceCookie] = jar[bobCookie];
    note(hinted(crossed, 'db-alice') === null,
         '9f. another binding\'s cookie under its name does not stand in');

    // --- 10. refresh among several accounts ------------------------------
    delete jar[aliceCookie];
    r = await post(jar, '/authn/dbsc/refresh',
                   { 'sec-secure-session-id':
                       quoted(aliceInstr.session_identifier) });
    next = challengeOf(r);
    r = await post(jar, '/authn/dbsc/refresh', {
      'sec-secure-session-id': quoted(aliceInstr.session_identifier),
      'secure-session-response': quoted(proof(aliceKey, next.challenge,
                                              false)) });
    note(r.status === 200 && !!jar[aliceCookie] &&
         (authn.sessionById(alice.sid).dbsc || {}).refreshes === 1 &&
         ((authn.sessionById(bobby.sid).dbsc || {}).refreshes || 0) === 0,
         '10a. a refresh naming one account\'s binding renews that ' +
         'account\'s cookie only', r.status + ' ' + r.text.slice(0, 300));
    r = await post(jar, '/authn/dbsc/refresh',
                   { 'sec-secure-session-id': quoted('none-of-these') });
    note(r.status === 401 && !!authn.sessionById(alice.sid) &&
         !!authn.sessionById(bobby.sid) &&
         !/STS-[A-Z]+-\d{4}/.test(r.text),
         '10b. a refresh naming no account\'s binding is refused (401) and ' +
         'ends nothing', r.status + ' ' + r.text);

    // --- 11. another key ends that account only ----------------------------
    const setId = authn.sessionById(alice.sid).accountSetId;
    const defaultBefore = jar.sts_session;
    r = await post(jar, '/authn/dbsc/refresh',
                   { 'sec-secure-session-id':
                       quoted(aliceInstr.session_identifier) });
    next = challengeOf(r);
    r = await post(jar, '/authn/dbsc/refresh', {
      'sec-secure-session-id': quoted(aliceInstr.session_identifier),
      'secure-session-response': quoted(proof(keyPair(), next.challenge,
                                              false)) });
    const setAfter = AccountSets.byId(setId) || {};
    const remembered = Object.keys(setAfter.remembered || {}).map(
      function (k) {
        return setAfter.remembered[k].username;
      });
    note(r.status === 401 && !authn.sessionById(alice.sid) &&
         !!authn.sessionById(bobby.sid) &&
         !(setAfter.sessions || {})[alice.sid] &&
         remembered.indexOf('db-alice') >= 0 &&
         jar.sts_session === defaultBefore &&
         String(defaultBefore).split('.')[0] === bobby.sid &&
         !jar[aliceCookie] && !!jar[bobCookie],
         '11. a refresh of one account signed by another key ends that ' +
         'account alone: out of the set to its remembered accounts, its ' +
         'bound cookie cleared, the default cookie (the other account\'s) ' +
         'kept', r.status + ' ' + JSON.stringify(setAfter.sessions || {}) +
         ' ' + JSON.stringify(remembered));
    const b3 = authn.sessionOf(reqOf(jar));
    note(b3 && b3.id === bobby.sid,
         '11b. and the other account is the browser\'s only one, honoured');

    // --- 12. the same person again, without the key -----------------------
    const thief = { sts_accounts: jar.sts_accounts, sts_session:
                    jar.sts_session };
    const again = await signIn('db-bobby', thief);
    const setNow = AccountSets.byId(authn.sessionById(again.sid)
      .accountSetId) || {};
    note(again.sid && again.sid !== bobby.sid && !authn.sessionById(bobby.sid) &&
         Object.keys(setNow.sessions || {}).indexOf(bobby.sid) < 0,
         '12. the same person signing in where the bound key is not proved ' +
         'replaces the bound session, never two of one person in the set',
         again.sid + ' ' + JSON.stringify(Object.keys(setNow.sessions || {})));
    config.clearOverride('authn.multipleAccounts');

    config.clearOverride('authn.deviceBoundSessions');
    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports its findings.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'dbsc-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  DB_ROOT: ROOT, DB_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'device_bound_sessions',
  describe: 'Device Bound Session Credentials (#725): no offer while off, ' +
            'registration with an ES256 key, the bound cookie honoured and ' +
            'its absence not, a refresh with a signed challenge renewing ' +
            'it, a replayed challenge and another key each ending the ' +
            'session, an unknown DBSC id leaving it alone, a browser ' +
            'without DBSC unchanged, and several accounts in one browser ' +
            'each bound and honoured on its own (#561)',
  run: run
};
