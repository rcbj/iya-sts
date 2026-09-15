'use strict';
//
// File: session_reauthentication.js
//
// ===========================================================================
// THE SAME PERSON SIGNING IN AGAIN IS A RE-AUTHENTICATION, AND A SESSION
// COOKIE IS `<sid>.<handle>` (2026-09-14).
//
// `authn/CLAUDE.md`, *What an authenticated identity is here*, is the design;
// this file is its contract. Two words are used the way that section defines
// them: a RE-AUTHENTICATION is any fresh proof by the same person on a live
// session (RFC 9470 `acr_values`, an elapsed `max_age`, `prompt=login`, SAML
// `ForceAuthn`), and a STEP-UP is the kind that raises `acr`.
//
// WHAT WAS WRONG, measured by an in-process probe before any of this was
// written: the same person stepping up in the same browser went through the
// path a CHANGE OF PERSON takes. The session was deleted and re-made, the
// portal session derived from it died, the relying parties a sign-out has to
// reach were forgotten, CAEP was told `session-revoked` and
// `session-established`, and in RFC 9700 mode every refresh token issued on the
// session was revoked. Each of those is an assertion below.
//
// And the cookie: one value was both the stable identifier every token, `sid`
// claim and console page names, and the bearer secret a browser presents. So a
// re-authentication could not rotate it without orphaning every `sid`, and an
// ARRIVAL session's cookie — handed out before anybody authenticated — stayed
// the authenticated session's cookie afterwards, which is session fixation.
//
// WHY IN PROCESS. Whether a record is the SAME record, which handle the store
// holds and what the observer was told are facts about the store; an HTTP
// caller holding a cookie that works cannot see any of them. The RFC 9700 half
// runs in a child process, because `oauth2.rfc9700` is restart-only and cannot
// be turned on inside this one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const realms = require('../common/realms');
const authn = require('../authn/authn');
const caep = require('../ssf/caep');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'session_reauthentication',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// The two things these functions want from express: somewhere to put a
// Set-Cookie, and a request to read one back from.
// ---------------------------------------------------------------------------
function fakeRes() {
  log.debug("Entering fakeRes().");
  const headers = [];
  log.debug("Leaving fakeRes().");
  return {
    headers: headers,
    set: function (name, value) {
      log.debug("Entering set().");
      headers.push(value);
      log.debug("Leaving set().");
    },
    req: null
  };
}

function cookieFrom(res, name) {
  log.debug("Entering cookieFrom().");
  let found = '';
  res.headers.forEach(function (line) {
    const pair = String(line).split(';')[0];
    const i = pair.indexOf('=');
    if (i > 0 && pair.slice(0, i).trim() === name) {
      found = pair.slice(i + 1).trim();
    }
  });
  log.debug("Leaving cookieFrom().");
  return found;
}

function reqWith(name, value) {
  log.debug("Entering reqWith().");
  log.debug("Leaving reqWith().");
  return { headers: { cookie: name + '=' + value }, query: {} };
}

// Everything the observer is told, as `kind:sid`.
function watchSessions() {
  log.debug("Entering watchSessions().");
  const seen = [];
  authn.setSessionObserver(function (notice) {
    seen.push({ kind: notice.kind,
                sid: (notice.session && notice.session.id) || '',
                previous: notice.previous || null });
  });
  log.debug("Leaving watchSessions().");
  return seen;
}

function stopWatching() {
  log.debug("Entering stopWatching().");
  authn.setSessionObserver(function () {
    return null;
  });
  log.debug("Leaving stopWatching().");
}

// A password sign-in, then a portal session derived from it, then one relying
// party answered — the state a step-up arrives in.
function signedInWithPortal(username) {
  log.debug("Entering signedInWithPortal().");
  const res = fakeRes();
  const session = authn.startSession(res, username, ['pwd'], '1',
                                     'OAuth 2.0 / OIDC', {});
  const cookie = cookieFrom(res, authn.SESSION_COOKIE);
  session.oidcClients = { 'reauth-client': { at: Date.now() } };
  authn.sessions.set(session.id, session);
  const portalRes = fakeRes();
  const portal = authn.startRelyingPartySession({
    res: portalRes, username: username, claims: { sid: session.id },
    via: 'User portal', parent: session.id, parentRealm: realms.DEFAULT_ID,
    surface: 'portal', label: 'User portal', clientId: 'sts-user-portal',
    cookie: 'sts_portal', tokens: null
  });
  log.debug("Leaving signedInWithPortal().");
  return { session: session, cookie: cookie, portal: portal,
           portalCookie: cookieFrom(portalRes, 'sts_portal') };
}

// ---------------------------------------------------------------------------
// The RFC 9700 half, in a child: the one place the refresh revocation lives
// (`dropSession()`) only runs in that mode, and the mode is restart-only.
// ---------------------------------------------------------------------------
function childMain() {
  const root = process.env.SR_ROOT;
  const realmsC = require(root + '/common/realms');
  const helpersC = require(root + '/common/helpers');
  const statsC = require(root + '/common/admin_stats');
  const authnC = require(root + '/authn/authn');
  const out = {};
  realmsC.run(realmsC.DEFAULT_REALM, function () {
    const headers = [];
    const res = { set: function (n, v) { headers.push(v); }, req: null };
    const first = authnC.startSession(res, 'sr-refresh', ['pwd'], '1',
                                      'OAuth 2.0 / OIDC', {});
    const cookie = String(headers[0]).split(';')[0].split('=')[1];
    const jti = 'sr-refresh-' + Date.now();
    helpersC.signJwt({ typ: 'Refresh', jti: jti, sub: first.user.sub,
                       client_id: 'sr-client-a',
                       exp: Math.floor(Date.now() / 1000) + 3600 },
                     { sessionId: first.id });
    authnC.startSession({ set: function () {}, req: null }, 'sr-refresh',
                        ['pwd', 'otp'], 'mfa', 'OAuth 2.0 / OIDC',
                        { request: { headers: { cookie: 'sts_session=' +
                                                        cookie },
                                     query: {} } });
    out.recorded = statsC.sessionIdOfJti(jti) === first.id;
    out.revokedAfterStepUp = statsC.isRevoked(jti);
    // A cookie naming the sid with a handle nobody was given: somebody else
    // signing in on it must not end the session, because the sid is not a
    // secret and a sign-in on a forged cookie would otherwise be a sign-out.
    const current = authnC.sessions.get(first.id);
    authnC.startSession({ set: function () {}, req: null },
                        'sr-somebody-else', ['pwd'], '1',
                        'OAuth 2.0 / OIDC',
                        { request: { headers: { cookie: 'sts_session=' +
                          current.id + '.' + 'not-the-handle' },
                                     query: {} } });
    out.forgedCookieEndedNothing = !!authnC.sessions.get(first.id);
    // A KEYED API SESSION PRESENTED AGAIN IS JOURNALLED (2026-09-14): its
    // extension used to be three fields stamped in memory, which every other
    // process in dispatch mode never saw. Asserted on the persistence journal
    // itself — the observer a persisted store is fed from.
    const journal = [];
    const realmsModule = require(root + '/common/realms');
    realmsModule.setPersistObserver(function (handle, realmId, key) {
      journal.push(String(key));
    });
    const keyedRes = { set: function () {}, req: null };
    const keyed = authnC.startSession(keyedRes, 'sr-scim-client', ['pwd'], '1',
                                      'SCIM', { key: 'sr-fingerprint',
                                                cookie: false });
    journal.length = 0;
    const again = authnC.startSession(keyedRes, 'sr-scim-client', ['pwd'],
                                      '1', 'SCIM', { key: 'sr-fingerprint',
                                                     cookie: false });
    out.keyedTouchJournalled = !!keyed && again === keyed &&
                               journal.indexOf(keyed.id) >= 0;
    // THE CONSOLE'S SESSION ROWS KEEP WHEN A SESSION BEGAN (2026-09-14):
    // `startedAt` is the first event and does not move on a re-authentication,
    // while `authTime` is the latest and does.
    const views = require(root + '/admin-core/admin_views');
    const rowOf = function (id) {
      return views.signOnSessionRows().filter(function (row) {
        return row.id === id;
      })[0] || {};
    };
    const beganRes = [];
    const began = authnC.startSession({ set: function (n, v) {
      beganRes.push(v);
    }, req: null }, 'sr-rows', ['pwd'], '1', 'OAuth 2.0 / OIDC', {});
    const rowsBefore = rowOf(began.id);
    const beganCookie = String(beganRes[0]).split(';')[0].split('=')[1];
    began.events[0].at -= 120;
    began.authTime -= 120;
    authnC.startSession({ set: function () {}, req: null }, 'sr-rows',
                        ['pwd', 'otp'], 'mfa', 'OAuth 2.0 / OIDC',
                        { request: { headers: { cookie: 'sts_session=' +
                                                        beganCookie },
                                     query: {} } });
    const rowsAfter = rowOf(began.id);
    out.rowsKeepStart = rowsBefore.startedAt > 0 &&
      rowsAfter.startedAt === (rowsBefore.startedAt - 120000) &&
      rowsAfter.authTime > rowsAfter.startedAt &&
      rowsAfter.authentications === 2;
    out.rowsDetail = JSON.stringify({ before: rowsBefore.startedAt,
                                      after: rowsAfter });
  });
  process.stdout.write('\n' + JSON.stringify(out) + '\n');
  process.exit(0);
}

function rfc9700Child(t) {
  log.debug("Entering rfc9700Child().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', SR_ROOT: ROOT,
                                  STS_OAUTH2_RFC9700: 'true' }),
      encoding: 'utf8', timeout: 120000, cwd: ROOT
    });
  let found = null;
  String(result.stdout || '').split('\n').forEach(function (line) {
    if (line.charAt(0) !== '{' || line.indexOf('"name"') >= 0) {
      return;
    }
    try {
      found = JSON.parse(line);
    } catch (e) {
      log.debug("Caught in rfc9700Child(): " + ((e && e.message) || e));
    }
  });
  if (!t.check(!!found, 'the RFC 9700 child process reported',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving rfc9700Child().");
    return;
  }
  t.check(found.recorded, 'a refresh token was recorded against the ' +
                          'session it was issued on');
  t.check(!found.revokedAfterStepUp,
          'RFC 9700 MODE: a step-up by the same person does NOT revoke the ' +
          'refresh tokens issued on the session — one client asking for mfa ' +
          'used to take another client\'s refresh token away');
  t.check(found.rowsKeepStart,
          'the console\'s session rows show when the session BEGAN beside ' +
          'its latest authentication, and count both', found.rowsDetail);
  t.check(found.keyedTouchJournalled,
          'a keyed API session presented AGAIN writes its extension through ' +
          'the store, so every other process sees the new expiry');
  t.check(found.forgedCookieEndedNothing,
          'a cookie naming the sid with a WRONG handle is nobody\'s cookie: ' +
          'another person signing in on it ends nothing, because the sid is ' +
          'not a secret');
  log.debug("Leaving rfc9700Child().");
}

function run(t) {
  log.debug("Entering run().");
  realms.run(realms.DEFAULT_REALM, function () {
    // -----------------------------------------------------------------------
    t.log.info('=== 1. a step-up by the same person keeps the session ===');
    const seen = watchSessions();
    const before = signedInWithPortal('reauth-alice');
    const sid = before.session.id;
    const startedAt = authn.sessionStartedAt(before.session);
    const expires = before.session.expires;
    seen.length = 0;
    const stepRes = fakeRes();
    const after = authn.startSession(stepRes, 'reauth-alice', ['pwd', 'otp'],
      'mfa', 'OAuth 2.0 / OIDC',
      { request: reqWith(authn.SESSION_COOKIE, before.cookie) });
    const newCookie = cookieFrom(stepRes, authn.SESSION_COOKIE);

    t.equal(after && after.id, sid, 'the sid is UNCHANGED — every ID Token ' +
            'sid, SAML SessionIndex and token record goes on naming it');
    t.check(after === authn.sessions.get(sid), 'and it is the same record, ' +
            'not a copy put back under the same key');
    t.equal((after.events || []).length, 2, 'the session holds TWO ' +
            'authentication events');
    t.equal(after.acr, 'mfa', 'acr is the most recent event\'s');
    t.equal(JSON.stringify(after.amr), JSON.stringify(['pwd', 'otp']),
            'and so is amr');
    t.equal(after.authTime, after.events[1].at, 'auth_time is the most ' +
            'recent authentication');
    t.equal(authn.sessionStartedAt(after), startedAt, 'while when the ' +
            'session BEGAN does not move');
    t.equal(after.expires, expires, 'and neither does its absolute expiry — ' +
            'proving yourself again is not an extension');
    t.check(!!(after.oidcClients && after.oidcClients['reauth-client']),
            'the relying parties it answered are still on it, so a sign-out ' +
            'can still reach them');
    t.check(!!authn.relyingPartySessionOf(
      reqWith('sts_portal', before.portalCookie), 'sts_portal'),
            'the portal session derived from it is still alive');
    // #10: the portal's "You" card reads the person's sign-in through its own
    // session, and that session's copy came from an ID Token issued BEFORE
    // the step-up.
    const portalFacts = authn.signOnFactsFor(before.portal);
    t.check(portalFacts.fromParent && portalFacts.acr === 'mfa' &&
            portalFacts.amr.join(',') === 'pwd,otp' &&
            portalFacts.authTime === after.authTime * 1000 &&
            portalFacts.startedAt === startedAt &&
            portalFacts.authentications === 2,
            'a relying-party session describes the person\'s sign-in from ' +
            'the sign-on session, so the step-up shows at once',
            JSON.stringify(portalFacts));
    // And the portal's card is drawn from that answer — as SOURCE, because
    // requiring the portal registers its routes in run.js's one process.
    const portalSource = require('fs').readFileSync(
      path.join(__dirname, '..', 'portal', 'portal.js'), 'utf8');
    const overviewAt = portalSource.indexOf('function overviewPage(');
    const overview = portalSource.slice(overviewAt,
      portalSource.indexOf('directoryBlock(session, entry)', overviewAt));
    t.check(/authn\.signOnFactsFor\(session\)/.test(overview) &&
            !/session\.(authTime|acr|amr)\b/.test(overview),
            'the portal\'s "You" card reads the sign-on facts and not its ' +
            'own session\'s copy');
    t.check(before.portal.acr !== 'mfa',
            'while its own copy is still what its ID Token said, which the ' +
            'token renewal compares against', before.portal.acr);
    t.equal(seen.map(function (one) { return one.kind; }).join(','),
            'reauthenticated', 'the observer was told `reauthenticated` and ' +
            'NOTHING ELSE — no session-revoked, no session-established');
    t.equal(seen[0] && seen[0].previous && seen[0].previous.acr, '1',
            'with what the session said before, which is what CAEP needs to ' +
            'say which way assurance moved');

    // -----------------------------------------------------------------------
    t.log.info('=== 2. the handle rotated and the sid did not ===');
    t.check(newCookie && newCookie !== before.cookie &&
            newCookie.split('.')[0] === sid,
            'a new cookie was written, naming the same sid with a new handle',
            before.cookie + ' -> ' + newCookie);
    t.check(!authn.sessionOf(reqWith(authn.SESSION_COOKIE, before.cookie)),
            'the OLD cookie no longer opens the session — a re-authentication ' +
            'is a change of privilege');
    t.check(authn.sessionOf(reqWith(authn.SESSION_COOKIE, newCookie)) ===
            after, 'the new one does');
    t.check(!authn.sessionOf(reqWith(authn.SESSION_COOKIE, sid)),
            'a BARE sid is not a cookie: every relying party that received ' +
            'an ID Token holds it');
    t.check(!authn.relyingPartySessionOf(
      reqWith('sts_portal', before.portal.id), 'sts_portal'),
            'nor is a bare relying-party session id, which /admin/sessions ' +
            'prints to every holder of Admin Read');
    t.check(!before.session.handle && typeof after.handleHash === 'string' &&
            after.handleHash.indexOf(newCookie.split('.')[1]) < 0,
            'the store holds a HASH of the handle and never the handle');

    // -----------------------------------------------------------------------
    t.log.info('=== 3. a step-down and a same-level re-authentication ===');
    seen.length = 0;
    const downRes = fakeRes();
    const down = authn.startSession(downRes, 'reauth-alice', ['pwd'], '1',
      'SAML 2.0', { request: reqWith(authn.SESSION_COOKIE, newCookie) });
    t.equal(down.acr, '1', 'a weaker re-authentication LOWERS acr — the ' +
            'session says what the most recent event proved');
    t.equal(down.via, 'SAML 2.0', 'and `via` follows it, because the SAML ' +
            'and WS-Federation authentication contexts read it');
    t.equal(down.events.length, 3, 'three events');

    // A snapshot rather than `after`, which the step-down above has already
    // moved back to acr 1: the register is asked about the step-up as it was.
    const row = caep.observe({ kind: 'reauthenticated',
      session: { id: 'reauth-up', user: after.user, acr: 'mfa',
                 amr: ['pwd', 'otp'] },
      via: 'OAuth 2.0 / OIDC', previous: { acr: '1' } });
    t.equal(row && row.uri, 'https://schemas.openid.net/secevent/caep/' +
            'event-type/assurance-level-change',
            'CAEP: a step-up is an assurance-level-change');
    t.equal(row && row.payload.namespace, 'urn:sts:acr', 'on this service\'s ' +
            'own scale, not NIST-AAL — nobody assessed an AAL');
    t.equal(row && row.payload.change_direction, 'increase',
            'it says the direction outright');
    t.equal(row && row.payload.previous_level, '1', 'and where it was');

    const stepDown = caep.observe({ kind: 'reauthenticated',
      session: { id: 'reauth-down', user: after.user, acr: '1',
                 amr: ['pwd'] },
      via: 'SAML 2.0', previous: { acr: 'mfa' } });
    t.equal(stepDown && stepDown.payload.change_direction, 'decrease',
            'a step-down is a DECREASE, which is the direction a receiver ' +
            'most needs to hear about');
    const same = caep.observe({ kind: 'reauthenticated',
      session: { id: 'reauth-same', user: after.user, acr: '1',
                 amr: ['pwd'] },
      via: 'OAuth 2.0 / OIDC', previous: { acr: '1' } });
    t.equal(same, null, 'a re-authentication that leaves acr where it was ' +
            '(an elapsed max_age) emits NOTHING');

    // -----------------------------------------------------------------------
    t.log.info('=== 4. a DIFFERENT person still replaces the session ===');
    seen.length = 0;
    const other = authn.startSession(fakeRes(), 'reauth-bob', ['pwd'], '1',
      'OAuth 2.0 / OIDC',
      { request: reqWith(authn.SESSION_COOKIE,
                         cookieFrom(downRes, authn.SESSION_COOKIE)) });
    t.check(other && other.id !== sid, 'somebody else signing in on that ' +
            'browser gets a session of their own');
    t.check(!authn.sessions.get(sid), 'and alice\'s is ENDED — a change of ' +
            'person is a replacement, which is the half that was always right');
    t.check(!authn.relyingPartySessionOf(
      reqWith('sts_portal', before.portalCookie), 'sts_portal'),
            'taking the portal session derived from it with it');
    t.check(!authn.signOnFactsFor(before.portal).fromParent,
            'and a relying-party session whose sign-on session is gone ' +
            'answers from its own copy');
    t.check(seen.map(function (one) { return one.kind; })
              .indexOf('revoked') >= 0 &&
            seen.map(function (one) { return one.kind; })
              .indexOf('established') >= 0,
            'and the observer hears a revocation and an establishment',
            JSON.stringify(seen.map(function (one) { return one.kind; })));

    // -----------------------------------------------------------------------
    t.log.info('=== 5. an arrival cookie does not survive the sign-in ===');
    const arrivalRes = fakeRes();
    const arrival = authn.startArrivalSession({ headers: {}, query: {} },
                                              arrivalRes, 'arrival');
    const planted = cookieFrom(arrivalRes, authn.SESSION_COOKIE);
    const signInRes = fakeRes();
    const upgraded = authn.startSession(signInRes, 'reauth-carol', ['pwd'],
      '1', 'OAuth 2.0 / OIDC',
      { request: reqWith(authn.SESSION_COOKIE, planted) });
    t.equal(upgraded && upgraded.id, arrival && arrival.id,
            'the arrival row is upgraded in place, so the sid a flow was ' +
            'correlated by survives');
    t.check(!authn.sessionOf(reqWith(authn.SESSION_COOKIE, planted)),
            'but the cookie handed out BEFORE anybody authenticated does not ' +
            'open the authenticated session — that was session fixation');
    t.check(!!authn.sessionOf(reqWith(authn.SESSION_COOKIE,
      cookieFrom(signInRes, authn.SESSION_COOKIE))),
            'the cookie the sign-in wrote does');

    // -----------------------------------------------------------------------
    t.log.info('=== 6. the event list is bounded, and keeps its beginning ===');
    const longRes = fakeRes();
    const long = authn.startSession(longRes, 'reauth-dave', ['pwd'], '1',
                                    'OAuth 2.0 / OIDC', {});
    let cookie = cookieFrom(longRes, authn.SESSION_COOKIE);
    const firstAt = long.events[0].at;
    for (let i = 0; i < authn.MAX_SESSION_EVENTS + 5; i++) {
      const r = fakeRes();
      authn.startSession(r, 'reauth-dave', ['pwd'], '1', 'OAuth 2.0 / OIDC',
                         { request: reqWith(authn.SESSION_COOKIE, cookie) });
      cookie = cookieFrom(r, authn.SESSION_COOKIE);
    }
    t.equal(long.events.length, authn.MAX_SESSION_EVENTS,
            'a max_age=0 client cannot grow a session without bound');
    t.equal(long.events[0].at, firstAt, 'the FIRST event is kept');
    t.equal(long.eventsDropped, 6, 'and the row says how many went');
    stopWatching();
  });

  // -------------------------------------------------------------------------
  t.log.info('=== 7. RFC 9700 mode, in a child process ===');
  rfc9700Child(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'session_reauthentication',
  describe: 'the same person re-authenticating keeps the session (sid, ' +
            'derived sessions, relying parties, refresh tokens) and adds an ' +
            'event; the cookie handle rotates; CAEP assurance-level-change; ' +
            'a ' +
            'different person still replaces it; no fixation through an ' +
            'arrival cookie',
  run: run
};
