'use strict';
//
// File: oidc_rp_renewal.js
//
// ===========================================================================
// THE CONSOLE AND THE PORTAL RENEW THEIR TOKENS INSIDE THE SAME SESSION
// (2026-09-12).
//
// An operator watched a console session expire an hour after signing in, with
// its ID Token and access token, and was sent back through the sign-in screen.
// `common/oidc_rp.ts` now keeps the tokens a sign-in was issued, and when they
// run out redeems the refresh token and writes the new ones onto THE SAME
// SESSION. The end-to-end half — a real refresh token grant over the loopback
// back channel, a page answered 200 on the same cookie — is
// `tests/vendored/sts_hosted_surface_renewal.js`. What is here is what that job
// cannot choose:
//
//   1. WHAT A SESSION IS MADE WITH. A renewable session's expiry is its renewal
//      window and not its sign-on session's; one with no refresh token is
//      exactly what it was.
//   2. WHY A PARENT IS MISSING. A sign-on session that RAN OUT leaves a
//      renewable child standing; one that vanished early — a cascade that did
//      not reach — still ends it. Over HTTP both are "the parent is gone", and
//      producing the second means breaking the cascade.
//   3. THE DECISION TABLE. Not due, renew, leave to run out, end — including
//      the window having closed, which over HTTP is a twenty-four-hour wait.
//   4. THE SAME SIGN-IN. A renewed ID Token naming another issuer, subject or
//      authentication time is refused — a state this service's own token
//      endpoint will not produce on demand.
//   5. THE RENEWAL ITSELF writes onto the same record, and what it keeps.
//   6. THE REGISTRATION ORDER, as source: middleware applies only to routes
//      added after it (rule 1), and a renewal registered below the console's
//      gate would run after the gate had already sent the browser away —
//      which no request can tell from a renewal that is not registered at all.
//
// In process, with no port: `authn.js` is called directly with a stub `res`,
// for `tests/cross_surface_sso.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const realms = require('../common/realms');
const audit = require('../common/audit');
const authn = require('../authn/authn');
const oidcRp = require('../common/oidc_rp');

const log = require('bunyan').createLogger({ name: 'oidc_rp_renewal',
  level: process.env.LOG_LEVEL || 'info' });

const HOUR = 60 * 60 * 1000;

// Somewhere to put a Set-Cookie. See cross_surface_sso.js.
function fakeRes() {
  log.debug("Entering fakeRes().");
  const headers = [];
  log.debug("Leaving fakeRes().");
  return {
    headers: headers,
    getHeader: function () {
      log.debug("Entering getHeader().");
      log.debug("Leaving getHeader().");
      return headers.slice();
    },
    setHeader: function (name, value) {
      log.debug("Entering setHeader().");
      headers.length = 0;
      [].concat(value).forEach(function (v) { headers.push(v); });
      log.debug("Leaving setHeader().");
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
  return { headers: { cookie: name + '=' + value } };
}

// Tokens shaped as `oidc_rp.tokensFrom()` makes them, running out `inMs` from
// now.
function tokensRunningOutIn(inMs, withRefresh) {
  log.debug("Entering tokensRunningOutIn().");
  const now = Date.now();
  log.debug("Leaving tokensRunningOutIn().");
  return {
    accessToken: 'access-' + now, tokenType: 'Bearer', scope: 'openid',
    accessExpiresAt: now + inMs,
    refreshToken: withRefresh ? 'refresh-' + now : '',
    idToken: 'id-' + now, idTokenExpiresAt: now + inMs,
    issuer: 'https://sts.test', sub: 'urn:sts:user:renew-alice',
    authTime: Math.floor(now / 1000) - 60, flowRealm: 'default',
    host: 'sts.test'
  };
}

// A sign-on session in the default realm, and a portal session derived from it.
function signOnAndPortal(username, tokens, renewableUntil) {
  log.debug("Entering signOnAndPortal().");
  return realms.run(realms.DEFAULT_REALM, function () {
    const parent = authn.startSession(fakeRes(), username, [], '1', 'Test', {});
    const res = fakeRes();
    const session = authn.startRelyingPartySession({
      res: res, username: username, claims: {}, via: 'User portal',
      parent: parent.id, parentRealm: realms.DEFAULT_ID,
      surface: 'portal', label: 'User portal', clientId: 'sts-user-portal',
      cookie: 'sts_portal', tokens: tokens, renewableUntil: renewableUntil
    });
    log.debug("Leaving signOnAndPortal().");
    return { parent: parent, session: session,
             cookie: cookieFrom(res, 'sts_portal') };
  });
}

function readPortal(cookie) {
  log.debug("Entering readPortal().");
  log.debug("Leaving readPortal().");
  return realms.run(realms.DEFAULT_REALM, function () {
    return authn.relyingPartySessionOf(reqWith('sts_portal', cookie),
                                       'sts_portal',
                                       realms.DEFAULT_ID);
  });
}

// Tidy up whatever a section left in the default realm's store, which is
// process-wide in `run.js`'s one process.
function forget(ids) {
  log.debug("Entering forget().");
  ids.forEach(function (id) {
    realms.run(realms.DEFAULT_REALM, function () {
      if (authn.sessions.get(id)) {
        authn.sessions.delete(id);
      }
    });
  });
  log.debug("Leaving forget().");
}

// ---------------------------------------------------------------------------
// 1. WHAT A SESSION IS MADE WITH.
// ---------------------------------------------------------------------------
function checkCreation(t) {
  log.debug("Entering checkCreation().");
  t.log.info('a relying-party session made with tokens');
  const renewableUntil = Date.now() + 24 * HOUR;
  const made = signOnAndPortal('renew-alice', tokensRunningOutIn(HOUR, true),
                               renewableUntil);
  t.check(made.session.expires >= renewableUntil,
          'a session holding a refresh token expires at the END OF ITS ' +
          'RENEWAL WINDOW, not with its sign-on session — which is what lets ' +
          'it renew past the hour',
          'expires=' + made.session.expires + ' window=' + renewableUntil +
          ' parent=' + made.parent.expires);
  t.check(made.session.expires > made.parent.expires,
          'and so it outlives the sign-on session\'s absolute expiry',
          made.session.expires + ' vs ' + made.parent.expires);
  t.equal(made.session.derivedFromExpires, made.parent.expires,
          'it records when its sign-on session would expire, which is how a ' +
          'reader later tells a parent that ran out from one that was ended');
  t.check(!!(made.session.rpTokens && made.session.rpTokens.refreshToken),
          'the tokens are on the session, including the refresh token it ' +
          'renews with');

  const plain = signOnAndPortal('renew-bob', tokensRunningOutIn(HOUR, false),
                                0);
  t.equal(plain.session.expires, plain.parent.expires,
          'a session with NO refresh token expires with its sign-on session, ' +
          'exactly as every relying-party session did before renewal existed');
  forget([made.parent.id, made.session.id, plain.parent.id, plain.session.id]);
  log.debug("Leaving checkCreation().");
}

// ---------------------------------------------------------------------------
// 2. WHY A PARENT IS MISSING.
// ---------------------------------------------------------------------------
function checkParentRanOut(t) {
  log.debug("Entering checkParentRanOut().");
  t.log.info('a sign-on session that RAN OUT against one that was ENDED');

  const ranOut = signOnAndPortal('renew-carol', tokensRunningOutIn(HOUR, true),
                                 Date.now() + 24 * HOUR);
  // What a sweep does to a session past its expiry, with the clock moved on:
  // the parent leaves the store with no cascade, after the moment it would
  // have expired.
  realms.run(realms.DEFAULT_REALM, function () {
    authn.sessions.delete(ranOut.parent.id);
    const held = authn.sessions.get(ranOut.session.id);
    held.derivedFromExpires = Date.now() - 1000;
    authn.sessions.set(ranOut.session.id, held);
  });
  const stillThere = readPortal(ranOut.cookie);
  t.check(!!stillThere && stillThere.id === ranOut.session.id,
          'A PARENT THAT RAN OUT LEAVES A RENEWABLE SESSION STANDING — the ' +
          'same session, same id — which is the whole of "stay signed in ' +
          'past the hour"',
          stillThere ? stillThere.id : '(ended)');

  const vanished = signOnAndPortal('renew-dave', tokensRunningOutIn(HOUR, true),
                                   Date.now() + 24 * HOUR);
  realms.run(realms.DEFAULT_REALM, function () {
    authn.sessions.delete(vanished.parent.id);
  });
  const gone = readPortal(vanished.cookie);
  t.check(!gone,
          'a parent gone BEFORE it would have expired is a sign-out whose ' +
          'cascade did not reach this session, and the session is still ' +
          'ended — renewal did not turn the orphan check off',
          gone ? gone.id : '(ended)');
  t.check(!realms.run(realms.DEFAULT_REALM, function () {
            return authn.sessions.get(vanished.session.id);
          }),
          'ENDED and not merely refused: it is out of the store');

  const notRenewable = signOnAndPortal('renew-erin',
                                       tokensRunningOutIn(HOUR, false), 0);
  realms.run(realms.DEFAULT_REALM, function () {
    authn.sessions.delete(notRenewable.parent.id);
    const held = authn.sessions.get(notRenewable.session.id);
    held.derivedFromExpires = Date.now() - 1000;
    authn.sessions.set(notRenewable.session.id, held);
  });
  t.check(!readPortal(notRenewable.cookie),
          'and a session with nothing to renew with still ends with a parent ' +
          'that ran out');
  forget([ranOut.session.id, vanished.session.id, notRenewable.session.id]);
  log.debug("Leaving checkParentRanOut().");
}

// ---------------------------------------------------------------------------
// 3. THE DECISION TABLE.
// ---------------------------------------------------------------------------
function checkDecision(t) {
  log.debug("Entering checkDecision().");
  t.log.info('when a renewal happens, and when a session ends instead');
  const now = Date.now();
  const margin = 60 * 1000;
  const decide = function (tokens, renewableUntil) {
    return oidcRp.renewalDecision({ rpTokens: tokens,
                                    rpRenewableUntil: renewableUntil },
                                  now, margin);
  };
  t.equal(decide(tokensRunningOutIn(HOUR, true), now + 24 * HOUR).action,
          'none',
          'tokens good for an hour are not renewed');
  t.equal(decide(tokensRunningOutIn(30 * 1000, true), now + 24 * HOUR).action,
          'renew',
          'tokens inside the lead time ARE renewed, before they run out');
  t.equal(decide(tokensRunningOutIn(-1000, true), now + 24 * HOUR).action,
          'renew',
          'and tokens already run out are renewed');
  const early = oidcRp.renewalDecision({ rpTokens: tokensRunningOutIn(HOUR,
                                                                      true),
                                         rpRenewableUntil: now + 24 * HOUR },
                                       now, 2 * HOUR);
  t.equal(early.action, 'renew',
          'a lead time at or above the token lifetime renews on every request');
  t.equal(decide(tokensRunningOutIn(30 * 1000, false), 0).action, 'none',
          'with NO refresh token, tokens inside the lead time are left to ' +
          'run out rather than the session being ended early');
  const noRefresh = decide(tokensRunningOutIn(-1000, false), 0);
  t.equal(noRefresh.action + ' ' + noRefresh.code, 'end STS-AUTHN-0136',
          'with NO refresh token, tokens that have run out end the session');
  const closed = decide(tokensRunningOutIn(-1000, true), now - 1000);
  t.equal(closed.action + ' ' + closed.code, 'end STS-AUTHN-0141',
          'past the renewal window, tokens that have run out end the session ' +
          '— renewing never extends the window');
  t.equal(decide(tokensRunningOutIn(30 * 1000, true), now - 1000).action,
          'none',
          'and past the window, tokens still good are left to run out');
  t.equal(oidcRp.renewalDecision({ rpTokens: null }, now, margin).action,
          'none',
          'a session made before renewal existed has nothing to decide');
  log.debug("Leaving checkDecision().");
}

// ---------------------------------------------------------------------------
// 4. THE SAME SIGN-IN.
// ---------------------------------------------------------------------------
function checkSameSignIn(t) {
  log.debug("Entering checkSameSignIn().");
  t.log.info('a renewed ID Token must describe the same sign-in');
  const was = tokensRunningOutIn(HOUR, true);
  const same = { iss: was.issuer, sub: was.sub, auth_time: was.authTime };
  t.check(oidcRp.checkRenewedClaims(was, same).ok,
          'the same issuer, subject and authentication time is accepted');
  t.check(oidcRp.checkRenewedClaims(was, { iss: was.issuer, sub: was.sub }).ok,
          'an ID Token with no auth_time at all is accepted — section 12.2 ' +
          'constrains it only where it is present');
  t.check(!oidcRp.checkRenewedClaims(was, Object.assign({}, same,
            { iss: 'https://elsewhere.test' })).ok,
          'ANOTHER ISSUER is refused');
  t.check(!oidcRp.checkRenewedClaims(was, Object.assign({}, same,
            { sub: 'urn:sts:user:mallory' })).ok,
          'ANOTHER SUBJECT is refused — a genuine token about somebody else ' +
          'is not a renewal of this session');
  t.check(!oidcRp.checkRenewedClaims(was, Object.assign({}, same,
            { auth_time: was.authTime + 3600 })).ok,
          'A NEW AUTHENTICATION TIME is refused: a refresh is not an ' +
          'authentication');
  log.debug("Leaving checkSameSignIn().");
}

// ---------------------------------------------------------------------------
// 5. THE RENEWAL ITSELF.
// ---------------------------------------------------------------------------
function checkRenewal(t) {
  log.debug("Entering checkRenewal().");
  t.log.info('renewing writes onto the same session');
  const renewableUntil = Date.now() + 24 * HOUR;
  const old = tokensRunningOutIn(-1000, true);
  const made = signOnAndPortal('renew-frank', old, renewableUntil);
  const authTime = made.session.authTime;

  // What a refresh response WITHOUT a new refresh token and WITHOUT an ID
  // Token looks like once it is read — the two optional members absent.
  const renewed = oidcRp.tokensFrom({ access_token: 'access-new',
                                      token_type: 'Bearer',
                                      expires_in: 3600 }, null, 'default',
                                    'sts.test', old);
  t.equal(renewed.refreshToken, old.refreshToken,
          'a response with no new refresh token keeps the one the session has');
  t.equal(renewed.idTokenExpiresAt, 0,
          'and one with no ID Token leaves the access token as the only ' +
          'clock — the old ID Token\'s expiry would make a renewal due on ' +
          'every request');
  t.equal(renewed.authTime, old.authTime,
          'the authentication time is the sign-in\'s and a renewal does not ' +
          'move it');

  const after = realms.run(realms.DEFAULT_REALM, function () {
    return authn.renewRelyingPartySession({ realmId: realms.DEFAULT_ID,
                                            id: made.session.id,
                                            tokens: renewed });
  });
  t.check(!!after && after.id === made.session.id,
          'THE SAME SESSION: the renewal answers the record under the same ' +
          'id — no new session was made', after ? after.id : '(none)');
  t.equal(after && after.rpTokens.accessToken, 'access-new',
          'carrying the new access token');
  t.equal(after && after.rpRenewals, 1, 'and counting the renewal');
  t.equal(after && after.authTime, authTime,
          'with the session\'s own authentication time untouched');
  t.check(after && after.expires >= renewableUntil &&
          after.expires <= Math.max(renewableUntil,
                                    authn.tokensExpireAt(renewed)),
          'its expiry is still the renewal window: a renewal does not extend ' +
          'it',
          after && after.expires);
  const read = readPortal(made.cookie);
  t.check(!!read && read.rpTokens.accessToken === 'access-new',
          'and the cookie the browser already holds reads the renewed session');
  const row = realms.run(realms.DEFAULT_REALM, function () {
    return audit.list().filter(function (event) {
      return event.action === 'session.renew' &&
             event.target === made.session.id;
    })[0];
  });
  t.check(!!row && row.outcome === 'success',
          'one `session.renew` audit row, and it is the only thing a renewal ' +
          'records', row ? row.summary : '(no row)');
  t.check(!!row && JSON.stringify(row).indexOf(old.refreshToken) < 0 &&
          JSON.stringify(row).indexOf('access-new') < 0,
          'and no token is in it');
  t.check(realms.run(realms.DEFAULT_REALM, function () {
            return authn.renewRelyingPartySession({ realmId: realms.DEFAULT_ID,
                                                    id: made.parent.id,
                                                    tokens: renewed });
          }) === null,
          'a SIGN-ON session is not a relying-party session and is not ' +
          'renewed');
  forget([made.parent.id, made.session.id]);
  log.debug("Leaving checkRenewal().");
}

// ---------------------------------------------------------------------------
// 6. THE REGISTRATION ORDER, AS SOURCE.
// ---------------------------------------------------------------------------
function firstIndex(source, patterns) {
  log.debug("Entering firstIndex().");
  let best = -1;
  patterns.forEach(function (re) {
    const m = re.exec(source);
    if (m && (best < 0 || m.index < best)) {
      best = m.index;
    }
  });
  log.debug("Leaving firstIndex().");
  return best;
}

function checkRegistration(t) {
  log.debug("Entering checkRegistration().");
  t.log.info('both surfaces register the renewal above everything that reads ' +
             'the session');
  const admin = fs.readFileSync(path.join(__dirname, '..', 'admin-ui',
                                          'admin.js'), 'utf8');
  const renewAdmin = admin.indexOf("app.use('/admin', " +
                                   "oidcRp.renewal('admin'))");
  const firstAdmin = firstIndex(admin, [/^app\.use\('\/admin', function/m,
                                        /^app\.(get|post|all)\('\/admin/m]);
  t.check(renewAdmin >= 0, 'the console registers oidcRp.renewal(\'admin\')');
  t.check(renewAdmin >= 0 && firstAdmin > renewAdmin,
          'ABOVE the console gate and every /admin route (rule 1)',
          'renewal at ' + renewAdmin + ', first /admin handler at ' +
          firstAdmin);

  const portal = fs.readFileSync(path.join(__dirname, '..', 'portal',
                                           'portal.ts'), 'utf8');
  const renewPortal = portal.indexOf("app.use(BASE, oidcRp.renewal('portal'))");
  const firstPortal = firstIndex(portal,
                                 [/^\s*app\.(get|post|all|use)\((?!BASE, oidcRp\.renewal)/m]);
  t.check(renewPortal >= 0, 'the portal registers oidcRp.renewal(\'portal\')');
  t.check(renewPortal >= 0 && firstPortal > renewPortal,
          'ABOVE the first /portal route (rule 1)',
          'renewal at ' + renewPortal + ', first route at ' + firstPortal);
  log.debug("Leaving checkRegistration().");
}

async function run(t) {
  log.debug("Entering run().");
  checkCreation(t);
  checkParentRanOut(t);
  checkDecision(t);
  checkSameSignIn(t);
  checkRenewal(t);
  checkRegistration(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidc_rp_renewal',
  describe: 'the console and portal renew their tokens inside the same ' +
            'session: what a session is made with, a parent that ran out, ' +
            'the decision, the same sign-in, the renewal, and the ' +
            'registration order',
  run: run
};
