'use strict';
//
// File: session_clocks.js
//
// ===========================================================================
// THE SESSION CLOCKS, AND WHO A SIGN-OUT MAY NAME (2026-09-12).
//
// Two findings from the audit for hard-coded values, tested together because
// both are about when a session stops being honoured and who may make it stop.
//
//   1. **THE SESSION LIFETIME WAS A LITERAL HOUR AND THERE WAS NO IDLE TIMEOUT
//      AT ALL.** `authn.sessionLifetimeS` and `authn.sessionIdleTimeoutS` now,
//      with the second's ZERO meaning none — the default, and a value the
//      obvious `Number(x) || fallback` would silently turn into something else.
//      The sign-in screen's ten minutes and the second-factor step's five are
//      `authn.pendingTtlS` and `authn.mfaStepTtlS`.
//   2. **AN ANONYMOUS `/logout?username=` ENDED ANYBODY'S SESSIONS IN PRODUCT
//      MODE.** The argument for it — nothing checks a password, so anybody can
//      already become that person — is a development-mode argument.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS.
//
// An idle timeout over HTTP is a test that sleeps for it, and the claim that
// matters most — a session unused for too long is ENDED, with the audit row
// and the CAEP event every other ending writes, rather than merely refused —
// is a claim about the store, which no response shows. The sign-out half is a
// decision about a mode and a setting that every stack runs at its defaults,
// and the parent suite has no product-mode stack to ask.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const authn = require('../authn/authn');
const logout = require('../logout/logout');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'session_clocks',
  level: process.env.LOG_LEVEL || 'info' });

function noBrowser() {
  log.debug("Entering noBrowser().");
  const headers = [];
  log.debug("Leaving noBrowser().");
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

function cookieOf(res, name) {
  log.debug("Entering cookieOf().");
  let found = '';
  res.headers.forEach(function (line) {
    const pair = String(line).split(';')[0];
    const i = pair.indexOf('=');
    if (i > 0 && pair.slice(0, i) === name) {
      found = pair.slice(i + 1);
    }
  });
  log.debug("Leaving cookieOf().");
  return found;
}

function reqWith(pairs, query) {
  log.debug("Entering reqWith().");
  const bits = Object.keys(pairs)
                     .map(function (k) { return k + '=' + pairs[k]; });
  log.debug("Leaving reqWith().");
  return { headers: { cookie: bits.join('; ') }, query: query || {} };
}

function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function near(actual, expected, slackMs) {
  log.debug("Entering near().");
  log.debug("Leaving near().");
  return Math.abs(actual - expected) <= (slackMs || 5000);
}

function run(t) {
  log.debug("Entering run().");
  // -----------------------------------------------------------------------
  t.log.info('=== 1. the lifetime is a setting, stamped at creation ===');
  const res = noBrowser();
  const plain = authn.startSession(res, 'clock-alice', ['pwd'], '1', 'Test');
  t.check(plain && near(plain.expires, Date.now() + 3600000),
          'an unedited service gives a session the hour it always did',
          plain && new Date(plain.expires).toISOString());
  withSettings({ 'authn.sessionLifetimeS': 120 }, function () {
    const short = authn.startSession(noBrowser(), 'clock-bob', ['pwd'], '1',
                                     'Test');
    t.check(near(short.expires, Date.now() + 120000),
            'authn.sessionLifetimeS=120 gives the next session two minutes',
            new Date(short.expires).toISOString());
    t.check(near(plain.expires, plain.authTime * 1000 + 3600000, 10000),
            'and leaves a session that already exists with the lifetime it ' +
            'was issued with');
    const keyed = authn.startSession(noBrowser(), 'clock-scim', ['pwd'], '1',
                                     'SCIM', { key: 'k-clock', cookie: false });
    const touched = authn.startSession(noBrowser(), 'clock-scim', ['pwd'], '1',
                                       'SCIM',
                                       { key: 'k-clock', cookie: false });
    t.check(touched.id === keyed.id &&
            near(touched.expires, Date.now() + 120000),
            'and an API session touched by a call is extended by the ' +
            'SETTING, not by the hour it used to be');
  });

  // -----------------------------------------------------------------------
  t.log.info('=== 2. the idle timeout: zero is none, and it is checked at ' +
             'read ===');
  const cookie = cookieOf(res, authn.SESSION_COOKIE);
  t.check(!!cookie, 'the browser session above set its cookie');
  const stored = authn.sessions.get(plain.id);
  stored.lastSeenAt = Date.now() - 7200000;
  authn.sessions.set(plain.id, stored);
  t.equal(authn.sessionIdleTimeoutMs(), 0,
          'with nothing configured there is NO idle timeout — a zero read as ' +
          '"absent" would have invented one');
  t.check(!!authn.sessionOf(reqWith({ sts_session: cookie })),
          'so a session unused for two hours is still honoured, as it always ' +
          'was');
  t.check(authn.sessions.get(plain.id).lastSeenAt < Date.now() - 3600000,
          'and reading it wrote NOTHING — with no idle timeout a read is not ' +
          'a write to a persisted store');

  withSettings({ 'authn.sessionIdleTimeoutS': 60 }, function () {
    t.equal(authn.sessionEnded({ expires: Date.now() + 60000, chosen: false,
                                 lastSeenAt: Date.now() - 600000 }), '',
            'an ARRIVAL session is exempt — it has an inactivity window of ' +
            'its own on the sign-in screen\'s clock');
    t.equal(authn.sessionEnded(authn.sessions.get(plain.id)), 'idle',
            'sessionEnded() calls the two-hour-idle session idle');
    const gone = authn.sessionOf(reqWith({ sts_session: cookie }));
    t.check(!gone, 'and sessionOf() refuses it');
    t.check(!authn.sessions.get(plain.id),
            'and ENDS it — it is out of the store, which is what makes the ' +
            'audit row and the CAEP event every other ending writes happen, ' +
            'rather than a row refused on every request and listed as live');

    const fresh = authn.startSession(noBrowser(), 'clock-carol', ['pwd'], '1',
                                     'Test');
    const freshStored = authn.sessions.get(fresh.id);
    freshStored.lastSeenAt = Date.now() - 30000;
    authn.sessions.set(fresh.id, freshStored);
    t.equal(authn.sessionEnded(freshStored), '',
            'a session used thirty seconds ago is live under a sixty-second ' +
            'timeout');
    t.check(logout.liveSessions().some(function (row) {
      return row.sessionId === fresh.id;
    }), 'and /admin/sessions lists it');
    freshStored.lastSeenAt = Date.now() - 90000;
    authn.sessions.set(fresh.id, freshStored);
    t.check(!logout.liveSessions().some(function (row) {
      return row.sessionId === fresh.id;
    }), 'while the SAME session gone ninety seconds idle is off that list — ' +
        'logout.js asks authn.js whether it has ended rather than comparing ' +
        'an expiry of its own');

    // USE OF THE CONSOLE IS USE OF THE SIGN-ON SESSION BEHIND IT.
    const parent = authn.startSession(noBrowser(), 'clock-dave', ['pwd'], '1',
                                      'Test');
    const rpRes = noBrowser();
    const child = authn.startRelyingPartySession({
      res: rpRes, username: 'clock-dave', claims: { sid: parent.id },
      via: 'Admin console', parent: parent.id, surface: 'admin',
      label: 'Admin console', clientId: 'sts-admin-console',
      cookie: 'sts_admin'
    });
    const parentStored = authn.sessions.get(parent.id);
    parentStored.lastSeenAt = Date.now() - 45000;
    authn.sessions.set(parent.id, parentStored);
    const rpCookie = cookieOf(rpRes, 'sts_admin');
    const read = authn.relyingPartySessionOf(reqWith({ sts_admin: rpCookie }),
                                             'sts_admin');
    t.check(read && read.id === child.id, 'the console session is read');
    t.check(Date.now() - authn.sessions.get(parent.id).lastSeenAt < 5000,
            'and reading it TOUCHED the sign-on session it came from — ' +
            'without that, somebody working in the console presents only the ' +
            'console\'s cookie, the sweep idles the parent out, and the ' +
            'cascade signs them out of the page they are using');
  });

  // -----------------------------------------------------------------------
  t.log.info('=== 3. the two waiting clocks ===');
  t.equal(authn.pendingTtlMs(), 600000, 'the sign-in screen waits ten minutes');
  t.equal(authn.mfaStepTtlMs(), 300000, 'and a second-factor step five');
  withSettings({ 'authn.pendingTtlS': 45, 'authn.mfaStepTtlS': 40 },
               function () {
    const url = authn.beginAuthentication({ returnTo: '/admin',
                                            protocol: 'Test' });
    const id = decodeURIComponent(String(url).split('authn=')[1] || '');
    const record = authn.pendingFor(id);
    t.check(record && near(record.expires, Date.now() + 45000),
            'a pending sign-in record takes authn.pendingTtlS', String(url));
    t.equal(authn.mfaStepTtlMs(), 40000, 'and the step clock follows its ' +
                                         'setting');
  });

  // -----------------------------------------------------------------------
  t.log.info('=== 4. the sentence each session row carries ===');
  t.check(/no idle timeout configured/.test(logout.SESSION_EXPIRY_RULES.session) &&
          /an hour after the sign-in/.test(logout.SESSION_EXPIRY_RULES.session),
          'unedited, the browser rule says an hour and no idle timeout',
          logout.SESSION_EXPIRY_RULES.session);
  withSettings({ 'authn.sessionLifetimeS': 1800,
                 'authn.sessionIdleTimeoutS': 300 }, function () {
    const rule = logout.SESSION_EXPIRY_RULES.session;
    t.check(/30 minutes after the sign-in/.test(rule) &&
            /5 minutes unused/.test(rule) && !/no idle timeout/.test(rule),
            'configured, it says thirty minutes and five idle — it was two ' +
            'literals that would have gone on saying an hour and none', rule);
    t.check(/30 minutes after the\s+last call/.test(
        logout.SESSION_EXPIRY_RULES.api),
            'and the API rule follows the same lifetime',
            logout.SESSION_EXPIRY_RULES.api);
  });

  // -----------------------------------------------------------------------
  t.log.info('=== 5. who a /logout may name ===');
  const erin = authn.startSession(noBrowser(), 'clock-erin', ['pwd'], '1',
                                  'Test');
  const erinRes = noBrowser();
  const erinAgain = authn.startSession(erinRes, 'clock-erin', ['pwd'], '1',
                                       'Test');
  const erinCookie = cookieOf(erinRes, authn.SESSION_COOKIE);
  t.check(!!erin && !!erinAgain && !!erinCookie, 'a signed-in person to sign ' +
                                                 'out');

  const devNamed = logout.subjectOf(reqWith({}, { username: 'clock-frank' }),
                                    null);
  t.check(devNamed.named && devNamed.username === 'clock-frank',
          'development mode, anonymous, naming somebody: honoured as it ' +
          'always was — nothing checks a password ' +
          'there', JSON.stringify(devNamed));

  withSettings({ 'global.mode': 'product' }, function () {
    const anonymous = logout.subjectOf(reqWith({}, { username: 'clock-frank' }),
                                       null);
    t.check(anonymous.refused && !anonymous.key,
            'PRODUCT mode, anonymous, naming somebody: REFUSED — this was an ' +
            'unauthenticated way to end any person\'s sessions and revoke ' +
            'their tokens', JSON.stringify(anonymous));
    const other = logout.subjectOf(
      reqWith({ sts_session: erinCookie }, { username: 'clock-frank' }), null);
    t.check(other.refused,
            'and a signed-in person naming SOMEBODY ELSE is refused too — ' +
            'the operator\'s door is /admin/logout', JSON.stringify(other));
    const own = logout.subjectOf(
      reqWith({ sts_session: erinCookie }, { username: 'clock-erin' }), null);
    t.check(!own.refused && own.username === 'clock-erin' && !!own.session,
            'while naming YOURSELF is honoured, because every form the page ' +
            'draws posts the name it was drawn for', JSON.stringify(own));
    const noName = logout.subjectOf(reqWith({ sts_session: erinCookie }), null);
    t.equal(noName.username, 'clock-erin',
            'and the ordinary sign-out, naming nobody, is untouched');
  });
  withSettings({ 'logout.anyUser': 'false' }, function () {
    t.check(logout.subjectOf(reqWith({}, { username: 'clock-frank' }),
                             null).refused,
            'and in development logout.anyUser=false still closes it, as ' +
            'before');
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'session_clocks',
  describe: 'the session lifetime and idle timeout as settings checked where ' +
            'a session is read, the two waiting clocks, the sentence a ' +
            'session row carries, and an anonymous /logout?username= refused ' +
            'in product',
  run: run
};
