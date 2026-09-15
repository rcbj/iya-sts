'use strict';
//
// File: cross_surface_sso.js
//
// ===========================================================================
// THE ADMIN CONSOLE AND THE USER PORTAL SHARE A SIGN-ON SESSION, IN EVERY
// REALM, AND EACH STILL HOLDS A SESSION OF ITS OWN (2026-09-11).
//
// This is the contract behind a sentence somebody says about the product:
// *sign in once and move between the two surfaces without signing in again.*
// It falls out of the protocol — both are relying parties of this service's own
// authorization server, and an authorization endpoint that finds a sign-on
// session answers out of it — so for a year it was true in the default realm
// and nowhere else, because the console's code flow ran in the DEFAULT realm
// wherever it was reached while the portal's ran in the AMBIENT one. Two
// realms, two partitions of `authn.js`'s session store, and neither
// authorization endpoint able to see the other's session: two sign-ins, in both
// directions, for one person in one browser.
//
// The fix is in `common/oidc_rp.js`: a surface has TWO realms now. The FLOW
// runs in the ambient realm for both — which is the whole of the single
// sign-on — and the console's SESSION still lives in the default realm's
// partition, which is what keeps one console session readable from every realm
// and keeps the role roster in one place.
//
// **SO A CONSOLE SESSION'S PARENT IS IN A DIFFERENT PARTITION FROM THE SESSION
// ITSELF**, whenever the console is reached in a realm, and that is the state
// every assertion below is about. Three pieces of machinery had to learn it and
// each fails in a way that is invisible from the other two:
//
//   * `relyingPartySessionOf()` checks that the parent is still there. Looking
//     in the wrong partition reports every console session in a realm as an
//     orphan and ends it on sight — a sign-in that lasts exactly one request.
//   * `startRelyingPartySession()` takes its expiry from the parent. Looking in
//     the wrong partition finds nothing, falls back to a full session lifetime,
//     and leaves a console session outliving the sign-on session it descends
//     from.
//   * `dropSession()`'s cascade ends the derived sessions. Walking only the
//     parent's own partition finds nothing, so **the sign-on session ends and
//     the console session it issued goes on working** — which is a sign-out
//     that visibly does nothing on the one surface an operator is looking at,
//     the exact defect the cascade was written for.
//
// WHY IT IS HERE RATHER THAN IN THE PROTOCOL HALF. `tests/CLAUDE.md`'s first
// question sends anything about `/admin` to `tests/vendored/`, and the
// end-to-end flow IS asserted over HTTP there — `sts_portal_sessions.js` drives
// both surfaces in both realms. What is here is the half that job cannot see:
// these are assertions about WHICH PARTITION a record is in, and an HTTP caller
// holding a cookie that works cannot tell a session found in the default realm
// from one found in the ambient realm. The same argument `realm_isolation.js`
// makes beside it.
//
// It needs no port, no container and no browser: `authn.js`'s three functions
// are called directly, with a stub for the `res` they set a cookie on.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: a
// developer with CONFIG_FILE exported would otherwise be asserting against
// their own appconfig rather than against the service as it ships.
delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const authn = require('../authn/authn');
const oidcRp = require('../common/oidc_rp');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'cross_surface_sso',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// The two things these functions want from express and nothing else: somewhere
// to put a Set-Cookie, and somewhere to read one back from. A real response
// would drag the whole app in for two header operations.
// ---------------------------------------------------------------------------
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
    // `startRelyingPartySession()` reads `res.req` for the CAEP observer's
    // issuer. There is no request here and null is what that path expects.
    req: null
  };
}

// The cookie value the response above was given, by name.
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

// A request carrying one cookie. `cookiesOf()` parses `req.headers.cookie` and
// wants nothing else.
function reqWith(pairs) {
  log.debug("Entering reqWith().");
  const bits = Object.keys(pairs)
                     .map(function (k) { return k + '=' + pairs[k]; });
  log.debug("Leaving reqWith().");
  return { headers: { cookie: bits.join('; ') } };
}

// Create a realm, hand it to `fn`, and remove it however that goes. The realm
// table is process-wide, so a realm left behind changes what a later test in
// the same run resolves. Same shape as realm_isolation.js's, deliberately.
function withRealm(t, id, fn) {
  log.debug("Entering withRealm().");
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving withRealm().");
    return undefined;
  }
  try {
    log.debug("Leaving withRealm().");
    return fn(made.realm);
  } finally {
    realms.remove(id);
  }
}

// A sign-on session in whatever realm is ambient, and the console session
// derived from it — which is what the code flow produces, with the parent in
// the ambient realm and the session in the default one.
function signOnIn(realm, username) {
  log.debug("Entering signOnIn().");
  log.debug("Leaving signOnIn().");
  return realms.run(realm, function () {
    return authn.startSession(fakeRes(), username, [], '1', 'Test', {});
  });
}

function consoleSessionFrom(parent, parentRealmId, username) {
  log.debug("Entering consoleSessionFrom().");
  const res = fakeRes();
  const session = realms.run(realms.DEFAULT_REALM, function () {
    return authn.startRelyingPartySession({
      res: res, username: username, claims: {}, via: 'Admin console',
      parent: parent.id, parentRealm: parentRealmId,
      surface: 'admin', label: 'Admin console',
      clientId: 'sts-admin-console', cookie: 'sts_admin'
    });
  });
  log.debug("Leaving consoleSessionFrom().");
  return { session: session, cookie: cookieFrom(res, 'sts_admin') };
}

// ---------------------------------------------------------------------------
// 1. THE SURFACE TABLE. The two realms are two fields, and which is which is
//    the whole of the design — so it is asserted before anything that rests on
//    it, and by name rather than by behaviour.
// ---------------------------------------------------------------------------
function checkSurfaceTable(t) {
  log.debug("Entering checkSurfaceTable().");
  t.log.info('the surface table: a FLOW realm and a SESSION realm');

  const admin = oidcRp.surfaceOf('admin');
  const portal = oidcRp.surfaceOf('portal');

  t.equal(admin.flowRealm, 'ambient',
          'the console AUTHORIZES in the ambient realm — this is the single ' +
          'sign-on');
  t.equal(portal.flowRealm, 'ambient',
          'and so does the portal, which is what makes them the same sign-on ' +
          'session');
  t.equal(admin.sessionRealm, 'default',
          'the console\'s own session stays in the DEFAULT realm, so one ' +
          'console session is readable from every realm and the role roster ' +
          'stays in one place');
  t.equal(portal.sessionRealm, 'ambient',
          'the portal\'s session is the realm\'s own — a person in acme is a ' +
          'different person from the one in the default realm');

  t.check(admin.cookie !== portal.cookie,
          'and the two surfaces keep separate cookies: sharing a sign-on ' +
          'session is not sharing a session',
          admin.cookie + ' / ' + portal.cookie);
  log.debug("Leaving checkSurfaceTable().");
}

// ---------------------------------------------------------------------------
// 2. A PARENT IN ANOTHER REALM IS FOUND.
//
// The console session below is the shape the code flow produces inside a realm:
// the record is in the default partition and its `derivedFrom` names a session
// in the realm's. If the parent were looked up in the session's own partition
// it would not be there, and the read would end the session as an orphan.
// ---------------------------------------------------------------------------
function checkParentAcrossRealms(t) {
  log.debug("Entering checkParentAcrossRealms().");
  t.log.info('a console session whose sign-on session is in another realm');

  withRealm(t, 'sso-parent', function (realm) {
    const parent = signOnIn(realm, 'cross-alice');
    t.check(!!parent && !!parent.id, 'the realm has a sign-on session',
            parent && parent.id);

    const made = consoleSessionFrom(parent, realm.id, 'cross-alice');
    t.equal(made.session.derivedFrom, parent.id,
            'the console session names the sign-on session it came from');
    t.equal(made.session.derivedFromRealm, realm.id,
            'AND NAMES THE REALM IT IS IN, which is the field the whole of ' +
            'this file rests on');

    // The read, from inside the realm — which is where the console is reached
    // when a person is looking at /realm/sso-parent/admin.
    const read = realms.run(realm, function () {
      return authn.relyingPartySessionOf(
        reqWith({ sts_admin: made.cookie }), 'sts_admin', realms.DEFAULT_ID);
    });
    t.check(!!read, 'and it is honoured when read from inside that realm — ' +
            'the parent check looks in the parent\'s partition and not in ' +
            'this one',
            read ? read.id : '(the session was refused or ended)');

    t.equal(read && read.user && read.user.username, 'cross-alice',
            'and it is the person who signed in');

    // The expiry is the parent's. Read out of the wrong partition the parent is
    // not found at all, and the session gets a full fresh lifetime instead.
    t.equal(made.session.expires, parent.expires,
            'the console session expires WITH the sign-on session, which ' +
            'means the parent was found in the right partition when it was ' +
            'created');
  });
  log.debug("Leaving checkParentAcrossRealms().");
}

// ---------------------------------------------------------------------------
// 3. THE CASCADE REACHES ACROSS.
//
// This is the assertion the whole change is worth having. A sign-out ends the
// sign-on session; the console session derived from it lives in a different
// partition, and before 2026-09-11 the walk never looked there.
// ---------------------------------------------------------------------------
function checkCascadeAcrossRealms(t) {
  log.debug("Entering checkCascadeAcrossRealms().");
  t.log.info('ending a realm\'s sign-on session ends the console session it ' +
             'issued');

  withRealm(t, 'sso-cascade', function (realm) {
    const parent = signOnIn(realm, 'cross-bob');
    const made = consoleSessionFrom(parent, realm.id, 'cross-bob');

    // ---------------------------------------------------------------------
    // **THE STORE IS READ AND NOT THE READER, AND THAT ORDER IS THE WHOLE
    // ASSERTION.** `relyingPartySessionOf()` ends an orphan as it finds one —
    // so asking IT whether the console session is gone passes whether the
    // cascade ran or the reader cleaned up after it, which is two opposite
    // states reported as one. It was written that way round first and survived
    // both cascade mutants. `sessionById()` is a bare map lookup: it changes
    // nothing, so what it reports is what the SIGN-OUT left behind.
    // ---------------------------------------------------------------------
    t.check(!!realms.run(realms.DEFAULT_REALM, function () {
              return authn.sessionById(made.session.id);
            }),
            'the console session is in the default realm\'s store before the ' +
            'sign-out');

    realms.run(realm, function () {
      authn.endSessionById(parent.id, 'this test');
    });

    t.check(!realms.run(realms.DEFAULT_REALM, function () {
              return authn.sessionById(made.session.id);
            }),
            'AND THE SIGN-OUT ITSELF TOOK IT. Walking only the parent\'s own ' +
            'partition finds no children, so the sign-on session ends and ' +
            'the console session it issued goes on working — a sign-out that ' +
            'visibly does nothing on the one surface an operator is looking at',
            'the console session ' + made.session.id +
            ' is still in the store');

    // And the reader agrees, which is the half a person actually meets. It is
    // asserted SECOND and never instead of the line above.
    const after = realms.run(realm, function () {
      return authn.relyingPartySessionOf(
        reqWith({ sts_admin: made.cookie }), 'sts_admin', realms.DEFAULT_ID);
    });
    t.check(!after, 'and the cookie no longer admits anybody',
            after ? 'the console session ' + after.id + ' is still honoured' :
            '');
  });
  log.debug("Leaving checkCascadeAcrossRealms().");
}

// ---------------------------------------------------------------------------
// 4. AND A CHILD IN ANOTHER PARTITION IS NOT ENDED BY SOMEBODY ELSE'S SIGN-OUT.
//
// **ONE CLAIM HERE IS NOT REACHED BY THIS TEST AND SAYING SO IS BETTER THAN
// LOOKING AS THOUGH IT IS.** `derivedFrom()` skips a child in the other
// partition whose `derivedFromRealm` is not the realm being signed out of, and
// removing that check leaves every assertion below passing — because reaching
// it needs TWO SESSIONS IN TWO PARTITIONS WITH THE SAME ID, and ids are 24
// random bytes. There is no public way to put a record into the store with an
// id of this test's choosing, and adding one to make an assertion reachable
// would be a door into the session store that exists for a test.
//
// So the check is defensive, against the day ids come from somewhere that can
// repeat them — a restored store, a fixture, an import — and what is asserted
// instead is the property it protects: a sign-out in one realm leaves another
// realm's children alone. That much IS reachable, and it is the half a person
// meets. `backup_codes.js` records an unreachable branch the same way and for
// the same reason.
// ---------------------------------------------------------------------------
function checkOtherRealmsSignOutLeavesItAlone(t) {
  log.debug("Entering checkOtherRealmsSignOutLeavesItAlone().");
  t.log.info('a sign-out in one realm leaves another realm\'s children alone');

  const parent = realms.run(realms.DEFAULT_REALM, function () {
    return authn.startSession(fakeRes(), 'cross-carol', [], '1', 'Test', {});
  });
  const made = consoleSessionFrom(parent, realms.DEFAULT_ID, 'cross-carol');

  withRealm(t, 'sso-other', function (realm) {
    // A sign-on session in the OTHER realm, ended. It is a different session
    // and must take nothing of the default realm's with it.
    const theirs = signOnIn(realm, 'cross-dave');
    realms.run(realm, function () {
      authn.endSessionById(theirs.id, 'this test');
    });

    const still = realms.run(realms.DEFAULT_REALM, function () {
      return authn.relyingPartySessionOf(
        reqWith({ sts_admin: made.cookie }), 'sts_admin', realms.DEFAULT_ID);
    });
    t.check(!!still,
            'the console session derived from the DEFAULT realm\'s sign-on ' +
            'session is untouched',
            still ? still.id : '(it was ended by a sign-out in another realm)');
  });

  realms.run(realms.DEFAULT_REALM, function () {
    authn.endSessionById(parent.id, 'this test cleaning up');
  });
  log.debug("Leaving checkOtherRealmsSignOutLeavesItAlone().");
}

// ---------------------------------------------------------------------------
// 5. THE DEFAULT REALM IS UNCHANGED, which is this repository's standing
//    contract about every realm feature: a service with no realms defined
//    behaves exactly as it did.
// ---------------------------------------------------------------------------
function checkDefaultRealmUnchanged(t) {
  log.debug("Entering checkDefaultRealmUnchanged().");
  t.log.info('a service with no realms defined');

  t.equal(realms.count(), 1,
          'this test cleaned up after itself — only the default realm is left');

  const parent = realms.run(realms.DEFAULT_REALM, function () {
    return authn.startSession(fakeRes(), 'cross-erin', [], '1', 'Test', {});
  });
  // No `parentRealm` at all, which is what every caller older than 2026-09-11
  // passed and what the portal passes in the default realm.
  const res = fakeRes();
  const session = realms.run(realms.DEFAULT_REALM, function () {
    return authn.startRelyingPartySession({
      res: res, username: 'cross-erin', claims: {}, via: 'User portal',
      parent: parent.id, surface: 'portal', label: 'User portal',
      clientId: 'sts-user-portal', cookie: 'sts_portal'
    });
  });
  t.equal(session.derivedFromRealm, realms.DEFAULT_ID,
          'a caller that names no parent realm gets its own, which is what ' +
          'an absent field has always meant');

  const cookie = cookieFrom(res, 'sts_portal');
  t.check(!!realms.run(realms.DEFAULT_REALM, function () {
            return authn.relyingPartySessionOf(
              reqWith({ sts_portal: cookie }), 'sts_portal');
          }),
          'and it reads back with no realm named at all, which is every ' +
          'caller in a service with no realms defined');

  realms.run(realms.DEFAULT_REALM, function () {
    authn.endSessionById(parent.id, 'this test');
  });
  t.check(!realms.run(realms.DEFAULT_REALM, function () {
            return authn.relyingPartySessionOf(
              reqWith({ sts_portal: cookie }), 'sts_portal');
          }),
          'and the cascade inside one realm still works, which is the case ' +
          'that existed before any of this');
  log.debug("Leaving checkDefaultRealmUnchanged().");
}

function run(t) {
  log.debug("Entering run().");
  checkSurfaceTable(t);
  checkParentAcrossRealms(t);
  checkCascadeAcrossRealms(t);
  checkOtherRealmsSignOutLeavesItAlone(t);
  checkDefaultRealmUnchanged(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cross_surface_sso',
  describe: 'the console and the portal share a sign-on session in every realm',
  run: run
};
