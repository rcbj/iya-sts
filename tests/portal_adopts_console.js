// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_adopts_console.js
//
// ===========================================================================
// THE USER PORTAL ADOPTS A LIVE ADMIN CONSOLE SESSION (2026-09-30).
//
// Observed on a product deployment: an administrator signed in to `/admin`,
// followed the console's link to their own account, and was asked to choose a
// realm and then to sign in again. The console session had outlived the
// sign-on session behind it by renewing its own tokens (`common/oidc_rp.ts`
// section 4), and the portal's own code flow met no sign-on session.
//
// The owner's decision: the portal reads the realm and the authenticated
// session from the console session. `portal/portal.ts`'s
// `adoptConsoleSession()` makes a portal session of its own from it, and
// `authn/authn.ts`'s `adoptRelyingPartySession()` and `dropSession()`'s
// cascade make that session end with the console session. What is asserted:
//
//   1. a live console session with NO sign-on session behind it is adopted —
//      no chooser, no redirect, the same person, in the realm they signed in
//      through, and the access policy still asked;
//   2. the adopted session ENDS with the console session, by the cascade and
//      by the reader;
//   3. with no console session the old path is untouched (the chooser);
//   4. a realm administrator's console session at the bare `/portal` is a
//      redirect to that realm's portal, and is adopted there;
//   5. a portal session never admits the console.
//
// In process for `cross_surface_sso.js`'s reason: these are assertions about
// which partition a row is in and what the cascade reaches, which an HTTP
// caller holding a working cookie cannot see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'portal_adopts_console',
  level: process.env.LOG_LEVEL || 'info' });

const HOUR = 3600 * 1000;

// A response with the parts `authn` and `portal.send()` touch.
function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = {
    headers: [],
    fields: {},
    statusCode: 200,
    body: undefined,
    location: '',
    headersSent: false,
    req: null,
    getHeader: function () {
      log.debug("Entering getHeader().");
      log.debug("Leaving getHeader().");
      return res.headers.slice();
    },
    setHeader: function (name, value) {
      log.debug("Entering setHeader().");
      res.headers.length = 0;
      [].concat(value).forEach(function (v) {
        res.headers.push(v);
      });
      log.debug("Leaving setHeader().");
    },
    status: function (code) {
      log.debug("Entering status().");
      res.statusCode = code;
      log.debug("Leaving status().");
      return res;
    },
    // `authn`'s cookie writer prefers express's `set()`, as a real
    // response does, so a Set-Cookie through here is a cookie too.
    set: function (name, value) {
      log.debug("Entering set().");
      if (String(name).toLowerCase() === 'set-cookie') {
        res.setHeader(name, value);
      } else {
        res.fields[name] = value;
      }
      log.debug("Leaving set().");
      return res;
    },
    type: function () {
      log.debug("Entering type().");
      log.debug("Leaving type().");
      return res;
    },
    send: function (body) {
      log.debug("Entering send().");
      res.body = body;
      res.headersSent = true;
      log.debug("Leaving send().");
      return res;
    },
    redirect: function (code, where) {
      log.debug("Entering redirect().");
      res.statusCode = code;
      res.location = where;
      res.headersSent = true;
      log.debug("Leaving redirect().");
    }
  };
  log.debug("Leaving fakeRes().");
  return res;
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

// A GET of `path` carrying `cookies`, shaped as far as `requireSignIn()`,
// `baseUrlOf()` and `cookiesOf()` read one.
function reqFor(path, cookies, query) {
  log.debug("Entering reqFor().");
  const bits = Object.keys(cookies || {}).map(function (k) {
    return k + '=' + cookies[k];
  });
  log.debug("Leaving reqFor().");
  return {
    method: 'GET', originalUrl: path, url: path, query: query || {},
    protocol: 'https',
    headers: { cookie: bits.join('; '), host: 'sts.test' },
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return String(name).toLowerCase() === 'host' ? 'sts.test' : undefined;
    }
  };
}

// Tokens shaped as `oidc_rp.tokensFrom()` makes them, good for an hour and
// renewable: what a console session holds after a code flow.
function renewableTokens() {
  log.debug("Entering renewableTokens().");
  const now = Date.now();
  log.debug("Leaving renewableTokens().");
  return {
    accessToken: 'access-' + now, tokenType: 'Bearer', scope: 'openid',
    accessExpiresAt: now + HOUR, refreshToken: 'refresh-' + now,
    idToken: 'id-' + now, idTokenExpiresAt: now + HOUR,
    issuer: 'https://sts.test', sub: 'urn:uuid:adopt', authTime:
      Math.floor(now / 1000) - 60, flowRealm: 'default', host: 'sts.test'
  };
}

function run(t) {
  log.debug("Entering run().");
  require('../common/app');
  const realms = require('../common/realms');
  const authn = require('../authn/authn');
  const oidcRp = require('../common/oidc_rp');
  const portalModule = require('../portal/portal');

  // THE ACCESS POLICY, RECORDED. A stub in place of the gate, so this file
  // asserts that `requireSignIn()` ASKS it about an adopted session — and
  // that a refusal is honoured — whatever policy another test in this process
  // armed.
  const asked = [];
  let refuse = false;
  const gate = {
    RESOURCE: { PORTAL: 'user-portal' },
    ACTION: { MANAGE_OWN: 'manage-own', READ: 'read' },
    check: function (request) {
      log.debug("Entering check().");
      asked.push(request);
      log.debug("Leaving check().");
      return refuse ? { allowed: false, why: 'refused by this test' }
                    : { allowed: true, why: 'allowed by this test' };
    }
  };
  const deps = Object.assign({}, portalModule.Portal.defaultDeps(),
                             { accessGate: gate });
  const portal = new portalModule.Portal(deps);

  // A sign-on session in `realm` and the console session derived from it, as
  // the code flow makes them — and then the sign-on session RUNS OUT, which is
  // the state the defect was observed in: gone from the store after the
  // moment it would have expired, with no cascade.
  const consoleWithoutSignOn = function (realm, username) {
    log.debug("Entering consoleWithoutSignOn().");
    const signOn = realms.run(realm, function () {
      return authn.startSession(fakeRes(), username, [], '1', 'Test', {});
    });
    const res = fakeRes();
    const held = realms.run(realms.DEFAULT_REALM, function () {
      return authn.startRelyingPartySession({
        res: res, username: username, claims: { acr: 'urn:test:acr' },
        amr: ['pwd'], via: 'Admin console', parent: signOn.id,
        parentRealm: realm.id, surface: 'admin', label: 'Admin console',
        clientId: 'sts-admin-console', cookie: 'sts_admin',
        tokens: renewableTokens(), renewableUntil: Date.now() + 24 * HOUR
      });
    });
    realms.run(realm, function () {
      authn.sessions.delete(signOn.id);
    });
    realms.run(realms.DEFAULT_REALM, function () {
      const row = authn.sessions.get(held.id);
      row.derivedFromExpires = Date.now() - 1000;
      authn.sessions.set(held.id, row);
    });
    log.debug("Leaving consoleWithoutSignOn().");
    return { signOnId: signOn.id, session: held,
             cookie: cookieFrom(res, 'sts_admin') };
  };

  const portalRow = function (realm, id) {
    log.debug("Entering portalRow().");
    log.debug("Leaving portalRow().");
    return realms.run(realm, function () {
      return authn.sessionById(id);
    });
  };

  const withRealm = function (id, fn) {
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
  };

  // -------------------------------------------------------------------------
  // 1. ADOPTED, WITH NO SIGN-ON SESSION BEHIND THE CONSOLE.
  // -------------------------------------------------------------------------
  t.log.info('=== a live console session and no sign-on session ===');
  withRealm('adopt-other', function () {
    // A realm exists, so the bare /portal would draw the chooser — which is
    // the first half of what the administrator met.
    const held = consoleWithoutSignOn(realms.DEFAULT_REALM, 'adopt-alice');
    t.check(!!realms.run(realms.DEFAULT_REALM, function () {
              return oidcRp.sessionFor(reqFor('/admin',
                                              { sts_admin: held.cookie }),
                                       'admin');
            }),
            'the console session is live with its sign-on session gone — ' +
            'the state the defect was observed in');
    const res = fakeRes();
    asked.length = 0;
    const got = realms.run(realms.DEFAULT_REALM, function () {
      return portal.requireSignIn(reqFor('/portal',
                                         { sts_admin: held.cookie }),
                                  res, '/portal', 'read');
    });
    t.check(!!got, 'the portal answers with a session of its own',
            'status=' + res.statusCode + ' location=' + res.location);
    t.check(res.body === undefined && !res.location,
            'AND NO CHOOSER AND NO REDIRECT TO SIGN IN — nothing was sent',
            String(res.body || res.location).slice(0, 120));
    t.equal(got && got.user && got.user.username, 'adopt-alice',
            'the same person');
    t.equal(got && got.rpSurface, 'portal', 'a PORTAL session');
    t.equal(got && got.derivedFrom, held.session.id,
            'whose parent is the console session');
    t.equal(got && got.derivedFromRealm, realms.DEFAULT_ID,
            'in the default realm\'s partition, where the console\'s lives');
    t.equal(got && got.rpAdoptedFrom, 'admin', 'and which says it was adopted');
    t.equal(got && got.expires, held.session.expires,
            'its life is bounded by the console session\'s');
    t.equal(got && got.acr, 'urn:test:acr',
            'and it carries the same authentication record');
    t.check(!!(got && portalRow(realms.DEFAULT_REALM, got.id)),
            'it is in the realm the person signed in through — the default');
    t.equal(asked.length, 1, 'THE ACCESS POLICY WAS ASKED about it');
    t.equal(asked[0] && asked[0].subject && asked[0].subject.name,
            'adopt-alice', 'about the adopted session\'s person');
    const portalCookie = cookieFrom(res, 'sts_portal');
    t.check(!!portalCookie, 'the portal\'s own cookie was set');
    t.check(!cookieFrom(res, 'sts_admin'),
            'and the console\'s was not touched');
    const again = realms.run(realms.DEFAULT_REALM, function () {
      return oidcRp.sessionFor(reqFor('/portal',
                                      { sts_portal: portalCookie }),
                               'portal');
    });
    t.equal(again && again.id, got && got.id,
            'the portal cookie reads back as that session');

    // 5. ONE DIRECTION: the portal session admits no console.
    t.log.info('=== a portal session never admits /admin ===');
    const asConsole = realms.run(realms.DEFAULT_REALM, function () {
      return oidcRp.sessionFor(reqFor('/admin',
                                      { sts_portal: portalCookie }),
                               'admin');
    });
    t.check(!asConsole, 'the portal\'s cookie is no console session',
            asConsole ? asConsole.id : '');

    // A policy refusal is honoured for an adopted session as for any.
    t.log.info('=== the policy can refuse an adopted session ===');
    const refusedRes = fakeRes();
    refuse = true;
    const refused = realms.run(realms.DEFAULT_REALM, function () {
      return portal.requireSignIn(reqFor('/portal',
                                         { sts_admin: held.cookie }),
                                  refusedRes, '/portal', 'read');
    });
    refuse = false;
    t.check(!refused && refusedRes.statusCode === 403,
            'a refusal of the adopted session is a 403, not a way round it',
            'status=' + refusedRes.statusCode);

    // 2. IT ENDS WITH THE CONSOLE SESSION — by the cascade.
    t.log.info('=== the console session ends, and the portal\'s with it ===');
    realms.run(realms.DEFAULT_REALM, function () {
      authn.endSessionById(held.session.id, 'this test');
    });
    t.check(!portalRow(realms.DEFAULT_REALM, got.id),
            'THE CONSOLE SIGN-OUT ITSELF TOOK THE ADOPTED SESSION (the ' +
            'store, not the reader)');
    const afterEnd = realms.run(realms.DEFAULT_REALM, function () {
      return oidcRp.sessionFor(reqFor('/portal',
                                      { sts_portal: portalCookie }),
                               'portal');
    });
    t.check(!afterEnd, 'and the portal cookie admits nobody');

    // …and by the reader, when the console row goes without a cascade.
    const second = consoleWithoutSignOn(realms.DEFAULT_REALM, 'adopt-bob');
    const res2 = fakeRes();
    const got2 = realms.run(realms.DEFAULT_REALM, function () {
      return portal.requireSignIn(reqFor('/portal',
                                         { sts_admin: second.cookie }),
                                  res2, '/portal', 'read');
    });
    t.check(!!got2, 'a second adoption');
    realms.run(realms.DEFAULT_REALM, function () {
      authn.sessions.delete(second.session.id);
    });
    const orphan = realms.run(realms.DEFAULT_REALM, function () {
      return oidcRp.sessionFor(reqFor('/portal',
                                      { sts_portal: cookieFrom(res2,
                                                               'sts_portal') }),
                               'portal');
    });
    t.check(!orphan && !(got2 && portalRow(realms.DEFAULT_REALM, got2.id)),
            'a console session gone by any road ends the adopted session on ' +
            'the next read — it holds no tokens, so it cannot outlive it');

    // 3. NO CONSOLE SESSION: the old path, unchanged.
    t.log.info('=== no console session: the chooser, as before ===');
    const res3 = fakeRes();
    const none = realms.run(realms.DEFAULT_REALM, function () {
      return portal.requireSignIn(reqFor('/portal', {}), res3, '/portal',
                                  'read');
    });
    t.check(!none && /Choose your realm/.test(String(res3.body || '')),
            'the bare /portal with no console session still asks which realm',
            'status=' + res3.statusCode);
    t.check(!cookieFrom(res3, 'sts_portal'), 'and made no portal session');
  });

  // -------------------------------------------------------------------------
  // 4. A REALM ADMINISTRATOR: redirected to their realm's portal, adopted
  //    there, and ended there by the console's cascade.
  // -------------------------------------------------------------------------
  t.log.info('=== a realm administrator at the bare /portal ===');
  withRealm('adopt-acme', function (realm) {
    const held = consoleWithoutSignOn(realm, 'adopt-carol');
    const res = fakeRes();
    const got = realms.run(realms.DEFAULT_REALM, function () {
      return portal.requireSignIn(reqFor('/portal/mfa',
                                         { sts_admin: held.cookie }),
                                  res, '/portal/mfa', 'read');
    });
    // The service's own base, as the portal reads it for this request, with
    // the realm's prefix from the registry.
    const base = realms.run(realms.DEFAULT_REALM, function () {
      return require('../common/helpers').baseUrlOf(reqFor('/portal', {}));
    });
    const expected = base + realms.prefixOf(realm) + '/portal/mfa';
    t.check(!got && res.statusCode === 303 && res.location === expected,
            'IT IS SENT TO ITS OWN REALM\'S PORTAL, built from the registry',
            'status=' + res.statusCode + ' location=' + res.location);
    t.check(!cookieFrom(res, 'sts_portal'),
            'and nothing was adopted in the default realm');

    const hostile = fakeRes();
    realms.run(realms.DEFAULT_REALM, function () {
      portal.requireSignIn(reqFor('/portal', { sts_admin: held.cookie }),
                           hostile, '//evil.test/portal', 'read');
    });
    t.equal(hostile.location, base + realms.prefixOf(realm) + '/portal',
            'a return address that is not a portal path is the root, never ' +
            'an echo');

    const there = fakeRes();
    const adopted = realms.run(realm, function () {
      return portal.requireSignIn(reqFor(realms.prefixOf(realm) + '/portal',
                                         { sts_admin: held.cookie }),
                                  there, '/portal', 'read');
    });
    t.equal(adopted && adopted.user && adopted.user.username, 'adopt-carol',
            'and adopted THERE');
    t.check(!!(adopted && portalRow(realm, adopted.id)),
            'in the realm\'s own partition');

    const elsewhere = withRealm('adopt-elsewhere', function (other) {
      return realms.run(other, function () {
        return portal.adoptConsoleSession(
          reqFor(realms.prefixOf(other) + '/portal',
                 { sts_admin: held.cookie }), fakeRes(), '/portal');
      });
    });
    t.check(!elsewhere,
            'a realm the console session is not from adopts nothing: that ' +
            'is a person asking to sign in there');

    realms.run(realms.DEFAULT_REALM, function () {
      authn.endSessionById(held.session.id, 'this test');
    });
    t.check(!(adopted && portalRow(realm, adopted.id)),
            'THE CASCADE REACHES THE REALM\'S PARTITION: ending the console ' +
            'session took the adopted session with it');
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal_adopts_console',
  describe: 'the user portal adopts a live admin console session',
  run: run
};
