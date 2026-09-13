'use strict';
//
// File: oidc_rp_addresses.js
//
// ===========================================================================
// WHERE THE ADMIN CONSOLE AND THE USER PORTAL SEND A BROWSER, WHAT THEY WRITE
// ONTO THEIR OWN CLIENT ENTRIES, AND WHERE THEY DIAL THEMSELVES (2026-09-12).
//
// `common/oidc_rp.js` built the console's and the portal's redirect URI from
// `baseUrlOf(req)` and ADDED it to the seeded client entry the first time a
// flow went through a base it had not seen. Its comment said an invented Host
// reached `baseUrlOf()` only with `global.trustProxy` on. That was false —
// `forwardedFrom()` reads the request's own Host header always — so an
// anonymous `GET /admin` carrying `Host: evil.example` planted
// `https://evil.example/admin/callback` on `sts-admin-console` for good.
//
// Four claims, and the first is the one the file is for:
//
//   A. in PRODUCT mode an address the entry does not carry is REFUSED before a
//      browser is sent anywhere, and nothing is written — whatever Host the
//      request carried;
//   B. `global.publicBaseUrl` pins the address and NOTHING IS LEARNT, in either
//      mode — the redirect goes to the pinned base whatever Host arrived;
//   C. in DEVELOPMENT, with nothing pinned, the entry still learns (that is the
//      container and proxy convenience this was for) and stops at
//      `oidcRp.maxRedirectUris`;
//   D. the back channel dials the interface this service LISTENS on, and the
//      flow's lifetime is the sign-in screen's own setting.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS.
//
// Over HTTP the only evidence for A and B is the absence of a value on a
// client entry after a request — which a job can read, and which the parent
// suite cannot arrange, because every stack there runs in development mode
// with nothing pinned. More to the point, the question is WHAT WAS WRITTEN,
// and every assertion below reads the registry after the call rather than
// reading the redirect: a refusal that still wrote the address, or a pinned
// redirect that still learnt the Host, both produce the right response.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const applications = require('../common/applications');
// The registry's store is the directory, and requiring this is what fills the
// slot and seeds `sts-admin-console`. It binds no port (the root CLAUDE.md's
// four-modules rule).
require('../ldap/ldap_server');
const oidcRp = require('../common/oidc_rp');
const helpers = require('../common/helpers');

const CLIENT = 'sts-admin-console';

// The two things `beginSignIn()` reads off express's request, and the three
// it calls on the response.
function fakeReq(host) {
  return {
    protocol: 'https',
    headers: { host: host },
    originalUrl: '/admin',
    get: function (name) {
      return String(name).toLowerCase() === 'host' ? host : undefined;
    }
  };
}

function fakeRes() {
  const res = { statusCode: 0, location: '', ended: false };
  res.status = function (code) { res.statusCode = code; return res; };
  res.set = function (name, value) {
    if (String(name).toLowerCase() === 'location') {
      res.location = value;
    }
    return res;
  };
  res.end = function () { res.ended = true; return res; };
  return res;
}

function redirectUris() {
  return [].concat(applications.clientConfigOf(CLIENT).redirect_uris || []);
}

function withSettings(pairs, fn) {
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

// Take back every value this file taught the entry, whatever happened, so the
// entry is what `seedInternal` wrote when the next file reads it.
function forget(values) {
  values.forEach(function (value) {
    if (redirectUris().indexOf(value) >= 0) {
      applications.updateApplication(CLIENT, {
        attribute: 'oauthRedirectUri', mode: 'remove', value: value,
        actor: 'tests/oidc_rp_addresses.js'
      });
    }
  });
}

function run(t) {
  const before = redirectUris();
  t.check(applications.clientConfigOf(CLIENT).registered,
          'the console\'s client is seeded, which everything below reads',
          JSON.stringify(before));
  const planted = [];
  try {
    // -----------------------------------------------------------------------
    t.log.info('=== A. product mode: an invented Host plants nothing ===');
    withSettings({ 'global.mode': 'product' }, function () {
      const res = fakeRes();
      const started = oidcRp.beginSignIn(fakeReq('evil.example'), res, 'admin',
                                         { returnTo: '/admin' });
      t.check(!started.ok, 'a sign-in at an address the entry does not carry ' +
              'is REFUSED in product mode', JSON.stringify(started).slice(0, 200));
      t.equal(started.reason, 'unregistered-address',
              'and the refusal says which kind it is, so a page can say which ' +
              'kind of fix it needs');
      t.check(/global\.publicBaseUrl/.test(started.why || ''),
              'naming global.publicBaseUrl, which is the fix', started.why);
      t.check(!res.ended && !res.location,
              'and NO browser was sent anywhere — the refusal comes before the ' +
              'redirect, not after it');
      t.check(redirectUris().indexOf('https://evil.example/admin/callback') < 0,
              'and — the assertion the file is for — nothing was written onto ' +
              'the console\'s client entry', JSON.stringify(redirectUris()));
      const held = before[0];
      if (held) {
        const ok = oidcRp.ensureRedirectUri(oidcRp.surfaceOf('admin'),
                                            applications.clientConfigOf(CLIENT),
                                            held);
        t.check(ok.ok && !ok.learnt,
                'while an address the entry ALREADY carries is used in product ' +
                'mode exactly as before', JSON.stringify(ok));
      }
    });

    // -----------------------------------------------------------------------
    t.log.info('=== B. a pinned base is used and never learnt ===');
    withSettings({ 'global.publicBaseUrl': 'https://idp.example.test' }, function () {
      const res = fakeRes();
      const started = oidcRp.beginSignIn(fakeReq('evil.example'), res, 'admin',
                                         { returnTo: '/admin' });
      t.check(started.ok, 'development mode with a pinned base starts the flow',
              started.why);
      t.check(res.location.indexOf('https://idp.example.test/oauth2/authorize?') === 0,
              'the browser is sent to the PINNED base whatever Host arrived',
              res.location.slice(0, 80));
      t.check(res.location.indexOf(encodeURIComponent(
                'https://idp.example.test/admin/callback')) > 0 &&
              res.location.indexOf('evil.example') < 0,
              'with the pinned callback as redirect_uri and no trace of the ' +
              'invented Host');
      t.check(redirectUris().indexOf('https://idp.example.test/admin/callback') < 0,
              'and the pinned callback was NOT written onto the entry — a ' +
              'pinned address is configuration, and learning is for an ' +
              'address nobody configured', JSON.stringify(redirectUris()));
    });
    withSettings({ 'global.publicBaseUrl': 'https://idp.example.test',
                   'global.mode': 'product' }, function () {
      const started = oidcRp.beginSignIn(fakeReq('evil.example'), fakeRes(),
                                         'admin', { returnTo: '/admin' });
      t.check(!started.ok && /POST \/admin-api\/applications\/add/.test(started.why),
              'in product mode a pinned callback the entry does not carry is ' +
              'refused too, naming how to register it', started.why);
    });

    // -----------------------------------------------------------------------
    t.log.info('=== C. development, nothing pinned: learnt, and capped ===');
    const learnHost = 'container-name.example:8443';
    const learnt = 'https://' + learnHost + '/admin/callback';
    planted.push(learnt);
    const res = fakeRes();
    const started = oidcRp.beginSignIn(fakeReq(learnHost), res, 'admin',
                                       { returnTo: '/admin' });
    t.check(started.ok && res.statusCode === 303,
            'development mode with nothing pinned starts the flow as it always ' +
            'did', started.why);
    t.check(redirectUris().indexOf(learnt) >= 0,
            'and the entry LEARNT the address — the container and proxy ' +
            'convenience this behaviour exists for is unchanged in development',
            JSON.stringify(redirectUris()));
    const capped = 'https://over-the-cap.example/admin/callback';
    planted.push(capped);
    withSettings({ 'oidcRp.maxRedirectUris': redirectUris().length }, function () {
      const again = oidcRp.beginSignIn(fakeReq('over-the-cap.example'), fakeRes(),
                                       'admin', { returnTo: '/admin' });
      t.check(again.ok, 'at the cap the flow still starts');
      t.check(redirectUris().indexOf(capped) < 0,
              'but nothing more is written — an entry reached under many names, ' +
              'or asked with many invented Hosts, cannot grow without bound ' +
              'even in development', JSON.stringify(redirectUris()));
    });

    // -----------------------------------------------------------------------
    t.log.info('=== D. the loopback address and the flow clock ===');
    const saved = process.env.STS_HOST;
    try {
      process.env.STS_HOST = '::';
      t.check(/^https?:\/\/\[::1\]:\d+$/.test(oidcRp.loopbackOrigin()),
              'a wildcard IPv6 bind is dialled on [::1], bracketed in the URL — ' +
              'it was 127.0.0.1 whatever the bind', oidcRp.loopbackOrigin());
      process.env.STS_HOST = '10.20.30.40';
      t.check(oidcRp.loopbackOrigin().indexOf('://10.20.30.40:') > 0,
              'an interface address is dialled as itself, since nothing ' +
              'answers on 127.0.0.1 for a listener bound only there',
              oidcRp.loopbackOrigin());
      t.equal(helpers.loopbackHost(), '10.20.30.40',
              'and it is helpers.loopbackHost()\'s answer, not a second opinion');
      // THE SOCKET ITSELF IS OPENED IN `backChannel()`, whose request options
      // name the host separately from `loopbackOrigin()` — node wants an IPv6
      // literal there WITHOUT brackets. Dialling it for real would mean binding
      // this service's own port on another interface in a shared test process,
      // so the options are read as SOURCE, `version.js`'s shape: a mutant
      // putting the literal back survived every behavioural check above.
      const source = require('fs').readFileSync(
        require('path').join(__dirname, '..', 'common', 'oidc_rp.js'), 'utf8');
      const requestBlock = source.slice(source.indexOf('.request({'),
                                        source.indexOf('.request({') + 400);
      t.check(/host:\s*helpers\.loopbackHost\(\)/.test(requestBlock) &&
              !/host:\s*'127\.0\.0\.1'/.test(requestBlock),
              'and backChannel() opens its socket on helpers.loopbackHost(), not ' +
              'on the literal 127.0.0.1', requestBlock.slice(0, 120));
    } finally {
      if (saved === undefined) {
        delete process.env.STS_HOST;
      } else {
        process.env.STS_HOST = saved;
      }
    }
    t.equal(oidcRp.flowTtlMs(), 600000,
            'a flow waits the sign-in screen\'s own ten minutes by default');
    withSettings({ 'authn.pendingTtlS': 90 }, function () {
      t.equal(oidcRp.flowTtlMs(), 90000,
              'and follows authn.pendingTtlS — the two were "deliberately the ' +
              'same" as two literals, which is how they come apart');
    });
  } finally {
    forget(planted);
  }
  t.equal(JSON.stringify(redirectUris()), JSON.stringify(before),
          'and the entry is back to what the seed wrote');
}

module.exports = {
  name: 'oidc_rp_addresses',
  describe: 'the console\'s and the portal\'s redirect URI: refused rather than ' +
            'learnt in product mode, never learnt when pinned, capped in ' +
            'development, and the back channel dialling the bound interface',
  run: run
};
