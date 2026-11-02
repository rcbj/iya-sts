// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wsfed_saml2_token.js
//
// ===========================================================================
// THE WS-FEDERATION SAML 2.0 TOKEN NAMES ITS SESSION (2026-10-30, #1243).
//
// `ws-federation/wsfed.ts` built the SAML 2.0 token with none of the three
// things `saml/saml2_sso.ts` passes the shared builder, so the builder's
// defaults went out: a SessionIndex that was the assertion's own ID, an
// AuthnInstant that was the moment of issue, and a bare bearer
// SubjectConfirmation. The first meant a CAEP session-revoked (which names
// the SESSION) could never be matched by a WS-Federation relying party to
// the sign-in it started; the second made every token look freshly
// authenticated; the third is refused by relying-party libraries written
// for SAML 2.0. Held here, in a child process on an ephemeral loopback port,
// with the token asked for the standard way, by a wreq RST:
//
//   a. SessionIndex is the session's id, the one authn holds, and not the
//      assertion's ID;
//   b. a second sign-in by single sign-on in the same session carries the
//      SAME SessionIndex and the SAME AuthnInstant — the session's
//      authentication time, not the token's IssueInstant;
//   c. a bearer SubjectConfirmationData: Recipient the wreply, NotOnOrAfter
//      the Conditions' to the second, and no InResponseTo (there is no
//      request to answer);
//   d. with saml.clockSkewS set, the two expiries still agree;
//   e. another browser's sign-in carries another SessionIndex;
//   f. the default SAML 1.1 token's AuthenticationInstant is the session's
//      authentication time too (it already was; held so it stays so).
//
// The usernames are invented here and named for this file; development mode
// accepts any password.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'wsfed_saml2_token',
                                             level: process.env.LOG_LEVEL ||
                                                    'info' });
const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.WT_ROOT;
  const OUT = process.env.WT_OUT;
  const findings = [];
  const http = require('http');

  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath) {
      return new Promise(function (resolve) {
        const headers = {};
        if (Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
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
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.end();
      });
    };
    return { go: go, jar: jar };
  }

  // The wresult off the sign-in response page, its entities undone.
  const wresultOf = function (r) {
    const m = /name="wresult" value="([^"]*)"/.exec(r.text || '');
    if (!m) return '';
    return m[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
      .replace(/&#39;/g, "'").replace(/&amp;/g, '&');
  };
  const attrOf = function (xml, element, name) {
    const el = new RegExp('<(?:\\w+:)?' + element + '\\b[^>]*>').exec(xml);
    if (!el) return undefined;
    const a = new RegExp('\\s' + name + '="([^"]*)"').exec(el[0]);
    return a ? a[1] : undefined;
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');
    const app = require(ROOT + '/common/app');
    const authn = require(ROOT + '/authn/authn');
    const config = require(ROOT + '/common/config');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    const REALM = 'urn:wsfed-saml2-token:rp';
    const WREPLY = 'https://rp.wsfed-saml2-token.example/wsfed';
    const SAML2 = 'urn:oasis:names:tc:SAML:2.0:assertion';
    // The standard request for a SAML 2.0 token: an RST by value, naming the
    // type, as a relying party sends it.
    const WREQ = '<wst:RequestSecurityToken ' +
      'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
      '<wst:TokenType>' + SAML2 + '</wst:TokenType>' +
      '</wst:RequestSecurityToken>';
    const signInUrl = function (saml2) {
      // A stand-in reply address nothing answers at: the response is read
      // off the page, as wsfed_wauth_step_up.js reads it.
      return '/wsfed?' + new URLSearchParams(Object.assign({
        wa: 'wsignin1.0', wtrealm: REALM, wctx: 'ctx-1', wreply: WREPLY },
        saml2 ? { wreq: WREQ } : {})).toString();
    };
    // A sign-in through the screen, or straight through by single sign-on
    // when the browser already holds a session.
    const tokenFor = async function (b, username, saml2) {
      const first = await b.go('GET', signInUrl(saml2));
      if (first.status === 200) return wresultOf(first);
      const page = await authnScreen.open({ port: port, jar: b.jar,
        at: String(first.headers.location) });
      const posted = await authnScreen.follow({ port: port, jar: b.jar,
        opened: page, fields: { action: 'login', username: username,
                                password: 'anything' } });
      const back = String((posted.headers || {}).location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      return wresultOf(back ? await b.go('GET', back) : posted);
    };
    const sessionOf = function (username) {
      const held = authn.sessionsOf(username) || [];
      return held[0];
    };
    const authTimeOf = function (session) {
      return new Date((session.authTime || 0) * 1000).toISOString();
    };

    try {
      // a. SessionIndex is the session's id.
      const alice = browser(port);
      const ALICE = 'wsfed-saml2-token-alice';
      const one = await tokenFor(alice, ALICE, true);
      const session = sessionOf(ALICE);
      note(/<(\w+:)?Assertion\b[^>]*urn:oasis:names:tc:SAML:2\.0:assertion/
             .test(one) && !!session,
           'a. a wreq naming SAML 2.0 yields a SAML 2.0 assertion, and ' +
           'authn holds the session', one.slice(0, 300));
      const index1 = attrOf(one, 'AuthnStatement', 'SessionIndex');
      const id1 = attrOf(one, 'Assertion', 'ID');
      note(session && index1 === session.id,
           'a. SessionIndex is the session\'s id',
           index1 + ' vs ' + (session && session.id));
      note(index1 !== id1, 'a. SessionIndex is not the assertion\'s ID',
           index1 + ' / ' + id1);

      // b. Single sign-on: the same session, the same authentication.
      await new Promise(function (r) { setTimeout(r, 1100); });
      const two = await tokenFor(alice, ALICE, true);
      const index2 = attrOf(two, 'AuthnStatement', 'SessionIndex');
      note(two && index2 === index1 &&
             attrOf(two, 'Assertion', 'ID') !== id1,
           'b. a second token in the same session names the same session',
           index2 + ' / ' + index1);
      const authnInstant2 = attrOf(two, 'AuthnStatement', 'AuthnInstant');
      const issued2 = attrOf(two, 'Assertion', 'IssueInstant');
      note(session && authnInstant2 === authTimeOf(session) &&
             authnInstant2 === attrOf(one, 'AuthnStatement', 'AuthnInstant'),
           'b. AuthnInstant is the session\'s authentication time, on both',
           authnInstant2 + ' vs ' + (session && authTimeOf(session)));
      note(Date.parse(authnInstant2) < Date.parse(issued2),
           'b. ... and earlier than the second token\'s IssueInstant',
           authnInstant2 + ' < ' + issued2);

      // c. The bearer confirmation's data.
      const scd = /<(\w+:)?SubjectConfirmationData\b[^>]*\/?>/.exec(one);
      note(!!scd, 'c. the bearer SubjectConfirmation carries ' +
                  'SubjectConfirmationData', one.slice(0, 200));
      note(attrOf(one, 'SubjectConfirmationData', 'Recipient') === WREPLY,
           'c. its Recipient is the wreply',
           attrOf(one, 'SubjectConfirmationData', 'Recipient'));
      note(attrOf(one, 'SubjectConfirmationData', 'NotOnOrAfter') ===
             attrOf(one, 'Conditions', 'NotOnOrAfter'),
           'c. its NotOnOrAfter is the Conditions\'',
           attrOf(one, 'SubjectConfirmationData', 'NotOnOrAfter') + ' vs ' +
             attrOf(one, 'Conditions', 'NotOnOrAfter'));
      note(attrOf(one, 'SubjectConfirmationData', 'InResponseTo') ===
             undefined, 'c. it carries no InResponseTo',
           attrOf(one, 'SubjectConfirmationData', 'InResponseTo'));

      // d. The skew widens both expiries alike.
      config.setOverride('saml.clockSkewS', 120);
      const skewed = await tokenFor(alice, ALICE, true);
      config.setOverride('saml.clockSkewS', 0);
      const scdExp = attrOf(skewed, 'SubjectConfirmationData', 'NotOnOrAfter');
      note(scdExp && scdExp === attrOf(skewed, 'Conditions', 'NotOnOrAfter') &&
             Date.parse(scdExp) - Date.parse(
               attrOf(skewed, 'Assertion', 'IssueInstant')) > 60 * 60000,
           'd. with saml.clockSkewS 120 the two expiries still agree, ' +
           'widened past the lifetime', scdExp);

      // e. Another browser, another session.
      const bob = browser(port);
      const BOB = 'wsfed-saml2-token-bob';
      const other = await tokenFor(bob, BOB, true);
      const bobSession = sessionOf(BOB);
      note(bobSession && attrOf(other, 'AuthnStatement', 'SessionIndex') ===
             bobSession.id && bobSession.id !== index1,
           'e. another browser\'s token names its own session',
           attrOf(other, 'AuthnStatement', 'SessionIndex'));

      // f. The SAML 1.1 default token's AuthenticationInstant.
      const eleven = await tokenFor(alice, ALICE, false);
      note(/urn:oasis:names:tc:SAML:1\.0:assertion/.test(eleven) &&
             attrOf(eleven, 'AuthenticationStatement',
                    'AuthenticationInstant') === authTimeOf(session),
           'f. the SAML 1.1 token\'s AuthenticationInstant is the ' +
           'session\'s authentication time',
           attrOf(eleven, 'AuthenticationStatement', 'AuthenticationInstant'));
    } catch (e) {
      note(false, 'the run finished', (e && e.stack) || e);
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    server.close();
    process.exit(0);
  })();
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'wsfed-saml2-token-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', WT_ROOT: ROOT, WT_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
  name: 'wsfed_saml2_token',
  describe: 'WS-Federation SAML 2.0 token: SessionIndex is the session id, ' +
            'AuthnInstant the session\'s authentication time, and the bearer ' +
            'confirmation carries a Recipient and the Conditions\' expiry ' +
            '(#1243)',
  run: run
};
