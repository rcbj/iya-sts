// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/authorization_code_once.js
// ===========================================================================
// AN AUTHORIZATION CODE IS PRESENTED ONCE, WHATEVER THE OUTCOME, AND LIVES AT
// MOST FIVE MINUTES (#424, 2026-10-02).
//
// rcbj: "I want an OAuth2 / OIDC authorization code to only be valid for five
// minutes and to only be allowed to be presented once. It doesn't matter why
// the request to the Token Endpoint failed. The caller can only submit a
// request with that authorization code once. Then, they have to start the
// flow / grant over again." Until then a refused Token Request left its code
// redeemable, on purpose, so a client could fix what the refusal named and
// try again; that is `oauth2.codeReplayIdempotent`'s now, off by default.
//
// In a CHILD PROCESS with the whole stack on a loopback port, codes from real
// authorization requests by a confidential client. For each kind of failed
// first presentation the second presentation — this time a correct one — is
// refused `invalid_grant` under STS-OAUTH-0789:
//
//   1. a failed client authentication (rcbj: it burns the code too) — in
//      RFC 9700 mode, which verifies a confidential client's secret;
//   2. a redirect_uri that does not match;
//   3. a wrong PKCE code_verifier;
//   4. a body that fails validation (a code_verifier too short);
//   5. a code past its lifetime (the clock moved), refused as expired and
//      then as presented;
//   6. a SUCCESSFUL redemption, whose repeat is refused (STS-OAUTH-0143) and
//      whose access token is revoked (RFC 6749 section 10.5);
//   7. two presentations at the same moment: exactly one is answered 200;
//   8. the lifetime: 300 seconds by default, 300 accepted, 301 refused;
//   9. `oauth2.codeReplayIdempotent` on: the old leniency — a refused
//      request leaves the code redeemable, and an identical repeat gets the
//      same tokens — the control that tells the rule from a broken endpoint.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'authorization_code_once',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AC_ROOT;
  const OUT = process.env.AC_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  const jar = {};
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    const body = o.form ? new URLSearchParams(o.form).toString() : '';
    return new Promise(function (resolve) {
      const headers = Object.assign({}, o.headers || {});
      const live = Object.keys(jar).filter(function (k) { return jar[k]; });
      if (live.length && o.cookies !== false) {
        headers.cookie = live.map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        (res.headers['set-cookie'] || []).forEach(function (line) {
          const pair = line.split(';')[0];
          const eq = pair.indexOf('=');
          jar[pair.slice(0, eq)] = /Max-Age=0/.test(line) ? ''
            : pair.slice(eq + 1);
        });
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(method === 'GET' ? undefined : body);
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const applications = require(ROOT_DIR + '/common/applications');
    const config = require(ROOT_DIR + '/common/config');
    const audit = require(ROOT_DIR + '/common/audit');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    config.setOverride('oauth2.consentRequired', false);

    const REDIRECT = 'https://rp.aco.example/cb';
    const SECRET = 'aco-secret-0123456789abcdef0123456789';
    const ID = 'aco-rp';
    applications.createApplication({ identifier: ID, protocols: ['oauth2'],
      fields: { oauthClientId: ID, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'client_secret_basic',
                oauthGlobalConsent: ['openid'] } });
    const basic = function (secret) {
      return 'Basic ' + Buffer.from(ID + ':' + (secret || SECRET))
        .toString('base64');
    };
    const b64u = function (buf) { return buf.toString('base64url'); };

    // A fresh code, from a real authorization request; the first one signs
    // in through the sign-in screen and the rest ride its session.
    const newCode = async function (pkceVerifier) {
      const params = { client_id: ID, response_type: 'code',
                       redirect_uri: REDIRECT, scope: 'openid', state: 'st',
                       nonce: 'n-' + crypto.randomBytes(4).toString('hex') };
      if (pkceVerifier) {
        params.code_challenge = b64u(crypto.createHash('sha256')
          .update(pkceVerifier).digest());
        params.code_challenge_method = 'S256';
      }
      let r = await request(port, 'GET', '/oauth2/authorize?' +
                            new URLSearchParams(params).toString());
      const to = String(r.headers.location || '');
      if (/\/authn\/login/.test(to)) {
        const page = await request(port, 'GET',
                                   to.replace(/^https?:\/\/[^/]+/, ''));
        const form = {};
        (page.text.match(/<input type="hidden"[^>]*>/g) || []).forEach(
          function (tag) {
            const name = /name="([^"]+)"/.exec(tag);
            const value = /value="([^"]*)"/.exec(tag);
            if (name) {
              form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
            }
          });
        form.username = 'aco-alice';
        form.password = 'anything';
        form.action = 'login';
        const posted = await request(port, 'POST', '/authn/login',
                                     { form: form });
        r = await request(port, 'GET', String(posted.headers.location || '')
          .replace(/^https?:\/\/[^/]+/, ''));
      }
      const loc = String(r.headers.location || '');
      const at = loc.indexOf('?');
      return loc.indexOf(REDIRECT) === 0 && at > 0
        ? new URLSearchParams(loc.slice(at + 1)).get('code') || '' : '';
    };
    const redeem = function (code, opts) {
      const o = opts || {};
      const form = Object.assign({ grant_type: 'authorization_code',
                                   code: code, redirect_uri: REDIRECT },
                                 o.form || {});
      return request(port, 'POST', '/oauth2/token', { cookies: false,
        headers: { authorization: basic(o.secret) }, form: form });
    };
    const tail = function (r) {
      return r.status + ' ' + String(r.text).slice(0, 220);
    };
    const coded = function (code) {
      return audit.list().filter(function (event) {
        return event.errorCode === code;
      }).length;
    };
    const settle = function () {
      return new Promise(function (r) { setTimeout(r, 30); });
    };
    // The second presentation, correct this time, after a failed first.
    const refusedAfter = async function (label, code, first, extra) {
      note(first.status >= 400, label + ': the first presentation is refused',
           tail(first));
      const before = coded('STS-OAUTH-0789');
      const second = await redeem(code, extra);
      await settle();
      note(second.status === 400 && second.json &&
           second.json.error === 'invalid_grant' &&
           /already presented/.test(String(second.json.error_description)) &&
           coded('STS-OAUTH-0789') === before + 1,
           label + ': a correct second presentation is refused invalid_grant ' +
           '(STS-OAUTH-0789) — the flow must start over', tail(second));
    };

    const code0 = await newCode();
    note(!!code0, 'precondition: an authorization request yields a code',
         code0);

    // --- 1. a failed client authentication --------------------------------
    // In RFC 9700 mode, where a confidential client's secret is VERIFIED:
    // development mode outside it takes any secret, so a wrong one is no
    // failure there. The mode wants PKCE, so the code carries a challenge.
    process.env.STS_OAUTH2_RFC9700 = 'true';
    const pkce1 = b64u(crypto.randomBytes(32));
    let code = await newCode(pkce1);
    try {
      await refusedAfter('1. failed client authentication', code,
        await redeem(code, { secret: 'wrong-secret',
                             form: { code_verifier: pkce1 } }),
        { form: { code_verifier: pkce1 } });
    } finally {
      delete process.env.STS_OAUTH2_RFC9700;
    }

    // --- 2. a redirect_uri that does not match ----------------------------
    code = await newCode();
    await refusedAfter('2. redirect_uri mismatch', code,
      await redeem(code,
                   { form: { redirect_uri: 'https://rp.aco.example/x' } }));

    // --- 3. a wrong PKCE code_verifier ------------------------------------
    const verifier = b64u(crypto.randomBytes(32));
    code = await newCode(verifier);
    await refusedAfter('3. wrong code_verifier', code,
      await redeem(code,
                   { form: { code_verifier: b64u(crypto.randomBytes(32)) } }),
      { form: { code_verifier: verifier } });

    // --- 4. a body that fails validation -----------------------------------
    code = await newCode(verifier);
    await refusedAfter('4. malformed body', code,
      await redeem(code, { form: { code_verifier: 'short' } }),
      { form: { code_verifier: verifier } });

    // --- 5. past its lifetime ---------------------------------------------
    code = await newCode();
    const realNow = Date.now;
    Date.now = function () { return realNow() + 301 * 1000; };
    let r;
    try {
      r = await redeem(code);
    } finally {
      Date.now = realNow;
    }
    note(r.status === 400 && /expired/.test(String(r.text)),
         '5a. a code presented after five minutes is refused as expired',
         tail(r));
    await refusedAfter('5b. after the expired presentation', code, r);

    // --- 6. a successful redemption, then a repeat --------------------------
    code = await newCode();
    const ok = await redeem(code);
    note(ok.status === 200 && ok.json && ok.json.access_token,
         '6a. a correct first presentation is redeemed', tail(ok));
    const replay = await redeem(code);
    note(replay.status === 400 && replay.json &&
         replay.json.error === 'invalid_grant' &&
         /single use/.test(String(replay.json.error_description)),
         '6b. its repeat — identical — is refused (single use)', tail(replay));
    const intro = await request(port, 'POST', '/oauth2/introspect', {
      cookies: false, headers: { authorization: basic() },
      form: { token: (ok.json && ok.json.access_token) || '' } });
    note(intro.json && intro.json.active === false,
         '6c. and the access token the first bought is revoked (RFC 6749 ' +
         'section 10.5)', tail(intro));

    // A repeat that DIFFERS from the redemption is refused the same way and
    // revokes too: the relaxed redemption's "differs" sentence, which revokes
    // nothing, is not the default's answer.
    code = await newCode();
    const ok2 = await redeem(code);
    const differing = await redeem(code,
      { form: { redirect_uri: 'https://rp.aco.example/x' } });
    const intro2 = await request(port, 'POST', '/oauth2/introspect', {
      cookies: false, headers: { authorization: basic() },
      form: { token: (ok2.json && ok2.json.access_token) || '' } });
    note(ok2.status === 200 && differing.status === 400 &&
         /single use/.test(String(differing.text)) && intro2.json &&
         intro2.json.active === false,
         '6d. a repeat that differs from the redemption is refused as single ' +
         'use and revokes what the first bought',
         tail(differing) + ' | ' + tail(intro2));

    // --- 7. two presentations at once ------------------------------------
    code = await newCode();
    const both = await Promise.all([redeem(code), redeem(code)]);
    const wins = both.filter(function (one) { return one.status === 200; });
    note(wins.length === 1 && both.filter(function (one) {
      return one.status === 400;
    }).length === 1, '7. two presentations at the same moment: exactly one ' +
         'is redeemed', both.map(tail).join(' | '));

    // --- 8. the lifetime --------------------------------------------------
    note(Number(config.value('oauth2.authorizationCodeTtlS')) === 300,
         '8a. the default lifetime is 300 seconds',
         config.value('oauth2.authorizationCodeTtlS'));
    note(config.checkOverride('oauth2.authorizationCodeTtlS', '300') === null,
         '8b. 300 may be set');
    note(config.checkOverride('oauth2.authorizationCodeTtlS', '301') !== null,
         '8c. 301 is refused: at most five minutes',
         config.checkOverride('oauth2.authorizationCodeTtlS', '301'));

    // --- 9. the relaxed redemption: the control ----------------------------
    const w = config.setOverride('oauth2.codeReplayIdempotent', true);
    code = await newCode();
    const firstBad = await redeem(code,
      { form: { redirect_uri: 'https://rp.aco.example/x' } });
    const then = await redeem(code);
    note(w.ok && firstBad.status === 400 && then.status === 200,
         '9a. oauth2.codeReplayIdempotent on: a refused presentation leaves ' +
         'the code redeemable', tail(firstBad) + ' | ' + tail(then));
    const again = await redeem(code);
    note(again.status === 200 && again.json && then.json &&
         again.json.access_token === then.json.access_token,
         '9b. and an identical repeat gets the same tokens', tail(again));
    config.clearOverride('oauth2.codeReplayIdempotent');

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ac-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  AC_ROOT: ROOT, AC_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
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
  name: 'authorization_code_once',
  describe: 'an authorization code is presented once whatever the outcome, ' +
            'and lives at most five minutes (#424)',
  run: run
};
