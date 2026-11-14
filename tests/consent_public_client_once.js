// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/consent_public_client_once.js
// ===========================================================================
// A PUBLIC CLIENT IS ASKED FOR CONSENT EVERY TIME, AND THE ANSWER TO THIS
// REQUEST COUNTS FOR THIS REQUEST ONCE (ASVS 5.0.0 10.7.1).
//
// `oauth2.consentAlwaysForPublicClients` (on by default in product) makes
// `common/consent.ts`'s `alwaysAsks()` treat every requested scope of a
// public client as outstanding. Nothing recorded that the person had just
// answered for THIS authorization request, so the authorization endpoint's
// second pass, arriving from the consent screen, asked again, and the
// browser went round /oauth2/consent for ever (the service log alternating
// "agreed that" and "is being asked whether"). The answer is now recorded by
// the consent screen under the scopes' digest in RFC 9396's one-time store
// and spent by the pass that follows, as an Allow on authorization details
// always was.
//
// The whole stack in a child process, over HTTP on 127.0.0.1, with the
// setting on (it is the setting `alwaysAsks()` reads; product mode only
// changes its default, which `asvs_protocol_rules.js` holds):
//
//   1. A public client: the sign-in, the consent screen, Allow, and the
//      pass that follows issues a code with no second ask.
//   2. A NEW authorization request by the same public client, with the
//      person's consent on file, is asked again — the earlier answer does
//      not speak for it — and its own Allow issues a code.
//   3. The answer is single use: nothing is left to spend after the pass.
//   4. A confidential client is unaffected: asked once, then a later
//      request issues a code at once.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'consent_public_client_once',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.CPO_ROOT;
  const OUT = process.env.CPO_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const applications = require(ROOT_DIR + '/common/applications');
    const details = require(ROOT_DIR + '/oauth-oidc/authorization_details');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;

    const PUBLIC = 'cpo-public';
    const CONFIDENTIAL = 'cpo-confidential';
    const REDIRECT = 'https://rp.cpo.example/cb';
    const made = [
      applications.createApplication({ identifier: PUBLIC,
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: PUBLIC, oauthRedirectUri: [REDIRECT],
                  oauthTokenEndpointAuthMethod: 'none' } }),
      applications.createApplication({ identifier: CONFIDENTIAL,
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: CONFIDENTIAL,
                  oauthClientSecret: 'cpo-secret-0123456789abcdef0123456789',
                  oauthRedirectUri: [REDIRECT],
                  oauthTokenEndpointAuthMethod: 'client_secret_basic' } })
    ];
    note(made.every(function (one) {
      return one && one.ok;
    }), '0. both clients are registered', JSON.stringify(made));

    const jar = {};
    const get = function (where) {
      return screen.call({ port: port, jar: jar, method: 'GET',
        path: String(where).replace(/^https?:\/\/[^/]+/, '') });
    };
    const authorize = function (client, state) {
      return get('/oauth2/authorize?' + new URLSearchParams({
        client_id: client, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid profile', state: state, nonce: 'n-' + state })
        .toString());
    };
    const where = function (r) {
      return String((r.headers || {}).location || '');
    };
    const isConsent = function (r) {
      return r.status === 302 && /\/oauth2\/consent\?/.test(where(r));
    };
    const codeOf = function (r, state) {
      const at = where(r);
      if (r.status !== 302 || at.indexOf(REDIRECT) !== 0) {
        return '';
      }
      const q = new URL(at).searchParams;
      return q.get('state') === state ? String(q.get('code') || '') : '';
    };
    // Allow on the screen, then the pass the answer names.
    const allow = async function (r) {
      const answered = await screen.answerConsent({ port: port, jar: jar,
                                                     at: where(r) });
      if (answered.next !== 'redirect') {
        return { status: 0, headers: {}, text: answered.text };
      }
      return get(answered.location);
    };

    // --- 1. a public client, asked, answers once ------------------------
    let r = await authorize(PUBLIC, 'p1');
    if (r.status === 302 && /\/authn\/login/.test(where(r))) {
      const sent = await screen.submit({ port: port, jar: jar, at: where(r),
        fields: { action: 'login', username: 'cpo-alice',
                  password: 'anything' } });
      note(sent.next === 'redirect', '1a. cpo-alice signs in', sent.text);
      r = await get(sent.location);
    }
    note(isConsent(r), '1b. the public client\'s request meets the consent ' +
         'screen', r.status + ' ' + where(r));
    r = await allow(r);
    note(!!codeOf(r, 'p1'), '1c. after Allow, the pass that follows issues ' +
         'a code and does not ask again', r.status + ' ' + where(r));
    if (isConsent(r)) {
      // The loop this file exists for: say so, and do not follow it.
      note(false, '1d. the second pass was sent back to the consent screen',
           where(r));
    }

    // --- 2. a new request by the same public client is asked again -------
    r = await authorize(PUBLIC, 'p2');
    note(isConsent(r), '2a. a NEW request by the same public client is ' +
         'asked again, with the earlier consent on file',
         r.status + ' ' + where(r));
    r = await allow(r);
    note(!!codeOf(r, 'p2'), '2b. and its own Allow issues a code',
         r.status + ' ' + where(r));

    // --- 3. the answer is single use -----------------------------------
    const digest = details.scopeAnswerDigestOf('openid profile');
    note(/^scope:/.test(digest) &&
         digest === details.scopeAnswerDigestOf('profile openid openid') &&
         digest !== details.scopeAnswerDigestOf('openid'),
         '3a. the answer\'s digest is the set of scopes, apart from a ' +
         'details digest', digest);
    note(!details.consumeConsented('cpo-alice', PUBLIC, digest),
         '3b. nothing is left to spend once the pass has spent it');
    details.noteConsented('cpo-alice', PUBLIC, digest, null);
    note(details.consumeConsented('cpo-alice', PUBLIC, digest) &&
         !details.consumeConsented('cpo-alice', PUBLIC, digest),
         '3c. an answer recorded is spent exactly once');

    // --- 4. a confidential client is unaffected --------------------------
    r = await authorize(CONFIDENTIAL, 'c1');
    note(isConsent(r), '4a. a confidential client is asked the first time',
         r.status + ' ' + where(r));
    r = await allow(r);
    note(!!codeOf(r, 'c1'), '4b. and its Allow issues a code',
         r.status + ' ' + where(r));
    r = await authorize(CONFIDENTIAL, 'c2');
    note(!!codeOf(r, 'c2'), '4c. a later request by it issues a code at ' +
         'once: the recorded consent counts', r.status + ' ' + where(r));

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
  const out = path.join(os.tmpdir(), 'cpo-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  // ONE ACCOUNT PER BROWSER, as `authn_consent_api.js` sets it (#751): an
  // answer's address carries no account ticket, so the pass it names is
  // the authorization request the consent screen was given.
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, {
        LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
        CPO_ROOT: ROOT, CPO_OUT: out,
        STS_AUTHN_MULTIPLE_ACCOUNTS: 'false',
        STS_OAUTH2_CONSENT_ALWAYS_FOR_PUBLIC_CLIENTS: 'true' }),
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
  name: 'consent_public_client_once',
  describe: 'a public client is asked for consent every time (ASVS 10.7.1) ' +
            'and the answer to one authorization request counts for that ' +
            'request once: no loop, a new request asked again, a ' +
            'confidential client unaffected',
  run: run
};
