// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/federation_pages.js
// ===========================================================================
// THE FEDERATION PAGES THAT ARE THIS SERVICE'S OWN ARE A STATIC SURFACE'S
// SHELL; THE ASSERTION CONSUMER SERVICE'S ANSWERS ARE UNCHANGED (#580).
//
// The whole stack in a child process, over HTTP on 127.0.0.1. Each page is
// asked for its STATUS and HEADERS — which #580 keeps — and then its body:
//
//   1. `GET /federation`: 200, no-store, text/html; the shell — the
//      federation pages' script, the card, the `<noscript>`, no
//      server-drawn table — under a policy that runs the script and keeps
//      `frame-ancestors`, carrying the relationships in each direction, the
//      endpoints' paths and the base in `data-sts-state`.
//   2. `/federation/login/{id}`'s refusals, each with the status it always
//      had: federation off (404), no such relationship (404), the other
//      direction (400), disabled (403, `fedLastError` written), not fully
//      configured (409) — the shell carrying what and why, English.
//   3. `/federation/link/{handle}` with no link waiting: 400, the shell.
//   4. THE ASSERTION CONSUMER SERVICE IS NOT CONVERTED: its refusal of the
//      same disabled relationship is still drawn by the server, under the
//      service's `script-src 'none'`, with no state.
//   5. `/federation/pages.js` is served as a script.
//   6. The renderers draw each kind of view (the escaping included), and
//      the email factor's end page is the bytes it was before #580.
//   7. The runtime draws the landing page from the shell it came in, in the
//      browser's language, fetching catalogs and nothing else.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'federation_pages',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.FP_ROOT;
  const OUT = process.env.FP_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function stateOf(text) {
    const m = /<html[^>]* data-sts-state="([^"]*)"/.exec(String(text || ''));
    if (!m) {
      return null;
    }
    const raw = m[1].replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    return JSON.parse(raw);
  }

  function isShell(r) {
    return r.text.indexOf('<script src="/federation/pages.js" defer>' +
                          '</script>') > 0 &&
      r.text.indexOf('<link rel="stylesheet" href="/web/card.css">') > 0 &&
      r.text.indexOf('<noscript>') > 0 && !/<table/.test(r.text);
  }

  function policyOk(r) {
    const csp = String(r.headers['content-security-policy'] || '');
    return /frame-ancestors 'none'/.test(csp) &&
      /script-src 'self'(;|$)/.test(csp) && !/unsafe-inline/.test(csp);
  }

  function headersOk(r, status) {
    return r.status === status &&
      /no-store/.test(String(r.headers['cache-control'])) &&
      /^text\/html/.test(String(r.headers['content-type'])) &&
      r.headers.location === undefined;
  }

  function translator(namespaces, chain) {
    const messages = require(ROOT_DIR + '/common/web_messages');
    const catalogs = {};
    chain.forEach(function (tag) {
      const flat = {};
      namespaces.forEach(function (ns) {
        const own = JSON.parse(fs.readFileSync(ROOT_DIR + '/common/locales/' +
          ns + '/' + tag + '.json', 'utf8'));
        Object.keys(own).forEach(function (key) {
          flat[ns + '.' + key] = own[key];
        });
      });
      catalogs[tag] = flat;
    });
    return messages.WebTranslator.fromData({ catalogs: catalogs,
      negotiated: { locale: chain[0], chain: chain, catalog: chain[0],
                    direction: 'ltr', matched: true } });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const federation = require(ROOT_DIR + '/federation/federation');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const get = function (p) {
      return screen.call({ port: port, jar: {}, method: 'GET', path: p,
                           headers: {} });
    };
    const stamp = String(Date.now()).slice(-6);
    const SP = 'fp-sp-' + stamp;
    const IDP = 'fp-idp-' + stamp;
    const HALF = 'fp-half-' + stamp;
    config.setOverride('federation.enabled', 'true');
    const made = [
      federation.create({ fedId: SP, fedRole: 'service-provider',
                          fedProtocol: 'saml2' }),
      federation.create({ fedId: IDP, fedRole: 'identity-provider',
                          fedProtocol: 'saml2' }),
      federation.create({ fedId: HALF, fedRole: 'service-provider',
                          fedProtocol: 'oidc' })
    ];
    const enabled = federation.update(HALF, { field: 'fedEnabled',
                                              value: 'TRUE' });
    note(made.every(function (m) {
      return m && m.ok;
    }) && enabled && enabled.ok,
         '0. three relationships: a disabled SAML partner, the other ' +
         'direction, an enabled half-configured OIDC partner',
         JSON.stringify(made.concat([enabled])));

    // --- 1. the landing page ------------------------------------------------
    let r = await get('/federation');
    let state = stateOf(r.text);
    const row = state && state.view && (state.view.consuming || [])
      .filter(function (one) {
        return one.id === SP;
      })[0];
    const half = state && state.view && (state.view.consuming || [])
      .filter(function (one) {
        return one.id === HALF;
      })[0];
    note(headersOk(r, 200) && isShell(r) && policyOk(r),
         '1a. GET /federation: 200, no-store, the federation pages\' shell ' +
         'under a policy that runs its script and keeps frame-ancestors',
         r.status + ' ' + String(r.headers['content-security-policy']) + ' ' +
         r.text.slice(0, 400));
    note(state && state.view.kind === 'index' && row &&
         row.state === 'disabled' && row.metadata === true && half &&
         half.state === 'incomplete' && half.missing.length > 0 &&
         (state.view.asserting || []).some(function (one) {
           return one.id === IDP;
         }) && state.view.paths.acs === '/federation/acs' &&
         /^http:\/\/127\.0\.0\.1:/.test(state.view.base),
         '1b. carrying the relationships in each direction, their states, ' +
         'the endpoints and the base', JSON.stringify(state).slice(0, 900));

    // --- 2. the login endpoint's refusals -----------------------------------
    config.setOverride('federation.enabled', 'false');
    r = await get('/federation/login/' + SP);
    state = stateOf(r.text);
    note(headersOk(r, 404) && isShell(r) && policyOk(r) && state &&
         state.view.kind === 'off',
         '2a. federation off: 404, the shell saying so', r.status + ' ' +
         JSON.stringify(state));
    config.setOverride('federation.enabled', 'true');
    r = await get('/federation/login/fp-nobody-' + stamp);
    state = stateOf(r.text);
    note(headersOk(r, 404) && isShell(r) && state &&
         state.view.kind === 'noRelationship' &&
         state.view.id === 'fp-nobody-' + stamp,
         '2b. no such relationship: 404, the shell naming it',
         r.status + ' ' + JSON.stringify(state));
    r = await get('/federation/login/' + IDP);
    state = stateOf(r.text);
    note(headersOk(r, 400) && isShell(r) && state &&
         state.view.kind === 'refused' &&
         state.view.what === 'That relationship goes the other way' &&
         state.view.relationship === '',
         '2c. the other direction: 400, the shell with what and why',
         r.status + ' ' + JSON.stringify(state));
    r = await get('/federation/login/' + SP);
    state = stateOf(r.text);
    const recorded = federation.get(SP);
    note(headersOk(r, 403) && isShell(r) && policyOk(r) && state &&
         state.view.kind === 'refused' &&
         state.view.what === 'That relationship is disabled' &&
         /fedEnabled is FALSE/.test(state.view.why) &&
         state.view.relationship === SP &&
         /^That relationship is disabled: /.test(String(
           recorded.fedLastError || '')),
         '2d. disabled: 403, the shell with the relationship, and ' +
         'fedLastError written as before', r.status + ' ' +
         JSON.stringify(state) + ' ' + String(recorded.fedLastError));
    r = await get('/federation/login/' + HALF);
    state = stateOf(r.text);
    note(headersOk(r, 409) && isShell(r) && state &&
         state.view.kind === 'refused' &&
         /not fully configured/.test(state.view.what),
         '2e. not fully configured: 409, the shell', r.status + ' ' +
         JSON.stringify(state));

    // --- 3. the linking endpoint --------------------------------------------
    r = await get('/federation/link/fed-nothing' + stamp);
    state = stateOf(r.text);
    note(headersOk(r, 400) && isShell(r) && policyOk(r) && state &&
         state.view.kind === 'refused' &&
         state.view.what === 'There is no link waiting',
         '3. no link waiting: 400, the shell', r.status + ' ' +
         JSON.stringify(state));

    // --- 4. the assertion consumer service is not converted ----------------
    r = await get('/federation/acs/' + SP);
    note(r.status >= 400 && stateOf(r.text) === null && !isShell(r) &&
         /The federated sign-in was refused/.test(r.text) &&
         /script-src 'none'/.test(String(
           r.headers['content-security-policy'])),
         '4. the assertion consumer service\'s refusal is drawn by the ' +
         'server as it was, under script-src \'none\'',
         r.status + ' ' + String(r.headers['content-security-policy']) +
         ' ' + r.text.slice(0, 300));

    // --- 5. the script ------------------------------------------------------
    r = await get('/federation/pages.js');
    note(r.status === 200 &&
         /javascript/.test(String(r.headers['content-type'])) &&
         r.text.length > 0,
         '5. /federation/pages.js is served as a script',
         r.status + ' ' + String(r.headers['content-type']));

    // --- 6. the renderers ---------------------------------------------------
    const views = require(ROOT_DIR + '/federation/web_federation_views');
    const en = translator(['federationPages', 'handoff'], ['en']);
    const refused = views.render({ kind: 'refused', what: 'W <1>',
      why: 'Y & "2"', relationship: 'r<3>' }, { t: en });
    note(refused.indexOf('<h1>The federated sign-in was refused</h1>') ===
           0 &&
         refused.indexOf('<p class="bad" id="federation-refused">W &lt;1&gt;' +
                         '</p>') > 0 &&
         refused.indexOf('Y &amp; &quot;2&quot;') > 0 &&
         refused.indexOf('?relationship=r%3C3%3E') > 0 &&
         refused.indexOf('<script') < 0,
         '6a. a refusal: English, escaped, recorded on its relationship',
         refused);
    const signedIn = views.render({ kind: 'signedIn', relationship: 'x',
      partner: 'P', peer: '', protocol: 'SAML 2.0', subject: 's',
      username: 'u<1>', usernamePrefixed: false, usernameFrom: 'NameID',
      session: 'abc', autocreate: true, updates: true,
      mapped: [], unmapped: [] }, { t: en });
    note(/<h1 id="federation-signed-in">Signed in through P<\/h1>/
           .test(signedIn) && signedIn.indexOf('u&lt;1&gt;') > 0,
         '6b. the linking step\'s outcome, in the handoff catalog\'s words',
         signedIn.slice(0, 300));
    const index = views.render({ kind: 'index', base: 'https://x',
      loginButtons: false, consuming: [], asserting: [],
      paths: { login: '/federation/login', acs: '/federation/acs',
               metadata: '/federation/metadata', slo: '/federation/slo',
               backchannel: '/b', frontchannel: '/f' } }, { t: en });
    note(index.indexOf('href="/portal"') > 0 &&
         !/href="\/authn\/login/.test(index) &&
         /id="federation-buttons">federation\.loginButtons is off/
           .test(index),
         '6c. the landing page offers the sign-in screen through /portal, ' +
         'never a bare /authn/login', index.slice(-400));
    const email = require(ROOT_DIR + '/authn/web_authn_email');
    const end = email.end({ title: 'T <1>', sentence: 'S & 2' });
    note(end === '<h1>T &lt;1&gt;</h1><div class="err" id="email-error">S ' +
                 '&amp; 2</div><p class="meta">Start again from the ' +
                 'application that sent you here.</p>',
         '6d. the emailed factor\'s end page is the bytes it was', end);

    // --- 7. the runtime -----------------------------------------------------
    r = await get('/federation');
    const attrs = {};
    const tag = /<html([^>]*)>/.exec(r.text)[1];
    tag.replace(/ ([a-z-]+)="([^"]*)"/g, function (all, n, v) {
      attrs[n] = v.replace(/&quot;/g, '"').replace(/&#39;/g, "'")
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
      return all;
    });
    const asked = [];
    const loc = new URL('https://sts.example/federation');
    const env = {
      location: { pathname: loc.pathname, search: loc.search, hash: '',
                  href: loc.href, origin: 'https://sts.example',
                  assign: function () {
                    return undefined;
                  } },
      history: { pushState: function () {
        return undefined;
      }, replaceState: function () {
        return undefined;
      } },
      document: {
        title: '', body: { innerHTML: '' },
        documentElement: {
          getAttribute: function (n) {
            return n in attrs ? attrs[n] : null;
          },
          setAttribute: function (n, v) {
            attrs[n] = v;
          }
        },
        addEventListener: function () {
          return undefined;
        }
      },
      navigator: { languages: ['fr', 'en'] },
      fetch: function (url, init) {
        const u = new URL(url);
        asked.push(u.pathname);
        return fetch('http://127.0.0.1:' + port + u.pathname + u.search,
                     init);
      }
    };
    const Surface = require(ROOT_DIR + '/federation/web_federation_surface');
    const surface = new Surface(env);
    await surface.route();
    const drawn = env.document.body.innerHTML;
    note(/^<div class="card wide">/.test(drawn) &&
         drawn.indexOf('<h1>Fédération</h1>') > 0 &&
         drawn.indexOf('<code>' + SP + '</code>') > 0 &&
         env.document.title === 'Fédération' &&
         asked.every(function (p) {
           return /^\/web\/locales\//.test(p);
         }) && asked.some(function (p) {
           return /^\/web\/locales\/federationPages\//.test(p);
         }),
         '7. the runtime draws the landing page from the shell\'s state, in ' +
         'the browser\'s language, asking for catalogs and nothing else',
         JSON.stringify(asked) + ' ' + env.document.title + ' ' +
         drawn.slice(0, 500));

    config.clearOverride('federation.enabled');
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
  const out = path.join(os.tmpdir(), 'fp-' + process.pid + '-' + Date.now() +
                        '.json');
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
                                  FP_ROOT: ROOT, FP_OUT: out }),
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
  name: 'federation_pages',
  describe: 'the federation landing page and the login and linking ' +
            'endpoints\' refusals are the federation pages\' shell with ' +
            'their statuses unchanged, and the assertion consumer service ' +
            'is not converted (#580)',
  run: run
};
