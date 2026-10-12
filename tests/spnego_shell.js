// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/spnego_shell.js
// ===========================================================================
// THE SPNEGO SIGN-IN'S BODIES ARE THE SIGN-IN SURFACE'S SHELL; ITS EXCHANGE
// IS UNCHANGED (#575).
//
// The whole stack in a child process, over HTTP on 127.0.0.1. Each response
// of `GET /authn/spnego` is asked for its STATUS and HEADERS — what RFC 4559
// specifies and what #575 must not change — and then for its body:
//
//   1. THE FIRST 401 (no Authorization): 401, `WWW-Authenticate: Negotiate`
//      exactly as the acceptor's verdict spells it, `no-store`, text/html;
//      the body is the shell — the sign-in bundle, the card, the
//      `<noscript>`, no server-drawn page — carrying `data-sts-state` with
//      the pending sign-in, the service principal, the realm and the hosts.
//      Its policy runs `script-src 'self'` and keeps `frame-ancestors`.
//   2. A CONTINUATION OR A TERMINAL REFUSAL (a token that is not SPNEGO) is
//      still drawn by the server, under the service's `script-src 'none'`.
//   3. OFF (`krb5.spnegoAuthentication` false): 403, `no-store`, no session
//      cookie, and the shell naming the setting in its state.
//   4. SIGNED IN with nothing interrupted (the acceptor's verdict stood in
//      for, so no KDC is needed): 200, the verdict's final
//      `WWW-Authenticate` token, `no-store`, the session cookie; the shell
//      carrying who, the session, the flags, amr, acr and the checks.
//   5. SIGNED IN for a waiting request: the 303 to `returnTo`, no shell.
//   6. The state draws: `kerberos/web_authn_spnego.ts` over each view.
//   7. The sign-in runtime draws the challenge from the shell it came in,
//      in the browser's language, fetching catalogs and no view.
//
// Every response's status and headers (CSP and per-request values set
// aside) are reported as a snapshot, which is what was compared against the
// tree before #575 to show the exchange did not change.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'spnego_shell',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.SS_ROOT;
  const OUT = process.env.SS_OUT;
  const http = require('http');
  const fs = require('fs');
  const path = require('path');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  // What the exchange specifies of a response, and nothing per request.
  function snapshot(r) {
    const keep = ['content-type', 'cache-control', 'www-authenticate',
                  'location'];
    const out = { status: r.status };
    keep.forEach(function (name) {
      if (r.headers[name] !== undefined) {
        out[name] = r.headers[name];
      }
    });
    out.cookies = (r.headers['set-cookie'] || []).map(function (line) {
      return line.replace(/=[^;]*/, '=…');
    });
    return out;
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
    return r.text.indexOf('<script src="/authn/signin.js" defer></script>') >
        0 &&
      r.text.indexOf('<link rel="stylesheet" href="/web/card.css">') > 0 &&
      r.text.indexOf('<noscript>') > 0 && !/<table/.test(r.text);
  }

  function englishSpnego() {
    const messages = require(ROOT_DIR + '/common/web_messages');
    const flat = {};
    const own = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'common',
      'locales', 'spnego', 'en.json'), 'utf8'));
    Object.keys(own).forEach(function (key) {
      flat['spnego.' + key] = own[key];
    });
    return messages.WebTranslator.fromData({ catalogs: { en: flat },
      negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                    direction: 'ltr', matched: true } });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const authn = require(ROOT_DIR + '/authn/authn');
    const config = require(ROOT_DIR + '/common/config');
    const exchange = require(ROOT_DIR + '/kerberos/spnego_exchange');
    const principals = require(ROOT_DIR + '/kerberos/krb5_principals');
    const gss = require(ROOT_DIR + '/kerberos/krb5_spnego');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const begin = function () {
      return authn.beginAuthentication({ returnTo: '/ss/after?x=1',
        protocol: 'ss-probe', application: '' });
    };
    const idOf = function (at) {
      return decodeURIComponent(String(at).split('authn=')[1] || '');
    };
    const get = function (p, headers) {
      return screen.call({ port: port, jar: {}, method: 'GET', path: p,
                           headers: headers || {} });
    };
    const snaps = {};
    const policyOk = function (r) {
      const csp = String(r.headers['content-security-policy'] || '');
      return /frame-ancestors 'none'/.test(csp) &&
        /script-src 'self'(;|$)/.test(csp) && !/unsafe-inline/.test(csp);
    };
    config.setOverride('krb5.spnegoAuthentication', 'true');

    // --- 1. the first 401 ----------------------------------------------------
    let at = begin();
    let r = await get('/authn/spnego?authn=' + encodeURIComponent(idOf(at)));
    snaps.challenge = snapshot(r);
    let state = stateOf(r.text);
    note(r.status === 401 &&
         /^Negotiate$/.test(String(r.headers['www-authenticate'])) &&
         /no-store/.test(String(r.headers['cache-control'])) &&
         /^text\/html/.test(String(r.headers['content-type'])) &&
         !(r.headers['set-cookie'] || []).some(function (c) {
           return /^sts_session=[^;]/.test(c);
         }),
         '1a. the first 401 keeps its status and its headers: Negotiate, ' +
         'no-store, text/html, no session', JSON.stringify(snaps.challenge));
    note(isShell(r) && policyOk(r),
         '1b. its body is the sign-in surface\'s shell, under a policy that ' +
         'runs the bundle and keeps frame-ancestors',
         String(r.headers['content-security-policy']) + ' ' +
         r.text.slice(0, 400));
    note(state && state.view && state.view.door === 'spnego' &&
         state.view.kind === 'challenge' && state.view.pending &&
         state.view.pending.id === idOf(at) &&
         state.view.pending.protocol === 'ss-probe' &&
         state.view.spn === exchange.SPN &&
         state.view.realm === principals.REALM &&
         Array.isArray(state.view.hosts),
         '1c. carrying the pending sign-in and the service principal',
         JSON.stringify(state));
    r = await get('/authn/spnego');
    state = stateOf(r.text);
    note(r.status === 401 && state && state.view.pending === null,
         '1d. reached directly, nothing is pending', JSON.stringify(state));

    // --- 2. a refusal of a token stays server-drawn --------------------------
    r = await get('/authn/spnego?authn=' + encodeURIComponent(idOf(at)),
      { authorization: 'Negotiate ' +
          Buffer.from('this is not a SPNEGO token').toString('base64') });
    snaps.refused = snapshot(r);
    note(r.status === 401 &&
         /^Negotiate\b/.test(String(r.headers['www-authenticate'])) &&
         !isShell(r) && /<table|<div class="err">/.test(r.text) &&
         /script-src 'none'/.test(String(
           r.headers['content-security-policy'])),
         '2. a token that is not SPNEGO is the negotiation\'s own 401, drawn ' +
         'by the server as it was', JSON.stringify(snaps.refused));

    // --- 3. off --------------------------------------------------------------
    config.setOverride('krb5.spnegoAuthentication', 'false');
    at = begin();
    r = await get('/authn/spnego?authn=' + encodeURIComponent(idOf(at)));
    snaps.off = snapshot(r);
    state = stateOf(r.text);
    note(r.status === 403 && r.headers['www-authenticate'] === undefined &&
         /no-store/.test(String(r.headers['cache-control'])) &&
         /^text\/html/.test(String(r.headers['content-type'])) &&
         !(r.headers['set-cookie'] || []).length,
         '3a. off: 403, no-store, no challenge and no cookie',
         JSON.stringify(snaps.off));
    note(isShell(r) && policyOk(r) && state && state.view.kind === 'off' &&
         state.view.setting === 'krb5.spnegoAuthentication' &&
         /krb5\.spnegoAuthentication/.test(r.text) &&
         state.view.pending && state.view.pending.id === idOf(at),
         '3b. its body is the shell naming the setting, with the way back',
         JSON.stringify(state));
    config.setOverride('krb5.spnegoAuthentication', 'true');

    // --- 4. signed in, nothing interrupted -----------------------------------
    // THE ACCEPTOR'S VERDICT, STOOD IN FOR: what is under test is what the
    // door does with an accepted ticket, not the ticket (the protocol jobs
    // `sts_kerberos_spnego.js` and `sts_kerberos_heimdal.js` spend real ones).
    const realNegotiate = exchange.negotiate;
    const user = 'ss-kerb-' + String(Date.now()).slice(-6);
    exchange.negotiate = async function () {
      return { ok: true, status: 200, code: 'accepted',
               wwwAuthenticate: 'Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg==',
               client: user + '@' + principals.REALM,
               ticketFlags: ['forwardable', 'pre-authent'],
               authIndicators: [], selected: gss.KRB5_MECH_OID,
               micVerified: true, rawKerberos: false,
               checks: [{ name: 'the ticket decrypts', ok: true,
                          detail: 'under the service key' }] };
    };
    r = await get('/authn/spnego', { 'user-agent': 'Mozilla/5.0 (X11; ' +
      'Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
      'Chrome/140.0.0.0 Safari/537.36' });
    snaps.signedIn = snapshot(r);
    state = stateOf(r.text);
    note(r.status === 200 &&
         r.headers['www-authenticate'] ===
           'Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg==' &&
         /no-store/.test(String(r.headers['cache-control'])) &&
         (r.headers['set-cookie'] || []).some(function (c) {
           return /^sts_session=[^;]/.test(c);
         }),
         '4a. signed in: 200, the final mutual-authentication token, ' +
         'no-store and the session cookie', JSON.stringify(snaps.signedIn));
    note(isShell(r) && policyOk(r) && state &&
         state.view.kind === 'signed-in' && state.view.username === user &&
         JSON.stringify(state.view.amr) === '["pwd"]' &&
         state.view.acr === '1' && state.view.mic === true &&
         /^urn:uuid:/.test(String(state.view.subject)) &&
         state.view.checks.length === 1,
         '4b. its body is the shell carrying who, the session and what the ' +
         'ticket claimed', JSON.stringify(state));
    const signedIn = state;

    // --- 5. signed in for a waiting request ----------------------------------
    at = begin();
    r = await get('/authn/spnego?authn=' + encodeURIComponent(idOf(at)),
                  { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) ' +
                    'AppleWebKit/537.36 (KHTML, like Gecko) ' +
                    'Chrome/140.0.0.0 Safari/537.36' });
    snaps.returned = snapshot(r);
    note(r.status === 303 && r.headers.location === '/ss/after?x=1' &&
         r.headers['www-authenticate'] ===
           'Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg==' && !isShell(r),
         '5. for a waiting request it is the 303 to returnTo, as it was',
         JSON.stringify(snaps.returned));
    exchange.negotiate = realNegotiate;

    // --- 6. the state draws --------------------------------------------------
    const draw = require(ROOT_DIR + '/kerberos/web_authn_spnego');
    const t = englishSpnego();
    const html = draw.render(signedIn.view, { t: t });
    note(html.indexOf('<strong>' + user + '</strong>') > 0 &&
         /<code>pwd<\/code>/.test(html) && /class="pass"/.test(html) &&
         draw.title(signedIn.view, { t: t }) === 'Signed in',
         '6a. the signed-in state draws the page that names the person',
         html.slice(0, 300));
    const off = draw.render({ door: 'spnego', kind: 'off',
      setting: 'krb5.spnegoAuthentication', demoPath: '',
      pending: { id: 'abc', protocol: 'p', application: '' } }, { t: t });
    note(/<code>krb5\.spnegoAuthentication<\/code>/.test(off) &&
         off.indexOf('href="/authn/login?authn=abc"') > 0 &&
         off.indexOf('/spnego/protected') < 0,
         '6b. the off state names the setting and the way back, and no ' +
         'demonstration a realm is not served', off.slice(0, 300));

    // --- 7. the runtime draws the embedded page, fetching no view ------------
    at = begin();
    r = await get('/authn/spnego?authn=' + encodeURIComponent(idOf(at)));
    const attrs = {};
    const tag = /<html([^>]*)>/.exec(r.text)[1];
    tag.replace(/ ([a-z-]+)="([^"]*)"/g, function (all, n, v) {
      attrs[n] = v.replace(/&quot;/g, '"').replace(/&#39;/g, "'")
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
      return all;
    });
    const asked = [];
    const loc = new URL('https://sts.example/authn/spnego?authn=' +
                        encodeURIComponent(idOf(at)));
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
    const AuthnSurface = require(ROOT_DIR + '/authn/web_authn');
    const surface = new AuthnSurface(env);
    await surface.route();
    const drawn = env.document.body.innerHTML;
    note(/^<div class="card wide">/.test(drawn) &&
         drawn.indexOf('href="/authn/login?authn=' +
                       encodeURIComponent(idOf(at)) + '"') > 0 &&
         /lang="fr"|<option value="fr[^"]*"[^>]* selected/.test(drawn) &&
         drawn.indexOf('Kerberos') > 0 &&
         !asked.some(function (p) {
           return /^\/authn-api/.test(p);
         }) &&
         asked.some(function (p) {
           return /^\/web\/locales\/spnego\//.test(p);
         }),
         '7. the runtime draws the challenge from the shell\'s state, in ' +
         'the browser\'s language, asking /authn-api for nothing',
         JSON.stringify(asked) + ' ' + drawn.slice(0, 600));

    note(true, '8. the snapshot of statuses and headers',
         JSON.stringify(snaps));
    config.clearOverride('krb5.spnegoAuthentication');
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
  const out = path.join(os.tmpdir(), 'ss-' + process.pid + '-' + Date.now() +
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
                                  SS_ROOT: ROOT, SS_OUT: out }),
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
  name: 'spnego_shell',
  describe: 'the SPNEGO sign-in\'s first 401, its 403 when off and its ' +
            'signed-in page are the sign-in surface\'s shell, with the RFC ' +
            '4559 statuses and headers unchanged (#575)',
  run: run
};
