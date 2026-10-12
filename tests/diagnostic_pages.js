// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/diagnostic_pages.js
// ===========================================================================
// THE SPNEGO DIAGNOSTIC PAGES ARE STATIC SURFACES' SHELLS; THE RFC 4559
// EXCHANGE IS UNCHANGED (#583). THE TLS HALF IS GONE (#597).
//
// The whole stack in a child process, over HTTP on 127.0.0.1:
//
//   1. THE TLS PAGES ARE GONE: `/tls`, `/tls/forwarded`, `/tls/pages.js`,
//      `POST /tls/trust` and `POST /tls/trust/clear` answer as unrouted
//      paths in a development process (#597). What they showed is
//      Monitoring → TLS connection, a console page over
//      `/admin-api/tls-connection` (`tests/tls_connection_page.js`), and
//      the truststore's doors are `/admin-api/tls/trust`'s.
//   4. `GET /spnego`: the shell carrying the advertisement (no last
//      exchange); `?format=json` still carries it.
//   5. THE RFC 4559 EXCHANGE IS UNCHANGED: every answer of
//      `/spnego/protected` — the bare challenge, a wrong scheme, a token
//      that is not SPNEGO, `request-mic` (its negotiation cookie), the
//      accepted 200 with its final token — has the status and headers it
//      had before #583. THE BEFORE IS IN THIS TREE: a copy of `spnego.js`
//      without `spnego_pages.ts` (the parent project's) draws exactly the
//      pre-#583 page, so each request is asked twice — with the shell
//      module, and with it taken away — and the two snapshots must be
//      equal while only the second body is server-drawn.
//   6. The script is served as JavaScript.
//   7. The renderers draw each kind of view, escaped.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'diagnostic_pages',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.DP_ROOT;
  const OUT = process.env.DP_OUT;
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

  function isShell(r, script) {
    return r.text.indexOf('<script src="' + script + '" defer></script>') >
        0 &&
      r.text.indexOf('<link rel="stylesheet" href="/web/card.css">') > 0 &&
      r.text.indexOf('<noscript>') > 0 && !/<table/.test(r.text);
  }

  function policyOk(r) {
    const csp = String(r.headers['content-security-policy'] || '');
    return /frame-ancestors 'none'/.test(csp) &&
      /script-src 'self'(;|$)/.test(csp) && !/unsafe-inline/.test(csp);
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
    await require(ROOT_DIR + '/common/service_state').start();
    const exchange = require(ROOT_DIR + '/kerberos/spnego_exchange');
    const principals = require(ROOT_DIR + '/kerberos/krb5_principals');
    const gss = require(ROOT_DIR + '/kerberos/krb5_spnego');
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const jar = {};
    const call = function (method, p, headers, body) {
      return new Promise(function (resolve, reject) {
        const h = Object.assign({}, headers || {});
        if (Object.keys(jar).length && !h.cookie) {
          h.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (h.cookie === '') {
          delete h.cookie;
        }
        const text = body === undefined ? '' : String(body);
        if (method !== 'GET') {
          h['content-length'] = Buffer.byteLength(text);
        }
        const req = http.request({ host: '127.0.0.1', port: port, path: p,
                                   method: method, headers: h },
          function (res) {
            let out = '';
            (res.headers['set-cookie'] || []).forEach(function (line) {
              const pair = line.split(';')[0];
              const eq = pair.indexOf('=');
              jar[pair.slice(0, eq)] = pair.slice(eq + 1);
            });
            res.on('data', function (c) {
              out += c;
            });
            res.on('end', function () {
              let json = null;
              try {
                json = JSON.parse(out);
              } catch (e) {
                json = null;
              }
              resolve({ status: res.statusCode, headers: res.headers,
                        text: out, json: json });
            });
          });
        req.on('error', reject);
        req.end(text);
      });
    };

    // --- 1. the TLS pages are gone (#597) -----------------------------------
    let r = null;
    let state = null;
    for (const asked of [['GET', '/tls'], ['GET', '/tls/forwarded'],
                         ['GET', '/tls/pages.js'], ['POST', '/tls/trust'],
                         ['POST', '/tls/trust/clear']]) {
      r = await call(asked[0], asked[1], { 'content-type': 'text/plain' },
                     '');
      note(r.status === 404 &&
           new RegExp('Cannot ' + asked[0] + ' ' +
                      asked[1].replace(/\//g, '\\/')).test(r.text),
           '1. ' + asked.join(' ') + ' answers as an unrouted path in ' +
           'development', r.status + ' ' + r.text.slice(0, 120));
    }

    // --- 4. /spnego ----------------------------------------------------------
    r = await call('GET', '/spnego');
    state = stateOf(r.text);
    const sjson = await call('GET', '/spnego?format=json');
    note(r.status === 200 && isShell(r, '/spnego/pages.js') && policyOk(r) &&
         state && state.view.kind === 'advert' &&
         state.view.realm === principals.REALM &&
         state.view.servicePrincipalName === exchange.SPN + '@' +
           principals.REALM &&
         state.view.lastExchange === undefined &&
         Array.isArray(state.view.mechanisms) &&
         sjson.json && sjson.json.kind === undefined &&
         'lastExchange' in sjson.json &&
         sjson.json.servicePrincipalName ===
           state.view.servicePrincipalName,
         '4. /spnego is the shell carrying the advertisement; ?format=json ' +
         'is unchanged', JSON.stringify(state));

    // --- 5. the exchange, before and after -----------------------------------
    // THE BEFORE: `spnego.js` without its shell module draws the pre-#583
    // page (its `pagesModule()` answers null for a module with no `send`).
    const pagesPath = require.resolve(ROOT_DIR + '/kerberos/spnego_pages');
    const pagesModule = require.cache[pagesPath];
    const realExports = pagesModule.exports;
    const twice = async function (label, p, headers) {
      jar.sts_spnego_negotiation = undefined;
      delete jar.sts_spnego_negotiation;
      pagesModule.exports = {};
      const before = await call('GET', p, Object.assign({ cookie: '' },
                                                         headers || {}));
      pagesModule.exports = realExports;
      const after = await call('GET', p, Object.assign({ cookie: '' },
                                                       headers || {}));
      const a = JSON.stringify(snapshot(before));
      const b = JSON.stringify(snapshot(after));
      note(a === b && !isShell(before, '/spnego/pages.js') &&
           /script-src 'none'/.test(String(
             before.headers['content-security-policy'])) &&
           isShell(after, '/spnego/pages.js') && policyOk(after),
           '5. ' + label + ': the status and headers are what they were (' +
           b + '), and only the body changed', 'before ' + a + ' ' +
           before.text.slice(0, 120) + ' after ' + b);
      return { before: before, after: after };
    };
    let pair = await twice('the bare challenge', '/spnego/protected');
    state = stateOf(pair.after.text);
    note(pair.after.status === 401 &&
         pair.after.headers['www-authenticate'] === 'Negotiate' &&
         state && state.view.kind === 'verdict' &&
         state.view.code === 'no-authorization' &&
         state.view.spn === exchange.SPN &&
         /<title>Authentication required<\/title>/.test(pair.before.text),
         '5a. the bare challenge carries its verdict; the copy without the ' +
         'shell draws the page it drew', JSON.stringify(state));
    pair = await twice('a wrong scheme', '/spnego/protected',
                       { authorization: 'Basic eDp5' });
    state = stateOf(pair.after.text);
    note(state && state.view.code === 'wrong-scheme' &&
         state.view.scheme === 'Basic',
         '5b. a wrong scheme carries the scheme offered',
         JSON.stringify(state));
    pair = await twice('a token that is not SPNEGO', '/spnego/protected',
      { authorization: 'Negotiate ' +
          Buffer.from('this is not a SPNEGO token').toString('base64') });
    state = stateOf(pair.after.text);
    note(state && state.view.ok === false && state.view.reason &&
         /^Negotiate\b/.test(String(pair.after.headers['www-authenticate'])),
         '5c. a token that is not SPNEGO is a reject with its reason',
         JSON.stringify(state));
    // THE ACCEPTOR'S VERDICT, STOOD IN FOR (as tests/spnego_shell.js does):
    // what is under test is the page over a verdict, not the ticket.
    const realNegotiate = exchange.negotiate;
    exchange.negotiate = async function () {
      return { ok: true, status: 200, code: 'accepted',
               wwwAuthenticate: 'Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg==',
               client: 'dp-alice@' + principals.REALM,
               selected: gss.KRB5_MECH_OID, micVerified: true,
               rawKerberos: false, mutual: true,
               sessionKey: 'MUST-NOT-APPEAR',
               checks: [{ name: 'the ticket decrypts', ok: true,
                          detail: 'under the service key' }] };
    };
    pair = await twice('the accepted 200', '/spnego/protected',
                       { authorization: 'Negotiate eA==' });
    state = stateOf(pair.after.text);
    note(pair.after.status === 200 &&
         pair.after.headers['www-authenticate'] ===
           'Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg==' &&
         state && state.view.ok === true &&
         state.view.client === 'dp-alice@' + principals.REALM &&
         state.view.micVerified === true && state.view.mutual === true &&
         state.view.checks.length === 1 &&
         pair.after.text.indexOf('MUST-NOT-APPEAR') < 0 &&
         /protected content/.test(pair.before.text),
         '5d. the accepted 200 keeps its final token and carries who, and ' +
         'nothing of the verdict that is not drawn', JSON.stringify(state));
    exchange.negotiate = async function () {
      return { ok: false, status: 401, code: 'request-mic',
               wwwAuthenticate: 'Negotiate oQcwBaADCgED',
               pendingId: 'dp-negotiation-' + Date.now(),
               selected: gss.KRB5_MECH_OID, checks: [] };
    };
    pair = await twice('request-mic and its negotiation cookie',
                       '/spnego/protected',
                       { authorization: 'Negotiate eA==' });
    note((pair.after.headers['set-cookie'] || []).some(function (c) {
      return /^sts_spnego_negotiation=[^;]+; Path=\/; HttpOnly/.test(c);
    }) && stateOf(pair.after.text).view.code === 'request-mic',
         '5e. request-mic keeps the cookie that names its negotiation',
         JSON.stringify(pair.after.headers['set-cookie']));
    exchange.negotiate = realNegotiate;
    pagesModule.exports = realExports;

    // --- 6. the scripts ------------------------------------------------------
    for (const p of ['/spnego/pages.js']) {
      r = await call('GET', p);
      note(r.status === 200 &&
           /javascript/.test(String(r.headers['content-type'])) &&
           r.text.length > 0, '6. ' + p + ' is served as a script',
           r.status + ' ' + String(r.headers['content-type']));
    }

    // --- 7. the renderers ----------------------------------------------------
    const spnegoViews = require(ROOT_DIR + '/kerberos/web_spnego_views');
    const spT = translator(['spnegoPages'], ['en']);
    const verdict = spnegoViews.render({ kind: 'verdict', ok: false,
      code: 'wrong-scheme', scheme: 'Basic<x>', spn: 's', reason: '',
      checks: null }, { t: spT });
    note(verdict.indexOf('401 — wrong authentication scheme') > 0 &&
         verdict.indexOf('Basic&lt;x&gt;') > 0,
         '7e. a verdict draws its heading and its detail, escaped', verdict);
    const reject = spnegoViews.render({ kind: 'verdict', ok: false,
      code: 'acceptor-threw', reason: 'R <1>', checks: [] }, { t: spT });
    note(reject.indexOf('401 — the negotiation was rejected') > 0 &&
         reject.indexOf('id="spnego-reason">R &lt;1&gt;</div>') > 0,
         '7f. a code no page knows is the REJECTED page, with its reason',
         reject);

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
  const out = path.join(os.tmpdir(), 'dp-' + process.pid + '-' + Date.now() +
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
                                  DP_ROOT: ROOT, DP_OUT: out }),
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
  name: 'diagnostic_pages',
  describe: 'the SPNEGO diagnostic pages are static surfaces\' shells and ' +
            'the RFC 4559 exchange is unchanged (#583); the TLS pages and ' +
            'the truststore\'s open acts are gone (#597)',
  run: run
};
