// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/diagnostic_pages.js
// ===========================================================================
// THE TLS AND SPNEGO DIAGNOSTIC PAGES ARE STATIC SURFACES' SHELLS; THE
// TRUSTSTORE'S API AND THE RFC 4559 EXCHANGE ARE UNCHANGED (#583).
//
// The whole stack in a child process, over HTTP on 127.0.0.1:
//
//   1. `GET /tls`: 200, no-store, text/html; the shell — `/tls/pages.js`,
//      the card, the `<noscript>`, no server-drawn table — under a policy
//      that runs the script and keeps `frame-ancestors`, carrying the very
//      object `?format=json` answers (built on the same request), whether
//      the port is HTTPS, a CSRF token, and setting the page's cookie.
//      `?format=json` is still that object.
//   2. `GET /tls/forwarded` with forwarding and client-certificate headers:
//      the shell carrying them as THIS request sent them; `?format=json`
//      unchanged.
//   3. THE ACTS. A script's `POST /tls/trust` (raw PEM, no Origin) and
//      `POST /tls/trust/clear` are answered the JSON they always were; a
//      browser's (an Origin) is refused unless it is JSON (415,
//      STS-TLS-0049), from an origin of this service (403, STS-TLS-0050),
//      with the page's token (403, STS-TLS-0051) — and with all three it
//      is answered the same JSON. Neither answers a page any more.
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
//   6. The two scripts are served as JavaScript.
//   7. The renderers draw each kind of view, escaped.
//   8. The TLS runtime draws `/tls` from its shell in the browser's
//      language, asking for catalogs and nothing else; its "Trust these"
//      sends JSON with the page's token, and draws what the act answered.
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
    const ORIGIN = 'http://127.0.0.1:' + port;
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

    // --- 1. /tls -------------------------------------------------------------
    let r = await call('GET', '/tls', { cookie: '' });
    let state = stateOf(r.text);
    const json = await call('GET', '/tls?format=json');
    note(r.status === 200 &&
         /no-store/.test(String(r.headers['cache-control'])) &&
         /^text\/html/.test(String(r.headers['content-type'])) &&
         isShell(r, '/tls/pages.js') && policyOk(r),
         '1a. /tls is 200, no-store, the shell under a policy that runs ' +
         '/tls/pages.js and keeps frame-ancestors',
         r.status + ' ' + String(r.headers['content-security-policy']) + ' ' +
         r.text.slice(0, 300));
    note(state && state.view && state.view.kind === 'tls' &&
         typeof state.view.https === 'boolean' && json.json &&
         JSON.stringify(state.view.info.serverCertificate) ===
           JSON.stringify(json.json.serverCertificate) &&
         JSON.stringify(state.view.info.truststore) ===
           JSON.stringify(json.json.truststore) &&
         JSON.stringify(state.view.info.listeners) ===
           JSON.stringify(json.json.listeners) &&
         typeof state.view.info.revocation.sentence === 'string' &&
         json.json.kind === undefined,
         '1b. its state is the object ?format=json answers, which is ' +
         'unchanged', JSON.stringify(state && state.view.info.truststore));
    note(state && /^[A-Za-z0-9_-]{20,}$/.test(String(state.csrf)) &&
         (r.headers['set-cookie'] || []).some(function (c) {
           return /^sts_tls_page=[A-Za-z0-9_-]{40,};.*HttpOnly.*SameSite=Strict/
             .test(c);
         }),
         '1c. a development process\'s /tls carries a token, bound to the ' +
         'page\'s own HttpOnly, SameSite=Strict cookie',
         JSON.stringify(r.headers['set-cookie']));
    const csrf = state ? state.csrf : '';

    // --- 2. /tls/forwarded ---------------------------------------------------
    r = await call('GET', '/tls/forwarded',
                   { 'x-forwarded-proto': 'https<x>',
                     'x-client-cert': 'forged' });
    state = stateOf(r.text);
    const fjson = await call('GET', '/tls/forwarded?format=json',
                             { 'x-forwarded-proto': 'https<x>' });
    note(r.status === 200 && isShell(r, '/tls/pages.js') && policyOk(r) &&
         state && state.view.kind === 'forwarded' &&
         state.view.forwarding[0].value === 'https<x>' &&
         state.view.clientCertificateHeaders.seen.indexOf('x-client-cert') >=
           0 && state.csrf === undefined &&
         fjson.json && fjson.json.forwarding[0].value === 'https<x>' &&
         fjson.json.kind === undefined,
         '2. /tls/forwarded is the shell carrying the headers this request ' +
         'sent, with no token; ?format=json is unchanged',
         JSON.stringify(state && state.view.forwarding));

    // --- 3. the acts ---------------------------------------------------------
    const pem = (await call('GET', '/tls/server-certificate')).text
      .split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----\n';
    r = await call('POST', '/tls/trust', { 'content-type': 'text/plain' },
                   pem);
    note(r.status === 200 && r.json && typeof r.json.added === 'number' &&
         Array.isArray(r.json.subjects) && typeof r.json.note === 'string',
         '3a. a script\'s raw PEM is answered the JSON it always was',
         r.status + ' ' + r.text.slice(0, 200));
    r = await call('POST', '/tls/trust',
                   { 'content-type': 'application/x-www-form-urlencoded',
                     accept: 'text/html', origin: ORIGIN },
                   'certificates=' + encodeURIComponent(pem));
    note(r.status === 415 && r.json && /JSON/.test(r.json.error) &&
         !/<html/i.test(r.text),
         '3b. a browser\'s form is refused, 415, and answers no page',
         r.status + ' ' + r.text.slice(0, 200));
    r = await call('POST', '/tls/trust',
                   { 'content-type': 'application/json',
                     origin: 'https://elsewhere.example',
                     'x-csrf-token': csrf },
                   JSON.stringify({ certificates: pem }));
    note(r.status === 403 && r.json && /origin/.test(r.json.error),
         '3c. a browser\'s act from another origin is refused, 403',
         r.status + ' ' + r.text.slice(0, 200));
    r = await call('POST', '/tls/trust',
                   { 'content-type': 'application/json', origin: ORIGIN },
                   JSON.stringify({ certificates: pem }));
    note(r.status === 403 && r.json && /X-CSRF-Token/.test(r.json.error),
         '3d. a browser\'s act without the page\'s token is refused, 403',
         r.status + ' ' + r.text.slice(0, 200));
    r = await call('POST', '/tls/trust',
                   { 'content-type': 'application/json', origin: ORIGIN,
                     'x-csrf-token': csrf, cookie: 'sts_tls_page=' +
                     'A'.repeat(43) },
                   JSON.stringify({ certificates: pem }));
    note(r.status === 403,
         '3e. the token of another browser\'s cookie is refused, 403',
         r.status + ' ' + r.text.slice(0, 200));
    r = await call('POST', '/tls/trust',
                   { 'content-type': 'application/json', origin: ORIGIN,
                     'x-csrf-token': csrf },
                   JSON.stringify({ certificates: pem }));
    note(r.status === 200 && r.json && typeof r.json.anchors === 'number' &&
         r.json.anchors >= 1,
         '3f. a bound act is answered the same JSON',
         r.status + ' ' + r.text.slice(0, 200));
    r = await call('POST', '/tls/trust',
                   { 'content-type': 'application/json', origin: ORIGIN,
                     'x-csrf-token': csrf },
                   JSON.stringify({ certificates: 'not a certificate' }));
    note(r.status === 400 && r.json && typeof r.json.error === 'string' &&
         !/<html/i.test(r.text),
         '3g. a refused act is its 400 JSON, and no page',
         r.status + ' ' + r.text.slice(0, 200));
    r = await call('POST', '/tls/trust/clear',
                   { 'content-type': 'application/json', origin: ORIGIN },
                   '{}');
    note(r.status === 403, '3h. the clear is bound too',
         r.status + ' ' + r.text.slice(0, 200));
    r = await call('POST', '/tls/trust/clear',
                   { 'content-type': 'application/json', origin: ORIGIN,
                     'x-csrf-token': csrf, accept: 'text/html' }, '{}');
    note(r.status === 200 && r.json && typeof r.json.removed === 'number' &&
         r.json.anchors === 0,
         '3i. a bound clear is answered the JSON it always was, Accept ' +
         'text/html or not', r.status + ' ' + r.text.slice(0, 200));
    r = await call('POST', '/tls/trust/clear', { cookie: '' }, '');
    note(r.status === 200 && r.json && r.json.anchors === 0,
         '3j. a script\'s clear (no Origin) is answered as it always was',
         r.status + ' ' + r.text.slice(0, 200));

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
    for (const p of ['/tls/pages.js', '/spnego/pages.js']) {
      r = await call('GET', p);
      note(r.status === 200 &&
           /javascript/.test(String(r.headers['content-type'])) &&
           r.text.length > 0, '6. ' + p + ' is served as a script',
           r.status + ' ' + String(r.headers['content-type']));
    }

    // --- 7. the renderers ----------------------------------------------------
    const tlsViews = require(ROOT_DIR + '/tls/web_tls_views');
    const spnegoViews = require(ROOT_DIR + '/kerberos/web_spnego_views');
    const tlsT = translator(['tlsPages'], ['en']);
    const spT = translator(['spnegoPages'], ['en']);
    r = await call('GET', '/tls');
    const tlsState = stateOf(r.text);
    const drawn = tlsViews.render(tlsState.view, { t: tlsT });
    note(drawn.indexOf('<h1>A TLS endpoint lives here</h1>') === 0 &&
         drawn.indexOf('action="/tls/trust"') > 0 &&
         drawn.indexOf('action="/tls/trust/clear"') > 0 &&
         drawn.indexOf('<script') < 0,
         '7a. /tls draws from its state, with its two acts',
         drawn.slice(0, 300));
    const noActs = JSON.parse(JSON.stringify(tlsState.view));
    noActs.info.truststore.addUrl = null;
    noActs.info.truststore.clearUrl = null;
    note(tlsViews.render(noActs, { t: tlsT }).indexOf('<form') < 0,
         '7b. without the acts (a product process, #585) it draws no form');
    const refused = tlsViews.render({ kind: 'notAdded', act: 'trust',
                                      error: 'E <1> & "2"' }, { t: tlsT });
    note(refused.indexOf('<h1>Nothing was added</h1>') === 0 &&
         refused.indexOf('E &lt;1&gt; &amp; &quot;2&quot;') > 0,
         '7c. a refused act: English, escaped', refused);
    const added = tlsViews.render({ kind: 'trusted', added: 1, anchors: 2 },
                                  { t: tlsT });
    note(added.indexOf('<h1>1 anchor added</h1>') === 0 &&
         /2 anchors/.test(added), '7d. anchors added, pluralised', added);
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

    // --- 8. the TLS runtime --------------------------------------------------
    r = await call('GET', '/tls');
    const attrs = {};
    const tag = /<html([^>]*)>/.exec(r.text)[1];
    tag.replace(/ ([a-z-]+)="([^"]*)"/g, function (all, n, v) {
      attrs[n] = v.replace(/&quot;/g, '"').replace(/&#39;/g, "'")
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
      return all;
    });
    const asked = [];
    const sent = [];
    const loc = new URL(ORIGIN + '/tls');
    const env = {
      location: { pathname: loc.pathname, search: loc.search, hash: '',
                  href: loc.href, origin: ORIGIN,
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
        const headers = Object.assign({}, (init && init.headers) || {});
        if (init && init.method === 'POST') {
          sent.push({ path: u.pathname, headers: headers,
                      body: init.body });
          headers.origin = ORIGIN;
          headers.cookie = 'sts_tls_page=' + jar.sts_tls_page;
        }
        return fetch(ORIGIN + u.pathname + u.search,
                     Object.assign({}, init || {}, { headers: headers }));
      },
      formDataOf: function (form) {
        return form.fields;
      }
    };
    const Surface = require(ROOT_DIR + '/tls/web_tls_surface');
    const surface = new Surface(env);
    await surface.route();
    const page = env.document.body.innerHTML;
    note(/^<div class="card wide diag tls">/.test(page) &&
         page.indexOf('Un point de terminaison TLS se trouve ici') > 0 &&
         env.document.title === 'Point de terminaison TLS' &&
         asked.every(function (p) {
           return /^\/web\/locales\//.test(p);
         }) && asked.some(function (p) {
           return /^\/web\/locales\/tlsPages\//.test(p);
         }),
         '8a. the runtime draws /tls from the shell\'s state, in the ' +
         'browser\'s language, asking for catalogs and nothing else',
         JSON.stringify(asked) + ' ' + env.document.title + ' ' +
         page.slice(0, 300));
    const form = { fields: { certificates: pem },
                   getAttribute: function (n) {
                     return n === 'action' ? '/tls/trust' : null;
                   } };
    const realFields = surface.formFields;
    surface.formFields = function () {
      return { certificates: pem };
    };
    await surface.submit(form, null);
    surface.formFields = realFields;
    const after = env.document.body.innerHTML;
    note(sent.length === 1 && sent[0].path === '/tls/trust' &&
         sent[0].headers['Content-Type'] === 'application/json' &&
         sent[0].headers['X-CSRF-Token'] === tlsState.csrf &&
         JSON.parse(sent[0].body).certificates === pem &&
         /ancre ajoutée|ancres ajoutées/.test(after),
         '8b. "Trust these" sends JSON with the page\'s token and draws ' +
         'what the act answered', JSON.stringify(sent.map(function (s) {
           return { path: s.path, headers: s.headers };
         })) + ' ' + after.slice(0, 300));

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
  describe: 'the TLS and SPNEGO diagnostic pages are static surfaces\' ' +
            'shells; the truststore\'s acts answer JSON and a browser\'s is ' +
            'bound; the RFC 4559 exchange is unchanged (#583)',
  run: run
};
