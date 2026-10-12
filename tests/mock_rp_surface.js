// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/mock_rp_surface.js
// ===========================================================================
// THE MOCK RELYING PARTIES ARE ONE STATIC SURFACE, AND THEIR PROTOCOL DOORS
// ARE UNCHANGED (#581).
//
// The whole stack in a child process, over HTTP on 127.0.0.1:
//
//   1. THE SHELLS: `/wsfed/rp`, `/saml2/sp` and `/saml11/rp` answer the
//      shell — each family's own script, the card, the `<noscript>`, the
//      family named, no state — with `no-store` and a policy that keeps
//      `frame-ancestors`; each script is served under its own path.
//   2. THE START VIEWS mint as the pages did: a `wctx` the WS-Federation
//      relying party then recognises, four AuthnRequests (three signed,
//      each with its own RelayState), the two SAML 1.1 profiles' starts —
//      facts, and no words.
//   3. THE RECEIVING DOORS ARE UNCHANGED: a sign-in response this service
//      issued, POSTed to `/wsfed/rp`, is verified check by check — 200, the
//      verdict in the shell's state, no error code; the same response with
//      a `wctx` the mock never minted is 200 with STS-WSFED-0016 and the
//      failing check named; the cleanup request is the server-drawn page it
//      always was. `/saml2/sp` answers an artifact that does not resolve
//      (200, STS-SAML-0021) and a Response that fails its checks (200,
//      STS-SAML-0022) on GET and POST; `/saml11/rp` a spent artifact (400,
//      STS-SAML-0042) and a Browser/POST Response that fails (200,
//      STS-SAML-0043), with TARGET echoed.
//   4. THE COMPILED RENDERERS draw the views the API and the shells
//      answered.
//
// Product realms answering these paths as unrouted is
// `tests/demo_endpoints.js`'s, which lists every one of them.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'mock_rp_surface',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.MRS_ROOT;
  const OUT = process.env.MRS_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const wsfed = require(ROOT_DIR + '/ws-federation/wsfed');

    // The error code each answer was marked with, read off the response
    // object itself when it finishes — the code is recorded, never sent.
    const codes = [];
    const server = http.createServer(function (req, res) {
      res.on('finish', function () {
        codes.push(errorCodes.codeOf(res) || '');
      });
      app(req, res);
    });
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const ask = function (method, p, body, headers) {
      return new Promise(function (resolve) {
        const req = http.request({ host: '127.0.0.1', port: port,
          method: method, path: p,
          headers: Object.assign(body ? {
            'content-type': 'application/x-www-form-urlencoded',
            'content-length': Buffer.byteLength(body) } : {},
          headers || {}) }, function (res) {
          const chunks = [];
          res.on('data', function (c) {
            chunks.push(c);
          });
          res.on('end', function () {
            // The code of the answer just finished.
            setImmediate(function () {
              resolve({ status: res.statusCode, headers: res.headers,
                        body: Buffer.concat(chunks).toString('utf8'),
                        code: codes[codes.length - 1] || '' });
            });
          });
        });
        req.setTimeout(30000, function () {
          req.destroy(new Error('timed out'));
        });
        req.on('error', function (e) {
          resolve({ status: 0, headers: {}, body: 'error: ' + e.message,
                    code: '' });
        });
        if (body) {
          req.write(body);
        }
        req.end();
      });
    };
    const unescape = function (text) {
      return String(text).replace(/&quot;/g, '"').replace(/&#39;/g, '\'')
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    };
    const stateOf = function (answer) {
      const m = /data-sts-state="([^"]*)"/.exec(answer.body);
      if (!m) {
        return null;
      }
      try {
        return JSON.parse(unescape(m[1])).view;
      } catch (e) {
        return { unreadable: String(e && e.message) };
      }
    };
    const form = function (fields) {
      return new URLSearchParams(fields).toString();
    };
    const FAMILIES = { wsfed: '/wsfed/rp', saml2: '/saml2/sp',
                       saml11: '/saml11/rp' };

    // --- 1. the shells and the scripts ---------------------------------------
    for (const family of Object.keys(FAMILIES)) {
      const base = FAMILIES[family];
      const shell = await ask('GET', base);
      const csp = String(shell.headers['content-security-policy'] || '');
      note(shell.status === 200 &&
           shell.body.indexOf('<script src="' + base + '/mock-rp.js" ' +
                              'defer></script>') > 0 &&
           shell.body.indexOf('data-sts-mock-rp="' + family + '"') > 0 &&
           shell.body.indexOf('<noscript>') > 0 &&
           shell.body.indexOf('/web/card.css') > 0 &&
           shell.body.indexOf('class="card mockrp"') > 0 &&
           !/data-sts-state=/.test(shell.body) && !/<form/.test(shell.body) &&
           /no-store/.test(String(shell.headers['cache-control'])) &&
           /frame-ancestors/.test(csp) && /script-src 'self'/.test(csp),
           '1. ' + base + ' answers the shell: its own script, the card, ' +
           'the family, no state, no-store, frame-ancestors kept',
           shell.status + ' ' + csp + ' ' + shell.body.slice(0, 300));
      const script = await ask('GET', base + '/mock-rp.js');
      note(script.status === 200 &&
           /javascript/.test(String(script.headers['content-type'])),
           '1. ' + base + '/mock-rp.js is served', script.status + ' ' +
           script.headers['content-type']);
    }

    // --- 2. the start views --------------------------------------------------
    const wsStart = await ask('GET', '/wsfed/rp/api/start');
    let ws = {};
    try {
      ws = JSON.parse(wsStart.body).view || {};
    } catch (e) {
      ws = {};
    }
    note(wsStart.status === 200 && ws.kind === 'start' &&
         /^rp-/.test(String(ws.wctx)) && (ws.requests || []).length === 6 &&
         ws.requests.every(function (r) {
           return r.href.indexOf('/wsfed?wa=wsignin1.0&') === 0 &&
             r.href.indexOf('wctx=' + ws.wctx) > 0;
         }) && /\/wsfed\/rp$/.test(String(ws.realm)) &&
         /no-store/.test(String(wsStart.headers['cache-control'])) &&
         !/[A-Z][a-z]+ [a-z]+ [a-z]+ [a-z]+/.test(JSON.stringify(
           ws.requests)),
         '2. /wsfed/rp/api/start mints a wctx and answers the six sign-in ' +
         'requests as facts', wsStart.body.slice(0, 400));
    const spStart = await ask('GET', '/saml2/sp/api/start');
    let sp = {};
    try {
      sp = JSON.parse(spStart.body).view || {};
    } catch (e) {
      sp = {};
    }
    const spRequests = sp.requests || [];
    note(spStart.status === 200 && sp.kind === 'start' &&
         spRequests.length === 4 &&
         spRequests.filter(function (r) {
           return /[?&]Signature=/.test(r.href) && r.signed;
         }).length === 3 &&
         !/[?&]Signature=/.test(spRequests[3].href) &&
         spRequests.every(function (r) {
           return /\/saml2\/sso\?SAMLRequest=/.test(r.href) &&
             /&RelayState=sp-/.test(r.href);
         }) &&
         ['post', 'redirect', 'artifact', 'post'].join() ===
           spRequests.map(function (r) {
             return r.binding;
           }).join() && typeof sp.requiresSigned === 'boolean',
         '2. /saml2/sp/api/start answers four AuthnRequests, three signed, ' +
         'each with its own RelayState', spStart.body.slice(0, 400));
    const rpStart = await ask('GET', '/saml11/rp/api/start');
    let rp = {};
    try {
      rp = JSON.parse(rpStart.body).view || {};
    } catch (e) {
      rp = {};
    }
    note(rpStart.status === 200 && rp.kind === 'start' &&
         /profile=post$/.test(String(rp.post)) &&
         /profile=artifact$/.test(String(rp.artifact)) &&
         /\/saml11\/rp$/.test(String(rp.providerId)),
         '2. /saml11/rp/api/start answers the two profiles\' starts',
         rpStart.body.slice(0, 400));

    // --- 3. the receiving doors ---------------------------------------------
    // A sign-in response this service issues for the mock's realm, as
    // `/wsfed` would POST it, with the wctx the start view minted.
    const instance = new wsfed.WsFederation(
      wsfed.WsFederation.defaultDeps());
    const session = { id: 'mrs-session', authenticated: true,
                      authTime: Math.floor(Date.now() / 1000),
                      user: { username: 'mrs-alice' }, events: [] };
    const issued = { statusCode: 200, headers: {}, body: '', locals: {} };
    issued.status = function (n) {
      issued.statusCode = n;
      return issued;
    };
    issued.type = function () {
      return issued;
    };
    issued.set = function (k, v) {
      issued.headers[k] = v;
      return issued;
    };
    issued.setHeader = issued.set;
    issued.send = function (b) {
      issued.body = String(b);
      return issued;
    };
    instance.issueSignInResponse({}, issued,
      { wa: 'wsignin1.0', wtrealm: ws.realm, wctx: ws.wctx }, session,
      ws.realm, ws.realm, wsfed.SAML2_TOKEN_TYPE);
    const m = /name="wresult" value="([^"]*)"/.exec(issued.body);
    const wresult = m ? unescape(m[1]) : '';
    note(!!wresult, '3. the identity provider issued a sign-in response ' +
         'for the mock\'s realm', issued.body.slice(0, 300));
    const good = await ask('POST', '/wsfed/rp',
      form({ wa: 'wsignin1.0', wresult: wresult, wctx: ws.wctx }));
    const goodView = stateOf(good) || {};
    note(good.status === 200 && good.code === '' &&
         goodView.kind === 'result' && goodView.ok === true &&
         goodView.subject !== '' && (goodView.claims || []).length > 0 &&
         goodView.document === wresult &&
         (goodView.checks || []).every(function (c) {
           return c.ok;
         }) && good.body.indexOf('/wsfed/rp/mock-rp.js') > 0,
         '3. POST /wsfed/rp verifies a response this service issued: 200, ' +
         'no code, every check passed, the verdict in the shell',
         good.status + ' ' + good.code + ' ' +
         JSON.stringify(goodView).slice(0, 500));
    const replayed = await ask('POST', '/wsfed/rp',
      form({ wa: 'wsignin1.0', wresult: wresult, wctx: 'rp-never-minted' }));
    const replayedView = stateOf(replayed) || {};
    note(replayed.status === 200 && replayed.code === 'STS-WSFED-0016' &&
         replayedView.ok === false &&
         (replayedView.checks || []).some(function (c) {
           return c.name === 'wctx came back unaltered' && !c.ok;
         }),
         '3. a wctx the mock never minted: 200, STS-WSFED-0016, the ' +
         'failing check named', replayed.status + ' ' + replayed.code + ' ' +
         JSON.stringify(replayedView.checks || []).slice(0, 400));
    const cleanup = await ask('GET', '/wsfed/rp?wa=wsignoutcleanup1.0');
    note(cleanup.status === 200 && /Cleanup received/.test(cleanup.body) &&
         cleanup.body.indexOf('mock-rp.js') < 0,
         '3. the cleanup request is answered as it always was, server-drawn',
         cleanup.status + ' ' + cleanup.body.slice(0, 200));

    const unresolved = await ask('GET', '/saml2/sp?SAMLart=AAQAAnot-issued');
    const unresolvedView = stateOf(unresolved) || {};
    note(unresolved.status === 200 && unresolved.code === 'STS-SAML-0021' &&
         unresolvedView.kind === 'unresolved' && !!unresolvedView.why,
         '3. /saml2/sp: an artifact that does not resolve is 200 with ' +
         'STS-SAML-0021, the reason in the shell', unresolved.status + ' ' +
         unresolved.code + ' ' + JSON.stringify(unresolvedView));
    const bogus = Buffer.from('<samlp:Response xmlns:samlp="urn:oasis:' +
      'names:tc:SAML:2.0:protocol"/>').toString('base64');
    const posted = await ask('POST', '/saml2/sp',
      form({ SAMLResponse: bogus, RelayState: 'sp-not-minted' }));
    const postedView = stateOf(posted) || {};
    note(posted.status === 200 && posted.code === 'STS-SAML-0022' &&
         postedView.kind === 'result' && postedView.ok === false &&
         postedView.arrived === 'post' &&
         (postedView.checks || []).length > 0,
         '3. /saml2/sp: a Response that fails its checks, POSTed, is 200 ' +
         'with STS-SAML-0022 and the checks in the shell', posted.status +
         ' ' + posted.code + ' ' + JSON.stringify(postedView).slice(0, 300));

    const spent = await ask('GET', '/saml11/rp?SAMLart=AAEnot-issued&' +
                                   'TARGET=t1');
    const spentView = stateOf(spent) || {};
    note(spent.status === 400 && spent.code === 'STS-SAML-0042' &&
         spentView.kind === 'spent',
         '3. /saml11/rp: a spent artifact is still 400 with STS-SAML-0042',
         spent.status + ' ' + spent.code + ' ' + JSON.stringify(spentView));
    const response11 = Buffer.from('<samlp:Response xmlns:samlp="urn:oasis:' +
      'names:tc:SAML:1.0:protocol"/>').toString('base64');
    const post11 = await ask('POST', '/saml11/rp',
      form({ SAMLResponse: response11, TARGET: 'the <target> & co' }));
    const post11View = stateOf(post11) || {};
    note(post11.status === 200 && post11.code === 'STS-SAML-0043' &&
         post11View.kind === 'result' && post11View.profile === 'post' &&
         post11View.target === 'the <target> & co' &&
         post11View.ok === false &&
         post11View.total === (post11View.checks || []).length,
         '3. /saml11/rp: a Browser/POST Response that fails is 200 with ' +
         'STS-SAML-0043, TARGET echoed', post11.status + ' ' + post11.code +
         ' ' + JSON.stringify(post11View).slice(0, 300));

    // --- 4. the compiled renderers draw what was answered --------------------
    const Pages = require(ROOT_DIR + '/common/web_mock_rp_pages');
    const messages = require(ROOT_DIR + '/common/web_messages');
    const own = JSON.parse(fs.readFileSync(ROOT_DIR +
                                           '/common/locales/mockRp/en.json'));
    const flat = {};
    Object.keys(own).forEach(function (k) {
      flat['mockRp.' + k] = own[k];
    });
    const t = messages.WebTranslator.fromData({ catalogs: { en: flat },
      negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                    direction: 'ltr', matched: true } });
    const ctx = { t: t, query: {} };
    const drawnStart = Pages.render('/wsfed/rp', ws, ctx);
    const drawnGood = Pages.render('/wsfed/rp', goodView, ctx);
    const drawnSp = Pages.render('/saml2/sp', sp, ctx);
    const drawnSpent = Pages.render('/saml11/rp', spentView, ctx);
    note(/Mock relying party/.test(drawnStart) &&
         drawnStart.indexOf(ws.wctx) > 0 &&
         /Sign-in response received/.test(drawnGood) &&
         /Every check passed/.test(drawnGood) &&
         (drawnSp.match(/href="\/[^"]*saml2\/sso\?SAMLRequest=/g) || [])
           .length === 4 &&
         /ALREADY BEEN RESOLVED/.test(drawnSpent) &&
         !/mockRp\./.test(drawnStart + drawnGood + drawnSp + drawnSpent),
         '4. the compiled renderers draw the start views and the verdicts',
         drawnStart.slice(0, 200) + ' | ' + drawnGood.slice(0, 200));

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
  const out = path.join(os.tmpdir(), 'mrs-' + process.pid + '-' +
                        Date.now() + '.json');
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
                                  MRS_ROOT: ROOT, MRS_OUT: out }),
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
  name: 'mock_rp_surface',
  describe: 'The mock relying parties are one static surface: the shells, ' +
            'the scripts and start views under each family\'s own path, ' +
            'the receiving doors\' statuses and codes unchanged, the ' +
            'verdict carried in the shell, and the compiled renderers',
  run: run
};
