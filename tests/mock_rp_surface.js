// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/mock_rp_surface.js
// ===========================================================================
// THE MOCK RELYING PARTIES ARE ONE STATIC SURFACE (#581), AND THEY ANSWER AS
// REAL RELYING PARTIES DO (#590).
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
//   3. THE RECEIVING DOORS ANSWER AS A REAL RELYING PARTY'S (#590): a
//      sign-in response this service issued, POSTed to `/wsfed/rp`, is a
//      303 to the application page with the relying party's own cookie
//      (HttpOnly, SameSite=Lax, Path=/wsfed/rp, Max-Age its lifetime, no
//      Secure over plain HTTP), and `/wsfed/rp/api/session` answers the
//      verdict with it — and nothing without it. A refusal keeps its status
//      and code (`STS-WSFED-0016`; `/saml2/sp`'s unresolved artifact 200
//      STS-SAML-0021 and failing Response 200 STS-SAML-0022; `/saml11/rp`'s
//      spent artifact 400 STS-SAML-0042 and failing Browser/POST 200
//      STS-SAML-0043), opens no session and is read once, leaving an
//      earlier session signed in. A second sign-in rotates the session; the
//      cleanup image and the relying party's own sign-out end it; in a
//      realm the 303 and the Path carry the prefix and the session is the
//      realm's. The SAML 2.0 service provider ends the session an identity
//      provider's LogoutRequest names and answers it with a signed
//      LogoutResponse (Requester and STS-SAML-0111 for one that fails),
//      sends a signed LogoutRequest from its own sign-out, and holds a
//      LogoutResponse it never asked for as STS-SAML-0110.
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
    const realms = require(ROOT_DIR + '/common/realms');

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
          // THE NAME OUTSIDE A REQUEST: the response below is issued with
          // no request in hand, where this realm's issuer is its default
          // base, so every request names that host too and the relying
          // party's issuer check compares like with like.
          headers: Object.assign({ host: 'localhost:8081' }, body ? {
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

    // --- 3. the receiving doors: a real relying party's answers (#590) -------
    // A cookie jar of one name per family: what a browser would send back.
    const cookieOf = function (answer, family) {
      const lines = [].concat(answer.headers['set-cookie'] || []);
      const mine = lines.filter(function (l) {
        return l.indexOf('sts_mockrp_' + family + '=') === 0;
      });
      return mine.length ? mine[mine.length - 1] : '';
    };
    const valueOf = function (line) {
      return String(line).split(';')[0];
    };
    const sessionOf = async function (base, cookie, prefix) {
      const answer = await ask('GET', (prefix || '') + base + '/api/session',
                               null, cookie ? { cookie: cookie } : {});
      let json = {};
      try {
        json = JSON.parse(answer.body);
      } catch (e) {
        json = { unreadable: String(e && e.message) };
      }
      return { answer: answer, view: json.view || null, json: json };
    };
    // A sign-in response this service issues for the mock's realm, as
    // `/wsfed` would POST it, with the wctx the start view minted.
    const instance = new wsfed.WsFederation(
      wsfed.WsFederation.defaultDeps());
    const issue = function (realm, wctx) {
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
        { wa: 'wsignin1.0', wtrealm: realm, wctx: wctx }, session,
        realm, realm, wsfed.SAML2_TOKEN_TYPE);
      const m = /name="wresult" value="([^"]*)"/.exec(issued.body);
      return m ? unescape(m[1]) : '';
    };
    const wresult = issue(ws.realm, ws.wctx);
    note(!!wresult, '3. the identity provider issued a sign-in response ' +
         'for the mock\'s realm', wresult.slice(0, 200));
    const good = await ask('POST', '/wsfed/rp',
      form({ wa: 'wsignin1.0', wresult: wresult, wctx: ws.wctx }));
    const goodCookie = cookieOf(good, 'wsfed');
    note(good.status === 303 && good.code === '' &&
         good.headers.location === '/wsfed/rp' &&
         /no-store/.test(String(good.headers['cache-control'])) &&
         good.body.indexOf('mrs-alice') < 0 &&
         !/data-sts-state/.test(good.body),
         '3. POST /wsfed/rp with a response that passes: 303 to the ' +
         'application page, no code, no verdict in the answer',
         good.status + ' ' + good.code + ' ' + good.headers.location);
    note(/^sts_mockrp_wsfed=[A-Za-z0-9_-]{20,};/.test(goodCookie) &&
         /; Path=\/wsfed\/rp;/.test(goodCookie) &&
         /; Max-Age=900;/.test(goodCookie) && /; HttpOnly/.test(goodCookie) &&
         /; SameSite=Lax/.test(goodCookie) && !/Secure/.test(goodCookie),
         '3. the relying party\'s own cookie: HttpOnly, SameSite=Lax, ' +
         'Path=/wsfed/rp, Max-Age the session lifetime, not Secure over ' +
         'plain HTTP', goodCookie);
    const jar = valueOf(goodCookie);
    const read1 = await sessionOf('/wsfed/rp', jar);
    const goodView = read1.view || {};
    note(read1.answer.status === 200 &&
         /no-store/.test(String(read1.answer.headers['cache-control'])) &&
         goodView.kind === 'result' && goodView.ok === true &&
         goodView.subject !== '' && (goodView.claims || []).length > 0 &&
         goodView.document === wresult && goodView.session &&
         goodView.session.signedIn === true &&
         goodView.session.signOut === '/wsfed/rp/sign-out' &&
         (goodView.checks || []).every(function (c) {
           return c.ok;
         }),
         '3. GET /wsfed/rp/api/session with that cookie answers the ' +
         'verdict: every check passed, signed in', read1.answer.body
           .slice(0, 300));
    const read2 = await sessionOf('/wsfed/rp', jar);
    const noCookie = await sessionOf('/wsfed/rp', '');
    const otherFamily = await sessionOf('/saml2/sp',
      jar.replace('sts_mockrp_wsfed', 'sts_mockrp_saml2'));
    note(read2.view && read2.view.ok === true && noCookie.view === null &&
         otherFamily.view === null,
         '3. the session answers for as long as it lives; without the ' +
         'cookie, or under another family\'s name, there is none',
         JSON.stringify([!!read2.view, noCookie.view, otherFamily.view]));

    // A REFUSAL keeps its status and code, opens no session, and is held
    // once — on the live session the browser has, which it leaves signed in.
    const replayed = await ask('POST', '/wsfed/rp',
      form({ wa: 'wsignin1.0', wresult: wresult, wctx: 'rp-never-minted' }),
      { cookie: jar });
    const refusedRead = await sessionOf('/wsfed/rp', jar);
    const refusedView = refusedRead.view || {};
    const afterRefusal = await sessionOf('/wsfed/rp', jar);
    note(replayed.status === 200 && replayed.code === 'STS-WSFED-0016' &&
         !/data-sts-state/.test(replayed.body) &&
         replayed.body.indexOf('/wsfed/rp/mock-rp.js') > 0 &&
         !cookieOf(replayed, 'wsfed') &&
         refusedView.ok === false && refusedView.session &&
         refusedView.session.signedIn === true &&
         (refusedView.checks || []).some(function (c) {
           return c.name === 'wctx came back unaltered' && !c.ok;
         }) && afterRefusal.view && afterRefusal.view.ok === true,
         '3. a wctx the mock never minted: 200, STS-WSFED-0016, the shell; ' +
         'the page reads the failing check once, and the earlier session ' +
         'is still signed in', replayed.status + ' ' + replayed.code + ' ' +
         JSON.stringify(refusedView.checks || []).slice(0, 300));
    const stranger = await ask('POST', '/wsfed/rp',
      form({ wa: 'wsignin1.0', wresult: wresult, wctx: 'rp-never-minted' }));
    const strangerJar = valueOf(cookieOf(stranger, 'wsfed'));
    const strangerRead = await sessionOf('/wsfed/rp', strangerJar);
    const strangerAgain = await sessionOf('/wsfed/rp', strangerJar);
    note(stranger.status === 200 && stranger.code === 'STS-WSFED-0016' &&
         !!strangerJar && strangerRead.view &&
         strangerRead.view.ok === false &&
         strangerRead.view.session.signedIn === false &&
         strangerAgain.view === null &&
         /Max-Age=0/.test(String(strangerRead.answer.headers['set-cookie'])),
         '3. a refusal to a browser with no session: held on a session of ' +
         'its own, read once, then gone and its cookie cleared',
         JSON.stringify(strangerRead.view || {}).slice(0, 200));

    // THE FRONT CHANNEL: the identity provider's cleanup image ends it.
    const cleanup = await ask('GET', '/wsfed/rp?wa=wsignoutcleanup1.0', null,
                              { cookie: jar });
    const afterCleanup = await sessionOf('/wsfed/rp', jar);
    note(cleanup.status === 200 && /Cleanup received/.test(cleanup.body) &&
         /ended its own session/.test(cleanup.body) &&
         cleanup.body.indexOf('mock-rp.js') < 0 &&
         /Max-Age=0/.test(cookieOf(cleanup, 'wsfed')) &&
         afterCleanup.view === null,
         '3. wsignoutcleanup1.0 ends the relying party\'s session and ' +
         'clears its cookie, server-drawn as it always was',
         cleanup.status + ' ' + cleanup.body.slice(0, 200));

    // ITS OWN SIGN-OUT: a second sign-in, then the relying party's sign-out,
    // which goes on to the identity provider's wsignout1.0.
    const ws2Start = await ask('GET', '/wsfed/rp/api/start');
    let ws2 = {};
    try {
      ws2 = JSON.parse(ws2Start.body).view || {};
    } catch (e) {
      ws2 = {};
    }
    const second = await ask('POST', '/wsfed/rp',
      form({ wa: 'wsignin1.0', wresult: issue(ws2.realm, ws2.wctx),
             wctx: ws2.wctx }), { cookie: jar });
    const jar2 = valueOf(cookieOf(second, 'wsfed'));
    const rotatedOld = await sessionOf('/wsfed/rp', jar);
    const signOut = await ask('POST', '/wsfed/rp/sign-out', '',
                              { cookie: jar2 });
    const afterSignOut = await sessionOf('/wsfed/rp', jar2);
    note(second.status === 303 && jar2 && jar2 !== jar &&
         rotatedOld.view === null && signOut.status === 303 &&
         /^\/wsfed\?wa=wsignout1\.0&wreply=/.test(
           String(signOut.headers.location)) &&
         /Max-Age=0/.test(cookieOf(signOut, 'wsfed')) &&
         afterSignOut.view === null,
         '3. a second sign-in rotates the session; POST /wsfed/rp/sign-out ' +
         'ends it, clears the cookie and goes on to wsignout1.0',
         second.status + ' ' + signOut.status + ' ' +
         signOut.headers.location);

    // PER REALM: the cookie is scoped to the realm's path, and the default
    // realm's session is not another realm's.
    realms.create({ id: 'mrsacme', name: 'mrsacme',
                    overrides: { 'global.mode': 'development' } });
    const acmeStart = await ask('GET', '/realm/mrsacme/wsfed/rp/api/start');
    let acme = {};
    try {
      acme = JSON.parse(acmeStart.body).view || {};
    } catch (e) {
      acme = {};
    }
    const acmeGood = await ask('POST', '/realm/mrsacme/wsfed/rp',
      form({ wa: 'wsignin1.0', wresult: realms.run(realms.get('mrsacme'),
        function () {
          return issue(acme.realm, acme.wctx);
        }), wctx: acme.wctx }));
    const acmeCookie = cookieOf(acmeGood, 'wsfed');
    const acmeJar = valueOf(acmeCookie);
    const acmeRead = await sessionOf('/wsfed/rp', acmeJar, '/realm/mrsacme');
    const crossRead = await sessionOf('/wsfed/rp', acmeJar);
    note(acmeGood.status === 303 &&
         acmeGood.headers.location === '/realm/mrsacme/wsfed/rp' &&
         /; Path=\/realm\/mrsacme\/wsfed\/rp;/.test(acmeCookie) &&
         acmeRead.view && acmeRead.view.ok === true &&
         crossRead.view === null,
         '3. in a realm: the 303 and the cookie\'s Path carry its prefix, ' +
         'and its session is not the default realm\'s',
         acmeGood.status + ' ' + acmeGood.headers.location + ' ' +
         acmeCookie + ' ' + JSON.stringify(acmeRead.view || {})
           .slice(0, 120));

    // SAML 2.0: the refusals keep their statuses and codes.
    const unresolved = await ask('GET', '/saml2/sp?SAMLart=AAQAAnot-issued');
    const unresolvedView = (await sessionOf('/saml2/sp',
      valueOf(cookieOf(unresolved, 'saml2')))).view || {};
    note(unresolved.status === 200 && unresolved.code === 'STS-SAML-0021' &&
         !/data-sts-state/.test(unresolved.body) &&
         unresolvedView.kind === 'unresolved' && !!unresolvedView.why,
         '3. /saml2/sp: an artifact that does not resolve is 200 with ' +
         'STS-SAML-0021; the page reads the reason from the session',
         unresolved.status + ' ' + unresolved.code + ' ' +
         JSON.stringify(unresolvedView));
    const bogus = Buffer.from('<samlp:Response xmlns:samlp="urn:oasis:' +
      'names:tc:SAML:2.0:protocol"/>').toString('base64');
    const posted = await ask('POST', '/saml2/sp',
      form({ SAMLResponse: bogus, RelayState: 'sp-not-minted' }));
    const postedView = (await sessionOf('/saml2/sp',
      valueOf(cookieOf(posted, 'saml2')))).view || {};
    note(posted.status === 200 && posted.code === 'STS-SAML-0022' &&
         postedView.kind === 'result' && postedView.ok === false &&
         postedView.arrived === 'post' &&
         (postedView.checks || []).length > 0,
         '3. /saml2/sp: a Response that fails its checks, POSTed, is 200 ' +
         'with STS-SAML-0022 and the checks in the session', posted.status +
         ' ' + posted.code + ' ' + JSON.stringify(postedView).slice(0, 300));

    // SAML 2.0 SINGLE LOGOUT AT THE SERVICE PROVIDER. A session is opened
    // in process (what a Response that passed opens), and the identity
    // provider's own LogoutRequest for it is delivered the way its sign-out
    // pages link it.
    const MockRp = require(ROOT_DIR + '/common/mock_rp_surface');
    const saml2 = require(ROOT_DIR + '/saml/saml2_sso');
    const zlib = require('zlib');
    const seeded = function (subject, sessionIndex) {
      const out = { lines: [] };
      out.append = function (name, line) {
        out.lines.push(line);
      };
      MockRp.open({ headers: {}, secure: false }, out, 'saml2', {
        signedIn: { kind: 'result', family: 'saml2', ok: true,
                    subject: subject, checks: [] },
        subject: subject, nameIdFormat: '', sessionIndex: sessionIndex });
      return valueOf(out.lines[0]);
    };
    const idp = new saml2.Saml2Sso(saml2.Saml2Sso.defaultDeps());
    const spBase = 'http://localhost:8081';
    const spEntity = spBase + '/saml2/sp';
    const logoutLink = function (issuer, subject, sessionIndex) {
      const xml = idp.buildLogoutRequest(issuer, spEntity, subject, '',
                                         sessionIndex, spEntity);
      const url = idp.redirectUrlFor(spEntity, 'SAMLRequest', xml, 'rs-590',
                                     spEntity);
      return { url: url.slice(spBase.length),
               id: (/ ID="([^"]+)"/.exec(xml) || [])[1] };
    };
    const inflate = function (location, field) {
      const u = new URL(location, spBase);
      return zlib.inflateRawSync(Buffer.from(u.searchParams.get(field),
                                             'base64')).toString('utf8');
    };
    const bobJar = seeded('mrs-bob', 'idx-bob');
    const carolJar = seeded('mrs-carol', 'idx-carol');
    const link = logoutLink(idp.idpEntityId(), 'mrs-bob', 'idx-bob');
    const slo = await ask('GET', link.url, null, { cookie: bobJar });
    const sloAnswer = slo.headers.location ? inflate(slo.headers.location,
                                                     'SAMLResponse') : '';
    const bobAfter = await sessionOf('/saml2/sp', bobJar);
    const carolAfter = await sessionOf('/saml2/sp', carolJar);
    note(slo.status === 303 && slo.code === '' &&
         /^http:\/\/localhost:8081\/saml2\/slo\?SAMLResponse=/.test(
           String(slo.headers.location)) &&
         /[?&]RelayState=rs-590&/.test(String(slo.headers.location)) &&
         /[?&]Signature=/.test(String(slo.headers.location)) &&
         /<samlp:LogoutResponse /.test(sloAnswer) &&
         sloAnswer.indexOf('InResponseTo="' + link.id + '"') > 0 &&
         /status:Success"/.test(sloAnswer) &&
         /Max-Age=0/.test(cookieOf(slo, 'saml2')) &&
         bobAfter.view === null && carolAfter.view &&
         carolAfter.view.ok === true,
         '3. /saml2/sp: the identity provider\'s LogoutRequest ends the ' +
         'session it names (and no other) and is answered with a signed ' +
         'Success LogoutResponse to its Single Logout service',
         slo.status + ' ' + slo.code + ' ' + sloAnswer.slice(0, 300));
    const forged = logoutLink('https://not-this-idp.example', 'mrs-carol',
                              'idx-carol');
    const forgedAnswer = await ask('GET', forged.url, null,
                                   { cookie: carolJar });
    const forgedXml = forgedAnswer.headers.location
      ? inflate(forgedAnswer.headers.location, 'SAMLResponse') : '';
    const carolStill = await sessionOf('/saml2/sp', carolJar);
    note(forgedAnswer.status === 303 &&
         forgedAnswer.code === 'STS-SAML-0111' &&
         /status:Requester"/.test(forgedXml) && carolStill.view &&
         carolStill.view.ok === true,
         '3. /saml2/sp: a LogoutRequest that fails its checks ends nothing, ' +
         'STS-SAML-0111, and is answered Requester',
         forgedAnswer.status + ' ' + forgedAnswer.code + ' ' +
         forgedXml.slice(0, 200));
    const strayResponse = '<samlp:LogoutResponse xmlns:samlp="urn:oasis:' +
      'names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
      'assertion" ID="_x" Version="2.0" IssueInstant="' +
      new Date().toISOString() + '" InResponseTo="_never"><saml:Issuer>' +
      idp.idpEntityId() + '</saml:Issuer><samlp:Status><samlp:StatusCode ' +
      'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
      '</samlp:LogoutResponse>';
    const stray = await ask('GET', '/saml2/sp?SAMLResponse=' +
      encodeURIComponent(zlib.deflateRawSync(Buffer.from(strayResponse))
        .toString('base64')) + '&RelayState=sp-not-minted');
    const strayView = (await sessionOf('/saml2/sp',
      valueOf(cookieOf(stray, 'saml2')))).view || {};
    note(stray.status === 303 && stray.code === 'STS-SAML-0110' &&
         stray.headers.location === '/saml2/sp' &&
         strayView.kind === 'signedOut' && strayView.ok === false &&
         (strayView.checks || []).some(function (c) {
           return /InResponseTo/.test(c.name) && !c.ok;
         }),
         '3. /saml2/sp: a LogoutResponse to a request it never sent is ' +
         'STS-SAML-0110, and the page reads the failing check once',
         stray.status + ' ' + stray.code + ' ' +
         JSON.stringify(strayView).slice(0, 300));
    const sp2Out = await ask('POST', '/saml2/sp/sign-out', '',
                             { cookie: carolJar });
    const sp2Request = sp2Out.headers.location
      ? inflate(sp2Out.headers.location, 'SAMLRequest') : '';
    note(sp2Out.status === 303 &&
         /^http:\/\/localhost:8081\/saml2\/slo\?SAMLRequest=/.test(
           String(sp2Out.headers.location)) &&
         /[?&]Signature=/.test(String(sp2Out.headers.location)) &&
         /<saml:Issuer>http:\/\/localhost:8081\/saml2\/sp<\/saml:Issuer>/
           .test(sp2Request) && /mrs-carol<\/saml:NameID>/.test(sp2Request) &&
         /<samlp:SessionIndex>idx-carol</.test(sp2Request) &&
         (await sessionOf('/saml2/sp', carolJar)).view === null,
         '3. POST /saml2/sp/sign-out ends the session and sends a signed ' +
         'LogoutRequest naming it to the identity provider (SP-initiated ' +
         'Single Logout)', sp2Out.status + ' ' + sp2Request.slice(0, 300));

    // SAML 1.1: the spent artifact keeps its 400.
    const spent = await ask('GET', '/saml11/rp?SAMLart=AAEnot-issued&' +
                                   'TARGET=t1');
    const spentView = (await sessionOf('/saml11/rp',
      valueOf(cookieOf(spent, 'saml11')))).view || {};
    note(spent.status === 400 && spent.code === 'STS-SAML-0042' &&
         !/data-sts-state/.test(spent.body) && spentView.kind === 'spent',
         '3. /saml11/rp: a spent artifact is still 400 with STS-SAML-0042; ' +
         'the page reads it from the session',
         spent.status + ' ' + spent.code + ' ' + JSON.stringify(spentView));
    const response11 = Buffer.from('<samlp:Response xmlns:samlp="urn:oasis:' +
      'names:tc:SAML:1.0:protocol"/>').toString('base64');
    const post11 = await ask('POST', '/saml11/rp',
      form({ SAMLResponse: response11, TARGET: 'the <target> & co' }));
    const post11View = (await sessionOf('/saml11/rp',
      valueOf(cookieOf(post11, 'saml11')))).view || {};
    note(post11.status === 200 && post11.code === 'STS-SAML-0043' &&
         post11View.kind === 'result' && post11View.profile === 'post' &&
         post11View.target === 'the <target> & co' &&
         post11View.ok === false &&
         post11View.total === (post11View.checks || []).length,
         '3. /saml11/rp: a Browser/POST Response that fails is 200 with ' +
         'STS-SAML-0043, TARGET echoed in the session', post11.status + ' ' +
         post11.code + ' ' + JSON.stringify(post11View).slice(0, 300));
    const out11 = await ask('POST', '/saml11/rp/sign-out', '');
    note(out11.status === 303 && out11.headers.location === '/saml11/rp',
         '3. POST /saml11/rp/sign-out with nothing held goes back to the page',
         out11.status + ' ' + out11.headers.location);

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
    const drawnOut = Pages.render('/saml2/sp', strayView, ctx);
    note(/Mock relying party/.test(drawnStart) &&
         drawnStart.indexOf(ws.wctx) > 0 &&
         /Sign-in response received/.test(drawnGood) &&
         /Every check passed/.test(drawnGood) &&
         /<form method="post" action="\/wsfed\/rp\/sign-out">/
           .test(drawnGood) &&
         (drawnSp.match(/href="[^"]*\/saml2\/sso\?SAMLRequest=/g) || [])
           .length === 4 &&
         /ALREADY BEEN RESOLVED/.test(drawnSpent) &&
         /Signed out/.test(drawnOut) &&
         !/mockRp\./.test(drawnStart + drawnGood + drawnSp + drawnSpent +
                          drawnOut),
         '4. the compiled renderers draw the start views, the verdicts with ' +
         'the session\'s sign-out, and the sign-out\'s outcome',
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
  describe: 'The mock relying parties are one static surface whose ' +
            'receiving doors answer as real relying parties: a 303 and a ' +
            'session of their own, the verdict read from it, refusals\' ' +
            'statuses and codes kept, sign-out and logout ending it, and ' +
            'the compiled renderers',
  run: run
};
