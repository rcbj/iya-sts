// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wsfed_initiation.js
//
// ===========================================================================
// WHO MAY START A WS-FEDERATION SIGN-IN (#426, #712).
//
// `GET /wsfed/initiate/{rp}` (or `?wtrealm=`) is this identity provider
// starting a sign-in to a relying party that did not ask; `wa=wsignin1.0` at
// `/wsfed` is the relying party starting one. Each has a switch, a realm
// setting with a per-application override (#710), and the first is OFF until
// an application opts in. `ws-federation/wsfed.ts` (`initiate()`) argues the
// rules. Held here, in a child process on an ephemeral loopback port, over
// HTTP with a cookie jar:
//
//   a. the link is refused 403 (STS-WSFED-0025) for a registered relying
//      party with no override, the realm setting being off by default; a
//      relying party nobody registered is 404 (STS-WSFED-0024);
//   b. with wsfedIdpInitiatedSso TRUE on the entry, a wreply is refused
//      (STS-WSFED-0026), and a relying party with no registered reply
//      address is refused (STS-WSFED-0027);
//   c. with no session the link goes to the sign-in screen and comes back to
//      itself; the response then POSTs to the REGISTERED wsfedReplyUrl, wctx
//      byte for byte, and the session records the realm the way `/logout`
//      reads it (`cleanupTargetsFor()`);
//   d. the `?wtrealm=` form answers the same on a session that exists;
//   e. the realm setting turned on opens the link for an entry with no
//      override, and an entry's FALSE still closes it;
//   f. a wsignin1.0 for an entry with wsfedSpInitiatedSso FALSE is refused
//      403 (STS-WSFED-0028), and one for an entry without it is answered;
//   g. a denial on risk naming a second factor sends the person to sign in
//      again with the factor demanded and the one-trip marker on the return
//      (STS-RISK-0017), and a request carrying the marker that is still
//      denied is refused 403 (STS-WSFED-0029). The risk is put on the
//      session object directly — what a MEDIUM assessment at the sign-in
//      would have left there — rather than produced by scoring, which
//      `tests/risk_decisions.js` holds.
//
// AND g AGAIN IN PRODUCT MODE (#715), in the same child, `global.mode`
// overridden and cleared afterwards: a person made with a real password,
// a wrong one refused at the screen, the right one signing in, then g1-g3
// under the labels "g1 (product)" and on. a-f run in product over the wire
// instead, in `tests/protocol/sts_idp_initiated_wsfed.js`; g is here because
// HTTP cannot put a risk on a session. The comment above that pass says what
// product changes for it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'wsfed_initiation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Run in a child process as a string (`node -e`), so it carries no
// Entering/Leaving pairs: the code style exempts a `node -e` child.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WI_ROOT;
  const OUT = process.env.WI_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };

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

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');
    const app = require(ROOT + '/common/app');
    const audit = require(ROOT + '/common/audit');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const authn = require(ROOT + '/authn/authn');
    const wsfed = require(ROOT + '/ws-federation/wsfed');
    // For g's product pass (#715): a person made on purpose, with a password.
    const ldap = require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    // INVENTED FIXTURES: the identifiers, the reply addresses and the
    // username below name nothing outside this test.
    const RP_PLAIN = 'urn:wsfed-initiation:plain';
    const RP_OPEN = 'urn:wsfed-initiation:open';
    const RP_NOREPLY = 'urn:wsfed-initiation:no-reply';
    const RP_CLOSED = 'urn:wsfed-initiation:closed';
    const RP_IDP_ONLY = 'urn:wsfed-initiation:idp-only';
    const REPLY_PLAIN = 'https://plain.wsfed-initiation.example/wsfed';
    const REPLY_OPEN = 'https://open.wsfed-initiation.example/wsfed';
    const REPLY_CLOSED = 'https://closed.wsfed-initiation.example/wsfed';
    const REPLY_IDP_ONLY = 'https://idp-only.wsfed-initiation.example/wsfed';
    const USER = 'wi-alice';
    // A wctx with bytes a careless pass would change: a space, an ampersand,
    // an equals sign, a percent sign and a non-ASCII letter.
    const WCTX = 'rm=0&id=passive ru=%2Fhome é';

    const made = [
      applications.createApplication({ identifier: RP_PLAIN,
        protocols: ['wsfed'], fields: { wsfedReplyUrl: [REPLY_PLAIN] } }),
      applications.createApplication({ identifier: RP_OPEN,
        protocols: ['wsfed'],
        fields: { wsfedReplyUrl: [REPLY_OPEN],
                  wsfedIdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: RP_NOREPLY,
        protocols: ['wsfed'], fields: { wsfedIdpInitiatedSso: 'TRUE' } }),
      applications.createApplication({ identifier: RP_CLOSED,
        protocols: ['wsfed'],
        fields: { wsfedReplyUrl: [REPLY_CLOSED],
                  wsfedIdpInitiatedSso: 'FALSE' } }),
      applications.createApplication({ identifier: RP_IDP_ONLY,
        protocols: ['wsfed'],
        fields: { wsfedReplyUrl: [REPLY_IDP_ONLY],
                  wsfedIdpInitiatedSso: 'TRUE',
                  wsfedSpInitiatedSso: 'FALSE' } })
    ];
    note(made.every(function (one) { return one && one.ok; }),
         '0. (the five relying parties are registered)',
         JSON.stringify(made).slice(0, 400));

    const link = function (rp, query) {
      const q = new URLSearchParams(query || {}).toString();
      return '/wsfed/initiate/' + encodeURIComponent(rp) + (q ? '?' + q : '');
    };
    const refusedWith = async function (code) {
      await sleep(50);
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    // The hidden inputs and action of the section 13.2.2 form, decoded.
    const unescape = function (s) {
      return String(s).replace(/&quot;/g, '"').replace(/&#39;/g, '\'')
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&');
    };
    const formOf = function (r) {
      const action = /<form method="post" action="([^"]*)"/.exec(r.text);
      const wctx = /<input type="hidden" name="wctx" value="([^"]*)"/
        .exec(r.text);
      return { action: action ? unescape(action[1]) : null,
               wctx: wctx ? unescape(wctx[1]) : null,
               wresult: /name="wresult"/.test(r.text) };
    };

    // --- a. off by default, and registered only ------------------------------
    const anon = browser(port);
    let r = await anon.go('GET', link(RP_PLAIN));
    note(r.status === 403 && await refusedWith('STS-WSFED-0025'),
         'a1. the link is REFUSED 403 for a registered relying party with ' +
         'no override: wsfed.idpInitiatedSso is off by default ' +
         '(STS-WSFED-0025)', r.status);
    r = await anon.go('GET', link('urn:wsfed-initiation:nobody'));
    note(r.status === 404 && await refusedWith('STS-WSFED-0024'),
         'a2. a relying party nobody registered is 404 (STS-WSFED-0024)',
         r.status);
    r = await anon.go('GET', link(RP_CLOSED));
    note(r.status === 403,
         'a3. an entry\'s wsfedIdpInitiatedSso FALSE refuses it too',
         r.status);

    // --- b. the wreply and the registered reply address ----------------------
    r = await anon.go('GET', link(RP_OPEN,
                                  { wreply: 'https://evil.example/wsfed' }));
    note(r.status === 400 && await refusedWith('STS-WSFED-0026') &&
         r.text.indexOf('evil.example') < 0,
         'b1. with wsfedIdpInitiatedSso TRUE, a wreply on the link is ' +
         'REFUSED 400 (STS-WSFED-0026), not followed', r.status);
    r = await anon.go('GET', link(RP_OPEN, { wreply: '' }));
    note(r.status === 400,
         'b2. an EMPTY wreply is refused too — the parameter, not its value',
         r.status);
    r = await anon.go('GET', link(RP_NOREPLY));
    note(r.status === 400 && await refusedWith('STS-WSFED-0027'),
         'b3. a relying party with no registered wsfedReplyUrl is refused ' +
         '(STS-WSFED-0027)', r.status);

    // --- c. the sign-in, and the response to the registered address ----------
    const alice = browser(port);
    const first = await alice.go('GET', link(RP_OPEN, { wctx: WCTX }));
    const location = String(first.headers.location || '');
    note(first.status === 303 && /\/authn\/login/.test(location),
         'c1. with no session the link goes to the sign-in screen (303)',
         first.status + ' ' + location);
    const page = await authnScreen.open({ port: port, jar: alice.jar,
                                          at: location });
    const posted = await authnScreen.follow({ port: port, jar: alice.jar,
      opened: page, fields: { action: 'login', username: USER,
                              password: 'anything' } });
    const back = String((posted.headers || {}).location || '')
      .replace(/^https?:\/\/[^/]+/, '');
    note(back.indexOf('/wsfed/initiate/' + encodeURIComponent(RP_OPEN)) === 0,
         'c2. the sign-in returns to the link itself', back);
    const answered = back ? await alice.go('GET', back) : posted;
    const form = formOf(answered);
    note(answered.status === 200 && form.wresult &&
         form.action === REPLY_OPEN,
         'c3. the sign-in response is a form POST to the REGISTERED ' +
         'wsfedReplyUrl', answered.status + ' ' + form.action);
    note(form.wctx === WCTX,
         'c4. wctx comes back byte for byte', JSON.stringify(form.wctx));
    const session = authn.sessionsOf(USER)[0];
    const targets = session ? wsfed.cleanupTargetsFor(session) : [];
    note(session && session.wsfedRealms &&
         session.wsfedRealms[RP_OPEN] === REPLY_OPEN &&
         targets.some(function (one) {
           return one.realm === RP_OPEN && one.wreply === REPLY_OPEN;
         }),
         'c5. the session records the realm and its reply address, and the ' +
         'cleanup list `/logout` reads names it',
         JSON.stringify(targets));

    // --- d. the ?wtrealm= form, on a session that exists ---------------------
    r = await alice.go('GET', '/wsfed/initiate?' + new URLSearchParams(
      { wtrealm: RP_OPEN, wctx: 'second' }).toString());
    note(r.status === 200 && formOf(r).action === REPLY_OPEN &&
         formOf(r).wctx === 'second',
         'd1. /wsfed/initiate?wtrealm= answers at once on a live session, ' +
         'to the same registered address', r.status + ' ' + formOf(r).action);

    // --- e. the realm switch, and an entry's override over it ----------------
    config.setOverride('wsfed.idpInitiatedSso', true);
    r = await alice.go('GET', link(RP_PLAIN));
    note(r.status === 200 && formOf(r).action === REPLY_PLAIN,
         'e1. wsfed.idpInitiatedSso on opens the link for an entry with no ' +
         'override', r.status + ' ' + formOf(r).action);
    r = await alice.go('GET', link(RP_CLOSED));
    note(r.status === 403,
         'e2. and an entry\'s wsfedIdpInitiatedSso FALSE still closes it',
         r.status);
    config.clearOverride('wsfed.idpInitiatedSso');

    // --- f. the relying party's own wsignin1.0 -------------------------------
    const signInUrl = function (rp, reply) {
      return '/wsfed?' + new URLSearchParams({ wa: 'wsignin1.0', wtrealm: rp,
        wreply: reply, wctx: 'sp' }).toString();
    };
    r = await alice.go('GET', signInUrl(RP_IDP_ONLY, REPLY_IDP_ONLY));
    note(r.status === 403 && await refusedWith('STS-WSFED-0028'),
         'f1. a wsignin1.0 for an entry with wsfedSpInitiatedSso FALSE is ' +
         'refused 403 (STS-WSFED-0028)', r.status);
    r = await alice.go('GET', signInUrl(RP_PLAIN, REPLY_PLAIN));
    note(r.status === 200 && formOf(r).action === REPLY_PLAIN,
         'f2. one for an entry without it is answered (on by default)',
         r.status);
    r = await alice.go('GET', link(RP_IDP_ONLY));
    note(r.status === 200 && formOf(r).action === REPLY_IDP_ONLY,
         'f3. and the identity-provider-initiated link still signs in to ' +
         'the relying party whose own start is off', r.status);

    // --- g. a step-up on risk, once ------------------------------------------
    config.setOverride('risk.enforceInDevelopment', true);
    const held = authn.sessionsOf(USER)[0];
    held.risk = { level: 'MEDIUM', score: 2, signals: ['tor-exit'],
                  assessmentId: 'wi-g' };
    r = await alice.go('GET', link(RP_OPEN, { wctx: 'risk' }));
    // The return address is held server-side on the pending record the
    // screen's URL names, so the record is read for it.
    const stepTo = String(r.headers.location || '');
    let record = null;
    new URL(stepTo, 'http://127.0.0.1').searchParams.forEach(function (v) {
      record = record || authn.pendingFor(v);
    });
    note(r.status === 303 && /\/authn\/login/.test(stepTo) && record &&
         /sts_risk_retry=1/.test(String(record.returnTo)) &&
         String(record.returnTo).indexOf('/wsfed/initiate/') === 0 &&
         record.forceMfa === true &&
         await refusedWith('STS-RISK-0017'),
         'g1. a denial on risk naming a second factor sends the person to ' +
         'sign in again with the factor demanded, back to the link with the ' +
         'one-trip marker (STS-RISK-0017)',
         r.status + ' ' + JSON.stringify(record && { returnTo:
           record.returnTo, forceMfa: record.forceMfa }));
    r = await alice.go('GET', link(RP_OPEN, { wctx: 'risk',
                                              sts_risk_retry: '1' }));
    note(r.status === 403 && await refusedWith('STS-WSFED-0029'),
         'g2. a request carrying the marker that is still denied is ' +
         'refused 403 rather than sent round again (STS-WSFED-0029)',
         r.status);
    r = await alice.go('GET', signInUrl(RP_PLAIN, REPLY_PLAIN));
    note(r.status === 403 && await refusedWith('STS-WSFED-0011'),
         'g3. the relying party\'s own wsignin1.0 is unchanged: refused on ' +
         'risk (STS-WSFED-0011), no step-up', r.status);
    delete held.risk;
    config.clearOverride('risk.enforceInDevelopment');

    // --- g, again, in PRODUCT mode (#715) ------------------------------------
    // The one section HTTP cannot set up — a session's risk comes from
    // scoring against datasets the suite does not load — so it runs a
    // second time here, in product, as `tests/scim_auth_discovery.js` does
    // (`global.mode` overridden for the process, cleared in the `finally`).
    // `tests/protocol/sts_idp_initiated_wsfed.js` holds a-f in product over
    // the wire. What product changes for g, and how each is met:
    //
    //   * it CHECKS PASSWORDS and creates nobody because a sign-in named
    //     them, so the person is made beforehand, in development as
    //     `tests/public_clients_product.js` makes its fixtures, with the
    //     attributes the realm's attribute policy (#396) requires in product,
    //     and a real password — and a wrong one is refused first (g0b);
    //   * risk is ENFORCED rather than observed, so no
    //     `risk.enforceInDevelopment` is needed — and scoring is turned off
    //     for the sign-in only (`risk.assessSignIns`), because this child's
    //     http client is an automated one product scores on its own terms,
    //     and the risk g is about is the one put on the session below. It is
    //     turned back on before g1: with it off the issuance policy is handed
    //     no risk at all (`RiskEngine.factsOf()`);
    //   * every relying party here is already registered with its reply
    //     address, which is what product requires of both doors.
    //
    // Each refusal's code is counted before and after, because the
    // development pass above already left one of each in the log.
    const PERSON_P = 'wi-paula';
    const PASSWORD_P = 'wsfed-initiation-Product-7!' +
      require('crypto').randomBytes(6).toString('hex');
    const codeCount = async function (code) {
      await sleep(50);
      return audit.list().filter(function (row) {
        return row.errorCode === code;
      }).length;
    };
    ldap.createUser(PERSON_P, { invent: false, attributes: {
      cn: 'Paula Product', givenName: 'Paula', sn: 'Product',
      mail: 'paula@wsfed-initiation.example' } });
    credentials.setPassword(PERSON_P, PASSWORD_P);
    config.setOverride('global.mode', 'product');
    config.setOverride('risk.assessSignIns', false);
    try {
      note(config.value('global.mode') === 'product',
           'g0 (product). (the process is in product mode)',
           config.value('global.mode'));
      const wrongly = browser(port);
      const wrongAt = String((await wrongly.go('GET', link(RP_OPEN, {
        wctx: 'product' }))).headers.location || '');
      const wrong = await authnScreen.submit({ port: port, jar: wrongly.jar,
        at: wrongAt, fields: { action: 'login', username: PERSON_P,
                               password: PASSWORD_P + '-not' } });
      note(/\/authn\/login/.test(wrongAt) && wrong.next !== 'redirect' &&
           authn.sessionsOf(PERSON_P).length === 0,
           'g0b (product). a wrong password at the screen the link sends a ' +
           'person to is refused, and no session is made',
           wrongAt + ' ' + wrong.next);
      const paula = browser(port);
      const startAt = String((await paula.go('GET', link(RP_OPEN, {
        wctx: 'product' }))).headers.location || '');
      const signed = await authnScreen.submit({ port: port, jar: paula.jar,
        at: startAt, fields: { action: 'login', username: PERSON_P,
                               password: PASSWORD_P } });
      const returned = String(signed.location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      const issued = returned ? await paula.go('GET', returned) : signed;
      note(issued.status === 200 && formOf(issued).action === REPLY_OPEN &&
           formOf(issued).wctx === 'product',
           'g0c (product). with the real password the person is signed in ' +
           'and the link answers, to the registered address',
           signed.next + ' ' + issued.status + ' ' + formOf(issued).action);
      config.clearOverride('risk.assessSignIns');

      const heldP = authn.sessionsOf(PERSON_P)[0];
      if (heldP) {
        heldP.risk = { level: 'MEDIUM', score: 2, signals: ['tor-exit'],
                       assessmentId: 'wi-g-product' };
      }
      let before = await codeCount('STS-RISK-0017');
      r = await paula.go('GET', link(RP_OPEN, { wctx: 'risk' }));
      const stepToP = String(r.headers.location || '');
      let recordP = null;
      new URL(stepToP, 'http://127.0.0.1').searchParams.forEach(function (v) {
        recordP = recordP || authn.pendingFor(v);
      });
      note(heldP && r.status === 303 && /\/authn\/login/.test(stepToP) &&
           recordP &&
           /sts_risk_retry=1/.test(String(recordP.returnTo)) &&
           String(recordP.returnTo).indexOf('/wsfed/initiate/') === 0 &&
           recordP.forceMfa === true &&
           await codeCount('STS-RISK-0017') > before,
           'g1 (product). a denial on risk naming a second factor sends the ' +
           'person to sign in again with the factor demanded, back to the ' +
           'link with the one-trip marker (STS-RISK-0017)',
           r.status + ' ' + JSON.stringify(recordP && { returnTo:
             recordP.returnTo, forceMfa: recordP.forceMfa }));
      before = await codeCount('STS-WSFED-0029');
      r = await paula.go('GET', link(RP_OPEN, { wctx: 'risk',
                                                sts_risk_retry: '1' }));
      note(r.status === 403 && await codeCount('STS-WSFED-0029') > before,
           'g2 (product). a request carrying the marker that is still ' +
           'denied is refused 403 rather than sent round again ' +
           '(STS-WSFED-0029)', r.status);
      before = await codeCount('STS-WSFED-0011');
      r = await paula.go('GET', signInUrl(RP_PLAIN, REPLY_PLAIN));
      note(r.status === 403 && await codeCount('STS-WSFED-0011') > before,
           'g3 (product). the relying party\'s own wsignin1.0 is unchanged: ' +
           'refused on risk (STS-WSFED-0011), no step-up', r.status);
      if (heldP) {
        delete heldP.risk;
      }
    } finally {
      config.clearOverride('risk.assessSignIns');
      config.clearOverride('global.mode');
    }

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'wsfed-initiation-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', WI_ROOT: ROOT, WI_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
  name: 'wsfed_initiation',
  describe: 'WS-Federation: /wsfed/initiate/{rp} is off until a relying ' +
            'party opts in, refuses a wreply, posts only to the registered ' +
            'reply address with wctx intact and records the realm for ' +
            '/logout, steps up once on risk (in development and again in ' +
            'product); wsignin1.0 obeys wsfed.spInitiatedSso',
  run: run
};
