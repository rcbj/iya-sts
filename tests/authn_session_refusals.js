'use strict';
//
// File: authn_session_refusals.js
//
// ===========================================================================
// A REFUSED SESSION IS ANSWERED, AND AN AUTHENTICATION EVENT SAYS WHERE IT
// CAME FROM (#62 P0, 2026-09-22).
//
// Two prerequisites of risk scoring, held here:
//
//   A. EVERY SIGN-IN SCREEN ANSWERS A REFUSED SESSION WITH A SCREEN.
//      `startSession()` refuses by returning null, and three callers ignored
//      it: the password door, the anonymous "continue" and the password
//      second factor. The password door then returned the browser to the
//      caller, whose request sent it straight back to the sign-in screen with
//      nothing said. The second-factor screens answered only a DISABLED
//      account. The risk decision will refuse at this same place, so every
//      refusal has to be answered. Measured with the refusal that is easiest
//      to cause from outside: a person with no directory entry and
//      `ldap.autocreateUsers` off (STS-AUTHN-0180). The screen that answers
//      must still be one a person can sign in from.
//   B. THE REFUSAL SAYS WHY on the caller's own `detail` — `refusedWith`, and
//      `refusedWhy` for the issuance policy.
//   C. THE EVENT'S CONTEXT: the address, the User-Agent's fingerprint (never
//      the header), the JA4 fingerprint, and the credential that answered (a
//      fingerprint of its id, never the id) — from the caller's request or
//      from the audit log's ambient one.
//
// In a child process, because it loads the whole stack and changes settings
// the rest of the in-process suite must not see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'authn_session_refusals',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SR_ROOT;
  const OUT = process.env.SR_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const partOf = function (jwt, n) {
    try {
      return JSON.parse(Buffer.from(String(jwt).split('.')[n], 'base64url')
        .toString('utf8'));
    } catch (e) {
      return { parseError: e.message };
    }
  };

  function browser(port, userAgent) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign({ 'user-agent': userAgent },
                                      o.headers || {});
        if (!o.noCookies && Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
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
            let parsed = null;
            try {
              parsed = JSON.parse(text);
            } catch (e) {
              parsed = { parseError: e.message };
            }
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, json: parsed });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }
  const hiddenFields = function (html) {
    const form = {};
    (html.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
      }
    });
    return form;
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const authn = require(ROOT + '/authn/authn');
    const gate = require(ROOT + '/common/issuance_gate');
    const credentials = require(ROOT + '/common/credentials');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const stsCrypto = require(ROOT + '/common/crypto');
    const clientHello = require(ROOT + '/tls/client_hello');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    config.setOverride('oauth2.consentRequired', false);

    const SECRET = 'session-refusals-secret-0123456789abcdef';
    const REDIRECT = 'https://rp.refusals.example/cb';
    const CLIENT = 'sr-client';
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const BOB = 'sr-bob';
    ldap.createUser(BOB, { invent: false });
    const GHOST = 'sr-ghost';
    const UA = 'session-refusals-probe/1.0';

    const authorize = function (b) {
      return b.go('GET', '/oauth2/authorize?' + new URLSearchParams({
        client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 's', nonce: 'n-' + Date.now() }).toString());
    };
    const submit = function (b, screenPath, form, username) {
      const sent = Object.assign({}, form, { username: username,
                                             password: 'anything',
                                             action: 'login' });
      return b.go('POST', screenPath, { form: sent });
    };
    const redeem = function (b, location) {
      const code = new URL(location).searchParams.get('code');
      return b.go('POST', '/oauth2/token', {
        noCookies: true,
        headers: { authorization: 'Basic ' +
          Buffer.from(CLIENT + ':' + SECRET).toString('base64') },
        form: { grant_type: 'authorization_code', code: code,
                redirect_uri: REDIRECT } });
    };

    // --- A. the password door answers a refused session ----------------------
    config.setOverride('ldap.autocreateUsers', false);
    const b = browser(port, UA);
    const start = await authorize(b);
    const screenAt = String(start.headers.location || '');
    const page = await b.go('GET', screenAt);
    const form = hiddenFields(page.text);
    const screenPath = screenAt.split('?')[0]
      .replace(/^https?:\/\/[^/]+/, '');
    const refused = await submit(b, screenPath, form, GHOST);
    note(refused.status === 200 &&
         /Authentication failed for sr-ghost/.test(refused.text),
         'A1. a session refused at the password door (no directory entry, ' +
         'STS-AUTHN-0180) is answered with the sign-in screen, not a ' +
         'redirect back to the caller', refused.status + ' ' +
         String(refused.headers.location || '') + ' ' +
         refused.text.slice(0, 160));
    note(!authn.sessionsOf(GHOST).length,
         'A2. and no session exists for them');
    const redrawn = hiddenFields(refused.text);
    note(redrawn.authn_id && redrawn.authn_id === form.authn_id,
         'A3. the screen is drawn for the SAME pending sign-in',
         JSON.stringify(redrawn));
    const after = await submit(b, screenPath, redrawn, BOB);
    // Back to the caller (a 303 to the authorization endpoint), which now
    // finds the session and answers the relying party.
    let finished = after;
    const hops = [after.status + ' ' + String(after.headers.location || '')];
    for (let i = 0; i < 3 && finished.status >= 300 && finished.status < 400 &&
         String(finished.headers.location || '').indexOf(REDIRECT) !== 0;
         i++) {
      finished = await b.go('GET', String(finished.headers.location));
      hops.push(finished.status + ' ' +
                String(finished.headers.location || ''));
    }
    const back = String(finished.headers.location || '');
    note(back.indexOf(REDIRECT) === 0 && /[?&]code=/.test(back),
         'A4. and a person can sign in from it — the pending sign-in was ' +
         'put back, so the redrawn form is not a dead end',
         hops.join(' -> '));
    config.setOverride('ldap.autocreateUsers', true);

    // --- C. what the event recorded about Bob's sign-in ----------------------
    let session = null;
    if (back.indexOf(REDIRECT) === 0) {
      const token = await redeem(b, back);
      const idToken = partOf((token.json && token.json.id_token) || '', 1);
      session = authn.sessionById(idToken.sid);
    }
    const first = session && session.events && session.events[0];
    const context = (first && first.context) || {};
    note(context.address === '127.0.0.1',
         'C1. the event records the address the sign-in came from',
         JSON.stringify(context));
    note(context.uaFingerprint === stsCrypto.userAgentFingerprint(UA) &&
         JSON.stringify(session).indexOf(UA) < 0,
         'C2. and a fingerprint of the User-Agent, never the header',
         context.uaFingerprint);
    note(context.credential && context.credential.kind === 'password' &&
         context.ja4 === '',
         'C3. and which credential answered (a password), with no JA4 on a ' +
         'plain-HTTP port', JSON.stringify(context.credential) + ' ja4=' +
         context.ja4);

    // THE SIGN-IN WAS ASSESSED FOR RISK (#62 P2), without the door waiting.
    const riskEngine = require(ROOT + '/risk/risk_engine');
    let assessed = null;
    for (let i = 0; i < 40 && !assessed && session; i++) {
      const view = await riskEngine.view('default', {});
      assessed = view.assessments.rows.filter(function (a) {
        return a.subject === session.user.sub;
      })[0] || null;
      if (!assessed) {
        await new Promise(function (r) { setTimeout(r, 50); });
      }
    }
    note(assessed && assessed.decision === 'observe' &&
         assessed.door && assessed.credentialKind === 'password',
         'C7. the sign-in was assessed for risk — observed, with its door ' +
         'and its credential — and decided nothing',
         JSON.stringify(assessed && { level: assessed.level,
                                      door: assessed.door }));

    // --- B and C, through startSession() directly ----------------------------
    const res = { set: function () { return res; },
                  append: function () { return res; },
                  status: function () { return res; },
                  type: function () { return res; },
                  send: function () { return res; },
                  req: null };
    const KEYED = 'sr-carol';
    ldap.createUser(KEYED, { invent: false });
    const keyDetail = { credential: { kind: 'webauthn',
                                      id: 'raw-credential-id-sr-carol',
                                      aaguid: 'adce0002-35bc-c60a-648b-' +
                                              '0b25f1f05503',
                                      backupEligible: true,
                                      backupState: false } };
    const keyed = authn.startSession(res, KEYED, ['hwk'], '1', 'a test',
                                     keyDetail);
    const keyedContext = (keyed && keyed.events[0].context) || {};
    const kc = keyedContext.credential || {};
    note(kc.kind === 'webauthn' &&
         kc.fingerprint === stsCrypto.credentialFingerprint(
           'raw-credential-id-sr-carol') &&
         kc.aaguid === 'adce0002-35bc-c60a-648b-0b25f1f05503' &&
         kc.backupEligible === true && kc.backupState === false,
         'C4. a security key\'s event names it by fingerprint, with its ' +
         'model (AAGUID) and its backup flags', JSON.stringify(kc));
    note(JSON.stringify(keyed).indexOf('raw-credential-id-sr-carol') < 0,
         'C5. and the credential id itself is nowhere on the session');

    const ambientReq = { headers: { 'user-agent': 'ambient-agent/2',
      [clientHello.FORWARD_HEADER]: Buffer.from(JSON.stringify({
        ja4: 't13d1516h2_8daaf6152771_e5627efa2ab1', version: '13',
        sni: 'x', alpn: ['h2'] })).toString('base64url') },
      socket: { remoteAddress: '192.0.2.44' }, ip: '192.0.2.44' };
    clientHello.adoptForwarded(ambientReq);
    const ambient = audit.withSource({ req: ambientReq }, function () {
      return authn.startSession(res, KEYED, ['pwd'], '1', 'a test', {});
    });
    const ac = (ambient && ambient.events[ambient.events.length - 1]
                  .context) || {};
    note(ac.uaFingerprint === stsCrypto.userAgentFingerprint(
           'ambient-agent/2') &&
         ac.ja4 === 't13d1516h2_8daaf6152771_e5627efa2ab1' &&
         ac.address === '192.0.2.44',
         'C6. a door that passes no request is described from the audit ' +
         'log\'s ambient one: address, User-Agent and JA4',
         JSON.stringify(ac));

    // --- B. the refusal says why ---------------------------------------------
    const DAVE = 'sr-dave';
    ldap.createUser(DAVE, { invent: false });
    credentials.setAccountDisabled(DAVE, true);
    const disabledDetail = {};
    const disabled = authn.startSession(res, DAVE, ['pwd'], '1', 'a test',
                                        disabledDetail);
    note(disabled === null && disabledDetail.refusedWith === 'STS-AUTHN-0201',
         'B1. a disabled account\'s refusal is STS-AUTHN-0201 on the ' +
         'caller\'s detail', JSON.stringify(disabledDetail));
    config.setOverride('ldap.autocreateUsers', false);
    const missingDetail = {};
    const missing = authn.startSession(res, 'sr-nobody', ['pwd'], '1',
                                       'a test', missingDetail);
    config.setOverride('ldap.autocreateUsers', true);
    note(missing === null && missingDetail.refusedWith === 'STS-AUTHN-0180',
         'B2. no directory entry is STS-AUTHN-0180',
         JSON.stringify(missingDetail));
    config.setOverride('roles.enforceIssuance', true);
    gate.setDecider(function () {
      return { allowed: false, decision: 'Deny', why: 'the test says no',
               roles: [], required: [], policy: null };
    });
    const policyDetail = { application: CLIENT };
    const policy = authn.startSession(res, BOB, ['pwd'], '1', 'a test',
                                      policyDetail);
    note(policy === null && policyDetail.refusedWith === 'STS-AUTHN-0010' &&
         policyDetail.refusedWhy === 'the test says no',
         'B3. the issuance policy\'s refusal is STS-AUTHN-0010, with its ' +
         'sentence as refusedWhy', JSON.stringify(policyDetail));

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
  const out = path.join(os.tmpdir(), 'session-refusals-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SR_ROOT: ROOT, SR_OUT: out }),
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
               String(result.stderr || '').slice(-1200))) {
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
  name: 'authn_session_refusals',
  describe: 'a refused session answered with a sign-in screen a person can ' +
            'use (#62 P0), the refusal\'s code and reason on the caller\'s ' +
            'detail, and the address, User-Agent fingerprint, JA4 and ' +
            'credential recorded on each authentication event',
  run: run
};
