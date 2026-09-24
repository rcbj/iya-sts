'use strict';
//
// File: wsfed_wauth_step_up.js
//
// ===========================================================================
// WS-FEDERATION `wauth` AS A STEP-UP (2026-09-17, #36).
//
// A `wauth` demanding a hardware token or multi-factor authentication, on a
// session that does not have it, was refused 400 (STS-WSFED-0009 / 0010).
// It is a step-up now, through the same two pieces RFC 9470 uses at the
// authorization endpoint — `beginAuthentication({ forceMfa })` and the
// `step_up_honoured` marker on the return — and the two refusals remain only
// for a demand still unmet after that one attempt. `ws-federation/wsfed.ts`
// argues it. Held here, in a child process on an ephemeral loopback port:
//
//   a. a password `wauth` on a one-factor session is answered at once;
//   b. a MULTI-FACTOR `wauth` on a one-factor session is sent to sign in
//      again — not refused — with the second factor demanded on the screen
//      and the marker on the return; a one-time code there yields an
//      assertion whose AuthenticationMethod is multipleauthn;
//   c. a HARDWARE `wauth` on that two-factor session (a one-time code, no
//      key) is sent to sign in again too — and since 2026-09-17 the screen
//      DEMANDS THE KEY (`forceKey`): the one-time code door refuses
//      (STS-AUTHN-0204), a person who holds a second factor and no key is
//      told so, and a demand still unmet on the way back is STS-WSFED-0009;
//   g. a real WebAuthn ceremony — a software authenticator built here, as
//      `tests/webauthn_session.js` does — meets the demand BOTH ways: a
//      passwordless key alone, and a key as the second factor after a
//      password. `step_up.screenDemandFor()` is the same mechanism the
//      authorization endpoint's key aliases use;
//   d. a forged marker on a first request gets the refusal (0010), not a pass
//      and not a loop;
//   e. with no session at all the demand still requires the second factor
//      and carries the marker;
//   f. an unknown `wauth` is refused as before (0006);
//   h. a one-time code posted at the second-factor door under the demand is
//      refused; i. `step_up.screenDemandFor()` is what both protocols read.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'wsfed_wauth_step_up',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WA_ROOT;
  const OUT = process.env.WA_OUT;
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
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign({}, o.headers || {});
        if (Object.keys(jar).length) {
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
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }
  // ---------------------------------------------------------------------
  // A SOFTWARE AUTHENTICATOR, `tests/webauthn_session.js`'s, built here for
  // the same reason it is built there: what is under test is the SERVER's
  // half of the ceremony, and producing the bytes a real authenticator
  // produces is the honest way to reach it. Enough CBOR for one attestation
  // object and a P-256 signature.
  // ---------------------------------------------------------------------
  const nodeCrypto = require('crypto');
  const sha256 = function (buf) {
    return nodeCrypto.createHash('sha256').update(buf).digest();
  };
  const cborBytes = function (buf) {
    const head = buf.length < 24 ? Buffer.from([0x40 + buf.length])
      : Buffer.concat([Buffer.from([0x58]), Buffer.from([buf.length])]);
    return Buffer.concat([head, buf]);
  };
  const cborText = function (text) {
    const body = Buffer.from(text, 'utf8');
    return Buffer.concat([Buffer.from([0x60 + body.length]), body]);
  };
  const cborMapHeader = function (n) {
    return Buffer.from([0xa0 + n]);
  };
  const cborInt = function (n) {
    return Buffer.from([n]);
  };
  const cborNegInt = function (n) {
    return Buffer.from([0x20 + (Math.abs(n) - 1)]);
  };
  const coseKey = function (jwk) {
    return Buffer.concat([
      cborMapHeader(5),
      cborInt(0x01), cborInt(0x02),
      cborInt(0x03), cborNegInt(-7),
      cborNegInt(-1), cborInt(0x01),
      cborNegInt(-2), cborBytes(Buffer.from(jwk.x, 'base64url')),
      cborNegInt(-3), cborBytes(Buffer.from(jwk.y, 'base64url'))
    ]);
  };
  const makeAuthenticator = function (rpId, origin) {
    const pair = nodeCrypto.generateKeyPairSync('ec',
                                                { namedCurve: 'prime256v1' });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const credentialId = nodeCrypto.randomBytes(32);
    let signCount = 0;
    const authData = function (opts) {
      const count = Buffer.alloc(4);
      count.writeUInt32BE(opts.signCount >>> 0, 0);
      const parts = [sha256(Buffer.from(rpId, 'utf8')),
                     Buffer.from([opts.flags]), count];
      if (opts.attested) {
        const idLen = Buffer.alloc(2);
        idLen.writeUInt16BE(credentialId.length, 0);
        parts.push(Buffer.alloc(16), idLen, credentialId, coseKey(jwk));
      }
      return Buffer.concat(parts);
    };
    const clientData = function (type, challenge) {
      return Buffer.from(JSON.stringify({ type: type, challenge: challenge,
                                          origin: origin,
                                          crossOrigin: false }), 'utf8');
    };
    return {
      credentialId: credentialId.toString('base64url'),
      register: function (challenge) {
        const data = authData({ flags: 0x45, signCount: signCount,
                                attested: true });
        const length = Buffer.alloc(2);
        length.writeUInt16BE(data.length, 0);
        const attestationObject = Buffer.concat([
          cborMapHeader(3),
          cborText('fmt'), cborText('none'),
          cborText('attStmt'), cborMapHeader(0),
          cborText('authData'),
          Buffer.concat([Buffer.from([0x59]), length, data])
        ]);
        return { id: credentialId.toString('base64url'),
                 rawId: credentialId.toString('base64url'),
                 type: 'public-key',
                 response: {
                   attestationObject: attestationObject.toString('base64url'),
                   clientDataJSON: clientData('webauthn.create', challenge)
                     .toString('base64url') } };
      },
      assert: function (challenge) {
        signCount += 1;
        const data = authData({ flags: 0x05, signCount: signCount });
        const cdj = clientData('webauthn.get', challenge);
        const signature = nodeCrypto.sign(
          'sha256', Buffer.concat([data, sha256(cdj)]), pair.privateKey);
        return { id: credentialId.toString('base64url'),
                 rawId: credentialId.toString('base64url'),
                 type: 'public-key',
                 response: {
                   authenticatorData: data.toString('base64url'),
                   clientDataJSON: cdj.toString('base64url'),
                   signature: signature.toString('base64url') } };
      }
    };
  };
  const dataAttribute = function (html, name) {
    const found = new RegExp(' data-' + name + '="([^"]*)"').exec(html);
    return found ? found[1].replace(/&amp;/g, '&') : '';
  };

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
    const audit = require(ROOT + '/common/audit');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');

    const config = require(ROOT + '/common/config');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    // Three one-time codes are spent below, each for a LATER 30-second step
    // than the last — a code for an earlier step than one already spent is a
    // replay — and two steps of skew keeps all three inside the window.
    config.setOverride('totp.window', 2);

    const REALM = 'urn:wauth-step-up:rp';
    const MFA = 'http://schemas.microsoft.com/claims/multipleauthn';
    const KEY = 'urn:oasis:names:tc:SAML:1.0:am:HardwareToken';
    const PASSWORD = 'urn:oasis:names:tc:SAML:1.0:am:password';
    const signInUrl = function (extra) {
      return '/wsfed?' + new URLSearchParams(Object.assign({
        wa: 'wsignin1.0', wtrealm: REALM, wctx: 'ctx-1' },
        extra || {})).toString();
    };
    const toSignIn = function (r) {
      return (r.status === 302 || r.status === 303) &&
             /\/authn\/login/.test(String(r.headers.location || ''));
    };
    // The screen as a person uses it, answering every hop. `code` is the
    // one-time code for the second-factor screen, when it is shown.
    const signIn = async function (b, first, username, code) {
      const page = await b.go('GET', first.headers.location);
      const form = hiddenFields(page.text);
      form.username = username;
      form.password = 'anything';
      form.action = 'login';
      const screen = String(first.headers.location).split('?')[0]
        .replace(/^https?:\/\/[^/]+/, '');
      let posted = await b.go('POST', screen, { form: form });
      let totpPage = null;
      if (code && posted.status === 200 && /name="mfa_id"/.test(posted.text)) {
        totpPage = posted;
        const mfaId = (posted.text.match(/name="mfa_id" value="([^"]+)"/) ||
                       [])[1];
        posted = await b.go('POST', '/authn/totp',
                            { form: { mfa_id: mfaId, code: code } });
      }
      const back = String(posted.headers.location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      const final = back ? await b.go('GET', back) : posted;
      return { page: page, posted: posted, totpPage: totpPage, back: back,
               final: final };
    };
    const assertionSays = function (r, method) {
      return r.status === 200 && /wresult/.test(r.text) &&
             r.text.indexOf(method) >= 0;
    };
    const refusedWith = async function (code) {
      await sleep(50);
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };

    // --- a. a one-factor session, and a password demand ----------------------
    const alice = browser(port);
    let first = await alice.go('GET', signInUrl());
    note(toSignIn(first), 'a0. (no session: to the sign-in screen)',
         first.status + ' ' + first.headers.location);
    let done = await signIn(alice, first, 'wa-alice');
    note(done.final.status === 200 && /wresult/.test(done.final.text),
         'a0b. (a password sign-in answers the relying party)',
         done.final.status);
    let r = await alice.go('GET', signInUrl({ wauth: PASSWORD }));
    note(assertionSays(r, PASSWORD),
         'a1. a password wauth on a one-factor session is answered at once',
         r.status + ' ' + r.text.slice(0, 120));

    // --- b. multi-factor: a step-up, not a refusal ---------------------------
    const began = credentials.beginTotpEnrolment('wa-alice');
    const t0 = Date.now();
    const confirmed = began.ok
      ? credentials.confirmTotpEnrolment('wa-alice',
                                         totp.codeAt(began.secret, t0))
      : began;
    note(began.ok && confirmed.ok, 'b0. (wa-alice enrols an authenticator ' +
         'app)', JSON.stringify(confirmed).slice(0, 200));
    first = await alice.go('GET', signInUrl({ wauth: MFA }));
    note(toSignIn(first),
         'b1. a MULTI-FACTOR wauth on a one-factor session is SENT TO SIGN ' +
         'IN AGAIN, not refused 400',
         first.status + ' ' + (first.headers.location || first.text
                                                                .slice(0, 200)));
    done = await signIn(alice, first, 'wa-alice',
                        totp.codeAt(began.secret, t0 + 30000));
    note(/step_up_honoured=1/.test(done.back),
         'b2. the return address carries the one-attempt marker', done.back);
    note(/id="use_webauthn"[^>]*checked disabled/.test(done.page.text),
         'b3. the sign-in screen demands the second factor', '');
    note(done.totpPage !== null, 'b4. and asks for the one-time code',
         done.posted.status);
    note(assertionSays(done.final, MFA),
         'b5. the stepped-up sign-in answers the relying party with ' +
         'AuthenticationMethod multipleauthn — what actually happened',
         done.final.status + ' ' + done.final.text.slice(0, 200));
    r = await alice.go('GET', signInUrl({ wauth: MFA }));
    note(assertionSays(r, MFA),
         'b6. the same demand on the two-factor session is now met at once',
         r.status);

    // --- c. hardware: the screen demands the KEY -----------------------------
    first = await alice.go('GET', signInUrl({ wauth: KEY }));
    note(toSignIn(first),
         'c1. a HARDWARE wauth on a session that used a code and no key is ' +
         'sent to sign in again', first.status + ' ' + first.headers.location);
    const keyScreen = await alice.go('GET', first.headers.location);
    note(/id="use_webauthn"[^>]*checked disabled/.test(keyScreen.text) &&
         /id="webauthn_only"/.test(keyScreen.text) &&
         !/id="webauthn_only"[^>]*disabled/.test(keyScreen.text) &&
         /demands a security key/.test(keyScreen.text),
         'c2. and the screen offers EXACTLY the two choices that meet it — ' +
         'the key alone (passwordless, not disabled) or the key after a ' +
         'password (checked and disabled) — and says so',
         (keyScreen.text.match(/<label class="chk">[\s\S]{0,240}/g) ||
          []).join(' | ').slice(0, 400));
    const keyForm = hiddenFields(keyScreen.text);
    keyForm.username = 'wa-alice';
    keyForm.password = 'anything';
    keyForm.action = 'login';
    const refusedNoKey = await alice.go('POST', '/authn/login',
                                        { form: keyForm });
    note(refusedNoKey.status === 200 &&
         /This request needs a security key/.test(refusedNoKey.text),
         'c3. a person who holds a SECOND FACTOR and no key is told so ' +
         'rather than walked through a ceremony that would enrol one — the ' +
         'bypass that would be', refusedNoKey.status + ' ' +
         ((refusedNoKey.text.match(/class="err[^>]*>[^<]*/) || [''])[0]));
    note(await refusedWith('STS-AUTHN-0204'),
         'c4. with STS-AUTHN-0204');
    const forgedKey = await alice.go('GET', signInUrl({
      wauth: KEY, step_up_honoured: '1' }));
    note(forgedKey.status === 400 &&
         /No security key was used/.test(forgedKey.text),
         'c5. and a session that comes back with the marker and still no ' +
         'key is refused — one attempt, then the refusal',
         forgedKey.status + ' ' +
         ((forgedKey.text.match(/<title>[^<]*/) || [''])[0]));
    note(await refusedWith('STS-WSFED-0009'),
         'c6. with STS-WSFED-0009');

    // --- d. a forged marker ---------------------------------------------------
    const bob = browser(port);
    first = await bob.go('GET', signInUrl());
    await signIn(bob, first, 'wa-bob');
    r = await bob.go('GET', signInUrl({ wauth: MFA, step_up_honoured: '1' }));
    note(r.status === 400 && /Still one factor/.test(r.text),
         'd1. a marker forged onto a first request buys a refusal, not a ' +
         'pass and not a loop', r.status + ' ' + r.text.slice(0, 160));
    note(await refusedWith('STS-WSFED-0010'),
         'd2. and it carries STS-WSFED-0010');

    // --- e. no session ---------------------------------------------------------
    const carol = browser(port);
    first = await carol.go('GET', signInUrl({ wauth: MFA }));
    note(toSignIn(first),
         'e1. with no session the demand goes to the sign-in screen',
         first.headers.location);
    const page = await carol.go('GET', first.headers.location);
    note(/id="use_webauthn"[^>]*checked disabled/.test(page.text),
         'e2. and the screen demands the second factor from the start');

    // --- f. an unknown method ---------------------------------------------------
    r = await bob.go('GET', signInUrl({ wauth: 'urn:example:retina' }));
    note(r.status === 400 && /not available/.test(r.text) &&
         r.text.indexOf(KEY) >= 0,
         'f1. an unknown wauth is still refused, and the list of what is ' +
         'accepted now names the hardware token too', r.status);
    note(await refusedWith('STS-WSFED-0006'), 'f2. with STS-WSFED-0006');

    // --- g. a REAL ceremony meets the demand, both ways ----------------------
    // The screen's own data attributes carry what a browser would be given;
    // the authenticator below produces what one would produce.
    const withKey = async function (username, passwordless) {
      const b = browser(port);
      const start = await b.go('GET', signInUrl({ wauth: KEY }));
      const screen = await b.go('GET', start.headers.location);
      const form = hiddenFields(screen.text);
      form.username = username;
      form.action = 'login';
      if (passwordless) {
        form.webauthn_only = '1';
        form.password = '';
      } else {
        form.password = 'anything';
      }
      const step = await b.go('POST', '/authn/login', { form: form });
      const mfaId = (step.text.match(/name="mfa_id" value="([^"]+)"/) ||
                     [])[1];
      const challenge = dataAttribute(step.text, 'challenge');
      const rpId = dataAttribute(step.text, 'rpid');
      const mode = dataAttribute(step.text, 'mode');
      const authenticator = makeAuthenticator(rpId,
                                              'http://127.0.0.1:' + port);
      const credential = mode === 'create'
        ? authenticator.register(challenge) : authenticator.assert(challenge);
      const done = await b.go('POST', '/authn/webauthn', { form: {
        mfa_id: mfaId, mode: mode,
        credential: JSON.stringify(credential) } });
      const backTo = String(done.headers.location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      const answer = backTo ? await b.go('GET', backTo) : done;
      return { screen: screen, step: step, mode: mode, done: done,
               answer: answer, browser: b };
    };
    const passwordlessKey = await withKey('wa-passkey', true);
    note(passwordlessKey.mode === 'create' &&
         (passwordlessKey.done.status === 302 ||
          passwordlessKey.done.status === 303) &&
         assertionSays(passwordlessKey.answer, KEY),
         'g1. a PASSWORDLESS security key — one factor, amr ["hwk"] — meets ' +
         'a hardware wauth, and the assertion says HardwareToken',
         passwordlessKey.done.status + ' ' +
         passwordlessKey.answer.status + ' ' +
         passwordlessKey.answer.text.slice(0, 160));
    const secondFactorKey = await withKey('wa-keypair', false);
    note(secondFactorKey.mode === 'create' &&
         assertionSays(secondFactorKey.answer, MFA),
         'g2. and so does a password AND a key — two factors, so the ' +
         'assertion says multipleauthn, which is what happened',
         secondFactorKey.answer.status + ' ' +
         secondFactorKey.answer.text.slice(0, 160));
    const again = await secondFactorKey.browser.go('GET',
      signInUrl({ wauth: KEY }));
    note(assertionSays(again, MFA),
         'g3. and the demand is met at once on that session afterwards',
         again.status);

    // --- h. the code door is shut while a key is demanded ---------------------
    const codeAttempt = await (async function () {
      const b = browser(port);
      const start = await b.go('GET', signInUrl({ wauth: KEY }));
      const screen = await b.go('GET', start.headers.location);
      const form = hiddenFields(screen.text);
      // Somebody who holds NO second factor: the demand takes them to the
      // key ceremony, which is the step a code is posted at below.
      form.username = 'wa-codeless';
      form.password = 'anything';
      form.action = 'login';
      const step = await b.go('POST', '/authn/login', { form: form });
      const mfaId = (step.text.match(/name="mfa_id" value="([^"]+)"/) ||
                     [])[1];
      return b.go('POST', '/authn/totp', { form: {
        mfa_id: mfaId || 'none',
        code: totp.codeAt(began.secret, Date.now() + 90000) } });
    })();
    note(codeAttempt.status === 400 &&
         /demands a security key/.test(codeAttempt.text),
         'h1. a ONE-TIME CODE posted at the second-factor door while a key ' +
         'is demanded is refused — the link is not drawn, and a link that ' +
         'is not drawn is still a URL',
         codeAttempt.status + ' ' + codeAttempt.text.slice(0, 200));

    // --- i. one mechanism, named in step_up.ts --------------------------------
    const stepUp = require(ROOT + '/oauth-oidc/step_up');
    note(JSON.stringify(stepUp.screenDemandFor(['hwk'])) ===
           JSON.stringify({ forceMfa: true, forceKey: true }) &&
         JSON.stringify(stepUp.screenDemandFor(['mfa'])) ===
           JSON.stringify({ forceMfa: true, forceKey: false }) &&
         JSON.stringify(stepUp.screenDemandFor(['mfa', '1'])) ===
           JSON.stringify({ forceMfa: false, forceKey: false }) &&
         JSON.stringify(stepUp.screenDemand('key')) ===
           JSON.stringify({ forceMfa: false, forceKey: true }),
         'i1. the same mechanism answers for the authorization endpoint: ' +
         'acr_values naming only RFC 8176 key aliases forces the key too, ' +
         'while `mfa` forces a second factor and `mfa 1` forces nothing',
         JSON.stringify([stepUp.screenDemandFor(['hwk']),
                         stepUp.screenDemandFor(['mfa', '1'])]));

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
  const out = path.join(os.tmpdir(), 'wauth-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', WA_ROOT: ROOT, WA_OUT: out }),
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
  name: 'wsfed_wauth_step_up',
  describe: 'WS-Federation wauth: a hardware or multi-factor demand the ' +
            'session cannot meet is a step-up through the sign-in, the ' +
            'assertion reports what happened, and a demand still unmet ' +
            'after one attempt is refused with its code',
  run: run
};
