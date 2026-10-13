// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/oid4vp_sign_in.js — A VERIFIED PRESENTATION SIGNS SOMEBODY IN, AND
// ONLY THE RIGHT ONE, IN ONLY THE RIGHT BROWSER (2026-09-17, #38).
//
// `/authn/wallet` (`oid4vc/vc_signin.ts`) turns an OpenID4VP presentation into
// the session every protocol family reads, and `oid4vc/vc_issued.ts` is the
// register that says whom. The claims, each driven over HTTP against the
// whole stack on an ephemeral loopback port, with a wallet written here:
//
//   1. the sign-in screen offers the wallet, and `oid4vp.signIn` off removes
//      the button and closes the door (STS-VC-0052); a request demanding two
//      factors IS offered it since #38's follow-ups, and says a second factor
//      follows;
//   2. the wait page carries ONE script — the Digital Credentials API
//      button, whose form has a real submit button — its CSP names
//      `script-src 'self'` and keeps `frame-ancestors`, the plain QR code is
//      OFF by default in both modes and is a page of its own (`?qr=1`, no
//      script, a <meta> refresh) when it is on; the request it hands a wallet
//      is signed and asks for this issuer's credential in every format;
//   3. a holder-bound credential this realm issued, presented with a good
//      Key Binding JWT, starts a session for the entry it was issued for —
//      amr ["pop"], acr "1", the entry's urn:uuid subject — completes the
//      pending authentication, and is on /logout's list of live sessions;
//   4. a response cannot complete a sign-in for another browser, even with
//      the response_code (STS-VC-0055); a wrong response_code is refused
//      (STS-VC-0065); the transaction is answered once (STS-VC-0057) and
//      finished once (STS-VC-0062); an expired one is refused (STS-VC-0056);
//   5. a sign-in on a browser holding a DIFFERENT person's session replaces
//      that session rather than joining it;
//   6. these verify-or-fail exactly as before and sign nobody in, each with
//      its code: no Key Binding JWT, a wrong nonce, a wrong audience, a
//      credential from another realm (STS-VC-0061); a credential this realm
//      signed on an access token it did NOT verify (STS-VC-0059); a trusted
//      foreign issuer's (STS-VC-0058); a deleted entry's (STS-VC-0060); and a
//      person the issuance policy refuses (STS-VC-0064);
//   7. a verification an administrator starts (POST /admin-api/
//      verifications/start's function) still signs nobody in, and the
//      Response Endpoint names the starter's page, or none (#594);
//   8. a DISOWNED credential signs nobody in (STS-VC-0071): a global sign-out
//      through `logout.terminate()` and through POST /logout, an
//      administrator's revocation on the issued register, and a suspended
//      status list entry — each undone where it can be undone, and a
//      credential issued AFTER a sign-out signing in again;
//   9. an ORDINARY session sign-out disowns nothing: the same credential
//      signs in again straight afterwards.
//
// In a CHILD PROCESS for `admin_credential_controls.js`'s reason: it loads the
// whole protocol stack and flips settings every other file in `run.js`'s one
// process would see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'oid4vp_sign_in',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  // The code each response was marked with, by request, read off the
  // response object after express has finished with it.
  const marks = [];

  function b64u(input) {
    return Buffer.from(input).toString('base64url');
  }

  function jws(header, payload, key) {
    const input = b64u(JSON.stringify(header)) + '.' +
                  b64u(JSON.stringify(payload));
    const alg = header.alg;
    const signature = alg === 'ES256'
      ? nodeCrypto.sign('sha256', Buffer.from(input),
                        { key: key, dsaEncoding: 'ieee-p1363' })
      : nodeCrypto.sign('sha256', Buffer.from(input), key);
    return input + '.' + signature.toString('base64url');
  }

  function decode(jwt) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
      .toString('utf8'));
  }

  // One browser: a cookie jar.
  function browser() {
    return { cookies: {} };
  }

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      let body = '';
      const headers = Object.assign({}, o.headers || {});
      if (o.json !== undefined) {
        body = JSON.stringify(o.json);
        headers['content-type'] = 'application/json';
      } else if (o.form) {
        body = new URLSearchParams(o.form).toString();
        headers['content-type'] = 'application/x-www-form-urlencoded';
      }
      if (method !== 'GET') {
        headers['content-length'] = Buffer.byteLength(body);
      }
      if (o.browser) {
        const jar = o.browser.cookies;
        const line = Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
        if (line) {
          headers.cookie = line;
        }
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          const set = [].concat(res.headers['set-cookie'] || []);
          if (o.browser) {
            set.forEach(function (one) {
              const pair = one.split(';')[0];
              const eq = pair.indexOf('=');
              const name = pair.slice(0, eq);
              const value = pair.slice(eq + 1);
              if (/Max-Age=0/.test(one) || value === '') {
                delete o.browser.cookies[name];
              } else {
                o.browser.cookies[name] = value;
              }
            });
          }
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            // A page, not JSON; the text is what is read.
            parsed = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed, setCookie: set,
                    code: marks.length ? marks[marks.length - 1] : '' });
        });
      });
      req.end(body);
    });
  }

  function pathOf(url) {
    const u = new URL(url, 'http://127.0.0.1');
    return u.pathname + u.search;
  }

  function unescapeHtml(text) {
    return String(text).replace(/&amp;/g, '&').replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    // The sign-in screen over `/authn-api` since #571.
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const helpers = require(ROOT + '/common/helpers');
    const errorCodes = require(ROOT + '/common/error_codes');
    const gate = require(ROOT + '/common/issuance_gate');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const applications = require(ROOT + '/common/applications');
    const offers = require(ROOT + '/oid4vc/vc_offers');
    const verifier = require(ROOT + '/oid4vc/vc_verifier');
    const issuedRegister = require(ROOT + '/oid4vc/vc_issued');
    const vcConfigs = require(ROOT + '/oid4vc/vc_configs');
    const authn = require(ROOT + '/authn/authn');
    const logout = require(ROOT + '/logout/logout');
    // USERNAMELESS SIGN-IN OFF (it is on by default since 2026-10-10): with it
    // on, the sign-in screen carried /authn/webauthn.js and relaxed
    // script-src for its own passkey button, and this test reads that
    // screen's policy as the base one. (The screen is the sign-in surface's
    // since #571 and that script is gone since #572; the setting is kept
    // off so the test reads the same screen it always did.)
    {
      const passkeyPolicy = require(ROOT + '/common/passkey_policy');
      realms.run(realms.get(realms.DEFAULT_ID), function () {
        passkeyPolicy.save('default', Object.assign({},
          passkeyPolicy.DEFAULTS, { allowUsernameless: false }));
      });
    }
    const DEFAULT = realms.DEFAULT_REALM;
    const DCQL_ID = 'identity_credential';
    const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

    const server = http.createServer(function (req, res) {
      res.on('finish', function () {
        marks.push(errorCodes.codeOf(res));
      });
      app(req, res);
    });
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const fakeReq = function (prefix) {
      return { protocol: 'http', originalUrl: (prefix || '') + '/',
               headers: { host: '127.0.0.1:' + port },
               get: function (n) {
                 return String(n).toLowerCase() === 'host' ?
                   '127.0.0.1:' + port : undefined;
               } };
    };

    const SECRET = 'wsi-client-secret-0123456789abcdef';
    const client = { client_id: 'wsi-wallet', client_secret: SECRET };
    function provision() {
      applications.createApplication({ identifier: 'wsi-wallet',
        protocols: ['oauth2', 'oid4vci'],
        fields: { oauthClientId: 'wsi-wallet', oauthClientSecret: SECRET,
                  oauthTokenEndpointAuthMethod: 'client_secret_post',
                  oauthGrantType: [PRE_AUTH] } });
    }

    // A holder key the wallet proves possession of.
    function holderKey() {
      const pair = nodeCrypto.generateKeyPairSync('ec',
                                                  { namedCurve: 'P-256' });
      const jwk = pair.publicKey.export({ format: 'jwk' });
      return { privateKey: pair.privateKey, jwk: jwk };
    }

    // THE ISSUANCE, as a wallet does it: redeem a pre-authorized code, get a
    // c_nonce, prove the key, ask for the credential. `token` overrides the
    // access token (the foreign-token case). `prefix` is a realm's path.
    async function issue(username, holder, opts) {
      const o = opts || {};
      const prefix = o.prefix || '';
      let accessToken = o.token;
      if (!accessToken) {
        const built = await realms.run(o.realm || DEFAULT, function () {
          return offers.buildCredentialOffer(fakeReq(prefix),
            ['IdentityCredential'], 'cross-device',
            { user: helpers.userFor(username) });
        });
        const redeemed = await request(port, 'POST', prefix + '/oauth2/token',
          { form: Object.assign({ grant_type: PRE_AUTH,
            'pre-authorized_code': built.preAuthorizedCode,
            tx_code: built.txCode }, client) });
        if (!redeemed.json || !redeemed.json.access_token) {
          return { error: 'token ' + redeemed.status + ' ' +
                          redeemed.text.slice(0, 200) };
        }
        accessToken = redeemed.json.access_token;
      }
      const nonce = await request(port, 'POST', prefix + '/oid4vci/nonce',
                                  { form: {} });
      const cNonce = nonce.json && nonce.json.c_nonce;
      const proof = jws({ alg: 'ES256', typ: 'openid4vci-proof+jwt',
                          jwk: holder.jwk },
                        { aud: base + prefix, iat: Math.floor(Date.now() /
                                                              1000),
                          nonce: cNonce }, holder.privateKey);
      const got = await request(port, 'POST', prefix + '/oid4vci/credential', {
        headers: { authorization: 'Bearer ' + accessToken },
        json: { credential_configuration_id: 'IdentityCredential',
                proofs: { jwt: [proof] } } });
      const credential = got.json && got.json.credentials &&
                         got.json.credentials[0] &&
                         got.json.credentials[0].credential;
      if (!credential) {
        return { error: 'credential ' + got.status + ' ' +
                        got.text.slice(0, 300) };
      }
      return { credential: credential, accessToken: accessToken };
    }

    // A presentation: the credential with no Disclosures (a sign-in asks for
    // the subject, which is never one) and a Key Binding JWT.
    function present(credential, holder, nonce, aud, opts) {
      const o = opts || {};
      const withoutKb = String(credential).split('~')[0] + '~';
      if (o.noKb) {
        return withoutKb;
      }
      const sdHash = nodeCrypto.createHash('sha256')
        .update(withoutKb, 'ascii').digest('base64url');
      const kb = jws({ alg: 'ES256', typ: 'kb+jwt' },
                     { iat: Math.floor(Date.now() / 1000), nonce: nonce,
                       aud: aud, sd_hash: sdHash }, holder.privateKey);
      return withoutKb + kb;
    }

    // A pending authentication, as a protocol module begins one.
    function pendingSignIn(opts) {
      const o = opts || {};
      return realms.run(o.realm || DEFAULT, function () {
        const to = authn.beginAuthentication(Object.assign({
          returnTo: '/wsi/after', protocol: 'wsi-probe', application: '' },
          o.begin || {}));
        return new URL(to, 'http://x').searchParams.get('authn');
      });
    }

    // THE WALLET'S PAGES ARE ROUTES OF THE SIGN-IN SURFACE SINCE #574, and
    // this drives them as the page does: the shells (the arrival cookie),
    // the views (the CSRF token), and the acts at `/authn-api/wallet` —
    // JSON, this service's Origin, the X-CSRF-Token. An act's answer is
    // read as the page it replaced was (`formLike()`): one naming an
    // address is the 303 it was.
    function formLike(r) {
      const j = r.json || {};
      const where = j.location || (j.ok && j.go) || '';
      if (j.ok && where) {
        return Object.assign({}, r, { status: 303,
          headers: Object.assign({}, r.headers, { location: where }) });
      }
      return r;
    }

    function act(who, urlPath, body) {
      const headers = { accept: 'application/json', origin: base };
      if (who && who.csrf) {
        headers['x-csrf-token'] = who.csrf;
      }
      return request(port, 'POST', urlPath, { browser: who,
                                              headers: headers, json: body });
    }

    // The start page's view and act: `{ opened, started }`, each read as a
    // page.
    async function startOnly(who, authnId, prefix) {
      const p = prefix || '';
      const q = 'authn=' + encodeURIComponent(authnId);
      await request(port, 'GET', p + '/authn/wallet?' + q, { browser: who });
      const opened = await request(port, 'GET', p + '/authn-api/wallet?' + q,
                                   { browser: who });
      if (opened.status !== 200) {
        return { opened: opened, started: opened };
      }
      who.csrf = opened.json.csrf;
      const started = await act(who, p + '/authn-api/wallet',
                                { authn: authnId });
      return { opened: opened, started: formLike(started), raw: started };
    }

    // Start a wallet sign-in in `who`; answer with the request the wallet is
    // handed. `prefix` is a realm's path.
    async function start(who, authnId, prefix) {
      const p = prefix || '';
      const begun = await startOnly(who, authnId, p);
      const started = begun.started;
      if (started.status !== 303) {
        return { started: started };
      }
      const waitPath = started.headers.location;
      const state = begun.raw.json.state;
      const waiting = await request(port, 'GET', p + '/authn-api/wallet/' +
                                    encodeURIComponent(state),
                                    { browser: who });
      const view = (waiting.json && waiting.json.view) || {};
      const walletUrl = view.sameDevice ? new URL(view.sameDevice) : null;
      let requestObject = null;
      if (walletUrl) {
        const ro = await request(port, 'GET',
          pathOf(walletUrl.searchParams.get('request_uri')));
        requestObject = decode(ro.text);
      }
      return { started: started, waitPath: waitPath, waiting: waiting,
               view: view, walletUrl: walletUrl,
               requestObject: requestObject, who: who, prefix: p,
               authn: authnId, state: state };
    }

    // THE COLLECTION, as the wait page asks for it (`POST …/status`), with
    // the `response_code` a same-device wallet sent the browser back with
    // where `redirect` names one.
    async function collect(who, s, redirect, code) {
      const body = { authn: s.authn };
      const m = /[?&]response_code=([^&#]+)/.exec(String(redirect || ''));
      if (code !== undefined) {
        body.response_code = code;
      } else if (m) {
        body.response_code = decodeURIComponent(m[1]);
      }
      return formLike(await act(who, (s.prefix || '') + '/authn-api/wallet/' +
                                encodeURIComponent(s.state) + '/status',
                                body));
    }

    // A SIGNED-IN session in a browser's jar — not the arrival session the
    // sign-in surface's shells mint for a browser without one (#571).
    function signedInSession(who) {
      return realms.run(DEFAULT, function () {
        const found = who.cookies.sts_session && authn.cookieSession(
          { headers: { cookie: 'sts_session=' + who.cookies.sts_session } },
          authn.SESSION_COOKIE);
        return (found && found.session && found.session.chosen !== false)
          ? found.session : null;
      });
    }

    // THE WALLET'S ANSWER. A sign-in asks for `direct_post.jwt` by
    // default since 2026-10-12 (`oid4vp.signInResponseMode`), so the answer
    // is ENCRYPTED to the request's ECDH-ES key, as a HAIP wallet sends it;
    // `plain` sends it in the clear whatever was asked.
    async function respond(req, presentation, prefix, plain) {
      const ro = req.requestObject || {};
      const fields = { state: ro.state,
                       vp_token: JSON.stringify({ [DCQL_ID]: [presentation] }) };
      let form = fields;
      if (ro.response_mode === 'direct_post.jwt' && !plain) {
        const key = ((ro.client_metadata || {}).jwks || { keys: [] }).keys
          .filter(function (k) {
            return k.alg === 'ECDH-ES';
          })[0];
        form = { response: require(ROOT + '/common/crypto').encryptJweCompact(
          JSON.stringify({ vp_token: { [DCQL_ID]: [presentation] } }),
          { alg: 'ECDH-ES', enc: 'A128GCM', jwk: key }) };
      }
      return request(port, 'POST', (prefix || '') + '/oid4vp/response',
                     { form: form });
    }

    const sessionCookie = function (r) {
      return r.setCookie.some(function (c) {
        return /^sts_session=[^;]+/.test(c) && !/Max-Age=0/.test(c);
      });
    };

    await realms.run(DEFAULT, async function () {
      provision();
      ldap.createUser('wsi-alice', { invent: false });
      ldap.createUser('wsi-bob', { invent: false });
      ldap.createUser('wsi-carol', { invent: false });
      ldap.createUser('wsi-dave', { invent: false });
    });
    const aliceSub = await realms.run(DEFAULT, function () {
      return helpers.subjectForName('wsi-alice');
    });
    // THE CLIENT IDENTIFIER A SIGN-IN SIGNS UNDER is x509_hash's since
    // 2026-10-12 (`oid4vp.signInClientIdPrefix`): the SHA-256 of the
    // Verifier's certificate, which exists once the first sign-in starts.
    // Read off that request (2i holds it to the certificate), and every
    // presentation below is made for it.
    let aud = '';

    // ====================================================================
    // 1. THE SCREEN, AND THE SWITCH
    // ====================================================================
    // THE SCREEN IS A STATIC PAGE SINCE #571, drawn from its view.
    const viewOf = async function (id) {
      return (await authnScreen.open({ port: port, jar: {},
        at: '/authn/login?authn=' + id })).view || {};
    };
    let authnId = pendingSignIn();
    let view = await viewOf(authnId);
    note(view.wallet && view.wallet.state === 'offered' &&
         view.wallet.href === '/authn/wallet?authn=' + authnId,
         '1a. the sign-in screen offers "Sign in with a wallet" for this ' +
         'pending authentication', JSON.stringify(view.wallet));
    // THE SERVICE'S BASE POLICY, which pages with no script of their own
    // keep: a refusal answered at the screen's path carries it (the screen
    // itself is a static page since #571, `script-src 'self'`).
    let r = await request(port, 'GET', '/authn/login?authn=nosuchsignin');
    const screenCsp = r.headers['content-security-policy'];
    await realms.run(DEFAULT, function () {
      config.setOverride('oid4vp.signIn', 'false');
    });
    view = await viewOf(authnId);
    note(view.id && !view.wallet,
         '1b. with oid4vp.signIn off the button is gone',
         JSON.stringify(view.wallet));
    let closedWho = browser();
    r = (await startOnly(closedWho, authnId)).started;
    note(r.status === 403 && r.code === 'STS-VC-0052' &&
         !closedWho.cookies.sts_wallet_binding &&
         r.json && r.json.next === 'refused' &&
         r.json.view && r.json.view.wallet === 'refused',
         '1c. and the door refuses, STS-VC-0052, starting nothing: no ' +
         'binding cookie, a refusal and its view', r.status + ' ' + r.code);
    closedWho = null;
    await realms.run(DEFAULT, function () {
      config.clearOverride('oid4vp.signIn');
    });
    const mfaId = pendingSignIn({ begin: { forceMfa: true } });
    view = await viewOf(mfaId);
    note(view.wallet && view.wallet.state === 'offered' &&
         view.wallet.mfaNote === true,
         '1d. a request demanding two factors IS offered the wallet since ' +
         '#38\'s follow-ups, and is told a second factor follows');
    r = (await startOnly(browser(), mfaId)).started;
    note(r.status === 303,
         '1e. and the door takes it: the second factor comes after the ' +
         'presentation (tests/oid4vp_wallet_mfa.js drives it)',
         r.status + ' ' + r.code);
    r = (await startOnly(browser(), 'nothing-pending')).started;
    note(r.status === 400 && r.code === 'STS-VC-0053',
         '1f. a door with no pending authentication refuses, STS-VC-0053',
         r.status + ' ' + r.code);

    // ====================================================================
    // 2. THE WAIT PAGE AND THE REQUEST
    // ====================================================================
    const aliceKey = holderKey();
    const alice = await issue('wsi-alice', aliceKey);
    note(!!alice.credential, '2a. a credential is issued to wsi-alice for ' +
         'a key she holds', alice.error);
    note(alice.credential &&
         decode(String(alice.credential).split('~')[0]).sub === aliceSub,
         '2b. its subject is her entry\'s urn:uuid subject', aliceSub);
    const kept = await realms.run(DEFAULT, function () {
      return issuedRegister.lookup(alice.credential);
    });
    note(kept && kept.subject === aliceSub && !('credential' in kept),
         '2c. this realm recorded it as one that may sign her in, by digest ' +
         'and subject and never the credential', JSON.stringify(kept));

    const browser1 = browser();
    let s = await start(browser1, authnId);
    aud = String((s.requestObject || {}).client_id || '');
    note(s.started.status === 303 &&
         !!browser1.cookies.sts_wallet_binding,
         '2d. starting sets the binding cookie and sends the browser to the ' +
         'wait page', s.started.status);
    const bindingLine = s.started.setCookie.join(' ');
    note(/HttpOnly/.test(bindingLine) && /SameSite=Lax/.test(bindingLine),
         '2e. the binding cookie is HttpOnly and SameSite=Lax', bindingLine);
    // THE WAIT PAGE IS A ROUTE OF THE SIGN-IN SURFACE SINCE #574: its
    // shell is the surface's (one script, the surface's bundle), and its
    // view is what the page draws.
    const waitShell = await request(port, 'GET', s.waitPath,
                                    { browser: browser1 });
    const scripts = waitShell.text.match(/<script[^>]*>/g) || [];
    note(waitShell.status === 200 && scripts.length === 1 &&
         /<script src="\/authn\/signin\.js"/.test(waitShell.text) &&
         !/<meta http-equiv="refresh"/.test(waitShell.text),
         '2f. the wait page is the sign-in surface\'s shell: ONE script, ' +
         '/authn/signin.js, and no <meta> refresh',
         JSON.stringify(scripts));
    note(s.waiting.status === 200 && s.view.wallet === 'wait' &&
         s.view.dcRequest &&
         s.view.dcRequest.protocol === 'openid4vp-v1-signed' &&
         !!s.walletUrl && s.view.kind === 'wallet' &&
         s.view.secondFactor === false && s.view.expiresIn > 0,
         '2f-ii. its view carries the Digital Credentials API request and ' +
         'the same-device link the page draws',
         JSON.stringify(Object.keys(s.view)));
    note(s.view.qr === '',
         '2g. the plain QR code is OFF by default, so the view carries no ' +
         'QR text and the page draws no link to it', s.view.qr);
    const waitCsp = waitShell.headers['content-security-policy'];
    note(/script-src 'self'/.test(waitCsp) &&
         !/script-src[^;]*unsafe-inline/.test(waitCsp) &&
         /frame-ancestors 'none'/.test(waitCsp) &&
         /base-uri 'none'/.test(waitCsp) &&
         /script-src 'none'/.test(screenCsp),
         '2h. its CSP relaxes script-src to \'self\' and nothing else, and ' +
         'keeps frame-ancestors and base-uri', waitCsp);
    const scriptRes = await request(port, 'GET', '/authn/wallet.js');
    note(scriptRes.status === 404,
         '2h-ii. and /authn/wallet.js is not served: the Digital ' +
         'Credentials API call is the sign-in surface\'s runtime\'s (#574)',
         scriptRes.status);
    const otherView = await request(port, 'GET', '/authn-api/wallet/' +
      encodeURIComponent(s.state), { browser: browser() });
    note(otherView.status === 403 && otherView.code === 'STS-VC-0055' &&
         !(otherView.json && otherView.json.csrf),
         '2h-iii. and the view is answered to the browser that started ' +
         'the sign-in only, STS-VC-0055', otherView.status + ' ' +
         otherView.code);
    const ro = s.requestObject || {};
    const queries = (ro.dcql_query || {}).credentials || [];
    const cq = queries[0] || {};
    const sets = (ro.dcql_query || {}).credential_sets || [];
    // WHAT A WALLET THAT HAS NEVER HEARD OF THIS SERVICE CAN ACT ON
    // (2026-10-12): an x509_hash Client Identifier — the SHA-256 of the
    // certificate the request carries first in `x5c`, computed here — and
    // an encrypted answer to a key the request offers.
    const roHeader = JSON.parse(Buffer.from(String(
      (await request(port, 'GET', pathOf(s.walletUrl.searchParams.get(
        'request_uri')))).text).split('.')[0], 'base64url').toString('utf8'));
    const leafHash = roHeader.x5c && roHeader.x5c.length
      ? nodeCrypto.createHash('sha256').update(
          Buffer.from(roHeader.x5c[0], 'base64')).digest('base64url') : '';
    note(!!leafHash && ro.client_id === 'x509_hash:' + leafHash &&
         s.walletUrl.searchParams.get('client_id') === ro.client_id &&
         roHeader.typ === 'oauth-authz-req+jwt',
         '2h-iv. the request is signed under the x509_hash Client ' +
         'Identifier, the SHA-256 of the x5c leaf (oid4vp.' +
         'signInClientIdPrefix, OpenID4VC HAIP 1.0 section 5)',
         ro.client_id + ' ' + leafHash);
    const offered = ((ro.client_metadata || {}).jwks || {}).keys || [];
    note(ro.response_mode === 'direct_post.jwt' && !!ro.response_uri &&
         offered.some(function (k) {
           return k.alg === 'ECDH-ES' && k.crv === 'P-256';
         }),
         '2h-v. and asks for an encrypted answer, direct_post.jwt, to a ' +
         'P-256 ECDH-ES key among those it offers (oid4vp.' +
         'signInResponseMode, HAIP section 5.1)',
         ro.response_mode + ' ' + JSON.stringify(offered.map(function (k) {
           return k.alg;
         })));
    note(/^openid4vp:\/\/\?client_id=/.test(s.view.sameDevice) &&
         s.walletUrl.searchParams.get('request_uri_method') === 'get' &&
         s.view.webWallet === '',
         '2h-vi. the same-device link is the request by reference under ' +
         'openid4vp://, which a wallet app registers for, and no web wallet ' +
         'is offered where none is configured',
         s.view.sameDevice.slice(0, 40) + ' web=' + s.view.webWallet);
    note(cq.format === 'dc+sd-jwt' &&
         JSON.stringify(cq.meta) === JSON.stringify(
           { vct_values: [vcConfigs.VCI_VCT] }) &&
         JSON.stringify(cq.claims) === JSON.stringify([{ path: ['sub'] }]),
         '2i. the signed request asks for this issuer\'s SD-JWT VC and its ' +
         'subject only', JSON.stringify(cq));
    note(queries.length === 3 &&
         queries.map(function (q) { return q.format; }).join(',') ===
           'dc+sd-jwt,jwt_vc_json,ldp_vc' &&
         sets.length === 1 && sets[0].required === true &&
         JSON.stringify(sets[0].options) === JSON.stringify(
           queries.map(function (q) { return [q.id]; })),
         '2i-ii. and for the other two formats beside it, with a ' +
         'credential_set saying any ONE of them answers',
         JSON.stringify(ro.dcql_query));
    // THE PLAIN QR CODE IS OFF BY DEFAULT IN BOTH MODES (#38's follow-ups).
    await realms.run(DEFAULT, function () {
      config.setOverride('global.mode', 'product');
    });
    const inProduct = await start(browser(), pendingSignIn());
    note(inProduct.waiting.status === 200 && inProduct.view.qr === '',
         '2j. in product mode it is off too — the default is the same in ' +
         'both modes, and no mode predicate decides it');
    await realms.run(DEFAULT, function () {
      config.clearOverride('global.mode');
      config.setOverride('oid4vp.signInCrossDevice', 'true');
    });
    const withQr = await start(browser(), pendingSignIn());
    note(withQr.waiting.status === 200 &&
         /^openid4vp:\/\/\?/.test(withQr.view.qr) &&
         /request_uri=/.test(withQr.view.qr),
         '2j-ii. oid4vp.signInCrossDevice on puts the QR code\'s text in ' +
         'the view, which the page draws as a link to ?qr=1 and the code',
         withQr.view.qr.slice(0, 40));
    const qrShell = await request(port, 'GET', withQr.waitPath + '&qr=1',
                                  { browser: withQr.who });
    note(qrShell.status === 200 &&
         /<script src="\/authn\/signin\.js"/.test(qrShell.text) &&
         !/<meta http-equiv="refresh"/.test(qrShell.text) &&
         withQr.view.pollSeconds > 0,
         '2j-iii. and that page is the same shell: the code is drawn in the ' +
         'browser and the runtime polls every pollSeconds, where a <meta> ' +
         'refresh did', qrShell.status + ' ' + withQr.view.pollSeconds);
    await realms.run(DEFAULT, function () {
      config.clearOverride('oid4vp.signInCrossDevice');
    });

    // HOW A REAL WALLET IS REACHED, AND ANSWERS (2026-10-12).
    const clear = await start(browser(), pendingSignIn());
    r = await respond(clear, present(alice.credential, aliceKey,
                                     clear.requestObject.nonce, aud),
                      '', true);
    note(r.status === 400 && r.code === 'STS-VC-0096',
         '2k. an answer in the clear to a sign-in that asked for ' +
         'direct_post.jwt is refused, STS-VC-0096 (HAIP section 5.1)',
         r.status + ' ' + r.code);
    await realms.run(DEFAULT, function () {
      config.setOverride('oid4vp.walletInvocation', 'haip-vp');
      config.setOverride('oid4vp.walletUrl', 'https://web-wallet.example/w');
      config.setOverride('oid4vp.walletPresentationPath', '/present');
      config.setOverride('oid4vp.signInResponseMode', 'direct_post');
      config.setOverride('oid4vp.signInClientIdPrefix', 'pre-registered');
    });
    const haip = await start(browser(), pendingSignIn());
    note(/^haip-vp:\/\/\?client_id=/.test(haip.view.sameDevice || '') &&
         /^https:\/\/web-wallet\.example\/w\/present\?client_id=/.test(
           haip.view.webWallet || ''),
         '2k-ii. oid4vp.walletInvocation=haip-vp puts the link under ' +
         'haip-vp:// (HAIP section 5.1), and a configured web wallet is ' +
         'offered beside it with its presentation page',
         (haip.view.sameDevice || '').slice(0, 30) + ' ' +
         (haip.view.webWallet || '').slice(0, 50));
    const preRegistered = await realms.run(DEFAULT, function () {
      return config.value('oid4vp.clientId');
    });
    note(haip.requestObject && haip.requestObject.response_mode ===
           'direct_post' &&
         haip.requestObject.client_id === preRegistered,
         '2k-iii. and oid4vp.signInResponseMode and ' +
         'oid4vp.signInClientIdPrefix choose the response mode and the ' +
         'Client Identifier',
         haip.requestObject && (haip.requestObject.response_mode + ' ' +
                                haip.requestObject.client_id));
    r = await respond(haip, present(alice.credential, aliceKey,
                                    haip.requestObject.nonce,
                                    haip.requestObject.client_id));
    note(r.status === 200 && /response_code=/.test(
           (r.json && r.json.redirect_uri) || ''),
         '2k-iv. which takes the answer in the clear', r.status + ' ' +
         r.text.slice(0, 120));
    // Collected, so no answered sign-in is left waiting for section 3's
    // inventory to find.
    r = await collect(haip.who, haip, r.json && r.json.redirect_uri);
    note(r.status === 303 && !!signedInSession(haip.who),
         '2k-v. and the browser that started it is signed in',
         r.status + ' ' + r.code + ' ' + (r.headers || {}).location);
    await realms.run(DEFAULT, function () {
      ['oid4vp.walletInvocation', 'oid4vp.walletUrl',
       'oid4vp.walletPresentationPath', 'oid4vp.signInResponseMode',
       'oid4vp.signInClientIdPrefix'].forEach(function (key) {
        config.clearOverride(key);
      });
    });

    // ====================================================================
    // 3 AND 4. THE SIGN-IN, AND THE BROWSER IT BELONGS TO
    // ====================================================================
    const browser2 = browser();
    await start(browser2, pendingSignIn());
    r = await collect(browser2, s);
    note(r.status === 403 && r.code === 'STS-VC-0055' && !sessionCookie(r),
         '4a. another browser asking about the sign-in is refused, ' +
         'STS-VC-0055', r.status + ' ' + r.code);
    r = await respond(s, present(alice.credential, aliceKey,
                                 ro.nonce, aud));
    const redirect = r.json && r.json.redirect_uri;
    note(r.status === 200 && /\/authn\/wallet\/wait\?/.test(redirect || '') &&
         /response_code=/.test(redirect || ''),
         '3a. the wallet\'s presentation is accepted and it is sent back to ' +
         'the wait page with a response_code', r.status + ' ' + r.text);
    r = await respond(s, present(alice.credential, aliceKey,
                                 ro.nonce, aud));
    note(r.status === 400 && r.code === 'STS-VC-0057',
         '4b. a second response to a sign-in is refused, STS-VC-0057',
         r.status + ' ' + r.code);
    r = await collect(browser2, s, redirect);
    note(r.status === 403 && r.code === 'STS-VC-0055' && !sessionCookie(r),
         '4c. the response_code does not let another browser finish it',
         r.status + ' ' + r.code);
    r = await collect(browser1, s, redirect, 'wrong');
    note(r.status === 403 && r.code === 'STS-VC-0065' && !sessionCookie(r),
         '4d. a wrong response_code is refused, STS-VC-0065',
         r.status + ' ' + r.code);
    const wallets = /\/authn\/wallet\/wait\?/.test(redirect || '');
    r = await collect(browser1, s, redirect);
    note(wallets && r.status === 303 && r.headers.location === '/wsi/after' &&
         sessionCookie(r),
         '3b. the browser that started it is signed in and sent back to the ' +
         'request that was waiting', r.status + ' ' + r.headers.location);
    const signed = await realms.run(DEFAULT, function () {
      return authn.cookieSession({ headers: { cookie: 'sts_session=' +
        browser1.cookies.sts_session } }, authn.SESSION_COOKIE);
    });
    const session = signed && signed.session;
    note(session && session.user.username === 'wsi-alice' &&
         session.user.sub === aliceSub,
         '3c. the session is wsi-alice\'s, under her entry\'s subject',
         session && JSON.stringify(session.user));
    note(session && JSON.stringify(session.amr) === '["pop"]' &&
         session.acr === '1',
         '3d. amr ["pop"], acr "1"', session &&
         JSON.stringify([session.amr, session.acr]));
    note(!authn.pendingFor(authnId),
         '3e. the pending authentication is spent');
    const live = await realms.run(DEFAULT, function () {
      return logout.liveSessions();
    });
    note(session && live.some(function (row) {
      return row.id === 'session:' + session.id;
    }), '3f. /logout\'s model lists it as a live session like any other');
    // The sign-in replaced the arrival session; the page's token is the new
    // session's (a fresh view answers it).
    await startOnly(browser1, pendingSignIn());
    r = await collect(browser1, s, redirect);
    note(r.status === 400 && r.code === 'STS-VC-0062' && !sessionCookie(r),
         '4e. the sign-in is finished once, STS-VC-0062',
         r.status + ' ' + r.code);

    // A sign-out between the wallet's answer and the browser's collection.
    const pendingOut = await start(browser(), pendingSignIn());
    const outBrowser = browser();
    const withdrawn = await start(outBrowser, pendingSignIn());
    await respond(withdrawn, present(alice.credential, aliceKey,
                                     withdrawn.requestObject.nonce, aud));
    const stats = require(ROOT + '/common/admin_stats');
    const aliceKeyOf = await realms.run(DEFAULT, function () {
      return stats.holderKeyOf('wsi-alice', aliceSub);
    });
    const inventory = await realms.run(DEFAULT, function () {
      return logout.inventoryFor(aliceKeyOf);
    });
    const walletRows = [].concat.apply([], (inventory.families || [])
      .filter(function (f) { return f.id === 'wallet-signin'; })
      .map(function (f) { return f.rows || []; }));
    note(walletRows.length === 1 && !JSON.stringify(walletRows)
      .includes(withdrawn.state) && !JSON.stringify(walletRows)
      .includes(pendingOut.state),
         '3g. /logout lists the answered, uncollected wallet sign-in (and ' +
         'not the unanswered one), by a handle and never its state',
         JSON.stringify(walletRows));
    const ended = await realms.run(DEFAULT, function () {
      return logout.terminate(aliceKeyOf, walletRows.map(function (row) {
        return row.id;
      }));
    });
    r = await collect(outBrowser, withdrawn);
    note(r.status === 403 && r.code === 'STS-VC-0070' && !sessionCookie(r),
         '3h. ending it withdraws the sign-in: the browser is told so and ' +
         'nobody is signed in, STS-VC-0070', r.status + ' ' + r.code + ' ' +
         JSON.stringify(ended && ended.done));

    // Expiry.
    const lateId = pendingSignIn();
    const late = await start(browser1, lateId);
    await realms.run(DEFAULT, function () {
      const tx = verifier.transactionFor(late.state);
      tx.expires = Date.now() - 1000;
      verifier.saveTransaction(tx);
    });
    r = await respond(late, present(alice.credential, aliceKey,
                                    late.requestObject.nonce, aud));
    note(r.status === 400,
         '4f. a wallet answering an expired sign-in is refused', r.status);
    r = await collect(browser1, late);
    note(r.status === 400 && r.code === 'STS-VC-0056',
         '4g. and the wait page\'s poll says it has expired, STS-VC-0056',
         r.status + ' ' + r.code);

    // ====================================================================
    // 5. A DIFFERENT PERSON'S SESSION IS REPLACED, NOT JOINED
    // ====================================================================
    const browser3 = browser();
    const bobId = pendingSignIn();
    r = await authnScreen.submit({ port: port, jar: browser3.cookies,
      at: '/authn/login?authn=' + bobId,
      fields: { action: 'login', username: 'wsi-bob', password: 'x' } });
    const bobSession = await realms.run(DEFAULT, function () {
      const found = authn.cookieSession({ headers: { cookie: 'sts_session=' +
        browser3.cookies.sts_session } }, authn.SESSION_COOKIE);
      return found && found.session;
    });
    note(bobSession && bobSession.user.username === 'wsi-bob',
         '5a. the browser holds wsi-bob\'s session', r.status);
    const again = await start(browser3, pendingSignIn());
    await respond(again, present(alice.credential, aliceKey,
                                 again.requestObject.nonce, aud));
    const againTx = await realms.run(DEFAULT, function () {
      return verifier.transactionFor(again.state);
    });
    r = await collect(browser3, again);
    const aliceThere = await realms.run(DEFAULT, function () {
      const found = authn.cookieSession({ headers: { cookie: 'sts_session=' +
        browser3.cookies.sts_session } }, authn.SESSION_COOKIE);
      return found && found.session;
    });
    const bobAfter = await realms.run(DEFAULT, function () {
      return bobSession ? authn.sessionById(bobSession.id) : null;
    });
    note(r.status === 303 && aliceThere &&
         aliceThere.user.username === 'wsi-alice' &&
         bobSession && aliceThere.id !== bobSession.id && !bobAfter,
         '5b. the wallet sign-in replaced wsi-bob\'s session with a new one ' +
         'for wsi-alice, and bob\'s ended', r.status + ' ' +
         JSON.stringify(againTx && againTx.signIn && againTx.signIn.outcome));

    // ====================================================================
    // 6. VERIFIES OR FAILS AS BEFORE, AND SIGNS NOBODY IN
    // ====================================================================
    async function refusal(label, presentation, expectVerified, code, who) {
      const b = who || browser();
      const one = await start(b, pendingSignIn());
      const answered = await respond(one, typeof presentation === 'function' ?
        presentation(one.requestObject) : presentation);
      // What the Verifier decided — `GET /admin-api/verifications?state=`'s
      // object (#594: the demonstration's `/oid4vp/result/:state` is gone).
      const outcome = await realms.run(DEFAULT, function () {
        return verifier.verificationOutcome(one.state);
      });
      const verified = !!(outcome && outcome.verdict && outcome.verdict.ok);
      const page = await collect(b, one);
      note(verified === expectVerified &&
           answered.status === (expectVerified ? 200 : 400) &&
           page.status === 403 && page.code === code &&
           !sessionCookie(page) && !signedInSession(b) &&
           page.json && page.json.next === 'refused' &&
           page.json.view && page.json.view.verdict ===
             (expectVerified ? 'presentation.verified'
                             : 'presentation.notVerified'),
           label, 'verified=' + verified + ' response=' + answered.status +
           ' page=' + page.status + ' ' + page.code);
    }

    await refusal('6a. no Key Binding JWT: refused as before, nobody signed ' +
                  'in, STS-VC-0061',
                  function () {
                    return present(alice.credential, aliceKey, '', '',
                                   { noKb: true });
                  }, false, 'STS-VC-0061');
    await refusal('6b. a Key Binding JWT for another nonce: refused, nobody ' +
                  'signed in, STS-VC-0061',
                  function () {
                    return present(alice.credential, aliceKey, 'other-nonce',
                                   aud);
                  }, false, 'STS-VC-0061');
    await refusal('6c. a Key Binding JWT for another audience: refused, ' +
                  'nobody signed in, STS-VC-0061',
                  function (req) {
                    return present(alice.credential, aliceKey, req.nonce,
                                   'someone-else');
                  }, false, 'STS-VC-0061');
    const otherKey = holderKey();
    await refusal('6d. a Key Binding JWT signed by a key the credential is ' +
                  'not bound to: refused, nobody signed in, STS-VC-0061',
                  function (req) {
                    return present(alice.credential, otherKey, req.nonce, aud);
                  }, false, 'STS-VC-0061');

    // A credential this realm SIGNED, on an access token it did not verify.
    const forged = jws({ alg: 'RS256', typ: 'at+jwt' },
                       { sub: aliceSub, scope: 'identity_credential',
                         iss: 'https://elsewhere.example',
                         iat: Math.floor(Date.now() / 1000),
                         exp: Math.floor(Date.now() / 1000) + 300 },
                       nodeCrypto.generateKeyPairSync('rsa',
                         { modulusLength: 2048 }).privateKey);
    const foreignKey = holderKey();
    const foreign = await issue('wsi-alice', foreignKey, { token: forged });
    note(foreign.credential &&
         decode(String(foreign.credential).split('~')[0]).sub === aliceSub,
         '6e. the issuer still issues on a token it did not issue, naming ' +
         'wsi-alice, as it always has', foreign.error);
    const foreignKept = await realms.run(DEFAULT, function () {
      return issuedRegister.lookup(foreign.credential);
    });
    note(!foreignKept, '6f. and does not record that credential as one that ' +
         'may sign anybody in');
    await refusal('6g. that credential VERIFIES and signs nobody in, ' +
                  'STS-VC-0059',
                  function (req) {
                    return present(foreign.credential, foreignKey, req.nonce,
                                   aud);
                  }, true, 'STS-VC-0059');

    // A token of THIS realm, genuinely issued, then DISOWNED by a sign-out
    // (`revoke()` is where every sign-out's `revokeWhere()` ends) while it is
    // still inside its `exp`.
    const dsKey = holderKey();
    const dsLive = await issue('wsi-alice', holderKey());
    const dsJti = dsLive.accessToken && decode(dsLive.accessToken).jti;
    await realms.run(DEFAULT, function () {
      return stats.revoke(dsJti, 'test: sign-out');
    });
    const dsCredential = await issue('wsi-alice', dsKey,
                                     { token: dsLive.accessToken });
    note(!!dsJti && dsCredential.credential,
         '6g-ii. a disowned but unexpired token still gets a credential, as ' +
         'it always has', dsCredential.error);
    const dsKept = await realms.run(DEFAULT, function () {
      return issuedRegister.lookup(dsCredential.credential);
    });
    note(!dsKept, '6g-iii. but that credential is NOT recorded as one ' +
         'that may sign anybody in');
    await refusal('6g-iv. and it VERIFIES and signs nobody in, STS-VC-0059',
                  function (req) {
                    return present(dsCredential.credential, dsKey,
                                   req.nonce, aud);
                  }, true, 'STS-VC-0059');

    // A trusted foreign issuer.
    const partner = await realms.run(DEFAULT, function () {
      return require(ROOT + '/common/crypto').selfSignedRsaCertificate(
        { commonName: 'wsi partner issuer' });
    });
    // The partner names no status, and since #165 a credential naming none
    // is refused by oid4vp.requireStatusReference before it could verify —
    // so the partner is exempted by its certificate's thumbprint, which is
    // what an operator whose partner publishes no status does, and what is
    // asserted is the refusal this row is about.
    await realms.run(DEFAULT, function () {
      config.setOverride('oid4vp.trustedIssuerCertificates', partner.certPem);
      config.setOverride('oid4vp.statusOptionalIssuers',
        require(ROOT + '/common/crypto').certificateThumbprint(
          partner.certPem, { format: 'hex' }));
    });
    const partnerKey = holderKey();
    const partnerCredential = jws({ alg: 'RS256', typ: 'dc+sd-jwt' },
      { iss: 'https://partner.example', vct: vcConfigs.VCI_VCT,
        sub: aliceSub, cnf: { jwk: partnerKey.jwk },
        nbf: Math.floor(Date.now() / 1000) - 5,
        exp: Math.floor(Date.now() / 1000) + 600,
        _sd_alg: 'sha-256', _sd: [] },
      nodeCrypto.createPrivateKey(partner.privateKeyPem)) + '~';
    await refusal('6h. a trusted foreign issuer\'s credential VERIFIES and ' +
                  'signs nobody in, STS-VC-0058',
                  function (req) {
                    return present(partnerCredential, partnerKey, req.nonce,
                                   aud);
                  }, true, 'STS-VC-0058');
    await realms.run(DEFAULT, function () {
      config.clearOverride('oid4vp.trustedIssuerCertificates');
      config.clearOverride('oid4vp.statusOptionalIssuers');
    });

    // A deleted entry.
    const carolKey = holderKey();
    const carol = await issue('wsi-carol', carolKey);
    const carolSub = await realms.run(DEFAULT, function () {
      return helpers.subjectForName('wsi-carol');
    });
    const deleted = await realms.run(DEFAULT, function () {
      return ldap.deletePerson(carolSub.replace(/^urn:uuid:/, ''));
    });
    note(carol.credential && deleted && deleted.ok !== false,
         '6i. a credential is issued to wsi-carol, and her entry is deleted',
         (carol.error || '') + ' ' + JSON.stringify(deleted));
    await refusal('6j. her credential VERIFIES and signs nobody in, ' +
                  'STS-VC-0060',
                  function (req) {
                    return present(carol.credential, carolKey, req.nonce,
                                   aud);
                  }, true, 'STS-VC-0060');

    // The issuance policy refusing the person.
    const daveKey = holderKey();
    const dave = await issue('wsi-dave', daveKey);
    const previousDecider = gate.deciderInstalled();
    gate.setDecider(function (asked) {
      const who = asked && asked.subject && asked.subject.name;
      return who === 'wsi-dave'
        ? { allowed: false, decision: 'Deny', why: 'wsi test policy',
            roles: [], required: [], policy: null }
        : { allowed: true, decision: 'Permit', why: 'wsi test policy',
            roles: [], required: [], policy: null };
    });
    try {
      const daveBrowser = browser();
      const daveOne = await start(daveBrowser, pendingSignIn(
        { begin: { application: 'wsi-wallet' } }));
      await respond(daveOne, present(dave.credential, daveKey,
                                     daveOne.requestObject.nonce, aud));
      r = await collect(daveBrowser, daveOne);
      note(r.status === 403 && r.code === 'STS-VC-0064' &&
           !sessionCookie(r),
           '6k. a person the issuance policy refuses verifies and is not ' +
           'signed in, STS-VC-0064', r.status + ' ' + r.code + ' ' +
           (dave.error || ''));
    } finally {
      gate.setDecider(previousDecider);
    }

    // Another realm's credential.
    await realms.run(DEFAULT, function () {
      realms.create({ id: 'wsi-other', name: 'wsi-other', overrides: {} });
    });
    await realms.run(realms.get('wsi-other'), async function () {
      provision();
      ldap.createUser('wsi-alice', { invent: false });
    });
    const otherRealmKey = holderKey();
    const elsewhere = await issue('wsi-alice', otherRealmKey,
                                  { prefix: '/realm/wsi-other',
                                    realm: realms.get('wsi-other') });
    note(!!elsewhere.credential, '6l. realm wsi-other issues its own ' +
         'wsi-alice a credential', elsewhere.error);
    const crossKept = await realms.run(DEFAULT, function () {
      return issuedRegister.lookup(elsewhere.credential);
    });
    const ownKept = await realms.run(realms.get('wsi-other'), function () {
      return issuedRegister.lookup(elsewhere.credential);
    });
    note(!crossKept && !!ownKept,
         '6m. its own realm recorded it, and the default realm has no record ' +
         'of it');
    await refusal('6n. presented to the default realm it does not verify, ' +
                  'and signs nobody in, STS-VC-0061',
                  function (req) {
                    return present(elsewhere.credential, otherRealmKey,
                                   req.nonce, aud);
                  }, false, 'STS-VC-0061');

    // ====================================================================
    // 8. A DISOWNED CREDENTIAL SIGNS NOBODY IN, AND 9. AN ORDINARY SIGN-OUT
    //    DISOWNS NOTHING (#38's follow-ups)
    // ====================================================================
    const stats8 = require(ROOT + '/common/admin_stats');
    const issuedRegister8 = issuedRegister;
    const vcStatus = require(ROOT + '/oid4vc/vc_status');
    const statusAdmin = require(ROOT + '/admin-ui/vc_status_admin');

    // Signs the credential in, in a fresh browser, and answers the wait
    // page's response: `{ ok, code, session }`.
    async function signInWith(credential, holder, opts) {
      const o = opts || {};
      const who = browser();
      const one = await start(who, pendingSignIn());
      await respond(one, present(credential, holder, one.requestObject.nonce,
                                 aud));
      const page = await collect(who, one);
      const session = await signedInSession(who);
      if (session && !o.keep) {
        await realms.run(DEFAULT, function () {
          authn.endSessionById(session.id, 'the test, tidying up');
        });
      }
      return { ok: page.status === 303, code: page.code, page: page,
               session: session, who: who };
    }

    const d1 = holderKey();
    const dCred = await issue('wsi-alice', d1);
    const firstIn = await signInWith(dCred.credential, d1);
    note(firstIn.ok && firstIn.session &&
         firstIn.session.user.username === 'wsi-alice',
         '8a. a fresh credential signs wsi-alice in (the baseline every ' +
         'refusal below is measured against)',
         firstIn.page.status + ' ' + firstIn.code);

    // AN ORDINARY SESSION SIGN-OUT. Every per-session door — /oauth2/logout,
    // SAML Single Logout, wsignout1.0, the console's and the portal's Sign
    // out — ends a session through authn.dropSession(), which is what
    // endSessionById() calls.
    const keepIn = await signInWith(dCred.credential, d1, { keep: true });
    await realms.run(DEFAULT, function () {
      authn.endSessionById(keepIn.session.id, '/oauth2/logout');
    });
    const afterSignOut = await signInWith(dCred.credential, d1);
    note(afterSignOut.ok,
         '9a. an ordinary session sign-out disowns nothing: the same ' +
         'credential signs in again straight afterwards',
         afterSignOut.page.status + ' ' + afterSignOut.code);

    // A GLOBAL SIGN-OUT, through the one function /logout, /admin/logout and
    // /admin-api/logout all go through.
    const aliceKey8 = await realms.run(DEFAULT, function () {
      return stats8.holderKeyOf('wsi-alice', aliceSub);
    });
    const inventory8 = await realms.run(DEFAULT, function () {
      return logout.inventoryFor(aliceKey8);
    });
    const walletCredentialRows = [].concat.apply([],
      (inventory8.families || [])
        .filter(function (f) { return f.id === 'wallet-credential'; })
        .map(function (f) { return f.rows || []; }));
    note(walletCredentialRows.length >= 1 &&
         !JSON.stringify(walletCredentialRows).includes(dCred.credential),
         '8b. /logout lists her wallet credentials as their own family, by ' +
         'a handle and never the credential',
         JSON.stringify(walletCredentialRows.map(function (r) {
           return r.label;
         })));
    const statusRow = await realms.run(DEFAULT, function () {
      return issuedRegister8.lookup(dCred.credential);
    });
    const statusKey = statusRow && statusRow.credentials[0].statusKey;
    note(!!statusKey && await realms.run(DEFAULT, function () {
      return vcStatus.statusOf(statusKey) === vcStatus.VALID;
    }), '8c. the credential carries a status-list entry, and it is VALID',
        statusKey);
    await realms.run(DEFAULT, function () {
      return logout.terminate(aliceKey8, walletCredentialRows.map(
        function (row) { return row.id; }), { by: 'a global sign-out' });
    });
    const afterGlobal = await signInWith(dCred.credential, d1);
    note(!afterGlobal.ok && afterGlobal.code === 'STS-VC-0071' &&
         afterGlobal.page.text.indexOf('disowned') > 0,
         '8d. after a global sign-out that credential VERIFIES and signs ' +
         'nobody in, STS-VC-0071, and the page says why',
         afterGlobal.page.status + ' ' + afterGlobal.code);
    note(await realms.run(DEFAULT, function () {
      return vcStatus.statusOf(statusKey) === vcStatus.INVALID;
    }), '8e. and the disown set its status-list entry INVALID, so a verifier ' +
        'elsewhere learns it');

    // A CREDENTIAL ISSUED AFTERWARDS, on a fresh token, signs in again.
    const d2 = holderKey();
    const afterCred = await issue('wsi-alice', d2);
    const freshIn = await signInWith(afterCred.credential, d2);
    note(freshIn.ok,
         '8f. a credential issued AFTER the sign-out signs her in again — a ' +
         'disown reaches what was issued up to it and no further',
         freshIn.page.status + ' ' + freshIn.code);

    // AN ADMINISTRATOR'S REVOCATION on the issued register.
    const freshRow = await realms.run(DEFAULT, function () {
      return issuedRegister8.lookup(afterCred.credential);
    });
    const artifact = await realms.run(DEFAULT, function () {
      return stats8.artifactByKey(freshRow.credentials[0].artifactKey);
    });
    await realms.run(DEFAULT, function () {
      return stats8.revokeArtifact(artifact, 'the admin console');
    });
    const afterRevoke = await signInWith(afterCred.credential, d2);
    note(!afterRevoke.ok && afterRevoke.code === 'STS-VC-0071',
         '8g. an administrator revoking it on the issued register refuses it ' +
         'too, STS-VC-0071', afterRevoke.page.status + ' ' +
         afterRevoke.code);
    note(await realms.run(DEFAULT, function () {
      return vcStatus.statusOf(freshRow.credentials[0].statusKey) ===
        vcStatus.INVALID;
    }), '8h. and its status-list entry reads INVALID from that act alone');
    await realms.run(DEFAULT, function () {
      return stats8.restoreArtifact(stats8.artifactByKey(
        freshRow.credentials[0].artifactKey));
    });
    const afterRestore = await signInWith(afterCred.credential, d2);
    note(afterRestore.ok,
         '8i. a restore (NON-SPEC) undoes it, in one place: the register ' +
         'and the status list agree because neither keeps a second answer',
         afterRestore.page.status + ' ' + afterRestore.code);

    // A SUSPENDED STATUS LIST ENTRY, set from the console's own function.
    const suspended = await realms.run(DEFAULT, function () {
      return statusAdmin.statusAction(
        { idx: freshRow.credentials[0].statusKey, action: 'suspend' },
        'the admin console');
    });
    const whileSuspended = await signInWith(afterCred.credential, d2);
    note(suspended.ok && !whileSuspended.ok &&
         whileSuspended.code === 'STS-VC-0071',
         '8j. suspending its status-list entry refuses it, STS-VC-0071',
         JSON.stringify(suspended) + ' ' + whileSuspended.code);
    const reinstated = await realms.run(DEFAULT, function () {
      return statusAdmin.statusAction(
        { idx: freshRow.credentials[0].statusKey, action: 'reinstate' },
        'the admin console');
    });
    const afterReinstate = await signInWith(afterCred.credential, d2);
    note(reinstated.ok && afterReinstate.ok,
         '8k. reinstating it lets her in again, and a revoked entry cannot ' +
         'be reinstated at all',
         JSON.stringify(reinstated) + ' ' + afterReinstate.code);
    const cannotReinstate = await realms.run(DEFAULT, function () {
      return statusAdmin.statusAction({ idx: statusKey, action: 'reinstate' },
                                      'the admin console');
    });
    note(!cannotReinstate.ok,
         '8l. INVALID is final: the revoked entry above refuses to be ' +
         'reinstated', JSON.stringify(cannotReinstate));

    // AND THROUGH THE ENDPOINT, not only the function: the sign-out page
    // with the browser's own cookie, its act selecting nothing and
    // therefore ending everything — over /authn-api/logout since #577,
    // as the page sends it (`authn_screen.signOut()`).
    const g1 = holderKey();
    const gCred = await issue('wsi-alice', g1);
    const globalIn = await signInWith(gCred.credential, g1, { keep: true });
    const posted = await authnScreen.signOut({ port: port,
                                              jar: globalIn.who.cookies,
                                              fields: {} });
    const afterPost = await signInWith(gCred.credential, g1);
    note(posted.status < 400 && !afterPost.ok &&
         afterPost.code === 'STS-VC-0071',
         '8m. POST /logout — a person signing themselves out of everything ' +
         '— disowns them too', posted.status + ' ' + afterPost.code);

    // ====================================================================
    // 7. THE BAR DOOR STILL SIGNS NOBODY IN
    // ====================================================================
    const barBrowser = browser();
    // A CREDENTIAL OF ITS OWN: section 8 disowned wsi-alice's earlier ones,
    // and a disowned credential is refused at this door too — which is the
    // status check working.
    const barKey = holderKey();
    const barCred = await issue('wsi-alice', barKey);
    // A VERIFICATION, STARTED AS `POST /admin-api/verifications/start`
    // STARTS ONE (#594), naming the starter's own page for the wallet to be
    // sent to afterwards — any absolute URL in development.
    const BAR_DONE = 'https://bar.example/verified';
    const barStart = await realms.run(DEFAULT, function () {
      return verifier.startVerification(
        { protocol: 'http', originalUrl: '/',
          headers: { host: '127.0.0.1:' + port },
          get: function (n) {
            return String(n).toLowerCase() === 'host'
              ? '127.0.0.1:' + port : undefined;
          } },
        { by: 'reference' }, 'body', { completionUri: BAR_DONE });
    });
    const barUrl = barStart.ok ? new URL(barStart.walletUrl) : null;
    let barRo = null;
    if (barUrl) {
      const got = await request(port, 'GET',
        pathOf(barUrl.searchParams.get('request_uri')));
      barRo = decode(got.text);
    }
    await realms.run(DEFAULT, function () {
      // The bar door asks for its configured claims; a credential with no
      // disclosures satisfies a request that names none.
      config.setOverride('oid4vp.claims', '');
    });
    if (barRo) {
      const tx = await realms.run(DEFAULT, function () {
        return verifier.transactionFor(barRo.state);
      });
      tx.requested = [];
      await realms.run(DEFAULT, function () {
        verifier.saveTransaction(tx);
      });
      r = await request(port, 'POST', '/oid4vp/response', {
        form: { state: barRo.state, vp_token: JSON.stringify({
          [DCQL_ID]: [present(barCred.credential, barKey, barRo.nonce,
                              barRo.client_id)] }) } });
    }
    await realms.run(DEFAULT, function () {
      config.clearOverride('oid4vp.claims');
    });
    note(barRo && r.status === 200 && r.json &&
         r.json.redirect_uri === BAR_DONE && !sessionCookie(r) &&
         !signedInSession(barBrowser),
         '7a. a presentation to a verification an administrator started ' +
         'verifies, names the starter\'s page as its redirect_uri (#594), ' +
         'and sets no session', r.status + ' ' + r.text);
    if (barRo) {
      const decided = await realms.run(DEFAULT, function () {
        return verifier.verificationOutcome(barRo.state);
      });
      note(decided && decided.received === true && decided.verdict &&
           decided.verdict.ok === true,
           '7b. and the outcome the start\'s twin reads says it was ' +
           'accepted', JSON.stringify(decided && decided.verdict &&
                                      decided.verdict.ok));
    }
    // A START THAT NAMED NO PAGE (#594): the Response Endpoint answers an
    // empty object — OpenID4VP 1.0 section 8.2's MAY — where it named the
    // service's own demonstration page until then.
    const quiet = await realms.run(DEFAULT, function () {
      return verifier.startVerification(
        { protocol: 'http', originalUrl: '/',
          headers: { host: '127.0.0.1:' + port },
          get: function (n) {
            return String(n).toLowerCase() === 'host'
              ? '127.0.0.1:' + port : undefined;
          } },
        {}, 'body');
    });
    const declined = quiet.ok ? await request(port, 'POST',
      '/oid4vp/response', { form: { state: quiet.record.state,
                                    error: 'access_denied' } }) : null;
    note(declined && declined.status === 200 && declined.json &&
         Object.keys(declined.json).length === 0,
         '7c. a verification started with no completion page is answered ' +
         'with no redirect_uri', declined && (declined.status + ' ' +
                                             declined.text));

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
  const out = path.join(os.tmpdir(), 'oid4vp-sign-in-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ADMIN_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', WSI_ROOT: ROOT,
                                  WSI_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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
  name: 'oid4vp sign-in',
  describe: 'a verified presentation of a credential this realm issued ' +
            'signs its entry in, in the browser that asked, once; ' +
            'everything else verifies as before and signs nobody in',
  run: run
};
