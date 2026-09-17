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
//      factors is not offered it and is refused at the door (STS-VC-0054);
//   2. the wait page carries no script, polls with a <meta> refresh, draws a
//      QR code and the same-device link, and its CSP is the base policy;
//      the request it hands a wallet is signed, asks for this issuer's
//      SD-JWT VC and its subject only;
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
//   7. the bar door at /oid4vp/verifier still signs nobody in.
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

    // Start a wallet sign-in in `who`; answer with the request the wallet is
    // handed. `prefix` is a realm's path.
    async function start(who, authnId, prefix) {
      const p = prefix || '';
      const started = await request(port, 'GET', p + '/authn/wallet?authn=' +
                                    encodeURIComponent(authnId),
                                    { browser: who });
      if (started.status !== 303) {
        return { started: started };
      }
      const waitPath = started.headers.location;
      const waiting = await request(port, 'GET', waitPath, { browser: who });
      const link = /id="wallet-open" href="([^"]+)"/.exec(waiting.text);
      const walletUrl = link ? new URL(unescapeHtml(link[1])) : null;
      let requestObject = null;
      if (walletUrl) {
        const ro = await request(port, 'GET',
          pathOf(walletUrl.searchParams.get('request_uri')));
        requestObject = decode(ro.text);
      }
      return { started: started, waitPath: waitPath, waiting: waiting,
               walletUrl: walletUrl, requestObject: requestObject,
               state: new URL(waitPath, 'http://x').searchParams.get('state') };
    }

    async function respond(req, presentation, prefix) {
      return request(port, 'POST', (prefix || '') + '/oid4vp/response', {
        form: { state: req.requestObject.state,
                vp_token: JSON.stringify({ [DCQL_ID]: [presentation] }) } });
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
    const aud = await realms.run(DEFAULT, function () {
      return config.value('oid4vp.clientId');
    });

    // ====================================================================
    // 1. THE SCREEN, AND THE SWITCH
    // ====================================================================
    let authnId = pendingSignIn();
    let r = await request(port, 'GET', '/authn/login?authn=' + authnId);
    note(r.status === 200 && r.text.indexOf('id="wallet-signin" href="' +
      '/authn/wallet?authn=' + authnId + '"') >= 0,
         '1a. the sign-in screen offers "Sign in with a wallet" for this ' +
         'pending authentication', r.status);
    const screenCsp = r.headers['content-security-policy'];
    await realms.run(DEFAULT, function () {
      config.setOverride('oid4vp.signIn', 'false');
    });
    r = await request(port, 'GET', '/authn/login?authn=' + authnId);
    note(r.status === 200 && r.text.indexOf('wallet-signin') < 0,
         '1b. with oid4vp.signIn off the button is gone', r.status);
    r = await request(port, 'GET', '/authn/wallet?authn=' + authnId,
                      { browser: browser() });
    note(r.status === 403 && r.code === 'STS-VC-0052' &&
         !r.setCookie.length,
         '1c. and the door refuses, STS-VC-0052', r.status + ' ' + r.code);
    await realms.run(DEFAULT, function () {
      config.clearOverride('oid4vp.signIn');
    });
    const mfaId = pendingSignIn({ begin: { forceMfa: true } });
    r = await request(port, 'GET', '/authn/login?authn=' + mfaId);
    note(r.text.indexOf('wallet-signin') < 0 &&
         r.text.indexOf('wallet-withheld') >= 0,
         '1d. a request demanding two factors is not offered the wallet, ' +
         'and is told why');
    r = await request(port, 'GET', '/authn/wallet?authn=' + mfaId,
                      { browser: browser() });
    note(r.status === 403 && r.code === 'STS-VC-0054',
         '1e. and the door refuses it, STS-VC-0054', r.status + ' ' + r.code);
    r = await request(port, 'GET', '/authn/wallet?authn=nothing-pending',
                      { browser: browser() });
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
    note(s.started.status === 303 &&
         !!browser1.cookies.sts_wallet_binding,
         '2d. starting sets the binding cookie and sends the browser to the ' +
         'wait page', s.started.status);
    const bindingLine = s.started.setCookie.join(' ');
    note(/HttpOnly/.test(bindingLine) && /SameSite=Lax/.test(bindingLine),
         '2e. the binding cookie is HttpOnly and SameSite=Lax', bindingLine);
    note(s.waiting.status === 200 &&
         !/<script/i.test(s.waiting.text) &&
         /<meta http-equiv="refresh" content="\d+;url=[^"]*\/authn\/wallet\/wait\?/
           .test(s.waiting.text),
         '2f. the wait page has no script and polls with a meta refresh',
         s.waiting.text.slice(0, 300));
    note(/id="wallet-qr"[^>]*src="data:image\/svg\+xml;base64,/
           .test(s.waiting.text) && !!s.walletUrl,
         '2g. it draws a server-rendered QR code and the same-device link');
    note(s.waiting.headers['content-security-policy'] === screenCsp &&
         /script-src 'none'/.test(screenCsp),
         '2h. its CSP is the base policy, script-src \'none\' and all',
         s.waiting.headers['content-security-policy']);
    const ro = s.requestObject || {};
    const cq = ((ro.dcql_query || {}).credentials || [])[0] || {};
    note(ro.client_id === aud && cq.format === 'dc+sd-jwt' &&
         JSON.stringify(cq.meta) === JSON.stringify(
           { vct_values: [vcConfigs.VCI_VCT] }) &&
         JSON.stringify(cq.claims) === JSON.stringify([{ path: ['sub'] }]),
         '2i. the signed request asks for this issuer\'s SD-JWT VC and its ' +
         'subject only', JSON.stringify(ro.dcql_query));
    await realms.run(DEFAULT, function () {
      config.setOverride('oid4vp.signInCrossDevice', 'false');
    });
    const noQr = await start(browser(), pendingSignIn());
    note(noQr.waiting.status === 200 &&
         noQr.waiting.text.indexOf('wallet-qr') < 0 && !!noQr.walletUrl,
         '2j. with oid4vp.signInCrossDevice off there is no QR code, and the ' +
         'same-device link stays');
    await realms.run(DEFAULT, function () {
      config.clearOverride('oid4vp.signInCrossDevice');
    });

    // ====================================================================
    // 3 AND 4. THE SIGN-IN, AND THE BROWSER IT BELONGS TO
    // ====================================================================
    const browser2 = browser();
    r = await request(port, 'GET', s.waitPath, { browser: browser2 });
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
    r = await request(port, 'GET', pathOf(redirect), { browser: browser2 });
    note(r.status === 403 && r.code === 'STS-VC-0055' && !sessionCookie(r),
         '4c. the response_code does not let another browser finish it',
         r.status + ' ' + r.code);
    r = await request(port, 'GET', pathOf(redirect).replace(
      /response_code=[^&]+/, 'response_code=wrong'), { browser: browser1 });
    note(r.status === 403 && r.code === 'STS-VC-0065' && !sessionCookie(r),
         '4d. a wrong response_code is refused, STS-VC-0065',
         r.status + ' ' + r.code);
    r = await request(port, 'GET', pathOf(redirect), { browser: browser1 });
    note(r.status === 303 && r.headers.location === '/wsi/after' &&
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
    r = await request(port, 'GET', pathOf(redirect), { browser: browser1 });
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
    r = await request(port, 'GET', withdrawn.waitPath,
                      { browser: outBrowser });
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
    r = await request(port, 'GET', late.waitPath, { browser: browser1 });
    note(r.status === 400 && r.code === 'STS-VC-0056',
         '4g. and the wait page says it has expired, STS-VC-0056',
         r.status + ' ' + r.code);

    // ====================================================================
    // 5. A DIFFERENT PERSON'S SESSION IS REPLACED, NOT JOINED
    // ====================================================================
    const browser3 = browser();
    const bobId = pendingSignIn();
    r = await request(port, 'POST', '/authn/login', {
      browser: browser3,
      form: { authn_id: bobId, username: 'wsi-bob', password: 'x',
              action: 'login' } });
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
    r = await request(port, 'GET', again.waitPath, { browser: browser3 });
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
      const verdict = await request(port, 'GET', '/oid4vp/result/' +
                                    encodeURIComponent(one.state));
      const verified = !!(verdict.json && verdict.json.verdict &&
                          verdict.json.verdict.ok);
      const page = await request(port, 'GET', one.waitPath, { browser: b });
      note(verified === expectVerified &&
           answered.status === (expectVerified ? 200 : 400) &&
           page.status === 403 && page.code === code &&
           !sessionCookie(page) && !b.cookies.sts_session &&
           page.text.indexOf('wallet-reason') >= 0,
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

    // A trusted foreign issuer.
    const partner = await realms.run(DEFAULT, function () {
      return require(ROOT + '/common/crypto').selfSignedRsaCertificate(
        { commonName: 'wsi partner issuer' });
    });
    await realms.run(DEFAULT, function () {
      config.setOverride('oid4vp.trustedIssuerCertificates', partner.certPem);
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
      r = await request(port, 'GET', daveOne.waitPath,
                        { browser: daveBrowser });
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
    // 7. THE BAR DOOR STILL SIGNS NOBODY IN
    // ====================================================================
    const barBrowser = browser();
    r = await request(port, 'GET', '/oid4vp/start?by=reference',
                      { browser: barBrowser });
    const barUrl = r.headers.location ? new URL(r.headers.location) : null;
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
          [DCQL_ID]: [present(alice.credential, aliceKey, barRo.nonce,
                              barRo.client_id)] }) } });
    }
    await realms.run(DEFAULT, function () {
      config.clearOverride('oid4vp.claims');
    });
    note(barRo && r.status === 200 && r.json &&
         /\/oid4vp\/done\?/.test(r.json.redirect_uri || '') &&
         !sessionCookie(r),
         '7a. a presentation at the bar door verifies, is sent to its ' +
         'thank-you page, and sets no session', r.status + ' ' + r.text);
    if (barRo) {
      const done = await request(port, 'GET',
        pathOf(r.json.redirect_uri), { browser: barBrowser });
      note(done.status === 200 && !sessionCookie(done) &&
           !barBrowser.cookies.sts_session,
           '7b. and its thank-you page signs nobody in either', done.status);
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
  const out = path.join(os.tmpdir(), 'oid4vp-sign-in-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
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
