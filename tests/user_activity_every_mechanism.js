// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/user_activity_every_mechanism.js
//
// ===========================================================================
// A PERSON'S PAGE SHOWS EVERY WAY THEY AUTHENTICATED.
//
// rcbj, 2026-11-16: after many TLS client certificate and RFC 7523
// authentications a person's Sessions & tokens tab listed nothing, and
// "these tabs have always been broken for some authentication types". So:
// one fresh ordinary person per mechanism, each signed in once through it,
// and then the two tabs of Directory → Users → that person read from the
// model both the console and `GET /admin-api/users?user=` draw from
// (`AdminViews.userDetailJson()`):
//
//   * AUTHENTICATIONS — `authenticationEvents`, the audit log's attempts
//     selected by who tried: at least one accepted `authentication` row.
//   * SESSIONS & TOKENS (the Activity tab) — what the mechanism produced:
//     the sign-on session it started (`sessions`), the tokens on it or on
//     none (`sessions[].tokens`, `tokensWithNoSession`,
//     `tokensOnEndedSessions`), and the assertions and tickets it issued
//     (`artifacts`). Each mechanism names what it must show; a mechanism
//     that produces nothing listable says so and is held to the
//     Authentications tab alone.
//
// Over a REAL mutual-TLS listener with the main port's posture
// (`requestCert`, never required), as `tests/authn_certificate_signin.js`
// builds it, so the certificate mechanisms are the real handshake. In a
// child process, because it loads the whole stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'user_activity_every_mechanism',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's program. It runs under `node -e`, so the code style's
// Entering/Leaving lines do not apply to it (root CLAUDE.md, *Code style*).
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.UAM_ROOT;
  const OUT = process.env.UAM_OUT;
  const https = require('https');
  const zlib = require('zlib');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const keystore = require(ROOT_DIR + '/common/keystore');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const pki = require(ROOT_DIR + '/common/pki');
    const applications = require(ROOT_DIR + '/common/applications');
    const tlsClient = require(ROOT_DIR + '/common/tls_client_certificates');
    const tls = require(ROOT_DIR + '/tls/tls_server');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const pkiAdmin = require(ROOT_DIR + '/admin-ui/pki_admin');
    const adminViews = require(ROOT_DIR + '/admin-core/admin_views');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');
    const testCa = require(ROOT_DIR + '/tests/protocol/outbound_test_ca');

    await keystore.start();
    await pki.start({ realmIds: [''],
      keySetFor: function (id) { return helpers.stsKeysFor.of(id); },
      keySetHeldFor: function () { return false; } });
    config.setOverride('oauth2.consentRequired', false);

    const SUFFIX = nodeCrypto.randomBytes(3).toString('hex');
    const CLIENT = 'uam-rp-' + SUFFIX;
    const SECRET = 'uam-secret-0123456789abcdef0123456789';
    const REDIRECT = 'https://rp.uam.example/cb';
    const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
               '(KHTML, like Gecko) Chrome/130.0 Safari/537.36';
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code', 'refresh_token',
                  'password',
                  'urn:ietf:params:oauth:grant-type:jwt-bearer'],
                oauthAllowedScope: ['openid', 'offline_access', 'profile'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });

    // THE LISTENER: the main port's posture over the client truststore.
    const serverCa = await testCa.makeCa();
    const serverLeaf = await testCa.listenerCertificate(serverCa,
                                                        '127.0.0.1');
    const CA = serverCa.certPem;
    const listener = https.createServer(Object.assign({
      cert: serverLeaf.cert, key: serverLeaf.key,
      ca: tls.clientTruststoreOptions().ca,
      requestCert: true, rejectUnauthorized: false
    }, tls.protocolOptions()), app);
    tls.trustClientCertificatesOn(listener, 'the user activity listener',
      function () {
        return { key: serverLeaf.key, cert: serverLeaf.cert };
      });
    await new Promise(function (ok) {
      listener.listen(0, '127.0.0.1', ok);
    });
    const port = listener.address().port;
    const ORIGIN = 'https://127.0.0.1:' + port;

    // ONE REQUEST, with a cookie jar and, where given, a client certificate.
    const call = function (o) {
      return new Promise(function (resolve) {
        const headers = Object.assign({ 'user-agent': UA }, o.headers || {});
        const jar = o.jar || {};
        if (Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        const body = o.body === undefined ? '' : String(o.body);
        if (o.method && o.method !== 'GET') {
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = https.request({ host: '127.0.0.1', port: port,
          path: String(o.path).replace(/^https?:\/\/[^/]+/, ''),
          method: o.method || 'GET', headers: headers, ca: CA,
          cert: o.cert || undefined, key: o.key || undefined, agent: false },
        function (res) {
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          let text = '';
          res.on('data', function (d) { text += d; });
          res.on('end', function () {
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (e) {
              json = null;
            }
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, json: json });
          });
        });
        req.on('error', function (e) {
          resolve({ status: 0, headers: {}, text: e.message, json: null });
        });
        req.end(body);
      });
    };
    const form = function (p, fields, extra) {
      return call(Object.assign({ method: 'POST', path: p,
        headers: Object.assign({
          'content-type': 'application/x-www-form-urlencoded',
          authorization: 'Basic ' + Buffer.from(CLIENT + ':' + SECRET)
            .toString('base64') }, (extra && extra.headers) || {}),
        body: new URLSearchParams(fields).toString() }, extra || {}));
    };

    // A BROWSER FLOW from `start`: the sign-in screen answered with `act`
    // (a password, or the certificate on the connection), every other
    // redirect on this origin followed. Answers the last response.
    const drive = async function (jar, start, act, cert, key) {
      let r = await call({ jar: jar, path: start, cert: cert, key: key });
      for (let hop = 0; hop < 14; hop += 1) {
        const to = String((r.headers && r.headers.location) || '');
        if (r.status >= 300 && r.status < 400 &&
            /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(to)) {
          const answer = await screen.submit({ port: port, ca: CA,
            cert: cert, key: key, jar: jar, userAgent: UA, at: to,
            fields: act });
          const next = await screen.ignoreOffer({ port: port, ca: CA,
            cert: cert, key: key, jar: jar, userAgent: UA }, answer);
          r = { status: next.status, headers: next.headers || {},
                text: next.text, json: next.json };
          continue;
        }
        if (r.status >= 300 && r.status < 400 && to) {
          if (to.indexOf('http') === 0 && to.indexOf(ORIGIN) !== 0) {
            break;
          }
          r = await call({ jar: jar, path: to, cert: cert, key: key });
          continue;
        }
        break;
      }
      return r;
    };
    const codeFlow = async function (jar, act, cert, key) {
      const last = await drive(jar, '/oauth2/authorize?' +
        new URLSearchParams({ client_id: CLIENT, response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid offline_access',
          state: 's', nonce: 'n-' + Date.now() }).toString(),
        act, cert, key);
      const to = String((last.headers && last.headers.location) || '');
      const code = new URL(to.indexOf('http') === 0 ? to
                                                     : ORIGIN + to)
        .searchParams.get('code');
      if (!code) {
        return { ok: false, why: last.status + ' ' + to + ' ' +
                 String(last.text || '').slice(0, 200) };
      }
      const token = await form('/oauth2/token', {
        grant_type: 'authorization_code', code: code,
        redirect_uri: REDIRECT }, { cert: cert, key: key });
      return { ok: token.status === 200, token: token.json,
               why: token.status + ' ' + String(token.text).slice(0, 200) };
    };

    // WHAT THE PERSON'S PAGE SHOWS: the model the console's tabs and the
    // API's user view are drawn from.
    const pageOf = function (username) {
      const answer = adminViews.userDetailJson({ query: {} }, username);
      const json = (answer && answer.json) || {};
      const sessions = [].concat(json.sessions || []);
      const onSessions = sessions.reduce(function (n, s) {
        return n + [].concat(s.tokens || []).length;
      }, 0);
      return {
        found: !!answer,
        events: [].concat(json.authenticationEvents || []),
        sessions: sessions.length,
        tokensOnSessions: onSessions,
        tokensSessionless: [].concat(json.tokensWithNoSession || []).length,
        tokensEnded: [].concat(json.tokensOnEndedSessions || []).length,
        artifacts: [].concat(json.artifacts || []).length,
        registryTokens: ((json.user || {}).tokens || {}).issued || 0
      };
    };
    const summary = function (p) {
      return JSON.stringify({ found: p.found,
        events: p.events.map(function (e) {
          return e.action + '/' + e.outcome + '/' + e.protocol + '/' +
                 ((e.detail || {}).method || '');
        }),
        sessions: p.sessions, tokensOnSessions: p.tokensOnSessions,
        tokensSessionless: p.tokensSessionless, tokensEnded: p.tokensEnded,
        artifacts: p.artifacts, registryTokens: p.registryTokens });
    };
    // Checks one mechanism's person against what it must show.
    const expect = function (mechanism, username, want) {
      const p = pageOf(username);
      const accepted = p.events.filter(function (e) {
        return e.action === 'authentication';
      });
      note(accepted.length >= 1,
           mechanism + ': the Authentications tab lists the sign-in',
           summary(p));
      if (want.session) {
        note(p.sessions >= 1,
             mechanism + ': Sessions & tokens lists the sign-on session',
             summary(p));
      }
      if (want.tokens) {
        const listed = p.tokensOnSessions + p.tokensSessionless +
                       p.tokensEnded;
        note(listed >= want.tokens,
             mechanism + ': Sessions & tokens lists the ' + want.tokens +
             '+ token(s) issued' + (want.session ? ' on the session' : ''),
             summary(p));
        if (want.session) {
          note(p.tokensOnSessions >= want.tokens,
               mechanism + ': and they are under the session they were ' +
               'issued on', summary(p));
        }
      }
      if (want.artifacts) {
        note(p.artifacts >= want.artifacts,
             mechanism + ': Sessions & tokens lists the issued ' +
             'assertion(s) or ticket(s)', summary(p));
      }
    };
    const person = function (tag) {
      const name = 'uam-' + tag + '-' + SUFFIX;
      ldap.createUser(name, { invent: false });
      return name;
    };

    // -----------------------------------------------------------------------
    // 1. THE SIGN-IN SCREEN, PASSWORD — an OpenID Connect code flow, then
    //    its refresh.
    // -----------------------------------------------------------------------
    {
      const who = person('password');
      const jar = {};
      const got = await codeFlow(jar, { action: 'login', username: who,
                                        password: 'x' });
      note(got.ok, 'password screen: the code flow issues tokens', got.why);
      if (got.ok && got.token.refresh_token) {
        const refreshed = await form('/oauth2/token', {
          grant_type: 'refresh_token',
          refresh_token: got.token.refresh_token });
        note(refreshed.status === 200,
             'password screen: the refresh grant issues tokens',
             refreshed.status + ' ' + refreshed.text.slice(0, 200));
      }
      expect('password screen + code flow', who,
             { session: true, tokens: 2 });
    }

    // -----------------------------------------------------------------------
    // 2. THE SIGN-IN SCREEN, THE TLS CLIENT CERTIFICATE (#1051).
    // -----------------------------------------------------------------------
    const certFor = async function (who) {
      const made = await tlsClient.issue(undefined, { username: who,
        label: 'uam', keyAlg: 'ec-p256' });
      return made.ok ? { cert: made.issued.certificatePem +
                           made.issued.chainPem.join(''),
                         key: made.issued.privateKeyPem }
                     : { error: JSON.stringify(made.errors) };
    };
    {
      const who = person('certscreen');
      const c = await certFor(who);
      note(!c.error, 'certificate screen: a certificate is issued', c.error);
      const got = await codeFlow({}, { action: 'certificate' }, c.cert,
                                 c.key);
      note(got.ok, 'certificate screen: the code flow issues tokens',
           got.why);
      expect('certificate screen + code flow', who,
             { session: true, tokens: 2 });
    }

    // -----------------------------------------------------------------------
    // 3. GET /tls/sign-in — the certificate as the whole sign-in.
    // -----------------------------------------------------------------------
    {
      const who = person('tlssignin');
      const c = await certFor(who);
      const got = await call({ jar: {}, path: '/tls/sign-in', cert: c.cert,
                               key: c.key });
      note(got.status < 400, 'GET /tls/sign-in: answered',
           got.status + ' ' + String(got.text).slice(0, 200));
      expect('GET /tls/sign-in', who, { session: true });
    }

    // -----------------------------------------------------------------------
    // 4. THE PASSWORD GRANT (RFC 6749 section 4.3).
    // -----------------------------------------------------------------------
    {
      const who = person('ropc');
      const got = await form('/oauth2/token', { grant_type: 'password',
        username: who, password: 'x', scope: 'openid' });
      note(got.status === 200, 'password grant: tokens issued',
           got.status + ' ' + got.text.slice(0, 200));
      expect('password grant', who, { tokens: 1 });
    }

    // -----------------------------------------------------------------------
    // 5. RFC 7523: THE PERSON'S OWN KEY PAIR, A SELF-ASSERTION.
    // -----------------------------------------------------------------------
    {
      const who = person('jwtbearer');
      const issued = await pkiAdmin.pkiAction({ action: 'issue',
        target: 'person', purpose: 'jwt', identifier: who,
        leafKeyAlg: 'rsa-2048' });
      note(issued.ok, 'RFC 7523: a key pair is issued to the person',
           issued.why || '');
      const head = Buffer.from(JSON.stringify({ alg: 'RS256',
        typ: 'JWT' })).toString('base64url');
      const now = Math.floor(Date.now() / 1000);
      const body = Buffer.from(JSON.stringify({ iss: who, sub: who,
        aud: ORIGIN + '/oauth2/token', iat: now, exp: now + 120,
        jti: nodeCrypto.randomBytes(16).toString('hex') }))
        .toString('base64url');
      const sig = nodeCrypto.sign('sha256', Buffer.from(head + '.' + body),
        issued.privateKeyPem || '').toString('base64url');
      const got = await form('/oauth2/token', {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: head + '.' + body + '.' + sig, scope: 'openid' });
      note(got.status === 200, 'RFC 7523: tokens issued',
           got.status + ' ' + got.text.slice(0, 300));
      expect('RFC 7523 self-assertion', who, { tokens: 1 });
    }

    // -----------------------------------------------------------------------
    // 6. WS-TRUST, A UsernameToken.
    // -----------------------------------------------------------------------
    {
      const who = person('wstrust');
      const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
      const envelope = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/' +
        'soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/' +
        '01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><s:Header>' +
        '<wsse:Security><wsse:UsernameToken><wsse:Username>' + who +
        '</wsse:Username><wsse:Password>x</wsse:Password>' +
        '</wsse:UsernameToken></wsse:Security></s:Header><s:Body>' +
        '<wst:RequestSecurityToken xmlns:wst="' + WST + '">' +
        '<wst:RequestType>' + WST + '/Issue</wst:RequestType>' +
        '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
        'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/' +
        '2005/08/addressing"><wsa:Address>https://rp.uam.example/ws' +
        '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
        '</wst:RequestSecurityToken></s:Body></s:Envelope>';
      const got = await call({ method: 'POST', path: '/sts',
        headers: { 'content-type': 'application/soap+xml' },
        body: envelope });
      note(got.status === 200, 'WS-Trust: an assertion is issued',
           got.status + ' ' + String(got.text).slice(0, 300));
      expect('WS-Trust UsernameToken', who, { artifacts: 1 });
    }

    // -----------------------------------------------------------------------
    // 7–9. THE BROWSER SSO PROFILES: SAML 2.0, SAML 1.1, WS-Federation.
    // -----------------------------------------------------------------------
    {
      const who = person('saml2');
      const xml = '<samlp:AuthnRequest ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_uam' + nodeCrypto.randomBytes(8).toString('hex') + '" ' +
        'Version="2.0" IssueInstant="' + new Date().toISOString() + '" ' +
        'AssertionConsumerServiceURL="https://sp.uam.test/acs">' +
        '<saml:Issuer>urn:uam:sp</saml:Issuer></samlp:AuthnRequest>';
      const last = await drive({}, '/saml2/sso?SAMLRequest=' +
        encodeURIComponent(zlib.deflateRawSync(Buffer.from(xml))
          .toString('base64')), { action: 'login', username: who,
                                  password: 'x' });
      note(/SAMLResponse/.test(String(last.text || '')),
           'SAML 2.0: a response is posted to the SP',
           last.status + ' ' + String(last.text || '').slice(0, 200));
      expect('SAML 2.0 Web Browser SSO', who,
             { session: true, artifacts: 1 });
    }
    {
      const who = person('saml11');
      const last = await drive({}, '/saml11/sso?providerId=' +
        encodeURIComponent('urn:uam:saml11') + '&shire=' +
        encodeURIComponent('https://rp11.uam.test/acs') + '&target=t',
        { action: 'login', username: who, password: 'x' });
      note(/SAMLResponse/.test(String(last.text || '')),
           'SAML 1.1: a response is posted to the SP',
           last.status + ' ' + String(last.text || '').slice(0, 200));
      expect('SAML 1.1 Browser/POST', who, { session: true, artifacts: 1 });
    }
    {
      const who = person('wsfed');
      const last = await drive({}, '/wsfed?wa=wsignin1.0&wtrealm=' +
        encodeURIComponent('urn:uam:wsfed') + '&wreply=' +
        encodeURIComponent('https://wsfed.uam.test/'),
        { action: 'login', username: who, password: 'x' });
      note(/wresult/.test(String(last.text || '')),
           'WS-Federation: a response is posted to the RP',
           last.status + ' ' + String(last.text || '').slice(0, 200));
      expect('WS-Federation passive', who, { session: true, artifacts: 1 });
    }

    listener.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'uam-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  UAM_ROOT: ROOT, UAM_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
  name: 'user_activity_every_mechanism',
  describe: 'a person\'s Authentications and Sessions & tokens tabs list ' +
            'what every authentication mechanism did',
  run: run
};
