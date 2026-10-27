// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authn_certificate_signin.js
//
// ===========================================================================
// THE SIGN-IN SCREEN CONTINUES WITH THE TLS CLIENT CERTIFICATE ON THE
// CONNECTION (#1051, 2026-10-27).
//
// rcbj's decision on #520: every browser protocol reaches the one sign-in
// screen, so a TLS client certificate is offered there, once. Where the
// connection presented a certificate the identity gate accepts for the realm
// of the pending sign-in, `GET /authn-api/pending/{id}` offers it
// (`certificate: { name }`) and `POST …/certificate` completes the pending
// sign-in on it as a first factor — `GET /tls/sign-in`'s event, `amr
// ["swk"]`, `acr "1"`, credential kind `certificate` — and the calling
// protocol (here the OIDC authorization endpoint) answers its relying party.
//
// Over a REAL HANDSHAKE, on a listener the child builds with the main port's
// posture (`requestCert: true, rejectUnauthorized: false` over `common/app`
// and the client truststore), as `tests/tls_client_certificates.js` does:
//
//   A. THE OFFER AND THE SIGN-IN: no offer on a connection that presents
//      nothing; the offer naming the holder on one that presents their
//      certificate; the act starting their session with `["swk"]`, `"1"` and
//      the certificate credential, and the authorization endpoint answering
//      the relying party with a code; the renderer drawing the button.
//   B. THE REFUSALS, each with the screen drawn again and no session: no
//      certificate on the act's connection; an application's certificate;
//      a person's certificate from ANOTHER realm's authority; an application
//      that names the mechanisms it allows (a certificate is not one); the
//      certificate once its holder revoked it.
//
// In a child process, because it loads the whole stack and holds the
// certificate authority, the realms and the revocation register.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const https = require('https');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_AUTHN_CERT_SIGNIN_CHILD';
const REALM = 'certscreen';
const PERSON = 'certalice';
const OTHER = 'certbob';
const CLIENT = 'certscreen-client';
const NARROW = 'certscreen-narrow';
const SECRET = 'certscreen-secret-0123456789abcdef';
const REDIRECT = 'https://rp.certscreen.example/cb';
const UA = 'Mozilla/5.0 (X11; Linux x86_64) certscreen';

// The test CA the child's listener certificate chains to, once made.
const CA_PEM = { value: '' };

const log = require('bunyan').createLogger({ name: 'authn_certificate_signin',
  level: process.env.LOG_LEVEL || 'info' });

// A recording harness: the child cannot reach the parent's `t`, so it keeps
// every assertion and hands the list back.
function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

// One GET on a connection of its own, presenting `cert` where given, keeping
// the jar.
function get(port, jar, urlPath, cert, key) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return new Promise(function (resolve) {
    const headers = { 'user-agent': UA };
    if (Object.keys(jar).length) {
      headers.cookie = Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ');
    }
    const req = https.request({ host: '127.0.0.1', port: port,
      path: String(urlPath).replace(/^https?:\/\/[^/]+/, ''), method: 'GET',
      headers: headers, ca: CA_PEM.value, cert: cert || undefined,
      key: key || undefined, agent: false }, function (res) {
      (res.headers['set-cookie'] || []).forEach(function (line) {
        const pair = line.split(';')[0];
        const eq = pair.indexOf('=');
        jar[pair.slice(0, eq)] = pair.slice(eq + 1);
      });
      res.resume();
      res.on('end', function () {
        resolve({ status: res.statusCode, headers: res.headers });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in get(): " + e.message);
      resolve({ status: 0, headers: {}, error: e.message });
    });
    req.end();
  });
}

// A translator for the renderer: the key and its parameters, escaped as the
// real one escapes them.
function fakeTranslator() {
  log.debug("Entering fakeTranslator().");
  const say = function (key, params) {
    return key + (params ? ' ' + JSON.stringify(params)
      .replace(/</g, '&lt;') : '');
  };
  log.debug("Leaving fakeTranslator().");
  return { html: say, text: say };
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require('../common/protocol_stack');
  const app = require('../common/app');
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const config = require('../common/config');
  const applications = require('../common/applications');
  const tlsClient = require('../common/tls_client_certificates');
  const tls = require('../tls/tls_server');
  const ldap = require('../ldap/ldap_server');
  const authn = require('../authn/authn');
  const screen = require('./tools/authn_screen');
  const errorCodes = require('../common/error_codes');
  const testCa = require('./protocol/outbound_test_ca');

  // EVERY CODE A RESPONSE IS MARKED WITH, in order: the refusals' codes are
  // recorded and never sent, so this is how a test reads them
  // (`federation_signout.js`'s arrangement).
  const marks = [];
  const mark = errorCodes.mark;
  errorCodes.mark = function (res, code) {
    marks.push(code);
    return mark.apply(this, arguments);
  };
  const markedSince = function (since, code) {
    log.debug("Entering markedSince().");
    log.debug("Leaving markedSince().");
    return marks.slice(since).indexOf(code) >= 0;
  };

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  await pki.ensureScope(REALM);
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };
  config.setOverride('oauth2.consentRequired', false);

  // The people, the applications and the certificates.
  inRealm(function () {
    ldap.createUser(PERSON, { invent: false });
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    applications.createApplication({ identifier: NARROW,
      protocols: ['oauth2'],
      fields: { oauthClientId: NARROW, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic',
                appAuthnMechanism: ['password'] } });
  });
  ldap.createUser(OTHER, { invent: false });
  const mine = await inRealm(function () {
    return tlsClient.issue(undefined, { username: PERSON, label: 'laptop',
                                        keyAlg: 'ec-p256' });
  });
  const theirs = await tlsClient.issue(undefined, { username: OTHER,
                                                    keyAlg: 'ec-p256' });
  const appCert = await inRealm(function () {
    return tlsClient.issue(undefined, { kind: 'application',
                                        application: CLIENT,
                                        keyAlg: 'ec-p256' });
  });
  t.check(mine.ok && theirs.ok && appCert.ok,
          'setup: a person\'s certificate in the realm, another realm\'s ' +
          'person\'s, and an application\'s are issued',
          JSON.stringify([mine.errors, theirs.errors, appCert.errors]));
  const pem = function (made) {
    log.debug("Entering pem().");
    log.debug("Leaving pem().");
    return made.issued.certificatePem + made.issued.chainPem.join('');
  };

  // The main port's posture: a client certificate asked for and never
  // required, over the client truststore. The SERVER's certificate is a test
  // CA's for 127.0.0.1, so a browser here verifies it (`ca`) whether or not
  // it presents a certificate of its own.
  const serverCa = await testCa.makeCa();
  const serverLeaf = await testCa.listenerCertificate(serverCa, '127.0.0.1');
  const caPem = serverCa.certPem;
  CA_PEM.value = caPem;
  const listener = https.createServer(Object.assign({
    cert: serverLeaf.cert, key: serverLeaf.key,
    ca: tls.clientTruststoreOptions().ca,
    requestCert: true, rejectUnauthorized: false
  }, tls.protocolOptions()), app);
  // Its own key and certificate kept when the truststore is applied (#472's
  // door for a listener that presents a certificate of its own).
  tls.trustClientCertificatesOn(listener,
    'the authn_certificate_signin listener', function () {
      log.debug("Entering the listener's certificateOf().");
      log.debug("Leaving the listener's certificateOf().");
      return { key: serverLeaf.key, cert: serverLeaf.cert };
    });
  await new Promise(function (ok) {
    listener.listen(0, '127.0.0.1', ok);
  });
  const port = listener.address().port;

  // A pending sign-in at the realm's authorization endpoint, on a browser
  // presenting `cert` (or nothing). Answers the browser and the screen.
  const start = async function (client, cert, key) {
    log.debug("Entering start().");
    const jar = {};
    const sent = await get(port, jar, '/realm/' + REALM + '/oauth2/authorize?' +
      new URLSearchParams({ client_id: client, response_type: 'code',
        redirect_uri: REDIRECT, scope: 'openid', state: 's',
        nonce: 'n-' + Date.now() }).toString(), cert, key);
    const at = String(sent.headers.location || '');
    const opened = await screen.open({ port: port, ca: caPem, jar: jar,
                                       userAgent: UA, cert: cert, key: key,
                                       at: at });
    log.debug("Leaving start().");
    return { jar: jar, at: at, opened: opened };
  };
  const act = function (b, cert, key) {
    log.debug("Entering act().");
    log.debug("Leaving act().");
    return screen.submit({ port: port, ca: caPem, jar: b.jar,
                           userAgent: UA,
                           cert: cert, key: key, at: b.at,
                           opened: b.opened,
                           fields: { action: 'certificate' } });
  };
  const sessionsOf = function (name) {
    log.debug("Entering sessionsOf().");
    log.debug("Leaving sessionsOf().");
    return inRealm(function () {
      return authn.sessionsOf(name);
    });
  };

  // -------------------------------------------------------------------------
  // A. THE OFFER AND THE SIGN-IN
  // -------------------------------------------------------------------------
  const bare = await start(CLIENT);
  t.check(bare.opened.status === 200 && bare.opened.view &&
          !bare.opened.view.certificate,
          'A1: a connection presenting no certificate is offered none',
          JSON.stringify(bare.opened.json).slice(0, 300));
  const b = await start(CLIENT, pem(mine), mine.issued.privateKeyPem);
  const offer = (b.opened.view || {}).certificate || {};
  t.check(offer.name === PERSON && offer.mfaNote === false,
          'A2: a connection presenting the person\'s certificate is offered ' +
          '"Continue as ' + PERSON + '"',
          JSON.stringify(b.opened.view && b.opened.view.certificate));
  const index = await screen.call({ port: port, ca: caPem, jar: b.jar,
    cert: pem(mine),
    key: mine.issued.privateKeyPem, method: 'GET',
    path: '/realm/' + REALM + '/authn-api' });
  t.check(index.status === 200 && JSON.stringify(index.json)
            .indexOf('/authn-api/pending/{id}/certificate') >= 0 &&
          JSON.stringify(index.json).indexOf('"action":"certificate"') >= 0,
          'A3: the index names the act, the screen\'s `certificate` button',
          String(index.text).slice(0, 200));
  const done = await act(b, pem(mine), mine.issued.privateKeyPem);
  t.check(done.next === 'redirect' &&
          /\/oauth2\/authorize/.test(done.location),
          'A4: the act completes the pending sign-in and sends the browser ' +
          'back to the authorization endpoint',
          done.apiStatus + ' ' + String(done.text).slice(0, 300));
  const held = sessionsOf(PERSON);
  const last = held.length ? held[held.length - 1] : null;
  const events = last && Array.isArray(last.events) ? last.events : [];
  const event = events.length ? events[events.length - 1] : {};
  t.check(held.length === 1 &&
          JSON.stringify(event.amr) === JSON.stringify(['swk']) &&
          String(event.acr) === '1' &&
          ((event.context || {}).credential || {}).kind === 'certificate',
          'A5: the session is the certificate\'s: amr ["swk"], acr "1", ' +
          'credential kind certificate — GET /tls/sign-in\'s event',
          JSON.stringify({ sessions: held.length, amr: event.amr,
                           acr: event.acr,
                           credential: (event.context || {}).credential }));
  const back = await get(port, b.jar, done.location, pem(mine),
                         mine.issued.privateKeyPem);
  const landed = String(back.headers.location || '');
  t.check(landed.indexOf(REDIRECT) === 0 && /[?&]code=/.test(landed),
          'A6: and the authorization endpoint answers the relying party ' +
          'with a code — the protocol endpoint itself is unchanged',
          back.status + ' ' + landed);
  const WebAuthnLogin = require('../authn/web_authn_login');
  const drawn = WebAuthnLogin.render(b.opened.view, { t: fakeTranslator() });
  const undrawn = WebAuthnLogin.render(bare.opened.view,
                                       { t: fakeTranslator() });
  t.check(/id="kc-certificate" name="action" value="certificate"/
            .test(drawn) && drawn.indexOf(PERSON) >= 0 &&
          undrawn.indexOf('kc-certificate') < 0,
          'A7: the screen draws the button where it is offered, naming the ' +
          'holder, and not where it is not');

  // -------------------------------------------------------------------------
  // B. THE REFUSALS
  // -------------------------------------------------------------------------
  const refusedAs = function (answer, pattern) {
    log.debug("Entering refusedAs().");
    log.debug("Leaving refusedAs().");
    return answer.apiStatus === 400 && answer.next === 'refused' &&
           pattern.test(answer.errors.join(' '));
  };
  const before = sessionsOf(PERSON).length;
  const noCert = await start(CLIENT, pem(mine), mine.issued.privateKeyPem);
  let since = marks.length;
  const noCertAct = await act(noCert);
  t.check(refusedAs(noCertAct, /No verified client certificate/) &&
          markedSince(since, 'STS-AUTHN-0463') &&
          sessionsOf(PERSON).length === before,
          'B1: an act on a connection presenting no certificate is refused ' +
          'and starts nothing (STS-AUTHN-0463)',
          noCertAct.apiStatus + ' ' + JSON.stringify(noCertAct.errors));
  const again = await screen.open({ port: port, ca: caPem, jar: noCert.jar,
    userAgent: UA, cert: pem(mine), key: mine.issued.privateKeyPem,
    at: noCert.at });
  t.check(again.status === 200 && again.view &&
          again.view.id === noCert.opened.id,
          'B2: the pending sign-in is kept, and the screen drawn again');
  const asApp = await start(CLIENT, pem(appCert),
                            appCert.issued.privateKeyPem);
  since = marks.length;
  const asAppAct = await act(asApp, pem(appCert),
                             appCert.issued.privateKeyPem);
  t.check(!(asApp.opened.view || {}).certificate &&
          refusedAs(asAppAct, /issued to an application/) &&
          markedSince(since, 'STS-AUTHN-0466'),
          'B3: an application\'s certificate is not offered, and its act is ' +
          'refused — it signs nobody in (STS-AUTHN-0466)',
          JSON.stringify(asAppAct.errors));
  const elsewhere = await start(CLIENT, pem(theirs),
                                theirs.issued.privateKeyPem);
  since = marks.length;
  const elsewhereAct = await act(elsewhere, pem(theirs),
                                 theirs.issued.privateKeyPem);
  t.check(!(elsewhere.opened.view || {}).certificate &&
          refusedAs(elsewhereAct, /another realm/) &&
          markedSince(since, 'STS-AUTHN-0465') &&
          inRealm(function () {
            return authn.sessionsOf(OTHER).length;
          }) === 0,
          'B4: a person\'s certificate from another realm\'s authority is ' +
          'not offered, and its act is refused (STS-AUTHN-0465)',
          JSON.stringify(elsewhereAct.errors));
  const narrow = await start(NARROW, pem(mine), mine.issued.privateKeyPem);
  since = marks.length;
  const narrowAct = await act(narrow, pem(mine), mine.issued.privateKeyPem);
  t.check(narrow.opened.view && !narrow.opened.view.certificate &&
          refusedAs(narrowAct, /not offered/) &&
          markedSince(since, 'STS-AUTHN-0467') &&
          sessionsOf(PERSON).length === before,
          'B5: an application that names the mechanisms it allows is not ' +
          'offered the certificate, and the act is refused (STS-AUTHN-0467)',
          JSON.stringify(narrowAct.errors));
  const revoked = tlsClient.revoke(REALM, PERSON, mine.issued.serialHex,
                                   'keyCompromise');
  t.check(revoked.ok, 'B6: the holder revokes the certificate',
          JSON.stringify(revoked.errors || ''));
  const afterRevoke = await start(CLIENT, pem(mine),
                                  mine.issued.privateKeyPem);
  since = marks.length;
  const afterRevokeAct = await act(afterRevoke, pem(mine),
                                   mine.issued.privateKeyPem);
  t.check(refusedAs(afterRevokeAct, /revoked/) &&
          markedSince(since, 'STS-AUTHN-0464') &&
          sessionsOf(PERSON).length === before,
          'B7: and from then on its act is refused on revocation, the chain ' +
          'still verifying (STS-AUTHN-0464)',
          JSON.stringify(afterRevokeAct.errors));

  await new Promise(function (ok) {
    listener.close(ok);
  });
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 240000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('CERT-SIGNIN-CHILD ') === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice('CERT-SIGNIN-CHILD '.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the sign-in screen continues with the TLS client ' +
             'certificate on the connection (#1051) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\nCERT-SIGNIN-CHILD ' + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'authn_certificate_signin',
  describe: 'The sign-in screen offers the TLS client certificate on the ' +
            'connection and completes the pending sign-in on it as GET ' +
            '/tls/sign-in\'s event, amr ["swk"]; refused with no ' +
            'certificate, for an application\'s, for another realm\'s, ' +
            'where the application names its mechanisms, and once revoked',
  run: run
};
