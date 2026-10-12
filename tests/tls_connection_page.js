// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tls_connection_page.js
//
// ===========================================================================
// MONITORING → TLS CONNECTION, IN PROCESS (#597, 2026-10-12; rcbj's decision
// 3 on #591).
//
// `GET /tls` and `GET /tls/forwarded` became one console page,
// `/admin/tls-connection`, drawn from `GET /admin-api/tls-connection`
// (`tls/tls_server.js`'s `connectionView()`). In a CHILD process, because it
// loads the whole protocol stack, and over a REAL TLS listener of the
// child's own — asked-for-never-required like the main port, serving the
// shared app — because what is under test is what a handshake left on the
// socket:
//
//   1. With no client certificate, the operation describes the request: TLS
//      version and cipher, nothing presented, every forwarding header by
//      the value this request sent, the client-certificate headers seen and
//      read by nothing, and `global.trustProxy` off so nothing believed.
//   2. With a client certificate whose Root is in the truststore: presented,
//      VERIFIED, its subject and fingerprint, an RFC 8705 thumbprint, the
//      identity gate's answer (not issued here) — and no session started.
//      Untrusted, the same certificate is presented and NOT verified, with
//      OpenSSL's reason.
//   3. `global.trustProxy` on: believed from any peer while
//      `global.trustedProxies` is empty, and the effective base URL follows
//      the forwarded host; with a range the peer is not in, not believed.
//   4. The page: drawn by the static console's renderer from the
//      operation's answer (`tests/tools/console_page.js`); the renderer
//      escapes what a request chose.
//   5. Where it is answered and by whom: both paths pinned to the front
//      process, NOT a service page (a realm's administrator may ask what
//      their own connection carried), the operation mirrors the page, and
//      the old paths answer as unrouted.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'tls_connection_page',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

function childMain() {
  const ROOT_DIR = process.env.TC_ROOT;
  const OUT = process.env.TC_OUT;
  const https = require('https');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const config = require(ROOT_DIR + '/common/config');
    const tls = require(ROOT_DIR + '/tls/tls_server');
    const requestPool = require(ROOT_DIR + '/common/request_pool');
    const adminScope = require(ROOT_DIR + '/admin-ui/admin_scope');
    const adminApi = require(ROOT_DIR + '/mgmt-api/admin_api');
    const credentials = require(ROOT_DIR + '/tests/tools/pep-credential.js');
    const Page = require(ROOT_DIR + '/tls/web_tls_connection');
    const WebKit = require(ROOT_DIR + '/admin-ui/web_kit');
    const nodeCrypto = require('crypto');

    // The open API, development only: the gate is `tests/vendored/
    // sts_tls_connection.js`'s to hold; what is asked here is the view.
    config.setOverride('adminApi.authRequired', false);
    const listener = https.createServer(
      Object.assign({ requestCert: true, rejectUnauthorized: false },
                    tls.clientTruststoreOptions()), app);
    await new Promise(function (ok) {
      listener.listen(0, '127.0.0.1', ok);
    });
    tls.trustClientCertificatesOn(listener, 'the tls_connection_page test ' +
                                            'listener');
    const port = listener.address().port;
    function ask(method, p, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const req = https.request({ host: '127.0.0.1', port: port,
          method: method, path: p, agent: false, rejectUnauthorized: false,
          cert: o.cert, key: o.key,
          headers: Object.assign({ accept: 'application/json' },
                                 o.headers || {}) },
        function (res) {
          let text = '';
          res.on('data', function (c) {
            text += c;
          });
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
          resolve({ status: 0, text: 'error: ' + e.message, json: null,
                    headers: {} });
        });
        req.end();
      });
    }

    // --- 1. no client certificate -----------------------------------------
    let r = await ask('GET', '/admin-api/tls-connection', { headers: {
      'x-forwarded-host': 'forged<1>.example',
      'x-forwarded-proto': 'http',
      'x-ssl-client-cert': 'forged' } });
    let v = r.json || {};
    const row = function (rows, name) {
      return (rows || []).filter(function (one) {
        return one.header === name;
      })[0] || {};
    };
    note(r.status === 200 && v.connection && v.connection.https === true &&
         v.connection.encrypted === true &&
         /^TLSv1\.[23]$/.test(String(v.connection.protocol)) &&
         !!v.connection.cipher && v.connection.peerAddress === '127.0.0.1',
         '1a. the operation describes the TLS connection the request came on',
         r.status + ' ' + JSON.stringify(v.connection));
    note(v.clientCertificate && v.clientCertificate.presented === false &&
         v.clientCertificate.verified === false &&
         v.clientCertificate.certificate === null,
         '1b. with nothing presented, nothing is described',
         JSON.stringify(v.clientCertificate));
    const f = v.forwarded || {};
    note(row(f.forwarding, 'x-forwarded-host').value === 'forged<1>.example' &&
         row(f.forwarding, 'x-forwarded-for').present === false &&
         f.trustProxy === false && f.believed === false &&
         !/forged/.test(String(f.effectiveBaseUrl)),
         '1c. every forwarding header is listed by this request\'s value, ' +
         'and with global.trustProxy off nothing is believed',
         JSON.stringify({ forwarding: f.forwarding,
                          base: f.effectiveBaseUrl }));
    note(f.clientCertificateHeaders &&
         f.clientCertificateHeaders.readByThisService === false &&
         f.clientCertificateHeaders.seen.indexOf('x-ssl-client-cert') >= 0,
         '1d. a client-certificate header is seen and read by nothing',
         JSON.stringify(f.clientCertificateHeaders &&
                        f.clientCertificateHeaders.seen));

    // --- 2. a client certificate ------------------------------------------
    const stamp = process.pid + '-' + Date.now();
    const cred = await credentials.mint({
      rootSubject: 'CN=tls-connection Root ' + stamp + ',O=iya-sts tests',
      subject: 'CN=tls-connection-leaf,O=iya-sts tests' });
    r = await ask('GET', '/admin-api/tls-connection',
                  { cert: cred.certPem, key: cred.keyPem });
    v = r.json || {};
    note(v.clientCertificate && v.clientCertificate.presented === true &&
         v.clientCertificate.verified === false &&
         !!v.clientCertificate.authorizationError,
         '2a. untrusted, the certificate is presented and NOT verified, ' +
         'with OpenSSL\'s reason', JSON.stringify(v.clientCertificate &&
           { verified: v.clientCertificate.verified,
             error: v.clientCertificate.authorizationError }));
    tls.addAnchors(cred.anchorPem);
    const anchorFingerprint = new nodeCrypto.X509Certificate(cred.anchorPem)
      .fingerprint256;
    try {
      r = await ask('GET', '/admin-api/tls-connection',
                    { cert: cred.certPem, key: cred.keyPem });
      v = r.json || {};
      const cc = v.clientCertificate || {};
      const leaf = new nodeCrypto.X509Certificate(cred.certPem);
      note(cc.presented === true && cc.verified === true &&
           cc.authorizationError === null &&
           /tls-connection-leaf/.test(String(cc.certificate &&
                                             cc.certificate.subject)) &&
           String(cc.certificate.fingerprint256).toUpperCase() ===
             leaf.fingerprint256.toUpperCase() && !!cc.thumbprint,
           '2b. trusted, it is presented and VERIFIED, with its subject, ' +
           'fingerprint and thumbprint', JSON.stringify(cc).slice(0, 500));
      note(cc.identity && cc.identity.issuedHere === false &&
           cc.identity.accepted === false && 'revocation' in cc,
           '2c. the identity gate says it was not issued here, and the ' +
           'revocation verdict is carried', JSON.stringify(cc.identity));
      note(!(r.headers['set-cookie'] || []).some(function (c) {
        return /^sts_session=/.test(c);
      }), '2d. and no session was started',
           JSON.stringify(r.headers['set-cookie']));
    } finally {
      tls.removeAnchor(anchorFingerprint);
    }

    // --- 3. global.trustProxy --------------------------------------------
    config.setOverride('global.trustProxy', true);
    try {
      r = await ask('GET', '/admin-api/tls-connection', { headers: {
        'x-forwarded-host': 'proxied.example',
        'x-forwarded-proto': 'https' } });
      v = r.json || {};
      note(v.forwarded && v.forwarded.trustProxy === true &&
           v.forwarded.believed === true &&
           v.forwarded.peerIsTrustedProxy === true &&
           /^https:\/\/proxied\.example/.test(v.forwarded.effectiveBaseUrl),
           '3a. with global.trustProxy on and no ranges, the forwarded host ' +
           'is believed from any peer', JSON.stringify(v.forwarded &&
             { believed: v.forwarded.believed,
               base: v.forwarded.effectiveBaseUrl }));
      config.setOverride('global.trustedProxies', '10.99.99.0/24');
      require(ROOT_DIR + '/common/client_address').reset();
      r = await ask('GET', '/admin-api/tls-connection', { headers: {
        'x-forwarded-host': 'proxied.example' } });
      v = r.json || {};
      note(v.forwarded && v.forwarded.believed === false &&
           v.forwarded.peerIsTrustedProxy === false &&
           v.forwarded.rangesConfigured > 0 &&
           !/proxied/.test(String(v.forwarded.effectiveBaseUrl)),
           '3b. with a range the peer is not in, nothing is believed',
           JSON.stringify(v.forwarded && { believed: v.forwarded.believed,
             ranges: v.forwarded.trustedProxies,
             base: v.forwarded.effectiveBaseUrl }));
    } finally {
      config.clearOverride('global.trustedProxies');
      config.clearOverride('global.trustProxy');
      require(ROOT_DIR + '/common/client_address').reset();
    }

    // --- 4. the page --------------------------------------------------------
    const drawer = require(ROOT_DIR + '/tests/tools/console_page.js')
      .consolePage(ROOT_DIR);
    const drawn = await drawer.draw('/admin/tls-connection', {});
    note(drawn.status === 200 &&
         /<h2 data-tab="connection">/.test(drawn.html) &&
         /<h2 data-tab="forwarded">/.test(drawn.html) &&
         drawn.html.indexOf('/admin-api/tls-connection') > 0 &&
         drawn.html.indexOf('<script') < 0,
         '4a. the static console draws the page from its operation, two ' +
         'tabs', drawn.status + ' ' + String(drawn.html).slice(0, 300));
    const hostile = Page.render({
      connection: { https: true, protocol: 'TLSv1.3<x>', cipher: 'c&d' },
      clientCertificate: { presented: true, verified: false,
        authorizationError: 'E<1>',
        certificate: { subject: 'CN=<script>', issuer: 'CN="q"' },
        identity: { issuedHere: true, accepted: false, why: 'W<2>' },
        revocation: { status: 'unknown', why: 'R<3>' }, note: 'N<4>' },
      forwarded: { trustProxy: false, trustedProxies: [], believed: false,
        socket: { scheme: 'https', host: 'h<5>' },
        effectiveBaseUrl: 'https://b<6>', whatItMeans: 'M<7>',
        forwarding: [{ header: 'x-forwarded-host', present: true,
                       value: 'v<8>', what: 'w<9>' }],
        clientCertificateHeaders: { note: 'c<10>', headers: [] },
        proxyMustSanitize: 'p<11>' } }, WebKit.context());
    note(hostile.indexOf('<script>') < 0 &&
         ['TLSv1.3&lt;x&gt;', 'CN=&lt;script&gt;', 'E&lt;1&gt;', 'W&lt;2&gt;',
          'R&lt;3&gt;', 'N&lt;4&gt;', 'h&lt;5&gt;', 'M&lt;7&gt;', 'v&lt;8&gt;',
          'p&lt;11&gt;'].every(function (s) {
            return hostile.indexOf(s) >= 0;
          }),
         '4b. the renderer escapes everything a request or a certificate ' +
         'chose', hostile.slice(0, 400));

    // --- 5. where, and by whom ---------------------------------------------
    const had = process.env.STS_WORKERS_DISPATCH;
    process.env.STS_WORKERS_DISPATCH = '*';
    try {
      note(requestPool.dispatched('/admin-api/tls-connection') === false &&
           requestPool.dispatched('/admin/tls-connection') === false &&
           requestPool.dispatched('/realm/acme/admin-api/tls-connection') ===
             false,
           '5a. both paths are answered by the front process, which holds ' +
           'the client\'s socket');
    } finally {
      if (had === undefined) {
        delete process.env.STS_WORKERS_DISPATCH;
      } else {
        process.env.STS_WORKERS_DISPATCH = had;
      }
    }
    note(!adminScope.pageIsService('/admin/tls-connection'),
         '5b. not a service page: a realm\'s administrator may ask what ' +
         'their own connection carried');
    const op = adminApi.ROUTES.filter(function (one) {
      return one.method === 'GET' && one.path === '/admin-api/tls-connection';
    })[0];
    note(!!op && op.mirrors === 'GET /admin/tls-connection' &&
         op.tag === 'TLS', '5c. the operation mirrors the page (rule 7)',
         JSON.stringify(op && { mirrors: op.mirrors, tag: op.tag }));
    const gone = [];
    for (const asked of [['GET', '/tls'], ['GET', '/tls/forwarded'],
                         ['GET', '/tls/pages.js'], ['POST', '/tls/trust'],
                         ['POST', '/tls/trust/clear']]) {
      r = await ask(asked[0], asked[1]);
      if (r.status !== 404 ||
          r.text.indexOf('Cannot ' + asked[0] + ' ' + asked[1]) < 0) {
        gone.push(asked.join(' ') + ' ' + r.status);
      }
    }
    note(gone.length === 0, '5d. the old paths answer as unrouted',
         gone.join(', ') || 'all unrouted');

    config.clearOverride('adminApi.authRequired');
    listener.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'tls-connection-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
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
                                  TC_ROOT: ROOT, TC_OUT: out }),
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
  if (!findings) {
    t.check(false, 'the child process reported its findings',
            String(result.stderr || result.error || '').slice(-2000));
    log.debug("Leaving run(). No findings.");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls_connection_page',
  describe: '#597: Monitoring → TLS connection — GET ' +
            '/admin-api/tls-connection over a real TLS listener, with and ' +
            'without a client certificate, the forwarding headers believed ' +
            'and not, the page drawn and escaped, pinned to the front ' +
            'process, and the old /tls paths unrouted',
  run: run
};
