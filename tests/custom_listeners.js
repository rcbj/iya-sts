// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/custom_listeners.js
// ===========================================================================
// CUSTOM LISTENERS AND THE HOSTED APPLICATIONS MAPPED TO THEM (#472,
// 2026-10-07; it was tests/realm_listener.js, #99's, whose realm listener is
// one of them now).
//
// Asserted in a CHILD PROCESS (the whole stack is loaded, as
// `protocol_endpoints.js` loads it):
//
//   A. the rules every write is held to, each by its code: a malformed
//      definition (STS-CORE-0153), a public base that is not an https origin
//      (0146), a port the process uses (0147), `listeners.realm` on the
//      default realm (0145), a mapping naming an unknown application or
//      listener, another realm's listener, or removing a mapped listener, or
//      oidfed off the issuer's listener (0154), the sign-on session's
//      applications on two host names without, and then with,
//      `authn.cookieDomain` (0155), and a mapping write taking the management
//      API off the listener the request arrived on, refused (0156) and then
//      confirmed;
//   B. the mapping as read: a realm's own entries before the service's, and
//      its `*` before the service's entries;
//   C. the URL rule: `pinnedBaseUrl(app)`, `baseUrlOf(req, app)` and
//      `urlOf()` on the advertised listener's base, the realm prefix kept,
//      with no request as a job reads it — and a realm mapping `*` to its
//      own listener is #99's realm listener;
//   D. the listeners over real sockets: a service listener answering only
//      the console and the API (the authorization server refused there,
//      STS-TLS-0046, naming where it is), the console's shell telling its
//      runtime where the authorization server is and letting it connect
//      there; a realm's own listener answering only its realm (STS-TLS-0041)
//      and its discovery document naming its own base;
//   E. the definitions drive the sockets: a new port rebinds, a certificate
//      file that cannot be read is a failed listener (STS-TLS-0040), a port
//      in use is one too (STS-TLS-0039), and removing the definition closes
//      it.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'custom_listeners',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.CL_ROOT;
  const OUT = process.env.CL_OUT;
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const net = require('net');
  const https = require('https');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function freePort() {
    return new Promise(function (resolve) {
      const s = net.createServer();
      s.listen(0, '127.0.0.1', function () {
        const port = s.address().port;
        s.close(function () { resolve(port); });
      });
    });
  }
  function get(port, urlPath) {
    return new Promise(function (resolve) {
      const req = https.get({ host: '127.0.0.1', port: port, path: urlPath,
                              rejectUnauthorized: false }, function (res) {
        let body = '';
        res.on('data', function (c) { body += c; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(body);
          } catch (e) {
            // Not JSON: a refusal is text, and the finding reads `body`.
            json = null;
          }
          resolve({ status: res.statusCode, body: body, json: json,
                    headers: res.headers, error: '' });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, body: '', json: null, headers: {},
                  error: e.code || e.message });
      });
    });
  }
  function settle(ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const realms = require(ROOT_DIR + '/common/realms');
    const config = require(ROOT_DIR + '/common/config');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const listenerMap = require(ROOT_DIR + '/common/listener_map');
    const ambient = require(ROOT_DIR + '/common/jose_certificate_header');
    const listeners = require(ROOT_DIR + '/tls/listeners');
    const stamp = Date.now().toString(36);
    const A = 'cla-' + stamp;
    const B = 'clb-' + stamp;
    realms.create({ id: A });
    realms.create({ id: B });
    const codeOf = function (r) {
      return r && r.ok === false ? errorCodes.codeOf(r) : 'accepted';
    };
    const json = function (v) {
      return JSON.stringify(v);
    };
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custom-listeners-'));
    const made = stsCrypto.selfSignedRsaCertificate({
      commonName: 'admin.example.test' });
    const certFile = path.join(dir, 'cert.pem');
    const keyFile = path.join(dir, 'key.pem');
    fs.writeFileSync(certFile, made.certPem);
    fs.writeFileSync(keyFile, made.privateKeyPem);
    const admPort = await freePort();
    const realmPort = await freePort();
    const admBase = 'https://admin.example.test:' + admPort;
    const realmBase = 'https://' + A + '.example.test:' + realmPort;
    const adm = { id: 'adm', port: admPort, publicBaseUrl: admBase,
                  certificateFile: certFile, privateKeyFile: keyFile };

    // --- A. the rules ------------------------------------------------------
    note(codeOf(config.setOverride('listeners.custom', '[{"id":')) ===
         'STS-CORE-0153', 'a definition that is not JSON is refused ' +
         '(STS-CORE-0153)');
    note(codeOf(config.setOverride('listeners.custom',
         json([Object.assign({}, adm, { id: 'main' })]))) === 'STS-CORE-0153',
         'a reserved id is refused');
    const plain = Object.assign({}, adm, { publicBaseUrl: 'http://x.test' });
    note(codeOf(config.setOverride('listeners.custom', json([plain]))) ===
         'STS-CORE-0146', 'a public base that is not https is refused ' +
         '(STS-CORE-0146)');
    const mainPort = Number(config.processValue('global.port'));
    note(codeOf(config.setOverride('listeners.custom',
         json([Object.assign({}, adm, { port: mainPort })]))) ===
         'STS-CORE-0147', 'the main port is refused (STS-CORE-0147)');
    note(codeOf(config.setOverride('listeners.custom', json([adm]))) ===
         'accepted', 'a well-formed service listener is accepted');
    note(codeOf(realms.setOverride(realms.DEFAULT_ID, 'listeners.realm',
         json([adm]))) !== 'accepted',
         'the default realm takes no listeners.realm: its listeners are ' +
         'the service\'s');
    note(codeOf(config.setOverride('listeners.applications',
         json({ nothing: { listeners: ['adm'] } }))) === 'STS-CORE-0154',
         'a mapping naming no application is refused (STS-CORE-0154)');
    note(codeOf(config.setOverride('listeners.applications',
         json({ portal: { listeners: ['nowhere'] } }))) === 'STS-CORE-0154',
         'a mapping naming a listener nobody defined is refused');
    note(codeOf(config.setOverride('listeners.applications',
         json({ 'oauth-oidc': { listeners: ['adm'] } }))) === 'STS-CORE-0154',
         'oauth-oidc advertised where oidfed is not is refused (the Entity ' +
         'Configuration is fetched at the issuer)');
    note(codeOf(config.setOverride('listeners.applications', json({
      'admin-console': { listeners: ['adm'] },
      'management-api': { listeners: ['adm'] } }))) === 'accepted',
         'the console and the API moved to the custom listener');
    note(codeOf(config.setOverride('listeners.custom', '')) ===
         'STS-CORE-0154', 'a listener the mapping names cannot be removed');
    note(codeOf(realms.setOverride(A, 'listeners.realm', json([{
      id: 'ra', port: realmPort, publicBaseUrl: realmBase,
      certificateFile: certFile, privateKeyFile: keyFile }]))) === 'accepted',
         'a realm\'s own listener is accepted');
    note(codeOf(realms.setOverride(B, 'listeners.applications', json({
      portal: { listeners: ['ra'] } }))) === 'STS-CORE-0154',
         'another realm\'s listener is refused in a realm\'s mapping');
    // The sign-on session's applications on two host names.
    const p2Port = await freePort();
    const twoHosts = json([adm, { id: 'p2', port: p2Port,
      publicBaseUrl: 'https://portal.other.test:' + p2Port,
      certificateFile: certFile, privateKeyFile: keyFile }]);
    note(codeOf(config.setOverride('listeners.custom', twoHosts)) ===
         'accepted', 'a second listener is accepted while nothing is on it');
    const split = json({ 'admin-console': { listeners: ['adm'] },
                         'management-api': { listeners: ['adm'] },
                         authn: { listeners: ['adm'] },
                         portal: { listeners: ['p2'] } });
    note(codeOf(config.setOverride('listeners.applications', split)) ===
         'STS-CORE-0155', 'authn and the portal on two host names with a ' +
         'host-only cookie are refused (STS-CORE-0155)');
    note(codeOf(config.setOverride('authn.cookieDomain', 'example.test')) ===
         'accepted', 'a cookie domain is accepted');
    note(codeOf(config.setOverride('listeners.applications', split)) ===
         'STS-CORE-0155', 'a host name not under the cookie domain is ' +
         'still refused');
    config.setOverride('authn.cookieDomain', '');
    config.setOverride('listeners.applications', json({
      'admin-console': { listeners: ['adm'] },
      'management-api': { listeners: ['adm'] } }));
    // D6: the API taken off the listener the write arrived on.
    const onAdm = { stsListener: 'adm', headers: {}, socket: {} };
    const moveApi = json({ 'admin-console': { listeners: ['adm'] } });
    const unconfirmed = ambient.enterRequest(onAdm, function () {
      return codeOf(config.setOverride('listeners.applications', moveApi));
    });
    note(unconfirmed === 'STS-CORE-0156', 'taking the management API off ' +
         'the listener the write arrived on is refused (STS-CORE-0156)',
         unconfirmed);
    onAdm.stsListenerChangeConfirmed = true;
    const confirmed = ambient.enterRequest(onAdm, function () {
      return codeOf(config.setOverride('listeners.applications', moveApi));
    });
    note(confirmed === 'accepted', 'and accepted when confirmed', confirmed);
    config.setOverride('listeners.custom', json([adm]));
    config.setOverride('listeners.applications', json({
      'admin-console': { listeners: ['adm'] },
      'management-api': { listeners: ['adm'] } }));
    note(codeOf(realms.setOverride(A, 'listeners.applications', json({
      '*': { listeners: ['main', 'ra'], advertised: 'ra' } }))) ===
         'accepted', 'a realm maps * to its own listener');

    // --- B. the mapping as read -------------------------------------------
    const inA = function (fn) {
      return realms.run(realms.get(A), fn);
    };
    const inB = function (fn) {
      return realms.run(realms.get(B), fn);
    };
    const consoleA = inA(function () {
      return listenerMap.effective('admin-console');
    });
    const consoleB = inB(function () {
      return listenerMap.effective('admin-console');
    });
    const oauthDefault = listenerMap.effective('oauth-oidc');
    note(json(consoleA.listeners) === '["main","ra"]' &&
         consoleA.advertised === 'ra' &&
         json(consoleB.listeners) === '["adm"]' &&
         json(oauthDefault.listeners) === '["main"]',
         'a realm\'s * comes before the service\'s entries; a realm with no ' +
         'mapping inherits them; an unnamed application is on main',
         json([consoleA, consoleB, oauthDefault]));

    // --- C. the URL rule ---------------------------------------------------
    const fakeReq = { protocol: 'https', headers: { host: 'idp.test' },
                      originalUrl: '/admin-api/status',
                      get: function () { return 'idp.test'; } };
    note(helpers.pinnedBaseUrl('management-api') === admBase &&
         helpers.baseUrlOf(fakeReq) === admBase &&
         helpers.urlOf(null, '/admin') === admBase + '/admin',
         'the API and the console are built on their listener\'s base',
         helpers.baseUrlOf(fakeReq));
    note(helpers.baseUrlOf(fakeReq, 'oauth-oidc') === 'https://idp.test',
         'the authorization server, on main, keeps the request\'s base',
         helpers.baseUrlOf(fakeReq, 'oauth-oidc'));
    const prefixA = realms.prefixOf(realms.get(A));
    const pinnedA = inA(function () {
      return helpers.pinnedBaseUrl();
    });
    const builtA = inA(function () {
      return helpers.baseUrlOf(fakeReq, 'oauth-oidc');
    });
    note(pinnedA === realmBase && builtA === realmBase + prefixA,
         'a realm mapping * to its own listener is built on its base with ' +
         'its prefix — #99\'s realm listener', pinnedA + ' | ' + builtA);

    // --- D. the sockets ----------------------------------------------------
    await listeners.start({
      build: function (label, certificate) {
        return https.createServer({
          key: certificate.key, cert: certificate.cert,
          requestCert: true, rejectUnauthorized: false
        }, app);
      }
    });
    await listeners.reconcile();
    const status = listeners.status();
    note(status.length === 2 && status.every(function (one) {
      return one.state === 'bound' && one.certificate &&
             one.certificate.source === 'file' && !('key' in one.certificate);
    }), 'both listeners are bound with the operator\'s certificate, and no ' +
        'key is reported', json(status));
    const offHere = await get(admPort, '/.well-known/openid-configuration');
    note(offHere.status === 404 &&
         /is not served on this listener/.test(offHere.body) &&
         offHere.body.indexOf(':' + mainPort) > 0,
         'the authorization server is refused on the console\'s listener ' +
         '(STS-TLS-0046), and the answer says where it is',
         offHere.status + ' ' + offHere.body.slice(0, 200));
    // A deep link: the console's root may ask which realm first.
    const shell = await get(admPort, '/admin/listeners');
    note(shell.status === 200 && /data-sts-oauth="https?:/.test(shell.body) &&
         /connect-src 'self' https?:/.test(
           String(shell.headers['content-security-policy'] || '')),
         'the console\'s shell tells its runtime where the authorization ' +
         'server is, and lets it connect there',
         shell.status + ' ' +
         String(shell.headers['content-security-policy'] || '').slice(0, 200));
    const disc = await get(realmPort, prefixA +
                           '/.well-known/openid-configuration');
    note(disc.status === 200 && disc.json &&
         disc.json.issuer === realmBase + prefixA,
         'the realm\'s discovery document on its own listener names its own ' +
         'base and prefix', disc.status + ' ' +
         (disc.json ? disc.json.issuer : disc.body.slice(0, 200)));
    const dflt = await get(realmPort, '/.well-known/openid-configuration');
    note(dflt.status === 404 && /serves realm/.test(dflt.body),
         'the default realm\'s path is not served on a realm\'s listener ' +
         '(STS-TLS-0041)', dflt.status + ' ' + dflt.body.slice(0, 120));

    // --- E. the definitions drive the sockets -----------------------------
    const port2 = await freePort();
    const realmDef = function (over) {
      return json([Object.assign({ id: 'ra', port: realmPort,
        publicBaseUrl: realmBase, certificateFile: certFile,
        privateKeyFile: keyFile }, over || {})]);
    };
    realms.setOverride(A, 'listeners.realm', realmDef({ port: port2 }));
    await settle(50);
    await listeners.reconcile();
    const gone = await get(realmPort, prefixA +
                           '/.well-known/openid-configuration');
    const moved = await get(port2, prefixA +
                            '/.well-known/openid-configuration');
    note(gone.status === 0 && moved.status === 200,
         'a new port closes the old listener and binds the new one',
         'old ' + (gone.status || gone.error) + ', new ' + moved.status);
    realms.setOverride(A, 'listeners.realm',
                       realmDef({ port: port2,
                                  certificateFile: certFile + '.missing' }));
    await settle(50);
    await listeners.reconcile();
    const bad = listeners.status(A)[0] || {};
    note(bad.state === 'failed' && bad.code === 'STS-TLS-0040',
         'a certificate file that cannot be read is a failed listener ' +
         '(STS-TLS-0040), not a stopped service', json(bad));
    const blocker = net.createServer();
    const port3 = await freePort();
    await new Promise(function (r) { blocker.listen(port3, r); });
    realms.setOverride(A, 'listeners.realm', realmDef({ port: port3 }));
    await settle(50);
    await listeners.reconcile();
    const busy = listeners.status(A)[0] || {};
    note(busy.state === 'failed' && busy.code === 'STS-TLS-0039',
         'a port in use is a failed listener (STS-TLS-0039)', json(busy));
    blocker.close();
    realms.setOverride(A, 'listeners.applications', '');
    note(codeOf(realms.setOverride(A, 'listeners.realm', '')) === 'accepted',
         'a realm\'s listener no mapping names can be removed');
    await settle(50);
    await listeners.reconcile();
    note(listeners.status(A).length === 0,
         'removing the definition closes the listener',
         json(listeners.status(A)));

    listeners.stop();
    fs.rmSync(dir, { recursive: true, force: true });
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
  const out = path.join(os.tmpdir(), 'custom-listeners-' + process.pid +
                        '-' + Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  CL_ROOT: ROOT, CL_OUT: out }),
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
  name: 'custom_listeners',
  describe: 'custom listeners and the hosted applications mapped to them: ' +
            'the rules, the mapping, the URL bases, the sockets and the ' +
            'definitions driving them (#472, #99)',
  run: run
};
