// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/realm_listener.js
// ===========================================================================
// A TRUST REALM'S OWN FRONT-END LISTENER (#99, 2026-10-02).
//
// A realm may set `listener.port` and `listener.publicBaseUrl` (and
// `listener.hostnames`, `listener.certificateFile`, `listener.privateKeyFile`)
// so it is served on a port of its own on every node, behind a load balancer
// of its own, with every URL it builds on its own base and its `/realm/<id>`
// prefix kept. Asserted here, in a CHILD PROCESS (the whole stack is loaded,
// as `protocol_endpoints.js` loads it):
//
//   A. the rules a set of `listener.*` overrides must meet, each by its code:
//      the default realm (0145), a port without a base and a base that is not
//      an https origin (0146), a port the process or another realm uses
//      (0147);
//   B. the rows are `realmOnly`: a realm reads its own value, the default
//      realm the default;
//   C. inside such a realm `helpers.pinnedBaseUrl()` is its base and
//      `baseUrlOf()` keeps the prefix — with no request, as a job reads it;
//   D. the listener over a real socket: bound on the realm's port with the
//      operator's certificate, its discovery document naming the realm's base
//      and prefix, the default realm's path and another realm's refused 404
//      (STS-TLS-0041), and the status the realms view reports;
//   E. the registry drives it: a new port rebinds (the old one closed), a
//      certificate file that cannot be read is a failed listener
//      (STS-TLS-0040), a port in use is one too (STS-TLS-0039), and clearing
//      the port closes it.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'realm_listener',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.RL_ROOT;
  const OUT = process.env.RL_OUT;
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
                    error: '' });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, body: '', json: null, error: e.code || e.message });
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
    const listeners = require(ROOT_DIR + '/tls/realm_listeners');
    const stamp = Date.now().toString(36);
    const A = 'rla-' + stamp;
    const B = 'rlb-' + stamp;
    realms.create({ id: A });
    realms.create({ id: B });
    const port = await freePort();
    const base = 'https://' + A + '.example.test:' + port;
    const codeOf = function (r) {
      return r && r.ok === false ? errorCodes.codeOf(r) : 'accepted';
    };

    // --- A. the rules ------------------------------------------------------
    const onDefault = codeOf(realms.setOverride(realms.DEFAULT_ID,
                                                'listener.port',
                                                String(port)));
    const processWide = config.checkOverride('listener.port', String(port),
                                             false);
    note(onDefault !== 'accepted' && !!processWide,
         'the default realm takes no listener of its own, as a realm ' +
         'override or for the whole process', onDefault + ' | ' +
         processWide);
    note(codeOf(realms.setOverride(A, 'listener.port', String(port))) ===
         'STS-CORE-0146', 'a port without a public base is refused ' +
         '(STS-CORE-0146)');
    note(codeOf(realms.setOverride(A, 'listener.publicBaseUrl',
                                   'http://' + A + '.example.test')) ===
         'STS-CORE-0146', 'a base that is not https is refused');
    note(codeOf(realms.setOverride(A, 'listener.publicBaseUrl',
                                   base + '/realm')) === 'STS-CORE-0146',
         'a base with a path is refused');
    note(codeOf(realms.setOverride(A, 'listener.publicBaseUrl', base)) ===
         'accepted', 'an https origin is accepted as the base');
    const mainPort = Number(config.processValue('global.port'));
    note(codeOf(realms.setOverride(A, 'listener.port', String(mainPort))) ===
         'STS-CORE-0147', 'the main port is refused (STS-CORE-0147)');
    note(codeOf(realms.setOverride(A, 'listener.port', String(port))) ===
         'accepted', 'a free port is accepted');
    realms.setOverride(B, 'listener.publicBaseUrl',
                       'https://' + B + '.example.test');
    note(codeOf(realms.setOverride(B, 'listener.port', String(port))) ===
         'STS-CORE-0147', 'another realm\'s port is refused');

    // --- B. realm-only -----------------------------------------------------
    const inA = realms.run(realms.get(A), function () {
      return Number(config.value('listener.port'));
    });
    note(inA === port && Number(config.value('listener.port')) === 0,
         'the realm reads its own listener.port; the default realm reads 0',
         inA);

    // --- C. the URL rule ---------------------------------------------------
    const fakeReq = { protocol: 'https', headers: { host: 'idp.test' },
                      get: function () { return 'idp.test'; } };
    const pinned = realms.run(realms.get(A), function () {
      return helpers.pinnedBaseUrl();
    });
    const built = realms.run(realms.get(A), function () {
      return helpers.baseUrlOf(fakeReq);
    });
    note(pinned === base && built === base + realms.prefixOf(realms.get(A)),
         'inside the realm the base is its own, and the /realm prefix is ' +
         'kept', pinned + ' | ' + built);
    const outside = helpers.baseUrlOf(fakeReq);
    note(outside.indexOf(base) < 0,
         'the default realm is not on the realm\'s base', outside);

    // --- D. the listener ---------------------------------------------------
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'realm-listener-'));
    const made = stsCrypto.selfSignedRsaCertificate({
      commonName: A + '.example.test' });
    const certFile = path.join(dir, 'cert.pem');
    const keyFile = path.join(dir, 'key.pem');
    fs.writeFileSync(certFile, made.certPem);
    fs.writeFileSync(keyFile, made.privateKeyPem);
    realms.setOverride(A, 'listener.certificateFile', certFile);
    realms.setOverride(A, 'listener.privateKeyFile', keyFile);
    await listeners.start({
      build: function (label, certificate) {
        const server = https.createServer({
          key: certificate.key, cert: certificate.cert,
          requestCert: true, rejectUnauthorized: false
        }, app);
        return server;
      }
    });
    await listeners.reconcile();
    const prefixA = realms.prefixOf(realms.get(A));
    const disc = await get(port, prefixA +
                           '/.well-known/openid-configuration');
    note(disc.status === 200 && disc.json &&
         disc.json.issuer === base + prefixA,
         'the realm\'s discovery document on its own port names its own ' +
         'base and prefix', disc.status + ' ' +
         (disc.json ? disc.json.issuer : disc.body.slice(0, 200)));
    const dflt = await get(port, '/.well-known/openid-configuration');
    note(dflt.status === 404 && /serves realm/.test(dflt.body),
         'the default realm\'s path is not served there (STS-TLS-0041)',
         dflt.status + ' ' + dflt.body.slice(0, 120));
    const other = await get(port, realms.prefixOf(realms.get(B)) +
                            '/.well-known/openid-configuration');
    note(other.status === 404, 'another realm\'s path is not served there',
         other.status);
    const row = listeners.status(A)[0] || {};
    note(row.state === 'bound' && row.port === port &&
         row.certificate && row.certificate.source === 'file' &&
         !('key' in row.certificate),
         'the status reports the listener bound with the operator\'s ' +
         'certificate, and no key', JSON.stringify(row));

    // --- E. the registry drives it -----------------------------------------
    const port2 = await freePort();
    realms.setOverride(A, 'listener.port', String(port2));
    await settle(50);
    await listeners.reconcile();
    const gone = await get(port, prefixA + '/.well-known/openid-configuration');
    const moved = await get(port2, prefixA +
                            '/.well-known/openid-configuration');
    note(gone.status === 0 && moved.status === 200,
         'a new port closes the old listener and binds the new one',
         'old ' + (gone.status || gone.error) + ', new ' + moved.status);
    realms.setOverride(A, 'listener.certificateFile', certFile + '.missing');
    await settle(50);
    await listeners.reconcile();
    const bad = listeners.status(A)[0] || {};
    realms.clearOverride(A, 'listener.privateKeyFile');
    await settle(50);
    await listeners.reconcile();
    const half = listeners.status(A)[0] || {};
    note(half.state === 'failed' && half.code === 'STS-TLS-0040' &&
         /both or neither/.test(half.why),
         'a certificate without its key is a failed listener that says so',
         JSON.stringify(half));
    realms.setOverride(A, 'listener.privateKeyFile', keyFile);
    note(bad.state === 'failed' && bad.code === 'STS-TLS-0040',
         'a certificate file that cannot be read is a failed listener ' +
         '(STS-TLS-0040), not a stopped service', JSON.stringify(bad));
    realms.setOverride(A, 'listener.certificateFile', certFile);
    const blocker = net.createServer();
    const port3 = await freePort();
    await new Promise(function (r) { blocker.listen(port3, r); });
    realms.setOverride(A, 'listener.port', String(port3));
    await settle(50);
    await listeners.reconcile();
    const busy = listeners.status(A)[0] || {};
    note(busy.state === 'failed' && busy.code === 'STS-TLS-0039',
         'a port in use is a failed listener (STS-TLS-0039)',
         JSON.stringify(busy));
    blocker.close();
    realms.clearOverride(A, 'listener.port');
    await settle(50);
    await listeners.reconcile();
    note(listeners.status(A).length === 0,
         'clearing the port closes the listener',
         JSON.stringify(listeners.status(A)));

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
  const out = path.join(os.tmpdir(), 'realm-listener-' + process.pid +
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
                                  RL_ROOT: ROOT, RL_OUT: out }),
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
  name: 'realm_listener',
  describe: 'a trust realm\'s own front-end listener: the settings\' rules, ' +
            'the URL base, the socket and the registry driving it (#99)',
  run: run
};
