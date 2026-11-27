// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/healthcheck_probe.js
//
// ===========================================================================
// THE CONTAINER'S HEALTHCHECK VERIFIES THE CERTIFICATE (2026-11-20),
// `common/healthcheck_probe.js`, run as the compose files and ECS run it —
// a process of its own — against loopback stand-ins: a plain-HTTP
// "revocation listener" answering `/pki/ca/service/root.cer` (DER) and a
// "main port" answering `/healthcheck` under a leaf of that Root.
//
//   1. healthy: the chain reaches the Root the revocation listener serves,
//      under the name checked — exit 0;
//   2. a main port under a stranger's CA — exit 1, saying the certificate;
//   3. the right chain under another name — exit 1;
//   4. no revocation listener and no other anchor — exit 1, and with
//      STS_HEALTHCHECK_CA_FILE naming the Root — exit 0;
//   5. STS_HEALTHCHECK_NAME and STS_TLS_HOSTNAMES pick the name checked;
//   6. a 503 is unhealthy; nothing listening is unhealthy;
//   7. STS_HTTPS=false probes plain http and needs no anchor;
//   8. as source: every compose healthcheck and the ECS task definition run
//      this file; an unverified check survives only after the test for the
//      file, for an image older than it (the two compose files that pull
//      the published image).
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');

const testCa = require('./protocol/outbound_test_ca');

const log = require('bunyan').createLogger({ name: 'healthcheck_probe',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const PROBE = path.join(ROOT, 'common', 'healthcheck_probe.js');

function listen(server) {
  log.debug("Entering listen().");
  log.debug("Leaving listen().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

// A main port answering /healthcheck with `status`.
function mainPort(cred, status) {
  log.debug("Entering mainPort().");
  const handler = function (req, res) {
    res.statusCode = req.url === '/healthcheck' ? status : 404;
    res.end('ok');
  };
  log.debug("Leaving mainPort().");
  return listen(cred
    ? https.createServer({ key: cred.key, cert: cred.cert }, handler)
    : http.createServer(handler));
}

// A revocation listener serving `pem` as DER at the Root's address.
function revocation(pem) {
  log.debug("Entering revocation().");
  const der = Buffer.from(pem.replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
  log.debug("Leaving revocation().");
  return listen(http.createServer(function (req, res) {
    if (req.url === '/pki/ca/service/root.cer') {
      res.end(der);
      return;
    }
    res.statusCode = 404;
    res.end();
  }));
}

// The probe as a container runs it: its exit code and stderr. Spawned, not
// spawnSync'd: the stand-in listeners are in THIS process, and a blocked
// event loop would answer the probe nothing.
function probe(env) {
  log.debug("Entering probe().");
  const clean = {};
  Object.keys(process.env).forEach(function (name) {
    if (!/^STS_|^PKI_HTTP_PORT$/.test(name)) {
      clean[name] = process.env[name];
    }
  });
  log.debug("Leaving probe().");
  return new Promise(function (resolve) {
    const child = childProcess.spawn(process.execPath, [PROBE], {
      env: Object.assign(clean, { STS_HTTPS: 'true' }, env),
      stdio: ['ignore', 'ignore', 'pipe'] });
    let err = '';
    child.stderr.on('data', function (c) {
      err += c;
    });
    child.on('close', function (code) {
      resolve({ code: code, err: err });
    });
  });
}

function portOf(server) {
  log.debug("Entering portOf().");
  log.debug("Leaving portOf().");
  return String(server.address().port);
}

async function run(t) {
  log.debug("Entering run().");
  const servers = [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'healthcheck-probe-'));
  try {
    const root = await testCa.makeCa();
    const leaf = await testCa.listenerCertificate(root, 'localhost');
    const stranger = await testCa.makeCa();
    const strangerLeaf = await testCa.listenerCertificate(stranger,
                                                          'localhost');
    const good = await mainPort(leaf, 200);
    const bad = await mainPort(strangerLeaf, 200);
    const sick = await mainPort(leaf, 503);
    const plain = await mainPort(null, 200);
    const pki = await revocation(root.certPem);
    servers.push(good, bad, sick, plain, pki);
    const nowhere = await listen(http.createServer());
    const deadPort = portOf(nowhere);
    await new Promise(function (resolve) {
      nowhere.close(resolve);
    });
    const withPki = function (main, extra) {
      return Object.assign({ STS_PORT: portOf(main),
                             PKI_HTTP_PORT: portOf(pki) }, extra || {});
    };

    const ok = await probe(withPki(good));
    t.check(ok.code === 0, '1. a chain reaching the Root the revocation ' +
            'listener serves, under the name checked, is healthy', ok.err);
    const refused = await probe(withPki(bad));
    t.check(refused.code === 1 && /certificate|CERT/i.test(refused.err),
            '2. a main port under a stranger\'s CA is unhealthy, and says ' +
            'it is the certificate', refused.err);
    // The leaf names localhost (and 127.0.0.1's host, `outbound_test_ca`):
    // checked for any other name, the right chain is still refused.
    const misnamed = await probe(withPki(good,
      { STS_HEALTHCHECK_NAME: 'elsewhere.test' }));
    t.check(misnamed.code === 1 && /elsewhere\.test/.test(misnamed.err),
            '3. the right chain under another name is unhealthy: the name ' +
            'is checked, not only the chain', misnamed.err);
    const noRoot = await probe({ STS_PORT: portOf(good),
                                 PKI_HTTP_PORT: deadPort });
    t.check(noRoot.code === 1 && /no service Root/.test(noRoot.err),
            '4a. no revocation listener and no other anchor is unhealthy, ' +
            'saying no Root was read', noRoot.err);
    const caFile = path.join(dir, 'root.pem');
    fs.writeFileSync(caFile, root.certPem);
    const fromFile = await probe({ STS_PORT: portOf(good), PKI_HTTP_PORT: '0',
                             STS_HEALTHCHECK_CA_FILE: caFile });
    t.check(fromFile.code === 0, '4b. STS_HEALTHCHECK_CA_FILE is an anchor ' +
            'of its own, with pki.httpPort 0', fromFile.err);
    const firstName = await probe(withPki(good,
      { STS_TLS_HOSTNAMES: 'elsewhere.test,localhost' }));
    const firstOk = await probe(withPki(good,
      { STS_TLS_HOSTNAMES: ' localhost , elsewhere.test' }));
    const nameWins = await probe(withPki(good,
      { STS_TLS_HOSTNAMES: 'elsewhere.test',
        STS_HEALTHCHECK_NAME: 'localhost' }));
    t.check(firstName.code === 1 && /elsewhere\.test/.test(firstName.err) &&
            firstOk.code === 0 && nameWins.code === 0,
            '5. the name checked is the first of STS_TLS_HOSTNAMES ' +
            '(trimmed), ' +
            'and STS_HEALTHCHECK_NAME over it',
            firstName.err + ' | ' + firstOk.err + ' | ' + nameWins.err);
    const unwell = await probe(withPki(sick));
    const closed = await probe({ STS_PORT: deadPort,
                                 PKI_HTTP_PORT: portOf(pki) });
    t.check(unwell.code === 1 && /503/.test(unwell.err) && closed.code === 1,
            '6. a 503 is unhealthy, and so is a port nothing listens on',
            unwell.err + ' | ' + closed.err);
    const overHttp = await probe({ STS_HTTPS: 'false', STS_PORT: portOf(plain),
                             PKI_HTTP_PORT: deadPort });
    t.check(overHttp.code === 0, '7. STS_HTTPS=false probes plain http and ' +
            'needs no anchor', overHttp.err);

    const sources = ['docker-compose.yml', 'docker-compose-quick.yml',
      'docker-compose-run-tests.yml', 'deploy/aws/environment/ecs.tf'];
    const unverified = /rejectUnauthorized/;
    sources.forEach(function (file) {
      const text = fs.readFileSync(path.join(ROOT, file), 'utf8');
      const checks = text.split('\n').filter(function (line) {
        return /(test|command)\s*[:=].*"node"|(test|command)\s*[:=].*node -e/
          .test(line) && /healthcheck/.test(line);
      });
      // The two files that pull the PUBLISHED image by default run the
      // probe when the image has it and the old check only on an image
      // older than it (1.1.0 has none): an unverified fall back is allowed
      // only behind that test, never in front of it.
      const guard = 'if [ -f /usr/src/sts/common/healthcheck_probe.js ]; ' +
        'then exec node /usr/src/sts/common/healthcheck_probe.js; fi;';
      t.check(checks.length > 0 && checks.every(function (line) {
        return /common\/healthcheck_probe\.js/.test(line) &&
          (!unverified.test(line) || (line.indexOf(guard) >= 0 &&
            line.search(unverified) > line.indexOf(guard) + guard.length));
      }), '8. ' + file + '\'s healthcheck runs the probe, verified',
      checks.join(' / ').slice(0, 300));
    });
  } finally {
    servers.forEach(function (s) {
      s.close();
    });
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'healthcheck_probe',
  describe: 'The container healthcheck verifies the main port against the ' +
            'Root the service publishes, chain and name (2026-11-20)',
  run: run
};
