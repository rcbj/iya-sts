'use strict';
//
// File: tests/healthcheck.js
//
// ===========================================================================
// GET /healthcheck, ON THE MAIN APP AND THROUGH THE PLAIN-HTTP REVOCATION
// LISTENER (2026-09-21).
//
// The AWS load balancer checked every port with a bare TCP connect, which on
// the TLS port read as a failed handshake about once a second per node. The
// ports that speak HTTP are now checked with a GET of /healthcheck
// (deploy/aws/environment/nlb.tf), so the route has to answer on both: the
// main app (8081) and the revocation listener (8082), whose filter passes
// only /pki/... and this path through.
//
// In a CHILD PROCESS, because it serves the shared app on a port and `run.js`
// runs every file in one process. Two loopback servers:
//
//   1. the main app answers 200 — the route `common/app.js` has always had,
//      which the compose healthchecks and the CI wait loop already use;
//   2. the revocation listener's filter lets /healthcheck through, and still
//      refuses a path that is neither it nor /pki/...
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'healthcheck',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childScript() {
  log.debug("Entering childScript().");
  log.debug("Leaving childScript().");
  return [
    "delete process.env.CONFIG_FILE;",
    "process.env.STS_HTTPS = 'false';",
    "const http = require('http');",
    "const app = require(" + JSON.stringify(ROOT + '/common/app') + ");",
    "const pki = require(" + JSON.stringify(ROOT + '/pki/pki_service') + ");",
    "function get(server, p) { return new Promise(function (resolve, reject) {",
    "  http.get({ host: '127.0.0.1', port: server.address().port, path: p },",
    "    function (res) { let b = ''; res.on('data', function (c) { b += c; });",
    "      res.on('end', function () { resolve({ status: res.statusCode,",
    "        type: res.headers['content-type'] || '',",
    "        cache: res.headers['cache-control'] || '', body: b }); }); })",
    "  .on('error', reject); }); }",
    "(async function () {",
    "  const main = http.createServer(app).listen(0, '127.0.0.1');",
    "  const revocation = http.createServer(function (req, res) {",
    "    pki.revocationOnly(req, res); }).listen(0, '127.0.0.1');",
    "  await new Promise(function (r) { setTimeout(r, 200); });",
    "  const out = { main: await get(main, '/healthcheck'),",
    "    listener: await get(revocation, '/healthcheck'),",
    "    other: await get(revocation, '/oauth2/jwks') };",
    "  process.stdout.write(JSON.stringify(out));",
    "  process.exit(0);",
    "})().catch(function (e) { process.stdout.write(JSON.stringify(",
    "  { threw: e.stack })); process.exit(1); });"
  ].join('\n');
}

function run(t) {
  log.debug("Entering run().");
  const env = Object.assign({}, process.env, { LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath, ['-e', childScript()],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 120000 });
  let out = null;
  try {
    out = JSON.parse(String(child.stdout).trim().split('\n').pop());
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.bad('the child reported nothing', String(child.stderr).slice(-1500));
    log.debug("Leaving run().");
    return;
  }
  if (out.threw) {
    t.bad('the child threw', out.threw);
    log.debug("Leaving run().");
    return;
  }
  t.equal(out.main.status, 200, 'GET /healthcheck answers 200 on the main app');
  t.check(/Success/.test(out.main.body),
          'with the body it has always had', JSON.stringify(out.main));
  t.equal(out.listener.status, 200,
          'the plain-HTTP revocation listener lets /healthcheck through — ' +
          'the load balancer\'s HTTP check on that port');
  t.equal(out.other.status, 404,
          'and still refuses a path that is neither it nor /pki/...');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'healthcheck',
  describe: 'GET /healthcheck answers on the main app and through the ' +
            'plain-HTTP revocation listener, for the load balancer',
  run: run
};
