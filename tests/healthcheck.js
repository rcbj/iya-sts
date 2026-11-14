// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   3. (#312) a successful probe on either is NOT a call on the metrics: it
//      leaves `calls.total` and the call table where they were and goes up
//      `calls.healthProbes` instead, while a refused `POST /healthcheck` and
//      a probe answered 503 ARE calls — the rule `common/audit.js`'s
//      `QUIET_WHEN_OK` already applied to the audit log. The 503 is handed
//      to `recordCall()` directly, because the route cannot be made to fail
//      from here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'healthcheck',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Successful probes made on EACH listener in the metrics half.
const PROBES = 4;

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
    "function post(server, p) { return new Promise(function (resolve, reject) {",
    "  const r = http.request({ host: '127.0.0.1', method: 'POST',",
    "    port: server.address().port, path: p }, function (res) {",
    "    res.resume(); res.on('end', function () {",
    "      resolve({ status: res.statusCode }); }); });",
    "  r.on('error', reject); r.end(); }); }",
    "function hcRows(snap) { const out = {};",
    "  snap.calls.rows.forEach(function (row) {",
    "    if (row.path === '/healthcheck') { out[row.method] = row.count; } });",
    "  return out; }",
    "function counts(snap) { return { total: snap.calls.total,",
    "  probes: snap.calls.healthProbes, rows: hcRows(snap),",
    "  byStatus: snap.calls.byStatusClass }; }",
    "(async function () {",
    "  const main = http.createServer(app).listen(0, '127.0.0.1');",
    "  const revocation = http.createServer(function (req, res) {",
    "    pki.revocationOnly(req, res); }).listen(0, '127.0.0.1');",
    "  await new Promise(function (r) { setTimeout(r, 200); });",
    "  const out = { main: await get(main, '/healthcheck'),",
    "    listener: await get(revocation, '/healthcheck'),",
    "    other: await get(revocation, '/oauth2/jwks') };",
    "  const stats = require(" + JSON.stringify(ROOT + '/common/admin_stats') +
      ");",
    "  const before = counts(stats.snapshot());",
    "  for (let i = 0; i < " + PROBES + "; i++) {",
    "    await get(main, '/healthcheck');",
    "    await get(revocation, '/healthcheck'); }",
    "  const quiet = counts(stats.snapshot());",
    "  out.refused = await post(main, '/healthcheck');",
    "  stats.recordCall({ method: 'GET', path: '/healthcheck', matched: true,",
    "    status: 503, durationMs: 1 });",
    "  out.metrics = { before: before, quiet: quiet,",
    "    after: counts(stats.snapshot()) };",
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

  const m = out.metrics || {};
  const before = m.before || {};
  const quiet = m.quiet || {};
  const after = m.after || {};
  t.equal(quiet.total, before.total,
          (2 * PROBES) + ' successful probes, on both listeners, leave the ' +
          'request total where it was (#312)', JSON.stringify(m));
  t.equal(JSON.stringify(quiet.rows), JSON.stringify(before.rows),
          'and leave the call table without a /healthcheck row moving',
          JSON.stringify(m));
  t.equal(JSON.stringify(quiet.byStatus), JSON.stringify(before.byStatus),
          'and the status classes untouched', JSON.stringify(m));
  t.equal(quiet.probes - before.probes, 2 * PROBES,
          'they go up calls.healthProbes, one each, instead',
          JSON.stringify(m));
  t.check(out.refused && out.refused.status >= 400,
          'POST /healthcheck is refused — the control the next check needs',
          JSON.stringify(out.refused));
  t.equal(after.total - quiet.total, 2,
          'a refused POST and a probe answered 503 ARE calls: a node ' +
          'reporting itself unhealthy is what should show', JSON.stringify(m));
  t.equal((after.rows || {}).GET, ((quiet.rows || {}).GET || 0) + 1,
          'the 503 is on the GET /healthcheck row', JSON.stringify(m));
  t.check(((after.rows || {}).POST || 0) > ((quiet.rows || {}).POST || 0),
          'and the refused POST on a row of its own', JSON.stringify(m));
  t.equal(after.probes, quiet.probes,
          'and neither is counted as a successful probe', JSON.stringify(m));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'healthcheck',
  describe: 'GET /healthcheck answers on the main app and through the ' +
            'plain-HTTP revocation listener, for the load balancer, and a ' +
            'successful one is not counted as a call on the metrics',
  run: run
};
