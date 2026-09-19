'use strict';
//
// File: tests/audit_client_address.js
//
// ---------------------------------------------------------------------------
// THE CLIENT'S ADDRESS ON EVERY AUDIT ROW (2026-09-18).
//
// `common/audit.js` records, on every row, the IP address of whoever sent the
// request, LDAP operation, Kerberos message or SPIRE Server API call the row
// came out of — an authentication, an attempted sign-in, a consent, a
// sign-out. Most rows are written deep inside code that was never handed a
// request (`admin_stats.recordAuthentication()` above all), so the address is
// AMBIENT: an entry point runs its work inside `audit.withSource()`, and a
// row written beneath it carries the source's address.
//
// What is held here:
//
//   1. A row written outside any source has no address — nobody sent it.
//   2. Inside a source naming an address, a row carries it, `::ffff:` taken
//      off, and so does a row written after an `await` — the case every
//      asynchronous handler is.
//   3. A source naming a REQUEST resolves it through `client_address.js`,
//      once, when a row is written.
//   4. An address on the event itself wins over the source.
//   5. `recordAuthentication()` — the funnel every protocol's sign-in goes
//      through — carries the source's address onto its `authentication` row
//      AND onto the person's own event list, the table `/admin/users` draws
//      (2026-09-19); an address the caller names wins in both.
//   6. `/admin/audit`'s and `GET /admin-api/audit`'s `address` filter is a
//      PREFIX, so `10.0.0.1` does not match inside `110.0.0.12`.
//   7. In a child: a real LDAP bind on the directory's own listener, and a
//      datagram to the KDC's own UDP socket, each write rows naming
//      127.0.0.1 — the two raw-socket entry points, end to end.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const audit = require('../common/audit');
const stats = require('../common/admin_stats');
const adminViews = require('../admin-core/admin_views');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({ name: 'audit_client_address',
  level: process.env.LOG_LEVEL || 'info' });

// The newest row whose summary carries `marker`.
function rowWith(marker) {
  log.debug("Entering rowWith().");
  log.debug("Leaving rowWith().");
  return audit.list().filter(function (row) {
    return String(row.summary).indexOf(marker) >= 0;
  })[0] || null;
}

// A child node process with this service's own settings cleared, running
// `body` and handing back its report — tests/ldap_tls_product_mode.js's
// arrangement, for the two listeners this file has to bind.
function inAChild(env, body) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'audit-address-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const script =
    'delete process.env.CONFIG_FILE;' +
    'const R = ' + JSON.stringify(ROOT) + ';' +
    'Promise.resolve((async function () {' + body + '})()).then(function ' +
    '(report) {  ' +
    'require("fs").writeFileSync(' + JSON.stringify(out) + ', ' +
    'JSON.stringify(report));  process.exit(0);}, function (e) {  ' +
    'require("fs").writeFileSync(' + JSON.stringify(out) +
    ', JSON.stringify({ threw: String(e && e.stack || e) }));' +
    '  process.exit(0);' +
    '});';
  const result = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign(clean, { LOG_LEVEL: 'fatal' }, env),
    encoding: 'utf8', timeout: 120000
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // The child exited before writing; the checks report the output instead.
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written; the read above already said so.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  log.debug("Leaving inAChild().");
  return { output: String(result.stdout || '') + String(result.stderr || ''),
           report: report };
}

async function run(t) {
  log.debug("Entering run().");
  const tag = 'audit-address-' + process.pid;

  // --- 1. No source ------------------------------------------------------
  audit.audit({ action: 'protocol.call', summary: tag + ' none' });
  t.equal(rowWith(tag + ' none').address, '',
          '1. a row written outside any source carries no address');

  // --- 2. An address source, across an await -----------------------------
  await audit.withSource({ address: '::ffff:203.0.113.9' }, async function () {
    audit.audit({ action: 'protocol.call', summary: tag + ' sync' });
    await new Promise(function (resolve) {
      setTimeout(resolve, 5);
    });
    audit.audit({ action: 'protocol.call', summary: tag + ' async' });
  });
  t.equal(rowWith(tag + ' sync').address, '203.0.113.9',
          '2a. inside a source, a row carries its address, the dual-stack ' +
          'prefix taken off');
  t.equal(rowWith(tag + ' async').address, '203.0.113.9',
          '2b. and so does a row written after an await');

  // --- 3. A request source -----------------------------------------------
  const req = { headers: {}, socket: { remoteAddress: '198.51.100.4' } };
  audit.withSource({ req: req }, function () {
    audit.audit({ action: 'protocol.call', summary: tag + ' req' });
  });
  t.equal(rowWith(tag + ' req').address, '198.51.100.4',
          '3. a request source is resolved through client_address.js — the ' +
          'socket\'s peer, with global.trustProxy off');

  // --- 4. The event's own address wins -----------------------------------
  audit.withSource({ address: '192.0.2.1' }, function () {
    audit.audit({ action: 'protocol.call', summary: tag + ' own',
                  address: '192.0.2.200' });
  });
  t.equal(rowWith(tag + ' own').address, '192.0.2.200',
          '4. an address on the event wins over the source');

  // --- 5. The authentication funnel --------------------------------------
  const person = tag + '-person';
  audit.withSource({ address: '198.51.100.77' }, function () {
    stats.recordAuthentication({ presented: person, protocol: 'test',
                                 method: 'a probe' });
  });
  const authn = audit.list().filter(function (row) {
    return row.category === 'authentication' &&
           (row.actor + ' ' + row.actorForm + ' ' + row.summary)
             .indexOf(person) >= 0;
  })[0];
  t.check(authn && authn.address === '198.51.100.77',
          '5. recordAuthentication() — handed no request — writes its ' +
          'authentication row with the source\'s address',
          JSON.stringify(authn && { action: authn.action,
                                    address: authn.address }));
  // The same act on the person's own record — the table /admin/users draws
  // under *How they authenticated* — from the same source.
  const detail = stats.userRows().filter(function (row) {
    return (row.events || []).some(function (e) {
      return e.presented === person;
    });
  })[0];
  const event = detail && detail.events.filter(function (e) {
    return e.presented === person;
  })[0];
  t.check(event && event.address === '198.51.100.77',
          '5b. and the person\'s own authentication event, which ' +
          '/admin/users lists, carries the same address',
          JSON.stringify(event && { protocol: event.protocol,
                                    address: event.address }));
  const named = person + '-named';
  audit.withSource({ address: '198.51.100.77' }, function () {
    stats.recordAuthentication({ presented: named, protocol: 'test',
                                 method: 'a probe',
                                 address: '203.0.113.50' });
  });
  const namedEvent = (stats.userRows().filter(function (row) {
    return (row.events || []).some(function (e) {
      return e.presented === named;
    });
  })[0] || { events: [] }).events.filter(function (e) {
    return e.presented === named;
  })[0];
  t.check(namedEvent && namedEvent.address === '203.0.113.50',
          '5c. an address the caller names wins over the source there too',
          JSON.stringify(namedEvent && namedEvent.address));

  // --- 6. The filter is a prefix -----------------------------------------
  audit.withSource({ address: '110.0.0.12' }, function () {
    audit.audit({ action: 'protocol.call', summary: tag + ' far' });
  });
  audit.withSource({ address: '10.0.0.12' }, function () {
    audit.audit({ action: 'protocol.call', summary: tag + ' near' });
  });
  const near = adminViews.auditView({ address: '10.0.0.1', q: tag,
                                      per: 100 });
  const summaries = near.filtered.map(function (row) {
    return row.summary;
  });
  t.check(summaries.some(function (s) { return s.indexOf(' near') >= 0; }) &&
          !summaries.some(function (s) { return s.indexOf(' far') >= 0; }),
          '6. the address filter matches the FRONT of an address and not ' +
          'inside one', JSON.stringify(summaries));
  t.equal(near.json.filter.address, '10.0.0.1',
          '6b. and the API\'s reply says which address it filtered on');

  // --- 7. The two raw-socket listeners, end to end -----------------------
  const child = inAChild({ STS_HOST: '127.0.0.1', LDAP_PORT: '0',
                           LDAPS_PORT: '0', KRB5_KDC_PORT: '0' },
    'const audit = require(R + "/common/audit");' +
    'const ldapServer = require(R + "/ldap/ldap_server.js");' +
    'const kdc = require(R + "/kerberos/krb5_kdc.js");' +
    'const l = ldapServer.listen(); const ready = await l.whenReady;' +
    'const ldapjs = require(R + "/node_modules/ldapjs");' +
    'const client = ldapjs.createClient({ url: "ldap://127.0.0.1:" + ' +
    'ready.port, reconnect: false });' +
    'client.on("error", function () {});' +
    'const bound = await new Promise(function (ok) { client.bind(' +
    '"uid=alice,ou=users," + ready.baseDn, "anything", function (e) { ' +
    'client.unbind(function () { ok(e ? e.code : 0); }); }); });' +
    'const k = kdc.listen(0); const kr = await k.whenReady;' +
    'const dgram = require("dgram"); const u = dgram.createSocket("udp4");' +
    'await new Promise(function (ok) { u.on("message", function () { ' +
    'u.close(); ok(); }); u.send(Buffer.from([0x30, 0x00]), ' +
    'kr.udp.address().port, "127.0.0.1"); });' +
    'await new Promise(function (ok) { setTimeout(ok, 100); });' +
    'return { bound: bound, rows: audit.list().filter(function (r) { ' +
    'return /^(ldap|ldaps|kerberos)$/.test(r.channel) || ' +
    '(r.category === "authentication" && /ldap/i.test(r.protocol)); ' +
    '}).map(function (r) { return { ' +
    'channel: r.channel, category: r.category, action: r.action, ' +
    'address: r.address, protocol: r.protocol }; }) };');
  const r = child.report || {};
  const rows = r.rows || [];
  // The rows the BIND wrote — its `directory.bind` on the socket and the
  // `authentication` row — and not the entries seeded at start-up, which
  // nobody sent and which rightly carry no address.
  const ldapRows = rows.filter(function (row) {
    return /^ldaps?$/.test(row.channel) || row.category === 'authentication';
  });
  const kdcRows = rows.filter(function (row) {
    return row.channel === 'kerberos';
  });
  t.check(r.bound === 0 && ldapRows.length > 0 &&
          ldapRows.every(function (row) {
            return row.address === '127.0.0.1';
          }),
          '7a. a bind on the directory\'s own listener writes rows that all ' +
          'name 127.0.0.1',
          JSON.stringify({ bound: r.bound, rows: ldapRows, threw: r.threw }) +
          (child.report ? '' : child.output.slice(-400)));
  t.check(ldapRows.some(function (row) {
    return row.category === 'authentication';
  }), '7b. including the authentication row admin_stats.js writes',
          JSON.stringify(ldapRows));
  t.check(kdcRows.length > 0 && kdcRows.every(function (row) {
    return row.address === '127.0.0.1';
  }), '7c. a datagram to the KDC writes rows naming its sender',
          JSON.stringify(kdcRows));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'audit client address',
  describe: 'every audit row names the client address of the request, LDAP ' +
            'operation or Kerberos message it came out of, through an ' +
            'ambient source; none for what nobody sent',
  run: run
};
