'use strict';
//
// File: ldap_tls_product_mode.js
//
// ===========================================================================
// WHAT THE DIRECTORY AND THE TLS LISTENERS HARD-CODED, AND WHAT EACH MODE DOES
// NOW (2026-09-12).
//
// The same audit as `kerberos_product_mode.js`, for the other two socket
// families this service owns. The directory seeded three invented people (one
// of them an `employeeType: admin`), two groups, a `cn=admin` bind account and
// two PRIVILEGED identities — `cn=remote-pep-1` and `cn=xacml-user-1` — on
// every start and in every realm, into groups named by a literal while the
// gate read the SETTING; it filled every person with generated credential
// attributes and gave an auto-created entry a displayName ending "(mock)"; its
// audit row said "no password was checked" about binds product mode verifies;
// and 389 always started. The TLS module let anybody who could reach the port
// add a trust anchor, had no protocol floor or cipher setting, and every one of
// the three families bound '0.0.0.0' whatever `global.host` said.
//
// **THE TLS MODULE'S OWN LISTENERS — 8443 AND 9443 — WERE DELETED ON
// 2026-09-16, AND ONE SECTION HERE MOVED RATHER THAN GOING WITH THEM.**
// `tls.minVersion` reaching a real handshake was asserted by refusing a TLS
// 1.2 client on 8443; it is now asserted on LDAPS 636, which `ldap_server.js`
// builds from the same `tlsServer.protocolOptions()`. The argument is beside
// the assertion. Nothing else here was about those two sockets: `POST
// /tls/trust` is a route on the main port and always was, and the bind-address
// section now asks the four raw sockets that are left.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, and why most of it in a CHILD process.
//
// The directory is SEEDED AT REQUIRE TIME in the mode the process starts in,
// and every stack this suite drives runs development mode — so a product
// directory can only be asked about by starting one. `run.js` runs every file
// in one process where `ldap_server.js` is already loaded, so each product
// section starts a child node process, reads what it built, and exits. No port
// is published anywhere; the listener sections bind 127.0.0.1:0.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'ldap_tls_product_mode',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// A clean environment for this service's own settings, the child's body, and
// its report. The body may return a promise.
function inAChild(env, body) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'ldap-tls-product-' + process.pid + '-' +
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
    // Not written: the child exited first, which the refusal sections expect
    // and every other section reports through `status` below.
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written; the read above already said so.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  log.debug("Leaving inAChild().");
  return { status: result.status, output: String(result.stdout || '') +
           String(result.stderr || ''), report: report };
}

// What a directory holds, by DN, with the attribute NAMES on each entry.
const DIRECTORY = 'const d = require(R + "/ldap/ldap_server.js");const out = ' +
  '{};d.entries.forEach(function (e, k) { out[k] = { attributes: ' +
  'Object.keys(e.attributes).sort(), member: e.attributes.member || [], ' +
  'description: e.attributes.description || [] }; });';

function has(report, dn) {
  log.debug("Entering has().");
  log.debug("Leaving has().");
  return !!(report && report.entries && report.entries[dn]);
}

// ---------------------------------------------------------------------------
// 1. PRODUCT MODE SEEDS THE TREE AND NOTHING ELSE.
// ---------------------------------------------------------------------------
function productDirectoryHoldsNoDemoData(t) {
  log.debug("Entering productDirectoryHoldsNoDemoData().");
  t.log.info('=== a product directory: containers, and no invented people ===');
  const run = inAChild({ STS_MODE: 'product' }, DIRECTORY +
    'return { entries: out };');
  t.check(run.report && run.report.entries, 'a product-mode directory builds',
          'exit ' + run.status + ' ' + run.output.slice(-300));
  if (!run.report || !run.report.entries) {
    log.debug("Leaving productDirectoryHoldsNoDemoData().");
    return;
  }
  const r = run.report;
  ['uid=alice,ou=users,dc=example,dc=com', 'uid=bob,ou=users,dc=example,dc=com',
   'uid=carol,ou=users,dc=example,dc=com', 'cn=admin,dc=example,dc=com',
   'cn=developers,ou=groups,dc=example,dc=com',
   'cn=directory-admins,ou=groups,dc=example,dc=com'].forEach(function (dn) {
    t.check(!has(r, dn), 'no demonstration entry ' + dn);
  });
  t.check(!has(r, 'cn=remote-pep-1,ou=users,dc=example,dc=com') &&
          !has(r, 'cn=xacml-user-1,ou=users,dc=example,dc=com'),
          'NEITHER PRIVILEGED IDENTITY is seeded — a predictable common name ' +
          'printed in this repository would otherwise be admitted to the ' +
          'documents this service enforces its own access with');
  const peps = r.entries['cn=remote-peps,ou=groups,dc=example,dc=com'];
  const users = r.entries['cn=xacml-users,ou=groups,dc=example,dc=com'];
  t.check(!!peps && !!users && !peps.member.length && !users.member.length,
          'the two role groups ARE seeded, EMPTY, so admitting somebody is ' +
          'one member added', JSON.stringify({ peps: peps, users: users }));
  ['dc=example,dc=com', 'ou=users,dc=example,dc=com',
   'ou=groups,dc=example,dc=com',
   'ou=applications,dc=example,dc=com'].forEach(function (dn) {
    t.check(has(r, dn), 'the structural container ' + dn + ' is there');
  });
  t.check(!/Every bind succeeds/.test(JSON.stringify(
      r.entries['dc=example,dc=com'].description)),
          'and the base entry does not describe development mode',
          JSON.stringify(r.entries['dc=example,dc=com'].description));
  log.debug("Leaving productDirectoryHoldsNoDemoData().");
}

// ---------------------------------------------------------------------------
// 2. THE ROLE GROUPS ARE THE ONES THE SETTINGS NAME (all modes).
// ---------------------------------------------------------------------------
function roleGroupsFollowTheSettings(t) {
  log.debug("Entering roleGroupsFollowTheSettings().");
  t.log.info('=== the seeded role groups are roles.remotePepGroup and ' +
             'roles.xacmlUserGroup ===');
  const run = inAChild({ STS_ROLES_REMOTE_PEP_GROUP: 'pep-gate',
                         STS_ROLES_XACML_USER_GROUP: 'xacml-gate' },
                       DIRECTORY + 'return { entries: out };');
  t.check(run.report && run.report.entries, 'a renamed-group directory builds',
          run.output.slice(-300));
  if (!run.report || !run.report.entries) {
    log.debug("Leaving roleGroupsFollowTheSettings().");
    return;
  }
  const r = run.report;
  const gate = r.entries['cn=pep-gate,ou=groups,dc=example,dc=com'];
  const users = r.entries['cn=xacml-gate,ou=groups,dc=example,dc=com'];
  t.check(!!gate &&
          gate.member.indexOf('cn=remote-pep-1,ou=users,dc=example,dc=com') >= 0,
          'the REMOTE_PEPS group seeded is the one `roles.remotePepGroup` ' +
          'names — the literal cn=remote-peps granted nothing once the ' +
          'setting was changed',
          JSON.stringify(gate || null));
  t.check(!!users &&
          users.member.indexOf('cn=xacml-user-1,ou=users,dc=example,dc=com') >= 0,
          'and the XACML_USER group is the one `roles.xacmlUserGroup` names',
          JSON.stringify(users || null));
  t.check(!has(r, 'cn=remote-peps,ou=groups,dc=example,dc=com') &&
          !has(r, 'cn=xacml-users,ou=groups,dc=example,dc=com'),
          'and the literal names are not seeded beside them');
  log.debug("Leaving roleGroupsFollowTheSettings().");
}

// ---------------------------------------------------------------------------
// 3. PRODUCT MODE INVENTS NO CLAIM VALUE, AND THE BIND AUDIT SAYS WHAT
//    HAPPENED.
// ---------------------------------------------------------------------------
function productInventsNothingAndAuditsTruthfully(t) {
  log.debug("Entering productInventsNothingAndAuditsTruthfully().");
  t.log.info('=== no invented values, and a verified bind is audited as ' +
             'verified ===');
  const run = inAChild({ STS_MODE: 'product' },
    'const d = require(R + "/ldap/ldap_server.js");const credentials = ' +
    'require(R + "/common/credentials");const audit = require(R + ' +
    '"/common/audit.js");const made = d.createUser("probe-person", { origin: ' +
    '"test" });const entry = ' +
    'd.entries.get("uid=probe-person,ou=users,dc=example,dc=com");const ' +
    'swept = d.populateVcAttributes();const through = require(R + ' +
    '"/oid4vc/vc_claims").populateDirectory();const pw = ' +
    'credentials.setPassword("probe-person", "Correct-Horse-9-Battery");' +
    // OVER LDAPS: product mode refuses a bind carrying a password on the plain
    // listener with confidentialityRequired before reading it (2026-09-12,
    // tests/directory_read_security.js), and a shape with no channel is plain.
    'const bind = d.performOperation("bind", { dn: ' +
    '"uid=probe-person,ou=users,dc=example,dc=com", channel: "ldaps", ' +
    'credentials: "Correct-Horse-9-Battery" });const row = ' +
    'audit.list().filter(function (e) { return e.action === ' +
    '"directory.bind"; })[0] || null;return { made: made && made.ok, ' +
    'attributes: entry ? Object.keys(entry.attributes).sort() : null, swept: ' +
    'swept, through: through, pw: pw && pw.ok, pwErrors: pw && pw.errors, bind: bind.ok, row: ' +
    'row };');
  const r = run.report || {};
  t.check(r.made === true, 'a person can be created in a product directory',
          run.output.slice(-400) + JSON.stringify(r));
  const invented = ['cn', 'sn', 'givenname', 'displayname', 'mail'];
  t.check(Array.isArray(r.attributes) && invented.every(function (name) {
    return r.attributes.indexOf(name) === -1;
  }), 'a SCIM-shaped create (invent defaulted to TRUE) puts NONE of the five ' +
      'persona attributes on the entry in product mode — no "(mock)" ' +
      'displayName, no invented mail', JSON.stringify(r.attributes));
  t.check(r.swept && r.swept.examined === 0 &&
          /product mode/.test(String(r.swept.skipped)),
          'and the credential-attribute sweep does not run, saying why',
          JSON.stringify(r.swept));
  // The reason has to survive the layer the console and /admin-api read:
  // vc_claims.populateDirectory() dropped it until 2026-09-19, so the
  // Populate button answered "Swept 0 directory entry/entries" about a sweep
  // that never started.
  t.check(r.through && r.through.ok === true &&
          /product mode/.test(String(r.through.skipped)),
          'and vc_claims.populateDirectory() hands that reason on to the ' +
          'console and the API',
          JSON.stringify(r.through));
  t.check(r.pw === true && r.bind === true, 'a real password verifies over a ' +
                                            'bind',
          JSON.stringify({ pw: r.pw, errors: r.pwErrors, bind: r.bind }));
  const detail = (r.row && r.row.detail) || {};
  t.check(detail.passwordVerified === true &&
          !/no password was checked/.test(String(detail.note)),
          'THE AUDIT ROW SAYS THE PASSWORD WAS VERIFIED — it said "no ' +
          'password was checked" on every successful bind, including the ' +
          'ones product mode verified',
          JSON.stringify(detail));
  log.debug("Leaving productInventsNothingAndAuditsTruthfully().");
}

// The development half of the same two claims, which is what keeps the change
// honest in the mode every stack runs: the persona is still invented and the
// audit row still says nothing was checked, because nothing was.
function developmentIsUnchanged(t) {
  log.debug("Entering developmentIsUnchanged().");
  t.log.info('=== development mode is unchanged ===');
  const run = inAChild({},
    'const d = require(R + "/ldap/ldap_server.js");const audit = require(R + ' +
    '"/common/audit.js");d.createUser("dev-probe", { origin: "test" });const ' +
    'entry = d.entries.get("uid=dev-probe,ou=users,dc=example,dc=com");' +
    'd.performOperation("bind", { dn: ' +
    '"uid=alice,ou=users,dc=example,dc=com", credentials: "x" });const row = ' +
    'audit.list().filter(function (e) { return e.action === ' +
    '"directory.bind"; })[0] || null;return { displayName: entry && ' +
    'entry.attributes.displayname, alice: ' +
    '!!d.entries.get("uid=alice,ou=users,dc=example,dc=com"), pep: ' +
    '!!d.entries.get("cn=remote-pep-1,ou=users,dc=example,dc=com"), row: row ' +
    '&& row.detail };');
  const r = run.report || {};
  t.check(r.alice === true && r.pep === true, 'development still seeds alice ' +
                                              'and the PEP identity',
          run.output.slice(-300));
  t.check(Array.isArray(r.displayName) && / \(mock\)$/.test(r.displayName[0]),
          'and still invents a persona, "(mock)" and all',
          JSON.stringify(r.displayName));
  t.check(r.row && r.row.passwordVerified === false &&
          /no password was checked/.test(r.row.note),
          'and still audits a bind as unchecked, which is what happened',
          JSON.stringify(r.row));
  log.debug("Leaving developmentIsUnchanged().");
}

// ---------------------------------------------------------------------------
// 4. LISTENERS BIND global.host, AND 389 CAN BE LEFT UNBOUND.
// ---------------------------------------------------------------------------
function listenersHonourTheBindAddress(t) {
  log.debug("Entering listenersHonourTheBindAddress().");
  t.log.info('=== every listener binds global.host ===');
  const run = inAChild({ STS_HOST: '127.0.0.1', LDAP_PORT: '0', LDAPS_PORT: '0',
                         KRB5_KDC_PORT: '0',
                         KRB5_SERVICE_PORT: '0' },
    // tls_server.js had two listeners of its own here until 2026-09-16. They
    // were deleted; the main port is `server.js`'s and binds global.host with
    // every other HTTP route on it, so the four raw sockets below are what is
    // left to ask.
    'const kdc = require(R + "/kerberos/krb5_kdc.js");const svc = require(R ' +
    '+ "/kerberos/krb5_service.js");const ldap = require(R + ' +
    '"/ldap/ldap_server.js");const k = kdc.listen(0); const kr = await ' +
    'k.whenReady;const s = svc.listen(0); await new Promise(function (ok) { ' +
    's.listening ? ok() : s.once("listening", ok); });const l = ' +
    'ldap.listen(); await l.whenReady;' +
    'return { kdcTcp: kr.tcp.address().address, kdcUdp: ' +
    'kr.udp.address().address, service: s.address().address, ldap: ' +
    'l.server.address().address, ldaps: l.secureServer && ' +
    'l.secureServer.address().address };');
  const r = run.report || {};
  t.check(r.kdcTcp === '127.0.0.1' && r.kdcUdp === '127.0.0.1',
          'the KDC binds global.host on TCP and UDP',
          JSON.stringify(r) + run.output.slice(-300));
  t.equal(r.service, '127.0.0.1', 'the Kerberos acceptor binds global.host');
  t.check(r.ldap === '127.0.0.1' && r.ldaps === '127.0.0.1',
          'LDAP and LDAPS bind global.host', JSON.stringify(r));

  const off = inAChild({ LDAP_PLAIN_LISTENER: 'false', LDAP_PORT: '0',
                         LDAPS_PORT: '0',
                         STS_HOST: '127.0.0.1' },
    'const ldap = require(R + "/ldap/ldap_server.js");const l = ' +
    'ldap.listen(); const ready = await l.whenReady;return { port: ' +
    'ready.port, plain: ready.plainListener, bound: !!(l.server.server && ' +
    'l.server.server.listening), ldaps: ready.ldapsListening };');
  const o = off.report || {};
  t.check(o.port === null && o.plain === false && o.bound === false &&
          o.ldaps === true,
          'ldap.plainListener off leaves 389 unbound and LDAPS answering, ' +
          'and the directory still counts as ' +
          'started', JSON.stringify(o) + off.output.slice(-300));

  const warned = inAChild({ STS_MODE: 'product', LDAP_PORT: '0',
                            LDAPS_PORT: '0',
                            STS_HOST: '127.0.0.1', LOG_LEVEL: 'warn' },
    'const ldap = require(R + "/ldap/ldap_server.js");' +
    'const l = ldap.listen(); await l.whenReady; return { ok: true };');
  t.check(/IN THE CLEAR/.test(warned.output) &&
          /ldap\.plainListener/.test(warned.output),
          'product mode with the plain listener on WARNS, naming the setting ' +
          'that ends it',
          warned.output.slice(-400));
  log.debug("Leaving listenersHonourTheBindAddress().");
}

// ---------------------------------------------------------------------------
// 5. THE TRUSTSTORE: REFUSED OVER HTTP IN PRODUCT, LOADED FROM A FILE, AND THE
//    PROTOCOL POLICY.
// ---------------------------------------------------------------------------
function httpProbe(env, method, pathname, body) {
  log.debug("Entering httpProbe().");
  log.debug("Leaving httpProbe().");
  return inAChild(env,
    'const app = require(R + "/common/app");require(R + ' +
    '"/tls/tls_server.js");const http = require("http");const server = ' +
    'http.createServer(app);await new Promise(function (ok) { ' +
    'server.listen(0, "127.0.0.1", ok); });return await new Promise(function ' +
    '(ok) {  const req = http.request({ host: "127.0.0.1", port: ' +
    'server.address().port, path: ' +
    JSON.stringify(pathname) + ', method: ' + JSON.stringify(method) + ',    ' +
    'headers: { "content-type": "text/plain", accept: "application/json" } ' +
    '}, function (res) {    let text = ""; res.on("data", function (c) { ' +
    'text += c; });    res.on("end", function () { ok({ status: ' +
    'res.statusCode, body: text }); });  });  ' +
    'req.end(' + JSON.stringify(body || '') + ');' +
    '});');
}

function theTruststoreIsNotATestControlInProduct(t) {
  log.debug("Entering theTruststoreIsNotATestControlInProduct().");
  t.log.info('=== POST /tls/trust in product mode, and tls.trustAnchorsFile ' +
             '===');
  const pem = require('../tls/tls_server.js').serverCertificatePem();
  const refused = httpProbe({ STS_MODE: 'product' }, 'POST', '/tls/trust', pem);
  const rr = refused.report || {};
  t.check(rr.status === 403 && /tls\.trustAnchorsFile/.test(rr.body),
          'a product service REFUSES a trust anchor from whoever reaches the ' +
          'port, and names the setting that is the door ' +
          'instead', JSON.stringify(rr).slice(0, 400));
  const cleared = httpProbe({ STS_MODE: 'product' }, 'POST', '/tls/trust/clear',
                            '');
  t.equal((cleared.report || {}).status, 403, 'and refuses to EMPTY it too');
  const accepted = httpProbe({}, 'POST', '/tls/trust', pem);
  t.equal((accepted.report || {}).status, 200,
          'while development mode still takes the anchor, which is what the ' +
          'launchers use');

  const file = path.join(os.tmpdir(), 'anchors-' + process.pid + '.pem');
  fs.writeFileSync(file, pem);
  try {
    const loaded = inAChild({ STS_TLS_TRUST_ANCHORS_FILE: file },
      'const tls = require(R + "/tls/tls_server.js");return { count: ' +
      'tls.anchorCount(), report: tls.trustAnchorsFileLoaded(), ca: ' +
      'tls.clientTruststoreOptions().ca.length };');
    const lr = loaded.report || {};
    t.check(lr.count === 1 && lr.ca === 1 && lr.report &&
            lr.report.file === file,
            'tls.trustAnchorsFile fills the truststore at startup, before ' +
            'the listeners are created from ' +
            'it', JSON.stringify(lr) + loaded.output.slice(-300));
  } finally {
    try {
      fs.unlinkSync(file);
    } catch (e) {
      // Already gone; nothing else wrote it.
      log.debug("Caught in theTruststoreIsNotATestControlInProduct(): " +
                ((e && e.message) || e));
    }
  }
  const missing =
      inAChild({ STS_TLS_TRUST_ANCHORS_FILE: '/nonexistent/anchors.pem' },
    'require(R + "/tls/tls_server.js"); return { started: true };');
  t.check(missing.status === 1 && missing.report === null &&
          /tls\.trustAnchorsFile/.test(missing.output),
          'a trust-anchor file that cannot be read STOPS the service, naming ' +
          'the setting',
          'exit ' + missing.status);
  log.debug("Leaving theTruststoreIsNotATestControlInProduct().");
}

async function theProtocolPolicyIsApplied(t) {
  log.debug("Entering theProtocolPolicyIsApplied().");
  t.log.info('=== tls.minVersion and tls.ciphers ===');
  const tlsServer = require('../tls/tls_server.js');
  const defaults = tlsServer.protocolOptions();
  t.check(defaults.minVersion === 'TLSv1.2' && defaults.ciphers === undefined,
          'the defaults are node\'s own written down — TLSv1.2, and no ' +
          'cipher list',
          JSON.stringify(defaults));
  t.equal(tlsServer.clientTruststoreOptions().minVersion, 'TLSv1.2',
          'and they ride in the context every listener is built from and ' +
          're-keyed with');

  const bad = inAChild({ STS_TLS_CIPHERS: 'NOT-A-CIPHER-AT-ALL' },
    'require(R + "/tls/tls_server.js"); return { started: true };');
  t.check(bad.status === 1 && bad.report === null &&
          /tls\.ciphers/.test(bad.output),
          'a cipher list matching nothing STOPS the service at startup, ' +
          'naming the setting',
          'exit ' + bad.status);

  // -------------------------------------------------------------------------
  // THE HANDSHAKE THIS IS ASSERTED ON MOVED TO LDAPS ON 2026-09-16, AND THE
  // MOVE IS HONEST RATHER THAN CONVENIENT.
  //
  // It was 8443 — `tls.port`, a listener of `tls_server.js`'s own — and that
  // listener and 9443 were deleted. LDAPS 636 is the socket this claim can
  // still be made on: `ldap_server.js` builds it through `tlsProtocolOptions()`
  // in that file, which is a call to the SAME `tlsServer.protocolOptions()`
  // the deleted listener used and the main port still uses in `server.js`. So
  // this is one statement of the policy reaching a real handshake, which is
  // what the assertion was ever about — a setting read and never applied
  // passes every comparison.
  //
  // **THE MAIN PORT WOULD NOT HAVE BEEN HONEST HERE**: this file's child does
  // not start `server.js`, so a listener it built itself would be spreading
  // `protocolOptions()` with its own hands and then asserting that spreading
  // it worked. The directory's socket is built by a module that is not this
  // test.
  // -------------------------------------------------------------------------
  const floor = inAChild({ STS_TLS_MIN_VERSION: 'TLSv1.3', LDAP_PORT: '0',
                           LDAPS_PORT: '0', STS_HOST: '127.0.0.1' },
    'const ldap = require(R + "/ldap/ldap_server.js");const ready = await ' +
    'ldap.listen().whenReady;const port = ready.ldapsPort;' +
    'const tls = require("tls");function ' +
    'attempt(max) { return new Promise(function (ok) {  const s = ' +
    'tls.connect({ host: "127.0.0.1", port: port, maxVersion: ' +
    'max,    rejectUnauthorized: false }, function () { const v = ' +
    's.getProtocol(); s.destroy(); ok(v); });  s.on("error", function (e) { ' +
    'ok("refused: " + e.code); }); }); }return { port: port, twelve: await ' +
    'attempt("TLSv1.2"), thirteen: await attempt("TLSv1.3") };');
  const f = floor.report || {};
  t.check(/^refused/.test(String(f.twelve)) && f.thirteen === 'TLSv1.3',
          'with tls.minVersion TLSv1.3 a TLS 1.2 client is REFUSED on LDAPS ' +
          'and a 1.3 client is served — the setting reaches the handshake, ' +
          'not only a report. It was asserted on 8443 until that listener ' +
          'was deleted (2026-09-16); LDAPS builds its context from the same ' +
          'tlsServer.protocolOptions()',
          JSON.stringify(f) + floor.output.slice(-300));
  log.debug("Leaving theProtocolPolicyIsApplied().");
}

module.exports = {
  name: 'ldap_tls_product_mode',
  describe: 'the directory and TLS literals the 2026-09-12 audit found, in ' +
            'both modes',
  run: async function (t) {
    log.debug("Entering run().");
    productDirectoryHoldsNoDemoData(t);
    roleGroupsFollowTheSettings(t);
    productInventsNothingAndAuditsTruthfully(t);
    developmentIsUnchanged(t);
    listenersHonourTheBindAddress(t);
    theTruststoreIsNotATestControlInProduct(t);
    await theProtocolPolicyIsApplied(t);
    log.debug("Leaving run().");
  }
};
