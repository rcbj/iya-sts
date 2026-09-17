'use strict';
//
// File: spiffe_authorized_entries.js
//
// ===========================================================================
// AN AGENT IS TOLD ONLY ABOUT THE ENTRIES BENEATH IT (2026-09-16).
//
// `Entry.GetAuthorizedEntries` and `Entry.SyncAuthorizedEntries` answered
// every entry in the registry to any agent, so the `spiffeParentId` an entry
// records decided nothing. This file holds SPIRE's answer instead: the
// entries parented on the calling agent, the node aliases its recorded
// selectors match, and everything descended from either — and nothing
// parented on another agent, nothing expired, and nothing at all for a caller
// with no verified identity. And BatchNewX509SVID and NewJWTSVID issue an
// agent nothing from an entry outside that set (STS-SPIFFE-0077).
//
// IN A CHILD PROCESS, for `spiffe_join_token.js`'s reasons: requiring the
// SPIFFE server builds a certificate authority and writes into the default
// realm's directory, and `run.js` runs every file in one process.
// ===========================================================================

const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({
  name: 'spiffe_authorized_entries',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childScript() {
  log.debug("Entering childScript().");
  log.debug("Leaving childScript().");
  return [
    "delete process.env.CONFIG_FILE;",
    "require(" + JSON.stringify(path.join(ROOT, 'common/app')) + ");",
    "require(" + JSON.stringify(path.join(ROOT, 'ldap/ldap_server')) + ");",
    "require(" + JSON.stringify(path.join(ROOT, 'spiffe/spiffe_server')) + ");",
    "const EventEmitter = require('events');",
    "const auth = require(" +
    JSON.stringify(path.join(ROOT, 'spiffe/spiffe_auth')) + ");",
    "const api = require(" +
    JSON.stringify(path.join(ROOT, 'spiffe/spiffe_api')) + ");",
    "const grpc = require(" +
    JSON.stringify(path.join(ROOT, 'spiffe/spiffe_grpc')) + ");",
    "const ca = require(" +
    JSON.stringify(path.join(ROOT, 'spiffe/spiffe_ca')) + ");",
    "const registry = require(" +
    JSON.stringify(path.join(ROOT, 'spiffe/spiffe_registry')) + ");",
    "(async function () {",
    "  const td = ca.trustDomain();",
    "  const id = function (p) { return 'spiffe://' + td + p; };",
    "  const A = id('/spire/agent/join_token/probe-a');",
    "  const B = id('/spire/agent/join_token/probe-b');",
    "  const SERVER = id('/spire/server');",
    "  const made = {};",
    "  const make = function (name, record) {",
    "    const r = registry.createEntry(record, 'test', td, 'test');",
    "    if (!r.ok) { throw new Error(name + ': ' + r.errors.join(' ')); }",
    "    made[name] = r.entry.id;",
    "  };",
    "  registry.recordAttestation(A, { attestationType: 'join_token',",
    "    selectors: [{ type: 'probe', value: 'rack:1' }] });",
    "  make('underA', { spiffeId: id('/probe/under-a'), parentId: A,",
    "    selectors: [{ type: 'unix', value: 'uid:1' }] });",
    "  make('grandchildA', { spiffeId: id('/probe/grandchild-a'),",
    "    parentId: id('/probe/under-a'),",
    "    selectors: [{ type: 'unix', value: 'uid:2' }] });",
    "  make('underB', { spiffeId: id('/probe/under-b'), parentId: B,",
    "    selectors: [{ type: 'unix', value: 'uid:3' }] });",
    "  make('alias', { spiffeId: id('/probe/rack-1'), parentId: SERVER,",
    "    selectors: [{ type: 'probe', value: 'rack:1' }] });",
    "  make('underAlias', { spiffeId: id('/probe/under-rack'),",
    "    parentId: id('/probe/rack-1'),",
    "    selectors: [{ type: 'unix', value: 'uid:4' }] });",
    "  make('emptyAlias', { spiffeId: id('/probe/everyone'),",
    "    parentId: SERVER, selectors: [] });",
    "  make('expiredA', { spiffeId: id('/probe/expired-a'), parentId: A,",
    "    selectors: [{ type: 'unix', value: 'uid:5' }], expiresAt: 1 });",
    "  const handler = grpc.localMethod('server', 'Entry.GetAuthorizedEntries');",
    "  const ask = async function (caller) {",
    "    const reply = await handler({ request: {}, spiffeCaller: caller });",
    "    const ids = (reply.entries || []).map(function (e) { return e.id; });",
    "    return Object.keys(made).filter(function (k) {",
    "      return ids.indexOf(made[k]) >= 0;",
    "    }).sort();",
    "  };",
    "  const out = {",
    "    total: registry.allEntries().length,",
    "    forA: await ask({ authenticated: true, spiffeId: A }),",
    "    forB: await ask({ authenticated: true, spiffeId: B }),",
    "    forNobody: await ask({ authenticated: false, spiffeId: A }),",
    "    forNoCaller: await ask(null)",
    "  };",
    "  const agentA = { authenticated: true, spiffeId: A };",
    "  const batch = grpc.localMethod('server', 'SVID.BatchNewX509SVID');",
    "  const codeOf = async function (entryName) {",
    "    const reply = await batch({ request: { params: [",
    "      { entry_id: made[entryName] }] }, spiffeCaller: agentA });",
    "    return reply.results[0].status.code;",
    "  };",
    "  out.x509Foreign = await codeOf('underB');",
    "  out.x509Own = await codeOf('underA');",
    "  const jwt = grpc.localMethod('server', 'SVID.NewJWTSVID');",
    "  const jwtCode = async function (entryName) {",
    "    try {",
    "      await jwt({ request: { entry_id: made[entryName], audience: [] },",
    "                  spiffeCaller: agentA });",
    "      return 0;",
    "    } catch (e) {",
    "      return e.code;",
    "    }",
    "  };",
    "  out.jwtForeign = await jwtCode('underB');",
    "  out.jwtOwn = await jwtCode('underAlias');",
    // The STREAM, through the real bidi wrapper. The caller is what the
    // wrapper derives from the TLS peer, which a test has none of, so the
    // derivation is replaced for this call with agent A's verified identity.
    "  const realCallerOf = auth.callerOf;",
    "  auth.callerOf = function (call, surface) {",
    "    const c = realCallerOf(call, surface);",
    "    c.authenticated = true; c.spiffeId = A; c.entities.agent = true;",
    "    return c;",
    "  };",
    "  const entry = api.SERVICE_HANDLERS.filter(function (s) {",
    "    return s.name === 'entry'; })[0].handlers;",
    "  const stream = new EventEmitter();",
    "  stream.getPeer = function () { return '127.0.0.1:1'; };",
    "  stream.getAuthContext = function () { return null; };",
    "  stream.metadata = { get: function () { return []; } };",
    "  stream.end = function () {};",
    "  const synced = new Promise(function (resolve) {",
    "    stream.write = function (reply) { resolve({ reply: reply }); };",
    "    stream.on('error', function (err) {",
    "      resolve({ error: String(err && (err.details || err.message)) });",
    "    });",
    "  });",
    "  entry.SyncAuthorizedEntries(stream);",
    "  stream.emit('data', { ids: [made.underA] });",
    "  const sync = await synced;",
    // A UNARY call through the real wrapper, which is what records the
    // call's metrics row.
    "  const unary = await new Promise(function (resolve) {",
    "    entry.GetAuthorizedEntries({ request: {},",
    "      getPeer: function () { return '127.0.0.1:1'; },",
    "      getAuthContext: function () { return null; },",
    "      metadata: { get: function () { return []; } } },",
    "      function (err, reply) { resolve({ err: err, reply: reply }); });",
    "  });",
    "  out.unaryError = unary.err ?",
    "    String(unary.err.details || unary.err.message) : '';",
    "  const stats = require(" +
    JSON.stringify(path.join(ROOT, 'common/admin_stats')) + ");",
    "  const snap = JSON.stringify(stats.snapshot());",
    "  out.metricsRow = snap.indexOf('grpc:Entry.GetAuthorizedEntries') >= 0;",
    "  auth.callerOf = realCallerOf;",
    "  out.syncError = sync.error || '';",
    "  const byId = function (list) {",
    "    const ids = (list || []).map(function (e) { return e.id; });",
    "    return Object.keys(made).filter(function (k) {",
    "      return ids.indexOf(made[k]) >= 0; }).sort();",
    "  };",
    "  out.syncRevisions = sync.reply ? byId(sync.reply.entry_revisions) : [];",
    "  out.syncEntries = sync.reply ? byId(sync.reply.entries) : [];",
    "  require('fs').writeFileSync(process.env.PROBE_OUT, JSON.stringify(out));",
    "  process.exit(0);",
    "})().catch(function (e) {",
    "  require('fs').writeFileSync(process.env.PROBE_OUT,",
    "    JSON.stringify({ threw: e.stack }));",
    "  process.exit(1);",
    "});"
  ].join('\n');
}

function run(t) {
  log.debug("Entering run().");
  const os = require('os');
  const fs = require('fs');
  const outFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(),
                                                     'authorized-entries-')),
                            'out.json');
  const env = Object.assign({}, process.env, {
    LOG_LEVEL: 'fatal', PROBE_OUT: outFile, SPIFFE_GRPC_PORT: '0'
  });
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath, ['-e', childScript()],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 120000 });
  let out = {};
  try {
    out = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    fs.rmSync(path.dirname(outFile), { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No file is the child dying before it wrote one; the stderr says why.
    t.bad('the child process reported nothing',
          (child.stderr || '').slice(-2000));
    log.debug("Leaving run().");
    return;
  }
  if (out.threw) {
    t.bad('the child process threw', out.threw);
    log.debug("Leaving run().");
    return;
  }

  t.log.info('=== an agent is told only about the entries beneath it ===');
  t.check(out.total >= 7, 'the registry holds all seven entries this file ' +
          'made, so what follows is a narrowing and not an empty registry',
          out.total);
  t.equal(out.forA.join(','), 'alias,grandchildA,underA,underAlias',
          'agent A gets its own entry, that entry\'s child, the node alias its ' +
          'selectors match and the alias\'s child — and not agent B\'s entry, ' +
          'not an expired one, and not an alias with no selectors');
  t.equal(out.forB.join(','), 'underB',
          'agent B, whose attestation recorded no selectors, gets only the ' +
          'entry parented on it');
  t.equal(out.forNobody.length, 0,
          'a caller whose identity did not verify is authorized for nothing');
  t.equal(out.forNoCaller.length, 0,
          'and so is a call with no caller at all');

  t.log.info('=== the stream answers the same set ===');
  t.equal(out.syncError, '', 'SyncAuthorizedEntries answers rather than ' +
          'failing — until 2026-09-16 its narrowing named a variable its ' +
          'handler was never given');
  t.equal(out.syncRevisions.join(','), 'alias,grandchildA,underA,underAlias',
          'it lists the revisions of agent A\'s set and no other entry');
  t.equal(out.syncEntries.join(','), 'alias,grandchildA,underAlias',
          'and sends in full only the ones the agent did not say it holds');

  t.log.info('=== a gRPC call is counted on its own metrics row ===');
  t.equal(out.unaryError, '', 'the unary wrapper answered');
  t.check(out.metricsRow, 'the call is on a row named ' +
          'grpc:Entry.GetAuthorizedEntries — until 2026-09-16 every gRPC ' +
          'call was counted on one row with no method or path');

  t.log.info('=== and is issued nothing from any other entry ===');
  // gRPC status codes: 7 is PERMISSION_DENIED, 3 is INVALID_ARGUMENT. The
  // requests carry no CSR and no audience, so an entry the agent IS
  // authorized for gets past the authorization and is refused for that.
  t.equal(out.x509Foreign, 7,
          'BatchNewX509SVID refuses agent A an entry beneath agent B ' +
          '(PERMISSION_DENIED)');
  t.equal(out.x509Own, 3,
          'and lets its own entry through to the CSR check');
  t.equal(out.jwtForeign, 7,
          'NewJWTSVID refuses agent A an entry beneath agent B');
  t.equal(out.jwtOwn, 3,
          'and lets an entry under its node alias through to the audience ' +
          'check');
  log.debug("Leaving run().");
}

module.exports = { run: run };
