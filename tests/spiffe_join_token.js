'use strict';
//
// File: spiffe_join_token.js
//
// ===========================================================================
// A SPIFFE JOIN TOKEN IS A CREDENTIAL, AND NOTHING THIS SERVICE KEEPS HOLDS IT
// (2026-09-12).
//
// Two places held one until this date, and neither was a place anybody looks
// for a credential:
//
//   * THE TOKEN STORE WAS KEYED BY THE TOKEN. `spiffe/spiffe_api.js`'s
//     `joinTokens` is a persisted `realms.map()`, and a persisted row's KEY is
//     written as it is — `persistence/persistence_minted.js` seals the body
//     and not the key — so every unspent token sat in `sts_minted` and
//     `sts_changes` in the clear, with a second copy inside the body.
//   * THE AGENT'S SELECTORS CARRIED IT. `selectorsFromAttestation()` put any
//     short printable attestation payload on the agent's registry entry as
//     `payload:<text>`, and a join token is exactly that — so the token that
//     had just attested an agent was written into the SPIFFE registry, which is
//     the directory.
//
// So this file mints a token through `Agent.CreateJoinToken` and attests an
// agent with it through `Agent.AttestAgent`, both through the real gRPC
// wrappers with a real PKCS#10 request, and then looks for the token
// EVERYWHERE the two stores keep anything: every key and every body of the
// token store, before and after it is spent, and every selector on the agent's
// entry. It also asserts the token still WORKS — a store that could no longer
// find the token would pass every "not stored" check by refusing every agent.
//
// IN A CHILD PROCESS, for `spiffe_authority.js`'s reasons: requiring the SPIFFE
// server builds a certificate authority and writes an agent into the default
// realm's directory, and `run.js` runs every file in one process.
// ===========================================================================

const path = require('path');
const childProcess = require('child_process');

const ROOT = path.join(__dirname, '..');

function childScript() {
  return [
    "delete process.env.CONFIG_FILE;",
    "const EventEmitter = require('events');",
    "const nodeCrypto = require('crypto');",
    "require(" + JSON.stringify(path.join(ROOT, 'common/app')) + ");",
    "require(" + JSON.stringify(path.join(ROOT, 'ldap/ldap_server')) + ");",
    "require(" + JSON.stringify(path.join(ROOT, 'spiffe/spiffe_server')) + ");",
    "const api = require(" + JSON.stringify(path.join(ROOT, 'spiffe/spiffe_api')) + ");",
    "const registry = require(" + JSON.stringify(path.join(ROOT, 'spiffe/spiffe_registry')) + ");",
    "const x509 = require(" + JSON.stringify(path.join(ROOT, 'common/vendored/x509')) + ");",
    "const agent = api.SERVICE_HANDLERS.filter(function (s) { return s.name === 'agent'; })[0].handlers;",
    "function storeHolds(token) {",
    "  let found = false;",
    "  api.joinTokens.forEach(function (value, key) {",
    "    if (String(key).indexOf(token) >= 0 || JSON.stringify(value).indexOf(token) >= 0) { found = true; }",
    "  });",
    "  return found;",
    "}",
    "function unaryCall(request) {",
    "  return { request: request, getPeer: function () { return 'unix:/probe'; },",
    "           getAuthContext: function () { return null; },",
    "           metadata: { get: function () { return []; } } };",
    "}",
    "(async function () {",
    "  const out = {};",
    "  const created = await new Promise(function (resolve) {",
    "    agent.CreateJoinToken(unaryCall({ ttl: 600 }), function (err, reply) {",
    "      resolve({ err: err ? err.message : '', reply: reply });",
    "    });",
    "  });",
    "  out.createError = created.err;",
    "  const token = created.reply && created.reply.value;",
    "  out.minted = !!token;",
    "  out.storeSize = api.joinTokens.size;",
    "  out.storeHoldsTokenAfterCreate = token ? storeHolds(token) : null;",
    "  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });",
    "  const csr = await x509.certificationRequest({ subject: 'CN=probe-agent',",
    "    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),",
    "    privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) });",
    "  const call = new EventEmitter();",
    "  call.getPeer = function () { return 'unix:/probe'; };",
    "  call.getAuthContext = function () { return null; };",
    "  call.metadata = { get: function () { return []; } };",
    "  const replied = new Promise(function (resolve) {",
    "    call.write = function (reply) { resolve({ reply: reply }); };",
    "    call.on('error', function (err) { resolve({ error: err && (err.details || err.message) }); });",
    "  });",
    "  call.end = function () {};",
    "  agent.AttestAgent(call);",
    "  call.emit('data', { params: { data: { type: 'join_token', payload: Buffer.from(token, 'utf8') },",
    "                               params: { csr: Buffer.from(csr.der) } } });",
    "  const answer = await replied;",
    "  out.attestError = answer.error || '';",
    "  out.attested = !!(answer.reply && answer.reply.result);",
    "  out.storeHoldsTokenAfterAttest = storeHolds(token);",
    "  out.storeSizeAfterAttest = api.joinTokens.size;",
    "  const found = registry.allAgents().filter(function (a) { return a.attestationType === 'join_token'; });",
    "  out.tokenInAudit = JSON.stringify(require(" + JSON.stringify(path.join(ROOT, 'common/audit')) + ").list()).indexOf(token) >= 0;",
    "  out.agentCount = found.length;",
    "  out.selectorsText = JSON.stringify(found.map(function (a) { return a.selectors; }));",
    "  out.anyAgentText = JSON.stringify(found);",
    "  out.tokenInAgent = out.anyAgentText.indexOf(token) >= 0;",
    "  out.digest = nodeCrypto.createHash('sha256').update(token, 'utf8').digest('hex').slice(0, 16);",
    "  const refused = new Promise(function (resolve) {",
    "    const again = new EventEmitter();",
    "    again.getPeer = call.getPeer; again.getAuthContext = call.getAuthContext; again.metadata = call.metadata;",
    "    again.write = function () { resolve('accepted'); };",
    "    again.end = function () {};",
    "    again.on('error', function (err) { resolve(String(err && (err.details || err.message))); });",
    "    agent.AttestAgent(again);",
    "    again.emit('data', { params: { data: { type: 'join_token', payload: Buffer.from(token, 'utf8') },",
    "                                   params: { csr: Buffer.from(csr.der) } } });",
    "  });",
    "  out.secondUse = await refused;",
    "  require('fs').writeFileSync(process.env.PROBE_OUT, JSON.stringify(out));",
    "  process.exit(0);",
    "})().catch(function (e) {",
    "  require('fs').writeFileSync(process.env.PROBE_OUT, JSON.stringify({ threw: e.stack }));",
    "  process.exit(1);",
    "});"
  ].join('\n');
}

function run(t) {
  const os = require('os');
  const fs = require('fs');
  const outFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'join-token-')), 'out.json');
  const env = Object.assign({}, process.env, {
    LOG_LEVEL: 'fatal', PROBE_OUT: outFile,
    // No socket is bound by requiring the server; these keep a stray bind off
    // anything live all the same.
    SPIFFE_GRPC_PORT: '0', STS_TLS_PORT: '0', STS_MTLS_PORT: '0'
  });
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath, ['-e', childScript()],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 120000 });
  let out = {};
  try {
    out = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    fs.rmSync(path.dirname(outFile), { recursive: true, force: true });
  } catch (e) {
    // No file is the child dying before it wrote one; the stderr says why.
    t.bad('the child process reported nothing', (child.stderr || '').slice(-2000));
    return;
  }
  if (out.threw) {
    t.bad('the child process threw', out.threw);
    return;
  }

  t.log.info('=== 1. the token store ===');
  t.check(out.minted, 'CreateJoinToken minted a token', out.createError);
  t.equal(out.storeSize, 1, 'and the store holds one row for it');
  t.equal(out.storeHoldsTokenAfterCreate, false,
          'and NO key and NO body in the store contains the token — a persisted ' +
          'row\'s key is written unsealed, so a key that was the token was a ' +
          'credential in the database');

  t.log.info('=== 2. the token still attests, once ===');
  t.check(out.attested, 'the token attests an agent — the digest-keyed store still finds it',
          out.attestError);
  t.equal(out.storeSizeAfterAttest, 0, 'and attesting spends it');
  t.equal(out.storeHoldsTokenAfterAttest, false, 'and nothing of it is left in the store');
  t.check(/already been spent|not issued by this server/.test(out.secondUse),
          'a second attestation with the same token is refused', out.secondUse);

  t.log.info('=== 3. the agent entry ===');
  t.check(out.agentCount >= 1, 'the attested agent is in the registry', out.anyAgentText);
  t.equal(out.tokenInAgent, false,
          'and the token appears NOWHERE on its entry — not in a selector, not anywhere',
          out.selectorsText);
  t.equal(out.tokenInAudit, false, 'nor in the audit log');
  t.check(out.selectorsText.indexOf('token-sha256:' + out.digest) >= 0,
          'its selector carries a digest prefix instead, so somebody holding the ' +
          'token can still recognise the agent it attested', out.selectorsText);
}

module.exports = {
  name: 'spiffe_join_token',
  describe: 'a SPIFFE join token is never held in clear: not as a store key, a store body or a selector',
  run: run
};
