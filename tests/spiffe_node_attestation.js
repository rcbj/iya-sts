'use strict';
//
// File: spiffe_node_attestation.js
//
// ===========================================================================
// NODE ATTESTATION IS VERIFIED OR REFUSED, AND A CHALLENGE IS A CONVERSATION
// (#40, 2026-09-21).
//
// Until this date `Agent.AttestAgent` accepted ANY attestation type: every
// type but `join_token` was issued an agent SVID with its payload unread and a
// selector saying `unverified:true`. This file holds the four things that
// replaced it, through the real gRPC wrappers and a real PKCS#10 request:
//
//   1. A type the realm does not accept — or accepts and nothing here
//      verifies — is FAILED_PRECONDITION and records no agent. An empty type
//      is INVALID_ARGUMENT.
//   2. An attestor can CHALLENGE on the same stream (`bidiStream()`'s
//      conversation): the next message is the answer, not a new request; no
//      answer is DEADLINE_EXCEEDED; a next message that is not an answer is
//      INVALID_ARGUMENT; the client ending the stream with a challenge
//      outstanding is CANCELLED — and in every failure the evidence the
//      attestor claimed is given back.
//   3. A CLIENT'S HALF-CLOSE WAITS FOR THE HANDLER. It used to end the stream
//      before the asynchronous handler answered, so the client saw nothing
//      while its join token was spent.
//   4. Evidence that is not re-attestable attests ONCE; and
//      `CreateJoinToken`'s `agent_id` registers an ALIAS entry, as SPIRE does,
//      where it used to be a constraint no attestation could ever meet.
//
// The three test attestors are registered on an instance of `SpiffeApi` built
// here, whose table is its own, so nothing about the service's installed
// instance changes.
//
// IN A CHILD PROCESS, for `spiffe_join_token.js`'s reasons: requiring the
// SPIFFE server builds a certificate authority and writes agents into the
// default realm's directory, and `run.js` runs every file in one process.
// ===========================================================================

const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'spiffe_node_attestation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childScript() {
  log.debug("Entering childScript().");
  log.debug("Leaving childScript().");
  return [
    "delete process.env.CONFIG_FILE;",
    "const EventEmitter = require('events');",
    "const nodeCrypto = require('crypto');",
    "require(" + JSON.stringify(path.join(ROOT, 'common/app')) + ");",
    "require(" + JSON.stringify(path.join(ROOT, 'ldap/ldap_server')) + ");",
    "require(" + JSON.stringify(path.join(ROOT, 'spiffe/spiffe_server')) + ");",
    "const api = require(" +
    JSON.stringify(path.join(ROOT, 'spiffe/spiffe_api')) + ");",
    "const ca = require(" +
    JSON.stringify(path.join(ROOT, 'spiffe/spiffe_ca')) + ");",
    "const registry = require(" +
    JSON.stringify(path.join(ROOT, 'spiffe/spiffe_registry')) + ");",
    "const spiffeId = require(" +
    JSON.stringify(path.join(ROOT, 'spiffe/spiffe_id')) + ");",
    "const x509 = require(" +
    JSON.stringify(path.join(ROOT, 'common/vendored/x509')) + ");",
    "const instance = new api.SpiffeApi(api.SpiffeApi.defaultDeps());",
    "const agent = instance.buildAgentHandlers();",
    "const table = instance.nodeAttestation();",
    "const settled = { released: 0, committed: 0 };",
    // Three test attestors: one that challenges (sends `nonce`, wants
    // `nonce-answered`), one that is not re-attestable, and one the realm
    // does not turn on.
    "function stubResult(id, canReattest) {",
    "  return { agentId: spiffeId.agentId(ca.trustDomain(), 'test', id),",
    "    selectors: [{ type: 'test', value: 'id:' + id }],",
    "    canReattest: canReattest, method: 'test', note: 'test',",
    "    commit: function () { settled.committed++; },",
    "    release: function () { settled.released++; } };",
    "}",
    "table.register({ type: 'test_challenge', verifies: 'a test',",
    "  attest: async function (ctx) {",
    "    const answer = await ctx.challenge(Buffer.from('nonce'));",
    "    if (answer.toString() !== 'nonce-answered') {",
    "      const e = new Error('wrong answer'); e.code = 7; throw e;",
    "    }",
    "    return stubResult(ctx.payload.toString() || 'c', true);",
    "  } });",
    "table.register({ type: 'test_once', verifies: 'a test',",
    "  attest: async function (ctx) {",
    "    return stubResult('once-' + ctx.payload.toString(), false);",
    "  } });",
    "table.register({ type: 'test_off', verifies: 'a test, not enabled',",
    "  attest: async function () { return stubResult('off', true); } });",
    "function unaryCall(request) {",
    "  return { request: request, getPeer: function () { return 'unix:/probe'; },",
    "           getAuthContext: function () { return null; },",
    "           metadata: { get: function () { return []; } } };",
    "}",
    "function unary(name, request) {",
    "  return new Promise(function (resolve) {",
    "    agent[name](unaryCall(request), function (err, reply) {",
    "      resolve({ err: err ? (err.details || err.message) : '',",
    "                code: err ? err.code : 0, reply: reply });",
    "    });",
    "  });",
    "}",
    // A fake bidi call on the real wrapper: `finished` resolves with what was
    // written, once the stream is ended or fails.
    "function stream() {",
    "  const call = new EventEmitter();",
    "  call.getPeer = function () { return 'unix:/probe'; };",
    "  call.getAuthContext = function () { return null; };",
    "  call.metadata = { get: function () { return []; } };",
    "  const events = [];",
    "  let done;",
    "  const finished = new Promise(function (r) { done = r; });",
    "  call.write = function (m) {",
    "    events.push(m.challenge ? 'challenge:' + Buffer.from(m.challenge).toString()",
    "                : (m.result ? 'result:' + m.result.svid.id.path +",
    "                   ':reattestable=' + m.result.reattestable : 'write'));",
    "    call.emit('wrote', m);",
    "  };",
    "  call.end = function () { events.push('end'); done(events); };",
    "  call.on('error', function (err) {",
    "    events.push('error:' + err.code + ':' + (err.details || err.message));",
    "    done(events);",
    "  });",
    "  agent.AttestAgent(call);",
    "  return { call: call, events: events, finished: finished };",
    "}",
    "let csrDer = null;",
    "function params(type, payload) {",
    "  return { params: { data: { type: type, payload: Buffer.from(payload || '', 'utf8') },",
    "                     params: { csr: csrDer } } };",
    "}",
    "function agentsOf(type) {",
    "  return registry.allAgents().filter(function (a) { return a.attestationType === type; });",
    "}",
    "(async function () {",
    "  const out = {};",
    "  await ca.ready();",
    "  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });",
    "  csrDer = Buffer.from((await x509.certificationRequest({ subject: 'CN=probe-agent',",
    "    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),",
    "    privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) })).der);",
    "  out.state = instance.nodeAttestationState();",
    // 1. Refusals.
    "  let s = stream(); s.call.emit('data', params('k8s_psat', 'anything')); s.call.emit('end');",
    "  out.unknownType = await s.finished;",
    "  s = stream(); s.call.emit('data', params('test_off', 'x')); s.call.emit('end');",
    "  out.notEnabled = await s.finished;",
    "  s = stream(); s.call.emit('data', params('bogus', 'x')); s.call.emit('end');",
    "  out.configuredUnknown = await s.finished;",
    "  s = stream(); s.call.emit('data', params('', 'x')); s.call.emit('end');",
    "  out.emptyType = await s.finished;",
    "  out.agentsAfterRefusals = agentsOf('k8s_psat').length + agentsOf('test_off').length +",
    "                            agentsOf('bogus').length;",
    // 2. The challenge conversation.
    "  s = stream();",
    "  s.call.once('wrote', function () {",
    "    s.call.emit('data', { challenge_response: Buffer.from('nonce-answered') });",
    "    s.call.emit('end');",
    "  });",
    "  s.call.emit('data', params('test_challenge', 'good'));",
    "  out.challengeAnswered = await s.finished;",
    "  const before = settled.released;",
    "  s = stream(); s.call.emit('data', params('test_challenge', 'late'));",
    "  out.challengeTimeout = await s.finished;",
    "  out.releasedOnTimeout = settled.released - before;",
    "  s = stream();",
    "  s.call.once('wrote', function () {",
    "    s.call.emit('data', params('test_challenge', 'again'));",
    "  });",
    "  s.call.emit('data', params('test_challenge', 'confused'));",
    "  out.challengeNotAnswered = await s.finished;",
    "  s = stream();",
    "  s.call.once('wrote', function () { s.call.emit('end'); });",
    "  s.call.emit('data', params('test_challenge', 'gone'));",
    "  out.challengeClientEnded = await s.finished;",
    "  s = stream(); s.call.emit('data', { challenge_response: Buffer.from('x') });",
    "  s.call.emit('end');",
    "  out.responseWithoutChallenge = await s.finished;",
    // 3. Half-close: a join token sent and the stream ended at once.
    "  let made = await unary('CreateJoinToken', { ttl: 600 });",
    "  s = stream(); s.call.emit('data', params('join_token', made.reply.value));",
    "  s.call.emit('end');",
    "  out.halfClosed = await s.finished;",
    // 4. Not re-attestable: once.
    "  s = stream(); s.call.emit('data', params('test_once', 'n1')); s.call.emit('end');",
    "  out.onceFirst = await s.finished;",
    "  const beforeOnce = settled.released;",
    "  s = stream(); s.call.emit('data', params('test_once', 'n1')); s.call.emit('end');",
    "  out.onceSecond = await s.finished;",
    "  out.releasedOnSecond = settled.released - beforeOnce;",
    // 4b. A join token minted for a named agent: an alias entry.
    "  const alias = spiffeId.make(ca.trustDomain(), '/node/alias-probe');",
    "  made = await unary('CreateJoinToken', { ttl: 600,",
    "    agent_id: spiffeId.toProto(alias) });",
    "  out.aliasCreateError = made.err;",
    "  s = stream(); s.call.emit('data', params('join_token', made.reply && made.reply.value));",
    "  s.call.emit('end');",
    "  out.aliasAttested = await s.finished;",
    "  const aliasEntries = registry.entriesForSpiffeId(alias);",
    "  out.aliasEntry = aliasEntries.map(function (e) {",
    "    return { parentId: e.parentId, selectors: e.selectors }; });",
    "  const attestedPath = (out.aliasAttested[0] || '').split(':')[1] || '';",
    "  out.aliasAgentId = 'spiffe://' + ca.trustDomain() + attestedPath;",
    "  out.aliasAuthorized = registry.entriesAuthorizedFor(out.aliasAgentId,",
    "    ca.trustDomain()).some(function (e) { return e.spiffeId === alias; });",
    "  const sizeBefore = api.joinTokens.size;",
    "  made = await unary('CreateJoinToken', { ttl: 600,",
    "    agent_id: { trust_domain: 'elsewhere.example', path: '/node/x' } });",
    "  out.foreignAlias = { code: made.code, err: made.err,",
    "                       stored: api.joinTokens.size - sizeBefore };",
    "  require('fs').writeFileSync(process.env.PROBE_OUT, JSON.stringify(out));",
    "  process.exit(0);",
    "})().catch(function (e) {",
    "  require('fs').writeFileSync(process.env.PROBE_OUT, JSON.stringify({ threw: e.stack }));",
    "  process.exit(1);",
    "});"
  ].join('\n');
}

function run(t) {
  log.debug("Entering run().");
  const os = require('os');
  const fs = require('fs');
  const outFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(),
                                                     'node-attest-')),
                            'out.json');
  const env = Object.assign({}, process.env, {
    LOG_LEVEL: 'fatal', PROBE_OUT: outFile,
    SPIFFE_GRPC_PORT: '0',
    STS_SPIFFE_NODE_ATTESTORS: 'join_token,test_challenge,test_once,bogus',
    STS_SPIFFE_ATTESTATION_CHALLENGE_TIMEOUT: '1'
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
  function text(events) {
    log.debug("Entering text().");
    log.debug("Leaving text().");
    return JSON.stringify(events);
  }
  // gRPC status numbers.
  const CANCELLED = 1;
  const INVALID_ARGUMENT = 3;
  const DEADLINE_EXCEEDED = 4;
  const PERMISSION_DENIED = 7;
  const FAILED_PRECONDITION = 9;
  function failedWith(events, code) {
    log.debug("Entering failedWith().");
    log.debug("Leaving failedWith().");
    return events.length === 1 &&
           events[0].indexOf('error:' + code + ':') === 0;
  }

  t.log.info('=== 1. a type nothing verifies is refused ===');
  t.check(failedWith(out.unknownType, FAILED_PRECONDITION),
          'a type the realm does not accept (k8s_psat) is FAILED_PRECONDITION',
          text(out.unknownType));
  t.check(failedWith(out.notEnabled, FAILED_PRECONDITION),
          'so is a type an attestor verifies but the realm has not turned on',
          text(out.notEnabled));
  t.check(failedWith(out.configuredUnknown, FAILED_PRECONDITION),
          'so is a type the realm names and nothing here verifies',
          text(out.configuredUnknown));
  t.check(failedWith(out.emptyType, INVALID_ARGUMENT),
          'an empty type is INVALID_ARGUMENT', text(out.emptyType));
  t.equal(out.agentsAfterRefusals, 0, 'and none of them recorded an agent');
  t.check(JSON.stringify(out.state.unknownConfigured) === '["bogus"]',
          'GET /spiffe\'s nodeAttestation names the configured type nothing ' +
          'verifies', JSON.stringify(out.state));

  t.log.info('=== 2. a challenge is a conversation on the stream ===');
  t.check(out.challengeAnswered[0] === 'challenge:nonce' &&
          /^result:\/spire\/agent\/test\/good:reattestable=true$/
            .test(out.challengeAnswered[1]) &&
          out.challengeAnswered[2] === 'end',
          'challenge, the answer as the next message, then the SVID, then ' +
          'the end', text(out.challengeAnswered));
  t.check(failedWith(out.challengeTimeout.slice(1), DEADLINE_EXCEEDED),
          'no answer within the timeout is DEADLINE_EXCEEDED',
          text(out.challengeTimeout));
  t.check(failedWith(out.challengeNotAnswered.slice(1), INVALID_ARGUMENT),
          'a next message that is not a challenge_response is ' +
          'INVALID_ARGUMENT', text(out.challengeNotAnswered));
  t.check(failedWith(out.challengeClientEnded.slice(1), CANCELLED),
          'the client ending the stream with a challenge outstanding is ' +
          'CANCELLED', text(out.challengeClientEnded));
  t.check(failedWith(out.responseWithoutChallenge, INVALID_ARGUMENT),
          'a challenge_response with no challenge outstanding is ' +
          'INVALID_ARGUMENT', text(out.responseWithoutChallenge));

  t.log.info('=== 3. a half-close waits for the answer ===');
  t.check(/^result:\/spire\/agent\/join_token\//
            .test(out.halfClosed[0] || '') &&
          out.halfClosed[1] === 'end',
          'a join token sent and the stream half-closed at once still gets ' +
          'its SVID before the stream ends', text(out.halfClosed));
  t.check(/reattestable=false$/.test(out.halfClosed[0] || ''),
          'and a join token is not re-attestable', text(out.halfClosed));

  t.log.info('=== 4. once, and the alias ===');
  t.check(/^result:/.test(out.onceFirst[0] || ''),
          'evidence that is not re-attestable attests once',
          text(out.onceFirst));
  t.check(failedWith(out.onceSecond, PERMISSION_DENIED),
          'and the same agent again is PERMISSION_DENIED',
          text(out.onceSecond));
  t.equal(out.releasedOnSecond, 1,
          'and what that attestor claimed is given back');
  t.equal(out.aliasCreateError, '', 'a join token for a named agent is ' +
                                    'minted');
  t.check(/^result:\/spire\/agent\/join_token\//
            .test(out.aliasAttested[0] || ''),
          'and it ATTESTS — it used to be refused, always, as minted for ' +
          'another agent', text(out.aliasAttested));
  t.check(out.aliasEntry.length === 1 &&
          out.aliasEntry[0].parentId === out.aliasAgentId &&
          JSON.stringify(out.aliasEntry[0].selectors) ===
            JSON.stringify([{ type: 'spiffe_id', value: out.aliasAgentId }]),
          'the name is an alias entry parented on the join token\'s agent, ' +
          'selecting spiffe_id:<that agent>, as SPIRE registers it',
          JSON.stringify(out.aliasEntry) + ' ' + out.aliasAgentId);
  t.check(out.aliasAuthorized, 'and the agent is authorized for it');
  t.check(out.foreignAlias.code === INVALID_ARGUMENT &&
          out.foreignAlias.stored === 0,
          'an agent_id in another trust domain is INVALID_ARGUMENT and mints ' +
          'no token', JSON.stringify(out.foreignAlias));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_node_attestation',
  describe: 'SPIFFE node attestation is verified or refused; a challenge is ' +
            'a conversation; a half-close waits; agent_id is an alias',
  run: run
};
