'use strict';
//
// File: spiffe_local_socket.js
//
// ===========================================================================
// THE SPIRE SERVER API'S `local` SOCKET, VERIFIED IN PRODUCT (#104).
//
// A real SPIRE server trusts its private Unix socket outright and relies on
// the socket's filesystem permissions. `spiffe.trustLocalSocket` (on by
// default) did the same here in every mode, and a chmod that failed
// (STS-SPIFFE-0010) left the socket served, and trusted, in product. Product
// now VERIFIES the boundary per connection; development is unchanged. Three
// halves:
//
//   1. THE DECISION, over stubbed facts: `SpiffeAuth.localTrust()` built with
//      a stub peer module and a stub uid. Product: no facts (no native
//      module) is not local (STS-SPIFFE-0119), a socket not verified private
//      is not local (STS-SPIFFE-0117), a peer running as another uid is not
//      local (STS-SPIFFE-0118), and a private socket with this service's own
//      uid is. Development: local with no facts at all. Off: nobody. And a
//      refused caller's `authorize()` carries the condition's code.
//   2. THE SOCKET'S MODE, over a real socket: `restrictSocket()` makes it
//      0600 and `socketPrivacy()` says private; a socket or a directory that
//      other users can reach is not private; a chmod that FAILED is not.
//   3. THE REAL THING: a realm's SPIRE Server API bound on a Unix socket in
//      this run's own directory, and a CHILD PROCESS — running as this uid,
//      as the spire-server CLI would — calling Entry.CountEntries, which
//      only `local` and an admin may. In a product realm it is answered; with
//      the socket made reachable by other users it is refused
//      UNAUTHENTICATED, naming why; in development the same reachable socket
//      is still trusted.
//
// The third half needs `spiffe/native/peercred.node`, which the tests image
// builds (`spiffe_workload_attestation.js`'s rule): its absence is a FAILURE,
// because without it a product realm trusts nobody on the socket and nothing
// else here would notice.
// ===========================================================================

const os = require('os');
const path = require('path');
const fs = require('fs');
const net = require('net');
const childProcess = require('child_process');

const config = require('../common/config');
const realms = require('../common/realms');
const server = require('../spiffe/spiffe_server');
const auth = require('../spiffe/spiffe_auth');
const rpc = require('../spiffe/spiffe_grpc');
const peer = require('../spiffe/spiffe_peer');

const log = require('bunyan').createLogger({ name: 'spiffe_local_socket',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-local-socket-'));
const SOCKET = path.join(WORK, 'private', 'api.sock');
// Left standing, SPIFFE turned off, for `tests/spiffe_pki.js`'s reason.
const REALM = 'spiffe-local-socket';
const OWN = typeof process.geteuid === 'function' ? process.geteuid() : -1;

function show(value) {
  log.debug("Entering show().");
  log.debug("Leaving show().");
  return JSON.stringify(value);
}

// A call whose peer is `tag`, arriving on no TLS.
function callFrom(tag) {
  log.debug("Entering callFrom().");
  log.debug("Leaving callFrom().");
  return {
    getAuthContext: function () {
      return {};
    },
    getPeer: function () {
      return tag;
    }
  };
}

// A SpiffeAuth whose peer module answers `facts` for every call, and whose
// process runs as `uid`.
function authWith(facts, uid) {
  log.debug("Entering authWith().");
  const deps = Object.assign({}, auth.SpiffeAuth.defaultDeps(), {
    peer: {
      factsFor: function () {
        return facts;
      },
      availability: function () {
        return { available: !!facts, problem: facts ? '' : 'stubbed away' };
      }
    },
    processUid: function () {
      return uid;
    }
  });
  log.debug("Leaving authWith().");
  return new auth.SpiffeAuth(deps);
}

function decision(t) {
  log.debug("Entering decision().");
  t.log.info('=== 1. the decision, over stubbed facts ===');
  const call = callFrom('unix:attested-9104:9104');
  const privateSocket = { private: true, why: '' };
  const facts = function (uid, localSocket, error) {
    return { tag: 'unix:attested-9104', uid: uid, error: error || '',
             localSocket: localSocket };
  };
  try {
    config.setOverride('global.mode', 'product');
    let trust = authWith(null, 4104).localTrust(call);
    t.check(!trust.local && trust.errorCode === 'STS-SPIFFE-0119',
            'product: a caller whose kernel credentials were never read is ' +
            'not local (STS-SPIFFE-0119)', show(trust));
    trust = authWith(facts(-1, privateSocket, 'SO_PEERCRED failed: x'), 4104)
      .localTrust(call);
    t.check(!trust.local && trust.errorCode === 'STS-SPIFFE-0119' &&
            /SO_PEERCRED failed/.test(trust.why),
            'product: nor is one whose SO_PEERCRED failed', show(trust));
    trust = authWith(facts(4104, { private: false,
      why: 'the socket could not be made mode 0600 (STS-SPIFFE-0010)' }),
                     4104).localTrust(call);
    t.check(!trust.local && trust.errorCode === 'STS-SPIFFE-0117' &&
            /STS-SPIFFE-0010/.test(trust.why),
            'product: a socket whose chmod failed is not trusted, even for ' +
            'this service\'s own uid (STS-SPIFFE-0117)', show(trust));
    trust = authWith(facts(4104, undefined), 4104).localTrust(call);
    t.check(!trust.local && trust.errorCode === 'STS-SPIFFE-0117',
            'product: nor is a connection whose socket was never checked',
            show(trust));
    trust = authWith(facts(4105, privateSocket), 4104).localTrust(call);
    t.check(!trust.local && trust.errorCode === 'STS-SPIFFE-0118' &&
            /uid 4105/.test(trust.why),
            'product: a peer running as ANOTHER uid is not local, on a ' +
            'private socket (STS-SPIFFE-0118)', show(trust));
    const verified = authWith(facts(4104, privateSocket), 4104);
    trust = verified.localTrust(call);
    t.check(trust.local && !trust.errorCode,
            'product: a private socket and this service\'s own uid is local',
            show(trust));
    const refused = authWith(facts(4105, privateSocket), 4104);
    const caller = refused.callerOf(call, 'server');
    t.check(caller.transport === 'uds' && !caller.entities.local,
            'product: callerOf() on the server surface leaves the foreign ' +
            'uid out of `local`', show(caller.entities));
    const no = refused.authorize(caller, 'Entry.CountEntries');
    t.check(!!no && no.status === 'UNAUTHENTICATED' &&
            no.errorCode === 'STS-SPIFFE-0118' &&
            /not this service's uid/.test(no.message),
            'product: and authorize() refuses Entry.CountEntries with the ' +
            'condition\'s code and sentence', show(no));
    t.check(verified.authorize(verified.callerOf(call, 'server'),
                               'Entry.CountEntries') === null,
            'product: while the verified caller is allowed it');
    config.setOverride('global.mode', 'development');
    trust = authWith(null, 4104).localTrust(call);
    t.check(trust.local,
            'development: the socket is trusted as it always was, with ' +
            'nothing read', show(trust));
    config.setOverride('spiffe.trustLocalSocket', false);
    trust = authWith(facts(4104, privateSocket), 4104).localTrust(call);
    t.check(!trust.local && !trust.errorCode,
            'spiffe.trustLocalSocket off: nobody is local, in any mode',
            show(trust));
  } finally {
    config.clearOverride('global.mode');
    config.clearOverride('spiffe.trustLocalSocket');
  }
  log.debug("Leaving decision().");
}

async function socketMode(t) {
  log.debug("Entering socketMode().");
  t.log.info('=== 2. the socket\'s mode, over a real socket ===');
  const dir = path.join(WORK, 'mode-probe');
  fs.mkdirSync(dir, { mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const at = path.join(dir, 'probe.sock');
  const listener = net.createServer();
  await new Promise(function (resolve) {
    listener.listen(at, resolve);
  });
  try {
    t.check(!rpc.socketPrivacy(at).private,
            'a socket restrictSocket() has not seen is not private');
    t.check(rpc.restrictSocket(at) === true,
            'restrictSocket() makes the socket 0600');
    t.check((fs.statSync(at).mode & 0o777) === 0o600,
            'and it is', (fs.statSync(at).mode & 0o777).toString(8));
    t.check(rpc.socketPrivacy(at).private,
            'a 0600 socket in a 0700 directory is private',
            show(rpc.socketPrivacy(at)));
    fs.chmodSync(at, 0o666);
    let verdict = rpc.socketPrivacy(at);
    t.check(!verdict.private && /mode 666/.test(verdict.why),
            'a socket other users can reach is not', show(verdict));
    fs.chmodSync(at, 0o600);
    fs.chmodSync(dir, 0o755);
    verdict = rpc.socketPrivacy(at);
    t.check(!verdict.private && /directory/.test(verdict.why),
            'nor is one in a directory other users can enter', show(verdict));
    fs.chmodSync(dir, 0o700);
    const missing = path.join(dir, 'never-bound.sock');
    t.check(rpc.restrictSocket(missing) === false,
            'restrictSocket() on a path it cannot chmod fails ' +
            '(STS-SPIFFE-0010)');
    verdict = rpc.socketPrivacy(missing);
    t.check(!verdict.private && /STS-SPIFFE-0010/.test(verdict.why),
            'and that socket is not private, saying why', show(verdict));
  } finally {
    listener.close();
  }
  log.debug("Leaving socketMode().");
}

// The spire-server CLI, as a child program: one Entry.CountEntries over the
// socket, the outcome on stdout. Runs in the child only, which the code style
// exempts from the Entering/Leaving lines.
function clientProgram(packageRoot, socketPath) {
  const rpc = require(require('path').join(packageRoot,
                                           'spiffe/spiffe_grpc'));
  const client = new (rpc.grpc.makeGenericClientConstructor(
    rpc.SERVICES.entry, 'Entry'))(
      'unix://' + socketPath, rpc.grpc.credentials.createInsecure());
  client.CountEntries({}, function (err, reply) {
    process.stdout.write('RESULT ' + JSON.stringify(err
      ? { ok: false, code: err.code, details: err.details }
      : { ok: true, count: reply && reply.count }) + '\n');
    process.exit(0);
  });
}

function countEntries() {
  log.debug("Entering countEntries().");
  const script = 'delete process.env.CONFIG_FILE;\n(' +
    clientProgram.toString() + ')(' + JSON.stringify(ROOT) + ', ' +
    JSON.stringify(SOCKET) + ');';
  const env = Object.assign({}, process.env, { LOG_LEVEL: 'fatal',
                                               STS_LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  const child = childProcess.spawn(process.execPath, ['-e', script],
    { cwd: ROOT, env: env, stdio: ['ignore', 'pipe', 'pipe'] });
  log.debug("Leaving countEntries().");
  return new Promise(function (resolve) {
    let out = '';
    let err = '';
    const timer = setTimeout(function () {
      child.kill();
      resolve({ ok: false, details: 'timed out; ' + err.slice(-800) });
    }, 60000);
    child.stderr.on('data', function (chunk) {
      err += chunk;
    });
    child.stdout.on('data', function (chunk) {
      out += chunk;
    });
    child.on('exit', function () {
      clearTimeout(timer);
      const start = out.indexOf('RESULT ');
      let outcome = { ok: false, details: 'no result: ' + err.slice(-800) };
      if (start >= 0) {
        try {
          outcome = JSON.parse(out.slice(start + 'RESULT '.length)
                                  .split('\n')[0]);
        } catch (e) {
          log.debug("Caught in countEntries(): " + ((e && e.message) || e));
          outcome = { ok: false, details: out };
        }
      }
      resolve(outcome);
    });
  });
}

async function realSocket(t) {
  log.debug("Entering realSocket().");
  t.log.info('=== 3. a real socket, and a CLI in another process ===');
  const availability = peer.availability();
  t.check(availability.available,
          'the native module is built in this image — without it a product ' +
          'realm trusts nobody on the socket', availability.problem);
  if (!availability.available) {
    log.debug("Leaving realSocket(). No native module.");
    return;
  }
  const made = realms.get(REALM) ? { ok: true } : realms.create({
    id: REALM, name: REALM, overrides: {
      'spiffe.workloadPort': 0, 'spiffe.serverPort': 0,
      'spiffe.workloadSocketEnabled': false,
      'spiffe.serverSocketEnabled': true,
      'spiffe.serverSocket': SOCKET } });
  t.check(made.ok, 'a realm of this run\'s own',
          (made.errors || []).join(' '));
  try {
    await server.listen().whenReady;
    const on = realms.setOverride(REALM, 'spiffe.enabled', true);
    t.check(on.ok, 'SPIFFE is turned on in it', (on.errors || []).join(' '));
    await server.reconcile();
    const bound = server.bindings();
    const onSocket = ((bound && bound.api) || []).filter(function (b) {
      return b.address === 'unix://' + SOCKET;
    })[0];
    t.check(!!onSocket && onSocket.listening && onSocket.restricted &&
            onSocket.peerCredentials,
            'the SPIRE Server API is bound on its Unix socket, made 0600, ' +
            'and read for its peer\'s credentials', show(onSocket));

    let mode = realms.setOverride(REALM, 'global.mode', 'product');
    t.check(mode.ok, 'the realm is switched to product',
            (mode.errors || []).join(' '));
    let outcome = await countEntries();
    t.check(outcome.ok,
            'product: a CLI running as this service\'s uid is the local ' +
            'entity and is answered', show(outcome));

    fs.chmodSync(SOCKET, 0o666);
    outcome = await countEntries();
    t.check(!outcome.ok && outcome.code === 16 &&
            /NOT trusted as local/.test(outcome.details || '') &&
            /mode 666/.test(outcome.details || ''),
            'product: once the socket is reachable by other users, the same ' +
            'CLI is refused UNAUTHENTICATED, naming why', show(outcome));

    mode = realms.setOverride(REALM, 'global.mode', 'development');
    t.check(mode.ok, 'the realm is switched back to development',
            (mode.errors || []).join(' '));
    outcome = await countEntries();
    t.check(outcome.ok,
            'development: the reachable socket is still trusted, as it ' +
            'always was', show(outcome));
    fs.chmodSync(SOCKET, 0o600);
  } finally {
    realms.setOverride(REALM, 'global.mode', 'development');
    realms.setOverride(REALM, 'spiffe.enabled', false);
    await server.reconcile();
    server.close();
  }
  log.debug("Leaving realSocket().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    decision(t);
    await socketMode(t);
    await realSocket(t);
  } finally {
    fs.rmSync(WORK, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_local_socket',
  describe: '#104: in product a SPIRE Server API socket caller is `local` ' +
            'only when the socket is verified private and the kernel says ' +
            'it runs as this service\'s uid; development trusts the socket ' +
            'as it always did',
  run: run
};
