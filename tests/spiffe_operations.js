'use strict';
//
// File: spiffe_operations.js
//
// ===========================================================================
// THE TWO gRPC SURFACES, RUN IN A PROCESS THAT HOLDS NO SOCKET.
//
// `ldap/ldap_server.js` was the first family to fill the request pool's
// OPERATION channel; SPIFFE is the second, and the cut is a different one
// because gRPC has a shape LDAP does not — five of the forty-seven methods are
// SERVER STREAMS, and those deliberately do not cross.
//
// The claim is the one `tests/ldap_operations.js` makes, in this family's
// words: **a method run through the codec produces the same answer as the same
// handler called directly**, and the things that cannot cross are the things
// that belong to a connection.
//
// ---------------------------------------------------------------------------
// WHY THIS CANNOT BE A gRPC TEST.
//
// Everything here is about the SEAM, and a client on a socket cannot see which
// process answered it. The ways a seam like this breaks are: a field that does
// not survive the channel (and this family's fields are DER BYTES, which is a
// trap the directory's codec never met), a refusal that arrives as the wrong
// gRPC status, a caller whose identity is silently lost so that every call is
// answered as somebody else, and a method dispatched that should never have
// been. Each produces a service that is WRONG in one mode and right in the
// other two.
//
// The end-to-end claim — a real client on a real socket getting a real SVID —
// is `spiffe/CLAUDE.md`'s standing obligation and belongs in the parent suite.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED, AND WHAT DELIBERATELY IS NOT.
//
// It drives `spiffeGrpc.performMethod()` — the function a worker runs — and
// `spiffeGrpc.errorFromResult()`, the front process's half, against the
// handlers those two share. No port, no fork, no container.
//
// **IT DOES NOT ASSERT WHAT A HANDLER ANSWERS.** Whether `BatchCreateEntry`
// creates the right entry is `spiffe_api.js`'s business and the parent suite's;
// what is asserted here is that the ANSWER IS THE SAME through the codec,
// compared against the same handler called directly. That is the only claim
// the seam is responsible for.
// ===========================================================================

const child_process = require('child_process');
const path = require('path');
const fs = require('fs');
const spiffeGrpc = require('../spiffe/spiffe_grpc');
const spiffeServer = require('../spiffe/spiffe_server');
const worker = require('../common/request_worker');

// ---------------------------------------------------------------------------
// A CALL AS THE FRONT PROCESS HANDS ONE OVER. Exactly the two members a
// handler reads — `request` and `spiffeCaller` — which is what
// `performMethod()` builds and is the whole surface counted across both
// handler files.
// ---------------------------------------------------------------------------
function callerLike(fields) {
  return Object.assign({
    surface: 'server',
    transport: 'tcp',
    peer: '127.0.0.1:50051',
    spiffeId: 'spiffe://example.org/agent/probe',
    authenticated: true,
    entities: { local: false, agent: false, admin: true, downstream: false },
    notes: [],
    certificate: null,
    refusal: ''
  }, fields || {});
}

// The round trip: what the worker is sent, THROUGH THE CHANNEL'S OWN CLONE,
// and then run the way a worker runs it.
function dispatched(surface, method, request, caller) {
  // **STRUCTURED CLONE AND NOT `JSON.parse(JSON.stringify(...))`**, which is
  // where this file differs from the directory's and is the point of section 2:
  // the request pool forks with `serialization: 'advanced'` precisely because
  // these messages carry Buffers, and cloning through JSON here would be
  // testing a channel this service does not use.
  const args = structuredClone({ request: request, caller: caller || null });
  return spiffeGrpc.performMethod(surface, method, args);
}

// The same handler called the way the wrapper calls it. This is the CONTROL and
// it does not go near the codec.
function directly(surface, method, request, caller) {
  const handler = spiffeGrpc.localMethod(surface, method);
  return Promise.resolve()
    .then(function () {
      return handler({ request: request, spiffeCaller: caller || null });
    })
    .then(function (reply) { return { ok: true, reply: reply || {} }; },
          function (err) {
            return { ok: false, code: err && err.code, message: err && err.message };
          });
}

// ---------------------------------------------------------------------------
// 1. THE SAME METHOD, BOTH WAYS, COMPARED AS A WHOLE ANSWER.
//
// `Entry.ListEntries` is the probe because it is a READ that answers out of the
// registry with no arguments worth getting wrong — so what is being compared is
// the codec and not a handler's opinion.
//
// **THE METHOD NAME IS SERVICE-QUALIFIED AND THAT IS THE SPIRE SERVER API'S
// OWN SHAPE.** Six gRPC services share one surface there — `Entry`, `Agent`,
// `Bundle`, `SVID`, `TrustDomain`, `Debug` — and two of them would otherwise
// collide (`Bundle.CountBundles` and `Agent.CountAgents` are fine, but
// `GetBundle` exists on two). So a kind is `spiffe.<surface>.<Service>.<Method>`
// and the method half contains a dot, which is why every split below takes the
// REMAINDER rather than the third segment.
// ---------------------------------------------------------------------------
async function checkAMethodAgrees(t) {
  t.log.info('=== a dispatched method gives the same answer ===');

  const caller = callerLike();
  const viaPool = await dispatched('server', 'Entry.ListEntries', {}, caller);
  const control = await directly('server', 'Entry.ListEntries', {}, caller);

  t.check(viaPool.ok === true,
          'the dispatched method succeeded',
          'it answered ' + JSON.stringify(viaPool.message || '(no message)'));
  t.check(control.ok === true,
          'and so does the handler called directly',
          'the control refused, so this section is comparing nothing');
  t.check(JSON.stringify(viaPool.reply) === JSON.stringify(control.reply),
          'and the two answers are identical',
          'through the pool: ' + JSON.stringify(viaPool.reply).slice(0, 300) +
          '\n  directly:  ' + JSON.stringify(control.reply).slice(0, 300));
}

// ---------------------------------------------------------------------------
// 2. A `bytes` FIELD SURVIVES THE REAL CHANNEL AS A BUFFER.
//
// **THIS IS THE ONE THE DIRECTORY'S CODEC NEVER HAD TO FACE.** LDAP attribute
// values are strings; a SPIFFE request and reply carry X509-SVIDs, bundles,
// CSRs and private keys as protobuf `bytes`, which grpc-js gives a handler as a
// Buffer and expects back as one.
//
// The request pool forked with node's DEFAULT JSON serialization until
// 2026-09-12, and JSON does not merely bloat a Buffer — `JSON.stringify` turns
// it into `{"type":"Buffer","data":[…]}`, so it arrives at the far end as a
// PLAIN OBJECT.
//
// **IT FORKS, AND THE FIRST VERSION OF THIS SECTION DID NOT AND WAS WRONG.**
// It modelled the channel with `structuredClone()`, which is the algorithm the
// documentation names — and `structuredClone(Buffer)` gives a **Uint8Array**,
// because the Buffer subclass is not part of that algorithm, while node's IPC
// gives back a real Buffer. So the model was HARSHER than the channel and the
// section failed against a service that was working. A test that models a
// mechanism can only be as right as the model; the mechanism here is one fork
// away, so it is asserted directly.
//
// The default-serialization control beside it is what makes this a comparison
// rather than a restatement of how Buffers work.
// ---------------------------------------------------------------------------
function roundTrip(options) {
  return new Promise(function (resolve, reject) {
    const child = child_process.fork(
      path.join(__dirname, 'tools', 'ipc_echo.js'), [], options);
    const timer = setTimeout(function () {
      child.kill();
      reject(new Error('the echo child did not answer within 10s'));
    }, 10000);
    child.once('message', function (message) {
      clearTimeout(timer);
      child.kill();
      resolve(message);
    });
    child.once('error', function (err) {
      clearTimeout(timer);
      reject(err);
    });
    child.send({ csr: Buffer.from([0x30, 0x82, 0x01, 0xff, 0x00, 0x7f]) });
  });
}

async function checkBytesSurvive(t) {
  t.log.info('=== a bytes field crosses the real channel as a Buffer ===');

  const advanced = await roundTrip({ serialization: 'advanced',
                                     stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  t.check(advanced.sawBuffer === true,
          'the child of an advanced-serialization fork sees a Buffer (' +
          advanced.sawType + ')',
          'it saw ' + advanced.sawType + ' — grpc-js would be handed a ' +
          'non-Buffer for a bytes field, and the failure would land inside ' +
          'protobuf serialization one process away from the cause');
  t.check(advanced.sameBytes === true,
          'and the same bytes',
          'the bytes changed across the channel');

  // THE CONTROL: the channel this replaced. Without it the assertion above is
  // a statement about node rather than about a decision this repository made.
  const plain = await roundTrip({ stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  t.check(plain.sawBuffer === false,
          'and the default JSON channel did NOT (' + plain.sawType + ')',
          'JSON preserved the Buffer, so the serialization change this ' +
          'section exists for was unnecessary and its reasoning is wrong');

  // AND THE FORK REALLY ASKS FOR IT. A comment saying "advanced" and a fork
  // without the option is exactly the shape of drift nothing else here checks.
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'common', 'request_pool.js'), 'utf8');
  t.check(/serialization:\s*'advanced'/.test(source),
          'and the request pool forks its workers asking for it',
          'common/request_pool.js does not pass serialization: advanced, so ' +
          'every bytes field in this family would arrive as a plain object');
}

// ---------------------------------------------------------------------------
// 3. A REFUSAL CROSSES AS ITS gRPC STATUS CODE.
//
// A status here is an `Error` carrying a NUMERIC code, and the number IS the
// protocol — which is why this family needs no name table where the directory's
// codec needed one. What a client acts on is the code: `PERMISSION_DENIED` and
// `INVALID_ARGUMENT` are different instructions, and a codec that flattened
// every refusal to one of them would change every negative path in every client
// while a success test went on passing.
// ---------------------------------------------------------------------------
function checkARefusalKeepsItsStatus(t) {
  t.log.info('=== a refusal crosses as its own gRPC status ===');

  const codes = [
    ['INVALID_ARGUMENT', spiffeGrpc.invalidArgument('no audience')],
    ['NOT_FOUND', spiffeGrpc.notFound('no such entry')],
    ['PERMISSION_DENIED', spiffeGrpc.permissionDenied('not an admin')],
    ['UNAVAILABLE', spiffeGrpc.unavailable('SPIFFE is off')]
  ];
  codes.forEach(function (pair) {
    const original = pair[1];
    const crossed = structuredClone({ ok: false, code: original.code,
                                      message: original.message, stack: '' });
    const rebuilt = spiffeGrpc.errorFromResult(crossed);
    t.check(rebuilt.code === original.code,
            pair[0] + ' rebuilds with the same status code (' + rebuilt.code + ')',
            'the client would be told ' + rebuilt.code + ' where the front ' +
            'process tells it ' + original.code);
    t.check(rebuilt.message === original.message,
            'and the same message',
            JSON.stringify(rebuilt.message));
  });
}

// ---------------------------------------------------------------------------
// 4. A THROW THAT IS NOT A STATUS STAYS ONE.
//
// `errorToStatus()` logs a non-status throw as a defect in this service and
// answers UNKNOWN. That decision has to survive the crossing, or a handler bug
// in a worker would be reported to the client as some plausible status and
// logged nowhere as the defect it is.
// ---------------------------------------------------------------------------
function checkANonStatusThrowIsStillOne(t) {
  t.log.info('=== a throw that is not a status does not acquire one ===');

  const crossed = structuredClone({ ok: false, code: null,
                                    message: 'x is not a function',
                                    stack: 'Error: x is not a function\n    at y' });
  const rebuilt = spiffeGrpc.errorFromResult(crossed);
  t.check(typeof rebuilt.code !== 'number',
          'it is rebuilt with NO status code, so errorToStatus() calls it a ' +
          'defect',
          'it came back carrying code ' + rebuilt.code + ', which would be ' +
          'reported to the client as a real status and logged as nothing');
  t.check(rebuilt.message.indexOf('x is not a function') >= 0,
          'and keeps what went wrong',
          JSON.stringify(rebuilt.message));
  t.check(String(rebuilt.stack || '').indexOf('at y') >= 0,
          'and the worker\'s stack, which is the only copy there is',
          'the stack was lost, so the defect is reported with no place in it');
}

// ---------------------------------------------------------------------------
// 5. THE CALLER CROSSES, WHICH IS THE ONE THING A WORKER CANNOT DERIVE.
//
// `prepareCall()` reads the transport, the peer address, the peer certificate
// and the socket's peer credentials — all properties of a connection the front
// process accepted. Four of the forty-two handlers read `call.spiffeCaller`,
// and on the SPIRE Server API what it decides is whose agent is being renewed
// and what an entry is created as. A codec that dropped it would answer every
// call as nobody.
// ---------------------------------------------------------------------------
function checkTheCallerCrosses(t) {
  t.log.info('=== the caller travels with the method ===');

  const caller = callerLike({
    spiffeId: 'spiffe://example.org/agent/probe-7',
    transport: 'uds',
    entities: { local: true, agent: true, admin: false, downstream: false },
    certificate: { subject: 'CN=probe', issuer: 'CN=issuer',
                   serialNumber: '01', validFrom: '', validTo: '' }
  });
  // **BUILT BY THE CODEC AND NOT BY THIS FILE**, which is the correction a
  // surviving mutant forced: the first version cloned a shape it had written
  // itself, so `methodRequest()` sending `caller: null` passed every assertion
  // below. What is under test is what the front process SENDS.
  const crossed = structuredClone(
    spiffeGrpc.methodRequest({ request: {}, spiffeCaller: caller }));

  t.check(crossed.caller !== null && crossed.caller !== undefined,
          'the codec puts a caller on what the worker is sent at all',
          'methodRequest() sent ' + JSON.stringify(crossed.caller) + ', so ' +
          'every dispatched call would be answered as nobody — and on the ' +
          'SPIRE Server API that decides whose agent is renewed');

  t.check(crossed.caller.spiffeId === caller.spiffeId,
          'the caller\'s SPIFFE ID is on what the worker is sent',
          'it came across as ' + JSON.stringify(crossed.caller.spiffeId));
  t.check(crossed.caller.transport === 'uds' &&
          crossed.caller.entities.agent === true &&
          crossed.caller.entities.local === true,
          'with the transport and the entity flags SPIRE\'s table decides on',
          'entities came across as ' + JSON.stringify(crossed.caller.entities));
  t.check(crossed.caller.certificate &&
          crossed.caller.certificate.subject === 'CN=probe',
          'and the certificate facts, already rendered to strings',
          'the DN came across as ' +
          JSON.stringify(crossed.caller.certificate &&
                         crossed.caller.certificate.subject) +
          ' — callerOf() renders both DNs with dnRfc4514() precisely so that ' +
          'nothing downstream meets node\'s null-prototype name objects');
}

// ---------------------------------------------------------------------------
// 6. THE UNARY METHODS ARE DISPATCHABLE AND THE STREAMS ARE NOT.
//
// Two halves of one rule, and the second is the one worth a test. A server
// stream here is a SUBSCRIPTION held open for the life of the process and fed
// by a rotation timer — `spiffe_grpc.js`'s `serverStream()` argues it — so
// moving one would put a live subscription in a process whose death silently
// turns it into one that never updates again, while a client goes on holding an
// SVID it believes is being renewed.
//
// The first half is the drift check: a method added and never registered goes
// on running in the front process with nothing anywhere reporting it.
// ---------------------------------------------------------------------------
function checkTheMethodTableAgrees(t) {
  t.log.info('=== the dispatchable methods are the unary ones ===');

  // PROBE METHODS ARE NOT METHODS. See the note above run(): four sections
  // register one, and this file must count the service's own either way round.
  const kinds = spiffeGrpc.dispatchedMethodKinds().filter(function (k) {
    return k.indexOf('.Probe') < 0;
  });
  const workload = kinds.filter(function (k) {
    return k.indexOf('spiffe.workload.') === 0;
  }).map(function (k) { return k.slice('spiffe.workload.'.length); });

  t.check(kinds.length > 0, 'methods are registered (' + kinds.length + ')',
          'nothing is registered, so every check below passes by having ' +
          'nothing to check');

  // THE FIVE STREAMS, BY NAME. Read off the loaded protos rather than written
  // down, so a method that becomes a stream — or stops being one — is caught
  // here rather than by a client that hangs.
  const streaming = spiffeGrpc.methodsOf('workload')
    .filter(function (m) { return m.responseStream; })
    .map(function (m) { return m.name; });
  t.check(streaming.length === 5,
          'the Workload API has five server streams (' + streaming.join(', ') + ')',
          'it has ' + streaming.length + ' — the argument for excluding them ' +
          'is about streams, so the count changing means re-reading it');
  const leaked = streaming.filter(function (name) {
    return kinds.indexOf('spiffe.workload.' + name) >= 0;
  });
  t.check(leaked.length === 0,
          'and NOT ONE of them is dispatchable',
          leaked.join(', ') + ' is registered as an operation. A stream is a ' +
          'subscription fed by a rotation timer and its socket is the front ' +
          'process\'s; a worker holding one dies silently into a client that ' +
          'thinks its SVID is being renewed');

  t.check(workload.sort().join(',') === 'FetchJWTSVID,ValidateJWTSVID',
          'the two unary Workload API methods are (' + workload.join(', ') + ')',
          'got ' + JSON.stringify(workload));

  const serverKinds = kinds.filter(function (k) {
    return k.indexOf('spiffe.server.') === 0;
  });
  t.check(serverKinds.length === 40,
          'and all forty of the SPIRE Server API\'s are (' +
          serverKinds.length + ')',
          'got ' + serverKinds.length + '. Every method on that surface is ' +
          'unary, so a number below forty is a method that quietly stopped ' +
          'being dispatched');

  // EVERY REGISTERED KIND HAS A HANDLER BEHIND IT.
  const unbacked = kinds.filter(function (k) {
    // THE REMAINDER, NOT THE THIRD SEGMENT — see the note in section 1: a
    // SPIRE Server API method is `Service.Method` and splitting on the first
    // dot after the surface would look up `Agent` and find nothing.
    const parts = k.split('.');
    const surface = parts[1];
    const method = parts.slice(2).join('.');
    return typeof spiffeGrpc.localMethod(surface, method) !== 'function';
  });
  t.check(unbacked.length === 0,
          'and each has its handler captured',
          'no handler for: ' + unbacked.join(', '));
}

// ---------------------------------------------------------------------------
// 7. THE WORKER TABLE IS FILLED IN A WORKER AND NOWHERE ELSE.
//
// **THIS SECTION EXISTS BECAUSE THE FIRST VERSION REGISTERED UNCONDITIONALLY
// AND COST `tests/spiffe_pki.js`.** Requiring `common/request_worker.js` pulls
// `common/service_state.js` in at module scope — the store, the keys, the
// minted rows, coordination — and `run.js` runs every file in ONE process, so
// doing it at a new point in the load order changed what a later file saw of
// the certificate hierarchy. That file passed alone and failed in the suite,
// which is the shape of flake that gets a test deleted rather than fixed.
//
// So both halves are asserted: a front process registers NOTHING, and a worker
// registers everything in the table.
// ---------------------------------------------------------------------------
function checkRegistrationIsAWorkerThing(t) {
  t.log.info('=== only a request worker fills the worker table ===');

  const spiffeKinds = function (withProbes) {
    return Array.from(worker.OPERATIONS.keys()).filter(function (k) {
      return k.indexOf('spiffe.') === 0 &&
             (withProbes || k.indexOf('.Probe') < 0);
    });
  };

  t.check(spiffeKinds().length === 0,
          'this process is not a worker, so nothing is registered',
          spiffeKinds().length + ' kind(s) are registered in a process that ' +
          'will never answer one — which is a table nothing reads bought with ' +
          'a load of service_state.js at a new point in the order');

  const hadMarker = process.env.STS_REQUEST_WORKER;
  let registered = [];
  try {
    process.env.STS_REQUEST_WORKER = '1';
    // The registration runs as each method is WRAPPED, so it is re-driven the
    // way it happens: hand the wrapper a handler and watch the table fill.
    spiffeGrpc.unary('server', 'ProbeMethodForTheTable', function () {
      return { probed: true };
    });
    registered = spiffeKinds(true);
  } finally {
    if (hadMarker === undefined) {
      delete process.env.STS_REQUEST_WORKER;
    } else {
      process.env.STS_REQUEST_WORKER = hadMarker;
    }
  }

  t.check(registered.indexOf('spiffe.server.ProbeMethodForTheTable') >= 0,
          'and a worker registers what it wraps',
          'the table holds ' + JSON.stringify(registered) + ' — with the ' +
          'marker set, wrapping a method must reach request_worker.register()');
}

// ---------------------------------------------------------------------------
// 3b. AND THE WORKER'S HALF OF THAT, DRIVEN THROUGH A REAL THROW.
//
// Section 3 hands `errorFromResult()` a result it built itself, which asserts
// the REBUILD and not the crossing. A mutant that dropped the status code
// inside `performMethod()` — so every refusal arrived as a defect — survived
// it. So this drives the function a worker actually runs, with a handler that
// throws the way forty-two of them do.
// ---------------------------------------------------------------------------
async function checkTheWorkerCarriesTheStatus(t) {
  t.log.info('=== the worker half carries the status of a real throw ===');

  const hadMarker = process.env.STS_REQUEST_WORKER;
  try {
    process.env.STS_REQUEST_WORKER = '1';
    spiffeGrpc.unary('server', 'ProbeThatRefuses', function () {
      throw spiffeGrpc.permissionDenied('not an admin');
    });
    spiffeGrpc.unary('server', 'ProbeThatBreaks', function () {
      throw new TypeError('x is not a function');
    });
  } finally {
    if (hadMarker === undefined) {
      delete process.env.STS_REQUEST_WORKER;
    } else {
      process.env.STS_REQUEST_WORKER = hadMarker;
    }
  }

  const refused = await spiffeGrpc.performMethod('server', 'ProbeThatRefuses',
                                                 { request: {}, caller: null });
  t.check(refused.ok === false,
          'a handler that throws a status is reported as a refusal',
          'it answered ok=' + refused.ok);
  t.check(refused.code === spiffeGrpc.grpc.status.PERMISSION_DENIED,
          'carrying that status code (' + refused.code + ')',
          'the code came back as ' + JSON.stringify(refused.code) + ' — a ' +
          'refusal that loses it is reported to the client as a defect in ' +
          'this service and logged as one');
  t.check(String(refused.message).indexOf('not an admin') >= 0,
          'and the sentence the caller can act on',
          JSON.stringify(refused.message));

  const broke = await spiffeGrpc.performMethod('server', 'ProbeThatBreaks',
                                               { request: {}, caller: null });
  t.check(broke.ok === false && broke.code === null,
          'and a handler that throws something else carries NO code',
          'it came back with code ' + JSON.stringify(broke.code) + ', which ' +
          'would turn a defect in this service into a status a client acts on');
}

// ---------------------------------------------------------------------------
// 5b. THE CALLER REACHES THE HANDLER, which is the other end of section 5.
//
// That one asserts what is SENT; this asserts that a worker puts it back on
// the object a handler reads, because `performMethod()` builds that object
// itself and four of the forty-two handlers look at it.
// ---------------------------------------------------------------------------
async function checkTheHandlerSeesTheCaller(t) {
  t.log.info('=== the worker rebuilds the call a handler reads ===');

  const hadMarker = process.env.STS_REQUEST_WORKER;
  try {
    process.env.STS_REQUEST_WORKER = '1';
    spiffeGrpc.unary('server', 'ProbeThatEchoes', function (call) {
      return { saw: (call.spiffeCaller && call.spiffeCaller.spiffeId) || '',
               req: (call.request && call.request.marker) || '' };
    });
  } finally {
    if (hadMarker === undefined) {
      delete process.env.STS_REQUEST_WORKER;
    } else {
      process.env.STS_REQUEST_WORKER = hadMarker;
    }
  }

  const caller = callerLike({ spiffeId: 'spiffe://example.org/agent/echo' });
  const answer = await spiffeGrpc.performMethod('server', 'ProbeThatEchoes', {
    request: { marker: 'here' }, caller: caller
  });
  t.check(answer.ok === true && answer.reply.saw === caller.spiffeId,
          'the handler reads the caller off call.spiffeCaller',
          'it saw ' + JSON.stringify(answer.reply && answer.reply.saw));
  t.check(answer.ok === true && answer.reply.req === 'here',
          'and the request off call.request',
          'it saw ' + JSON.stringify(answer.reply && answer.reply.req));
}

// ---------------------------------------------------------------------------
// THE ORDER IS A CONSTRAINT AND NOT A PREFERENCE.
//
// Four sections below REGISTER a probe method, because the only honest way to
// drive `performMethod()`'s error path and `unary()`'s registration is to give
// them a handler. `LOCAL_METHODS` and the worker's table are module-wide, so
// every probe is permanent for the life of the process — which means the two
// sections that COUNT what is registered have to run before any of them.
//
// They also ignore anything named `Probe*`, which is belt and braces on
// purpose: ordering alone is one edit away from being wrong, and the failure
// it produces is an assertion about forty methods going red because somebody
// added a forty-third that is not a method at all.
// ---------------------------------------------------------------------------
async function run(t) {
  checkTheMethodTableAgrees(t);
  checkRegistrationIsAWorkerThing(t);
  await checkAMethodAgrees(t);
  await checkBytesSurvive(t);
  checkARefusalKeepsItsStatus(t);
  await checkTheWorkerCarriesTheStatus(t);
  checkANonStatusThrowIsStillOne(t);
  checkTheCallerCrosses(t);
  await checkTheHandlerSeesTheCaller(t);
}

module.exports = {
  name: 'spiffe_operations',
  describe: 'the two gRPC surfaces as operations: what crosses to a request ' +
            'worker, that a dispatched method is the same answer, that a bytes ' +
            'field survives the channel, and that the streams stay put',
  run: run
};
