// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kdc_broker_operations.js
//
// ===========================================================================
// PORT 88 AND THE BROKER API'S FetchJWTSVID, ANSWERED IN A REQUEST WORKER
// (2026-10-07, rcbj's decision).
//
// Two suite failures were races between the front process and a request
// worker: a KDC sign-in written in the front was not yet seen by a worker
// answering a global logout (`sts_kerberos_signout`, STS-LOGOUT-0007), and a
// registration entry written by a worker was not yet seen by the Broker API
// answering in the front (`sts_spiffe_broker`, STS-SPIFFE-0138). Both now run
// their work in a worker through the request pool's OPERATION channel —
// `krb5.message` (`kerberos/krb5_kdc.js`) and `spiffe.broker.FetchJWTSVID`
// (`spiffe/spiffe_broker.ts`) — whose `runOperation()` puts it behind the read
// barrier, so the existing barrier orders the write and the read.
//
// What a client on a socket cannot see, and so what is asserted here:
//
//   1. a KDC message crosses the REAL pool to a stub worker thread and back:
//      the worker sees a Buffer, the client's address, transport and port,
//      and the reply arrives as a Buffer, byte for byte, with the REFUSAL the
//      worker's reply carried put back under its Symbol;
//   2. NOT DISPATCHED is answered in the front process — `krb5` not named in
//      `workers.dispatch` with a worker ready, and no pool at all;
//   3. A WORKER THAT FAILS is KDC_ERR_SVC_UNAVAILABLE (29) with STS-KRB-0204
//      and is NOT answered again here — a worker thread that dies holding the
//      message — and a worker answering no bytes is 29 with STS-KRB-0205;
//   4. the worker's half, the real `handleMessage()`: the table is filled
//      only in a worker and only once, and a whole AS exchange run through
//      the table function — arguments and answers cloned and revived as the
//      channel does — issues a TGT and writes the `authentication` row naming
//      the address the socket saw;
//   5. a worker does not wait for workers: `catchUpWithWorkers()` asks the
//      pool's commit barrier in the front process and not in a worker;
//   6. the Broker API's half: FetchJWTSVID's entitlement and minting through
//      the pool to a worker-side instance — the attested caller, audiences,
//      SPIFFE ID, realm and address reach it, the SVIDs come back, a workload
//      with no entry is WORKLOAD_NOT_ENTITLED with its ErrorInfo built in the
//      front, a status refusal keeps its code, a failed worker is
//      UNAVAILABLE with STS-SPIFFE-0145, not dispatched answers in place, the
//      table is filled only in a worker, and `referenced()` no longer waits
//      for the workers (only SubscribeToX509SVID does).
//
// WHY IN PROCESS: every claim is about which process does what, which no
// endpoint reports. The end-to-end halves are `sts_kerberos_signout` and
// `sts_spiffe_broker`.
//
// MUTANTS (2026-10-07), each made in the source, seen red, and restored:
//   M1  performMessage() without audit.withSource()       — 4 (the row's
//       address)
//   M2  replyFromResult() not putting the refusal back     — 1
//   M3  a rejected operation answered by handleMessage()   — 3 (0048, not 0204)
//   M4  `!answer.dispatched` fallback removed              — 2
//   M5  registerWorkerOperation() without its worker gate  — 4
//   M6  messageRequest() dropping the address              — 1
//   M7  catchUpWithWorkers() without the worker early exit — 5
//   M8  issueForReference() without realms.run()          — 6 (the realm)
//   M9  dispatchFetchJwt() retrying in place on a reject   — 6 (UNAVAILABLE)
//   M10 referenced() calling catchUpWithWorkers() again    — 6
//   M11 fetchJwtRequest() dropping the caller              — 6 (selectors)
//   M12 SpiffeBroker.registerWorkerOperation() ungated     — 6
//   M13 issueForReference() without audit.withSource()     — 6 (the address)
// M8 SURVIVED THE FIRST ROUND AND IT WAS THE FIXTURE, this directory's
// standing lesson: the stub pool ran the worker half inside the front's own
// realm and audit source, which AsyncLocalStorage carried in, so a worker
// that never entered the realm it was sent still answered in it. The stub
// now runs it in the default realm with no source, as a worker thread is.
//
// ORDER AND STATE: sections 4 and 6 put a kind in `request_worker.ts`'s
// module-wide table to prove the gate, and take it out again at once —
// `spiffe_operations.js` asserts that a front process's table holds no
// `spiffe.` kind, and `run.js` runs every file in one process. Sections 1 to
// 3 start and stop a stub pool of their own and `reset()` it after.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const os = require('os');
const fs = require('fs');
const path = require('path');

const config = require('../common/config');
const realms = require('../common/realms');
const audit = require('../common/audit');
const errorCodes = require('../common/error_codes');
const requestPool = require('../common/request_pool');
const worker = require('../common/request_worker');
const WorkerChannel = require('../common/worker_channel');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const wire = require('./vendored/krb5_wire.js');
const rpc = require('../spiffe/spiffe_grpc');
const broker = require('../spiffe/spiffe_broker');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'kdc_broker_operations',
  level: process.env.LOG_LEVEL || 'info' });

const CLIENT = '203.0.113.7';
// A byte no Kerberos message starts with: the stub thread dies on it, and
// answers no reply on the other.
const DIE = 0xee;
const EMPTY = 0xef;

// Sets `vars` for the length of `fn` and puts them back, whatever happens.
async function withVars(vars, fn) {
  log.debug("Entering withVars().");
  const had = {};
  Object.keys(vars).forEach(function (name) {
    had[name] = process.env[name];
    if (vars[name] === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = vars[name];
    }
  });
  try {
    return await fn();
  } finally {
    Object.keys(had).forEach(function (name) {
      if (had[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = had[name];
      }
    });
    log.debug("Leaving withVars().");
  }
}

// What the channel does to a value: a structured clone, then the revival both
// ends of `worker_channel.ts` apply.
function overTheChannel(value) {
  log.debug("Entering overTheChannel().");
  log.debug("Leaving overTheChannel().");
  return WorkerChannel.revive(structuredClone(value));
}

// The KRB-ERROR code a reply carries, or null for something else.
function krbErrorCode(reply) {
  log.debug("Entering krbErrorCode().");
  try {
    const read = wire.msgs.readKdcResponse(Buffer.from(reply));
    log.debug("Leaving krbErrorCode().");
    return read.kind === 'KRB-ERROR' ? read.error.errorCode : null;
  } catch (e) {
    log.debug("Caught in krbErrorCode(): " + ((e && e.message) || e));
    log.debug("Leaving krbErrorCode().");
    return null;
  }
}

function refusalCode(reply) {
  log.debug("Entering refusalCode().");
  const refusal = kdc.refusalOf(reply);
  log.debug("Leaving refusalCode().");
  return refusal ? refusal.code : null;
}

// ---------------------------------------------------------------------------
// A STUB WORKER THREAD over the real channel (`spiffe_operations.js`'s
// arrangement): `begin` in, `ready` out. A `krb5.message` is answered with
// a reply whose bytes are the JSON of what the stub SAW — so the front's
// reply carries the worker's view back through the same channel — and a
// refusal object; a message starting DIE kills the thread, and one starting
// EMPTY is answered with no reply.
// ---------------------------------------------------------------------------
function stubSource() {
  log.debug("Entering stubSource().");
  log.debug("Leaving stubSource().");
  return [
    "'use strict';",
    "const http = require('http');",
    "const WorkerChannel = require(" + JSON.stringify(
      path.join(__dirname, '..', 'common', 'worker_channel')) + ");",
    "WorkerChannel.on(function (m) {",
    "  if (m && m.stop) { process.exit(0); }",
    "  if (m && m.operation) {",
    "    const a = m.args || {};",
    "    const b = a.bytes;",
    "    if (b && b[0] === " + DIE + ") { process.exit(3); }",
    "    if (b && b[0] === " + EMPTY + ") {",
    "      WorkerChannel.send({ operation: true, id: m.id, ok: true,",
    "        ran: true, result: {} });",
    "      return;",
    "    }",
    "    const saw = { kind: m.kind, isBuffer: Buffer.isBuffer(b),",
    "      hex: b ? Buffer.from(b).toString('hex') : '',",
    "      address: a.address, transport: a.transport, port: a.port };",
    "    WorkerChannel.send({ operation: true, id: m.id, ok: true,",
    "      ran: true, result: { reply: Buffer.from(JSON.stringify(saw)),",
    "        refusal: { code: 'STS-KRB-0047', krbError: 'probe',",
    "                   actor: '', target: '' } } });",
    "    return;",
    "  }",
    "  if (!m || !m.begin) { return; }",
    "  const server = http.createServer(function (req, res) {",
    "    res.end('');",
    "  });",
    "  server.listen(m.socket, function () {",
    "    WorkerChannel.send({ ready: true });",
    "  });",
    "});",
    ""
  ].join('\n');
}

// Runs `fn` with ONE stub worker thread in the protocol pool and `dispatch`
// as `workers.dispatch`, read-your-write off: what is asserted is the
// channel and the fallbacks, not the ticket machinery.
async function withStubPool(dispatch, fn) {
  log.debug("Entering withStubPool().");
  const stubPath = path.join(os.tmpdir(), 'sts-stub-krb5-op-' + process.pid +
                             '.js');
  fs.writeFileSync(stubPath, stubSource());
  try {
    return await withVars({ STS_WORKERS_REQUEST_COUNT: '1',
                            STS_WORKERS_DISPATCH: dispatch,
                            STS_WORKERS_READ_YOUR_WRITE: 'false' },
                          async function () {
      requestPool.reset();
      requestPool.useWorkerModule(stubPath);
      try {
        const entry = requestPool.fork(requestPool.PROTOCOL_POOL, 0);
        await entry.settled;
        return await fn(entry);
      } finally {
        await requestPool.stop(3000);
        requestPool.reset();
      }
    });
  } finally {
    try {
      fs.unlinkSync(stubPath);
    } catch (e) {
      log.debug("Caught in withStubPool(): " + ((e && e.message) || e));
    }
    log.debug("Leaving withStubPool().");
  }
}

// ---------------------------------------------------------------------------
// 1. A KDC MESSAGE THROUGH THE REAL POOL, AND BACK.
// ---------------------------------------------------------------------------
async function checkDispatched(t) {
  log.debug("Entering checkDispatched().");
  t.log.info('=== a port-88 message crosses the real pool and back ===');
  const message = Buffer.from([0x6a, 0x03, 0x02, 0x01, 0x05]);
  await withStubPool('krb5', async function (entry) {
    t.check(entry.ready, '1a. a stub worker thread comes up', '');
    const reply = await kdc.answerSocketMessage(message, 'udp', CLIENT, 5353);
    let saw = {};
    try {
      saw = JSON.parse(Buffer.from(reply).toString('utf8'));
    } catch (e) {
      log.debug("Caught in checkDispatched(): " + ((e && e.message) || e));
    }
    t.check(Buffer.isBuffer(reply) && saw.kind === kdc.MESSAGE_OPERATION,
            '1b. the reply is the worker\'s, as a Buffer, for the ' +
            'krb5.message operation', JSON.stringify(saw));
    t.check(saw.isBuffer === true && saw.hex === message.toString('hex'),
            '1c. the worker saw the request as a Buffer, byte for byte',
            JSON.stringify(saw));
    t.check(saw.address === CLIENT && saw.transport === 'udp' &&
            saw.port === 5353,
            '1d. and the client\'s address, transport and port',
            JSON.stringify(saw));
    t.equal(refusalCode(reply), 'STS-KRB-0047',
            '1e. the worker\'s refusal is back on the reply, for ' +
            'recordRawRefusal()');
  });
  log.debug("Leaving checkDispatched().");
}

// ---------------------------------------------------------------------------
// 2. NOT DISPATCHED IS ANSWERED HERE.
// ---------------------------------------------------------------------------
async function checkNotDispatched(t) {
  log.debug("Entering checkNotDispatched().");
  t.log.info('=== not dispatched: answered in the front process ===');
  // Not a request a KDC answers: KRB_ERR_GENERIC, STS-KRB-0048, wherever
  // handleMessage() runs — and never the stub's JSON.
  const garbage = Buffer.from([0x30, 0x00]);
  await withStubPool('ldap', async function (entry) {
    t.check(entry.ready, '2a. a worker is ready, and krb5 is not named', '');
    const reply = await kdc.answerSocketMessage(garbage, 'tcp', CLIENT, 1);
    t.check(krbErrorCode(reply) === 60 &&
            refusalCode(reply) === 'STS-KRB-0048',
            '2b. so the message is answered here, by handleMessage()',
            Buffer.from(reply).toString('hex').slice(0, 80));
  });
  await withVars({ STS_WORKERS_REQUEST_COUNT: '0',
                   STS_WORKERS_DISPATCH: '*' }, async function () {
    requestPool.reset();
    const reply = await kdc.answerSocketMessage(garbage, 'udp', CLIENT, 2);
    t.check(krbErrorCode(reply) === 60 &&
            refusalCode(reply) === 'STS-KRB-0048',
            '2c. and with no pool at all, the same',
            Buffer.from(reply).toString('hex').slice(0, 80));
  });
  log.debug("Leaving checkNotDispatched().");
}

// ---------------------------------------------------------------------------
// 3. A WORKER THAT FAILS IS NOT RETRIED HERE.
// ---------------------------------------------------------------------------
async function checkWorkerFailure(t) {
  log.debug("Entering checkWorkerFailure().");
  t.log.info('=== a failed worker: KDC_ERR_SVC_UNAVAILABLE ===');
  await withStubPool('krb5', async function () {
    const reply = await kdc.answerSocketMessage(Buffer.from([DIE, 0x00]),
                                                'tcp', CLIENT, 3);
    t.check(krbErrorCode(reply) === 29 &&
            refusalCode(reply) === 'STS-KRB-0204',
            '3a. a worker that dies holding the message: 29, STS-KRB-0204, ' +
            'and not answered again here',
            'error ' + krbErrorCode(reply) + ', ' + refusalCode(reply));
  });
  await withStubPool('krb5', async function () {
    const reply = await kdc.answerSocketMessage(Buffer.from([EMPTY, 0x00]),
                                                'udp', CLIENT, 4);
    t.check(krbErrorCode(reply) === 29 &&
            refusalCode(reply) === 'STS-KRB-0205',
            '3b. a worker answering no reply bytes: 29, STS-KRB-0205',
            'error ' + krbErrorCode(reply) + ', ' + refusalCode(reply));
  });
  log.debug("Leaving checkWorkerFailure().");
}

// ---------------------------------------------------------------------------
// 4. THE WORKER'S HALF: THE TABLE, AND A WHOLE AS EXCHANGE THROUGH IT.
// ---------------------------------------------------------------------------
async function checkWorkerHalf(t) {
  log.debug("Entering checkWorkerHalf().");
  t.log.info('=== the worker half: the table and a real AS exchange ===');
  const kind = kdc.MESSAGE_OPERATION;
  const outside = await withVars({ STS_REQUEST_WORKER: undefined },
                                 async function () {
    return kdc.registerWorkerOperation();
  });
  t.check(outside === false && !worker.OPERATIONS.has(kind),
          '4a. outside a worker the table is not filled',
          'registered: ' + outside);
  const inside = await withVars({ STS_REQUEST_WORKER: '1' },
                                async function () {
    return [kdc.registerWorkerOperation(), kdc.registerWorkerOperation()];
  });
  t.check(inside[0] === true && inside[1] === false &&
          worker.OPERATIONS.get(kind) === kdc.performMessage,
          '4b. in a worker it is, once, with performMessage()',
          JSON.stringify(inside));
  const fn = worker.OPERATIONS.get(kind) || kdc.performMessage;
  // Out of the shared table again before anything else can read it: this
  // process is not a worker (`spiffe_operations.js`'s rule, below).
  worker.OPERATIONS.delete(kind);
  const name = 'kdcop' + Date.now().toString(36);
  const transport = {
    label: 'the worker table',
    send: async function (bytes) {
      log.debug("Entering send().");
      const answer = overTheChannel(await fn(overTheChannel(
        kdc.messageRequest(bytes, 'tcp', CLIENT, 4242))));
      log.debug("Leaving send().");
      return Buffer.from(answer.reply);
    }
  };
  const r = await wire.asExchange(transport, principals.REALM, name,
    { password: String(config.value('krb5.userPassword')) });
  t.check(!!r.tgt, '4c. an AS exchange through the table issues a TGT',
          JSON.stringify(r.second || r.first));
  const rows = audit.list().filter(function (row) {
    return row.action === 'authentication' &&
           String(row.actor || '').indexOf(name) === 0;
  });
  t.check(rows.length > 0 && rows.every(function (row) {
    return row.address === CLIENT;
  }), '4d. and its authentication row names the address the socket saw',
          JSON.stringify(rows.map(function (row) {
            return { actor: row.actor, address: row.address };
          })));
  log.debug("Leaving checkWorkerHalf().");
}

// ---------------------------------------------------------------------------
// 5. A WORKER DOES NOT WAIT FOR WORKERS.
// ---------------------------------------------------------------------------
async function checkNoCatchUpInWorker(t) {
  log.debug("Entering checkNoCatchUpInWorker().");
  t.log.info('=== catchUpWithWorkers(): the front waits, a worker not ===');
  const original = requestPool.awaitCommitConfirmations;
  let asked = 0;
  requestPool.awaitCommitConfirmations = function () {
    asked++;
    return Promise.resolve();
  };
  const transport = {
    label: 'handleMessage()',
    send: async function (bytes) {
      log.debug("Entering send().");
      const reply = await kdc.handleMessage(Buffer.from(bytes));
      log.debug("Leaving send().");
      return Buffer.from(reply);
    }
  };
  const name = 'kdcwait' + Date.now().toString(36);
  try {
    const counts = {};
    await withVars({ STS_WORKERS_REQUEST_COUNT: '1',
                     STS_WORKERS_READ_YOUR_WRITE: 'true' }, async function () {
      await withVars({ STS_REQUEST_WORKER: undefined }, async function () {
        asked = 0;
        await wire.asExchange(transport, principals.REALM, name,
          { password: String(config.value('krb5.userPassword')) });
        counts.front = asked;
      });
      await withVars({ STS_REQUEST_WORKER: '1' }, async function () {
        asked = 0;
        await wire.asExchange(transport, principals.REALM, name,
          { password: String(config.value('krb5.userPassword')) });
        counts.worker = asked;
      });
    });
    t.check(counts.front > 0,
            '5a. the CONTROL: the front process asks the commit barrier',
            JSON.stringify(counts));
    t.equal(counts.worker, 0,
            '5b. a worker does not: the pool\'s barrier brought it there');
  } finally {
    requestPool.awaitCommitConfirmations = original;
    log.debug("Leaving checkNoCatchUpInWorker().");
  }
}

// ---------------------------------------------------------------------------
// 6. THE BROKER API'S FetchJWTSVID, ITS SECOND HALF IN A WORKER.
// ---------------------------------------------------------------------------
const PID_REF_CALLER = { brokered: true, brokerId: 'spiffe://b.test/broker',
                         selectors: [{ type: 'unix', value: 'uid:1000' }] };

// A worker-side instance: the real realms and audit, a stub workload and CA
// that say what they saw.
function workerSide(seen, opts) {
  log.debug("Entering workerSide().");
  const o = opts || {};
  const deps = broker.SpiffeBroker.defaultDeps(function () {
    return null;
  });
  deps.ca = { ready: function () { return Promise.resolve(); } };
  deps.workload = {
    entitledEntries: function (caller) {
      seen.caller = caller;
      seen.realm = realms.currentId();
      seen.address = audit.currentAddress();
      return o.entries || [];
    },
    issueJwtSvids: async function (entries, audiences) {
      seen.audiences = audiences;
      if (o.refuse) {
        throw rpc.statusError(rpc.status.FAILED_PRECONDITION, 'probe refusal');
      }
      return entries.map(function (entry) {
        return { spiffe_id: entry.spiffeId, svid: 'jwt.' + entry.spiffeId,
                 hint: entry.hint || '' };
      });
    }
  };
  log.debug("Leaving workerSide().");
  return new broker.SpiffeBroker(deps);
}

// A front-side instance whose pool hands the operation, over the channel's
// clone, to `target` — or does what `behaviour` says.
function frontSide(target, behaviour) {
  log.debug("Entering frontSide().");
  const deps = broker.SpiffeBroker.defaultDeps(function () {
    return null;
  });
  const pool = {
    sent: [],
    runOperation: async function (kind, args) {
      pool.sent.push(kind);
      if (behaviour === 'reject') {
        throw new Error('the worker went away');
      }
      if (behaviour === 'none') {
        return { dispatched: false };
      }
      // OUTSIDE THE FRONT'S REALM AND AUDIT SOURCE, as a worker thread is:
      // the stub runs inside the caller's async context, so without this the
      // realm and the address would arrive by ambient inheritance and a
      // worker that dropped them would pass (M8 survived the first round
      // for exactly that reason).
      const cloned = overTheChannel(args);
      const result = await realms.run(realms.DEFAULT_REALM, function () {
        return audit.withSource({ address: '' }, function () {
          return target.issueForReference(cloned);
        });
      });
      return { dispatched: true, result: overTheChannel(result) };
    }
  };
  deps.loadRequestPool = function () {
    if (behaviour === 'absent') {
      throw new Error('no pool module');
    }
    return pool;
  };
  const front = new broker.SpiffeBroker(deps);
  log.debug("Leaving frontSide().");
  return { front: front, pool: pool };
}

// One FetchJWTSVID second half, from the front, inside a realm and an audit
// source as `spiffe_server.ts` and `fromCaller()` enter them.
function fetchFrom(front, realm, call, wanted) {
  log.debug("Entering fetchFrom().");
  const ref = { caller: PID_REF_CALLER,
                resolved: { describe: 'pid 4242', selectors: [],
                            gone: function () { return Promise.resolve(''); },
                            release: function () {} } };
  log.debug("Leaving fetchFrom().");
  return realms.run(realm, function () {
    return audit.withSource({ address: '198.51.100.4' }, function () {
      return front.dispatchFetchJwt(call, ref, ['aud-1', 'aud-2'],
                                    wanted || '');
    });
  });
}

async function settle(promise) {
  log.debug("Entering settle().");
  try {
    const value = await promise;
    log.debug("Leaving settle().");
    return { value: value };
  } catch (err) {
    log.debug("Caught in settle(): " + ((err && err.message) || err));
    log.debug("Leaving settle().");
    return { err: err };
  }
}

// THE REALM IS REMOVED AFTERWARDS (2026-10-07). run.js runs every file in
// one process, and a realm left behind here was the second realm that
// tests/realm_isolation.js and tests/realm_directory_lookups.js, which run
// later and assert that only the default realm is left, then found.
async function checkBroker(t) {
  log.debug("Entering checkBroker().");
  t.log.info('=== the Broker API: FetchJWTSVID\'s second half ===');
  const id = 'kdcbroker' + Date.now().toString(36);
  realms.create({ id: id, name: 'KDC and broker operations' });
  try {
    await checkBrokerIn(t, id);
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving checkBroker().");
}

async function checkBrokerIn(t, id) {
  log.debug("Entering checkBrokerIn().");
  const realm = realms.get(id);
  const entries = [{ spiffeId: 'spiffe://x.test/a', hint: 'h' },
                   { spiffeId: 'spiffe://x.test/b', hint: 'h' },
                   { spiffeId: 'spiffe://x.test/c', hint: '' }];

  // 6a-e. Dispatched and answered.
  let seen = {};
  let pair = frontSide(workerSide(seen, { entries: entries }));
  let r = await settle(fetchFrom(pair.front, realm, {}));
  const svids = (r.value && r.value.reply && r.value.reply.svids) || [];
  t.check(r.value && r.value.dispatched === true &&
          pair.pool.sent[0] === broker.FETCH_JWT_OPERATION,
          '6a. dispatched as ' + broker.FETCH_JWT_OPERATION,
          JSON.stringify(r.err ? r.err.message : r.value));
  t.check(svids.length === 2 && svids[0].spiffe_id === 'spiffe://x.test/a' &&
          svids[1].spiffe_id === 'spiffe://x.test/c',
          '6b. the SVIDs come back, hints made unique',
          JSON.stringify(svids));
  t.check(seen.caller && seen.caller.brokered === true &&
          JSON.stringify(seen.caller.selectors) ===
            JSON.stringify(PID_REF_CALLER.selectors),
          '6c. the ATTESTED caller reached the worker', JSON.stringify(seen));
  t.check(seen.realm === id && seen.address === '198.51.100.4' &&
          JSON.stringify(seen.audiences) === '["aud-1","aud-2"]',
          '6d. in the call\'s realm and audit source, with its audiences',
          JSON.stringify(seen));
  seen = {};
  pair = frontSide(workerSide(seen, { entries: entries }));
  r = await settle(fetchFrom(pair.front, realm, {}, 'spiffe://x.test/c'));
  t.check(r.value && r.value.reply.svids.length === 1 &&
          r.value.reply.svids[0].spiffe_id === 'spiffe://x.test/c',
          '6e. a SPIFFE ID asked for narrows it in the worker',
          JSON.stringify(r.value || r.err.message));

  // 6f. No entry: WORKLOAD_NOT_ENTITLED, built in the front.
  const denied = {};
  pair = frontSide(workerSide({}, { entries: [] }));
  r = await settle(fetchFrom(pair.front, realm, denied));
  t.check(r.err && r.err.code === rpc.status.PERMISSION_DENIED &&
          r.err.metadata &&
          r.err.metadata.get('grpc-status-details-bin').length > 0 &&
          errorCodes.codeOf(denied) === 'STS-SPIFFE-0138',
          '6f. no entry is PERMISSION_DENIED with its ErrorInfo, STS-SPIFFE-' +
          '0138 on the front\'s call', r.err ? r.err.message : 'answered');

  // 6g. A status refusal in the worker keeps its code.
  pair = frontSide(workerSide({}, { entries: entries, refuse: true }));
  r = await settle(fetchFrom(pair.front, realm, {}));
  t.check(r.err && r.err.code === rpc.status.FAILED_PRECONDITION,
          '6g. a status refusal in the worker keeps its code',
          r.err ? r.err.code + ' ' + r.err.message : 'answered');

  // 6h. A failed worker: UNAVAILABLE, STS-SPIFFE-0145, not run here.
  const failed = {};
  pair = frontSide(null, 'reject');
  r = await settle(fetchFrom(pair.front, realm, failed));
  t.check(r.err && r.err.code === rpc.status.UNAVAILABLE &&
          errorCodes.codeOf(failed) === 'STS-SPIFFE-0145',
          '6h. a worker that fails is UNAVAILABLE, STS-SPIFFE-0145',
          r.err ? r.err.code + ' ' + r.err.message : 'answered in place');

  // 6i. Not dispatched, and no pool: answered in place.
  pair = frontSide(null, 'none');
  r = await settle(fetchFrom(pair.front, realm, {}));
  const none = r.value;
  pair = frontSide(null, 'absent');
  r = await settle(fetchFrom(pair.front, realm, {}));
  t.check(none && none.dispatched === false && r.value &&
          r.value.dispatched === false,
          '6i. not dispatched, or no pool module: answered in place',
          JSON.stringify([none, r.value]));

  // 6j. The table, only in a worker and once.
  const kind = broker.FETCH_JWT_OPERATION;
  const outside = await withVars({ STS_REQUEST_WORKER: undefined },
                                 async function () {
    return broker.SpiffeBroker.registerWorkerOperation();
  });
  const inside = await withVars({ STS_REQUEST_WORKER: '1' },
                                async function () {
    return [broker.SpiffeBroker.registerWorkerOperation(),
            broker.SpiffeBroker.registerWorkerOperation()];
  });
  t.check(outside === false && inside[0] === true && inside[1] === false &&
          typeof worker.OPERATIONS.get(kind) === 'function',
          '6j. the worker table is filled only in a worker, once',
          JSON.stringify({ outside: outside, inside: inside }));
  // OUT AGAIN: `spiffe_operations.js` asserts that a front process's table
  // holds no `spiffe.` kind, and `run.js` runs every file in one process.
  worker.OPERATIONS.delete(kind);

  // 6k. referenced() attests and does not wait for the workers.
  const probe = new broker.SpiffeBroker(broker.SpiffeBroker.defaultDeps(
    function () { return null; }));
  let waited = 0;
  probe.catchUpWithWorkers = async function () {
    waited++;
  };
  probe.authorizeType = function () {};
  probe.decodeReference = function () {
    return { type: 'pid', typeUrl: broker.PID_REFERENCE, pid: 4242 };
  };
  probe.resolve = async function () {
    return { selectors: PID_REF_CALLER.selectors, describe: 'pid 4242',
             gone: function () { return Promise.resolve(''); },
             release: function () {} };
  };
  const got = await probe.referenced({
    request: { reference: { reference: { type_url: broker.PID_REFERENCE } } },
    spiffeCaller: { broker: { id: 'spiffe://b.test/broker' } } });
  t.check(waited === 0 && got.caller.brokered === true,
          '6k. referenced() attests without waiting for the workers',
          'waited ' + waited);
  log.debug("Leaving checkBrokerIn().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkDispatched(t);
  await checkNotDispatched(t);
  await checkWorkerFailure(t);
  await checkWorkerHalf(t);
  await checkNoCatchUpInWorker(t);
  await checkBroker(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kdc broker operations',
  describe: 'port 88 and the Broker API\'s FetchJWTSVID answered in a ' +
            'request worker through the pool\'s operation channel: the ' +
            'bytes, the client\'s address, the refusal, the fallbacks and a ' +
            'failed worker',
  run: run
};
