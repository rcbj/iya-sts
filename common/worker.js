//
// common/worker.js — one process of the pool, and the whole of what a worker
// is allowed to be.
//
// SOMETHING HAS TO GIVE, and in this service it is the event loop. There is one
// process here and it owns six listener families — the Express app, the KDC on
// TCP and UDP 88, the Kerberos service on 8888, the LDAP directory, two gRPC
// surfaces and two HTTPS endpoints — and node runs all of them on one thread.
// A synchronous computation therefore does not slow this service down, it STOPS
// it: for the duration of one SLH-DSA-SHAKE-128s signature the process answers
// nobody at all, and a KDC that does not answer looks from the outside exactly
// like a KDC that is not there. Stalls of 14.6, 15.4, 17.8 and 23.3 seconds
// were measured on 2026-08-29 and each of them failed some unrelated test in a
// way that named anything but the cause.
//
// THIS FILE HOLDS NO STATE AND MUST NOT, which is the rule the whole design
// rests on. The front process owns every socket AND every piece of mutable
// state this service has — the operator configuration, the realms, the KDC's
// replay cache, the SCIM nonce sets, the principals, the SPIFFE registry, the
// issued tokens — because almost none of that is scoped to a session and
// splitting it N ways would break it SILENTLY: replay detection that stops
// detecting, a configuration change that lands on one worker of four, a token
// minted here and introspected there. So a worker is handed everything it needs
// in the job and hands back everything it produced, and two workers can never
// disagree about anything because neither remembers anything.
//
// What that leaves a worker is pure computation, and the computation that
// actually costs is asymmetric cryptography over post-quantum parameter sets:
// `pq_jose.sign`, `.verify` and `.generate` are (algorithm, key bytes, message)
// in and bytes out, with no ambient anything. They are the whole job table
// below, and a new entry belongs here only if it is a function of its arguments
// in the same way.
//
// It is a CHILD PROCESS rather than a worker_thread deliberately. The @noble
// post-quantum code is CPU-bound JavaScript, so a thread would contend for the
// same isolate's garbage collector and — worse — the synchronous shape of
// `Atomics.wait` that makes a thread convenient to call is exactly the
// blocking this file exists to remove.
//

const bunyan = require('bunyan');
const pqJose = require('./pq_jose');

// The module's own logger, made the way pq_jose.js makes its own and for the
// same reason: helpers.js requires crypto.js, which requires that file.
const log = bunyan.createLogger({
  name: 'sts_worker',
  level: (function () {
    try {
      return require('./config').value('global.logLevel') || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

// The job table. A `kind` names one of these and nothing else is reachable
// from the front process, which is the point: the surface a worker exposes is
// a list of pure functions rather than "run this".
const JOBS = {
  // (alg, priv, message) -> signature bytes.
  'pq.sign': function (args) {
    log.debug("Entering pq.sign job. alg=" + args.alg);
    const out = pqJose.sign(args.alg, Buffer.from(args.priv, 'base64'),
      Buffer.from(args.message, 'base64'));
    log.debug("Leaving pq.sign job.");
    return { signature: Buffer.from(out).toString('base64') };
  },
  // (alg, pub, message, signature) -> boolean. A verification that THROWS and
  // one that returns false are different answers and both are carried back:
  // a malformed key is not a bad signature.
  'pq.verify': function (args) {
    log.debug("Entering pq.verify job. alg=" + args.alg);
    const ok = pqJose.verify(args.alg, Buffer.from(args.pub, 'base64'),
      Buffer.from(args.message, 'base64'),
      Buffer.from(args.signature, 'base64'));
    log.debug("Leaving pq.verify job. ok=" + ok);
    return { ok: !!ok };
  },
  // (alg) -> a fresh key pair. The slowest thing this service does at startup,
  // once per algorithm per realm.
  'pq.generate': function (args) {
    log.debug("Entering pq.generate job. alg=" + args.alg);
    const pair = pqJose.generate(args.alg);
    log.debug("Leaving pq.generate job.");
    return {
      pub: Buffer.from(pair.pub).toString('base64'),
      priv: Buffer.from(pair.priv).toString('base64')
    };
  }
};

// One message in, one message out, always — including for a job that threw.
// A worker that answered nothing would leave the front process holding a
// promise for ever, and a hung request is harder to read than a failed one.
function onJob(msg) {
  log.debug("Entering onJob().");
  if (!msg || typeof msg.id === 'undefined') {
    log.debug("Leaving onJob(). Not a job.");
    return;
  }
  const job = JOBS[msg.kind];
  if (!job) {
    process.send({ id: msg.id, ok: false,
      error: 'this worker has no job called "' + msg.kind + '". It knows: ' +
             Object.keys(JOBS).join(', ') + '.' });
    log.debug("Leaving onJob(). Unknown kind.");
    return;
  }
  try {
    const result = job(msg.args || {});
    process.send({ id: msg.id, ok: true, result: result });
  } catch (e) {
    // The MESSAGE crosses, not the Error: an Error does not survive the
    // structured clone the channel uses, and what arrives instead is `{}` —
    // a failure that says nothing anywhere.
    process.send({ id: msg.id, ok: false,
      error: (e && e.message) || String(e) });
  }
  log.debug("Leaving onJob().");
}

process.on('message', onJob);

// A worker whose parent has gone should go too, rather than becoming an
// orphan holding a CPU. `disconnect` fires when the channel closes for any
// reason, which covers the parent exiting without a word.
process.on('disconnect', function () {
  log.debug("Entering the disconnect handler. The parent has gone.");
  process.exit(0);
});

log.debug("A worker is ready. pid=" + process.pid + ", jobs: " +
  Object.keys(JOBS).join(', ') + ".");

// Tell the parent we are up. The pool counts these before it reports itself
// ready, so that the first request does not race the fork.
if (process.send) {
  process.send({ ready: true, pid: process.pid });
}

module.exports = { JOBS: JOBS };
