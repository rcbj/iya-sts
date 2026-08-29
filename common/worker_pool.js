//
// common/worker_pool.js — the front process's half of the pool.
//
// THE SHAPE. One process owns all the sockets and all the state (see
// common/worker.js for why the state cannot be split), and hands units of pure
// computation to N child processes. Nothing here changes what this service
// puts on the wire; it changes only which thread computes it, which is the one
// property no protocol test can see and every timing failure could.
//
// SESSION AFFINITY. A job may name a session, and every job naming the same
// session goes to the same worker. Nothing in the job table needs that today —
// the three post-quantum operations are functions of their arguments and would
// be correct on any worker — and it is here because the moment a worker holds
// anything derived (a parsed key, a cached expansion) affinity is the
// difference between a cache and a bug. Routing is by hash rather than by a
// table, so it survives a worker being replaced and costs no bookkeeping.
// Without a session a job goes to the LEAST LOADED worker, which is what keeps
// one slow algorithm from queueing behind another on the same child.
//
// WHAT HAPPENS WHEN THE POOL CANNOT BE USED. Every entry point falls back to
// computing in this process, and that is deliberate rather than defensive: the
// in-process path is the one every test drove before this file existed, so a
// pool that fails to start degrades to the old behaviour — slow, correct, and
// saying so in the log — instead of taking the service down. `workers.count`
// of 0 selects that path on purpose.
//
// ORDERING. `submit()` resolves with the worker's answer and nothing here
// reorders anything; a caller that needs two operations in an order awaits
// them in that order, exactly as it did when they were synchronous.
//

const childProcess = require('child_process');
const path = require('path');
const bunyan = require('bunyan');

// The module's own logger, made the way pq_jose.js makes its own — this file
// is required from the crypto path, which is below helpers.js.
const log = bunyan.createLogger({
  name: 'worker_pool',
  level: (function () {
    try {
      return require('./config').value('global.logLevel') || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

const WORKER_PATH = path.join(__dirname, 'worker.js');

// How many. `workers.count` decides, and 0 means "do not fork at all" — the
// documented way back to the single-process behaviour.
//
// IT IS A WHOLE NUMBER AND NOT "one per core", and that is the config layer's
// doing rather than a preference: an `int` setting cannot express "unset"
// there, so a null default is read back as 0, which is OFF. A pool that
// silently did not exist because its default meant "auto" is a worse failure
// than a fixed two, and it is the one this had for an afternoon.
//
// FALLBACK is the declared default rather than 0, for the same reason: a
// value nobody can parse must not turn the pool off silently.
const DEFAULT_COUNT = 2;

function resolveCount() {
  log.debug("Entering resolveCount().");
  let asked;
  try {
    asked = require('./config').value('workers.count');
  } catch (e) {
    log.debug("Leaving resolveCount(). No config; " + DEFAULT_COUNT + ".");
    return DEFAULT_COUNT;
  }
  const n = parseInt(asked, 10);
  if (Number.isFinite(n) && n >= 0) {
    log.debug("Leaving resolveCount(). " + n + ".");
    return n;
  }
  log.warn("workers.count is not a whole number of workers (" +
    JSON.stringify(asked) + "); using " + DEFAULT_COUNT + " instead.");
  log.debug("Leaving resolveCount(). Default.");
  return DEFAULT_COUNT;
}

// A stable, well-spread integer from a session id. Not a security property —
// it decides which child does the arithmetic, nothing more — so the cheapest
// thing that spreads is the right one.
function hashOf(key) {
  log.debug("Entering hashOf().");
  const s = String(key);
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h = h ^ s.charCodeAt(i);
    // FNV-1a's prime, by shifts because Math.imul on every character is the
    // slower half of a function called once per job.
    h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  log.debug("Leaving hashOf().");
  return h >>> 0;
}

function Pool() {
  log.debug("Entering Pool().");
  this.workers = [];
  this.nextJobId = 1;
  this.pending = new Map();
  this.started = false;
  this.stopping = false;
  this.count = 0;
  log.debug("Leaving Pool().");
}

// One child, wired up. Separated from start() because a worker that dies is
// replaced by calling this again, and a replacement must be indistinguishable
// from an original.
Pool.prototype.spawn = function (slot) {
  log.debug("Entering Pool.spawn(). slot=" + slot);
  const self = this;
  const child = childProcess.fork(WORKER_PATH, [], {
    // The worker inherits the log level and nothing else it could act on.
    env: process.env,
    // stdio inherited so a worker's bunyan lines land in the same place every
    // other line of this service does. A worker whose output went nowhere
    // would be a worker whose failures went nowhere.
    stdio: ['inherit', 'inherit', 'inherit', 'ipc']
  });
  const entry = { child: child, slot: slot, inFlight: 0, ready: false };
  child.on('message', function (msg) {
    if (msg && msg.ready) {
      entry.ready = true;
      log.debug("Worker " + slot + " reported ready. pid=" + msg.pid);
      return;
    }
    self.settle(entry, msg);
  });
  child.on('exit', function (code, signal) {
    self.onExit(entry, code, signal);
  });
  child.on('error', function (err) {
    log.warn("Worker " + slot + " errored: " + err.message);
  });
  this.workers[slot] = entry;
  log.debug("Leaving Pool.spawn().");
  return entry;
};

// One answer from one worker.
Pool.prototype.settle = function (entry, msg) {
  log.debug("Entering Pool.settle().");
  if (!msg || typeof msg.id === 'undefined') {
    log.debug("Leaving Pool.settle(). Not an answer.");
    return;
  }
  const waiter = this.pending.get(msg.id);
  if (!waiter) {
    // An answer to a job we already gave up on — a worker that came back after
    // its replacement was spoken to. Dropped rather than thrown: the caller
    // has long since been settled one way or the other.
    log.debug("Leaving Pool.settle(). Nobody is waiting for " + msg.id + ".");
    return;
  }
  this.pending.delete(msg.id);
  entry.inFlight = Math.max(0, entry.inFlight - 1);
  if (msg.ok) {
    waiter.resolve(msg.result);
  } else {
    waiter.reject(new Error(msg.error || 'the worker failed and said nothing'));
  }
  log.debug("Leaving Pool.settle().");
};

// A worker died. Everything it was holding is failed by hand — a promise whose
// worker is gone is never settled by anything else — and a replacement is
// forked unless we are on our way out.
Pool.prototype.onExit = function (entry, code, signal) {
  log.debug("Entering Pool.onExit(). slot=" + entry.slot);
  const self = this;
  entry.ready = false;
  this.pending.forEach(function (waiter, id) {
    if (waiter.slot !== entry.slot) {
      return;
    }
    self.pending.delete(id);
    waiter.reject(new Error('the worker computing this exited (' +
      (signal || ('code ' + code)) + ') before it answered'));
  });
  entry.inFlight = 0;
  if (this.stopping) {
    log.debug("Leaving Pool.onExit(). Stopping; not replacing it.");
    return;
  }
  log.warn("Worker " + entry.slot + " exited (" + (signal || ('code ' + code)) +
    "); forking a replacement.");
  this.spawn(entry.slot);
  log.debug("Leaving Pool.onExit().");
};

Pool.prototype.start = function () {
  log.debug("Entering Pool.start().");
  if (this.started) {
    log.debug("Leaving Pool.start(). Already started.");
    return this;
  }
  this.count = resolveCount();
  if (this.count === 0) {
    this.started = true;
    log.info('worker pool: OFF (workers.count is 0). Post-quantum signing ' +
      'runs in this process, which is what it did before the pool existed — ' +
      'correct, and blocking for as long as it takes.');
    log.debug("Leaving Pool.start(). Count 0.");
    return this;
  }
  for (let i = 0; i < this.count; i++) {
    try {
      this.spawn(i);
    } catch (e) {
      log.error('worker pool: could not fork worker ' + i + ': ' + e.message);
    }
  }
  this.started = true;
  const up = this.workers.filter(Boolean).length;
  log.info('worker pool: ' + up + ' worker(s) for the post-quantum ' +
    'operations. They hold NO state — the front process owns every socket ' +
    'and everything mutable — so what moves off this thread is arithmetic ' +
    'and nothing else. Set workers.count to 0 to compute in this process.');
  log.debug("Leaving Pool.start().");
  return this;
};

Pool.prototype.stop = function () {
  log.debug("Entering Pool.stop().");
  this.stopping = true;
  this.workers.filter(Boolean).forEach(function (entry) {
    try {
      entry.child.disconnect();
    } catch (e) {
      // Already gone, which is the outcome we wanted.
    }
  });
  this.workers = [];
  this.started = false;
  log.debug("Leaving Pool.stop().");
};

// Which worker. A session always maps to the same one; without a session the
// least loaded takes it, ties going to the lower slot so that an idle pool
// fills predictably rather than at random.
Pool.prototype.pick = function (sessionKey) {
  log.debug("Entering Pool.pick().");
  const live = this.workers.filter(Boolean);
  if (!live.length) {
    log.debug("Leaving Pool.pick(). Nothing live.");
    return null;
  }
  if (sessionKey) {
    const entry = live[hashOf(sessionKey) % live.length];
    log.debug("Leaving Pool.pick(). Session " + sessionKey + " -> slot " +
      entry.slot + ".");
    return entry;
  }
  let best = live[0];
  live.forEach(function (entry) {
    if (entry.inFlight < best.inFlight) {
      best = entry;
    }
  });
  log.debug("Leaving Pool.pick(). Least loaded is slot " + best.slot + ".");
  return best;
};

Pool.prototype.available = function () {
  log.debug("Entering Pool.available().");
  const ok = this.started && this.workers.filter(Boolean).length > 0;
  log.debug("Leaving Pool.available(). " + ok);
  return ok;
};

// Hand one job to one worker. Rejects rather than throws for every outcome,
// including "there is no pool" — a caller written against a promise should not
// also have to catch.
Pool.prototype.submit = function (kind, args, sessionKey) {
  log.debug("Entering Pool.submit(). kind=" + kind);
  const self = this;
  const entry = this.pick(sessionKey);
  if (!entry) {
    log.debug("Leaving Pool.submit(). No worker.");
    return Promise.reject(new Error('there is no worker to run ' + kind));
  }
  const id = this.nextJobId;
  this.nextJobId = this.nextJobId + 1;
  const p = new Promise(function (resolve, reject) {
    self.pending.set(id, { resolve: resolve, reject: reject,
                           slot: entry.slot });
    try {
      entry.child.send({ id: id, kind: kind, args: args });
      entry.inFlight = entry.inFlight + 1;
    } catch (e) {
      self.pending.delete(id);
      reject(new Error('the worker would not take the job: ' + e.message));
    }
  });
  log.debug("Leaving Pool.submit(). id=" + id);
  return p;
};

const pool = new Pool();

module.exports = {
  pool: pool,
  start: function () {
    log.debug("Entering start().");
    const p = pool.start();
    log.debug("Leaving start().");
    return p;
  },
  stop: function () {
    log.debug("Entering stop().");
    pool.stop();
    log.debug("Leaving stop().");
  },
  submit: function (kind, args, sessionKey) {
    log.debug("Entering submit().");
    const p = pool.submit(kind, args, sessionKey);
    log.debug("Leaving submit().");
    return p;
  },
  available: function () {
    log.debug("Entering available().");
    const a = pool.available();
    log.debug("Leaving available().");
    return a;
  },
  hashOf: hashOf,
  resolveCount: resolveCount
};
