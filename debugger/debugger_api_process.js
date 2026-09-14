'use strict';
//
// File: debugger_api_process.js
//
// ===========================================================================
// THE DEBUGGER'S API, AS A CHILD PROCESS OF THIS ONE (2026-09-13).
//
// **FORKED AND NEVER REQUIRED, AND THAT IS THE WHOLE DEPENDENCY STORY.** The
// debugger's api is an Express 5 application with a dependency tree of its
// own; this service is Express 4. It parses request bodies its own way (this
// service reads every body as text), installs interceptors on a shared axios
// module, sets `global.DOMParser`, reads `CONFIG_FILE` from the environment
// and keeps state in memory. Loaded into this process every one of those is a
// collision; forked, none of them is anything: the child has its own module
// cache, its own `node_modules`, its own environment and its own event loop,
// and a hang or a crash in it is a 502 on `/api` rather than an identity
// provider that stopped answering. rcbj chose this over an in-process mount on
// 2026-09-13.
//
// The interface is the debugger project's `embedded/CLAUDE.md` contract, and
// it is environment variables and one IPC message:
//
//   CONFIG_FILE                     the api tree's own env/embedded.js
//   DEBUGGER_LISTEN_SOCKET          plain HTTP on this unix socket, mode 0600
//   DEBUGGER_UI_URL                 the debugger origin the browser uses
//   DEBUGGER_ALLOWED_ADDRESS_RANGES JSON list; non-empty means ALLOW-LIST mode
//   DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS  used when there is no allow-list
//   NODE_EXTRA_CA_CERTS             this service's trust anchor, so the api
//                                   can dial the main port over TLS
//   <- { type: 'debugger-api-listening' }   once the socket is bound
//
// **THE ENVIRONMENT IS BUILT, NOT INHERITED.** This process's environment
// holds whatever a deployment put there — a client secret, a database URL, a
// key-encryption key's location — and a child whose job is to make requests a
// caller describes has no business holding any of it. It gets PATH, HOME,
// LANG, TZ and the contract, and nothing else.
//
// ---------------------------------------------------------------------------
// ONE CHILD, IN THE FRONT PROCESS, NEVER ONE PER REQUEST WORKER.
//
// The api keeps SAML exchanges, WS-Federation responses and Shared Signals
// inboxes in memory — a response stashed by one request and read by the next.
// That is exactly the state `common/CLAUDE.md` says a second copy of cannot
// hold, so there is ONE api process, forked by the process that owns the
// debugger's listener, and every `/api` call reaches the same one. A request
// worker never forks it (`STS_REQUEST_WORKER`).
//
// ---------------------------------------------------------------------------
// WHAT IT MAY DIAL IS DECIDED HERE, BEFORE IT STARTS.
//
// Development hands it no allow-list and private networks allowed, which is
// what the debugger is for beside a local stack. Product
// (`mode.limitsDebuggerDestinations()`) hands it an ALLOW-LIST: this
// service's loopback addresses, the addresses of its network interfaces, what
// `global.publicBaseUrl` and `debugger.publicBaseUrl` resolve to, and
// `debugger.allowedDestinations`. The api's address guard applies it to every
// HTTP call AND to its raw Kerberos, LDAP, TLS and gRPC relays, and an
// allow-list with no usable entry refuses everything rather than nothing.
// ===========================================================================

const childProcess = require('child_process');
const dns = require('dns');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { log } = require('../common/helpers');
const config = require('../common/config');
const mode = require('../common/mode');
const errorCodes = require('../common/error_codes');

// The package root, against which a relative directory setting is read.
const PACKAGE_ROOT = path.join(__dirname, '..');

// How long a start must stay up before its failures stop counting, and the
// ceiling on the delay between starts. Neither is a deployment decision: they
// shape a restart loop, and the settings that are — the start timeout and the
// restart limit — are rows.
const STABLE_AFTER_MS = 60 * 1000;
const MAX_BACKOFF_MS = 60 * 1000;
const FIRST_BACKOFF_MS = 1000;
// How long a SIGTERM is given before a SIGKILL.
const STOP_GRACE_MS = 5000;

let child = null;
let wanted = false;
let state = 'stopped';
let socketDir = '';
let socketFile = '';
let spec = null;
let starts = 0;
let consecutiveFailures = 0;
let startedAt = 0;
let listeningAt = 0;
let lastExit = null;
let lastError = '';
let restartTimer = null;
let startTimer = null;
let allowedRanges = [];
let allowListProblems = [];
// Set while this module itself is replacing the child, so that its exit is a
// hand-over and not a failure: it is not counted, and the next fork is made
// at once rather than after a backoff.
let replacing = false;
let anchorReplacements = 0;

function directorySetting(key) {
  log.debug("Entering directorySetting(). key=" + key);
  const raw = String(config.value(key) || '').trim();
  log.debug("Leaving directorySetting().");
  return path.isAbsolute(raw) ? raw : path.join(PACKAGE_ROOT, raw);
}

function apiDirectory() {
  log.debug("Entering apiDirectory().");
  log.debug("Leaving apiDirectory().");
  return directorySetting('debugger.apiDirectory');
}

// Whether the built api is where the setting says, and the sentence if not.
function installedProblem() {
  log.debug("Entering installedProblem().");
  const dir = apiDirectory();
  const entry = path.join(dir, 'server.js');
  const configFile = path.join(dir, 'env', 'embedded.js');
  if (!fs.existsSync(entry)) {
    log.debug("Leaving installedProblem(). No server.js.");
    return 'the debugger api is not installed: ' + entry + ' does not exist ' +
           '(debugger.apiDirectory). The image copies it from the debugger ' +
           'project\'s embedded build; a checkout makes one with that ' +
           'project\'s embedded/build.sh --out debugger/embedded.';
  }
  if (!fs.existsSync(configFile)) {
    log.debug("Leaving installedProblem(). No env/embedded.js.");
    return 'the debugger api at ' + dir + ' has no env/embedded.js, so it ' +
           'is not an embedded build — the standalone api would bind TCP ' +
           'instead of the socket this service forwards to.';
  }
  log.debug("Leaving installedProblem(). Installed.");
  return '';
}

// ---------------------------------------------------------------------------
// THE ALLOW-LIST.
// ---------------------------------------------------------------------------

// A CIDR range, or null. Bare addresses are refused rather than widened to a
// /32, which is the api's own rule — a typo in a range is a hole, and it is
// better named than guessed at.
function cidrOrNull(value) {
  log.debug("Entering cidrOrNull().");
  const text = String(value || '').trim();
  const match = /^([0-9a-fA-F:.]+)\/([0-9]{1,3})$/.exec(text);
  if (!match) {
    log.debug("Leaving cidrOrNull(). Not a range.");
    return null;
  }
  const family = net.isIP(match[1]);
  const bits = Number(match[2]);
  if (!family || bits > (family === 4 ? 32 : 128)) {
    log.debug("Leaving cidrOrNull(). Out of bounds.");
    return null;
  }
  log.debug("Leaving cidrOrNull().");
  return match[1] + '/' + bits;
}

function hostRange(address) {
  log.debug("Entering hostRange().");
  const family = net.isIP(String(address || ''));
  log.debug("Leaving hostRange().");
  return family ? address + (family === 4 ? '/32' : '/128') : null;
}

function hostOf(url) {
  log.debug("Entering hostOf().");
  const text = String(url || '').trim();
  if (!text) {
    log.debug("Leaving hostOf(). None.");
    return '';
  }
  try {
    const host = new URL(text).hostname.replace(/^\[|\]$/g, '');
    log.debug("Leaving hostOf().");
    return host;
  } catch (e) {
    log.debug("Caught in hostOf(): " + ((e && e.message) || e));
    return '';
  }
}

function lookupAll(host) {
  log.debug("Entering lookupAll(). host=" + host);
  log.debug("Leaving lookupAll().");
  return new Promise(function (resolve) {
    if (!host) {
      resolve([]);
      return;
    }
    if (net.isIP(host)) {
      resolve([host]);
      return;
    }
    dns.lookup(host, { all: true }, function (err, addresses) {
      if (err) {
        log.debug("Caught in a callback in lookupAll(): " + err.message);
        resolve([]);
        return;
      }
      resolve((addresses || []).map(function (one) {
        return one.address;
      }));
    });
  });
}

// The allow-list for product mode, or [] in development. Asynchronous because
// a public base URL is a NAME and what the api is allowed to reach is what
// that name resolves to.
async function computeAllowedRanges() {
  log.debug("Entering computeAllowedRanges().");
  allowListProblems = [];
  if (!mode.limitsDebuggerDestinations()) {
    log.debug("Leaving computeAllowedRanges(). Development: no allow-list.");
    return [];
  }
  const ranges = ['127.0.0.0/8', '::1/128'];
  const add = function (range) {
    if (range && ranges.indexOf(range) < 0) {
      ranges.push(range);
    }
  };
  const interfaces = os.networkInterfaces();
  Object.keys(interfaces).forEach(function (name) {
    (interfaces[name] || []).forEach(function (one) {
      add(hostRange(String(one.address || '').split('%')[0]));
    });
  });
  const names = [hostOf(config.value('global.publicBaseUrl')),
                 hostOf(config.value('debugger.publicBaseUrl'))];
  for (let i = 0; i < names.length; i++) {
    const addresses = await lookupAll(names[i]);
    addresses.forEach(function (address) {
      add(hostRange(address));
    });
  }
  const extra = config.value('debugger.allowedDestinations') || [];
  (Array.isArray(extra) ? extra : String(extra).split(','))
    .map(function (one) {
      return String(one).trim();
    })
    .filter(Boolean)
    .forEach(function (entry) {
      const range = cidrOrNull(entry);
      if (!range) {
        allowListProblems.push(entry);
        log.error(errorCodes.tag('STS-DBG-0020') + 'debugger: "' + entry +
                  '" in debugger.allowedDestinations is not a CIDR range ' +
                  '(203.0.113.0/24, 10.1.2.3/32) and was left out of the ' +
                  'allow-list, which is narrower for it rather than wider.');
        return;
      }
      add(range);
    });
  log.debug("Leaving computeAllowedRanges(). " + ranges.length + " range(s).");
  return ranges;
}

// ---------------------------------------------------------------------------
// THE CHILD.
// ---------------------------------------------------------------------------

// A private directory for the socket and the anchor file: 0700, so nothing
// else on the machine can connect to the api past the gate.
function ensureSocketDir() {
  log.debug("Entering ensureSocketDir().");
  if (!socketDir || !fs.existsSync(socketDir)) {
    socketDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-debugger-'));
    fs.chmodSync(socketDir, 0o700);
    socketFile = path.join(socketDir, 'api.sock');
  }
  log.debug("Leaving ensureSocketDir(). " + socketDir);
  return socketDir;
}

function childEnvironment() {
  log.debug("Entering childEnvironment().");
  const env = {};
  ['PATH', 'HOME', 'LANG', 'TZ'].forEach(function (name) {
    if (process.env[name] !== undefined) {
      env[name] = process.env[name];
    }
  });
  const dir = apiDirectory();
  env.CONFIG_FILE = path.join(dir, 'env', 'embedded.js');
  env.DEBUGGER_LISTEN_SOCKET = socketFile;
  env.DEBUGGER_UI_URL = spec.uiUrl;
  env.DEBUGGER_LOG_LEVEL = String(config.value('global.logLevel') || 'info');
  env.DEBUGGER_ALLOWED_ADDRESS_RANGES = JSON.stringify(allowedRanges);
  env.DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS =
    mode.limitsDebuggerDestinations() ? 'true' : 'false';
  if (spec.anchorPem) {
    const anchorFile = path.join(socketDir, 'trust-anchor.pem');
    fs.writeFileSync(anchorFile, spec.anchorPem, { mode: 0o600 });
    env.NODE_EXTRA_CA_CERTS = anchorFile;
  }
  log.debug("Leaving childEnvironment().");
  return env;
}

function clearTimers() {
  log.debug("Entering clearTimers().");
  if (startTimer) {
    clearTimeout(startTimer);
    startTimer = null;
  }
  if (restartTimer) {
    clearTimeout(restartTimer);
    restartTimer = null;
  }
  log.debug("Leaving clearTimers().");
}

function scheduleRestart() {
  log.debug("Entering scheduleRestart().");
  if (!wanted) {
    log.debug("Leaving scheduleRestart(). Not wanted.");
    return;
  }
  const limit = Number(config.value('debugger.restartLimit'));
  if (consecutiveFailures >= limit) {
    state = 'given-up';
    log.error(errorCodes.tag('STS-DBG-0014') + 'debugger: the api process ' +
              'failed ' + consecutiveFailures + ' time(s) in a row ' +
              '(debugger.restartLimit=' + limit + ') and will not be ' +
              'started again until this service restarts. Every /api call ' +
              'answers 502. The last failure: ' + (lastError || 'none given'));
    log.debug("Leaving scheduleRestart(). Given up.");
    return;
  }
  const delay = Math.min(MAX_BACKOFF_MS,
                         FIRST_BACKOFF_MS * Math.pow(2,
                           Math.max(0, consecutiveFailures - 1)));
  state = 'restarting';
  restartTimer = setTimeout(function () {
    restartTimer = null;
    fork();
  }, delay);
  restartTimer.unref();
  log.debug("Leaving scheduleRestart(). In " + delay + "ms.");
}

function fork() {
  log.debug("Entering fork().");
  clearTimers();
  ensureSocketDir();
  try {
    fs.unlinkSync(socketFile);
  } catch (e) {
    // Nothing there is the ordinary case; the api unlinks a stale file too.
    log.debug("Caught in fork(): " + ((e && e.message) || e));
  }
  const dir = apiDirectory();
  starts += 1;
  startedAt = Date.now();
  listeningAt = 0;
  state = 'starting';
  let spawned = null;
  try {
    spawned = childProcess.fork(path.join(dir, 'server.js'), [], {
      cwd: dir,
      env: childEnvironment(),
      stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
      serialization: 'json'
    });
  } catch (e) {
    lastError = 'fork failed: ' + e.message;
    consecutiveFailures += 1;
    log.error(errorCodes.tag('STS-DBG-0013') + 'debugger: the api process ' +
              'could not be forked: ' + e.message);
    scheduleRestart();
    log.debug("Leaving fork(). Fork threw.");
    return;
  }
  child = spawned;
  const timeoutMs = Number(config.value('debugger.startTimeoutS')) * 1000;
  startTimer = setTimeout(function () {
    startTimer = null;
    if (child === spawned && !listeningAt) {
      lastError = 'it did not report listening within ' + (timeoutMs / 1000) +
                  's (debugger.startTimeoutS)';
      log.error(errorCodes.tag('STS-DBG-0013') + 'debugger: the api process ' +
                spawned.pid + ' ' + lastError + ', so it is being killed.');
      spawned.kill('SIGKILL');
    }
  }, timeoutMs);
  startTimer.unref();
  spawned.on('message', function (message) {
    if (message && message.type === 'debugger-api-listening' &&
        child === spawned) {
      listeningAt = Date.now();
      state = 'running';
      if (startTimer) {
        clearTimeout(startTimer);
        startTimer = null;
      }
      log.info('debugger: the api process ' + spawned.pid + ' is listening ' +
               'on ' + socketFile + (allowedRanges.length
                 ? ', allowed to dial ' + allowedRanges.length + ' range(s)'
                 : ', with no allow-list (development mode)') + '.');
    }
  });
  spawned.on('error', function (err) {
    lastError = err.message;
    log.error(errorCodes.tag('STS-DBG-0013') + 'debugger: the api process ' +
              'reported an error: ' + err.message);
  });
  spawned.on('exit', function (code, signal) {
    if (child !== spawned) {
      return;
    }
    child = null;
    const upMs = listeningAt ? Date.now() - listeningAt : 0;
    lastExit = { code: code, signal: signal, at: Date.now(), upMs: upMs };
    if (!wanted) {
      state = 'stopped';
      return;
    }
    if (replacing) {
      replacing = false;
      log.info('debugger: the api process ' + spawned.pid + ' was replaced ' +
               'to take a new trust anchor; forking its successor.');
      fork();
      return;
    }
    consecutiveFailures = upMs >= STABLE_AFTER_MS ? 1
                                                  : consecutiveFailures + 1;
    if (!lastError || listeningAt) {
      lastError = 'it exited with ' + (signal ? 'signal ' + signal
                                              : 'code ' + code) +
                  (upMs ? ' after ' + Math.round(upMs / 1000) + 's' : '');
    }
    log.error(errorCodes.tag('STS-DBG-0013') + 'debugger: the api process ' +
              spawned.pid + ' stopped: ' + lastError + '.');
    scheduleRestart();
  });
  log.debug("Leaving fork(). pid=" + spawned.pid);
}

// ---------------------------------------------------------------------------
// start({ uiUrl, anchorPem }) — asynchronous only for the allow-list's
// lookups; it resolves once the first fork has been made, not once the api is
// listening, because a slow api must not hold the rest of the service back.
// ---------------------------------------------------------------------------
async function start(options) {
  log.debug("Entering start().");
  if (process.env.STS_REQUEST_WORKER) {
    log.debug("Leaving start(). A request worker never forks the api.");
    return { started: false, why: 'request worker' };
  }
  const problem = installedProblem();
  if (problem) {
    state = 'not-installed';
    lastError = problem;
    log.error(errorCodes.tag('STS-DBG-0015') + 'debugger: not started — ' +
              problem);
    log.debug("Leaving start(). Not installed.");
    return { started: false, why: problem };
  }
  spec = Object.assign({}, options || {});
  wanted = true;
  allowedRanges = await computeAllowedRanges();
  fork();
  log.debug("Leaving start().");
  return { started: true };
}

// The private directory goes with the child: it holds the socket and a copy of
// the trust anchor, and a directory per start left in the temporary directory
// is how a machine running test stacks all day fills it.
function removeSocketDir() {
  log.debug("Entering removeSocketDir().");
  if (socketDir) {
    try {
      fs.rmSync(socketDir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in removeSocketDir(): " + ((e && e.message) || e));
    }
    socketDir = '';
    socketFile = '';
  }
  log.debug("Leaving removeSocketDir().");
}

// ---------------------------------------------------------------------------
// A NEW TRUST ANCHOR REPLACES THE CHILD (2026-09-13).
//
// The api dials this service's main port over TLS and trusts it through
// `NODE_EXTRA_CA_CERTS`, which node reads ONCE, when the process starts. So the
// day an operator replaces the service Root on /admin/pki (`build-root`), the
// running child goes on trusting the Root that is gone and every call it makes
// to this service fails `unable to get local issuer certificate` — about a
// service that is working. Nothing inside the child can be told; the only way
// to give it the new anchor is a new process, so that is what this does: write
// the new PEM and replace the child, as a hand-over rather than a failure.
//
// The caller decides when to ask (`debugger_server.js` compares, at most every
// few seconds, the anchor `tls_server.js` publishes now with the one the child
// was started with). A call in flight when the old child exits gets the 502 a
// dead child always gives; an anchor change is an operator's act and rare.
// Answers whether a replacement was started.
// ---------------------------------------------------------------------------
function updateAnchor(pem) {
  log.debug("Entering updateAnchor().");
  const next = String(pem || '');
  if (!spec || !wanted || !next || next === String(spec.anchorPem || '')) {
    log.debug("Leaving updateAnchor(). Nothing to do.");
    return false;
  }
  spec.anchorPem = next;
  anchorReplacements += 1;
  const running = child;
  if (!running) {
    // No child to replace: the next fork — a restart already scheduled, or
    // none at all after giving up — writes the new anchor on its own.
    log.debug("Leaving updateAnchor(). No child; the next fork takes it.");
    return false;
  }
  log.info('debugger: this service\'s trust anchor changed, so the api ' +
           'process ' + running.pid + ' is being replaced — it read the old ' +
           'one at start and cannot be given another.');
  replacing = true;
  // Not ready from this moment: a call must not be forwarded to a child that
  // has been told to exit.
  listeningAt = 0;
  state = 'replacing';
  const killer = setTimeout(function () {
    running.kill('SIGKILL');
  }, STOP_GRACE_MS);
  killer.unref();
  running.once('exit', function () {
    clearTimeout(killer);
  });
  running.kill('SIGTERM');
  log.debug("Leaving updateAnchor(). Replacing.");
  return true;
}

// Stop it, for a shutdown. SIGTERM, then SIGKILL after a grace period.
function stop() {
  log.debug("Entering stop().");
  wanted = false;
  clearTimers();
  const running = child;
  if (!running) {
    removeSocketDir();
    log.debug("Leaving stop(). Nothing running.");
    return Promise.resolve({ stopped: false });
  }
  log.debug("Leaving stop().");
  return new Promise(function (resolve) {
    const killer = setTimeout(function () {
      running.kill('SIGKILL');
    }, STOP_GRACE_MS);
    killer.unref();
    running.once('exit', function () {
      clearTimeout(killer);
      removeSocketDir();
      resolve({ stopped: true });
    });
    running.kill('SIGTERM');
  });
}

// A last resort for an exit that did not go through stop(): an orphaned api
// would hold a socket in a directory nothing will clean.
process.on('exit', function () {
  if (child) {
    try {
      child.kill('SIGKILL');
    } catch (e) {
      // The process is exiting and there is nobody left to tell.
      lastError = String((e && e.message) || e);
    }
  }
  removeSocketDir();
});

function ready() {
  log.debug("Entering ready().");
  log.debug("Leaving ready().");
  return !!(child && listeningAt);
}

function socketPath() {
  log.debug("Entering socketPath().");
  log.debug("Leaving socketPath().");
  return socketFile;
}

function status() {
  log.debug("Entering status().");
  log.debug("Leaving status().");
  return {
    state: state,
    pid: child ? child.pid : null,
    socket: socketFile || null,
    apiDirectory: apiDirectory(),
    starts: starts,
    consecutiveFailures: consecutiveFailures,
    startedAt: startedAt ? new Date(startedAt).toISOString() : null,
    listeningAt: listeningAt ? new Date(listeningAt).toISOString() : null,
    lastExit: lastExit ? { code: lastExit.code, signal: lastExit.signal,
                           at: new Date(lastExit.at).toISOString(),
                           upSeconds: Math.round(lastExit.upMs / 1000) }
                       : null,
    lastError: lastError || null,
    uiUrl: spec ? spec.uiUrl : null,
    allowList: mode.limitsDebuggerDestinations(),
    allowedRanges: allowedRanges.slice(0),
    allowListProblems: allowListProblems.slice(0),
    anchorReplacements: anchorReplacements
  };
}

module.exports = {
  start: start,
  stop: stop,
  ready: ready,
  socketPath: socketPath,
  status: status,
  updateAnchor: updateAnchor,
  installedProblem: installedProblem,
  // For tests/debugger_api_process.js: the two pure pieces of the allow-list.
  cidrOrNull: cidrOrNull,
  computeAllowedRanges: computeAllowedRanges
};
