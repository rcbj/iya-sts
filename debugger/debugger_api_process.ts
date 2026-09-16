'use strict';
//
// File: debugger_api_process.ts
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

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `DebuggerApiProcess` takes the modules it uses through its constructor
// (`DebuggerApiProcessDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `DebuggerApiProcess` is exported beside them for the
// composition root.
// ---------------------------------------------------------------------------

import childProcess = require('child_process');
import dns = require('dns');
import fs = require('fs');
import net = require('net');
import os = require('os');
import path = require('path');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import mode = require('../common/mode');
import errorCodes = require('../common/error_codes');

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

// What `DebuggerApiProcess` needs from the rest of the service: the modules
// this file used to reach for itself, passed in so that the composition root
// can build one and a test can build one with stubs.
interface DebuggerApiProcessDeps {
  childProcess: typeof childProcess;
  dns: typeof dns;
  fs: typeof fs;
  net: typeof net;
  os: typeof os;
  path: typeof path;
  log: typeof log;
  config: typeof config;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
}

class DebuggerApiProcess {
  constructor(private readonly deps: DebuggerApiProcessDeps) {
    deps.log.debug("Entering DebuggerApiProcess.constructor().");
    deps.log.debug("Leaving DebuggerApiProcess.constructor().");
  }

  directorySetting(key) {
    const { log, config, path } = this.deps;
    log.debug("Entering DebuggerApiProcess.directorySetting(). key=" + key);
    const raw = String(config.value(key) || '').trim();
    log.debug("Leaving DebuggerApiProcess.directorySetting().");
    return path.isAbsolute(raw) ? raw : path.join(PACKAGE_ROOT, raw);
  }

  apiDirectory() {
    const { log } = this.deps;
    log.debug("Entering DebuggerApiProcess.apiDirectory().");
    log.debug("Leaving DebuggerApiProcess.apiDirectory().");
    return this.directorySetting('debugger.apiDirectory');
  }

  // Whether the built api is where the setting says, and the sentence if not.
  installedProblem() {
    const { log, path, fs } = this.deps;
    log.debug("Entering DebuggerApiProcess.installedProblem().");
    const dir = this.apiDirectory();
    const entry = path.join(dir, 'server.js');
    const configFile = path.join(dir, 'env', 'embedded.js');
    if (!fs.existsSync(entry)) {
      log.debug("Leaving DebuggerApiProcess.installedProblem(). No server.js.");
      return 'the debugger api is not installed: ' + entry +
             ' does not exist (debugger.apiDirectory). The image copies it ' +
             'from the debugger project\'s embedded build; a checkout makes ' +
             'one with that project\'s embedded/build.sh --out ' +
             'debugger/embedded.';
    }
    if (!fs.existsSync(configFile)) {
      log.debug("Leaving DebuggerApiProcess.installedProblem(). No " +
                "env/embedded.js.");
      return 'the debugger api at ' + dir + ' has no env/embedded.js, so it ' +
             'is not an embedded build — the standalone api would bind TCP ' +
             'instead of the socket this service forwards to.';
    }
    log.debug("Leaving DebuggerApiProcess.installedProblem(). Installed.");
    return '';
  }

  // ---------------------------------------------------------------------------
  // THE ALLOW-LIST.
  // ---------------------------------------------------------------------------

  // A CIDR range, or null. Bare addresses are refused rather than widened to a
  // /32, which is the api's own rule — a typo in a range is a hole, and it is
  // better named than guessed at.
  cidrOrNull(value) {
    const { log, net } = this.deps;
    log.debug("Entering DebuggerApiProcess.cidrOrNull().");
    const text = String(value || '').trim();
    const match = /^([0-9a-fA-F:.]+)\/([0-9]{1,3})$/.exec(text);
    if (!match) {
      log.debug("Leaving DebuggerApiProcess.cidrOrNull(). Not a range.");
      return null;
    }
    const family = net.isIP(match[1]);
    const bits = Number(match[2]);
    if (!family || bits > (family === 4 ? 32 : 128)) {
      log.debug("Leaving DebuggerApiProcess.cidrOrNull(). Out of bounds.");
      return null;
    }
    log.debug("Leaving DebuggerApiProcess.cidrOrNull().");
    return match[1] + '/' + bits;
  }

  hostRange(address) {
    const { log, net } = this.deps;
    log.debug("Entering DebuggerApiProcess.hostRange().");
    const family = net.isIP(String(address || ''));
    log.debug("Leaving DebuggerApiProcess.hostRange().");
    return family ? address + (family === 4 ? '/32' : '/128') : null;
  }

  hostOf(url) {
    const { log } = this.deps;
    log.debug("Entering DebuggerApiProcess.hostOf().");
    const text = String(url || '').trim();
    if (!text) {
      log.debug("Leaving DebuggerApiProcess.hostOf(). None.");
      return '';
    }
    try {
      const host = new URL(text).hostname.replace(/^\[|\]$/g, '');
      log.debug("Leaving DebuggerApiProcess.hostOf().");
      return host;
    } catch (e) {
      log.debug("Caught in DebuggerApiProcess.hostOf(): " +
                ((e && e.message) || e));
      return '';
    }
  }

  lookupAll(host): Record<string, any> {
    const { log, net, dns } = this.deps;
    log.debug("Entering DebuggerApiProcess.lookupAll(). host=" + host);
    log.debug("Leaving DebuggerApiProcess.lookupAll().");
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
  async computeAllowedRanges() {
    const { log, mode, os, config, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering DebuggerApiProcess.computeAllowedRanges().");
    allowListProblems = [];
    if (!mode.limitsDebuggerDestinations()) {
      log.debug("Leaving DebuggerApiProcess.computeAllowedRanges(). " +
                "Development: no allow-list.");
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
        add(self.hostRange(String(one.address || '').split('%')[0]));
      });
    });
    const names = [this.hostOf(config.value('global.publicBaseUrl')),
                   this.hostOf(config.value('debugger.publicBaseUrl'))];
    for (let i = 0; i < names.length; i++) {
      const addresses = await this.lookupAll(names[i]);
      addresses.forEach(function (address) {
        add(self.hostRange(address));
      });
    }
    const extra = config.value('debugger.allowedDestinations') || [];
    (Array.isArray(extra) ? extra : String(extra).split(','))
      .map(function (one) {
        return String(one).trim();
      })
      .filter(Boolean)
      .forEach(function (entry) {
        const range = self.cidrOrNull(entry);
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
    log.debug("Leaving DebuggerApiProcess.computeAllowedRanges(). " +
              ranges.length + " range(s).");
    return ranges;
  }

  // ---------------------------------------------------------------------------
  // THE CHILD.
  // ---------------------------------------------------------------------------

  // A private directory for the socket and the anchor file: 0700, so nothing
  // else on the machine can connect to the api past the gate.
  ensureSocketDir() {
    const { log, fs, path, os } = this.deps;
    log.debug("Entering DebuggerApiProcess.ensureSocketDir().");
    if (!socketDir || !fs.existsSync(socketDir)) {
      socketDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-debugger-'));
      fs.chmodSync(socketDir, 0o700);
      socketFile = path.join(socketDir, 'api.sock');
    }
    log.debug("Leaving DebuggerApiProcess.ensureSocketDir(). " + socketDir);
    return socketDir;
  }

  childEnvironment() {
    const { log, path, config, mode, fs } = this.deps;
    log.debug("Entering DebuggerApiProcess.childEnvironment().");
    const env: Record<string, any> = {};
    ['PATH', 'HOME', 'LANG', 'TZ'].forEach(function (name) {
      if (process.env[name] !== undefined) {
        env[name] = process.env[name];
      }
    });
    const dir = this.apiDirectory();
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
    log.debug("Leaving DebuggerApiProcess.childEnvironment().");
    return env;
  }

  clearTimers() {
    const { log } = this.deps;
    log.debug("Entering DebuggerApiProcess.clearTimers().");
    if (startTimer) {
      clearTimeout(startTimer);
      startTimer = null;
    }
    if (restartTimer) {
      clearTimeout(restartTimer);
      restartTimer = null;
    }
    log.debug("Leaving DebuggerApiProcess.clearTimers().");
  }

  scheduleRestart() {
    const { log, config, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering DebuggerApiProcess.scheduleRestart().");
    if (!wanted) {
      log.debug("Leaving DebuggerApiProcess.scheduleRestart(). Not wanted.");
      return;
    }
    const limit = Number(config.value('debugger.restartLimit'));
    if (consecutiveFailures >= limit) {
      state = 'given-up';
      log.error(errorCodes.tag('STS-DBG-0014') + 'debugger: the api process ' +
                'failed ' + consecutiveFailures + ' time(s) in a row ' +
                '(debugger.restartLimit=' + limit + ') and will not be ' +
                'started again until this service restarts. Every /api call ' +
                'answers 502. The last failure: ' +
                (lastError || 'none given'));
      log.debug("Leaving DebuggerApiProcess.scheduleRestart(). Given up.");
      return;
    }
    const delay = Math.min(MAX_BACKOFF_MS,
                           FIRST_BACKOFF_MS * Math.pow(2,
                             Math.max(0, consecutiveFailures - 1)));
    state = 'restarting';
    restartTimer = setTimeout(function () {
      restartTimer = null;
      self.fork();
    }, delay);
    restartTimer.unref();
    log.debug("Leaving DebuggerApiProcess.scheduleRestart(). In " + delay +
              "ms.");
  }

  fork() {
    const { log, fs, childProcess, path, errorCodes, config } = this.deps;
    const self = this;
    log.debug("Entering DebuggerApiProcess.fork().");
    this.clearTimers();
    this.ensureSocketDir();
    try {
      fs.unlinkSync(socketFile);
    } catch (e) {
      // Nothing there is the ordinary case; the api unlinks a stale file too.
      log.debug("Caught in DebuggerApiProcess.fork(): " +
                ((e && e.message) || e));
    }
    const dir = this.apiDirectory();
    starts += 1;
    startedAt = Date.now();
    listeningAt = 0;
    state = 'starting';
    let spawned = null;
    try {
      spawned = childProcess.fork(path.join(dir, 'server.js'), [], {
        cwd: dir,
        env: this.childEnvironment(),
        stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
        serialization: 'json'
      });
    } catch (e) {
      lastError = 'fork failed: ' + e.message;
      consecutiveFailures += 1;
      log.error(errorCodes.tag('STS-DBG-0013') + 'debugger: the api process ' +
                'could not be forked: ' + e.message);
      this.scheduleRestart();
      log.debug("Leaving DebuggerApiProcess.fork(). Fork threw.");
      return;
    }
    child = spawned;
    const timeoutMs = Number(config.value('debugger.startTimeoutS')) * 1000;
    startTimer = setTimeout(function () {
      startTimer = null;
      if (child === spawned && !listeningAt) {
        lastError = 'it did not report listening within ' + (timeoutMs / 1000) +
                    's (debugger.startTimeoutS)';
        log.error(errorCodes.tag('STS-DBG-0013') +
                  'debugger: the api process ' +
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
        self.fork();
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
      self.scheduleRestart();
    });
    log.debug("Leaving DebuggerApiProcess.fork(). pid=" + spawned.pid);
  }

  // ---------------------------------------------------------------------------
  // start({ uiUrl, anchorPem }) — asynchronous only for the allow-list's
  // lookups; it resolves once the first fork has been made, not once the api is
  // listening, because a slow api must not hold the rest of the service back.
  // ---------------------------------------------------------------------------
  async start(options) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering DebuggerApiProcess.start().");
    if (process.env.STS_REQUEST_WORKER) {
      log.debug("Leaving DebuggerApiProcess.start(). A request worker never " +
                "forks the api.");
      return { started: false, why: 'request worker' };
    }
    const problem = this.installedProblem();
    if (problem) {
      state = 'not-installed';
      lastError = problem;
      log.error(errorCodes.tag('STS-DBG-0015') + 'debugger: not started — ' +
                problem);
      log.debug("Leaving DebuggerApiProcess.start(). Not installed.");
      return { started: false, why: problem };
    }
    spec = Object.assign({}, options || {});
    wanted = true;
    allowedRanges = await this.computeAllowedRanges();
    this.fork();
    log.debug("Leaving DebuggerApiProcess.start().");
    return { started: true };
  }

  // The private directory goes with the child: it holds the socket and a copy
  // of the trust anchor, and a directory per start left in the temporary
  // directory is how a machine running test stacks all day fills it.
  removeSocketDir() {
    const { log, fs } = this.deps;
    log.debug("Entering DebuggerApiProcess.removeSocketDir().");
    if (socketDir) {
      try {
        fs.rmSync(socketDir, { recursive: true, force: true });
      } catch (e) {
        log.debug("Caught in DebuggerApiProcess.removeSocketDir(): " +
                  ((e && e.message) || e));
      }
      socketDir = '';
      socketFile = '';
    }
    log.debug("Leaving DebuggerApiProcess.removeSocketDir().");
  }

  // ---------------------------------------------------------------------------
  // A NEW TRUST ANCHOR REPLACES THE CHILD (2026-09-13).
  //
  // The api dials this service's main port over TLS and trusts it through
  // `NODE_EXTRA_CA_CERTS`, which node reads ONCE, when the process starts. So
  // the day an operator replaces the service Root on /admin/pki (`build-root`),
  // the running child goes on trusting the Root that is gone and every call it
  // makes to this service fails `unable to get local issuer certificate` —
  // about a service that is working. Nothing inside the child can be told; the
  // only way to give it the new anchor is a new process, so that is what this
  // does: write the new PEM and replace the child, as a hand-over rather than a
  // failure.
  //
  // The caller decides when to ask (`debugger_server.ts` compares, at most
  // every few seconds, the anchor `tls_server.js` publishes now with the one
  // the child was started with). A call in flight when the old child exits gets
  // the 502 a dead child always gives; an anchor change is an operator's act
  // and rare. Answers whether a replacement was started.
  // ---------------------------------------------------------------------------
  updateAnchor(pem) {
    const { log } = this.deps;
    log.debug("Entering DebuggerApiProcess.updateAnchor().");
    const next = String(pem || '');
    if (!spec || !wanted || !next || next === String(spec.anchorPem || '')) {
      log.debug("Leaving DebuggerApiProcess.updateAnchor(). Nothing to do.");
      return false;
    }
    spec.anchorPem = next;
    anchorReplacements += 1;
    const running = child;
    if (!running) {
      // No child to replace: the next fork — a restart already scheduled, or
      // none at all after giving up — writes the new anchor on its own.
      log.debug("Leaving DebuggerApiProcess.updateAnchor(). No child; the " +
                "next fork takes it.");
      return false;
    }
    log.info('debugger: this service\'s trust anchor changed, so the api ' +
             'process ' + running.pid +
             ' is being replaced — it read the old ' +
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
    log.debug("Leaving DebuggerApiProcess.updateAnchor(). Replacing.");
    return true;
  }

  // Stop it, for a shutdown. SIGTERM, then SIGKILL after a grace period.
  stop() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering DebuggerApiProcess.stop().");
    wanted = false;
    this.clearTimers();
    const running = child;
    if (!running) {
      this.removeSocketDir();
      log.debug("Leaving DebuggerApiProcess.stop(). Nothing running.");
      return Promise.resolve({ stopped: false });
    }
    log.debug("Leaving DebuggerApiProcess.stop().");
    return new Promise(function (resolve) {
      const killer = setTimeout(function () {
        running.kill('SIGKILL');
      }, STOP_GRACE_MS);
      killer.unref();
      running.once('exit', function () {
        clearTimeout(killer);
        self.removeSocketDir();
        resolve({ stopped: true });
      });
      running.kill('SIGTERM');
    });
  }

  ready() {
    const { log } = this.deps;
    log.debug("Entering DebuggerApiProcess.ready().");
    log.debug("Leaving DebuggerApiProcess.ready().");
    return !!(child && listeningAt);
  }

  socketPath() {
    const { log } = this.deps;
    log.debug("Entering DebuggerApiProcess.socketPath().");
    log.debug("Leaving DebuggerApiProcess.socketPath().");
    return socketFile;
  }

  status() {
    const { log, mode } = this.deps;
    log.debug("Entering DebuggerApiProcess.status().");
    log.debug("Leaving DebuggerApiProcess.status().");
    return {
      state: state,
      pid: child ? child.pid : null,
      socket: socketFile || null,
      apiDirectory: this.apiDirectory(),
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
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const debuggerApiProcess = new DebuggerApiProcess({
  childProcess: childProcess,
  dns: dns,
  fs: fs,
  net: net,
  os: os,
  path: path,
  log: log,
  config: config,
  mode: mode,
  errorCodes: errorCodes
});

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
  debuggerApiProcess.removeSocketDir();
});

export = {
  DebuggerApiProcess: DebuggerApiProcess,
  start: debuggerApiProcess.start.bind(debuggerApiProcess) as
    DebuggerApiProcess['start'],
  stop: debuggerApiProcess.stop.bind(debuggerApiProcess) as
    DebuggerApiProcess['stop'],
  ready: debuggerApiProcess.ready.bind(debuggerApiProcess) as
    DebuggerApiProcess['ready'],
  socketPath: debuggerApiProcess.socketPath.bind(debuggerApiProcess) as
    DebuggerApiProcess['socketPath'],
  status: debuggerApiProcess.status.bind(debuggerApiProcess) as
    DebuggerApiProcess['status'],
  updateAnchor: debuggerApiProcess.updateAnchor.bind(debuggerApiProcess) as
    DebuggerApiProcess['updateAnchor'],
  installedProblem:
    debuggerApiProcess.installedProblem.bind(debuggerApiProcess) as
      DebuggerApiProcess['installedProblem'],
  // For tests/debugger_api_process.js: the two pure pieces of the allow-list.
  cidrOrNull: debuggerApiProcess.cidrOrNull.bind(debuggerApiProcess) as
    DebuggerApiProcess['cidrOrNull'],
  computeAllowedRanges:
    debuggerApiProcess.computeAllowedRanges.bind(debuggerApiProcess) as
      DebuggerApiProcess['computeAllowedRanges']
};
