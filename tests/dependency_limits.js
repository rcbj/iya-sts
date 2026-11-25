// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: dependency_limits.js
//
// ===========================================================================
// THE LIMITS AND TIMEOUTS ON WHAT THIS SERVICE DIALS (#2220, section C; ASVS
// 5.0.0 13.1.2, 13.1.3, 13.2.6). docs/v1.2.0/dependencies.md lists them.
//
//   A. outbound HTTP (`common/outbound_limits.ts`): the shared agent's caps
//      come from the settings, keep-alive is on, and a socket is not shared
//      across a different pinned address, identity check or realm; the
//      overall deadline ends a request that answers too slowly; the connect
//      timeout ends one whose socket never connects, and a reused socket is
//      not timed.
//   B. the malware scanner: past malwareScan.concurrency running and
//      malwareScan.queueLimit waiting, a file is refused 503 STS-CORE-0182.
//   C. the HSM: past keys.pkcs11QueueLimit waiting an operation is refused
//      STS-KEYS-0215; a wait past keys.pkcs11TimeoutMs, and an operation that
//      does not answer, are refused STS-KEYS-0216, and the late session is
//      discarded, not lent again.
//   D. the secret stores: each SDK is handed its own timeout and attempt
//      bound; node-vault's calls are made again for no answer or a 5xx, and
//      never for a 4xx.
//   E. the database pool's size (`persistence.poolSize`) and the
//      attribute-source pool's (`attributeSources.poolSize`).
//   F. a synchronous call to another cell whose answer passes
//      cells.maxAnswerBytes fails STS-CELL-0212.
// ===========================================================================

delete process.env.CONFIG_FILE;

const http = require('http');
const net = require('net');
const path = require('path');
const EventEmitter = require('events');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({ name: 'dependency_limits',
  level: process.env.LOG_LEVEL || 'info' });

// Runs `fn` with some settings answered by the test.
async function withSettings(values, fn) {
  log.debug('Entering withSettings().');
  const config = require(ROOT + '/common/config');
  const real = config.value;
  config.value = function (key) {
    if (Object.prototype.hasOwnProperty.call(values, key)) {
      return values[key];
    }
    return real.apply(config, arguments);
  };
  try {
    return await fn();
  } finally {
    config.value = real;
    log.debug('Leaving withSettings().');
  }
}

async function outbound(t) {
  log.debug('Entering outbound().');
  t.log.info('=== A. outbound HTTP ===');
  const OutboundLimits = require(ROOT + '/common/outbound_limits');
  await withSettings({ 'federation.outboundMaxSockets': 3,
                       'federation.outboundMaxTotalSockets': 7 },
    async function () {
      const agent = /** @type {any} */ (OutboundLimits.agentFor(true));
      t.check(agent.maxSockets === 3 && agent.maxTotalSockets === 7 &&
              agent.keepAlive === true &&
              OutboundLimits.agentFor(true) === agent,
              'A1. one shared https agent, kept alive, with the caps the ' +
              'settings name', agent.maxSockets + '/' + agent.maxTotalSockets);
    });
  const fed = require(ROOT + '/federation/federation_http');
  const pinA = fed.pinnedLookup({ address: '192.0.2.1', family: 4 });
  const pinB = fed.pinnedLookup({ address: '192.0.2.2', family: 4 });
  const a = OutboundLimits.useAgent({ host: 'p.example', port: 443,
                                      lookup: pinA }, true);
  const b = OutboundLimits.useAgent({ host: 'p.example', port: 443,
                                      lookup: pinB }, true);
  const a2 = OutboundLimits.useAgent({ host: 'p.example', port: 443,
                                       lookup: fed.pinnedLookup(
                                         { address: '192.0.2.1',
                                           family: 4 }) }, true);
  const agent = a.agent;
  t.check(agent.getName(a) !== agent.getName(b) &&
          agent.getName(a) === agent.getName(a2),
          'A2. a kept-alive socket is pooled under the address it was ' +
          'pinned to: two pins are two pools, the same pin one');
  const own = OutboundLimits.useAgent({ host: 'p.example', port: 443,
    checkServerIdentity: function () {
      return undefined;
    } }, true);
  t.check(agent.getName(own) !== agent.getName(
    OutboundLimits.useAgent({ host: 'p.example', port: 443 }, true)),
          'A3. and under the identity check it was verified with');
  const unix = OutboundLimits.useAgent({ socketPath: '/var/run/x.sock' },
                                       false);
  const none = OutboundLimits.useAgent({ host: 'x', agent: false }, true);
  t.check(unix.agent === undefined && none.agent === false,
          'A4. a Unix socket and a caller\'s own `agent: false` are left ' +
          'alone');
  // A3a. The realm is in the pool key.
  const realms = require(ROOT + '/common/realms');
  t.check(/realm=/.test(String(a.stsPoolKey)) &&
          typeof realms.currentId === 'function',
          'A5. the realm a socket was made in is in its pool key',
          String(a.stsPoolKey));

  // A6. The overall deadline, against a server that never finishes.
  const server = http.createServer(function (req, res) {
    res.writeHead(200, { 'content-type': 'text/plain' });
    const drip = setInterval(function () {
      res.write('.');
    }, 20);
    res.on('close', function () {
      clearInterval(drip);
    });
  });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = /** @type {any} */ (server.address()).port;
  try {
    const outcome = await new Promise(function (resolve) {
      const options = OutboundLimits.useAgent({ host: '127.0.0.1',
                                                port: port, path: '/' },
                                              false);
      const request = http.request(options, function (response) {
        response.on('data', function () {});
        response.on('error', function () {});
      });
      // The inactivity timeout never fires: a byte comes every 20 ms.
      request.setTimeout(5000, function () {
        resolve('inactivity');
      });
      request.on('error', function () {});
      OutboundLimits.guard(request, { deadlineMs: 250, where: 'the test',
        onTimeout: function (why) {
          resolve(why);
        } });
      request.end();
    });
    t.check(/overall deadline of 250ms/.test(String(outcome)),
            'A6. a peer that answers a byte at a time is ended at the ' +
            'overall deadline, though it is never idle', String(outcome));
  } finally {
    server.close();
  }

  // A7. The connect timeout: a socket that never connects.
  await withSettings({ 'federation.outboundConnectTimeoutMs': 100 },
    async function () {
      const request = new EventEmitter();
      let destroyed = false;
      /** @type {any} */ (request).destroy = function () {
        destroyed = true;
      };
      const why = await new Promise(function (resolve) {
        OutboundLimits.guard(request, { deadlineMs: 0, onTimeout: resolve });
        const socket = new EventEmitter();
        /** @type {any} */ (socket).connecting = true;
        request.emit('socket', socket);
      });
      t.check(/did not connect within 100ms/.test(String(why)) && destroyed,
              'A7. a new connection that does not connect within ' +
              'federation.outboundConnectTimeoutMs is ended', String(why));
      const reused = new EventEmitter();
      let fired = false;
      /** @type {any} */ (reused).destroy = function () {};
      OutboundLimits.guard(reused, { deadlineMs: 0,
        onTimeout: function () {
          fired = true;
        } });
      const kept = new EventEmitter();
      /** @type {any} */ (kept).connecting = false;
      reused.emit('socket', kept);
      await new Promise(function (resolve) {
        setTimeout(resolve, 200);
      });
      t.check(!fired, 'A8. a kept-alive socket, already connected, is not ' +
              'timed');
    });
  log.debug('Leaving outbound().');
}

async function malware(t) {
  log.debug('Entering malware().');
  t.log.info('=== B. the malware scanner\'s queue ===');
  const MalwareScan = require(ROOT + '/common/malware_scan');
  let release = null;
  const server = net.createServer(function (socket) {
    let text = '';
    socket.on('data', function (chunk) {
      text += chunk.toString('latin1');
      if (/\r\n0\r\n\r\n$/.test(text)) {
        release = function () {
          socket.end('ICAP/1.0 204 No Content\r\n\r\n');
        };
      }
    });
    socket.on('error', function () {});
  });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = /** @type {any} */ (server.address()).port;
  try {
    await withSettings({ 'malwareScan.enabled': true,
                         'malwareScan.url': 'icap://127.0.0.1:' + port +
                           '/avscan',
                         'malwareScan.timeoutMs': 5000,
                         'malwareScan.concurrency': 1,
                         'malwareScan.queueLimit': 0 },
      async function () {
        const mode = require(ROOT + '/common/mode');
        const realTls = mode.requiresTlsToMalwareScanner;
        mode.requiresTlsToMalwareScanner = function () {
          return false;
        };
        try {
          const first = MalwareScan.refusal(Buffer.from('one'));
          await new Promise(function (resolve) {
            setTimeout(resolve, 100);
          });
          const second = await MalwareScan.refusal(Buffer.from('two'));
          t.check(!!second && second.status === 503 &&
                  second.code === 'STS-CORE-0182',
                  'B1. a scan past malwareScan.concurrency running and ' +
                  'malwareScan.queueLimit waiting is refused 503 ' +
                  'STS-CORE-0182', JSON.stringify(second));
          if (release) {
            release();
          }
          t.equal(await first, null, 'B2. the scan that held the place ' +
                  'still finishes clean');
        } finally {
          mode.requiresTlsToMalwareScanner = realTls;
        }
      });
  } finally {
    server.close();
  }
  log.debug('Leaving malware().');
}

async function hsm(t) {
  log.debug('Entering hsm().');
  t.log.info('=== C. the HSM\'s queue and timeout ===');
  const pk = require(ROOT + '/common/crypto_impl/pkcs11');
  const token = new pk.Pkcs11Token(null, { tokenLabel: 'limits',
    maxSessions: 1, timeoutMs: 150, queueLimit: 1 });
  // Every session is lent: the next operation must wait for one.
  /** @type {any} */ (token).entry = { recovering: null };
  token.takeIdle = function () {
    return null;
  };
  token.pooled = function () {
    return 1;
  };
  const waiting = token.acquire().then(function () {
    return null;
  }, function (e) {
    return e;
  });
  const refused = await token.acquire().then(function () {
    return null;
  }, function (e) {
    return e;
  });
  const codes = require(ROOT + '/common/error_codes');
  t.equal(refused && codes.codeOf(refused), 'STS-KEYS-0215',
          'C1. past keys.pkcs11QueueLimit waiting, an operation is refused ' +
          'at once');
  const timedOut = await waiting;
  t.check(!!timedOut && codes.codeOf(timedOut) === 'STS-KEYS-0216' &&
          token.waiters.length === 0,
          'C2. a wait for a session past keys.pkcs11TimeoutMs is refused, ' +
          'and leaves the queue', timedOut && timedOut.message);
  let discarded = null;
  token.discard = function (session) {
    discarded = session;
  };
  let answer = null;
  const late = new Promise(function (resolve) {
    answer = resolve;
  });
  const session = { h: 1 };
  const outcome = await token.bounded('a signature', session, late)
    .then(function () {
      return null;
    }, function (e) {
      return e;
    });
  t.check(!!outcome && codes.codeOf(outcome) === 'STS-KEYS-0216' &&
          outcome.stsTimedOut === true && discarded === null,
          'C3. an operation that does not answer is refused at the timeout',
          outcome && outcome.message);
  answer('signed');
  await new Promise(function (resolve) {
    setImmediate(resolve);
  });
  t.check(discarded === session,
          'C4. and its session is discarded when the module answers, not ' +
          'lent again');
  log.debug('Leaving hsm().');
}

async function stores(t) {
  log.debug('Entering stores().');
  t.log.info('=== D. the secret stores ===');
  const secrets = require(ROOT + '/common/secrets');
  await withSettings({ 'keys.storeTimeoutMs': 4000, 'keys.storeAttempts': 3 },
    async function () {
      const limits = secrets.sdkLimits;
      const aws = limits.aws({ region: 'us-west-2' });
      t.check(aws.region === 'us-west-2' && aws.maxAttempts === 3 &&
              aws.requestHandler.requestTimeout === 4000 &&
              aws.requestHandler.connectionTimeout === 4000,
              'D1. an AWS client gets maxAttempts and its request ' +
              'handler\'s timeouts', JSON.stringify(aws));
      const calls = [];
      const gcp = limits.gcp({
        accessSecretVersion: function () {
          calls.push(Array.from(arguments));
          return Promise.resolve([{}]);
        },
        secretVersionPath: function () {
          calls.push(Array.from(arguments));
          return 'p';
        }
      });
      await gcp.accessSecretVersion({ name: 'n' });
      gcp.secretVersionPath('a', 'b');
      t.check(calls[0].length === 2 && calls[0][1].timeout === 4000 &&
              calls[0][1].maxRetries === 2 && calls[1].length === 2,
              'D2. a Google Cloud call gets its call options; a path ' +
              'helper does not', JSON.stringify(calls));
      const azure = limits.azure();
      const request = { timeout: 0 };
      azure.additionalPolicies[0].policy.sendRequest(request,
        function (r) {
          return r;
        });
      t.check(azure.retryOptions.maxRetries === 2 &&
              azure.additionalPolicies[0].position === 'perRetry' &&
              request.timeout === 4000,
              'D3. an Azure client gets its retry bound and a per-try ' +
              'timeout');
      let tries = 0;
      const vault = limits.vault({ request: function () {
        tries++;
        return tries < 3 ? Promise.reject(new Error('socket hang up'))
          : Promise.resolve({ data: 'ok' });
      } });
      const got = await vault.request({ path: '/x', method: 'GET' });
      t.check(tries === 3 && got.data === 'ok',
              'D4. a Vault call with no answer is made again, up to ' +
              'keys.storeAttempts', 'tries=' + tries);
      let denied = 0;
      const strict = limits.vault({ request: function () {
        denied++;
        return Promise.reject(Object.assign(new Error('permission denied'),
          { response: { statusCode: 403 } }));
      } });
      await strict.request({ path: '/x', method: 'GET' }).catch(function () {
        return null;
      });
      t.equal(denied, 1, 'D5. a 4xx is an answer, and is never repeated');
    });
  log.debug('Leaving stores().');
}

async function pools(t) {
  log.debug('Entering pools().');
  t.log.info('=== E. the pools ===');
  const postgres = require(ROOT + '/persistence/persistence_postgres');
  t.check(postgres.poolMax(1) === 4 && postgres.poolMax(5) === 10 &&
          postgres.poolMax(5, 0) === 10 && postgres.poolMax(5, 12) === 12 &&
          postgres.poolMax(5, 1) === 2,
          'E1. persistence.poolSize replaces the automatic size, never ' +
          'below two; 0 keeps the automatic one');
  const Drivers = require(ROOT + '/attribute-sources/attribute_source_drivers');
  await withSettings({ 'attributeSources.poolSize': 9 }, async function () {
    t.equal(Drivers.poolSize(), 9, 'E2. an attribute source\'s pool is ' +
            'attributeSources.poolSize');
  });
  t.equal(Drivers.poolSize(), 4, 'E3. 4 by default, the number it was');
  log.debug('Leaving pools().');
}

async function cells(t) {
  log.debug('Entering cells().');
  t.log.info('=== F. an inter-cell answer\'s cap ===');
  const channel = require(ROOT + '/common/cell_channel');
  const one = new channel.CellChannel();
  /** @type {any} */ (one).dial = function () {
    const response = new EventEmitter();
    /** @type {any} */ (response).statusCode = 200;
    /** @type {any} */ (response).destroy = function () {};
    setImmediate(function () {
      for (let i = 0; i < 5; i++) {
        response.emit('data', Buffer.alloc(40000, 0x20));
      }
      response.emit('end');
    });
    return Promise.resolve(response);
  };
  await withSettings({ 'cells.maxAnswerBytes': 65536 }, async function () {
    const failed = await one.call('peer', 'op', {}).then(function () {
      return null;
    }, function (e) {
      return e;
    });
    t.check(!!failed && /STS-CELL-0212/.test(String(failed.message)),
            'F1. an answer past cells.maxAnswerBytes fails the call ' +
            'without being read', failed && failed.message);
  });
  log.debug('Leaving cells().');
}

module.exports = {
  name: 'dependency_limits',
  describe: 'the limits and timeouts on what this service dials (#2220): ' +
            'outbound HTTP, the malware scanner, the HSM, the secret ' +
            'stores, the pools and an inter-cell answer',
  run: async function (t) {
    log.debug('Entering run().');
    await outbound(t);
    await malware(t);
    await hsm(t);
    await stores(t);
    await pools(t);
    await cells(t);
    log.debug('Leaving run().');
  }
};
