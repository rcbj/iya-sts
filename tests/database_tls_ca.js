// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// @ts-check
'use strict';

// ===========================================================================
// THE DATABASE'S OWN TRUST ANCHOR, AND VERIFICATION BY DEFAULT (2026-10-12).
//
// rcbj's decision: the PostgreSQL server's certificate is verified BY
// DEFAULT, in every mode (`persistence.databaseTlsRejectUnauthorized` is
// true). The compose stack's certificate is self-signed inside the postgres
// container, so the stack hands it to the service read-only and names it in
// `persistence.databaseTlsCaFile` — a PEM file trusted for the database
// connections ONLY, in place of the default trust store for them. This file
// holds the service to that:
//
//   A. THE DEFAULT IS ON. With nothing set, `verifiesDatabaseTls()` is true
//      and a string with no sslmode, or `require`, verifies the chain and
//      the host name.
//   B. THE CA FILE IS APPLIED. `databaseTlsCa()` answers the file's
//      certificates; `dialOptions()` puts them on the `ssl` option as `ca`;
//      a driver built with them hands them to its read pool and to the
//      directory bridge's thread — for verify-ca too, where the bridge's
//      options are rewritten as data — and the bridge's answer survives
//      structured cloning, as a Worker's data must; and
//      `databaseConnection()` hands them to a process that is not the
//      service (the risk loader, `cell_convert`). A DIRECTORY is read too,
//      every `.crt` and `.pem` in it — the cells stack's databases share
//      their certificates in one, as `<CN>.crt`.
//   C. A FILE NAMED AND UNUSABLE IS REFUSED under STS-STORE-0079: a path
//      that does not exist, and a file holding no certificate (a private
//      key named by mistake), both from `databaseTlsCa()` and as the
//      rejection of `databaseConnection()`.
//   D. AN ADDRESS IS THE NAME THAT IS CHECKED (#951). The hook calls
//      `tls.checkServerIdentity` with the host from the string, not the
//      `localhost` argument `pg` leaves it, and the bridge is handed that
//      host as data. `verify-ca` still checks nothing.
//   E. `pg` ACTUALLY USES THAT HOOK. A stand-in that speaks only the
//      SSLRequest/'S' exchange refuses `127.0.0.1` when the certificate
//      names `localhost` alone, accepts it when the certificate names the
//      address, and `verify-ca` accepts the first certificate.
//   F. THE BRIDGE'S THREAD DIALS WITH THE SAME CHECK (#951's review). The
//      real `common/sync_query_thread.js`, handed what `bridgeConnection()`
//      posts, refuses that certificate by address in `outbound_tls`'s
//      RFC 9525 sentence, accepts the one that names the address, checks
//      no name under `verify-ca`, and builds no hook of its own.
//
// WHY IN PROCESS (tests/CLAUDE.md's first question): every case chooses how
// the process was started — which file, which setting — and none needs a
// database. What is asserted of the driver is what `pg` is given, and E
// is a TLS handshake against a socket this file opens. A real handshake
// against the compose stack's certificate through the shared file is every
// postgres mode of `run-tests.sh`, which cannot start otherwise. The
// stack's refusal of its own bridge address is
// `tests/protocol/sts_persistence_postgres.js`.
//
// The certificate is MADE HERE, at run time (no key material in git), with
// the service's own `common/crypto.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const storeDouble = require('./tools/store_double');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');
const workerThreads = require('worker_threads');

const persistence = require('../persistence/persistence');
const postgres = require('../persistence/persistence_postgres');
const stsCrypto = require('../common/crypto');

const log = require('bunyan').createLogger({ name: 'database_tls_ca',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// Every setting this file moves is restart-only, so it moves through the
// environment, which `config.value()` reads on every call.
const VARS = ['STS_DATABASE_TLS_REJECT_UNAUTHORIZED',
              'STS_DATABASE_TLS_CA_FILE', 'STS_DATABASE_URL',
              'STS_DATABASE_PASSWORD_PROVIDER'];

function withEnvironment(values, fn) {
  log.debug("Entering withEnvironment().");
  const before = {};
  VARS.forEach(function (name) {
    before[name] = process.env[name];
    delete process.env[name];
  });
  Object.keys(values).forEach(function (name) {
    process.env[name] = values[name];
  });
  log.debug("Leaving withEnvironment().");
  return Promise.resolve()
    .then(fn)
    .finally(function () {
      VARS.forEach(function (name) {
        if (before[name] === undefined) {
          delete process.env[name];
        } else {
          process.env[name] = before[name];
        }
      });
    });
}

// What a call threw, or a promise rejected with, as text; '' when it did not.
async function refusalOf(fn) {
  log.debug("Entering refusalOf().");
  try {
    await fn();
  } catch (e) {
    log.debug("Caught in refusalOf(): " + ((e && e.message) || e));
    log.debug("Leaving refusalOf(). Refused.");
    return String((e && e.message) || e);
  }
  log.debug("Leaving refusalOf(). Did not refuse.");
  return '';
}

// A driver over a stand-in `pg`, for what it hands the bridge; nothing is
// dialled.
function driverWith(url, tlsCa) {
  log.debug("Entering driverWith().");
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.query = function () {
    return Promise.resolve({ rows: [], rowCount: 0 });
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  const restore = storeDouble.install({ Pool: FakePool,
                                        Client: function () {} });
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({ url: url, log: QUIET, verifyTls: true,
                             tlsCa: tlsCa });
  } finally {
    restore();
  }
}

// What the hook reports for one presented name, with `tls.checkServerIdentity`
// standing in: an error when it is asked about `expect`, and success for any
// other name. That is the old bug — `localhost` would have been a success.
function forwardedHost(dial, presented, expect) {
  log.debug("Entering forwardedHost().");
  const seen = [];
  const previous = tls.checkServerIdentity;
  tls.checkServerIdentity = function (host) {
    seen.push(String(host));
    if (String(host) === expect) {
      return Object.assign(new Error('checked ' + host), {
        code: 'ERR_TLS_CERT_ALTNAME_INVALID'
      });
    }
    return undefined;
  };
  let result = null;
  try {
    result = dial.ssl.checkServerIdentity(presented, {});
  } finally {
    tls.checkServerIdentity = previous;
  }
  log.debug("Leaving forwardedHost().");
  return { seen: seen, result: result };
}

// One STARTTLS exchange and what `pg` said about it. '' when the client
// connected. A name that matched is followed by the startup message, which
// the stand-in drops, so the client reports a terminated connection. pg's
// own connection timeout is unref'd: without the timer here a dropped
// handshake empties the event loop while connect() is still pending.
//
// With `viaThread` the dialler is the DIRECTORY BRIDGE'S THREAD itself
// (#951's review): the compiled `common/sync_query_thread.js` in a Worker,
// handed what the driver's `bridgeConnection()` posts — after structured
// cloning, as a Worker's data is — and asked one question over its port,
// asynchronously, so this thread keeps serving the stand-in. What it
// answers is what `pg` said in the thread.
async function dialOutcome(host, sslmode, pem, certPem, keyPem, viaThread) {
  log.debug("Entering dialOutcome().");
  const server = net.createServer();
  let port = 0;
  try {
    port = await new Promise(function (resolve, reject) {
      function failed(e) {
        log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
        reject(e);
      }
      server.once('error', failed);
      server.listen(0, '127.0.0.1', function () {
        server.removeListener('error', failed);
        resolve(server.address().port);
      });
    });
  } catch (e) {
    log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
    log.debug("Leaving dialOutcome(). Not listening.");
    throw e;
  }
  server.on('error', function (e) {
    log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
  });
  const sockets = [];
  let client = null;
  let thread = null;
  const message = await new Promise(function (resolve) {
    let done = false;
    let sawHandshake = false;
    let timer = null;
    function finish(text) {
      if (done) {
        return;
      }
      done = true;
      clearTimeout(timer);
      sockets.forEach(function (socket) {
        try {
          socket.destroy();
        } catch (err) {
          log.debug("Caught in dialOutcome(): " +
                    ((err && err.message) || err));
        }
      });
      resolve(text);
    }
    timer = setTimeout(function () {
      finish(sawHandshake ? '' : 'timed out before a TLS result');
    }, 5000);
    server.on('connection', function (socket) {
      sockets.push(socket);
      socket.on('error', function (e) {
        log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
      });
      socket.once('data', function () {
        const secure = new tls.TLSSocket(socket, {
          isServer: true, cert: certPem, key: keyPem
        });
        secure.on('error', function (e) {
          // The client closing on a refused name, which is the result.
          log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
        });
        secure.on('secure', function () {
          sawHandshake = true;
        });
        // The startup message is sent only after the handshake, so this
        // byte means the name was accepted. Dropping it is the report.
        secure.once('data', function () {
          sawHandshake = true;
          secure.destroy();
        });
        socket.write('S');
      });
    });
    const target = 'postgres://sts@' + host + ':' + port + '/sts?sslmode=' +
      sslmode;
    if (viaThread) {
      thread = bridgeThread(driverWith(target, pem).bridgeConnection(),
                            finish);
      return;
    }
    const dial = postgres.dialOptions(target, true, pem);
    // Through the store's own door (#326): nothing in this tree requires
    // `pg` itself, which tests/knex_store.js A1 holds.
    client = require('../persistence/knex_store').openConnection({
      connectionString: dial.connectionString,
      ssl: dial.ssl,
      connectionTimeoutMillis: 4000
    });
    client.on('error', function (e) {
      log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
    });
    client.connect().then(function () {
      finish('');
    }, function (e) {
      log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
      finish(String((e && e.message) || e));
    });
  });
  if (thread) {
    await thread.terminate().catch(function (e) {
      log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
    });
  }
  if (client) {
    try {
      client.end().catch(function (e) {
        log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
      });
    } catch (e) {
      log.debug("Caught in dialOutcome(): " + ((e && e.message) || e));
    }
  }
  await new Promise(function (resolve) {
    const closeTimer = setTimeout(function () {
      server.unref();
      resolve();
    }, 500);
    server.close(function () {
      clearTimeout(closeTimer);
      resolve();
    });
  });
  log.debug("Leaving dialOutcome().");
  return message;
}

// Starts the bridge's thread over `connection` (what `bridgeConnection()`
// posts) and asks it one question; `finish` gets '' when it was answered and
// the thread's error message otherwise. The statement is never run: the
// stand-in drops the connection after the handshake.
function bridgeThread(connection, finish) {
  log.debug("Entering bridgeThread().");
  const channel = new workerThreads.MessageChannel();
  const worker = new workerThreads.Worker(
    path.join(__dirname, '..', 'common', 'sync_query_thread.js'), {
      workerData: { counter: new SharedArrayBuffer(4), port: channel.port2,
                    connection: structuredClone(connection),
                    backend: null },
      transferList: [channel.port2]
    });
  worker.on('error', function (e) {
    log.debug("Caught in bridgeThread(): " + ((e && e.message) || e));
    finish('the thread failed: ' + String((e && e.message) || e));
  });
  channel.port1.on('message', function (answer) {
    channel.port1.close();
    finish(answer && answer.ok ? ''
      : String((answer && answer.error && answer.error.message) || answer));
  });
  channel.port1.postMessage({ id: 1, name: 'byKeys',
                             args: ['', ['cn=nobody']] });
  log.debug("Leaving bridgeThread().");
  return worker;
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-db-tls-ca-'));
  const made = stsCrypto.selfSignedRsaCertificate({ commonName: 'postgres' });
  const caFile = path.join(dir, 'server.crt');
  const keyFile = path.join(dir, 'server.key');
  fs.writeFileSync(caFile, made.certPem);
  fs.writeFileSync(keyFile, made.privateKeyPem, { mode: 0o600 });
  const url = 'postgres://sts_app@postgres:5432/sts?sslmode=require';

  try {
    // -------------------------------------------------------------------
    // A. THE DEFAULT IS ON.
    // -------------------------------------------------------------------
    await withEnvironment({}, async function () {
      t.equal(persistence.verifiesDatabaseTls(), true,
              'A. with nothing set, the database server\'s certificate is ' +
              'verified (persistence.databaseTlsRejectUnauthorized ' +
              'defaults to true, in every mode)');
      t.equal(persistence.databaseTlsCa(), '',
              'and with persistence.databaseTlsCaFile empty there are no ' +
              'trust anchors of the database\'s own');
      const dial = postgres.dialOptions(
        'postgres://db/sts?sslmode=require', persistence.verifiesDatabaseTls(),
        persistence.databaseTlsCa());
      t.check(dial.verifyChain && dial.verifyHostname &&
              dial.ssl.rejectUnauthorized === true && !('ca' in dial.ssl),
              'so require verifies the chain and the host name against ' +
              'the default trust store', JSON.stringify(dial.ssl));
    });

    // -------------------------------------------------------------------
    // B. THE CA FILE IS APPLIED.
    // -------------------------------------------------------------------
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: caFile,
                            STS_DATABASE_URL: url },
    async function () {
      const pem = persistence.databaseTlsCa();
      t.check(/-----BEGIN CERTIFICATE-----/.test(pem) &&
              pem.indexOf(made.certB64.slice(0, 64)) >= 0,
              'B. databaseTlsCa() answers the certificate the file holds');
      const dial = postgres.dialOptions(url, true, pem);
      t.check(dial.ssl.ca === pem && dial.ssl.rejectUnauthorized === true,
              'dialOptions() puts it on the ssl option as ca, in place of ' +
              'the default trust store for that connection');
      const full = postgres.dialOptions(
        'postgres://postgres/sts?sslmode=verify-full', false, pem);
      t.check(full.ssl.ca === pem && full.verifyHostname === true,
              'and for verify-full too, the mode the compose stack dials');
      const bridged = driverWith(url, pem).bridgeConnection();
      t.check(bridged.ssl && bridged.ssl.ca === pem &&
              bridged.ssl.checkHost === 'postgres' &&
              bridged.ssl.checkServerIdentity === undefined,
              'a driver built with it hands the certificate and the host ' +
              'to the directory bridge as data (#951)');
      const caBridged = driverWith(
        'postgres://sts_app@postgres:5432/sts?sslmode=verify-ca', pem)
        .bridgeConnection();
      let cloned = null;
      try {
        cloned = structuredClone(caBridged);
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
      }
      t.check(cloned && cloned.ssl && cloned.ssl.ca === pem &&
              cloned.ssl.hostnameUnchecked === true,
              'and for verify-ca, whose options are rewritten as data for ' +
              'the thread, the trust anchors survive the rewrite and ' +
              'structured cloning', JSON.stringify(caBridged &&
                caBridged.ssl && Object.keys(caBridged.ssl)));
      const connection = await persistence.databaseConnection();
      t.equal(connection.tlsCa, pem,
              'databaseConnection() hands them to a process that is not ' +
              'the service (the risk loader, cell_convert)');
      t.equal(connection.verifyTls, true, 'with verifyTls: true');
    });
    const shared = path.join(dir, 'shared');
    const other = stsCrypto.selfSignedRsaCertificate({
      commonName: 'postgres-global' });
    fs.mkdirSync(shared);
    fs.writeFileSync(path.join(shared, 'postgres.crt'), made.certPem);
    fs.writeFileSync(path.join(shared, 'postgres-global.crt'), other.certPem);
    fs.writeFileSync(path.join(shared, '.postgres-cellb.crt.tmp'),
                     'half a certificate');
    fs.writeFileSync(path.join(shared, 'README'), 'not a certificate');
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: shared },
    async function () {
      const pem = persistence.databaseTlsCa();
      t.check(pem.indexOf(made.certB64.slice(0, 64)) >= 0 &&
              pem.indexOf(other.certB64.slice(0, 64)) >= 0 &&
              (pem.match(/-----BEGIN CERTIFICATE-----/g) || []).length === 2,
              'a directory is read: both databases\' certificates, and ' +
              'neither the hidden temporary file nor the README');
    });

    // -------------------------------------------------------------------
    // C. A FILE NAMED AND UNUSABLE IS REFUSED, STS-STORE-0079.
    // -------------------------------------------------------------------
    const missing = path.join(dir, 'no-such.crt');
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: missing,
                            STS_DATABASE_URL: url },
    async function () {
      const why = await refusalOf(function () {
        return persistence.databaseTlsCa();
      });
      t.check(/\[STS-STORE-0079\]/.test(why) && why.indexOf(missing) >= 0,
              'C. a file that does not exist is refused under ' +
              'STS-STORE-0079, naming it', why);
      const rejected = await refusalOf(function () {
        return persistence.databaseConnection();
      });
      t.check(/\[STS-STORE-0079\]/.test(rejected),
              'and databaseConnection() rejects with it, so a tool does ' +
              'not dial with a trust anchor nobody chose', rejected);
    });
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: keyFile,
                            STS_DATABASE_URL: url },
    async function () {
      const why = await refusalOf(function () {
        return persistence.databaseTlsCa();
      });
      t.check(/\[STS-STORE-0079\]/.test(why) &&
              /holds no PEM certificate/.test(why),
              'a file holding no certificate (a private key named by ' +
              'mistake) is refused under STS-STORE-0079 too', why);
    });
    const empty = path.join(dir, 'empty');
    fs.mkdirSync(empty);
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: empty },
    async function () {
      const why = await refusalOf(function () {
        return persistence.databaseTlsCa();
      });
      t.check(/\[STS-STORE-0079\]/.test(why),
              'and so is a directory with no certificate in it', why);
    });

    // -------------------------------------------------------------------
    // D. AN ADDRESS IS THE NAME THAT IS CHECKED (#951).
    // -------------------------------------------------------------------
    const address = '10.9.8.7';
    const byAddress = postgres.dialOptions(
      'postgres://sts_app@' + address + ':5432/sts?sslmode=require',
      true, '');
    const refused = forwardedHost(byAddress, 'localhost', address);
    t.check(refused.seen.length === 1 && refused.seen[0] === address &&
            refused.result &&
            refused.result.code === 'ERR_TLS_CERT_ALTNAME_INVALID',
            'D. a database dialled by address is checked against that ' +
            'address. localhost, which is the name pg leaves node, would ' +
            'have been accepted', JSON.stringify(refused.seen));
    const byName = postgres.dialOptions(
      'postgres://sts@postgres.example:5432/sts?sslmode=verify-full',
      false, '');
    const named = forwardedHost(byName, 'localhost', 'postgres.example');
    t.check(named.seen.length === 1 &&
            named.seen[0] === 'postgres.example' &&
            named.result &&
            named.result.code === 'ERR_TLS_CERT_ALTNAME_INVALID',
            'and a DNS name is checked as that name, with the setting off');
    const v6 = postgres.dialOptions(
      'postgres://sts@[2001:db8::1]:5432/sts?sslmode=require', true, '');
    t.equal(v6.ssl.checkHost, '2001:db8::1',
            'an IPv6 address is the host, without brackets');
    const caOnly = postgres.dialOptions(
      'postgres://sts@' + address + '/sts?sslmode=verify-ca', false, '');
    const previous = tls.checkServerIdentity;
    let caCalls = 0;
    tls.checkServerIdentity = function () {
      caCalls += 1;
      return new Error('should not have been asked');
    };
    let caResult = null;
    try {
      caResult = caOnly.ssl.checkServerIdentity('localhost', {});
    } finally {
      tls.checkServerIdentity = previous;
    }
    t.check(caResult === undefined && caCalls === 0 &&
            caOnly.ssl.checkHost === undefined,
            'verify-ca still does not check the host, address or not');
    const posted = driverWith(
      'postgres://sts_app@' + address + ':5432/sts?sslmode=require',
      made.certPem).bridgeConnection();
    let cloned = null;
    try {
      cloned = structuredClone(posted);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
    t.check(cloned && cloned.ssl && cloned.ssl.checkHost === address &&
            cloned.ssl.ca === made.certPem &&
            cloned.ssl.checkServerIdentity === undefined &&
            cloned.ssl.hostnameUnchecked !== true &&
            cloned.ssl.stsOutboundVariant === 'store',
            'the bridge is handed the address as data, with the trust ' +
            'anchors and the store variant, and nothing a thread cannot ' +
            'be posted', JSON.stringify(posted && posted.ssl &&
              Object.keys(posted.ssl)));

    // -------------------------------------------------------------------
    // E. pg USES THE HOOK. A certificate naming only localhost.
    // -------------------------------------------------------------------
    const serverExtensions = function (altNames) {
      log.debug("Entering serverExtensions().");
      log.debug("Leaving serverExtensions().");
      return [
        { name: 'basicConstraints', cA: false, critical: true },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true,
          critical: true },
        { name: 'extKeyUsage', serverAuth: true },
        { name: 'subjectAltName', altNames: altNames }
      ];
    };
    const localhostOnly = stsCrypto.selfSignedRsaCertificate({
      commonName: 'postgres',
      extensions: serverExtensions([{ type: 2, value: 'localhost' }])
    });
    const byIp = await dialOutcome('127.0.0.1', 'require',
      localhostOnly.certPem, localhostOnly.certPem,
      localhostOnly.privateKeyPem);
    t.check(/altname|does not match/i.test(byIp),
            'E. pg, dialling 127.0.0.1, refuses a certificate that names ' +
            'only localhost (#951)', byIp);
    const withAddress = stsCrypto.selfSignedRsaCertificate({
      commonName: 'postgres',
      rsaPrivateKeyPem: localhostOnly.privateKeyPem,
      extensions: serverExtensions([{ type: 2, value: 'localhost' },
                                    { type: 7, ip: '127.0.0.1' }])
    });
    const accepted = await dialOutcome('127.0.0.1', 'require',
      withAddress.certPem, withAddress.certPem, withAddress.privateKeyPem);
    t.check((accepted === '' ||
             /terminated|ECONNRESET|closed|hang up/i.test(accepted)) &&
            !/altname|self-signed|unable to verify/i.test(accepted),
            'and accepts 127.0.0.1 when the certificate names that address ' +
            '(the stand-in then drops the socket)', accepted);
    const chainOnly = await dialOutcome('127.0.0.1', 'verify-ca',
      localhostOnly.certPem, localhostOnly.certPem,
      localhostOnly.privateKeyPem);
    t.check((chainOnly === '' ||
             /terminated|ECONNRESET|closed|hang up/i.test(chainOnly)) &&
            !/altname|self-signed|unable to verify/i.test(chainOnly),
            'verify-ca still accepts that certificate for the address: ' +
            'the chain, and no host name', chainOnly);

    // -------------------------------------------------------------------
    // F. THE BRIDGE'S THREAD DIALS WITH THE SAME CHECK (#951's review).
    // The real thread, handed what the driver posts. The refusal's
    // sentence is `outbound_tls`'s (RFC 9525: no common name), not
    // node's own, so the check that ran is the one that goes on to hold
    // the chain to the path rules.
    // -------------------------------------------------------------------
    const threadByIp = await dialOutcome('127.0.0.1', 'require',
      localhostOnly.certPem, localhostOnly.certPem,
      localhostOnly.privateKeyPem, true);
    t.check(/127\.0\.0\.1 is not in the certificate's subjectAltName/
              .test(threadByIp) && /RFC 9525/.test(threadByIp),
            'F. the bridge\'s thread, dialling 127.0.0.1, refuses a ' +
            'certificate that names only localhost, through outbound_tls\'s ' +
            'check (RFC 9525 and the path rules) against the address',
            threadByIp);
    const threadAccepted = await dialOutcome('127.0.0.1', 'require',
      withAddress.certPem, withAddress.certPem, withAddress.privateKeyPem,
      true);
    t.check(!/altname|subjectAltName|self-signed|unable to verify|path|timed out|the thread failed/i
              .test(threadAccepted),
            'and accepts the certificate that names the address (the ' +
            'stand-in then drops the socket)', threadAccepted);
    const threadChainOnly = await dialOutcome('127.0.0.1', 'verify-ca',
      localhostOnly.certPem, localhostOnly.certPem,
      localhostOnly.privateKeyPem, true);
    t.check(!/altname|subjectAltName|self-signed|unable to verify|timed out|the thread failed/i
              .test(threadChainOnly),
            'and under verify-ca checks the chain and no name, as the ' +
            'pools do', threadChainOnly);
    const threadSource = fs.readFileSync(path.join(__dirname, '..',
      'common', 'sync_query_thread.ts'), 'utf8');
    t.check(/knexStore\.restoredSsl\(/.test(threadSource) &&
            !/checkServerIdentity\s*=/.test(threadSource) &&
            !/tls\.checkServerIdentity\(/.test(threadSource),
            'and builds no hook of its own: knex_store.restoredSsl() is ' +
            'the inverse of what bridgeConnection() posts');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'database_tls_ca',
  describe: 'the database certificate is verified by default, ' +
            'persistence.databaseTlsCaFile is applied to every dialler ' +
            '(the pools, the bridge\'s thread, the out-of-process tools), ' +
            'a file named and unusable is refused under STS-STORE-0079, ' +
            'and an address in the connection string is the name checked',
  run: run
};
