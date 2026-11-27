// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: client_ca_names.js
//
// ===========================================================================
// THE LISTENERS NAME EVERY ISSUER OF A CLIENT CERTIFICATE (#2292).
//
// A YubiKey holding a piv-auth leaf from a realm's EST Issuing CA signed
// nobody in to the portal from Firefox: the card holds the leaf alone, the
// main port named only `iya-sts Root CA` in its CertificateRequest, and
// Firefox (NSS's FilterPotentialClientCertificatesByCANames) dropped the
// certificate as matching no name. Since #2292 the client truststore holds
// every built realm's Intermediate and its client Issuing CAs beside the
// Root (`tls_client_certificates.issuerPems()`), so node names each, and a
// leaf sent with no chain verifies, because the server holds its issuers.
//
// In a child process, over real handshakes on a listener built with the
// main port's posture and registered as server.js registers it:
//
//   A. THE NAMES: the CertificateRequest `openssl s_client` reads names the
//      Root, each realm's Intermediate and its TLS client and EST Issuing
//      CAs, and nothing the hierarchy does not hold.
//   B. A LEAF ALONE VERIFIES: a person's certificate presented with no
//      chain is `authorized`, as a smart card presents it.
//   C. IT TRUSTS NOTHING MORE: a leaf from an outside CA still does not
//      verify, and with tls.trustIssuedClientCertificates off no issuer is
//      named at all.
//   D. A REALM BUILT LATER IS NAMED WITHOUT A RESTART: its branch, once
//      built, reaches the registered listener through the keystore's
//      observer.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeTls = require('tls');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_CLIENT_CA_NAMES_CHILD';
const REALM = 'canames';
const LATER = 'canameslater';
const PERSON = 'canames-alice';

// What the last `openssl s_client` printed, for a failure's detail.
const LAST_SCLIENT = { value: '' };

const log = require('bunyan').createLogger({ name: 'client_ca_names',
  level: process.env.LOG_LEVEL || 'info' });

// The child cannot reach the parent's `t`, so it keeps every assertion and
// hands the list back.
function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

// The CA names a CertificateRequest from `port` carries, as openssl prints
// them, one per line. Asynchronous: the listener answers on this process's
// event loop, which a spawnSync would block.
function caNamesOf(port) {
  log.debug("Entering caNamesOf().");
  log.debug("Leaving caNamesOf().");
  return new Promise(function (resolve) {
    const child = childProcess.spawn('openssl', ['s_client', '-connect',
      '127.0.0.1:' + port, '-tls1_3'], { stdio: ['pipe', 'pipe', 'pipe'] });
    let text = '';
    let errText = '';
    child.stdout.on('data', function (chunk) {
      text += chunk;
    });
    child.stderr.on('data', function (chunk) {
      errText += chunk;
    });
    const timer = setTimeout(function () {
      child.kill();
    }, 20000);
    child.on('error', function (e) {
      log.debug("Caught in caNamesOf(): " + ((e && e.message) || e));
    });
    child.on('close', function () {
      clearTimeout(timer);
      LAST_SCLIENT.value = text.slice(0, 600) + ' ' + errText.slice(0, 300);
      const at = text.indexOf('Acceptable client certificate CA names');
      const names = [];
      if (at >= 0) {
        text.slice(at).split('\n').slice(1).some(function (line) {
          if (!/^(CN|O|C|OU)\s*=/.test(line.trim())) {
            return true;
          }
          names.push(line.trim());
          return false;
        });
      }
      resolve(names);
    });
    child.stdin.end();
  });
}

// Whether the listener verified the certificate a client presents with
// `cert` and `key`, read on the server's side of the handshake.
function verifiedOn(server, port, cert, key) {
  log.debug("Entering verifiedOn().");
  log.debug("Leaving verifiedOn().");
  return new Promise(function (resolve) {
    const seen = function (socket) {
      server.removeListener('secureConnection', seen);
      resolve({ authorized: socket.authorized,
                error: String(socket.authorizationError || '') });
      socket.destroy();
    };
    server.on('secureConnection', seen);
    const client = nodeTls.connect({ host: '127.0.0.1', port: port,
      cert: cert, key: key, rejectUnauthorized: false });
    client.on('error', function (e) {
      log.debug("Caught in verifiedOn(): " + ((e && e.message) || e));
    });
    client.on('secureConnect', function () {
      setTimeout(function () {
        client.destroy();
      }, 200);
    });
  });
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require('../common/protocol_stack');
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const tlsClient = require('../common/tls_client_certificates');
  const tls = require('../tls/tls_server');
  const ldap = require('../ldap/ldap_server');
  const testCa = require('./protocol/outbound_test_ca');

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  await pki.ensureScope(REALM);
  realms.run(realms.get(REALM), function () {
    ldap.createUser(PERSON, { invent: false });
  });
  const mine = await realms.run(realms.get(REALM), function () {
    return tlsClient.issue(undefined, { username: PERSON, keyAlg: 'ec-p256' });
  });
  t.check(mine.ok, 'setup: a person\'s TLS client certificate is issued in ' +
          'the realm', JSON.stringify(mine.errors));

  // The main port's posture over the client truststore, registered so a
  // truststore or hierarchy change re-applies it, its own certificate kept.
  const serverCa = await testCa.makeCa();
  const serverLeaf = await testCa.listenerCertificate(serverCa, '127.0.0.1');
  const server = nodeTls.createServer(Object.assign({
    cert: serverLeaf.cert, key: serverLeaf.key,
    ca: tls.clientTruststoreOptions().ca
  }, tls.clientAuthOptions('optional'), tls.protocolOptions()));
  tls.trustClientCertificatesOn(server, 'the client_ca_names listener',
    function () {
      log.debug("Entering the listener's certificateOf().");
      log.debug("Leaving the listener's certificateOf().");
      return { key: serverLeaf.key, cert: serverLeaf.cert };
    });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;

  try {
    // A. The names.
    const names = await caNamesOf(port);
    const has = function (cn) {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      // openssl prints `CN = x, O = y` or `CN=x, O=y` by version.
      return names.some(function (one) {
        const flat = one.replace(/\s*=\s*/g, '=');
        return flat.indexOf('CN=' + cn + ',') === 0 || flat === 'CN=' + cn;
      });
    };
    t.check(has('iya-sts Root CA'), 'A: the Root is named',
            JSON.stringify(names) + ' ' + LAST_SCLIENT.value);
    t.check(has('iya-sts Intermediate CA (default)') &&
            has('iya-sts Intermediate CA (' + REALM + ')'),
            'A: each built realm\'s Intermediate is named',
            JSON.stringify(names));
    t.check(has('iya-sts TLS Client Issuing CA (' + REALM + ')'),
            'A: the realm\'s TLS client Issuing CA is named',
            JSON.stringify(names));
    t.check(has('iya-sts EST Issuing CA (' + REALM + ')'),
            'A: the realm\'s EST Issuing CA is named (a piv-auth leaf\'s ' +
            'issuer)', JSON.stringify(names));
    t.check(names.every(function (one) {
      return /iya-sts/.test(one);
    }), 'A: nothing but this service\'s own authorities is named',
            JSON.stringify(names));

    // B. A leaf alone verifies.
    const alone = await verifiedOn(server, port,
      mine.issued.certificatePem, mine.issued.privateKeyPem);
    t.check(alone.authorized, 'B: a person\'s certificate presented with ' +
            'no chain verifies, as a smart card presents it',
            JSON.stringify(alone));

    // C. It trusts nothing more.
    const outsideCa = await testCa.makeCa();
    const outsideLeaf = await testCa.listenerCertificate(outsideCa,
                                                         'outside.example');
    const outside = await verifiedOn(server, port, outsideLeaf.cert,
                                     outsideLeaf.key);
    t.check(!outside.authorized, 'C: a leaf from an outside CA still does ' +
            'not verify', JSON.stringify(outside));
    t.check(tlsClient.issuerPems(false).length === 0, 'C: with the ' +
            'listener\'s trustIssuedClientCertificates off, no issuer is ' +
            'named');

    // D. A realm built later is named without a restart.
    if (!realms.get(LATER)) {
      realms.create({ id: LATER, name: LATER });
    }
    await pki.ensureScope(LATER);
    await new Promise(function (resolve) {
      setTimeout(resolve, 300);
    });
    const later = await caNamesOf(port);
    t.check(later.some(function (one) {
      return one.indexOf('Intermediate CA (' + LATER + ')') >= 0;
    }), 'D: a realm whose branch is built after the listener started is ' +
            'named on the next handshake', JSON.stringify(later));
  } finally {
    server.close();
  }
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 240000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('CLIENT-CA-NAMES-CHILD ') === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice('CLIENT-CA-NAMES-CHILD '.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the listeners name every issuer of a client ' +
             'certificate (#2292) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\nCLIENT-CA-NAMES-CHILD ' + JSON.stringify(rows) +
                         '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'client_ca_names',
  describe: 'The TLS listeners name the Root, every realm\'s Intermediate ' +
            'and its client Issuing CAs in the CertificateRequest, so a ' +
            'leaf presented alone verifies; an outside leaf still does ' +
            'not, and a realm built later is named without a restart',
  run: run
};
