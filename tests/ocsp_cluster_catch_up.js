// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ocsp_cluster_catch_up.js
//
// ===========================================================================
// THE PROCESS AUTHORITY'S OCSP RESPONDER ANSWERS FOR EVERY NODE'S LISTENER
// (#162, 2026-10-05).
//
// rcbj's decision on #162: the process branch is ONE authority for the
// cluster, every node signs its own listener certificate under it, and no
// node's own address is ever published — so whichever node a balancer picks
// must answer for a certificate another node issued a moment ago. The store
// already holds every serial (`pki_merge.js` keeps a displaced slot's serial
// in `issuedKeyPairs`); what failed was a node answering `unknown` before the
// change log had brought that row to it (`sts_pki_distribution_points`,
// cluster mode, seconds after the stack started).
//
// `pki_revocation.js`'s `answerOcsp()` now asks the store once before it says
// `unknown` for want of a record. **WHY IN PROCESS**: "another node wrote the
// row and this one has not caught up" is a window of up to
// `persistence.pollInterval` between two containers, which no request over
// HTTP can hold open on purpose. Here `pki.refreshScope()` — the one door the
// responder reads the store through — is replaced by a stand-in that does
// what an adoption of the other node's row does: it puts the merge's
// displaced record on the row this process holds.
//
// The four claims, each with its negative:
//
//   A. a serial the store does not hold either is still `unknown`, after ONE
//      read of the store — the catch-up widens nothing;
//   B. a serial the store holds and this process did not is `good`, after ONE
//      read;
//   C. a serial already held asks the store NOTHING;
//   D. concurrent questions share ONE read of the row in flight, because the
//      responder is anonymous and every serial nobody issued takes this path.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');
const { execFileSync } = require('child_process');

const pki = require('../common/pki');
const pkiMerge = require('../common/pki_merge');
const revocation = require('../common/pki_revocation');
const keystore = require('../common/keystore');
const helpers = require('../common/helpers');

const log = require('bunyan').createLogger({ name: 'ocsp_cluster_catch_up',
  level: process.env.LOG_LEVEL || 'info' });

let scratch = '';

// Built by OpenSSL rather than pkijs, for `tests/pki_revocation.js`'s reason:
// a pkijs request is this implementation agreeing with itself, and
// `toSchema(true)` sends its cached TBS bytes whatever serial was set after.
function ocspRequestFor(issuerPem, serialHex) {
  log.debug("Entering ocspRequestFor().");
  const issuerFile = path.join(scratch, 'issuer.pem');
  const out = path.join(scratch, 'req-' + serialHex + '.der');
  fs.writeFileSync(issuerFile, issuerPem);
  execFileSync('openssl', ['ocsp', '-no_nonce', '-issuer', issuerFile,
                           '-serial', '0x' + serialHex, '-reqout', out],
               { stdio: 'pipe' });
  log.debug("Leaving ocspRequestFor().");
  return fs.readFileSync(out);
}

function statusOf(answer) {
  log.debug("Entering statusOf().");
  log.debug("Leaving statusOf().");
  return ((answer && answer.answers) || [])[0]
    ? answer.answers[0].status : '';
}

// A serial no authority here has issued: sixteen random octets with the high
// bit clear, so it is a positive INTEGER in any spelling.
function freshSerial() {
  log.debug("Entering freshSerial().");
  const bytes = nodeCrypto.randomBytes(16);
  bytes[0] = (bytes[0] & 0x7f) | 0x10;
  log.debug("Leaving freshSerial().");
  return bytes.toString('hex');
}

// What adopting the other node's row puts on this one: the merge's own
// displaced record for the `tls:server` slot (`pki_merge.displacedRecord()`),
// on a copy of the row, attached as the keystore attaches an adopted row.
function adoptOtherNodesListener(serialHex) {
  log.debug("Entering adoptOtherNodesListener().");
  const row = JSON.parse(JSON.stringify(pki.rawRowFor(pki.PROCESS_SCOPE)));
  row.issuedKeyPairs = (row.issuedKeyPairs || []).concat([
    pkiMerge.displacedRecord('tls:server', {
      serialHex: serialHex,
      subject: 'CN=sts-lb, O=sts',
      notAfter: new Date(Date.now() + 86400000).toISOString(),
      useCase: 'tls',
      createdAt: Date.now()
    })
  ]);
  keystore.attachPki(pki.PROCESS_SCOPE, row);
  log.debug("Leaving adoptOtherNodesListener().");
}

async function run(t) {
  log.debug("Entering run().");
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-ocsp-catch-up-'));
  await keystore.start();
  const started = await pki.start({
    realmIds: [''],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    }
  });
  t.check(started.ok, 'the hierarchy is built',
          JSON.stringify(started.errors || []));
  const row = pki.rawRowFor(pki.PROCESS_SCOPE);
  const tls = row && row.issuing && row.issuing.tls;
  t.check(!!(tls && tls.certificatePem),
          'the process branch has its TLS Issuing CA');
  if (!tls || !tls.certificatePem) {
    log.debug("Leaving run(). No TLS Issuing CA.");
    return;
  }
  const issuerPem = tls.certificatePem;
  // `run.js` runs every file in one process, so the row this file adds a
  // record to is put back as it was found.
  const rowBefore = JSON.parse(JSON.stringify(row));

  const realRefresh = pki.refreshScope;
  let reads = 0;
  let onRead = function () {
    return null;
  };
  pki.refreshScope = function (scopeId) {
    log.debug("Entering refreshScope() stand-in.");
    reads += 1;
    t.equal(String(scopeId), pki.PROCESS_SCOPE,
            'the store is asked about the scope the request named');
    log.debug("Leaving refreshScope() stand-in.");
    return Promise.resolve().then(function () {
      return onRead();
    });
  };
  try {
    t.log.info('=== A. a serial nobody issued stays unknown ===');
    const stranger = freshSerial();
    reads = 0;
    let answer = await revocation.answerOcsp(
      pki.PROCESS_SCOPE, 'tls', ocspRequestFor(issuerPem, stranger));
    t.equal(statusOf(answer), 'unknown',
            'a serial neither this process nor the store holds is unknown — ' +
            'asking the store made the responder vouch for nothing more');
    t.equal(reads, 1, 'and the store was asked exactly once before saying so');

    t.log.info('=== B. another node\'s listener, written a moment ago ===');
    const otherNode = freshSerial();
    reads = 0;
    onRead = function () {
      adoptOtherNodesListener(otherNode);
      return { kind: 'pki', adopted: true };
    };
    answer = await revocation.answerOcsp(
      pki.PROCESS_SCOPE, 'tls', ocspRequestFor(issuerPem, otherNode));
    t.equal(statusOf(answer), 'good',
            'a listener certificate another node issued under the shared ' +
            'process authority is good from THIS node, once the store has ' +
            'been read — not unknown because this node had not caught up');
    t.equal(reads, 1, 'after one read of the store');

    t.log.info('=== C. a serial already held costs no read ===');
    reads = 0;
    onRead = function () {
      return null;
    };
    answer = await revocation.answerOcsp(
      pki.PROCESS_SCOPE, 'tls', ocspRequestFor(issuerPem, otherNode));
    t.equal(statusOf(answer), 'good', 'the same serial is still good');
    t.equal(reads, 0, 'and answering it asked the store nothing');

    t.log.info('=== D. concurrent questions share one read ===');
    const requests = [0, 1, 2, 3, 4].map(function () {
      return ocspRequestFor(issuerPem, freshSerial());
    });
    reads = 0;
    let release = null;
    const gate = new Promise(function (resolve) {
      release = resolve;
    });
    onRead = function () {
      return gate;
    };
    const asked = requests.map(function (der) {
      return revocation.answerOcsp(pki.PROCESS_SCOPE, 'tls', der);
    });
    // Hold the read open long enough for every request to reach the store.
    // Each request first computes the CertID's digests through SubtleCrypto
    // (several turns of the loop), so one `setImmediate` released the read
    // before the later requests arrived: they then asked one after another,
    // which is sequential and not the case under test.
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
    t.equal(reads, 1,
            'while one read is in flight, the other questions wait on it ' +
            'rather than starting their own');
    release(null);
    const answers = await Promise.all(asked);
    t.check(answers.every(function (one) {
      return statusOf(one) === 'unknown';
    }), 'five strangers asked at once are all unknown');
    t.equal(reads, 1,
            'and they shared ONE read of the row, so an anonymous flood of ' +
            'made-up serials is one store read at a time, not one each');
  } finally {
    pki.refreshScope = realRefresh;
    keystore.attachPki(pki.PROCESS_SCOPE, rowBefore);
    try {
      fs.rmSync(scratch, { recursive: true, force: true });
    } catch (e) {
      // A few hundred bytes of DER in the OS temp space; never a failure.
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ocsp_cluster_catch_up',
  describe: 'the process authority answers OCSP for every node\'s listener ' +
            '(#162): a serial this process has not caught up on is asked ' +
            'of the store once, a stranger stays unknown, a held serial ' +
            'asks nothing, and concurrent questions share one read',
  run: run
};
