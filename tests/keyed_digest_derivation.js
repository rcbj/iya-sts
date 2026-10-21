// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: keyed_digest_derivation.js
//
// ===========================================================================
// A KEYED DIGEST DERIVES ITS KEY ONCE PER LABEL, AND THE SAME DIGEST COMES
// OUT (#760).
//
// `keystore.keyedDigest()` ran HKDF on every call, and under a sign-in load
// on 8081 that was about 5% of a request worker (the minted store's
// `keyColumnOf()` asks it for every row). The derived key is kept per label
// beside the key it came from, which is compared on every call.
//
//   D1. the digest is HMAC-SHA-256 under HKDF(KEK, "sts-keyed-digest:" +
//       label), computed here by hand: the same digest as before #760;
//   D2. fifty digests under one label derive the key once;
//   D3. a different label is a different key;
//   D4. a new key-encryption key is seen at once: the digest is the new
//       key's, and the old key is not used again;
//   D5. `reset()` drops every derived key.
//
// In a child process, because the keystore is module-wide and a KEK set
// here must not outlive this file (tests/CLAUDE.md).
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'keyed_digest_derivation',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: drives the keystore and reports what it found.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.KD_ROOT;
  const OUT = process.env.KD_OUT;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    const keystore = require(ROOT_DIR + '/common/keystore');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const cacheRegistry = require(ROOT_DIR + '/common/cache_registry');
    const counts = function () {
      const d = cacheRegistry.detail('keys.derived-digest-keys');
      const s = (d && d.summary) || {};
      return { hits: Number(s.hits || 0), misses: Number(s.misses || 0),
               rows: d ? d.rows.length : -1 };
    };
    const byHand = function (hex, label, text) {
      const ikm = stsCrypto.kekBytes(hex);
      const key = Buffer.from(nodeCrypto.hkdfSync('sha256', ikm,
        Buffer.alloc(0), Buffer.from('sts-keyed-digest:' + label, 'utf8'),
        32));
      return nodeCrypto.createHmac('sha256', key).update(String(text))
        .digest('base64url');
    };
    const A = nodeCrypto.randomBytes(32).toString('hex');
    const B = nodeCrypto.randomBytes(32).toString('hex');

    keystore.reset();
    note(keystore.useEphemeralKek(A), 'D0. an ephemeral KEK is taken');
    const first = keystore.keyedDigest('test-label', 'carol');
    note(first === byHand(A, 'test-label', 'carol'),
         'D1. the digest is HMAC-SHA-256 under HKDF(KEK, label): the same ' +
         'digest as before #760', first);

    const before = counts();
    for (let i = 0; i < 50; i++) {
      keystore.keyedDigest('test-label', 'carol-' + i);
    }
    const after = counts();
    note(after.misses === before.misses && after.hits === before.hits + 50,
         'D2. fifty digests under one label derive the key once',
         JSON.stringify([before, after]));
    note(keystore.keyedDigest('other-label', 'carol') ===
           byHand(A, 'other-label', 'carol') &&
         keystore.keyedDigest('other-label', 'carol') !== first,
         'D3. a different label is a different key');

    keystore.reset();
    note(counts().rows === 0, 'D5. reset() drops every derived key',
         counts().rows);
    note(keystore.useEphemeralKek(B), 'D4a. a new KEK is taken');
    const second = keystore.keyedDigest('test-label', 'carol');
    note(second === byHand(B, 'test-label', 'carol') && second !== first,
         'D4. the new KEK is seen at once: the digest is the new key\'s',
         second);
    keystore.useEphemeralKek(A);
    note(keystore.keyedDigest('test-label', 'carol') === first,
         'D4b. and back under the first KEK, the first digest again');
  } catch (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }
  fs.writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'kd-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  KD_ROOT: ROOT, KD_OUT: out }),
      encoding: 'utf8', timeout: 120000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'keyed_digest_derivation',
  describe: 'a keyed digest derives its key once per label and gives the ' +
            'same digest (#760): kept beside the key it came from, a new ' +
            'KEK seen at once',
  run: run
};
