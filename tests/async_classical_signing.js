// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: async_classical_signing.js
//
// ===========================================================================
// A CLASSICAL JWS SIGNATURE IS COMPUTED ON LIBUV'S THREAD POOL, OVER THE
// SIGNING INPUT THE SYNCHRONOUS DOOR BUILDS (#772).
//
// `crypto.signJwsAsync()` sent only post-quantum algorithms off the thread
// and signed RSA and ECDSA in place: about 6% of the two request workers on
// 8081, most of it the SETs the transmitter signs. It now signs those with
// node's asynchronous `crypto.sign()`, reproducing `jsonwebtoken`'s framing,
// and leaves to `signJws()` every call whose framing only the library can
// say.
//
//   A1. RS256, RS384, RS512 — deterministic — are BYTE FOR BYTE what
//       `signJws()` makes, with and without an `iat`, a `kid` and a `typ`;
//   A2. PS256/384/512, ES256/384/512, EdDSA and ES256K have the same header
//       and payload as `signJws()`'s and a signature that verifies;
//   B.  each of those is signed by `crypto.sign()` WITH A CALLBACK — the
//       asynchronous door, on libuv's pool — and never synchronously;
//   C.  a claim convenience (`expiresIn`), an `alg` in the header, an RSA key
//       under 2048 bits, a key of the wrong type and HS256 all go through
//       `signJws()` in place: the same token, or the same refusal.
//
// In a child process: it replaces `crypto.sign` to watch how it is called.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'async_classical_signing',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ACS_OUT;
  const ROOT = process.env.ACS_ROOT;
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  (async function () {
    const nodeCrypto = require('crypto');
    const jwt = require('jsonwebtoken');
    const stsCrypto = require(ROOT + '/common/crypto');
    const pair = function (type, opts) {
      return nodeCrypto.generateKeyPairSync(type, opts);
    };
    const rsa = pair('rsa', { modulusLength: 2048 });
    const weak = pair('rsa', { modulusLength: 1024 });
    const ec = { ES256: pair('ec', { namedCurve: 'P-256' }),
                 ES384: pair('ec', { namedCurve: 'P-384' }),
                 ES512: pair('ec', { namedCurve: 'P-521' }) };
    const ed = pair('ed25519');
    const k1 = pair('ec', { namedCurve: 'secp256k1' });
    const pem = function (k) {
      return k.privateKey.export({ type: 'pkcs8', format: 'pem' });
    };
    // How crypto.sign is called while `fn` runs: with a callback or not.
    const realSign = nodeCrypto.sign;
    const watch = async function (fn) {
      const calls = { async: 0, sync: 0 };
      nodeCrypto.sign = function () {
        if (typeof arguments[arguments.length - 1] === 'function') {
          calls.async++;
        } else {
          calls.sync++;
        }
        return realSign.apply(this, arguments);
      };
      try {
        const value = await fn();
        return { value: value, calls: calls };
      } catch (e) {
        return { error: (e && e.message) || String(e), calls: calls };
      } finally {
        nodeCrypto.sign = realSign;
      }
    };
    const segments = function (token) {
      return String(token).split('.').slice(0, 2).join('.');
    };
    const realNow = Date.now;
    const frozen = function (fn) {
      Date.now = function () {
        return 1760000000000;
      };
      try {
        return fn();
      } finally {
        Date.now = realNow;
      }
    };

    // --- A1 --------------------------------------------------------------
    const payloads = [
      { sub: 'a', aud: 'c', iat: 1700000000, exp: 1700000600 },
      { sub: 'b', nested: { x: [1, 2] } }
    ];
    const optionSets = [
      {},
      { keyid: 'key-1' },
      { keyid: 'key-2', header: { typ: 'secevent+jwt' } },
      { header: { typ: 'at+jwt', x5t: 'abc' } }
    ];
    const mismatches = [];
    let deterministic = 0;
    for (const alg of ['RS256', 'RS384', 'RS512']) {
      for (const payload of payloads) {
        for (const extra of optionSets) {
          const opts = Object.assign({ algorithm: alg }, extra);
          const syncToken = frozen(function () {
            return stsCrypto.signJws(payload, pem(rsa), opts);
          });
          Date.now = function () {
            return 1760000000000;
          };
          const asyncToken = await stsCrypto.signJwsAsync(payload, pem(rsa),
                                                          opts);
          Date.now = realNow;
          deterministic++;
          if (asyncToken !== syncToken) {
            mismatches.push(alg + ' ' + JSON.stringify(extra));
          }
        }
      }
    }
    note(mismatches.length === 0 && deterministic === 24,
         'A1. RS256, RS384 and RS512 are byte for byte what signJws() makes, ' +
         'with and without iat, kid and a typ (' + deterministic + ' tokens)',
         mismatches.join('; '));

    // --- A2 and B ----------------------------------------------------------
    const cases = [
      ['PS256', pem(rsa), rsa.publicKey], ['PS384', pem(rsa), rsa.publicKey],
      ['PS512', pem(rsa), rsa.publicKey],
      ['ES256', pem(ec.ES256), ec.ES256.publicKey],
      ['ES384', pem(ec.ES384), ec.ES384.publicKey],
      ['ES512', pem(ec.ES512), ec.ES512.publicKey],
      ['EdDSA', ed.privateKey, ed.publicKey],
      ['ES256K', k1.privateKey, k1.publicKey],
      ['RS256', rsa.privateKey, rsa.publicKey]
    ];
    const bad = [];
    const notOffThread = [];
    for (const row of cases) {
      const alg = row[0];
      const payload = { sub: 's', iat: 1700000000 };
      const opts = { algorithm: alg, keyid: 'k', header: { typ: 'JWT' } };
      const syncToken = stsCrypto.signJws(payload, row[1], opts);
      const watched = await watch(function () {
        return stsCrypto.signJwsAsync(payload, row[1], opts);
      });
      const token = String(watched.value || '');
      const spec = stsCrypto.JWS_ALGS[alg];
      const params = { key: row[2] };
      if (spec.padding !== undefined) {
        params.padding = spec.padding;
        params.saltLength = spec.saltLength;
      }
      if (spec.family === 'ec') {
        params.dsaEncoding = 'ieee-p1363';
      }
      const parts = token.split('.');
      const verifies = parts.length === 3 && nodeCrypto.verify(spec.hash,
        Buffer.from(parts[0] + '.' + parts[1], 'ascii'), params,
        Buffer.from(parts[2] || '', 'base64url'));
      let library = true;
      if (/^(RS|PS|ES)(256|384|512)$/.test(alg)) {
        try {
          jwt.verify(token, row[2], { algorithms: [alg] });
        } catch (e) {
          library = false;
        }
      }
      if (watched.error || segments(token) !== segments(syncToken) ||
          !verifies || !library) {
        bad.push(alg + ': ' + (watched.error || (verifies ? 'library' :
                                                  'signature')));
      }
      if (watched.calls.async !== 1 || watched.calls.sync !== 0) {
        notOffThread.push(alg + ' ' + JSON.stringify(watched.calls));
      }
    }
    note(bad.length === 0,
         'A2. PS, ES, EdDSA and ES256K have signJws()\'s header and payload ' +
         'and a signature that verifies — by node and by jsonwebtoken',
         bad.join('; '));
    note(notOffThread.length === 0,
         'B. EACH IS SIGNED BY crypto.sign() WITH A CALLBACK — on libuv\'s ' +
         'thread pool — and never synchronously on this thread',
         notOffThread.join('; '));

    // --- C -----------------------------------------------------------------
    const inPlace = async function (payload, key, opts) {
      const syncResult = await (async function () {
        try {
          return { value: frozen(function () {
            return stsCrypto.signJws(payload, key, opts);
          }) };
        } catch (e) {
          return { error: (e && e.message) || String(e) };
        }
      })();
      Date.now = function () {
        return 1760000000000;
      };
      const watched = await watch(function () {
        return stsCrypto.signJwsAsync(payload, key, opts);
      });
      Date.now = realNow;
      return { same: syncResult.error
                 ? watched.error === syncResult.error
                 : watched.value === syncResult.value,
               async: watched.calls.async, sync: syncResult, watched: watched };
    };
    const conv = await inPlace({ sub: 'c' }, pem(rsa),
      { algorithm: 'RS256', expiresIn: 600, issuer: 'https://i' });
    note(conv.same && conv.async === 0,
         'C. a claim convenience (expiresIn, issuer) is signJws()\'s: the ' +
         'same token, signed in place', JSON.stringify(conv.watched));
    const algHeader = await inPlace({ sub: 'c' }, pem(rsa),
      { algorithm: 'RS256', header: { alg: 'RS256', typ: 'JWT' } });
    note(algHeader.same && algHeader.async === 0,
         'C. an alg in the caller\'s header is signJws()\'s');
    const short = await inPlace({ sub: 'c' }, pem(weak), { algorithm: 'RS256' });
    note(short.same && short.async === 0 && short.watched.error &&
         /2048/.test(short.watched.error),
         'C. an RSA key under 2048 bits is refused as signJws() refuses it',
         JSON.stringify(short.watched));
    const wrongType = await inPlace({ sub: 'c' }, pem(ec.ES256),
                                    { algorithm: 'RS256' });
    note(wrongType.same && wrongType.async === 0 && wrongType.watched.error,
         'C. a key of the wrong type is refused as signJws() refuses it',
         JSON.stringify(wrongType.watched));
    const wrongCurve = await inPlace({ sub: 'c' }, pem(ec.ES384),
                                     { algorithm: 'ES256' });
    note(wrongCurve.same && wrongCurve.async === 0 && wrongCurve.watched.error,
         'C. an ECDSA key on the wrong curve is refused as signJws() refuses ' +
         'it', JSON.stringify(wrongCurve.watched));
    const badClaim = await inPlace({ sub: 'c', exp: 'soon' }, pem(rsa),
                                   { algorithm: 'RS256' });
    note(badClaim.same && badClaim.async === 0 && badClaim.watched.error,
         'C. a non-numeric exp is refused as signJws() refuses it',
         JSON.stringify(badClaim.watched));
    const hmac = await inPlace({ sub: 'c' }, 'a-shared-secret-of-enough-length',
                               { algorithm: 'HS256' });
    note(hmac.same && hmac.async === 0, 'C. HS256 is signed in place');
    finish();
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
    finish();
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-acs-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { ACS_OUT: out, ACS_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'async_classical_signing',
  describe: 'a classical JWS signature is computed on libuv\'s thread pool, ' +
            'over the signing input the synchronous door builds (#772)',
  run: run
};
