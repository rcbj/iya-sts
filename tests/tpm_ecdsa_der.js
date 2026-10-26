// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tpm_ecdsa_der.js
//
// ===========================================================================
// A TPM'S ECDSA SIGNATURE BECOMES VALID DER (#904, 2026-10-23).
//
// `crypto.tpmParseSignature()` turns a TPMT_SIGNATURE's r and s into the DER
// SEQUENCE OpenSSL verifies. It put a zero byte in front of each integer
// whatever its top bit, which DER forbids where the top bit is clear, so
// about three genuine signatures in four were refused — WebAuthn `tpm`
// attestation (STS-AUTHN-0233) and TPM key attestation for EST and SCEP
// (STS-DEVICE-0020) both read it. Held here, for P-256 and P-384:
//
//   1. a signature whose r and s have the top bit CLEAR verifies;
//   2. one whose r or s has the top bit SET verifies;
//   3. r and s zero-padded to the curve size, as a TPM may send them, verify;
//   4. the DER carries each INTEGER in its minimal form.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const stsCrypto = require('../common/crypto');

const log = require('bunyan').createLogger({ name: 'tpm_ecdsa_der',
  level: process.env.LOG_LEVEL || 'info' });

const TPM_ALG_ECDSA = 0x0018;
const TPM_ALG_SHA256 = 0x000b;

// A TPMT_SIGNATURE for ECDSA: sigAlg, hash, then r and s as TPM2B buffers.
function tpmSignature(r, s) {
  log.debug("Entering tpmSignature().");
  const u16 = function (n) {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n, 0);
    return b;
  };
  log.debug("Leaving tpmSignature().");
  return Buffer.concat([u16(TPM_ALG_ECDSA), u16(TPM_ALG_SHA256),
                        u16(r.length), r, u16(s.length), s]);
}

// The minimal form of a positive INTEGER's content octets.
function minimal(b) {
  log.debug("Entering minimal().");
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) {
    i++;
  }
  let body = b.subarray(i);
  if (body[0] & 0x80) {
    body = Buffer.concat([Buffer.from([0]), body]);
  }
  log.debug("Leaving minimal().");
  return body;
}

// Signs until `want(r, s)` holds, so each case is the case it names.
function signatureWhere(pair, size, data, want) {
  log.debug("Entering signatureWhere().");
  for (let i = 0; i < 400; i++) {
    const raw = nodeCrypto.sign('sha256', data, { key: pair.privateKey,
      dsaEncoding: 'ieee-p1363' });
    const r = raw.subarray(0, size);
    const s = raw.subarray(size);
    if (want(r, s)) {
      log.debug("Leaving signatureWhere().");
      return { r: r, s: s };
    }
  }
  log.debug("Leaving signatureWhere(). None found.");
  return null;
}

function holdsFor(t, curve, size) {
  log.debug("Entering holdsFor().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: curve });
  const data = Buffer.from('tpm_ecdsa_der ' + curve, 'utf8');
  const verifies = function (sig) {
    const parsed = stsCrypto.tpmParseSignature(tpmSignature(sig.r, sig.s));
    return !!parsed && nodeCrypto.verify('sha256', data, pair.publicKey,
                                         parsed.signature);
  };
  // Leading zeros stripped from what the TPM sends, so the case is the
  // UNPADDED one; case 3 pads them back.
  const strip = function (b) {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) {
      i++;
    }
    return b.subarray(i);
  };
  const clear = signatureWhere(pair, size, data, function (r, s) {
    return !(r[0] & 0x80) && !(s[0] & 0x80) && r[0] !== 0 && s[0] !== 0;
  });
  t.check(clear && verifies(clear),
          curve + ' 1. r and s with the top bit CLEAR verify', '');
  const set = signatureWhere(pair, size, data, function (r, s) {
    return !!(r[0] & 0x80) || !!(s[0] & 0x80);
  });
  t.check(set && verifies(set),
          curve + ' 2. r or s with the top bit SET verifies', '');
  const padded = signatureWhere(pair, size, data, function (r, s) {
    return r[0] === 0 || s[0] === 0;
  });
  t.check(padded && verifies(padded),
          curve + ' 3. r or s zero-padded to the curve size verifies', '');
  if (clear) {
    const der = stsCrypto.tpmParseSignature(
      tpmSignature(strip(clear.r), strip(clear.s))).signature;
    const expected = (function () {
      const ri = minimal(clear.r);
      const si = minimal(clear.s);
      const body = Buffer.concat([Buffer.from([0x02, ri.length]), ri,
                                  Buffer.from([0x02, si.length]), si]);
      return Buffer.concat([Buffer.from([0x30, body.length]), body]);
    })();
    t.check(der.equals(expected),
            curve + ' 4. the DER carries each INTEGER in its minimal form',
            der.toString('hex') + ' vs ' + expected.toString('hex'));
  }
  log.debug("Leaving holdsFor().");
}

async function run(t) {
  log.debug("Entering run().");
  holdsFor(t, 'prime256v1', 32);
  holdsFor(t, 'secp384r1', 48);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tpm_ecdsa_der',
  describe: 'a TPM\'s ECDSA signature becomes minimal DER (#904): r and s ' +
            'with the top bit clear, set, or zero-padded all verify',
  run: run
};
