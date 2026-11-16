// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: utilities/pep-assertion-request.js
// ---------------------------------------------------------------------------
// A REMOTE PEP'S ASSERTION KEY AND ITS CERTIFICATE REQUEST, MADE WHERE THE
// PEP RUNS (#1827's follow-up, phase 3; rcbj 2026-11-16: "the service never
// holds the PEP's private key").
//
// One function, `assertionRequest()`: a key pair (EC P-256 by default, the
// ES256 key the PEP prefers, or RSA 2048) and a PKCS #10 request signed with
// it, for `POST /admin-api/xacml/issue-pep-credential`. The request's subject
// names the PEP only as a courtesy to a reader: the service ignores it and
// names the entry.
//
// **IT LIVES HERE, AND NOT IN tests/tools/pep-credential.js WHERE IT WAS
// WRITTEN, BECAUSE AN OPERATOR'S TOOL NEEDS IT TOO.** `register-remote-pep.js`
// beside it runs from the service image, which ships no `tests/`; so the code
// moved to the one directory both can reach, and `pep-credential.js` requires
// it from here rather than keeping a second copy. `.dockerignore` lets this
// file into the image with the utility.
//
// THE ENGINE IS THE VENDORED ONE (`common/crypto_impl/key_material.js` and
// `x509.js`'s `certificationRequest()`), for the reason pep-credential.js's
// header gives: a fifth reading of RFC 2986 would be the first thing to get
// wrong. They need the service's npm dependencies, which the image holds and
// a checkout has after `npm ci`.
//
// `MOCK_STS_DIR` relocates the engine, as it does for pep-credential.js; by
// default it is this file's parent directory.
// ---------------------------------------------------------------------------

const path = require('path');

// A console-backed logger of bunyan's shape (the parent's arrangement for a
// file that runs outside the service), quiet unless PEP_REQUEST_DEBUG is set.
const log = {
  debug: function (message) {
    if (process.env.PEP_REQUEST_DEBUG) {
      console.error(message);
    }
  }
};

const ROOT = process.env.MOCK_STS_DIR || path.join(__dirname, '..');

// The two keys the remote PEP signs its self-assertion and its DPoP proofs
// with; anything else the service refuses by name (STS-PKI-0281).
const ASSERTION_KEY_ALGS = ['ec-p256', 'rsa-2048'];

/**
 * Loads the vendored engine, lazily, so that requiring this file for its
 * constants costs nothing.
 *
 * @returns `{ keys, x509 }`
 */
function engine() {
  log.debug("Entering engine().");
  const keys = require(path.join(ROOT, 'common', 'crypto_impl',
                                 'key_material.js'));
  const x509 = require(path.join(ROOT, 'common', 'crypto_impl', 'x509.js'));
  log.debug("Leaving engine().");
  return { keys: keys, x509: x509 };
}

/**
 * Makes a key pair and a PKCS #10 request signed with it.
 *
 * @param spec - `keyAlg` (one of ASSERTION_KEY_ALGS, default ec-p256) and
 *   `name`, the common name the request carries
 * @returns a promise of `{ keyAlg, privateKeyPem, publicKeyPem, csrPem }`
 */
async function assertionRequest(spec) {
  log.debug("Entering assertionRequest().");
  const keyAlg = String((spec && spec.keyAlg) || 'ec-p256');
  if (ASSERTION_KEY_ALGS.indexOf(keyAlg) < 0) {
    log.debug("Leaving assertionRequest(). Key algorithm refused.");
    throw new Error('--key-alg must be one of ' +
                    ASSERTION_KEY_ALGS.join(', ') + ': the two keys the ' +
                    'remote PEP signs its self-assertion and its DPoP ' +
                    'proofs with.');
  }
  const { keys, x509 } = engine();
  const pair = await keys.generateKeyPair(keyAlg);
  const request = await x509.certificationRequest({
    subject: [{ name: 'CN', value: String((spec && spec.name) ||
                                          'remote-pep') }],
    publicKeyPem: pair.publicPem,
    privateKeyPem: pair.privatePem
  });
  const der = Buffer.from(request.der);
  const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\n' +
    der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '') +
    '\n-----END CERTIFICATE REQUEST-----\n';
  log.debug("Leaving assertionRequest(). " + keyAlg);
  return { keyAlg: keyAlg, privateKeyPem: pair.privatePem,
           publicKeyPem: pair.publicPem, csrPem: csrPem };
}

module.exports = { assertionRequest: assertionRequest,
                   ASSERTION_KEY_ALGS: ASSERTION_KEY_ALGS };
