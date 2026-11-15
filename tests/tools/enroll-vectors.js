// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: enroll-vectors.js
//
// ---------------------------------------------------------------------------
// CERTIFICATE ENROLLMENT (#444, phase 6, the `enroll` slice): what
// `common/cert_enrollment.ts` reads of a PKCS#10 request, what
// `common/enrollment_model.ts` makes of a body, what `est/est_codec.ts`
// writes, and the SCEP messages `tests/protocol/scep_client.js` and
// `scep/scep_cms.ts` build, for the Rust crate `sts-enroll` to read and
// reproduce. Called by `tests/tools/crypto-vectors.js`'s `enroll-node.json`
// row; the work is done in `enroll-vectors-child.js`, which says what each
// member holds.
//
// THE RUST HALF (`rust/crates/sts-enroll/tests/node_vectors.rs`) reads each
// request as Node did, answers each body as zod did, writes EST's and SCEP's
// certs-only and CSR attributes byte for byte, opens each PKCSReq with the
// RA's key to the request Node enveloped, and opens Node's CertRep with the
// requester's key. With STS_WRITE_VECTORS=1 it writes a CertRep of its own
// for Node's requester; `checkRust()` below has the client code a SCEP
// device test uses read it. A CertRep is not compared byte for byte: its
// senderNonce and its envelope's content key are random, as RFC 8894 and
// RFC 5652 require.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const CHILD = path.join(__dirname, 'enroll-vectors-child.js');

/**
 * Runs the child and reads its answer.
 *
 * @param {string} ROOT - the compiled tree
 * @param {string[]} args - the mode, the answer file, and Rust's file
 * @returns {any} the answer
 */
function child(ROOT, args) {
  const answerFile = args[1];
  childProcess.execFileSync(process.execPath, [CHILD, ROOT].concat(args),
    { env: Object.assign({}, process.env, { STS_LOG_LEVEL: 'fatal',
                                            STS_KEYS_SOURCE: 'generated' }),
      stdio: ['ignore', 'ignore', 'inherit'] });
  const answer = JSON.parse(fs.readFileSync(answerFile, 'utf8'));
  fs.unlinkSync(answerFile);
  return answer;
}

/**
 * The Node half.
 *
 * @param {string} ROOT - the compiled tree
 * @param {string} OUT - the vector directory
 * @returns {any} enroll-node.json
 */
function build(ROOT, OUT) {
  return child(ROOT, ['build', path.join(OUT, 'enroll-node.answer.json')]);
}

/**
 * What Node reads of Rust's half.
 *
 * @param {string} ROOT - the compiled tree
 * @param {string} file - enroll-rust.json
 * @param {Function} check - `(ok, what, detail)`
 */
function checkRust(ROOT, file, check) {
  const answers = child(ROOT, ['check', file + '.answer.json', file]);
  answers.forEach(function (one) {
    check(one.ok, one.what, one.detail);
  });
}

module.exports = { build: build, checkRust: checkRust };
