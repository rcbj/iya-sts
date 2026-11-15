// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: auditmail-vectors.js
//
// ---------------------------------------------------------------------------
// THE AUDIT LOG'S AND THE MAIL CHANNEL'S VECTORS (#444, phase 4): one row of
// `crypto-vectors.js`'s VECTORS (`auditmail-node.json`) and one call in
// `tests/rust_crypto_vectors.js`'s `run()`, each half kept in a file of its
// own so the two crates' builders cannot collide:
//
//   audit-vectors.js   common/audit.js, the /admin-api/audit answer,
//                      common/audit_export.ts and common/outbound_tls.ts —
//                      `sts-audit` reads `auditmail-node.json`'s `audit`
//   mail-vectors.js    common/mail*.ts — `sts-mail` reads its `mail`
//
// The other direction: `sts-audit` writes `audit-rust.json` and `sts-mail`
// `mail-rust.json` (`STS_WRITE_VECTORS=1`), and `fromRust()` checks each in
// Node. Both halves need the compiled tree (`audit_export.ts`, `mail.ts`), so
// they run in the tests image.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'auditmail_vectors',
  level: process.env.STS_LOG_LEVEL || 'info' });

/**
 * Both halves' Node vectors, as `auditmail-node.json`.
 *
 * @param {string} root - the repository root
 * @param {string} out - the vectors directory
 * @returns {Promise<any>} { audit, mail }
 */
async function build(root, out) {
  log.debug("Entering build().");
  const audit = await require('./audit-vectors.js').build(root, out);
  const mail = await require('./mail-vectors.js').build(root, out);
  log.debug("Leaving build().");
  return { audit: audit, mail: mail };
}

/**
 * What Rust made, checked in Node: each half whose file is there.
 *
 * @param {any} t - the runner's check collector
 * @param {string} dir - the vectors directory
 * @returns {Promise<void>} when both halves are checked
 */
async function fromRust(t, dir) {
  log.debug("Entering fromRust().");
  const halves = [['audit-rust.json', './audit-vectors.js'],
                  ['mail-rust.json', './mail-vectors.js']];
  for (const half of halves) {
    const file = path.join(dir, half[0]);
    if (fs.existsSync(file)) {
      await require(half[1]).fromRust(t,
        JSON.parse(fs.readFileSync(file, 'utf8')), dir);
    }
  }
  log.debug("Leaving fromRust().");
}

module.exports = { build: build, fromRust: fromRust };
