// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openbao/generate-seal.js
//
// Makes the key OpenBao's static seal unlocks its storage with, once, the first
// time a stack starts (ASVS 5.0.0 13.3.1). A key written in the compose file is
// the same for everybody who runs it. This one is random, 32 bytes as the seal
// requires, and stays on the store's own volume.
//
// STS_BAO_SEAL_KEY, where a deployment sets it, wins and nothing is written.
// The file is never replaced: a key that changes unseals nothing.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const FILE = process.env.STS_BAO_SEAL_KEY_FILE ||
  '/openbao/file/seal/seal.key';
// The server runs as uid 100 in that image, as generate-tls.js says.
const SERVER_UID = 100;
const SERVER_GID = 1000;

/**
 * Writes the seal key if there is none.
 *
 * @returns what was done
 */
function ensureSealKey() {
  if (process.env.STS_BAO_SEAL_KEY) {
    return 'STS_BAO_SEAL_KEY is set, so no key file is needed.';
  }
  if (fs.existsSync(FILE)) {
    return 'The seal key already exists.';
  }
  const raft = path.join(path.dirname(path.dirname(FILE)), 'raft');
  const existing = fs.existsSync(raft) && fs.readdirSync(raft).length > 0;
  fs.mkdirSync(path.dirname(FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(FILE, crypto.randomBytes(32).toString('base64'),
                   { mode: 0o400 });
  try {
    fs.chownSync(path.dirname(FILE), SERVER_UID, SERVER_GID);
    fs.chownSync(FILE, SERVER_UID, SERVER_GID);
  } catch (e) {
    // Not root: a test's own directory. The server owns the real one.
    console.log('generate-seal: left the owner alone: ' + e.message);
  }
  return existing
    ? 'Made a new seal key, but this volume already holds a store sealed ' +
      'under another key, which it cannot open. Recreate the volume, or set ' +
      'STS_BAO_SEAL_KEY to that key.'
    : 'Made a new seal key.';
}

if (require.main === module) {
  console.log('generate-seal: ' + ensureSealKey());
}

module.exports = { ensureSealKey: ensureSealKey };
