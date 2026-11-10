// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/openbao_seal_key.js
//
// OpenBao's seal key is made once, is unique, and is not in the compose file.

const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');

function run(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seal-'));
  const file = path.join(dir, 'seal', 'seal.key');
  const saved = process.env.STS_BAO_SEAL_KEY;
  delete process.env.STS_BAO_SEAL_KEY;
  process.env.STS_BAO_SEAL_KEY_FILE = file;
  delete require.cache[require.resolve(ROOT + '/openbao/generate-seal.js')];
  const seal = require(ROOT + '/openbao/generate-seal.js');
  try {
    t.equal(seal.ensureSealKey(), 'Made a new seal key.',
            'a first start makes a key');
    const key = fs.readFileSync(file, 'utf8');
    t.equal(Buffer.from(key, 'base64').length, 32,
            'of the 32 bytes the seal requires');
    t.equal((fs.statSync(file).mode & 0o777), 0o400, 'readable by its owner');
    seal.ensureSealKey();
    t.equal(fs.readFileSync(file, 'utf8'), key, 'a restart keeps it');
    fs.unlinkSync(file);
    seal.ensureSealKey();
    t.check(fs.readFileSync(file, 'utf8') !== key, 'and each key is different');
    fs.unlinkSync(file);
    process.env.STS_BAO_SEAL_KEY = 'x';
    seal.ensureSealKey();
    t.equal(fs.existsSync(file), false,
            'a key the deployment sets means no file is written');
  } finally {
    if (saved === undefined) {
      delete process.env.STS_BAO_SEAL_KEY;
    } else {
      process.env.STS_BAO_SEAL_KEY = saved;
    }
    delete process.env.STS_BAO_SEAL_KEY_FILE;
  }
  const compose = fs.readFileSync(ROOT + '/docker-compose.yml', 'utf8');
  t.equal(/KSVmck/.test(compose), false,
          'no seal key is written in the compose file');
}

module.exports = {
  name: 'openbao_seal_key',
  describe: 'the OpenBao seal key is generated once at first start',
  run: run
};
