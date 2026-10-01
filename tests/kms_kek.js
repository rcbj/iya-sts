// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kms_kek.js
//
// ===========================================================================
// A KEY-ENCRYPTION KEY IN A KEY MANAGEMENT SERVICE (#391 P3): Vault or
// OpenBao TRANSIT, and AWS KMS, each wrapping every data encryption key
// directly (rcbj's decision) so that no root key is ever in this process.
//
// In a CHILD PROCESS, for `data_key_rotation.js`'s reason: the keystore is the
// process's, and the sections restart it. Neither KMS is dialled:
//
//   * TRANSIT is a small HTTP server in the child that does what Transit does
//     — AES-256-GCM per key version, `associated_data` bound, `vault:vN:`
//     ciphertexts, the key's type and latest version — reached through a
//     node-vault-shaped client handed in with `secrets.setSdkLoader()` (the
//     tests image has no node-vault where `common/` can require it). The
//     client is twenty lines of `request()`; what is under test is this
//     service's use of Transit, and a by-hand run against a real OpenBao
//     holds the rest.
//   * AWS KMS is a fake `@aws-sdk/client-kms` with the five commands this
//     service sends, holding the encryption context to what it was given.
//
// Asserted:
//   A. Transit: a data key's row holds Transit's ciphertext, never the key;
//      every wrap carries the data key's own associated data; a restart
//      unwraps through Transit and every value opens; no KEK bytes are held.
//   B. a key rotated INSIDE Transit: the next start moves every data key to
//      the newest version.
//   C. a Transit key that is not AEAD refuses the start (STS-KEYS-0102).
//   D. AWS KMS: the same round trip, the context bound — a context that does
//      not match is refused by the KMS and the start stops (STS-KEYS-0091).
//   E. moving from a local KEK to a KMS: the local key as the PREVIOUS key,
//      every data key re-wrapped by the KMS, and the next start needs only
//      the KMS.
//   F. the report says the key is in a KMS.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'kms_kek',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.KK_ROOT;
  const OUT = process.env.KK_OUT;
  const DIR = process.env.KK_DIR;
  const fs = require('fs');
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  // ------------------------------------------------------------- TRANSIT
  const transit = { keys: {}, calls: [] };
  function transitKey(name, type) {
    transit.keys[name] = { type: type || 'aes256-gcm96',
                           versions: [nodeCrypto.randomBytes(32)] };
  }
  function gcm(key, plain, ad) {
    const iv = nodeCrypto.randomBytes(12);
    const c = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
    if (ad) {
      c.setAAD(ad);
    }
    const ct = Buffer.concat([c.update(plain), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]);
  }
  function ungcm(key, blob, ad) {
    const d = nodeCrypto.createDecipheriv('aes-256-gcm', key,
                                          blob.subarray(0, 12));
    d.setAuthTag(blob.subarray(12, 28));
    if (ad) {
      d.setAAD(ad);
    }
    return Buffer.concat([d.update(blob.subarray(28)), d.final()]);
  }
  const server = http.createServer(function (req, res) {
    let body = '';
    req.on('data', function (c) { body += c; });
    req.on('end', function () {
      const reply = function (status, json) {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(json));
      };
      if (req.headers['x-vault-token'] !== 'test-token') {
        return reply(403, { errors: ['permission denied'] });
      }
      const m = /^\/v1\/transit\/(keys|encrypt|decrypt)\/([^/]+)$/
        .exec(req.url);
      const k = m ? transit.keys[decodeURIComponent(m[2])] : null;
      if (!k) {
        return reply(404, { errors: ['no such key'] });
      }
      const json = body ? JSON.parse(body) : {};
      transit.calls.push({ op: m[1], json: json });
      if (m[1] === 'keys') {
        return reply(200, { data: { name: m[2], type: k.type,
                                    latest_version: k.versions.length,
                                    keys: {} } });
      }
      const ad = json.associated_data
        ? Buffer.from(json.associated_data, 'base64') : null;
      if (m[1] === 'encrypt') {
        const v = k.versions.length;
        const blob = gcm(k.versions[v - 1],
                         Buffer.from(json.plaintext, 'base64'), ad);
        return reply(200, { data: { ciphertext: 'vault:v' + v + ':' +
                                                blob.toString('base64') } });
      }
      const p = /^vault:v(\d+):(.*)$/.exec(String(json.ciphertext || ''));
      try {
        const plain = ungcm(k.versions[Number(p[1]) - 1],
                            Buffer.from(p[2], 'base64'), ad);
        return reply(200, { data: { plaintext: plain.toString('base64') } });
      } catch (e) {
        return reply(400, { errors: ['cipher: message authentication ' +
                                     'failed'] });
      }
    });
  });
  // A node-vault-shaped client: `request({ path, method, json })` against
  // `endpoint + '/v1' + path`, the token in X-Vault-Token.
  function fakeNodeVault(opts) {
    return {
      token: opts.token,
      request: function (r) {
        const self = this;
        return new Promise(function (resolve, reject) {
          const url = new URL(opts.endpoint + '/v1' + r.path);
          const req = http.request({ method: r.method, host: url.hostname,
                                     port: url.port, path: url.pathname,
                                     headers: { 'X-Vault-Token': self.token,
                                       'Content-Type': 'application/json' } },
            function (res) {
              let text = '';
              res.on('data', function (c) { text += c; });
              res.on('end', function () {
                const json = text ? JSON.parse(text) : {};
                if (res.statusCode >= 400) {
                  const e = new Error((json.errors || []).join('; '));
                  e.response = { statusCode: res.statusCode };
                  return reject(e);
                }
                resolve(json);
              });
            });
          req.on('error', reject);
          req.end(r.json ? JSON.stringify(r.json) : undefined);
        });
      }
    };
  }

  // ------------------------------------------------------------- AWS KMS
  const kms = { key: nodeCrypto.randomBytes(32), spec: 'SYMMETRIC_DEFAULT',
                calls: [] };
  function cmd(name) {
    return function (input) { this.name = name; this.input = input; };
  }
  const fakeKmsSdk = {
    KMSClient: function () {
      this.send = async function (c) {
        kms.calls.push({ name: c.name, input: c.input });
        if (c.name === 'DescribeKey') {
          return { KeyMetadata: { KeyId: 'k-1', Arn: 'arn:aws:kms:x:1:key/k-1',
                                  KeyUsage: 'ENCRYPT_DECRYPT',
                                  KeySpec: kms.spec, Enabled: true } };
        }
        const ctx = Buffer.from(JSON.stringify(c.input.EncryptionContext ||
                                               {}), 'utf8');
        if (c.name === 'Encrypt') {
          return { CiphertextBlob: gcm(kms.key, c.input.Plaintext, ctx) };
        }
        if (c.name === 'Decrypt') {
          try {
            return { Plaintext: ungcm(kms.key, c.input.CiphertextBlob, ctx) };
          } catch (e) {
            const err = new Error('InvalidCiphertextException');
            err.name = 'InvalidCiphertextException';
            throw err;
          }
        }
        throw new Error('unexpected command ' + c.name);
      };
    },
    DescribeKeyCommand: cmd('DescribeKey'),
    EncryptCommand: cmd('Encrypt'),
    DecryptCommand: cmd('Decrypt'),
    GetKeyRotationStatusCommand: cmd('GetKeyRotationStatus')
  };

  // ------------------------------------------------------------- STORE
  const rows = new Map();
  const store = {
    loadKeys: function () {
      return Promise.resolve(Array.from(rows.entries()).map(function (p) {
        return { realm: p[0], material: p[1] };
      }));
    },
    loadKey: function (key) {
      return Promise.resolve(rows.has(key) ? rows.get(key) : null);
    },
    saveKeys: function (key, text) {
      rows.set(key, text);
      return Promise.resolve();
    },
    deleteKeys: function (key) {
      rows.delete(key);
      return Promise.resolve();
    },
    mergeKeys: function (key, text, merge) {
      return Promise.resolve().then(function () {
        const current = rows.has(key) ? rows.get(key) : null;
        const next = current === null ? text : merge(current);
        if (next !== null && next !== undefined) {
          rows.set(key, next);
        }
        return { material: rows.get(key) };
      });
    }
  };

  function useTransit(name) {
    process.env.STS_KEYS_KEK_PROVIDER = 'vault-transit';
    process.env.STS_KEYS_KEK_REF = name;
    process.env.STS_KEYS_KEK_VAULT = 'http://127.0.0.1:' +
      server.address().port;
    process.env.STS_KEYS_KEK_TOKEN = 'test-token';
  }
  function useAws() {
    process.env.STS_KEYS_KEK_PROVIDER = 'aws-kms';
    process.env.STS_KEYS_KEK_REF = 'k-1';
    process.env.STS_KEYS_KEK_REGION = 'us-west-2';
  }
  const kekFile = DIR + '/kek';
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_FILE = kekFile;

  (async function () {
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const secrets = require(ROOT + '/common/secrets');
    secrets.setSdkLoader(function (name) {
      if (name === 'node-vault') {
        return fakeNodeVault;
      }
      if (name === '@aws-sdk/client-kms') {
        return fakeKmsSdk;
      }
      throw new Error('Cannot find module \'' + name + '\'');
    });
    const keystore = require(ROOT + '/common/keystore');
    const crypto = require(ROOT + '/common/crypto');
    async function restart() {
      await keystore.settleAll();
      keystore.reset();
      keystore.setStore(store);
      await keystore.start();
    }

    // ------------------------------------------------------------ A
    transitKey('dek-key');
    useTransit('dek-key');
    await restart();
    const v1 = keystore.seal('alpha', 'minted-rows', undefined,
                             { realm: '' });
    await keystore.settleDeks();
    const row = rows.get('dek:service:default') || '';
    note(/\$dekkms\$1\$vault-transit\$/.test(row) &&
         /vault:v1:/.test(row),
         'A1. the data-key row holds Transit\'s ciphertext', row.slice(0, 160));
    const id = crypto.dekIdOf(v1);
    const enc = transit.calls.filter(function (c) {
      return c.op === 'encrypt';
    });
    note(enc.length >= 1 && enc.every(function (c) {
      return /^sts dek v1\|/.test(Buffer.from(c.json.associated_data,
                                              'base64').toString('utf8'));
    }) && enc.some(function (c) {
      return Buffer.from(c.json.associated_data, 'base64').toString('utf8')
        .indexOf('|' + id + '|') > 0;
    }), 'A2. every wrap carries the data key\'s own associated data');
    const report = keystore.report();
    note(report.kekInKms === true && report.kekKms &&
         report.kekKms.provider === 'vault-transit',
         'F1. the report says the key is in a KMS',
         JSON.stringify(report.kekKms));
    const before = transit.calls.length;
    await restart();
    note(transit.calls.slice(before).some(function (c) {
      return c.op === 'decrypt';
    }), 'A3. a restart asks Transit to unwrap');
    note(keystore.open(v1, 'minted-rows') === 'alpha',
         'A4. and every value opens');

    // ------------------------------------------------------------ B
    transit.keys['dek-key'].versions.push(nodeCrypto.randomBytes(32));
    await restart();
    await keystore.settleDeks();
    const rotated = rows.get('dek:service:default') || '';
    note(/vault:v2:/.test(rotated) && !/vault:v1:/.test(rotated),
         'B1. a key rotated in Transit moves every data key to version 2',
         rotated.slice(0, 160));
    await restart();
    note(keystore.open(v1, 'minted-rows') === 'alpha',
         'B2. and the values still open');

    // ------------------------------------------------------------ C
    transitKey('rsa-key', 'rsa-2048');
    useTransit('rsa-key');
    let refused = '';
    try {
      await restart();
    } catch (e) {
      refused = String((e && e.message) || e);
    }
    note(/STS-KEYS-0102/.test(refused),
         'C1. a Transit key that is not AEAD refuses the start', refused);

    // ------------------------------------------------------------ E
    rows.clear();
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    delete process.env.STS_KEYS_KEK_REF;
    await restart();
    const local = keystore.seal('beta', 'minted-rows', undefined,
                                { realm: '' });
    await keystore.settleDeks();
    note(/\$dekwrap\$1\$/.test(rows.get('dek:service:default') || ''),
         'E0. under a local key the row holds a local wrap');
    useAws();
    process.env.STS_PREVIOUS_KEK_PROVIDER = 'file';
    process.env.STS_PREVIOUS_KEK_REF = kekFile;
    await restart();
    await keystore.settleDeks();
    note(keystore.open(local, 'minted-rows') === 'beta' &&
         /\$dekkms\$1\$aws-kms\$/.test(rows.get('dek:service:default') || ''),
         'E1. with the local key as the previous one, every data key is ' +
         're-wrapped by the KMS');
    delete process.env.STS_PREVIOUS_KEK_PROVIDER;
    delete process.env.STS_PREVIOUS_KEK_REF;
    await restart();
    note(keystore.open(local, 'minted-rows') === 'beta',
         'E2. and the next start needs only the KMS');

    // ------------------------------------------------------------ D
    note(kms.calls.some(function (c) {
      return c.name === 'Encrypt' && c.input.EncryptionContext &&
             /^sts dek v1\|/.test(c.input.EncryptionContext['sts-dek']);
    }), 'D1. AWS KMS is handed the data key\'s AAD as its context');
    note(kms.calls.some(function (c) { return c.name === 'Decrypt'; }),
         'D2. and a restart asks it to unwrap');
    // A wrapped data key moved onto another realm's row: its AAD names the
    // realm, so the KMS refuses it and the start stops.
    // The default realm's row is taken away, so the moved copy is the only
    // place the keystore meets those DEKs and has to unwrap them.
    const own = JSON.parse(rows.get('dek:service:default'));
    const keep = rows.get('dek:service:default');
    rows.delete('dek:service:default');
    rows.set('dek:service:other', JSON.stringify({ v: own.v,
      scope: 'service', realm: 'other', deks: own.deks }));
    let moved = '';
    try {
      await restart();
    } catch (e) {
      moved = String((e && e.message) || e);
    }
    note(/STS-KEYS-0091/.test(moved),
         'D3. a wrapped key moved to another realm\'s row is refused by the ' +
         'KMS', moved.slice(0, 200));
    rows.delete('dek:service:other');
    rows.set('dek:service:default', keep);
    kms.spec = 'RSA_2048';
    let notSym = '';
    try {
      await restart();
    } catch (e) {
      notSym = String((e && e.message) || e);
    }
    note(/STS-KEYS-0102/.test(notSym),
         'D4. a KMS key that is not symmetric refuses the start', notSym);
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-kms-'));
  const out = path.join(dir, 'findings.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', KK_ROOT: ROOT,
                                  KK_OUT: out, KK_DIR: dir }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings), 'the child process reported its ' +
                                       'findings',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-1500))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kms_kek',
  describe: 'a key-encryption key in Vault Transit or AWS KMS wrapping every ' +
            'data encryption key: the rows, the associated data, a restart, ' +
            'a rotation inside the KMS, the refusals, and moving to a KMS',
  run: run
};
