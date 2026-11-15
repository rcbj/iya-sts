// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kms_kek.js
//
// ===========================================================================
// A KEY-ENCRYPTION KEY IN A KEY MANAGEMENT SERVICE (#391 P3, P4): Vault or
// OpenBao TRANSIT, AWS KMS, Google Cloud KMS and an Azure Key Vault key, each
// wrapping every data encryption key
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
//   * Cloud KMS and Key Vault are fakes of `@google-cloud/kms` and
//     `@azure/keyvault-keys` (with `@azure/identity`) the same way: key
//     versions, the AAD bound, real RSA-OAEP-256 for the RSA key.
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
//   F. the report says the key is in a KMS; and (A5) a secret with no
//      location of its own borrows none from a KMS key.
//   G. Cloud KMS (#391 P4): the round trip with the AAD, the version used in
//      the row and a new primary re-wrapping at start, a moved row refused,
//      a key VERSION or a non-ENCRYPT_DECRYPT key refusing the start.
//   H. an Azure Key Vault RSA key: RSA-OAEP-256, a moved row refused HERE by
//      the AAD digest the wrap carries, a new version re-wrapping, a key
//      under 3072 bits refusing the start.
//   I. a Managed HSM oct-HSM key: A256GCM with the AAD, a moved row refused.
//   K. (#391 P5) the key-encryption key rotated FROM HERE in each KMS: a new
//      version made (Transit, Cloud KMS, Key Vault) and every data key
//      re-wrapped at once, without a restart; AWS on demand, behind the same
//      key id, re-wrapping nothing.
//   L. (2026-11-14, found by #444's port) an EMPTY ciphertext or plaintext
//      from AWS KMS, Cloud KMS or Key Vault is refused (STS-KEYS-0103), not
//      stored or used — an empty Uint8Array is truthy; a Key Vault RSA
//      modulus answered with a leading zero byte is counted by its bits, in
//      the handle, the probe and the 3072-bit floor; and a Key Vault key with
//      no version refuses the start before anything is wrapped
//      (STS-KEYS-0198).
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
      const m = /^\/v1\/transit\/(keys|encrypt|decrypt)\/([^/]+)(\/rotate)?$/
        .exec(req.url);
      const k = m ? transit.keys[decodeURIComponent(m[2])] : null;
      if (!k) {
        return reply(404, { errors: ['no such key'] });
      }
      const json = body ? JSON.parse(body) : {};
      transit.calls.push({ op: m[3] ? 'rotate' : m[1], json: json });
      if (m[3]) {
        k.versions.push(nodeCrypto.randomBytes(32));
        return reply(200, {});
      }
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
                calls: [], empty: {} };
  function cmd(name) {
    return function (input) { this.name = name; this.input = input; };
  }
  const fakeKmsSdk = {
    KMSClient: function () {
      this.send = async function (c) {
        kms.calls.push({ name: c.name, input: c.input });
        if (c.name === 'RotateKeyOnDemand') {
          return { KeyId: c.input.KeyId };
        }
        if (c.name === 'DescribeKey') {
          return { KeyMetadata: { KeyId: 'k-1', Arn: 'arn:aws:kms:x:1:key/k-1',
                                  KeyUsage: 'ENCRYPT_DECRYPT',
                                  KeySpec: kms.spec, Enabled: true } };
        }
        const ctx = Buffer.from(JSON.stringify(c.input.EncryptionContext ||
                                               {}), 'utf8');
        if (kms.empty[c.name]) {
          // An EMPTY Uint8Array, as the SDK answers bytes: truthy (section L).
          return c.name === 'Encrypt' ? { CiphertextBlob: new Uint8Array(0) } :
                                        { Plaintext: new Uint8Array(0) };
        }
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
    GetKeyRotationStatusCommand: cmd('GetKeyRotationStatus'),
    RotateKeyOnDemandCommand: cmd('RotateKeyOnDemand')
  };

  // ------------------------------------------------------------- CLOUD KMS
  // A fake `@google-cloud/kms`: a CryptoKey of versions, the primary the one
  // encrypt uses, decrypt finding the version in the ciphertext as Cloud KMS
  // does, the additional authenticated data bound.
  const KEY_NAME = 'projects/p/locations/global/keyRings/r/cryptoKeys/dek';
  const gkms = { versions: [nodeCrypto.randomBytes(32)], primary: 1,
                 purpose: 'ENCRYPT_DECRYPT', calls: [], empty: {} };
  const fakeGcpKms = {
    KeyManagementServiceClient: function () {
      this.getCryptoKey = async function (r) {
        gkms.calls.push({ op: 'getCryptoKey', r: r });
        return [{ name: r.name, purpose: gkms.purpose,
                  versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
                                     protectionLevel: 'SOFTWARE' },
                  primary: { name: r.name + '/cryptoKeyVersions/' +
                                   gkms.primary, state: 'ENABLED' } }];
      };
      this.encrypt = async function (r) {
        gkms.calls.push({ op: 'encrypt', r: r });
        const v = gkms.primary;
        if (gkms.empty.encrypt) {
          return [{ name: r.name + '/cryptoKeyVersions/' + v,
                    ciphertext: Buffer.alloc(0) }];
        }
        const blob = gcm(gkms.versions[v - 1], r.plaintext,
                         r.additionalAuthenticatedData);
        return [{ name: r.name + '/cryptoKeyVersions/' + v,
                  ciphertext: Buffer.concat([Buffer.from([v]), blob]) }];
      };
      this.createCryptoKeyVersion = async function (r) {
        gkms.calls.push({ op: 'createCryptoKeyVersion', r: r });
        gkms.versions.push(nodeCrypto.randomBytes(32));
        return [{ name: r.parent + '/cryptoKeyVersions/' +
                        gkms.versions.length, state: 'ENABLED' }];
      };
      this.updateCryptoKeyPrimaryVersion = async function (r) {
        gkms.calls.push({ op: 'updateCryptoKeyPrimaryVersion', r: r });
        gkms.primary = Number(r.cryptoKeyVersionId);
        return [{ name: r.name }];
      };
      this.decrypt = async function (r) {
        gkms.calls.push({ op: 'decrypt', r: r });
        if (gkms.empty.decrypt) {
          return [{ plaintext: Buffer.alloc(0) }];
        }
        const ct = Buffer.from(r.ciphertext);
        const key = gkms.versions[ct[0] - 1];
        try {
          return [{ plaintext: ungcm(key, ct.subarray(1),
                                     r.additionalAuthenticatedData) }];
        } catch (e) {
          throw new Error('3 INVALID_ARGUMENT: Decryption failed');
        }
      };
    }
  };

  // ------------------------------------------------------------- KEY VAULT
  // A fake `@azure/keyvault-keys` (and `@azure/identity`): one key of
  // versions, RSA (wrapKey/unwrapKey with real RSA-OAEP-256) or oct-HSM
  // (A256GCM with AAD), a CryptographyClient per versioned key id.
  // `empty` names the operations that answer an empty Uint8Array,
  // `noVersion` drops the version from getKey(), and `leadingZero` answers
  // `n` with a leading zero byte, as Key Vault does (section L).
  const akv = { type: 'RSA', bits: 3072, versions: [], calls: [], empty: {},
                noVersion: false, leadingZero: false };
  const NOTHING = new Uint8Array(0);
  function akvVersion() {
    const v = 'v' + nodeCrypto.randomBytes(6).toString('hex');
    if (akv.type === 'oct-HSM') {
      akv.versions.push({ id: v, secret: nodeCrypto.randomBytes(32) });
    } else {
      const pair = nodeCrypto.generateKeyPairSync('rsa',
        { modulusLength: akv.bits });
      akv.versions.push({ id: v, pair: pair });
    }
  }
  function akvFind(id) {
    return akv.versions.filter(function (one) { return one.id === id; })[0];
  }
  const OAEP = { padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
                 oaepHash: 'sha256' };
  const fakeAzureKeys = {
    KeyClient: function (vault) {
      this.rotateKey = async function (name) {
        akv.calls.push({ op: 'rotateKey', vault: vault, name: name });
        akvVersion();
        return { name: name, properties: {
          version: akv.versions[akv.versions.length - 1].id } };
      };
      this.getKey = async function (name) {
        akv.calls.push({ op: 'getKey', vault: vault, name: name });
        const cur = akv.versions[akv.versions.length - 1];
        let n = cur.pair ?
          Buffer.from(cur.pair.publicKey.export({ format: 'jwk' }).n,
                      'base64url') : undefined;
        if (n && akv.leadingZero) {
          n = Buffer.concat([Buffer.from([0]), n]);
        }
        return { id: vault + '/keys/' + name +
                     (akv.noVersion ? '' : '/' + cur.id), name: name,
                 keyType: akv.type, key: { n: n },
                 keyOperations: akv.type === 'oct-HSM' ?
                   ['encrypt', 'decrypt'] : ['wrapKey', 'unwrapKey'],
                 properties: { enabled: true,
                               version: akv.noVersion ? undefined : cur.id } };
      };
    },
    CryptographyClient: function (kid) {
      const one = akvFind(String(kid).split('/').pop());
      this.wrapKey = async function (alg, key) {
        akv.calls.push({ op: 'wrapKey', alg: alg, kid: kid });
        if (akv.empty.wrapKey) {
          return { result: NOTHING };
        }
        return { result: nodeCrypto.publicEncrypt(
          Object.assign({ key: one.pair.publicKey }, OAEP), key) };
      };
      this.unwrapKey = async function (alg, wrapped) {
        akv.calls.push({ op: 'unwrapKey', alg: alg, kid: kid });
        if (akv.empty.unwrapKey) {
          return { result: NOTHING };
        }
        return { result: nodeCrypto.privateDecrypt(
          Object.assign({ key: one.pair.privateKey }, OAEP), wrapped) };
      };
      this.encrypt = async function (r) {
        akv.calls.push({ op: 'encrypt', r: r, kid: kid });
        const blob = gcm(one.secret, r.plaintext,
                         r.additionalAuthenticatedData);
        const e = akv.empty.encrypt || {};
        return { result: e.result ? NOTHING : blob.subarray(28),
                 iv: e.iv ? NOTHING : blob.subarray(0, 12),
                 authenticationTag: e.tag ? NOTHING : blob.subarray(12, 28) };
      };
      this.decrypt = async function (r) {
        akv.calls.push({ op: 'decrypt', r: r, kid: kid });
        if (akv.empty.decrypt) {
          return { result: NOTHING };
        }
        return { result: ungcm(one.secret, Buffer.concat([
          Buffer.from(r.iv), Buffer.from(r.authenticationTag),
          Buffer.from(r.ciphertext)]), r.additionalAuthenticatedData) };
      };
    }
  };
  const fakeAzureIdentity = { DefaultAzureCredential: function () {} };

  // ------------------------------------------------------- SECRET MANAGER
  // A fake `@google-cloud/secret-manager` whose one version's payload is an
  // EMPTY Buffer — truthy, which is what section L asserts is refused.
  const fakeSecretManager = {
    SecretManagerServiceClient: function () {
      this.accessSecretVersion = async function (r) {
        return [{ name: r.name, payload: { data: Buffer.alloc(0) } }];
      };
    }
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
      if (name === '@google-cloud/kms') {
        return fakeGcpKms;
      }
      if (name === '@azure/keyvault-keys') {
        return fakeAzureKeys;
      }
      if (name === '@azure/identity') {
        return fakeAzureIdentity;
      }
      if (name === '@google-cloud/secret-manager') {
        return fakeSecretManager;
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
    // A password with no location of its own borrows the KEK's — but not
    // from a KMS key, whose `ref` is a key's name and no place to read.
    process.env.STS_DATABASE_PASSWORD_PROVIDER = 'vault';
    const dbAt = JSON.stringify(secrets.describeDatabasePassword());
    delete process.env.STS_DATABASE_PASSWORD_PROVIDER;
    note(dbAt.indexOf('dek-key') < 0 && !/"shared":true/.test(dbAt),
         'A5. a secret with no location borrows none from a KMS key', dbAt);

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
    // ROTATED FROM HERE (#391 P5): a new version, re-wrapped live.
    const kRot = await keystore.rotateKek();
    await keystore.settleDeks();
    const kRow = rows.get('dek:service:default') || '';
    note(kRot.ok && kRot.version === 'v3' && kRot.rewrapped >= 1 &&
         /vault:v3:/.test(kRow) && !/vault:v2:/.test(kRow) &&
         transit.calls.some(function (c) { return c.op === 'rotate'; }),
         'K1. Transit: a rotation from here makes version 3 and re-wraps ' +
         'every data key at once, without a restart', JSON.stringify(kRot));
    await restart();
    note(keystore.open(v1, 'minted-rows') === 'alpha',
         'K2. and after a restart the values open');

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
    process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';
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
    const aRot = await keystore.rotateKek();
    note(aRot.ok && aRot.rewrapped === 0 && /same key id/.test(aRot.note) &&
         kms.calls.some(function (c) { return c.name === 'RotateKeyOnDemand'; }),
         'K3. AWS KMS: a rotation from here is on demand, behind the same ' +
         'key id, and re-wraps nothing', JSON.stringify(aRot));
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

    // A start that must fail, its message, or '' when it did not.
    async function refusal() {
      try {
        await restart();
      } catch (e) {
        return String((e && e.message) || e);
      }
      return '';
    }
    // The default realm's row moved onto another realm's, the start's
    // answer, and the row put back.
    async function movedRefusal() {
      const keep = rows.get('dek:service:default');
      const own = JSON.parse(keep);
      rows.delete('dek:service:default');
      rows.set('dek:service:other', JSON.stringify({ v: own.v,
        scope: 'service', realm: 'other', deks: own.deks }));
      const why = await refusal();
      rows.delete('dek:service:other');
      rows.set('dek:service:default', keep);
      return why;
    }

    // ------------------------------------------------------------ G
    rows.clear();
    process.env.STS_KEYS_KEK_PROVIDER = 'gcp-kms';
    process.env.STS_KEYS_KEK_REF = KEY_NAME;
    await restart();
    const g1 = keystore.seal('gamma', 'minted-rows', undefined,
                             { realm: '' });
    await keystore.settleDeks();
    const gRow = rows.get('dek:service:default') || '';
    note(/\$dekkms\$1\$gcp-kms\$[A-Za-z0-9_-]+\$1:/.test(gRow),
         'G1. Cloud KMS: the row holds its ciphertext and the version used',
         gRow.slice(0, 160));
    note(gkms.calls.filter(function (c) { return c.op === 'encrypt'; })
      .every(function (c) {
        return /^sts dek v1\|/.test(String(c.r.additionalAuthenticatedData));
      }), 'G2. every wrap carries the data key\'s AAD');
    await restart();
    note(keystore.open(g1, 'minted-rows') === 'gamma' &&
         gkms.calls.some(function (c) { return c.op === 'decrypt'; }),
         'G3. a restart asks Cloud KMS to unwrap, and the values open');
    gkms.versions.push(nodeCrypto.randomBytes(32));
    gkms.primary = 2;
    await restart();
    await keystore.settleDeks();
    const gRotated = rows.get('dek:service:default') || '';
    note(/\$2:/.test(gRotated) && !/\$1:/.test(gRotated),
         'G4. a new primary version: every data key is re-wrapped under it',
         gRotated.slice(0, 160));
    await restart();
    note(keystore.open(g1, 'minted-rows') === 'gamma',
         'G5. and the values still open');
    const gRot = await keystore.rotateKek();
    await keystore.settleDeks();
    const gRow3 = rows.get('dek:service:default') || '';
    note(gRot.ok && gRot.version === '3' && gkms.primary === 3 &&
         /\$3:/.test(gRow3) && !/\$2:/.test(gRow3),
         'K4. Cloud KMS: a rotation from here makes version 3 primary and ' +
         're-wraps every data key under it', JSON.stringify(gRot));
    const gMoved = await movedRefusal();
    note(/STS-KEYS-0091/.test(gMoved),
         'G6. a wrapped key moved to another realm\'s row is refused by the ' +
         'KMS', gMoved.slice(0, 200));
    process.env.STS_KEYS_KEK_REF = KEY_NAME + '/cryptoKeyVersions/2';
    const gVersion = await refusal();
    note(/STS-KEYS-0102/.test(gVersion),
         'G7. a key VERSION named instead of the key refuses the start',
         gVersion);
    process.env.STS_KEYS_KEK_REF = KEY_NAME;
    gkms.purpose = 'ASYMMETRIC_DECRYPT';
    const gPurpose = await refusal();
    note(/STS-KEYS-0102/.test(gPurpose),
         'G8. a key that is not ENCRYPT_DECRYPT refuses the start', gPurpose);

    // ------------------------------------------------------------ H
    rows.clear();
    akvVersion();
    process.env.STS_KEYS_KEK_PROVIDER = 'azure-keys';
    process.env.STS_KEYS_KEK_REF = 'dek';
    process.env.STS_KEYS_KEK_VAULT = 'https://v.vault.azure.net/';
    await restart();
    const h1 = keystore.seal('eta', 'minted-rows', undefined, { realm: '' });
    await keystore.settleDeks();
    const hRow = rows.get('dek:service:default') || '';
    note(/\$dekkms\$1\$azure-keys\$/.test(hRow) &&
         hRow.indexOf('$' + akv.versions[0].id + ':') > 0 &&
         akv.calls.some(function (c) {
           return c.op === 'wrapKey' && c.alg === 'RSA-OAEP-256';
         }),
         'H1. Key Vault RSA: the row holds an RSA-OAEP-256 wrap and the ' +
         'version used', hRow.slice(0, 160));
    await restart();
    note(keystore.open(h1, 'minted-rows') === 'eta',
         'H2. a restart unwraps in the vault, and the values open');
    const hMoved = await movedRefusal();
    note(/STS-KEYS-0091/.test(hMoved),
         'H3. a wrapped key moved to another realm\'s row unwraps in the ' +
         'vault and is refused here, by its AAD digest', hMoved.slice(0, 200));
    akvVersion();
    await restart();
    await keystore.settleDeks();
    const hRotated = rows.get('dek:service:default') || '';
    note(hRotated.indexOf('$' + akv.versions[1].id + ':') > 0 &&
         hRotated.indexOf('$' + akv.versions[0].id + ':') < 0,
         'H4. a new key version: every data key is re-wrapped under it');
    const hRot = await keystore.rotateKek();
    await keystore.settleDeks();
    const hNew = akv.versions[akv.versions.length - 1].id;
    note(hRot.ok && hRot.version === hNew &&
         (rows.get('dek:service:default') || '').indexOf('$' + hNew + ':') > 0,
         'K5. Key Vault: a rotation from here makes a new version and ' +
         're-wraps every data key under it', JSON.stringify(hRot));
    await restart();
    note(keystore.open(h1, 'minted-rows') === 'eta',
         'K6. and after a restart the values open');
    akv.bits = 2048;
    akvVersion();
    const hWeak = await refusal();
    note(/STS-KEYS-0102/.test(hWeak),
         'H5. an RSA key under 3072 bits refuses the start', hWeak);

    // ------------------------------------------------------------ I
    rows.clear();
    akv.type = 'oct-HSM';
    akv.versions = [];
    akvVersion();
    await restart();
    const i1 = keystore.seal('iota', 'minted-rows', undefined, { realm: '' });
    await keystore.settleDeks();
    note(akv.calls.some(function (c) {
      return c.op === 'encrypt' && c.r.algorithm === 'A256GCM' &&
             /^sts dek v1\|/.test(String(c.r.additionalAuthenticatedData));
    }), 'I1. a Managed HSM oct-HSM key: A256GCM with the data key\'s AAD');
    await restart();
    note(keystore.open(i1, 'minted-rows') === 'iota',
         'I2. and a restart unwraps, and the values open');
    const iMoved = await movedRefusal();
    note(/STS-KEYS-0091/.test(iMoved),
         'I3. a wrapped key moved to another realm\'s row is refused by the ' +
         'HSM', iMoved.slice(0, 200));

    // ------------------------------------------------------------ L
    // THE ANSWER CHECKS AND THE KEY SIZE (2026-11-14, found by #444's port).
    // Each KMS's handle is asked directly, through `secrets.readKek()`, with
    // its fake answering what a broken or surprising KMS would.
    const errorCodes = require(ROOT + '/common/error_codes');
    const AAD = 'sts dek v1|L|service||minted-rows';
    const DEK = nodeCrypto.randomBytes(32);
    // The code a wrap or unwrap was refused with, or '' when it was not.
    async function refusedWith(fn) {
      try {
        await fn();
      } catch (e) {
        return errorCodes.codeOf(e) || String((e && e.message) || e);
      }
      return '';
    }
    useAws();
    kms.spec = 'SYMMETRIC_DEFAULT';
    const lAws = await secrets.readKek();
    const lAwsText = await lAws.wrap(DEK, AAD);
    kms.empty.Encrypt = true;
    const lAwsWrap = await refusedWith(function () {
      return lAws.wrap(DEK, AAD);
    });
    kms.empty.Encrypt = false;
    note(lAwsWrap === 'STS-KEYS-0103',
         'L1. AWS KMS answering an EMPTY CiphertextBlob is refused, not ' +
         'stored', lAwsWrap);
    kms.empty.Decrypt = true;
    const lAwsUnwrap = await refusedWith(function () {
      return lAws.unwrap(lAwsText, AAD);
    });
    kms.empty.Decrypt = false;
    note(lAwsUnwrap === 'STS-KEYS-0103',
         'L2. AWS KMS answering an EMPTY Plaintext is refused, not used as ' +
         'a data key', lAwsUnwrap);

    process.env.STS_KEYS_KEK_PROVIDER = 'gcp-kms';
    process.env.STS_KEYS_KEK_REF = KEY_NAME;
    gkms.purpose = 'ENCRYPT_DECRYPT';
    const lGcp = await secrets.readKek();
    const lGcpText = await lGcp.wrap(DEK, AAD);
    gkms.empty.encrypt = true;
    const lGcpWrap = await refusedWith(function () {
      return lGcp.wrap(DEK, AAD);
    });
    gkms.empty.encrypt = false;
    note(lGcpWrap === 'STS-KEYS-0103',
         'L3. Cloud KMS answering an EMPTY ciphertext (with a version) is ' +
         'refused, not stored', lGcpWrap);
    gkms.empty.decrypt = true;
    const lGcpUnwrap = await refusedWith(function () {
      return lGcp.unwrap(lGcpText, AAD);
    });
    gkms.empty.decrypt = false;
    note(lGcpUnwrap === 'STS-KEYS-0103',
         'L4. Cloud KMS answering an EMPTY plaintext is refused, not used ' +
         'as a data key', lGcpUnwrap);

    process.env.STS_KEYS_KEK_PROVIDER = 'azure-keys';
    process.env.STS_KEYS_KEK_REF = 'dek';
    process.env.STS_KEYS_KEK_VAULT = 'https://v.vault.azure.net/';
    akv.type = 'oct-HSM';
    akv.versions = [];
    akvVersion();
    const lOct = await secrets.readKek();
    const lOctText = await lOct.wrap(DEK, AAD);
    const lOctEmpty = [];
    for (const piece of ['result', 'iv', 'tag']) {
      akv.empty.encrypt = {};
      akv.empty.encrypt[piece] = true;
      lOctEmpty.push(piece + '=' + await refusedWith(function () {
        return lOct.wrap(DEK, AAD);
      }));
    }
    akv.empty.encrypt = null;
    note(lOctEmpty.every(function (one) {
      return /=STS-KEYS-0103$/.test(one);
    }), 'L5. a Managed HSM answering an EMPTY ciphertext, iv or tag is ' +
        'refused, not stored', lOctEmpty.join(' '));
    akv.empty.decrypt = true;
    const lOctUnwrap = await refusedWith(function () {
      return lOct.unwrap(lOctText, AAD);
    });
    akv.empty.decrypt = false;
    note(lOctUnwrap === 'STS-KEYS-0103',
         'L6. a Managed HSM answering an EMPTY plaintext is refused, not ' +
         'used as a data key', lOctUnwrap);

    akv.type = 'RSA';
    akv.bits = 3072;
    akv.versions = [];
    akvVersion();
    akv.leadingZero = true;
    const lRsa = await secrets.readKek();
    const lProbes = await Promise.all(secrets.PROBES['azure-keys']
      .secret(secrets.KEK));
    const lBits = lProbes[0] && lProbes[0].data && lProbes[0].data.bits;
    note(/\(RSA 3072\)$/.test(lRsa.label) && lBits === 3072,
         'L7. a 3072-bit Key Vault key whose n carries a leading zero byte ' +
         'is reported as 3072 bits, by the handle and by the probe',
         lRsa.label + ' / probe ' + lBits);
    const lRsaText = await lRsa.wrap(DEK, AAD);
    akv.empty.wrapKey = true;
    const lRsaWrap = await refusedWith(function () {
      return lRsa.wrap(DEK, AAD);
    });
    akv.empty.wrapKey = false;
    akv.empty.unwrapKey = true;
    const lRsaUnwrap = await refusedWith(function () {
      return lRsa.unwrap(lRsaText, AAD);
    });
    akv.empty.unwrapKey = false;
    note(lRsaWrap === 'STS-KEYS-0103' && lRsaUnwrap === 'STS-KEYS-0103',
         'L8. Key Vault answering an EMPTY wrapped or unwrapped key is ' +
         'refused', lRsaWrap + ' ' + lRsaUnwrap);
    akv.bits = 3064;
    akv.versions = [];
    akvVersion();
    const lShort = await refusal();
    note(/STS-KEYS-0102/.test(lShort) && /RSA 3064-bit/.test(lShort),
         'L9. a 3064-bit key whose n carries a leading zero byte (384 bytes) ' +
         'is under 3072 bits and refuses the start', lShort);
    akv.bits = 3072;
    akv.versions = [];
    akvVersion();
    akv.noVersion = true;
    rows.clear();
    const lNoVersion = await refusal();
    const lRows = Array.from(rows.keys());
    note(/STS-KEYS-0198/.test(lNoVersion) &&
         !lRows.some(function (k) { return /^dek:/.test(k); }),
         'L10. a Key Vault key answered with no version refuses the start ' +
         'before anything is wrapped: no data-key row is written',
         lNoVersion + ' rows=' + lRows.join(','));
    akv.noVersion = false;
    akv.leadingZero = false;
    process.env.STS_KEYS_KEK_PROVIDER = 'gcp';
    process.env.STS_KEYS_KEK_REF = 'projects/p/secrets/kek';
    const lPayload = await refusedWith(function () {
      return secrets.readKek();
    });
    note(lPayload === 'STS-KEYS-0048',
         'L11. Secret Manager answering an EMPTY payload is refused as no ' +
         'value, not handed back as the key', lPayload);
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
