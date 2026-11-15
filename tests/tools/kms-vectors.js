// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: tests/tools/kms-vectors.js
//
// ---------------------------------------------------------------------------
// THE CLOUD KEY-ENCRYPTION KEYS' VECTORS (#444, phase 3): `kms-node.json`,
// built through `tests/tools/crypto-vectors.js`'s VECTORS row, and Node's
// check of what Rust wrote back (`kms-pkcs12-rust.json` from sts-crypto,
// `kms-rust.json` from sts-core), called from
// `tests/rust_crypto_vectors.js`. Two things are proved against Node:
//
//   * pkcs12 — the PKCS#12 an Azure client certificate in PEM becomes for
//     `azure_identity` (`sts_crypto::keys::pkcs12_of_pem`). Node's
//     `@azure/identity` reads AZURE_CLIENT_CERTIFICATE_PATH as a PEM itself:
//     every CERTIFICATE block in order (the first the one whose SHA-1
//     thumbprint is sent, the rest its chain) and the private key
//     `createPrivateKey({ key, passphrase })` finds. Each case here is a PEM
//     made per run, with what Node reads out of it; Rust builds the PKCS#12,
//     opens it again and compares, and writes it back, and Node opens
//     Rust's PKCS#12 — `tls.createSecureContext({ pfx, passphrase })`, then
//     node-forge for its bags — and finds the same certificates and key.
//
//   * azure — develop's #1789, the cloud answer checks: a Key Vault RSA
//     modulus counted in bits (`rsaModulusBits()`), the version a key must
//     carry (STS-KEYS-0198), and the sentence each provider refuses an EMPTY
//     answer with (`noBytes()`). Node is driven through
//     `secrets.setSdkLoader()` with fake SDKs, as `tests/kms_kek.js` section
//     L drives it, and what it answered is recorded: Rust compares its own
//     answers to the same inputs, and writes them back for Node to compare
//     here.
//
// The output carries private keys and is never committed (tests/vectors/ is
// gitignored).
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'kms-vectors',
  level: process.env.STS_LOG_LEVEL || 'info' });

const VAULT = 'https://v.vault.azure.net';
const KEY = 'dek';

/**
 * What `@azure/identity`'s `parseCertificate()` takes out of a PEM: the
 * CERTIFICATE blocks' DER in order, the first one's SHA-1 thumbprint, and
 * the private key's public half (SPKI DER), or the refusal.
 *
 * @param {string} pem - the file's text
 * @param {string} password - AZURE_CLIENT_CERTIFICATE_PASSWORD, or ''
 * @returns {object} the parts
 */
function identityParts(pem, password) {
  log.debug("Entering identityParts().");
  const pattern = new RegExp('(-+BEGIN CERTIFICATE-+)(\\n\\r?|\\r\\n?)' +
    '([A-Za-z0-9+/\\n\\r]+=*)(\\n\\r?|\\r\\n?)(-+END CERTIFICATE-+)', 'g');
  const certs = [];
  let match;
  do {
    match = pattern.exec(pem);
    if (match) {
      certs.push(Buffer.from(match[3], 'base64'));
    }
  } while (match);
  if (!certs.length) {
    log.debug("Leaving identityParts(). No certificate.");
    return { refusal: 'The file at the specified path does not contain a ' +
                      'PEM-encoded certificate.' };
  }
  const key = nodeCrypto.createPrivateKey({ key: pem, format: 'pem',
                                            passphrase: password ||
                                              undefined });
  log.debug("Leaving identityParts().");
  return {
    leaf: certs[0].toString('base64'),
    chain: certs.slice(1).map(function (c) {
      return c.toString('base64');
    }),
    thumbprint: nodeCrypto.createHash('sha1').update(certs[0])
      .digest('hex').toUpperCase(),
    spki: nodeCrypto.createPublicKey(key)
      .export({ type: 'spki', format: 'der' }).toString('base64')
  };
}

/**
 * The PEM cases, each made this run.
 *
 * @param {string} root - the repository
 * @returns {Array<object>} the cases
 */
function pkcs12Cases(root) {
  log.debug("Entering pkcs12Cases().");
  const crypto = require(path.join(root, 'common', 'crypto'));
  const leaf = crypto.selfSignedRsaCertificate({ commonName: 'sts azure',
                                                 bits: 2048 });
  const ca = crypto.selfSignedRsaCertificate({ commonName: 'sts azure ca',
                                               bits: 2048 });
  const pkcs1 = nodeCrypto.createPrivateKey(leaf.privateKeyPem)
    .export({ type: 'pkcs1', format: 'pem' });
  const encrypted = nodeCrypto.createPrivateKey(leaf.privateKeyPem)
    .export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc',
              passphrase: 'pässword 1' });
  const cases = [
    { name: 'certificate then PKCS#8 key', password: '',
      pem: leaf.certPem + leaf.privateKeyPem },
    { name: 'PKCS#1 key first, then the certificate', password: '',
      pem: pkcs1 + leaf.certPem },
    { name: 'a chain of two', password: '',
      pem: leaf.certPem + ca.certPem + leaf.privateKeyPem },
    { name: 'an encrypted key and its password', password: 'pässword 1',
      pem: leaf.certPem + encrypted },
    { name: 'a password and a key that is not encrypted', password: 'x',
      pem: leaf.certPem + leaf.privateKeyPem },
    { name: 'no certificate', password: '', pem: leaf.privateKeyPem }
  ];
  cases.forEach(function (one) {
    Object.assign(one, identityParts(one.pem, one.password));
  });
  log.debug("Leaving pkcs12Cases(). " + cases.length + ".");
  return cases;
}

/**
 * Fake SDKs, each answering what a case asks.
 *
 * @param {object} ask - the case's knobs, changed between calls
 * @returns {Function} the SDK loader
 */
function fakeSdks(ask) {
  log.debug("Entering fakeSdks().");
  const NOTHING = new Uint8Array(0);
  const SOME = Buffer.alloc(48, 7);
  function cmd(name) {
    return function (input) {
      this.name = name;
      this.input = input;
    };
  }
  const aws = {
    KMSClient: function () {
      this.send = async function (c) {
        if (c.name === 'DescribeKey') {
          return { KeyMetadata: { KeyId: 'k-1', Arn: 'arn:aws:kms:x:1:key/k-1',
                                  KeyUsage: 'ENCRYPT_DECRYPT',
                                  KeySpec: 'SYMMETRIC_DEFAULT',
                                  Enabled: true } };
        }
        if (c.name === 'Encrypt') {
          return { CiphertextBlob: ask.empty ? NOTHING : SOME };
        }
        if (c.name === 'Decrypt') {
          return { Plaintext: ask.empty ? NOTHING : SOME.subarray(0, 32) };
        }
        return {};
      };
    },
    DescribeKeyCommand: cmd('DescribeKey'),
    EncryptCommand: cmd('Encrypt'),
    DecryptCommand: cmd('Decrypt'),
    GetKeyRotationStatusCommand: cmd('GetKeyRotationStatus'),
    RotateKeyOnDemandCommand: cmd('RotateKeyOnDemand')
  };
  const gcp = {
    KeyManagementServiceClient: function () {
      this.getCryptoKey = async function (r) {
        return [{ name: r.name, purpose: 'ENCRYPT_DECRYPT',
                  versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
                                     protectionLevel: 'SOFTWARE' },
                  primary: { name: r.name + '/cryptoKeyVersions/1',
                             state: 'ENABLED' } }];
      };
      this.encrypt = async function (r) {
        return [{ name: r.name + '/cryptoKeyVersions/1',
                  ciphertext: ask.empty ? Buffer.alloc(0) : SOME }];
      };
      this.decrypt = async function () {
        return [{ plaintext: ask.empty ? Buffer.alloc(0) :
                                         SOME.subarray(0, 32) }];
      };
    }
  };
  const azureKeys = {
    KeyClient: function (vault) {
      this.getKey = async function (name) {
        return { id: vault + '/keys/' + name + '/' + (ask.version || ''),
                 name: name, keyType: ask.type,
                 key: { n: ask.n }, keyOperations: ask.ops,
                 properties: { enabled: true, version: ask.version } };
      };
    },
    CryptographyClient: function () {
      this.wrapKey = async function () {
        return { result: ask.empty ? NOTHING : SOME };
      };
      this.unwrapKey = async function () {
        return { result: NOTHING };
      };
      this.encrypt = async function () {
        const e = ask.emptyPiece || '';
        return { result: e === 'result' ? NOTHING : SOME,
                 iv: e === 'iv' ? NOTHING : SOME.subarray(0, 12),
                 authenticationTag: e === 'tag' ? NOTHING :
                                                  SOME.subarray(0, 16) };
      };
      this.decrypt = async function () {
        return { result: NOTHING };
      };
    }
  };
  const identity = { DefaultAzureCredential: function () {} };
  const secretManager = {
    SecretManagerServiceClient: function () {
      this.accessSecretVersion = async function (r) {
        return [{ name: r.name, payload: { data: Buffer.alloc(0) } }];
      };
    }
  };
  log.debug("Leaving fakeSdks().");
  return function (name) {
    const sdks = { '@aws-sdk/client-kms': aws, '@google-cloud/kms': gcp,
                   '@azure/keyvault-keys': azureKeys,
                   '@azure/identity': identity,
                   '@google-cloud/secret-manager': secretManager };
    if (!sdks[name]) {
      throw new Error('Cannot find module \'' + name + '\'');
    }
    return sdks[name];
  };
}

/**
 * What Node answers, through its fake SDKs: the modulus sizes, the
 * versions, and the empty answers.
 *
 * @param {string} root - the repository
 * @returns {Promise<object>} the azure section
 */
async function azureCases(root) {
  log.debug("Entering azureCases().");
  const secrets = require(path.join(root, 'common', 'secrets'));
  const errorCodes = require(path.join(root, 'common', 'error_codes'));
  const ask = { type: 'RSA', ops: ['wrapKey', 'unwrapKey'], version: 'v1',
                n: undefined, empty: false, emptyPiece: '' };
  secrets.setSdkLoader(fakeSdks(ask));
  const saved = Object.assign({}, process.env);
  async function outcome(fn) {
    try {
      const value = await fn();
      return { ok: true, value: value };
    } catch (e) {
      return { ok: false, code: errorCodes.codeOf(e) || '',
               message: String((e && e.message) || e) };
    }
  }
  function useAzure() {
    process.env.STS_KEYS_KEK_PROVIDER = 'azure-keys';
    process.env.STS_KEYS_KEK_REF = KEY;
    process.env.STS_KEYS_KEK_VAULT = VAULT + '/';
  }
  // A modulus of `bits` significant bits in `bytes` bytes, leading zeros
  // first.
  function modulus(bytes, bits) {
    const n = nodeCrypto.randomBytes(bytes);
    const zeros = bytes - Math.ceil(bits / 8);
    n.fill(0, 0, zeros);
    const top = bits % 8 || 8;
    n[zeros] = (n[zeros] & ((1 << top) - 1)) | (1 << (top - 1));
    return n;
  }
  const out = { vault: VAULT, key: KEY, moduli: [], versions: [],
                empty: [] };
  useAzure();
  const moduli = [['3072 bits with a leading zero byte', modulus(385, 3072)],
                  ['3072 bits in 384 bytes', modulus(384, 3072)],
                  ['3064 bits with a leading zero byte', modulus(385, 3064)],
                  ['4096 bits', modulus(512, 4096)],
                  ['2048 bits', modulus(256, 2048)],
                  ['all zero', Buffer.alloc(384)],
                  ['no modulus', undefined]];
  for (const one of moduli) {
    ask.type = 'RSA';
    ask.ops = ['wrapKey', 'unwrapKey'];
    ask.version = 'v1';
    ask.n = one[1];
    const read = await outcome(function () {
      return secrets.readKek();
    });
    const probes = await Promise.all(secrets.PROBES['azure-keys']
      .secret(secrets.KEK));
    const probed = probes[0] && probes[0].data;
    out.moduli.push({ name: one[0],
                      n: one[1] ? one[1].toString('base64url') : null,
                      label: read.ok ? read.value.label : null,
                      code: read.ok ? '' : read.code,
                      message: read.ok ? '' : read.message,
                      probeBits: probed && probed.bits !== undefined ?
                        probed.bits : null });
  }
  ask.n = modulus(385, 3072);
  for (const version of ['0123456789abcdef0123456789ABCDEF', '', undefined,
                         'v-1', 'v1 ', 'é1']) {
    for (const type of ['RSA', 'oct-HSM']) {
      ask.type = type;
      ask.ops = type === 'RSA' ? ['wrapKey', 'unwrapKey'] :
                                 ['encrypt', 'decrypt'];
      ask.version = version;
      const read = await outcome(function () {
        return secrets.readKek();
      });
      out.versions.push({ type: type,
                          version: version === undefined ? null : version,
                          code: read.ok ? '' : read.code,
                          message: read.ok ? '' : read.message });
    }
  }
  // The empty answers: each provider's wrap and unwrap, the provider's
  // source file in sts-core beside it.
  const AAD = 'sts dek v1|K|service||minted-rows';
  const DEK = nodeCrypto.randomBytes(32);
  async function empty(file, what, fn) {
    const got = await outcome(fn);
    out.empty.push({ file: file, what: what, code: got.ok ? '' : got.code,
                     message: got.ok ? '' : got.message });
  }
  process.env.STS_KEYS_KEK_PROVIDER = 'aws-kms';
  process.env.STS_KEYS_KEK_REF = 'k-1';
  process.env.STS_KEYS_KEK_REGION = 'us-west-2';
  ask.empty = false;
  const aws = await secrets.readKek();
  const awsText = await aws.wrap(DEK, AAD);
  ask.empty = true;
  await empty('aws', 'Encrypt', function () {
    return aws.wrap(DEK, AAD);
  });
  await empty('aws', 'Decrypt', function () {
    return aws.unwrap(awsText, AAD);
  });
  process.env.STS_KEYS_KEK_PROVIDER = 'gcp-kms';
  process.env.STS_KEYS_KEK_REF =
    'projects/p/locations/global/keyRings/r/cryptoKeys/dek';
  ask.empty = false;
  const gcp = await secrets.readKek();
  const gcpText = await gcp.wrap(DEK, AAD);
  ask.empty = true;
  await empty('gcp', 'encrypt', function () {
    return gcp.wrap(DEK, AAD);
  });
  await empty('gcp', 'decrypt', function () {
    return gcp.unwrap(gcpText, AAD);
  });
  useAzure();
  ask.type = 'RSA';
  ask.ops = ['wrapKey', 'unwrapKey'];
  ask.version = 'v1';
  ask.empty = false;
  const rsa = await secrets.readKek();
  const rsaText = await rsa.wrap(DEK, AAD);
  ask.empty = true;
  await empty('azure', 'wrapKey', function () {
    return rsa.wrap(DEK, AAD);
  });
  await empty('azure', 'unwrapKey', function () {
    return rsa.unwrap(rsaText, AAD);
  });
  ask.type = 'oct-HSM';
  ask.ops = ['encrypt', 'decrypt'];
  ask.empty = false;
  const oct = await secrets.readKek();
  ask.emptyPiece = '';
  const octText = await oct.wrap(DEK, AAD);
  for (const piece of ['result', 'iv', 'tag']) {
    ask.emptyPiece = piece;
    await empty('azure', 'encrypt ' + piece, function () {
      return oct.wrap(DEK, AAD);
    });
  }
  ask.emptyPiece = '';
  await empty('azure', 'decrypt', function () {
    return oct.unwrap(octText, AAD);
  });
  process.env.STS_KEYS_KEK_PROVIDER = 'gcp';
  process.env.STS_KEYS_KEK_REF = 'projects/p/secrets/kek';
  await empty('cloud', 'accessSecretVersion', function () {
    return secrets.readKek();
  });
  secrets.setSdkLoader(null);
  Object.keys(process.env).forEach(function (k) {
    if (!(k in saved)) {
      delete process.env[k];
    }
  });
  Object.assign(process.env, saved);
  log.debug("Leaving azureCases().");
  return out;
}

/**
 * Builds `kms-node.json`.
 *
 * @param {string} root - the repository
 * @returns {Promise<object>} the vectors
 */
async function build(root) {
  log.debug("Entering build().");
  const pkcs12 = pkcs12Cases(root);
  const azure = await azureCases(root);
  log.debug("Leaving build().");
  return { pkcs12: pkcs12, azure: azure };
}

/**
 * The bags of a PKCS#12 Rust built, opened by node-forge: the certificates'
 * DER (the one with the key's local id first) and the key's public half.
 *
 * @param {Buffer} der - the PKCS#12
 * @param {string} password - its password
 * @returns {object} what it holds
 */
function forgeOpen(der, password) {
  log.debug("Entering forgeOpen().");
  const forge = require('node-forge');
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(
    der.toString('binary')));
  // A PBES2 PASSWORD IS ITS UTF-8 BYTES to OpenSSL — what built this, what
  // `azure_identity` opens it with and what node's TLS opened it with above
  // — while forge hands PBES2 the string's char codes; its MAC, a BMPString,
  // is right either way. So PBES2 is given the UTF-8 form here, or a
  // password beyond ASCII would be refused by forge alone.
  const getCipher = forge.pki.pbe.getCipher;
  forge.pki.pbe.getCipher = function (oid, params, pw) {
    return getCipher(oid, params, oid === forge.pki.oids.pkcs5PBES2 ?
      forge.util.encodeUtf8(pw) : pw);
  };
  let p12;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, true, password);
  } finally {
    forge.pki.pbe.getCipher = getCipher;
  }
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[
    forge.pki.oids.certBag] || [];
  const keyBags = (p12.getBags({
    bagType: forge.pki.oids.pkcs8ShroudedKeyBag
  })[forge.pki.oids.pkcs8ShroudedKeyBag] || []).concat(p12.getBags({
    bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || []);
  const derOf = function (bag) {
    return Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(
      bag.cert)).getBytes(), 'binary').toString('base64');
  };
  const keyed = certBags.filter(function (bag) {
    return bag.attributes && bag.attributes.localKeyId;
  });
  const rest = certBags.filter(function (bag) {
    return !(bag.attributes && bag.attributes.localKeyId);
  });
  const key = keyBags[0] && keyBags[0].key;
  const spki = key ? Buffer.from(forge.asn1.toDer(forge.pki.publicKeyToAsn1(
    forge.pki.setRsaPublicKey(key.n, key.e))).getBytes(), 'binary')
    .toString('base64') : '';
  log.debug("Leaving forgeOpen().");
  return { leaf: keyed.length ? derOf(keyed[0]) : '',
           chain: rest.map(derOf), keys: keyBags.length, spki: spki };
}

/**
 * Node's check of `kms-rust.json`.
 *
 * @param {any} t - the runner's check collector
 * @param {string} dir - the vectors directory
 */
function fromRust(t, dir) {
  log.debug("Entering fromRust().");
  // Two files, one per crate: sts-crypto's PKCS#12 and sts-core's answer
  // checks.
  const nodeFile = path.join(dir, 'kms-node.json');
  if (!fs.existsSync(nodeFile)) {
    log.debug("Leaving fromRust(). No vectors.");
    return;
  }
  const node = JSON.parse(fs.readFileSync(nodeFile, 'utf8'));
  const readIf = function (name) {
    const one = path.join(dir, name);
    return fs.existsSync(one) ? JSON.parse(fs.readFileSync(one, 'utf8'))
                              : null;
  };
  const rust = { pkcs12: (readIf('kms-pkcs12-rust.json') || {}).pkcs12,
                 azure: (readIf('kms-rust.json') || {}).azure };
  if (!rust.pkcs12 && !rust.azure) {
    log.debug("Leaving fromRust(). No Rust vectors.");
    return;
  }
  const byName = {};
  node.pkcs12.forEach(function (one) {
    byName[one.name] = one;
  });
  let opened = 0;
  (rust.pkcs12 || []).forEach(function (one) {
    const want = byName[one.name];
    if (!want) {
      t.check(false, 'kms: Rust wrote a PKCS#12 case Node did not make',
              one.name);
      return;
    }
    if (want.refusal) {
      t.check(!one.pfx && one.refusal === want.refusal,
              'kms: a PEM with no certificate is refused with Node\'s ' +
              'sentence', String(one.refusal));
      return;
    }
    const der = Buffer.from(String(one.pfx || ''), 'base64');
    let context = null;
    try {
      context = tls.createSecureContext({ pfx: der,
                                          passphrase: want.password });
    } catch (e) {
      context = null;
      log.debug("Caught in fromRust(): " + ((e && e.message) || e));
    }
    t.check(!!context, 'kms: node\'s TLS opens Rust\'s PKCS#12 with the ' +
            'password: ' + one.name);
    let parts = null;
    try {
      parts = forgeOpen(der, want.password);
    } catch (e) {
      parts = { error: (e && e.message) || String(e) };
      log.debug("Caught in fromRust(): " + parts.error);
    }
    t.check(!!parts && parts.leaf === want.leaf && parts.keys === 1 &&
            parts.spki === want.spki &&
            JSON.stringify(parts.chain) === JSON.stringify(want.chain),
            'kms: Rust\'s PKCS#12 holds the PEM\'s certificate, its chain ' +
            'in order and its key, as @azure/identity reads them: ' +
            one.name, parts && parts.error ? parts.error : '');
    opened += 1;
  });
  t.check(!rust.pkcs12 || opened === node.pkcs12.filter(function (one) {
    return !one.refusal;
  }).length, 'kms: every PKCS#12 case came back from Rust', String(opened));
  const answers = rust.azure || {};
  (answers.moduli || []).forEach(function (one, i) {
    const want = node.azure.moduli[i];
    const labelBits = want.label ? Number((/ (\d+)\)$/.exec(want.label) ||
                                           [])[1] || 0) : null;
    t.check(one.name === want.name && one.message === want.message &&
            (labelBits === null || one.bits === labelBits),
            'kms: Rust counts a Key Vault modulus as Node does: ' +
            want.name, one.bits + ' / ' + want.label + ' / ' + one.message);
  });
  (answers.versions || []).forEach(function (one, i) {
    const want = node.azure.versions[i];
    t.check(one.message === want.message && one.code === want.code,
            'kms: Rust refuses a Key Vault version as Node does: ' +
            JSON.stringify(want.version) + ' ' + want.type,
            one.code + ' ' + one.message);
  });
  log.debug("Leaving fromRust().");
}

module.exports = { build: build, fromRust: fromRust };
