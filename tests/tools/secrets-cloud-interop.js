#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: secrets-cloud-interop.js
//
// ---------------------------------------------------------------------------
// THE NODE HALF OF THE CLOUD KEY-ENCRYPTION KEY PARITY PROOF (#444 phase 3).
//
// `sts-core::secrets` ports `common/secrets.js`'s six cloud providers —
// `aws`, `gcp`, `azure` (a secret read) and `aws-kms`, `gcp-kms`,
// `azure-keys` (a key that wraps each data key) — through the official
// Rust SDKs. What must agree is what a 1.x store holds: a data key wrapped
// by Node under its AAD has to be unwrapped by Rust, and the reverse, and a
// secret has to read as the same bytes. `tests/tools/secrets-interop.js`
// proves it for OpenBao; this proves it against EMULATORS, since no test may
// dial a cloud:
//
//   * AWS: LocalStack (Secrets Manager and KMS), reached as the SDK reaches
//     any endpoint — AWS_ENDPOINT_URL — with static test credentials;
//   * Google: floci-gcp (Secret Manager and Cloud KMS on one port, gRPC for
//     Node's libraries and REST for Google's Rust ones). Node's clients are
//     handed the emulator's address here, since no Google variable names
//     one; Rust's through `Secrets::set_emulators()`;
//   * Azure: Lowkey Vault (secrets, and an RSA key wrapping with
//     RSA-OAEP-256), its managed-identity token endpoint reached as App
//     Service's is (IDENTITY_ENDPOINT, IDENTITY_HEADER). Both SDKs verify
//     that a challenge's resource is a PARENT domain of the vault's, as
//     `vault.azure.net` is of `<name>.vault.azure.net`, and Lowkey names
//     its own host — so `vaults`, below, fronts it as `vault.localhost`
//     with the challenge naming `localhost`, and the verification stays on
//     in both. Lowkey has no A256GCM, so an oct-HSM key is proved against
//     the second half of `vaults`: a Key Vault that answers only what
//     `azure-keys` asks of an oct-HSM key, with node's own AES-256-GCM, and
//     RECORDS each request (`fake-vault-requests.jsonl`), so the two
//     runtimes' requests are compared as well as their stored forms.
//     Lowkey's token endpoint answers `expires_on` as a number where App
//     Service answers a string, which `@azure/identity` forgives and
//     `azure_identity` does not, so `vaults` fronts that too, as App
//     Service answers.
//
//   node tests/tools/secrets-cloud-interop.js seed <dir>      # once
//   node tests/tools/secrets-cloud-interop.js vaults <dir>     # left up
//   node tests/tools/secrets-cloud-interop.js run <dir>
//     → secrets-cloud-node.json; with secrets-cloud-rust.json there, Rust's
//       wrapped data keys are unwrapped (secrets-cloud-node-check.json).
//
// sts-core's `tests/secrets_cloud.rs` is the other half. The environment
// (each run needs the SDKs on NODE_PATH, as optional peer dependencies):
//
//   AWS_ENDPOINT_URL=http://127.0.0.1:<port> AWS_REGION=us-east-1
//   AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
//   STS_PROBE_GCP=127.0.0.1:<port>
//   STS_PROBE_LOWKEY=https://localhost:<Lowkey's port>
//   STS_PROBE_AZURE_VAULT=https://vault.localhost:<port>  (Lowkey, fronted)
//   STS_PROBE_AZURE_FAKE=https://vault.localhost:<port>   (the oct-HSM key)
//   STS_PROBE_LOWKEY_IDENTITY=http://127.0.0.1:<Lowkey's port>
//   IDENTITY_ENDPOINT=http://127.0.0.1:<port>/metadata/identity/oauth2/token
//   IDENTITY_HEADER=probe  NODE_EXTRA_CA_CERTS=<lowkey's certificate>
//   STS_PROBE_TLS_KEY / STS_PROBE_TLS_CERT  (`vaults`', PEM: Lowkey's own,
//                                            which names *.localhost)
//
// The values are key material: the output is never committed (tests/vectors/
// is gitignored).
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const COMMAND = process.argv[2] || 'run';
const OUT = path.resolve(process.argv[3] ||
  path.join(ROOT, 'tests', 'vectors', 'sts-core'));

const GCP_PROJECT = 'iya-probe';
const GCP_RING = 'projects/' + GCP_PROJECT + '/locations/global/keyRings/sts';
const GCP_KEY = GCP_RING + '/cryptoKeys/sts-kek';
const AZURE_RSA = 'sts-kek-rsa';
const AZURE_OCT = 'sts-kek-oct';

// Fixed patterns rather than random bytes, so a run says which one failed.
function pattern(seed, length) {
  const out = Buffer.alloc(length);
  for (let j = 0; j < length; j++) {
    out[j] = (seed * 37 + j * 11) & 0xff;
  }
  return out;
}

function deks() {
  const out = [];
  for (let i = 0; i < 6; i++) {
    out.push({ dek: pattern(i, i === 5 ? 64 : 32).toString('hex'),
               aad: 'dek|v1|d' + i + '|service|' +
                    (i % 2 ? 'acme' : 'default') + '|class-' + i });
  }
  return out;
}

const KEK_JSON = JSON.stringify({ kek: pattern(91, 32).toString('base64'),
                                  databasePassword: 'probe-db-password' });

// Google's Node clients, pointed at the emulator over plaintext gRPC: the
// module objects secrets.js requires are the ones patched.
function pointGoogleAtEmulator() {
  const at = String(process.env.STS_PROBE_GCP || '');
  if (!at) {
    return;
  }
  const grpc = require('google-gax').grpc;
  const options = { apiEndpoint: at.split(':')[0], port: Number(at.split(':')[1]),
                    sslCreds: grpc.credentials.createInsecure() };
  [['@google-cloud/secret-manager', 'SecretManagerServiceClient'],
   ['@google-cloud/kms', 'KeyManagementServiceClient']].forEach(function (one) {
    const sdk = require(one[0]);
    const Real = sdk[one[1]];
    sdk[one[1]] = class extends Real {
      constructor(given) {
        super(Object.assign({}, given || {}, options));
      }
    };
  });
}

async function ignoreExisting(fn) {
  try {
    return await fn();
  } catch (e) {
    const said = String((e && (e.name || '')) + ' ' + ((e && e.message) || e));
    if (/exist|ALREADY|409|Conflict/i.test(said)) {
      return null;
    }
    throw e;
  }
}

async function seed() {
  const sm = require('@aws-sdk/client-secrets-manager');
  const smc = new sm.SecretsManagerClient({});
  await ignoreExisting(function () {
    return smc.send(new sm.CreateSecretCommand({ Name: 'sts-kek',
                                                 SecretString: KEK_JSON }));
  });
  await ignoreExisting(function () {
    return smc.send(new sm.CreateSecretCommand({
      Name: 'sts-kek-binary', SecretBinary: pattern(92, 32) }));
  });
  const kms = require('@aws-sdk/client-kms');
  const kc = new kms.KMSClient({});
  const aliases = await kc.send(new kms.ListAliasesCommand({}));
  if (!(aliases.Aliases || []).some(function (a) {
    return a.AliasName === 'alias/sts-kek';
  })) {
    const made = await kc.send(new kms.CreateKeyCommand({}));
    await kc.send(new kms.CreateAliasCommand({
      AliasName: 'alias/sts-kek', TargetKeyId: made.KeyMetadata.KeyId }));
  }
  console.log('seeded AWS');

  pointGoogleAtEmulator();
  const gsm = new (require('@google-cloud/secret-manager')
    .SecretManagerServiceClient)();
  const secret = 'projects/' + GCP_PROJECT + '/secrets/sts-kek';
  const made = await ignoreExisting(function () {
    return gsm.createSecret({ parent: 'projects/' + GCP_PROJECT,
                              secretId: 'sts-kek',
                              secret: { replication: { automatic: {} } } });
  });
  if (made) {
    await gsm.addSecretVersion({ parent: secret,
                                 payload: { data: Buffer.from(KEK_JSON) } });
  }
  const gkms = new (require('@google-cloud/kms').KeyManagementServiceClient)();
  await ignoreExisting(function () {
    return gkms.createKeyRing({ parent: 'projects/' + GCP_PROJECT +
                                        '/locations/global',
                                keyRingId: 'sts', keyRing: {} });
  });
  await ignoreExisting(function () {
    return gkms.createCryptoKey({ parent: GCP_RING, cryptoKeyId: 'sts-kek',
      cryptoKey: { purpose: 'ENCRYPT_DECRYPT', versionTemplate:
                   { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION' } } });
  });
  console.log('seeded Google');

  const identity = require('@azure/identity');
  const credential = new identity.DefaultAzureCredential();
  const vault = process.env.STS_PROBE_AZURE_VAULT;
  const sc = new (require('@azure/keyvault-secrets').SecretClient)(vault,
                                                                  credential);
  await sc.setSecret('sts-kek', KEK_JSON);
  const kc2 = new (require('@azure/keyvault-keys').KeyClient)(vault,
                                                             credential);
  await ignoreExisting(async function () {
    try {
      await kc2.getKey(AZURE_RSA);
      return null;
    } catch (e) {
      return kc2.createRsaKey(AZURE_RSA, { keySize: 3072,
        keyOps: ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'] });
    }
  });
  console.log('seeded Azure');
}

// ---------------------------------------------------------------------------
// vaults: Lowkey fronted as vault.localhost, and an oct-HSM key, A256GCM,
// over HTTPS, recording each request.
// ---------------------------------------------------------------------------
const CHALLENGE = 'Bearer authorization="https://login.microsoftonline.com/' +
                  'common", resource="https://localhost"';

function frontLowkey() {
  const https = require('https');
  const upstream = new URL(process.env.STS_PROBE_LOWKEY);
  const at = new URL(process.env.STS_PROBE_AZURE_VAULT);
  const server = https.createServer({
    key: fs.readFileSync(process.env.STS_PROBE_TLS_KEY),
    cert: fs.readFileSync(process.env.STS_PROBE_TLS_CERT)
  }, function (req, res) {
    const headers = Object.assign({}, req.headers, { host: upstream.host });
    const ask = https.request({ host: upstream.hostname, port: upstream.port,
                                method: req.method, path: req.url,
                                headers: headers }, function (answer) {
      const back = Object.assign({}, answer.headers);
      if (back['www-authenticate']) {
        back['www-authenticate'] = CHALLENGE;
      }
      res.writeHead(answer.statusCode, back);
      answer.pipe(res);
    });
    ask.on('error', function (e) {
      res.writeHead(502);
      res.end(String(e.message));
    });
    req.pipe(ask);
  });
  server.listen(Number(at.port), '::', function () {
    console.log('vaults: Lowkey fronted on ' + at.origin);
  });
}

// App Service's token endpoint, over Lowkey's: `expires_on` as a string.
function frontIdentity() {
  const http = require('http');
  const upstream = new URL(process.env.STS_PROBE_LOWKEY_IDENTITY);
  const at = new URL(process.env.IDENTITY_ENDPOINT);
  http.createServer(function (req, res) {
    http.get({ host: upstream.hostname, port: upstream.port, path: req.url,
               headers: req.headers }, function (answer) {
      let body = '';
      answer.on('data', function (c) {
        body += c;
      });
      answer.on('end', function () {
        let out = body;
        try {
          const token = JSON.parse(body);
          token.expires_on = String(token.expires_on);
          out = JSON.stringify(token);
        } catch (e) {
          // Not a token: handed back as it came.
          out = body;
        }
        res.writeHead(answer.statusCode, { 'content-type':
                                           'application/json' });
        res.end(out);
      });
    }).on('error', function (e) {
      res.writeHead(502);
      res.end(String(e.message));
    });
  }).listen(Number(at.port), '127.0.0.1', function () {
    console.log('vaults: the token endpoint on ' + at.origin);
  });
}

function fakeVault() {
  const https = require('https');
  const crypto = require('crypto');
  const versions = ['0a1b2c3d4e5f60718293a4b5c6d7e8f9'];
  const keyOf = function (v) {
    return crypto.createHash('sha256').update('probe-oct|' + v).digest();
  };
  const log = path.join(OUT, 'fake-vault-requests.jsonl');
  const at = new URL(process.env.STS_PROBE_AZURE_FAKE);
  const server = https.createServer({
    key: fs.readFileSync(process.env.STS_PROBE_TLS_KEY),
    cert: fs.readFileSync(process.env.STS_PROBE_TLS_CERT)
  }, function (req, res) {
    let body = '';
    req.on('data', function (c) {
      body += c;
    });
    req.on('end', function () {
      const send = function (status, json, headers) {
        res.writeHead(status, Object.assign({ 'content-type':
                                              'application/json' }, headers));
        res.end(json === null ? '' : JSON.stringify(json));
      };
      if (!req.headers.authorization) {
        send(401, null, { 'www-authenticate': CHALLENGE });
        return;
      }
      const url = new URL(req.url, 'https://' + req.headers.host);
      const parts = url.pathname.split('/').filter(Boolean);
      const base = at.origin + '/keys/' + AZURE_OCT + '/';
      if (parts[0] !== 'keys' || parts[1] !== AZURE_OCT) {
        send(404, { error: { code: 'KeyNotFound', message: 'no such key' } });
        return;
      }
      const latest = versions[versions.length - 1];
      if (req.method === 'GET' && parts.length <= 3) {
        send(200, { key: { kid: base + (parts[2] || latest), kty: 'oct-HSM',
                           key_ops: ['encrypt', 'decrypt'] },
                    attributes: { enabled: true } });
        return;
      }
      if (req.method === 'POST' && parts[2] === 'rotate') {
        versions.push(crypto.createHash('md5').update(String(Date.now()))
          .digest('hex'));
        send(200, { key: { kid: base + versions[versions.length - 1],
                           kty: 'oct-HSM', key_ops: ['encrypt', 'decrypt'] },
                    attributes: { enabled: true } });
        return;
      }
      const op = parts[3];
      const version = parts[2] || latest;
      const ask = JSON.parse(body || '{}');
      fs.appendFileSync(log, JSON.stringify({
        agent: String(req.headers['user-agent'] || ''), op: op,
        version: version, alg: ask.alg, keys: Object.keys(ask).sort(),
        aad: ask.aad ? Buffer.from(ask.aad, 'base64url').toString() : null
      }) + '\n');
      if (ask.alg !== 'A256GCM' || versions.indexOf(version) < 0) {
        send(400, { error: { code: 'BadParameter', message: 'probe: ' +
                             ask.alg + ' ' + version } });
        return;
      }
      const aad = ask.aad ? Buffer.from(ask.aad, 'base64url') : null;
      try {
        if (op === 'encrypt') {
          const iv = crypto.randomBytes(12);
          const c = crypto.createCipheriv('aes-256-gcm', keyOf(version), iv);
          if (aad) {
            c.setAAD(aad);
          }
          const ct = Buffer.concat([c.update(Buffer.from(ask.value,
                                                         'base64url')),
                                    c.final()]);
          send(200, { kid: base + version, value: ct.toString('base64url'),
                      iv: iv.toString('base64url'),
                      tag: c.getAuthTag().toString('base64url') });
          return;
        }
        const d = crypto.createDecipheriv('aes-256-gcm', keyOf(version),
                                          Buffer.from(ask.iv, 'base64url'));
        if (aad) {
          d.setAAD(aad);
        }
        d.setAuthTag(Buffer.from(ask.tag, 'base64url'));
        const plain = Buffer.concat([d.update(Buffer.from(ask.value,
                                                          'base64url')),
                                     d.final()]);
        send(200, { kid: base + version, value: plain.toString('base64url') });
      } catch (e) {
        send(400, { error: { code: 'BadParameter', message: e.message } });
      }
    });
  });
  server.listen(Number(at.port), '::', function () {
    console.log('vaults: the oct-HSM key on ' + at.origin);
  });
}

// ---------------------------------------------------------------------------
// run: every provider through secrets.js itself.
// ---------------------------------------------------------------------------
function setProvider(provider, ref, extra) {
  ['STS_KEYS_KEK_FIELD', 'STS_KEYS_KEK_VAULT', 'STS_KEYS_KEK_REF',
   'STS_DATABASE_PASSWORD_PROVIDER'].forEach(function (k) {
    delete process.env[k];
  });
  process.env.STS_KEYS_KEK_PROVIDER = provider;
  process.env.STS_KEYS_KEK_REF = ref;
  Object.assign(process.env, extra || {});
}

function shown(value) {
  return Buffer.isBuffer(value) ? { hex: value.toString('hex') } :
    { text: String(value) };
}

async function handleRun(secrets, label, provider, ref, extra, rustWrapped) {
  setProvider(provider, ref, extra);
  const handle = await secrets.readKek();
  const wrapped = [];
  const all = deks();
  for (let i = 0; i < all.length; i++) {
    const one = all[i];
    const text = await handle.wrap(Buffer.from(one.dek, 'hex'), one.aad);
    wrapped.push(Object.assign({ text: text, owns: handle.owns(text),
                                 stale: handle.isStale(text) }, one));
  }
  let refused = false;
  try {
    await handle.unwrap(wrapped[0].text, wrapped[0].aad + 'x');
  } catch (e) {
    refused = String((e && e.message) || e);
  }
  const back = await handle.unwrap(wrapped[1].text, wrapped[1].aad);
  const failures = [];
  for (const one of rustWrapped || []) {
    try {
      const dek = await handle.unwrap(one.text, one.aad);
      if (dek.toString('hex') !== one.dek) {
        failures.push(one.aad + ': a different key');
      }
    } catch (e) {
      failures.push(one.aad + ': ' + ((e && e.message) || e));
    }
  }
  console.log(label + ': ' + wrapped.length + ' wrapped, own unwrap ' +
              (back.toString('hex') === wrapped[1].dek ? 'ok' : 'WRONG') +
              ', changed AAD ' + (refused ? 'refused' : 'NOT REFUSED') +
              (rustWrapped ? ', Rust\'s: ' + (rustWrapped.length -
                failures.length) + ' of ' + rustWrapped.length : ''));
  return { provider: handle.provider, keyRef: handle.keyRef,
           label: handle.label, wrapped: wrapped, wrongAad: refused,
           ownUnwrap: back.toString('hex') === wrapped[1].dek,
           rustChecked: (rustWrapped || []).length, failures: failures };
}

async function run() {
  pointGoogleAtEmulator();
  const secrets = require(path.join(ROOT, 'common', 'secrets.js'));
  const rustFile = path.join(OUT, 'secrets-cloud-rust.json');
  const rust = fs.existsSync(rustFile) ?
    JSON.parse(fs.readFileSync(rustFile, 'utf8')) : null;
  const theirs = function (name) {
    return rust && rust.kms && rust.kms[name] ? rust.kms[name].wrapped : null;
  };
  const out = { reads: {}, kms: {} };
  const reads = [
    ['aws', 'aws', 'sts-kek', { STS_KEYS_KEK_FIELD: 'kek' }],
    ['aws-binary', 'aws', 'sts-kek-binary', {}],
    ['aws-whole', 'aws', 'sts-kek', {}],
    ['gcp', 'gcp', 'projects/' + GCP_PROJECT + '/secrets/sts-kek',
     { STS_KEYS_KEK_FIELD: 'kek' }],
    ['azure', 'azure', 'sts-kek', { STS_KEYS_KEK_FIELD: 'kek',
      STS_KEYS_KEK_VAULT: process.env.STS_PROBE_AZURE_VAULT }]
  ];
  for (const one of reads) {
    setProvider(one[1], one[2], one[3]);
    try {
      out.reads[one[0]] = shown(await secrets.readKek());
    } catch (e) {
      // A refusal is an answer to compare too: `aws-whole` reads a JSON
      // secret with keys.kekField at its default, `value`, which it lacks.
      out.reads[one[0]] = { refused: String((e && e.message) || e) };
    }
    // The database password borrows the key's location and takes its own
    // field, as a deployment with one secret holding both does.
    process.env.STS_DATABASE_PASSWORD_PROVIDER = one[1];
    try {
      out.reads[one[0]].password = await secrets.readDatabasePassword();
    } catch (e) {
      out.reads[one[0]].passwordRefused = String((e && e.message) || e);
    }
  }
  setProvider('aws', 'no-such-secret', {});
  try {
    await secrets.readKek();
  } catch (e) {
    out.reads.awsMissing = { refused: String(e.message) };
  }
  out.kms['aws-kms'] = await handleRun(secrets, 'aws-kms', 'aws-kms',
                                       'alias/sts-kek', {}, theirs('aws-kms'));
  out.kms['gcp-kms'] = await handleRun(secrets, 'gcp-kms', 'gcp-kms', GCP_KEY,
                                       {}, theirs('gcp-kms'));
  out.kms['azure-rsa'] = await handleRun(secrets, 'azure-keys (RSA)',
    'azure-keys', AZURE_RSA,
    { STS_KEYS_KEK_VAULT: process.env.STS_PROBE_AZURE_VAULT },
    theirs('azure-rsa'));
  if (process.env.STS_PROBE_AZURE_FAKE) {
    out.kms['azure-oct'] = await handleRun(secrets, 'azure-keys (oct-HSM)',
      'azure-keys', AZURE_OCT,
      { STS_KEYS_KEK_VAULT: process.env.STS_PROBE_AZURE_FAKE },
      theirs('azure-oct'));
  }
  fs.writeFileSync(path.join(OUT, rust ? 'secrets-cloud-node-check.json' :
                                         'secrets-cloud-node.json'),
                   JSON.stringify(out, null, 1));
  const failed = Object.keys(out.kms).filter(function (k) {
    return out.kms[k].failures.length || !out.kms[k].wrongAad ||
           !out.kms[k].ownUnwrap;
  });
  if (failed.length) {
    console.log('FAILED: ' + failed.map(function (k) {
      return k + ' ' + out.kms[k].failures.join('; ');
    }).join('\n'));
    process.exitCode = 1;
  }
  console.log('wrote ' + (rust ? 'secrets-cloud-node-check.json' :
                          'secrets-cloud-node.json') + ' in ' + OUT);
}

if (COMMAND === 'seed') {
  seed().catch(function (e) {
    console.error('secrets-cloud-interop seed: ' + ((e && e.stack) || e));
    process.exitCode = 1;
  });
} else if (COMMAND === 'vaults') {
  frontLowkey();
  frontIdentity();
  fakeVault();
} else {
  run().catch(function (e) {
    console.error('secrets-cloud-interop: ' + ((e && e.stack) || e));
    process.exitCode = 1;
  });
}
