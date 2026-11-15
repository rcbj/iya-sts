#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: secrets-interop.js
//
// ---------------------------------------------------------------------------
// THE NODE HALF OF THE KEY-ENCRYPTION KEY PARITY PROOF (#444 phase 3).
//
// `sts-core::secrets` ports `common/secrets.js`'s `vault` and
// `vault-transit` providers, and what must agree is what a 1.x store holds:
// a data encryption key wrapped by Transit under its AAD, as Node wrote it,
// has to be unwrapped by Rust, and the reverse. So against a running OpenBao
// (or Vault) seeded by `openbao/seed.js`, this asks `secrets.js` itself:
//
//   * `readKek()` with `keys.kekProvider=vault`: the KV key-encryption key;
//   * `readKek()` with `vault-transit`: the handle, which wraps a set of data
//     keys under their AADs (`secrets-node.json`) and unwraps every one Rust
//     wrapped, when `secrets-rust.json` is there (`secrets-node-check.json`).
//
// sts-core's `tests/secrets_openbao.rs` is the other half. The store is
// reached as the service reaches it: the client certificate seed.js issued,
// at `auth/cert`. The values are key material: the output is never
// committed (tests/vectors/ is gitignored).
//
//   STS_KEYS_KEK_VAULT=https://… STS_KEYS_VAULT_CA_CERT=… \
//   STS_KEYS_VAULT_CLIENT_CERT=… STS_KEYS_VAULT_CLIENT_KEY=… \
//     node tests/tools/secrets-interop.js <directory>
//
// It needs node-vault, an optional peer dependency (NODE_PATH).
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const OUT = path.resolve(process.argv[2] || process.env.STS_SECRETS_VECTORS ||
  path.join(ROOT, 'tests', 'vectors', 'sts-core'));

// Data keys and AADs: fixed patterns rather than random bytes, so a run says
// which one failed; the AAD has `keystore.js`'s `dekAad()` shape.
function deks() {
  const out = [];
  for (let i = 0; i < 8; i++) {
    const dek = Buffer.alloc(32);
    for (let j = 0; j < 32; j++) {
      dek[j] = (i * 37 + j * 11) & 0xff;
    }
    out.push({ dek: dek.toString('hex'),
               aad: 'dek|v1|d' + i + '|service|' +
                    (i % 2 ? 'acme' : 'default') + '|class-' + i });
  }
  return out;
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  process.env.STS_KEYS_KEK_PROVIDER = 'vault';
  process.env.STS_KEYS_KEK_REF = process.env.STS_PROBE_KV_REF ||
    'secret/data/sts';
  process.env.STS_KEYS_KEK_FIELD = process.env.STS_PROBE_KV_FIELD || 'kek';
  const secrets = require(path.join(ROOT, 'common', 'secrets.js'));
  const kv = await secrets.readKek();
  process.env.STS_KEYS_KEK_PROVIDER = 'vault-transit';
  process.env.STS_KEYS_KEK_REF = process.env.STS_PROBE_TRANSIT_KEY ||
    'sts-kek';
  const handle = await secrets.readKek();
  const wrapped = [];
  for (const one of deks()) {
    const text = await handle.wrap(Buffer.from(one.dek, 'hex'), one.aad);
    wrapped.push(Object.assign({ text: text, owns: handle.owns(text),
                                 stale: handle.isStale(text) }, one));
  }
  // An AAD changed by one character must be refused by the KMS itself.
  let refused = false;
  try {
    await handle.unwrap(wrapped[0].text, wrapped[0].aad + 'x');
  } catch (e) {
    refused = true;
  }
  fs.writeFileSync(path.join(OUT, 'secrets-node.json'), JSON.stringify({
    kv: Buffer.isBuffer(kv) ? kv.toString('utf8') : String(kv),
    transitKey: handle.keyRef, wrapped: wrapped, wrongAadRefused: refused
  }));
  const rustFile = path.join(OUT, 'secrets-rust.json');
  if (fs.existsSync(rustFile)) {
    const rust = JSON.parse(fs.readFileSync(rustFile, 'utf8'));
    const failures = [];
    for (const one of rust.wrapped) {
      try {
        const dek = await handle.unwrap(one.text, one.aad);
        if (dek.toString('hex') !== one.dek) {
          failures.push(one.aad + ': a different key');
        }
      } catch (e) {
        failures.push(one.aad + ': ' + ((e && e.message) || e));
      }
    }
    fs.writeFileSync(path.join(OUT, 'secrets-node-check.json'),
      JSON.stringify({ checked: rust.wrapped.length, failures: failures }));
    console.log('Node unwrapped ' + (rust.wrapped.length - failures.length) +
                ' of ' + rust.wrapped.length + ' Rust-wrapped data keys');
    if (failures.length) {
      console.log(failures.join('\n'));
      process.exitCode = 1;
    }
  }
  console.log('wrote ' + path.join(OUT, 'secrets-node.json') + ': ' +
              wrapped.length + ' wrapped data keys');
}

main().catch(function (e) {
  console.error('secrets-interop: ' + ((e && e.stack) || e));
  process.exitCode = 1;
});
