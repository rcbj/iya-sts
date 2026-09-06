'use strict';
//
// File: keystore.js
//
// ===========================================================================
// A SIGNING KEY THAT SURVIVES A RESTART, AND THE ONE FAILURE THAT MUST NOT BE
// SURVIVABLE.
//
// Development mode generates a signing key on every start and that is a
// FEATURE — a mock is disposable and the `kid` is derived from the key
// material, so two instances can never publish one name over two keys. Product
// mode generates once and reads back, because a token issued yesterday has to
// verify today.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Everything here needs to CHOOSE HOW THE PROCESS WAS STARTED, which is the
// second half of that file's rule and the reason the in-process suite exists.
// The claim under test is "the key is the same one after a restart", and over
// HTTP that means launching a service twice against a store you control — which
// `tests/vendored/` has no way to ask for. Here it is two calls to
// `keystore.start()` around a temporary directory.
//
// **THE ENCRYPTION IS THE OTHER HALF AND IS PURE**: that a wrong
// key-encryption key REFUSES rather than yielding different bytes is a property
// of AES-GCM's tag, and asking a running service to demonstrate it would mean
// deliberately corrupting its store and restarting it.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const crypto = require('../common/crypto');

// A directory of its own per run, removed at the end. The KEK file lives in it
// too, which is not how a deployment would do it — the whole point of a KEK is
// that it is somewhere the ciphertext is not — but a test that put them apart
// would be testing the filesystem.
// **`async` AND `await fn(dir)`, WHICH IT WAS NOT AT FIRST.** A synchronous
// `try/finally` around a call that returns a PROMISE runs its `finally` the
// moment the promise is created rather than when it settles — so the directory
// was removed while the body was still using it, and the failure arrived as
// "the key-encryption key file could not be read" three assertions later. That
// is the ordinary shape of this mistake: the error names the file rather than
// the lifetime.
async function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-keystore-'));
  try {
    return await fn(dir);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // A directory that could not be removed is not a failed assertion. Said
      // rather than swallowed silently.
      process.stderr.write('keystore test: could not remove ' + dir + ': ' +
                           e.message + '\n');
    }
  }
}

// A store that behaves like the drivers do — the two real ones are asserted
// against a running service by the persistence job; what this needs is
// something that keeps rows so the round trip can be made twice.
function fakeStore() {
  const rows = new Map();
  return {
    rows: rows,
    loadKeys: function () {
      return Promise.resolve(Array.from(rows.entries()).map(function (pair) {
        return { realm: pair[0], material: pair[1] };
      }));
    },
    saveKeys: function (realm, material) {
      rows.set(realm, material);
      return Promise.resolve();
    },
    deleteKeys: function (realm) {
      rows.delete(realm);
      return Promise.resolve();
    }
  };
}

async function run(t) {
  // -----------------------------------------------------------------------
  // 1. THE ENCRYPTION. Everything else rests on these four.
  // -----------------------------------------------------------------------
  t.log.info('=== the envelope ===');
  const kek = nodeCrypto.randomBytes(32).toString('base64');
  const secret = 'a private key, or something shaped like one';
  const sealed = crypto.encryptWithKek(kek, secret);

  t.equal(crypto.decryptWithKek(kek, sealed), secret,
          'a record encrypted under a key-encryption key comes back');
  t.check(sealed.indexOf(secret) < 0,
          'AND THE PLAINTEXT IS NOT IN THE STORED FORM, which is the whole ' +
          'point and is worth asserting rather than assuming: a bug that ' +
          'stored the value beside its ciphertext would pass every round-trip ' +
          'check ever written',
          sealed.slice(0, 40));
  t.check(crypto.isEncryptedWithKek(sealed) &&
          !crypto.isEncryptedWithKek('plain text'),
          'the stored form is recognisable, so a value this service did not ' +
          'write is not fed to the decrypter');

  let refusedWrongKey = false;
  try {
    crypto.decryptWithKek(nodeCrypto.randomBytes(32), sealed);
  } catch (e) {
    refusedWrongKey = true;
  }
  t.check(refusedWrongKey,
          'THE WRONG KEY-ENCRYPTION KEY IS REFUSED RATHER THAN YIELDING ' +
          'DIFFERENT BYTES. This is why AES-256-GCM and not CBC: a signing ' +
          'key that decrypted to the wrong bytes would produce signatures ' +
          'nothing can verify, and the failure would surface at a relying ' +
          'party as "the signature is invalid" — as far from the cause as it ' +
          'is possible to get');

  let refusedTampering = false;
  try {
    crypto.decryptWithKek(kek, sealed.slice(0, sealed.length - 8) + 'AAAAAAAA');
  } catch (e) {
    refusedTampering = true;
  }
  t.check(refusedTampering,
          'and so is a ciphertext somebody altered — the authentication tag ' +
          'is what makes the store tamper-evident rather than merely opaque');

  // A KEK too short for AES-256 is refused rather than stretched. Stretching
  // would let a four-character password protect every signing key while the
  // log said AES-256.
  let refusedShort = false;
  try {
    crypto.kekBytes('too-short');
  } catch (e) {
    refusedShort = true;
  }
  t.check(refusedShort,
          'a key-encryption key shorter than 32 bytes is REFUSED and never ' +
          'padded or stretched');

  // The three encodings a human or a secret manager might hand back.
  const raw = nodeCrypto.randomBytes(32);
  t.equal(crypto.kekBytes(raw.toString('hex')).toString('hex'),
          raw.toString('hex'),
          'a hex key-encryption key decodes to the bytes it names');
  t.equal(crypto.kekBytes(raw.toString('base64')).toString('hex'),
          raw.toString('hex'),
          'and so does a base64 one — hex is tried FIRST, because a ' +
          '64-character hex string is also valid base64 and reading it that ' +
          'way would produce 48 different bytes');

  // -----------------------------------------------------------------------
  // 2. THE ROUND TRIP: generate, store, and read back as the same key.
  // -----------------------------------------------------------------------
  t.log.info('=== the same key after a restart ===');
  await withTempDir(async function (dir) {
    const kekFile = path.join(dir, 'kek');
    fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                     { mode: 0o600 });

    const keystore = require('../common/keystore');
    const helpers = require('../common/helpers');

    // **THE ENVIRONMENT LAYER AND NOT `setOverride()`**, and the reason is the
    // thing under test: all three of these are RESTART-ONLY, because the keys
    // are read once before the listener binds and a service that changed where
    // they come from while running would hold keys from one source and report
    // another. `setOverride()` refuses a restart-only row — correctly — so a
    // test that used it would silently assert against the defaults.
    //
    // `config.value()` resolves its layers on every call, so setting the
    // variable here is enough and nothing has to be re-required.
    process.env.STS_KEYS_SOURCE = 'persisted';
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    process.env.STS_KEYS_KEK_FILE = kekFile;

    const store = fakeStore();
    t.check(keystore.setStore(store),
            'the keystore takes a store that carries both halves');
    t.equal(keystore.persists(), true,
            'keys.source=persisted turns the keystore on WITHOUT product ' +
            'mode, which is what makes this testable at all');

    await keystore.start();
    // **FORGET WHATEVER IS ALREADY BUILT BEFORE THE FIRST READ**, and this line
    // is the whole difference between passing alone and passing in a full run.
    // `realms.keyed()` builds a realm's key set ONCE and caches it, and any
    // earlier test file that signed anything has already built the default
    // realm's — so without this the factory never runs under the store this
    // test just installed, and `first` is a key from before the test began.
    // It failed exactly that way and only in the full suite, which is the
    // shape of ordering bug worth leaving a comment about.
    helpers.resetStsKeys();
    // Reading `STS.kid` is what builds the key set — the factory is reached
    // through a Proxy on a property read, which is why none of this can be
    // asynchronous below `start()`.
    const first = helpers.STS.kid;
    t.check(typeof first === 'string' && first.length > 0,
            'a signing key exists', first);

    // The write is queued rather than awaited by the property read, so let it
    // land. This is the one place this file waits on anything.
    await new Promise(function (r) { setTimeout(r, 50); });
    t.equal(store.rows.size, 1,
            'and it was written to the store');
    const stored = store.rows.get('default') || '';
    t.check(crypto.isEncryptedWithKek(stored),
            'ENCRYPTED. What is in the store is a ciphertext and not a key');
    t.check(stored.indexOf('BEGIN') < 0 && stored.indexOf('PRIVATE') < 0,
            'and no PEM survives into it, which is the assertion an operator ' +
            'would actually want made about a file of signing keys',
            stored.slice(0, 30));

    // THE RESTART, as far as this process can have one: forget everything the
    // keystore holds in memory and start again against the same store.
    keystore.reset();
    keystore.setStore(store);
    await keystore.start();
    helpers.resetStsKeys();
    const second = helpers.STS.kid;
    t.equal(second, first,
            'THE SAME KEY COMES BACK. This is the whole feature: a token ' +
            'issued before a restart still verifies after it, which is what ' +
            'separates a product from a mock');

    // -------------------------------------------------------------------
    // 3. ROTATION, which is destructive and has to be.
    // -------------------------------------------------------------------
    t.log.info('=== rotation ===');
    const rotated = await keystore.rotate('default');
    t.equal(rotated.ok, true, 'rotating removes the stored material');
    t.equal(store.rows.size, 0, 'and the store no longer holds it');

    keystore.reset();
    keystore.setStore(store);
    await keystore.start();
    helpers.resetStsKeys();
    const third = helpers.STS.kid;
    t.check(third !== first,
            'so the next start generates a DIFFERENT key — which is what ' +
            'rotation means, and why everything signed with the old one ' +
            'stops verifying at that moment. There is no overlap: this ' +
            'service publishes one key per realm per algorithm',
            first + ' -> ' + third);

    // PUT THE PROCESS BACK. Every later test in this run reads the same
    // config, so a variable left behind would make them assert against a
    // keystore this file turned on.
    delete process.env.STS_KEYS_SOURCE;
    delete process.env.STS_KEYS_KEK_PROVIDER;
    delete process.env.STS_KEYS_KEK_FILE;
    keystore.reset();
    keystore.setStore({ loadKeys: function () { return Promise.resolve([]); },
                        saveKeys: function () { return Promise.resolve(); },
                        deleteKeys: function () { return Promise.resolve(); } });
    helpers.resetStsKeys();
  });

  // -----------------------------------------------------------------------
  // 4. DEVELOPMENT MODE IS UNTOUCHED, which is the property every other test
  //    in this repository depends on.
  // -----------------------------------------------------------------------
  t.log.info('=== development mode ===');
  t.equal(require('../common/keystore').persists(), false,
          'with keys.source at its default, a development service persists ' +
          'nothing and generates a key on every start exactly as it always did');
}

module.exports = {
  name: 'keystore',
  describe: 'a signing key that survives a restart, and a wrong key that must not',
  run: run
};
