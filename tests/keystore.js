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

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'keystore',
  level: process.env.LOG_LEVEL || 'info' });

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
  log.debug("Entering withTempDir().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-keystore-'));
  try {
    log.debug("Leaving withTempDir().");
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
  log.debug("Entering fakeStore().");
  const rows = new Map();
  log.debug("Leaving fakeStore().");
  return {
    rows: rows,
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve(Array.from(rows.entries()).map(function (pair) {
        return { realm: pair[0], material: pair[1] };
      }));
    },
    saveKeys: function (realm, material) {
      log.debug("Entering saveKeys().");
      rows.set(realm, material);
      log.debug("Leaving saveKeys().");
      return Promise.resolve();
    },
    deleteKeys: function (realm) {
      log.debug("Entering deleteKeys().");
      rows.delete(realm);
      log.debug("Leaving deleteKeys().");
      return Promise.resolve();
    }
  };
}

async function run(t) {
  log.debug("Entering run().");
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
          'stored the value beside its ciphertext would pass every ' +
          'round-trip check ever written',
          sealed.slice(0, 40));
  t.check(crypto.isEncryptedWithKek(sealed) &&
          !crypto.isEncryptedWithKek('plain text'),
          'the stored form is recognisable, so a value this service did not ' +
          'write is not fed to the decrypter');

  let refusedWrongKey = false;
  try {
    crypto.decryptWithKek(nodeCrypto.randomBytes(32), sealed);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
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
    log.debug("Caught in run(): " + ((e && e.message) || e));
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
    log.debug("Caught in run(): " + ((e && e.message) || e));
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
    // Required HERE with the two above it, and for their reason: the
    // environment is set a few lines up and these modules read it at load.
    const bbs2023 = require('../common/vendored/bbs2023.js');

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
    // **AND SO DOES THE POST-QUANTUM HALF, WHICH IT DID NOT UNTIL
    // 2026-09-12.**
    //
    // `serialise()` has written these since 2026-09-07 and `deserialise()`
    // has read them back the whole time — and the RESTORED key set threw them
    // away, because `helpers.js`'s `lazyKeySet()` had nowhere to get them
    // from. Nothing failed: the process generated eleven more, offered them
    // to its siblings, was refused because another process had got there
    // first, and went on signing with its own.
    //
    // **MEASURED IN A DISPATCHED STACK**: three workers publishing three
    // different ML-DSA and SLH-DSA kids for one realm, so a UserInfo response
    // signed by one could not be verified against the JWKS served by another.
    //
    // Asserted through `privateMaterialFor()` rather than by signing,
    // because what broke is the RESTORE and signing would only prove that
    // SOME key exists — which it did, eleven times over, and that was the
    // bug.
    // -------------------------------------------------------------------
    const warmed = await helpers.warmPqKeys('');
    t.check(Array.isArray(warmed) && warmed.length > 0,
            'the realm has a post-quantum key set at all',
            String(warmed && warmed.length) + ' key(s)');
    const warmedKids = (warmed || []).map(function (one) {
      return one.publicJwk && one.publicJwk.kid;
    }).join(',');
    await new Promise(function (r) { setTimeout(r, 50); });

    keystore.reset();
    keystore.setStore(store);
    await keystore.start();
    helpers.resetStsKeys();
    const restoredPq = helpers.STS.pqKeys || [];
    t.equal(restoredPq.map(function (one) {
              return one.publicJwk && one.publicJwk.kid;
            }).join(','), warmedKids,
            'THE POST-QUANTUM KEYS COME BACK TOO — every process that ' +
            'restores a realm from the store publishes the same ML-DSA and ' +
            'SLH-DSA keys, which is what stops one worker\'s signature ' +
            'being unverifiable against another worker\'s JWKS');
    // **AS BYTES, AND THE KIDS ABOVE AGREED WHILE THESE DID NOT.** A stored
    // post-quantum private key is base64 in the blob and raw bytes in a key
    // set, and the first version of the restore handed the STRING on: every
    // kid matched, the JWKS was right, and the first signature answered *an
    // ML-DSA "priv" is the 32-byte seed of RFC 9964 section 3.2; this one is
    // 44 bytes* — 44 being the length of 32 bytes in base64. A comparison of
    // public names cannot see that, which is why this assertion is about the
    // private half.
    const firstPq = restoredPq[0] || {};
    t.check(Buffer.isBuffer(firstPq.privateKey),
            'and as BYTES rather than as the base64 the blob holds them in — ' +
            'the kid matches either way and only the signature does not',
            typeof firstPq.privateKey + ' of length ' +
            String(firstPq.privateKey && firstPq.privateKey.length));
    t.equal((firstPq.privateKey || '').length,
            ((warmed[0] || {}).privateKey || '').length,
            'the same number of bytes the generated key had');

    // -------------------------------------------------------------------
    // **AND THE BBS KEY, WHICH IS THE THIRD OF THIS FAMILY (#161,
    // 2026-09-22).** The post-quantum half above was written and never read
    // back; this one was read back WRONGLY. `keystore.js`'s
    // serialiseBbsKey() stores the public half as a base64 STRING, and
    // `helpers.js`'s lazyKeySet() read it with `Uint8Array.from(...)` — which
    // over a string maps each CHARACTER through Number(), NaN for every
    // base64 character, landing as 0. So a realm whose keys persist got a
    // public half of ZEROS against a secret half that decodes correctly: a
    // mismatched pair, silently, and one that GREW on every round trip (96
    // real bytes, then 128 zeros, then 172) because the zeros were
    // re-encoded.
    //
    // Nothing in the key set looked wrong — the kid is derived from the
    // public half, so it was consistently wrong — and what failed was every
    // ldp_vc credential, at the issuer's own self-check, only in the modes
    // where keys persist. So this asserts the two things a name comparison
    // cannot see: the LENGTH of the public half, and that the pair actually
    // SIGNS AND VERIFIES.
    // -------------------------------------------------------------------
    const madeBbs = await helpers.bbsKeyPair();
    t.equal(madeBbs.publicKey.length, 96,
            'a fresh BLS12-381 G2 public key is 96 bytes');

    keystore.reset();
    keystore.setStore(store);
    await keystore.start();
    helpers.resetStsKeys();
    // **READ OFF THE KEY SET ITSELF, NOT THROUGH `bbsKeyPair()`.** That
    // function asks the keystore for the held pair first and REPLACES a
    // differing one on the set — so it repairs this very corruption on the
    // way past, and a test written through it passes with the bug in place
    // (measured: the mutant survived). What every signer actually reads is
    // the set's own property, which is the stored view.
    const restoredBbs = helpers.stsKeysFor.of('').bbsKey;
    t.equal(restoredBbs.publicKey.length, 96,
            'THE RESTORED PUBLIC HALF IS 96 BYTES — it was the base64 string ' +
            'read as an array, so it came back as that many ZEROS');
    t.equal(Buffer.from(restoredBbs.publicKey).toString('base64'),
            Buffer.from(madeBbs.publicKey).toString('base64'),
            'and it is the same key that was generated');
    const signed = await bbs2023.issue(
      { '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'], issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' } },
      { verificationMethod: 'did:example:issuer#bbs',
        created: new Date().toISOString() },
      restoredBbs.secretKey, restoredBbs.publicKey);
    const verified = await bbs2023.verifyBase(signed.credential,
                                              restoredBbs.publicKey);
    t.check(!!(verified && verified.ok),
            'AND THE RESTORED PAIR SIGNS AND VERIFIES — the halves come from ' +
            'two different places (the blob for the public, ' +
            'privateMaterialFor() for the secret), so only signing shows ' +
            'they are still a pair',
            JSON.stringify({ ok: verified && verified.ok,
                             statements: (verified &&
                                          verified.statements || []).length }));

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
    keystore.setStore({ loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve([]);
    },
                        saveKeys: function () {
                          log.debug("Entering saveKeys().");
                          log.debug("Leaving saveKeys().");
                          return Promise.resolve();
                        },
                        deleteKeys: function () {
                          log.debug("Entering deleteKeys().");
                          log.debug("Leaving deleteKeys().");
                          return Promise.resolve();
                        } });
    helpers.resetStsKeys();
  });

  // -----------------------------------------------------------------------
  // 3b. THE SHARING CHANNEL WORKS WHILE THE KEYSTORE PERSISTS (2026-09-09).
  //
  // Until that day both halves of it — `publishShared()` and `sharedFor()` —
  // returned early whenever `persists()` was true, on the argument that a
  // store IS the channel between processes. That is true on every start
  // except the one where the store is EMPTY, which is the first start of
  // every product deployment there has ever been: nothing to read, so all
  // four processes generate, and each keeps its own.
  //
  // Measured on a default `docker compose up` before the fix — product mode,
  // three request workers — `/oauth2/jwks` answered THREE DIFFERENT key sets
  // depending on which worker took the request, and an access token minted at
  // `/oauth2/token` was refused by `/admin-api` as unverifiable. A restart
  // cleared it, because by then the store had a row and everybody read the
  // same one, which is the worst possible shape for a defect: the first thing
  // anybody does about it is the thing that hides it.
  //
  // **BOTH GUARDS ARE ASSERTED, AND SEPARATELY, BECAUSE REMOVING ONE FIXED
  // NOTHING.** With `sharedFor()` answering and `publishShared()` still
  // silent, the map is never filled, the parent never learns which set a
  // realm's keys are, no worker is ever told to adopt — and the stack answered
  // exactly as many key sets as before. A test that only drove the read would
  // have gone green over a service that was still broken.
  // -----------------------------------------------------------------------
  t.log.info('=== the sharing channel, with a store in use ===');
  await (async function () {
    const keystore = require('../common/keystore');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-keystore-share-'));
    const kekFile = path.join(dir, 'kek');
    fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                     'utf8');
    process.env.STS_KEYS_SOURCE = 'persisted';
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    process.env.STS_KEYS_KEK_FILE = kekFile;
    const store = fakeStore();
    keystore.setStore(store);
    await keystore.start();
    t.equal(keystore.persists(), true,
            'this section is only about the persisting case — the other one ' +
            'never had the bug');

    // A key set to share. Built the way the service builds one, then handed
    // to the channel exactly as helpers.js hands it over.
    const helpers = require('../common/helpers');
    helpers.resetStsKeys();
    // Read first, because reading `STS.kid` is what BUILDS the key set — the
    // factory is reached through a Proxy on a property read, so nothing below
    // would have a set to publish without this line.
    const madeKid = helpers.STS.kid;
    t.check(!!madeKid, 'a key set was built to share (kid=' + madeKid + ')');

    // PUBLISHED. The guard that used to be here made this a no-op.
    keystore.publishShared('default', helpers.STS);
    const blob = keystore.sharedBlobFor('default');
    t.check(!!blob,
            'publishShared() records the set even though the keystore ' +
            'persists — with the old guard this was undefined, and a parent ' +
            'process that is never told which keys a realm has cannot tell ' +
            'anybody else to adopt them');

    // READ BACK. The other guard made this null, so a sibling that had
    // already generated the realm's keys was invisible.
    const seen = keystore.sharedFor('default');
    t.check(!!seen,
            'sharedFor() answers with the set a sibling published, while the ' +
            'keystore persists — this is the lookup a worker makes on the ' +
            'start that finds an empty store');
    // COMPARED ON THE CERTIFICATE AND NOT ON THE `kid`, because this layer
    // has no kid: what crosses the channel is key MATERIAL, and the kid is
    // derived from the certificate by helpers.js when it builds the usable
    // set. The certificate is what `publishShared()` itself compares to tell
    // an enrichment from a second key set, so it is the identity of a set
    // here in the sense that matters — two processes holding this certificate
    // derive the same kid and advertise the same JWKS.
    t.equal(seen && seen.certPem, helpers.STS.certPem,
            'and it is the SAME key set rather than merely a set: the whole ' +
            'property is that every process in this service advertises one ' +
            'kid, so different material here would be the bug wearing a ' +
            'passing test');

    // AND THE ORDERING THAT KEEPS THE WRITE. `storedFor()` is asked first by
    // helpers.js, so a realm with a stored set never reaches the sibling
    // lookup — which is what stopped `remember()` being called the first time
    // this map was consulted, and is why the fix was an ordering rather than
    // a guard.
    t.check(!!keystore.storedFor('default'),
            'the generated set was WRITTEN DOWN as well, which is the ' +
            'property the old early-return was really protecting: sharing ' +
            'must not stop a product service persisting its keys');

    // -------------------------------------------------------------------
    // **LOSING THE RACE HAS TO REACH THE STORED SET, AND UNTIL 2026-09-12 IT
    // DID NOT.** Everything above is the WINNER's side of the channel; this
    // is the loser's. A process that generated a realm's keys, wrote them to
    // `sts_keys` and is then told another process got there first drops its
    // CACHED set — and `helpers.js` asks `storedFor()` FIRST, which is the
    // ordering the block above argues for, so it rebuilt from its own row and
    // went on signing with what it had made. The adoption logged as a success
    // and reversed itself on the next property read.
    //
    // Measured on a dispatched stack with `keys.source=persisted`: a realm
    // created at runtime had FOUR key sets in four processes, three generated
    // within 43ms of each other and each written down, so `/oauth2/jwks`
    // answered a different key per worker. It was found as an "intermittent"
    // OAEP failure in `tests/vendored/sts_jwt_bearer_grant.js`, which encrypts
    // to the key one worker publishes and posts to whichever answers.
    //
    // The winning blob is the held one with a DIFFERENT certificate rather
    // than a second generated key set, and that is the right stand-in: the
    // certificate is what `publishShared()` compares to tell an enrichment
    // from a race, so it is the identity of a set at this layer.
    // -------------------------------------------------------------------
    const mine = keystore.storedFor('default');
    const winner = Object.assign({}, mine, {
      certB64: 'WINNING-CERTIFICATE',
      createdAt: (mine.createdAt || Date.now()) + 1
    });
    const wroteBefore = store.rows.get('default');
    keystore.adoptShared('default', winner);
    const after = keystore.storedFor('default');
    // The write is QUEUED — `hold()` seals synchronously and hands the store
    // a promise — so the row has not moved until the microtask queue has run.
    // Awaited rather than asserted optimistically, for the reason every other
    // timing assertion in this repository is: a check that happens to pass on
    // a fast machine is not a check.
    await new Promise(function (resolve) { setImmediate(resolve); });
    t.equal(after && after.certB64, 'WINNING-CERTIFICATE',
            'ADOPTING ANOTHER PROCESS\'S KEY SET REPLACES THE STORED ONE — ' +
            'without this the loser rebuilds from its own row and the ' +
            'adoption is a no-op that logged as a success');
    t.check(store.rows.get('default') !== wroteBefore,
            'AND THE WINNER IS WRITTEN DOWN, so the row converges on the set ' +
            'every process is using rather than on whichever process wrote ' +
            'last — the loser had already stored its own',
            String(store.rows.get('default') !== wroteBefore));

    delete process.env.STS_KEYS_SOURCE;
    delete process.env.STS_KEYS_KEK_PROVIDER;
    delete process.env.STS_KEYS_KEK_FILE;
    keystore.reset();
    keystore.setStore({ loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve([]);
    },
                        saveKeys: function () {
                          log.debug("Entering saveKeys().");
                          log.debug("Leaving saveKeys().");
                          return Promise.resolve();
                        },
                        deleteKeys: function () {
                          log.debug("Entering deleteKeys().");
                          log.debug("Leaving deleteKeys().");
                          return Promise.resolve();
                        } });
    helpers.resetStsKeys();
  }());

  // -----------------------------------------------------------------------
  // 4. DEVELOPMENT MODE IS UNTOUCHED, which is the property every other test
  //    in this repository depends on.
  // -----------------------------------------------------------------------
  t.log.info('=== development mode ===');
  t.equal(require('../common/keystore').persists(), false,
          'with keys.source at its default, a development service persists ' +
          'nothing and generates a key on every start exactly as it always ' +
          'did');

  // -----------------------------------------------------------------------
  // 5. THE BLOB A PROCESS SHARES IS IDENTIFIED BY THE KEY AND NOT BY WHAT IT
  //    CURRENTLY PUBLISHES (2026-09-11).
  //
  // `helpers.js`'s certifiedView() makes `certPem` and `certB64` GETTERS that
  // switch from the certificate a key set was BORN with to the one `pki.js`
  // issued over it. `serialise()` read them, so the blob moved under a key that
  // had not — and two things that compare blobs by certificate stopped working
  // at the moment a realm's keys were certified:
  //
  //   * publishShared()'s enrichment test, which is how a realm's POST-QUANTUM
  //     keys reach the other processes. It answered "different key set" for
  //     ever after, the offer was refused, and every request worker in a
  //     dispatched service signed ML-DSA and SLH-DSA with eleven keys of its
  //     own while `/oauth2/jwks` published a sibling's. Nothing failed here; it
  //     failed at a client, as "No key in the set has kid …".
  //   * the `kid` a restored set derives, which would have MOVED across a
  //     restart — the one thing certifiedView()'s own header says must never
  //     happen.
  //
  // This is in process for tests/CLAUDE.md's reason twice over: it needs a key
  // set whose certificate it can make move on demand, and the thing asserted is
  // what ONE process offers ANOTHER, which no HTTP surface publishes.
  // -----------------------------------------------------------------------
  t.log.info('=== the shared blob names the key, not the certificate ===');
  (function () {
    const keystore = require('../common/keystore');
    keystore.reset();
    const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const born = 'THE-CERTIFICATE-THIS-KEY-WAS-BORN-WITH';
    const issued = 'THE-ONE-ITS-ISSUING-CA-MINTED-LATER';
    let certified = false;
    const keys = {
      realm: '',
      createdAt: Date.now(),
      privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      extraKeys: [],
      pqKeys: null,
      selfSignedCertPem: '-----BEGIN CERTIFICATE-----\nBORN\n-----END ' +
                         'CERTIFICATE-----\n',
      selfSignedCertB64: born
    };
    // The moving pair, exactly as certifiedView() installs it.
    Object.defineProperty(keys, 'certB64', {
      enumerable: true, configurable: true,
      get: function () {
        log.debug("Entering get().");
        log.debug("Leaving get().");
        return certified ? issued : born;
      } });
    Object.defineProperty(keys, 'certPem', {
      enumerable: true, configurable: true,
      get: function () {
        log.debug("Entering get().");
        log.debug("Leaving get().");
        return certified ? 'ISSUED-PEM' : keys.selfSignedCertPem;
      } });

    const offered = [];
    keystore.setKeyPublisher(function (realmId, blob) { offered.push(blob); });

    // Generated, and offered to the rest of the service before anything has
    // certified it. This is the publish that already worked.
    keystore.publishShared('', keys);
    t.equal(offered.length, 1,
            'a realm generating its keys offers them to every other process');
    t.equal(offered[0].certB64, born,
            'and the blob carries the certificate the key was born with');

    // `pki.js` certifies it a moment later — certifyLater() is a setImmediate,
    // so this is the ordinary case rather than an unusual one.
    certified = true;
    t.equal(keys.certB64, issued,
            'after certification the key set PUBLISHES the issued certificate');
    t.equal(keystore.sharedBlobFor('').certB64, born,
            'and the blob it shared still names the key, so the kid a ' +
            'sibling derives from it cannot move');

    // And now the post-quantum half arrives. THIS is the publish that was
    // refused, and the eleven keys that never left the process that made them.
    keys.pqKeys = [{ alg: 'ML-DSA-44',
                     privateKey: Buffer.from('not a key'),
                     publicJwk: { kty: 'AKP', kid: 'sts-ml-dsa-44-0000' } }];
    keystore.publishShared('', keys);
    t.equal(offered.length, 2,
            'THE POST-QUANTUM KEYS ARE OFFERED ON — the same key set gaining ' +
            'its second half is an ENRICHMENT and not a second key set, and ' +
            'a certificate issued in between must not make it look like one');
    t.equal((offered[1].pqKeys || []).length, 1,
            'and the offer carries them');
    t.equal(offered[1].certB64, born,
            'still under the name the key was born with');

    keystore.reset();
  }());

  // ---------------------------------------------------------------------------
  // A CERTIFICATE AUTHORITY FROM BEFORE A REBUILD IS REFUSED ON THE POOL'S
  // CHANNEL (2026-09-24). The front process saved a new realm's branch from
  // its copy while a worker rebuilt that branch; the save arrived after the
  // rebuild, every process adopted it, and the realm published the
  // Intermediate the Root's CRL had just superseded (single-node,
  // sts_gnap_mtls). A chain publishing a tier the held rows call superseded
  // is that old copy.
  // ---------------------------------------------------------------------------
  (function () {
    const keystore = require('../common/keystore');
    keystore.reset();
    const published = [];
    keystore.setPkiPublisher(function (id, chain) {
      published.push({ id: id, chain: chain });
    });
    const rebuilt = {
      intermediate: { serialHex: 'b1' },
      issuing: { jose: { serialHex: 'b2' } },
      revoked: { intermediate: [{ serialHex: 'a2', reason: 'superseded' }] }
    };
    keystore.attachPki('r1', rebuilt);
    keystore.attachPki('*service', {
      root: { serialHex: 'c1' },
      revoked: { root: [{ serialHex: '0a1', reason: 'superseded' }] }
    });
    published.length = 0;
    const before = {
      intermediate: { serialHex: 'a1' },
      issuing: { jose: { serialHex: 'a2' } },
      certs: { 'jose:RS256': { serialHex: 'a3' } }
    };
    t.check(keystore.adoptPki('r1', before) === false,
            'a chain publishing tiers the held rows call SUPERSEDED — a copy ' +
            'from before a rebuild — is refused');
    t.check(keystore.pkiFor('r1') === rebuilt,
            'and the rebuilt branch is still the one held');
    t.check(published.length === 1 && published[0].id === 'r1' &&
            published[0].chain === rebuilt,
            'and it is published again, so the process that sent the old ' +
            'copy adopts the rebuild (' + published.length + ' publish(es))');

    // The Intermediate alone superseded, on the Root's list.
    published.length = 0;
    t.check(keystore.adoptPki('r1', {
      intermediate: { serialHex: 'A1' }, issuing: { jose: { serialHex: 'e2' } }
    }) === false, 'an Intermediate the Root\'s list supersedes is refused ' +
                  'too, serials compared normalised');

    // A NEWER branch is adopted as it always was.
    const newer = {
      intermediate: { serialHex: 'd1' },
      issuing: { jose: { serialHex: 'd2' } },
      revoked: { intermediate: [{ serialHex: 'a2', reason: 'superseded' },
                                { serialHex: 'b2', reason: 'superseded' }] }
    };
    t.check(keystore.adoptPki('r1', newer) === true &&
            keystore.pkiFor('r1') === newer,
            'a newer branch, which supersedes nothing it publishes, is ' +
            'adopted');

    // A HOLD IS NOT A SUPERSESSION: it can be lifted, and a row without it
    // is newer, not stale.
    keystore.attachPki('r2', {
      intermediate: { serialHex: 'f1' }, issuing: { jose: { serialHex: 'f2' } },
      revoked: { intermediate: [{ serialHex: 'f2',
                                  reason: 'certificateHold' }] }
    });
    const lifted = { intermediate: { serialHex: 'f1' },
                     issuing: { jose: { serialHex: 'f2' } } };
    t.check(keystore.adoptPki('r2', lifted) === true,
            'a tier held here only on HOLD does not make a chain stale');

    // HELD MID-REBUILD — tiers the held row itself supersedes — refuses the
    // old copy but asserts nothing: the rebuild's last row settles it.
    keystore.attachPki('r3', {
      intermediate: { serialHex: '11' }, issuing: { jose: { serialHex: '12' } },
      revoked: { intermediate: [{ serialHex: '12', reason: 'superseded' }] }
    });
    published.length = 0;
    t.check(keystore.adoptPki('r3', {
      intermediate: { serialHex: '11' }, issuing: { jose: { serialHex: '12' } }
    }) === false && published.length === 0,
            'a process holding a rebuild caught halfway refuses the old copy ' +
            'and publishes nothing of its own');
    keystore.setPkiPublisher(null);
    keystore.reset();
  }());
  log.debug("Leaving run().");
}

module.exports = {
  name: 'keystore',
  describe: 'a signing key that survives a restart, and a wrong key that ' +
            'must not',
  run: run
};
