'use strict';
//
// File: key_residency.js
//
// ===========================================================================
// A PRIVATE KEY IS IN MEMORY WHILE SOMETHING SIGNS WITH IT, AND NOT THE REST
// OF THE TIME.
//
// `tests/keystore.js` asserts the half at REST: what goes into the store is a
// ciphertext, the wrong key-encryption key refuses rather than yielding
// different bytes, and the same key comes back after a restart. This file
// asserts the half IN MEMORY, which was the gap that half left open: the store
// was encrypted and the running process kept every realm's private key in the
// clear for as long as it ran, so a core dump, a swapped page or a debugger
// attached for a moment yielded the signing key of a service that had never
// written one down unencrypted.
//
// ---------------------------------------------------------------------------
// WHAT IS AND IS NOT BEING CLAIMED, because a test is where an overstatement
// gets believed.
//
// The claim is about a WINDOW and nothing else. The key-encryption key is
// resident — it has to be — so an attacker who can read this process's memory
// at a moment of their choosing simply waits for the next signature. What
// narrows is the exposure to a SNAPSHOT taken at an arbitrary instant, which is
// the realistic shape of the problem for material that used to sit there for
// weeks. `common/keystore.js`'s header carries the argument.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// The claim is about what this process is HOLDING, which no request can ask
// about and no endpoint can answer honestly — a page reporting "nothing is
// decrypted" is a page that has to be believed. It also needs the process
// started against a store this file controls, which is `tests/keystore.js`'s
// reason and the second half of that file's rule.
//
// **AND IT NEEDS TO SEE A SIGNATURE STILL WORK**, which is the assertion that
// stops this being a feature that quietly breaks signing: every residency check
// below is paired with a real RS256 signature verified against the public key
// the JWKS publishes.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

// `tests/keystore.js`'s two fixtures, deliberately repeated rather than
// exported from it: a test file that requires another test file is one that
// cannot be run alone, and these are eight lines each.
async function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-residency-'));
  try {
    return await fn(dir);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // A directory that could not be removed is not a failed assertion.
      process.stderr.write('key_residency: could not remove ' + dir + ': ' +
                           e.message + '\n');
    }
  }
}

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

// One turn of the event loop, which is the unit `per-use` purges on.
function tick() {
  return new Promise(function (r) { setImmediate(r); });
}

async function run(t) {
  const config = require('../common/config');
  const crypto = require('../common/crypto');

  await withTempDir(async function (dir) {
    const kekFile = path.join(dir, 'kek');
    fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                     { mode: 0o600 });

    const keystore = require('../common/keystore');
    const helpers = require('../common/helpers');

    // THE ENVIRONMENT LAYER AND NOT `setOverride()`: all three are
    // restart-only, and `setOverride()` correctly refuses a restart-only row —
    // so a test that used it would silently assert against the defaults.
    process.env.STS_KEYS_SOURCE = 'persisted';
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    process.env.STS_KEYS_KEK_FILE = kekFile;

    const store = fakeStore();
    keystore.setStore(store);
    await keystore.start();
    // Forget whatever an earlier file in this run already built — see the same
    // line in tests/keystore.js, where it is the difference between passing
    // alone and passing in a full run.
    helpers.resetStsKeys();

    // Build and store a key, then get the process into the state a RESTART
    // leaves it in: rows in the store, nothing decrypted.
    const kid = helpers.STS.kid;
    await new Promise(function (r) { setTimeout(r, 50); });
    t.equal(store.rows.size, 1, 'a key was generated and written');

    keystore.reset();
    keystore.setStore(store);
    await keystore.start();
    helpers.resetStsKeys();

    // -------------------------------------------------------------------
    // 1. AFTER A START, NOTHING IS DECRYPTED.
    //
    // The startup decrypt is a CHECK — the wrong key-encryption key has to
    // stop the service before it binds rather than at the first signature —
    // and its result is thrown away. If it were not, every assertion below
    // would be about a purge that never had anything to purge.
    // -------------------------------------------------------------------
    t.log.info('=== after a start, the process holds ciphertext ===');
    t.equal(keystore.report().plaintextHeld.length, 0,
            'NO PRIVATE KEY IS DECRYPTED after start(), although one was ' +
            'decrypted DURING it to check the key-encryption key — the ' +
            'plaintext of that check is deliberately dropped');
    t.equal(keystore.report().realmsHeld.length, 1,
            'and the realm is held all the same, as ciphertext');

    // -------------------------------------------------------------------
    // 2. THE PUBLIC HALF IS FREE.
    //
    // The single most likely way to build this feature and get no benefit
    // from it: the JWKS endpoint walks every key on every fetch, so if
    // reading a public JWK decrypted the private half, the key would be
    // resident whenever anything was discovering this service.
    // -------------------------------------------------------------------
    t.log.info('=== reading the public half decrypts nothing ===');
    // **THE FIRST READ OF ANY REALM'S KEY SET DECRYPTS ONCE AND THAT IS NOT
    // THE BUG.** Building the set needs the certificate and every curve key's
    // public JWK, which live in the encrypted blob beside the private halves;
    // what it does NOT do is keep them, and the set it hands back holds the
    // public members as ordinary properties. So the honest assertion is made
    // from the state that follows: build, purge, and then read the public half
    // as the JWKS endpoint does.
    void helpers.STS.kid;
    t.equal(keystore.purgeAll(), 1,
            'building the key set decrypted the record once — for the ' +
            'certificate and the public JWKs, which live in the same blob — ' +
            'and that one decrypt is purgeable like any other');
    const publicKid = helpers.STS.kid;
    const cert = helpers.STS.certPem;
    const jwks = (helpers.STS.extraKeys || []).map(function (one) {
      return one.publicJwk.kid;
    });
    t.equal(publicKid, kid, 'the same key came back after the restart');
    t.check(typeof cert === 'string' && cert.indexOf('BEGIN CERTIFICATE') >= 0,
            'the certificate reads');
    t.equal(jwks.length, 6,
            'and every curve key\'s public JWK reads — which is what the ' +
            'JWKS endpoint walks');
    t.equal(keystore.report().plaintextHeld.length, 0,
            'AND NOTHING WAS DECRYPTED TO ANSWER ANY OF IT. The key set holds ' +
            'the public half as ordinary properties and the private half as ' +
            'getters, so discovery never touches a private key');

    // -------------------------------------------------------------------
    // 3. SIGNING DECRYPTS, AND THE SIGNATURE IS REAL.
    // -------------------------------------------------------------------
    t.log.info('=== signing decrypts, and still signs ===');
    config.setOverride('keys.plaintextRetention', 'resident');
    const signed = crypto.signJws({ sub: 'residency' }, helpers.STS.privateKey,
                                  { alg: 'RS256', kid: helpers.STS.kid });
    t.check(typeof signed === 'string' && signed.split('.').length === 3,
            'a signature is produced from the encrypted key');
    const publicPem = nodeCrypto.createPublicKey(
      nodeCrypto.createPrivateKey(helpers.STS.privateKeyPem)).export(
        { type: 'spki', format: 'pem' });
    t.check(crypto.verifyJws(signed, publicPem).ok !== false,
            'AND IT VERIFIES — the point at which this stops being a claim ' +
            'about bookkeeping and becomes one about a working signer');
    t.equal(keystore.report().plaintextHeld.length, 1,
            'and the key is decrypted while it is being used');

    // -------------------------------------------------------------------
    // 4. `resident` KEEPS IT, which is what the service did before the
    //    setting existed and is the control the other two are measured
    //    against. Asserted BEFORE the purging words, so that a report()
    //    that always answered "nothing held" could not pass this file.
    // -------------------------------------------------------------------
    await tick();
    t.equal(keystore.report().plaintextHeld.length, 1,
            'UNDER `resident` IT IS STILL THERE A TICK LATER, which is the ' +
            'behaviour this service had before the setting and is what makes ' +
            'the next two assertions mean something');

    // -------------------------------------------------------------------
    // 5. `per-use` PURGES AT THE END OF THE TURN.
    // -------------------------------------------------------------------
    t.log.info('=== per-use ===');
    config.setOverride('keys.plaintextRetention', 'per-use');
    keystore.purgeAll();
    const again = crypto.signJws({ sub: 'per-use' }, helpers.STS.privateKey,
                                 { alg: 'RS256', kid: helpers.STS.kid });
    t.check(typeof again === 'string',
            'a signature is still produced with nothing cached');
    t.equal(keystore.report().plaintextHeld.length, 1,
            'the key is decrypted for the signature');
    await tick();
    t.equal(keystore.report().plaintextHeld.length, 0,
            'AND IS GONE BY THE NEXT TURN OF THE EVENT LOOP. The unit is the ' +
            'turn and not the operation, because this is reached through a ' +
            'property read and the caller has not signed yet when it returns');

    // -------------------------------------------------------------------
    // 6. `timed` PURGES ON AN IDLE CLOCK, and the clock RESTARTS ON USE.
    //    The second half is what makes it an idle timeout rather than an
    //    absolute one, and a bug that armed the timer only on decrypt would
    //    pass the first assertion and fail this one.
    // -------------------------------------------------------------------
    t.log.info('=== timed ===');
    config.setOverride('keys.plaintextRetention', 'timed');
    config.setOverride('keys.plaintextTtlS', '1');
    keystore.purgeAll();
    void helpers.STS.privateKey;
    t.equal(keystore.report().plaintextHeld.length, 1, 'decrypted on use');
    await new Promise(function (r) { setTimeout(r, 700); });
    void helpers.STS.privateKey;
    await new Promise(function (r) { setTimeout(r, 700); });
    t.equal(keystore.report().plaintextHeld.length, 1,
            'A USE AT 700ms RESTARTED THE CLOCK, so at 1400ms — past the ' +
            'one-second timeout measured from the first use — it is still ' +
            'held. That is the difference between an idle timeout and an ' +
            'absolute one');
    await new Promise(function (r) { setTimeout(r, 1400); });
    t.equal(keystore.report().plaintextHeld.length, 0,
            'and once it goes unused for the whole second it is dropped');

    // -------------------------------------------------------------------
    // 7. DEVELOPMENT MODE IS UNTOUCHED, and the reason is not squeamishness:
    //    a service that generates its key in memory has NO CIPHERTEXT to fall
    //    back to, so there is nothing to purge to. Saying so here is what
    //    stops somebody reading the setting as a service-wide guarantee.
    // -------------------------------------------------------------------
    t.log.info('=== development has nothing to purge to ===');
    config.clearOverride('keys.plaintextRetention');
    config.clearOverride('keys.plaintextTtlS');
    delete process.env.STS_KEYS_SOURCE;
    delete process.env.STS_KEYS_KEK_PROVIDER;
    delete process.env.STS_KEYS_KEK_FILE;
    keystore.reset();
    t.equal(keystore.persists(), false,
            'with keys.source back at auto and the mode development, the ' +
            'keystore is off');
    t.equal(keystore.report().plaintextHeld.length, 0,
            'and it reports nothing held, because it holds nothing at all — ' +
            'the key lives in the key set helpers.js generated and there is ' +
            'no encrypted copy anywhere for it to be purged back to');
    helpers.resetStsKeys();
    t.check(typeof helpers.STS.kid === 'string' && helpers.STS.kid.length > 0,
            'and a development service generates and signs exactly as it did ' +
            'before any of this existed');
  });
}

module.exports = {
  name: 'key residency',
  describe: 'a private key is decrypted while it signs and not the rest of ' +
            'the time',
  run: run
};
