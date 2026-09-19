// @ts-check
'use strict';
//
// File: keystore.js
//
// ---------------------------------------------------------------------------
// THE SIGNING KEYS THIS SERVICE HOLDS, AND WHETHER THEY SURVIVE A RESTART.
//
// **DEVELOPMENT GENERATES ON EVERY START, AND THAT IS A FEATURE.** A mock is
// disposable, its tokens are meant to die with it, and a key regenerated per
// start is what makes two instances impossible to confuse — the `kid` is
// derived from the key material, so a stale container and a fresh one cannot
// publish one name over two keys. Everything below is off in that mode and this
// file does nothing.
//
// **PRODUCT GENERATES ONCE.** A token issued yesterday has to verify today, so
// the keys are written down — which is the moment this service acquires a
// private key at rest and everything in this file exists because of it:
//
//   * it is ENCRYPTED, AES-256-GCM, by `crypto.js`'s `encryptWithKek()`;
//   * the key that opens it is READ from outside — a mounted file, AWS, GCP,
//     Azure or HashiCorp Vault — by `secrets.js`, and is never generated here
//     and never written anywhere by this service;
//   * it lives in the PERSISTENCE STORE, which product mode therefore requires.
//
// ---------------------------------------------------------------------------
// AND IT IS DECRYPTED ONLY WHILE SOMETHING SIGNS WITH IT (2026-09-06).
//
// The three bullets above are about the key AT REST. They said nothing about
// the running process, which until this date held every realm's private key in
// the clear from `start()` until it exited — so a store encrypted with a key
// from a cloud secret manager sat behind a process any core dump gave the
// plaintext up from.
//
// What is resident now is the CIPHERTEXT. `storedFor()` decrypts on demand and
// `purgeFor()` drops the result, on a policy `keys.plaintextRetention` names
// in three words. The map's own header below carries the whole argument,
// including what this does NOT defend against, which is the half worth reading.
//
// ---------------------------------------------------------------------------
// LOADED ONCE, SYNCHRONOUSLY SERVED.
//
// `helpers.js`'s `stsKeysFor` is a `realms.keyed()` factory reached through a
// PROXY — eight modules do `STS.privateKey` on a property read — so it cannot
// await anything. Reading a secret from AWS can only be asynchronous. The two
// are reconciled the way `persistence.js` already reconciles opening a
// connection pool: **everything asynchronous happens in `start()`, before the
// listener binds**, and what remains is an in-memory map that answers
// instantly.
//
// **THAT CONSTRAINT IS ALSO WHY THE ON-DEMAND DECRYPT IS AFFORDABLE.** The
// expensive, asynchronous thing is reading the KEK from a secret manager, and
// that still happens exactly once in `start()`. What happens per use is an
// AES-256-GCM open of a few kilobytes and a PEM parse — microseconds and a
// fraction of a millisecond — against an RSA signature that costs more than
// both. It is measurable under `per-use` and invisible under `timed`, which is
// why `timed` is the default.
//
// A realm created at RUNTIME is the one case that does not fit, and it is
// handled honestly rather than by blocking: its keys are generated on the spot
// (off the event loop where `helpers.prepareKeySet()` got there first, since
// 2026-09-14, and synchronously otherwise) and WRITTEN asynchronously
// afterwards. So a realm made
// at 11:00 has the same keys at 11:05, and if the process dies between the two
// it has new ones — which is the same window `persistence.js`'s write delay
// already has for everything else it stores.
//
// ---------------------------------------------------------------------------
// WHAT IS STORED, AND WHAT IS DELIBERATELY NOT.
//
// The RSA key and certificate, and the six EC/Ed keys `makeStsKeys()` builds
// beside it — the material every `kid` this service publishes is derived from.
// And, since they joined the set, the eleven post-quantum keys (2026-09-07,
// written down since 2026-09-12 — see `serialise()`), the OpenID4VCI
// request-encryption key, the refresh-token encryption keys and the RFC 9101
// request object encryption keys.
//
// **This section used to say NOT the post-quantum keys**, as a decision: they
// are generated on the worker pool because generating them is expensive, and
// were reachable only through the process's own cache. The blob carries them
// now; `common/CLAUDE.md` (*AND THE POST-QUANTUM HALF WAS WRITTEN AND NEVER
// READ BACK*) records what that took.
//
// **NOT the TLS server certificate and NOT the SPIFFE JWT authority.** Both are
// held by their own modules and are shared across realms. The SPIFFE X.509
// authority was on this list until 2026-09-11; it is `pki.js`'s SPIFFE Issuing
// CA now and lives in the `pki:` rows below.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, `crypto`,
// `mode`, `realms`, `secrets`, `error_codes`, `pki_merge` and
// `cluster/cluster_capabilities`, none of which requires it back — so it is a
// LEAF and `helpers.js` may require it.
// ---------------------------------------------------------------------------

// A LOGGER OF ITS OWN RATHER THAN helpers.js's, AND IT HAS TO BE.
// `helpers.js` requires this module — it is where the signing keys are built —
// so requiring it back would close a cycle, and a cycle in node does not fail
// loudly: it hands back a half-initialised module whose exports are
// `undefined`, and the symptom arrives later as something that is not a
// function (rule 2). `crypto.js` and `config.js` make their own for the same
// reason.
const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({
  name: 'keystore',
  level: config.value('global.logLevel')
});
const crypto = require('./crypto');
// Node's own, for `createPrivateKey()`. `./crypto` is this service's ONE
// signing module and does not export it; the two names one letter apart are
// worth the care, and this file is the only place both are in scope.
const nodeCrypto = require('crypto');
const mode = require('./mode');
// FOR onRemove() ALONE — see the handler at the bottom of this file. A plain
// require in the ordinary direction: `realms.js` requires `config` and
// nothing else here, so it cannot close a cycle back to this module, and
// this file registers no route so it cannot move one.
const realms = require('./realms');
const secrets = require('./secrets');
// A LEAF with no requires: the failure codes on the log lines and the fatal
// refusals below. NOT audit.js, which requires helpers.js, which requires this.
const errorCodes = require('./error_codes');
const cacheRegistry = require('./cache_registry');
// THE THREE-WAY MERGE OF A CERTIFICATE AUTHORITY ROW (#46). A LEAF that
// requires config and bunyan and nothing here, so it cannot close a cycle.
const pkiMerge = require('./pki_merge');
// The table of what active-active mode depends on, for the one row this file
// provides (at the bottom). A LEAF requiring config and bunyan.
const capabilities = require('../cluster/cluster_capabilities');

// The KEK, read once in `start()` and held for the life of the process. Never
// written anywhere, never logged, and never handed out — `encryptWithKek()` and
// `decryptWithKek()` take it as an argument and this is the only variable in
// the service that holds it.
let kek = null;

// ---------------------------------------------------------------------------
// realm id -> what this process is holding for that realm. Serves `helpers.js`
// synchronously.
//
// **THE CIPHERTEXT IS WHAT IS RESIDENT AND THE PLAINTEXT IS WHAT COMES AND
// GOES.** Until 2026-09-06 this map held the decrypted blob for the life of
// the process: the store was encrypted at rest and the running service kept
// every realm's private key in the clear, for weeks, whether or not anything
// was signing. Now each entry is
//
//   { cipher, createdAt, plain, parsed, timer, immediate }
//
// where `cipher` and `createdAt` are always there — the second so that
// `report()` and the console can answer without a decrypt — and `plain` and
// `parsed` are made on demand and dropped again by `purgeFor()`.
//
// ---------------------------------------------------------------------------
// WHAT THIS DEFENDS AGAINST, AND WHAT IT DOES NOT. Read this before believing
// anything about it, because the honest claim is narrow.
//
// It defends against a SNAPSHOT: a core dump, a heap dump, a swapped-out page,
// a `/proc/<pid>/mem` read, a container image made from a live process, a
// debugger attached for a moment. Those catch whatever is in memory at ONE
// instant, and a signing key that is resident for a fortnight is in every one
// of them while a key that is resident for the milliseconds around a signature
// is in almost none.
//
// **IT DOES NOT DEFEND AGAINST AN ATTACKER WHO CAN READ THIS PROCESS'S MEMORY
// AT A MOMENT OF THEIR CHOOSING**, because the key-encryption key is resident
// too — it has to be, or nothing could ever decrypt — and because such an
// attacker can simply wait for the next signature. Narrowing the window is the
// whole of what is being claimed. Anything stronger needs the private key to
// live somewhere this process cannot read it at all, which is an HSM or a KMS
// that signs on your behalf, and is named in `common/mode.js`'s `NOT_YET`.
//
// **AND A JAVASCRIPT STRING CANNOT BE WIPED.** A PEM is a string, strings are
// immutable, and there is no `memset` available from here: dropping the last
// reference makes it collectable and nothing more. The plaintext is decrypted
// into a Buffer and that Buffer IS zeroed, which covers the one copy this file
// controls; the strings `JSON.parse()` makes out of it, and the copy OpenSSL
// keeps inside a `KeyObject`, are released rather than erased. Saying so is
// the point — a feature like this is worth having and is worth exactly nothing
// if somebody reads it as "the key is not in memory".
// ---------------------------------------------------------------------------
const material = new Map();

// ---------------------------------------------------------------------------
// THE DECRYPTED HALF OF `material`, DESCRIBED TO `/admin/caches` (#74, rule
// 3ap). A row is a realm and when its plaintext will be dropped — NEVER the
// key, which `cache_registry.js` could not carry anyway. Only entries holding
// plaintext are rows: the ciphertext is the stored record, not a cache. A hit
// is a signature that found the key already decrypted; a miss is a decrypt.
// ---------------------------------------------------------------------------
const plaintextCount = cacheRegistry.register({
  name: 'keys.plaintext',
  title: 'Decrypted signing keys',
  description: 'A realm\'s signing-key material, decrypted from the ' +
    'persistence store under the key-encryption key and held for an idle ' +
    'window so steady signing does not pay a decrypt each time. Product ' +
    'mode only; development keys are never stored encrypted.',
  owner: 'common/keystore.js',
  scope: 'realm',
  settings: ['keys.plaintextRetention', 'keys.plaintextTtlS'],
  maxEntries: function () {
    return 1;
  },
  bound: 'Structural: one realm\'s key material per realm, whatever the ' +
    'retention policy; the policy decides only how long it is held.',
  lifetime: function () {
    const policy = retention();
    if (policy === 'resident') {
      return 'keys.plaintextRetention=resident: held until the process ' +
        'stops.';
    }
    if (policy === 'per-use' || plaintextTtlMs() === 0) {
      return 'keys.plaintextRetention=per-use: dropped at the end of the ' +
        'event-loop turn that used it.';
    }
    return 'keys.plaintextRetention=timed: dropped keys.plaintextTtlS (' +
      Math.floor(plaintextTtlMs() / 1000) + ' s) after the last use.';
  },
  entries: function () {
    const out = [];
    const policy = retention();
    material.forEach(function (entry, id) {
      if (!entry.plain && !entry.parsed) {
        return;
      }
      out.push({
        realm: id || 'default',
        key: 'signing-key material',
        validUntil: policy === 'resident' ? null
          : (typeof entry.purgeAt === 'number' ? entry.purgeAt : null),
        valid: true,
        basis: policy === 'resident' ? 'held until the process stops'
          : 'idle timeout'
      });
    });
    return out;
  }
});

// The store's own hooks, filled by `persistence.js` at require time. An
// INVERTED HOOK for the reason every other one on this path is (rule 3e):
// `helpers.js` requires this file and `persistence.js` requires `config`, so a
// require in the obvious direction from here would build a cycle through the
// module that opens the database.
let store = null;

function setStore(hooks) {
  log.debug('Entering setStore().');
  const needed = ['loadKeys', 'saveKeys'];
  const missing = needed.filter(function (name) {
    return !hooks || typeof hooks[name] !== 'function';
  });
  if (missing.length) {
    log.error(errorCodes.tag('STS-KEYS-0026') +
              'keystore: setStore() was given something without ' +
              missing.join(', ') + ', so it was refused whole. Half of it ' +
              'would be a service that reads its keys and cannot write them, ' +
              'or writes them and cannot read them back — and the second one ' +
              'generates a new signing key on every start while reporting ' +
              'that it persists them.');
    log.debug('Leaving setStore(). Refused.');
    return false;
  }
  store = hooks;
  log.debug('Leaving setStore(). The keystore is backed by the persistence ' +
            'store.');
  return true;
}

// ---------------------------------------------------------------------------
// IS THE KEYSTORE IN USE? `keys.source` decides, and `auto` follows the mode —
// which is what almost every deployment wants and is why it is the default.
//
// `persisted` in DEVELOPMENT is the setting that makes this testable without
// turning on everything else product mode does: a test can point at a temporary
// directory, restart, and assert that the `kid` did not change.
// ---------------------------------------------------------------------------
function persists() {
  log.debug("Entering persists().");
  const source = String(config.value('keys.source') || 'auto');
  if (source === 'generated') {
    log.debug("Leaving persists().");
    return false;
  }
  if (source === 'persisted') {
    log.debug("Leaving persists().");
    return true;
  }
  log.debug("Leaving persists().");
  return mode.isProduct();
}

// ---------------------------------------------------------------------------
// THE RETENTION POLICY. Three words, read fresh every time — a value captured
// at require time is the one thing a runtime override cannot change, which is
// `common/CLAUDE.md`'s rule and bites hardest on settings somebody turns up in
// order to WATCH something happen.
//
// An unrecognised word falls to `timed` rather than to `resident`, which is the
// safe end of the range to fall off: a typo shortens the window rather than
// opening it for ever.
// ---------------------------------------------------------------------------
function retention() {
  log.debug("Entering retention().");
  const word = String(config.value('keys.plaintextRetention') || 'timed');
  if (word === 'resident' || word === 'per-use') {
    log.debug("Leaving retention().");
    return word;
  }
  log.debug("Leaving retention().");
  return 'timed';
}

// Zero seconds means `per-use`, and it is folded here rather than at three call
// sites: "keep it for no time at all" and "purge it at the end of this turn"
// are the same request, and a `timed` policy with a zero timeout would arm a
// `setTimeout(0)` per signature, which is strictly worse than the immediate.
function plaintextTtlMs() {
  log.debug("Entering plaintextTtlMs().");
  const seconds = Number(config.value('keys.plaintextTtlS'));
  if (!isFinite(seconds) || seconds < 0) {
    log.debug("Leaving plaintextTtlMs().");
    return 300000;
  }
  log.debug("Leaving plaintextTtlMs().");
  return Math.floor(seconds) * 1000;
}

// ---------------------------------------------------------------------------
// DROP THE PLAINTEXT. Everything this file can do about a key already in memory
// happens here, and the header above says what that amounts to.
//
// The Buffer the decrypt produced IS zeroed. The strings `JSON.parse()` made
// out of it and the `KeyObject`s node built from those are RELEASED, because
// there is no other verb available: a JavaScript string is immutable and a
// KeyObject's copy lives in the OpenSSL heap.
// ---------------------------------------------------------------------------
function purgeFor(realmId) {
  log.debug("Entering purgeFor().");
  const id = String(realmId || '');
  const entry = material.get(id);
  if (!entry) {
    log.debug("Leaving purgeFor().");
    return false;
  }
  if (entry.timer) {
    clearTimeout(entry.timer);
    entry.timer = null;
  }
  entry.immediate = false;
  if (!entry.plain && !entry.parsed) {
    log.debug("Leaving purgeFor().");
    return false;
  }
  if (entry.buffer && Buffer.isBuffer(entry.buffer)) {
    entry.buffer.fill(0);
  }
  entry.buffer = null;
  entry.plain = null;
  entry.parsed = null;
  entry.purgeAt = null;
  log.debug('purgeFor(): the "' + id + '" realm\'s decrypted signing key was ' +
            'dropped.');
  log.debug("Leaving purgeFor().");
  return true;
}

// Every realm at once. `reset()` calls it, so that a test doing what a restart
// does leaves nothing decrypted behind, and the residency tests call it
// directly. (`/admin/keys` deliberately offers no Purge button —
// `common/CLAUDE.md` says why.)
function purgeAll() {
  log.debug('Entering purgeAll().');
  let dropped = 0;
  material.forEach(function (entry, id) {
    if (purgeFor(id)) dropped += 1;
  });
  log.debug('Leaving purgeAll(). ' + dropped + ' realm(s).');
  return dropped;
}

// ---------------------------------------------------------------------------
// ARM THE PURGE. Called on every USE rather than on every decrypt, which is
// what makes `timed` an IDLE timeout rather than an absolute one: a realm
// signing steadily keeps its key and stops paying the decrypt, and a realm that
// goes quiet lets it go.
//
// **THE TIMER IS `unref()`d.** Without that, a service holding a decrypted key
// would keep the event loop alive for the whole TTL after everything else had
// finished — so `npm test` would hang for five minutes at the end and the cause
// would be a key that had been purged correctly.
//
// `per-use` is a `setImmediate` and NOT a synchronous purge at the end of
// `storedFor()`, because this is reached through a PROPERTY READ: the caller
// has the plaintext in hand and has not signed with it yet. The unit is
// therefore the TURN OF THE EVENT LOOP and not the operation — which for a
// synchronous signature is exactly the operation, and for one that awaits the
// worker pool is the tick it was dispatched on. That is a real difference and
// it is stated rather than rounded off.
// ---------------------------------------------------------------------------
function armPurge(realmId) {
  log.debug("Entering armPurge().");
  const id = String(realmId || '');
  const entry = material.get(id);
  if (!entry) {
    log.debug("Leaving armPurge().");
    return;
  }
  const policy = retention();
  if (policy === 'resident') {
    log.debug("Leaving armPurge().");
    return;
  }
  const ttl = plaintextTtlMs();
  if (policy === 'per-use' || ttl === 0) {
    if (entry.immediate) {
      log.debug("Leaving armPurge().");
      return;
    }
    entry.immediate = true;
    entry.purgeAt = Date.now();
    setImmediate(function () {
      // Re-read the policy: it is runtime-settable, and an immediate queued
      // under `per-use` must not purge a key the operator has since asked to
      // keep resident.
      if (retention() === 'resident') {
        entry.immediate = false;
        return;
      }
      purgeFor(id);
    });
    log.debug("Leaving armPurge().");
    return;
  }
  if (entry.timer) clearTimeout(entry.timer);
  entry.purgeAt = Date.now() + ttl;
  entry.timer = setTimeout(function () { purgeFor(id); }, ttl);
  if (typeof entry.timer.unref === 'function') entry.timer.unref();
  log.debug("Leaving armPurge().");
}

// ---------------------------------------------------------------------------
// THE REFRESH-TOKEN ENCRYPTION KEYS, AS THE STORED BLOB CARRIES THEM
// (2026-09-12). Three members because the JWE algorithms are three kinds:
// RSA-OAEP needs an RSA pair, ECDH-ES an EC pair, and the symmetric families a
// shared secret. PEM for the two private keys, for `extraKeys`' reason; base64
// for the secret, because a Buffer does not survive JSON. Null when a set has
// none, which `deserialiseRefreshTokenKeys()` reads back as nothing to restore.
// ---------------------------------------------------------------------------
function serialiseRefreshTokenKeys(held) {
  log.debug("Entering serialiseRefreshTokenKeys().");
  if (!held || !held.rsa || !held.ec || !held.secret) {
    log.debug("Leaving serialiseRefreshTokenKeys().");
    return null;
  }
  log.debug("Leaving serialiseRefreshTokenKeys().");
  return {
    rsa: { privateKeyPem: held.rsa.privateKey.export(
        { type: 'pkcs8', format: 'pem' }),
           publicJwk: held.rsa.publicJwk },
    ec: { privateKeyPem: held.ec.privateKey.export(
        { type: 'pkcs8', format: 'pem' }),
          publicJwk: held.ec.publicJwk },
    secret: Buffer.from(held.secret).toString('base64'),
    secretKid: held.secretKid
  };
}

function deserialiseRefreshTokenKeys(blob, nodeCryptoModule) {
  log.debug("Entering deserialiseRefreshTokenKeys().");
  if (!blob || !blob.rsa || !blob.ec || !blob.secret ||
      !blob.rsa.privateKeyPem || !blob.ec.privateKeyPem) {
    log.debug("Leaving deserialiseRefreshTokenKeys().");
    return null;
  }
  log.debug("Leaving deserialiseRefreshTokenKeys().");
  return {
    rsa: { privateKey: nodeCryptoModule.createPrivateKey(
        blob.rsa.privateKeyPem),
           publicJwk: blob.rsa.publicJwk },
    ec: { privateKey: nodeCryptoModule.createPrivateKey(blob.ec.privateKeyPem),
          publicJwk: blob.ec.publicJwk },
    secret: Buffer.from(String(blob.secret), 'base64'),
    secretKid: blob.secretKid
  };
}

// THE REQUEST OBJECT ENCRYPTION KEYS (2026-09-13): an RSA pair and an EC pair,
// the refresh-token shape without the secret. NULL rather than absent for the
// refresh-token keys' reason, and read back as null from a blob that lacks
// them, which `helpers.js`'s requestObjectKeysFor() backfills.
function serialiseRequestObjectKeys(held) {
  log.debug("Entering serialiseRequestObjectKeys().");
  if (!held || !held.rsa || !held.ec) {
    log.debug("Leaving serialiseRequestObjectKeys().");
    return null;
  }
  log.debug("Leaving serialiseRequestObjectKeys().");
  return {
    rsa: { privateKeyPem: held.rsa.privateKey.export(
        { type: 'pkcs8', format: 'pem' }),
           publicJwk: held.rsa.publicJwk },
    ec: { privateKeyPem: held.ec.privateKey.export(
        { type: 'pkcs8', format: 'pem' }),
          publicJwk: held.ec.publicJwk }
  };
}

function deserialiseRequestObjectKeys(blob, nodeCryptoModule) {
  log.debug("Entering deserialiseRequestObjectKeys().");
  if (!blob || !blob.rsa || !blob.ec || !blob.rsa.privateKeyPem ||
      !blob.ec.privateKeyPem) {
    log.debug("Leaving deserialiseRequestObjectKeys().");
    return null;
  }
  log.debug("Leaving deserialiseRequestObjectKeys().");
  return {
    rsa: { privateKey: nodeCryptoModule.createPrivateKey(
        blob.rsa.privateKeyPem),
           publicJwk: blob.rsa.publicJwk },
    ec: { privateKey: nodeCryptoModule.createPrivateKey(blob.ec.privateKeyPem),
          publicJwk: blob.ec.publicJwk }
  };
}

// ---------------------------------------------------------------------------
// SERIALISING A KEY SET. PEM in, PEM out — `makeStsKeys()` already produces
// PEM for the RSA pair, and node's `KeyObject.export()` gives it for the other
// eight, so nothing here has to know what an EC key looks like.
//
// The DERIVED members are deliberately not stored: `privateKey` is a parsed
// `KeyObject` built from `privateKeyPem`, and every `kid` is a hash of the
// public material. Storing a derived value is how a store comes to disagree
// with itself after a change to the derivation.
// ---------------------------------------------------------------------------
function serialise(keys) {
  log.debug('Entering serialise().');
  const out = {
    version: 1,
    createdAt: keys.createdAt || Date.now(),
    privateKeyPem: keys.privateKeyPem,
    // **THE CERTIFICATE THIS KEY SET WAS BORN WITH, AND NOT THE ONE IT
    // CURRENTLY PUBLISHES (2026-09-11).** `helpers.js`'s `certifiedView()`
    // makes `certPem` and `certB64` GETTERS that switch to the certificate
    // `pki.js` issued over this key as soon as it has issued one — so reading
    // them here wrote a MOVING value into a blob whose whole job is to
    // identify a fixed key.
    //
    // It broke two things, and neither of them failed loudly. `publishShared()`
    // compares `certB64` to decide whether a second publish is the SAME key set
    // gaining its post-quantum half or a different process's set losing a race:
    // after certification the comparison was false for ever, the enrichment was
    // refused, and every process in a dispatched service kept eleven
    // post-quantum keys of its own while `/oauth2/jwks` published a sibling's —
    // so a UserInfo response or an ID Token signed by one worker could not be
    // verified against the JWKS served by another. And `certifiedView()`
    // derives the `kid` from whatever certificate it is handed as the
    // self-signed one, so a restored set would have taken its name from the
    // certificate rather than from the key, and the `kid` would have moved
    // across a restart.
    //
    // The fallback is for a key set built before this existed and for
    // `makeStsKeys()`'s raw return, which has no view installed yet.
    certPem: keys.selfSignedCertPem || keys.certPem,
    certB64: keys.selfSignedCertB64 || keys.certB64,
    // **THE POST-QUANTUM SET TRAVELS TOO (2026-09-07).** `pqKeysForAsync()`
    // makes these LAZILY and per process, after the key set already exists, so
    // they were the one part of a realm's material that stayed local: every
    // worker signed ML-DSA and SLH-DSA with a key of its own and published a
    // different one, and a UserInfo response signed by one could not be
    // verified against the JWKS served by another.
    //
    // A private key here is raw bytes rather than a PEM, so it goes as base64;
    // `publicJwk` is already JSON.
    pqKeys: (keys.pqKeys || []).map(function (one) {
      return {
        alg: one.alg,
        privateKey: Buffer.from(one.privateKey).toString('base64'),
        publicJwk: one.publicJwk
      };
    }),
    extraKeys: (keys.extraKeys || []).map(function (one) {
      return {
        alg: one.alg,
        // The PEM rather than the KeyObject, because a KeyObject does not
        // survive JSON and rebuilding one from PEM is what the loader does
        // anyway.
        privateKeyPem: one.privateKey.export({ type: 'pkcs8', format: 'pem' }),
        publicJwk: one.publicJwk
      };
    }),
    // **THE OPENID4VCI REQUEST-ENCRYPTION KEY TRAVELS AND IS WRITTEN DOWN WITH
    // THE SET (2026-09-12)** — which is the whole of what making it a member
    // bought: sealed in `sts_keys` in product mode, shared over the pool's key
    // channel in every mode, per realm because the set is. `helpers.js`'s
    // makeRequestEncryptionKey() argues why it is here at all.
    //
    // NULL rather than absent when a set has none, so that "a blob from before
    // this existed" and "a blob that says it has no such key" read the same on
    // the way back — `deserialise()` and `privateMaterialFor()` both treat a
    // missing member as nothing to restore, and `helpers.js` backfills.
    vciRequestEncKey: (keys.vciRequestEncKey && keys.vciRequestEncKey.publicJwk)
      ? {
          privateKeyPem: keys.vciRequestEncKey.privateKey.export({
            type: 'pkcs8', format: 'pem' }),
          publicJwk: keys.vciRequestEncKey.publicJwk
        }
      : null,
    // **THE REFRESH-TOKEN ENCRYPTION KEYS (2026-09-12)** — the realm's own RSA
    // pair, EC pair and symmetric secret that
    // `oauth-oidc/refresh_token_crypto.ts` encrypts every refresh token to.
    // Written down and shared exactly as the request-encryption key above is,
    // and for its reason: a refresh token outlives the process that minted it
    // in product mode, and a request worker that encrypted to a key another
    // worker does not hold would mint a token nothing else can open. NULL
    // rather than absent for the same reason too; `helpers.js`'s
    // refreshTokenKeysFor() backfills a set written before it.
    refreshTokenEncKeys: serialiseRefreshTokenKeys(keys.refreshTokenEncKeys),
    // **THE REQUEST OBJECT ENCRYPTION KEYS (RFC 9101, 2026-09-13)** — written
    // down and shared exactly as the two members above are, and for a reason
    // that is sharper here: these public halves are PUBLISHED, so a process
    // holding keys of its own would serve a JWKS a client encrypts to and a
    // sibling cannot open.
    requestObjectEncKeys: serialiseRequestObjectKeys(keys.requestObjectEncKeys)
  };
  log.debug('Leaving serialise(). ' + out.extraKeys.length + ' extra key(s).');
  return out;
}

function deserialise(blob, nodeCrypto) {
  log.debug('Entering deserialise().');
  const out = {
    createdAt: blob.createdAt || 0,
    privateKeyPem: blob.privateKeyPem,
    certPem: blob.certPem,
    certB64: blob.certB64,
    // Absent on a blob written before this existed, and on one whose realm has
    // not warmed its post-quantum keys yet — both mean "generate them here",
    // which is what the code did before any of this.
    pqKeys: (blob.pqKeys || []).length
      ? blob.pqKeys.map(function (one) {
          return {
            alg: one.alg,
            privateKey: Buffer.from(one.privateKey, 'base64'),
            publicJwk: one.publicJwk
          };
        })
      : null,
    extraKeys: (blob.extraKeys || []).map(function (one) {
      return {
        alg: one.alg,
        privateKey: nodeCrypto.createPrivateKey(one.privateKeyPem),
        publicJwk: one.publicJwk
      };
    }),
    // THE REQUEST-ENCRYPTION KEY, put back. Null on a blob written before it
    // joined the set, which `helpers.js`'s requestEncryptionKeyFor() backfills.
    vciRequestEncKey: (blob.vciRequestEncKey &&
                       blob.vciRequestEncKey.privateKeyPem)
      ? {
          privateKey: nodeCrypto.createPrivateKey(
              blob.vciRequestEncKey.privateKeyPem),
          publicJwk: blob.vciRequestEncKey.publicJwk
        }
      : null,
    refreshTokenEncKeys: deserialiseRefreshTokenKeys(blob.refreshTokenEncKeys,
                                                     nodeCrypto),
    requestObjectEncKeys: deserialiseRequestObjectKeys(
        blob.requestObjectEncKeys, nodeCrypto)
  };
  log.debug('Leaving deserialise(). ' + out.extraKeys.length +
            ' extra key(s).');
  return out;
}

// ---------------------------------------------------------------------------
// START. Everything asynchronous happens here, before the listener binds.
//
// **A FAILURE IS FATAL AND THE CALLER MUST TREAT IT SO.** That is the same
// decision `persistence.js` makes about its own store and for a sharper reason:
// a product-mode service that cannot read its signing keys and starts anyway
// generates new ones, and every token, assertion and document it ever issued
// stops verifying — silently, at somebody else's relying party, with nothing in
// any log here to point at. Refusing to start is the only honest answer.
// ---------------------------------------------------------------------------
async function start() {
  log.debug('Entering start().');
  if (!persists()) {
    log.debug('Leaving start(). Keys are generated per start.');
    return { persisting: false,
             why: mode.isProduct()
               ? 'keys.source is "generated", so this product-mode service ' +
                 'makes new signing keys on every start'
               : 'development mode generates a signing key on every start' };
  }
  if (!store) {
    throw new Error(errorCodes.tag('STS-KEYS-0027') +
                    'key material is configured to persist (keys.source=' +
                    config.value('keys.source') + ') and no persistence ' +
                    'store is open. Product mode requires one: set ' +
                    'persistence.mode to ldif or postgres.');
  }
  kek = await secrets.readKek();
  // Fail here rather than at the first decrypt, so the message names the KEK
  // rather than a record.
  crypto.kekBytes(kek);
  let rows = [];
  try {
    rows = (await store.loadKeys()) || [];
  } catch (e) {
    throw new Error(errorCodes.tag('STS-KEYS-0028') +
                    'the stored key material could not be read: ' + e.message);
  }
  let loaded = 0;
  let pkiLoaded = 0;
  rows.forEach(function (row) {
    const realmId = String(row.realm || '');
    let plain;
    try {
      plain = crypto.decryptWithKek(kek, row.material, 'signing-keys');
    } catch (e) {
      // THE MOST IMPORTANT ERROR IN THIS FILE. The overwhelmingly likely cause
      // is the wrong key-encryption key — a rotated secret, a different
      // provider, the wrong file mounted — and the overwhelmingly wrong
      // response is to generate a new signing key and carry on.
      throw new Error(errorCodes.tag('STS-KEYS-0029') +
                      'the stored key material for the "' + realmId + '" ' +
                      'realm could not be decrypted. The key-encryption key ' +
                      'is almost certainly not the one it was encrypted with ' +
                      '(provider: ' + secrets.describe().provider + '). This ' +
                      'service will NOT start rather than generate a new ' +
                      'signing key, because doing that would silently stop ' +
                      'every token it has ever issued from verifying. The ' +
                      'underlying error was: ' + e.message);
    }
    // **THE DECRYPT ABOVE IS A CHECK AND ITS RESULT IS THROWN AWAY.** It has to
    // happen here — the wrong key-encryption key must stop the service before
    // it binds, rather than at the first signature hours later — and the
    // plaintext must NOT be kept, because keeping it is the thing this change
    // was made to stop. `JSON.parse` runs too, so a row that decrypts to
    // something malformed also fails at startup rather than at first use.
    const blob = JSON.parse(plain);
    // ---------------------------------------------------------------------
    // **A `pki:` ROW IS A CERTIFICATE AUTHORITY AND NOT A KEY SET.** They
    // share this table on purpose — see attachPki() — and they are told apart
    // by the row key rather than by a column, because `sts_keys` has one and
    // adding a second would mean a schema version for a distinction the key
    // already carries. A row whose realm begins `pki:` is routed here and
    // never reaches `material`, where it would be handed to `deserialise()`
    // and come back as a key set with no private key in it.
    // ---------------------------------------------------------------------
    if (realmId.indexOf(PKI_ROW_PREFIX) === 0) {
      pkiHeld.set(realmId.slice(PKI_ROW_PREFIX.length), blob);
      // THE BASE THIS PROCESS'S FIRST SAVE OF THE ROW MERGES FROM (#46) —
      // see `writePki()`.
      pkiBase.set(realmId.slice(PKI_ROW_PREFIX.length), row.material);
      pkiLoaded += 1;
      return;
    }
    material.set(realmId, {
      cipher: row.material,
      // Public metadata, kept in the clear so `report()` and the console can
      // say when a key was made without decrypting it to find out.
      createdAt: blob.createdAt || 0,
      plain: null, parsed: null, buffer: null, timer: null, immediate: false
    });
    loaded += 1;
  });
  if (pkiLoaded) {
    log.info('keystore: ' + pkiLoaded + ' certificate authority/authorities ' +
             'were read back from the store. A hierarchy built in a previous ' +
             'run still signs, so everything issued from it still chains.');
  }
  log.info('keystore: key material is PERSISTED. ' + loaded + ' realm(s) ' +
           'loaded from the ' + config.value('persistence.mode') + ' store, ' +
           'encrypted with AES-256-GCM under a key read from ' +
           secrets.describe().label + '. A realm with no stored keys gets ' +
           'them generated and written on first use. WHAT IS RESIDENT IN ' +
           'THIS PROCESS IS THE CIPHERTEXT: a private key is decrypted when ' +
           'something signs with it and dropped again (' +
           retentionSentence() + ').');
  log.debug('Leaving start(). ' + loaded + ' realm(s).');
  return { persisting: true, loaded: loaded, pki: pkiLoaded,
           provider: secrets.describe().provider };
}

// ---------------------------------------------------------------------------
// SHARED KEY MATERIAL: ONE SET OF SIGNING KEYS ACROSS THE FRONT PROCESS AND
// EVERY REQUEST WORKER (2026-09-07).
//
// **THIS IS THE SECOND HALF OF A RULE THIS SERVICE ALREADY HAD AND APPLIED TO
// ONE THING.** `request_pool.js`'s setServerCertificate() says it outright —
// "every process in this service must present and pin the SAME certificate" —
// and hands the TLS material down the fork's IPC channel. The JWS SIGNING KEYS
// were never put on that channel, so each process generated its own: the front
// process and three workers advertised four different `kid`s from one port. A
// token signed by one did not verify at another, and the suite measured it as
// 16 distinct kids in a dispatch run against 7 in a single-process one.
//
// **IT IS SEPARATE FROM `material` ON PURPOSE.** That map is the PRODUCT-mode
// store — sealed under the key-encryption key, written to `sts_keys`, read back
// across restarts. This one is neither sealed nor stored and does not survive
// the process: it is the answer to "has a sibling process already generated
// this realm's keys", and it is exactly as durable as the pool is. Putting
// shared keys in `material` would have made `persists()` true in development
// and turned every product-mode gate into a lie.
//
// **FIRST GENERATOR WINS, AND THE PARENT ARBITRATES.** A realm created at
// runtime is generated by whichever process first has a request that needs
// its keys (no watcher generates them since 2026-08-30 — see the block below
// helpers.js's warmPqKeys()); that process publishes, the parent records
// it if the realm is new and broadcasts, and a process that generated a second
// set for the same realm is told to adopt the first and throws its own away.
// The window in which two processes hold different keys for one realm is the
// microseconds between generating and publishing, and anything signed in it is
// lost — which is the price of a synchronous property read that cannot await,
// and is written down here rather than discovered.
// ---------------------------------------------------------------------------
const shared = new Map();
let publisher = null;
let adoptListener = null;

// Filled by whoever owns the IPC channel — request_pool.js in the front process
// and request_worker.ts in a worker. Unset in a service with no pool, where
// every one of these functions is inert and nothing calls them twice.
function setKeyPublisher(fn) {
  log.debug("Entering setKeyPublisher().");
  publisher = typeof fn === 'function' ? fn : null;
  log.debug("Leaving setKeyPublisher().");
}

// Filled by helpers.js: "drop the cached key set for this realm". See
// adoptShared() for why adopting without it changes nothing.
function onAdopt(fn) {
  log.debug("Entering onAdopt().");
  adoptListener = typeof fn === 'function' ? fn : null;
  log.debug("Leaving onAdopt().");
}

// What a sibling process already generated, as a key set this process can use,
// or null. Unlike storedFor() this does NOT consult persists(): sharing is
// about several processes agreeing within one run, which is a different
// question from whether anything is written down.
function sharedFor(realmId, nodeCryptoModule) {
  log.debug("Entering sharedFor().");
  // -------------------------------------------------------------------------
  // **THIS ANSWERED `null` WHENEVER THE KEYSTORE PERSISTED UNTIL 2026-09-09,
  // AND THAT WAS A BUG WITH A CORRECT-SOUNDING REASON.** The reason read:
  //
  //   "Sharing over IPC is the DEVELOPMENT-mode substitute for a store: where
  //    there is a store, every process already reads the same `sts_keys` and
  //    that is the channel."
  //
  // Every clause of that is true EXCEPT on the start where the store is empty,
  // which is the first start of every product deployment there has ever been.
  // There is nothing in `sts_keys` to read, so all four processes fall through
  // to generating — and each keeps what it made. Measured on a default
  // `docker compose up` (product mode, three request workers): `/oauth2/jwks`
  // answered THREE DIFFERENT key sets depending on which worker took the
  // request, and an access token minted at `/oauth2/token` was refused by
  // `/admin-api` as unverifiable. A restart cleared it — by then the store had
  // a row and everybody loaded the same one — which is the worst shape for a
  // defect to have, because the first thing anybody does is restart.
  //
  // **WHAT THE GUARD WAS REALLY PROTECTING IS AN ORDERING, AND THE ORDERING IS
  // IN `helpers.js` RATHER THAN HERE.** The regression it was written for was
  // this map being consulted BEFORE the store: helpers.js returns as soon as it
  // has a key set, so a product service whose sibling had already generated a
  // realm's keys never called `remember()` and never wrote them down.
  // `stsKeysFor` asks `storedFor()` first, then this, then generates — so the
  // stored set still wins wherever there is one, and this is only ever reached
  // in the window the store cannot cover. **Do not reorder those three
  // lookups**; that, and not this early return, is what keeps the write.
  //
  // The adopting process writes the set down as well (`helpers.js` calls
  // `remember()` on this path too), so the row exists even if the generator's
  // own asynchronous write failed. Two writes of identical bytes are the cheap
  // side of that trade.
  // -------------------------------------------------------------------------
  const blob = shared.get(String(realmId || ''));
  if (!blob) {
    log.debug("Leaving sharedFor().");
    return null;
  }
  log.debug("Leaving sharedFor().");
  return deserialise(blob, nodeCryptoModule || nodeCrypto);
}

// A blob that arrived from another process. Recorded whatever this process may
// have generated already — the sender is the authority, and the caller decided
// that before calling.
function adoptShared(realmId, blob) {
  log.debug("Entering adoptShared().");
  if (!blob) {
    log.debug("Leaving adoptShared().");
    return false;
  }
  const id = String(realmId || '');
  let replacing = shared.has(id) && shared.get(id) !== blob;
  // **AND A SET HELD ONLY AS STORED MATERIAL IS REPLACED TOO (2026-09-14,
  // #46).** A process that RESTORED a realm's keys has nothing in `shared`, so
  // the line above called a confirmed set from the store "not replacing" and
  // left the cached key set in place — whose PUBLIC half is copied out once,
  // while its private half is read from `material`, which the hold below is
  // about to change. A JWKS naming one key and signatures made with another.
  // A DIFFERENT set only (another certificate): the same set gaining a member
  // leaves every public half the cache copied true, and
  // `tests/vci_request_encryption_key.js` holds that such a set is NOT dropped
  // — the backfill asks the keystore for the member instead.
  if (!replacing && !shared.has(id) && material.has(id) && kek) {
    try {
      const entry = material.get(id);
      const heldBlob = entry.plain || openBlob(entry.cipher, 'signing-keys');
      replacing = !heldBlob || heldBlob.certB64 !== blob.certB64;
    } catch (e) {
      log.debug("Caught in adoptShared(): " + ((e && e.message) || e));
      replacing = true;
    }
  }
  shared.set(id, blob);
  // ---------------------------------------------------------------------
  // **AND THE STORED SET HAS TO GO TOO, OR THE ADOPTION IS UNDONE ON THE
  // NEXT READ (2026-09-12).** The paragraph below is about the CACHED key
  // set; this is about the one this process persisted, and until this line
  // existed the second silently won.
  //
  // `helpers.js` looks a realm's keys up in three places in a fixed order —
  // STORED, then a SIBLING'S, then generate — and that order is right. What
  // it means here is that a process which generated its own set, wrote it to
  // `sts_keys` and THEN lost the race would drop its cached set, rebuild, and
  // find its own material in the store again. Adopting became a no-op with a
  // log line saying it had happened.
  //
  // **MEASURED, on a dispatched run with `keys.source=persisted`:** a realm
  // created at runtime got FOUR key sets in four processes — three generated
  // within 43ms of each other and each written down — so `/oauth2/jwks`
  // answered a different `kid` per worker and an assertion encrypted to the
  // key one worker published would not decrypt on another. In development
  // with no keystore `storedFor()` answers null, so the channel worked and
  // this was invisible; it is PRODUCT MODE WITH REQUEST WORKERS that had it
  // all along.
  //
  // Writing the winner down from here is deliberate as well: the loser's row
  // is in the store, and every process that adopts writes the same plaintext
  // over it, so the row converges on the set everybody is using rather than on
  // whichever process wrote last.
  // ---------------------------------------------------------------------
  if (persists() && store && kek) {
    try {
      hold(id, blob, 'adopted from another process in this service');
    } catch (e) {
      log.error(errorCodes.tag('STS-KEYS-0030') +
                'keystore: the "' + id + '" realm\'s adopted signing keys ' +
                'could not be held: ' + e.message + '. This process will go ' +
                'on using its own, which means it disagrees with the rest of ' +
                'this service.');
    }
  }
  // **AND THE CACHED SET HAS TO GO, OR ADOPTING IS A NO-OP.** `helpers.js`
  // holds the built key set in a `realms.keyed()` map, so a process that
  // generated its own and then lost the race would go on signing with what it
  // made: the blob would be right and the key in use wrong, which is the
  // failure this whole channel exists to remove and would have been invisible.
  // An inverted hook because helpers.js requires THIS file and not the reverse.
  if (replacing && adoptListener) {
    try {
      adoptListener(id);
    } catch (e) {
      log.error(errorCodes.tag('STS-KEYS-0030') +
                'keystore: the "' + id + '" realm\'s cached key set could ' +
                'not be dropped after adopting another process\'s: ' +
                e.message + '. This process is still signing with its own.');
    }
  }
  log.debug('adoptShared(): the "' + realmId + '" realm\'s signing keys came ' +
            'from another process in this service.');
  log.debug("Leaving adoptShared().");
  return true;
}

// Called by helpers.js the moment it GENERATES a realm's keys. Records them as
// this process's answer and offers them to the rest of the service; the
// publisher decides whether they win.
function publishShared(realmId, keys) {
  log.debug("Entering publishShared().");
  // **THIS RETURNED EARLY WHENEVER THE KEYSTORE PERSISTED UNTIL 2026-09-09,
  // AND IT IS THE OTHER HALF OF THE BUG `sharedFor()` DESCRIBES.** Removing
  // that guard alone changed NOTHING measurable: with nobody publishing, the
  // parent never learns which set a realm's keys are, so it never arbitrates
  // and no worker is ever told to adopt. The default stack still answered
  // three different key sets from `/oauth2/jwks` — the same symptom, one layer
  // further back, which is why both had to go together and why the fix was not
  // finished when the first one looked right.
  //
  // The argument for it was `sharedFor()`'s: "with a store there is nothing to
  // share this way". True once the store has a row for the realm, and false on
  // the start that creates it — which is where every process is generating at
  // once and arbitration is the only thing that can make them agree.
  const id = String(realmId || '');
  const held = shared.get(id);
  if (held) {
    // **AN ENRICHMENT IS NOT A SECOND KEY SET.** First-generator-wins is about
    // two processes racing to MAKE a realm's keys; this is the same key set
    // gaining its post-quantum half, which `pqKeysForAsync()` adds later. The
    // certificate is what identifies the set, so a blob carrying the same one
    // and more content replaces what is held and is published on; a different
    // certificate is the race and still loses.
    let enriching = false;
    try {
      enriching = enriches(serialise(keys), held);
    } catch (e) {
      log.debug("Caught in publishShared(): " + ((e && e.message) || e));
      // A set that cannot be serialised is not an enrichment of anything; the
      // branch below reports the serialisation failure on the path that
      // actually tries to share it.
      enriching = false;
    }
    if (!enriching) {
      log.debug("Leaving publishShared().");
      // **FALSE AND NOT undefined SINCE 2026-09-12**, and it is read: the
      // caller that warms a realm's post-quantum keys writes them to the
      // STORE as well, and a process whose offer lost the race must not write
      // the set it is about to be told to discard. See `pqKeysForAsync()`.
      return false;
    }
  }
  let blob;
  try {
    blob = serialise(keys);
  } catch (e) {
    log.error(errorCodes.tag('STS-KEYS-0031') +
              'keystore: the "' + id + '" realm\'s keys could not be ' +
              'serialised for sharing: ' + e.message + '. This process will ' +
              'use them alone, which means a second process holds different ' +
              'ones.');
    log.debug("Leaving publishShared().");
    return false;
  }
  shared.set(id, blob);
  if (publisher) {
    publisher(id, blob);
  }
  log.debug("Leaving publishShared().");
  return true;
}

// ---------------------------------------------------------------------------
// IS `candidate` THE SAME KEY SET AS `held`, CARRYING MORE? (2026-09-12)
//
// The enrichment rule, in ONE place, because both ends of the key channel
// apply it — `publishShared()` above in the process that offers, and
// `request_pool.js`'s `receivePublishedKeys()` in the process that arbitrates —
// and it was written out twice with ONE member in it (the post-quantum count).
// A second member arriving is exactly how two copies of a rule come to
// disagree.
//
// **THE SAME SET** is the certificate the key was born with (see serialise()).
// **CARRYING MORE** is "at least everything held has, and strictly more of
// something" — never "more of one thing": a set gaining its request-encryption
// key before its post-quantum keys, offered against a held blob that already
// has the post-quantum keys, would otherwise replace the held blob with one
// that has lost them, and every process would go back to generating its own.
// ---------------------------------------------------------------------------
function enriches(candidate, held) {
  log.debug("Entering enriches().");
  if (!candidate || !held || candidate.certB64 !== held.certB64) {
    log.debug("Leaving enriches().");
    return false;
  }
  const pqHere = (candidate.pqKeys || []).length;
  const pqThere = (held.pqKeys || []).length;
  const vciHere = candidate.vciRequestEncKey ? 1 : 0;
  const vciThere = held.vciRequestEncKey ? 1 : 0;
  // The refresh-token encryption keys are the THIRD member, and the rule is
  // unchanged: at least everything held has, and strictly more of something.
  const rtHere = candidate.refreshTokenEncKeys ? 1 : 0;
  const rtThere = held.refreshTokenEncKeys ? 1 : 0;
  // And the request object encryption keys, the FOURTH (2026-09-13).
  const roHere = candidate.requestObjectEncKeys ? 1 : 0;
  const roThere = held.requestObjectEncKeys ? 1 : 0;
  if (pqHere < pqThere || vciHere < vciThere || rtHere < rtThere ||
      roHere < roThere) {
    log.debug("Leaving enriches().");
    return false;
  }
  log.debug("Leaving enriches().");
  return pqHere > pqThere || vciHere > vciThere || rtHere > rtThere ||
         roHere > roThere;
}

// ---------------------------------------------------------------------------
// A REQUEST-ENCRYPTION KEY SOME PROCESS OF THIS SERVICE ALREADY MADE FOR THIS
// REALM, as `{ privateKey, publicJwk }`, or null. It READS and never makes.
//
// Asked by `helpers.js`'s backfill before it generates, for the case the key
// channel cannot see: a process holding a set built before the key existed,
// whose realm has since been backfilled somewhere else and ADOPTED here —
// into the stored material in product mode, into `shared` in every mode —
// without the set it already built being dropped. Stored first, then shared,
// which is `stsKeysFor`'s own order and for its reason.
// ---------------------------------------------------------------------------
function requestEncryptionKeyHeldFor(realmId) {
  log.debug("Entering requestEncryptionKeyHeldFor().");
  const id = String(realmId || '');
  const fromStore = storedFor(id);
  const blob = (fromStore && fromStore.vciRequestEncKey)
    ? fromStore
    : shared.get(id);
  const member = blob && blob.vciRequestEncKey;
  if (!member || !member.privateKeyPem || !member.publicJwk) {
    log.debug("Leaving requestEncryptionKeyHeldFor().");
    return null;
  }
  log.debug("Leaving requestEncryptionKeyHeldFor().");
  return { privateKey: nodeCrypto.createPrivateKey(member.privateKeyPem),
           publicJwk: member.publicJwk };
}

// ---------------------------------------------------------------------------
// THE REFRESH-TOKEN ENCRYPTION KEYS SOME PROCESS ALREADY MADE FOR THIS REALM,
// deserialised, or null. It READS and never makes —
// `requestEncryptionKeyHeldFor()` above, for the same backfill, in the same
// order: stored, then shared.
// ---------------------------------------------------------------------------
function refreshTokenKeysHeldFor(realmId) {
  log.debug("Entering refreshTokenKeysHeldFor().");
  const id = String(realmId || '');
  const fromStore = storedFor(id);
  const blob = (fromStore && fromStore.refreshTokenEncKeys)
    ? fromStore
    : shared.get(id);
  log.debug("Leaving refreshTokenKeysHeldFor().");
  return deserialiseRefreshTokenKeys(blob && blob.refreshTokenEncKeys,
                                     nodeCrypto);
}

// ---------------------------------------------------------------------------
// THE REQUEST OBJECT ENCRYPTION KEYS SOME PROCESS ALREADY MADE FOR THIS REALM,
// deserialised, or null — `refreshTokenKeysHeldFor()` for the other member, in
// the same order: stored, then shared. It READS and never makes.
// ---------------------------------------------------------------------------
function requestObjectKeysHeldFor(realmId) {
  log.debug("Entering requestObjectKeysHeldFor().");
  const id = String(realmId || '');
  const fromStore = storedFor(id);
  const blob = (fromStore && fromStore.requestObjectEncKeys)
    ? fromStore
    : shared.get(id);
  log.debug("Leaving requestObjectKeysHeldFor().");
  return deserialiseRequestObjectKeys(blob && blob.requestObjectEncKeys,
                                      nodeCrypto);
}

// The raw blob a realm is held under, for request_pool.js's enrichment test.
// `sharedFor()` deserialises; this is the stored form, which is what has to be
// compared and rebroadcast.
function sharedBlobFor(realmId) {
  log.debug("Entering sharedBlobFor().");
  log.debug("Leaving sharedBlobFor().");
  return shared.get(String(realmId || '')) || null;
}

// Every realm this process holds keys for, for the fork-time seed.
function sharedAll() {
  log.debug("Entering sharedAll().");
  const out = [];
  shared.forEach(function (blob, id) { out.push({ realm: id, blob: blob }); });
  log.debug("Leaving sharedAll().");
  return out;
}

// ---------------------------------------------------------------------------
// THE STORED MATERIAL FOR A REALM, DECRYPTED, OR NULL.
//
// Synchronous — see the header; it is reached through a property read and
// cannot await. Every call ARMS THE PURGE, which is what makes `timed` an idle
// timeout: the clock restarts on use rather than on decrypt.
//
// A caller must not hold what this returns across a turn of the event loop. The
// two that matter — `helpers.js`'s key set and `privateMaterialFor()` below —
// both copy the PUBLIC half out and re-ask for the private half every time,
// which is the whole arrangement.
// ---------------------------------------------------------------------------
function storedFor(realmId) {
  log.debug("Entering storedFor().");
  if (!persists()) {
    log.debug("Leaving storedFor().");
    return null;
  }
  const id = String(realmId || '');
  const entry = material.get(id);
  if (!entry) {
    log.debug("Leaving storedFor().");
    return null;
  }
  if (entry.plain) {
    plaintextCount.hit();
    armPurge(id);
    log.debug("Leaving storedFor().");
    return entry.plain;
  }
  plaintextCount.miss();
  if (!kek) {
    // Not an assertion about the caller: `start()` refuses to finish without a
    // KEK, so reaching here means somebody called `reset()` and did not start
    // again — which is a test, and a null answer sends `helpers.js` down the
    // generate path rather than throwing out of a property read.
    log.error(errorCodes.tag('STS-KEYS-0032') +
              'keystore: the "' + id + '" realm\'s key material is held ' +
              'encrypted and there is no key-encryption key to open it with. ' +
              'A new signing key will be generated, and every token issued ' +
              'under the stored one stops verifying.');
    log.debug("Leaving storedFor().");
    return null;
  }
  let buffer;
  try {
    buffer = Buffer.from(crypto.decryptWithKek(kek, entry.cipher,
                                               'signing-keys'), 'utf8');
  } catch (e) {
    // The wrong KEK cannot be the cause here — `start()` decrypted this very
    // record — so this is corruption or a bug, and it is louder for that.
    log.error(errorCodes.tag('STS-KEYS-0033') +
              'keystore: the "' + id + '" realm\'s key material decrypted at ' +
              'startup and does NOT decrypt now: ' + e.message);
    log.debug("Leaving storedFor().");
    return null;
  }
  entry.buffer = buffer;
  entry.plain = JSON.parse(buffer.toString('utf8'));
  log.debug('storedFor(): the "' + id +
            '" realm\'s signing key was decrypted.');
  armPurge(id);
  log.debug("Leaving storedFor().");
  return entry.plain;
}

// ---------------------------------------------------------------------------
// THE SAME MATERIAL WITH THE PRIVATE HALVES ALREADY PARSED, and it is here for
// speed rather than tidiness — the same argument `helpers.js` makes beside
// `STS.privateKey`, which measured the PEM-to-KeyObject parse at 21% of this
// service's non-idle CPU.
//
// It is cached ON THE ENTRY and purged BY THE SAME TIMER as the plaintext, so
// the parsed key can never outlive the string it was parsed from. That is the
// property to preserve if any of this is reworked: a KeyObject cache with a
// lifetime of its own would make the purge above cosmetic.
//
// Under `per-use` this parses on every signature, which is the cost the word
// names. Under `timed` a realm signing steadily parses once.
// ---------------------------------------------------------------------------
function privateMaterialFor(realmId) {
  log.debug("Entering privateMaterialFor().");
  const id = String(realmId || '');
  const blob = storedFor(id);
  if (!blob) {
    log.debug("Leaving privateMaterialFor().");
    return null;
  }
  const entry = material.get(id);
  if (entry.parsed) {
    log.debug("Leaving privateMaterialFor().");
    return entry.parsed;
  }
  const parsed = {
    privateKeyPem: blob.privateKeyPem,
    privateKey: nodeCrypto.createPrivateKey(blob.privateKeyPem),
    extra: new Map(),
    // ---------------------------------------------------------------------
    // **THE POST-QUANTUM SET, WHICH THIS FUNCTION DID NOT CARRY UNTIL
    // 2026-09-12 AND `lazyKeySet()` THEREFORE COULD NOT RESTORE.**
    //
    // `serialise()` has written these since 2026-09-07 and `deserialise()`
    // has read them back — and the RESTORED path threw them away, because
    // `helpers.js`'s `lazyKeySet()` had nowhere to get them from. So a
    // process that built its key set from the STORE generated eleven
    // post-quantum keys of its own and published them; the sibling channel
    // refused the offer (another process had got there first) and it kept
    // them anyway.
    //
    // **MEASURED IN A DISPATCHED STACK**: three workers, three different
    // ML-DSA and SLH-DSA kids for the default realm, so a UserInfo response
    // signed by one could not be verified against the JWKS served by another
    // — `No key in the set has kid "sts-slh-dsa-shake-128s-…"`. It is
    // the same defect `publishShared()`'s enrichment branch was written for,
    // arriving by the one door that branch cannot see.
    //
    // They are RAW BYTES rather than KeyObjects — `pq_jose.js` signs with the
    // bytes — so there is nothing to parse, and they live here rather than on
    // the key set for the residency reason every other private key here does:
    // this record is purged on the same timer.
    // ---------------------------------------------------------------------
    // **DECODED HERE, AND THE FIRST VERSION OF THIS LINE DID NOT.**
    // `storedFor()` hands back the SERIALISED blob — `deserialise()` is a
    // different door — so a post-quantum private key is 44 characters of
    // base64 at this point and 32 bytes after it. Handing the string on
    // reached `pq_jose.js` as *an ML-DSA "priv" is the 32-byte seed of RFC
    // 9964 section 3.2; this one is 44 bytes*, which is the encoding trap
    // this file's own header records having been caught by twice.
    pq: (blob.pqKeys || []).length
      ? blob.pqKeys.map(function (one) {
          return {
            alg: one.alg,
            privateKey: Buffer.isBuffer(one.privateKey)
              ? one.privateKey
              : Buffer.from(String(one.privateKey), 'base64'),
            publicJwk: one.publicJwk
          };
        })
      : null,
    // THE OPENID4VCI REQUEST-ENCRYPTION KEY, parsed and purged on the same
    // timer as everything else on this record — the line `pq` above had to be
    // added for the post-quantum half, added here on the day the key joined
    // the set rather than a day later. `helpers.js`'s lazy key set reads it
    // through a getter; the PUBLIC JWK is kept on the set and never comes
    // through here, so publishing the issuer metadata decrypts nothing.
    vci: (blob.vciRequestEncKey && blob.vciRequestEncKey.privateKeyPem)
      ? nodeCrypto.createPrivateKey(blob.vciRequestEncKey.privateKeyPem)
      : null,
    // THE REFRESH-TOKEN ENCRYPTION KEYS — both private keys AND the secret,
    // parsed and purged on this record's timer. The secret is private material
    // exactly as a private key is: anybody holding it opens every refresh token
    // encrypted under a symmetric algorithm.
    rt: deserialiseRefreshTokenKeys(blob.refreshTokenEncKeys, nodeCrypto),
    // THE REQUEST OBJECT ENCRYPTION KEYS — both private keys, parsed and
    // purged on this record's timer. The public halves stay on the set.
    ro: deserialiseRequestObjectKeys(blob.requestObjectEncKeys, nodeCrypto)
  };
  (blob.extraKeys || []).forEach(function (one) {
    parsed.extra.set(one.publicJwk && one.publicJwk.kid,
                     nodeCrypto.createPrivateKey(one.privateKeyPem));
  });
  entry.parsed = parsed;
  log.debug('privateMaterialFor(): the "' + id + '" realm\'s ' +
            (parsed.extra.size + 1) + ' private key(s) were parsed.');
  log.debug("Leaving privateMaterialFor().");
  return parsed;
}

// One sentence naming the policy in force, used by the startup line, the
// report and the console so that three surfaces cannot describe it differently.
function retentionSentence() {
  log.debug("Entering retentionSentence().");
  const policy = retention();
  if (policy === 'resident') {
    log.debug("Leaving retentionSentence().");
    return 'keys.plaintextRetention is "resident", so a decrypted key is ' +
           'kept for the life of the process — which is what this service ' +
           'did before the setting existed';
  }
  if (policy === 'per-use' || plaintextTtlMs() === 0) {
    log.debug("Leaving retentionSentence().");
    return 'keys.plaintextRetention is "' + policy + '", so a decrypted key ' +
           'is dropped at the end of the turn of the event loop that needed it';
  }
  log.debug("Leaving retentionSentence().");
  return 'keys.plaintextRetention is "timed", so a decrypted key is dropped ' +
         'after ' + (plaintextTtlMs() / 1000) + 's unused';
}

// Remember and write. The write is asynchronous and NOT awaited by the caller,
// which is `helpers.js` building a key set inside a property read; a failure is
// logged loudly rather than thrown, because throwing out of a getter would take
// down the request that happened to be first.
function remember(realmId, keys) {
  log.debug('Entering remember(). realm=' + realmId);
  if (!persists()) {
    log.debug('Leaving remember(). Not persisting.');
    return;
  }
  const id = String(realmId || '');
  const blob = serialise(keys);
  if (!store || !kek) {
    log.error(errorCodes.tag('STS-KEYS-0034') +
              'keystore: the "' + id + '" realm\'s signing keys were ' +
              'generated and CANNOT BE WRITTEN — ' +
              (!store ? 'no persistence store is open'
                      : 'no key-encryption key was read') + '. They will be ' +
              'different after the next restart, and every token issued with ' +
              'them will stop verifying.');
    log.debug('Leaving remember(). Nowhere to write.');
    return;
  }
  // ---------------------------------------------------------------------
  // **ENCRYPTED HERE AND NOT INSIDE THE WRITE**, which is what changed on
  // 2026-09-06. The ciphertext is now what this process HOLDS as well as what
  // it stores, so it has to exist synchronously — and doing it once means the
  // bytes in memory and the bytes in the store are the same bytes rather than
  // two encryptions of one blob under two per-record subkeys.
  //
  // The freshly generated plaintext is put in `plain` and the purge is armed
  // exactly as a decrypt would arm it. It is NOT dropped on the spot: the
  // caller is `helpers.js` in the middle of building a key set and is about to
  // read it, and purging under that would decrypt the record we just made.
  // ---------------------------------------------------------------------
  hold(id, blob, 'generated');
  log.debug('Leaving remember(). Queued a write.');
}

// The half of `remember()` that takes an ALREADY SERIALISED blob: seal it,
// hold it as this process's material for that realm, and queue the write.
// Split out for `adoptShared()`, which has a blob and must never re-serialise
// a key set it did not build.
function hold(id, blob, why) {
  log.debug('Entering hold(). realm=' + id + ' why=' + why);
  const cipher = crypto.encryptWithKek(kek, JSON.stringify(blob),
                                       'signing-keys');
  material.set(id, { cipher: cipher, createdAt: blob.createdAt || Date.now(),
                     plain: blob, parsed: null, buffer: null,
                     timer: null, immediate: false });
  armPurge(id);
  // QUEUED PER REALM AND DECIDED BY THE STORE (2026-09-14, #46) — see
  // `writeKeys()` below. It was a bare `saveKeys()` upsert here, and the
  // later of two nodes' upserts won the row while the earlier went on signing.
  queueWrite(id, { cipher: cipher, blob: blob, why: why }, writeKeys);
  log.debug('Leaving hold().');
}

// ---------------------------------------------------------------------------
// ROTATION. Forget a realm's stored keys so the next read generates and stores
// new ones.
//
// **IT IS DESTRUCTIVE AND SAYS SO.** Every token, assertion and signed document
// issued under the old key stops verifying the moment the new one is in use —
// there is no overlap, because this service publishes ONE key per realm per
// algorithm and a JWKS carrying both would need the old private key kept, which
// is the thing rotation is for getting rid of. Overlapping keys are the obvious
// next increment and are named in `mode.js`'s `NOT_YET`.
// ---------------------------------------------------------------------------
async function rotate(realmId) {
  log.debug('Entering rotate(). realm=' + realmId);
  const id = String(realmId || '');
  if (!persists()) {
    log.debug('Leaving rotate(). Nothing is stored.');
    return { ok: false, errors: ['Key material is not being persisted, so ' +
                                 'there is nothing to rotate: this service ' +
                                 'already generates a new signing key on ' +
                                 'every start.'] };
  }
  // Purge first, so the timer is cleared: deleting the entry alone would leave
  // a `setTimeout` holding a closure over the id of a realm that no longer has
  // one, which fires harmlessly and is exactly the kind of thing that is read
  // as a leak six months later.
  // A WRITE OF THIS REALM'S KEYS STILL QUEUED WOULD PUT THEM BACK after the
  // delete below (2026-09-14, #46), so it lands first.
  await settle(id);
  purgeFor(id);
  material.delete(id);
  // AND THE SHARED COPY, or rotation hands back the key it just removed. The
  // set is republished by whichever process generates the next one, so this is
  // a removal and not a gap: `tests/keystore.js` asserts the new kid differs
  // from the old, and it did not until this line existed.
  shared.delete(id);
  // AND THE CACHED SET — which nothing dropped until rotation reached other
  // nodes, because the only caller was a console button followed by a
  // restart-shaped test. A node told by the change log that the row is gone
  // drops it the same way (`applyStoredChange()`).
  if (adoptListener) {
    try {
      adoptListener(id);
    } catch (e) {
      log.debug("Caught in rotate(): " + ((e && e.message) || e));
    }
  }
  if (store && typeof store.deleteKeys === 'function') {
    try {
      await store.deleteKeys(id);
    } catch (e) {
      log.error(errorCodes.tag('STS-KEYS-0036') +
                'keystore: the stored keys for "' + id + '" could not be ' +
                'removed: ' + e.message);
      log.debug("Leaving rotate().");
      return { ok: false, errors: ['The stored keys could not be removed: ' +
                                   e.message] };
    }
  }
  log.warn('keystore: the "' + id + '" realm\'s stored signing keys were ' +
           'REMOVED. New ones are generated the next time the realm signs ' +
           'anything, and EVERY TOKEN, ASSERTION AND SIGNED DOCUMENT ISSUED ' +
           'UNDER THE OLD KEY STOPS VERIFYING at that moment. There is no ' +
           'overlap: this service publishes one key per realm per algorithm.');
  log.debug('Leaving rotate(). Removed.');
  return { ok: true, realm: id,
           message: 'The stored signing keys for "' + id + '" were removed. ' +
                    'New ones are generated on next use. Everything signed ' +
                    'with the old key stops verifying.' };
}

// ---------------------------------------------------------------------------
// A REALM THAT IS GONE TAKES ITS SIGNING KEYS WITH IT (2026-09-07).
//
// Until this, removing a realm left BOTH halves behind: the decrypted material
// in this process's `material` Map, with the `plaintextRetention` timer still
// holding a closure over the id of a realm that no longer has one, and the
// encrypted row in the store. Nothing collected either — `deleteKeys()` had
// exactly one caller, `rotate()`, which is an operator pressing a button.
//
// **THE STORED HALF IS THE ONE THAT MATTERED.** A realm id is a name an
// operator chooses, so a realm deleted and then re-created under the same name
// silently INHERITED the old realm's signing keys — and with them the `kid`
// derived from that key material, so a relying party holding a JWKS from the
// first realm would have verified the second one's tokens without noticing
// anything had changed. That is the opposite of what deleting a realm means.
//
// **IT IS DONE HERE RATHER THAN IN THE DRIVER'S removedRealms LOOP**, where
// the directory rows and the minted rows go, for two reasons. This module owns
// the keys — `rotate()` is the same three steps and they belong together — and
// that loop rides on the DIRECTORY diff, so it does not run at all when the
// directory is not being persisted while the keys are. Here it reaches both
// drivers through the same `store` hook and needs neither.
//
// Failures are logged and never thrown: a realm is already gone by the time
// this runs, and taking down a removal that has otherwise succeeded would
// leave the service holding a realm the caller was told was deleted.
// ---------------------------------------------------------------------------
realms.onRemove(function (id) {
  const realmId = String(id || '');
  log.debug('Entering the keystore realm purge. realm=' + realmId);
  // The timer first, for the reason rotate() gives: dropping the entry alone
  // would leave a setTimeout holding a closure over a realm that is gone.
  purgeFor(realmId);
  material.delete(realmId);
  // The shared copy goes with it, for rotate()'s reason and one of its own: a
  // realm re-created under the same name must not be handed the keys a sibling
  // process is still holding for the realm that was deleted.
  shared.delete(realmId);
  // AND THE CERTIFICATE AUTHORITY, for the same reason: a realm re-created
  // under the same name must not inherit the last one's CA, or certificates
  // issued to the applications of a realm that is gone would go on chaining.
  pkiHeld.delete(realmId);
  pkiBase.delete(realmId);
  if (!store || typeof store.deleteKeys !== 'function') {
    log.debug('Leaving the keystore realm purge. Nothing is stored.');
    return;
  }
  Promise.resolve().then(function () {
    return store.deleteKeys(realmId);
  }).then(function () {
    return store.deleteKeys(PKI_ROW_PREFIX + realmId);
  }).then(function () {
    log.info('keystore: the "' + realmId + '" realm was removed, and its ' +
             'stored signing keys went with it.');
    log.debug('Leaving the keystore realm purge.');
  }).catch(function (e) {
    log.error(errorCodes.tag('STS-KEYS-0037') +
              'keystore: the "' + realmId + '" realm was removed but its ' +
              'stored signing keys could not be: ' + e.message + '. A realm ' +
              'later created under the same name would inherit them.');
  });
});

// What the console and the metadata report draw. Says WHERE and never WHAT.
function report() {
  log.debug("Entering report().");
  const on = persists();
  log.debug("Leaving report().");
  return {
    persisting: on,
    source: String(config.value('keys.source') || 'auto'),
    realmsHeld: on ? Array.from(material.keys()) : [],
    // WHAT IS DECRYPTED RIGHT NOW, which is the number this feature exists to
    // keep small and the only way to see from outside that it is working.
    //
    // **`plain` OR `parsed`, AND THE `parsed` HALF IS NOT PEDANTRY.** A parsed
    // `KeyObject` is decrypted key material — it is the thing that actually
    // signs — so a report that counted only the JSON blob would answer "nothing
    // is held" about a process holding every private key node can sign with. It
    // is exactly the state a purge that forgot one of the two fields would
    // leave behind, and it would look like the feature working.
    retention: retention(),
    plaintextTtlS: plaintextTtlMs() / 1000,
    retentionNote: retentionSentence(),
    plaintextHeld: on
      ? Array.from(material.keys()).filter(function (id) {
          const e = material.get(id);
          return !!(e && (e.plain || e.parsed));
        })
      : [],
    kek: secrets.describe(),
    kekRead: !!kek,
    encryption: 'AES-256-GCM, with a per-record subkey derived from the ' +
                'key-encryption key by HKDF-SHA256',
    storeOpen: !!store,
    note: on
      ? 'Signing keys are generated once and read back on every start, so a ' +
        'token issued before a restart still verifies after it.'
      : 'Signing keys are generated on every start and held in memory. A ' +
        'token does not survive a restart, which is what makes this service ' +
        'disposable — and the `kid` is derived from the key material, so two ' +
        'instances can never publish one name over two keys.'
  };
}

// ---------------------------------------------------------------------------
// THE EPHEMERAL KEY-ENCRYPTION KEY: THE THIRD PIECE OF GENERATED MATERIAL THAT
// HAS TO BE THE SAME IN EVERY PROCESS (2026-09-07).
//
// The TLS certificate was shared first, then the signing keys. This is the
// same rule reaching the last thing that stopped a request worker pool from
// working: WHAT THIS SERVICE MINTS.
//
// Sessions, access and ID tokens, refresh tokens, authorization codes and
// revoked jtis live in `sts_minted`, every row sealed under a KEK — and in
// development mode there is no KEK, so `persistence_minted.js` is off and each
// worker keeps its own. A token minted on one worker then introspected on
// another came back INACTIVE, which is most of what a dispatched run measured
// as broken after the signing keys were shared.
//
// **THIS KEY IS GENERATED, NOT READ, AND THAT IS THE WHOLE OF WHY IT IS SAFE.**
// The product-mode KEK comes from outside the database entirely — a mounted
// file or a cloud secret store — precisely so that a dump of the store is not a
// set of live sessions. This one is 32 random bytes made at startup, shared
// over the fork's IPC channel and never written anywhere, so:
//
//   * every process in the run seals and opens the same rows;
//   * the rows are STILL ciphertext at rest, so the trade the schema comment
//     describes is unchanged;
//   * and a RESTART cannot read them, which is exactly what development mode
//     already promises — it persists nothing it minted ACROSS RESTARTS. The
//     rows from a previous run are unreadable by construction rather than by
//     a policy somebody has to remember, and they are purged on the way up.
//
// It is refused in product mode. There the KEK is the operator's and the store
// is meant to outlive the process; quietly substituting a per-run key would
// turn a product deployment's persisted sessions into garbage on restart.
// ---------------------------------------------------------------------------
let ephemeral = false;

function useEphemeralKek(hex) {
  log.debug("Entering useEphemeralKek().");
  if (persists()) {
    log.error(errorCodes.tag('STS-KEYS-0038') +
              'keystore: an ephemeral key-encryption key was offered while ' +
              'the keystore persists. Refused: in product mode the KEK is ' +
              'the operator\'s and the store outlives this process.');
    log.debug("Leaving useEphemeralKek().");
    return false;
  }
  const bytes = String(hex || '');
  if (!bytes) {
    log.debug("Leaving useEphemeralKek().");
    return false;
  }
  kek = bytes;
  try {
    crypto.kekBytes(kek);
  } catch (e) {
    kek = null;
    log.error(errorCodes.tag('STS-KEYS-0039') +
              'keystore: the ephemeral key-encryption key was not usable: ' +
              e.message);
    log.debug("Leaving useEphemeralKek().");
    return false;
  }
  ephemeral = true;
  log.info('keystore: an ephemeral key-encryption key is in use, so every ' +
           'process in this service seals and opens the same minted rows. It ' +
           'is generated per run and never written down, so nothing minted ' +
           'survives a restart — which is what development mode has always ' +
           'promised.');
  log.debug("Leaving useEphemeralKek().");
  return true;
}

// True when minted state is shareable BECAUSE of the line above rather than
// because this is a product deployment. `persistence_minted.js` reads it.
function hasEphemeralKek() {
  log.debug("Entering hasEphemeralKek().");
  log.debug("Leaving hasEphemeralKek().");
  return ephemeral && !!kek;
}

// The material, for handing to a request worker over IPC. Null unless this
// process generated one.
function ephemeralKek() {
  log.debug("Entering ephemeralKek().");
  log.debug("Leaving ephemeralKek().");
  return ephemeral ? kek : null;
}

// ---------------------------------------------------------------------------
// SEALING SOMETHING THAT IS NOT A SIGNING KEY (2026-09-06) — `sealed()`,
// `seal()` and `open()` below.
//
// Product mode writes down what this process MINTS — sessions, tokens,
// authorization codes, SAML artifact handles, Kerberos long-term keys — and
// every one of those is bearer-equivalent: a database dump holding them in the
// clear is a set of live sessions and usable codes. So each row is sealed, and
// it is sealed WITH THE KEY THAT IS ALREADY HERE rather than with a second one
// of `persistence_minted.js`'s own.
//
// **THE KEK IS PRIVATE TO THIS FILE AND THAT IS THE WHOLE ARGUMENT FOR THESE
// FUNCTIONS EXISTING.** `secrets.readKek()` is called in exactly one place
// (`start()`, above) and the bytes are held in exactly one binding. A second
// module reading `common/secrets.js` for itself would be a second answer to
// "where does the key come from" and a second thing to get wrong when a
// deployment moves from a mounted file to Vault — and it would double the
// number of places a KEK is in memory for no gain at all. So callers hand this
// file text and get ciphertext, and the key never leaves.
//
// They answer NULL rather than throwing when there is no KEK, because both
// callers are on paths that must not fail the request that reached them: a
// flush that cannot seal logs and retries, and a restore that cannot open
// reports and drops the row. `sealed()` is how a caller asks before it starts.
// ---------------------------------------------------------------------------
function sealed() {
  log.debug("Entering sealed().");
  log.debug("Leaving sealed().");
  return !!kek;
}

// ---------------------------------------------------------------------------
// A KEYED DIGEST UNDER THE KEY-ENCRYPTION KEY (2026-09-14, #46), or null when
// there is none.
//
// `cluster/cluster.js` writes a fingerprint of the settings every node must
// agree on into the membership table, and several of those settings are
// PASSWORDS — `krb5.krbtgtPassword` IS the key every ticket is sealed under. A
// bare SHA-256 of a password in a database row is a password a dictionary can
// read back; an HMAC under a key the database never holds is not. The HMAC key
// is DERIVED (HKDF, with the label as its info) rather than the KEK itself, so
// this use can never produce a value that means anything to the sealing path.
// ---------------------------------------------------------------------------
function keyedDigest(label, text) {
  log.debug("Entering keyedDigest().");
  if (!kek) {
    log.debug("Leaving keyedDigest(). No key-encryption key.");
    return null;
  }
  const nodeCrypto = require('crypto');
  const derived = Buffer.from(nodeCrypto.hkdfSync('sha256',
    crypto.kekBytes(kek), Buffer.alloc(0),
    Buffer.from('sts-keyed-digest:' + String(label), 'utf8'), 32));
  const out = nodeCrypto.createHmac('sha256', derived)
    .update(String(text), 'utf8').digest('base64url');
  log.debug("Leaving keyedDigest().");
  return out;
}

// **THE `label` IS FOR ACCOUNTING AND FOR NOTHING ELSE**, which is why it is
// optional and why nothing here validates it: `/admin/encryption` breaks the
// operation count down by what KIND of data was sealed, and the only party
// that knows that is the caller. It reaches `crypto.js`'s tally unchanged; a
// caller that passes none is still counted, in `(unlabelled)`.
function seal(plaintext, label) {
  log.debug('Entering seal().');
  if (!kek) {
    log.debug('Leaving seal(). No key-encryption key.');
    return null;
  }
  try {
    const out = crypto.encryptWithKek(kek, String(plaintext), label);
    log.debug('Leaving seal(). Sealed.');
    return out;
  } catch (e) {
    log.error(errorCodes.tag('STS-KEYS-0040') +
              'keystore: something could not be sealed: ' + e.message);
    log.debug('Leaving seal(). It threw.');
    return null;
  }
}

function open(ciphertext, label) {
  log.debug('Entering open().');
  if (!kek) {
    log.debug('Leaving open(). No key-encryption key.');
    return null;
  }
  try {
    const out = crypto.decryptWithKek(kek, ciphertext, label);
    log.debug('Leaving open(). Opened.');
    return out;
  } catch (e) {
    // NOT rethrown, and the caller is what makes that right: a row that will
    // not open was written under a DIFFERENT key-encryption key, which is the
    // ordinary consequence of rotating one. The restore reports how many and
    // drops them; the alternative is a service that will not start because of
    // a session from last week.
    log.debug('Leaving open(). It would not open: ' + e.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// THE CERTIFICATE AUTHORITY MATERIAL (2026-09-10), AND WHY IT IS IN THIS FILE.
//
// `common/pki.js` builds a Root, an Intermediate and an Issuing CA per trust
// realm and issues application signing keys from the bottom of it. Those are
// PRIVATE KEYS THIS SERVICE GENERATED, which is the exact description of what
// this file already holds — so they go in the same table, under the same
// key-encryption key, read back by the same `start()` and shared across the
// request-worker pool by the same kind of channel. A store of their own would
// have been a second answer to *where does this service keep a private key*,
// and the second answer is the one nobody remembers to rotate.
//
// **THE ROW KEY IS `pki:<realm>` AND THAT IS THE WHOLE OF THE SCHEMA CHANGE.**
// `sts_keys` has one key column, `realm`, and a hierarchy is per realm — so
// prefixing it distinguishes the two kinds of row without a migration and
// without a column whose only value is a discriminator. `start()` routes them
// on the way in.
//
// **IT IS PLAINTEXT IN THIS PROCESS AND CIPHERTEXT EVERYWHERE ELSE, WHICH IS A
// WEAKER CLAIM THAN THE SIGNING KEYS GET AND IS SAID RATHER THAN GLOSSED.**
// The signing keys hold their ciphertext resident and decrypt per signature
// (see the header); the CA keys do not, because every read of them is an
// OPERATOR ACTION — build a hierarchy, issue a key pair, draw the page — and a
// page that had to decrypt to print a serial number would decrypt on every
// render, which is the opposite of what that policy is for. Narrowing this
// window the same way is the obvious next increment and is named in
// `mode.js`'s `NOT_YET` rather than left to be discovered.
// ---------------------------------------------------------------------------
const PKI_ROW_PREFIX = 'pki:';
const pkiHeld = new Map();       // realm id -> the hierarchy, in the clear

// Described to `/admin/caches` (#74, rule 3ap): a row is a scope and
// nothing of the hierarchy, which holds CA private keys. A hit is a signing
// or path check that found the scope's hierarchy held; a miss found none.
const pkiHeldCount = cacheRegistry.register({
  name: 'keys.ca-hierarchies',
  title: 'Certificate authorities',
  description: 'Each scope\'s certificate authority hierarchy — the service ' +
    'Root, a realm\'s Intermediate and its Issuing CAs — held decrypted ' +
    'for signing, read from the store at start or adopted from another ' +
    'process.',
  owner: 'common/keystore.js',
  scope: 'realm',
  maxEntries: function () {
    return 1;
  },
  bound: 'Structural: one hierarchy per scope (the service Root, the ' +
    'process branch, and one per realm), replaced rather than added to.',
  lifetime: function () {
    return 'No expiry: replaced when the hierarchy changes here or on ' +
      'another node, and dropped with its realm.';
  },
  entries: function () {
    const out = [];
    pkiHeld.forEach(function (chain, id) {
      out.push({ realm: id || 'default', key: 'CA hierarchy',
                 validUntil: null, basis: 'until the hierarchy changes' });
    });
    return out;
  }
});
let pkiPublisher = null;

// Filled by whoever owns the IPC channel — `request_pool.js` in the front
// process and `request_worker.ts` in a worker — exactly as `setKeyPublisher()`
// is, and unset in a service with no pool, where it is inert.
//
// **A SECOND CHANNEL RATHER THAN MORE MEMBERS ON THE FIRST**, and the test is
// rule 3e's read one layer down: the key channel arbitrates FIRST-GENERATOR-
// WINS, because two processes racing to make a realm's signing keys is a race
// nobody asked for. A hierarchy is built by an OPERATOR pressing a button, so
// there is no race and the last write wins — putting it on the key channel
// would have meant teaching that arbitration to tell an enrichment from a
// replacement for a second kind of payload, and getting it wrong there would
// have broken signing.
function setPkiPublisher(fn) {
  log.debug("Entering setPkiPublisher().");
  pkiPublisher = typeof fn === 'function' ? fn : null;
  log.debug("Leaving setPkiPublisher().");
}

// What another process built, adopted whole. The sender is the authority: see
// the paragraph above on why there is no arbitration here.
function adoptPki(realmId, chain) {
  log.debug("Entering adoptPki().");
  const id = String(realmId || '');
  if (chain) {
    pkiHeld.set(id, chain);
  } else {
    pkiHeld.delete(id);
  }
  log.debug('adoptPki(): the "' + id + '" realm\'s certificate authority ' +
            'came from another process in this service.');
  log.debug("Leaving adoptPki().");
  return true;
}

// Every hierarchy this process holds, for the fork-time seed.
function pkiAll() {
  log.debug("Entering pkiAll().");
  const out = [];
  pkiHeld.forEach(function (chain, id) {
    out.push({ realm: id, chain: chain });
  });
  log.debug("Leaving pkiAll().");
  return out;
}

// The hierarchy this realm holds, or null. Synchronous, for `pki.js`'s reason:
// the console draws it inside a render and the token endpoint reads its trust
// anchors inside a client-authentication check.
function pkiFor(realmId) {
  log.debug("Entering pkiFor().");
  const held = pkiHeld.get(String(realmId || '')) || null;
  if (held) {
    pkiHeldCount.hit();
  } else {
    pkiHeldCount.miss();
  }
  log.debug("Leaving pkiFor().");
  return held;
}

// Record it, share it, and write it down. `null` REMOVES the hierarchy, which
// is what `pki.clearChain()` asks for — and the removal has to reach all three
// places or a worker goes on issuing from a CA the operator threw away.
function attachPki(realmId, chain) {
  log.debug('Entering attachPki(). realm=' + realmId);
  const id = String(realmId || '');
  adoptPki(id, chain);
  if (pkiPublisher) {
    pkiPublisher(id, chain || null);
  }
  if (!persists()) {
    // Development mode, where a signing key is generated per start and dies
    // with the process. A hierarchy behaves the same way, which is the honest
    // answer rather than a gap — `pki.js`'s header and `/admin/pki` both say
    // so, and `report()` below reports it.
    log.debug('Leaving attachPki(). Held in memory; nothing persists here.');
    return;
  }
  if (!store || !kek) {
    log.error(errorCodes.tag('STS-KEYS-0041') +
              'keystore: the "' + id + '" realm\'s certificate authority ' +
              'CANNOT BE WRITTEN — ' +
              (!store ? 'no persistence store is open'
                      : 'no key-encryption key was read') + '. It will be ' +
              'gone after the next restart, and every certificate issued ' +
              'from it will chain to nothing.');
    log.debug('Leaving attachPki(). Nowhere to write.');
    return;
  }
  // QUEUED PER ROW, COALESCED, AND MERGED UNDER THE ROW'S LOCK (2026-09-14,
  // #46) — see `writePki()`. `gen` is how the write knows, when it lands,
  // whether this process has attached something newer since.
  const gen = (pkiLocalGen.get(id) || 0) + 1;
  pkiLocalGen.set(id, gen);
  queueWrite(PKI_ROW_PREFIX + id, { chain: chain || null, gen: gen },
             writePki);
  log.debug('Leaving attachPki(). Queued a write.');
}

// ===========================================================================
// THE STORE IS THE ARBITER BETWEEN NODES (2026-09-14, #46 section 1).
//
// Everything above this line was built for ONE container, where the request
// pool's IPC channels made every process agree — first generator wins for a
// key set, last write wins for a certificate authority — and the store was a
// mirror each process wrote whole. Between containers the only link is the
// store, and the issue's worst section is what that did:
//
//   * two nodes cold-starting against an empty store each generated a realm's
//     signing keys, and the later UPSERT won the row while the earlier node
//     went on signing — one JWKS per node, a token from A refused at B, and
//     everything the loser signed stranded at the next restart;
//   * `applyKeysChange()` did nothing, so a rotation, a realm created on A and
//     first used on B, and a rebuilt Root each reached one node;
//   * the whole certificate authority of a scope is one row, and any node's
//     next save of its copy threw another node's revocations out of it.
//
// **THE ANSWER IS ONE RULE: A WRITE ASKS THE STORE WHAT IS THERE, UNDER THE
// ROW'S LOCK, AND EVERY NODE ENDS UP HOLDING WHAT THE STORE HOLDS.**
// `persistence_postgres.js`'s `mergeKeys()` locks the row and calls back with
// its current ciphertext; this file decides, because it alone holds the
// key-encryption key:
//
//   * **a key set is FIRST WRITER WINS** (`decideKeys()`) — a different set in
//     the row is kept and THIS process adopts it; the same set is JOINED, the
//     members one side lacks (the post-quantum keys, the three encryption key
//     pairs) taken from the other, because they are made lazily and either
//     node may make them first;
//   * **a certificate authority is a THREE-WAY MERGE** (`common/pki_merge.js`
//     argues every rule, and why a merge rather than a row per revocation);
//   * **and a row another node wrote is ADOPTED** (`applyStoredChange()`,
//     which `persistence.js`'s `keys` applier calls), reading the CURRENT row
//     rather than replaying an operation — the replication rule every other
//     applier already keeps.
//
// **WHAT ADOPTING STRANDS, AND WHY THAT IS THE RIGHT TRADE.** A process that
// signed with keys it then adopts away from has signed something no JWKS will
// publish. `applyKeysChange()` refused to adopt for exactly that reason. But
// the keys it would refuse are, by construction, the ones the store REJECTED
// — every other node is already signing with the winner — so refusing strands
// the same tokens for ever instead of for a window. The window is the round
// trip of the first write: a cold start closes it by settling BEFORE anything
// is served (`common/service_state.ts`), and a realm created at runtime keeps
// the one this service already had inside a container, from generation to the
// commit that says who won. There are no retained keys to fall back on: this
// service publishes one key per realm per algorithm (`rotate()` says so, and
// overlapping keys are in `mode.js`'s `NOT_YET`).
//
// **A STORE THAT CANNOT ARBITRATE CHANGES NOTHING.** `arbitrates()` is false on
// `ldif` (one process's file), in development (nothing persists), with a
// driver from before this, and with `cluster.mode=off`, and every write below
// is then the `saveKeys()` upsert it always was.
// ===========================================================================
const writes = new Map();        // row key -> { tail, queued, pending }
const lastOutcome = new Map();   // row key -> what its last write decided
const pkiBase = new Map();       // scope id -> ciphertext last read or written
const pkiLocalGen = new Map();   // scope id -> attachPki() calls so far

// **AND ONLY WHERE THIS SERVICE IS A CLUSTER** — `cluster.mode` resolved to
// anything but `off`, which in product mode on postgres is the default
// (`cluster/CLAUDE.md`). `off` is the operator saying this is one container,
// and one container already agrees over the request pool's channels, so it
// keeps the upsert it had: the brief for #46 was that nothing about a single
// node changes. Required lazily, because `cluster.js` is a library this leaf
// has no other reason to load.
function arbitrates() {
  log.debug("Entering arbitrates().");
  if (!persists() || !store || !kek ||
      typeof store.mergeKeys !== 'function' ||
      typeof store.loadKey !== 'function') {
    log.debug("Leaving arbitrates(). No arbitrating store.");
    return false;
  }
  let clustered = false;
  try {
    clustered = require('../cluster/cluster').mode() !== 'off';
  } catch (e) {
    log.debug("Caught in arbitrates(): " + ((e && e.message) || e));
    clustered = false;
  }
  log.debug("Leaving arbitrates(). " + clustered);
  return clustered;
}

// ---------------------------------------------------------------------------
// ONE WRITE OF A ROW AT A TIME, AND A WRITE NOT YET STARTED TAKES THE LATEST
// PAYLOAD. A realm's branch build saves its row a dozen times in one turn; a
// merge per save would be a dozen locked round trips, and two in flight at
// once from one process would merge against each other. So a row has a queue
// of one running write and at most one waiting, and the waiting one is handed
// whatever was attached last — which is cumulative, because every attach is
// the whole row.
// ---------------------------------------------------------------------------
function queueWrite(rowKey, payload, perform) {
  log.debug("Entering queueWrite(). row=" + rowKey);
  let slot = writes.get(rowKey);
  if (!slot) {
    slot = { tail: Promise.resolve(null), queued: null, pending: 0 };
    writes.set(rowKey, slot);
  }
  if (slot.queued) {
    slot.queued.payload = payload;
    log.debug("Leaving queueWrite(). Coalesced into the waiting write.");
    return slot.queued.promise;
  }
  const entry = { payload: payload, promise: null };
  slot.queued = entry;
  slot.pending += 1;
  entry.promise = slot.tail.then(function () {
    if (slot.queued === entry) {
      slot.queued = null;
    }
    return perform(rowKey, entry.payload);
  }).then(function (outcome) {
    return outcome;
  }, function (e) {
    // `perform` reports its own failures with their codes; this is the net
    // under a bug in one, so the queue behind it still runs.
    log.error(errorCodes.tag('STS-KEYS-0056') + 'keystore: a write of the "' +
              rowKey + '" row failed unexpectedly: ' +
              ((e && e.message) || e));
    return { ok: false, error: (e && e.message) || String(e) };
  }).then(function (outcome) {
    lastOutcome.set(rowKey, outcome);
    slot.pending -= 1;
    if (!slot.pending && writes.get(rowKey) === slot) {
      writes.delete(rowKey);
    }
    return outcome;
  });
  slot.tail = entry.promise;
  log.debug("Leaving queueWrite(). Queued.");
  return entry.promise;
}

// Whether any row this process holds is not yet written — for the cluster
// barrier's commit-before-respond, through `persistence.pendingWrites()`.
function pendingWrites() {
  log.debug("Entering pendingWrites().");
  log.debug("Leaving pendingWrites().");
  return writes.size > 0;
}

// The outcome of the last write of one row, once everything queued for it has
// landed.
function settle(rowKey) {
  log.debug("Entering settle().");
  const slot = writes.get(String(rowKey));
  log.debug("Leaving settle().");
  return slot ? slot.tail : Promise.resolve(lastOutcome.get(String(rowKey)) ||
                                            null);
}

function settleAll() {
  log.debug("Entering settleAll().");
  const tails = [];
  writes.forEach(function (slot) {
    tails.push(slot.tail);
  });
  log.debug("Leaving settleAll(). " + tails.length + " row(s).");
  return Promise.all(tails);
}

function pkiSettled(scopeId) {
  log.debug("Entering pkiSettled().");
  log.debug("Leaving pkiSettled().");
  return settle(PKI_ROW_PREFIX + String(scopeId || ''));
}

// ---------------------------------------------------------------------------
// TWO BLOBS, ONE KEY SET? The certificate a set was born with names it (see
// `serialise()`), and the MEMBERS are the parts made lazily and independently.
// ---------------------------------------------------------------------------
const KEY_SET_MEMBERS = ['pqKeys', 'vciRequestEncKey', 'refreshTokenEncKeys',
                         'requestObjectEncKeys'];

function hasMember(blob, member) {
  log.debug("Entering hasMember().");
  const value = blob && blob[member];
  log.debug("Leaving hasMember().");
  return member === 'pqKeys' ? !!(value && value.length) : !!value;
}

function sameKeySet(a, b) {
  log.debug("Entering sameKeySet().");
  if (!a || !b || a.certB64 !== b.certB64) {
    log.debug("Leaving sameKeySet(). Different sets.");
    return false;
  }
  const differing = KEY_SET_MEMBERS.filter(function (member) {
    return hasMember(a, member) !== hasMember(b, member) ||
           (hasMember(a, member) &&
            JSON.stringify(a[member]) !== JSON.stringify(b[member]));
  });
  log.debug("Leaving sameKeySet(). " + differing.length + " member(s) differ.");
  return !differing.length;
}

// What the row should hold, given what is in it (`stored`, or null for no row)
// and what this process offers. `{ keep: true }` leaves the row alone.
function decideKeys(stored, offered) {
  log.debug("Entering decideKeys().");
  if (!stored) {
    log.debug("Leaving decideKeys(). No row: first writer.");
    return { outcome: 'won', blob: offered, write: true };
  }
  if (stored.certB64 !== offered.certB64) {
    log.debug("Leaving decideKeys(). Another set was first.");
    return { outcome: 'lost', blob: stored, write: false };
  }
  const joined = Object.assign({}, stored);
  let added = 0;
  KEY_SET_MEMBERS.forEach(function (member) {
    if (!hasMember(stored, member) && hasMember(offered, member)) {
      joined[member] = offered[member];
      added += 1;
    }
  });
  log.debug("Leaving decideKeys(). " + added + " member(s) added.");
  return { outcome: added ? 'joined' : 'kept', blob: added ? joined : stored,
           write: added > 0 };
}

function openBlob(cipher, label) {
  log.debug("Entering openBlob().");
  log.debug("Leaving openBlob().");
  return JSON.parse(crypto.decryptWithKek(kek, cipher, label));
}

// ---------------------------------------------------------------------------
// ADOPT A KEY SET THE STORE HOLDS, replacing whatever this process built.
// Every place a set is dropped for another goes through here, because each of
// the three halves has a defect behind it when skipped: the SHARED blob
// (`sharedFor()`), the STORED material (`adoptShared()`'s 2026-09-12 note), and
// the CACHED set `helpers.js` signs with (the adopt listener).
// ---------------------------------------------------------------------------
function adoptStoredKeys(id, blob, cipher, options) {
  log.debug("Entering adoptStoredKeys(). realm=" + id);
  purgeFor(id);
  material.set(id, { cipher: cipher, createdAt: blob.createdAt || 0,
                     plain: null, parsed: null, buffer: null, timer: null,
                     immediate: false });
  shared.set(id, blob);
  if (adoptListener) {
    try {
      adoptListener(id);
    } catch (e) {
      log.error(errorCodes.tag('STS-KEYS-0030') + 'keystore: the "' + id +
                '" realm\'s cached key set could not be dropped after ' +
                'adopting the one the store holds: ' + e.message + '. This ' +
                'process is still signing with its own.');
    }
  }
  // **CONFIRMED**, so the request pool's arbitration adopts it rather than
  // telling this process to take the set the front process happened to hear
  // about first — see `request_pool.js`'s `receivePublishedKeys()`.
  if (options && options.publish && publisher) {
    publisher(id, blob, { confirmed: true });
  }
  log.debug("Leaving adoptStoredKeys().");
}

function writeKeys(id, payload) {
  log.debug("Entering writeKeys(). realm=" + id);
  if (!arbitrates()) {
    log.debug("Leaving writeKeys(). An upsert.");
    return Promise.resolve().then(function () {
      return store.saveKeys(id, payload.cipher);
    }).then(function () {
      log.info('keystore: the "' + id + '" realm\'s signing keys were ' +
               payload.why + ' and written to the store, encrypted.');
      return { ok: true, outcome: 'written' };
    }, function (e) {
      log.error(errorCodes.tag('STS-KEYS-0035') +
                'keystore: the "' + id + '" realm\'s signing keys could not ' +
                'be written: ' + e.message + '. They will be different after ' +
                'the next restart.');
      return { ok: false, error: e.message };
    });
  }
  let decided = null;
  log.debug("Leaving writeKeys(). A merge under the row's lock.");
  return Promise.resolve().then(function () {
    return store.mergeKeys(id, payload.cipher, function (current) {
      log.debug("Entering the key-set merge. realm=" + id);
      decided = decideKeys(current ? openBlob(current, 'signing-keys') : null,
                           payload.blob);
      log.debug("Leaving the key-set merge. " + decided.outcome);
      if (!decided.write) {
        return null;
      }
      return decided.blob === payload.blob
        ? payload.cipher
        : crypto.encryptWithKek(kek, JSON.stringify(decided.blob),
                                'signing-keys');
    });
  }).then(function (result) {
    if (!decided) {
      // `mergeKeys()` always asks; a driver that did not has written nothing
      // this process can reason about, and the next start reads the row.
      return { ok: true, outcome: 'unknown' };
    }
    const stored = result.material;
    const entry = material.get(id);
    // A NEWER WRITE OF THIS REALM IS WAITING, or the realm's keys were rotated
    // or removed while this one was in flight: that write, or that removal,
    // decides what this process holds.
    const superseded = !entry || (writes.get(id) && writes.get(id).queued);
    if (superseded) {
      return { ok: true, outcome: decided.outcome, superseded: true };
    }
    if (sameKeySet(decided.blob, payload.blob)) {
      // What this process holds IS what the store holds. The ciphertext is
      // taken from the store so the bytes match, and nothing is rebuilt.
      entry.cipher = stored;
      log.info('keystore: the "' + id + '" realm\'s signing keys were ' +
               payload.why + ' and ' + (decided.outcome === 'kept'
                 ? 'were already in the store'
                 : 'written to the store, encrypted') + '.');
      return { ok: true, outcome: decided.outcome };
    }
    // THE STORE HOLDS OTHER KEYS — another node's set, or this set with a
    // member another node made first — and they are the ones every node uses.
    adoptStoredKeys(id, decided.blob, stored, { publish: true });
    log.warn('keystore: the "' + id + '" realm\'s signing keys ' +
             (decided.outcome === 'lost'
               ? 'were generated here and ANOTHER NODE\'S were already in ' +
                 'the store; this process adopted those'
               : 'gained members another node had made first; this process ' +
                 'adopted them') + '. Anything this process signed with what ' +
             'it held in between will not verify against the published keys.');
    return { ok: true, outcome: decided.outcome, adopted: true };
  }, function (e) {
    log.error(errorCodes.tag('STS-KEYS-0035') +
              'keystore: the "' + id + '" realm\'s signing keys could not ' +
              'be written: ' + e.message + '. They will be different after ' +
              'the next restart, and another node may hold different ones.');
    return { ok: false, error: e.message };
  });
}

function writePki(rowKey, payload) {
  log.debug("Entering writePki(). row=" + rowKey);
  const id = rowKey.slice(PKI_ROW_PREFIX.length);
  const chain = payload.chain;
  if (!chain) {
    log.debug("Leaving writePki(). A removal.");
    return Promise.resolve().then(function () {
      return typeof store.deleteKeys === 'function'
        ? store.deleteKeys(rowKey)
        // A driver with no delete is told to store an EMPTY hierarchy rather
        // than being left with the old one. `start()` reads a falsy `tiers`
        // back as no hierarchy, so the two spellings mean the same thing.
        : store.saveKeys(rowKey, crypto.encryptWithKek(kek, JSON.stringify({}),
                                                       'pki-hierarchy'));
    }).then(function () {
      pkiBase.delete(id);
      log.info('keystore: the "' + id + '" realm\'s certificate authority ' +
               'was removed from the store.');
      return { ok: true, removed: true, lost: [] };
    }, function (e) {
      log.error(errorCodes.tag('STS-KEYS-0042') +
                'keystore: the "' + id + '" realm\'s certificate authority ' +
                'could not be removed from the store: ' + e.message + '.');
      return { ok: false, error: e.message, lost: [] };
    });
  }
  const text = JSON.stringify(chain);
  const cipher = crypto.encryptWithKek(kek, text, 'pki-hierarchy');
  if (!arbitrates()) {
    log.debug("Leaving writePki(). An upsert.");
    return Promise.resolve().then(function () {
      return store.saveKeys(rowKey, cipher);
    }).then(function () {
      log.info('keystore: the "' + id + '" realm\'s certificate authority ' +
               'was written to the store, encrypted.');
      return { ok: true, merged: false, lost: [] };
    }, function (e) {
      log.error(errorCodes.tag('STS-KEYS-0042') +
                'keystore: the "' + id + '" realm\'s certificate authority ' +
                'could not be written: ' + e.message + '. It will be ' +
                'different after the next restart.');
      return { ok: false, error: e.message, lost: [] };
    });
  }
  const baseCipher = pkiBase.has(id) ? pkiBase.get(id) : null;
  let decided = null;
  log.debug("Leaving writePki(). A merge under the row's lock.");
  return Promise.resolve().then(function () {
    return store.mergeKeys(rowKey, cipher, function (current) {
      log.debug("Entering the hierarchy merge. scope=" + id);
      // NOBODY ELSE HAS WRITTEN THE ROW SINCE THIS PROCESS LAST SAW IT — the
      // ordinary case, and a comparison of ciphertexts rather than a decrypt:
      // every seal has a fresh IV, so equal bytes are the same write.
      if (current === baseCipher) {
        decided = { merged: false, lost: [], displaced: 0 };
        log.debug("Leaving the hierarchy merge. Unchanged underneath.");
        return cipher;
      }
      const base = baseCipher ? openBlob(baseCipher, 'pki-hierarchy') : null;
      const theirs = current ? openBlob(current, 'pki-hierarchy') : {};
      const answer = pkiMerge.merge(base, JSON.parse(text), theirs);
      decided = { merged: true, lost: answer.lost,
                  displaced: answer.displaced, row: answer.row };
      log.debug("Leaving the hierarchy merge. Merged.");
      return crypto.encryptWithKek(kek, JSON.stringify(answer.row),
                                   'pki-hierarchy');
    });
  }).then(function (result) {
    pkiBase.set(id, result.material);
    if (!decided) {
      return { ok: true, merged: false, lost: [] };
    }
    const newer = pkiLocalGen.get(id) !== payload.gen;
    if (decided.merged && !newer) {
      // WHAT THE STORE NOW HOLDS IS WHAT THIS PROCESS HOLDS — held, shared
      // with the rest of this container, and reconciled with the listener
      // where this process has one, exactly as a row another node wrote is.
      pkiHeld.set(id, decided.row);
      if (pkiPublisher) {
        pkiPublisher(id, decided.row);
      }
      notifyHierarchyAdopted(id);
    }
    if (decided.lost.length) {
      log.warn(errorCodes.tag('STS-KEYS-0057') + 'keystore: the "' + id +
               '" certificate authority was changed by another node at the ' +
               'same moment, and ITS ' + decided.lost.join(', ') + ' ' +
               (decided.lost.length === 1 ? 'was' : 'were') + ' kept — the ' +
               'first to commit wins a CA tier or a certificate slot, ' +
               'because the other has already issued under it.' +
               (decided.displaced ? ' ' + decided.displaced + ' displaced ' +
                'certificate serial(s) were kept in the issued register.'
                                  : ''));
    } else {
      log.info('keystore: the "' + id + '" realm\'s certificate authority ' +
               'was ' + (decided.merged
                 ? 'MERGED with a copy another node had written, and stored'
                 : 'written to the store, encrypted') + '.');
    }
    return { ok: true, merged: decided.merged, lost: decided.lost,
             displaced: decided.displaced };
  }, function (e) {
    log.error(errorCodes.tag('STS-KEYS-0042') +
              'keystore: the "' + id + '" realm\'s certificate authority ' +
              'could not be written: ' + e.message + '. It will be ' +
              'different after the next restart, and another node may hold ' +
              'a different one.');
    return { ok: false, error: e.message, lost: [] };
  });
}

function notifyHierarchyAdopted(id) {
  log.debug("Entering notifyHierarchyAdopted().");
  if (store && typeof store.hierarchyAdopted === 'function') {
    try {
      store.hierarchyAdopted(id);
    } catch (e) {
      log.debug("Caught in notifyHierarchyAdopted(): " +
                ((e && e.message) || e));
    }
  }
  log.debug("Leaving notifyHierarchyAdopted().");
}

// ---------------------------------------------------------------------------
// A ROW ANOTHER PROCESS WROTE. `persistence.js`'s `keys` applier calls this
// for every change row, and `pki.js` before it builds anything, so a node does
// not build what the store already has.
//
// **IT READS THE CURRENT ROW**, never an operation, which is what makes a late
// change, a duplicate and an out-of-order pair all safe. **AND IT DEFERS TO A
// WRITE OF ITS OWN IN FLIGHT**, whose merge is about to decide against the
// same row and will adopt the answer — adopting underneath it would replace
// this process's unwritten change with a copy that lacks it.
// ---------------------------------------------------------------------------
function applyStoredChange(rowKey) {
  log.debug("Entering applyStoredChange(). row=" + rowKey);
  const key = String(rowKey || '');
  const isPki = key.indexOf(PKI_ROW_PREFIX) === 0;
  const id = isPki ? key.slice(PKI_ROW_PREFIX.length) : key;
  const kind = isPki ? 'pki' : 'keys';
  // ONLY WHERE THE STORE ARBITRATES. With `cluster.mode=off` every write is
  // still the last-writer-wins upsert, and adopting rows under that would be
  // two processes each adopting the other's set in the same moment and ending
  // as split as they started — which is the argument `applyKeysChange()` used
  // to make for doing nothing, and it still holds there.
  if (!arbitrates()) {
    log.debug("Leaving applyStoredChange(). The store does not arbitrate.");
    return Promise.resolve({ kind: kind, realm: id, adopted: false });
  }
  if (writes.has(key)) {
    log.debug("Leaving applyStoredChange(). A write of ours is in flight.");
    return Promise.resolve({ kind: kind, realm: id, adopted: false,
                             pending: true });
  }
  log.debug("Leaving applyStoredChange(). Reading the row.");
  return Promise.resolve().then(function () {
    return store.loadKey(key);
  }).then(function (cipher) {
    if (writes.has(key)) {
      return { kind: kind, realm: id, adopted: false, pending: true };
    }
    try {
      return isPki ? adoptPkiRow(id, cipher) : adoptKeyRow(id, cipher);
    } catch (e) {
      log.error(errorCodes.tag('STS-KEYS-0058') + 'keystore: the "' + key +
                '" row another process wrote could not be opened: ' +
                e.message + '. This process keeps what it holds.');
      return { kind: kind, realm: id, adopted: false, error: e.message };
    }
  });
}

function adoptKeyRow(id, cipher) {
  log.debug("Entering adoptKeyRow(). realm=" + id);
  const entry = material.get(id);
  if (!cipher) {
    if (!entry && !shared.has(id)) {
      log.debug("Leaving adoptKeyRow(). Nothing held, nothing stored.");
      return { kind: 'keys', realm: id, adopted: false };
    }
    // ROTATED OR REMOVED ON ANOTHER NODE. The set is dropped here as
    // `rotate()` drops it there, and whichever node signs next makes the
    // next one — which the store then arbitrates.
    purgeFor(id);
    material.delete(id);
    shared.delete(id);
    if (adoptListener) {
      adoptListener(id);
    }
    log.warn('keystore: the "' + (id || 'default') + '" realm\'s signing ' +
             'keys were REMOVED by another node (a rotation, or the realm ' +
             'went); this process dropped them too.');
    log.debug("Leaving adoptKeyRow(). Removed.");
    return { kind: 'keys', realm: id, adopted: true, removed: true };
  }
  if (entry && entry.cipher === cipher) {
    log.debug("Leaving adoptKeyRow(). Already held.");
    return { kind: 'keys', realm: id, adopted: false };
  }
  const stored = openBlob(cipher, 'signing-keys');
  const held = entry ? (entry.plain || openBlob(entry.cipher, 'signing-keys'))
                     : shared.get(id);
  if (held && sameKeySet(held, stored)) {
    if (entry) {
      entry.cipher = cipher;
    } else {
      material.set(id, { cipher: cipher, createdAt: stored.createdAt || 0,
                         plain: null, parsed: null, buffer: null, timer: null,
                         immediate: false });
    }
    log.debug("Leaving adoptKeyRow(). The same set.");
    return { kind: 'keys', realm: id, adopted: false };
  }
  adoptStoredKeys(id, stored, cipher, { publish: false });
  log.info('keystore: the "' + (id || 'default') + '" realm\'s signing keys ' +
           'were written by another node' + (held ? ', replacing the set ' +
           'this process held' : '') + '; this process uses them now.');
  log.debug("Leaving adoptKeyRow(). Adopted.");
  return { kind: 'keys', realm: id, adopted: true };
}

function adoptPkiRow(id, cipher) {
  log.debug("Entering adoptPkiRow(). scope=" + id);
  if (cipher === (pkiBase.has(id) ? pkiBase.get(id) : null)) {
    log.debug("Leaving adoptPkiRow(). Already the base.");
    return { kind: 'pki', realm: id, adopted: false };
  }
  const chain = cipher ? openBlob(cipher, 'pki-hierarchy') : null;
  const empty = !chain || !Object.keys(chain).length;
  if (empty) {
    pkiBase.delete(id);
    if (!pkiHeld.has(id)) {
      log.debug("Leaving adoptPkiRow(). Nothing held, nothing stored.");
      return { kind: 'pki', realm: id, adopted: false };
    }
    pkiHeld.delete(id);
  } else {
    pkiHeld.set(id, chain);
    pkiBase.set(id, cipher);
  }
  notifyHierarchyAdopted(id);
  log.info('keystore: the "' + (id || 'default') + '" certificate authority ' +
           'was ' + (empty ? 'removed' : 'written') + ' by another node; ' +
           'this process holds what the store holds.');
  log.debug("Leaving adoptPkiRow().");
  return { kind: 'pki', realm: id, adopted: true, removed: empty };
}

// For `pki.js`: land this process's queued writes of a scope's row, then take
// what the store holds. Resolves the adoption answer.
function refreshPki(scopeId) {
  log.debug("Entering refreshPki().");
  const rowKey = PKI_ROW_PREFIX + String(scopeId || '');
  log.debug("Leaving refreshPki().");
  return settle(rowKey).then(function () {
    return applyStoredChange(rowKey);
  });
}

// FORGET EVERYTHING HELD IN MEMORY, so a test can do what a restart does
// without being a restart. It clears the loaded material and the KEK; the
// STORE is not cleared, because a caller that wanted that would be testing
// `setStore()` rather than a restart.
//
// It is exported for the tests (`tests/keystore.js` and its neighbours) and
// for nothing else. That is a real cost — an export that exists for a test is
// a seam somebody can misuse — and it is paid because the alternative is a
// test that launches two processes and therefore cannot run in the in-process
// suite at all.
function reset() {
  log.debug("Entering reset().");
  shared.clear();
  pkiHeld.clear();
  // What the store arbitration holds (#46): a test doing what a restart does
  // starts with nothing queued and no base to merge from.
  writes.clear();
  lastOutcome.clear();
  pkiBase.clear();
  pkiLocalGen.clear();
  publisher = null;
  pkiPublisher = null;
  ephemeral = false;
  log.debug('Entering reset().');
  purgeAll();
  material.clear();
  kek = null;
  log.debug('Leaving reset().');
}

module.exports = {
  // The shared-key channel. See the SHARED KEY MATERIAL block above
  // sharedFor().
  setKeyPublisher: setKeyPublisher,
  useEphemeralKek: useEphemeralKek,
  hasEphemeralKek: hasEphemeralKek,
  ephemeralKek: ephemeralKek,
  onAdopt: onAdopt,
  sharedFor: sharedFor,
  sharedBlobFor: sharedBlobFor,
  adoptShared: adoptShared,
  publishShared: publishShared,
  sharedAll: sharedAll,
  // The enrichment rule both ends of that channel apply, and the read-only
  // question `helpers.js` asks before it backfills a request-encryption key.
  enriches: enriches,
  requestEncryptionKeyHeldFor: requestEncryptionKeyHeldFor,
  refreshTokenKeysHeldFor: refreshTokenKeysHeldFor,
  requestObjectKeysHeldFor: requestObjectKeysHeldFor,
  reset: reset,
  setStore: setStore,
  persists: persists,
  sealed: sealed,
  keyedDigest: keyedDigest,
  seal: seal,
  open: open,
  start: start,
  storedFor: storedFor,
  privateMaterialFor: privateMaterialFor,
  purgeFor: purgeFor,
  purgeAll: purgeAll,
  retention: retention,
  retentionSentence: retentionSentence,
  remember: remember,
  // `serialise()` beside it (2026-09-12), so a test can hold a blob's shape
  // without driving the key channel to get one. Pure; it writes nothing.
  serialise: serialise,
  deserialise: deserialise,
  rotate: rotate,
  // The certificate authority material. See the block above attachPki() for
  // why it is in this file and why it has a channel of its own.
  setPkiPublisher: setPkiPublisher,
  adoptPki: adoptPki,
  pkiAll: pkiAll,
  pkiFor: pkiFor,
  attachPki: attachPki,
  // THE STORE AS THE ARBITER BETWEEN NODES (#46). See the block above
  // `arbitrates()`.
  arbitrates: arbitrates,
  applyStoredChange: applyStoredChange,
  refreshPki: refreshPki,
  pendingWrites: pendingWrites,
  settle: settle,
  settleAll: settleAll,
  pkiSettled: pkiSettled,
  report: report
};

// DECLARED AT REQUIRE TIME (cluster/CLAUDE.md): the code that makes a realm's
// signing keys one set for the cluster — the first-writer-wins write, the
// adoption of a row another node wrote, rotation reaching every node — is
// this file, and a cold start settles through it before anything is served
// (`common/service_state.ts`).
capabilities.provide('keys.agreement');
