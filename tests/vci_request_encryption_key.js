'use strict';
//
// File: vci_request_encryption_key.js
//
// ===========================================================================
// THE OPENID4VCI CREDENTIAL REQUEST-ENCRYPTION KEY IS A MEMBER OF THE REALM'S
// KEY SET (2026-09-12).
//
// It was a key of its own until that date: generated when `oid4vc/vc_issuer.js`
// loaded, handed to request workers in
// `process.env.STS_VCI_REQUEST_ENC_KEY_PEM`, persisted in no mode, and SHARED
// by every trust realm in a pooled process — so a realm's issuer decrypted
// requests encrypted to another realm's published key. `common/mode.js` carried
// it as NOT_YET (`vci-request-encryption-key`).
//
// Now it is `vciRequestEncKey` on `helpers.stsKeysFor`'s set, and every
// property it lacked is one that set already has. What this file asserts is
// that each of those properties really REACHES the new member, because a member
// added to a key set is exactly the thing `common/CLAUDE.md` records being
// written and never read back twice already:
//
//   1. PER REALM: two realms, two keys, each the size its realm asked for, and
//      a JWE encrypted to one refused by the other — by the kid AND, with the
//      kid forged, by the key itself. A realm removed and re-created gets a new
//      key rather than the old one's.
//   2. THE CHANNEL: a set published by one process and adopted by another
//      carries the key, so the two publish and decrypt with the same one.
//   3. THE STORE: in product-shaped mode (`keys.source=persisted`) the key is
//      written down SEALED, comes back after a restart, publishes its public
//      half without a decrypt, and a row written BEFORE the key joined the set
//      is backfilled once and then restored like any other.
//   4. THE ENRICHMENT RULE, which both ends of the channel now share.
//   5. THE HAND-OFF IS GONE, read as source, because a fourth copy of the old
//      arrangement would pass every behavioural assertion above.
//   6. THE ISSUER USES IT — in a CHILD PROCESS, because requiring
//      `oid4vc/vc_issuer.js` registers routes on the shared app and `run.js`
//      runs every file in one process.
//
// WHY IN PROCESS AT ALL, tests/CLAUDE.md's first question: sections 2 to 4 are
// what one process offers another and what a restart puts back, neither of
// which any HTTP surface publishes, and section 1's forged-kid case is a JWE no
// wallet would build.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'vci_request_encryption_key',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function modulusBits(publicJwk) {
  log.debug("Entering modulusBits().");
  log.debug("Leaving modulusBits().");
  return Buffer.from(String((publicJwk || {}).n || ''), 'base64url').length * 8;
}

// A store with the drivers' shape, for the round trip — `tests/keystore.js`'s.
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

function nullStore() {
  log.debug("Entering nullStore().");
  log.debug("Leaving nullStore().");
  return { loadKeys: function () {
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
           } };
}

function settle(ms) {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) { setTimeout(resolve, ms || 50); });
}

// -------------------------------------------------------------------------
// 1. ONE KEY PER REALM.
// -------------------------------------------------------------------------
function checkPerRealm(t) {
  log.debug("Entering checkPerRealm().");
  t.log.info('=== one request-encryption key per trust realm ===');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const stsCrypto = require('../common/crypto');

  const made = [];
  function create(id, overrides) {
    log.debug("Entering create().");
    const r = realms.create({ id: id, name: id, overrides: overrides || {},
                              description: 'Created by ' + __filename });
    if (!r.ok) {
      t.bad('could not create the realm "' + id + '"',
            (r.errors || []).join(' '));
      log.debug("Leaving create().");
      return null;
    }
    made.push(id);
    log.debug("Leaving create().");
    return r.realm;
  }
  try {
    const a = create('vci-key-a');
    const b = create('vci-key-b',
                     { 'oid4vci.requestEncryptionKeyBits': '3072' });
    if (!a || !b) {
      log.debug("Leaving checkPerRealm().");
      return;
    }
    const kDefault = helpers.requestEncryptionKeyFor();
    // B'S SET IS BUILT FROM OUTSIDE ITS REALM, through `.of()` — which is how a
    // watcher or a sweep reaches a realm's keys — so the size assertion below
    // is about the factory entering the realm, and not about a caller that
    // happened to be in it already.
    helpers.stsKeysFor.of('vci-key-b');
    const kA = realms.run(a,
                          function () {
                            return helpers.requestEncryptionKeyFor();
                          });
    const kB = realms.run(b,
                          function () {
                            return helpers.requestEncryptionKeyFor();
                          });

    t.check(!!(kDefault && kA && kB && kDefault.publicJwk && kA.publicJwk &&
               kB.publicJwk),
            'the default realm and two realms each answer with a ' +
            'request-encryption key');
    t.check(kA.publicJwk.kid !== kB.publicJwk.kid &&
            kA.publicJwk.kid !== kDefault.publicJwk.kid &&
            kB.publicJwk.kid !== kDefault.publicJwk.kid,
            'THREE REALMS, THREE KEYS. In a pooled process this was one key ' +
            'the pool handed down, shared by every realm',
            [kDefault.publicJwk.kid, kA.publicJwk.kid, kB.publicJwk.kid].join(
                ' ' +
                '/ '));
    t.check(kA.publicJwk.n !== kB.publicJwk.n,
            'and different KEY MATERIAL, not merely different names');
    t.check(helpers.stsKeysFor.of('vci-key-a').vciRequestEncKey.publicJwk.kid ===
            kA.publicJwk.kid,
            'the key IS the realm\'s key set\'s member, which is the whole ' +
            'of the change: every property of the set reaches it');
    t.check(/^sts-req-enc-/.test(kA.publicJwk.kid) &&
            kA.publicJwk.alg === helpers.VCI_REQUEST_ENC_ALG &&
            kA.publicJwk.use === 'enc' &&
            JSON.stringify(kA.publicJwk.key_ops) === '["encrypt"]',
            'what a wallet sees is unchanged: the kid prefix, alg ' +
            'RSA-OAEP-256, use enc and key_ops encrypt, which OID4VCI ' +
            'section 10 requires',
            JSON.stringify({ kid: kA.publicJwk.kid, alg: kA.publicJwk.alg,
                             use: kA.publicJwk.use,
                             key_ops: kA.publicJwk.key_ops }));
    t.check(!('d' in kA.publicJwk) && !('p' in kA.publicJwk),
            'the PUBLISHED half carries no private member');
    t.equal(modulusBits(kA.publicJwk), 2048,
            'a realm with no override gets ' +
            'oid4vci.requestEncryptionKeyBits\'s default');
    t.equal(modulusBits(kB.publicJwk), 3072,
            'A REALM CARRYING THE SETTING GETS THE SIZE IT ASKED FOR — the ' +
            'key set is made inside the realm it is for, so the setting is ' +
            'read there');

    // A JWE encrypted to realm A's published key.
    const compact = stsCrypto.encryptJweCompact(JSON.stringify({ probe: 'a' }),
                                                {
      alg: 'RSA-OAEP-256', enc: 'A256GCM', jwk: kA.publicJwk });
    let readInA = null;
    try {
      readInA = stsCrypto.decryptJweCompact(compact, {
        privateKey: kA.privateKey, expectedKid: kA.publicJwk.kid });
    } catch (e) {
      readInA = { error: e.message };
    }
    t.check(!!(readInA && readInA.plaintext &&
               JSON.parse(readInA.plaintext).probe === 'a'),
            'realm A decrypts a request encrypted to the key realm A publishes',
            JSON.stringify(readInA && (readInA.error || readInA.header)));

    let refusedByKid = '';
    try {
      stsCrypto.decryptJweCompact(compact, {
        privateKey: kB.privateKey, expectedKid: kB.publicJwk.kid });
    } catch (e) {
      refusedByKid = e.message;
    }
    t.check(/kid/.test(refusedByKid),
            'REALM B REFUSES IT — on the kid, which is the first thing the ' +
            'issuer checks and names the wrong issuer rather than a corrupt ' +
            'request',
            refusedByKid);

    // And with B's kid FORGED into the header, so the refusal has to come from
    // the key: the header is authenticated data, so this is a JWE that was
    // encrypted to A and claims to be for B.
    const forged = stsCrypto.encryptJweCompact(JSON.stringify(
        { probe: 'forged' }), {
      alg: 'RSA-OAEP-256', enc: 'A256GCM',
      jwk: Object.assign({}, kA.publicJwk, { kid: kB.publicJwk.kid }) });
    let refusedByKey = '';
    try {
      stsCrypto.decryptJweCompact(forged, {
        privateKey: kB.privateKey, expectedKid: kB.publicJwk.kid });
    } catch (e) {
      refusedByKey = e.message;
    }
    t.check(refusedByKey !== '' && !/kid/.test(refusedByKey),
            'AND WITH B\'S KID FORGED ONTO IT, B\'S KEY STILL CANNOT OPEN IT ' +
            '— the refusal is the unwrap, which is the property the shared ' +
            'key did not have',
            refusedByKey);

    // Removal takes the key with it.
    realms.remove('vci-key-a');
    made.splice(made.indexOf('vci-key-a'), 1);
    const again = create('vci-key-a');
    if (again) {
      const kAgain = realms.run(again, function () {
        return helpers.requestEncryptionKeyFor();
      });
      t.check(kAgain.publicJwk.kid !== kA.publicJwk.kid,
              'a realm removed and created again under the same id gets a ' +
              'NEW key — the key set\'s purge reaches the new member',
              kA.publicJwk.kid + ' -> ' + kAgain.publicJwk.kid);
    }
  } finally {
    made.forEach(function (id) { realms.remove(id); });
  }
  log.debug("Leaving checkPerRealm().");
}

// -------------------------------------------------------------------------
// 2. THE KEY CHANNEL CARRIES IT.
//
// One process generates a realm's keys and publishes the blob; another adopts
// it (at fork, or when told it lost the race). Both have to publish and
// decrypt with ONE key, which is the property the env hand-off provided for
// one key and nothing else.
// -------------------------------------------------------------------------
function checkChannel(t) {
  log.debug("Entering checkChannel().");
  t.log.info('=== the key channel carries it ===');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const keystore = require('../common/keystore');

  const r = realms.create({ id: 'vci-key-chan', name: 'vci-key-chan',
                            description: 'Created by ' + __filename });
  if (!r.ok) {
    t.bad('could not create the channel realm', (r.errors || []).join(' '));
    log.debug("Leaving checkChannel().");
    return;
  }
  const published = [];
  try {
    keystore.setKeyPublisher(function (realmId, blob) {
      published.push({ realm: realmId, blob: blob });
    });
    const front = realms.run(r.realm, function () {
      return helpers.requestEncryptionKeyFor();
    });
    const offer = published.filter(function (one) {
      return one.realm === 'vci-key-chan';
    })[0];
    t.check(!!(offer && offer.blob && offer.blob.vciRequestEncKey),
            'THE BLOB A PROCESS OFFERS CARRIES THE KEY — serialise() writes ' +
            'the new member',
            offer ? Object.keys(offer.blob).join(',') : '(nothing offered)');
    t.check(!!(offer && offer.blob.vciRequestEncKey.privateKeyPem &&
               /PRIVATE KEY/.test(offer.blob.vciRequestEncKey.privateKeyPem)),
            'as a PEM, which is what survives JSON and the fork\'s IPC ' +
            'channel');

    // THE OTHER PROCESS: forget everything and adopt what was offered, which
    // is exactly what a forked worker does with `message.keys`.
    keystore.reset();
    helpers.resetStsKeys();
    if (offer) {
      keystore.adoptShared('vci-key-chan', offer.blob);
    }
    // ON THE SET ITSELF, before anything asks for the key — so this is about
    // plainKeySet() and deserialise() putting the member back, and not about
    // the backfill finding it in the shared blob afterwards, which would pass
    // the assertion below with both of those broken.
    const adoptedSet = helpers.stsKeysFor.of('vci-key-chan');
    t.check(!!(adoptedSet.vciRequestEncKey &&
               adoptedSet.vciRequestEncKey.publicJwk &&
               adoptedSet.vciRequestEncKey.publicJwk.kid === front.publicJwk.kid),
            'THE SET BUILT FROM A SIBLING\'S BLOB CARRIES THE KEY ITSELF',
            adoptedSet.vciRequestEncKey ?
            adoptedSet.vciRequestEncKey.publicJwk.kid : '(absent)');
    const worker = realms.run(r.realm, function () {
      return helpers.requestEncryptionKeyFor();
    });
    t.equal(worker && worker.publicJwk.kid, front.publicJwk.kid,
            'THE ADOPTING PROCESS PUBLISHES THE SAME KEY — plainKeySet() ' +
            'puts the member back on a sibling\'s set rather than leaving it ' +
            'to be generated');
    t.check(!!(worker && worker.privateKey &&
               nodeCrypto.createPublicKey(worker.privateKey)
                         .export({ format: 'jwk' }).n ===
               front.publicJwk.n),
            'and holds the matching PRIVATE key, so a request encrypted to ' +
            'what one process published is decrypted by the other');
  } finally {
    keystore.reset();
    helpers.resetStsKeys();
    realms.remove('vci-key-chan');
  }
  log.debug("Leaving checkChannel().");
}

// -------------------------------------------------------------------------
// 3. THE STORE: SEALED, RESTORED, RESIDENT ONLY WHILE USED, AND BACKFILLED.
// -------------------------------------------------------------------------
async function checkStore(t) {
  log.debug("Entering checkStore().");
  t.log.info('=== persisted with the key set ===');
  const helpers = require('../common/helpers');
  const keystore = require('../common/keystore');
  const stsCrypto = require('../common/crypto');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-vci-key-'));
  const kekFile = path.join(dir, 'kek');
  const kekText = nodeCrypto.randomBytes(32).toString('base64');
  fs.writeFileSync(kekFile, kekText, { mode: 0o600 });
  // THE ENVIRONMENT LAYER, for tests/keystore.js's reason: all three are
  // restart-only and setOverride() would refuse them.
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  const store = fakeStore();

  async function restart() {
    log.debug("Entering restart().");
    keystore.reset();
    keystore.setStore(store);
    await keystore.start();
    helpers.resetStsKeys();
    log.debug("Leaving restart().");
  }

  try {
    await restart();
    t.equal(keystore.persists(), true, 'the keystore persists in this section');
    const first = helpers.requestEncryptionKeyFor();
    await settle();
    const row = store.rows.get('default') || '';
    t.check(stsCrypto.isEncryptedWithKek(row) && row.indexOf('PRIVATE KEY') < 0,
            'the key set, request-encryption key included, is written SEALED');
    const opened = JSON.parse(stsCrypto.decryptWithKek(kekText, row,
                                                       'signing-keys'));
    t.check(!!(opened.vciRequestEncKey && opened.vciRequestEncKey.publicJwk &&
               opened.vciRequestEncKey.publicJwk.kid === first.publicJwk.kid),
            'AND THE ROW CARRIES THE KEY — this is what "persisted in ' +
            'neither mode" becomes',
            opened.vciRequestEncKey ? opened.vciRequestEncKey.publicJwk.kid :
            '(absent)');

    await restart();
    const restoredSet = helpers.stsKeysFor.of('default');
    t.check(!!(restoredSet.vciRequestEncKey &&
               restoredSet.vciRequestEncKey.publicJwk &&
               restoredSet.vciRequestEncKey.publicJwk.kid === first.publicJwk.kid),
            'THE SET RESTORED FROM THE STORE CARRIES THE KEY ITSELF — ' +
            'lazyKeySet() puts the member back, which is the post-quantum ' +
            'half\'s defect not made a second time');
    const restored = helpers.requestEncryptionKeyFor();
    t.equal(restored.publicJwk.kid, first.publicJwk.kid,
            'THE SAME KEY COMES BACK AFTER A RESTART, so a wallet that ' +
            'cached the issuer metadata before it can still encrypt to this ' +
            'issuer after it');

    // RESIDENCY. Purge, read the public half, and nothing is decrypted.
    keystore.purgeAll();
    const publicOnly = helpers.requestEncryptionKeyFor().publicJwk.kid;
    t.check(publicOnly === first.publicJwk.kid &&
            keystore.report().plaintextHeld.indexOf('default') < 0,
            'PUBLISHING THE KEY DECRYPTS NOTHING — the public JWK is ' +
            'resident on the set and the private half is a getter, as the ' +
            'curve keys are',
            JSON.stringify(keystore.report().plaintextHeld));
    const privateKey = helpers.requestEncryptionKeyFor().privateKey;
    t.check(keystore.report().plaintextHeld.indexOf('default') >= 0 &&
            !!privateKey && privateKey.type === 'private',
            'and asking for the PRIVATE half is what decrypts it');
    const compact = stsCrypto.encryptJweCompact('{"restored":true}', {
      alg: 'RSA-OAEP-256', enc: 'A128GCM', jwk: first.publicJwk });
    let restoredRead = '';
    try {
      restoredRead = stsCrypto.decryptJweCompact(compact, {
        privateKey: helpers.requestEncryptionKeyFor().privateKey,
        expectedKid: first.publicJwk.kid }).plaintext;
    } catch (e) {
      restoredRead = 'refused: ' + e.message;
    }
    t.equal(restoredRead, '{"restored":true}',
            'the restored private key decrypts what was encrypted to the key ' +
            'published before the restart');

    // A ROW FROM BEFORE THE KEY JOINED THE SET. Strip the member and restart.
    const legacy = Object.assign({}, opened);
    delete legacy.vciRequestEncKey;
    store.rows.set('default',
                   stsCrypto.encryptWithKek(kekText, JSON.stringify(legacy),
                                                        'signing-keys'));
    await restart();
    t.equal(helpers.STS.vciRequestEncKey, undefined,
            'a set restored from a row written before the key existed has no ' +
            'member');
    t.equal(keystore.requestEncryptionKeyHeldFor('default'), null,
            'and nothing this service holds names one, so the backfill must ' +
            'make one');
    const backfilled = helpers.requestEncryptionKeyFor();
    t.check(!!(backfilled && backfilled.publicJwk && backfilled.privateKey),
            'THE LEGACY SET IS BACKFILLED on first use rather than failing ' +
            'the issuer');
    await settle();
    const rewritten = JSON.parse(stsCrypto.decryptWithKek(
      kekText, store.rows.get('default'), 'signing-keys'));
    t.check(!!(rewritten.vciRequestEncKey &&
               rewritten.vciRequestEncKey.publicJwk.kid === backfilled.publicJwk.kid),
            'AND WRITTEN DOWN, so the backfill happens once',
            rewritten.vciRequestEncKey ?
            rewritten.vciRequestEncKey.publicJwk.kid : '(absent)');
    t.equal(rewritten.privateKeyPem, legacy.privateKeyPem,
            'without replacing the signing key it was added beside');
    await restart();
    t.equal(helpers.requestEncryptionKeyFor().publicJwk.kid,
            backfilled.publicJwk.kid,
            'and the next start restores the backfilled key like any other');

    // THE READ-ONLY QUESTION ANSWERS BEFORE THE SET DOES. A process holding a
    // set built before somebody else backfilled the realm must adopt that
    // backfill rather than generate a second key — which is this process
    // restoring the LEGACY row, building its set, and then being handed a
    // sibling's backfilled blob without that set being dropped (adoptShared()
    // drops a cached set only when it REPLACES a shared blob, and on this path
    // there was none).
    store.rows.set('default',
                   stsCrypto.encryptWithKek(kekText, JSON.stringify(legacy),
                                                        'signing-keys'));
    await restart();
    const stale = helpers.stsKeysFor.of('default');
    t.equal(stale.vciRequestEncKey, undefined,
            'a process holding a set restored from the legacy row');
    keystore.adoptShared('default', rewritten);
    t.equal(helpers.stsKeysFor.of('default'), stale,
            'is handed a sibling\'s backfill without its cached set being ' +
            'dropped');
    const adopted = helpers.requestEncryptionKeyFor();
    t.equal(adopted.publicJwk.kid, backfilled.publicJwk.kid,
            'AND USES THE SIBLING\'S KEY RATHER THAN MAKING A SECOND ONE — ' +
            'the backfill asks requestEncryptionKeyHeldFor() before it ' +
            'generates, or this process would publish a key no other process ' +
            'can decrypt for');
  } finally {
    delete process.env.STS_KEYS_SOURCE;
    delete process.env.STS_KEYS_KEK_PROVIDER;
    delete process.env.STS_KEYS_KEK_FILE;
    keystore.reset();
    keystore.setStore(nullStore());
    helpers.resetStsKeys();
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // A directory that could not be removed is not a failed assertion. Said
      // rather than swallowed silently.
      process.stderr.write('vci key test: could not remove ' + dir + ': ' +
                           e.message + '\n');
    }
  }
  log.debug("Leaving checkStore().");
}

// -------------------------------------------------------------------------
// 4. THE ENRICHMENT RULE, which the offering process and the arbitrating one
//    both apply.
// -------------------------------------------------------------------------
function checkEnrichment(t) {
  log.debug("Entering checkEnrichment().");
  t.log.info('=== the enrichment rule ===');
  const keystore = require('../common/keystore');
  const base = { certB64: 'SAME', pqKeys: [], vciRequestEncKey: null };
  const withVci = Object.assign({}, base,
                                { vciRequestEncKey: { publicJwk: {} } });
  const withPq = Object.assign({}, base, { pqKeys: [{}, {}] });
  const withBoth = Object.assign({}, withPq,
                                 { vciRequestEncKey: { publicJwk: {} } });

  t.equal(keystore.enriches(withVci, base), true,
          'a set gaining its request-encryption key is an ENRICHMENT, so a ' +
          'backfill made in one process reaches the rest');
  t.equal(keystore.enriches(withPq, base), true,
          'and a set gaining its post-quantum keys still is');
  t.equal(keystore.enriches(withVci, withPq), false,
          'BUT A SET THAT GAINED ONE MEMBER AND LACKS THE OTHER IS NOT — it ' +
          'would replace a held blob with one that has lost its post-quantum ' +
          'keys');
  t.equal(keystore.enriches(withPq, withVci), false,
          'and the same the other way round: post-quantum keys offered ' +
          'against a held blob that already has the request-encryption key ' +
          'would lose the key — which the one-member rule this replaced ' +
          'accepted');
  t.equal(keystore.enriches(withBoth, withPq), true,
          'while one carrying everything held has, and more, is');
  t.equal(keystore.enriches(withVci, withVci), false,
          'the same content again is not an enrichment');
  t.equal(keystore.enriches(Object.assign({}, withBoth, { certB64: 'OTHER' }),
                            base), false,
          'and a different key set is the race, whatever it carries');
  log.debug("Leaving checkEnrichment().");
}

// -------------------------------------------------------------------------
// 5. THE OLD HAND-OFF IS GONE.
// -------------------------------------------------------------------------
function checkSource(t) {
  log.debug("Entering checkSource().");
  t.log.info('=== the environment hand-off is gone ===');
  const read = function (rel) {
    log.debug("Entering read().");
    log.debug("Leaving read().");
    return fs.readFileSync(path.join(ROOT, rel), 'utf8');
  };
  const pool = read('common/request_pool.js');
  const worker = read('common/request_worker.js');
  const issuer = read('oid4vc/vc_issuer.js');
  const code = function (text) {
    log.debug("Entering code().");
    log.debug("Leaving code().");
    return text.split('\n').filter(function (line) {
      return !/^\s*\/\//.test(line);
    }).join('\n');
  };
  t.check(code(pool).indexOf('STS_VCI_REQUEST_ENC_KEY_PEM') < 0 &&
          code(pool).indexOf('vciRequestEncKeyPem') < 0,
          'the front process no longer generates a key and hands it down the ' +
          'fork');
  t.check(code(worker).indexOf('STS_VCI_REQUEST_ENC_KEY_PEM') < 0,
          'and a worker no longer reads one from its environment');
  t.check(code(issuer).indexOf('STS_VCI_REQUEST_ENC_KEY_PEM') < 0 &&
          code(issuer).indexOf('generateKeyPairSync') < 0,
          'and the issuer makes no key of its own — a fourth copy of the old ' +
          'arrangement would pass every behavioural section above');
  t.check(/keystore\.enriches\(/.test(code(pool)),
          'the arbitrating process applies keystore.enriches() rather than a ' +
          'copy of the rule with one member in it');
  log.debug("Leaving checkSource().");
}

// -------------------------------------------------------------------------
// 6. THE ISSUER, IN A CHILD PROCESS.
// -------------------------------------------------------------------------
function childMain() {
  const OUT = process.env.VCI_KEY_TEST_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    delete process.env.CONFIG_FILE;
    const ROOT = process.env.VCI_KEY_TEST_ROOT;
    const realms = require(ROOT + '/common/realms');
    const stsCrypto = require(ROOT + '/common/crypto');
    const issuer = require(ROOT + '/oid4vc/vc_issuer');
    const a = realms.create({ id: 'vci-issuer-a', name: 'a' }).realm;
    const b = realms.create({ id: 'vci-issuer-b', name: 'b' }).realm;
    const pubA = realms.run(a, function () {
      return issuer.credentialRequestEncryptionMetadata().jwks.keys[0];
    });
    const pubB = realms.run(b, function () {
      return issuer.credentialRequestEncryptionMetadata().jwks.keys[0];
    });
    note(pubA && pubB && pubA.kid !== pubB.kid,
         'the issuer metadata of two realms publishes two keys in ' +
         'credential_request_encryption.jwks',
         (pubA && pubA.kid) + ' / ' + (pubB && pubB.kid));
    const compact = stsCrypto.encryptJweCompact(JSON.stringify(
        { credential_identifier: 'x' }), {
      alg: 'RSA-OAEP-256', enc: 'A256GCM', jwk: pubA });
    let inA = null;
    try {
      inA = realms.run(a,
                       function () {
                         return issuer.decryptJweRequest(compact);
                       });
    } catch (e) {
      inA = { error: e.message };
    }
    note(inA && inA.credential_identifier === 'x',
         'realm A\'s issuer decrypts a Credential Request encrypted to realm ' +
         'A\'s published key',
         JSON.stringify(inA));
    let inB = '';
    try {
      realms.run(b, function () { return issuer.decryptJweRequest(compact); });
    } catch (e) {
      inB = e.message;
    }
    note(inB !== '',
         'REALM B\'S ISSUER REFUSES THE SAME JWE — the defect this closes',
         inB);
    const forged = stsCrypto.encryptJweCompact('{"credential_identifier":"y"}',
                                               {
      alg: 'RSA-OAEP-256', enc: 'A256GCM',
      jwk: Object.assign({}, pubA, { kid: pubB.kid }) });
    let forgedInB = '';
    try {
      realms.run(b, function () { return issuer.decryptJweRequest(forged); });
    } catch (e) {
      forgedInB = e.message;
    }
    note(forgedInB !== '' && !/kid/.test(forgedInB),
         'and refuses it with B\'s kid forged on, at the unwrap', forgedInB);

    // THE LAST-REQUEST RECORD IS THE REALM'S OWN.
    const fakeReq = function (body, type) {
      return { path: '/oid4vci/credential', body: body,
               get: function (name) {
                 return /content-type/i.test(name) ? type : '';
               } };
    };
    realms.run(a, function () {
      return issuer.readPossiblyEncryptedRequest(
          fakeReq(compact, 'application/jwt'));
    });
    const lastA = realms.run(a,
                             function () {
                               return issuer.lastCredentialRequest();
                             });
    const lastB = realms.run(b,
                             function () {
                               return issuer.lastCredentialRequest();
                             });
    const lastDefault = issuer.lastCredentialRequest();
    note(lastA.seen === true && lastA.encrypted === true &&
         lastA.kid === pubA.kid,
         '/oid4vci/last_request in realm A reports the encrypted request it ' +
         'received',
         JSON.stringify(lastA));
    note(lastB.seen === false && lastDefault.seen === false,
         'AND NEITHER REALM B NOR THE DEFAULT REALM REPORTS IT — it was one ' +
         '`let` for the process',
         JSON.stringify({ b: lastB, default: lastDefault }));
  } catch (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function checkIssuer(t) {
  log.debug("Entering checkIssuer().");
  t.log.info('=== the issuer, in a child process ===');
  const out = path.join(os.tmpdir(),
                        'sts-vci-key-' + process.pid + '-' + Date.now() +
                        '.json');
  const env = Object.assign({}, process.env, {
    VCI_KEY_TEST_OUT: out, VCI_KEY_TEST_ROOT: ROOT, LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      cwd: ROOT, env: env, encoding: 'utf8', timeout: 120000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in checkIssuer(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and the tail of what it printed.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    t.log.debug('could not remove ' + out + ': ' + e.message);
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'status=' + result.status + ' ' +
               String(result.stderr || '').slice(-2000))) {
    log.debug("Leaving checkIssuer().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving checkIssuer().");
}

async function run(t) {
  log.debug("Entering run().");
  checkPerRealm(t);
  checkChannel(t);
  await checkStore(t);
  checkEnrichment(t);
  checkSource(t);
  checkIssuer(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vci_request_encryption_key',
  describe: 'the OpenID4VCI request-encryption key is a per-realm member of ' +
            'the key set',
  run: run
};
