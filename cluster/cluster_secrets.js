'use strict';
//
// File: cluster/cluster_secrets.js
//
// ===========================================================================
// THE SECRETS EVERY NODE MUST AGREE ON (2026-09-14, #46).
//
// Three keys in this service were generated per process or per run: the CSRF
// key a form's token is MACed with, the key ACME's Replay-Nonce is MACed with,
// and the SSF receiver's secret. (The DPoP server nonce, which #46 lists beside
// them, is not a key: it is a persisted store of issued nonces, and the read
// barrier is what makes a nonce issued on one node current on the next.) Per process
// that is fine and per container it is a service that refuses its own forms: a
// form drawn by node A and posted to node B carries a token B cannot verify, and
// without sticky sessions that is (N-1)/N of every console form. It never
// converges, because nothing is wrong with either copy.
//
// So each is DECLARED here, generated once for the whole store, and read by
// every process before it serves: `start()` offers a fresh value, the store
// keeps the first offer it ever received (`ensureSharedSecret()`,
// `INSERT … ON CONFLICT DO NOTHING`), and every process uses what the store
// kept. `get(name)` is synchronous and answers the shared value once started,
// and a per-process random value before — which is what a store that cannot
// share (memory, ldif) keeps for ever, and is correct for exactly the reason it
// was correct before: there is only one process to agree with.
//
// ---------------------------------------------------------------------------
// WHY THE STORE AND NOT THE KEY-ENCRYPTION KEY OR OPENBAO.
//
// The review on #46 raised both. Deriving these from the KEK with HKDF would
// rotate every one of them — and invalidate every outstanding form and nonce —
// whenever the KEK is rotated, unless a version and an overlap were designed
// in. A separate secret in OpenBao is a second thing an operator has to
// provision per deployment. A row SEALED under the KEK is neither: rotating the
// KEK re-seals it and leaves its value alone, and there is nothing to
// provision, because the first node to start makes it. The seal is the same
// AES-256-GCM `sts_keys` uses.
//
// **AN ENVIRONMENT VARIABLE STILL WINS** (`STS_CSRF_SECRET`,
// `STS_ACME_NONCE_SECRET`, `STS_SSF_RECEIVER_SECRET`, `STS_BBS_KEYPAIR`): an
// operator who set one has set it on every node, and that is agreement by
// configuration.
//
// **A FOURTH SINCE 2026-09-14 IS A KEY PAIR, NOT RANDOM BYTES** — the BBS pair
// — and its offer is made by an asynchronous `generate` on its row. Its
// argument is at the row in `DECLARED`.
//
// A LIBRARY (rule 3). `start()` is called from `common/service_state.js` after
// the keystore opens; `persistence.js` is required lazily.
// ===========================================================================

const bunyan = require('bunyan');
const nodeCrypto = require('crypto');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const capabilities = require('./cluster_capabilities');

const log = bunyan.createLogger({ name: 'sts-cluster-secrets' });
config.registerLogger(log);

// name -> { bytes, what, env }. Adding a secret here is what makes it shared;
// a module asking `get()` for a name that is not here is a programming error.
//
// `env`, where there is one, is BOTH an operator's way to set the value and the
// channel a front process hands it to its own request workers through: they are
// forked with `Object.assign({}, process.env, …)`, so whatever is in the
// variable when `request_pool.js` forks is what every worker holds. That is the
// arrangement `acme/acme_jws.js` and `ssf/ssf_receivers.js` already had for one
// container; this module only changes WHERE the front process's value comes
// from.
const DECLARED = {
  'csrf': { bytes: 32, env: 'STS_CSRF_SECRET',
    what: 'The key a form\'s CSRF token is MACed with (common/websecurity.js).' },
  'acme-nonce': { bytes: 32, env: 'STS_ACME_NONCE_SECRET',
    what: 'The key ACME\'s Replay-Nonce values are MACed with ' +
          '(acme/acme_jws.js).' },
  'ssf-receiver': { bytes: 32, env: 'STS_SSF_RECEIVER_SECRET',
    what: 'The secret the console\'s and the portal\'s own SSF receivers ' +
          'authenticate pushes with (ssf/ssf_receivers.js).' },
  // -------------------------------------------------------------------------
  // THE BBS KEY PAIR (2026-09-14, #46 section 1) — A SECRET WHOSE OFFER IS
  // MADE BY A GENERATOR RATHER THAN BY `randomBytes()`.
  //
  // It is the key a bbs-2023 Data Integrity proof is signed with and the key
  // `/bbs/keys/1` and the did:web document PUBLISH. `common/helpers.js` made
  // one per process and shared it only with its own request workers, through
  // this same variable, so two nodes behind one balancer each published a
  // different `publicKeyMultibase`: a credential issued through node A and
  // resolved through node B did not verify — `ldp_vc_issuance`,
  // `ldp_vc_refresh` and `vc_did`, in the suite's `cluster` mode.
  //
  // **HERE AND NOT IN THE KEYSTORE'S SEALED ROWS**, and the smaller design is
  // also the correct one. `sts_keys` is a REALM's key set — keyed by realm,
  // enriched member by member, backfilled, rotated, certified by the PKI —
  // and this pair is one per SERVICE and none of those things: it is never
  // rotated, never certified and never per realm (`helpers.js` said as much
  // when it kept it off the keystore's shared channel). What it needs is
  // exactly what this table already gives the CSRF key: made once for the
  // store, sealed under the KEK, first writer wins, read before serving, and
  // handed to the request workers in the environment variable they already
  // read. The only thing it lacks is a synchronous way to be made, which is
  // `generate`.
  //
  // **A SECRET WITH A GENERATOR IS NEVER MADE PER PROCESS HERE.** Where
  // nothing is shared (memory, ldif, no KEK, an ephemeral KEK) `text()`
  // answers '' and `helpers.bbsKeyPair()` makes its own, asynchronously,
  // exactly as it did before this row existed — so a single process and a
  // single container behave as they always have.
  'bbs-keypair': { env: 'STS_BBS_KEYPAIR',
    generate: function () {
      // LAZILY: helpers.js is loaded long before start() runs, and a require
      // at the top of this library would drag the whole of it into every
      // module that only wants the CSRF key.
      return require('../common/helpers').newBbsKeyPairText();
    },
    what: 'The BBS key pair bbs-2023 Data Integrity proofs are signed with ' +
          'and /bbs/keys/1 and the did:web document publish ' +
          '(common/helpers.js).' }
};

// Is this secret one a GENERATOR makes (asynchronously), rather than random
// bytes? Such a secret has no per-process value in this module.
function generated(name) {
  log.debug("Entering generated(). name=" + name);
  log.debug("Leaving generated().");
  return !!(DECLARED[name] && typeof DECLARED[name].generate === 'function');
}

// name -> { text, source: 'process'|'store'|'environment'|'node' }. The TEXT is
// the secret — callers that derive with it use the string, as they always did,
// and `get()` hands out its bytes for a caller that wants a key.
const values = new Map();
// Names whose environment variable THIS process wrote, so start() can tell its
// own per-process value from one an operator set.
const generatedHere = new Set();
let started = false;

function isWorker() {
  log.debug("Entering isWorker().");
  log.debug("Leaving isWorker().");
  return !!process.env.STS_REQUEST_WORKER;
}

function processValue(name) {
  log.debug("Entering processValue(). name=" + name);
  const declared = DECLARED[name];
  if (!declared) {
    log.debug("Leaving processValue(). Undeclared.");
    throw new Error('cluster_secrets: "' + name + '" is not a declared ' +
                    'shared secret; add it to DECLARED.');
  }
  if (process.env[declared.env]) {
    const held = { text: String(process.env[declared.env]),
                   source: isWorker() ? 'node' : 'environment' };
    values.set(name, held);
    log.debug("Leaving processValue(). From the environment.");
    return held;
  }
  if (generated(name)) {
    // NOTHING TO MAKE SYNCHRONOUSLY, and nothing recorded: the owner makes its
    // own where nothing is shared, and a later start() or a variable an
    // operator sets is read on the next call.
    log.debug("Leaving processValue(). Made by its owner, not here.");
    return { text: '', source: 'process' };
  }
  const fresh = { text: nodeCrypto.randomBytes(declared.bytes)
                    .toString('base64'), source: 'process' };
  // INTO THE ENVIRONMENT, so a worker forked from here inherits it — the
  // per-container agreement that existed before this module.
  process.env[declared.env] = fresh.text;
  generatedHere.add(name);
  values.set(name, fresh);
  log.debug("Leaving processValue(). Generated for this process.");
  return fresh;
}

// THE SECRET'S TEXT, synchronously. See the header for what it is before
// start().
function text(name) {
  log.debug("Entering text(). name=" + name);
  const held = values.get(name) || processValue(name);
  log.debug("Leaving text().");
  return held.text;
}

// THE SECRET AS KEY BYTES.
function get(name) {
  log.debug("Entering get(). name=" + name);
  log.debug("Leaving get().");
  return Buffer.from(text(name), 'utf8');
}

// Where a secret's value came from, for /admin/cluster. Never the value.
function describe() {
  log.debug("Entering describe().");
  const out = Object.keys(DECLARED).map(function (name) {
    const held = values.get(name);
    return { name: name, what: DECLARED[name].what,
             source: held ? held.source : 'not yet used' };
  });
  log.debug("Leaving describe().");
  return { started: started, secrets: out };
}

// Every declared secret made NOW, in a process that shares none of them, so the
// request workers it forks next inherit one value per container rather than
// each making its own on first use.
function seedProcessValues() {
  log.debug("Entering seedProcessValues().");
  Object.keys(DECLARED).forEach(function (name) {
    if (!values.has(name) && !generated(name)) {
      processValue(name);
    }
  });
  log.debug("Leaving seedProcessValues().");
}

// ---------------------------------------------------------------------------
// STARTING. Reads (or, first, writes) every declared secret. A store that
// cannot share leaves every value per process. A failure on a store that CAN
// share is fatal: a node that serves with its own CSRF key is a node that
// refuses every other node's forms, and that is the failure this module exists
// to remove.
// ---------------------------------------------------------------------------
function start(keystore) {
  log.debug("Entering start().");
  // A WORKER HOLDS WHAT ITS FRONT PROCESS PUT IN THE ENVIRONMENT, which that
  // process read from the store before it forked anything. Asking again could
  // only agree.
  if (isWorker()) {
    Object.keys(DECLARED).forEach(function (name) {
      processValue(name);
    });
    started = true;
    log.debug("Leaving start(). A worker inherits.");
    return Promise.resolve({ shared: false, inherited: true });
  }
  const persistence = require('../persistence/persistence');
  const theStore = persistence.clusterStore();
  if (!theStore || typeof theStore.ensureSharedSecret !== 'function') {
    seedProcessValues();
    started = true;
    log.debug("Leaving start(). No store to share through.");
    return Promise.resolve({ shared: false });
  }
  // NO KEY-ENCRYPTION KEY, NO SHARING — and that is correct everywhere except
  // active-active. A development service on postgres with one process has
  // nobody to agree with; a dispatched one has an ephemeral KEK its workers
  // share; and active-active cannot start without an operator's KEK at all
  // (cluster.js refuses it), so reaching this line there is a fault.
  // AN EPHEMERAL KEK IS TREATED AS NONE: it changes at every restart, so a row
  // sealed under the last run's would not open under this one's — and the
  // processes it is shared between are one container's, which agree already.
  if (!keystore || !keystore.sealed() ||
      (typeof keystore.hasEphemeralKek === 'function' &&
       keystore.hasEphemeralKek())) {
    const cluster = require('./cluster');
    if (cluster.isActiveActive()) {
      log.debug("Leaving start(). Active-active without a KEK.");
      return Promise.reject(new Error(errorCodes.tag('STS-CLUSTER-0017') +
        'cluster secrets: active-active mode and no key-encryption key is ' +
        'open to seal the shared secrets with.'));
    }
    seedProcessValues();
    started = true;
    log.debug("Leaving start(). No key-encryption key; per process.");
    return Promise.resolve({ shared: false });
  }
  // AN OPERATOR'S VARIABLE WINS: they set it on every node, which is agreement
  // by configuration. One this process wrote itself does not.
  const names = Object.keys(DECLARED).filter(function (name) {
    const env = DECLARED[name].env;
    if (process.env[env] && !generatedHere.has(name)) {
      processValue(name);
      return false;
    }
    return true;
  });
  let chain = Promise.resolve();
  names.forEach(function (name) {
    chain = chain.then(function () {
      // A GENERATED SECRET'S OFFER IS MADE BEFORE IT IS KNOWN WHETHER IT WILL
      // WIN, which for the BBS pair is a few milliseconds of key generation
      // thrown away by every node but the first. Asking the store first and
      // offering only when it is empty would be a second round trip on every
      // start to save that, and the two-step would still have to handle the
      // race the single INSERT … ON CONFLICT already decides.
      if (generated(name)) {
        return Promise.resolve(DECLARED[name].generate());
      }
      return nodeCrypto.randomBytes(DECLARED[name].bytes).toString('base64');
    }).then(function (offer) {
      if (!offer) {
        throw new Error(errorCodes.tag('STS-CLUSTER-0016') + 'cluster ' +
          'secrets: the "' + name + '" secret\'s generator made nothing to ' +
          'offer.');
      }
      const sealed = keystore.seal(String(offer), 'cluster-secret');
      if (!sealed) {
        throw new Error(errorCodes.tag('STS-CLUSTER-0017') + 'cluster ' +
          'secrets: the "' + name + '" secret could not be sealed, and a ' +
          'shared secret is never written to the store in the clear.');
      }
      return theStore.ensureSharedSecret(name, sealed).then(function (row) {
        if (!row) {
          throw new Error(errorCodes.tag('STS-CLUSTER-0016') + 'cluster ' +
            'secrets: the "' + name + '" secret was not in the store after ' +
            'it was offered.');
        }
        const opened = keystore.open(row.material, 'cluster-secret');
        if (!opened) {
          throw new Error(errorCodes.tag('STS-CLUSTER-0017') + 'cluster ' +
            'secrets: the stored "' + name + '" secret would not open under ' +
            'this node\'s key-encryption key. Every node against one store ' +
            'must hold the same one.');
        }
        values.set(name, { text: String(opened), source: 'store' });
        // AND INTO THE ENVIRONMENT, replacing this process's own value, so
        // the request workers forked after this inherit the shared one.
        process.env[DECLARED[name].env] = String(opened);
        generatedHere.delete(name);
      });
    });
  });
  log.debug("Leaving start().");
  return chain.then(function () {
    started = true;
    log.info('cluster secrets: ' + names.length + ' secret(s) are shared ' +
             'through the store: ' + names.join(', ') + '.');
    return { shared: true, names: names };
  }, function (err) {
    if (/STS-CLUSTER-\d{4}/.test(err.message)) {
      throw err;
    }
    throw new Error(errorCodes.tag('STS-CLUSTER-0016') + 'cluster secrets: ' +
                    'the shared secrets could not be read: ' + err.message);
  });
}

// For tests: forgets every value and every variable this module wrote.
function reset() {
  log.debug("Entering reset().");
  generatedHere.forEach(function (name) {
    delete process.env[DECLARED[name].env];
  });
  values.clear();
  generatedHere.clear();
  started = false;
  log.debug("Leaving reset().");
}

// At require time; see cluster.js's note on why a capability is the code.
capabilities.provide('cluster.shared-secrets');
// THE BBS PAIR'S ROW IN `DECLARED` is the fix for `vc.keys-agreement`: every
// node reads the one pair the store kept before it serves, and hands it to its
// request workers in `STS_BBS_KEYPAIR`, which `helpers.bbsKeyPair()` adopts.
capabilities.provide('vc.keys-agreement');

module.exports = {
  DECLARED: DECLARED,
  get: get,
  text: text,
  describe: describe,
  start: start,
  reset: reset
};
