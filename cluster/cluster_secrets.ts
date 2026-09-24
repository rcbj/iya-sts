'use strict';
//
// File: cluster/cluster_secrets.ts
//
// ===========================================================================
// THE SECRETS EVERY NODE MUST AGREE ON (2026-09-14, #46).
//
// Three keys in this service were generated per process or per run: the CSRF
// key a form's token is MACed with, the key ACME's Replay-Nonce is MACed with,
// and the SSF receiver's secret. (The DPoP server nonce, which #46 lists beside
// them, is not a key: it is a persisted store of issued nonces, and the read
// barrier is what makes a nonce issued on one node current on the next.) Per
// process that is fine and per container it is a service that refuses its own
// forms: a form drawn by node A and posted to node B carries a token B cannot
// verify, and without sticky sessions that is (N-1)/N of every console form.
// It never converges, because nothing is wrong with either copy.
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
// `STS_ACME_NONCE_SECRET`, `STS_SSF_RECEIVER_SECRET`): an
// operator who set one has set it on every node, and that is agreement by
// configuration.
//
// **A SECRET MAY HAVE A GENERATOR** (an asynchronous `generate` on its row)
// rather than random bytes. The BBS pair was the one that did, from
// 2026-09-14 until 2026-09-22, when it became a member of each realm's key
// set (#49 P5, `common/helpers.js`) so that it could rotate.
//
// A LIBRARY (rule 3). `start()` is called from `common/service_state.ts` after
// the keystore opens; `persistence.js` is required lazily.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ClusterSecrets` takes its logger, the error-code table, the
// environment, a random-bytes source and three LAZY loaders (the persistence
// store, `cluster.js`) through its constructor. `DECLARED` and the two
// process-wide collections (`values`, `generatedHere`) stay module-scope
// declarations, and the two `capabilities.provide()` calls still run at
// require time, before the exports are assigned. The module still exports
// `DECLARED`, `get`, `text`, `describe`, `start` and `reset`, for the
// unconverted modules that require it. Since #50's R2 the composition root
// builds the instance (`ClusterSecrets.defaultDeps()`) and installs it; the
// module's old export names are FACADES that forward to it, for the JavaScript
// callers, and a process without the root builds a default when this module
// finishes loading.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import nodeCrypto = require('crypto');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import capabilities = require('./cluster_capabilities');
import InstanceSlot = require('../common/instance_slot');

const log = bunyan.createLogger({ name: 'sts-cluster-secrets' });
config.registerLogger(log);

// One declared secret. `bytes` for random bytes, `generate` for a secret a
// generator makes (asynchronously).
interface DeclaredSecret {
  bytes?: number;
  env: string;
  what: string;
  generate?: () => unknown;
}

// What this process holds for a secret. `source` is one of 'process',
// 'store', 'environment' and 'node'.
interface HeldSecret {
  text: string;
  source: string;
}

// The parts of the keystore `start()` uses.
interface SecretsKeystore {
  sealed(): boolean;
  hasEphemeralKek?: () => boolean;
  seal(text: string, purpose: string): unknown;
  open(material: unknown, purpose: string): unknown;
}

// The parts of the persistence store `start()` uses.
interface SharedSecretStore {
  ensureSharedSecret?: (name: string,
                        sealed: unknown) => Promise<{ material: unknown }>;
}

interface ClusterSecretsDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
  };
  errorCodes: { tag(code: string): string };
  env: NodeJS.ProcessEnv;
  randomBytes(size: number): Buffer;
  // LAZY, as the requires were: see `start()`.
  clusterStore(): SharedSecretStore | null | undefined;
  isActiveActive(): boolean;
}

// name -> { bytes, what, env }. Adding a secret here is what makes it shared;
// a module asking `get()` for a name that is not here is a programming error.
//
// `env`, where there is one, is BOTH an operator's way to set the value and the
// channel a front process hands it to its own request workers through: they
// are forked with `Object.assign({}, process.env, …)`, so whatever is in the
// variable when `request_pool.js` forks is what every worker holds. That is
// the arrangement `acme/acme_jws.ts` and `ssf/ssf_receivers.ts` already had
// for one container; this module only changes WHERE the front process's value
// comes from.
const DECLARED: Record<string, DeclaredSecret> = {
  'csrf': { bytes: 32, env: 'STS_CSRF_SECRET',
    what: 'The key a form\'s CSRF token is MACed with ' +
          '(common/websecurity.ts).' },
  'acme-nonce': { bytes: 32, env: 'STS_ACME_NONCE_SECRET',
    what: 'The key ACME\'s Replay-Nonce values are MACed with ' +
          '(acme/acme_jws.ts).' },
  'ssf-receiver': { bytes: 32, env: 'STS_SSF_RECEIVER_SECRET',
    what: 'The secret the console\'s and the portal\'s own SSF receivers ' +
          'authenticate pushes with (ssf/ssf_receivers.ts).' },
  // #118: a pairwise `sub` must be the same on every node and across
  // restarts, or a client would see one person as several.
  'oidc-pairwise': { bytes: 32, env: 'STS_OIDC_PAIRWISE_SECRET',
    what: 'The key an OpenID Connect pairwise subject identifier is derived ' +
          'with (oauth-oidc/pairwise_subjects.ts, OIDC Core section 8.1).' },
  // #135, #136: a page drawn by one node is continued on another, so the
  // pointer its `next` carries must verify on every node.
  'oidfed-page': { bytes: 32, env: 'STS_OIDFED_PAGE_SECRET',
    what: 'The key an OpenID Federation listing\'s or collection\'s page ' +
          'pointer is MACed with (oidfed/page_pointer.ts).' }
};

// name -> { text, source: 'process'|'store'|'environment'|'node' }. The TEXT is
// the secret — callers that derive with it use the string, as they always did,
// and `get()` hands out its bytes for a caller that wants a key.
const values: Map<string, HeldSecret> = new Map();
// Names whose environment variable THIS process wrote, so start() can tell its
// own per-process value from one an operator set.
const generatedHere: Set<string> = new Set();

class ClusterSecrets {
  static readonly DECLARED = DECLARED;

  private started = false;

  constructor(private readonly deps: ClusterSecretsDeps) {
    deps.log.debug("Entering ClusterSecrets.constructor().");
    deps.log.debug("Leaving ClusterSecrets.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): ClusterSecretsDeps {
    log.debug("Entering ClusterSecrets.defaultDeps().");
    log.debug("Leaving ClusterSecrets.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      env: process.env,
      randomBytes: nodeCrypto.randomBytes,
      clusterStore: ClusterSecrets.persistenceClusterStore,
      isActiveActive: ClusterSecrets.clusterIsActiveActive
    };
  }

  // The persistence store to share through, required LAZILY: the default
  // `clusterStore` in `defaultDeps()`.
  static persistenceClusterStore(): SharedSecretStore | null | undefined {
    log.debug("Entering ClusterSecrets.persistenceClusterStore().");
    const persistence = require('../persistence/persistence');
    log.debug("Leaving ClusterSecrets.persistenceClusterStore().");
    return persistence.clusterStore();
  }

  // Is this node active-active? `cluster.js` is required LAZILY, as it was.
  static clusterIsActiveActive(): boolean {
    log.debug("Entering ClusterSecrets.clusterIsActiveActive().");
    const cluster = require('./cluster');
    log.debug("Leaving ClusterSecrets.clusterIsActiveActive().");
    return cluster.isActiveActive();
  }

  // Is this secret one a GENERATOR makes (asynchronously), rather than random
  // bytes? Such a secret has no per-process value in this module.
  private generated(name: string): boolean {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.generated(). name=" + name);
    log.debug("Leaving ClusterSecrets.generated().");
    return !!(DECLARED[name] &&
              typeof DECLARED[name].generate === 'function');
  }

  private isWorker(): boolean {
    const { log, env } = this.deps;
    log.debug("Entering ClusterSecrets.isWorker().");
    log.debug("Leaving ClusterSecrets.isWorker().");
    return !!env.STS_REQUEST_WORKER;
  }

  private processValue(name: string): HeldSecret {
    const { log, env, randomBytes } = this.deps;
    log.debug("Entering ClusterSecrets.processValue(). name=" + name);
    const declared = DECLARED[name];
    if (!declared) {
      log.debug("Leaving ClusterSecrets.processValue(). Undeclared.");
      throw new Error('cluster_secrets: "' + name + '" is not a declared ' +
                      'shared secret; add it to DECLARED.');
    }
    if (env[declared.env]) {
      const held = { text: String(env[declared.env]),
                     source: this.isWorker() ? 'node' : 'environment' };
      values.set(name, held);
      log.debug("Leaving ClusterSecrets.processValue(). From the " +
                "environment.");
      return held;
    }
    if (this.generated(name)) {
      // NOTHING TO MAKE SYNCHRONOUSLY, and nothing recorded: the owner makes
      // its own where nothing is shared, and a later start() or a variable an
      // operator sets is read on the next call.
      log.debug("Leaving ClusterSecrets.processValue(). Made by its owner, " +
                "not here.");
      return { text: '', source: 'process' };
    }
    const fresh = { text: randomBytes(declared.bytes)
                      .toString('base64'), source: 'process' };
    // INTO THE ENVIRONMENT, so a worker forked from here inherits it — the
    // per-container agreement that existed before this module.
    env[declared.env] = fresh.text;
    generatedHere.add(name);
    values.set(name, fresh);
    log.debug("Leaving ClusterSecrets.processValue(). Generated for this " +
              "process.");
    return fresh;
  }

  // THE SECRET'S TEXT, synchronously. See the header for what it is before
  // start().
  text(name: string): string {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.text(). name=" + name);
    const held = values.get(name) || this.processValue(name);
    log.debug("Leaving ClusterSecrets.text().");
    return held.text;
  }

  // THE SECRET AS KEY BYTES.
  get(name: string): Buffer {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.get(). name=" + name);
    log.debug("Leaving ClusterSecrets.get().");
    return Buffer.from(this.text(name), 'utf8');
  }

  // Where a secret's value came from, for /admin/cluster. Never the value.
  describe(): { started: boolean;
                secrets: { name: string; what: string; source: string }[] } {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.describe().");
    const out = Object.keys(DECLARED).map(function (name) {
      const held = values.get(name);
      return { name: name, what: DECLARED[name].what,
               source: held ? held.source : 'not yet used' };
    });
    log.debug("Leaving ClusterSecrets.describe().");
    return { started: this.started, secrets: out };
  }

  // Every declared secret made NOW, in a process that shares none of them, so
  // the request workers it forks next inherit one value per container rather
  // than each making its own on first use.
  private seedProcessValues(): void {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.seedProcessValues().");
    Object.keys(DECLARED).forEach((name) => {
      if (!values.has(name) && !this.generated(name)) {
        this.processValue(name);
      }
    });
    log.debug("Leaving ClusterSecrets.seedProcessValues().");
  }

  // -------------------------------------------------------------------------
  // STARTING. Reads (or, first, writes) every declared secret. A store that
  // cannot share leaves every value per process. A failure on a store that
  // CAN share is fatal: a node that serves with its own CSRF key is a node
  // that refuses every other node's forms, and that is the failure this module
  // exists to remove.
  // -------------------------------------------------------------------------
  start(keystore?: SecretsKeystore | null): Promise<any> {
    const { log, errorCodes, env, randomBytes } = this.deps;
    log.debug("Entering ClusterSecrets.start().");
    // A WORKER HOLDS WHAT ITS FRONT PROCESS PUT IN THE ENVIRONMENT, which that
    // process read from the store before it forked anything. Asking again
    // could only agree.
    if (this.isWorker()) {
      Object.keys(DECLARED).forEach((name) => {
        this.processValue(name);
      });
      this.started = true;
      log.debug("Leaving ClusterSecrets.start(). A worker inherits.");
      return Promise.resolve({ shared: false, inherited: true });
    }
    const theStore = this.deps.clusterStore();
    if (!theStore || typeof theStore.ensureSharedSecret !== 'function') {
      this.seedProcessValues();
      this.started = true;
      log.debug("Leaving ClusterSecrets.start(). No store to share through.");
      return Promise.resolve({ shared: false });
    }
    // NO KEY-ENCRYPTION KEY, NO SHARING — and that is correct everywhere
    // except active-active. A development service on postgres with one
    // process has nobody to agree with; a dispatched one has an ephemeral KEK
    // its workers share; and active-active cannot start without an operator's
    // KEK at all (cluster.js refuses it), so reaching this line there is a
    // fault.
    // AN EPHEMERAL KEK IS TREATED AS NONE: it changes at every restart, so a
    // row sealed under the last run's would not open under this one's — and
    // the processes it is shared between are one container's, which agree
    // already.
    if (!keystore || !keystore.sealed() ||
        (typeof keystore.hasEphemeralKek === 'function' &&
         keystore.hasEphemeralKek())) {
      if (this.deps.isActiveActive()) {
        log.debug("Leaving ClusterSecrets.start(). Active-active without a " +
                  "KEK.");
        return Promise.reject(new Error(errorCodes.tag('STS-CLUSTER-0017') +
          'cluster secrets: active-active mode and no key-encryption key is ' +
          'open to seal the shared secrets with.'));
      }
      this.seedProcessValues();
      this.started = true;
      log.debug("Leaving ClusterSecrets.start(). No key-encryption key; per " +
                "process.");
      return Promise.resolve({ shared: false });
    }
    // AN OPERATOR'S VARIABLE WINS: they set it on every node, which is
    // agreement by configuration. One this process wrote itself does not.
    const names = Object.keys(DECLARED).filter((name) => {
      const envName = DECLARED[name].env;
      if (env[envName] && !generatedHere.has(name)) {
        this.processValue(name);
        return false;
      }
      return true;
    });
    let chain: Promise<unknown> = Promise.resolve();
    names.forEach((name) => {
      chain = chain.then(() => {
        // A GENERATED SECRET'S OFFER IS MADE BEFORE IT IS KNOWN WHETHER IT
        // WILL WIN, which for the BBS pair is a few milliseconds of key
        // generation thrown away by every node but the first. Asking the store
        // first and offering only when it is empty would be a second round
        // trip on every start to save that, and the two-step would still have
        // to handle the race the single INSERT … ON CONFLICT already decides.
        if (this.generated(name)) {
          return Promise.resolve(DECLARED[name].generate());
        }
        return randomBytes(DECLARED[name].bytes).toString('base64');
      }).then(function (offer) {
        if (!offer) {
          throw new Error(errorCodes.tag('STS-CLUSTER-0016') + 'cluster ' +
            'secrets: the "' + name + '" secret\'s generator made nothing ' +
            'to offer.');
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
              'secrets: the "' + name + '" secret was not in the store ' +
              'after it was offered.');
          }
          const opened = keystore.open(row.material, 'cluster-secret');
          if (!opened) {
            throw new Error(errorCodes.tag('STS-CLUSTER-0017') + 'cluster ' +
              'secrets: the stored "' + name + '" secret would not open ' +
              'under this node\'s key-encryption key. Every node against ' +
              'one store must hold the same one.');
          }
          values.set(name, { text: String(opened), source: 'store' });
          // AND INTO THE ENVIRONMENT, replacing this process's own value, so
          // the request workers forked after this inherit the shared one.
          env[DECLARED[name].env] = String(opened);
          generatedHere.delete(name);
        });
      });
    });
    log.debug("Leaving ClusterSecrets.start().");
    return chain.then(() => {
      this.started = true;
      log.info('cluster secrets: ' + names.length + ' secret(s) are shared ' +
               'through the store: ' + names.join(', ') + '.');
      return { shared: true, names: names };
    }, function (err) {
      if (/STS-CLUSTER-\d{4}/.test(err.message)) {
        throw err;
      }
      throw new Error(errorCodes.tag('STS-CLUSTER-0016') + 'cluster ' +
                      'secrets: the shared secrets could not be read: ' +
                      err.message);
    });
  }

  // For tests: forgets every value and every variable this module wrote.
  reset(): void {
    const { log, env } = this.deps;
    log.debug("Entering ClusterSecrets.reset().");
    generatedHere.forEach(function (name) {
      delete env[DECLARED[name].env];
    });
    values.clear();
    generatedHere.clear();
    this.started = false;
    log.debug("Leaving ClusterSecrets.reset().");
  }
}

// At require time; see cluster.js's note on why a capability is the code.
capabilities.provide('cluster.shared-secrets');
// `vc.keys-agreement`: every node signs and publishes the same BBS key. It
// was a row in `DECLARED` here until 2026-09-22 (#49 P5); the BBS key is a
// member of each realm's key set now (`common/helpers.js`), agreed across
// nodes and processes the way every member is — the store's first writer and
// the sibling channel's enrichment rule — which is what this still stands for.
capabilities.provide('vc.keys-agreement');

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ClusterSecrets>(
  'cluster/cluster_secrets',
  () => new ClusterSecrets(ClusterSecrets.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  ClusterSecrets: ClusterSecrets,
  installInstance: (instance: ClusterSecrets): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  DECLARED: ClusterSecrets.DECLARED,
  get: slot.forward('get'),
  text: slot.forward('text'),
  describe: slot.forward('describe'),
  start: slot.forward('start'),
  reset: slot.forward('reset')
};
