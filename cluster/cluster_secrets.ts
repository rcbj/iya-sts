// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//
// ---------------------------------------------------------------------------
// ROTATION, WITH AN OVERLAP (2026-11-25, #2220 D).
//
// "Made once and never changed" was the gap ASVS 5.0.0 13.3.4 names. Each
// stored KEY now rotates, and nothing it MACed stops verifying while it can
// still be presented:
//
//   * THE STORED VALUE IS AN ENVELOPE once it has been rotated (or merely
//     dated): `{"v":2,"current","next","nextAt","previous","previousUntil",
//     "rotatedAt"}`, sealed exactly as the bare value was. A value that is
//     not one is the bare text every earlier build wrote, read as `current`
//     with no date — so nothing written before this is unreadable. An older
//     node reading an envelope would use the envelope's text as its key, so
//     a rolling upgrade must finish before the first rotation is due, which
//     the no-mass-rotation rule below makes `cluster.secretRotationDays`.
//   * TWO STEPS, NEXT AND THEN CURRENT (`cluster.secret-rotate`, a cluster
//     job). A due rotation first PUBLISHES a next value, which every process
//     accepts and none MACs with; only once it has been published for
//     ACTIVATION_LEAD_MS — forty times the per-process refresh below — is it
//     PROMOTED, and the old current becomes `previous` until
//     `cluster.secretOverlapS` has passed. So no process ever meets a MAC
//     under a value it has not yet heard of, and nothing made under the old
//     one is refused inside the overlap.
//   * EVERY PROCESS RE-READS (`cluster.secret-refresh`, per process, every
//     REFRESH_MS), because a node and its request workers read the store at
//     start only; a worker is also handed the envelope by its front process
//     through `STS_CLUSTER_SECRET_STATE` when it is forked.
//   * `text()` / `get()` ARE THE CURRENT VALUE, unchanged for every caller;
//     a VERIFIER asks `texts()` / `keys()` — current, next, and previous
//     inside its overlap — and accepts a MAC under any of them.
//   * NO MASS ROTATION AFTER AN UPGRADE: a bare value has no date, and the
//     job's first sight of one only DATES it (`rotatedAt` now, the value
//     unchanged), so the first real rotation is `cluster.secretRotationDays`
//     after the upgrade, not at it.
//
// **TWO SECRETS ARE IDENTIFIERS, NOT KEYS, AND NEVER ROTATE** (`identifier`
// on the row). `oidc-pairwise` derives every pairwise `sub` (OIDC Core
// section 8.1), the device identifiers and GNAP's opaque subject ids:
// rotating it would make every person a new person to every pairwise client.
// `bootstrap-name` derives the generated bootstrap administrator's name,
// which was the CSRF key's job until #2220 — so it is SEEDED, once, from the
// CSRF value the store already held (`seedFrom`), and the name an upgraded
// deployment knows does not change when the CSRF key starts rotating.
//
// AN OPERATOR'S ENVIRONMENT VARIABLE IS NOT ROTATED: it is the operator's
// value on every node, and changing it is theirs. Nor is a value no store
// shares (memory, ldif, no key-encryption key): it is made anew at every
// start already.
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
import config = require('../common/config');
// The one place this service draws random values (#453). A leaf over
// `config`, so this require cannot close a cycle.
import stsCrypto = require('../common/crypto');
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
  // An identifier's key, never rotated (header, #2220).
  identifier?: boolean;
  // The declared secret whose value this one is first offered as (#2220).
  seedFrom?: string;
}

// What this process holds for a secret. `source` is one of 'process',
// 'store', 'environment' and 'node'. `next` and `previous` are the values a
// rotation keeps beside the current one (#2220), '' when there is none.
interface HeldSecret {
  text: string;
  source: string;
  next?: string;
  previous?: string;
  previousUntil?: number;
}

// The stored form of a rotated secret (#2220); a bare value reads as `v: 1`.
interface SecretEnvelope {
  v: number;
  current: string;
  next?: string;
  nextAt?: number;
  previous?: string;
  previousUntil?: number;
  rotatedAt?: number;
}

// The parts of the keystore `start()` uses.
interface SecretsKeystore {
  sealed(): boolean;
  hasEphemeralKek?: () => boolean;
  seal(text: string, purpose: string): unknown;
  open(material: unknown, purpose: string): unknown;
  settleDeks?: () => Promise<unknown>;
}

// The parts of the persistence store `start()` uses.
interface SharedSecretStore {
  ensureSharedSecret?: (name: string,
                        sealed: unknown) => Promise<{ material: unknown }>;
  // #2220: the row as it is, and a compare-and-set replacement of it.
  readSharedSecret?: (name: string) => Promise<{ material: unknown } | null>;
  replaceSharedSecret?: (name: string, expected: unknown,
                         sealed: unknown) => Promise<{ replaced: boolean }>;
}

interface ClusterSecretsDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    // #2220: optional, so a test's logger of two methods still builds one.
    warn?(message: string): void;
    error?(message: string): void;
  };
  errorCodes: { tag(code: string): string };
  env: NodeJS.ProcessEnv;
  randomBytes(size: number): Buffer;
  // LAZY, as the requires were: see `start()`.
  clusterStore(): SharedSecretStore | null | undefined;
  isActiveActive(): boolean;
  // #2220: a setting's value, the clock, and the audit log. Optional, so a
  // test's dependencies written before rotation still build an instance.
  setting?: (key: string) => unknown;
  now?: () => number;
  audit?: (row: Record<string, unknown>) => void;
}

// #2220. How long a published NEXT value is accepted before it is made
// current: forty times the refresh below, so every process has re-read the
// store many times over before anything is MACed under it. Constants, not
// settings: they order two steps of one mechanism, and the length an
// operator may want to choose is the overlap, `cluster.secretOverlapS`.
const ACTIVATION_LEAD_MS = 10 * 60 * 1000;
const REFRESH_MS = 15 * 1000;
// The scheduler jobs (#2220).
const ROTATE_JOB = 'cluster.secret-rotate';
const REFRESH_JOB = 'cluster.secret-refresh';
const ROTATE_EVERY_MS = 60 * 1000;
// The environment variables a front process hands its request workers: the
// names it read from the store, and what a rotation keeps beside each.
const STORED_VAR = 'STS_CLUSTER_SECRETS_STORED';
const STATE_VAR = 'STS_CLUSTER_SECRET_STATE';

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
/**
 * The secrets every node must agree on, by name: the bytes to generate, the
 * environment variable that overrides the value, and what it keys.
 */
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
  // AN IDENTIFIER (#2220): never rotated; see the header.
  'oidc-pairwise': { bytes: 32, env: 'STS_OIDC_PAIRWISE_SECRET',
    identifier: true,
    what: 'The key an OpenID Connect pairwise subject identifier is derived ' +
          'with (oauth-oidc/pairwise_subjects.ts, OIDC Core section 8.1).' },
  // #135, #136: a page drawn by one node is continued on another, so the
  // pointer its `next` carries must verify on every node.
  'oidfed-page': { bytes: 32, env: 'STS_OIDFED_PAGE_SECRET',
    what: 'The key an OpenID Federation listing\'s or collection\'s page ' +
          'pointer is MACed with (oidfed/page_pointer.ts).' },
  // #577: the sign-out is answered by one request and its signed-out
  // document drawn by the next, which may be another node's.
  'logout-result': { bytes: 32, env: 'STS_LOGOUT_RESULT_SECRET',
    what: 'The key a sign-out\'s result is MACed with on its way to the ' +
          'signed-out document (logout/logout.ts).' },
  // #725: a challenge minted by one node is signed by the browser and
  // presented to another, and a bound cookie renewed by one is presented
  // to every other the next moment.
  'dbsc': { bytes: 32, env: 'STS_DBSC_SECRET',
    what: 'The key a Device Bound Session Credentials challenge and bound ' +
          'cookie are MACed with (authn/device_bound_sessions.ts).' },
  // #2220: the generated bootstrap administrator's name was derived from
  // the CSRF key, which rotates now. An IDENTIFIER, first offered as the
  // CSRF value this store already holds, so the name does not change. LAST,
  // so the value it is seeded from has been read when it is offered.
  'bootstrap-name': { bytes: 32, env: 'STS_BOOTSTRAP_NAME_SECRET',
    identifier: true, seedFrom: 'csrf',
    what: 'The key the generated bootstrap administrator\'s username is ' +
          'derived with in product mode (common/bootstrap_name.ts).' }
};

// name -> { text, source: 'process'|'store'|'environment'|'node' }. The TEXT is
// the secret — callers that derive with it use the string, as they always did,
// and `get()` hands out its bytes for a caller that wants a key.
const values: Map<string, HeldSecret> = new Map();
// Names whose environment variable THIS process wrote, so start() can tell its
// own per-process value from one an operator set.
const generatedHere: Set<string> = new Set();
// Names whose value this process read from the shared store (#2220): the
// ones the refresh reads again and the rotation may change.
const storedNames: Set<string> = new Set();
// The keystore start() was given, which the two jobs open and seal with.
let heldKeystore: SecretsKeystore | null = null;

/**
 * The secrets every node must agree on (#46): generated once for the whole
 * store, sealed under the key-encryption key, and read by every process
 * before it serves; a per-process value where nothing can be shared.
 */
class ClusterSecrets {
  /**
   * The declared secrets; see the module-level DECLARED.
   */
  static readonly DECLARED = DECLARED;

  private started = false;

  /**
   * Builds the instance from its dependencies.
   *
   * @param deps - the logger, the error-code table, the environment, a
   *   random-bytes source, and lazy loaders for the shared store and the
   *   active-active check
   */
  constructor(private readonly deps: ClusterSecretsDeps) {
    deps.log.debug("Entering ClusterSecrets.constructor().");
    deps.log.debug("Leaving ClusterSecrets.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the dependencies the composition root builds the instance from.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): ClusterSecretsDeps {
    log.debug("Entering ClusterSecrets.defaultDeps().");
    log.debug("Leaving ClusterSecrets.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      env: process.env,
      randomBytes: stsCrypto.randomBytes,
      clusterStore: ClusterSecrets.persistenceClusterStore,
      isActiveActive: ClusterSecrets.clusterIsActiveActive,
      setting: function (key: string): unknown {
        return config.value(key);
      },
      now: function (): number {
        return Date.now();
      },
      // LAZY: the audit log requires much of the service, and this module is
      // required early (#2220).
      audit: function (row: Record<string, unknown>): void {
        require('../common/audit').audit(row);
      }
    };
  }

  // The persistence store to share through, required LAZILY: the default
  // `clusterStore` in `defaultDeps()`.
  /**
   * Returns the persistence store's cluster functions, required lazily.
   *
   * @returns the store, or null when none is open
   */
  static persistenceClusterStore(): SharedSecretStore | null | undefined {
    log.debug("Entering ClusterSecrets.persistenceClusterStore().");
    const persistence = require('../persistence/persistence');
    log.debug("Leaving ClusterSecrets.persistenceClusterStore().");
    return persistence.clusterStore();
  }

  // Is this node active-active? `cluster.js` is required LAZILY, as it was.
  /**
   * Says whether this node is active-active, requiring `cluster.js` lazily.
   *
   * @returns true in active-active mode
   */
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
    // SEEDED FROM ANOTHER (#2220): where nothing is shared, the same value
    // the secret it replaces holds in this process, so a name derived from
    // either is the one it always was.
    const fresh = { text: declared.seedFrom ? this.text(declared.seedFrom)
                      : randomBytes(declared.bytes).toString('base64'),
                    source: 'process' };
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
  /**
   * Returns a secret's text, synchronously: the shared value once started, and
   * a per-process random value (or the environment's) before.
   *
   * @param name - a name in DECLARED
   * @returns the secret's text
   * @throws Error when the name is not declared
   */
  text(name: string): string {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.text(). name=" + name);
    const held = values.get(name) || this.processValue(name);
    log.debug("Leaving ClusterSecrets.text().");
    return held.text;
  }

  // THE SECRET AS KEY BYTES.
  /**
   * Returns a secret as key bytes, the UTF-8 of text().
   *
   * @param name - a name in DECLARED
   * @returns the key bytes
   */
  get(name: string): Buffer {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.get(). name=" + name);
    log.debug("Leaving ClusterSecrets.get().");
    return Buffer.from(this.text(name), 'utf8');
  }

  // EVERY VALUE A VERIFIER ACCEPTS (#2220): the current one first, then a
  // published next value, then the previous one while its overlap lasts.
  /**
   * Returns every text a MAC under this secret may have been made with: the
   * current value, a published next value, and the previous value until its
   * overlap ends. A verifier accepts a MAC under any of them.
   *
   * @param name - a name in DECLARED
   * @returns the texts, the current one first
   */
  texts(name: string): string[] {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.texts(). name=" + name);
    const current = this.text(name);
    const held = values.get(name) || { text: current, source: 'process' };
    const out = [current];
    if (held.next && out.indexOf(held.next) < 0) {
      out.push(held.next);
    }
    if (held.previous && out.indexOf(held.previous) < 0 &&
        Number(held.previousUntil) > this.nowMs()) {
      out.push(held.previous);
    }
    log.debug("Leaving ClusterSecrets.texts(). " + out.length + ".");
    return out;
  }

  /**
   * Returns `texts()` as key bytes, the current one first.
   *
   * @param name - a name in DECLARED
   * @returns the key bytes of every value a verifier accepts
   */
  keys(name: string): Buffer[] {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.keys(). name=" + name);
    log.debug("Leaving ClusterSecrets.keys().");
    return this.texts(name).map(function (one) {
      return Buffer.from(one, 'utf8');
    });
  }

  private nowMs(): number {
    const { log, now } = this.deps;
    log.debug("Entering ClusterSecrets.nowMs().");
    log.debug("Leaving ClusterSecrets.nowMs().");
    return typeof now === 'function' ? now() : Date.now();
  }

  private settingOf(key: string): unknown {
    const { log, setting } = this.deps;
    log.debug("Entering ClusterSecrets.settingOf(). " + key);
    log.debug("Leaving ClusterSecrets.settingOf().");
    return typeof setting === 'function' ? setting(key) : config.value(key);
  }

  /**
   * Reads a stored value: an envelope (#2220), or the bare text every earlier
   * build wrote, which is its `current` with no date.
   *
   * @param text - the opened value
   * @returns the envelope
   */
  static envelopeOf(text: unknown): SecretEnvelope {
    log.debug("Entering ClusterSecrets.envelopeOf().");
    const raw = String(text == null ? '' : text);
    if (raw.charAt(0) === '{') {
      let parsed: any = null;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        // Not JSON: a bare value that happens to start with a brace, which
        // a base64 value never does — kept whole, as before.
        log.debug("Caught in ClusterSecrets.envelopeOf(): " +
                  ((e && e.message) || e));
        parsed = null;
      }
      if (parsed && parsed.v === 2 && typeof parsed.current === 'string' &&
          parsed.current) {
        log.debug("Leaving ClusterSecrets.envelopeOf(). An envelope.");
        return {
          v: 2, current: parsed.current,
          next: typeof parsed.next === 'string' ? parsed.next : '',
          nextAt: Number(parsed.nextAt) || 0,
          previous: typeof parsed.previous === 'string' ? parsed.previous
                                                        : '',
          previousUntil: Number(parsed.previousUntil) || 0,
          rotatedAt: Number(parsed.rotatedAt) || 0
        };
      }
    }
    log.debug("Leaving ClusterSecrets.envelopeOf(). A bare value.");
    return { v: 1, current: raw, next: '', nextAt: 0, previous: '',
             previousUntil: 0, rotatedAt: 0 };
  }

  // Holds an envelope as this process's value of a secret, and puts the
  // current value in the environment for the workers forked after this.
  private adopt(name: string, envelope: SecretEnvelope,
                source: string): void {
    const { log, env } = this.deps;
    log.debug("Entering ClusterSecrets.adopt(). name=" + name);
    values.set(name, { text: envelope.current, source: source,
                       next: envelope.next || '',
                       previous: envelope.previous || '',
                       previousUntil: Number(envelope.previousUntil) || 0 });
    env[DECLARED[name].env] = envelope.current;
    generatedHere.delete(name);
    storedNames.add(name);
    this.publishState();
    log.debug("Leaving ClusterSecrets.adopt().");
  }

  // What a request worker forked from here inherits beside the current
  // values: the names read from the store, and each one's next and previous.
  private publishState(): void {
    const { log, env } = this.deps;
    log.debug("Entering ClusterSecrets.publishState().");
    const state: Record<string, unknown> = {};
    storedNames.forEach(function (name) {
      const held = values.get(name);
      if (held && (held.next || held.previous)) {
        state[name] = { next: held.next || '', previous: held.previous || '',
                        previousUntil: Number(held.previousUntil) || 0 };
      }
    });
    env[STORED_VAR] = Array.from(storedNames).join(',');
    if (Object.keys(state).length) {
      env[STATE_VAR] = JSON.stringify(state);
    } else {
      delete env[STATE_VAR];
    }
    log.debug("Leaving ClusterSecrets.publishState().");
  }

  // A worker's view of what its front process read from the store (#2220).
  private inheritState(): void {
    const { log, env } = this.deps;
    log.debug("Entering ClusterSecrets.inheritState().");
    String(env[STORED_VAR] || '').split(',').forEach(function (name) {
      if (DECLARED[name]) {
        storedNames.add(name);
      }
    });
    let state: any = null;
    try {
      state = env[STATE_VAR] ? JSON.parse(String(env[STATE_VAR])) : null;
    } catch (e) {
      // A value this module did not write: the worker verifies under the
      // current value alone until its first refresh reads the store.
      log.debug("Caught in ClusterSecrets.inheritState(): " +
                ((e && e.message) || e));
      state = null;
    }
    Object.keys(state || {}).forEach(function (name) {
      const held = values.get(name);
      const one = state[name] || {};
      if (held && storedNames.has(name)) {
        held.next = String(one.next || '');
        held.previous = String(one.previous || '');
        held.previousUntil = Number(one.previousUntil) || 0;
      }
    });
    log.debug("Leaving ClusterSecrets.inheritState().");
  }

  // -------------------------------------------------------------------------
  // THE REFRESH (#2220): every value this process read from the store, read
  // again, so a rotation another process made is heard of here. A per-process
  // job; a secret that will not open is logged and the value already held is
  // kept, because a node that dropped its key would refuse every MAC.
  // -------------------------------------------------------------------------
  /**
   * Reads again every secret this process holds from the shared store, so a
   * rotation made by another process is adopted here.
   *
   * @param keystore - the open keystore; the one start() was given when
   *   omitted
   * @returns a promise of `{ refreshed, changed }`
   */
  async refresh(keystore?: SecretsKeystore | null): Promise<any> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ClusterSecrets.refresh().");
    const ks = keystore || heldKeystore;
    const theStore = this.deps.clusterStore();
    if (!ks || !theStore || typeof theStore.readSharedSecret !== 'function' ||
        !storedNames.size) {
      log.debug("Leaving ClusterSecrets.refresh(). Nothing shared.");
      return { refreshed: 0, changed: [] };
    }
    const changed: string[] = [];
    let refreshed = 0;
    for (const name of Array.from(storedNames)) {
      try {
        const row = await theStore.readSharedSecret(name);
        const opened = row ? ks.open(row.material, 'cluster-secret') : null;
        if (!opened) {
          throw new Error('the stored value would not open');
        }
        const envelope = ClusterSecrets.envelopeOf(opened);
        const before = values.get(name);
        if (!before || before.text !== envelope.current ||
            (before.next || '') !== (envelope.next || '') ||
            (before.previous || '') !== (envelope.previous || '')) {
          changed.push(name);
        }
        this.adopt(name, envelope, 'store');
        refreshed += 1;
      } catch (e) {
        log.debug("Caught in ClusterSecrets.refresh(): " +
                  ((e && e.message) || e));
        (log.warn || log.info).call(log, errorCodes.tag('STS-CLUSTER-0167') +
                 'cluster secrets: ' +
                 'the "' + name + '" secret could not be read again from ' +
                 'the store, so this process keeps the value it holds: ' +
                 String((e && e.message) || e));
      }
    }
    if (changed.length) {
      log.info('cluster secrets: a rotation of ' + changed.join(', ') +
               ' was read from the store.');
    }
    log.debug("Leaving ClusterSecrets.refresh(). " + refreshed + ".");
    return { refreshed: refreshed, changed: changed };
  }

  /**
   * Decides what a rotation does to one stored envelope at a moment: date a
   * bare value, publish a next value, promote it, or drop an expired
   * previous one. Pure, so a test can walk every step.
   *
   * @param envelope - the stored envelope
   * @param nowMs - the moment
   * @param rotationMs - the interval between rotations; 0 never rotates
   * @param overlapMs - how long the previous value is still accepted
   * @param fresh - makes a new value
   * @returns `{ envelope, step }`, `step` '' when nothing is to change
   */
  static nextStep(envelope: SecretEnvelope, nowMs: number, rotationMs: number,
                  overlapMs: number,
                  fresh: () => string): { envelope: SecretEnvelope;
                                          step: string } {
    log.debug("Entering ClusterSecrets.nextStep().");
    const out: SecretEnvelope = Object.assign({}, envelope, { v: 2 });
    if (out.next && nowMs >= Number(out.nextAt) + ACTIVATION_LEAD_MS) {
      out.previous = out.current;
      out.previousUntil = nowMs + overlapMs;
      out.current = out.next;
      out.next = '';
      out.nextAt = 0;
      out.rotatedAt = nowMs;
      log.debug("Leaving ClusterSecrets.nextStep(). Promoted.");
      return { envelope: out, step: 'promoted' };
    }
    if (out.previous && nowMs >= Number(out.previousUntil)) {
      out.previous = '';
      out.previousUntil = 0;
      log.debug("Leaving ClusterSecrets.nextStep(). Previous dropped.");
      return { envelope: out, step: 'previous-dropped' };
    }
    if (!out.rotatedAt) {
      // THE FIRST SIGHT OF A BARE VALUE: dated, not changed.
      out.rotatedAt = nowMs;
      log.debug("Leaving ClusterSecrets.nextStep(). Dated.");
      return { envelope: out, step: 'dated' };
    }
    if (!out.next && rotationMs > 0 &&
        nowMs - Number(out.rotatedAt) >= rotationMs) {
      out.next = fresh();
      out.nextAt = nowMs;
      log.debug("Leaving ClusterSecrets.nextStep(). Next published.");
      return { envelope: out, step: 'next-published' };
    }
    log.debug("Leaving ClusterSecrets.nextStep(). Nothing due.");
    return { envelope: envelope, step: '' };
  }

  // -------------------------------------------------------------------------
  // THE ROTATION (#2220): one step for every stored secret that is a key and
  // not an identifier, written only if the row is still what was read (a
  // compare-and-set), so two runs cannot both rotate one secret.
  // -------------------------------------------------------------------------
  /**
   * Takes the due rotation step of every shared secret that is a key: dates a
   * bare value, publishes a next value, promotes it, or drops an expired
   * previous one. Identifiers and operator-set values are left alone.
   *
   * @param keystore - the open keystore; the one start() was given when
   *   omitted
   * @returns a promise of `{ steps }`, one `{ name, step }` per change
   */
  async rotate(keystore?: SecretsKeystore | null): Promise<any> {
    const { log, errorCodes, randomBytes, audit } = this.deps;
    log.debug("Entering ClusterSecrets.rotate().");
    const ks = keystore || heldKeystore;
    const theStore = this.deps.clusterStore();
    if (!ks || !theStore || typeof theStore.readSharedSecret !== 'function' ||
        typeof theStore.replaceSharedSecret !== 'function') {
      log.debug("Leaving ClusterSecrets.rotate(). Nothing shared.");
      return { steps: [] };
    }
    const days = Number(this.settingOf('cluster.secretRotationDays'));
    const rotationMs = isFinite(days) && days > 0 ? days * 86400000 : 0;
    const overlapS = Number(this.settingOf('cluster.secretOverlapS'));
    const overlapMs = (isFinite(overlapS) && overlapS > 0 ? overlapS : 0) *
                      1000;
    const steps: { name: string; step: string }[] = [];
    for (const name of Array.from(storedNames)) {
      const declared = DECLARED[name];
      if (!declared || declared.identifier || this.generated(name)) {
        continue;
      }
      try {
        const row = await theStore.readSharedSecret(name);
        const opened = row ? ks.open(row.material, 'cluster-secret') : null;
        if (!opened) {
          throw new Error('the stored value would not open');
        }
        const decided = ClusterSecrets.nextStep(
          ClusterSecrets.envelopeOf(opened), this.nowMs(), rotationMs,
          overlapMs, function () {
            return randomBytes(declared.bytes).toString('base64');
          });
        if (!decided.step) {
          continue;
        }
        if (typeof ks.settleDeks === 'function') {
          await ks.settleDeks();
        }
        const sealed = ks.seal(JSON.stringify(decided.envelope),
                               'cluster-secret');
        if (!sealed) {
          throw new Error('the rotated value could not be sealed');
        }
        const written = await theStore.replaceSharedSecret(name, row.material,
                                                           sealed);
        if (!written || !written.replaced) {
          // Another run changed the row first: its step stands, and this
          // process reads it at its next refresh.
          continue;
        }
        this.adopt(name, decided.envelope, 'store');
        steps.push({ name: name, step: decided.step });
        if (decided.step !== 'dated' && typeof audit === 'function') {
          audit({ action: 'cluster.secret-rotated', actor: 'scheduler',
                  protocol: 'console', channel: 'internal', target: name,
                  summary: 'The shared "' + name + '" secret: ' +
                           decided.step.replace(/-/g, ' '),
                  detail: { name: name, step: decided.step,
                            previousUntil: decided.envelope.previousUntil ||
                                           0 } });
        }
      } catch (e) {
        log.debug("Caught in ClusterSecrets.rotate(): " +
                  ((e && e.message) || e));
        (log.error || log.info).call(log,
                  errorCodes.tag('STS-CLUSTER-0168') + 'cluster secrets: ' +
                  'the "' + name + '" secret could not be rotated, and ' +
                  'keeps its value: ' + String((e && e.message) || e));
      }
    }
    if (steps.length) {
      log.info('cluster secrets: ' + steps.map(function (one) {
        return one.name + ' ' + one.step;
      }).join(', ') + '.');
    }
    log.debug("Leaving ClusterSecrets.rotate(). " + steps.length + ".");
    return { steps: steps };
  }

  // Why the two jobs have nothing to do in this process, or ''.
  private jobsOff(): string {
    const { log } = this.deps;
    log.debug("Entering ClusterSecrets.jobsOff().");
    const theStore = this.deps.clusterStore();
    log.debug("Leaving ClusterSecrets.jobsOff().");
    if (!theStore || typeof theStore.readSharedSecret !== 'function') {
      return 'no store shares the secrets in this process';
    }
    return storedNames.size ? '' : 'no secret was read from the store';
  }

  /**
   * Registers the rotation job (a cluster job) and the refresh job (per
   * process) with a scheduler. Idempotent.
   *
   * @param scheduler - the scheduler instance
   */
  static ensureJobs(scheduler: any): void {
    log.debug("Entering ClusterSecrets.ensureJobs().");
    if (!scheduler || typeof scheduler.register !== 'function') {
      log.debug("Leaving ClusterSecrets.ensureJobs(). No scheduler yet.");
      return;
    }
    if (!scheduler.job(ROTATE_JOB)) {
      scheduler.register({
        id: ROTATE_JOB,
        title: 'Shared secret rotation',
        describe: 'Rotates each shared secret that is a key (the CSRF, ACME ' +
                  'nonce, Shared Signals receiver, OpenID Federation page, ' +
                  'sign-out result and DBSC keys) every ' +
                  'cluster.secretRotationDays: a next value is published, ' +
                  'made current ten minutes later, and the old one is ' +
                  'still accepted for cluster.secretOverlapS. The pairwise ' +
                  'subject and bootstrap name secrets are identifiers and ' +
                  'never rotate.',
        owner: 'cluster/cluster_secrets.ts',
        everyMs: function () {
          return ROTATE_EVERY_MS;
        },
        off: function () {
          return slot.get().jobsOff();
        },
        run: function () {
          return slot.get().rotate();
        }
      });
    }
    if (!scheduler.job(REFRESH_JOB)) {
      scheduler.register({
        id: REFRESH_JOB,
        title: 'Shared secret refresh',
        describe: 'Reads the shared secrets again from the store in this ' +
                  'process, so a rotation made on any node is used here.',
        owner: 'cluster/cluster_secrets.ts',
        kind: 'per-process', quiet: true,
        everyMs: function () {
          return REFRESH_MS;
        },
        off: function () {
          return slot.get().jobsOff();
        },
        run: function () {
          return slot.get().refresh();
        }
      });
    }
    log.debug("Leaving ClusterSecrets.ensureJobs().");
  }

  // Where a secret's value came from, for /admin/cluster. Never the value.
  /**
   * Reports where each secret's value came from, for `/admin/cluster`; never
   * the value.
   *
   * @returns whether start() ran, and each secret's name, purpose and source
   */
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
  /**
   * Reads every declared secret from the shared store, offering a fresh sealed
   * value first so the store keeps the first offer; a worker inherits its
   * front process's values through the environment, and an operator's
   * environment variable wins.
   *
   * Without a shared store or a key-encryption key the values stay per process,
   * except in active-active mode, where that is refused.
   * @param keystore - the open keystore that seals and opens the stored values
   * @returns a promise of `{ shared, names }`, or `{ shared: false }`; it
   *   rejects on any failure on a store that can share
   */
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
      // AND WHAT A ROTATION KEEPS BESIDE EACH (#2220), so a MAC made under
      // a previous or next value verifies here from the first request.
      this.inheritState();
      heldKeystore = keystore || null;
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
    const self = this;
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
        // SEEDED (#2220): offered as the value the secret it replaces holds
        // NOW, which on an upgraded store is the value it always held.
        if (DECLARED[name].seedFrom) {
          return this.text(DECLARED[name].seedFrom);
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
        // THE DATA-KEY ROW LANDS FIRST (#391): another node opening this
        // secret must find the data encryption key it was sealed under.
        return Promise.resolve(typeof keystore.settleDeks === 'function'
          ? keystore.settleDeks() : null).then(function () {
          return theStore.ensureSharedSecret(name, sealed);
        }).then(function (row) {
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
          // AN ENVELOPE OR A BARE VALUE (#2220), held as its current value
          // with what a rotation keeps beside it — and INTO THE ENVIRONMENT,
          // replacing this process's own value, so the request workers
          // forked after this inherit the shared one (`adopt()`).
          self.adopt(name, ClusterSecrets.envelopeOf(opened), 'store');
        });
      });
    });
    heldKeystore = keystore;
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
  /**
   * Forgets every value and every environment variable this module wrote. For
   * tests.
   */
  reset(): void {
    const { log, env } = this.deps;
    log.debug("Entering ClusterSecrets.reset().");
    generatedHere.forEach(function (name) {
      delete env[DECLARED[name].env];
    });
    values.clear();
    generatedHere.clear();
    storedNames.clear();
    heldKeystore = null;
    delete env[STORED_VAR];
    delete env[STATE_VAR];
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

/**
 * The secrets every node must agree on (#46), shared through the store.
 *
 * The exports other than `ClusterSecrets` forward to the instance the
 * composition root installs.
 * @namespace
 */
export = {
  ClusterSecrets: ClusterSecrets,
  /**
   * Installs the instance the composition root built.
   */
  installInstance: (instance: ClusterSecrets): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  DECLARED: ClusterSecrets.DECLARED,
  get: slot.forward('get'),
  text: slot.forward('text'),
  texts: slot.forward('texts'),
  keys: slot.forward('keys'),
  refresh: slot.forward('refresh'),
  rotate: slot.forward('rotate'),
  ensureJobs: ClusterSecrets.ensureJobs,
  envelopeOf: ClusterSecrets.envelopeOf,
  nextStep: ClusterSecrets.nextStep,
  ROTATE_JOB: ROTATE_JOB,
  REFRESH_JOB: REFRESH_JOB,
  describe: slot.forward('describe'),
  start: slot.forward('start'),
  reset: slot.forward('reset')
};
