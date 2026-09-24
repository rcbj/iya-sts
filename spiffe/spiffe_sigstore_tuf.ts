'use strict';
//
// File: spiffe_sigstore_tuf.ts
//
// ---------------------------------------------------------------------------
// THE SIGSTORE TRUST ROOT, FETCHED THROUGH TUF AS A SCHEDULER JOB (#170,
// 2026-09-23 — decision 3 on the issue).
//
// A keyless cosign signature is trusted because a Fulcio CA certified its
// key, a Rekor log recorded it and a CT log recorded the certificate. Those
// CAs and log keys ROTATE, and sigstore publishes the current set as the
// `trusted_root.json` target of its TUF repository — which is what SPIRE's
// sigstore verifier reads through `fulcioroots.Get()` and cosign's TUF
// client. This is that client, for the Update Framework specification's
// "Detailed client workflow" (section 5), and nothing more:
//
//   5.3  root: `N.root.json` for each next version until one is missing,
//        each verified under the threshold of the PREVIOUS root's root role
//        AND its own (so a key rotation is signed by both sets), each version
//        exactly one more than the last; the final root must not be expired.
//        A rotation of the timestamp or snapshot keys forgets the stored
//        versions of those roles, as the specification says (fast-forward
//        recovery).
//   5.4  timestamp: `timestamp.json`, verified under the root's timestamp
//        role; its version and the snapshot version it names may not go
//        backwards; not expired.
//   5.5  snapshot: `<v>.snapshot.json` (consistent snapshots), its length and
//        hashes as the timestamp says, verified under the snapshot role, the
//        version the timestamp named; the targets version it names may not go
//        backwards; not expired.
//   5.6  targets: `<v>.targets.json` likewise, under the targets role.
//   5.7  the target: `targets/<sha256>.trusted_root.json`, its length and
//        EVERY hash the targets metadata lists checked.
//
// **A FAILED REFRESH KEEPS THE LAST GOOD SET AND NEVER WIDENS IT.** The state
// is written only when every step above passed, in one row, so a bad
// signature, an expired file, a rollback, a network failure or a truncated
// target leaves the previous verified trust root in force (STS-SPIFFE-0131)
// and the job's run fails with the reason. Nothing unverified is ever
// merged into it.
//
// **THE FIRST ROOT IS THE OPERATOR'S**: `spiffe.dockerSigstoreTufRootFile`,
// a FILE PATH (no key material is ever a setting). It must verify under its
// own root role. The row is keyed by a digest of that file and of
// `spiffe.dockerSigstoreTufUrl`, so pointing either somewhere else starts a
// fresh chain rather than continuing one another repository began.
//
// **TOP-LEVEL TARGETS ONLY.** `trusted_root.json` is a top-level target of
// sigstore's repository; delegated targets roles are not walked, and a
// repository that delegated it would be refused, saying so.
//
// The state is `realms.sharedMap({ scope: 'shared' })`: the trust root is
// the process's, not a realm's (the three settings are `perProcess`), and the
// job is a CLUSTER job, so one node refreshes and the store replicates the
// row to the others.
// ---------------------------------------------------------------------------

import fs = require('fs');
import helpers = require('../common/helpers');
const { log } = helpers;
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import outbound = require('../federation/federation_http');

// The job's id on /admin/scheduler.
const JOB = 'spiffe.sigstore-tuf-refresh';
// The TUF reference client's bound on root rotations in one refresh.
const MAX_ROOT_ROTATIONS = 32;
// The largest metadata or target document read, in bytes.
const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;
// The target this client wants.
const TARGET = 'trusted_root.json';

// One row per repository and first root (see the header).
const state = realms.sharedMap({ persist: 'spiffe.sigstoreTuf',
                                 scope: 'shared' });

interface TufDeps {
  log: typeof log;
  fs: typeof fs;
  config: typeof config;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  // GET one URL; `{ ok, status, body, why }` as `requestConfigured()`.
  fetch(url: string): Promise<{ ok: boolean; status: number; body: Buffer;
                                why: string }>;
  nowMs(): number;
  // The row store: `realms.sharedMap()`, or a Map in a test.
  store: { get(key: string): any; set(key: string, value: any): any };
}

class SigstoreTuf {
  constructor(private readonly deps: TufDeps) {
    deps.log.debug("Entering SigstoreTuf.constructor().");
    deps.log.debug("Leaving SigstoreTuf.constructor().");
  }

  static defaultDeps(): TufDeps {
    helpers.log.debug("Entering SigstoreTuf.defaultDeps().");
    helpers.log.debug("Leaving SigstoreTuf.defaultDeps().");
    return {
      log: log, fs: fs, config: config, errorCodes: errorCodes,
      stsCrypto: stsCrypto, store: state,
      fetch: function (url: string) {
        return outbound.requestConfigured(url);
      },
      nowMs: function () {
        return Date.now();
      }
    };
  }

  // The repository URL, without a trailing slash; '' when TUF is off.
  repository(): string {
    const { log, config } = this.deps;
    log.debug("Entering SigstoreTuf.repository().");
    log.debug("Leaving SigstoreTuf.repository().");
    return String(config.value('spiffe.dockerSigstoreTufUrl') || '')
      .replace(/\/+$/, '');
  }

  rootFile(): string {
    const { log, config } = this.deps;
    log.debug("Entering SigstoreTuf.rootFile().");
    log.debug("Leaving SigstoreTuf.rootFile().");
    return String(config.value('spiffe.dockerSigstoreTufRootFile') || '');
  }

  // Why TUF is off, or ''.
  off(): string {
    const { log } = this.deps;
    log.debug("Entering SigstoreTuf.off().");
    let why = '';
    if (!this.rootFile()) {
      why = 'spiffe.dockerSigstoreTufRootFile is empty';
    } else if (!this.repository()) {
      why = 'spiffe.dockerSigstoreTufUrl is empty';
    }
    log.debug("Leaving SigstoreTuf.off(). " + (why || 'on'));
    return why;
  }

  // The operator's first root, read from its file, and the row key.
  firstRoot(): { root: any; key: string } {
    const { log, fs, stsCrypto } = this.deps;
    log.debug("Entering SigstoreTuf.firstRoot().");
    const text = fs.readFileSync(this.rootFile());
    log.debug("Leaving SigstoreTuf.firstRoot().");
    return { root: JSON.parse(text.toString('utf8')),
             key: stsCrypto.sha256Hex(Buffer.concat([
               Buffer.from(this.repository() + '\n', 'utf8'), text])) };
  }

  // The verified state for the configured repository and root, or null.
  current(): any {
    const { log, store } = this.deps;
    log.debug("Entering SigstoreTuf.current().");
    if (this.off()) {
      log.debug("Leaving SigstoreTuf.current(). Off.");
      return null;
    }
    let key = '';
    try {
      key = this.firstRoot().key;
    } catch (e) {
      log.debug("Caught in SigstoreTuf.current(): " + ((e && e.message) || e));
      log.debug("Leaving SigstoreTuf.current(). No root file.");
      return null;
    }
    log.debug("Leaving SigstoreTuf.current().");
    return store.get(key) || null;
  }

  // The trusted_root.json the last verified refresh fetched, parsed, or
  // null when TUF is off or has never completed.
  trustedRoot(): any {
    const { log } = this.deps;
    log.debug("Entering SigstoreTuf.trustedRoot().");
    const held = this.current();
    if (!held || !held.trustedRoot) {
      log.debug("Leaving SigstoreTuf.trustedRoot(). None.");
      return null;
    }
    log.debug("Leaving SigstoreTuf.trustedRoot().");
    return JSON.parse(held.trustedRoot);
  }

  // One document, capped; throws a sentence.
  async get(name: string): Promise<Buffer | null> {
    const { log, fetch } = this.deps;
    log.debug("Entering SigstoreTuf.get(). " + name);
    const answer = await fetch(this.repository() + '/' + name);
    if (answer.status === 404 || answer.status === 403) {
      log.debug("Leaving SigstoreTuf.get(). Absent.");
      return null;
    }
    if (!answer.ok) {
      log.debug("Leaving SigstoreTuf.get(). Failed.");
      // error-code: none — refresh() tags the refresh's failure
      throw new Error(name + ' could not be fetched: ' + answer.why);
    }
    if (answer.body.length > MAX_DOCUMENT_BYTES) {
      log.debug("Leaving SigstoreTuf.get(). Too large.");
      // error-code: none — refresh() tags the refresh's failure
      throw new Error(name + ' is larger than ' + MAX_DOCUMENT_BYTES +
                      ' bytes');
    }
    log.debug("Leaving SigstoreTuf.get().");
    return answer.body;
  }

  // A metadata file verified under `role` of `root`, of `type`; throws.
  async verified(bytes: Buffer, root: any, roleName: string,
                 type: string): Promise<any> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering SigstoreTuf.verified(). " + roleName);
    let doc = null;
    try {
      doc = JSON.parse(bytes.toString('utf8'));
    } catch (e) {
      log.debug("Caught in SigstoreTuf.verified(): " +
                ((e && e.message) || e));
    }
    if (!doc || !doc.signed || doc.signed._type !== type) {
      log.debug("Leaving SigstoreTuf.verified(). Not " + type + ".");
      // error-code: none — refresh() tags the refresh's failure
      throw new Error('the ' + roleName + ' metadata is not a TUF ' + type +
                      ' document');
    }
    const role = ((root.signed || {}).roles || {})[roleName];
    const outcome = await stsCrypto.verifyThresholdSignatures(
      doc.signed, doc.signatures, (root.signed || {}).keys, role);
    if (!outcome.ok) {
      log.debug("Leaving SigstoreTuf.verified(). Threshold.");
      // error-code: none — refresh() tags the refresh's failure
      throw new Error('the ' + roleName + ' metadata carries ' +
                      outcome.valid + ' valid signature(s) and its role ' +
                      'needs ' + outcome.threshold);
    }
    log.debug("Leaving SigstoreTuf.verified().");
    return doc;
  }

  // Refuse metadata past its `expires`.
  notExpired(doc: any, name: string): void {
    const { log, nowMs } = this.deps;
    log.debug("Entering SigstoreTuf.notExpired(). " + name);
    const expires = Date.parse(String((doc.signed || {}).expires || ''));
    if (!Number.isFinite(expires) || expires <= nowMs()) {
      log.debug("Leaving SigstoreTuf.notExpired(). Expired.");
      // error-code: none — refresh() tags the refresh's failure
      throw new Error('the ' + name + ' metadata expired at ' +
                      (doc.signed || {}).expires);
    }
    log.debug("Leaving SigstoreTuf.notExpired().");
  }

  // Bytes against a `{ length, hashes }` meta entry, when it gives them;
  // throws.
  matchesMeta(bytes: Buffer, meta: any, name: string): void {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering SigstoreTuf.matchesMeta(). " + name);
    if (meta && meta.length !== undefined &&
        Number(meta.length) !== bytes.length) {
      log.debug("Leaving SigstoreTuf.matchesMeta(). Length.");
      // error-code: none — refresh() tags the refresh's failure
      throw new Error(name + ' is ' + bytes.length + ' bytes and its ' +
                      'metadata says ' + meta.length);
    }
    const hashes = (meta && meta.hashes) || {};
    Object.keys(hashes).forEach(function (alg) {
      const got = alg === 'sha256' ? stsCrypto.sha256Hex(bytes)
        : alg === 'sha512' ? stsCrypto.sha512Hex(bytes) : null;
      if (got === null) return;
      if (got !== String(hashes[alg]).toLowerCase()) {
        log.debug("Leaving SigstoreTuf.matchesMeta(). Hash.");
        // error-code: none — refresh() tags the refresh's failure
        throw new Error(name + '\'s ' + alg + ' does not match its metadata');
      }
    });
    log.debug("Leaving SigstoreTuf.matchesMeta().");
  }

  // Whether `a` and `b` name the same keys for `roleName`.
  sameRoleKeys(a: any, b: any, roleName: string): boolean {
    const { log } = this.deps;
    log.debug("Entering SigstoreTuf.sameRoleKeys(). " + roleName);
    const ids = function (root: any) {
      return JSON.stringify((((root.signed || {}).roles || {})[roleName] ||
                             {}).keyids || []);
    };
    log.debug("Leaving SigstoreTuf.sameRoleKeys().");
    return ids(a) === ids(b);
  }

  // ONE REFRESH (see the header). Resolves `{ ok, summary }`; the state is
  // written only on success.
  async refresh(): Promise<{ ok: boolean; summary: string }> {
    const { log, store, errorCodes } = this.deps;
    log.debug("Entering SigstoreTuf.refresh().");
    const off = this.off();
    if (off) {
      log.debug("Leaving SigstoreTuf.refresh(). Off.");
      return { ok: true, summary: 'TUF is off: ' + off };
    }
    let key = '';
    try {
      const first = this.firstRoot();
      key = first.key;
      const held = store.get(key) || null;
      const next = await this.walk(first.root, held);
      store.set(key, next);
      log.debug("Leaving SigstoreTuf.refresh(). Verified.");
      return { ok: true, summary: 'trusted_root.json verified: root v' +
               next.rootVersion + ', timestamp v' + next.timestampVersion +
               ', targets v' + next.targetsVersion };
    } catch (e) {
      log.debug("Caught in SigstoreTuf.refresh(): " + ((e && e.message) || e));
      const why = String((e && e.message) || e);
      if (key) {
        const held = store.get(key);
        if (held) {
          // THE LAST GOOD SET STAYS: only the attempt is recorded on it.
          store.set(key, Object.assign({}, held, {
            lastError: why, lastErrorAt: new Date().toISOString() }));
        }
      }
      log.error(errorCodes.tag('STS-SPIFFE-0131') + 'spiffe: the sigstore ' +
                'TUF refresh failed and the last verified trust root is ' +
                'kept: ' + why);
      log.debug("Leaving SigstoreTuf.refresh(). Failed.");
      return { ok: false, summary: why };
    }
  }

  // The workflow itself; throws on the first failure.
  async walk(firstRoot: any, held: any): Promise<any> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering SigstoreTuf.walk().");
    // 5.2: the first root must hold itself up.
    const trustedFirst = held && held.root ? JSON.parse(held.root) : firstRoot;
    await this.verified(Buffer.from(JSON.stringify(trustedFirst), 'utf8'),
                        trustedFirst, 'root', 'root');
    // 5.3: root rotations.
    let root = trustedFirst;
    for (let i = 0; i < MAX_ROOT_ROTATIONS; i++) {
      const version = Number(root.signed.version) + 1;
      const bytes = await this.get(version + '.root.json');
      if (!bytes) break;
      const byOld = await this.verified(bytes, root, 'root', 'root');
      await this.verified(bytes, byOld, 'root', 'root');
      if (Number(byOld.signed.version) !== version) {
        // error-code: none — refresh() tags the refresh's failure
        throw new Error(version + '.root.json says it is version ' +
                        byOld.signed.version);
      }
      root = byOld;
    }
    this.notExpired(root, 'root');
    let timestampFloor = held ? Number(held.timestampVersion) || 0 : 0;
    let snapshotFloor = held ? Number(held.snapshotVersion) || 0 : 0;
    const targetsFloor = held ? Number(held.targetsVersion) || 0 : 0;
    // 5.3.11: a rotated timestamp or snapshot key forgets the floors.
    if (!this.sameRoleKeys(trustedFirst, root, 'timestamp')) {
      timestampFloor = 0;
      snapshotFloor = 0;
    }
    if (!this.sameRoleKeys(trustedFirst, root, 'snapshot')) {
      snapshotFloor = 0;
    }
    // 5.4: the timestamp.
    const timestampBytes = await this.get('timestamp.json');
    if (!timestampBytes) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error('timestamp.json is missing');
    }
    const timestamp = await this.verified(timestampBytes, root, 'timestamp',
                                          'timestamp');
    if (Number(timestamp.signed.version) < timestampFloor) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error('timestamp.json went back from version ' +
                      timestampFloor + ' to ' + timestamp.signed.version);
    }
    const snapshotMeta = (timestamp.signed.meta || {})['snapshot.json'] || {};
    if (!(Number(snapshotMeta.version) >= snapshotFloor)) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error('the timestamp names snapshot version ' +
                      snapshotMeta.version + ', older than ' + snapshotFloor);
    }
    this.notExpired(timestamp, 'timestamp');
    // 5.5: the snapshot.
    const snapshotName = snapshotMeta.version + '.snapshot.json';
    const snapshotBytes = await this.get(snapshotName);
    if (!snapshotBytes) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error(snapshotName + ' is missing');
    }
    this.matchesMeta(snapshotBytes, snapshotMeta, snapshotName);
    const snapshot = await this.verified(snapshotBytes, root, 'snapshot',
                                         'snapshot');
    if (Number(snapshot.signed.version) !== Number(snapshotMeta.version)) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error(snapshotName + ' says it is version ' +
                      snapshot.signed.version);
    }
    const targetsMeta = (snapshot.signed.meta || {})['targets.json'] || {};
    if (!(Number(targetsMeta.version) >= targetsFloor)) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error('the snapshot names targets version ' +
                      targetsMeta.version + ', older than ' + targetsFloor);
    }
    this.notExpired(snapshot, 'snapshot');
    // 5.6: the targets.
    const targetsName = targetsMeta.version + '.targets.json';
    const targetsBytes = await this.get(targetsName);
    if (!targetsBytes) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error(targetsName + ' is missing');
    }
    this.matchesMeta(targetsBytes, targetsMeta, targetsName);
    const targets = await this.verified(targetsBytes, root, 'targets',
                                        'targets');
    if (Number(targets.signed.version) !== Number(targetsMeta.version)) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error(targetsName + ' says it is version ' +
                      targets.signed.version);
    }
    this.notExpired(targets, 'targets');
    // 5.7: the target.
    const info = (targets.signed.targets || {})[TARGET];
    if (!info || !info.hashes || !info.hashes.sha256) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error(TARGET + ' is not a top-level target with a sha256; ' +
                      'delegated targets are not walked here');
    }
    const targetBytes = await this.get('targets/' +
      String(info.hashes.sha256).toLowerCase() + '.' + TARGET);
    if (!targetBytes) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error('the ' + TARGET + ' target is missing');
    }
    this.matchesMeta(targetBytes, info, TARGET);
    const trusted = JSON.parse(targetBytes.toString('utf8'));
    if (!trusted || !Array.isArray(trusted.certificateAuthorities)) {
      // error-code: none — refresh() tags the refresh's failure
      throw new Error(TARGET + ' is not a sigstore trusted root');
    }
    log.debug("Leaving SigstoreTuf.walk().");
    return {
      root: JSON.stringify(root), rootVersion: Number(root.signed.version),
      timestampVersion: Number(timestamp.signed.version),
      snapshotVersion: Number(snapshot.signed.version),
      targetsVersion: Number(targets.signed.version),
      trustedRoot: targetBytes.toString('utf8'),
      trustedRootSha256: stsCrypto.sha256Hex(targetBytes),
      verifiedAt: new Date().toISOString(), lastError: '', lastErrorAt: ''
    };
  }

  // What GET /spiffe draws.
  state(): any {
    const { log } = this.deps;
    log.debug("Entering SigstoreTuf.state().");
    const held = this.current();
    log.debug("Leaving SigstoreTuf.state().");
    return { off: this.off(), repository: this.repository(),
             verified: !!(held && held.trustedRoot),
             rootVersion: held ? held.rootVersion : 0,
             targetsVersion: held ? held.targetsVersion : 0,
             verifiedAt: held ? held.verifiedAt : '',
             lastError: held ? held.lastError : '',
             lastErrorAt: held ? held.lastErrorAt : '' };
  }

  // THE JOB, registered at load in every process (cluster/CLAUDE.md).
  registerJob(): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SigstoreTuf.registerJob().");
    const scheduler = require('../cluster/scheduler');
    if (scheduler.job(JOB)) {
      log.debug("Leaving SigstoreTuf.registerJob(). Registered.");
      return;
    }
    scheduler.register({
      id: JOB,
      title: 'sigstore TUF refresh',
      describe: 'Fetches the sigstore trust root (Fulcio CAs, Rekor and CT ' +
                'log keys) through TUF for the docker workload attestor\'s ' +
                'image-signature checks; a refresh that fails keeps the last ' +
                'verified set.',
      owner: 'spiffe/spiffe_sigstore_tuf.ts',
      everySetting: 'spiffe.dockerSigstoreTufRefreshS',
      everySettingUnit: 's',
      off: function (): string {
        return self.off();
      },
      manual: true,
      run: function (): Promise<any> {
        return self.refresh().then(function (outcome) {
          if (!outcome.ok) {
            // error-code: none — tagged STS-SPIFFE-0131 by refresh()
            throw new Error(outcome.summary);
          }
          return { summary: outcome.summary };
        });
      }
    });
    log.debug("Leaving SigstoreTuf.registerJob().");
  }
}

const shared = new SigstoreTuf(SigstoreTuf.defaultDeps());
shared.registerJob();

export = {
  SigstoreTuf: SigstoreTuf,
  JOB: JOB,
  shared: shared,
  trustedRoot: (): any => shared.trustedRoot(),
  state: (): any => shared.state(),
  refresh: (): Promise<any> => shared.refresh()
};
