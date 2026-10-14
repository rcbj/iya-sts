// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap/directory_create_claims.ts
//
// ===========================================================================
// ONE CREATE OF A NAME AT A TIME, ACROSS EVERY NODE (2026-09-14, #46 sec. 3).
//
// Every door that creates an entry asks the directory first — `getEntry(dn)`,
// `existingUserEntry(name)` — and a hit is a refusal. In one process that
// check and the write it guards cannot be separated. Across nodes they can:
// two `POST /scim/v2/Users` for `dave`, one to each node, both find nobody,
// both create, both answer 201 with an id — and the flush can keep only one of
// them. `persistence/directory_merge.js` makes the store keep the FIRST and
// replace the second node's copy with it, which is the right repair and the
// wrong answer to have given a client: the id that client was handed names
// nothing.
//
// So a door that can wait claims what it is about to create BEFORE it asks the
// directory: the DN, and the username for a person, through
// `cluster/cluster_claims.js` — one atomic statement against every node. The
// second of two concurrent creates WAITS for the first to finish (see
// `CLAIM_WAIT_MS`) and then meets the directory's own "already exists", and is
// refused as in progress (`STS-LDAP-0092`: LDAP 68, HTTP 409) only when the
// first is still holding the name when the wait runs out. A store that cannot
// be asked refuses at once (`STS-LDAP-0093`), which is that module's
// fail-closed rule.
//
// **THE CLAIM GUARDS THE WINDOW AND NOTHING LONGER.** Once the create has
// committed every node sees the entry — the winner of the next claim catches up
// with the store before its door looks — and the ordinary check refuses a
// duplicate. So a claim is released as soon as the write it guards has been
// flushed, and a refused or failed create releases it at once: a person deleted
// and created again a moment later must not be refused by the claim of their
// first life. The lifetime below is only the ceiling for a process that dies
// holding one.
//
// **ONLY WHERE SEVERAL PROCESSES WRITE ONE STORE** — active-active, or request
// workers dispatched against a shared store. Anywhere else the directory
// check is already atomic, and a round trip per create would slow every bulk
// load for nothing.
//
// **AND DECIDED BY WHOEVER CAN SEE EVERY WRITER (#628, 2026-10-14).** Where
// the only other writers are this node's own request workers — the cluster
// `off` or `active-passive` — the node's FRONT PROCESS decides, in memory,
// over the worker channel (`directory_create_arbiter.ts`), and a create's
// claim costs the database nothing. Where other NODES write too —
// `active-active` — the store decides, and it costs ONE statement: the DN and
// the username claimed together, all or none (`cluster_claims.claimMany()`),
// given back by a statement of the very flush transaction that writes the
// entry (`persistence.js`, `releaseClaimsAtCommit()`). It was four: two
// claims and two deletes, each its own transaction. `arbitratedHere()`
// argues the line; the arbiter's header lists the rules both paths keep.
//
// The doors: an LDAP add (`ldap_server.js`, at registration), a SCIM create
// (`scim/scim.ts`), `POST /admin-api/users/create` and
// `/admin-api/groups/create` — and since 2026-09-14 a SCIM Bulk create
// (claimed in the ingress, which scimmy awaits, for an operation the create
// handler did not already claim) and the console's own forms, `POST
// /admin/users` and `/admin/users/new` with `action=create` and `POST
// /admin/groups` with `action=create`, through `runClaimed()` below.
//
// **AN ENTRY CREATED BY A SIGN-IN IS STILL NOT CLAIMED, AND THE REASON IS NOT
// THE ONE THIS HEADER USED TO GIVE.** It said a sign-in creates "the SAME
// person by name on both nodes, and the flush's merge makes it one entry".
// Since a person's `sub` became `urn:uuid:<entryUUID>` (2026-09-14) that is
// only half true: the merge keeps the FIRST committed entry (`STS-STORE-0052`),
// and the node whose copy lost has already issued a session and tokens naming
// ITS entryUUID — a subject that names nobody. What keeps it unclaimed is the
// shape of the path: `ldap_server.js`'s `autoCreateUser()` is
// `admin_stats.recordAuthentication()`'s synchronous observer, reached from
// inside every protocol's credential check, and a claim is a round trip that
// path cannot await without making every one of those handlers asynchronous
// first. It is DEVELOPMENT MODE only (`mode.autoCreates()` is false in
// product), and reachable with several processes only in a development dispatch
// run or a development active-active cluster. **RESOLVED 2026-09-14 BY rcbj'S
// CHOICE: THE ENTRY'S entryUUID IS NAME-DERIVED THERE.** `ldap_server.js`'s
// `putEntry()` gives an entry created by a sign-in (`origin: 'authentication'`)
// the seed's version 5 value over the realm and the DN whenever another process
// can race — a cluster mode, or a dispatched pool — so both create the SAME
// entry and the merge makes them one. A person deleted and signed in again
// under the same name gets the same subject there; a single process keeps
// random values. `tests/cluster_autocreate_subject.js` holds both halves.
//
// A LIBRARY (rule 3): it registers no route. `persistence.js` and
// `cluster_claims.js` are reached lazily inside the calls.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `DirectoryCreateClaims` takes the logger, the settings, the error
// codes, the cluster's claims and mode, and LOADERS for the persistence store
// and a loaded `ldap_server.js` through its constructor, so both stay as lazy
// as they were. The module still exports `active`, `claim`, `claimFor`,
// `runClaimed`, `refusalMessage`, `CLAIM_TTL_MS` and `CLAIM_WAIT_MS`, for the
// unconverted modules that require it (`ldap/ldap_server.js`, `scim/`, the
// console and the management API). Since #50's R2 the composition root builds
// the instance (`DirectoryCreateClaims.defaultDeps()`) and installs it; the
// module's old export names are FACADES that forward to it, for the JavaScript
// callers, and a process without the root builds a default when this module
// finishes loading. `DirectoryCreateClaims` is exported beside them for the
// composition root.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import claims = require('../cluster/cluster_claims');
import cluster = require('../cluster/cluster');
import InstanceSlot = require('../common/instance_slot');

const log = bunyan.createLogger({ name: 'sts-directory-create-claims' });
config.registerLogger(log);

// One value to claim.
interface Wanted {
  scope: 'directory.dn' | 'directory.username';
  value: string;
}

// What `claim()` is asked.
interface ClaimSpec {
  realm?: string;
  dns?: string[];
  usernames?: string[];
  waitMs?: number;
}

// A claim held, or refused. `settle` is present on a held one, and answers a
// promise of whether the claim went back (`{ released, error }`); `catchUp`
// says whether the winner must pull the store before its door looks.
interface HeldClaim {
  ok: boolean;
  settle?: (succeeded?: boolean) => any;
  catchUp?: boolean;
  // Called once the catch-up has finished (one node: the front process is
  // told, so the next create in this process need not pull again).
  caughtUp?: () => void;
  reason?: string;
  code?: string;
  what?: string;
  whatKind?: string;
  index?: number;
}

// The front process's arbitration on one node (`directory_create_arbiter.ts`),
// as much of it as this module uses.
interface CreateArbiter {
  ask(keys: string[], ttlMs: number): Promise<{
    ok: boolean; reservation?: string; catchUp?: boolean; through?: number;
    reason?: string; index?: number; code?: string;
  }>;
  give(reservation: string, keys: string[], committed: boolean): void;
  caughtUp(through: number): void;
}

// The parts of the persistence store this module uses.
interface ClaimsPersistence {
  clusterStore(): unknown;
  syncNow(): unknown;
  flush(): unknown;
}

// The part of `ldap_server.js` `claimFor()` uses.
interface ClaimingDirectory {
  claimCreate?: (what: unknown) => Promise<HeldClaim>;
}

interface DirectoryCreateClaimsDeps {
  log: {
    debug(message: string): void;
    info(message: string): void;
    warn(message: string): void;
  };
  config: { value(key: string): unknown };
  errorCodes: { tag(code: string): string };
  claims: {
    claimMany(spec: object): Promise<any>;
    releaseMany(handles: unknown[]): Promise<any>;
    releaseAtCommit(handles: unknown[]): Promise<any>;
  };
  isActiveActive(): boolean;
  // `cluster/cluster.js`'s mode: 'off', 'active-passive' or 'active-active'.
  clusterMode(): string;
  // LAZY: the arbiter on one node (#628), required at the first claim.
  loadArbiter(): CreateArbiter;
  // LAZY: see `persistence()`.
  loadPersistence(): ClaimsPersistence;
  // A LOADED `ldap_server.js`, or null: see `claimFor()`.
  loadedDirectory(): ClaimingDirectory | null;
}

/**
 * One create of a directory name at a time across every node: a door that
 * creates an entry claims its DN (and a person's username) through the
 * cluster's claim store before it asks the directory, and releases the claim
 * once the write is flushed.
 *
 * It is active only where several processes write one store.
 */
class DirectoryCreateClaims {
  // The ceiling on a claim a process died holding. A create's flush commits
  // in milliseconds; two minutes is long past every barrier and every retry.
  /**
   * The ceiling on a claim a process died holding: two minutes.
   */
  static readonly CLAIM_TTL_MS = 2 * 60 * 1000;

  // -------------------------------------------------------------------------
  // A CREATE THAT FINDS ITS NAME CLAIMED WAITS, AND ASKS AGAIN (2026-09-15).
  // A claim is released AFTER its create's flush and its response, so for a
  // few tens of milliseconds after a 200 the name is still claimed — and the
  // SAME client's next create of that name, sequential rather than
  // concurrent, was refused 409 "being created by another request" where it
  // should have been told the entry exists. `sts_admin_api_operations` met
  // exactly that in a dispatch run: its create, then its duplicate 70ms later
  // on the same worker.
  //
  // Answering the first create only after its release fixed it and cost every
  // create in a multi-process service a store commit before it answered —
  // /admin-api creates went from 11ms to 37ms in the bulk load, three times
  // slower, to spare a cost that only a COLLISION should pay. So the cost
  // moved to the collision: a refused claim gives back what it holds, waits
  // `CLAIM_RETRY_MS`, and claims again until `CLAIM_WAIT_MS` has passed. The
  // holder commits and releases; the waiter wins, catches up with the store
  // below, and its door refuses the duplicate by its own check — or, if the
  // holder's create failed, creates the entry itself. Only a name still held
  // when the wait runs out is refused as in progress. A store that cannot be
  // asked is not waited on.
  // -------------------------------------------------------------------------
  /**
   * How long a create that finds its name claimed waits and asks again before
   * it is refused as in progress: five seconds.
   */
  static readonly CLAIM_WAIT_MS = 5000;
  /**
   * How long a waiting create sleeps between attempts: 50 ms.
   */
  static readonly CLAIM_RETRY_MS = 50;

  /**
   * Builds the claimer from its dependencies.
   *
   * @param deps - the modules and loaders it reads, from
   * `DirectoryCreateClaims.defaultDeps()` or the composition root
   */
  constructor(private readonly deps: DirectoryCreateClaimsDeps) {
    deps.log.debug("Entering DirectoryCreateClaims.constructor().");
    deps.log.debug("Leaving DirectoryCreateClaims.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the real modules and loaders the claimer depends on, as the
   * composition root passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): DirectoryCreateClaimsDeps {
    log.debug("Entering DirectoryCreateClaims.defaultDeps().");
    log.debug("Leaving DirectoryCreateClaims.defaultDeps().");
    return {
      log: log,
      config: config,
      errorCodes: errorCodes,
      claims: claims,
      isActiveActive: function () {
        return cluster.isActiveActive();
      },
      clusterMode: function () {
        return String(cluster.mode() || '');
      },
      loadPersistence: DirectoryCreateClaims.persistenceModule,
      loadedDirectory: DirectoryCreateClaims.cachedDirectory,
      loadArbiter: DirectoryCreateClaims.arbiterModule
    };
  }

  // The default `loadArbiter`, passed by `defaultDeps()`.
  /**
   * Returns this process's arbiter of one node's create claims, required
   * lazily; the default `loadArbiter`.
   *
   * @returns the arbiter
   */
  static arbiterModule(): CreateArbiter {
    log.debug("Entering DirectoryCreateClaims.arbiterModule().");
    log.debug("Leaving DirectoryCreateClaims.arbiterModule().");
    return require('./directory_create_arbiter').arbiter;
  }

  // The default `loadPersistence`, passed by `defaultDeps()`.
  /**
   * Returns the persistence module, required lazily; the default
   * `loadPersistence`.
   *
   * @returns the persistence module
   */
  static persistenceModule(): ClaimsPersistence {
    log.debug("Entering DirectoryCreateClaims.persistenceModule().");
    log.debug("Leaving DirectoryCreateClaims.persistenceModule().");
    // LAZY: this module is required by `ldap_server.js`, which the require
    // order loads far below `persistence.js` (#4a), and the value is only
    // wanted inside a request.
    return require('../persistence/persistence');
  }

  // The default `loadedDirectory`, passed by `defaultDeps()`: the
  // directory module from the require CACHE, never required from here (see
  // `claimFor()`).
  /**
   * Returns `ldap_server.js` from the require cache without loading it; the
   * default `loadedDirectory`.
   *
   * @returns the directory module, or null when it is not loaded
   */
  static cachedDirectory(): ClaimingDirectory | null {
    log.debug("Entering DirectoryCreateClaims.cachedDirectory().");
    let directory: ClaimingDirectory | null = null;
    try {
      const cached = require.cache[require.resolve('./ldap_server')];
      directory = cached && cached.loaded ? cached.exports : null;
    } catch (e) {
      log.debug("Caught in DirectoryCreateClaims.cachedDirectory(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving DirectoryCreateClaims.cachedDirectory().");
    return directory;
  }

  private persistence(): ClaimsPersistence {
    const { log, loadPersistence } = this.deps;
    log.debug("Entering DirectoryCreateClaims.persistence().");
    log.debug("Leaving DirectoryCreateClaims.persistence().");
    return loadPersistence();
  }

  // Whether a create has anything to race here. See the header.
  /**
   * Says whether a create has anything to race here: a shared store, and an
   * active-active cluster or dispatched request workers.
   *
   * @returns true when creates are claimed
   */
  active(): boolean {
    const { log, config, isActiveActive } = this.deps;
    log.debug("Entering DirectoryCreateClaims.active().");
    if (!this.persistence().clusterStore()) {
      log.debug("Leaving DirectoryCreateClaims.active(). No shared store.");
      return false;
    }
    const dispatched =
      // The #364 rule: the default of one worker is none without a store
      // that coordinates.
      require('../common/process_memory').requestWorkers() > 0 &&
      String(config.value('workers.dispatch') || '').trim() !== '';
    log.debug("Leaving DirectoryCreateClaims.active().");
    return isActiveActive() || dispatched;
  }

  // -------------------------------------------------------------------------
  // WHICH ARBITER: THE STORE, OR THIS NODE'S FRONT PROCESS (#628, 2026-10-14).
  //
  // The claim exists for the writers of one store. Which writers those can be
  // is the cluster mode's to say, and only `active-active` lets another NODE
  // write while this one does:
  //
  // * `active-active` — every node writes; the store decides, one statement
  //   per claim (`cluster_claims.claimMany()`), released in the flush that
  //   commits the create.
  // * `active-passive` — one node serves at a time, and a standby has bound
  //   nothing and restored nothing until it holds the service lease; a node
  //   that lost the lease cannot commit (the fence is checked inside every
  //   write transaction). So the only concurrent writers are this node's own
  //   processes.
  // * `off` — one container, by definition: `cluster/cluster.js` says at
  //   start that the change log alone is "correct for one container and NOT
  //   for several", and two containers on one store with the cluster off
  //   already get no claim at all unless they dispatch, and none of the
  //   barrier, the fence or the agreement. So, again, this node's processes.
  //
  // So everything but `active-active` is decided by the front process in
  // memory (`directory_create_arbiter.ts`), and `active-active` by the store.
  // A mode this module does not know is the store's: unsure is the store.
  // -------------------------------------------------------------------------
  /**
   * Says whether this node's own front process decides its create claims
   * (one node: cluster `off` or `active-passive`) rather than the store
   * (`active-active`, where other nodes write too).
   *
   * @returns true when the front process arbitrates
   */
  arbitratedHere(): boolean {
    const { log, isActiveActive, clusterMode } = this.deps;
    log.debug("Entering DirectoryCreateClaims.arbitratedHere().");
    const mode = clusterMode();
    const here = !isActiveActive() &&
      (mode === 'off' || mode === 'active-passive');
    log.debug("Leaving DirectoryCreateClaims.arbitratedHere(). " +
              (here ? 'The front process.' : 'The store.'));
    return here;
  }

  // -------------------------------------------------------------------------
  // claim({ realm, dns, usernames }) -> Promise of
  //   { ok: true, settle(succeeded), catchUp }
  //   { ok: false, reason: 'used' | 'store', code, what }
  //
  // `dns` are NORMALISED DNs and `usernames` are lower-cased; both are the
  // caller's to compute, because deciding what a DN and a username are is
  // `ldap_server.js`'s job. Every value is claimed or none is (#628: in one
  // statement, or one decision of the front process). `settle(true)` gives
  // the claim back once the write has committed — in the very transaction
  // that commits it, on the store — and `settle(false)` gives it back now. A
  // value another request holds is waited for — `waitMs`, `CLAIM_WAIT_MS` by
  // default, which only a test passes — before `used` is answered.
  // -------------------------------------------------------------------------
  /**
   * Claims every DN and username a create is about to write, all or none,
   * waiting up to `waitMs` for a value another request holds.
   *
   * @param spec - `realm`, `dns` (normalised), `usernames` (lower-cased) and
   * `waitMs` (default `CLAIM_WAIT_MS`, for tests)
   * @returns a promise of `{ ok: true, settle(succeeded), catchUp }`, where
   * `settle(true)` releases once the write has committed and
   * `settle(false)` at once, or `{ ok: false, reason: 'used' | 'store',
   * code, what }`
   */
  claim(spec?: ClaimSpec): Promise<HeldClaim> {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering DirectoryCreateClaims.claim().");
    const o: ClaimSpec = spec || {};
    const wanted: Wanted[] = [];
    (o.dns || []).forEach(function (dn) {
      const value = dn ? String(dn) : '';
      if (value && !wanted.some(function (one) {
        return one.scope === 'directory.dn' && one.value === value;
      })) {
        wanted.push({ scope: 'directory.dn', value: value });
      }
    });
    (o.usernames || []).forEach(function (name) {
      const value = String(name == null ? '' : name).trim().toLowerCase();
      if (value && !wanted.some(function (one) {
        return one.scope === 'directory.username' && one.value === value;
      })) {
        wanted.push({ scope: 'directory.username', value: value });
      }
    });
    if (!wanted.length || !this.active()) {
      log.debug("Leaving DirectoryCreateClaims.claim(). Nothing to claim " +
                "here.");
      return Promise.resolve({ ok: true, settle: function () {} });
    }
    const realm = String(o.realm || '');
    const here = this.arbitratedHere();
    const waitMs = o.waitMs === undefined
      ? DirectoryCreateClaims.CLAIM_WAIT_MS
      : Math.max(0, Number(o.waitMs) || 0);
    const deadline = Date.now() + waitMs;
    let attempts = 0;
    const attempt = function (): Promise<HeldClaim> {
      attempts += 1;
      return (here ? self.claimHere(wanted, realm)
        : self.claimInStore(wanted, realm)).then(function (answer) {
        if (answer.ok || answer.reason === 'store' ||
            Date.now() >= deadline) {
          return answer;
        }
        log.debug("claim(): " + answer.what + " is claimed; asking again " +
                  "in " + DirectoryCreateClaims.CLAIM_RETRY_MS +
                  "ms (attempt " + attempts + ").");
        return new Promise(function (resolve) {
          setTimeout(resolve, DirectoryCreateClaims.CLAIM_RETRY_MS);
        }).then(attempt);
      });
    };
    log.debug("Leaving DirectoryCreateClaims.claim(). Asking " +
              (here ? 'the front process' : 'the store') + " for " +
              wanted.length + ".");
    return attempt().then(function (answer): HeldClaim | Promise<HeldClaim> {
      if (!answer.ok) {
        log.info(errorCodes.tag(answer.code) + 'ldap: a create of ' +
                 answer.whatKind + answer.what + ' was refused: ' +
                 (answer.reason === 'store'
                   ? 'whether it is already being created elsewhere could ' +
                     'not be decided.'
                   : 'another request was still creating it after ' +
                     waitMs + 'ms and ' + attempts + ' attempt(s).'));
        return { ok: false, reason: answer.reason, code: answer.code,
                 what: answer.what };
      }
      // ---------------------------------------------------------------------
      // AND CAUGHT UP BEFORE THE DOOR LOOKS. A claim held by a create that
      // has since committed is released at once, so a request that arrived
      // before that commit — whose barrier therefore did not wait for it —
      // could win the claim a moment later and then ask a directory that does
      // not hold the entry yet. Catching up after the claim closes that:
      // whoever held it committed before releasing, so the door's own check
      // now sees the entry and refuses the duplicate. A catch-up that fails is
      // not a refusal; the flush's merge still keeps the first add.
      //
      // **ONLY WHEN IT HAS TO, ON ONE NODE (#628).** The store's claim cannot
      // say who held a row it deleted, so every winner there pulls. The front
      // process remembers which holder last committed a create of each key,
      // and says `catchUp` only to a winner that has not pulled since — the
      // pull a read barrier would make in that worker, made here because the
      // barrier runs only with `workers.readYourWrite` on.
      // ---------------------------------------------------------------------
      if (!answer.catchUp) {
        return answer;
      }
      return Promise.resolve().then(function () {
        return self.persistence().syncNow();
      }).then(function () {
        if (answer.caughtUp) {
          answer.caughtUp();
        }
      }, function (e) {
        // NOT REPORTED AS CAUGHT UP: the next create here pulls again.
        log.debug("Caught in DirectoryCreateClaims.claim(): " +
                  ((e && e.message) || e));
      }).then(function () {
        return answer;
      });
    });
  }

  // The refusal of one attempt: `one` is the value somebody else holds.
  private refusal(reason: string | undefined, one: Wanted | undefined,
                  code?: string): HeldClaim {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateClaims.refusal().");
    const store = reason === 'store';
    const what = one || { scope: 'directory.dn', value: '' };
    log.debug("Leaving DirectoryCreateClaims.refusal().");
    return { ok: false, reason: store ? 'store' : 'used',
             code: code || (store ? 'STS-LDAP-0093' : 'STS-LDAP-0092'),
             what: what.value,
             whatKind: what.scope === 'directory.dn' ? 'the DN '
               : 'the username ' };
  }

  // A held claim: `release(succeeded)` gives it back, once whatever the
  // caller settles it with — the first settle decides.
  private granted(catchUp: boolean,
                  release: (succeeded: boolean) => Promise<any>): HeldClaim {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateClaims.granted().");
    let settled: Promise<any> | null = null;
    log.debug("Leaving DirectoryCreateClaims.granted().");
    return {
      ok: true,
      catchUp: catchUp,
      settle: function (succeeded) {
        log.debug("Entering settle().");
        if (settled) {
          log.debug("Leaving settle(). Already settled.");
          return settled;
        }
        settled = Promise.resolve().then(function () {
          return release(!!succeeded);
        }).catch(function (e) {
          log.debug("Caught in settle(): " + ((e && e.message) || e));
          return { released: false, error: (e && e.message) || String(e) };
        });
        log.debug("Leaving settle(). " +
                  (succeeded ? 'Released at the commit.' : 'Released now.'));
        return settled;
      }
    };
  }

  // -------------------------------------------------------------------------
  // ONE ATTEMPT IN THE STORE (active-active): every value in ONE statement,
  // all or none (#628, `cluster_claims.claimMany()`). Given back at the
  // commit — in the transaction that writes the entry, where this process
  // writes it — or now; and the winner always catches up, since a deleted
  // row cannot say who held it.
  // -------------------------------------------------------------------------
  private claimInStore(wanted: Wanted[], realm: string): Promise<HeldClaim> {
    const self = this;
    const { log, claims } = this.deps;
    log.debug("Entering DirectoryCreateClaims.claimInStore().");
    log.debug("Leaving DirectoryCreateClaims.claimInStore().");
    return claims.claimMany({
      entries: wanted.map(function (one) {
        return { scope: one.scope, value: one.value };
      }),
      realm: realm,
      ttlMs: DirectoryCreateClaims.CLAIM_TTL_MS
    }).then(function (answer): HeldClaim {
      if (!answer || !answer.ok) {
        return self.refusal(answer && answer.reason,
                            wanted[Number(answer && answer.index) || 0]);
      }
      const handles = answer.handles || [];
      return self.granted(true, function (succeeded) {
        // AFTER THE WRITE IS IN THE STORE. Where this process wrote it, that
        // is the flush transaction itself; where it has committed already —
        // a door that answers after its commit, or a dispatched worker that
        // committed before its answer reached this process — one statement
        // of its own.
        return succeeded ? claims.releaseAtCommit(handles)
          : claims.releaseMany(handles).then(function (count) {
            return { released: Number(count) > 0 };
          });
      });
    });
  }

  // -------------------------------------------------------------------------
  // ONE ATTEMPT ON ONE NODE: the front process decides, in memory
  // (`directory_create_arbiter.ts`). Given back after this process's flush
  // has committed — a flush that fails keeps it until it expires, as a
  // rolled-back release does in the store — or now.
  // -------------------------------------------------------------------------
  private claimHere(wanted: Wanted[], realm: string): Promise<HeldClaim> {
    const self = this;
    const { log, errorCodes, loadArbiter } = this.deps;
    log.debug("Entering DirectoryCreateClaims.claimHere().");
    const arbiter = loadArbiter();
    const keys = wanted.map(function (one) {
      return realm + '\u0000' + one.scope + '\u0000' + one.value;
    });
    log.debug("Leaving DirectoryCreateClaims.claimHere().");
    return arbiter.ask(keys, DirectoryCreateClaims.CLAIM_TTL_MS)
      .then(function (answer): HeldClaim {
        if (!answer || !answer.ok) {
          return self.refusal(answer && answer.reason,
                              wanted[Number(answer && answer.index) || 0],
                              answer && answer.code);
        }
        const reservation = String(answer.reservation);
        const through = Number(answer.through) || 0;
        const held = self.granted(!!answer.catchUp, function (succeeded) {
          if (!succeeded) {
            arbiter.give(reservation, keys, false);
            return Promise.resolve({ released: true });
          }
          return Promise.resolve().then(function () {
            return self.persistence().flush();
          }).then(function (result: any) {
            if (result && result.error) {
              log.warn(errorCodes.tag('STS-CLUSTER-0164') + 'ldap: the ' +
                       'flush after a create failed, so its claim stays ' +
                       'held until it expires; a create of the same name ' +
                       'before then waits and is refused as in progress ' +
                       '(STS-LDAP-0092).');
              return { released: false, error: result.error };
            }
            arbiter.give(reservation, keys, true);
            return { released: true };
          });
        });
        if (held.catchUp) {
          held.caughtUp = function () {
            arbiter.caughtUp(through);
          };
        }
        return held;
      });
  }

  // -------------------------------------------------------------------------
  // THE CLAIM FOR A DOOR THAT DOES NOT HOLD THE DIRECTORY MODULE. `what` is
  // `{ username }` or `{ group }`; `ldap_server.js`'s `claimCreate()` turns
  // it into DNs and names. It is looked up in the require CACHE and never
  // required from here — it registers routes, and the console that calls this
  // is above it in the route order — and a process that never loaded it has
  // no directory to race for.
  // -------------------------------------------------------------------------
  /**
   * Claims a create for a door that does not hold the directory module, through
   * `ldap_server.js`'s `claimCreate()`; where the directory is not loaded,
   * answers a claim that holds nothing.
   *
   * @param what - `{ username }` or `{ group }`
   * @returns a promise of the claim, as `claim()` answers it
   */
  claimFor(what: unknown): Promise<HeldClaim> {
    const { log, loadedDirectory } = this.deps;
    log.debug("Entering DirectoryCreateClaims.claimFor().");
    const directory = loadedDirectory();
    if (!directory || typeof directory.claimCreate !== 'function') {
      log.debug("Leaving DirectoryCreateClaims.claimFor(). No directory in " +
                "this process.");
      return Promise.resolve({ ok: true, settle: function () {} });
    }
    log.debug("Leaving DirectoryCreateClaims.claimFor().");
    return directory.claimCreate(what);
  }

  // -------------------------------------------------------------------------
  // RUN A CREATE WITH ITS NAME CLAIMED, for a door whose handler was
  // synchronous. Where nothing can race (`what` null, or `active()` false —
  // every single-process service) `run` is called SYNCHRONOUSLY with an idle
  // claim, exactly as the handler behaved before. Otherwise the claim is
  // awaited: a refusal goes to `refuse(held)`, and `run(held)` must settle it
  // with the outcome. A throw out of `run` settles it as failed and is handed
  // on to `onThrow(e)`, which the caller answers in its own shape.
  // -------------------------------------------------------------------------
  /**
   * Runs a create with its name claimed. Where nothing can race, `run` is
   * called synchronously with an idle claim; otherwise the claim is awaited, a
   * refusal goes to `refuse`, and `run` must settle the claim.
   *
   * @param what - `{ username }` or `{ group }`, or null for no claim
   * @param run - the create, handed the claim
   * @param refuse - answers a refused claim
   * @param onThrow - answers a throw out of `run`, after the claim is settled
   * as failed
   * @returns what `run` or `refuse` returns, or a promise of it
   */
  runClaimed(what: unknown, run: (held: HeldClaim) => any,
             refuse: (held: HeldClaim) => any,
             onThrow: (e: any) => any): any {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateClaims.runClaimed().");
    const idle: HeldClaim = { ok: true, settle: function () {} };
    if (!what || !this.active()) {
      log.debug("Leaving DirectoryCreateClaims.runClaimed(). Nothing to " +
                "claim.");
      return run(idle);
    }
    log.debug("Leaving DirectoryCreateClaims.runClaimed(). Claiming first.");
    return this.claimFor(what).then(function (held) {
      if (!held.ok) {
        return refuse(held);
      }
      try {
        return run(held);
      } catch (e) {
        log.debug("Caught in DirectoryCreateClaims.runClaimed(): " +
                  ((e && e.message) || e));
        held.settle(false);
        return onThrow(e);
      }
    });
  }

  // The sentence a refusal carries to a client, for the doors that are not
  // LDAP.
  /**
   * Returns the sentence a refused claim carries to a client that is not LDAP.
   *
   * @param refusal - the refused claim's `reason` and `what`
   * @returns the sentence
   */
  refusalMessage(refusal: { reason?: string; what?: string }): string {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateClaims.refusalMessage().");
    log.debug("Leaving DirectoryCreateClaims.refusalMessage().");
    return refusal.reason === 'store'
      ? 'This service could not confirm that "' + refusal.what + '" is not ' +
        'being created by another request at this moment, so it was not ' +
        'created. Try again.'
      : '"' + refusal.what + '" is being created by another request at this ' +
        'moment. One entry per name: it was not created twice.';
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DirectoryCreateClaims>(
  'ldap/directory_create_claims',
  () => new DirectoryCreateClaims(DirectoryCreateClaims.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * One create of a directory name at a time across every node.
 *
 * Exports the `DirectoryCreateClaims` class, its constants, and facades that
 * forward to the installed instance.
 *
 * @namespace
 */
export = {
  DirectoryCreateClaims: DirectoryCreateClaims,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: DirectoryCreateClaims): void =>
    slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  active: slot.forward('active'),
  claim: slot.forward('claim'),
  claimFor: slot.forward('claimFor'),
  runClaimed: slot.forward('runClaimed'),
  refusalMessage: slot.forward('refusalMessage'),
  CLAIM_TTL_MS: DirectoryCreateClaims.CLAIM_TTL_MS,
  CLAIM_WAIT_MS: DirectoryCreateClaims.CLAIM_WAIT_MS
};
