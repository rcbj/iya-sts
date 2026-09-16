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
// `runClaimed`, `refusalMessage`, `CLAIM_TTL_MS` and `CLAIM_WAIT_MS` from a
// TRANSITIONAL instance for the unconverted modules that require it
// (`ldap/ldap_server.js`, `scim/`, the console and the management API).
// `DirectoryCreateClaims` is exported beside them for the composition root.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import claims = require('../cluster/cluster_claims');
import cluster = require('../cluster/cluster');

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

// A claim held, or refused. `settle` is present on a held one.
interface HeldClaim {
  ok: boolean;
  settle?: (succeeded?: boolean) => void;
  reason?: string;
  code?: string;
  what?: string;
  whatKind?: string;
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
  };
  config: { value(key: string): unknown };
  errorCodes: { tag(code: string): string };
  claims: {
    claim(spec: object): Promise<any>;
    release(handle: unknown): unknown;
  };
  isActiveActive(): boolean;
  // LAZY: see `persistence()`.
  loadPersistence(): ClaimsPersistence;
  // A LOADED `ldap_server.js`, or null: see `claimFor()`.
  loadedDirectory(): ClaimingDirectory | null;
}

class DirectoryCreateClaims {
  // The ceiling on a claim a process died holding. A create's flush commits
  // in milliseconds; two minutes is long past every barrier and every retry.
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
  static readonly CLAIM_WAIT_MS = 5000;
  static readonly CLAIM_RETRY_MS = 50;

  constructor(private readonly deps: DirectoryCreateClaimsDeps) {
    deps.log.debug("Entering DirectoryCreateClaims.constructor().");
    deps.log.debug("Leaving DirectoryCreateClaims.constructor().");
  }

  // The default `loadPersistence` for the transitional instance.
  static persistenceModule(): ClaimsPersistence {
    log.debug("Entering DirectoryCreateClaims.persistenceModule().");
    log.debug("Leaving DirectoryCreateClaims.persistenceModule().");
    // LAZY: this module is required by `ldap_server.js`, which the require
    // order loads far below `persistence.js` (#4a), and the value is only
    // wanted inside a request.
    return require('../persistence/persistence');
  }

  // The default `loadedDirectory` for the transitional instance: the
  // directory module from the require CACHE, never required from here (see
  // `claimFor()`).
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
  active(): boolean {
    const { log, config, isActiveActive } = this.deps;
    log.debug("Entering DirectoryCreateClaims.active().");
    if (!this.persistence().clusterStore()) {
      log.debug("Leaving DirectoryCreateClaims.active(). No shared store.");
      return false;
    }
    const dispatched =
      (Number(config.value('workers.requestCount')) || 0) > 0 &&
      String(config.value('workers.dispatch') || '').trim() !== '';
    log.debug("Leaving DirectoryCreateClaims.active().");
    return isActiveActive() || dispatched;
  }

  // -------------------------------------------------------------------------
  // claim({ realm, dns, usernames }) -> Promise of
  //   { ok: true, settle(succeeded) }
  //   { ok: false, reason: 'used' | 'store', code, what }
  //
  // `dns` are NORMALISED DNs and `usernames` are lower-cased; both are the
  // caller's to compute, because deciding what a DN and a username are is
  // `ldap_server.js`'s job. Every value is claimed or none is: a partial set
  // is given back before the refusal is answered. `settle(true)` releases
  // once the write has been flushed; `settle(false)` releases now. A value
  // another request holds is waited for — `waitMs`, `CLAIM_WAIT_MS` by
  // default, which only a test passes — before `used` is answered.
  // -------------------------------------------------------------------------
  claim(spec?: ClaimSpec): Promise<HeldClaim> {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering DirectoryCreateClaims.claim().");
    const o: ClaimSpec = spec || {};
    const wanted: Wanted[] = [];
    (o.dns || []).forEach(function (dn) {
      if (dn) {
        wanted.push({ scope: 'directory.dn', value: String(dn) });
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
    const waitMs = o.waitMs === undefined
      ? DirectoryCreateClaims.CLAIM_WAIT_MS
      : Math.max(0, Number(o.waitMs) || 0);
    const deadline = Date.now() + waitMs;
    let attempts = 0;
    const attempt = function (): Promise<HeldClaim> {
      attempts += 1;
      return self.claimAll(wanted, realm).then(function (answer) {
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
    log.debug("Leaving DirectoryCreateClaims.claim(). Asking for " +
              wanted.length + ".");
    return attempt().then(function (answer): HeldClaim | Promise<HeldClaim> {
      if (!answer.ok) {
        log.info(errorCodes.tag(answer.code) + 'ldap: a create of ' +
                 answer.whatKind + answer.what + ' was refused: ' +
                 (answer.reason === 'store'
                   ? 'the store that decides whether it is already being ' +
                     'created elsewhere could not be asked.'
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
      // ---------------------------------------------------------------------
      return Promise.resolve().then(function () {
        return self.persistence().syncNow();
      }).catch(function (e) {
        log.debug("Caught in DirectoryCreateClaims.claim(): " +
                  ((e && e.message) || e));
      }).then(function () {
        return answer;
      });
    });
  }

  // One attempt at every value in `wanted`: all of them held, or none (a
  // partial set is given back) and the first refusal described.
  private claimAll(wanted: Wanted[], realm: string): Promise<HeldClaim> {
    const self = this;
    const { log, claims } = this.deps;
    log.debug("Entering DirectoryCreateClaims.claimAll().");
    log.debug("Leaving DirectoryCreateClaims.claimAll().");
    return Promise.all(wanted.map(function (one) {
      return claims.claim({ scope: one.scope, value: one.value,
                            realm: realm,
                            ttlMs: DirectoryCreateClaims.CLAIM_TTL_MS })
        .then(function (answer) {
          return { one: one, answer: answer };
        });
    })).then(function (answers): HeldClaim {
      const held = answers.filter(function (row) {
        return row.answer.ok;
      }).map(function (row) {
        return row.answer.handle;
      });
      const releaseAll = function () {
        held.forEach(function (handle) {
          claims.release(handle);
        });
      };
      const refused = answers.find(function (row) {
        return !row.answer.ok;
      });
      if (refused) {
        releaseAll();
        const store = refused.answer.reason === 'store';
        return { ok: false, reason: refused.answer.reason,
                 code: store ? 'STS-LDAP-0093' : 'STS-LDAP-0092',
                 what: refused.one.value,
                 whatKind: refused.one.scope === 'directory.dn' ? 'the DN '
                   : 'the username ' };
      }
      let settled = false;
      const granted: HeldClaim = {
        ok: true,
        settle: function (succeeded) {
          log.debug("Entering settle().");
          if (settled) {
            log.debug("Leaving settle(). Already settled.");
            return;
          }
          settled = true;
          if (!succeeded) {
            releaseAll();
            log.debug("Leaving settle(). Released at once.");
            return;
          }
          // AFTER THE WRITE IS IN THE STORE. A flush with nothing dirty
          // resolves at once, which is the dispatched case: the worker that
          // wrote has already committed before its answer reached this
          // process.
          Promise.resolve().then(function () {
            return self.persistence().flush();
          }).catch(function (e) {
            log.debug("Caught in settle(): " + ((e && e.message) || e));
          }).then(releaseAll);
          log.debug("Leaving settle(). Released after the flush.");
        }
      };
      return granted;
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

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, as the composition root will build one.
const createClaims = new DirectoryCreateClaims({
  log: log,
  config: config,
  errorCodes: errorCodes,
  claims: claims,
  isActiveActive: function () {
    return cluster.isActiveActive();
  },
  loadPersistence: DirectoryCreateClaims.persistenceModule,
  loadedDirectory: DirectoryCreateClaims.cachedDirectory
});

export = {
  DirectoryCreateClaims: DirectoryCreateClaims,
  active: createClaims.active.bind(createClaims) as
    DirectoryCreateClaims['active'],
  claim: createClaims.claim.bind(createClaims) as
    DirectoryCreateClaims['claim'],
  claimFor: createClaims.claimFor.bind(createClaims) as
    DirectoryCreateClaims['claimFor'],
  runClaimed: createClaims.runClaimed.bind(createClaims) as
    DirectoryCreateClaims['runClaimed'],
  refusalMessage: createClaims.refusalMessage.bind(createClaims) as
    DirectoryCreateClaims['refusalMessage'],
  CLAIM_TTL_MS: DirectoryCreateClaims.CLAIM_TTL_MS,
  CLAIM_WAIT_MS: DirectoryCreateClaims.CLAIM_WAIT_MS
};
