// @ts-check
'use strict';
//
// File: ldap/directory_create_claims.js
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

const bunyan = require('bunyan');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const claims = require('../cluster/cluster_claims');
const cluster = require('../cluster/cluster');

const log = bunyan.createLogger({ name: 'sts-directory-create-claims' });
config.registerLogger(log);

// The ceiling on a claim a process died holding. A create's flush commits in
// milliseconds; two minutes is long past every barrier and every retry.
const CLAIM_TTL_MS = 2 * 60 * 1000;

// ---------------------------------------------------------------------------
// A CREATE THAT FINDS ITS NAME CLAIMED WAITS, AND ASKS AGAIN (2026-09-15).
// A claim is released AFTER its create's flush and its response, so for a few
// tens of milliseconds after a 200 the name is still claimed — and the SAME
// client's next create of that name, sequential rather than concurrent, was
// refused 409 "being created by another request" where it should have been
// told the entry exists. `sts_admin_api_operations` met exactly that in a
// dispatch run: its create, then its duplicate 70ms later on the same worker.
//
// Answering the first create only after its release fixed it and cost every
// create in a multi-process service a store commit before it answered —
// /admin-api creates went from 11ms to 37ms in the bulk load, three times
// slower, to spare a cost that only a COLLISION should pay. So the cost moved
// to the collision: a refused claim gives back what it holds, waits
// `CLAIM_RETRY_MS`, and claims again until `CLAIM_WAIT_MS` has passed. The
// holder commits and releases; the waiter wins, catches up with the store
// below, and its door refuses the duplicate by its own check — or, if the
// holder's create failed, creates the entry itself. Only a name still held when
// the wait runs out is refused as in progress. A store that cannot be asked is
// not waited on.
// ---------------------------------------------------------------------------
const CLAIM_WAIT_MS = 5000;
const CLAIM_RETRY_MS = 50;

function persistence() {
  log.debug("Entering persistence().");
  log.debug("Leaving persistence().");
  // LAZY: this module is required by `ldap_server.js`, which the require order
  // loads far below `persistence.js` (#4a), and the value is only wanted
  // inside a request.
  return require('../persistence/persistence');
}

// Whether a create has anything to race here. See the header.
function active() {
  log.debug("Entering active().");
  if (!persistence().clusterStore()) {
    log.debug("Leaving active(). No shared store.");
    return false;
  }
  const dispatched = (Number(config.value('workers.requestCount')) || 0) > 0 &&
    String(config.value('workers.dispatch') || '').trim() !== '';
  log.debug("Leaving active().");
  return cluster.isActiveActive() || dispatched;
}

// ---------------------------------------------------------------------------
// claim({ realm, dns, usernames }) -> Promise of
//   { ok: true, settle(succeeded) }
//   { ok: false, reason: 'used' | 'store', code, what }
//
// `dns` are NORMALISED DNs and `usernames` are lower-cased; both are the
// caller's to compute, because deciding what a DN and a username are is
// `ldap_server.js`'s job. Every value is claimed or none is: a partial set
// is given back before the refusal is answered. `settle(true)` releases once
// the write has been flushed; `settle(false)` releases now. A value another
// request holds is waited for — `waitMs`, `CLAIM_WAIT_MS` by default, which
// only a test passes — before `used` is answered.
// ---------------------------------------------------------------------------
function claim(spec) {
  log.debug("Entering claim().");
  const o = spec || {};
  const wanted = [];
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
  if (!wanted.length || !active()) {
    log.debug("Leaving claim(). Nothing to claim here.");
    return Promise.resolve({ ok: true, settle: function () {} });
  }
  const realm = String(o.realm || '');
  const waitMs = o.waitMs === undefined ? CLAIM_WAIT_MS
    : Math.max(0, Number(o.waitMs) || 0);
  const deadline = Date.now() + waitMs;
  let attempts = 0;
  const attempt = function () {
    attempts += 1;
    return claimAll(wanted, realm).then(/** @param {any} answer */
                                        function (answer) {
      if (answer.ok || answer.reason === 'store' || Date.now() >= deadline) {
        return answer;
      }
      log.debug("claim(): " + answer.what + " is claimed; asking again in " +
                CLAIM_RETRY_MS + "ms (attempt " + attempts + ").");
      return new Promise(function (resolve) {
        setTimeout(resolve, CLAIM_RETRY_MS);
      }).then(attempt);
    });
  };
  log.debug("Leaving claim(). Asking for " + wanted.length + ".");
  return attempt().then(function (answer) {
    if (!answer.ok) {
      log.info(errorCodes.tag(answer.code) + 'ldap: a create of ' +
               answer.whatKind + answer.what + ' was refused: ' +
               (answer.reason === 'store'
                 ? 'the store that decides whether it is already being ' +
                   'created elsewhere could not be asked.'
                 : 'another request was still creating it after ' + waitMs +
                   'ms and ' + attempts + ' attempt(s).'));
      return { ok: false, reason: answer.reason, code: answer.code,
               what: answer.what };
    }
    // -----------------------------------------------------------------------
    // AND CAUGHT UP BEFORE THE DOOR LOOKS. A claim held by a create that has
    // since committed is released at once, so a request that arrived before
    // that commit — whose barrier therefore did not wait for it — could win
    // the claim a moment later and then ask a directory that does not hold
    // the entry yet. Catching up after the claim closes that: whoever held it
    // committed before releasing, so the door's own check now sees the entry
    // and refuses the duplicate. A catch-up that fails is not a refusal; the
    // flush's merge still keeps the first add.
    // -----------------------------------------------------------------------
    return Promise.resolve().then(function () {
      return persistence().syncNow();
    }).catch(function (e) {
      log.debug("Caught in claim(): " + ((e && e.message) || e));
    }).then(function () {
      return answer;
    });
  });
}

// One attempt at every value in `wanted`: all of them held, or none (a partial
// set is given back) and the first refusal described.
function claimAll(wanted, realm) {
  log.debug("Entering claimAll().");
  log.debug("Leaving claimAll().");
  return Promise.all(wanted.map(function (one) {
    return claims.claim({ scope: one.scope, value: one.value,
                          realm: realm, ttlMs: CLAIM_TTL_MS })
      .then(function (answer) {
        return { one: one, answer: answer };
      });
  })).then(function (answers) {
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
    const granted = {
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
        // AFTER THE WRITE IS IN THE STORE. A flush with nothing dirty resolves
        // at once, which is the dispatched case: the worker that wrote has
        // already committed before its answer reached this process.
        Promise.resolve().then(function () {
          return persistence().flush();
        }).catch(function (e) {
          log.debug("Caught in settle(): " + ((e && e.message) || e));
        }).then(releaseAll);
        log.debug("Leaving settle(). Released after the flush.");
      }
    };
    return granted;
  });
}

// ---------------------------------------------------------------------------
// THE CLAIM FOR A DOOR THAT DOES NOT HOLD THE DIRECTORY MODULE. `what` is
// `{ username }` or `{ group }`; `ldap_server.js`'s `claimCreate()` turns it
// into DNs and names. It is looked up in the require CACHE and never required
// from here — it registers routes, and the console that calls this is above it
// in the route order — and a process that never loaded it has no directory to
// race for.
// ---------------------------------------------------------------------------
function claimFor(what) {
  log.debug("Entering claimFor().");
  let directory = null;
  try {
    const cached = require.cache[require.resolve('./ldap_server')];
    directory = cached && cached.loaded ? cached.exports : null;
  } catch (e) {
    log.debug("Caught in claimFor(): " + ((e && e.message) || e));
  }
  if (!directory || typeof directory.claimCreate !== 'function') {
    log.debug("Leaving claimFor(). No directory in this process.");
    return Promise.resolve({ ok: true, settle: function () {} });
  }
  log.debug("Leaving claimFor().");
  return directory.claimCreate(what);
}

// ---------------------------------------------------------------------------
// RUN A CREATE WITH ITS NAME CLAIMED, for a door whose handler was
// synchronous. Where nothing can race (`what` null, or `active()` false —
// every single-process service) `run` is called SYNCHRONOUSLY with an idle
// claim, exactly as the handler behaved before. Otherwise the claim is
// awaited: a refusal goes to `refuse(held)`, and `run(held)` must settle it
// with the outcome. A throw out of `run` settles it as failed and is handed on
// to `onThrow(e)`, which the caller answers in its own shape.
// ---------------------------------------------------------------------------
function runClaimed(what, run, refuse, onThrow) {
  log.debug("Entering runClaimed().");
  const idle = { ok: true, settle: function () {} };
  if (!what || !active()) {
    log.debug("Leaving runClaimed(). Nothing to claim.");
    return run(idle);
  }
  log.debug("Leaving runClaimed(). Claiming first.");
  return claimFor(what).then(function (held) {
    if (!held.ok) {
      return refuse(held);
    }
    try {
      return run(held);
    } catch (e) {
      log.debug("Caught in runClaimed(): " + ((e && e.message) || e));
      held.settle(false);
      return onThrow(e);
    }
  });
}

// The sentence a refusal carries to a client, for the doors that are not
// LDAP.
function refusalMessage(refusal) {
  log.debug("Entering refusalMessage().");
  log.debug("Leaving refusalMessage().");
  return refusal.reason === 'store'
    ? 'This service could not confirm that "' + refusal.what + '" is not ' +
      'being created by another request at this moment, so it was not ' +
      'created. Try again.'
    : '"' + refusal.what + '" is being created by another request at this ' +
      'moment. One entry per name: it was not created twice.';
}

module.exports = {
  active: active,
  claim: claim,
  claimFor: claimFor,
  runClaimed: runClaimed,
  refusalMessage: refusalMessage,
  CLAIM_TTL_MS: CLAIM_TTL_MS,
  CLAIM_WAIT_MS: CLAIM_WAIT_MS
};
