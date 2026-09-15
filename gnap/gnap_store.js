'use strict';
//
// File: gnap_store.js
//
// ---------------------------------------------------------------------------
// EVERYTHING GNAP MINTS, PER TRUST REALM, IN ONE PLACE.
//
// RFC 9767 section 2.1.13 describes the model this file keeps: a GRANT is the
// tuple of the AS, the client instance, the resource owner(s), the rights and a
// state (RFC 9635 section 1.5: processing, pending, approved, finalized), and
// every access token hangs off the grant that issued it. So the grant is the
// record and everything else is an INDEX onto it: the continuation access
// token, the interaction start URIs and user codes, the interaction reference,
// the access tokens and their management tokens.
//
// **EACH STORE IS PER REALM AT ITS DECLARATION**, which is the rule
// common/CLAUDE.md states and `tests/realm_isolation.js` guards. A grant made
// in `/realm/acme` is acme's authorization server's, and a continuation token
// from it presented to the default realm must find NOTHING — not a grant it is
// refused for, nothing — because the two realms are two logical identity
// services.
//
// **EACH STORE IS DECLARED WITH `persist`**, so in product mode on a postgres
// store it survives a restart and replicates between request workers — the
// minted-row rule of persistence/CLAUDE.md. That has three consequences this
// file honours everywhere:
//
//   * **a row is JSON.** No KeyObject, no Buffer. A key is stored as the object
//     the client sent and re-described by `gnap_keys.js` on read.
//   * **an in-place edit is re-set.** The journal sees set/delete/clear and
//     nothing else, so `saveGrant()` and `saveToken()` exist and every mutation
//     goes through them — a grant moved to `approved` in place and never re-set
//     would be persisted pending.
//   * **no bearer credential is a key.** Every token VALUE is indexed by its
//     SHA-256, the rule `vc_offers.deferredAccessTokens` set: a dump of the
//     store is then not a list of working tokens.
//
// Expiry is checked on READ rather than by a timer: a timer runs in every
// request worker, and a sweep that raced a lookup in another process would be
// a grant that exists in one and not the other for no reason anybody could
// see. A row past its life reads as absent, and `prune()` removes the dead ones
// opportunistically when something new is written.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const { log, randomId, nowSec } = require('../common/helpers');
const realms = require('../common/realms');
// THE CLUSTER CLAIM (2026-09-14, #46) — see spend() below. A LIBRARY that
// registers no route and requires persistence lazily, so this file stays a
// leaf of the family.
const clusterClaims = require('../cluster/cluster_claims');
const capabilities = require('../cluster/cluster_capabilities');
const errorCodes = require('../common/error_codes');

const grants = realms.map({ persist: 'gnap.grants' });
const continuations = realms.map({ persist: 'gnap.continuations' });
const interactions = realms.map({ persist: 'gnap.interactions' });
const userCodes = realms.map({ persist: 'gnap.userCodes' });
const tokens = realms.map({ persist: 'gnap.tokens' });
const tokenValues = realms.map({ persist: 'gnap.tokenValues' });
const manageValues = realms.map({ persist: 'gnap.manageValues' });
const manageHandles = realms.map({ persist: 'gnap.manageHandles' });
const instances = realms.map({ persist: 'gnap.instances' });
const userRefs = realms.map({ persist: 'gnap.userRefs' });
const resources = realms.map({ persist: 'gnap.resources' });
// THE REPLAY CACHE for httpsig nonces and JWS proofs (RFC 9635 section 7.3.1:
// "the verifier MUST determine that the nonce value is unique within a
// reasonably short time period"). Persisted for the reason the DPoP replay
// cache is: across request workers a proof refused by one and accepted by
// another is the replay the cache exists to stop.
const replay = realms.map({ persist: 'gnap.replay' });

// Grant states, RFC 9635 section 1.5.
const STATE = { PROCESSING: 'processing', PENDING: 'pending',
                APPROVED: 'approved',
                FINALIZED: 'finalized' };

function digest(value) {
  log.debug("Entering digest().");
  log.debug("Leaving digest().");
  return nodeCrypto.createHash('sha256')
                   .update(String(value), 'utf8')
                   .digest('base64url');
}

// A value of the given length made of unreserved characters (RFC 3986 section
// 2.3). base64url is exactly that alphabet, which is why every GNAP artifact
// here is one: section 4.2 requires it of the interaction reference and
// section 3.2.1's token68 is satisfied by it for every token.
function mint(bytes) {
  log.debug("Entering mint().");
  log.debug("Leaving mint().");
  return randomId(bytes || 24);
}

// ---------------------------------------------------------------------------
// GRANTS.
// ---------------------------------------------------------------------------
function newGrant(fields) {
  log.debug("Entering newGrant().");
  const now = nowSec();
  const grant = Object.assign({
    id: mint(18),
    state: STATE.PROCESSING,
    createdAt: now,
    updatedAt: now,
    expiresAt: null,
    tokens: [],
    history: []
  }, fields || {});
  grants.set(grant.id, grant);
  prune();
  log.debug("Leaving newGrant(). id=" + grant.id);
  return grant;
}

function getGrant(id) {
  log.debug("Entering getGrant().");
  if (!id || !grants.has(id)) {
    log.debug("Leaving getGrant().");
    return null;
  }
  log.debug("Leaving getGrant().");
  return grants.get(id);
}

// Every change to a grant passes through here, because the journal only sees a
// set (header). `note` goes onto the grant's own history, which the console
// shows: a grant is a state machine and a reader debugging a client wants the
// transitions, not the final state.
function saveGrant(grant, note) {
  log.debug("Entering saveGrant().");
  grant.updatedAt = nowSec();
  if (note) {
    grant.history = (grant.history || []).concat(
        [{ at: grant.updatedAt, state: grant.state,
                                                     note: String(note).slice(0,
                                                                              200) }])
      .slice(-40);
  }
  grants.set(grant.id, grant);
  log.debug("Leaving saveGrant().");
  return grant;
}

function listGrants() {
  log.debug("Entering listGrants().");
  const out = [];
  grants.forEach(function (grant) {
    out.push(grant);
  });
  log.debug("Leaving listGrants().");
  return out.sort(function (a, b) {
    return b.updatedAt - a.updatedAt;
  });
}

function deleteGrant(id) {
  log.debug("Entering deleteGrant().");
  grants.delete(id);
  log.debug("Leaving deleteGrant().");
}

// ---------------------------------------------------------------------------
// CONTINUATION ACCESS TOKENS (section 3.1). One live value per grant: section 5
// says the new token SHOULD invalidate the previous one, and this service
// always does, so an old continuation token read from a log cannot be replayed
// after the client has used its successor.
// ---------------------------------------------------------------------------
function issueContinuation(grant) {
  log.debug("Entering issueContinuation(). grant=" + grant.id);
  if (grant.continuationHash) {
    continuations.delete(grant.continuationHash);
  }
  const value = mint(24);
  grant.continuationHash = digest(value);
  continuations.set(grant.continuationHash,
                    { grantId: grant.id, issuedAt: nowSec() });
  log.debug("Leaving issueContinuation().");
  return value;
}

function grantByContinuation(value) {
  log.debug("Entering grantByContinuation().");
  const row = continuations.get(digest(value));
  log.debug("Leaving grantByContinuation().");
  return row ? getGrant(row.grantId) : null;
}

function dropContinuation(grant) {
  log.debug("Entering dropContinuation().");
  if (grant.continuationHash) {
    continuations.delete(grant.continuationHash);
    grant.continuationHash = null;
  }
  log.debug("Leaving dropContinuation().");
}

// ---------------------------------------------------------------------------
// INTERACTION START HANDLES: the unique path segment of a redirect or app URI,
// and a user code. Both are ONE-TIME-USE and short-lived (section 4); the
// grant holds the expiry and the "which mode was used" state, and these rows
// are only the lookup.
// ---------------------------------------------------------------------------
function putInteraction(id, grantId) {
  log.debug("Entering putInteraction().");
  interactions.set(id, { grantId: grantId, at: nowSec() });
  log.debug("Leaving putInteraction().");
}

function grantByInteraction(id) {
  log.debug("Entering grantByInteraction().");
  const row = id ? interactions.get(id) : null;
  log.debug("Leaving grantByInteraction().");
  return row ? getGrant(row.grantId) : null;
}

function dropInteraction(id) {
  log.debug("Entering dropInteraction().");
  interactions.delete(id);
  log.debug("Leaving dropInteraction().");
}

function putUserCode(code, grantId) {
  log.debug("Entering putUserCode().");
  userCodes.set(code, { grantId: grantId, at: nowSec() });
  log.debug("Leaving putUserCode().");
}

function grantByUserCode(code) {
  log.debug("Entering grantByUserCode().");
  const row = code ? userCodes.get(code) : null;
  log.debug("Leaving grantByUserCode().");
  return row ? getGrant(row.grantId) : null;
}

function dropUserCode(code) {
  log.debug("Entering dropUserCode().");
  userCodes.delete(code);
  log.debug("Leaving dropUserCode().");
}

function userCodeTaken(code) {
  log.debug("Entering userCodeTaken().");
  log.debug("Leaving userCodeTaken().");
  return userCodes.has(code);
}

// ---------------------------------------------------------------------------
// ACCESS TOKENS (section 3.2) and their MANAGEMENT tokens (section 6).
//
// A token record is the RFC 9767 section 2.1 model plus the bookkeeping the AS
// needs: the grant, the management handle and hash, the format, and whether it
// is revoked. It is keyed by `jti` and indexed by the SHA-256 of its value, so
// that introspection of any of the five formats is one lookup — including the
// three whose value a self-contained verifier could also read.
// ---------------------------------------------------------------------------
function putToken(record, value) {
  log.debug("Entering putToken(). jti=" + record.jti);
  record.valueHash = digest(value);
  tokens.set(record.jti, record);
  tokenValues.set(record.valueHash, { jti: record.jti });
  log.debug("Leaving putToken().");
  return record;
}

function saveToken(record) {
  log.debug("Entering saveToken().");
  tokens.set(record.jti, record);
  log.debug("Leaving saveToken().");
  return record;
}

function tokenByJti(jti) {
  log.debug("Entering tokenByJti().");
  log.debug("Leaving tokenByJti().");
  return jti ? (tokens.get(jti) || null) : null;
}

function tokenByValue(value) {
  log.debug("Entering tokenByValue().");
  const row = value ? tokenValues.get(digest(value)) : null;
  log.debug("Leaving tokenByValue().");
  return row ? tokenByJti(row.jti) : null;
}

function listTokens() {
  log.debug("Entering listTokens().");
  const out = [];
  tokens.forEach(function (record) {
    out.push(record);
  });
  log.debug("Leaving listTokens().");
  return out;
}

// The management URI's handle and its access token (section 3.2.1). The handle
// is NOT the token (the URI "MUST NOT include the value of the access token
// being managed or the value of the access token used to protect the URI").
function issueManagement(record) {
  log.debug("Entering issueManagement(). jti=" + record.jti);
  if (record.manageHash) {
    manageValues.delete(record.manageHash);
  }
  if (!record.manageHandle) {
    record.manageHandle = mint(12);
    manageHandles.set(record.manageHandle, { jti: record.jti });
  }
  const value = mint(24);
  record.manageHash = digest(value);
  manageValues.set(record.manageHash, { jti: record.jti });
  log.debug("Leaving issueManagement().");
  return value;
}

// A rotated token takes its management handle with it — section 6.1: "the
// value of this URI MAY be different from the URI used by the client instance".
// This service keeps the URI and moves the handle onto the new record, which is
// the arrangement a client can least get wrong.
function moveManagement(from, to) {
  log.debug("Entering moveManagement().");
  if (from.manageHandle) {
    to.manageHandle = from.manageHandle;
    manageHandles.set(to.manageHandle, { jti: to.jti });
    from.manageHandle = null;
  }
  if (from.manageHash) {
    manageValues.delete(from.manageHash);
    from.manageHash = null;
  }
  log.debug("Leaving moveManagement().");
}

function tokenByManagement(handle, value) {
  log.debug("Entering tokenByManagement().");
  const byHandle = handle ? manageHandles.get(handle) : null;
  const byValue = value ? manageValues.get(digest(value)) : null;
  if (!byHandle || !byValue || byHandle.jti !== byValue.jti) {
    log.debug("Leaving tokenByManagement().");
    // Section 6: "The AS MUST uniquely identify the token being managed from
    // the token management URI, the token management access token, or a
    // combination of both." This service requires BOTH to agree, so a
    // management token for one of a client's tokens cannot rotate another.
    return null;
  }
  log.debug("Leaving tokenByManagement().");
  return tokenByJti(byHandle.jti);
}

function dropManagement(record) {
  log.debug("Entering dropManagement().");
  if (record.manageHandle) {
    manageHandles.delete(record.manageHandle);
  }
  if (record.manageHash) {
    manageValues.delete(record.manageHash);
  }
  record.manageHandle = null;
  record.manageHash = null;
  log.debug("Leaving dropManagement().");
}

// ---------------------------------------------------------------------------
// DYNAMIC INSTANCE IDENTIFIERS (section 3.5) and USER REFERENCES (section
// 2.4.1). Both are secrets the client holds, so both are indexed by digest.
// ---------------------------------------------------------------------------
function putInstance(instanceId, fields) {
  log.debug("Entering putInstance().");
  instances.set(digest(instanceId),
                Object.assign({ createdAt: nowSec() }, fields));
  log.debug("Leaving putInstance().");
}

function instanceById(instanceId) {
  log.debug("Entering instanceById().");
  log.debug("Leaving instanceById().");
  return instanceId ? (instances.get(digest(instanceId)) || null) : null;
}

function putUserRef(reference, fields) {
  log.debug("Entering putUserRef().");
  userRefs.set(digest(reference),
               Object.assign({ createdAt: nowSec() }, fields));
  log.debug("Leaving putUserRef().");
}

function userByRef(reference) {
  log.debug("Entering userByRef().");
  log.debug("Leaving userByRef().");
  return reference ? (userRefs.get(digest(reference)) || null) : null;
}

// ---------------------------------------------------------------------------
// REGISTERED RESOURCE SETS (RFC 9767 section 3.4). Keyed by the reference the
// AS hands back; section 3.4 lets the AS return the SAME reference for a set
// registered again, which is what `canonical` makes possible.
// ---------------------------------------------------------------------------
function putResource(reference, fields) {
  log.debug("Entering putResource().");
  resources.set(reference,
                Object.assign({ reference: reference, createdAt: nowSec() },
                              fields));
  log.debug("Leaving putResource().");
  return resources.get(reference);
}

function resourceByReference(reference) {
  log.debug("Entering resourceByReference().");
  log.debug("Leaving resourceByReference().");
  return reference ? (resources.get(reference) || null) : null;
}

function resourceByCanonical(canonical, rsIdentity) {
  log.debug("Entering resourceByCanonical().");
  let found = null;
  resources.forEach(function (row) {
    if (!found && row.canonical === canonical &&
        row.rsIdentity === rsIdentity) {
      found = row;
    }
  });
  log.debug("Leaving resourceByCanonical().");
  return found;
}

function listResources() {
  log.debug("Entering listResources().");
  const out = [];
  resources.forEach(function (row) {
    out.push(row);
  });
  log.debug("Leaving listResources().");
  return out.sort(function (a, b) {
    return b.createdAt - a.createdAt;
  });
}

function deleteResource(reference) {
  log.debug("Entering deleteResource().");
  log.debug("Leaving deleteResource().");
  return resources.delete(reference);
}

// ---------------------------------------------------------------------------
// REPLAY. `remember(key, lifetimeS)` answers true the first time and false for
// a repeat within the window, which is the whole contract a verifier needs.
// ---------------------------------------------------------------------------
function remember(key, lifetimeS) {
  log.debug("Entering remember().");
  const now = nowSec();
  const hashed = digest(key);
  const seen = replay.get(hashed);
  if (seen && seen.until > now) {
    log.debug("Leaving remember().");
    return false;
  }
  replay.set(hashed, { until: now + Math.max(1, Number(lifetimeS) || 1) });
  log.debug("Leaving remember().");
  return true;
}

// ---------------------------------------------------------------------------
// SPENDING A SINGLE-USE VALUE ACROSS THE CLUSTER (2026-09-14, #46).
//
// Every one-time value in this family — a continuation access token, an
// interaction reference, an interaction start link, a user code, a token
// management access token, a key proof — is spent in THIS file's maps, which
// are `realms.map({ persist })`: once in one process, and a replicated write
// in several. Two requests carrying one value, landing on two nodes inside the
// replication window, both found it live and both were answered — two
// continuations issuing two successor tokens for one grant, two rotations of
// one access token, a signature nonce accepted twice (RFC 9635 section 7.3.1
// says MUST be unique).
//
// So each caller keeps its in-memory check first, exactly as it was, and then
// asks `spend(kind, value, lifetimeS)` before acting: one
// `cluster_claims.claim()` in the scope `gnap.<kind>`, which exactly one
// caller on any node wins. On a store that cannot be shared the claim is this
// process's memory, which is as atomic as the maps it sits beside.
//
// The lifetime is the value's own — `lifetimeS` — plus CLAIM_SKEW_S for clocks
// that disagree. A value with no expiry of its own (a continuation or
// management token lives until it is used) is claimed for UNBOUNDED_LIFETIME_S:
// the claim has to outlive only the window in which another node could still
// hold the value, and a day is far past every replication delay, including a
// transaction the change log gives up on after ten minutes.
//
// Resolves to `{ ok: true, handle }`, or `{ ok: false, reason, errorCode }`
// where `reason` is `used` (the caller refuses with the protocol's own error
// and `usedCode`) or `store` (STS-GNAP-0716, fail closed). It never rejects.
// ---------------------------------------------------------------------------
const CLAIM_SKEW_S = 60;
const UNBOUNDED_LIFETIME_S = 24 * 60 * 60;

function spend(kind, value, lifetimeS, usedCode) {
  log.debug("Entering spend(). kind=" + kind);
  const seconds = Number(lifetimeS);
  const ttlS = (Number.isFinite(seconds) && seconds > 0 ? seconds :
                UNBOUNDED_LIFETIME_S) + CLAIM_SKEW_S;
  log.debug("Leaving spend(). Asking the claim store.");
  return clusterClaims.claim({ scope: 'gnap.' + kind, value: value,
                               ttlMs: ttlS * 1000 })
    .then(function (claimed) {
      log.debug("Entering spend()'s answer.");
      if (claimed.ok) {
        log.debug("Leaving spend()'s answer. Spent here.");
        return claimed;
      }
      if (claimed.reason === 'used') {
        log.warn(errorCodes.tag(usedCode) + 'gnap: a single-use value ("' +
                 kind + '") this process still accepted was ALREADY SPENT, ' +
                 'on this node or another against the same store. Refused.');
        log.debug("Leaving spend()'s answer. Used.");
        return { ok: false, reason: 'used', errorCode: usedCode };
      }
      log.error(errorCodes.tag('STS-GNAP-0716') + 'gnap: whether a ' +
                'single-use value ("' + kind + '") was already spent could ' +
                'not be asked of the claim store (' +
                (claimed.why || 'no reason given') + '). It is refused.');
      log.debug("Leaving spend()'s answer. Store unavailable.");
      return { ok: false, reason: 'store', errorCode: 'STS-GNAP-0716' };
    });
}

// Gives a claim back when what it guarded did not happen — see the callers,
// which release only where the value is still live in this process's map.
function unspend(handle) {
  log.debug("Entering unspend().");
  log.debug("Leaving unspend().");
  return clusterClaims.release(handle);
}

// ---------------------------------------------------------------------------
// OPPORTUNISTIC PRUNE of rows that can no longer be used. Bounded work per
// call, so a store with a large backlog is cleaned over several writes rather
// than stalling one.
// ---------------------------------------------------------------------------
function prune() {
  log.debug("Entering prune().");
  const now = nowSec();
  let budget = 200;
  replay.forEach(function (row, key) {
    if (budget > 0 && row.until <= now) {
      replay.delete(key);
      budget -= 1;
    }
  });
  grants.forEach(function (grant, id) {
    if (budget <= 0) {
      return;
    }
    // A FINALIZED grant is kept for a day so the console can show what
    // happened to it; a pending one past its life is simply gone.
    const finalizedLongAgo = grant.state === STATE.FINALIZED &&
                             grant.updatedAt < now - 86400;
    const pendingExpired = grant.state !== STATE.APPROVED &&
      grant.state !== STATE.FINALIZED &&
      grant.expiresAt && grant.expiresAt < now - 3600;
    if (finalizedLongAgo || pendingExpired) {
      if (grant.continuationHash) {
        continuations.delete(grant.continuationHash);
      }
      grants.delete(id);
      budget -= 1;
    }
  });
  log.debug("Leaving prune().");
}

// #46: every GNAP single-use value is spent once across the cluster — the
// helper above, called from gnap_grants.js, gnap_interact.js, gnap_proof.js
// and gnap_rs.js. Provided here because the capability row names this file.
capabilities.provide('gnap.once');

module.exports = {
  STATE: STATE,
  spend: spend,
  unspend: unspend,
  digest: digest,
  mint: mint,
  newGrant: newGrant,
  getGrant: getGrant,
  saveGrant: saveGrant,
  listGrants: listGrants,
  deleteGrant: deleteGrant,
  issueContinuation: issueContinuation,
  grantByContinuation: grantByContinuation,
  dropContinuation: dropContinuation,
  putInteraction: putInteraction,
  grantByInteraction: grantByInteraction,
  dropInteraction: dropInteraction,
  putUserCode: putUserCode,
  grantByUserCode: grantByUserCode,
  dropUserCode: dropUserCode,
  userCodeTaken: userCodeTaken,
  putToken: putToken,
  saveToken: saveToken,
  tokenByJti: tokenByJti,
  tokenByValue: tokenByValue,
  listTokens: listTokens,
  issueManagement: issueManagement,
  moveManagement: moveManagement,
  tokenByManagement: tokenByManagement,
  dropManagement: dropManagement,
  putInstance: putInstance,
  instanceById: instanceById,
  putUserRef: putUserRef,
  userByRef: userByRef,
  putResource: putResource,
  resourceByReference: resourceByReference,
  resourceByCanonical: resourceByCanonical,
  listResources: listResources,
  deleteResource: deleteResource,
  remember: remember,
  prune: prune
};
