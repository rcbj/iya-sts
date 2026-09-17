// @ts-check
'use strict';
//
// File: used_assertions.js
//
// ===========================================================================
// THE USED-ASSERTION HISTORY: EVERY RFC 7523 JWT AND EVERY RFC 7522 SAML
// ASSERTION THIS SERVICE HAS ACCEPTED, SO THAT NONE IS ACCEPTED TWICE, EVER
// (2026-09-13).
//
// A signed assertion is a bearer credential until it expires. Whoever captures
// one off the wire — out of a log line, a proxy, a browser's history, a test
// fixture — holds exactly what the party that signed it held, and the only
// thing standing between that copy and a second access token is this service
// remembering that the first one was spent. RFC 7521 section 5.2 (7), RFC 7523
// section 3 claim 7 and RFC 7522 section 3 item 6 all make remembering a MAY;
// this service reads it as the whole of the difference between an assertion
// and a password, and remembers.
//
// ---------------------------------------------------------------------------
// WHAT THIS REPLACED, AND THE FOUR WAYS IT WAS NOT "ONCE EVER".
//
// Until this file there were THREE replay caches — one each in
// `oauth-oidc/client_auth.js`, `assertion_grant.js` and
// `saml_assertion_grant.js` — each a `realms.map({ persist: … })`. Every one of
// them refused a second use inside one process, and the phrase "once ever" was
// false four ways:
//
//   1. **A RESTART FORGOT THEM IN DEVELOPMENT MODE.** Minted state persists
//      only in product mode on postgres, because "development persists
//      nothing it minted" rests on the signing key being regenerated. That
//      premise does not reach an assertion: it is signed by the CLIENT's key,
//      which is on the application's entry in the directory, which persists in
//      every store. So a development service with a store accepted every
//      assertion it had ever spent the moment it restarted.
//   2. **THE `ldif` STORE NEVER HELD THEM**, in either mode — it holds no
//      minted state at all.
//   3. **SEVERAL PROCESSES CONVERGED RATHER THAN AGREED.** A journalled row
//      reaches another process after the change log is pulled, so for up to
//      `persistence.pollInterval` a second worker accepted what the first had
//      already spent. `persistence/CLAUDE.md` called that a security
//      statement and it was one.
//   4. **A JWT COULD BE SPENT TWICE**, once as a `client_assertion` and once
//      as an `assertion` grant, because those were two caches keyed two ways.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS, EACH ASKED OF THE OWNER BEFORE IT WAS BUILT.
//
// * **PERSISTENT IN EVERY STORE, IN BOTH MODES.** postgres holds it in a table
//   of its own (`sts_used_assertions`); ldif in a file per realm; `memory`, the
//   default, in this process — and a memory-mode service persists nothing that
//   could verify one of these assertions after a restart either, so there is
//   nothing to replay.
// * **AN ATOMIC CLAIM IN THE STORE.** On postgres recording a use is one
//   `INSERT … ON CONFLICT` — two workers cannot both accept one assertion,
//   because the database's unique key arbitrates rather than a change log
//   arriving later. It costs one round trip per assertion.
// * **ONE HISTORY FOR EVERY USE.** Keyed by the document's FORMAT, its ISSUER
//   and its IDENTIFIER (the `jti`, or the SAML `ID`) and NOT by what it was
//   presented as, so an assertion that authenticated a client cannot then be a
//   grant, or the reverse. The format is in the key because a SAML `ID` and a
//   JWT `jti` are two namespaces with no reason to be disjoint — the argument
//   `saml_assertion_grant.js` made for a third cache, kept.
// * **SUCCESSFUL MEANS TOKENS WERE ISSUED.** An accepted assertion is
//   RESERVED, which a concurrent replay is refused on exactly as on a spent
//   one; the reservation becomes permanent only when the response it belongs
//   to finishes with a 2xx, and is RELEASED otherwise — a bad authorization
//   code, an `invalid_scope`, the issuance gate. A document that bought
//   nothing has not been used, and refusing its retry would be refusing a
//   credential for a failure somewhere else.
//
// ---------------------------------------------------------------------------
// AND AN RFC 9101 REQUEST OBJECT, SINCE 2026-09-17 (#35).
//
// A signed request object carrying a `jti` is recorded here too, as a third
// USE of a `jwt`: it is a document a client signed, it is a bearer
// credential for the authorization request inside it until it expires, and
// the service used to say outright that it did not remember one. It is SPENT
// where the authorization endpoint issues something on it, or where the
// pushed authorization request endpoint keeps it — not where it is first
// read, because the authorization endpoint reads every request twice, and
// `peek()` is the look those earlier reads take. `request_object.ts` argues
// it.
//
// ---------------------------------------------------------------------------
// FOR HOW LONG: UNTIL IT WOULD HAVE EXPIRED, AND NOT A MOMENT LONGER.
//
// A row's `expiresAt` is the assertion's own expiry plus the clock skew the
// verifier allowed, so this history and the expiry check cover exactly the same
// span with no gap between them: an assertion is refused as used while it could
// still be valid, and refused as expired after that. Nothing is kept past it —
// there is no retention setting, because a row outliving its assertion guards
// nothing.
//
// **THE CAP REFUSES, IT NEVER FORGETS.** `oauth2.assertionReplayCacheSize` is
// the number of unexpired rows a realm may hold, and a realm full of live ones
// refuses the next assertion — a retryable refusal of a fresh credential,
// rather than a live one forgotten and replayable. That was the three caches'
// rule since 2026-09-12 and it is unchanged; what changed is that it is one
// count per realm now rather than three.
//
// ---------------------------------------------------------------------------
// THE LOCKS THIS DOES NOT TAKE, AND WHY A CRASH IS SAFE.
//
// A reservation held by a process that dies before its response finishes is
// neither confirmed nor released, and on postgres and ldif it stays until the
// assertion expires — so that assertion is refused as used for the rest of its
// life. That is the safe direction and it is deliberate: the alternative is a
// reservation that evaporates, which on a crash AFTER the tokens reached the
// client is a replayable assertion.
//
// ---------------------------------------------------------------------------
// WHERE IT IS REQUIRED FROM.
//
// A LIBRARY (rule 3): it registers no route. It requires only `config`,
// `realms`, `error_codes` and npm leaves, and uses its own logger rather than
// `helpers.js`'s, because `persistence/persistence.js` requires it to install
// the store and that module is at 4a, beside `helpers.js` rather than below it.
// `persistence.js` fills `setStore()` the moment a driver is open — the
// arrangement `keystore.setStore()` already has, for its reason.
// ===========================================================================

const crypto = require('crypto');
const bunyan = require('bunyan');
const config = require('./config');
const realms = require('./realms');
// A LEAF that requires nothing here. The store failures below are tagged in the
// log; the refusals are the three verifiers' to code, because each answers in
// its own protocol's vocabulary.
const errorCodes = require('./error_codes');

// Registered with `config.js` like `persistence.js`'s own, so the level
// follows `global.logLevel` rather than being read once here.
const log = bunyan.createLogger({ name: 'sts-used-assertions' });
config.registerLogger(log);

// The two formats and the three uses. Closed lists: a row carrying anything
// else is refused at `claim()` rather than written, because a history whose
// rows can say anything is one a page cannot draw a column for.
const FORMATS = {
  jwt: 'RFC 7523 JWT',
  saml: 'RFC 7522 SAML 2.0 assertion'
};
const USES = {
  'client-authentication': 'client authentication (RFC 7521 section 4.2)',
  'authorization-grant': 'authorization grant (RFC 7521 section 4.1)',
  // RFC 9101 (#35, 2026-09-17). A request object is a JWT its CLIENT signs,
  // so it is keyed exactly as a client assertion is — format `jwt`, the
  // client as issuer, and its `jti` — and the two share one namespace, which
  // is what RFC 7519 section 4.1.7 asks of a `jti` in the first place: one
  // identifier, one document. `oauth-oidc/request_object.ts` argues the rest.
  'request-object': 'request object (RFC 9101)'
};

// What a row is, spelt once. Every store hands rows back in this shape.
const STATES = {
  reserved: 'accepted, and the response it belongs to has not finished',
  spent: 'tokens were issued for it'
};

// The default of `oauth2.assertionReplayCacheSize`, used only when the setting
// reads as nonsense.
const DEFAULT_CAP = 1000;

// How long to leave between two sweeps of a DATABASE store. A memory or file
// store is swept on every claim, because it is in this process and small.
const PURGE_INTERVAL_MS = 60 * 1000;

// Display ceilings. The identifier and issuer are copied into a row for the
// console to draw, and a hostile assertion may carry megabytes in either; the
// KEY is a digest of the WHOLE value, so clipping what is drawn never makes two
// assertions one.
const MAX_SHOWN = 512;

// ---------------------------------------------------------------------------
// THE STORE. `null` means this process's memory, which is what `memory` mode
// is and what a driver without either group falls back to. Exactly one of
// `database` and `snapshot` is set when a store is installed.
// ---------------------------------------------------------------------------
let store = {
  mode: 'memory', kind: 'memory', driver: null, persistent: false,
  why: 'persistence.mode is memory, so this history is held in this ' +
       'process and is gone at a restart — and so is everything that could ' +
       'verify one of these assertions, since nothing a memory-mode service ' +
       'holds survives one.'
};

// realm id -> Map(key -> row). The memory store, and the ldif store's working
// copy. A database store keeps nothing here.
const partitions = new Map();

// Realms whose snapshot has changed since it was last written.
const dirtyRealms = new Set();
let writeTimer = null;
let lastPurgeAt = 0;
// The last live count each realm's store reported, for the one synchronous
// reader (`GET /oauth2/rfc9700`). A database store is asked on every claim.
const lastKnownLive = new Map();

function capOf() {
  log.debug("Entering capOf().");
  const count = Number(config.value('oauth2.assertionReplayCacheSize'));
  log.debug("Leaving capOf().");
  return isFinite(count) && count > 0 ? Math.floor(count) : DEFAULT_CAP;
}

// One key for one DOCUMENT, whatever it was presented as. The use is left out
// on purpose — see the header. base64url of SHA-256, so a key is short and
// fixed-length whatever an issuer put in its `jti`.
function keyOf(format, issuer, identifier) {
  log.debug("Entering keyOf().");
  const digest = crypto.createHash('sha256')
    .update(String(format) + '\n' + String(issuer) + '\n' + String(identifier))
    .digest('base64url');
  log.debug("Leaving keyOf().");
  return digest;
}

function clip(value) {
  log.debug("Entering clip().");
  const text = String(value === undefined || value === null ? '' : value);
  log.debug("Leaving clip().");
  return text.length > MAX_SHOWN ? text.slice(0, MAX_SHOWN) + '…' : text;
}

function partitionOf(realmId) {
  log.debug("Entering partitionOf().");
  let rows = partitions.get(realmId);
  if (!rows) {
    rows = new Map();
    partitions.set(realmId, rows);
  }
  log.debug("Leaving partitionOf().");
  return rows;
}

// Takes the expired rows out of one realm's partition and says how many live
// ones are left. Never removes a live row.
function sweep(realmId, now) {
  log.debug("Entering sweep(). realm=" + realmId);
  const rows = partitionOf(realmId);
  let removed = 0;
  rows.forEach(function (row, key) {
    if (row.expiresAt < now) {
      rows.delete(key);
      removed += 1;
    }
  });
  if (removed && store.kind === 'snapshot') {
    dirtyRealms.add(realmId);
  }
  log.debug("Leaving sweep(). " + removed + " expired, " + rows.size +
            " live.");
  return rows.size;
}

// ---------------------------------------------------------------------------
// INSTALLATION. Called by `persistence.js` once a driver is open. Returns a
// promise because a snapshot store is READ before anything can be claimed
// against it — a claim answered from an empty copy of a history that exists on
// disk would be the restart-replay this file exists to close.
// ---------------------------------------------------------------------------
const DATABASE_GROUP = ['claimUsedAssertion', 'settleUsedAssertion',
                        'listUsedAssertions', 'purgeUsedAssertions',
                        'removeUsedAssertions'];
const SNAPSHOT_GROUP = ['loadUsedAssertions', 'saveUsedAssertions',
                        'removeUsedAssertions'];

function hasGroup(theDriver, names) {
  log.debug("Entering hasGroup().");
  const all = !!theDriver && names.every(function (name) {
    return typeof theDriver[name] === 'function';
  });
  log.debug("Leaving hasGroup().");
  return all;
}

function setStore(theDriver, activeMode) {
  log.debug("Entering setStore(). mode=" + activeMode);
  partitions.clear();
  dirtyRealms.clear();
  lastKnownLive.clear();
  if (hasGroup(theDriver, DATABASE_GROUP)) {
    store = { mode: activeMode, kind: 'database', driver: theDriver,
              persistent: true,
              why: 'Held in the ' + activeMode + ' store, where recording a ' +
                   'use is one atomic claim: every process against that store ' +
                   'agrees at once, and the history survives a restart.' };
    log.info('used assertions: the ' + activeMode + ' store holds the ' +
             'used-assertion history; a claim is atomic across every ' +
             'process against it.');
    log.debug("Leaving setStore(). A database store.");
    return Promise.resolve(true);
  }
  if (hasGroup(theDriver, SNAPSHOT_GROUP)) {
    log.debug("Leaving setStore(). A snapshot store, loading.");
    return Promise.resolve(theDriver.loadUsedAssertions()).then(function (by) {
      const now = Date.now();
      let restored = 0;
      Object.keys(by || {}).forEach(function (realmId) {
        const rows = partitionOf(realmId);
        (by[realmId] || []).forEach(function (row) {
          if (row && row.key && Number(row.expiresAt) >= now) {
            rows.set(row.key, row);
            restored += 1;
          }
        });
      });
      store = { mode: activeMode, kind: 'snapshot', driver: theDriver,
                persistent: true,
                why: 'Held in the ' + activeMode + ' store, written before ' +
                     'the response that used an assertion is sent, and read ' +
                     'back at startup. One process: this store does not ' +
                     'coordinate, and a service that dispatches refuses to ' +
                     'start without a store that does.' };
      log.info('used assertions: restored ' + restored + ' unexpired ' +
               'row(s) from the ' + activeMode + ' store.');
      return true;
    });
  }
  store = {
    mode: activeMode, kind: 'memory', driver: null, persistent: false,
    why: 'The ' + activeMode + ' store has no used-assertion functions, so ' +
         'this history is held in this process and is forgotten at a ' +
         'restart. Every real driver has them; this is a test double or an ' +
         'older build.'
  };
  log.warn(errorCodes.tag('STS-STORE-0044') +
           'used assertions: the ' + activeMode + ' store cannot hold the ' +
           'used-assertion history, so it is held in this process and an ' +
           'assertion spent before a restart will be accepted after one.');
  log.debug("Leaving setStore(). No usable group; memory.");
  return Promise.resolve(false);
}

// Back to this process's memory, for `persistence.stop()`. Writes whatever a
// snapshot store still owes first.
function clearStore() {
  log.debug("Entering clearStore().");
  const pending = flush();
  log.debug("Leaving clearStore().");
  return pending.then(function () {
    store = { mode: 'memory', kind: 'memory', driver: null, persistent: false,
              why: 'No store is open, so this history is held in this ' +
                   'process.' };
    partitions.clear();
    lastKnownLive.clear();
  });
}

// ---------------------------------------------------------------------------
// SNAPSHOT WRITES. A CLAIM AND A RELEASE ARE WRITTEN BEFORE THEY RETURN; A
// CONFIRMATION IS COALESCED.
//
// The claim must be on disk before the response can leave, because a crash
// after the client has its tokens and before the write is the restart-replay
// in miniature. A confirmation only turns `reserved` into `spent`, and both
// refuse a replay, so losing one to a crash changes a word on a console page
// and nothing about what is accepted — which is what makes coalescing it safe.
// ---------------------------------------------------------------------------
function writeRealm(realmId) {
  log.debug("Entering writeRealm(). realm=" + realmId);
  dirtyRealms.delete(realmId);
  const rows = [];
  partitionOf(realmId).forEach(function (row) { rows.push(row); });
  log.debug("Leaving writeRealm(). " + rows.length + " row(s).");
  return Promise.resolve(store.driver.saveUsedAssertions(realmId, rows));
}

function scheduleWrite(realmId) {
  log.debug("Entering scheduleWrite(). realm=" + realmId);
  dirtyRealms.add(realmId);
  if (!writeTimer) {
    writeTimer = setTimeout(function () {
      writeTimer = null;
      flush();
    }, 0);
    if (writeTimer.unref) {
      writeTimer.unref();
    }
  }
  log.debug("Leaving scheduleWrite().");
}

function flush() {
  log.debug("Entering flush().");
  if (store.kind !== 'snapshot' || !dirtyRealms.size) {
    log.debug("Leaving flush(). Nothing to write.");
    return Promise.resolve();
  }
  const owed = Array.from(dirtyRealms);
  log.debug("Leaving flush(). " + owed.length + " realm(s).");
  return Promise.all(owed.map(function (realmId) {
    return writeRealm(realmId).catch(function (e) {
      log.error(errorCodes.tag('STS-STORE-0045') +
                'used assertions: writing the history for the realm "' +
                realmId + '" failed: ' + ((e && e.message) || e) + '. A ' +
                'confirmation is lost; the rows it would have changed still ' +
                'refuse a replay.');
    });
  }));
}

// ---------------------------------------------------------------------------
// THE CLAIM.
//
// Resolves to `{ ok: true, claim }` for an assertion nobody has used, or to
// `{ ok: false, reason }` where reason is `replay` (a row is there: `existing`
// says whose), `full` (the realm holds `cap` live rows) or `store` (the store
// could not be asked — FAIL CLOSED, because an assertion this service cannot
// prove unused is not one it may accept).
//
// `request`, where there is one, binds the claim to its response: a 2xx makes
// it `spent`, anything else releases it. `keepBelow` moves that line for a
// response whose success is not a 2xx — the authorization endpoint answers a
// request object it issued on with a 302 or 303, so its claim passes 400 and
// is kept by any status under it. Without a request — a caller verifying an
// assertion outside a request, which is what the in-process tests do — the
// claim is spent at once, which is what every caller did before this file.
// ---------------------------------------------------------------------------
function claim(opts) {
  log.debug("Entering claim().");
  const o = opts || {};
  const format = String(o.format || '');
  const use = String(o.use || '');
  if (!FORMATS[format] || !USES[use] || !o.issuer || !o.identifier) {
    log.debug("Leaving claim(). A malformed claim.");
    return Promise.resolve({ ok: false, reason: 'store',
      why: 'a claim needs a format (' + Object.keys(FORMATS).join(', ') +
           '), a use (' + Object.keys(USES).join(', ') + '), an issuer and ' +
           'an identifier; this one had ' + JSON.stringify({ format: format,
             use: use, issuer: !!o.issuer, identifier: !!o.identifier }) });
  }
  const now = Date.now();
  const realmId = realms.currentId();
  const expiresAt = Math.max(now, Number(o.expiresAt) || now);
  const row = {
    realm: realmId,
    key: keyOf(format, o.issuer, o.identifier),
    format: format,
    use: use,
    issuer: clip(o.issuer),
    identifier: clip(o.identifier),
    clientId: clip(o.clientId || ''),
    subject: clip(o.subject || ''),
    state: o.request ? 'reserved' : 'spent',
    reservation: crypto.randomBytes(12).toString('base64url'),
    origin: store.driver && typeof store.driver.origin === 'function'
      ? String(store.driver.origin()) : 'local',
    usedAt: now,
    spentAt: o.request ? 0 : now,
    expiresAt: expiresAt
  };
  const cap = capOf();
  log.debug("Leaving claim().");
  const decided = store.kind === 'database'
    ? claimInDatabase(row, cap, now)
    : claimInMemory(row, cap, now);
  return decided.then(function (result) {
    if (result.ok && o.request) {
      bindToResponse(o.request, result.claim, Number(o.keepBelow) || 300);
    }
    return result;
  });
}

// ---------------------------------------------------------------------------
// A LOOK, WITHOUT A CLAIM (#35). Resolves to `{ used: true, existing }` when a
// live row holds this document, and `{ used: false }` otherwise — including
// when a database store cannot be asked, or has no statement for it, with
// `unknown: true` beside it.
//
// For a caller that meets one document more than once before it is spent: the
// authorization endpoint reads a request object before the sign-in screen and
// again after it, and refusing a replay on the FIRST pass saves a person a
// sign-in that could only end in the refusal. It decides nothing on its own.
// The claim is the authority, which is why a store that cannot answer here is
// not a refusal here — the claim that follows fails closed on the same store.
// ---------------------------------------------------------------------------
/**
 * @param {{ format?: string, issuer?: string, identifier?: string }} opts
 * @returns {Promise<{ used: boolean, unknown?: boolean,
 *                     existing?: Object }>}
 */
function peek(opts) {
  log.debug("Entering peek().");
  const o = opts || {};
  const format = String(o.format || '');
  if (!FORMATS[format] || !o.issuer || !o.identifier) {
    log.debug("Leaving peek(). Nothing to look for.");
    return Promise.resolve({ used: false });
  }
  const now = Date.now();
  const realmId = realms.currentId();
  const key = keyOf(format, o.issuer, o.identifier);
  if (store.kind !== 'database') {
    sweep(realmId, now);
    const existing = partitionOf(realmId).get(key);
    log.debug("Leaving peek(). " + (existing ? "Used." : "Not used."));
    return Promise.resolve(existing
      ? { used: true, existing: publicRow(existing) } : { used: false });
  }
  if (typeof store.driver.findUsedAssertion !== 'function') {
    log.debug("Leaving peek(). The store has no look-up.");
    return Promise.resolve({ used: false, unknown: true });
  }
  log.debug("Leaving peek(). Asking the database.");
  return Promise.resolve().then(function () {
    return store.driver.findUsedAssertion(realmId, key, now);
  }).then(function (found) {
    return found ? { used: true, existing: publicRow(found) }
      : { used: false };
  }, function (e) {
    log.warn(errorCodes.tag('STS-STORE-0046') +
             'used assertions: the ' + store.mode + ' store could not be ' +
             'asked whether a document from "' + clip(o.issuer) + '" has ' +
             'been used: ' + ((e && e.message) || e) + '. The look is ' +
             'answered "not known"; the claim that decides fails closed.');
    return { used: false, unknown: true };
  });
}

function claimInMemory(row, cap, now) {
  log.debug("Entering claimInMemory().");
  const live = sweep(row.realm, now);
  const rows = partitionOf(row.realm);
  const existing = rows.get(row.key);
  if (existing) {
    lastKnownLive.set(row.realm, live);
    log.debug("Leaving claimInMemory(). A replay.");
    return Promise.resolve({ ok: false, reason: 'replay',
                             existing: publicRow(existing) });
  }
  if (live >= cap) {
    lastKnownLive.set(row.realm, live);
    log.debug("Leaving claimInMemory(). Full.");
    return Promise.resolve({ ok: false, reason: 'full', live: live, cap: cap });
  }
  // SET BEFORE ANY AWAIT, which is what makes this atomic in one process: two
  // requests racing for one assertion cannot both reach this line, because
  // nothing between the `get` above and here yields.
  rows.set(row.key, row);
  lastKnownLive.set(row.realm, live + 1);
  if (store.kind !== 'snapshot') {
    log.debug("Leaving claimInMemory(). Claimed.");
    return Promise.resolve({ ok: true, claim: handleOf(row) });
  }
  log.debug("Leaving claimInMemory(). Claimed; writing.");
  return writeRealm(row.realm).then(function () {
    return { ok: true, claim: handleOf(row) };
  }, function (e) {
    // FAIL CLOSED, AND TAKE THE ROW BACK OUT. A claim this process cannot write
    // down is one a restart would forget, and accepting the assertion anyway
    // would be the restart-replay with a log line in front of it.
    rows.delete(row.key);
    log.error(errorCodes.tag('STS-STORE-0045') +
              'used assertions: the claim could not be written to the ' +
              store.mode + ' store: ' + ((e && e.message) || e) + '. The ' +
              'assertion is refused rather than accepted unrecorded.');
    return { ok: false, reason: 'store',
             why: 'the used-assertion history could not be written: ' +
                  ((e && e.message) || e) };
  });
}

function claimInDatabase(row, cap, now) {
  log.debug("Entering claimInDatabase().");
  maybePurge(now);
  log.debug("Leaving claimInDatabase().");
  return Promise.resolve().then(function () {
    return store.driver.claimUsedAssertion(row, { cap: cap, now: now });
  }).then(function (answer) {
    const a = answer || {};
    if (typeof a.live === 'number') {
      lastKnownLive.set(row.realm, a.live);
    }
    if (a.claimed) {
      return { ok: true, claim: handleOf(row) };
    }
    if (a.existing) {
      return { ok: false, reason: 'replay', existing: publicRow(a.existing) };
    }
    return { ok: false, reason: 'full', live: a.live, cap: cap };
  }, function (e) {
    log.error(errorCodes.tag('STS-STORE-0046') +
              'used assertions: the ' + store.mode + ' store could not be ' +
              'asked whether an assertion from "' + row.issuer + '" has been ' +
              'used: ' + ((e && e.message) || e) + '. It is refused.');
    return { ok: false, reason: 'store',
             why: 'the used-assertion history could not be consulted: ' +
                  ((e && e.message) || e) };
  });
}

function maybePurge(now) {
  log.debug("Entering maybePurge().");
  if (now - lastPurgeAt < PURGE_INTERVAL_MS) {
    log.debug("Leaving maybePurge(). Not due.");
    return;
  }
  lastPurgeAt = now;
  Promise.resolve().then(function () {
    return store.driver.purgeUsedAssertions(now);
  }).then(function (count) {
    if (count) {
      log.debug('used assertions: swept ' + count + ' expired row(s).');
    }
  }, function (e) {
    log.warn(errorCodes.tag('STS-STORE-0047') +
             'used assertions: sweeping expired rows failed: ' +
             ((e && e.message) || e) + '. They are ignored by every read and ' +
             'swept on the next attempt.');
  });
  log.debug("Leaving maybePurge(). Started.");
}

// What a caller holds: enough to settle this one row and nothing it could use
// to settle somebody else's.
function handleOf(row) {
  log.debug("Entering handleOf().");
  log.debug("Leaving handleOf().");
  return { realm: row.realm, key: row.key, reservation: row.reservation,
           state: row.state };
}

// The row as a page and the API draw it. The reservation is a capability to
// settle the row and is never handed out.
function publicRow(row) {
  log.debug("Entering publicRow().");
  log.debug("Leaving publicRow().");
  return {
    format: row.format, formatLabel: FORMATS[row.format] || row.format,
    use: row.use, useLabel: USES[row.use] || row.use,
    issuer: row.issuer, identifier: row.identifier,
    clientId: row.clientId || '', subject: row.subject || '',
    state: row.state, usedAt: Number(row.usedAt) || 0,
    spentAt: Number(row.spentAt) || 0, expiresAt: Number(row.expiresAt) || 0,
    origin: row.origin || ''
  };
}

// ---------------------------------------------------------------------------
// SETTLING. `finish` is the response having been written; `close` without it
// is the client going away first. Both listeners are attached; the first to
// run settles and the second finds nothing to do.
// ---------------------------------------------------------------------------
function bindToResponse(request, handle, keepBelow) {
  log.debug("Entering bindToResponse().");
  const res = request && request.res;
  if (!res || typeof res.once !== 'function') {
    // A request object with no response on it — a test double. Spent now,
    // which is the behaviour without a request at all.
    settle(handle, true);
    log.debug("Leaving bindToResponse(). No response; spent.");
    return;
  }
  let settled = false;
  const onFinish = function () {
    if (!settled) {
      settled = true;
      settle(handle, res.statusCode >= 200 && res.statusCode < keepBelow);
    }
  };
  const onClose = function () {
    if (!settled) {
      settled = true;
      settle(handle, false);
    }
  };
  res.once('finish', onFinish);
  res.once('close', onClose);
  log.debug("Leaving bindToResponse().");
}

function settle(handle, spent) {
  log.debug("Entering settle(). spent=" + spent);
  const at = Date.now();
  if (store.kind === 'database') {
    Promise.resolve().then(function () {
      return store.driver.settleUsedAssertion(handle.realm, handle.key,
                                              handle.reservation, spent, at);
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-STORE-0048') +
                'used assertions: ' + (spent ? 'confirming' : 'releasing') +
                ' a claim failed: ' + ((e && e.message) || e) + '. The row ' +
                'stays reserved until the assertion expires, which refuses ' +
                'a replay and ' +
                (spent ? 'changes nothing else.'
                       : 'also refuses the retry this release was for.'));
    });
    log.debug("Leaving settle(). Sent to the database.");
    return;
  }
  const rows = partitionOf(handle.realm);
  const row = rows.get(handle.key);
  if (!row || row.reservation !== handle.reservation) {
    log.debug("Leaving settle(). The row is not this claim's.");
    return;
  }
  if (spent) {
    row.state = 'spent';
    row.spentAt = at;
    if (store.kind === 'snapshot') {
      scheduleWrite(handle.realm);
    }
    log.debug("Leaving settle(). Spent.");
    return;
  }
  rows.delete(handle.key);
  if (store.kind === 'snapshot') {
    writeRealm(handle.realm).catch(function (e) {
      log.error(errorCodes.tag('STS-STORE-0048') +
                'used assertions: writing a release failed: ' +
                ((e && e.message) || e) + '. After a restart the assertion ' +
                'reads as used until it expires.');
    });
  }
  log.debug("Leaving settle(). Released.");
}

// ---------------------------------------------------------------------------
// READING, for the console page and `GET /admin-api/used-assertions`. Always
// the ambient realm, always unexpired rows only, newest first.
// ---------------------------------------------------------------------------
function list(opts) {
  log.debug("Entering list().");
  const o = opts || {};
  const now = Date.now();
  const realmId = realms.currentId();
  const filter = {
    q: String(o.q || '').trim().slice(0, 200),
    format: FORMATS[o.format] ? String(o.format) : '',
    use: USES[o.use] ? String(o.use) : '',
    state: STATES[o.state] ? String(o.state) : ''
  };
  const limit = Math.max(1, Math.floor(Number(o.limit) || 50));
  const offset = Math.max(0, Math.floor(Number(o.offset) || 0));
  if (store.kind === 'database') {
    log.debug("Leaving list(). Asking the database.");
    return Promise.resolve().then(function () {
      return store.driver.listUsedAssertions(realmId, {
        now: now, q: filter.q, format: filter.format, use: filter.use,
        state: filter.state, limit: limit, offset: offset
      });
    }).then(function (answer) {
      const a = answer || {};
      if (typeof a.live === 'number') {
        lastKnownLive.set(realmId, a.live);
      }
      return { rows: (a.rows || []).map(publicRow), matched: a.total || 0,
               live: a.live || 0, filter: filter };
    });
  }
  const live = sweep(realmId, now);
  lastKnownLive.set(realmId, live);
  const needle = filter.q.toLowerCase();
  const matched = [];
  partitionOf(realmId).forEach(function (row) {
    if (filter.format && row.format !== filter.format) {
      return;
    }
    if (filter.use && row.use !== filter.use) {
      return;
    }
    if (filter.state && row.state !== filter.state) {
      return;
    }
    if (needle && (row.issuer + ' ' + row.identifier + ' ' + row.clientId +
                   ' ' + row.subject).toLowerCase().indexOf(needle) < 0) {
      return;
    }
    matched.push(row);
  });
  matched.sort(function (a, b) { return b.usedAt - a.usedAt; });
  log.debug("Leaving list(). " + matched.length + " matched.");
  return Promise.resolve({
    rows: matched.slice(offset, offset + limit).map(publicRow),
    matched: matched.length, live: live, filter: filter
  });
}

// How a replay refusal says what the document was spent AS, which is the one
// thing a client author cannot work out from their own request once a JWT that
// authenticated a client is refused as a grant, or the reverse. A clause, with
// its leading dash, so each verifier can put it after its own sentence.
function usedAs(existing) {
  log.debug("Entering usedAs().");
  if (!existing) {
    log.debug("Leaving usedAs(). Nothing to say.");
    return '';
  }
  const inFlight = existing.state === 'reserved'
    ? ', by a request that has not finished yet' : '';
  log.debug("Leaving usedAs().");
  if (existing.use === 'request-object') {
    log.debug("Leaving usedAs(). A request object.");
    return ' — as an RFC 9101 request object' + inFlight;
  }
  return ' — ' + (existing.format === 'saml' ? 'under RFC 7522 section ' +
    (existing.use === 'authorization-grant' ? '2.1' : '2.2')
    : 'as ' + (existing.use === 'authorization-grant'
      ? 'an authorization grant' : 'a client assertion')) + inFlight;
}

// What is known without asking anybody: where the history is held, whether it
// survives a restart, the cap, and the last live count this process saw.
function summary() {
  log.debug("Entering summary().");
  const realmId = realms.currentId();
  let live = lastKnownLive.has(realmId) ? lastKnownLive.get(realmId) : null;
  if (store.kind !== 'database') {
    live = sweep(realmId, Date.now());
  }
  log.debug("Leaving summary().");
  return {
    store: store.mode, kind: store.kind, persistent: store.persistent,
    atomicAcrossProcesses: store.kind === 'database', why: store.why,
    cap: capOf(), live: live,
    liveIsCurrent: store.kind !== 'database'
  };
}

// A realm that is removed takes its history with it: the realm's clients and
// their keys are gone too, so nothing it held could verify again. Called
// synchronously by `realms.remove()`, which catches a throw per hook.
realms.onRemove(function (realmId) {
  log.debug("Entering the used-assertions realm removal hook. realm=" +
            realmId);
  partitions.delete(realmId);
  dirtyRealms.delete(realmId);
  lastKnownLive.delete(realmId);
  if (store.driver && typeof store.driver.removeUsedAssertions === 'function') {
    Promise.resolve().then(function () {
      return store.driver.removeUsedAssertions(realmId);
    }).catch(function (e) {
      log.warn(errorCodes.tag('STS-STORE-0047') +
               'used assertions: removing the history of the realm "' +
               realmId + '" failed: ' + ((e && e.message) || e) + '. Its ' +
               'rows expire on their own.');
    });
  }
  log.debug("Leaving the used-assertions realm removal hook.");
});

module.exports = {
  FORMATS: FORMATS,
  USES: USES,
  STATES: STATES,
  DATABASE_GROUP: DATABASE_GROUP,
  SNAPSHOT_GROUP: SNAPSHOT_GROUP,
  keyOf: keyOf,
  setStore: setStore,
  clearStore: clearStore,
  flush: flush,
  claim: claim,
  peek: peek,
  usedAs: usedAs,
  list: list,
  summary: summary
};
