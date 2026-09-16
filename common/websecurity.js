// @ts-check
'use strict';
//
// File: websecurity.js
//
// ---------------------------------------------------------------------------
// THE TWO CONTROLS EVERY BROWSER-FACING FORM IN THIS SERVICE NEEDS, AND HAD
// NEITHER OF (2026-09-06).
//
// This service grew a console, a sign-in screen, a consent screen and now a
// User Portal, and every state-changing control on all four was a plain form
// POST with nothing but `SameSite=Lax` between it and a cross-site request.
// That is a MITIGATION and not a defence — it is a browser default that a
// browser may not apply, it does nothing about a same-site subdomain, and it is
// exactly the kind of thing that is true until the day somebody deploys behind
// a shared origin.
//
// ---------------------------------------------------------------------------
// 1. CSRF — OWASP A01/A08.
//
// A per-session token, in a hidden field, checked on every POST that changes
// something. **THE TOKEN IS DERIVED FROM THE SESSION AND NOT STORED BESIDE
// IT**: HMAC-SHA256 over the session id under a key every process shares where
// a store can share one (per process otherwise — see THE CSRF KEY below), so
// there is no second map to keep in step with the session store, nothing to
// sweep when a session ends, and a token cannot outlive the session it belongs
// to. That is the "signed double submit" pattern and it is what lets this be
// one function rather than a store.
//
// **THE COMPARISON IS CONSTANT-TIME**, through `crypto.js`'s
// `constantTimeEquals()` — the same one every other secret comparison here
// uses. A byte-by-byte early return on a CSRF token is a timing oracle, and it
// is the kind that gets written by accident because `===` is right for
// everything else on the page.
//
// **A REQUEST WITH NO SESSION IS NOT REFUSED FOR CSRF**, and that is deliberate
// rather than a hole: there is nothing to forge on behalf of an anonymous
// caller, and refusing would break the sign-in POST itself — which is the one
// form that CANNOT carry a session token, because the session is what it is
// about to create. Login is protected by being unauthenticated: an attacker who
// can make somebody's browser POST a login they already know the credentials
// for has achieved nothing.
//
// ---------------------------------------------------------------------------
// 2. RATE LIMITING — OWASP A04/A07.
//
// Nothing throttled the sign-in screen, and after this change nothing would
// have throttled an activation URL either — which is a 32-byte token that
// completes an account setup, so it is brute-forceable at network speed in
// exactly the way a password is.
//
// **TWO BUCKETS, AND BOTH ARE NEEDED.** By IDENTITY, so one account cannot be
// ground down from many addresses; by ADDRESS, so one address cannot grind down
// many accounts. Either alone is the half an attacker does not use.
//
// **IT IS A FIXED WINDOW AND NOT A TOKEN BUCKET**, which is the cruder choice
// and the right one here: what it has to stop is thousands of guesses a second,
// the exact refill semantics do not matter for that, and a window somebody can
// read off the page ("5 in 60 seconds") is one an operator can reason about.
//
// **A REFUSAL IS AUDITED**, because a lockout nobody can see is a support call
// with no evidence in it.
//
// A LIBRARY (rule 3): it registers no route. It requires `config`, `crypto`,
// `helpers`, `realms`, the error-code table, `client_address` and three
// `cluster/` libraries, none of which requires it back.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const { log } = require('./helpers');
const config = require('./config');
const stsCrypto = require('./crypto');
// PER PROCESS AND NOT PER REALM — see the store below. Required only for
// `sharedMap()`, and it is a LEAF that registers no route, so this cannot
// move a route or join a cycle.
const realms = require('./realms');
// The registry of failure codes, a LEAF. A refusal answered here carries its
// code NON-ENUMERABLY, so a caller that renders it can mark its response with
// `errorCodes.codeOf(result)` and nothing about the object serialises
// differently.
const errorCodes = require('./error_codes');

// ---------------------------------------------------------------------------
// THE CSRF KEY, FROM `cluster/cluster_secrets.js` SINCE 2026-09-14 (#46).
//
// It was `randomBytes(32)` here, per process and regenerated on every start,
// with the argument that a CSRF token means nothing past its session and a
// session did not survive a restart. Both halves moved: product mode on
// postgres persists sessions, and several containers serve one session. A form
// drawn by one node and posted to another carried a token the second could not
// verify, and without sticky sessions that is most of every console's forms —
// `STS-HTTP-0016` on (N-1)/N of them, never converging, because neither key was
// wrong. So the key is the cluster's: generated once, sealed in the store, and
// read by every process before it serves. Where nothing can share it, it is per
// process exactly as before — that module says which. READ PER TOKEN rather
// than captured here, because the shared value arrives after this file loads.
// ---------------------------------------------------------------------------
const clusterSecrets = require('../cluster/cluster_secrets');
// The table active-active mode is held to, a LEAF. The CSRF key here, the ACME
// nonce key in acme/acme_jws.js and the SSF receiver secret in
// ssf/ssf_receivers.js were moved onto the cluster's shared secrets together,
// and this is where the capability for all three is declared.
const capabilities = require('../cluster/cluster_capabilities');
capabilities.provide('secrets.protocol-keys');
// ONE BUDGET FOR EVERY NODE (2026-09-14, #46 section 2): the windows the
// limiter counts in when a store is shared. A LIBRARY that requires
// `persistence.js` lazily, so this closes no cycle. See `attemptShared()`.
const clusterCounters = require('../cluster/cluster_counters');
// Who a request came from. A LEAF. See `addressOf()`.
const clientAddress = require('./client_address');
const CSRF_FIELD = 'csrf_token';

// The token for a session. A pure function of the id, so it is the same on
// every page of one session and needs no storage.
function tokenFor(sessionId) {
  log.debug("Entering tokenFor().");
  const id = String(sessionId || '');
  if (!id) {
    log.debug("Leaving tokenFor().");
    return '';
  }
  log.debug("Leaving tokenFor().");
  return nodeCrypto.createHmac('sha256', clusterSecrets.get('csrf'))
                   .update(id)
                   .digest('base64url');
}

// The hidden input a form carries. Returns '' when there is no session, so a
// form on an unauthenticated page renders unchanged.
function field(sessionId) {
  log.debug("Entering field().");
  const token = tokenFor(sessionId);
  if (!token) {
    log.debug("Leaving field().");
    return '';
  }
  log.debug("Leaving field().");
  return '<input type="hidden" name="' + CSRF_FIELD + '" value="' + token +
         '">';
}

// Does this POST carry the right token for this session?
//
// `ok: true` with `reason: 'no-session'` for a request with no session — see
// the header for why that is not a hole.
function checkCsrf(sessionId, body) {
  log.debug("Entering checkCsrf().");
  const id = String(sessionId || '');
  if (!id) {
    log.debug("Leaving checkCsrf().");
    return { ok: true, reason: 'no-session' };
  }
  const presented = String((body || {})[CSRF_FIELD] || '');
  if (!presented) {
    log.debug("Leaving checkCsrf().");
    return errorCodes.mark({ ok: false, reason: 'missing',
             detail: 'this form carried no ' + CSRF_FIELD + '. Every ' +
                     'state-changing form in this service does; a request ' +
                     'without one did not come from a page this service ' +
                     'drew.' },
                           'STS-HTTP-0015');
  }
  const same = stsCrypto.constantTimeEquals(presented, tokenFor(id));
  log.debug("Leaving checkCsrf().");
  return same
    ? { ok: true, reason: 'verified' }
    : errorCodes.mark({ ok: false, reason: 'mismatch',
        detail: 'the ' + CSRF_FIELD + ' presented is not this session\'s. It ' +
                'belongs to a different session, or to one that has ended.' },
                      'STS-HTTP-0016');
}

// ---------------------------------------------------------------------------
// THE RATE LIMITER.
//
// PER PROCESS and not per realm, deliberately (and per CLUSTER where a store is
// shared — see `attemptShared()`): an attacker choosing which realm to guess in
// must not get a fresh allowance for each, and the buckets are keyed by a
// string the caller composes — which is where the realm goes if a caller wants
// it counted separately.
// ---------------------------------------------------------------------------
// -------------------------------------------------------------------------
// PERSISTED, AND SHARED RATHER THAN PER REALM (2026-09-06).
// `realms.sharedMap()` is a plain Map that reports its writes so product mode
// can write them down; `scope: 'shared'` is what says the store deliberately
// has no realm in it, which is the discriminator `tests/realm_isolation.js`
// checks against.
// -------------------------------------------------------------------------
// **AND PERSISTED FOR THE SAME REASON IT IS PER PROCESS**: an attacker who
// could empty the buckets by making the service restart would have a fresh
// allowance whenever they wanted one, which is the opposite of what the
// limiter is for.
const buckets = realms.sharedMap({ persist: 'security.rateLimitBuckets',
                                   scope: 'shared' });
const MAX_BUCKETS = 20000;

function windowMs() {
  log.debug("Entering windowMs().");
  log.debug("Leaving windowMs().");
  return Math.max(1, Number(config.value('security.rateLimitWindowS') || 60)) *
         1000;
}

function limitFor(kind) {
  log.debug("Entering limitFor().");
  const key = kind === 'address' ? 'security.rateLimitPerAddress'
                                 : 'security.rateLimitPerIdentity';
  log.debug("Leaving limitFor().");
  return Math.max(1, Number(config.value(key) || 5));
}

// The address a request came from, honouring the proxy setting this service
// already has — a limiter that counted every request from one load balancer as
// one address would lock out the world on the first attacker.
//
// **`common/client_address.js`'S ANSWER SINCE 2026-09-14 (#46).** The rule
// that was here — the left-most `X-Forwarded-For` entry whenever
// `global.trustProxy` was on, the socket otherwise — let a caller that reached
// a node directly choose a fresh address per guess, and answered `unknown` for
// every caller in a request worker, whose socket has no peer address. That
// file argues the boundary; with `global.trustedProxies` empty it is the old
// rule exactly, outside a request worker.
function addressOf(req) {
  log.debug("Entering addressOf().");
  const address = clientAddress.clientAddressOf(req);
  log.debug("Leaving addressOf().");
  return address;
}

function prune(now) {
  log.debug("Entering prune().");
  if (buckets.size < MAX_BUCKETS) {
    log.debug("Leaving prune().");
    return;
  }
  // Oldest first — Map iterates in insertion order — which is the same rule
  // admin_stats.js's caps follow. A limiter that grew without bound would be a
  // denial of service of its own.
  const cutoff = Math.floor(MAX_BUCKETS / 4);
  let dropped = 0;
  for (const key of buckets.keys()) {
    if (dropped >= cutoff) break;
    buckets.delete(key);
    dropped += 1;
  }
  log.warn('websecurity: the rate-limit table reached ' + MAX_BUCKETS +
           ' entries and the oldest ' + dropped + ' were dropped. That is a ' +
           'cap on memory rather than a decision about any one caller.');
  log.debug("Leaving prune().");
}

// Count one attempt. Answers whether it is allowed, and says which bucket
// refused so the message can be honest without naming the other one.
//
// ---------------------------------------------------------------------------
// `limit` IS AN OPTIONAL FOURTH ARGUMENT, AND IT EXISTS BECAUSE ONE NUMBER
// CANNOT SERVE TWO RHYTHMS (2026-09-06).
//
// The two settings this reads are FIVE and TWENTY, and they are right for what
// they were written for: a SIGN-IN, where five attempts a minute is generous
// and a sixth is somebody guessing. **A machine-to-machine door is the
// opposite shape** — `POST /xacml/pip` is called once per access decision by a
// remote enforcement point, so a busy one makes several a second and every one
// of them is legitimate.
//
// A door like that had two options before this argument existed: share the
// sign-in numbers and be switched off for its only caller, or not be limited
// at all. **The first is worse than the second**, because the caller degrades
// silently — the PEP falls back to deciding on what the request asserts and
// reports nothing wrong.
//
// So a caller may name its own ceiling, and the WINDOW stays shared: an
// operator who widens `security.rateLimitWindowS` widens every bucket at once,
// which is what that setting is for. **The default is unchanged** — omit the
// argument and this behaves exactly as it did, which is what every existing
// caller does.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AND `limit` MAY NAME THE TWO BUCKETS SEPARATELY (2026-09-12).
//
// One number for both was right for `POST /xacml/pip`, whose caller is one
// machine at one address. It was wrong for the portal's signing-key door,
// which passed five: the IDENTITY bucket was the point (five key generations
// a minute for one person), and the ADDRESS bucket then meant five for
// everybody behind one NAT or proxy — an office sharing an allowance a single
// person could spend. So `{ identity: n, address: m }` is accepted beside a
// bare number, a member left out falls back to the shared setting for that
// bucket, and a bare number means exactly what it always did.
// ---------------------------------------------------------------------------
function namedLimit(limit, kind) {
  log.debug("Entering namedLimit().");
  const raw = (limit && typeof limit === 'object') ? limit[kind] : limit;
  log.debug("Leaving namedLimit().");
  return Number(raw) > 0 ? Math.floor(Number(raw)) : 0;
}

function attempt(what, req, identity, limit) {
  log.debug('Entering attempt(). what=' + what);
  const now = Date.now();
  const span = windowMs();
  const checks = [
    { kind: 'identity',
      key: what + '|id|' + String(identity || '').toLowerCase(),
      limit: namedLimit(limit, 'identity') || limitFor('identity'),
      on: !!identity },
    { kind: 'address', key: what + '|ip|' + addressOf(req),
      limit: namedLimit(limit, 'address') || limitFor('address'), on: true }
  ];
  prune(now);
  let refusal = null;
  checks.forEach(function (check) {
    if (!check.on) return;
    const row = buckets.get(check.key);
    if (!row || row.until <= now) {
      buckets.set(check.key, { count: 1, until: now + span });
      return;
    }
    row.count += 1;
    // SET AGAIN, NOT ONLY EDITED IN PLACE (2026-09-14). `buckets` journals a
    // `set()` and a `delete()`, and an increment made on the row alone was
    // never written down — so in the request-worker pool only a bucket's FIRST
    // failure reached the other workers, each kept its own count, and a
    // caller spreading its guesses across three workers was never refused.
    // `sts_est_enrollment` met it in `dispatch` mode: three wrong passwords in
    // a row, 401, 401, 401 where the third must be 429. Written down, the
    // read barrier makes the next request see the count. Two concurrent
    // attempts can still both read the older count, so the limit is a limit
    // to within the concurrency of one caller, not an exact one.
    buckets.set(check.key, row);
    if (row.count > check.limit && !refusal) {
      refusal = { kind: check.kind, limit: check.limit,
                  retryAfterS: Math.ceil((row.until - now) / 1000) };
    }
  });
  if (refusal) {
    const code = refusal.kind === 'address' ? 'STS-HTTP-0018' : 'STS-HTTP-0017';
    log.warn(errorCodes.tag(code) + 'websecurity: too many "' + what + '" ' +
        'attempts (' +
             refusal.kind + ' bucket, limit ' + refusal.limit + ' per ' +
             Math.round(span / 1000) + 's). Refusing for another ' +
             refusal.retryAfterS + 's.');
    log.debug('Leaving attempt(). Refused.');
    return errorCodes.mark({ ok: false, kind: refusal.kind,
             limit: refusal.limit,
             retryAfterS: refusal.retryAfterS,
             detail: 'Too many attempts. Wait ' + refusal.retryAfterS +
                     ' seconds and try again.' }, code);
  }
  log.debug('Leaving attempt(). Allowed.');
  return { ok: true };
}

// ---------------------------------------------------------------------------
// blocked() — IS THIS CALLER OVER A LIMIT RIGHT NOW, WITHOUT COUNTING ANYTHING
// (2026-09-12).
//
// `attempt()` counts and answers in one call, which is right for a sign-in
// screen: every POST is somebody trying a password. It is wrong for a door
// whose SUCCESSES are many and legitimate — an LDAP connection pool binds on
// every connection it opens, fifty at once from one address, and counting those
// would lock an application out of its own directory for being busy.
//
// So that door asks `blocked()` first, which reads the buckets and changes
// nothing, counts only a FAILURE with `attempt()`, and clears on success with
// `succeeded()`. The refusal a blocked caller gets is decided before its
// password is looked at, so a right guess during a lockout is refused exactly
// like a wrong one and teaches the guesser nothing. Same buckets, same window,
// same limits and the same `limit` argument as `attempt()` — one limiter with a
// read beside its write, not a second limiter.
// ---------------------------------------------------------------------------
function blocked(what, req, identity, limit) {
  log.debug('Entering blocked(). what=' + what);
  const now = Date.now();
  const checks = [
    { kind: 'identity',
      key: what + '|id|' + String(identity || '').toLowerCase(),
      limit: namedLimit(limit, 'identity') || limitFor('identity'),
      on: !!identity },
    { kind: 'address', key: what + '|ip|' + addressOf(req),
      limit: namedLimit(limit, 'address') || limitFor('address'), on: true }
  ];
  let refusal = null;
  checks.forEach(function (check) {
    if (!check.on || refusal) return;
    const row = buckets.get(check.key);
    // AT the limit is blocked, where `attempt()` refuses only PAST it: that
    // call counts the attempt it is deciding about, and this one does not — so
    // `limit` failures have been spent and the next try is the one over.
    if (row && row.until > now && row.count >= check.limit) {
      refusal = { kind: check.kind, limit: check.limit,
                  retryAfterS: Math.ceil((row.until - now) / 1000) };
    }
  });
  if (!refusal) {
    log.debug('Leaving blocked(). Not blocked.');
    return null;
  }
  const code = refusal.kind === 'address' ? 'STS-HTTP-0018' : 'STS-HTTP-0017';
  log.debug('Leaving blocked(). Blocked by the ' + refusal.kind + ' bucket.');
  return errorCodes.mark({ ok: false, kind: refusal.kind, limit: refusal.limit,
           retryAfterS: refusal.retryAfterS,
           detail: 'Too many failed attempts. Wait ' + refusal.retryAfterS +
                   ' seconds and try again.' }, code);
}

// Forget the counters for one identity — what a SUCCESSFUL sign-in does, so
// that somebody who mistyped a password four times is not still near the limit
// once they get it right.
//
// `options.keepAddress` LEAVES THE ADDRESS BUCKET ALONE (2026-09-12), and a
// door whose successes are cheap to come by needs it. On an LDAP bind, anybody
// holding ONE working password could otherwise clear their address's failure
// count between guesses at every other DN by binding as themselves once — the
// address limit would never be reached by the one caller it exists for.
function succeeded(what, req, identity, options) {
  log.debug("Entering succeeded().");
  if (identity) {
    buckets.delete(what + '|id|' + String(identity).toLowerCase());
  }
  if (!(options && options.keepAddress)) {
    buckets.delete(what + '|ip|' + addressOf(req));
  }
  log.debug("Leaving succeeded().");
}

// ---------------------------------------------------------------------------
// ONE BUDGET FOR EVERY NODE: `attemptShared()`, `blockedShared()` AND
// `succeededShared()` (2026-09-14, #46 section 2).
//
// The three functions above are right for one process and wrong for several,
// in two ways that multiply. Each node refused only on ITS OWN count, so a
// guesser spreading attempts over N nodes had N budgets; and the buckets are a
// replicated Map whose rows are whole values, so two nodes counting one bucket
// at once each read 3 and each wrote 4 — last writer wins on a counter — and
// even the counts that did replicate were short. `sts_est_enrollment` had
// already met the one-container half of it (see the comment in `attempt()`),
// and the fix there, writing the row down on every count, made the count
// visible and left it racy.
//
// So when the store is shared these count in `cluster/cluster_counters.js`'s
// windows: one conditional upsert per bucket, under the row lock, returning
// the count THIS attempt made. The decision is taken on that number, which is
// the same number whichever node asked, and a burst of concurrent guesses
// across nodes is refused at exactly the limit — every one of them landed in
// the one row.
//
// **SAME BUCKETS, SAME WINDOW, SAME LIMITS, SAME REFUSALS**, and the same
// codes (`STS-HTTP-0017` / `-0018`): the key is the string the synchronous
// functions use, digested, and the realm is '' for the reason the header of
// this section gives. A caller changes one name and an `await`.
//
// **WITH NO SHARED STORE THEY ARE THE SYNCHRONOUS FUNCTIONS**, resolved —
// memory and ldif stores, development mode, `npm test` — so nothing that does
// not share a store changes by a byte.
//
// **A STORE THAT CANNOT BE ASKED FALLS BACK TO THIS PROCESS'S BUCKETS**, logged
// `STS-CLUSTER-0023`, and that is a deliberate difference from a claim, which
// refuses. A claim that cannot be proven spent must not be accepted, because
// the harm is a credential used twice. A limiter that cannot reach the shared
// count still has a count — its own, which is what every node had before this
// — and refusing every sign-in for as long as the database is unreachable
// would turn a database blip into a sign-in outage nobody caused. For that
// window the budget is per node again, and the log says so.
//
// **`blockedShared()` + a counted failure was still not atomic**, exactly as
// `blocked()` + `attempt()` is not on one node: concurrent attempts all read
// the count before any failure is added — measured with forty concurrent
// wrong client secrets against a limit of 5 on two nodes: 19 to 34 answered
// `invalid_client`. **SINCE 2026-09-14 THE ANSWER IS DECIDED ON THE ATOMIC
// COUNT** — `failedShared()` and `succeededShared({ unlessBlocked })` below —
// and the check before verification stays as the cheap refusal it was.
//
// **WHY NOT COUNT BEFORE CHECKING — THE RESERVATION `attemptShared()` IS —
// AT THESE DOORS.** Counting every attempt at admission bounds guesses
// exactly, and it also counts every SUCCESS that is still in flight: a
// confidential client making six concurrent token requests from one host
// (the secret bucket is client and address), or an LDAP connection pool
// binding fifty connections as one DN, would be refused for being busy —
// the reason `blocked()` exists at all. So these doors verify first and
// decide the ANSWER after, atomically:
//
//   * a failure increments; an increment that took the bucket PAST the limit
//     is answered with the lockout, not with "wrong" — so at most `limit`
//     failures per window are ever answered as failures, across every node
//     and every concurrent request;
//   * a success is answered only while the bucket is under the limit (a
//     read, so concurrent successes cost nothing); at the limit it gets the
//     same lockout, so a right guess racing a burst that spent the budget
//     teaches nothing. What is left is the right guess that lands before the
//     burst's failures have counted — the race a lockout decided before
//     verification had too, bounded by the same `limit`.
//
// A door whose successes are rare and sequential (a sign-in screen, a
// one-time code) keeps `attemptShared()`, which is the stricter property.
// ---------------------------------------------------------------------------
const SHARED_SCOPE = 'security.rate-limit';

function bucketChecks(what, req, identity, limit) {
  log.debug("Entering bucketChecks().");
  log.debug("Leaving bucketChecks().");
  return [
    { kind: 'identity',
      key: what + '|id|' + String(identity || '').toLowerCase(),
      limit: namedLimit(limit, 'identity') || limitFor('identity'),
      on: !!identity },
    { kind: 'address', key: what + '|ip|' + addressOf(req),
      limit: namedLimit(limit, 'address') || limitFor('address'), on: true }
  ].filter(function (check) {
    return check.on;
  });
}

function sharedRefusal(refusal, detailLead) {
  log.debug("Entering sharedRefusal().");
  const code = refusal.kind === 'address' ? 'STS-HTTP-0018' : 'STS-HTTP-0017';
  log.debug("Leaving sharedRefusal().");
  return errorCodes.mark({ ok: false, kind: refusal.kind,
           limit: refusal.limit, retryAfterS: refusal.retryAfterS,
           shared: true,
           detail: detailLead + ' Wait ' + refusal.retryAfterS +
                   ' seconds and try again.' }, code);
}

function secondsLeft(remainingMs) {
  log.debug("Entering secondsLeft().");
  log.debug("Leaving secondsLeft().");
  return Math.max(1, Math.ceil((Number(remainingMs) || 0) / 1000));
}

function attemptShared(what, req, identity, limit) {
  log.debug('Entering attemptShared(). what=' + what);
  if (!clusterCounters.sharesWindows()) {
    log.debug('Leaving attemptShared(). No shared store: attempt().');
    return Promise.resolve(attempt(what, req, identity, limit));
  }
  const checks = bucketChecks(what, req, identity, limit);
  const span = windowMs();
  log.debug('Leaving attemptShared(). Counting in the store.');
  return Promise.all(checks.map(function (check) {
    return clusterCounters.countInWindow({ scope: SHARED_SCOPE,
                                           key: check.key, realm: '',
                                           windowMs: span });
  })).then(function (answers) {
    if (answers.some(function (answer) { return !answer.ok; })) {
      log.warn(errorCodes.tag('STS-CLUSTER-0023') + 'websecurity: the "' +
               what + '" attempt could not be counted in the shared store; ' +
               'it is counted in this process\'s buckets, so for now the ' +
               'budget is per node.');
      return attempt(what, req, identity, limit);
    }
    let refusal = null;
    checks.forEach(function (check, i) {
      if (!refusal && answers[i].count > check.limit) {
        refusal = { kind: check.kind, limit: check.limit,
                    retryAfterS: secondsLeft(answers[i].remainingMs) };
      }
    });
    if (!refusal) {
      return { ok: true, shared: true };
    }
    log.warn(errorCodes.tag(refusal.kind === 'address' ? 'STS-HTTP-0018'
                                                      : 'STS-HTTP-0017') +
             'websecurity: too many "' + what + '" attempts across the ' +
             'cluster (' + refusal.kind + ' bucket, limit ' + refusal.limit +
             ' per ' + Math.round(span / 1000) + 's). Refusing for another ' +
             refusal.retryAfterS + 's.');
    return sharedRefusal(refusal, 'Too many attempts.');
  });
}

function blockedShared(what, req, identity, limit) {
  log.debug('Entering blockedShared(). what=' + what);
  if (!clusterCounters.sharesWindows()) {
    log.debug('Leaving blockedShared(). No shared store: blocked().');
    return Promise.resolve(blocked(what, req, identity, limit));
  }
  const checks = bucketChecks(what, req, identity, limit);
  log.debug('Leaving blockedShared(). Reading the store.');
  return Promise.all(checks.map(function (check) {
    return clusterCounters.peekWindow({ scope: SHARED_SCOPE, key: check.key,
                                        realm: '' });
  })).then(function (answers) {
    if (answers.some(function (answer) { return !answer.ok; })) {
      log.warn(errorCodes.tag('STS-CLUSTER-0023') + 'websecurity: the "' +
               what + '" buckets could not be read from the shared store; ' +
               'this process\'s own buckets decide, so for now the budget ' +
               'is per node.');
      return blocked(what, req, identity, limit);
    }
    let refusal = null;
    // AT the limit, for `blocked()`'s reason: this counts nothing.
    checks.forEach(function (check, i) {
      if (!refusal && answers[i].count >= check.limit) {
        refusal = { kind: check.kind, limit: check.limit,
                    retryAfterS: secondsLeft(answers[i].remainingMs) };
      }
    });
    return refusal ? sharedRefusal(refusal, 'Too many failed attempts.')
      : null;
  });
}

// ---------------------------------------------------------------------------
// failedShared() — COUNT A FAILURE AND SAY WHETHER IT IS STILL ANSWERABLE AS
// ONE (2026-09-14). Resolves to null while the increment this failure made is
// within the limit, and to the lockout refusal once it is past it. The count
// is `attemptShared()`'s — the one atomic increment — so the decision is the
// same whichever node, however many at once. See the block above.
// ---------------------------------------------------------------------------
function failedShared(what, req, identity, limit) {
  log.debug('Entering failedShared(). what=' + what);
  log.debug('Leaving failedShared().');
  return attemptShared(what, req, identity, limit).then(function (counted) {
    return counted && counted.ok === false ? counted : null;
  });
}

// Whether the shared functions above count in a store every process shares —
// for a caller that must stay synchronous where nothing is shared (the LDAP
// bind, whose operation is run synchronously by its in-process callers).
function sharesLimits() {
  log.debug("Entering sharesLimits().");
  log.debug("Leaving sharesLimits().");
  return clusterCounters.sharesWindows();
}

// Resolves when the store has forgotten the buckets (or could not be asked,
// which is logged). This process's own buckets are cleared first and always,
// so a count made while the store was unreachable is forgotten too.
//
// `options.unlessBlocked` (2026-09-14): a verified credential is answered only
// while the bucket is under the limit — see the block above `failedShared()`.
// Resolves to the lockout refusal, clearing nothing, when it is at the limit;
// null otherwise.
function succeededShared(what, req, identity, options) {
  log.debug("Entering succeededShared().");
  if (options && options.unlessBlocked) {
    log.debug("Leaving succeededShared(). Asking first.");
    return blockedShared(what, req, identity,
                         options.limit).then(function (lockedOut) {
      if (lockedOut) {
        return lockedOut;
      }
      return succeededShared(what, req, identity,
                             { keepAddress: !!options.keepAddress })
        .then(function () {
          return null;
        });
    });
  }
  succeeded(what, req, identity, options);
  if (!clusterCounters.sharesWindows()) {
    log.debug("Leaving succeededShared(). No shared store.");
    return Promise.resolve();
  }
  const keys = [];
  if (identity) {
    keys.push(what + '|id|' + String(identity).toLowerCase());
  }
  if (!(options && options.keepAddress)) {
    keys.push(what + '|ip|' + addressOf(req));
  }
  log.debug("Leaving succeededShared(). Clearing " + keys.length +
            " window(s).");
  return Promise.all(keys.map(function (key) {
    return clusterCounters.clearWindow({ scope: SHARED_SCOPE, key: key,
                                         realm: '' });
  })).then(function () {
    return undefined;
  });
}

// DECLARED AT REQUIRE TIME, for `cluster/cluster.js`'s reason. The shared
// functions above are the fix; every door that counts — the sign-in screen,
// the password grant, the second-factor steps, the portal's links and forms,
// client secrets, the enrollment throttles, GNAP's user code, the PIP and the
// LDAP bind — calls them.
capabilities.provide('security.rate-limits');

// For the console and the tests.
function report() {
  log.debug("Entering report().");
  log.debug("Leaving report().");
  return {
    csrf: { field: CSRF_FIELD,
            how: 'HMAC-SHA256 of the session id under a per-process key, ' +
                 'compared in constant time. Derived rather than stored, so ' +
                 'a token cannot outlive its session and there is no second ' +
                 'map to sweep.' },
    rateLimit: {
      windowS: Math.round(windowMs() / 1000),
      perIdentity: limitFor('identity'),
      perAddress: limitFor('address'),
      bucketsHeld: buckets.size,
      cap: MAX_BUCKETS,
      // Whether the count is the cluster's (`sts_cluster_windows`) rather than
      // `bucketsHeld` above, which is then only what a fallback counted here.
      sharedAcrossNodes: clusterCounters.sharesWindows()
    }
  };
}

// Tests only — see the same note on keystore.reset().
function reset() {
  log.debug("Entering reset().");
  buckets.clear();
  log.debug("Leaving reset().");
}

module.exports = {
  CSRF_FIELD: CSRF_FIELD,
  tokenFor: tokenFor,
  field: field,
  checkCsrf: checkCsrf,
  attempt: attempt,
  blocked: blocked,
  succeeded: succeeded,
  attemptShared: attemptShared,
  blockedShared: blockedShared,
  succeededShared: succeededShared,
  failedShared: failedShared,
  sharesLimits: sharesLimits,
  addressOf: addressOf,
  report: report,
  reset: reset
};
