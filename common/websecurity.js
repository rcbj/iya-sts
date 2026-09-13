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
// IT**: HMAC-SHA256 over the session id under a per-process key, so there is no
// second map to keep in step with the session store, nothing to sweep when a
// session ends, and a token cannot outlive the session it belongs to. That is
// the "signed double submit" pattern and it is what lets this be one function
// rather than a store.
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
// A LIBRARY (rule 3): it registers no route. It requires `config`, `crypto` and
// `helpers`, none of which requires it back.
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
// THE CSRF KEY. Per PROCESS and regenerated on every start, exactly like the
// signing key — and unlike the signing key it is deliberately NOT persisted in
// product mode. A CSRF token is only meaningful for the life of a session, a
// session does not survive a restart, so a key that did would be protecting
// nothing and would be one more secret at rest.
// ---------------------------------------------------------------------------
const CSRF_KEY = nodeCrypto.randomBytes(32);
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
  return nodeCrypto.createHmac('sha256', CSRF_KEY)
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
// PER PROCESS and not per realm, deliberately: an attacker choosing which realm
// to guess in must not get a fresh allowance for each, and the buckets are
// keyed by a string the caller composes — which is where the realm goes if a
// caller wants it counted separately.
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
function addressOf(req) {
  log.debug("Entering addressOf().");
  if (!req) {
    log.debug("Leaving addressOf().");
    return 'unknown';
  }
  if (config.value('global.trustProxy')) {
    const forwarded = String((req.headers || {})['x-forwarded-for'] || '');
    const first = forwarded.split(',')[0].trim();
    if (first) {
      log.debug("Leaving addressOf().");
      return first;
    }
  }
  log.debug("Leaving addressOf().");
  return String((req.socket && req.socket.remoteAddress) || 'unknown');
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
      cap: MAX_BUCKETS
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
  addressOf: addressOf,
  report: report,
  reset: reset
};
