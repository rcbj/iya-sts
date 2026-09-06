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
  const id = String(sessionId || '');
  if (!id) return '';
  return nodeCrypto.createHmac('sha256', CSRF_KEY).update(id).digest('base64url');
}

// The hidden input a form carries. Returns '' when there is no session, so a
// form on an unauthenticated page renders unchanged.
function field(sessionId) {
  const token = tokenFor(sessionId);
  if (!token) return '';
  return '<input type="hidden" name="' + CSRF_FIELD + '" value="' + token + '">';
}

// Does this POST carry the right token for this session?
//
// `ok: true` with `reason: 'no-session'` for a request with no session — see
// the header for why that is not a hole.
function checkCsrf(sessionId, body) {
  const id = String(sessionId || '');
  if (!id) {
    return { ok: true, reason: 'no-session' };
  }
  const presented = String((body || {})[CSRF_FIELD] || '');
  if (!presented) {
    return { ok: false, reason: 'missing',
             detail: 'this form carried no ' + CSRF_FIELD + '. Every ' +
                     'state-changing form in this service does; a request ' +
                     'without one did not come from a page this service drew.' };
  }
  const same = stsCrypto.constantTimeEquals(presented, tokenFor(id));
  return same
    ? { ok: true, reason: 'verified' }
    : { ok: false, reason: 'mismatch',
        detail: 'the ' + CSRF_FIELD + ' presented is not this session\'s. It ' +
                'belongs to a different session, or to one that has ended.' };
}

// ---------------------------------------------------------------------------
// THE RATE LIMITER.
//
// PER PROCESS and not per realm, deliberately: an attacker choosing which realm
// to guess in must not get a fresh allowance for each, and the buckets are keyed
// by a string the caller composes — which is where the realm goes if a caller
// wants it counted separately.
// ---------------------------------------------------------------------------
const buckets = new Map();
const MAX_BUCKETS = 20000;

function windowMs() {
  return Math.max(1, Number(config.value('security.rateLimitWindowS') || 60)) * 1000;
}

function limitFor(kind) {
  const key = kind === 'address' ? 'security.rateLimitPerAddress'
                                 : 'security.rateLimitPerIdentity';
  return Math.max(1, Number(config.value(key) || 5));
}

// The address a request came from, honouring the proxy setting this service
// already has — a limiter that counted every request from one load balancer as
// one address would lock out the world on the first attacker.
function addressOf(req) {
  if (!req) return 'unknown';
  if (config.value('global.trustProxy')) {
    const forwarded = String((req.headers || {})['x-forwarded-for'] || '');
    const first = forwarded.split(',')[0].trim();
    if (first) return first;
  }
  return String((req.socket && req.socket.remoteAddress) || 'unknown');
}

function prune(now) {
  if (buckets.size < MAX_BUCKETS) return;
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
}

// Count one attempt. Answers whether it is allowed, and says which bucket
// refused so the message can be honest without naming the other one.
function attempt(what, req, identity) {
  log.debug('Entering attempt(). what=' + what);
  const now = Date.now();
  const span = windowMs();
  const checks = [
    { kind: 'identity',
      key: what + '|id|' + String(identity || '').toLowerCase(),
      limit: limitFor('identity'), on: !!identity },
    { kind: 'address', key: what + '|ip|' + addressOf(req),
      limit: limitFor('address'), on: true }
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
    log.warn('websecurity: too many "' + what + '" attempts (' +
             refusal.kind + ' bucket, limit ' + refusal.limit + ' per ' +
             Math.round(span / 1000) + 's). Refusing for another ' +
             refusal.retryAfterS + 's.');
    log.debug('Leaving attempt(). Refused.');
    return { ok: false, kind: refusal.kind, limit: refusal.limit,
             retryAfterS: refusal.retryAfterS,
             detail: 'Too many attempts. Wait ' + refusal.retryAfterS +
                     ' seconds and try again.' };
  }
  log.debug('Leaving attempt(). Allowed.');
  return { ok: true };
}

// Forget the counters for one identity — what a SUCCESSFUL sign-in does, so
// that somebody who mistyped a password four times is not still near the limit
// once they get it right.
function succeeded(what, req, identity) {
  if (identity) {
    buckets.delete(what + '|id|' + String(identity).toLowerCase());
  }
  buckets.delete(what + '|ip|' + addressOf(req));
}

// For the console and the tests.
function report() {
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
  buckets.clear();
}

module.exports = {
  CSRF_FIELD: CSRF_FIELD,
  tokenFor: tokenFor,
  field: field,
  checkCsrf: checkCsrf,
  attempt: attempt,
  succeeded: succeeded,
  addressOf: addressOf,
  report: report,
  reset: reset
};
