'use strict';
//
// File: websecurity.ts
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
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `WebSecurity` takes its logger, `config`, `crypto`, the error-code
// table, the cluster's shared secrets and counters and `client_address`
// through its constructor. The rate-limit store stays a module-scope
// `realms.sharedMap()` declared exactly as before, and both
// `capabilities.provide()` calls still run at require time, in their old
// places relative to the store. The module still exports every name it did —
// `CSRF_FIELD`, `tokenFor`, `field`, `checkCsrf`, the three synchronous and
// four shared limiter functions, `sharesLimits`, `addressOf`, `report` and
// `reset` — from a TRANSITIONAL instance for the unconverted modules that
// require it (`common/app.js` among them); it goes when the composition root
// exists.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import config = require('./config');
import stsCrypto = require('./crypto');
// PER PROCESS AND NOT PER REALM — see the store below. Required only for
// `sharedMap()`, and it is a LEAF that registers no route, so this cannot
// move a route or join a cycle.
import realms = require('./realms');
// The registry of failure codes, a LEAF. A refusal answered here carries its
// code NON-ENUMERABLY, so a caller that renders it can mark its response with
// `errorCodes.codeOf(result)` and nothing about the object serialises
// differently.
import errorCodes = require('./error_codes');

// ---------------------------------------------------------------------------
// THE CSRF KEY, FROM `cluster/cluster_secrets.ts` SINCE 2026-09-14 (#46).
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
import clusterSecrets = require('../cluster/cluster_secrets');
// The table active-active mode is held to, a LEAF. The CSRF key here, the ACME
// nonce key in acme/acme_jws.ts and the SSF receiver secret in
// ssf/ssf_receivers.ts were moved onto the cluster's shared secrets together,
// and this is where the capability for all three is declared.
import capabilities = require('../cluster/cluster_capabilities');
capabilities.provide('secrets.protocol-keys');
// ONE BUDGET FOR EVERY NODE (2026-09-14, #46 section 2): the windows the
// limiter counts in when a store is shared. A LIBRARY that requires
// `persistence.js` lazily, so this closes no cycle. See `attemptShared()`.
import clusterCounters = require('../cluster/cluster_counters');
// Who a request came from. A LEAF. See `addressOf()`.
import clientAddress = require('./client_address');
const CSRF_FIELD = 'csrf_token';

// What a `WebSecurity` needs from the rest of the service, each named for the
// module that supplies it today.
interface WebSecurityDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
  };
  config: { value(key: string): any };
  crypto: { constantTimeEquals(a: string, b: string): boolean };
  errorCodes: typeof errorCodes;
  clusterSecrets: { get(name: string): Buffer };
  clusterCounters: typeof clusterCounters;
  clientAddress: { clientAddressOf(req: any): string };
  // The rate-limit buckets, the module-scope store below.
  buckets: BucketStore;
}

// The parts of `realms.sharedMap()`'s Map-like store this class uses.
interface BucketStore {
  readonly size: number;
  get(key: string): Bucket | undefined;
  set(key: string, value: Bucket): unknown;
  delete(key: string): boolean;
  clear(): void;
  keys(): IterableIterator<string>;
}

// One bucket's row: how many attempts, and when its window ends.
interface Bucket {
  count: number;
  until: number;
}

// A refusal as the limiter decides it, before it becomes an answer.
interface Refusal {
  kind: string;
  limit: number;
  retryAfterS: number;
}

// One bucket a call counts in or reads.
interface BucketCheck {
  kind: string;
  key: string;
  limit: number;
  on: boolean;
}

// A caller's ceiling: a bare number for both buckets, or each named.
type NamedLimit = number | { identity?: number; address?: number } | null;

// The answer every limiter function gives. `ok: false` carries the refusal.
interface LimitAnswer {
  ok: boolean;
  kind?: string;
  limit?: number;
  retryAfterS?: number;
  shared?: boolean;
  detail?: string;
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

// The scope the shared windows are counted under — see the block above
// `WebSecurity.bucketChecks()`.
const SHARED_SCOPE = 'security.rate-limit';

class WebSecurity {
  static readonly CSRF_FIELD = CSRF_FIELD;
  static readonly MAX_BUCKETS = MAX_BUCKETS;
  static readonly SHARED_SCOPE = SHARED_SCOPE;

  constructor(private readonly deps: WebSecurityDeps) {
    deps.log.debug("Entering WebSecurity.constructor().");
    deps.log.debug("Leaving WebSecurity.constructor().");
  }

  // The token for a session. A pure function of the id, so it is the same on
  // every page of one session and needs no storage.
  tokenFor(sessionId: unknown): string {
    const { log, clusterSecrets } = this.deps;
    log.debug("Entering WebSecurity.tokenFor().");
    const id = String(sessionId || '');
    if (!id) {
      log.debug("Leaving WebSecurity.tokenFor().");
      return '';
    }
    log.debug("Leaving WebSecurity.tokenFor().");
    return nodeCrypto.createHmac('sha256', clusterSecrets.get('csrf'))
                     .update(id)
                     .digest('base64url');
  }

  // The hidden input a form carries. Returns '' when there is no session, so a
  // form on an unauthenticated page renders unchanged.
  field(sessionId: unknown): string {
    const { log } = this.deps;
    log.debug("Entering WebSecurity.field().");
    const token = this.tokenFor(sessionId);
    if (!token) {
      log.debug("Leaving WebSecurity.field().");
      return '';
    }
    log.debug("Leaving WebSecurity.field().");
    return '<input type="hidden" name="' + CSRF_FIELD + '" value="' + token +
           '">';
  }

  // Does this POST carry the right token for this session?
  //
  // `ok: true` with `reason: 'no-session'` for a request with no session — see
  // the header for why that is not a hole.
  checkCsrf(sessionId: unknown,
            body?: any): { ok: boolean; reason: string; detail?: string } {
    const { log, errorCodes, crypto } = this.deps;
    log.debug("Entering WebSecurity.checkCsrf().");
    const id = String(sessionId || '');
    if (!id) {
      log.debug("Leaving WebSecurity.checkCsrf().");
      return { ok: true, reason: 'no-session' };
    }
    const presented = String((body || {})[CSRF_FIELD] || '');
    if (!presented) {
      log.debug("Leaving WebSecurity.checkCsrf().");
      return errorCodes.mark({ ok: false, reason: 'missing',
               detail: 'this form carried no ' + CSRF_FIELD + '. Every ' +
                       'state-changing form in this service does; a ' +
                       'request without one did not come from a page this ' +
                       'service drew.' },
                             'STS-HTTP-0015');
    }
    const same = crypto.constantTimeEquals(presented, this.tokenFor(id));
    log.debug("Leaving WebSecurity.checkCsrf().");
    return same
      ? { ok: true, reason: 'verified' }
      : errorCodes.mark({ ok: false, reason: 'mismatch',
          detail: 'the ' + CSRF_FIELD + ' presented is not this session\'s. ' +
                  'It belongs to a different session, or to one that has ' +
                  'ended.' },
                        'STS-HTTP-0016');
  }

  private windowMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering WebSecurity.windowMs().");
    log.debug("Leaving WebSecurity.windowMs().");
    return Math.max(1,
                    Number(config.value('security.rateLimitWindowS') || 60)) *
           1000;
  }

  private limitFor(kind: string): number {
    const { log, config } = this.deps;
    log.debug("Entering WebSecurity.limitFor().");
    const key = kind === 'address' ? 'security.rateLimitPerAddress'
                                   : 'security.rateLimitPerIdentity';
    log.debug("Leaving WebSecurity.limitFor().");
    return Math.max(1, Number(config.value(key) || 5));
  }

  // The address a request came from, honouring the proxy setting this service
  // already has — a limiter that counted every request from one load balancer
  // as one address would lock out the world on the first attacker.
  //
  // **`common/client_address.js`'S ANSWER SINCE 2026-09-14 (#46).** The rule
  // that was here — the left-most `X-Forwarded-For` entry whenever
  // `global.trustProxy` was on, the socket otherwise — let a caller that
  // reached a node directly choose a fresh address per guess, and answered
  // `unknown` for every caller in a request worker, whose socket has no peer
  // address. That file argues the boundary; with `global.trustedProxies` empty
  // it is the old rule exactly, outside a request worker.
  addressOf(req: any): string {
    const { log, clientAddress } = this.deps;
    log.debug("Entering WebSecurity.addressOf().");
    const address = clientAddress.clientAddressOf(req);
    log.debug("Leaving WebSecurity.addressOf().");
    return address;
  }

  private prune(now: number): void {
    const { log, buckets } = this.deps;
    log.debug("Entering WebSecurity.prune().");
    if (buckets.size < MAX_BUCKETS) {
      log.debug("Leaving WebSecurity.prune().");
      return;
    }
    // Oldest first — Map iterates in insertion order — which is the same rule
    // admin_stats.js's caps follow. A limiter that grew without bound would be
    // a denial of service of its own.
    const cutoff = Math.floor(MAX_BUCKETS / 4);
    let dropped = 0;
    for (const key of buckets.keys()) {
      if (dropped >= cutoff) {
        break;
      }
      buckets.delete(key);
      dropped += 1;
    }
    log.warn('websecurity: the rate-limit table reached ' + MAX_BUCKETS +
             ' entries and the oldest ' + dropped + ' were dropped. That is ' +
             'a cap on memory rather than a decision about any one caller.');
    log.debug("Leaving WebSecurity.prune().");
  }

  // Count one attempt. Answers whether it is allowed, and says which bucket
  // refused so the message can be honest without naming the other one.
  //
  // -------------------------------------------------------------------------
  // `limit` IS AN OPTIONAL FOURTH ARGUMENT, AND IT EXISTS BECAUSE ONE NUMBER
  // CANNOT SERVE TWO RHYTHMS (2026-09-06).
  //
  // The two settings this reads are FIVE and TWENTY, and they are right for
  // what they were written for: a SIGN-IN, where five attempts a minute is
  // generous and a sixth is somebody guessing. **A machine-to-machine door is
  // the opposite shape** — `POST /xacml/pip` is called once per access
  // decision by a remote enforcement point, so a busy one makes several a
  // second and every one of them is legitimate.
  //
  // A door like that had two options before this argument existed: share the
  // sign-in numbers and be switched off for its only caller, or not be limited
  // at all. **The first is worse than the second**, because the caller
  // degrades silently — the PEP falls back to deciding on what the request
  // asserts and reports nothing wrong.
  //
  // So a caller may name its own ceiling, and the WINDOW stays shared: an
  // operator who widens `security.rateLimitWindowS` widens every bucket at
  // once, which is what that setting is for. **The default is unchanged** —
  // omit the argument and this behaves exactly as it did, which is what every
  // existing caller does.
  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // AND `limit` MAY NAME THE TWO BUCKETS SEPARATELY (2026-09-12).
  //
  // One number for both was right for `POST /xacml/pip`, whose caller is one
  // machine at one address. It was wrong for the portal's signing-key door,
  // which passed five: the IDENTITY bucket was the point (five key generations
  // a minute for one person), and the ADDRESS bucket then meant five for
  // everybody behind one NAT or proxy — an office sharing an allowance a
  // single person could spend. So `{ identity: n, address: m }` is accepted
  // beside a bare number, a member left out falls back to the shared setting
  // for that bucket, and a bare number means exactly what it always did.
  // -------------------------------------------------------------------------
  private namedLimit(limit: NamedLimit | undefined, kind: string): number {
    const { log } = this.deps;
    log.debug("Entering WebSecurity.namedLimit().");
    const raw = (limit && typeof limit === 'object') ? limit[kind] : limit;
    log.debug("Leaving WebSecurity.namedLimit().");
    return Number(raw) > 0 ? Math.floor(Number(raw)) : 0;
  }

  attempt(what: string, req: any, identity?: unknown,
          limit?: NamedLimit): LimitAnswer {
    const { log, buckets, errorCodes } = this.deps;
    log.debug('Entering WebSecurity.attempt(). what=' + what);
    const now = Date.now();
    const span = this.windowMs();
    const checks: BucketCheck[] = [
      { kind: 'identity',
        key: what + '|id|' + String(identity || '').toLowerCase(),
        limit: this.namedLimit(limit, 'identity') || this.limitFor('identity'),
        on: !!identity },
      { kind: 'address', key: what + '|ip|' + this.addressOf(req),
        limit: this.namedLimit(limit, 'address') || this.limitFor('address'),
        on: true }
    ];
    this.prune(now);
    let refusal: Refusal | null = null;
    checks.forEach(function (check) {
      if (!check.on) {
        return;
      }
      const row = buckets.get(check.key);
      if (!row || row.until <= now) {
        buckets.set(check.key, { count: 1, until: now + span });
        return;
      }
      row.count += 1;
      // SET AGAIN, NOT ONLY EDITED IN PLACE (2026-09-14). `buckets` journals a
      // `set()` and a `delete()`, and an increment made on the row alone was
      // never written down — so in the request-worker pool only a bucket's
      // FIRST failure reached the other workers, each kept its own count, and
      // a caller spreading its guesses across three workers was never refused.
      // `sts_est_enrollment` met it in `dispatch` mode: three wrong passwords
      // in a row, 401, 401, 401 where the third must be 429. Written down, the
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
      const found: Refusal = refusal;
      const code = found.kind === 'address' ? 'STS-HTTP-0018'
                                            : 'STS-HTTP-0017';
      log.warn(errorCodes.tag(code) + 'websecurity: too many "' + what + '" ' +
          'attempts (' +
               found.kind + ' bucket, limit ' + found.limit + ' per ' +
               Math.round(span / 1000) + 's). Refusing for another ' +
               found.retryAfterS + 's.');
      log.debug('Leaving WebSecurity.attempt(). Refused.');
      return errorCodes.mark({ ok: false, kind: found.kind,
               limit: found.limit,
               retryAfterS: found.retryAfterS,
               detail: 'Too many attempts. Wait ' + found.retryAfterS +
                       ' seconds and try again.' }, code);
    }
    log.debug('Leaving WebSecurity.attempt(). Allowed.');
    return { ok: true };
  }

  // -------------------------------------------------------------------------
  // blocked() — IS THIS CALLER OVER A LIMIT RIGHT NOW, WITHOUT COUNTING
  // ANYTHING (2026-09-12).
  //
  // `attempt()` counts and answers in one call, which is right for a sign-in
  // screen: every POST is somebody trying a password. It is wrong for a door
  // whose SUCCESSES are many and legitimate — an LDAP connection pool binds on
  // every connection it opens, fifty at once from one address, and counting
  // those would lock an application out of its own directory for being busy.
  //
  // So that door asks `blocked()` first, which reads the buckets and changes
  // nothing, counts only a FAILURE with `attempt()`, and clears on success
  // with `succeeded()`. The refusal a blocked caller gets is decided before
  // its password is looked at, so a right guess during a lockout is refused
  // exactly like a wrong one and teaches the guesser nothing. Same buckets,
  // same window, same limits and the same `limit` argument as `attempt()` —
  // one limiter with a read beside its write, not a second limiter.
  // -------------------------------------------------------------------------
  blocked(what: string, req: any, identity?: unknown,
          limit?: NamedLimit): LimitAnswer | null {
    const { log, buckets, errorCodes } = this.deps;
    log.debug('Entering WebSecurity.blocked(). what=' + what);
    const now = Date.now();
    const checks: BucketCheck[] = [
      { kind: 'identity',
        key: what + '|id|' + String(identity || '').toLowerCase(),
        limit: this.namedLimit(limit, 'identity') || this.limitFor('identity'),
        on: !!identity },
      { kind: 'address', key: what + '|ip|' + this.addressOf(req),
        limit: this.namedLimit(limit, 'address') || this.limitFor('address'),
        on: true }
    ];
    let refusal: Refusal | null = null;
    checks.forEach(function (check) {
      if (!check.on || refusal) {
        return;
      }
      const row = buckets.get(check.key);
      // AT the limit is blocked, where `attempt()` refuses only PAST it: that
      // call counts the attempt it is deciding about, and this one does not —
      // so `limit` failures have been spent and the next try is the one over.
      if (row && row.until > now && row.count >= check.limit) {
        refusal = { kind: check.kind, limit: check.limit,
                    retryAfterS: Math.ceil((row.until - now) / 1000) };
      }
    });
    if (!refusal) {
      log.debug('Leaving WebSecurity.blocked(). Not blocked.');
      return null;
    }
    const found: Refusal = refusal;
    const code = found.kind === 'address' ? 'STS-HTTP-0018' : 'STS-HTTP-0017';
    log.debug('Leaving WebSecurity.blocked(). Blocked by the ' + found.kind +
              ' bucket.');
    return errorCodes.mark({ ok: false, kind: found.kind, limit: found.limit,
             retryAfterS: found.retryAfterS,
             detail: 'Too many failed attempts. Wait ' + found.retryAfterS +
                     ' seconds and try again.' }, code);
  }

  // Forget the counters for one identity — what a SUCCESSFUL sign-in does, so
  // that somebody who mistyped a password four times is not still near the
  // limit once they get it right.
  //
  // `options.keepAddress` LEAVES THE ADDRESS BUCKET ALONE (2026-09-12), and a
  // door whose successes are cheap to come by needs it. On an LDAP bind,
  // anybody holding ONE working password could otherwise clear their
  // address's failure count between guesses at every other DN by binding as
  // themselves once — the address limit would never be reached by the one
  // caller it exists for.
  succeeded(what: string, req: any, identity?: unknown,
            options?: { keepAddress?: boolean } | null): void {
    const { log, buckets } = this.deps;
    log.debug("Entering WebSecurity.succeeded().");
    if (identity) {
      buckets.delete(what + '|id|' + String(identity).toLowerCase());
    }
    if (!(options && options.keepAddress)) {
      buckets.delete(what + '|ip|' + this.addressOf(req));
    }
    log.debug("Leaving WebSecurity.succeeded().");
  }

  // -------------------------------------------------------------------------
  // ONE BUDGET FOR EVERY NODE: `attemptShared()`, `blockedShared()` AND
  // `succeededShared()` (2026-09-14, #46 section 2).
  //
  // The three functions above are right for one process and wrong for several,
  // in two ways that multiply. Each node refused only on ITS OWN count, so a
  // guesser spreading attempts over N nodes had N budgets; and the buckets are
  // a replicated Map whose rows are whole values, so two nodes counting one
  // bucket at once each read 3 and each wrote 4 — last writer wins on a counter
  // — and even the counts that did replicate were short. `sts_est_enrollment`
  // had already met the one-container half of it (see the comment in
  // `attempt()`), and the fix there, writing the row down on every count, made
  // the count visible and left it racy.
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
  // **A STORE THAT CANNOT BE ASKED FALLS BACK TO THIS PROCESS'S BUCKETS**,
  // logged `STS-CLUSTER-0023`, and that is a deliberate difference from a
  // claim, which refuses. A claim that cannot be proven spent must not be
  // accepted, because the harm is a credential used twice. A limiter that
  // cannot reach the shared count still has a count — its own, which is what
  // every node had before this — and refusing every sign-in for as long as the
  // database is unreachable would turn a database blip into a sign-in outage
  // nobody caused. For that window the budget is per node again, and the log
  // says so.
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
  // -------------------------------------------------------------------------
  private bucketChecks(what: string, req: any, identity: unknown,
                       limit: NamedLimit | undefined): BucketCheck[] {
    const { log } = this.deps;
    log.debug("Entering WebSecurity.bucketChecks().");
    log.debug("Leaving WebSecurity.bucketChecks().");
    return [
      { kind: 'identity',
        key: what + '|id|' + String(identity || '').toLowerCase(),
        limit: this.namedLimit(limit, 'identity') || this.limitFor('identity'),
        on: !!identity },
      { kind: 'address', key: what + '|ip|' + this.addressOf(req),
        limit: this.namedLimit(limit, 'address') || this.limitFor('address'),
        on: true }
    ].filter(function (check) {
      return check.on;
    });
  }

  private sharedRefusal(refusal: Refusal, detailLead: string): LimitAnswer {
    const { log, errorCodes } = this.deps;
    log.debug("Entering WebSecurity.sharedRefusal().");
    const code = refusal.kind === 'address' ? 'STS-HTTP-0018'
                                            : 'STS-HTTP-0017';
    log.debug("Leaving WebSecurity.sharedRefusal().");
    return errorCodes.mark({ ok: false, kind: refusal.kind,
             limit: refusal.limit, retryAfterS: refusal.retryAfterS,
             shared: true,
             detail: detailLead + ' Wait ' + refusal.retryAfterS +
                     ' seconds and try again.' }, code);
  }

  private secondsLeft(remainingMs: unknown): number {
    const { log } = this.deps;
    log.debug("Entering WebSecurity.secondsLeft().");
    log.debug("Leaving WebSecurity.secondsLeft().");
    return Math.max(1, Math.ceil((Number(remainingMs) || 0) / 1000));
  }

  attemptShared(what: string, req: any, identity?: unknown,
                limit?: NamedLimit): Promise<LimitAnswer> {
    const { log, clusterCounters, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering WebSecurity.attemptShared(). what=' + what);
    if (!clusterCounters.sharesWindows()) {
      log.debug('Leaving WebSecurity.attemptShared(). No shared store: ' +
                'attempt().');
      return Promise.resolve(this.attempt(what, req, identity, limit));
    }
    const checks = this.bucketChecks(what, req, identity, limit);
    const span = this.windowMs();
    log.debug('Leaving WebSecurity.attemptShared(). Counting in the store.');
    return Promise.all(checks.map(function (check) {
      return clusterCounters.countInWindow({ scope: SHARED_SCOPE,
                                             key: check.key, realm: '',
                                             windowMs: span });
    })).then(function (answers: any[]) {
      if (answers.some(function (answer) { return !answer.ok; })) {
        log.warn(errorCodes.tag('STS-CLUSTER-0023') + 'websecurity: the "' +
                 what + '" attempt could not be counted in the shared ' +
                 'store; it is counted in this process\'s buckets, so for ' +
                 'now the budget is per node.');
        return self.attempt(what, req, identity, limit);
      }
      let refusal: Refusal | null = null;
      checks.forEach(function (check, i) {
        if (!refusal && answers[i].count > check.limit) {
          refusal = { kind: check.kind, limit: check.limit,
                      retryAfterS: self.secondsLeft(answers[i].remainingMs) };
        }
      });
      if (!refusal) {
        return { ok: true, shared: true };
      }
      const found: Refusal = refusal;
      log.warn(errorCodes.tag(found.kind === 'address' ? 'STS-HTTP-0018'
                                                       : 'STS-HTTP-0017') +
               'websecurity: too many "' + what + '" attempts across the ' +
               'cluster (' + found.kind + ' bucket, limit ' + found.limit +
               ' per ' + Math.round(span / 1000) + 's). Refusing for ' +
               'another ' + found.retryAfterS + 's.');
      return self.sharedRefusal(found, 'Too many attempts.');
    });
  }

  blockedShared(what: string, req: any, identity?: unknown,
                limit?: NamedLimit): Promise<LimitAnswer | null> {
    const { log, clusterCounters, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering WebSecurity.blockedShared(). what=' + what);
    if (!clusterCounters.sharesWindows()) {
      log.debug('Leaving WebSecurity.blockedShared(). No shared store: ' +
                'blocked().');
      return Promise.resolve(this.blocked(what, req, identity, limit));
    }
    const checks = this.bucketChecks(what, req, identity, limit);
    log.debug('Leaving WebSecurity.blockedShared(). Reading the store.');
    return Promise.all(checks.map(function (check) {
      return clusterCounters.peekWindow({ scope: SHARED_SCOPE, key: check.key,
                                          realm: '' });
    })).then(function (answers: any[]) {
      if (answers.some(function (answer) { return !answer.ok; })) {
        log.warn(errorCodes.tag('STS-CLUSTER-0023') + 'websecurity: the "' +
                 what + '" buckets could not be read from the shared store; ' +
                 'this process\'s own buckets decide, so for now the budget ' +
                 'is per node.');
        return self.blocked(what, req, identity, limit);
      }
      let refusal: Refusal | null = null;
      // AT the limit, for `blocked()`'s reason: this counts nothing.
      checks.forEach(function (check, i) {
        if (!refusal && answers[i].count >= check.limit) {
          refusal = { kind: check.kind, limit: check.limit,
                      retryAfterS: self.secondsLeft(answers[i].remainingMs) };
        }
      });
      return refusal ? self.sharedRefusal(refusal, 'Too many failed attempts.')
        : null;
    });
  }

  // -------------------------------------------------------------------------
  // failedShared() — COUNT A FAILURE AND SAY WHETHER IT IS STILL ANSWERABLE AS
  // ONE (2026-09-14). Resolves to null while the increment this failure made
  // is within the limit, and to the lockout refusal once it is past it. The
  // count is `attemptShared()`'s — the one atomic increment — so the decision
  // is the same whichever node, however many at once. See the block above.
  // -------------------------------------------------------------------------
  failedShared(what: string, req: any, identity?: unknown,
               limit?: NamedLimit): Promise<LimitAnswer | null> {
    const { log } = this.deps;
    log.debug('Entering WebSecurity.failedShared(). what=' + what);
    log.debug('Leaving WebSecurity.failedShared().');
    return this.attemptShared(what, req, identity,
                              limit).then(function (counted) {
      return counted && counted.ok === false ? counted : null;
    });
  }

  // Whether the shared functions above count in a store every process shares
  // — for a caller that must stay synchronous where nothing is shared (the
  // LDAP bind, whose operation is run synchronously by its in-process
  // callers).
  sharesLimits(): boolean {
    const { log, clusterCounters } = this.deps;
    log.debug("Entering WebSecurity.sharesLimits().");
    log.debug("Leaving WebSecurity.sharesLimits().");
    return clusterCounters.sharesWindows();
  }

  // Resolves when the store has forgotten the buckets (or could not be asked,
  // which is logged). This process's own buckets are cleared first and always,
  // so a count made while the store was unreachable is forgotten too.
  //
  // `options.unlessBlocked` (2026-09-14): a verified credential is answered
  // only while the bucket is under the limit — see the block above
  // `failedShared()`. Resolves to the lockout refusal, clearing nothing, when
  // it is at the limit; null otherwise.
  succeededShared(what: string, req: any, identity?: unknown,
                  options?: { keepAddress?: boolean; unlessBlocked?: boolean;
                              limit?: NamedLimit } | null):
      Promise<LimitAnswer | null | void> {
    const { log, clusterCounters } = this.deps;
    const self = this;
    log.debug("Entering WebSecurity.succeededShared().");
    if (options && options.unlessBlocked) {
      log.debug("Leaving WebSecurity.succeededShared(). Asking first.");
      return this.blockedShared(what, req, identity,
                                options.limit).then(function (lockedOut) {
        if (lockedOut) {
          return lockedOut;
        }
        return self.succeededShared(what, req, identity,
                                    { keepAddress: !!options.keepAddress })
          .then(function () {
            return null;
          });
      });
    }
    this.succeeded(what, req, identity, options);
    if (!clusterCounters.sharesWindows()) {
      log.debug("Leaving WebSecurity.succeededShared(). No shared store.");
      return Promise.resolve();
    }
    const keys: string[] = [];
    if (identity) {
      keys.push(what + '|id|' + String(identity).toLowerCase());
    }
    if (!(options && options.keepAddress)) {
      keys.push(what + '|ip|' + this.addressOf(req));
    }
    log.debug("Leaving WebSecurity.succeededShared(). Clearing " +
              keys.length + " window(s).");
    return Promise.all(keys.map(function (key) {
      return clusterCounters.clearWindow({ scope: SHARED_SCOPE, key: key,
                                           realm: '' });
    })).then(function () {
      return undefined;
    });
  }

  // For the console and the tests.
  report(): Record<string, any> {
    const { log, buckets, clusterCounters } = this.deps;
    log.debug("Entering WebSecurity.report().");
    log.debug("Leaving WebSecurity.report().");
    return {
      csrf: { field: CSRF_FIELD,
              how: 'HMAC-SHA256 of the session id under a per-process key, ' +
                   'compared in constant time. Derived rather than stored, ' +
                   'so a token cannot outlive its session and there is no ' +
                   'second map to sweep.' },
      rateLimit: {
        windowS: Math.round(this.windowMs() / 1000),
        perIdentity: this.limitFor('identity'),
        perAddress: this.limitFor('address'),
        bucketsHeld: buckets.size,
        cap: MAX_BUCKETS,
        // Whether the count is the cluster's (`sts_cluster_windows`) rather
        // than `bucketsHeld` above, which is then only what a fallback counted
        // here.
        sharedAcrossNodes: clusterCounters.sharesWindows()
      }
    };
  }

  // Tests only — see the same note on keystore.reset().
  reset(): void {
    const { log, buckets } = this.deps;
    log.debug("Entering WebSecurity.reset().");
    buckets.clear();
    log.debug("Leaving WebSecurity.reset().");
  }
}

// DECLARED AT REQUIRE TIME, for `cluster/cluster.js`'s reason. The shared
// functions above are the fix; every door that counts — the sign-in screen,
// the password grant, the second-factor steps, the portal's links and forms,
// client secrets, the enrollment throttles, GNAP's user code, the PIP and the
// LDAP bind — calls them.
capabilities.provide('security.rate-limits');

// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules, as
// the composition root will build one.
const webSecurity = new WebSecurity({
  log: helpers.log,
  config: config,
  crypto: stsCrypto,
  errorCodes: errorCodes,
  clusterSecrets: clusterSecrets,
  clusterCounters: clusterCounters,
  clientAddress: clientAddress,
  buckets: buckets
});

export = {
  WebSecurity: WebSecurity,
  CSRF_FIELD: WebSecurity.CSRF_FIELD,
  tokenFor: webSecurity.tokenFor.bind(webSecurity) as WebSecurity['tokenFor'],
  field: webSecurity.field.bind(webSecurity) as WebSecurity['field'],
  checkCsrf: webSecurity.checkCsrf.bind(webSecurity) as
    WebSecurity['checkCsrf'],
  attempt: webSecurity.attempt.bind(webSecurity) as WebSecurity['attempt'],
  blocked: webSecurity.blocked.bind(webSecurity) as WebSecurity['blocked'],
  succeeded: webSecurity.succeeded.bind(webSecurity) as
    WebSecurity['succeeded'],
  attemptShared: webSecurity.attemptShared.bind(webSecurity) as
    WebSecurity['attemptShared'],
  blockedShared: webSecurity.blockedShared.bind(webSecurity) as
    WebSecurity['blockedShared'],
  succeededShared: webSecurity.succeededShared.bind(webSecurity) as
    WebSecurity['succeededShared'],
  failedShared: webSecurity.failedShared.bind(webSecurity) as
    WebSecurity['failedShared'],
  sharesLimits: webSecurity.sharesLimits.bind(webSecurity) as
    WebSecurity['sharesLimits'],
  addressOf: webSecurity.addressOf.bind(webSecurity) as
    WebSecurity['addressOf'],
  report: webSecurity.report.bind(webSecurity) as WebSecurity['report'],
  reset: webSecurity.reset.bind(webSecurity) as WebSecurity['reset']
};
