// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: device_bound_sessions.ts
//
// ---------------------------------------------------------------------------
// DEVICE BOUND SESSION CREDENTIALS (#725): THE SIGN-ON SESSION BOUND TO A KEY
// THE BROWSER HOLDS, AS THE W3C WEBAPPSEC DRAFT WRITES IT DOWN.
//
// `sts_session` is a bearer cookie. Copied off a machine, it is the person
// until the session ends — the passkey ceremony that made it is not asked
// again (#544). DBSC is the browser's answer: at a sign-in this service asks
// the browser to make a key pair (TPM-backed where it can), the browser
// proves the key once to the REGISTRATION endpoint, and from then on the
// session needs a SHORT-LIVED second cookie that only a proof with that key
// renews, at the REFRESH endpoint. A thief who copies both cookies has the
// session for what is left of the bound cookie's lifetime
// (`authn.deviceBoundCookieLifetimeS`, ten minutes by default), and then
// nothing, because the key never leaves the browser.
//
// The names below are the draft's (Editor's Draft of 8 September 2026,
// https://w3c.github.io/webappsec-dbsc/), section by section:
//
//   9.1  `Secure-Session-Registration: (ES256 RS256);path="…";challenge="…"`
//        on the answer that sets the session cookie.
//   9.2  `Secure-Session-Challenge: "<challenge>";id="<session id>"`, on a 403
//        from the refresh endpoint and on every successful answer, so the
//        browser's next refresh is one round trip.
//   9.3  `Secure-Session-Response`: the DBSC proof, a JWT (9.10) with `typ`
//        `dbsc+jwt`, `alg` ES256 or RS256, the public `jwk` in the header at
//        registration and never at refresh, and the challenge as `jti`.
//   9.4  `Sec-Secure-Session-Id`: the session identifier, on every refresh.
//        A `Sec-` header no page script can set, which is what makes a
//        refresh request one the browser made (section 5).
//   9.6  the JSON session instructions the registration answer carries.
//   8.8  the status codes: a 403 means "sign this challenge and try again",
//        any other 4xx ends the browser's DBSC session, a 5xx backs off.
//        **SO NO REFUSAL HERE IS A 403** — a refusal answered 403 would be a
//        loop.
//
// ---------------------------------------------------------------------------
// NOTHING ABOUT A CHALLENGE OR A BOUND COOKIE IS STORED (the store rule).
//
// Both are MACed under the cluster secret `dbsc` (`cluster/cluster_secrets.ts`)
// over the realm, the sign-on session, the DBSC session (and for the cookie
// the bound key's thumbprint) and an expiry — so a value minted by one
// process verifies in every other the moment it is minted, with no row to
// replicate. That matters most for the cookie: written to the session row, a
// refresh on one node would leave every other node refusing the new cookie
// until replication caught up, which is a person signed out every ten
// minutes in cluster mode. What IS written to the session row is the binding
// itself — the key, once, at registration — and the refresh count.
//
// **A CHALLENGE IS SPENT ONCE FOR THE CLUSTER** through
// `cluster/cluster_claims` (scope `authn.dbsc-challenge`), after the
// signature verifies. A refresh whose proof verifies with the bound key but
// carries a challenge already spent is a REPLAY, and it ends the session —
// as does a refresh signed by any other key. Both end it through
// `logout/logout.ts`, so the person's relying parties are told (CAEP
// `session-revoked`, Back-Channel Logout).
//
// ---------------------------------------------------------------------------
// WHAT IT DOES NOT CHANGE (rcbj's requirement on the ticket).
//
// Off by default and per realm (`authn.deviceBoundSessions`). On, a browser
// that does not speak DBSC ignores the header, never registers, and its
// session is exactly the bearer session it always was: the bound cookie is
// asked for only once a session HAS a key. Turning the setting off makes a
// bound session a bearer one again, because the refresh endpoint that keeps
// its cookie alive is gone with it.
//
// A ROUTE MODULE, registered by `common/protocol_stack.ts` just after `authn`.
// `authn.ts` requires it as a library (the header, the cookie check); it
// reaches `authn` and `logout` LAZILY, so the require closes no cycle.
// ---------------------------------------------------------------------------

import stsCrypto = require('../common/crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import structuredFields = require('../common/structured_fields');
import clusterClaims = require('../cluster/cluster_claims');
import clusterSecrets = require('../cluster/cluster_secrets');
import AccountSets = require('./account_sets');

const { log } = helpers;

type Json = any;

/**
 * The registration endpoint's path, under the realm's prefix.
 */
const REGISTER_PATH = '/authn/dbsc/register';
/**
 * The refresh endpoint's path, under the realm's prefix.
 */
const REFRESH_PATH = '/authn/dbsc/refresh';
/**
 * The name of the short-lived cookie a bound session needs beside
 * `sts_session`.
 */
const BOUND_COOKIE = 'sts_session_bound';

// The algorithms offered in `Secure-Session-Registration`, in the order the
// draft's own examples give them. Section 9.10 allows "none" as well; it is
// never offered, so a proof naming it is refused like any other algorithm
// this service did not ask for.
const ALGORITHMS = ['ES256', 'RS256'];

// The shape of a compact JWS, for an unquoted Secure-Session-Response.
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

// The draft's `typ` (section 9.10).
const PROOF_TYP = 'dbsc+jwt';

// The cluster secret both MACs are made under, and the labels that keep a
// challenge from ever verifying as a cookie and the other way round.
const SECRET = 'dbsc';
const CHALLENGE_LABEL = 'sts-dbsc-challenge-v1';
const COOKIE_LABEL = 'sts-dbsc-cookie-v1';

// The claim scope a spent challenge is recorded under.
const CLAIM_SCOPE = 'authn.dbsc-challenge';

// A challenge outlives the cookie it was handed out with by this much: the
// browser caches the challenge on the answer that set the cookie and signs it
// when the cookie runs out, so a challenge that died with the cookie would
// send every refresh round the 403 first.
const CHALLENGE_GRACE_S = 120;

// The members of a JWK that are private key material, refused in a proof's
// header for `oauth-oidc/dpop.ts`'s reason.
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'priv'];

interface DeviceBoundDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  clusterClaims: typeof clusterClaims;
  secret(): Buffer;
  now(): number;
  // LAZY: `authn` requires this module, and `logout` is required 23rd.
  authn(): any;
  logout(): any;
  // Whether `authn.multipleAccounts` is on (#561), which names the bound
  // cookie per binding.
  multipleAccounts(): boolean;
}

type RouteApp = { post: Function };

// What `readProof()` answers: the parsed proof, or a refusal.
interface Proof {
  raw?: string;
  header?: Json;
  claims?: Json;
  code?: string;
  why?: string;
}

/**
 * The relying-party side of Device Bound Session Credentials: the
 * registration header, the two endpoints, and the bound cookie a bound
 * session needs.
 */
class DeviceBoundSessions {
  static readonly REGISTER_PATH = REGISTER_PATH;
  static readonly REFRESH_PATH = REFRESH_PATH;
  static readonly BOUND_COOKIE = BOUND_COOKIE;
  static readonly ALGORITHMS = ALGORITHMS;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, settings, realms, error codes, audit log,
   *   cluster claims, the MAC secret, the clock, and lazy loaders for the
   *   sign-in service and the sign-out
   */
  constructor(private readonly deps: DeviceBoundDeps) {
    deps.log.debug("Entering DeviceBoundSessions.constructor().");
    deps.log.debug("Leaving DeviceBoundSessions.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): DeviceBoundDeps {
    log.debug("Entering DeviceBoundSessions.defaultDeps().");
    log.debug("Leaving DeviceBoundSessions.defaultDeps().");
    return {
      log: log, config: config, realms: realms, errorCodes: errorCodes,
      audit: audit, clusterClaims: clusterClaims,
      secret: function (): Buffer {
        return clusterSecrets.get(SECRET);
      },
      now: function (): number {
        return Date.now();
      },
      authn: function (): any {
        return require('./authn');
      },
      multipleAccounts: function (): boolean {
        return AccountSets.enabled();
      },
      logout: function (): any {
        return require('../logout/logout');
      }
    };
  }

  // --- the settings ---------------------------------------------------------

  /**
   * Tells whether the ambient realm binds sessions to the browser's key
   * (`authn.deviceBoundSessions`, off by default).
   *
   * @returns true when it does
   */
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering DeviceBoundSessions.enabled().");
    log.debug("Leaving DeviceBoundSessions.enabled().");
    return config.value('authn.deviceBoundSessions') === true;
  }

  /**
   * Returns how long a bound cookie lives
   * (`authn.deviceBoundCookieLifetimeS`), in seconds.
   *
   * @returns the lifetime in seconds
   */
  cookieLifetimeS(): number {
    const { log, config } = this.deps;
    log.debug("Entering DeviceBoundSessions.cookieLifetimeS().");
    const seconds = Number(config.value('authn.deviceBoundCookieLifetimeS'));
    log.debug("Leaving DeviceBoundSessions.cookieLifetimeS().");
    return isFinite(seconds) && seconds >= 1 ? Math.floor(seconds) : 600;
  }

  /**
   * Tells whether a bound session is scoped to the registrable domain
   * (`authn.deviceBoundIncludeSite`, off by default, #742).
   *
   * @returns true when `scope.include_site` is set
   */
  includeSite(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering DeviceBoundSessions.includeSite().");
    log.debug("Leaving DeviceBoundSessions.includeSite().");
    return config.value('authn.deviceBoundIncludeSite') === true;
  }

  /**
   * Returns how long issuance waits for a registration that was offered
   * (`authn.deviceBoundIssuanceWaitS`, #740), in seconds.
   *
   * Zero is legal and means the wait has already elapsed. Read directly:
   * `0 || 60` would make that setting unreachable.
   *
   * @returns the wait in seconds
   */
  issuanceWaitS(): number {
    const { log, config } = this.deps;
    log.debug("Entering DeviceBoundSessions.issuanceWaitS().");
    const wait = Number(config.value('authn.deviceBoundIssuanceWaitS'));
    const seconds = isFinite(wait) ? wait : 60;
    log.debug("Leaving DeviceBoundSessions.issuanceWaitS().");
    return seconds;
  }

  // --- the MACs -------------------------------------------------------------

  private mac(parts: unknown[]): string {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.mac().");
    const out = stsCrypto.hmac('sha256', this.deps.secret(),
                               parts.map(String).join('\n'), 'base64url');
    log.debug("Leaving DeviceBoundSessions.mac().");
    return out;
  }

  // A challenge is `<expiry>.<nonce>.<mac>`: the expiry in epoch seconds, 16
  // random bytes, and the MAC over the label, the realm, the sign-on
  // session, the DBSC session ('' at registration), the purpose, the expiry
  // and the nonce. Every character is base64url or a dot, so it is a valid
  // sf-string as it stands.
  /**
   * Mints a challenge for one purpose of one session.
   *
   * @param purpose - `register` or `refresh`
   * @param sid - the sign-on session id
   * @param dbscId - the DBSC session identifier; '' at registration
   * @returns the challenge
   */
  mintChallenge(purpose: string, sid: string, dbscId: string): string {
    const { log, realms, now } = this.deps;
    log.debug("Entering DeviceBoundSessions.mintChallenge(). " + purpose);
    const expires = Math.floor(now() / 1000) + this.cookieLifetimeS() +
      CHALLENGE_GRACE_S;
    const nonce = stsCrypto.randomBytes(16).toString('base64url');
    const mac = this.mac([CHALLENGE_LABEL, realms.currentId(), sid,
                          dbscId || '', purpose, expires, nonce]);
    log.debug("Leaving DeviceBoundSessions.mintChallenge().");
    return expires + '.' + nonce + '.' + mac;
  }

  /**
   * Checks a challenge a proof carried against the session and purpose it
   * must have been minted for.
   *
   * @param challenge - the proof's `jti`
   * @param purpose - `register` or `refresh`
   * @param sid - the sign-on session id
   * @param dbscId - the DBSC session identifier; '' at registration
   * @returns `ok`, `foreign` (not minted here for this) or `expired`
   */
  checkChallenge(challenge: unknown, purpose: string, sid: string,
                 dbscId: string): string {
    const { log, realms, now } = this.deps;
    log.debug("Entering DeviceBoundSessions.checkChallenge(). " + purpose);
    const parts = String(challenge || '').split('.');
    if (parts.length !== 3 || !/^\d{1,12}$/.test(parts[0])) {
      log.debug("Leaving DeviceBoundSessions.checkChallenge(). Malformed.");
      return 'foreign';
    }
    const expected = this.mac([CHALLENGE_LABEL, realms.currentId(), sid,
                               dbscId || '', purpose, parts[0], parts[1]]);
    if (!stsCrypto.constantTimeEquals(expected, parts[2])) {
      log.debug("Leaving DeviceBoundSessions.checkChallenge(). Not ours.");
      return 'foreign';
    }
    if (Number(parts[0]) * 1000 <= now()) {
      log.debug("Leaving DeviceBoundSessions.checkChallenge(). Expired.");
      return 'expired';
    }
    log.debug("Leaving DeviceBoundSessions.checkChallenge(). Ours.");
    return 'ok';
  }

  // The bound cookie is `<expiry>.<mac>`, the MAC over the label, the realm,
  // the sign-on session, the DBSC session and the bound key's thumbprint —
  // so a cookie minted for one binding is refused for any other, a re-bound
  // session included. It never outlives the session.
  private cookieValueFor(session: Json, expiresS: number): string {
    const { log, realms } = this.deps;
    log.debug("Entering DeviceBoundSessions.cookieValueFor().");
    const binding = session.dbsc || {};
    const mac = this.mac([COOKIE_LABEL, realms.currentId(), session.id,
                          binding.id, binding.jkt, expiresS]);
    log.debug("Leaving DeviceBoundSessions.cookieValueFor().");
    return expiresS + '.' + mac;
  }

  /**
   * Tells whether a session has been bound to a browser key.
   *
   * @param session - the session row
   * @returns true when it carries a bound key
   */
  isBound(session: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.isBound().");
    log.debug("Leaving DeviceBoundSessions.isBound().");
    return !!(session && session.dbsc && session.dbsc.jkt && session.dbsc.id);
  }

  /**
   * The device-bound fact of a session (#743, #740): `bound`, `skipped`,
   * `pending`, `timedout` or `none`.
   *
   * Computed from the session, not from the setting. `timedout` is decided
   * at this read when a pending offer is older than
   * `authn.deviceBoundIssuanceWaitS`; nothing stores that word and no timer
   * flips it. `common/issuance_gate.js`'s `deviceBoundFactOf()` is the same
   * reading and must stay the same: the gate cannot require this module
   * (the Kerberos COPY closure).
   *
   * Precedence: a key (`jkt` and `id`) is `bound`, even if a skip header
   * arrived later; stored skip reasons are `skipped`; an offer whose age
   * exceeds the wait is `timedout`, and one still inside it is `pending`;
   * anything else is `none` (DBSC was not in play for this session).
   *
   * @param session - the session row
   * @returns the fact token
   */
  factOf(session: Json): string {
    const { log, config, now } = this.deps;
    log.debug("Entering DeviceBoundSessions.factOf().");
    const fact = this.factFrom(session, config, now());
    log.debug("Leaving DeviceBoundSessions.factOf(). " + fact);
    return fact;
  }

  // One reading, so `factOf()` and a caller that already has the clock
  // cannot drift. `nowMs` is the caller's clock.
  private factFrom(session: Json, cfg: Json, nowMs: number): string {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.factFrom().");
    const d = session && session.dbsc;
    let fact = 'none';
    if (!d) {
      fact = 'none';
    } else if (d.jkt && d.id) {
      fact = 'bound';
    } else if (Array.isArray(d.skippedReasons) && d.skippedReasons.length) {
      fact = 'skipped';
    } else if (d.offeredAt) {
      const wait = Number(cfg.value('authn.deviceBoundIssuanceWaitS'));
      const seconds = isFinite(wait) ? wait : 60;
      fact = nowMs - Number(d.offeredAt) > seconds * 1000
        ? 'timedout' : 'pending';
    }
    log.debug("Leaving DeviceBoundSessions.factFrom(). " + fact);
    return fact;
  }

  // ---------------------------------------------------------------------------
  // ONE BOUND COOKIE PER BINDING WHERE A BROWSER HOLDS SEVERAL ACCOUNTS
  // (#561 with #725). The draft's session instructions name the cookie a
  // DBSC session refreshes (section 9.6), and one browser holding two bound
  // sign-on sessions under ONE name would have each refresh overwrite the
  // other's cookie — every second account refused on every request, and its
  // refreshes fighting for ever. So a binding made while
  // `authn.multipleAccounts` is on names its cookie after its own DBSC
  // session identifier (base64url, a valid cookie-name token), and records
  // the name on the binding, so the name stays the binding's whatever the
  // setting does later. A binding made with the setting off is
  // `sts_session_bound`, exactly as before — and it is the only binding such
  // a browser can hold.
  // ---------------------------------------------------------------------------
  private cookieNameOf(session: Json): string {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.cookieNameOf().");
    const named = session && session.dbsc && session.dbsc.cookie;
    log.debug("Leaving DeviceBoundSessions.cookieNameOf().");
    return typeof named === 'string' && /^[A-Za-z0-9_-]{1,160}$/.test(named)
      ? named : BOUND_COOKIE;
  }

  private presentedCookie(req: Json, name?: string): string {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.presentedCookie().");
    const wanted = name || BOUND_COOKIE;
    let found = '';
    String((req && req.headers && req.headers.cookie) || '').split(';')
      .forEach(function (part) {
        const at = part.indexOf('=');
        if (at > 0 && part.slice(0, at).trim() === wanted) {
          found = part.slice(at + 1).trim();
        }
      });
    log.debug("Leaving DeviceBoundSessions.presentedCookie().");
    return found;
  }

  // THE ONE QUESTION `authn.ts` ASKS OF EVERY SESSION IT HANDS OUT. True for
  // every session that is not bound, and for every session while the
  // setting is off — that is today's behaviour, unchanged. A bound session is
  // honoured only beside a bound cookie minted for its binding and not yet
  // expired. A refusal here is NOT an ending: the browser that holds the key
  // refreshes the cookie before it sends the request (section 10.1), so a
  // request without one is a copied `sts_session`, or a browser that chose to
  // skip a refresh; neither is a reason to end the person's session.
  // A hot path (sessionOf() is called several times per request): no
  // Entering/Leaving pair.
  /**
   * Tells whether a session may be honoured for this request: always, unless
   * it is bound and the request carries no valid bound cookie.
   *
   * @param session - the session row
   * @param req - the request
   * @returns true when the session may be used
   */
  honours(session: Json, req: Json): boolean {
    if (!this.isBound(session) || !this.enabled()) {
      return true;
    }
    const value = this.presentedCookie(req, this.cookieNameOf(session));
    const dot = value.indexOf('.');
    const expiresS = dot > 0 ? value.slice(0, dot) : '';
    const ok = /^\d{1,12}$/.test(expiresS) &&
      Number(expiresS) * 1000 > this.deps.now() &&
      stsCrypto.constantTimeEquals(this.cookieValueFor(session,
                                                       Number(expiresS)),
                                   value);
    // At debug: a copied cookie is presented on every request it is tried
    // on, and a line per request at info is the log the no-per-event rule
    // keeps out (the binding's own events are audit rows).
    if (!ok) {
      this.deps.log.debug(this.deps.errorCodes.tag('STS-AUTHN-0406') +
                          'authn: the device-bound session ' + session.id +
                          ' was presented without a valid bound cookie (' +
                          (value ? 'expired or not this binding\'s'
                                 : 'none') +
                          ') and was not honoured for this request.');
    }
    return ok;
  }

  // A hot path (honouredSession runs on every session read): no
  // Entering/Leaving pair. A debug line is written only when the header is
  // present. Absent is the ordinary request and changes nothing. A
  // well-formed skip is not a failure. A malformed one is recorded
  // (STS-AUTHN-0460) and the request continues; the session is not marked
  // skipped. A session that already has a key is not unbound by a later
  // skip. An empty list is a no-op, not a malformed header.
  /**
   * Records `Secure-Session-Skipped` on a session that is not yet bound
   * (#743).
   *
   * @param session - the session the request presented
   * @param req - the request
   */
  noteSkipped(session: Json, req: Json): void {
    if (this.deps.config.value('authn.deviceBoundSessions') !== true ||
        !session ||
        (session.dbsc && session.dbsc.jkt && session.dbsc.id)) {
      return;
    }
    const raw = req && req.headers
      ? req.headers['secure-session-skipped'] : '';
    const text = Array.isArray(raw) ? raw.join(', ') : String(raw || '');
    if (!text.trim()) {
      return;
    }
    const parsed = this.parseSkipped(text);
    if (!parsed.ok) {
      this.deps.log.debug(this.deps.errorCodes.tag('STS-AUTHN-0460') +
        'authn: Secure-Session-Skipped on session ' + session.id +
        ' was not a list of sf-tokens (' + parsed.why +
        ') and was not recorded.');
      this.deps.audit.audit({
        action: 'authn.session.binding-skipped', outcome: 'failure',
        errorCode: 'STS-AUTHN-0460',
        actor: (session.user && session.user.username) || '',
        target: String(session.id || ''), channel: 'http',
        protocol: 'Authentication',
        summary: 'Secure-Session-Skipped on session ' + session.id +
                 ' was malformed and was not recorded',
        detail: { sessionId: session.id, why: parsed.why }
      });
      return;
    }
    if (!parsed.reasons.length) {
      return;
    }
    const held = session.dbsc || {};
    const prev = Array.isArray(held.skippedReasons) ? held.skippedReasons
                                                    : [];
    const prevIds = Array.isArray(held.skippedIds) ? held.skippedIds : [];
    let same = prev.length === parsed.reasons.length;
    parsed.reasons.forEach(function (reason, i) {
      if (!same) {
        return;
      }
      if (reason !== prev[i] ||
          String(parsed.ids[i] || '') !== String(prevIds[i] || '')) {
        same = false;
      }
    });
    if (same) {
      return;
    }
    session.dbsc = Object.assign({}, held, {
      skippedReasons: parsed.reasons.slice(),
      skippedIds: parsed.ids.slice()
    });
    this.deps.authn().noteSessionChanged(session);
    const who = (session.user && session.user.username) || '';
    this.deps.audit.audit({
      action: 'authn.session.binding-skipped', outcome: 'success',
      actor: who, target: who, channel: 'http',
      protocol: 'Authentication',
      summary: 'session ' + session.id + ' skipped device binding (' +
               parsed.reasons.join(', ') + ')',
      detail: { sessionId: session.id, reasons: parsed.reasons,
                ids: parsed.ids }
    });
  }

  // Section 9.5: a list of sf-tokens, each optionally carrying
  // `session_identifier` as an sf-string. Any well-formed token is
  // recorded, including one this service does not name. A non-token
  // member, a `session_identifier` that is not an sf-string, or a value
  // that does not parse, is malformed.
  private parseSkipped(text: string): { ok: boolean; reasons: string[];
                                        ids: string[]; why: string } {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.parseSkipped().");
    let list: Json = null;
    try {
      list = structuredFields.parseList(text);
    } catch (e) {
      // A throw is a field that is not a Structured Field list. That is
      // the malformed case; the session stays as it was.
      log.debug("Caught in DeviceBoundSessions.parseSkipped(): " +
                ((e && e.message) || e));
      log.debug("Leaving DeviceBoundSessions.parseSkipped(). Malformed.");
      return { ok: false, reasons: [], ids: [],
               why: 'it is not a Structured Field list' };
    }
    const reasons: string[] = [];
    const ids: string[] = [];
    let why = '';
    (list || []).forEach(function (item: Json) {
      if (why) {
        return;
      }
      if (!item || item.type !== 'token' ||
          typeof item.value !== 'string' || !item.value) {
        why = 'a member is not an sf-token';
        return;
      }
      const idBare = structuredFields.param(item.params,
                                            'session_identifier');
      if (idBare !== undefined && idBare.type !== 'string') {
        why = 'session_identifier is not an sf-string';
        return;
      }
      reasons.push(String(item.value));
      ids.push(idBare && typeof idBare.value === 'string'
        ? String(idBare.value) : '');
    });
    if (why) {
      log.debug("Leaving DeviceBoundSessions.parseSkipped(). " + why);
      return { ok: false, reasons: [], ids: [], why: why };
    }
    log.debug("Leaving DeviceBoundSessions.parseSkipped(). " +
              reasons.length + " token(s).");
    return { ok: true, reasons: reasons, ids: ids, why: '' };
  }

  // --- the cookie and the headers -------------------------------------------

  // The attributes the bound cookie is SET with and the attributes the
  // instructions DECLARE are one string, because the browser matches the two
  // (section 8.6: Domain, Path, Secure, HttpOnly, SameSite) and a cookie
  // whose attributes differ from its declaration is a cookie it refreshes
  // for ever. With `authn.deviceBoundIncludeSite` off, the domain is
  // exactly `cookieDomainAttribute()` — no Domain that widens the cookie.
  // On, Domain is the registrable domain of the request host, and an IP,
  // localhost or single-label host keeps the attribute it already had:
  // there is no wider site to name.
  private cookieAttributes(req?: Json): string {
    const { log, config } = this.deps;
    log.debug("Entering DeviceBoundSessions.cookieAttributes().");
    let domain = String(helpers.cookieDomainAttribute() || '')
      .replace(/^;\s*/, '');
    if (this.includeSite()) {
      const site = this.widensTo(this.requestHost(req || null));
      if (site) {
        domain = 'Domain=' + site;
      }
    }
    const out = ['Path=/'].concat(domain ? [domain] : [])
      .concat(config.value('global.https') ? ['Secure'] : [])
      .concat(['HttpOnly', 'SameSite=Lax']).join('; ');
    log.debug("Leaving DeviceBoundSessions.cookieAttributes().");
    return out;
  }

  // The host a request was addressed to, without a port or a trailing dot.
  // A URL is reduced to its host, so a listener's `publicBaseUrl` and a
  // Host header share one reading.
  private static bareHost(value: unknown): string {
    log.debug("Entering DeviceBoundSessions.bareHost().");
    let name = String(value || '').trim().toLowerCase();
    const scheme = name.indexOf('://');
    if (scheme >= 0) {
      name = name.slice(scheme + 3);
    }
    name = name.split('/')[0].split('?')[0];
    if (name.charAt(0) === '[') {
      const end = name.indexOf(']');
      name = end > 0 ? name.slice(1, end) : name;
    } else if (name.indexOf(':') >= 0 &&
               name.indexOf(':') === name.lastIndexOf(':')) {
      name = name.slice(0, name.indexOf(':'));
    }
    name = name.replace(/\.$/, '');
    log.debug("Leaving DeviceBoundSessions.bareHost().");
    return name;
  }

  private requestHost(req: Json): string {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.requestHost().");
    const raw = req && req.headers ? req.headers.host : '';
    const text = Array.isArray(raw) ? String(raw[0] || '')
                                    : String(raw || '');
    const host = DeviceBoundSessions.bareHost(text);
    log.debug("Leaving DeviceBoundSessions.requestHost().");
    return host;
  }

  // The registrable domain of a host. There is no public-suffix list here:
  // `webauthn.rpId`, when it is the host or a label-boundary suffix and
  // contains a dot, is the domain; otherwise the last two labels. A name
  // under a multi-level suffix (`example.co.uk`) needs `webauthn.rpId`.
  // An IP address, localhost or a single label is returned as itself —
  // there is no wider site.
  private registrableDomain(host: string): string {
    const { log, config } = this.deps;
    log.debug("Entering DeviceBoundSessions.registrableDomain().");
    const name = DeviceBoundSessions.bareHost(host);
    let site = name;
    const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(name);
    if (!name || name === 'localhost' || name.indexOf(':') >= 0 || ip ||
        name.indexOf('.') < 0) {
      site = name;
    } else {
      const rp = DeviceBoundSessions.bareHost(
        config.value('webauthn.rpId') || '');
      if (rp.indexOf('.') >= 0 &&
          (name === rp || name.endsWith('.' + rp))) {
        site = rp;
      } else {
        const labels = name.split('.');
        site = labels.length <= 2 ? name : labels.slice(-2).join('.');
      }
    }
    log.debug("Leaving DeviceBoundSessions.registrableDomain().");
    return site;
  }

  // The Domain to set when site scope is on, or '' when the host has no
  // wider DNS site (an address, localhost, a single label).
  private widensTo(host: string): string {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.widensTo().");
    const site = this.registrableDomain(host);
    const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(site);
    const out = site && site.indexOf('.') >= 0 && !ip ? site : '';
    log.debug("Leaving DeviceBoundSessions.widensTo().");
    return out;
  }

  // Sibling hosts a site-scoped session must not cover (#742). Cookie
  // Domain cannot exclude a host, so the draft's scope rule does: an
  // `exclude` of the debugger's public host and of every custom or realm
  // listener hostname under the registrable domain, other than the host
  // that registered. The main listener is this origin. A debugger on the
  // SAME host and another port cannot be excluded: cookies are not
  // port-scoped (RFC 6265), and a scope rule's domain and path cannot
  // name a port. Realm path prefixes are the same origin and are not
  // listed. Nothing is excluded when site scope is off, or when the host
  // has no wider site.
  private siteExclusions(host: string): Json[] {
    const { log, config } = this.deps;
    log.debug("Entering DeviceBoundSessions.siteExclusions().");
    const site = this.widensTo(host);
    const found: string[] = [];
    if (!site) {
      log.debug("Leaving DeviceBoundSessions.siteExclusions(). No site.");
      return [];
    }
    this.considerExclusion(found, host, site,
                           config.value('debugger.publicBaseUrl'));
    try {
      const map = require('../common/listener_map');
      (map.allListeners() || []).forEach((one: Json) => {
        if (!one || one.builtin) {
          return;
        }
        this.considerExclusion(found, host, site, one.host);
        this.considerExclusion(found, host, site, one.publicBaseUrl);
        (one.hostnames || []).forEach((named: string) => {
          this.considerExclusion(found, host, site, named);
        });
      });
    } catch (e) {
      // The exclusion list is a narrowing. A listener map that cannot be
      // read leaves the session site-scoped without holes rather than
      // refusing the registration.
      log.debug("Caught in DeviceBoundSessions.siteExclusions(): " +
                ((e && e.message) || e));
    }
    const out = found.map(function (domain) {
      return { type: 'exclude', domain: domain, path: '/' };
    });
    log.debug("Leaving DeviceBoundSessions.siteExclusions(). " +
              out.length + " exclusion(s).");
    return out;
  }

  private considerExclusion(found: string[], host: string, site: string,
                            value: unknown): void {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.considerExclusion().");
    const bare = DeviceBoundSessions.bareHost(value);
    if (bare && bare !== host &&
        (bare === site || bare.endsWith('.' + site)) &&
        found.indexOf(bare) < 0) {
      found.push(bare);
    }
    log.debug("Leaving DeviceBoundSessions.considerExclusion().");
  }

  private appendHeader(res: Json, name: string, value: string): void {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.appendHeader(). " + name);
    if (res && typeof res.append === 'function') {
      res.append(name, value);
    } else if (res && typeof res.setHeader === 'function') {
      res.setHeader(name, value);
    } else if (res && typeof res.set === 'function') {
      res.set(name, value);
    }
    log.debug("Leaving DeviceBoundSessions.appendHeader().");
  }

  private setBoundCookie(res: Json, session: Json, req?: Json): void {
    const { log, now } = this.deps;
    log.debug("Entering DeviceBoundSessions.setBoundCookie().");
    const nowS = Math.floor(now() / 1000);
    const endS = Math.floor(Number(session.expires || 0) / 1000);
    const expiresS = Math.max(nowS + 1,
                              Math.min(nowS + this.cookieLifetimeS(),
                                       endS || Infinity));
    this.appendHeader(res, 'Set-Cookie', this.cookieNameOf(session) + '=' +
                      this.cookieValueFor(session, expiresS) +
                      '; Max-Age=' + (expiresS - nowS) + '; ' +
                      this.cookieAttributes(req));
    log.debug("Leaving DeviceBoundSessions.setBoundCookie().");
  }

  private setChallengeHeader(res: Json, session: Json): void {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.setChallengeHeader().");
    const challenge = this.mintChallenge('refresh', session.id,
                                         session.dbsc.id);
    res.set('Secure-Session-Challenge', structuredFields.serializeList([
      { type: 'string', value: challenge,
        params: [['id', { type: 'string', value: session.dbsc.id }]] }]));
    log.debug("Leaving DeviceBoundSessions.setChallengeHeader().");
  }

  // THE OFFER, made by `authn.ts` on the answer that sets the session
  // cookie. The challenge is a MAC, so it is not stored. The instant of
  // the offer is (`session.dbsc.offeredAt`, #743): #740 reads it when a
  // pending registration has waited long enough, and a second offer does
  // not move it. No timer is armed.
  /**
   * Adds `Secure-Session-Registration` to the answer that sets a sign-on
   * session's cookie, where the realm binds sessions and this one is a
   * signed-in browser session not yet bound.
   *
   * @param res - the response
   * @param session - the session just started or re-authenticated
   * @returns true when the header was added
   */
  offer(res: Json, session: Json): boolean {
    const { log, realms, errorCodes } = this.deps;
    log.debug("Entering DeviceBoundSessions.offer().");
    if (!this.enabled() || !session || this.isBound(session) ||
        session.authenticated === false || session.chosen === false ||
        session.credentialKey || session.rpSurface) {
      log.debug("Leaving DeviceBoundSessions.offer(). Not offered.");
      return false;
    }
    if (!res || (typeof res.append !== 'function' &&
                 typeof res.setHeader !== 'function' &&
                 typeof res.set !== 'function')) {
      log.warn(errorCodes.tag('STS-AUTHN-0408') + 'authn: session ' +
               session.id + ' could not be offered device binding: the ' +
               'response object takes no header.');
      log.debug("Leaving DeviceBoundSessions.offer(). No response.");
      return false;
    }
    const value = structuredFields.serializeList([{
      type: 'innerList',
      value: ALGORITHMS.map(function (alg) {
        return { type: 'token', value: alg, params: [] };
      }),
      params: [
        ['path', { type: 'string',
                   value: realms.currentPrefix() + REGISTER_PATH }],
        ['challenge', { type: 'string',
                        value: this.mintChallenge('register', session.id,
                                                  '') }]
      ] }]);
    this.appendHeader(res, 'Secure-Session-Registration', value);
    if (!(session.dbsc && Number(session.dbsc.offeredAt) > 0)) {
      session.dbsc = Object.assign({}, session.dbsc || {}, {
        offeredAt: this.deps.now()
      });
      this.deps.authn().noteSessionChanged(session);
    }
    log.debug("Leaving DeviceBoundSessions.offer(). Offered.");
    return true;
  }

  // Section 9.6. `include_site` is false unless
  // `authn.deviceBoundIncludeSite` is on (#742). Off, the scope
  // specification is empty and the cookie domain is today's. On, the
  // cookie's Domain is the registrable domain and sibling listener hosts
  // under it are excluded (`siteExclusions()`).
  private instructions(session: Json, req?: Json): Json {
    const { log, realms } = this.deps;
    log.debug("Entering DeviceBoundSessions.instructions().");
    const site = this.includeSite();
    const host = this.requestHost(req || null);
    const spec = site ? this.siteExclusions(host) : [];
    log.debug("Leaving DeviceBoundSessions.instructions().");
    return {
      session_identifier: session.dbsc.id,
      refresh_url: realms.currentPrefix() + REFRESH_PATH,
      continue: true,
      scope: { include_site: site, scope_specification: spec },
      credentials: [{ type: 'cookie', name: this.cookieNameOf(session),
                      attributes: this.cookieAttributes(req) }],
      allowed_refresh_initiators: []
    };
  }

  // --- reading a request ----------------------------------------------------

  // A header that is a Structured Field sf-string (sections 9.3, 9.4). A bare
  // value that does not parse is taken as it stands when it has the shape the
  // field carries — a compact JWS, an identifier — because an implementation
  // that leaves the quotes off is sending the same value, and section 8.8
  // ends the browser's session on a 4xx, so a refusal of the quoting would
  // sign the person out over a syntax nobody can see.
  private headerString(req: Json, name: string, bare: RegExp): string {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.headerString(). " + name);
    const raw = req && req.headers ? req.headers[name] : undefined;
    const text = Array.isArray(raw) ? raw.join(', ') : String(raw || '');
    if (!text.trim()) {
      log.debug("Leaving DeviceBoundSessions.headerString(). Absent.");
      return '';
    }
    let out = '';
    try {
      const item = structuredFields.parseItem(text);
      out = item && item.type === 'string' ? String(item.value) : '';
    } catch (e) {
      log.debug("Caught in DeviceBoundSessions.headerString(): " +
                ((e && e.message) || e));
      out = bare.test(text.trim()) ? text.trim() : '';
    }
    log.debug("Leaving DeviceBoundSessions.headerString().");
    return out;
  }

  // The proof's header and claims, read without verifying it: which key to
  // verify with is decided from what it says, and the signature is checked
  // after.
  private readProof(req: Json): Proof {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.readProof().");
    const raw = this.headerString(req, 'secure-session-response',
                                  COMPACT_JWS);
    if (!raw) {
      log.debug("Leaving DeviceBoundSessions.readProof(). None.");
      return { code: 'STS-AUTHN-0393',
               why: 'the request carries no Secure-Session-Response, or one ' +
                    'that is not a structured string' };
    }
    const parts = raw.split('.');
    let header: Json = null;
    let claims: Json = null;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch (e) {
      log.debug("Caught in DeviceBoundSessions.readProof(): " +
                ((e && e.message) || e));
      header = null;
    }
    if (parts.length !== 3 || !header || typeof header !== 'object' ||
        !claims || typeof claims !== 'object') {
      log.debug("Leaving DeviceBoundSessions.readProof(). Unreadable.");
      return { code: 'STS-AUTHN-0394',
               why: 'the DBSC proof is not a compact JWS of JSON objects' };
    }
    if (header.typ !== PROOF_TYP) {
      log.debug("Leaving DeviceBoundSessions.readProof(). Wrong typ.");
      return { code: 'STS-AUTHN-0394',
               why: 'the DBSC proof has typ ' + JSON.stringify(header.typ) +
                    ', not "' + PROOF_TYP + '"' };
    }
    if (typeof claims.jti !== 'string' || !claims.jti) {
      log.debug("Leaving DeviceBoundSessions.readProof(). No jti.");
      return { code: 'STS-AUTHN-0394',
               why: 'the DBSC proof carries no jti' };
    }
    log.debug("Leaving DeviceBoundSessions.readProof(). " + header.alg + ".");
    return { raw: raw, header: header, claims: claims };
  }

  // The key a registration proof carries, checked before it is believed:
  // an algorithm this service offered, a public key of that algorithm's type,
  // and no private member.
  private keyProblem(header: Json): string {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.keyProblem().");
    const spec = ALGORITHMS.indexOf(header.alg) >= 0
      ? stsCrypto.JWS_ALGS[header.alg] : null;
    const jwk = header.jwk;
    let why = '';
    if (!spec) {
      why = 'the DBSC proof is signed with ' + JSON.stringify(header.alg) +
            ', which was not offered (' + ALGORITHMS.join(', ') + ')';
    } else if (!jwk || typeof jwk !== 'object' || !jwk.kty) {
      why = 'the registration proof carries no jwk';
    } else if (PRIVATE_MEMBERS.some(function (m) {
      return jwk[m] !== undefined;
    })) {
      why = 'the registration proof\'s jwk carries private key material';
    } else if (jwk.kty !== spec.kty || (spec.crv && jwk.crv !== spec.crv)) {
      why = 'the registration proof\'s jwk (' + jwk.kty +
            (jwk.crv ? '/' + jwk.crv : '') + ') does not match its alg ' +
            header.alg;
    }
    log.debug("Leaving DeviceBoundSessions.keyProblem(). " + (why || 'none'));
    return why;
  }

  // --- answering ------------------------------------------------------------

  private answer(res: Json, status: number, code: string, body: Json): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering DeviceBoundSessions.answer(). " + status);
    if (code) {
      errorCodes.mark(res, code);
    }
    res.set('Cache-Control', 'no-store');
    res.status(status).json(body);
    log.debug("Leaving DeviceBoundSessions.answer().");
  }

  // A refusal: logged with its code, recorded, and answered in English with
  // no code — the code is an operator's (root CLAUDE.md).
  // error-code: none — the definition of this helper; every caller passes its code
  private refuse(res: Json, status: number, code: string, why: string,
                 session: Json, action: string): void {
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering DeviceBoundSessions.refuse(). " + code);
    log.info(errorCodes.tag(code) + 'authn: a device-bound session ' +
             action + ' was refused: ' + why + '.');
    const who = (session && session.user && session.user.username) || '';
    audit.audit({ action: 'authn.session.' + action + '.refused',
                  outcome: 'failure', actor: who, target: who,
                  channel: 'http', protocol: 'Authentication',
                  errorCode: code,
                  summary: 'a device-bound session ' + action +
                           ' was refused: ' + why,
                  detail: { sessionId: (session && session.id) || '' } });
    this.answer(res, status, code, {
      error: 'invalid_request',
      error_description: why.charAt(0).toUpperCase() + why.slice(1) + '.' });
    log.debug("Leaving DeviceBoundSessions.refuse().");
  }

  // A REFRESH THAT PROVES THE COOKIE IS IN THE WRONG HANDS ENDS THE SESSION,
  // through the protocol-independent sign-out so it has every consequence a
  // sign-out has (`logout.endBoundSession()`). The answer is a 401, which
  // ends the browser's DBSC session too (section 8.8), and clears both
  // cookies.
  private endSession(res: Json, session: Json, code: string,
                     why: string, req?: Json): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering DeviceBoundSessions.endSession(). " + code);
    const by = 'a device-bound session refresh that ' + why;
    try {
      this.deps.logout().endBoundSession(session, {
        by: by, initiatingEntity: 'policy', channel: 'http' });
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0407') + 'authn: the sign-out ' +
                'could not end device-bound session ' + session.id +
                ' (' + ((e && e.message) || e) + '); it is ended here.');
      this.deps.authn().endSessionById(session.id, by, 'policy');
    }
    // The default cookie only where it is THIS session's (#561): with
    // several accounts in the browser it can name another account, whose
    // session the evidence says nothing about. With the setting off it is
    // always this session's, as before.
    if (!this.deps.multipleAccounts() || !req ||
        this.deps.authn().sessionCookieNames(req, session.id)) {
      this.deps.authn().clearSessionCookie(res);
    }
    this.appendHeader(res, 'Set-Cookie', this.cookieNameOf(session) +
                      '=; Max-Age=0; ' + this.cookieAttributes());
    // error-code: none — `code` is the caller's literal (STS-AUTHN-0403, -0404)
    this.refuse(res, 401, code, 'the refresh ' + why + '; the session was ' +
                'ended', session, 'refresh');
    log.debug("Leaving DeviceBoundSessions.endSession().");
  }

  // The signed-in session the request's `sts_session` names, read WITHOUT
  // the bound-cookie gate — at refresh the bound cookie is exactly what is
  // missing.
  //
  // WITH SEVERAL ACCOUNTS IN THE BROWSER (#561) no ticket or hint names one
  // here, so `sessionOf()` would answer nobody whenever two are signed in.
  // The browser's proof names the session instead: `pick` is asked of each
  // live session the account set holds (`authn.bindingSessionOf()`) — the
  // registration challenge's MAC is over one session id, the refresh's
  // `Sec-Secure-Session-Id` is one binding's — and the first it accepts is
  // the session. A browser with no set, and every request with the setting
  // off, reads `sessionOf()` as before. `{ session, others }`: `others`
  // says the browser holds signed-in sessions none of which is the one.
  private sessionFor(req: Json, pick?: (session: Json) => boolean): Json {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.sessionFor().");
    const authn = this.deps.authn();
    const many = pick && typeof authn.bindingSessionOf === 'function'
      ? authn.bindingSessionOf(req, function (one: Json) {
        return !!one && one.authenticated !== false && pick(one);
      }) : null;
    if (many) {
      log.debug("Leaving DeviceBoundSessions.sessionFor(). From the " +
                "account set.");
      return many;
    }
    const session = authn.sessionOf(req, true);
    log.debug("Leaving DeviceBoundSessions.sessionFor().");
    return { session: session && session.authenticated !== false
      ? session : null, others: false };
  }

  // Spends a challenge once for the cluster. `used`, `store` or `ok`.
  private async spend(challenge: string): Promise<string> {
    const { log, clusterClaims, now } = this.deps;
    log.debug("Entering DeviceBoundSessions.spend().");
    const expiresMs = Number(challenge.split('.')[0]) * 1000;
    const answer: Json = await clusterClaims.claim({
      scope: CLAIM_SCOPE, value: challenge,
      ttlMs: Math.max(1000, expiresMs - now() + 60 * 1000) });
    const out = answer && answer.ok ? 'ok'
      : (answer && answer.reason === 'used' ? 'used' : 'store');
    log.debug("Leaving DeviceBoundSessions.spend(). " + out);
    return out;
  }

  // --- the endpoints --------------------------------------------------------

  /**
   * Answers `POST /authn/dbsc/register`: verifies the proof of the browser's
   * new key over the challenge the sign-in offered, binds the session to it,
   * and answers the session instructions and the first bound cookie.
   *
   * @param req - the request
   * @param res - the response
   * @returns when answered
   */
  async register(req: Json, res: Json): Promise<void> {
    const { log, audit } = this.deps;
    log.debug("Entering DeviceBoundSessions.register().");
    if (!this.enabled()) {
      this.refuse(res, 404, 'STS-AUTHN-0390', 'this realm does not bind ' +
                  'sessions to a browser key (authn.deviceBoundSessions)',
                  null, 'registration');
      log.debug("Leaving DeviceBoundSessions.register(). Off.");
      return;
    }
    const self = this;
    // The challenge the proof carries, read before which session it is for
    // is known, only to choose among a browser's several accounts (#561);
    // the proof is read again and checked in full below.
    const early = this.readProof(req);
    const jti = early.claims ? early.claims.jti : '';
    const found = this.sessionFor(req, function (one: Json) {
      return self.checkChallenge(jti, 'register', one.id, '') !== 'foreign';
    });
    const session = found.session;
    if (!session && found.others && early.code) {
      // error-code: none — readProof()'s literal (STS-AUTHN-0393, -0394)
      this.refuse(res, 400, early.code, early.why, null, 'registration');
      log.debug("Leaving DeviceBoundSessions.register(). Unreadable proof, " +
                "several accounts.");
      return;
    }
    if (!session && found.others) {
      this.refuse(res, 400, 'STS-AUTHN-0397', 'the registration proof\'s ' +
                  'challenge is not one this service offered any of this ' +
                  'browser\'s signed-in accounts', null, 'registration');
      log.debug("Leaving DeviceBoundSessions.register(). No account's " +
                "challenge.");
      return;
    }
    if (!session) {
      this.refuse(res, 401, 'STS-AUTHN-0391', 'no signed-in session is ' +
                  'behind this request', null, 'registration');
      log.debug("Leaving DeviceBoundSessions.register(). No session.");
      return;
    }
    if (this.isBound(session)) {
      this.refuse(res, 409, 'STS-AUTHN-0392', 'the session is already ' +
                  'bound to a key, and a second key is never accepted for ' +
                  'it', session, 'registration');
      log.debug("Leaving DeviceBoundSessions.register(). Already bound.");
      return;
    }
    const proof = this.readProof(req);
    if (proof.code) {
      // error-code: none — readProof()'s literal (STS-AUTHN-0393, -0394)
      this.refuse(res, 400, proof.code, proof.why, session, 'registration');
      log.debug("Leaving DeviceBoundSessions.register(). Unreadable proof.");
      return;
    }
    const problem = this.keyProblem(proof.header);
    if (problem) {
      this.refuse(res, 400, 'STS-AUTHN-0395', problem, session,
                  'registration');
      log.debug("Leaving DeviceBoundSessions.register(). Bad key.");
      return;
    }
    try {
      stsCrypto.verifyCompactJws(proof.raw, proof.header.jwk,
                                 { algorithms: [proof.header.alg] });
    } catch (e) {
      log.debug("Caught in DeviceBoundSessions.register(): " +
                ((e && e.message) || e));
      this.refuse(res, 400, 'STS-AUTHN-0396', 'the registration proof does ' +
                  'not verify with the key in its own header', session,
                  'registration');
      log.debug("Leaving DeviceBoundSessions.register(). Bad signature.");
      return;
    }
    const fresh = this.checkChallenge(proof.claims.jti, 'register',
                                      session.id, '');
    if (fresh !== 'ok') {
      this.refuse(res, 400, 'STS-AUTHN-0397', 'the registration proof\'s ' +
                  'challenge is ' + (fresh === 'expired' ? 'expired'
                    : 'not one this service offered this session'),
                  session, 'registration');
      log.debug("Leaving DeviceBoundSessions.register(). Challenge " + fresh);
      return;
    }
    const spent = await this.spend(proof.claims.jti);
    if (spent !== 'ok') {
      if (spent === 'used') {
        this.refuse(res, 400, 'STS-AUTHN-0398', 'the registration ' +
                    'challenge was already used', session, 'registration');
      } else {
        this.refuse(res, 503, 'STS-AUTHN-0399', 'the cluster store could ' +
                    'not record the challenge as spent', session,
                    'registration');
      }
      log.debug("Leaving DeviceBoundSessions.register(). Not spent.");
      return;
    }
    const jwk = proof.header.jwk;
    const publicJwk: Json = {};
    Object.keys(jwk).filter(function (m) {
      return ['kty', 'crv', 'x', 'y', 'n', 'e'].indexOf(m) >= 0;
    }).forEach(function (m) {
      publicJwk[m] = jwk[m];
    });
    const dbscId = stsCrypto.randomBytes(16).toString('base64url');
    // The offer's instant stays, so a registration that finishes still
    // says when it was asked. A skip recorded before the key arrived is
    // cleared: the fact is `bound` because `jkt` is set, and the reasons
    // would otherwise outlive the binding they described.
    const offeredAt = session.dbsc && Number(session.dbsc.offeredAt) > 0
      ? Number(session.dbsc.offeredAt) : this.deps.now();
    session.dbsc = {
      id: dbscId,
      alg: proof.header.alg, jwk: publicJwk,
      jkt: stsCrypto.jwkThumbprint(publicJwk),
      boundAt: this.deps.now(), refreshes: 0, refreshedAt: 0,
      offeredAt: offeredAt
    };
    if (this.deps.multipleAccounts()) {
      // A cookie of this binding's own (`cookieNameOf()`).
      session.dbsc.cookie = BOUND_COOKIE + '_' + dbscId;
    }
    const authn = this.deps.authn();
    authn.noteSessionChanged(session);
    const who = (session.user && session.user.username) || '';
    audit.audit({ action: 'authn.session.bound', outcome: 'success',
                  actor: who, target: who, channel: 'http',
                  protocol: 'Authentication',
                  summary: 'session ' + session.id + ' was bound to a ' +
                           proof.header.alg + ' key the browser holds',
                  detail: { sessionId: session.id, alg: proof.header.alg,
                            jkt: session.dbsc.jkt } });
    this.setBoundCookie(res, session, req);
    this.setChallengeHeader(res, session);
    this.answer(res, 200, '', this.instructions(session, req));
    log.debug("Leaving DeviceBoundSessions.register(). Bound.");
  }

  /**
   * Answers `POST /authn/dbsc/refresh`: a 403 with a challenge when no proof
   * came, a new bound cookie for a proof with the bound key over a fresh
   * challenge, and the end of the session for one signed by any other key
   * or carrying a challenge already spent.
   *
   * @param req - the request
   * @param res - the response
   * @returns when answered
   */
  async refresh(req: Json, res: Json): Promise<void> {
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering DeviceBoundSessions.refresh().");
    if (!this.enabled()) {
      this.refuse(res, 404, 'STS-AUTHN-0390', 'this realm does not bind ' +
                  'sessions to a browser key (authn.deviceBoundSessions)',
                  null, 'refresh');
      log.debug("Leaving DeviceBoundSessions.refresh(). Off.");
      return;
    }
    const dbscId = this.headerString(req, 'sec-secure-session-id',
                                     /^[A-Za-z0-9_-]{1,128}$/);
    if (!dbscId) {
      this.refuse(res, 400, 'STS-AUTHN-0400', 'the refresh carries no ' +
                  'Sec-Secure-Session-Id', null, 'refresh');
      log.debug("Leaving DeviceBoundSessions.refresh(). No id.");
      return;
    }
    const self = this;
    const found = this.sessionFor(req, function (one: Json) {
      return self.isBound(one) && one.dbsc.id === dbscId;
    });
    if (!found.session && found.others) {
      // Signed-in accounts, none of them this binding: the 401 below that
      // ends only the browser's stale registration (STS-AUTHN-0401).
      this.refuse(res, 401, 'STS-AUTHN-0401', 'the refresh names a ' +
                  'device-bound session none of this browser\'s signed-in ' +
                  'accounts is', null, 'refresh');
      log.debug("Leaving DeviceBoundSessions.refresh(). Unknown id, " +
                "several accounts.");
      return;
    }
    const session = found.session;
    if (!session) {
      this.refuse(res, 401, 'STS-AUTHN-0391', 'no signed-in session is ' +
                  'behind this request', null, 'refresh');
      log.debug("Leaving DeviceBoundSessions.refresh(). No session.");
      return;
    }
    // AN UNKNOWN DBSC SESSION ENDS THE BROWSER'S, NOT THIS ONE. The browser
    // can hold a DBSC session left over from a sign-on session that was
    // since replaced — somebody else signed in in the same browser — and it
    // refreshes it with the NEW session's cookie. Ending the cookie's
    // session for that would sign the newer person out; the 401 ends only
    // the stale registration in the browser.
    if (!this.isBound(session) || session.dbsc.id !== dbscId) {
      this.refuse(res, 401, 'STS-AUTHN-0401', 'the refresh names a ' +
                  'device-bound session this sign-on session is not',
                  session, 'refresh');
      log.debug("Leaving DeviceBoundSessions.refresh(). Unknown id.");
      return;
    }
    if (!this.headerString(req, 'secure-session-response', /^\S+$/)) {
      log.debug(errorCodes.tag('STS-AUTHN-0402') + 'authn: a refresh of ' +
                session.id + ' came without a proof; a challenge is sent.');
      this.setChallengeHeader(res, session);
      this.answer(res, 403, 'STS-AUTHN-0402', {
        error: 'invalid_request',
        error_description: 'Sign the challenge in Secure-Session-Challenge.' });
      log.debug("Leaving DeviceBoundSessions.refresh(). Challenged.");
      return;
    }
    const proof = this.readProof(req);
    if (proof.code) {
      // error-code: none — readProof()'s literal (STS-AUTHN-0393, -0394)
      this.refuse(res, 400, proof.code, proof.why, session, 'refresh');
      log.debug("Leaving DeviceBoundSessions.refresh(). Unreadable proof.");
      return;
    }
    // THE KEY FIRST, whatever the challenge: a proof that is not the bound
    // key's is the one thing that shows the cookie is somewhere else.
    let verified = proof.header.alg === session.dbsc.alg;
    if (verified) {
      try {
        stsCrypto.verifyCompactJws(proof.raw, session.dbsc.jwk,
                                   { algorithms: [session.dbsc.alg] });
      } catch (e) {
        log.debug("Caught in DeviceBoundSessions.refresh(): " +
                  ((e && e.message) || e));
        verified = false;
      }
    }
    if (!verified) {
      this.endSession(res, session, 'STS-AUTHN-0403', 'was not signed by ' +
                      'the key the session is bound to', req);
      log.debug("Leaving DeviceBoundSessions.refresh(). Wrong key.");
      return;
    }
    if (proof.header.jwk !== undefined) {
      this.refuse(res, 400, 'STS-AUTHN-0405', 'a refresh proof must not ' +
                  'carry a jwk (section 9.10)', session, 'refresh');
      log.debug("Leaving DeviceBoundSessions.refresh(). A jwk.");
      return;
    }
    const fresh = this.checkChallenge(proof.claims.jti, 'refresh',
                                      session.id, session.dbsc.id);
    if (fresh !== 'ok') {
      // Stale, or minted for something else: a new one, and the browser
      // signs it (section 8.8's 403). Not a refusal of the person.
      log.debug(errorCodes.tag('STS-AUTHN-0397') + 'authn: a refresh of ' +
                session.id + ' signed a challenge that is ' + fresh +
                '; a new one is sent.');
      this.setChallengeHeader(res, session);
      this.answer(res, 403, 'STS-AUTHN-0397', {
        error: 'invalid_request',
        error_description: 'The challenge is ' + fresh + '; sign the one ' +
                           'in Secure-Session-Challenge.' });
      log.debug("Leaving DeviceBoundSessions.refresh(). Re-challenged.");
      return;
    }
    const spent = await this.spend(proof.claims.jti);
    if (spent === 'used') {
      this.endSession(res, session, 'STS-AUTHN-0404', 'replayed a ' +
                      'challenge already spent', req);
      log.debug("Leaving DeviceBoundSessions.refresh(). Replayed.");
      return;
    }
    if (spent !== 'ok') {
      // A 5xx: the browser keeps its session and backs off (section 8.8).
      this.refuse(res, 503, 'STS-AUTHN-0399', 'the cluster store could not ' +
                  'record the challenge as spent', session, 'refresh');
      log.debug("Leaving DeviceBoundSessions.refresh(). Store.");
      return;
    }
    session.dbsc = Object.assign({}, session.dbsc, {
      refreshes: Number(session.dbsc.refreshes || 0) + 1,
      refreshedAt: this.deps.now() });
    this.deps.authn().noteSessionChanged(session);
    const who = (session.user && session.user.username) || '';
    audit.audit({ action: 'authn.session.refreshed', outcome: 'success',
                  actor: who, target: who, channel: 'http',
                  protocol: 'Authentication',
                  summary: 'the bound cookie of session ' + session.id +
                           ' was renewed on a proof of its key',
                  detail: { sessionId: session.id,
                            refreshes: session.dbsc.refreshes } });
    this.setBoundCookie(res, session, req);
    this.setChallengeHeader(res, session);
    this.answer(res, 200, '', this.instructions(session, req));
    log.debug("Leaving DeviceBoundSessions.refresh(). Renewed.");
  }

  // What the console's and the portal's session rows say about a binding.
  /**
   * Describes a session's binding for a session row.
   *
   * @param session - the session row
   * @returns `{ bound, alg, boundAt, refreshes, refreshedAt, fact, reasons }`
   */
  bindingOf(session: Json): Json {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.bindingOf().");
    const bound = this.isBound(session);
    const d = (session && session.dbsc) || {};
    const fact = this.factOf(session);
    const reasons = Array.isArray(d.skippedReasons)
      ? d.skippedReasons.map(String) : [];
    log.debug("Leaving DeviceBoundSessions.bindingOf(). " + fact);
    return { bound: bound, alg: bound ? String(d.alg || '') : '',
             boundAt: bound ? Number(d.boundAt || 0) : 0,
             refreshes: bound ? Number(d.refreshes || 0) : 0,
             refreshedAt: bound ? Number(d.refreshedAt || 0) : 0,
             fact: fact, reasons: reasons };
  }

  /**
   * Registers the two endpoints.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteApp): void {
    const { log } = this.deps;
    log.debug("Entering DeviceBoundSessions.registerRoutes().");
    const self = this;
    (app as any).post(REGISTER_PATH, function (req: Json, res: Json,
                                                next: Function) {
      log.debug("Entering POST " + REGISTER_PATH + ".");
      self.register(req, res).then(function () {
        log.debug("Leaving POST " + REGISTER_PATH + ".");
      }, function (e) {
        log.debug("Caught in POST " + REGISTER_PATH + ": " +
                  ((e && e.message) || e));
        next(e);
      });
    });
    (app as any).post(REFRESH_PATH, function (req: Json, res: Json,
                                               next: Function) {
      log.debug("Entering POST " + REFRESH_PATH + ".");
      self.refresh(req, res).then(function () {
        log.debug("Leaving POST " + REFRESH_PATH + ".");
      }, function (e) {
        log.debug("Caught in POST " + REFRESH_PATH + ": " +
                  ((e && e.message) || e));
        next(e);
      });
    });
    log.debug("Leaving DeviceBoundSessions.registerRoutes().");
  }
}

const slot = new InstanceSlot<DeviceBoundSessions>(
  'authn/device_bound_sessions',
  () => new DeviceBoundSessions(DeviceBoundSessions.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Device Bound Session Credentials (#725): the registration header, the
 * registration and refresh endpoints, and the bound-cookie check.
 *
 * Exports the class for the composition root and facades that forward to
 * the installed instance; `authn.ts` calls `offer`, `honours` and
 * `bindingOf`, and (#743) `noteSkipped` and `factOf`.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  DeviceBoundSessions: DeviceBoundSessions,
  installInstance: (instance: DeviceBoundSessions): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  REGISTER_PATH: REGISTER_PATH,
  REFRESH_PATH: REFRESH_PATH,
  BOUND_COOKIE: BOUND_COOKIE,
  ALGORITHMS: ALGORITHMS,
  enabled: slot.forward('enabled'),
  offer: slot.forward('offer'),
  honours: slot.forward('honours'),
  isBound: slot.forward('isBound'),
  bindingOf: slot.forward('bindingOf'),
  noteSkipped: slot.forward('noteSkipped'),
  factOf: slot.forward('factOf'),
  includeSite: slot.forward('includeSite')
};
