// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: ssf_http.ts
//
// ===========================================================================
// THE SECOND OUTBOUND REQUEST IN THIS REPOSITORY, AND IT IS A WEAKER CASE THAN
// THE FIRST ONE. SAY SO RATHER THAN CITING IT.
//
// `federation/federation_http.ts` is the first, and its header makes an
// argument this file CANNOT make. Its rule is:
//
//     THOSE URLS ARE SUPPLIED BY THE CALLER. THESE ARE SUPPLIED BY THE
//     ADMINISTRATOR.
//
// — and it enforces it by refusing to take a URL at all: `fetchJson()` takes a
// relationship record and the NAME of an attribute on it, and there are three
// legal names. A push delivery endpoint is not like that and pretending
// otherwise would be the dangerous version of this feature.
//
// **RFC 8935 PUSH DELIVERY IS, BY CONSTRUCTION, THE RECEIVER TELLING THE
// TRANSMITTER WHERE TO POST.** That is not an implementation choice here; it
// is what the delivery method IS. A receiver creates a stream at the
// management API and names `delivery.endpoint_url`, and the transmitter posts
// SETs there. Any transmitter that speaks push takes a caller-supplied URL,
// including every commercial one.
//
// So the honest statement is: this file makes an outbound request to an
// address a caller chose, and these are the four things that bound it.
//
// 1. **`ssf.pushDelivery` TURNS IT OFF ENTIRELY**, and a deployment that is
//    reachable by anybody it does not trust should set it. With it off, this
//    service still speaks the whole of SSF over POLL delivery — where nothing
//    is dialled at all, because the receiver comes here — and
//    `ssf.deliveryMethods` then advertises only `urn:ietf:rfc:8936`, so a
//    receiver finds out at stream creation rather than by never receiving
//    anything.
//
// 2. **`ssf.pushAllowedHosts` IS AN ALLOWLIST AND IT IS EMPTY BY DEFAULT,
//    MEANING ANY.** That default is the one deliberate looseness here and it
//    is what makes this service usable as a mock; a deployment sets the list
//    and every other host is refused by name. It is a HOST list rather than a
//    URL list on purpose: a receiver legitimately moves its endpoint path
//    around and does not legitimately move to another host.
//
// 3. **https, WITH THE CERTIFICATE VERIFIED**, exactly as federation does,
//    and for a reason that is different in kind: what travels on this request
//    is not a credential, it is an EVENT — that somebody's session was
//    revoked, that an account was disabled. That is somebody's security
//    posture in transit, and it is also carrying the receiver's own
//    `authorization_header`, which IS a credential. Both halves want TLS, and
//    RFC 8935 requires it with the receiver authenticated. Since #171 the
//    policy is `common/outbound_tls.ts`'s: plain http only with
//    `ssf.pushAllowHttp`, and never in product mode; verification off only
//    with `ssf.pushSkipTlsVerification`, and only in development; a private
//    CA through `ssf.pushCaFile`. This service's own receivers are the one
//    exception to all three, and it is not a relaxation — see `pushSet()`.
//
// 4. **NO REDIRECTS, A CAPPED BODY AND A TIMEOUT**, for federation's reasons.
//    A 302 from a push endpoint is not a protocol this service speaks and
//    following one would post the event, and the receiver's authorization
//    header, wherever the Location said.
//
// **AND ONE THING THAT IS NOT A BOUND AND IS WORTH NOT MISTAKING FOR ONE.**
// These endpoints are gated — unconditionally, since `global.mode` replaced
// `ssf.authRequired` on 2026-09-06 — but every credential this service accepts
// is a turnstile, see `ssf/CLAUDE.md`. So "a receiver created the stream" is
// not evidence of anything much. The bounds above are the bounds; the gate is
// not one of them.
//
// ---------------------------------------------------------------------------
// WHAT IT DOES NOT DO, AND THE ONE THAT SURPRISES PEOPLE.
//
// **IT DOES NOT RETRY BY DEFAULT.** RFC 8935 section 2.4 lets a transmitter
// retry a failed push and this service does not, because a mock that retried
// would make a receiver's ONE-SHOT failure invisible: a client under test that
// answers 500 to the first push and 202 to the second looks, from its own
// logs, like a client that works. The failed SET goes to the stream's
// dead-letter queue with the reason (2026-09-14; it stayed on the live queue
// before, and the `redeliver` operation this comment named never existed).
// `ssf.pushRetries` (0 by default) turns retries on — see
// `pushSetWithRetries()`. Deliberate rather than unfinished, and
// `ssf/CLAUDE.md` lists it under what this family does not do.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route and requires `helpers.js`,
// `config.js`, `realms.js`, `version.js` and node's own `http`/`https`/`url`
// (and `tls/tls_server.js` lazily, see pushSet()) — nothing else here — so it
// cannot join a cycle and a test can drive it against a throwaway listener.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `SsfHttp` takes the logger, `config`, `realms`, the four address
// readers of `helpers.js`, the User-Agent and a LOADER for `tls/tls_server.js`
// (a loader, for the lazy require `pushSet()` argues) through its constructor.
// Node's own `http`/`https`/`url` are libraries and are used directly. The
// push cap's two counters stay module state, as they were. The module still
// exports its old names as FACADES forwarding to the instance the composition
// root builds (#50, R2), for `ssf.ts`, `ssf_receivers.ts`,
// `ssf_dead_letter_report.ts` and the tests. A process that loads this module
// without the root builds a default instance when the module loads.
// ---------------------------------------------------------------------------

import https = require('https');
import http = require('http');
import nodeUrl = require('url');
import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// For the realm prefix on `ownBaseUrl()`. A leaf with respect to this
// directory: it requires nothing here.
import realms = require('../common/realms');
import version = require('../common/version');
import OutboundTls = require('../common/outbound_tls');

const { URL } = nodeUrl;

// WHO IS CALLING, AND WHICH BUILD OF IT. A Security Event Token arrives at a
// receiver unasked — that is what RFC 8935 push IS — so the receiver's log is
// the only place its operator can find out what has been talking to them. RFC
// 9110 product form; common/version.js owns the one copy of the product token.
// Built once at require time: the version cannot change while the process
// runs.
const USER_AGENT = version.userAgent('ssf-transmitter');

// THE OUTBOUND TRANSPORT POLICY, as `common/outbound_tls.ts` takes it (#171).
// No plain http in product at all: RFC 8935 names no loopback exception, and
// this service's own receivers are exempt for a different reason (header,
// point 3).
/**
 * The outbound transport policy for a push, as `common/outbound_tls.ts` takes
 * it: its settings and codes, with no plain http in product mode.
 */
const PUSH_TRANSPORT = {
  what: 'an SSF push delivery',
  allowHttpKey: 'ssf.pushAllowHttp',
  skipTlsKey: 'ssf.pushSkipTlsVerification',
  caFileKey: 'ssf.pushCaFile',
  loopbackHttpInProduct: false,
  httpRefusedCode: 'STS-SSF-0108',
  skipIgnoredCode: 'STS-SSF-0109'
};

// THE ERROR CODES (common/error_codes.js). Every way a push can fail carries
// its code on the result as `errorCode`, which `ssf.ts`'s transmit() puts on
// the SET's dead letter, and the sweep counts by code in its one summary line
// (2026-09-14; it was an audit row per failure). That result is read field by
// field there and never serialised to anybody, so the code reaches no receiver
// and no caller — which is why this file needs no require of the registry at
// all.

// A receiver that answers a push with more than this is not answering RFC
// 8935. A success is 202 with an EMPTY body and a failure is a small JSON
// object; 64 KiB is three orders of magnitude of headroom and still a bound.
// `ssf.pushMaxResponseBytes` since 2026-09-12, read per push; this constant is
// its default and is kept as an export for what printed it.
const MAX_BODY_BYTES = 64 * 1024;

// The media type of a SET on the wire (RFC 8417 section 2.3). It is not
// `application/jwt` and a receiver that dispatches on the type — several do —
// drops one sent as a plain JWT with no error anybody sees.
const SET_MEDIA_TYPE = 'application/secevent+jwt';

// ---------------------------------------------------------------------------
// THE PUSH CAP'S STATE — see `acquirePushSlot()`. Per process, as the setting
// says.
// ---------------------------------------------------------------------------
let pushesActive = 0;
// WAITING PUSHES ARE QUEUED PER DESTINATION (2026-09-27), and a freed slot
// goes to the destinations in turn. The key is the receiver's endpoint; the
// Map's insertion order is the turn. See `acquirePushSlot()`.
const pushesWaiting: Map<string, Array<(release: () => void) => void>> =
  new Map();
let pushesWaitingCount = 0;

// What a push answers. `url` and `attempts` are added on the way out.
interface PushResult {
  ok: boolean;
  status: number;
  err: string;
  description: string;
  why: string;
  errorCode?: string;
  retryable?: boolean;
  url?: string;
  attempts?: Array<{ status: number; why: string }>;
  [member: string]: unknown;
}

interface PushOptions {
  authorizationHeader?: unknown;
}

interface SsfHttpDeps {
  log: { debug(m: string): void; info(m: string): void;
         warn(m: string): void };
  config: { value(key: string): any };
  realms: {
    current(): any;
    currentPrefix(): string;
  };
  PORT: unknown;
  loopbackHost(): string;
  hostForUrl(host: string): string;
  pinnedBaseUrl(): string;
  baseUrlOf(req: any): string;
  userAgent: string;
  // `tls/tls_server.js`, required when first asked for. See `pushSet()`.
  loadTlsServer(): {
    serverCertificate(): { trustAnchorPem?: string;
                          fingerprint256?: string };
  };
}

/**
 * The transmitter's outbound half: pushing a Security Event Token to a
 * receiver's endpoint (RFC 8935), with the URL rules, a per-process concurrency
 * cap and retries.
 *
 * The endpoint is the receiver's choice by construction; the bounds are
 * `ssf.pushDelivery`, `ssf.pushAllowedHosts`, https and the response size. This
 * service's own loopback receivers are exempt from the allowlist and, where the
 * listener is http, from the https rule.
 */
class SsfHttp {
  /**
   * The default bound on a receiver's response body, 64 KiB.
   */
  static readonly MAX_BODY_BYTES = MAX_BODY_BYTES;
  /**
   * The media type a SET is posted with, `application/secevent+jwt`.
   */
  static readonly SET_MEDIA_TYPE = SET_MEDIA_TYPE;

  /**
   * Builds the transport from its dependencies.
   *
   * @param deps - the modules and functions it reads, from
   * `SsfHttp.defaultDeps()` or the composition root
   */
  constructor(private readonly deps: SsfHttpDeps) {
    deps.log.debug("Entering SsfHttp.constructor().");
    deps.log.debug("Leaving SsfHttp.constructor().");
  }

  /**
   * Returns the bound on a receiver's response body
   * (`ssf.pushMaxResponseBytes`).
   *
   * @returns the bound, in bytes
   */
  maxBodyBytes(): any {
    const { log, config } = this.deps;
    log.debug("Entering SsfHttp.maxBodyBytes().");
    log.debug("Leaving SsfHttp.maxBodyBytes().");
    return config.value('ssf.pushMaxResponseBytes');
  }

  /**
   * Says whether this service makes push deliveries at all
   * (`ssf.pushDelivery`).
   *
   * @returns true when it does
   */
  pushAllowed(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering SsfHttp.pushAllowed().");
    const on = !!config.value('ssf.pushDelivery');
    log.debug("Leaving SsfHttp.pushAllowed(). " + on);
    return on;
  }

  // The three transport settings as they are IN FORCE in this realm (#171) —
  // in product a stored `ssf.pushSkipTlsVerification` is not.
  /**
   * Describes the three push transport settings as they are in force in the
   * ambient realm.
   *
   * @returns the description
   */
  transportSettings(): ReturnType<typeof OutboundTls.describe> {
    const { log } = this.deps;
    log.debug("Entering SsfHttp.transportSettings().");
    log.debug("Leaving SsfHttp.transportSettings().");
    return OutboundTls.describe(PUSH_TRANSPORT);
  }

  private timeoutMs(): any {
    const { log, config } = this.deps;
    log.debug("Entering SsfHttp.timeoutMs().");
    const value = config.value('ssf.pushTimeoutMs');
    log.debug("Leaving SsfHttp.timeoutMs(). " + value);
    return value;
  }

  // The allowlist, as a list of lower-case host names. Empty means ANY, which
  // is the default and the one deliberate looseness in this file — see point
  // 2 of the header.
  /**
   * Returns the push host allowlist, lower-cased (`ssf.pushAllowedHosts`);
   * empty means any host.
   *
   * @returns the host names
   */
  allowedHosts(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering SsfHttp.allowedHosts().");
    const asked = config.value('ssf.pushAllowedHosts');
    const list = Array.isArray(asked) ? asked
                                      : String(asked || '').split(',');
    const out = list.map(function (one) {
      return String(one).trim().toLowerCase();
    }).filter(Boolean);
    log.debug("Leaving SsfHttp.allowedHosts(). " + out.length +
              ' entry/entries.');
    return out;
  }

  // =========================================================================
  // THIS PROCESS'S OWN ADDRESS, AND THE ONE ENDPOINT FAMILY THAT IS NOT
  // SOMEBODY ELSE'S (2026-09-10).
  //
  // The admin console and the user portal are SSF receivers now — each with a
  // seeded stream and a receive endpoint of its own — and the stream's
  // `delivery.endpoint_url` is this service's own loopback address. That was
  // a decision with an alternative, and the alternative was rejected for
  // `common/oidc_rp.ts`'s reason: handing the SET to the inbox by function
  // call would have been a receiver that never parses a body, never checks a
  // media type, never presents an authorization header and never verifies a
  // signature — the half of a receiver that only looks run. `ssf/CLAUDE.md`
  // argues it beside that file's own.
  //
  // **SO TWO OF THE FOUR BOUNDS IN THE HEADER DO NOT APPLY TO THIS ONE
  // ADDRESS, AND BOTH EXEMPTIONS ARE ABOUT WHAT THEY WERE PROTECTING.**
  //
  //   * The ALLOWLIST (`ssf.pushAllowedHosts`) exists to stop this service
  //     dialling a host somebody named in a stream configuration. This host
  //     is not named by anybody — it is computed here, from `global.port`,
  //     and it is the process making the request. A deployment that narrows
  //     the list to its own receivers would otherwise silently take its own
  //     console offline, and the failure would read as "the console shows
  //     nothing" rather than as a setting.
  //
  //   * The https RULE exists because a Security Event Token is somebody's
  //     security posture IN TRANSIT and the receiver's `authorization_header`
  //     travels beside it. A request from this process to itself over
  //     127.0.0.1 does not traverse a network — the same reading RFC 8252
  //     section 8.3 gives the loopback interface — so with `global.https`
  //     off, where the listener genuinely is http, the internal push is
  //     dialled rather than refused. Nothing else about http changes.
  //
  // **WHAT IS NOT EXEMPT IS `ssf.pushDelivery`.** With it off this service
  // makes no outbound request at all, including this one, and the two
  // internal receivers go quiet. That is stated at seeding time and on both
  // inbox pages rather than left to be discovered — see `ssf_receivers.ts`.
  //
  // It is a computed ORIGIN comparison and never a substring match: a
  // receiver whose endpoint is
  // `https://evil.example/?x=https://127.0.0.1:8081/` is not this service and
  // must not inherit either exemption.
  // =========================================================================
  /**
   * Returns the origin this process dials itself on: the loopback address of
   * the bound family, `global.port`, and https or http as `global.https` says.
   *
   * @returns the origin
   */
  loopbackOrigin(): string {
    const { log, config, hostForUrl, loopbackHost, PORT } = this.deps;
    log.debug("Entering SsfHttp.loopbackOrigin().");
    const scheme = config.value('global.https') ? 'https' : 'http';
    // An address rather than `localhost`, which resolves to ::1 first on some
    // hosts while this service binds 0.0.0.0 — a connection refused on a name
    // that pings, which is among the least obvious failures available.
    //
    // **`helpers.loopbackHost()` AND NOT THE LITERAL `127.0.0.1`
    // (2026-09-12).** The literal reached nothing when `global.host` bound one
    // interface address or IPv6 only, so every push to this service's own two
    // receivers failed with ECONNREFUSED and both inbox pages stayed empty for
    // a reason nothing named. `loopbackHost()` is how this process dials
    // itself — a wildcard bind maps to the loopback address of its own family
    // — and `hostForUrl()` brackets an IPv6 literal, which a URL needs and a
    // bind does not.
    const out = scheme + '://' + hostForUrl(loopbackHost()) + ':' + PORT;
    log.debug("Leaving SsfHttp.loopbackOrigin(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // THIS SERVICE'S OWN BASE URL WHEN THERE IS NO REQUEST TO READ ONE FROM
  // (2026-09-12).
  //
  // Two things here name an issuer with no request behind them — a stream
  // seeded at startup, and a CAEP event sent by the expiry sweep's timer —
  // and both used `helpers.baseUrlOf(null)`, which falls back to
  // `http://localhost:<port>`: HTTP whatever `global.https` says, and a host
  // nothing dials. So a seeded stream on an HTTPS service carried an `iss` in
  // the wrong scheme.
  //
  // `global.publicBaseUrl` wins where it is set — it is the operator saying
  // what this service is called, and every other issuer here already takes
  // it. Where it is not, the loopback origin in the scheme this listener
  // really speaks. The realm's prefix goes on the end ONCE, which is
  // `baseUrlOf()`'s own contract.
  // -------------------------------------------------------------------------
  /**
   * Returns this service's base URL when there is no request to read one from:
   * `global.publicBaseUrl` where set, else the loopback origin, with the
   * ambient realm's prefix.
   *
   * @returns the base URL
   */
  ownBaseUrl(): string {
    const { log, pinnedBaseUrl, realms } = this.deps;
    log.debug("Entering SsfHttp.ownBaseUrl().");
    const pinned = pinnedBaseUrl();
    const out = (pinned || this.loopbackOrigin()) + realms.currentPrefix();
    log.debug("Leaving SsfHttp.ownBaseUrl(). " + out);
    return out;
  }

  // The `iss` of this transmitter in the ambient realm. `ssf.ts`'s
  // `issuerFor()` argues the three rules; it is here, beside `ownBaseUrl()`,
  // because both `ssf.ts` and `ssf_receivers.ts` need it and the second
  // cannot require the first. A value the REALM carries is used as it stands;
  // a process-wide value gets the realm's prefix; an empty one is the base
  // URL, which carries the prefix already.
  /**
   * Returns this transmitter's `iss` in the ambient realm: a realm's own
   * `ssf.issuer` as it stands, a process-wide one with the realm's prefix, and
   * otherwise the base URL.
   *
   * @param req - the request, when there is one
   * @returns the issuer
   */
  transmitterIssuer(req?: any): string {
    const { log, config, realms, baseUrlOf } = this.deps;
    log.debug("Entering SsfHttp.transmitterIssuer().");
    const configured = String(config.value('ssf.issuer') || '').trim();
    let value;
    if (configured) {
      const realm = realms.current();
      const ownValue = !!(realm && realm.overrides &&
        Object.prototype.hasOwnProperty.call(realm.overrides, 'ssf.issuer'));
      value = ownValue ? configured
                       : configured.replace(/\/+$/, '') +
                         realms.currentPrefix();
    } else {
      value = req ? baseUrlOf(req) : this.ownBaseUrl();
    }
    log.debug("Leaving SsfHttp.transmitterIssuer(). " + value);
    return value;
  }

  /**
   * Says whether a URL's origin is this process's own loopback origin, by
   * comparing origins, never substrings.
   *
   * @param raw - the URL
   * @returns true when it is this process
   */
  isOwnLoopback(raw: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering SsfHttp.isOwnLoopback().");
    let parsed = null;
    try {
      parsed = new URL(String(raw || '').trim());
    } catch (e) {
      log.debug("Caught in SsfHttp.isOwnLoopback(): " +
                ((e && e.message) || e));
      // Not a URL at all. `urlProblem()` says so properly a few lines down;
      // here the only question is whether it is OURS, and an unparseable
      // string is not.
      log.debug("Leaving SsfHttp.isOwnLoopback(). It will not parse.");
      return false;
    }
    const mine = parsed.origin === this.loopbackOrigin();
    log.debug("Leaving SsfHttp.isOwnLoopback(). " + mine);
    return mine;
  }

  // -------------------------------------------------------------------------
  // WHETHER THIS URL MAY BE DIALLED, as a sentence rather than a boolean.
  //
  // Every refusal ends up on the stream's own log and on `/admin/ssf`, so
  // each one names what is wrong and which setting decides it — "refused"
  // would send somebody to read this file.
  //
  // It is exported and is called at STREAM CREATION as well as at push time,
  // which is the half that matters to a receiver: a stream whose endpoint can
  // never be dialled is refused when it is created rather than accepted and
  // then silently delivering nothing.
  // -------------------------------------------------------------------------
  /**
   * Says why a delivery endpoint may not be dialled, as a sentence naming the
   * setting that decides it; called at stream creation and at push time.
   *
   * @param raw - the endpoint URL
   * @returns the problem; empty when it may be dialled
   */
  urlProblem(raw: unknown): string {
    const { log } = this.deps;
    log.debug("Entering SsfHttp.urlProblem().");
    log.debug("Leaving SsfHttp.urlProblem().");
    return this.urlVerdict(raw).why;
  }

  // The same answer, with `STS-SSF-0108` when the refusal is plain http in
  // product mode and '' for every other, whose code is the caller's
  // (`STS-SSF-0012` at stream creation, `STS-SSF-0034` at push time).
  /**
   * Says why a delivery endpoint may not be dialled, with `STS-SSF-0108` when
   * the refusal is plain http in product mode.
   *
   * @param raw - the endpoint URL
   * @returns `{ why, errorCode }`; `why` is empty when it may be dialled, and
   * `errorCode` is empty for a refusal whose code is the caller's
   */
  urlVerdict(raw: unknown): { why: string; errorCode: string } {
    const { log } = this.deps;
    log.debug("Entering SsfHttp.urlVerdict().");
    const text = String(raw || '').trim();
    if (!text) {
      log.debug("Leaving SsfHttp.urlVerdict(). Empty.");
      return { why: 'there is no delivery.endpoint_url on the stream',
               errorCode: '' };
    }
    let parsed = null;
    try {
      parsed = new URL(text);
    } catch (e) {
      log.debug("Caught in SsfHttp.urlVerdict(): " + ((e && e.message) || e));
      log.debug("Leaving SsfHttp.urlVerdict(). It will not parse.");
      return { why: '"' + text + '" is not a URL (' + e.message + ')',
               errorCode: '' };
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      log.debug("Leaving SsfHttp.urlVerdict(). Wrong scheme.");
      return { why: 'its scheme is "' + parsed.protocol.replace(':', '') +
                    '", and a push endpoint is https (or http, with ' +
                    'ssf.pushAllowHttp on, in development mode)',
               errorCode: '' };
    }
    const ours = this.isOwnLoopback(text);
    if (parsed.protocol === 'http:' && !ours) {
      const verdict = OutboundTls.httpVerdict(PUSH_TRANSPORT,
                                              parsed.hostname);
      if (!verdict.ok) {
        log.debug("Leaving SsfHttp.urlVerdict(). http, refused.");
        return { why: verdict.why + '. A Security Event Token is ' +
                      'somebody\'s security posture in transit, and the ' +
                      'receiver\'s own authorization_header travels beside ' +
                      'it',
                 errorCode: verdict.errorCode };
      }
    }
    const hosts = this.allowedHosts();
    if (hosts.length && !ours &&
        hosts.indexOf(parsed.hostname.toLowerCase()) < 0) {
      log.debug("Leaving SsfHttp.urlVerdict(). Not on the allowlist.");
      return { why: 'its host "' + parsed.hostname + '" is not in ' +
               'ssf.pushAllowedHosts (' + hosts.join(', ') + '). That list ' +
               'is empty by default, meaning any host; this deployment has ' +
               'set it',
               errorCode: '' };
    }
    log.debug("Leaving SsfHttp.urlVerdict(). Fine.");
    return { why: '', errorCode: '' };
  }

  // -------------------------------------------------------------------------
  // PUSH ONE SET.
  //
  //   url      the stream's delivery.endpoint_url
  //   token    the signed SET, as a compact JWS
  //   options  { authorizationHeader }
  //
  // Returns a promise of `{ ok, status, err, description, why }` and NEVER
  // rejects, for the reason `federation_http.ts` gives about its own: a
  // rejected promise here would have to be caught at every call site, and the
  // one added later would not be.
  //
  // **THE THREE OUTCOMES ARE NOT TWO.** RFC 8935 section 2.3 makes a 202 the
  // success and section 2.4 makes a 400 with `err`/`description` a REFUSAL BY
  // THE RECEIVER — which is a completely different thing from a network
  // failure, and the most interesting thing a receiver ever says. `ok` is
  // false for both, and `err` is set only for the second, so the stream's log
  // can tell "nothing answered" from "the receiver said invalid_audience".
  // -------------------------------------------------------------------------
  /**
   * Pushes one SET to a receiver's endpoint.
   *
   * A 202 is success; a 400 with `err`/`description` is the receiver refusing;
   * anything else is a failure to deliver. The promise never rejects.
   *
   * @param url - the stream's `delivery.endpoint_url`
   * @param token - the signed SET, as a compact JWS
   * @param options - `authorizationHeader`, sent as the `Authorization`
   * header
   * @returns a promise of `{ ok, status, err, description, why, errorCode,
   * retryable }`
   */
  pushSet(url: unknown, token: unknown,
          options?: PushOptions | null): Promise<PushResult> {
    const { log, loadTlsServer, userAgent } = this.deps;
    log.debug("Entering SsfHttp.pushSet().");
    const opts = options || {};
    if (!this.pushAllowed()) {
      log.debug("Leaving SsfHttp.pushSet(). ssf.pushDelivery is off.");
      return Promise.resolve({ ok: false, status: 0, err: '', description: '',
        errorCode: 'STS-SSF-0033',
        why: 'ssf.pushDelivery is off, so this service makes no outbound ' +
             'request at all. Poll delivery (urn:ietf:rfc:8936) needs none — ' +
             'the receiver comes here.' });
    }
    const problem = this.urlVerdict(url);
    if (problem.why) {
      log.debug("Leaving SsfHttp.pushSet(). " + problem.why);
      return Promise.resolve({ ok: false, status: 0, err: '', description: '',
        errorCode: problem.errorCode || 'STS-SSF-0034',
        why: 'the delivery endpoint cannot be dialled: ' + problem.why });
    }
    const target = new URL(String(url).trim());
    const secure = target.protocol === 'https:';
    const ours = this.isOwnLoopback(url);
    // -----------------------------------------------------------------------
    // THE PIN, FOR THIS SERVICE'S OWN RECEIVERS ONLY (2026-09-10).
    //
    // The certificate on the main port is issued by this service's own Root
    // (or, with no Root, generated per start and self-signed) — nobody a
    // public truststore knows — so the ordinary check below would refuse
    // every push to the console's and the portal's receive endpoints — and
    // `ssf.pushSkipTlsVerification` is NOT the way round it, because that
    // setting turns the check off for every receiver in the world to fix a
    // connection to ourselves (and is not honoured in product at all).
    //
    // So: our own trust anchor — the Root while there is one, the self-signed
    // certificate while there is not (`trustAnchorPems()` in
    // `tls/tls_server.js`) — and the hostname check skipped, because the
    // certificate names this service and the connection names the loopback
    // interface. Pinning the anchor is the stronger half of the two.
    // `common/oidc_rp.ts`'s back channel does exactly this and these are the
    // same three lines.
    //
    // **THE REQUIRE IS LAZY AND HAS TO BE.** `tls/tls_server.js` registers the
    // /tls routes (rule 1), and this file is required by `ssf.ts` at 23b —
    // but also, through `ssf_receivers.ts`, by `admin-ui/admin.ts` at 18 and
    // `portal/portal.ts` just after `authn` (8), either of which would drag
    // /tls ahead of the management API's own routes. Here every module is
    // loaded and it is a cache hit.
    // -----------------------------------------------------------------------
    let anchor = null;
    let ownLeaf = '';
    if (ours && secure) {
      try {
        // THE ANCHOR AND NOT THE CERTIFICATE — see common/oidc_rp.ts's
        // back channel, which pinned the leaf and stopped being able to reach
        // this service at all the hour that leaf acquired an issuer.
        const own = loadTlsServer().serverCertificate();
        anchor = own.trustAnchorPem;
        ownLeaf = String(own.fingerprint256 || '');
      } catch (e) {
        // Reported as a push failure rather than thrown, like every other
        // outcome here: the stream's log is where a receiver's operator finds
        // out, and a throw would have to be caught at every call site.
        log.debug("Caught in SsfHttp.pushSet(): " + ((e && e.message) || e));
        log.debug("Leaving SsfHttp.pushSet(). No server certificate: " +
                  e.message);
        return Promise.resolve({ ok: false, status: 0, err: '',
          description: '',
          errorCode: 'STS-SSF-0035',
          why: 'this is one of this service\'s own receivers, on the ' +
               'loopback address, and its TLS certificate could not be read ' +
               'to verify the connection against: ' + e.message });
      }
    }
    if (!secure && ours) {
      // NOT the warning below. That one is about a Security Event Token
      // travelling in clear across a network; this request does not leave the
      // host. Said at debug so that a reader chasing a push can still see
      // which branch it took.
      log.debug('pushSet(): ' + target.origin + ' is this process, so ' +
                'plain http is not a transit exposure. See ' +
                'isOwnLoopback().');
    }
    if (!secure && !ours) {
      // Every insecure request, not just the setting. See federation_http.ts's
      // header, point 2 — a check disabled six months ago and forgotten is the
      // worst kind of leftover.
      log.warn('ssf: pushing a Security Event Token to ' + target.origin +
               ' over plain http because ssf.pushAllowHttp is ON. The ' +
               'event and the receiver\'s authorization_header both travel ' +
               'in clear.');
    }
    // THE CERTIFICATE POLICY FOR ANY OTHER RECEIVER (#171): verified against
    // node's store and `ssf.pushCaFile`, and skipped only where development
    // mode and `ssf.pushSkipTlsVerification` both say so. Not asked for one
    // of our own receivers: the pin above is what that connection checks.
    // Nor for one of our own with NO anchor (#311): a SUPPLIED, publicly
    // issued certificate (testidp's ACM leaf) has none, and the ordinary
    // policy then checked its name against 127.0.0.1, which it never
    // carries — every push to this service's own two receivers failed and
    // both streams were declared dead. Such a push is verified below against
    // the system's store AND held to this process's own leaf.
    const policy = secure && !anchor && !ours
      ? OutboundTls.tlsVerdict(PUSH_TRANSPORT, target.origin) : null;
    if (policy && !policy.ok) {
      log.debug("Leaving SsfHttp.pushSet(). " + policy.why);
      // error-code: none — the policy answers its own, STS-CORE-0104
      return Promise.resolve({ ok: false, status: 0, err: '', description: '',
        errorCode: policy.errorCode,
        why: 'the delivery endpoint cannot be dialled: ' + policy.why });
    }
    const body = Buffer.from(String(token), 'utf8');
    const headers: Record<string, string | number> = {
      'Content-Type': SET_MEDIA_TYPE,
      'Content-Length': body.length,
      'Accept': 'application/json',
      'User-Agent': userAgent
    };
    if (opts.authorizationHeader) {
      headers.Authorization = String(opts.authorizationHeader);
    }

    // Read once per push, so a runtime change cannot move the bound half way
    // through one response.
    const limit = this.maxBodyBytes();
    const timeoutMs = this.timeoutMs.bind(this);
    log.debug("Leaving SsfHttp.pushSet(). Dialling " + target.origin + '.');
    return new Promise(function (resolve) {
      const done = function (result: PushResult): void {
        log.debug("Entering done().");
        log.debug('pushSet() finished. ok=' + result.ok + ', status=' +
                  result.status);
        resolve(Object.assign({ url: String(url) }, result));
        log.debug("Leaving done().");
      };
      let request = null;
      const requestOptions: https.RequestOptions = {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (secure ? 443 : 80),
        path: target.pathname + target.search,
        method: 'POST',
        headers: headers,
        // The ordinary certificate check, and it is deliberately NOT this
        // service's usual "verify nothing" posture: what is being protected
        // is the receiver's authorization_header and the fact that somebody's
        // session was revoked. `policy` above is what decides it; only
        // development mode with `ssf.pushSkipTlsVerification` turns it off,
        // and that is warned about on every request.
        //
        // For one of this service's own receivers it stays ON and the anchor
        // above is what it checks against — a PIN rather than a relaxation,
        // which is the whole difference between this and setting that
        // setting.
        rejectUnauthorized: secure &&
          (!!anchor || !policy || policy.rejectUnauthorized),
        ca: anchor ? [anchor] : (policy && policy.ca ? policy.ca : undefined)
      };
      // **ADDED ONLY WHEN THERE IS A PIN, AND NEVER AS `undefined`**
      // (2026-09-15). Node validates this option by PRESENCE: an explicit
      // `checkServerIdentity: undefined` throws `The "options.
      // checkServerIdentity" property must be of type function` synchronously
      // out of `https.request()`, so from f76594d until this change every
      // push to a receiver that is NOT one of this service's own — which is
      // every push anybody configures — failed before it dialled,
      // dead-lettered as STS-SSF-0041 "the request could not be built", and
      // logged nothing a receiver's operator would connect with a certificate
      // option. `ca: undefined` above is harmless by contrast: that option is
      // read by value.
      if (anchor) {
        requestOptions.checkServerIdentity = function () {
          return undefined;
        };
      } else if (ours && secure) {
        // THIS PROCESS, WITH A SUPPLIED CERTIFICATE (#311): the chain is
        // verified against the system's store (rejectUnauthorized, above,
        // with no `ca`), and in place of a name the loopback address cannot
        // match, the peer must present EXACTLY the leaf this process serves
        // — stronger than a name, and the same leaf the front process handed
        // a request worker.
        requestOptions.rejectUnauthorized = true;
        requestOptions.checkServerIdentity = function (host: string,
            cert: { fingerprint256?: string }) {
          const norm = function (f: string): string {
            return String(f || '').replace(/:/g, '').toLowerCase();
          };
          return ownLeaf && norm(cert && cert.fingerprint256) === norm(ownLeaf)
            ? undefined
            : new Error('the loopback peer did not present this ' +
                        'process\'s own certificate');
        };
      } else if (policy && policy.checkServerIdentity) {
        // The host check, and the verified chain held to the path rules
        // (#201, `OutboundTls.checkServerIdentity()`).
        requestOptions.checkServerIdentity = policy.checkServerIdentity;
      }
      try {
        request = (secure ? https : http).request(requestOptions,
                                                  function (response) {
          const status = response.statusCode || 0;
          const location = response.headers.location;
          if (status >= 300 && status < 400 && location) {
            response.destroy();
            return done({ ok: false, status: status, err: '',
              description: '',
              errorCode: 'STS-SSF-0036',
              why: 'it answered ' + status + ' redirecting to "' + location +
                   '", and this service does not follow a redirect on a ' +
                   'push. The event and the receiver\'s ' +
                   'authorization_header would go wherever that pointed.' });
          }
          let text = '';
          let bytes = 0;
          let overflowed = false;
          response.setEncoding('utf8');
          response.on('data', function (chunk) {
            if (overflowed) {
              return;
            }
            bytes += Buffer.byteLength(chunk);
            if (bytes > limit) {
              overflowed = true;
              response.destroy();
              return;
            }
            text += chunk;
          });
          response.on('end', function () {
            if (overflowed) {
              return done({ ok: false, status: status, err: '',
                description: '', errorCode: 'STS-SSF-0037',
                why: 'it answered with more than ' + limit +
                     ' bytes (ssf.pushMaxResponseBytes). RFC 8935 makes a ' +
                     'success an EMPTY 202 and a failure a small JSON ' +
                     'object, so this is not a push endpoint answering.' });
            }
            if (status === 202 || status === 200 || status === 204) {
              // 202 is what RFC 8935 section 2.3 specifies. 200 and 204 are
              // accepted as well and NOT silently: a receiver answering one of
              // those is very slightly wrong, the event did arrive, and a mock
              // that refused would be testing the transmitter's pedantry
              // rather than the receiver's behaviour. The note says which it
              // was.
              return done({ ok: true, status: status, err: '',
                description: '',
                why: status === 202 ? '' : 'it answered ' + status +
                     ' rather than the 202 RFC 8935 section 2.3 specifies. ' +
                     'The event was accepted; a stricter transmitter might ' +
                     'not have treated it as delivered.' });
            }
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (e) {
              log.debug("Caught in a callback in pushSet(): " +
                        ((e && e.message) || e));
              // Not JSON. A proxy in front of the receiver serving an HTML
              // error page is the ordinary case, and the TEXT is then the
              // diagnosis — so it is carried rather than discarded.
              json = null;
            }
            if (status === 400 && json && json.err) {
              return done({ ok: false, status: status, err: String(json.err),
                description: String(json.description || ''),
                errorCode: 'STS-SSF-0038',
                why: 'the receiver REFUSED the event: ' + String(json.err) +
                     ' — ' +
                     String(json.description || '(no description)') });
            }
            return done({ ok: false, status: status, err: '',
              description: '',
              errorCode: 'STS-SSF-0039',
              // A 5xx or a 429 is the receiver not coping rather than
              // refusing, which is the one kind of answer `ssf.pushRetries`
              // may try again.
              retryable: status >= 500 || status === 429,
              why: 'it answered ' + status + (text
                ? ': ' + text.slice(0, 200) : ' with no body') });
          });
          response.on('error', function (e) {
            log.debug("Caught in a callback in pushSet(): " +
                      ((e && e.message) || e));
            done({ ok: false, status: status, err: '', description: '',
              errorCode: 'STS-SSF-0040',
              why: 'the response failed: ' + e.message });
          });
        });
      } catch (e) {
        log.debug("Caught in a callback in pushSet(): " +
                  ((e && e.message) || e));
        // A malformed option rather than a network failure — new URL() has
        // already succeeded by here, so this is a bug in the caller.
        return done({ ok: false, status: 0, err: '', description: '',
          errorCode: 'STS-SSF-0041',
          why: 'the request could not be built: ' + e.message });
      }
      request.setTimeout(timeoutMs(), function () {
        request.destroy();
        done({ ok: false, status: 0, err: '', description: '',
          retryable: true,
          errorCode: 'STS-SSF-0042',
          why: 'it did not answer within ' + timeoutMs() +
               'ms (ssf.pushTimeoutMs)' });
      });
      request.on('error', function (e) {
        log.debug("Caught in a callback in pushSet(): " +
                  ((e && e.message) || e));
        // The one that actually happens: DNS, connection refused, a
        // certificate nothing trusts. `e.code` is the useful half and is
        // named, because "self-signed certificate" and "connection refused"
        // send somebody to two completely different places.
        const selfSigned = e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
          e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
          e.code === 'SELF_SIGNED_CERT_IN_CHAIN';
        done({ ok: false, status: 0, err: '', description: '',
          errorCode: selfSigned ? 'STS-SSF-0044' : 'STS-SSF-0043',
          // A connection that failed may succeed; a certificate nothing
          // trusts will not, and retrying it is only delay.
          retryable: !selfSigned,
          why: 'the request failed: ' + (e.code ? e.code + ' — ' : '') +
               e.message + (selfSigned
            ? '. Name the receiver\'s CA in ssf.pushCaFile to push to a ' +
              'receiver whose certificate nothing here trusts.' : '') });
      });
      request.write(body);
      request.end();
    });
  }

  // -------------------------------------------------------------------------
  // THE PUSH CAP (2026-09-14): at most `ssf.pushConcurrency` pushes in flight
  // in this process, the rest waiting in order, at most `ssf.pushBacklog` of
  // them.
  //
  // **FAIR BETWEEN RECEIVERS (2026-09-27).** It was one queue in arrival
  // order, so a flood toward one receiver held up every other: a SCIM bulk
  // load in one lane of the suite put ten thousand RISC pushes to this
  // service's own receivers ahead of the OpenID conformance suite's
  // solicited verification event, which never arrived in time. Waiting pushes
  // are queued per destination and a freed slot goes to the destinations in
  // turn, and `ssf.pushBacklog` bounds each destination's queue, so a flood
  // can neither delay nor crowd out another receiver's pushes. With one
  // destination it is the queue it was.
  //
  // `emitProtocolEvent()` fans one event out to every stream that takes it
  // with `Promise.all()`, and a directory write is two events — so a SCIM
  // bulk load against forty-two push streams asked for eighty-four pushes per
  // person, all at once. Most were to this service's OWN receivers, which is
  // a request back into the worker pool, so the burst was load on the service
  // itself and it stopped answering. The cap makes that fan-out a queue.
  //
  // **A PUSH THAT CANNOT WAIT IS NOT MADE**, and says so with a code: the SET
  // is dead-lettered by `transmit()`, which is where the bound on memory comes
  // from. **A RETRY WAITS FOR A SLOT OF ITS OWN**, and gives its slot back
  // during the delay, so a receiver being retried does not hold a slot it is
  // not using. **THE CAP IS PER PROCESS**: the four processes of a dispatched
  // service have four, which is the arithmetic a per-process setting states
  // rather than hides.
  // -------------------------------------------------------------------------
  private pushConcurrency(): number {
    const { log, config } = this.deps;
    log.debug("Entering SsfHttp.pushConcurrency().");
    const raw = Number(config.value('ssf.pushConcurrency'));
    log.debug("Leaving SsfHttp.pushConcurrency().");
    return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 0;
  }

  private pushBacklog(): number {
    const { log, config } = this.deps;
    log.debug("Entering SsfHttp.pushBacklog().");
    const raw = Number(config.value('ssf.pushBacklog'));
    log.debug("Leaving SsfHttp.pushBacklog().");
    return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 2000;
  }

  // Resolves with a release function once a slot is free, or with null when
  // this destination's backlog is full.
  private acquirePushSlot(destination?: unknown): Promise<(() => void) |
                                                          null> {
    const { log } = this.deps;
    log.debug("Entering SsfHttp.acquirePushSlot().");
    const cap = this.pushConcurrency();
    const key = String(destination || '');
    const release = (): void => {
      log.debug("Entering release().");
      pushesActive = Math.max(0, pushesActive - 1);
      while (pushesWaitingCount && (!this.pushConcurrency() ||
             pushesActive < this.pushConcurrency())) {
        // The destination whose turn it is: the first in the Map, moved to
        // the end once served, or dropped when its queue is empty.
        const turn = pushesWaiting.keys().next().value;
        const queue = pushesWaiting.get(turn);
        const next = queue.shift();
        pushesWaiting.delete(turn);
        if (queue.length) {
          pushesWaiting.set(turn, queue);
        }
        pushesWaitingCount -= 1;
        pushesActive += 1;
        next(release);
      }
      log.debug("Leaving release().");
    };
    if (!cap || pushesActive < cap) {
      pushesActive += 1;
      log.debug("Leaving SsfHttp.acquirePushSlot(). A slot at once.");
      return Promise.resolve(release);
    }
    const queue = pushesWaiting.get(key) || [];
    if (queue.length >= this.pushBacklog()) {
      log.debug("Leaving SsfHttp.acquirePushSlot(). The backlog is full.");
      return Promise.resolve(null);
    }
    log.debug("Leaving SsfHttp.acquirePushSlot(). Waiting behind " +
              queue.length + " for this destination, " + pushesWaitingCount +
              " in all.");
    return new Promise(function (resolve) {
      queue.push(resolve);
      if (!pushesWaiting.has(key)) {
        pushesWaiting.set(key, queue);
      }
      pushesWaitingCount += 1;
    });
  }

  // One push, inside a slot. What every push this module makes goes through.
  /**
   * Pushes one SET inside a slot of the per-process cap
   * (`ssf.pushConcurrency`), or fails at once with `STS-SSF-0092` when
   * `ssf.pushBacklog` pushes to that receiver are already waiting.
   *
   * @param url - the endpoint
   * @param token - the signed SET
   * @param options - as `pushSet()` takes them
   * @returns a promise of the push's result
   */
  pushSetGated(url: unknown, token: unknown,
               options?: PushOptions | null): Promise<PushResult> {
    const { log } = this.deps;
    log.debug("Entering SsfHttp.pushSetGated().");
    log.debug("Leaving SsfHttp.pushSetGated().");
    return this.acquirePushSlot(url).then((release) => {
      if (!release) {
        const queued = (pushesWaiting.get(String(url || '')) || []).length;
        return { ok: false, status: 0, err: '', description: '',
          retryable: false, errorCode: 'STS-SSF-0092',
          why: 'the push was not made: ' + queued + ' pushes to this ' +
               'receiver were already waiting for one of ' +
               this.pushConcurrency() + ' slots (ssf.pushConcurrency, ' +
               'ssf.pushBacklog)' };
      }
      return this.pushSet(url, token, options).then(function (result) {
        release();
        return result;
      }, function (e) {
        log.debug("Caught in SsfHttp.pushSetGated(): " +
                  ((e && e.message) || e));
        release();
        throw e;
      });
    });
  }

  // For a report: how busy the cap is in this process right now.
  /**
   * Reports how busy this process's push cap is.
   *
   * @returns `{ active, waiting, concurrency, backlog }`
   */
  pushGateState(): { active: number; waiting: number; concurrency: number;
                     backlog: number } {
    const { log } = this.deps;
    log.debug("Entering SsfHttp.pushGateState().");
    log.debug("Leaving SsfHttp.pushGateState().");
    return { active: pushesActive, waiting: pushesWaitingCount,
             concurrency: this.pushConcurrency(),
             backlog: this.pushBacklog() };
  }

  // -------------------------------------------------------------------------
  // PUSH ONE SET, TRYING AGAIN WHERE `ssf.pushRetries` SAYS TO (2026-09-12).
  //
  // `ssf/CLAUDE.md` argues why this service does not retry, and **the default
  // is still 0, which is exactly that**: a mock that retried would make a
  // receiver's one-shot failure invisible. A deployment is the other case — a
  // receiver that restarts for thirty seconds should not lose every event sent
  // in them — so the count is a setting rather than a rewrite of the
  // argument.
  //
  // ONLY A FAILURE THAT COULD GO DIFFERENTLY IS RETRIED: no connection, a
  // timeout, a 5xx or a 429. A 400 with `{err, description}` is the receiver
  // REFUSING — it read the SET and will read it the same way next time, and
  // RFC 8935 section 2.4 makes that a final answer. Nor is a push this service
  // refused to make (delivery off, a URL it may not dial) retried: nothing
  // about it changes with time. The delay is linear — `ssf.pushRetryDelayMs`
  // times the attempt number — and every attempt's result is returned in
  // `attempts`, so the stream's log says how many were made rather than only
  // how the last one went.
  // -------------------------------------------------------------------------
  /**
   * Pushes one SET, retrying a failure that could go differently (no
   * connection, a timeout, a 5xx or a 429) up to `ssf.pushRetries` times with a
   * linear delay of `ssf.pushRetryDelayMs`.
   *
   * @param url - the endpoint
   * @param token - the signed SET
   * @param options - as `pushSet()` takes them
   * @returns a promise of the last result, with every attempt in `attempts`
   */
  pushSetWithRetries(url: unknown, token: unknown,
                     options?: PushOptions | null): Promise<PushResult> {
    const { log, config } = this.deps;
    log.debug("Entering SsfHttp.pushSetWithRetries().");
    const retries = config.value('ssf.pushRetries');
    const delay = config.value('ssf.pushRetryDelayMs');
    const attempts = [];
    const attempt = (n: number): Promise<PushResult> => {
      log.debug("Entering attempt().");
      log.debug("Leaving attempt().");
      return this.pushSetGated(url, token, options).then(function (result) {
        attempts.push({ status: result.status, why: result.why });
        if (result.ok || !result.retryable || n >= retries) {
          log.debug('pushSetWithRetries() finished after ' + (n + 1) +
                    ' attempt(s). ok=' + result.ok);
          return Object.assign({}, result, { attempts: attempts });
        }
        log.info('ssf: a push to ' + url + ' failed (' + result.why + '); ' +
                 'trying again in ' + (delay * (n + 1)) + 'ms, attempt ' +
                 (n + 2) + ' of ' + (retries + 1) + ' (ssf.pushRetries).');
        return new Promise(function (resolve) {
          const timer = setTimeout(resolve, delay * (n + 1));
          // A retry must not keep a process that is shutting down alive.
          if (timer.unref) {
            timer.unref();
          }
        }).then(function () {
          return attempt(n + 1);
        });
      });
    };
    log.debug("Leaving SsfHttp.pushSetWithRetries(). " + retries +
              ' retr(ies) allowed.');
    return attempt(0);
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  /**
   * Returns the real modules and functions this transport depends on, as the
   * composition root passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): SsfHttpDeps {
    helpers.log.debug("Entering SsfHttp.defaultDeps().");
    helpers.log.debug("Leaving SsfHttp.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      PORT: helpers.PORT,
      loopbackHost: helpers.loopbackHost,
      hostForUrl: helpers.hostForUrl,
      pinnedBaseUrl: helpers.pinnedBaseUrl,
      baseUrlOf: helpers.baseUrlOf,
      userAgent: USER_AGENT,
      loadTlsServer: function () {
        return require('../tls/tls_server');
      }
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SsfHttp>(
  'ssf/ssf_http',
  () => new SsfHttp(SsfHttp.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Push delivery of Security Event Tokens (RFC 8935): the URL rules, the
 * concurrency cap, retries, and this transmitter's own address and issuer.
 *
 * Exports the `SsfHttp` class, its constants, and facades that forward to the
 * installed instance.
 *
 * @namespace
 */
export = {
  SsfHttp: SsfHttp,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: SsfHttp): void => slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  pushSetWithRetries: slot.forward('pushSetWithRetries'),
  pushSetGated: slot.forward('pushSetGated'),
  pushGateState: slot.forward('pushGateState'),
  loopbackOrigin: slot.forward('loopbackOrigin'),
  ownBaseUrl: slot.forward('ownBaseUrl'),
  transmitterIssuer: slot.forward('transmitterIssuer'),
  maxBodyBytes: slot.forward('maxBodyBytes'),
  isOwnLoopback: slot.forward('isOwnLoopback'),
  MAX_BODY_BYTES: SsfHttp.MAX_BODY_BYTES,
  SET_MEDIA_TYPE: SsfHttp.SET_MEDIA_TYPE,
  pushAllowed: slot.forward('pushAllowed'),
  transportSettings: slot.forward('transportSettings'),
  urlVerdict: slot.forward('urlVerdict'),
  PUSH_TRANSPORT: PUSH_TRANSPORT,
  allowedHosts: slot.forward('allowedHosts'),
  urlProblem: slot.forward('urlProblem'),
  pushSet: slot.forward('pushSet')
};
