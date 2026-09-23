'use strict';
//
// File: federation_http.ts
//
// ===========================================================================
// THE FIRST OUTBOUND REQUEST IN THIS REPOSITORY, AND THE STRONGEST.
//
// Until this file nothing here had ever dialled anything. This service is
// reached; it does not reach. That was not an accident of what got built — it
// is a position taken in two places and argued in both (the requesters added
// since — SSF, the XACML nudge, the embedded debugger's api, the RFC 9728
// import, a registered RFC 9101 `request_uri`, SPIFFE's node attestors'
// configured sources and `http_challenge` (#40) — each argue their own case;
// the root CLAUDE.md's non-goal index lists them):
//
//   * `oauthJwksUri` on an application entry was RECORDED AND NEVER FETCHED
//     until #120 (2026-09-22). It is fetched now, through this module's
//     `fetchPublished()` — the policy above is what answers the SSRF argument
//     that refused it — by `oauth-oidc/client_jwks.js`.
//   * WS-Federation's `wreqptr` gets the refusal in `wsfed.ts`.
//
// THE SECOND STANDS, UNCHANGED, AND THIS FILE DOES NOT CONTRADICT IT. (The
// first fell to a different argument: a `jwks_uri` is REGISTERED once, and
// RFC 7591 expects it honoured, where `wreqptr` arrives on each request.) The
// distinction is not "this feature needs it" — that is the argument every
// SSRF ever shipped was made with. It is:
//
//   **THOSE URLS ARE SUPPLIED BY THE CALLER. THESE ARE SUPPLIED BY THE
//   ADMINISTRATOR.**
//
// `POST /oauth2/register` is unauthenticated and takes any `jwks_uri` anybody
// types; a `wreqptr` rides on a query string from a browser. Following either
// turns this service into a request-forwarder for whoever can reach the port,
// and the URL that gets dialled is chosen by the attacker on the spot. A
// federation relationship is created through the admin console — which is
// gated — or through `/admin-api`, and its `fedTokenUrl` was written down
// deliberately by somebody configuring a partner. Anybody who can set it can
// already do worse things than make this process issue a GET.
//
// So the rule this file enforces, and the reason it exists at all rather than
// being three lines inside `federation_sp.ts`:
//
//   **EVERY URL DIALLED COMES OFF A FEDERATION RELATIONSHIP ENTRY, BY
//   ATTRIBUTE NAME, AND THE ATTRIBUTE NAME IS PASSED IN.** `fetchJson()` will
//   not take a bare URL. It takes the relationship and the name of the
//   attribute holding the URL, looks it up itself, and refuses a name that is
//   not one of the three it is allowed to read. A caller that has a URL from
//   somewhere else cannot use this module, which is the whole point — there is
//   no back door here for the next feature that "just needs to fetch one
//   thing".
//
// If that ever needs to change, it is a SEPARATE argument in a SEPARATE
// function, never a fourth name quietly added to `DIALLABLE`.
//
// **`deliverForm()` IS THAT SEPARATE FUNCTION, FOR THE SECOND KIND OF URL
// (2026-09-17, #36).** OpenID Connect Back-Channel Logout 1.0 has this service
// POST a signed Logout Token to each relying party's registered
// `backchannel_logout_uri`. That address can arrive through
// `POST /oauth2/register`, which is unauthenticated — so it is NOT the
// administrator's kind of URL, and the argument above does not cover it. What
// covers it is the other distinction the root CLAUDE.md's non-goal index
// draws: **a URL somebody asked to be SENT something at is not a URL to fetch
// something FROM.** Nothing this service reads comes back from it — the
// status code is the whole answer, the body is drained and discarded — and
// what goes out is a token saying one of that client's own sessions ended.
// The request-forwarder risk is what is left, and it is bounded the way the
// RFC 9728 import bounds it: in product mode the name is resolved ONCE, every
// address it resolves to is checked against the internal ranges below, and
// the connection is pinned to the address that was checked
// (`mode.dialsInternalAddresses()`). It keeps every other rule here — the kill
// switch, https with the certificate verified (#171), no redirect, the
// body cap, a timeout — and it reads its URL off a record by an attribute
// name from its OWN list, `SENDABLE`, never from `DIALLABLE`.
//
// **AND THE INTERNAL-ADDRESS CHECK MOVED HERE WITH IT.** It was written for
// the RFC 9728 import inside `oauth-oidc/protected_resource_metadata.ts`; a
// second outbound requester needing it made this module — the one that owns
// the outbound policy — the place it lives, and that module now asks this one.
//
// ---------------------------------------------------------------------------
// FIVE MORE THINGS ARE ENFORCED HERE, AND EACH IS A DIFFERENT FAILURE.
//
// 1. **`federation.outbound` TURNS IT ALL OFF.** A deployment with no egress
//    sets it and nothing here dials anything. The refusal names the setting, so
//    somebody watching a federated sign-in fail in an air-gapped test knows
//    within one line why.
//
// 2. **https ONLY, WITH THE PARTNER'S CERTIFICATE VERIFIED.** What travels on
//    these requests is a client secret and an authorization code, at somebody
//    ELSE'S service — this is the one place in this repository where a
//    credential leaves the process, and it is the one place this service is
//    stricter than a mock would ordinarily be (RFC 6749 section 3.2, RFC 9700
//    section 2, BCP 195). Since #171 the policy is `common/outbound_tls.ts`'s,
//    shared with GNAP, SSF and XACML, and it is three settings where there was
//    one: `federation.outboundAllowHttp` admits plain http, in development
//    only; `federation.outboundSkipTlsVerification` turns the certificate
//    check off, in development only — federating against another mock on
//    localhost is the case it exists for; and `federation.outboundCaFile`
//    names a private CA, which is what product uses instead. Every request
//    made insecurely is LOGGED as such rather than only the setting being
//    logged once: a certificate check disabled six months ago and forgotten
//    is the worst kind of leftover. The SAML SP metadata refresh, the RFC 9728
//    import and every other requester that borrows this policy ask
//    `tlsFor()` here rather than reading a setting of their own.
//
// 3. **NO REDIRECTS ARE FOLLOWED.** A 302 from a token endpoint is not a
//    protocol this service speaks, and following one would hand the credential
//    in the Authorization header to whatever the Location said — which is the
//    SSRF this whole file is arranged to avoid, arriving through the front
//    door instead of the back. A redirect is a failure and says so.
//
// 4. **THE BODY IS CAPPED AND THE REQUEST IS TIMED OUT.** A partner that
//    answers slowly is a browser hanging on a blank tab, and a partner that
//    answers forever is this process's memory. Both are bounded, and the
//    error names which bound was hit.
//
// 5. **NOTHING THAT ARRIVES IS TRUSTED.** This module returns parsed JSON and
//    a status code and makes no judgement at all. Whether the token is any
//    good, whether the issuer is the configured one, whether the signature
//    verifies — all of that is `federation_sp.ts`'s, where the relationship's
//    keys are. A fetcher that also validated would be the place both halves of
//    a check ended up half-written.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers nothing and requires `helpers.js`,
// `config.js`, `mode.js`, `error_codes.js` and `version.js` — plus node's own
// `https`, `http`, `url`, `dns` and `net` — so it cannot join a cycle.
// `federation.js` is NOT required from here, deliberately: this module is
// handed a relationship record and reads two attributes off it, which keeps
// the dependency pointing one way and lets a test drive this file with a
// plain object.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `FederationHttp` takes the logger, `config`, the error-code table,
// node's `http` and `https` and the User-Agent string through its
// constructor, and the module still exports `DIALLABLE`, `fetchJson()` and
// the four readers — since #50's R2 as FACADES forwarding to the instance the
// composition root builds — for the unconverted modules that require it
// (`federation_sp.ts`, `saml/sp_metadata.ts`,
// `oauth-oidc/protected_resource_metadata.ts`). A process without the root
// builds a default at load.
// ---------------------------------------------------------------------------

import https = require('https');
import http = require('http');
import url = require('url');
import dns = require('dns');
import net = require('net');
import config = require('./../common/config');
// Whether an internal address may be dialled: development yes, product no.
// A LEAF that requires only `config`.
import mode = require('./../common/mode');
import helpers = require('./../common/helpers');
import InstanceSlot = require('./../common/instance_slot');
// THE ERROR CODES. Every way a request fails carries its code as `errorCode` on
// the result, and `federation_sp.ts` marks the refusal page's response with it
// — the result object itself is never sent to anybody. A leaf, so no cycle.
import errorCodes = require('./../common/error_codes');
import version = require('./../common/version');
import OutboundTls = require('./../common/outbound_tls');

const { URL } = url;

// WHO IS CALLING, AND WHICH BUILD OF IT. This is the STRONGEST of this
// repository's outbound requesters, and the one whose requests carry a client
// secret and an authorization code — so the partner's access log is where an
// integration problem gets diagnosed, and a User-Agent naming a version is what
// makes that log worth reading. RFC 9110 product form; see common/version.js,
// which owns the one copy of the product token.
//
// Built once at require time rather than per request: the version cannot
// change while the process runs, and computing it per call would read a file
// on every federated sign-in.
const USER_AGENT = version.userAgent('federation');

// THE THREE ATTRIBUTES THAT MAY HOLD A URL THIS SERVICE WILL DIAL. See the
// header — this list is the mechanism, not a convenience. A fourth name here is
// a new argument, not a new line.
const DIALLABLE = ['fedTokenUrl', 'fedUserinfoUrl', 'fedJwksUri'];

// THE ATTRIBUTES `deliverForm()` MAY SEND TO (2026-09-17, #36), and they are a
// list of their own for the header's reason: an address something is SENT to
// is a different argument from one something is fetched from, and neither
// list may borrow the other's names.
const SENDABLE = ['oauthBackchannelLogoutUri'];

// ---------------------------------------------------------------------------
// WHICH ADDRESSES ARE INTERNAL. Moved from
// `oauth-oidc/protected_resource_metadata.ts` on 2026-09-17, unchanged.
//
// Loopback, the RFC 1918 and RFC 6598 private ranges, link-local (the cloud
// instance-metadata address among them), unique-local IPv6, "this network",
// multicast and the reserved blocks — every range whose address a request from
// inside this process's network would reach something that network did not
// mean to publish. The documentation ranges are included because nothing
// legitimate lives there. A NAT64 prefix is included because it embeds an IPv4
// address that may be any of the above.
// ---------------------------------------------------------------------------
const INTERNAL = (function () {
  const list = new net.BlockList();
  [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
   ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24],
   ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
   ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4],
   ['240.0.0.0', 4]].forEach(function (row) {
    list.addSubnet(row[0] as string, row[1] as number, 'ipv4');
  });
  [['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64],
   ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10],
   ['ff00::', 8]].forEach(function (row) {
    list.addSubnet(row[0] as string, row[1] as number, 'ipv6');
  });
  return list;
})();

// What `vetHost()` answers: an address to pin the connection to (empty in
// development, where nothing is pinned), or the reason it may not be dialled.
// `kind` is `internal` or `unresolved` on a refusal, so each caller can name
// the refusal with a code of its own.
interface VettedHost {
  ok: boolean;
  address: string;
  family: number;
  kind?: string;
  why?: string;
}

// What `deliverForm()` answers. It never rejects. `kind` names the failure
// for a caller that codes it in its own vocabulary: `outbound-off`, `url`,
// `internal`, `unresolved`, `redirect`, `status`, `timeout`, `network`,
// `build`, `attribute` — or '' on success.
interface DeliveryResult {
  ok: boolean;
  status: number;
  kind: string;
  why: string;
  url: string;
  cacheControl: string;
}

// What `fetchJson()` answers. It never rejects.
interface FetchResult {
  ok: boolean;
  status: number;
  json: any;
  text: string;
  url: string;
  errorCode: string;
  why: string;
}

interface FetchOptions {
  method?: string;
  form?: Record<string, string> | URLSearchParams | string;
  bearer?: string;
  basic?: { user: unknown; pass: unknown };
  headers?: Record<string, any>;
}

interface FederationHttpDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  errorCodes: { tag(code: string): string };
  http: typeof http;
  https: typeof https;
  userAgent: string;
  // Since 2026-09-17: the name resolution and the address test the product
  // mode check needs, and the predicate that decides whether it applies.
  dns?: typeof dns;
  net?: typeof net;
  mode?: { dialsInternalAddresses(): boolean;
          skipsOutboundTlsVerification(): boolean };
}

// THE OUTBOUND TRANSPORT POLICY, as `common/outbound_tls.ts` takes it (#171).
// No plain http in product: a client secret travels on these requests, and
// no specification a partner speaks names a loopback exception.
const OUTBOUND_TRANSPORT = {
  what: 'a federation back-channel request',
  allowHttpKey: 'federation.outboundAllowHttp',
  skipTlsKey: 'federation.outboundSkipTlsVerification',
  caFileKey: 'federation.outboundCaFile',
  loopbackHttpInProduct: false,
  httpRefusedCode: 'STS-FED-0112',
  skipIgnoredCode: 'STS-FED-0113'
};

class FederationHttp {
  static readonly DIALLABLE = DIALLABLE;
  static readonly SENDABLE = SENDABLE;

  constructor(private readonly deps: FederationHttpDeps) {
    deps.log.debug("Entering FederationHttp.constructor().");
    deps.log.debug("Leaving FederationHttp.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): FederationHttpDeps {
    helpers.log.debug("Entering FederationHttp.defaultDeps().");
    helpers.log.debug("Leaving FederationHttp.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      http: http,
      https: https,
      userAgent: USER_AGENT,
      dns: dns,
      net: net,
      mode: mode
    };
  }

  // A partner that answers with more than this is not answering a protocol. A
  // token response is a few hundred bytes and a JWKS a few kilobytes; 256 KiB
  // is two orders of magnitude of headroom and still a bound.
  //
  // `federation.maxResponseBytes` since 2026-09-12; it was the constant
  // MAX_BODY_BYTES. Read once per REQUEST, so a change reaches the next one
  // and a response already being read keeps the cap it started under.
  maxBodyBytes(): number {
    const { log, config } = this.deps;
    log.debug("Entering FederationHttp.maxBodyBytes().");
    log.debug("Leaving FederationHttp.maxBodyBytes().");
    return Number(config.value('federation.maxResponseBytes'));
  }

  outboundAllowed(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering FederationHttp.outboundAllowed().");
    log.debug("Leaving FederationHttp.outboundAllowed().");
    return !!config.value('federation.outbound');
  }

  // THE TLS OPTIONS FOR ONE REQUEST to `origin` (#171), for this module and
  // for every requester that borrows its policy: `{ ok, why, errorCode,
  // rejectUnauthorized, ca, skipped }`. `ok: false` is a CA file that cannot
  // be used, and the request is not to be made.
  tlsFor(origin: string): ReturnType<typeof OutboundTls.tlsVerdict> {
    const { log } = this.deps;
    log.debug("Entering FederationHttp.tlsFor().");
    log.debug("Leaving FederationHttp.tlsFor().");
    return OutboundTls.tlsVerdict(OUTBOUND_TRANSPORT, origin);
  }

  // The three transport settings as they are IN FORCE in this realm.
  transportSettings(): ReturnType<typeof OutboundTls.describe> {
    const { log } = this.deps;
    log.debug("Entering FederationHttp.transportSettings().");
    log.debug("Leaving FederationHttp.transportSettings().");
    return OutboundTls.describe(OUTBOUND_TRANSPORT);
  }

  // Node's request options for the policy's answer: `ca` only when a CA file
  // named one, because node reads that option by value and an explicit list
  // REPLACES its store.
  applyTls(requestOptions: any,
           policy: ReturnType<typeof OutboundTls.tlsVerdict>): void {
    const { log } = this.deps;
    log.debug("Entering FederationHttp.applyTls().");
    requestOptions.rejectUnauthorized = policy.rejectUnauthorized;
    if (policy.ca) {
      requestOptions.ca = policy.ca;
    }
    log.debug("Leaving FederationHttp.applyTls().");
  }

  private timeoutMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering FederationHttp.timeoutMs().");
    log.debug("Leaving FederationHttp.timeoutMs().");
    return config.value('federation.outboundTimeoutMs');
  }

  // -------------------------------------------------------------------------
  // WHETHER THIS URL MAY BE DIALLED AT ALL, as a sentence rather than a
  // boolean.
  //
  // Every refusal here ends up on the relationship's `fedLastError` and on
  // `/admin/federation`, so each one has to name what is wrong and what to do
  // about it — "refused" would send somebody to read this file.
  // -------------------------------------------------------------------------
  urlProblem(raw: unknown): string {
    const { log } = this.deps;
    log.debug("Entering FederationHttp.urlProblem().");
    log.debug("Leaving FederationHttp.urlProblem().");
    return this.urlVerdict(raw).why;
  }

  // The same answer, with `STS-FED-0112` when the refusal is plain http in
  // product mode and '' for every other, whose code is the caller's.
  urlVerdict(raw: unknown): { why: string; errorCode: string } {
    const { log } = this.deps;
    log.debug("Entering FederationHttp.urlVerdict().");
    const text = String(raw || '').trim();
    if (!text) {
      log.debug("Leaving FederationHttp.urlVerdict(). Empty.");
      return { why: 'there is no URL configured for it', errorCode: '' };
    }
    let parsed = null;
    try {
      parsed = new URL(text);
    } catch (e) {
      log.debug("Caught in FederationHttp.urlVerdict(): " +
                ((e && e.message) || e));
      log.debug("Leaving FederationHttp.urlVerdict(). It will not parse.");
      return { why: '"' + text + '" is not a URL (' + e.message + ')',
               errorCode: '' };
    }
    if (parsed.protocol === 'https:') {
      log.debug("Leaving FederationHttp.urlVerdict(). https, fine.");
      return { why: '', errorCode: '' };
    }
    if (parsed.protocol === 'http:') {
      const verdict = OutboundTls.httpVerdict(OUTBOUND_TRANSPORT,
                                              parsed.hostname);
      if (verdict.ok) {
        log.debug("Leaving FederationHttp.urlVerdict(). http, allowed by " +
                  'setting.');
        return { why: '', errorCode: '' };
      }
      log.debug("Leaving FederationHttp.urlVerdict(). http, refused.");
      return { why: verdict.why + '. A client secret and an authorization ' +
                    'code travel on this kind of request',
               errorCode: verdict.errorCode };
    }
    log.debug("Leaving FederationHttp.urlVerdict(). Wrong scheme.");
    return { why: 'its scheme is "' + parsed.protocol.replace(':', '') +
                  '", and only https (or http, with ' +
                  'federation.outboundAllowHttp on, in development mode) is ' +
                  'dialled',
             errorCode: '' };
  }

  // -------------------------------------------------------------------------
  // WHY AN ADDRESS MAY NOT BE DIALLED IN PRODUCT MODE, or ''. An IPv4-mapped
  // IPv6 address is judged as the IPv4 address inside it, whichever of its
  // two spellings arrived, because `::ffff:127.0.0.1` reaches loopback
  // exactly as `127.0.0.1` does. Moved from the RFC 9728 import, unchanged.
  // -------------------------------------------------------------------------
  internalAddressProblem(address: unknown): string {
    const { log } = this.deps;
    const netModule = this.deps.net || net;
    log.debug("Entering FederationHttp.internalAddressProblem(). address=" +
              address);
    let text = String(address || '').replace(/^\[|\]$/g, '');
    const mappedDotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(text);
    const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(text);
    if (mappedDotted) {
      text = mappedDotted[1];
    } else if (mappedHex) {
      const high = parseInt(mappedHex[1], 16);
      const low = parseInt(mappedHex[2], 16);
      text = [high >> 8, high & 255, low >> 8, low & 255].join('.');
    }
    const family = netModule.isIP(text);
    if (!family) {
      log.debug("Leaving FederationHttp.internalAddressProblem(). Not an " +
                "address.");
      return '"' + address + '" is not an IP address';
    }
    const internal = INTERNAL.check(text, family === 4 ? 'ipv4' : 'ipv6');
    log.debug("Leaving FederationHttp.internalAddressProblem(). internal=" +
              internal);
    return internal
      ? text + ' is a loopback, private, link-local or reserved address'
      : '';
  }

  // -------------------------------------------------------------------------
  // RESOLVE ONCE, AND SAY WHICH ADDRESS THE CONNECTION MAY USE.
  //
  // In development (`mode.dialsInternalAddresses()`) the name is resolved by
  // the connection itself and nothing is pinned. In product every address
  // the name resolves to is checked and the first is what the request
  // connects to — resolving twice is how a name that answered a public
  // address to the check answers a private one to the connection. Never
  // rejects.
  // -------------------------------------------------------------------------
  vetHost(hostname: unknown): Promise<VettedHost> {
    const { log } = this.deps;
    const self = this;
    const netModule = this.deps.net || net;
    const dnsModule = this.deps.dns || dns;
    const modeModule = this.deps.mode || mode;
    log.debug("Entering FederationHttp.vetHost(). hostname=" + hostname);
    const host = String(hostname || '').replace(/^\[|\]$/g, '');
    if (modeModule.dialsInternalAddresses()) {
      log.debug("Leaving FederationHttp.vetHost(). Development: not pinned.");
      return Promise.resolve({ ok: true, address: '', family: 0 });
    }
    const judge = function (addresses): VettedHost {
      log.debug("Entering judge().");
      const bad = addresses.map(function (one) {
        return self.internalAddressProblem(one.address);
      }).filter(function (one) { return !!one; });
      if (bad.length || !addresses.length) {
        log.debug("Leaving judge(). Refused.");
        return { ok: false, address: '', family: 0,
                 kind: bad.length ? 'internal' : 'unresolved',
                 why: '"' + host + '" resolves to ' +
                      (bad.length ? bad.join('; ') : 'no address') +
                      '. This service is running as a product ' +
                      '(global.mode=product), so an outbound request may ' +
                      'not reach an address inside this service\'s own ' +
                      'network.' };
      }
      log.debug("Leaving judge(). ok.");
      return { ok: true, address: addresses[0].address,
               family: addresses[0].family };
    };
    const literal = netModule.isIP(host);
    if (literal) {
      log.debug("Leaving FederationHttp.vetHost(). A literal address.");
      return Promise.resolve(judge([{ address: host, family: literal }]));
    }
    log.debug("Leaving FederationHttp.vetHost(). Resolving.");
    return new Promise<VettedHost>(function (resolve) {
      dnsModule.lookup(host, { all: true }, function (error, addresses) {
        if (error) {
          log.debug("Caught in FederationHttp.vetHost(): " +
                    ((error && error.message) || error));
          resolve({ ok: false, address: '', family: 0, kind: 'unresolved',
                    why: '"' + host + '" could not be resolved: ' +
                         error.message });
          return;
        }
        resolve(judge(addresses || []));
      });
    });
  }

  // -------------------------------------------------------------------------
  // SEND A FORM TO AN ADDRESS SOMEBODY REGISTERED TO BE SENT IT AT
  // (2026-09-17, #36). See the header for why this is a function of its own.
  //
  //   record     an object carrying the address under `attribute`, and `id`
  //              for the log — the application entry's fields, as the caller
  //              read them.
  //   attribute  one of SENDABLE, checked.
  //   form       the name/value pairs, sent
  //              application/x-www-form-urlencoded.
  //   options    { timeoutMs }
  //
  // The body of the answer is drained, capped and DISCARDED: nothing that
  // comes back is used, which is the property that makes this a delivery
  // rather than a fetch. The status and the `Cache-Control` header are the
  // whole result. It NEVER rejects.
  // -------------------------------------------------------------------------
  deliverForm(record: any, attribute: string, form: Record<string, string>,
              options?: { timeoutMs?: number }): Promise<DeliveryResult> {
    const { log, errorCodes } = this.deps;
    const self = this;
    const opts = options || {};
    const id = (record && (record.id || record.fedId)) || '?';
    log.debug("Entering FederationHttp.deliverForm(). id=" + id +
              ', attribute=' + attribute);
    const refused = function (kind: string, why: string,
                              raw?: string): Promise<DeliveryResult> {
      log.debug("Entering refused(). " + kind);
      log.debug("Leaving refused().");
      return Promise.resolve({ ok: false, status: 0, kind: kind, why: why,
                               url: raw || '', cacheControl: '' });
    };
    if (SENDABLE.indexOf(String(attribute)) === -1) {
      // A programming error, and loud for DIALLABLE's reason.
      log.error(errorCodes.tag('STS-FED-0046') + 'federation: something ' +
                'asked to send to "' + attribute + '" on ' + id + ', which ' +
                'is not one of the attributes this service will deliver to (' +
                SENDABLE.join(', ') + '). Refused. This is a bug in the ' +
                'caller — see the header of federation_http.ts.');
      log.debug("Leaving FederationHttp.deliverForm(). Not sendable.");
      return refused('attribute', 'this service will not send to a URL ' +
                     'from "' + attribute + '"');
    }
    if (!this.outboundAllowed()) {
      log.debug("Leaving FederationHttp.deliverForm(). Outbound is off.");
      return refused('outbound-off', 'federation.outbound is off, so this ' +
                     'service makes no outbound request at all');
    }
    const raw = String((record && record[attribute]) || '');
    const problem = this.urlVerdict(raw);
    if (problem.why) {
      log.debug("Leaving FederationHttp.deliverForm(). " + problem.why);
      return refused('url', attribute + ' cannot be dialled: ' + problem.why,
                     raw);
    }
    const target = new URL(raw);
    const secure = target.protocol === 'https:';
    if (!secure) {
      // Every insecure request, not just the setting. See the header.
      log.warn('outbound: sending to ' + target.origin + ' over plain http ' +
               'for ' + id + ' because federation.outboundAllowHttp is ON.');
    }
    const policy = this.tlsFor(target.origin);
    if (secure && !policy.ok) {
      log.debug("Leaving FederationHttp.deliverForm(). " + policy.why);
      return refused('ca-file', policy.why, raw);
    }
    const body = new URLSearchParams(form).toString();
    const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs)
                                                 : this.timeoutMs();
    const cap = this.maxBodyBytes();
    const transport = secure ? this.deps.https : this.deps.http;
    log.debug("Leaving FederationHttp.deliverForm(). Vetting the host.");
    return this.vetHost(target.hostname).then(function (vetted) {
      if (!vetted.ok) {
        return { ok: false, status: 0, kind: vetted.kind || 'internal',
                 why: vetted.why || '', url: raw, cacheControl: '' };
      }
      return new Promise<DeliveryResult>(function (resolve) {
        let settled = false;
        const done = function (result) {
          log.debug("Entering done().");
          if (!settled) {
            settled = true;
            resolve(Object.assign({ url: raw, cacheControl: '', why: '',
                                    kind: '' }, result));
          }
          log.debug("Leaving done().");
        };
        const requestOptions: any = {
          protocol: target.protocol,
          hostname: target.hostname,
          port: target.port || (secure ? 443 : 80),
          path: target.pathname + target.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body),
            'User-Agent': self.deps.userAgent
          },
          rejectUnauthorized: secure
        };
        if (secure) {
          self.applyTls(requestOptions, policy);
        }
        if (vetted.address) {
          // PINNED to the address that was checked. The Host header and the
          // TLS server name still come from the URL, so a certificate is
          // checked against the name that was registered.
          requestOptions.servername = target.hostname;
          requestOptions.lookup = function (hostname, lookupOptions,
                                            callback) {
            log.debug("Entering lookup().");
            log.debug("Leaving lookup().");
            if (lookupOptions && lookupOptions.all) {
              callback(null, [{ address: vetted.address,
                                family: vetted.family }]);
              return;
            }
            callback(null, vetted.address, vetted.family);
          };
        }
        let request = null;
        try {
          request = transport.request(requestOptions, function (response) {
            const status = response.statusCode || 0;
            const cacheControl = String(response.headers['cache-control'] ||
                                        '');
            if (status >= 300 && status < 400) {
              // Header point 3: a redirect is not followed. The token would
              // go wherever the Location pointed.
              response.destroy();
              done({ ok: false, status: status, kind: 'redirect',
                     cacheControl: cacheControl,
                     why: 'it answered ' + status + ' redirecting to "' +
                          (response.headers.location || '(no Location)') +
                          '", and a redirect is not followed' });
              return;
            }
            let bytes = 0;
            response.on('data', function (chunk) {
              bytes += chunk.length;
              if (bytes > cap) {
                // Drained to the cap and no further: the body is discarded
                // anyway, and a relying party that answers forever is this
                // process's memory.
                response.destroy();
              }
            });
            const finish = function () {
              log.debug("Entering finish().");
              const ok = status >= 200 && status < 300;
              done({ ok: ok, status: status, kind: ok ? '' : 'status',
                     cacheControl: cacheControl,
                     why: ok ? '' : 'it answered ' + status });
              log.debug("Leaving finish().");
            };
            response.on('end', finish);
            response.on('close', finish);
            response.on('error', function (e) {
              log.debug("Caught in a callback in deliverForm(): " +
                        ((e && e.message) || e));
              finish();
            });
          });
        } catch (e) {
          log.debug("Caught in FederationHttp.deliverForm(): " +
                    ((e && e.message) || e));
          done({ ok: false, status: 0, kind: 'build',
                 why: 'the request could not be built: ' + e.message });
          return;
        }
        request.setTimeout(timeoutMs, function () {
          request.destroy();
          done({ ok: false, status: 0, kind: 'timeout',
                 why: 'it did not answer within ' + timeoutMs + 'ms' });
        });
        request.on('error', function (e) {
          log.debug("Caught in a request callback in deliverForm(): " +
                    ((e && e.message) || e));
          done({ ok: false, status: 0, kind: 'network',
                 why: 'the request failed: ' +
                      (e.code ? e.code + ' — ' : '') + e.message });
        });
        request.write(body);
        request.end();
      });
    });
  }

  // -------------------------------------------------------------------------
  // A DOCUMENT A TRUSTED ISSUER PUBLISHED (2026-09-17, #38's follow-ups): a
  // Token Status List (draft-ietf-oauth-status-list) or a Bitstring Status
  // List credential, fetched by `oid4vc/vc_status.ts` for a credential a
  // presentation carried.
  //
  // THE THIRD ARGUMENT, AND IT IS NOT EITHER OF THE OTHER TWO. The URL comes
  // out of a CREDENTIAL, which a presenter handed over — the caller's kind of
  // URL, which the header says this module will not dial. What makes this one
  // different is where it sits inside that credential: under a signature that
  // has already VERIFIED against a certificate an ADMINISTRATOR put in
  // `oid4vp.trustedIssuerCertificates`. The presenter cannot choose it; the
  // issuer the administrator trusted did. `vc_status.ts` calls this only after
  // that verification, and never for a credential this realm signed (whose
  // list it reads from its own store). What is fetched is then verified
  // against that same certificate, so nothing that arrives is believed on
  // its own say-so (header point 5).
  //
  // Everything else here still applies: the kill switch, the transport
  // policy (`tlsFor()`, #171), the internal-address check in product
  // mode with the connection pinned, the body cap, the timeout — and NO
  // REDIRECT, which the draft's section 8.2 says a client SHOULD follow and
  // its section 11.4 says is where the risk is; a list that has moved is a
  // failure, and the verifier refuses the credential rather than follow it.
  // It sends nothing but `Accept`. It NEVER rejects: `{ ok, status, body,
  // contentType, kind, why, url }`.
  // -------------------------------------------------------------------------
  fetchPublished(raw: string, options?: { accept?: string;
                                          timeoutMs?: number }):
      Promise<{ ok: boolean; status: number; body: Buffer;
                contentType: string; kind: string; why: string;
                url: string }> {
    const { log } = this.deps;
    const self = this;
    const opts = options || {};
    log.debug("Entering FederationHttp.fetchPublished().");
    const empty = Buffer.alloc(0);
    const refused = function (kind: string, why: string): Promise<any> {
      log.debug("Entering refused(). " + kind);
      log.debug("Leaving refused().");
      return Promise.resolve({ ok: false, status: 0, body: empty,
                               contentType: '', kind: kind, why: why,
                               url: String(raw || '') });
    };
    if (!this.outboundAllowed()) {
      log.debug("Leaving FederationHttp.fetchPublished(). Outbound is off.");
      return refused('outbound-off', 'federation.outbound is off, so this ' +
                     'service makes no outbound request at all');
    }
    const problem = this.urlProblem(raw);
    if (problem) {
      log.debug("Leaving FederationHttp.fetchPublished(). " + problem);
      return refused('url', 'the URL cannot be dialled: ' + problem);
    }
    const target = new URL(String(raw));
    const secure = target.protocol === 'https:';
    if (!secure) {
      log.warn('outbound: fetching ' + target.origin + ' over plain http ' +
               'because federation.outboundAllowHttp is ON.');
    }
    const policy = this.tlsFor(target.origin);
    if (secure && !policy.ok) {
      log.debug("Leaving FederationHttp.fetchPublished(). " + policy.why);
      return refused('ca-file', policy.why);
    }
    const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs)
                                                 : this.timeoutMs();
    const cap = this.maxBodyBytes();
    const transport = secure ? this.deps.https : this.deps.http;
    log.debug("Leaving FederationHttp.fetchPublished(). Vetting the host.");
    return this.vetHost(target.hostname).then(function (vetted) {
      if (!vetted.ok) {
        return { ok: false, status: 0, body: empty, contentType: '',
                 kind: vetted.kind || 'internal', why: vetted.why || '',
                 url: String(raw) };
      }
      return new Promise<any>(function (resolve) {
        let settled = false;
        const done = function (result) {
          log.debug("Entering done().");
          if (!settled) {
            settled = true;
            resolve(Object.assign({ body: empty, contentType: '', why: '',
                                    kind: '', url: String(raw) }, result));
          }
          log.debug("Leaving done().");
        };
        const requestOptions: any = {
          protocol: target.protocol,
          hostname: target.hostname,
          port: target.port || (secure ? 443 : 80),
          path: target.pathname + target.search,
          method: 'GET',
          headers: {
            'Accept': String(opts.accept || '*/*'),
            'User-Agent': self.deps.userAgent
          },
          rejectUnauthorized: secure
        };
        if (secure) {
          self.applyTls(requestOptions, policy);
        }
        if (vetted.address) {
          requestOptions.servername = target.hostname;
          requestOptions.lookup = function (hostname, lookupOptions,
                                            callback) {
            log.debug("Entering lookup().");
            log.debug("Leaving lookup().");
            if (lookupOptions && lookupOptions.all) {
              callback(null, [{ address: vetted.address,
                                family: vetted.family }]);
              return;
            }
            callback(null, vetted.address, vetted.family);
          };
        }
        let request = null;
        try {
          request = transport.request(requestOptions, function (response) {
            const status = response.statusCode || 0;
            const contentType = String(response.headers['content-type'] ||
                                       '');
            if (status >= 300 && status < 400) {
              response.destroy();
              done({ ok: false, status: status, kind: 'redirect',
                     why: 'it answered ' + status + ' redirecting to "' +
                          (response.headers.location || '(no Location)') +
                          '", and a redirect is not followed' });
              return;
            }
            const chunks: Buffer[] = [];
            let bytes = 0;
            response.on('data', function (chunk) {
              bytes += chunk.length;
              if (bytes > cap) {
                response.destroy();
                done({ ok: false, status: status, kind: 'too-large',
                       why: 'it answered with more than ' + cap +
                            ' bytes (federation.maxResponseBytes)' });
                return;
              }
              chunks.push(chunk);
            });
            response.on('end', function () {
              const ok = status >= 200 && status < 300;
              done({ ok: ok, status: status, body: Buffer.concat(chunks),
                     contentType: contentType, kind: ok ? '' : 'status',
                     why: ok ? '' : 'it answered ' + status });
            });
            response.on('error', function (e) {
              log.debug("Caught in a callback in fetchPublished(): " +
                        ((e && e.message) || e));
              done({ ok: false, status: status, kind: 'network',
                     why: 'the response failed: ' + e.message });
            });
          });
        } catch (e) {
          log.debug("Caught in FederationHttp.fetchPublished(): " +
                    ((e && e.message) || e));
          done({ ok: false, status: 0, kind: 'build',
                 why: 'the request could not be built: ' + e.message });
          return;
        }
        request.setTimeout(timeoutMs, function () {
          request.destroy();
          done({ ok: false, status: 0, kind: 'timeout',
                 why: 'it did not answer within ' + timeoutMs + 'ms' });
        });
        request.on('error', function (e) {
          log.debug("Caught in a request callback in fetchPublished(): " +
                    ((e && e.message) || e));
          done({ ok: false, status: 0, kind: 'network',
                 why: 'the request failed: ' +
                      (e.code ? e.code + ' — ' : '') + e.message });
        });
        request.end();
      });
    });
  }

  // -------------------------------------------------------------------------
  // ONE RESPONSE, READ WITHIN THE RULES EVERY REQUESTER HERE SHARES: no
  // redirect followed, the body capped at `cap`, the request timed out. The
  // two SPIFFE requesters below use it; the older three keep their own
  // readers, which grew their own messages. It NEVER rejects.
  // -------------------------------------------------------------------------
  private exchange(transport: any, requestOptions: any, body: Buffer | null,
                   cap: number, timeoutMs: number, raw: string):
      Promise<{ ok: boolean; status: number; body: Buffer; headers: any;
                kind: string; why: string; url: string }> {
    const { log } = this.deps;
    log.debug("Entering FederationHttp.exchange().");
    const empty = Buffer.alloc(0);
    log.debug("Leaving FederationHttp.exchange().");
    return new Promise<any>(function (resolve) {
      let settled = false;
      const done = function (result) {
        log.debug("Entering done().");
        if (!settled) {
          settled = true;
          resolve(Object.assign({ body: empty, headers: {}, why: '',
                                  kind: '', url: raw }, result));
        }
        log.debug("Leaving done().");
      };
      let request = null;
      try {
        request = transport.request(requestOptions, function (response) {
          const status = response.statusCode || 0;
          if (status >= 300 && status < 400) {
            response.destroy();
            done({ ok: false, status: status, kind: 'redirect',
                   headers: response.headers,
                   why: 'it answered ' + status + ' redirecting to "' +
                        (response.headers.location || '(no Location)') +
                        '", and a redirect is not followed' });
            return;
          }
          const chunks: Buffer[] = [];
          let bytes = 0;
          response.on('data', function (chunk) {
            bytes += chunk.length;
            if (bytes > cap) {
              response.destroy();
              done({ ok: false, status: status, kind: 'too-large',
                     headers: response.headers,
                     why: 'it answered with more than ' + cap + ' bytes' });
              return;
            }
            chunks.push(chunk);
          });
          response.on('end', function () {
            const ok = status >= 200 && status < 300;
            done({ ok: ok, status: status, body: Buffer.concat(chunks),
                   headers: response.headers, kind: ok ? '' : 'status',
                   why: ok ? '' : 'it answered ' + status });
          });
          response.on('error', function (e) {
            log.debug("Caught in a callback in exchange(): " +
                      ((e && e.message) || e));
            done({ ok: false, status: status, kind: 'network',
                   why: 'the response failed: ' + e.message });
          });
        });
      } catch (e) {
        log.debug("Caught in FederationHttp.exchange(): " +
                  ((e && e.message) || e));
        done({ ok: false, status: 0, kind: 'build',
               why: 'the request could not be built: ' + e.message });
        return;
      }
      request.setTimeout(timeoutMs, function () {
        request.destroy();
        done({ ok: false, status: 0, kind: 'timeout',
               why: 'it did not answer within ' + timeoutMs + 'ms' });
      });
      request.on('error', function (e) {
        log.debug("Caught in a request callback in exchange(): " +
                  ((e && e.message) || e));
        done({ ok: false, status: 0, kind: 'network',
               why: 'the request failed: ' +
                    (e.code ? e.code + ' — ' : '') + e.message });
      });
      if (body && body.length) {
        request.write(body);
      }
      request.end();
    });
  }

  // -------------------------------------------------------------------------
  // A SOURCE A SPIFFE NODE ATTESTOR WAS CONFIGURED TO ASK (#40, 2026-09-21):
  // a Kubernetes API server (TokenReview, a pod, a node), Google's
  // identity-token certificates, Microsoft's tenant discovery and the
  // intermediate its attested documents name.
  //
  // THE ADMINISTRATOR'S KIND OF URL, AND THE FOURTH ARGUMENT HERE. Every URL
  // that reaches this function was written into a `spiffe.*` setting by
  // somebody who administers the realm — a cluster's API server — or is a
  // constant SPIRE itself dials, which an administrator may point elsewhere
  // (for an air-gapped mirror, or a test); the agent attesting names none of
  // them. That is `fetchJson()`'s argument, not `fetchPublished()`'s, and so
  // this function does what `fetchJson()` does about addresses: NOTHING. A
  // Kubernetes API server lives on an internal address as a rule, and
  // refusing internal addresses here would refuse the one place it lives.
  //
  // Everything else holds: the kill switch, the transport policy
  // (`tlsFor()`, #171), no redirect, the body cap, the
  // timeout. `options.ca` is a PEM bundle to verify the server against
  // INSTEAD of node's default roots — a cluster's own CA — and the TLS check
  // is never turned off by it.
  //
  // `options.signedArtifact` admits plain http for ONE kind of fetch: a
  // document whose own signature the caller verifies before believing a byte
  // of it — the intermediate certificate an Azure attested document's
  // signing certificate names in its CA Issuers URL, which Microsoft serves
  // over http, as AIA URLs are. Nothing secret travels on such a request and
  // nothing unverified comes back from it, which is the whole of what https
  // would have added.
  //
  // FOUR MORE OPTIONS, FOR THE KUBELET (#40 phase four), each SPIRE's k8s
  // workload attestor's: `cert` and `key` (PEM) authenticate this client with
  // a certificate; `chainOnly` verifies the server's chain against `ca` and
  // not its NAME — SPIRE's check when no node name is configured, because a
  // kubelet's certificate names the node and not 127.0.0.1; `skipVerify` is
  // `skip_kubelet_verification`, an administrator's explicit choice, logged on
  // every request and honoured in DEVELOPMENT MODE ONLY (#171); and `loopbackPlainHttp` admits http to 127.0.0.1 or ::1
  // ONLY, which is the kubelet's read-only port. It NEVER rejects.
  // -------------------------------------------------------------------------
  requestConfigured(raw: string, options?: {
    method?: string; headers?: Record<string, string>; body?: Buffer | string;
    ca?: string; timeoutMs?: number; signedArtifact?: boolean;
    cert?: string; key?: string; chainOnly?: boolean; skipVerify?: boolean;
    loopbackPlainHttp?: boolean }):
      Promise<{ ok: boolean; status: number; body: Buffer; headers: any;
                kind: string; why: string; url: string }> {
    const { log } = this.deps;
    const opts = options || {};
    log.debug("Entering FederationHttp.requestConfigured().");
    const empty = Buffer.alloc(0);
    if (!this.outboundAllowed()) {
      log.debug("Leaving FederationHttp.requestConfigured(). Outbound off.");
      return Promise.resolve({ ok: false, status: 0, body: empty,
        headers: {}, kind: 'outbound-off', url: String(raw || ''),
        why: 'federation.outbound is off, so this service makes no ' +
             'outbound request at all' });
    }
    const plainSigned = (!!opts.signedArtifact && !opts.body &&
      /^http:\/\//i.test(String(raw || ''))) ||
      (!!opts.loopbackPlainHttp &&
       /^http:\/\/(127\.0\.0\.1|\[::1\])(:\d+)?\//i.test(String(raw || '')));
    const problem = plainSigned ? '' : this.urlProblem(raw);
    if (problem) {
      log.debug("Leaving FederationHttp.requestConfigured(). " + problem);
      return Promise.resolve({ ok: false, status: 0, body: empty,
        headers: {}, kind: 'url', url: String(raw || ''),
        why: 'the URL cannot be dialled: ' + problem });
    }
    const target = new URL(String(raw));
    const secure = target.protocol === 'https:';
    if (!secure && !plainSigned) {
      log.warn('outbound: a SPIFFE node attestor is dialling ' +
               target.origin + ' over plain http because ' +
               'federation.outboundAllowHttp is ON.');
    }
    // THE ADMINISTRATOR'S OWN ANCHOR WINS: `opts.ca` (a cluster's CA, the
    // kubelet's) replaces node's store as it always did, and the federation
    // policy's CA file is asked only when there is none. Verification off is
    // the policy's to decide, in development only (#171).
    const policy = this.tlsFor(target.origin);
    if (secure && !opts.ca && !policy.ok) {
      log.debug("Leaving FederationHttp.requestConfigured(). " + policy.why);
      return Promise.resolve({ ok: false, status: 0, body: empty,
        headers: {}, kind: 'ca-file', url: String(raw || ''),
        why: policy.why });
    }
    const body = opts.body === undefined || opts.body === null ? null
      : Buffer.isBuffer(opts.body) ? opts.body
        : Buffer.from(String(opts.body), 'utf8');
    const headers = Object.assign({ 'Accept': 'application/json',
                                    'User-Agent': this.deps.userAgent },
                                  opts.headers || {});
    if (body) headers['Content-Length'] = String(body.length);
    const requestOptions: any = {
      protocol: target.protocol, hostname: target.hostname,
      port: target.port || (secure ? 443 : 80),
      path: target.pathname + target.search,
      method: String(opts.method || 'GET').toUpperCase(),
      headers: headers,
      rejectUnauthorized: secure
    };
    if (secure) {
      this.applyTls(requestOptions, policy);
    }
    if (secure && opts.ca) requestOptions.ca = String(opts.ca);
    if (secure && opts.cert && opts.key) {
      requestOptions.cert = String(opts.cert);
      requestOptions.key = String(opts.key);
    }
    if (secure && opts.chainOnly) {
      // The chain is still verified against `ca`; only the name is not.
      requestOptions.checkServerIdentity = function () {
        return undefined;
      };
    }
    // SPIRE's `skip_kubelet_verification` (#171): development only. The
    // attestor asks `common/outbound_tls.ts` before it sets `skipVerify`, and
    // says once when product mode ignores it; this is the same predicate
    // asked again where the option is applied, so no other caller can pass
    // it past the mode.
    const modeModule = this.deps.mode || mode;
    if (secure && opts.skipVerify &&
        modeModule.skipsOutboundTlsVerification()) {
      log.warn('outbound: ' + target.origin + ' is dialled WITHOUT ' +
               'verifying its certificate, because the configuration asks ' +
               'for that (a kubelet\'s skip_kubelet_verification).');
      requestOptions.rejectUnauthorized = false;
    }
    const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs)
                                                 : this.timeoutMs();
    log.debug("Leaving FederationHttp.requestConfigured().");
    return this.exchange(secure ? this.deps.https : this.deps.http,
                         requestOptions, body, this.maxBodyBytes(),
                         timeoutMs, String(raw));
  }

  // -------------------------------------------------------------------------
  // A LOCAL UNIX SOCKET AN ADMINISTRATOR NAMED (#40 phase four): the Docker
  // Engine API, which SPIRE's docker workload attestor asks about the
  // container a workload runs in. Not a network request at all — nothing
  // leaves the host — but it is a request this service makes, so it keeps the
  // rules the others do: the kill switch, no redirect, the cap, the timeout.
  // `socketPath` is a setting (`spiffe.dockerSocketPath`); `path` is built by
  // the caller from a container ID read out of the kernel's cgroup file.
  // It NEVER rejects.
  // -------------------------------------------------------------------------
  requestLocalSocket(socketPath: string, path: string, options?: {
    method?: string; timeoutMs?: number }):
      Promise<{ ok: boolean; status: number; body: Buffer; headers: any;
                kind: string; why: string; url: string }> {
    const { log } = this.deps;
    const opts = options || {};
    log.debug("Entering FederationHttp.requestLocalSocket(). " + socketPath +
              " " + path);
    const where = 'unix://' + socketPath + path;
    if (!this.outboundAllowed()) {
      log.debug("Leaving FederationHttp.requestLocalSocket(). Outbound off.");
      return Promise.resolve({ ok: false, status: 0, body: Buffer.alloc(0),
        headers: {}, kind: 'outbound-off', url: where,
        why: 'federation.outbound is off, so this service makes no ' +
             'outbound request at all' });
    }
    const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs)
                                                 : this.timeoutMs();
    log.debug("Leaving FederationHttp.requestLocalSocket().");
    return this.exchange(this.deps.http, {
      socketPath: socketPath, path: path,
      method: String(opts.method || 'GET').toUpperCase(),
      headers: { 'Accept': 'application/json', 'Host': 'docker',
                 'User-Agent': this.deps.userAgent }
    }, null, this.maxBodyBytes(), timeoutMs, where);
  }

  // -------------------------------------------------------------------------
  // SPIRE'S `http_challenge`: the one GET here to an address the CALLER
  // named (#40, 2026-09-21 — rcbj's decision, with these bounds).
  //
  // THE FIFTH ARGUMENT, AND THE ONLY ONE OF ITS KIND. An agent attesting with
  // `http_challenge` says "I am `hostname`, and I am serving on `port`", and
  // the proof is this server fetching
  // `http://<hostname>:<port>/.well-known/spiffe/nodeattestor/http_challenge/
  // <agent>/challenge` and finding the nonce it sent. The address is the
  // caller's — the header's first refusal — and what makes it acceptable is
  // what bounds it, in order:
  //
  //   1. the attestor has already matched `hostname` against the realm's
  //      `spiffe.httpChallengeAllowedDnsPatterns` BEFORE this is called — an
  //      empty list refuses every agent, which is stricter than SPIRE, whose
  //      empty list allows any name;
  //   2. the kill switch;
  //   3. in product mode every address the name resolves to is checked
  //      against the internal ranges and the connection is pinned to the one
  //      checked (`vetHost()`), as the RFC 9728 import does;
  //   4. no redirect, 64 bytes of body (SPIRE reads 64), a 10-second timeout
  //      (SPIRE's);
  //   5. nothing is sent but the request line and a User-Agent, and what
  //      comes back is compared with a nonce and discarded.
  //
  // It is plain HTTP, and `federation.outboundAllowHttp` is not asked:
  // SPIRE's plugin speaks http, nothing secret travels on the request, and
  // the proof is the nonce coming back from the address the name resolves
  // to — which is exactly as strong as this network's DNS, and no stronger.
  // It NEVER rejects.
  // -------------------------------------------------------------------------
  fetchHttpChallenge(hostname: string, port: number, path: string):
      Promise<{ ok: boolean; status: number; body: Buffer; headers: any;
                kind: string; why: string; url: string }> {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering FederationHttp.fetchHttpChallenge(). host=" +
              hostname + " port=" + port);
    const empty = Buffer.alloc(0);
    const where = 'http://' + (String(hostname).indexOf(':') >= 0
      ? '[' + hostname + ']' : hostname) + ':' + port + path;
    if (!this.outboundAllowed()) {
      log.debug("Leaving FederationHttp.fetchHttpChallenge(). Outbound off.");
      return Promise.resolve({ ok: false, status: 0, body: empty,
        headers: {}, kind: 'outbound-off', url: where,
        why: 'federation.outbound is off, so this service makes no ' +
             'outbound request at all' });
    }
    log.debug("Leaving FederationHttp.fetchHttpChallenge(). Vetting.");
    return this.vetHost(hostname).then(function (vetted) {
      if (!vetted.ok) {
        return { ok: false, status: 0, body: empty, headers: {},
                 kind: vetted.kind || 'internal', why: vetted.why || '',
                 url: where };
      }
      const requestOptions: any = {
        protocol: 'http:', hostname: hostname, port: port, path: path,
        method: 'GET',
        headers: { 'User-Agent': self.deps.userAgent, 'Accept': '*/*' }
      };
      if (vetted.address) {
        requestOptions.lookup = function (name, lookupOptions, callback) {
          log.debug("Entering lookup().");
          log.debug("Leaving lookup().");
          if (lookupOptions && lookupOptions.all) {
            callback(null, [{ address: vetted.address,
                              family: vetted.family }]);
            return;
          }
          callback(null, vetted.address, vetted.family);
        };
      }
      return self.exchange(self.deps.http, requestOptions, null, 64, 10000,
                           where);
    });
  }

  // -------------------------------------------------------------------------
  // THE REQUEST.
  //
  //   record     the federation relationship, as `federation.js` hands it back
  //   attribute  WHICH attribute holds the URL. One of DIALLABLE, checked.
  //   options    { method, form, bearer, basic, headers }
  //
  // Returns a promise of { ok, status, json, text, url, why } and NEVER
  // rejects. A rejected promise here would have to be caught at four call
  // sites in the middle of a browser redirect, and the fourth one added later
  // would not be — which is the same reasoning `audit.audit()` and the user
  // observer are written under. `ok` is false and `why` is a sentence.
  // -------------------------------------------------------------------------
  fetchJson(record: any, attribute: string,
            options?: FetchOptions): Promise<FetchResult> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering FederationHttp.fetchJson().");
    const opts = options || {};
    const id = (record && record.fedId) || '?';
    log.debug("Entering FederationHttp.fetchJson(). id=" + id +
              ', attribute=' + attribute);

    if (DIALLABLE.indexOf(String(attribute)) === -1) {
      // A programming error rather than a configuration one, so it is loud.
      // See the header: this is the mechanism that keeps the SSRF position
      // honest, and it must never be possible to slip past it by passing a
      // string.
      log.error(errorCodes.tag('STS-FED-0046') + 'federation: something ' +
                'asked to dial ' +
                '"' + attribute + '" ' +
                'on ' + id +
                ', which is not one of the three attributes this service ' +
                'will follow (' + DIALLABLE.join(', ') + '). Refused. This ' +
                'is a bug in the caller, not a misconfiguration — see the ' +
                'header of federation_http.js.');
      log.debug("Leaving FederationHttp.fetchJson(). Not a diallable " +
                'attribute.');
      log.debug("Leaving FederationHttp.fetchJson().");
      return Promise.resolve({ ok: false, status: 0, json: null, text: '',
                               url: '',
                               errorCode: 'STS-FED-0046',
                               why: 'this service will not follow a URL ' +
                                    'from "' + attribute + '"' });
    }
    if (!this.outboundAllowed()) {
      log.debug("Leaving FederationHttp.fetchJson(). Outbound is off.");
      log.debug("Leaving FederationHttp.fetchJson().");
      return Promise.resolve({ ok: false, status: 0, json: null, text: '',
                               url: '',
                               errorCode: 'STS-FED-0047',
                               why: 'federation.outbound is off, so this ' +
                                    'service makes no back-channel request ' +
                                    'at all. SAML, SAML 1.1 and ' +
                                    'WS-Federation need none; an OIDC ' +
                                    'partner can be used with ' +
                                    'fedResponseType=id_token and its ' +
                                    'keys in fedJwks' });
    }
    const raw = String((record && record[attribute]) || '');
    const problem = this.urlVerdict(raw);
    if (problem.why) {
      log.debug("Leaving FederationHttp.fetchJson(). " + problem.why);
      log.debug("Leaving FederationHttp.fetchJson().");
      return Promise.resolve({ ok: false, status: 0, json: null, text: '',
                               url: raw,
                               errorCode: problem.errorCode || 'STS-FED-0048',
                               why: attribute + ' cannot be dialled: ' +
                                    problem.why });
    }

    const target = new URL(raw);
    const secure = target.protocol === 'https:';
    if (!secure) {
      // Every insecure request, not just the setting. See the header.
      log.warn('federation: dialling ' + target.origin + ' over plain http ' +
               'for ' + id +
               ' because federation.outboundAllowHttp is ON. A client ' +
               'secret and an authorization code travel on this request.');
    }
    const policy = this.tlsFor(target.origin);
    if (secure && !policy.ok) {
      log.debug("Leaving FederationHttp.fetchJson(). " + policy.why);
      return Promise.resolve({ ok: false, status: 0, json: null, text: '',
                               url: raw, errorCode: policy.errorCode,
                               why: attribute + ' cannot be dialled: ' +
                                    policy.why });
    }
    const method = String(opts.method || 'GET').toUpperCase();
    const headers = Object.assign({ 'Accept': 'application/json',
                                    'User-Agent': this.deps.userAgent },
                                  opts.headers || {});
    let body = '';
    if (opts.form) {
      body = new URLSearchParams(opts.form).toString();
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    if (opts.bearer) {
      headers['Authorization'] = 'Bearer ' + opts.bearer;
    }
    if (opts.basic) {
      headers['Authorization'] = 'Basic ' +
        Buffer.from(String(opts.basic.user) + ':' + String(opts.basic.pass))
              .toString('base64');
    }

    const cap = this.maxBodyBytes();
    const transport = secure ? this.deps.https : this.deps.http;
    log.debug("Leaving FederationHttp.fetchJson().");
    return new Promise<FetchResult>((resolve) => {
      const done = function (result) {
        log.debug("Entering done().");
        log.debug("Leaving FederationHttp.fetchJson(). ok=" + result.ok +
                  ', status=' + result.status);
        resolve(Object.assign({ url: raw }, result));
        log.debug("Leaving done().");
      };
      let request = null;
      try {
        const requestOptions: any = {
          protocol: target.protocol,
          hostname: target.hostname,
          port: target.port || (secure ? 443 : 80),
          path: target.pathname + target.search,
          method: method,
          headers: headers,
          // The certificate check, and it is the ordinary one — this is the
          // one place in this service where a real TLS verification happens
          // against somebody else's certificate, and the mock's usual "verify
          // nothing" posture is exactly wrong for it: what is being protected
          // is the secret in the Authorization header. `policy` decides it:
          // only development mode with
          // `federation.outboundSkipTlsVerification` on turns it off, and
          // that is warned about on every request.
          rejectUnauthorized: secure
        };
        if (secure) {
          this.applyTls(requestOptions, policy);
        }
        request = transport.request(requestOptions, function (response) {
          const status = response.statusCode || 0;
          const location = response.headers.location;
          if (status >= 300 && status < 400 && location) {
            // See the header, point 3. The socket is destroyed rather than
            // read: there is nothing here worth having.
            response.destroy();
            return done({ ok: false, status: status, json: null, text: '',
                          errorCode: 'STS-FED-0049',
                          why: 'it answered ' + status + ' redirecting to "' +
                               location +
                               '", and this service does not follow a ' +
                               'redirect on a back-channel request — the ' +
                               'credential in the Authorization header ' +
                               'would go wherever that pointed' });
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
            if (bytes > cap) {
              overflowed = true;
              response.destroy();
              return;
            }
            text += chunk;
          });
          response.on('end', function () {
            if (overflowed) {
              return done({ ok: false, status: status, json: null, text: '',
                            errorCode: 'STS-FED-0050',
                            why: 'it answered with more than ' + cap +
                                 ' bytes (federation.maxResponseBytes), ' +
                                 'which is not a token response, a ' +
                                 'UserInfo document or a JWKS' });
            }
            let json = null;
            try {
              json = JSON.parse(text);
            } catch (e) {
              log.debug("Caught in a callback in fetchJson(): " +
                        ((e && e.message) || e));
              // Not JSON. Kept rather than failed here, because an OAuth
              // error is often served as HTML by a proxy in front of the
              // partner and the TEXT is the diagnosis — the caller decides
              // whether it needed JSON.
              json = null;
            }
            done({ ok: status >= 200 && status < 300, status: status,
                   json: json,
                   text: text,
                   errorCode: status >= 200 && status < 300 ? ''
                     : 'STS-FED-0051',
                   why: status >= 200 && status < 300 ? ''
                     : 'it answered ' + status +
                       (json && json.error ? ' ' + json.error : '') });
          });
          response.on('error', function (e) {
            done({ ok: false, status: status, json: null, text: text,
                   errorCode: 'STS-FED-0052',
                   why: 'the response failed: ' + e.message });
          });
        });
      } catch (e) {
        log.debug("Caught in FederationHttp.fetchJson(): " +
                  ((e && e.message) || e));
        // A malformed option rather than a network failure — new URL() has
        // already succeeded by here, so this is a bug in the caller and is
        // reported as a refusal rather than thrown into a redirect.
        return done({ ok: false, status: 0, json: null, text: '',
                      errorCode: 'STS-FED-0053',
                      why: 'the request could not be built: ' + e.message });
      }
      request.setTimeout(this.timeoutMs(), () => {
        request.destroy();
        done({ ok: false, status: 0, json: null, text: '',
               errorCode: 'STS-FED-0054',
               why: 'it did not answer within ' + this.timeoutMs() + 'ms ' +
                    '(federation.outboundTimeoutMs). A browser is waiting ' +
                    'on this request, which is why the wait is short' });
      });
      request.on('error', function (e) {
        // The one that actually happens: DNS, connection refused, a
        // certificate nothing trusts. `e.code` is the useful half and is
        // named, because "self-signed certificate" and "connection refused"
        // send somebody to two completely different places.
        done({ ok: false, status: 0, json: null, text: '',
               errorCode: 'STS-FED-0055',
               why: 'the request failed: ' + (e.code ? e.code + ' — ' : '') +
                    e.message +
                    (e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
                     e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
                     e.code === 'SELF_SIGNED_CERT_IN_CHAIN'
                       ? '. Name its CA in federation.outboundCaFile to dial a ' +
                         'partner whose certificate nothing here trusts'
                       : '') });
      });
      if (body) {
        request.write(body);
      }
      request.end();
    });
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<FederationHttp>(
  'federation/federation_http',
  () => new FederationHttp(FederationHttp.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  FederationHttp: FederationHttp,
  installInstance: (instance: FederationHttp): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  DIALLABLE: FederationHttp.DIALLABLE,
  SENDABLE: FederationHttp.SENDABLE,
  internalAddressProblem: slot.forward('internalAddressProblem'),
  vetHost: slot.forward('vetHost'),
  deliverForm: slot.forward('deliverForm'),
  fetchPublished: slot.forward('fetchPublished'),
  requestConfigured: slot.forward('requestConfigured'),
  fetchHttpChallenge: slot.forward('fetchHttpChallenge'),
  requestLocalSocket: slot.forward('requestLocalSocket'),
  maxBodyBytes: slot.forward('maxBodyBytes'),
  urlProblem: slot.forward('urlProblem'),
  fetchJson: slot.forward('fetchJson'),
  outboundAllowed: slot.forward('outboundAllowed'),
  urlVerdict: slot.forward('urlVerdict'),
  tlsFor: slot.forward('tlsFor'),
  transportSettings: slot.forward('transportSettings'),
  OUTBOUND_TRANSPORT: OUTBOUND_TRANSPORT
};
