'use strict';
//
// File: xacml_pep_http.ts
//
// ===========================================================================
// THE THIRD OUTBOUND REQUEST IN THIS REPOSITORY, AND IT IS THE WEAKEST CASE OF
// THE THREE. MAKE THE ARGUMENT; DO NOT CITE THE OTHER TWO.
//
// `federation/federation_http.ts` is the first and `ssf/ssf_http.ts` is the
// second, and the second one's header opens by refusing to lean on the first.
// That is the rule this file inherits — the ARGUMENT is what is inherited, not
// the permission — so here it is from the beginning.
//
// Federation's rule is:
//
//     THOSE URLS ARE SUPPLIED BY THE CALLER. THESE ARE SUPPLIED BY THE
//     ADMINISTRATOR.
//
// and it enforces it by refusing to take a URL at all: `fetchJson()` takes a
// relationship record and the NAME of an attribute on it. SSF cannot make that
// argument, because RFC 8935 push IS the receiver telling the transmitter
// where to post, so it says so plainly and lists four bounds instead.
//
// **THIS FILE CANNOT MAKE EITHER ARGUMENT.** A notify URL is supplied by the
// PEP that registers, which is a caller; and no specification requires it,
// because there is no specification here at all — XACML 3.0 says nothing about
// how a policy reaches a PEP. So the honest statement is the shortest of the
// three: this service makes an outbound request to an address a caller chose,
// for a feature nobody asked it to have.
//
// ---------------------------------------------------------------------------
// WHAT MAKES IT AFFORDABLE ANYWAY IS THE ONE THING THE OTHER TWO CANNOT SAY.
//
// **THE NUDGE IS NEVER THE MECHANISM.** A remote PEP PULLS
// `GET /xacml/pep/policies` on its own interval, and that is the contract —
// the whole of it. This request says one sentence, "the repository changed,
// pull now", and carries nothing else: no policy, no decision, no event, no
// credential, not even the new sync token. Every PEP converges without it.
//
// That is a different KIND of bound from federation's and SSF's, and it is
// stronger than either. Federation's request carries a client secret to
// somebody else's token endpoint, so a failure there is a sign-in that does
// not happen. SSF's carries a Security Event Token, so a failure is an event
// the receiver never learns about — which is why that file records failures on
// the stream and offers a redeliver. Here a failure costs ONE POLLING INTERVAL
// OF LATENCY and is not otherwise observable, which means:
//
//   * `xacml.pepNotify` can be turned off in a deployment with no egress and
//     nothing breaks — not the feature, not a test, not a PEP;
//   * there is no retry and there is nothing to redeliver, because there is
//     nothing to lose;
//   * a refusal here is worth RECORDING (a nudge that never succeeds means a
//     PEP this service cannot reach, which is worth seeing on the console) and
//     is never worth escalating.
//
// If a future change ever puts something in this body that a PEP cannot get
// any other way, that removes the whole of the argument above and the feature
// needs a new one. The body is built in `nudge()` and is three members; keep
// it that way, or move the argument.
//
// ---------------------------------------------------------------------------
// AND FOUR BOUNDS, WHICH ARE SSF'S FOUR BECAUSE TWO FAMILIES MAKING ONE
// OUTBOUND REQUEST EACH SHOULD BE CONFIGURED THE SAME WAY.
//
// 1. **`xacml.pepNotify` TURNS IT OFF ENTIRELY**, and see above for why that
//    costs nothing but latency.
//
// 2. **`xacml.pepNotifyAllowedHosts` IS AN ALLOWLIST, EMPTY BY DEFAULT,
//    MEANING ANY.** SSF's default and SSF's reason: it is what makes this
//    usable as a mock, and a deployment reachable by anybody it does not trust
//    sets the list. Hosts rather than URLs, because a component legitimately
//    moves its path and does not legitimately move to another host.
//
// 3. **https, WITH THE PEP'S CERTIFICATE VERIFIED.** What travels here is
//    weaker than what travels on either of the other two — no credential and
//    no event — and it is still held to TLS, because a request this service
//    makes in the clear is a request somebody else can answer for, and a PEP
//    that acted on a forged nudge would pull from wherever it was told to
//    pull from. What protects it is that the PEP holds the PDP's address
//    itself and a nudge cannot change it; what TLS protects is the rest.
//    Since #171 the policy is `common/outbound_tls.ts`'s: plain http only
//    with `xacml.pepNotifyAllowHttp`, and never in product mode; verification
//    off only with `xacml.pepNotifySkipTlsVerification`, and only in
//    development; a PEP certified by a private CA through
//    `xacml.pepNotifyCaFile`.
//
// 4. **NO REDIRECTS, A CAPPED BODY AND A TIMEOUT**, for federation's reasons.
//    A 302 from a notify endpoint is not a protocol this service speaks.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route and requires `helpers.js`,
// `config.js`, `audit.js`, `error_codes.js`, `version.js` and node's own
// `http`/`https`/`url` — none of which reaches back here — so it cannot join a
// cycle and a test can drive it against a throwaway listener.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `PepNotifier` takes the settings, the logger, the audit log, node's
// two transports and the User-Agent string through its constructor
// (`PepNotifierDeps`). The module still exports `MAX_BODY_BYTES` and the
// seven functions it always did, as FACADES forwarding to the instance the
// composition root builds and installs (#50's R2), for `xacml.ts`,
// `xacml_admin.ts` and `tests/xacml_pep.js`. A process without the root
// builds a default when this module loads. `PepNotifier` is exported for the
// root.
// ---------------------------------------------------------------------------

import https = require('https');
import http = require('http');
import url = require('url');
import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// The audit log and the error-code registry, for a nudge that was not
// delivered. `audit.js` requires `helpers`, `config`, `realms`, the
// replication module and the registry, none of which reaches back here, so the
// require closes no cycle. A failed nudge is recorded rather than escalated —
// this header's own rule — and a row with a code is how it is recorded.
import audit = require('../common/audit');
import errorCodes = require('../common/error_codes');
import version = require('../common/version');
import OutboundTls = require('../common/outbound_tls');

const { URL } = url;

// Kept for its place in the require order; the codes this file records are
// literals handed to `audit.failure()`.
void errorCodes;

// What a nudge resolves with.
interface NudgeResult {
  ok: boolean;
  status: number;
  why: string;
}

// What `nudgeAll()` resolves with, per PEP.
interface NudgeOutcome extends NudgeResult {
  name: string;
}

// The two members of a registered PEP's row this module reads.
interface PepRow {
  name: string;
  notifyUrl?: string;
}

interface Transport {
  request: typeof https.request;
}

interface PepNotifierDeps {
  config: { value(key: string): any };
  log: typeof helpers.log;
  audit: { failure(code: string, event: object): unknown };
  http: Transport;
  https: Transport;
  // Built once at require time: the version cannot change while the process
  // runs. See the comment on the headers block in `nudge()` for why the nudge
  // carries one at all.
  userAgent: string;
}

// A PEP that answers a nudge with more than this is not answering a nudge. The
// expected reply is 204 with nothing in it; 16 KiB is generous for the error
// object a broken one might send and is still a bound.
const MAX_BODY_BYTES = 16 * 1024;

// THE OUTBOUND TRANSPORT POLICY, as `common/outbound_tls.ts` takes it (#171).
// No plain http in product: nothing about a nudge names loopback.
const NOTIFY_TRANSPORT = {
  what: 'an XACML PEP nudge',
  allowHttpKey: 'xacml.pepNotifyAllowHttp',
  skipTlsKey: 'xacml.pepNotifySkipTlsVerification',
  caFileKey: 'xacml.pepNotifyCaFile',
  loopbackHttpInProduct: false,
  httpRefusedCode: 'STS-XACML-0073',
  skipIgnoredCode: 'STS-XACML-0074'
};

class PepNotifier {
  static readonly MAX_BODY_BYTES = MAX_BODY_BYTES;

  constructor(private readonly deps: PepNotifierDeps) {
    deps.log.debug('Entering PepNotifier.constructor().');
    deps.log.debug('Leaving PepNotifier.constructor().');
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): PepNotifierDeps {
    helpers.log.debug("Entering PepNotifier.defaultDeps().");
    helpers.log.debug("Leaving PepNotifier.defaultDeps().");
    return {
      config: config,
      log: helpers.log,
      audit: audit,
      http: http,
      https: https,
      userAgent: version.userAgent('xacml-pdp-notify')
    };
  }

  notifyAllowed(): boolean {
    const { log, config } = this.deps;
    log.debug('Entering PepNotifier.notifyAllowed().');
    const on = !!config.value('xacml.pepNotify');
    log.debug('Leaving PepNotifier.notifyAllowed(). ' + on);
    return on;
  }

  // The three transport settings as they are IN FORCE in this realm (#171).
  transportSettings(): ReturnType<typeof OutboundTls.describe> {
    const { log } = this.deps;
    log.debug('Entering PepNotifier.transportSettings().');
    log.debug('Leaving PepNotifier.transportSettings().');
    return OutboundTls.describe(NOTIFY_TRANSPORT);
  }

  timeoutMs(): number {
    const { log, config } = this.deps;
    log.debug('Entering PepNotifier.timeoutMs().');
    const value = config.value('xacml.pepNotifyTimeoutMs');
    log.debug('Leaving PepNotifier.timeoutMs(). ' + value);
    return value;
  }

  // The allowlist as lower-case host names. Empty means ANY, which is the
  // default and the one deliberate looseness here — see bound 2.
  allowedHosts(): string[] {
    const { log, config } = this.deps;
    log.debug('Entering PepNotifier.allowedHosts().');
    const raw = config.value('xacml.pepNotifyAllowedHosts');
    const list = String(raw || '').split(',').map(function (one) {
      return one.trim().toLowerCase();
    }).filter(function (one) {
      return !!one;
    });
    log.debug('Leaving PepNotifier.allowedHosts(). ' + list.length +
              ' host(s).');
    return list;
  }

  // -------------------------------------------------------------------------
  // WHY A URL IS REFUSED, or null when it is fine. Separate from the request
  // so that the console and `/admin-api` can show the refusal a PEP's notify
  // URL WOULD get without anything being dialled to find out.
  // -------------------------------------------------------------------------
  urlProblem(raw: unknown): string | null {
    const { log } = this.deps;
    log.debug('Entering PepNotifier.urlProblem().');
    log.debug('Leaving PepNotifier.urlProblem().');
    return this.urlVerdict(raw).why || null;
  }

  // The same answer with `STS-XACML-0073` when the refusal is plain http in
  // product mode, and '' for every other (whose code is STS-XACML-0066).
  urlVerdict(raw: unknown): { why: string; errorCode: string } {
    const { log } = this.deps;
    log.debug('Entering PepNotifier.urlVerdict(). raw=' + raw);
    if (!raw) {
      log.debug('Leaving PepNotifier.urlVerdict(). Empty.');
      return { why: 'There is no notify URL on this PEP, so it is never ' +
               'nudged. That is not a fault: the nudge is an optimisation ' +
               'and the PEP still pulls on its own interval.',
               errorCode: '' };
    }
    let parsed: InstanceType<typeof URL>;
    try {
      parsed = new URL(String(raw));
    } catch (error) {
      log.debug("Caught in PepNotifier.urlVerdict(): " +
                ((error && error.message) || error));
      // Not a URL. The parser's own message adds nothing a person reading the
      // console row needs, so the refusal is the one sentence below.
      log.debug('Leaving PepNotifier.urlVerdict(). Unparseable.');
      return { why: 'That is not a URL.', errorCode: '' };
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      log.debug('Leaving PepNotifier.urlVerdict(). Wrong scheme.');
      return { why: 'A notify URL is http or https; this one is "' +
               parsed.protocol.replace(/:$/, '') + '".', errorCode: '' };
    }
    if (parsed.protocol === 'http:') {
      const verdict = OutboundTls.httpVerdict(NOTIFY_TRANSPORT,
                                              parsed.hostname);
      if (!verdict.ok) {
        log.debug('Leaving PepNotifier.urlVerdict(). Plain http refused.');
        return { why: 'This notify URL is plain http: ' + verdict.why +
                 '. A nudge carries no credential and no event, so this is ' +
                 'the mildest of this service\'s outbound refusals — but a ' +
                 'request made in the clear is a request somebody else can ' +
                 'answer for.',
                 errorCode: verdict.errorCode };
      }
    }
    const list = this.allowedHosts();
    if (list.length && list.indexOf(parsed.hostname.toLowerCase()) < 0) {
      log.debug('Leaving PepNotifier.urlVerdict(). Not on the allowlist.');
      return { why: 'The host "' + parsed.hostname + '" is not in ' +
               'xacml.pepNotifyAllowedHosts (' + list.join(', ') + ').',
               errorCode: '' };
    }
    log.debug('Leaving PepNotifier.urlVerdict(). None.');
    return { why: '', errorCode: '' };
  }

  // -------------------------------------------------------------------------
  // THE NUDGE ITSELF.
  //
  // Resolves — never rejects — with `{ ok, status, why }`, because every
  // caller of this wants to RECORD what happened rather than to handle it. A
  // nudge that failed is a sentence on a console row; there is no recovery to
  // attempt and nothing upstream that should stop because of one.
  //
  // THE BODY IS THREE MEMBERS AND THE HEADER ABOVE DEPENDS ON THAT. It says
  // that something changed, when, and which PDP is saying so — and nothing a
  // PEP could not get by pulling. Adding a fourth that carries content removes
  // the argument for this file existing.
  // -------------------------------------------------------------------------
  // One row per nudge that did not arrive. The TARGET is the notify URL's
  // origin and never its path or query, which a PEP may have put anything in.
  private recordUndelivered(code: string, origin: string,
                            summary: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering PepNotifier.recordUndelivered().");
    audit.failure(code, {
      action: 'service.failure', protocol: 'XACML', channel: 'http',
      // error-code: none — the code is this helper's parameter; every caller passes a literal
      target: origin || '', summary: summary, outcome: 'error'
    });
    log.debug("Leaving PepNotifier.recordUndelivered().");
  }

  nudge(url: unknown, issuer?: unknown,
        options?: object): Promise<NudgeResult> {
    const self = this;
    const { log, http, https, userAgent } = this.deps;
    log.debug('Entering PepNotifier.nudge(). url=' + url);
    const settings = options || {};
    void settings;
    log.debug("Leaving PepNotifier.nudge().");
    return new Promise(function (resolve: (r: NudgeResult) => void) {
      if (!self.notifyAllowed()) {
        log.debug('Leaving nudge(). Notification is off.');
        resolve({ ok: false, status: 0,
                  why: 'xacml.pepNotify is off, so nothing was dialled. The ' +
                       'PEP converges on its next poll.' });
        return;
      }
      const problem = self.urlVerdict(url);
      if (problem.why) {
        log.debug('Leaving nudge(). Refused before dialling.');
        if (problem.errorCode === 'STS-XACML-0073') {
          self.recordUndelivered('STS-XACML-0073', '',
                                 'A change nudge was not sent: the PEP\'s ' +
                                 'notify URL is plain http and this realm ' +
                                 'is in product mode.');
        } else {
          self.recordUndelivered('STS-XACML-0066', '',
                                 'A change nudge was not sent: ' +
                                 'the PEP\'s notify URL is outside this ' +
                                 'service\'s outbound bounds.');
        }
        resolve({ ok: false, status: 0, why: problem.why });
        return;
      }
      const parsed = new URL(String(url));
      const insecure = parsed.protocol === 'http:';
      // The certificate policy (#171): node's store and
      // `xacml.pepNotifyCaFile`, skipped only in development with
      // `xacml.pepNotifySkipTlsVerification` on. A PEP's certificate is its
      // own and this service is not the authority for it.
      const policy = insecure ? null :
        OutboundTls.tlsVerdict(NOTIFY_TRANSPORT, parsed.origin);
      if (policy && !policy.ok) {
        log.debug('Leaving nudge(). ' + policy.why);
        self.recordUndelivered('STS-CORE-0104', parsed.origin,
                               'A change nudge was not sent: the CA file ' +
                               'xacml.pepNotifyCaFile names cannot be used.');
        resolve({ ok: false, status: 0, why: policy.why });
        return;
      }
      const body = JSON.stringify({
        event: 'policy-repository-changed',
        at: new Date().toISOString(),
        pdp: String(issuer || '')
      });
      if (insecure) {
        // Logged per REQUEST rather than once when the setting was read, for
        // federation's reason: a check disabled six months ago and forgotten
        // is the worst kind of leftover.
        log.warn('xacml: nudging ' + parsed.origin + ' over plain http ' +
                 '(xacml.pepNotifyAllowHttp is on).');
      }
      const transport = insecure ? http : https;
      const request = transport.request(Object.assign({
        method: 'POST',
        hostname: parsed.hostname,
        port: parsed.port || (insecure ? 80 : 443),
        path: parsed.pathname + parsed.search,
        headers: { 'Content-Type': 'application/json',
                   'Content-Length': Buffer.byteLength(body),
                   // WHO IS CALLING, AND WHICH BUILD OF IT. This is the
                   // WEAKEST of this repository's three outbound requests —
                   // no specification asks for it at all, and a PEP pulls and
                   // converges whether or not the nudge arrives — which is
                   // exactly why the receiver deserves to be told what an
                   // unsolicited POST it never asked for is. RFC 9110 product
                   // form; common/version.js owns the product token.
                   'User-Agent': userAgent },
        timeout: self.timeoutMs(),
        // Two settings since #171, where there was one that turned off both
        // halves of "insecure" at once — and product mode honoured it. The
        // policy above decides this; `ca` is added only when a CA file names
        // one, because node reads that option by value.
        rejectUnauthorized: !policy || policy.rejectUnauthorized
      }, policy && policy.ca ? { ca: policy.ca } : {}),
      function (response) {
        let received = 0;
        const chunks: Buffer[] = [];
        response.on('data', function (chunk: Buffer) {
          received += chunk.length;
          if (received <= MAX_BODY_BYTES) {
            chunks.push(chunk);
            return;
          }
          // A body over the cap is not read further and the request is
          // ended. What a PEP says back is not used for anything, so there is
          // nothing to lose by truncating it.
          response.destroy();
        });
        response.on('end', function () {
          const status = response.statusCode || 0;
          if (status >= 300 && status < 400) {
            log.debug('Leaving nudge(). A redirect.');
            self.recordUndelivered('STS-XACML-0067', parsed.origin,
                                   'A PEP\'s notify endpoint answered a ' +
                                   'nudge with a redirect, which is not ' +
                                   'followed.');
            resolve({ ok: false, status: status,
                      why: 'The notify endpoint answered ' + status +
                           '. Redirects are not followed: a nudge posted ' +
                           'wherever a Location said would be this ' +
                           'service dialling an address nobody ' +
                           'configured.' });
            return;
          }
          if (status >= 200 && status < 300) {
            log.debug('Leaving nudge(). ' + status);
            resolve({ ok: true, status: status,
                      why: 'The PEP answered ' + status + '.' });
            return;
          }
          const text = Buffer.concat(chunks).toString('utf8').trim();
          log.debug('Leaving nudge(). Refused with ' + status);
          self.recordUndelivered('STS-XACML-0068', parsed.origin,
                                 'A PEP\'s notify endpoint answered a nudge ' +
                                 'with HTTP ' + status + '.');
          resolve({ ok: false, status: status,
                    why: 'The PEP answered ' + status +
                         (text ? ': ' + text.slice(0, 300) : '.') });
        });
      });
      let timedOut = false;
      request.on('timeout', function () {
        timedOut = true;
        request.destroy(new Error('the notify endpoint did not answer ' +
                                  'within ' + self.timeoutMs() + 'ms'));
      });
      request.on('error', function (error) {
        log.debug('Leaving nudge(). Failed.');
        if (timedOut) {
          self.recordUndelivered('STS-XACML-0069', parsed.origin,
                                 'A PEP\'s notify endpoint did not answer a ' +
                                 'nudge within xacml.pepNotifyTimeoutMs.');
        } else {
          self.recordUndelivered('STS-XACML-0070', parsed.origin,
                                 'A nudge could not be delivered to a PEP\'s ' +
                                 'notify endpoint: the connection failed.');
        }
        resolve({ ok: false, status: 0,
                  why: 'The nudge could not be delivered: ' +
                       (error && error.message ? error.message :
                        String(error)) +
                       '. The PEP converges on its next poll.' });
      });
      request.end(body);
    });
  }

  // -------------------------------------------------------------------------
  // NUDGE EVERY REGISTERED PEP THAT HAS A URL. Awaited by nobody who is
  // holding a browser: `xacml.ts` calls this and does not wait, because a
  // console form that saved a policy has finished its work whether or not four
  // PEPs answered. The result of each is recorded on that PEP's row.
  // -------------------------------------------------------------------------
  nudgeAll(rows: PepRow[] | null | undefined, issuer?: unknown,
           record?: (name: string, why: string) => void):
      Promise<NudgeOutcome[]> {
    const self = this;
    const { log } = this.deps;
    log.debug('Entering PepNotifier.nudgeAll(). ' + (rows || []).length +
              ' PEP(s).');
    const work = (rows || []).map(function (row) {
      return self.nudge(row.notifyUrl, issuer).then(function (result) {
        if (typeof record === 'function') {
          record(row.name, result.why);
        }
        return { name: row.name, ok: result.ok, status: result.status,
                 why: result.why };
      });
    });
    log.debug('Leaving PepNotifier.nudgeAll(). Dispatched.');
    return Promise.all(work);
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PepNotifier>(
  'xacml/xacml_pep_http',
  () => new PepNotifier(PepNotifier.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  PepNotifier: PepNotifier,
  installInstance: (instance: PepNotifier): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  MAX_BODY_BYTES: PepNotifier.MAX_BODY_BYTES,
  notifyAllowed: slot.forward('notifyAllowed'),
  transportSettings: slot.forward('transportSettings'),
  urlVerdict: slot.forward('urlVerdict'),
  NOTIFY_TRANSPORT: NOTIFY_TRANSPORT,
  allowedHosts: slot.forward('allowedHosts'),
  timeoutMs: slot.forward('timeoutMs'),
  urlProblem: slot.forward('urlProblem'),
  nudge: slot.forward('nudge'),
  nudgeAll: slot.forward('nudgeAll')
};
