// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// 3. **https ONLY, WITH THE PEP'S CERTIFICATE VERIFIED, ALWAYS.** What
//    travels here is weaker than what travels on either of the other two —
//    no credential and no event — and it is still held to TLS, because a
//    request this service makes in the clear is a request somebody else can
//    answer for, and a PEP that acted on a forged nudge would pull from
//    wherever it was told to pull from. What protects it is that the PEP
//    holds the PDP's address itself and a nudge cannot change it; what TLS
//    protects is the rest.
//
//    **SINCE 2026-11-14 (rcbj: "Let's assume always HTTPS") THERE IS NO
//    PLAIN-HTTP NUDGE AND NO UNVERIFIED ONE, IN EITHER MODE.** An `http://`
//    notify URL is reported unusable with a short reason (`STS-XACML-0259`
//    when one is refused at dialling) and the PEP converges by polling, as a
//    PEP with no notify URL always has. The two settings #171 gave the
//    escape — `xacml.pepNotifyAllowHttp` and
//    `xacml.pepNotifySkipTlsVerification` — are RETIRED, not removed: a
//    deployment that names either still starts, the value is ignored, and
//    the first nudge that would have read it says so once per process
//    (`STS-XACML-0258`). That is the backwards-compatible half; the
//    secure half is that nothing it says reaches the wire.
//
//    **AND IT VERIFIES WITH NO SETTING AT ALL.** A PEP's HTTPS listener
//    certificate is issued by the `pep-tls` Issuing CA of the realm it
//    registered to (`xacml_pep_tls.ts`, the issue and the CSR paths), so a
//    nudge is verified against THAT CHAIN by default — the realm's `pep-tls`
//    Issuing CA, its Intermediate and the service Root — with the host
//    checked against the notify URL's host (RFC 9525, the outbound host
//    check). **A LEAF THAT CHAINS TO THIS SERVICE'S ROOT MUST HAVE BEEN
//    ISSUED BY THIS REALM'S `pep-tls` CA** (`pinProblem()`,
//    `STS-XACML-0260`): the Root also vouches for every other Issuing CA of
//    every realm, and a custom listener's certificate or another realm's
//    PEP's is not "a PEP of this realm". `xacml.pepNotifyCaFile` stays as an
//    ADDITIONAL anchor, for a PEP whose listener certificate comes from
//    elsewhere, beside node's own store, as it always was; an unusable file
//    still refuses the nudge (`STS-CORE-0104`). Under paranoid PKI mode the
//    handshake is held by the door's `tls-server-outbound` purpose like every
//    other outbound connection (rule 3dd), which already names this nudge.
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
// Whether the User-Agent may name the build (#2142). A leaf of this module.
import mode = require('../common/mode');
import OutboundTls = require('../common/outbound_tls');
// The realm's `pep-tls` chain, the default trust of a nudge (2026-11-14). A
// LIBRARY (rule 3w) that registers no route and requires nothing here.
import pki = require('../common/pki');
// The one place this service parses a certificate (#453), for the pin.
import stsCrypto = require('../common/crypto');

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
  // The realm's `pep-tls` Issuing CA with the Intermediate and Root above
  // it, or null (`pki.useCaseChainPems()`).
  pepTlsChain(): { issuing: string; intermediate: string; root: string } |
    null;
  // Built once at require time: the version cannot change while the process
  // runs. See the comment on the headers block in `nudge()` for why the nudge
  // carries one at all.
  userAgent: string;
  // The `pdp` member of the body (#1830): the base this realm's PDP is
  // reached at, '' when it cannot be known. `nudge()` argues it.
  pdpIdentity(): string;
}

/**
 * The path every remote PEP's base URL (`PEP_PDP_URL`) is the base of: the
 * pull, whose hosted application the `pdp` member's base is that of.
 */
const PDP_PULL_PATH = '/xacml/pep/policies';

// A PEP that answers a nudge with more than this is not answering a nudge. The
// expected reply is 204 with nothing in it; 16 KiB is generous for the error
// object a broken one might send and is still a bound.
/**
 * The most of a PEP's reply to a nudge that is read: 16 KiB.
 */
const MAX_BODY_BYTES = 16 * 1024;

// THE OUTBOUND TRANSPORT SETTINGS, as `common/outbound_tls.ts` names a
// family's (#171). KEPT, and still exported, for what reads its names — the
// CA file is `caFileKey` — but the nudge no longer asks `httpVerdict()` or
// `tlsVerdict()`: plain http is refused and verification is never skipped
// (2026-11-14), so the two settings those would read are RETIRED (below).
/**
 * The nudge's transport settings in `common/outbound_tls.ts`'s shape. Since
 * 2026-11-14 only `caFileKey` is in force: the other two settings are
 * retired and ignored.
 */
const NOTIFY_TRANSPORT = {
  what: 'an XACML PEP nudge',
  allowHttpKey: 'xacml.pepNotifyAllowHttp',
  skipTlsKey: 'xacml.pepNotifySkipTlsVerification',
  caFileKey: 'xacml.pepNotifyCaFile',
  loopbackHttpInProduct: false,
  httpRefusedCode: 'STS-XACML-0073',
  skipIgnoredCode: 'STS-XACML-0074'
};

// THE TWO RETIRED SETTINGS (2026-11-14). Accepted wherever a setting is
// accepted — an appconfig file, the environment, a stored override — so a
// deployment that named one still starts, and IGNORED: a nudge is https and
// verified whatever they say. Said once per process per setting, with
// `STS-XACML-0258`, the first time a nudge would have read it.
const RETIRED_SETTINGS = ['xacml.pepNotifyAllowHttp',
                          'xacml.pepNotifySkipTlsVerification'];
const RETIRED_CODE = 'STS-XACML-0258';
const HTTP_REFUSED_CODE = 'STS-XACML-0259';
const PIN_REFUSED_CODE = 'STS-XACML-0260';
const announcedRetired = new Set<string>();

/**
 * Sends the "the repository changed, pull now" nudge to a remote PEP's
 * notify URL, within four bounds: a switch, a host allowlist, https with the
 * certificate verified, and no redirects with a capped body and a timeout.
 *
 * The nudge is never the mechanism: a PEP pulls on its own interval, so a
 * failed nudge costs one polling interval and is recorded, never retried.
 */
class PepNotifier {
  /**
   * The most of a PEP's reply to a nudge that is read: 16 KiB.
   */
  static readonly MAX_BODY_BYTES = MAX_BODY_BYTES;

  /**
   * Builds the notifier over the given dependencies.
   * @param deps - the settings, logger, audit log, node's two transports and
   * the User-Agent string
   */
  constructor(private readonly deps: PepNotifierDeps) {
    deps.log.debug('Entering PepNotifier.constructor().');
    deps.log.debug('Leaving PepNotifier.constructor().');
  }

  // What the composition root passes, from the real modules.
  /**
   * Returns the dependencies built from the real modules, for the default
   * instance.
   * @returns the notifier's dependencies
   */
  static defaultDeps(): PepNotifierDeps {
    helpers.log.debug("Entering PepNotifier.defaultDeps().");
    helpers.log.debug("Leaving PepNotifier.defaultDeps().");
    return {
      config: config,
      log: helpers.log,
      audit: audit,
      http: http,
      https: https,
      pepTlsChain: function () {
        helpers.log.debug("Entering pepTlsChain().");
        helpers.log.debug("Leaving pepTlsChain().");
        return pki.useCaseChainPems('', 'pep-tls');
      },
      // ASKED PER REQUEST (#2142): product leaves the build out, and the
      // mode is per realm and may change while the process runs.
      get userAgent(): string {
        helpers.log.debug("Entering PepNotifier.defaultDeps().userAgent.");
        const out = version.userAgent('xacml-pdp-notify',
          mode.publishesBuildDetail());
        helpers.log.debug("Leaving PepNotifier.defaultDeps().userAgent.");
        return out;
      },
      pdpIdentity: function () {
        helpers.log.debug("Entering pdpIdentity().");
        // The base `/xacml/pep/*` is served under in this realm: pinned
        // where the listener or `global.publicBaseUrl` pins it, else the
        // base the request that made the change was answered under, moved
        // to the PDP's application (`helpers.urlOf()`) — the rule every URL
        // this service builds follows. Nothing pinned and no request is ''.
        const url = helpers.urlOf(audit.currentRequest(), PDP_PULL_PATH);
        helpers.log.debug("Leaving pdpIdentity().");
        return /^https?:\/\//i.test(url)
          ? url.slice(0, url.length - PDP_PULL_PATH.length) : '';
      }
    };
  }

  /**
   * Tells whether nudges are sent at all (`xacml.pepNotify`).
   * @returns true when `xacml.pepNotify` is on
   */
  notifyAllowed(): boolean {
    const { log, config } = this.deps;
    log.debug('Entering PepNotifier.notifyAllowed().');
    const on = !!config.value('xacml.pepNotify');
    log.debug('Leaving PepNotifier.notifyAllowed(). ' + on);
    return on;
  }

  // The three transport settings as they are IN FORCE in this realm (#171),
  // in the shape `GET /admin-api/xacml/peps`' `notify.transport` has always
  // answered. Since 2026-11-14 the first two are false whatever is stored —
  // plain http and an unverified nudge do not exist — and
  // `skipTlsVerificationSet` still says whether a stored value names the
  // retired skip, so a reader can see it is set and ignored.
  /**
   * Describes the three transport settings as they are in force in this
   * realm: plain http and skipped verification are never in force.
   * @returns `{ allowHttp, skipTlsVerification, skipTlsVerificationSet,
   *   caFile }`
   */
  transportSettings(): ReturnType<typeof OutboundTls.describe> {
    const { log, config } = this.deps;
    log.debug('Entering PepNotifier.transportSettings().');
    log.debug('Leaving PepNotifier.transportSettings().');
    return {
      allowHttp: false,
      skipTlsVerification: false,
      skipTlsVerificationSet:
        !!config.value(NOTIFY_TRANSPORT.skipTlsKey),
      caFile: String(config.value(NOTIFY_TRANSPORT.caFileKey) || '')
    };
  }

  // A RETIRED SETTING THAT IS ON IS SAID ONCE PER PROCESS (2026-11-14), the
  // first time a nudge would have read it, and changes nothing.
  private announceRetired(): void {
    const { log, config } = this.deps;
    log.debug('Entering PepNotifier.announceRetired().');
    RETIRED_SETTINGS.forEach(function (key) {
      if (!config.value(key) || announcedRetired.has(key)) {
        return;
      }
      announcedRetired.add(key);
      log.warn(errorCodes.tag(RETIRED_CODE) + 'xacml: ' + key + ' is on ' +
               'and is IGNORED: it was retired on 2026-11-14, and a nudge ' +
               'is sent over https with the PEP\'s certificate verified, in ' +
               'every mode. A PEP whose notify URL is http converges by ' +
               'polling. Remove the setting to silence this; said once per ' +
               'process.');
    });
    log.debug('Leaving PepNotifier.announceRetired().');
  }

  // -------------------------------------------------------------------------
  // THE PIN (2026-11-14). A chain node verified that runs through THIS
  // SERVICE'S Root must have been issued, at the leaf, by this realm's
  // `pep-tls` Issuing CA. A chain that reaches some other anchor — the CA
  // file, node's store — is not this service's to judge further: the
  // operator named that anchor, and the host check has already been made.
  // Compared by SHA-256 fingerprint, the certificate itself, never by name:
  // every realm's `pep-tls` CA has the same subject.
  // -------------------------------------------------------------------------
  /**
   * Says why a verified chain is refused for a nudge: one that reaches this
   * service's Root but whose leaf was not issued by the realm's `pep-tls`
   * Issuing CA.
   * @param cert - the peer certificate node verified, with its chain
   * @param chain - the realm's `pep-tls` chain, or null
   * @returns a sentence, or '' when the chain may be used
   */
  static pinProblem(cert: any,
                    chain: { issuing: string; root: string } | null): string {
    helpers.log.debug('Entering PepNotifier.pinProblem().');
    if (!chain) {
      helpers.log.debug('Leaving PepNotifier.pinProblem(). No realm chain.');
      return '';
    }
    let rootPrint = '';
    let issuingPrint = '';
    try {
      rootPrint = stsCrypto.parseCertificate(chain.root).fingerprint256;
      issuingPrint = stsCrypto.parseCertificate(chain.issuing).fingerprint256;
    } catch (e) {
      helpers.log.debug('Caught in PepNotifier.pinProblem(): ' +
                        ((e && e.message) || e));
      // A tier node cannot read pins nothing; the chain it would have pinned
      // could not have verified through it either.
      return '';
    }
    const seen: string[] = [];
    let at = cert;
    for (let hop = 0; at && hop < 10; hop++) {
      seen.push(String(at.fingerprint256 || ''));
      if (!at.issuerCertificate || at.issuerCertificate === at) {
        break;
      }
      at = at.issuerCertificate;
    }
    if (seen.indexOf(rootPrint) < 0) {
      helpers.log.debug('Leaving PepNotifier.pinProblem(). Another anchor.');
      return '';
    }
    const issuer = cert && cert.issuerCertificate;
    if (issuer && String(issuer.fingerprint256 || '') === issuingPrint) {
      helpers.log.debug('Leaving PepNotifier.pinProblem(). This realm\'s.');
      return '';
    }
    helpers.log.debug('Leaving PepNotifier.pinProblem(). Refused.');
    return 'the certificate chains to this service\'s Root but was not ' +
      'issued by this realm\'s Remote PEP listeners (pep-tls) Issuing CA';
  }

  // THE TRUST FOR ONE NUDGE: node's store, this realm's `pep-tls` chain and
  // the CA file, the RFC 9525 host check and the path rules, then the pin.
  // A CA file that cannot be used refuses (`STS-CORE-0104`), as before.
  private trust(origin: string): { ok: boolean; why: string;
                                   options: Record<string, unknown> } {
    const { log, config } = this.deps;
    log.debug('Entering PepNotifier.trust(). ' + origin);
    const chain = this.deps.pepTlsChain();
    const anchors: string[] = chain
      ? [chain.issuing, chain.intermediate, chain.root] : [];
    const file = String(config.value(NOTIFY_TRANSPORT.caFileKey) || '');
    if (file) {
      const pems = OutboundTls.caFilePems(file);
      if (typeof pems === 'string') {
        log.warn(errorCodes.tag(OutboundTls.CA_FILE_CODE) + 'outbound: ' +
                 NOTIFY_TRANSPORT.what + ' to ' + origin + ' was not sent: ' +
                 pems);
        log.debug('Leaving PepNotifier.trust(). The CA file is unusable.');
        return { ok: false, options: {},
                 why: NOTIFY_TRANSPORT.caFileKey + ' names "' + file +
                      '", and ' + pems };
      }
      pems.forEach(function (pem) {
        anchors.push(pem);
      });
    }
    const verified: any = OutboundTls.verifiedOptions(anchors);
    const hostCheck = verified.checkServerIdentity;
    verified.checkServerIdentity = function (host: string, cert: any) {
      const problem = hostCheck(host, cert);
      if (problem) {
        return problem;
      }
      const pinned = PepNotifier.pinProblem(cert, chain);
      if (!pinned) {
        return undefined;
      }
      log.warn(errorCodes.tag(PIN_REFUSED_CODE) + 'xacml: a nudge to ' +
               host + ' was refused before anything was sent: ' + pinned +
               '.');
      return Object.assign(new Error('the PEP\'s certificate is refused: ' +
                                     pinned),
                           { code: 'ERR_STS_PEP_TLS_PIN' });
    };
    log.debug('Leaving PepNotifier.trust(). ' + anchors.length +
              ' anchor(s) beside node\'s store.');
    return { ok: true, why: '', options: verified };
  }

  /**
   * Returns the nudge's timeout (`xacml.pepNotifyTimeoutMs`).
   * @returns the timeout in milliseconds
   */
  timeoutMs(): number {
    const { log, config } = this.deps;
    log.debug('Entering PepNotifier.timeoutMs().');
    const value = config.value('xacml.pepNotifyTimeoutMs');
    log.debug('Leaving PepNotifier.timeoutMs(). ' + value);
    return value;
  }

  // The allowlist as lower-case host names. Empty means ANY, which is the
  // default and the one deliberate looseness here — see bound 2.
  /**
   * Returns the host allowlist (`xacml.pepNotifyAllowedHosts`) as lower-case
   * host names; empty means any host.
   * @returns the allowed host names
   */
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
  /**
   * Says why a notify URL would be refused, without dialling anything.
   * @param raw - the notify URL
   * @returns the reason, or null when the URL is fine
   */
  urlProblem(raw: unknown): string | null {
    const { log } = this.deps;
    log.debug('Entering PepNotifier.urlProblem().');
    log.debug('Leaving PepNotifier.urlProblem().');
    return this.urlVerdict(raw).why || null;
  }

  // The same answer with `STS-XACML-0259` when the refusal is plain http
  // (since 2026-11-14, every mode), and '' for every other (whose code is
  // STS-XACML-0066).
  /**
   * Says why a notify URL would be refused, with the error code when the
   * refusal is plain http (`STS-XACML-0259`, in every mode since
   * 2026-11-14).
   *
   * An absent URL is refused with a note that it is not a fault.
   * @param raw - the notify URL
   * @returns `{ why, errorCode }`: `why` '' when fine, `errorCode`
   * `STS-XACML-0259` for plain http refused and '' otherwise
   */
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
      return { why: 'A notify URL is https; this one is "' +
               parsed.protocol.replace(/:$/, '') + '".', errorCode: '' };
    }
    if (parsed.protocol === 'http:') {
      // ALWAYS REFUSED (2026-11-14), in both modes: the retired
      // `xacml.pepNotifyAllowHttp` is not read. Short, because the console
      // draws it as the row's reason; the PEP still converges by polling.
      this.announceRetired();
      log.debug('Leaving PepNotifier.urlVerdict(). Plain http refused.');
      return { why: 'This notify URL is plain http, and a nudge is sent ' +
               'over https only: register the PEP\'s HTTPS notify URL, ' +
               'https://<host>:<PEP_HTTPS_PORT>/notify. Until then it ' +
               'converges by polling.',
               errorCode: HTTP_REFUSED_CODE };
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

  /**
   * Posts the three-member nudge (event, time and the PDP's issuer) to one
   * notify URL.
   *
   * It resolves and never rejects; a nudge refused before dialling is
   * recorded on the audit log.
   * @param url - the PEP's notify URL
   * @param issuer - the PDP's identifier, carried as `pdp` in the body;
   *   empty asks `pdpIdentity()` for this realm's (#1830)
   * @param options - `{ full: true }` asks the PEP to pull every document
   *   whole (a Sync from the console, 2026-11-16)
   * @returns a promise of `{ ok, status, why }`
   */
  nudge(url: unknown, issuer?: unknown,
        options?: { full?: boolean }): Promise<NudgeResult> {
    const self = this;
    const { log, https, userAgent } = this.deps;
    log.debug('Entering PepNotifier.nudge(). url=' + url);
    const full = !!(options && options.full);
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
        if (problem.errorCode === HTTP_REFUSED_CODE) {
          self.recordUndelivered(HTTP_REFUSED_CODE, '',
                                 'A change nudge was not sent: the PEP\'s ' +
                                 'notify URL is plain http, and a nudge is ' +
                                 'sent over https only.');
        } else {
          self.recordUndelivered('STS-XACML-0066', '',
                                 'A change nudge was not sent: ' +
                                 'the PEP\'s notify URL is outside this ' +
                                 'service\'s outbound bounds.');
        }
        resolve({ ok: false, status: 0, why: problem.why });
        return;
      }
      self.announceRetired();
      const parsed = new URL(String(url));
      // The certificate policy (2026-11-14): this realm's `pep-tls` chain,
      // node's store and `xacml.pepNotifyCaFile`, ALWAYS verified, with the
      // host check and the pin. The retired skip is not read.
      const policy = self.trust(parsed.origin);
      if (!policy.ok) {
        log.debug('Leaving nudge(). ' + policy.why);
        self.recordUndelivered('STS-CORE-0104', parsed.origin,
                               'A change nudge was not sent: the CA file ' +
                               'xacml.pepNotifyCaFile names cannot be used.');
        resolve({ ok: false, status: 0, why: policy.why });
        return;
      }
      // `full` (2026-11-16) is a Sync's: the PEP pulls every document whole
      // rather than being answered 304. It carries no content, so the
      // nudge is still never the mechanism; a PEP that does not read it
      // pulls as it always did.
      // `pdp` IS THIS REALM'S PDP (#1830): the base the PEP's own
      // `PEP_PDP_URL` names, realm prefix included, so a receiver can tell
      // which PDP — and which realm of it — is asking. Every caller passed
      // '' until then, so the member was always empty. An explicit issuer
      // still wins; '' asks `pdpIdentity()`, which is '' only with nothing
      // pinned and no request in hand. The PEP reads none of it.
      const fields: Record<string, unknown> = {
        event: 'policy-repository-changed',
        at: new Date().toISOString(),
        pdp: String(issuer || self.deps.pdpIdentity() || '')
      };
      if (full) {
        fields.full = true;
      }
      const body = JSON.stringify(fields);
      const transport = https;
      const request = transport.request(Object.assign({
        method: 'POST',
        hostname: parsed.hostname,
        port: parsed.port || 443,
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
        timeout: self.timeoutMs()
      // Verification ON, the anchors above beside node's store, the RFC 9525
      // host check with the path rules (#201), and the pin.
      }, policy.options),
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
  /**
   * Nudges every given PEP registration, concurrently.
   * @param rows - the PEP registrations, each with a `name` and `notifyUrl`
   * @param issuer - the PDP's identifier, carried in each body
   * @param record - called with each PEP's name and the result's `why`
   * @returns a promise of `{ name, ok, status, why }` per PEP
   */
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

/**
 * The nudge a remote XACML PEP is sent when the policy repository changes:
 * the third outbound request in this repository, and the weakest case.
 *
 * A library: it registers no route. The functions forward to the instance
 * the composition root installs.
 * @namespace
 */
export = {
  PepNotifier: PepNotifier,
  pinProblem: PepNotifier.pinProblem,
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
