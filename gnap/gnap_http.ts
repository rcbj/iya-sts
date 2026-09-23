'use strict';
//
// File: gnap_http.ts
//
// ---------------------------------------------------------------------------
// THE FIFTH OUTBOUND REQUEST IN THIS REPOSITORY: GNAP'S PUSH INTERACTION
// FINISH.
//
// RFC 9635 section 4.2.2: when a client asked to be told by `push` that
// interaction has finished, the AS "signals to the client instance that
// interaction is complete ... by sending an HTTP POST request to the client
// instance's callback URI", with `{ hash, interact_ref }` as JSON. That URI
// came from the CLIENT, in the grant request, which is the one thing root
// CLAUDE.md's row on outbound requests is careful about: this service does not
// dial a URL a caller supplied for it to fetch something FROM, and every URL it
// does dial is "an address somebody is asking to be SENT something at". A push
// finish URI is squarely the second kind — the client is naming where it wants
// the notification delivered — which is SSF push delivery's argument
// (`ssf/ssf_http.ts`) made again rather than cited.
//
// **SECTION 11.34 (SSRF) IS WHY THE BOUNDS BELOW EXIST**, and each is a bound
// the SSF transmitter already applies, read from GNAP's own settings so that
// turning one family's outbound traffic off does not silently turn off the
// other's:
//
//   1. **A switch.** `gnap.pushFinish` off refuses before any socket opens, and
//      discovery stops advertising `push`.
//   2. **The address is checked BEFORE it is dialled, in `gnap_grants.ts`**:
//      in product mode it must be a finish URI REGISTERED on the client's
//      application entry (`applications.returnAddressesOf()`, the same decision
//      every return address here goes through), and a sighting never registers
//      one.
//   3. **https, with the certificate verified** (#171): plain http only with
//      `gnap.pushAllowHttp` on — and in product mode only to a loopback
//      address, RFC 9635 section 2.5.2.1's exception and `STS-GNAP-0103`'s
//      rule; verification off only with `gnap.pushSkipTlsVerification`, and
//      only in development; a private CA through `gnap.pushCaFile`. The policy
//      is `common/outbound_tls.ts`'s, shared with SSF, federation and XACML.
//      Every insecure request is warned about. An optional host allowlist,
//      `gnap.pushAllowedHosts`.
//   4. **No redirects, a capped response, a timeout.** A 3xx is a failure — a
//      redirect is how an allowed host forwards the request somewhere that is
//      not — and nothing the client returns is read beyond its status.
//
// The result NEVER rejects: `{ ok, status, errorCode, why, url }`, because the
// caller has already answered the browser and the only honest thing to do with
// a failed push is record it — on the grant's history, on the audit log and on
// the monitor — which is what `gnap_grants.ts` does with this shape.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapHttp` takes the settings reader, the logger, the error-code
// table and the two transports through its constructor. The module still
// exports `urlProblem` and `pushFinish` as FACADES forwarding to the instance
// the composition root builds (#50, R2), for `gnap_grants.ts`, which requires
// it by those names. A process that loads this module without the root builds
// a default instance when the module loads.
// ---------------------------------------------------------------------------

import http = require('http');
import https = require('https');
import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import version = require('../common/version');
import OutboundTls = require('../common/outbound_tls');

// What a push answers. It never rejects.
interface PushResult {
  ok: boolean;
  status: number;
  errorCode?: string;
  why?: string;
  url?: string;
}

interface GnapHttpDeps {
  config: { value(key: string): any };
  log: {
    debug(message: string): void;
    warn(message: string): void;
  };
  errorCodes: { mark<T>(res: T, code: string): T };
  http: typeof http;
  https: typeof https;
}

const log = helpers.log;

const USER_AGENT = (function () {
  try {
    return version.userAgent('gnap-push-finish');
  } catch (e) {
    log.debug("Caught in a callback in module scope: " +
              ((e && e.message) || e));
    // The version record is never allowed to stop a request (root CLAUDE.md,
    // Versioning); a bare product token is the degraded answer.
    return 'sts (gnap-push-finish)';
  }
}());

const MAX_RESPONSE_BYTES = 64 * 1024;

// THE OUTBOUND TRANSPORT POLICY, as `common/outbound_tls.ts` takes it (#171).
// Plain http in product is admitted to loopback only — RFC 9635 section
// 2.5.2.1 — and a refusal of it is `STS-GNAP-0103`, the code the grant-time
// check already gives that same condition (one code per condition).
const PUSH_TRANSPORT = {
  what: 'a GNAP push interaction finish',
  allowHttpKey: 'gnap.pushAllowHttp',
  skipTlsKey: 'gnap.pushSkipTlsVerification',
  caFileKey: 'gnap.pushCaFile',
  loopbackHttpInProduct: true,
  httpRefusedCode: 'STS-GNAP-0103',
  skipIgnoredCode: 'STS-GNAP-0720'
};

class GnapHttp {
  static readonly USER_AGENT = USER_AGENT;
  static readonly MAX_RESPONSE_BYTES = MAX_RESPONSE_BYTES;

  constructor(private readonly deps: GnapHttpDeps) {
    deps.log.debug("Entering GnapHttp.constructor().");
    deps.log.debug("Leaving GnapHttp.constructor().");
  }

  private allowedHosts(): string[] {
    const { log, config } = this.deps;
    log.debug("Entering GnapHttp.allowedHosts().");
    const asked = config.value('gnap.pushAllowedHosts');
    const list: unknown[] = Array.isArray(asked) ? asked :
      String(asked || '').split(',');
    log.debug("Leaving GnapHttp.allowedHosts().");
    return list.map(function (one) {
      return String(one).trim().toLowerCase();
    }).filter(Boolean);
  }

  // A sentence, or '' when the URI may be dialled. Called at GRANT time as
  // well as at push time, so a finish URI that could never be dialled is
  // refused while the client is still there to be told (as
  // `invalid_interaction`), rather than after a person has approved a request
  // that can then never finish.
  urlProblem(raw: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapHttp.urlProblem().");
    log.debug("Leaving GnapHttp.urlProblem().");
    return this.urlVerdict(raw).why;
  }

  // The same answer with the code a product-mode refusal of plain http
  // carries (`STS-GNAP-0103`), '' for every other refusal — whose code is the
  // caller's (`STS-GNAP-0102` at grant time, `STS-GNAP-0601` at push time).
  urlVerdict(raw: unknown): { why: string; errorCode: string } {
    const { log } = this.deps;
    log.debug("Entering GnapHttp.urlVerdict().");
    let parsed: URL;
    try {
      parsed = new URL(String(raw || ''));
    } catch (e) {
      log.debug("Caught in GnapHttp.urlVerdict(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapHttp.urlVerdict(). Not a URL.");
      return { why: 'the push finish URI is not an absolute URL',
               errorCode: '' };
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      log.debug("Leaving GnapHttp.urlVerdict(). Scheme.");
      return { why: 'the push finish URI must be http(s); "' +
                    parsed.protocol + '" cannot be POSTed to',
               errorCode: '' };
    }
    if (parsed.protocol === 'http:') {
      const verdict = OutboundTls.httpVerdict(PUSH_TRANSPORT,
                                              parsed.hostname);
      if (!verdict.ok) {
        log.debug("Leaving GnapHttp.urlVerdict(). Plain http refused.");
        return { why: 'the push finish URI: ' + verdict.why,
                 errorCode: verdict.errorCode };
      }
    }
    const hosts = this.allowedHosts();
    if (hosts.length && hosts.indexOf(parsed.hostname.toLowerCase()) < 0) {
      log.debug("Leaving GnapHttp.urlVerdict(). Host not allowed.");
      return { why: 'the push finish URI\'s host ' + parsed.hostname +
                    ' is not in gnap.pushAllowedHosts',
               errorCode: '' };
    }
    log.debug("Leaving GnapHttp.urlVerdict(). Dialable.");
    return { why: '', errorCode: '' };
  }

  pushFinish(url: string, message: unknown): Promise<PushResult> {
    const { log, config, errorCodes, http, https } = this.deps;
    log.debug("Entering GnapHttp.pushFinish().");
    if (!config.value('gnap.pushFinish')) {
      log.debug("Leaving GnapHttp.pushFinish(). Switched off.");
      return Promise.resolve(errorCodes.mark({ ok: false, status: 0,
        errorCode: 'STS-GNAP-0600',
        why: 'gnap.pushFinish is off, so this service makes no outbound ' +
             'request.',
        url: url },
        'STS-GNAP-0600'));
    }
    const problem = this.urlVerdict(url);
    if (problem.why) {
      log.debug("Leaving GnapHttp.pushFinish(). " + problem.why);
      const code = problem.errorCode || 'STS-GNAP-0601';
      return Promise.resolve(errorCodes.mark({ ok: false, status: 0,
        errorCode: code,
        why: problem.why, url: url }, code));
    }
    const target = new URL(url);
    const secure = target.protocol === 'https:';
    if (!secure) {
      log.warn('gnap: pushing an interaction finish to ' + target.origin +
               ' over plain http because gnap.pushAllowHttp is ON. The ' +
               'interaction reference travels in clear.');
    }
    // The certificate IS checked unless development mode and
    // `gnap.pushSkipTlsVerification` both say otherwise: what travels is a
    // one-time interaction reference, and a client that can be impersonated
    // on the network is a grant that can be finished by somebody else (RFC
    // 9635 section 11.1).
    const transport = secure ? OutboundTls.tlsVerdict(PUSH_TRANSPORT,
                                                      target.origin) : null;
    if (transport && !transport.ok) {
      log.debug("Leaving GnapHttp.pushFinish(). " + transport.why);
      return Promise.resolve(errorCodes.mark({ ok: false, status: 0,
        errorCode: transport.errorCode,
        why: transport.why, url: url }, transport.errorCode));
    }
    const body = Buffer.from(JSON.stringify(message), 'utf8');
    const timeout = Number(config.value('gnap.pushTimeoutMs')) || 5000;
    log.debug("Leaving GnapHttp.pushFinish(). Dialling " + target.origin +
              ".");
    return new Promise(function (resolve) {
      let settled = false;
      const done = function (result: PushResult) {
        log.debug("Entering GnapHttp.pushFinish().done().");
        if (settled) {
          log.debug("Leaving GnapHttp.pushFinish().done().");
          return;
        }
        settled = true;
        if (!result.ok) {
          errorCodes.mark(result, result.errorCode);
        }
        resolve(Object.assign({ url: url }, result));
        log.debug("Leaving GnapHttp.pushFinish().done().");
      };
      let request: http.ClientRequest;
      const requestOptions: https.RequestOptions = {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (secure ? 443 : 80),
        path: target.pathname + target.search,
        method: 'POST',
        headers: { 'Content-Type': 'application/json',
                   'Content-Length': body.length,
                   'User-Agent': USER_AGENT },
        rejectUnauthorized: !transport || transport.rejectUnauthorized
      };
      if (transport && transport.ca) {
        requestOptions.ca = transport.ca;
      }
      try {
        request = (secure ? https : http).request(requestOptions,
                                                  function (response) {
          let received = 0;
          response.on('data', function (chunk) {
            received += chunk.length;
            if (received > MAX_RESPONSE_BYTES) {
              response.destroy();
            }
          });
          response.on('end', function () {
            const status = response.statusCode;
            if (status >= 300 && status < 400) {
              done({ ok: false, status: status, errorCode: 'STS-GNAP-0602',
                     why: 'the client answered the push with a redirect, ' +
                          'which is not followed' });
            } else if (status >= 200 && status < 300) {
              done({ ok: true, status: status });
            } else {
              done({ ok: false, status: status, errorCode: 'STS-GNAP-0603',
                     why: 'the client answered the push with HTTP ' +
                          status });
            }
          });
          response.on('error', function (error) {
            done({ ok: false, status: response.statusCode,
                   errorCode: 'STS-GNAP-0604',
                   why: 'the push response could not be read: ' +
                        error.message });
          });
        });
        request.setTimeout(timeout, function () {
          request.destroy(new Error('timed out after ' + timeout + 'ms'));
          done({ ok: false, status: 0, errorCode: 'STS-GNAP-0605',
                 why: 'the push timed out after ' + timeout + 'ms' });
        });
        request.on('error', function (error) {
          done({ ok: false, status: 0, errorCode: 'STS-GNAP-0604',
                 why: 'the push could not be delivered: ' + error.message });
        });
        request.end(body);
      } catch (e) {
        log.debug("Caught in GnapHttp.pushFinish(): " +
                  ((e && e.message) || e));
        done({ ok: false, status: 0, errorCode: 'STS-GNAP-0604',
               why: 'the push could not be started: ' + e.message });
      }
    });
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): GnapHttpDeps {
    helpers.log.debug("Entering GnapHttp.defaultDeps().");
    helpers.log.debug("Leaving GnapHttp.defaultDeps().");
    return {
      config: config,
      log: helpers.log,
      errorCodes: errorCodes,
      http: http,
      https: https
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
const slot = new InstanceSlot<GnapHttp>(
  'gnap/gnap_http',
  () => new GnapHttp(GnapHttp.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  GnapHttp: GnapHttp,
  installInstance: (instance: GnapHttp): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  urlProblem: slot.forward('urlProblem'),
  urlVerdict: slot.forward('urlVerdict'),
  PUSH_TRANSPORT: PUSH_TRANSPORT,
  pushFinish: slot.forward('pushFinish')
};
