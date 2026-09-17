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
// import, a registered RFC 9101 `request_uri` — each argue their own case; the
// root CLAUDE.md's non-goal index lists them):
//
//   * `oauthJwksUri` on an application entry is RECORDED AND NEVER FETCHED.
//     `applications.js`'s schema row says why: following it would mean this
//     service making an outbound request to a URL somebody registered in order
//     to verify a credential, "which is a server-side request forgery with a
//     specification citation attached".
//   * WS-Federation's `wreqptr` gets the same refusal in `wsfed.ts`, and
//     `client_auth.js` says holding that position in one file and not the other
//     would be no position at all.
//
// BOTH OF THOSE STAND, UNCHANGED, AND THIS FILE DOES NOT CONTRADICT THEM. The
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
// ---------------------------------------------------------------------------
// FIVE MORE THINGS ARE ENFORCED HERE, AND EACH IS A DIFFERENT FAILURE.
//
// 1. **`federation.outbound` TURNS IT ALL OFF.** A deployment with no egress
//    sets it and nothing here dials anything. The refusal names the setting, so
//    somebody watching a federated sign-in fail in an air-gapped test knows
//    within one line why.
//
// 2. **https ONLY, unless `federation.outboundAllowInsecure` says otherwise.**
//    What travels on these requests is a client secret and an authorization
//    code, at somebody ELSE'S service — this is the one place in this
//    repository where a credential leaves the process, and it is the one place
//    this service is stricter than a mock would ordinarily be. `allowInsecure`
//    exists because federating against another mock on localhost is the
//    ordinary development case, and every request made under it is LOGGED as
//    insecure rather than only the setting being logged once: a certificate
//    check disabled six months ago and forgotten is the worst kind of leftover.
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
// `config.js`, `error_codes.js` and `version.js` — plus node's own `https`,
// `http` and `url` — so it cannot join a cycle. `federation.js` is NOT
// required from here, deliberately: this module is handed a relationship
// record and reads two attributes off it, which keeps the dependency pointing
// one way and lets a test drive this file with a plain object.
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
import config = require('./../common/config');
import helpers = require('./../common/helpers');
import InstanceSlot = require('./../common/instance_slot');
// THE ERROR CODES. Every way a request fails carries its code as `errorCode` on
// the result, and `federation_sp.ts` marks the refusal page's response with it
// — the result object itself is never sent to anybody. A leaf, so no cycle.
import errorCodes = require('./../common/error_codes');
import version = require('./../common/version');

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
}

class FederationHttp {
  static readonly DIALLABLE = DIALLABLE;

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
      userAgent: USER_AGENT
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

  allowInsecure(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering FederationHttp.allowInsecure().");
    log.debug("Leaving FederationHttp.allowInsecure().");
    return !!config.value('federation.outboundAllowInsecure');
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
    const text = String(raw || '').trim();
    if (!text) {
      log.debug("Leaving FederationHttp.urlProblem(). Empty.");
      return 'there is no URL configured for it';
    }
    let parsed = null;
    try {
      parsed = new URL(text);
    } catch (e) {
      log.debug("Caught in FederationHttp.urlProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving FederationHttp.urlProblem(). It will not parse.");
      return '"' + text + '" is not a URL (' + e.message + ')';
    }
    if (parsed.protocol === 'https:') {
      log.debug("Leaving FederationHttp.urlProblem(). https, fine.");
      return '';
    }
    if (parsed.protocol === 'http:') {
      if (this.allowInsecure()) {
        log.debug("Leaving FederationHttp.urlProblem(). http, allowed by " +
                  'setting.');
        return '';
      }
      log.debug("Leaving FederationHttp.urlProblem(). http, refused.");
      return 'it is an http:// URL and federation.outboundAllowInsecure is ' +
             'off. A client secret and an authorization code travel on this ' +
             'request, so plain http is refused unless that setting says ' +
             'otherwise';
    }
    log.debug("Leaving FederationHttp.urlProblem(). Wrong scheme.");
    return 'its scheme is "' + parsed.protocol.replace(':', '') + '", and ' +
           'only https (or http, with federation.outboundAllowInsecure on) ' +
           'is dialled';
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
    const problem = this.urlProblem(raw);
    if (problem) {
      log.debug("Leaving FederationHttp.fetchJson(). " + problem);
      log.debug("Leaving FederationHttp.fetchJson().");
      return Promise.resolve({ ok: false, status: 0, json: null, text: '',
                               url: raw,
                               errorCode: 'STS-FED-0048',
                               why: attribute + ' cannot be dialled: ' +
                                    problem });
    }

    const target = new URL(raw);
    const secure = target.protocol === 'https:';
    if (!secure) {
      // Every insecure request, not just the setting. See the header.
      log.warn('federation: dialling ' + target.origin + ' over plain http ' +
               'for ' + id +
               ' because federation.outboundAllowInsecure is ON. A client ' +
               'secret and an authorization code travel on this request.');
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
        request = transport.request({
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
          // is the secret in the Authorization header. `allowInsecure` turns
          // it off for localhost work and is warned about above.
          rejectUnauthorized: secure && !this.allowInsecure()
        }, function (response) {
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
                       ? '. Set federation.outboundAllowInsecure to dial a ' +
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
  maxBodyBytes: slot.forward('maxBodyBytes'),
  urlProblem: slot.forward('urlProblem'),
  fetchJson: slot.forward('fetchJson'),
  outboundAllowed: slot.forward('outboundAllowed'),
  allowInsecure: slot.forward('allowInsecure')
};
