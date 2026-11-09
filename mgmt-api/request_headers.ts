// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: request_headers.ts
//
// ---------------------------------------------------------------------------
// WHICH REQUEST HEADERS `/admin-api` TAKES (#1476, rcbj 2026-11-09).
//
// "If a spec defines it, then it would be allowed." A request header is
// accepted on an operation when any of these holds, and refused 400 with
// `STS-API-0144` otherwise:
//
//   1. the OpenAPI document declares it for that operation (`in: header`, in
//      the same `parameters` the query is held to, so there is no second list
//      of what an operation takes: `DPoP` is the one every operation declares,
//      added to each by `AdminApi.declareImplicitParameters()`);
//   2. it is a standard HTTP request header;
//   3. it is in a family a browser, a proxy, a CDN, a load balancer or a
//      tracing system adds, which the caller did not choose and could not
//      remove (`ADDED_IN_TRANSIT`, grouped by who adds it);
//   4. it is one of this service's own, set between its own processes
//      (`INTERNAL`). A worker sees those on a real request. The front process
//      deletes a caller's copy before forwarding, so accepting the name
//      admits nothing; `tests/admin_api_request_names.js` fails on an
//      `x-sts-` name in the source that is not listed here.
//
// FOR `/admin-api` ONLY. A protocol endpoint's headers are its specification's
// business and nothing here is consulted there.
//
// A LEAF (rule 3): it requires nothing of this service but `bunyan`, and it
// registers nothing.
// ---------------------------------------------------------------------------
import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-admin-api-headers' });

// A check's answer: `ok`, or the header and the sentence to refuse it with.
interface HeaderCheck {
  ok: boolean;
  header?: string;
  sentence?: string;
}

// A parameter as an OpenAPI operation declares it.
interface DeclaredParameter {
  name?: string;
  in?: string;
}

// How much of a header's name a refusal repeats.
const MAX_NAME_SAID = 128;

// HTTP's own request headers: RFC 9110 and RFC 9111 (semantics and caching),
// RFC 9112 and RFC 9113 (the connection's), the RFCs that added one (6265
// Cookie, 6454 Origin, 7240 Prefer, 7838 Alt-Used, 8470 Early-Data, 8586
// CDN-Loop, 8942 and 9218 Priority, 9421 HTTP signatures, 9530 digests), the
// CORS preflight's, and what browsers and older intermediaries still send.
const STANDARD: ReadonlySet<string> = new Set([
  'accept', 'accept-charset', 'accept-datetime', 'accept-encoding',
  'accept-language', 'accept-signature', 'access-control-request-headers',
  'access-control-request-method', 'access-control-request-private-network',
  'alt-used', 'authorization', 'cache-control', 'cdn-loop', 'connection',
  'content-digest', 'content-disposition', 'content-encoding',
  'content-language', 'content-length', 'content-location', 'content-md5',
  'content-range', 'content-type', 'cookie', 'date', 'device-memory', 'dnt',
  'downlink', 'dpr', 'early-data', 'ect', 'expect', 'from', 'host',
  'http2-settings', 'if-match', 'if-modified-since', 'if-none-match',
  'if-range', 'if-unmodified-since', 'keep-alive', 'link', 'max-forwards',
  'mime-version', 'origin', 'pragma', 'prefer', 'priority',
  'proxy-authorization', 'proxy-connection', 'purpose', 'range', 'referer',
  'repr-digest', 'rtt', 'save-data', 'service-worker', 'signature',
  'signature-input', 'te', 'timing-allow-origin', 'trailer',
  'transfer-encoding', 'upgrade', 'upgrade-insecure-requests', 'user-agent',
  'viewport-width', 'want-content-digest', 'want-repr-digest', 'warning',
  'width'
]);

// ---------------------------------------------------------------------------
// WHAT IS ADDED IN TRANSIT, BY WHO ADDS IT. A name ending in `*` is a family.
// Add a provider as a new group here; the CDN or load balancer in front of
// this service puts these on a request the caller wrote without them, so
// refusing one would refuse every request through that edge.
//
// VERIFIED AGAINST `deploy/` ON 2026-11-09: only AWS has an HTTP edge there.
// `deploy/aws/environment/cloudfront.tf` sets `X-Origin-Verify`,
// `X-Forwarded-Host` and `X-Forwarded-Proto` on the origin and forwards every
// viewer header (the AllViewer policy). `deploy/gcp/` and `deploy/azure/`
// front the nodes with network load balancers that add no header, and
// `deploy/multicloud/` is the private links between cells. EVERY OTHER NAME
// BELOW IS FROM THE PROVIDER'S DOCUMENTATION, for the edge those clouds would
// put in front of this service.
// ---------------------------------------------------------------------------
const ADDED_IN_TRANSIT: ReadonlyArray<{ by: string; names: string[] }> = [
  // RFC 7239, RFC 9110 section 7.6.3 and the de-facto proxy set.
  // `x-request-id` is what an ingress proxy or load balancer stamps on a
  // request to trace it. `x-requested-with` looks like its neighbour and is
  // not: a client sets that one, so it is refused like any custom header.
  { by: 'any proxy',
    names: ['forwarded', 'via', 'x-forwarded-*', 'x-real-ip',
            'x-request-id'] },
  // Fetch metadata and client hints: a browser's, and new ones arrive
  // without notice, so the family and never its members.
  { by: 'a browser', names: ['sec-*'] },
  // W3C Trace Context and Baggage.
  { by: 'a tracing system', names: ['traceparent', 'tracestate', 'baggage'] },
  // Mutual TLS ended at the edge, the headers `common/` reads a client
  // certificate from (`x-forwarded-client-cert` is in the proxy family and
  // `x-amzn-mtls-clientcert` in AWS's).
  { by: 'an edge ending mutual TLS',
    names: ['x-client-cert', 'x-ssl-client-*'] },
  // `x-origin-verify` is this deployment's own origin secret, set by the
  // distribution (`cloudfront.tf`, `common/client_address.js`).
  { by: 'AWS: CloudFront and the load balancers',
    names: ['cloudfront-*', 'x-amz-*', 'x-amzn-*', 'x-origin-verify'] },
  { by: 'Google Cloud: its load balancers and Cloud CDN',
    names: ['x-cloud-trace-context', 'x-goog-*'] },
  { by: 'Azure: Front Door, Application Gateway and App Service',
    names: ['x-appgw-*', 'x-arr-*', 'x-azure-*', 'x-fd-*', 'x-ms-*',
            'x-original-*'] }
];

// THIS SERVICE'S OWN, set by one of its processes for another: the front to
// a request worker (`common/request_pool.js`, `common/request_phases.js`,
// `tls/client_hello.ts`) and one cell to another (`common/cell_channel.ts`).
// NOT a family: `x-sts-anything` from a caller is exactly what is refused.
const INTERNAL: ReadonlySet<string> = new Set([
  'x-sts-cell-client', 'x-sts-cell-from', 'x-sts-cell-hops',
  'x-sts-cell-reason', 'x-sts-ldap-drop', 'x-sts-listener',
  'x-sts-peer-authorized', 'x-sts-peer-certificate', 'x-sts-pool-phases',
  'x-sts-pool-phases-wanted', 'x-sts-pool-protocol-worker',
  'x-sts-pool-ticket', 'x-sts-tls-client-hello'
]);

const EXACT: ReadonlySet<string> = new Set(
  ([] as string[]).concat(...ADDED_IN_TRANSIT.map(function (group) {
    return group.names.filter(function (name) {
      return !name.endsWith('*');
    });
  })));

const FAMILIES: ReadonlyArray<string> =
  ([] as string[]).concat(...ADDED_IN_TRANSIT.map(function (group) {
    return group.names.filter(function (name) {
      return name.endsWith('*');
    }).map(function (name) {
      return name.slice(0, -1);
    });
  }));

/**
 * The request headers `/admin-api` takes, and the refusal of any other.
 */
class AdminApiRequestHeaders {
  /**
   * Whether a header is accepted whatever the operation declares.
   *
   * @param name - the header's name, in any case
   * @returns true for a standard, in-transit or internal header
   */
  static accepted(name: string): boolean {
    log.debug("Entering AdminApiRequestHeaders.accepted().");
    const lower = String(name || '').toLowerCase();
    // HTTP/2's pseudo-headers arrive in node's `req.headers` (`:method`).
    const accepted = lower.charAt(0) === ':' || STANDARD.has(lower) ||
      EXACT.has(lower) || INTERNAL.has(lower) ||
      FAMILIES.some(function (prefix) {
        return lower.indexOf(prefix) === 0;
      });
    log.debug("Leaving AdminApiRequestHeaders.accepted(). " + accepted);
    return accepted;
  }

  /**
   * Checks a request's headers against what its operation declares. The
   * sentence names the header and never its value.
   *
   * @param parameters - the operation's parameters
   * @param headers - the request's headers
   * @returns `{ ok: true }`, or `{ ok: false, header, sentence }`
   */
  static check(parameters: DeclaredParameter[] | undefined,
               headers: any): HeaderCheck {
    log.debug("Entering AdminApiRequestHeaders.check().");
    const declared = new Set((parameters || []).filter(function (p) {
      return p && p.in === 'header' && p.name;
    }).map(function (p) {
      return String(p.name).toLowerCase();
    }));
    const names = Object.keys(headers || {});
    for (let i = 0; i < names.length; i++) {
      const lower = names[i].toLowerCase();
      if (declared.has(lower) || AdminApiRequestHeaders.accepted(lower)) {
        continue;
      }
      log.debug("Leaving AdminApiRequestHeaders.check(). Refused.");
      return { ok: false, header: lower,
               sentence: 'The request header ' +
                         JSON.stringify(lower.slice(0, MAX_NAME_SAID)) +
                         ' is not one this operation takes: it is not ' +
                         'declared in the OpenAPI document and no ' +
                         'specification defines it.' };
    }
    log.debug("Leaving AdminApiRequestHeaders.check(). Accepted.");
    return { ok: true };
  }
}

export = AdminApiRequestHeaders;
