// @ts-check
'use strict';
//
// File: common/client_address.js
//
// ===========================================================================
// WHO A REQUEST CAME FROM, AND WHICH HOPS MAY SAY SO (2026-09-14, #46 section
// 8).
//
// Three readers ask this service where a request came from — the rate
// limiter's address bucket, the request pool telling a worker, and
// `baseUrlOf()` deciding whether `X-Forwarded-Proto` and `X-Forwarded-Host`
// are believed — and until this file each had one switch, `global.trustProxy`,
// with two failures on either side of it:
//
//   * **ON, IT BELIEVED ANYBODY.** A forwarded header is an ordinary header a
//     client can set, so with the setting on, a caller who reached a node
//     DIRECTLY — past the load balancer, on the container network — chose its
//     own rate-limit address per request (a fresh bucket per guess) and chose
//     what this service believed its own issuer was. And the limiter read the
//     LEFT-MOST `X-Forwarded-For` entry, which is the one a client writes
//     itself: every proxy APPENDS, so the only entries worth anything are the
//     ones on the right that a proxy you run put there.
//   * **DISPATCHED, IT LOST THE CLIENT ENTIRELY.** A request worker is reached
//     over a unix socket, whose `remoteAddress` is `undefined`, and the limiter
//     read the socket whenever the setting was off — so in the request-worker
//     pool EVERY caller shared the one address bucket `unknown`, which the
//     comment in `request_pool.js` believed it had prevented by writing
//     `X-Forwarded-For` (measured 2026-09-14: `remoteAddress` on a unix-socket
//     request is `undefined`). With the setting on, the worker read the header
//     the front process wrote from `req.ip`, which behind a load balancer is
//     the balancer — one bucket again.
//
// `global.trustedProxies` is the boundary. EMPTY — the default — keeps the old
// rule exactly (the setting alone decides, believed from anybody), so nothing
// that runs today changes. SET to the CIDRs a deployment's proxies live in,
// the forwarded headers are believed only when the connection's own peer is
// one of them, and the client is the RIGHT-MOST `X-Forwarded-For` entry that is
// not one of them. A request worker believes what the front process wrote,
// always: the unix socket it listens on is reachable by nothing else
// (`request_worker.js` argues that), and the front process writes ONE address,
// the one it resolved here.
//
// **WHAT THIS IS NOT.** It does not read a client certificate from a header
// and never will (`global.trustProxy`'s own description): mutual TLS behind a
// load balancer needs L4 passthrough, `common/CLAUDE.md` says how. And it does
// not speak the PROXY protocol — `common/proxy_protocol.js` does, below this
// file: it puts the header's client address on the SOCKET, so the peer this
// file reads is already the client's and the balancer is never a hop here.
//
// A LEAF (rule 3): it registers no route and requires only `net`, bunyan and
// `config`, so `helpers.js`, `websecurity.js`, `proxy_protocol.js` and
// `request_pool.js` — which loads before the protocol stack — can all require
// it.
// ===========================================================================

const net = require('net');
const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({ name: 'sts-client-address' });
config.registerLogger(log);

const IS_REQUEST_WORKER = !!process.env.STS_REQUEST_WORKER;

// The parsed ranges, rebuilt only when the setting's text changes — it is
// runtime, and a BlockList per request would be a parse per request.
let cachedText = null;
let cached = null;

// `::ffff:10.0.0.1` is an IPv4 client on a dual-stack socket, and a range
// written `10.0.0.0/8` must match it.
function normalise(address) {
  log.debug("Entering normalise().");
  const text = String(address || '').trim();
  log.debug("Leaving normalise().");
  return /^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(text) ? text.slice(7) : text;
}

function familyOf(address) {
  log.debug("Entering familyOf().");
  const kind = net.isIP(address);
  log.debug("Leaving familyOf().");
  return kind === 4 ? 'ipv4' : (kind === 6 ? 'ipv6' : '');
}

function rangesText() {
  log.debug("Entering rangesText().");
  const raw = config.value('global.trustedProxies');
  log.debug("Leaving rangesText().");
  return (Array.isArray(raw) ? raw : String(raw || '').split(','))
    .map(function (one) { return String(one).trim(); })
    .filter(Boolean);
}

// `{ list: BlockList, count }` for the configured ranges. A value that is not
// an address or a CIDR is IGNORED AND LOGGED, never widened: a typo must not
// turn into "trust everybody".
function ranges() {
  log.debug("Entering ranges().");
  const entries = rangesText();
  const text = entries.join(',');
  if (text === cachedText && cached) {
    log.debug("Leaving ranges(). Cached.");
    return cached;
  }
  const list = new net.BlockList();
  let count = 0;
  entries.forEach(function (entry) {
    const slash = entry.indexOf('/');
    const address = normalise(slash >= 0 ? entry.slice(0, slash) : entry);
    const family = familyOf(address);
    const bits = slash >= 0 ? Number(entry.slice(slash + 1))
      : (family === 'ipv4' ? 32 : 128);
    const max = family === 'ipv4' ? 32 : 128;
    if (!family || !Number.isInteger(bits) || bits < 0 || bits > max) {
      log.warn('client_address: "' + entry + '" in global.trustedProxies is ' +
               'not an address or a CIDR range and is ignored.');
      return;
    }
    try {
      list.addSubnet(address, bits, family);
      count += 1;
    } catch (e) {
      log.debug("Caught in ranges(): " + ((e && e.message) || e));
      log.warn('client_address: "' + entry + '" in global.trustedProxies ' +
               'could not be read (' + e.message + ') and is ignored.');
    }
  });
  cachedText = text;
  cached = { list: list, count: count, configured: entries.length };
  log.debug("Leaving ranges(). " + count + " range(s).");
  return cached;
}

function inRanges(address, theRanges) {
  log.debug("Entering inRanges().");
  const clean = normalise(address);
  const family = familyOf(clean);
  if (!family) {
    log.debug("Leaving inRanges(). Not an address.");
    return false;
  }
  log.debug("Leaving inRanges().");
  return theRanges.list.check(clean, family);
}

function peerOf(req) {
  log.debug("Entering peerOf().");
  const socket = (req && (req.socket || req.connection)) || {};
  log.debug("Leaving peerOf().");
  return normalise(socket.remoteAddress);
}

function forwardedFor(req) {
  log.debug("Entering forwardedFor().");
  const raw = String(((req && req.headers) || {})['x-forwarded-for'] || '');
  log.debug("Leaving forwardedFor().");
  return raw.split(',').map(function (one) {
    return normalise(one);
  }).filter(Boolean);
}

// A request that reached a request worker from its own front process: the
// worker's listener is a unix socket, which has no peer address. Nothing else
// can reach that socket.
function fromFrontProcess(req) {
  log.debug("Entering fromFrontProcess().");
  log.debug("Leaving fromFrontProcess().");
  return IS_REQUEST_WORKER && !peerOf(req);
}

// Is the connection's own peer one of the proxies this deployment runs?
// Always true when no range is configured — the pre-2026-09-14 rule, in which
// `global.trustProxy` alone decided.
function peerIsTrustedProxy(req) {
  log.debug("Entering peerIsTrustedProxy().");
  const theRanges = ranges();
  if (!theRanges.configured) {
    log.debug("Leaving peerIsTrustedProxy(). No ranges: the old rule.");
    return true;
  }
  log.debug("Leaving peerIsTrustedProxy().");
  return inRanges(peerOf(req), theRanges);
}

// ---------------------------------------------------------------------------
// THE SAME RANGES, ASKED ONE LAYER DOWN (2026-09-14):
// `common/proxy_protocol.js` believes a PROXY protocol header from these
// addresses and from nobody else.
// Unlike `peerIsTrustedProxy()`, an empty list trusts NOBODY here — the old
// rule that list keeps for forwarded headers would let any caller name any
// address, which is why that file refuses to start with none.
// ---------------------------------------------------------------------------
function trustedProxyRanges() {
  log.debug("Entering trustedProxyRanges().");
  const theRanges = ranges();
  log.debug("Leaving trustedProxyRanges().");
  return { count: theRanges.count, configured: theRanges.configured };
}

function isTrustedProxy(address) {
  log.debug("Entering isTrustedProxy().");
  const theRanges = ranges();
  if (!theRanges.count) {
    log.debug("Leaving isTrustedProxy(). No usable range.");
    return false;
  }
  log.debug("Leaving isTrustedProxy().");
  return inRanges(address, theRanges);
}

// May this request's X-Forwarded-* headers be believed at all?
function forwardedBelieved(req) {
  log.debug("Entering forwardedBelieved().");
  if (fromFrontProcess(req)) {
    log.debug("Leaving forwardedBelieved(). From the front process.");
    return true;
  }
  if (!config.value('global.trustProxy')) {
    log.debug("Leaving forwardedBelieved(). global.trustProxy is off.");
    return false;
  }
  log.debug("Leaving forwardedBelieved().");
  return peerIsTrustedProxy(req);
}

// ---------------------------------------------------------------------------
// THE CLIENT'S ADDRESS.
//
//   * in a request worker, what the front process wrote (one address);
//   * `global.trustProxy` off: the socket's peer;
//   * on, with no ranges: the LEFT-MOST forwarded entry — the old rule, kept
//     exactly, so a deployment that has not named its proxies sees nothing
//     move;
//   * on, with ranges, from a peer outside them: the peer, and the header is
//     ignored — a caller that reached the node directly;
//   * on, with ranges, from a trusted peer: walking from the RIGHT, the first
//     entry that is not a trusted proxy. Everything to its left was written
//     by the client or by a hop nobody vouches for.
// ---------------------------------------------------------------------------
function clientAddressOf(req) {
  log.debug("Entering clientAddressOf().");
  if (!req) {
    log.debug("Leaving clientAddressOf(). No request.");
    return 'unknown';
  }
  const peer = peerOf(req);
  const chain = forwardedFor(req);
  if (fromFrontProcess(req)) {
    log.debug("Leaving clientAddressOf(). As the front process resolved it.");
    return chain.length ? chain[chain.length - 1] : 'unknown';
  }
  if (!config.value('global.trustProxy')) {
    log.debug("Leaving clientAddressOf(). The socket.");
    return peer || 'unknown';
  }
  const theRanges = ranges();
  if (!theRanges.configured) {
    log.debug("Leaving clientAddressOf(). The old rule.");
    return chain[0] || peer || 'unknown';
  }
  if (!inRanges(peer, theRanges)) {
    log.debug("Leaving clientAddressOf(). An untrusted peer's header is " +
              "ignored.");
    return peer || 'unknown';
  }
  for (let i = chain.length - 1; i >= 0; i--) {
    if (!inRanges(chain[i], theRanges)) {
      log.debug("Leaving clientAddressOf(). Right-most untrusted hop.");
      return chain[i];
    }
  }
  log.debug("Leaving clientAddressOf(). Every hop is a trusted proxy.");
  return chain[0] || peer || 'unknown';
}

// For tests: forget the parsed ranges.
function reset() {
  log.debug("Entering reset().");
  cachedText = null;
  cached = null;
  log.debug("Leaving reset().");
}

module.exports = {
  clientAddressOf: clientAddressOf,
  forwardedBelieved: forwardedBelieved,
  peerIsTrustedProxy: peerIsTrustedProxy,
  trustedProxyRanges: trustedProxyRanges,
  isTrustedProxy: isTrustedProxy,
  normalise: normalise,
  reset: reset
};
