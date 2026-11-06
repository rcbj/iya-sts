// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
// File: auth_proxy.js
// ===========================================================================
// THE SCHEMATHESIS AUTH ADAPTER (#1299): a forward proxy that attaches this
// service's product-mode authentication to every request Schemathesis makes.
//
// Schemathesis points at this proxy (`--url http://127.0.0.1:<port>`); the
// proxy forwards each request to the real service at STS_SCHEMA_SERVICE_BASE,
// under the realm prefix STS_SCHEMA_REALM_PREFIX, and, for a gated surface,
// adds a DPoP-bound access token and a freshly signed DPoP proof whose htu is
// the real forwarded URL — then retries once on a use_dpop_nonce challenge and
// once on an expired token. It reuses this repository's own sign-in helpers
// (portal_signin, console_signin, report_signin), so there is no second DPoP
// implementation and PAR/JARM/consent are handled where they already are. The
// tlsfuzzer-adapter analogue: the unmodified fuzzer, a thing it cannot be told
// answered beside it.
//
// It does NOT forward a fuzzed Authorization or DPoP header — the proxy owns
// those — but it passes every other header, the method, the path, the query
// and the body through unchanged, which is what keeps the fuzzing faithful.
//
// Configuration is entirely by environment, set by schemathesis_kit.js:
//   STS_SCHEMA_PROXY_PORT    the port to listen on (127.0.0.1 only)
//   STS_SCHEMA_SERVICE_BASE  e.g. https://sts:8081
//   STS_SCHEMA_REALM_PREFIX  e.g. /realm/fuzz-9700  ("" for the default realm)
//   STS_SCHEMA_SURFACE       account-api|authn-api|admin-api|report-api|
//                            protocol
//   STS_SCHEMA_AUTH          none|authn|dpop-portal|dpop-console|dpop-report|
//                            per-op
//   STS_SCHEMA_USER          the fuzz person (or admin) to sign in as
//   STS_SCHEMA_PASSWORD      that person's password
//
// The proxy listens on loopback and the stack has no egress (the `internal`
// network), so nothing it forwards can leave the device.
// ===========================================================================

const http = require("http");
const https = require("https");
const { URL } = require("url");

const log = require("bunyan").createLogger({ name: "schemathesis_auth_proxy",
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || "info" });

const PORT = parseInt(process.env.STS_SCHEMA_PROXY_PORT || "0", 10);
const SERVICE_BASE = String(process.env.STS_SCHEMA_SERVICE_BASE || "")
  .replace(/\/$/, "");
const REALM_PREFIX = String(process.env.STS_SCHEMA_REALM_PREFIX || "")
  .replace(/\/$/, "");
const SURFACE = String(process.env.STS_SCHEMA_SURFACE || "");
const AUTH = String(process.env.STS_SCHEMA_AUTH || "none");
const USER = String(process.env.STS_SCHEMA_USER || "");
const PASSWORD = String(process.env.STS_SCHEMA_PASSWORD || "");

// The realm base the sign-in helpers drive, and the forwarding target.
const REALM_BASE = SERVICE_BASE + REALM_PREFIX;
const SERVICE = new URL(SERVICE_BASE + "/");
const UPSTREAM = SERVICE.protocol === "http:" ? http : https;

// The proxy->service hop runs over the service's self-signed TLS on an
// isolated network; this hop's certificate is not what the run verifies
// (tlsfuzzer exercises the listener's TLS). The JOBS get a real anchor
// elsewhere; here the question is only whether the service answers.
const AGENT = SERVICE.protocol === "http:" ? undefined
  : new https.Agent({ rejectUnauthorized: false });

// The session established for a gated surface: a DPoP key, the current token,
// a refresh(), the sign-in wrapper (its `token` getter is live, so a refresh
// is read from there rather than from refresh()'s own return — which is the
// token RESPONSE object its internal retry consumes, not the access-token
// string), and (for authn) the sign-on cookie. Filled by signIn().
const session = { key: null, token: "", refresh: null, wrapper: null,
  cookie: "", csrf: "", origin: SERVICE.origin };

// The access token in force right now: the wrapper's live getter once a
// gated surface has signed in, so a value replaced by a refresh is picked up
// without the proxy ever holding a stale or non-string token.
function currentToken() {
  return session.wrapper ? session.wrapper.token : session.token;
}

// Signs the surface's credential in, reusing the matching helper. The authn
// surface takes no token but its POSTs are bound, so a portal sign-in's
// sign-on cookie is borrowed for them.
async function signIn() {
  log.debug("Entering signIn().");
  const say = function (message) {
    log.info(message);
  };
  if (AUTH === "dpop-portal") {
    const portal = require("../protocol/portal_signin")
      .signInToThePortal(REALM_BASE, USER, say, { password: PASSWORD });
    const wrapper = await portal;
    session.key = wrapper.key;
    session.token = wrapper.token;
    session.refresh = wrapper.refresh;
    session.wrapper = wrapper;
  } else if (AUTH === "dpop-console") {
    const wrapper = await require("../protocol/console_signin")
      .signInToTheConsole(REALM_BASE, USER, say, { password: PASSWORD });
    session.key = wrapper.key;
    session.token = wrapper.token;
    session.refresh = wrapper.refresh;
    session.wrapper = wrapper;
  } else if (AUTH === "dpop-report") {
    const wrapper = await require("../protocol/report_signin")
      .signInToReport(REALM_BASE, USER, say, { password: PASSWORD });
    session.key = wrapper.key;
    session.token = wrapper.token;
    session.refresh = wrapper.refresh;
    session.wrapper = wrapper;
  } else if (AUTH === "authn") {
    // The authn-api operations take no token; its POSTs are bound (an Origin,
    // and X-CSRF-Token matching the sts_session cookie). A portal sign-in
    // yields that cookie; the CSRF value a bogus pending id cannot satisfy
    // anyway, so this is best-effort and most authn POSTs exercise a refusal.
    const wrapper = await require("../protocol/portal_signin")
      .signInToThePortal(REALM_BASE, USER, say, { password: PASSWORD });
    session.cookie = wrapper.cookie || "";
    const match = /(?:^|;\s*)sts_session=([^;]+)/.exec(session.cookie);
    session.csrf = match ? match[1] : "";
  }
  log.debug("Leaving signIn().");
}

// The headers to forward: the client's, minus the ones the proxy or the hop
// owns, plus the authentication this surface needs for this method and URL.
function outboundHeaders(req, url) {
  log.debug("Entering outboundHeaders().");
  const headers = {};
  Object.keys(req.headers).forEach(function (name) {
    const low = name.toLowerCase();
    if (low === "host" || low === "authorization" || low === "dpop" ||
        low === "content-length" || low === "connection" ||
        low === "transfer-encoding") {
      return;
    }
    headers[name] = req.headers[name];
  });
  headers.host = SERVICE.host;
  if (AUTH === "dpop-portal" || AUTH === "dpop-console" ||
      AUTH === "dpop-report") {
    const token = currentToken();
    headers.authorization = "DPoP " + token;
    headers.dpop = session.key.proof(req.method, url, token);
  } else if (AUTH === "authn") {
    if (session.cookie) {
      headers.cookie = session.cookie +
        (req.headers.cookie ? "; " + req.headers.cookie : "");
    }
    headers.origin = session.origin;
    if (session.csrf) {
      headers["x-csrf-token"] = session.csrf;
    }
  }
  log.debug("Leaving outboundHeaders().");
  return headers;
}

// One forward to the service; resolves { status, headers, body, challenge }.
function forwardOnce(method, url, headers, body) {
  log.debug("Entering forwardOnce().");
  return new Promise(function (resolve, reject) {
    const target = new URL(url);
    const options = { method: method, hostname: target.hostname,
      port: target.port, path: target.pathname + target.search,
      headers: headers, agent: AGENT };
    const upstream = UPSTREAM.request(options, function (res) {
      const chunks = [];
      res.on("data", function (chunk) {
        chunks.push(chunk);
      });
      res.on("end", function () {
        const buffer = Buffer.concat(chunks);
        const challenge = String(res.headers["www-authenticate"] || "");
        log.debug("Leaving forwardOnce(). " + res.statusCode);
        resolve({ status: res.statusCode || 502, headers: res.headers,
          body: buffer, challenge: challenge,
          nonce: String(res.headers["dpop-nonce"] || "") });
      });
    });
    upstream.on("error", function (e) {
      log.debug("Caught in forwardOnce(): " + ((e && e.message) || e));
      reject(e);
    });
    if (body && body.length) {
      upstream.write(body);
    }
    upstream.end();
  });
}

// A fetch-shaped Response wrapper so session.key.keepNonce() can read the
// DPoP-Nonce from a forwardOnce() answer.
function nonceCarrier(answer) {
  log.debug("Entering nonceCarrier().");
  log.debug("Leaving nonceCarrier().");
  return { headers: { get: function (name) {
    return String(name).toLowerCase() === "dpop-nonce"
      ? (answer.nonce || null) : null;
  } } };
}

// A gated surface's token can genuinely expire or be disowned over a long
// run. When that happens the proxy RE-SIGNS IN (a fresh token family) rather
// than refreshing: replaying a one-time refresh token trips the server's
// refresh-token reuse-revocation and spins -- on 2026-11-05 that turned every
// fuzz-induced 401 into a refresh, 56,750 oauth2/token calls, and a run that
// timed out before it left the first realm. A re-sign-in is bounded by a
// cooldown so a token that cannot be recovered cannot storm either.
// 2s (#1299): low enough that a fuzz-induced token revocation/disown
// (STS-API-0122, "token revoked or disowned") costs at most ~2s of the cell
// rather than 20s — on the 2026-11-06 run that refusal held for whole cooldown
// windows across 295 routes — and high enough that a fresh PKCE sign-in cannot
// storm (a re-sign-in is NOT a refresh, so it does not trip the reuse-revocation
// the 2026-11-05 spin did; the bound is only on sign-in VOLUME, ~30/min here).
const RESIGN_COOLDOWN_MS = parseInt(
  process.env.STS_SCHEMA_RESIGN_COOLDOWN_MS || "2000", 10);
let lastResignAt = 0;

// Re-signs the surface's credential in, at most once per cooldown. Returns
// whether it did AND recovered, so the caller retries only after a fresh
// sign-in. A sign-in that THROWS — the account disabled is the case
// (STS-API-0122's third cause), which no fresh token recovers and the per-cell
// re-assert re-enables — is caught, logged, and reported as not recovered, so
// the original 401 is returned rather than becoming a 502 the no-5xx check
// would flag. lastResignAt is set either way, so a persistently failing
// sign-in backs off on the cooldown instead of storming.
async function resignInIfDue(reason) {
  log.debug("Entering resignInIfDue().");
  const now = Date.now();
  if (now - lastResignAt < RESIGN_COOLDOWN_MS) {
    log.debug("Leaving resignInIfDue(). within cooldown");
    return false;
  }
  lastResignAt = now;
  log.info("[schemathesis] re-signing in: " + reason);
  try {
    await signIn();
  } catch (e) {
    log.warn("[schemathesis] re-sign-in failed (" + reason + "): " +
      ((e && e.message) || e) + " -- returning the refusal unchanged");
    log.debug("Leaving resignInIfDue(). sign-in threw");
    return false;
  }
  log.debug("Leaving resignInIfDue(). re-signed in");
  return true;
}

// Forwards a request, correcting at most a few times for a DPoP nonce
// challenge (apply the nonce and retry) or the proxy's own token having
// expired or been disowned (re-sign-in, bounded, and retry). Any other 401 --
// insufficient_scope, or a fuzz case the turnstile correctly refuses -- is
// returned unchanged. The proxy signs a fresh proof on every try.
async function forward(req, url, body) {
  log.debug("Entering forward().");
  let answer = await forwardOnce(req.method, url,
    outboundHeaders(req, url), body);
  const dpop = AUTH === "dpop-portal" || AUTH === "dpop-console" ||
    AUTH === "dpop-report";
  if (!dpop) {
    log.debug("Leaving forward(). " + answer.status);
    return answer;
  }
  for (let attempt = 0; attempt < 3 && answer.status === 401; attempt++) {
    if (/use_dpop_nonce/.test(answer.challenge)) {
      session.key.keepNonce(nonceCarrier(answer));
    } else if (/invalid_token/.test(answer.challenge)) {
      const resigned = await resignInIfDue("invalid_token on " + SURFACE);
      if (!resigned) {
        break;
      }
    } else {
      break;
    }
    answer = await forwardOnce(req.method, url,
      outboundHeaders(req, url), body);
  }
  log.debug("Leaving forward(). " + answer.status);
  return answer;
}

// Reads a request body whole; fuzz bodies are small and a retry needs them
// again.
function readBody(req) {
  log.debug("Entering readBody().");
  return new Promise(function (resolve) {
    const chunks = [];
    req.on("data", function (chunk) {
      chunks.push(chunk);
    });
    req.on("end", function () {
      log.debug("Leaving readBody().");
      resolve(Buffer.concat(chunks));
    });
  });
}

// The proxy's request handler.
async function handle(req, res) {
  log.debug("Entering handle(). " + req.method + " " + req.url);
  const body = await readBody(req);
  const url = SERVICE_BASE + REALM_PREFIX + req.url;
  try {
    const answer = await forward(req, url, body);
    const headers = Object.assign({}, answer.headers);
    delete headers["transfer-encoding"];
    delete headers["connection"];
    res.writeHead(answer.status, headers);
    res.end(answer.body);
  } catch (e) {
    // A transport failure forwarding to the service is the proxy's problem,
    // not a service finding; 502 with a marker the kit can tell apart from a
    // genuine server error.
    log.debug("Caught in handle(): " + ((e && e.message) || e));
    res.writeHead(502, { "content-type": "text/plain",
      "x-sts-schemathesis-proxy": "forward-failed" });
    res.end("proxy could not forward: " + ((e && e.message) || e));
  }
  log.debug("Leaving handle().");
}

async function main() {
  log.debug("Entering main().");
  if (!PORT || !SERVICE_BASE || !SURFACE) {
    throw new Error("auth_proxy needs STS_SCHEMA_PROXY_PORT, " +
      "STS_SCHEMA_SERVICE_BASE and STS_SCHEMA_SURFACE");
  }
  await signIn();
  const server = http.createServer(function (req, res) {
    handle(req, res).catch(function (e) {
      log.error("Unhandled in handle(): " + ((e && e.message) || e));
      try {
        res.writeHead(502, { "x-sts-schemathesis-proxy": "handler-failed" });
        res.end("");
      } catch (inner) {
        log.debug("Caught writing 502 in main(): " +
                  ((inner && inner.message) || inner));
      }
    });
  });
  await new Promise(function (resolve) {
    server.listen(PORT, "127.0.0.1", resolve);
  });
  log.info("[schemathesis] auth proxy for " + SURFACE + " (" + AUTH +
    ") on 127.0.0.1:" + PORT + " -> " + REALM_BASE);
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("auth_proxy failed to start: " + ((e && e.message) || e));
  process.exit(1);
});
