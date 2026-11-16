// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_xacml_pep_proxy_cluster.js
//
// ===========================================================================
// A REMOTE PEP REVERSE-PROXY CLUSTER BEHIND A LOAD BALANCER, END TO END
// (2026-11-16, rcbj: "add the reverse proxy cluster test. Model it after the
// two node remote pep cluster we have on 8081 at this point. use the pep-app.
// test with user who has role access. Test with a user who does not. check
// public access endpoints as well.").
//
// THE MODEL IS THE DEMONSTRATION INSTANCE ON 8081 (iya-sts-8081/override.yml,
// pep-haproxy.cfg and pep-proxy.json beside it): two remote PEPs, each a
// service account in `remote-peps` authenticating with ITS OWN RFC 7523 key
// alone (no client certificate, `xacml.pepAuthentication=token`), both
// members of ONE cluster that holds the reverse proxy, the companion's
// `/pep-app` as the upstream, and an HAProxy in front: 9543 the proxy
// listener, TLS passed through and sticky by source address, 9443 the
// decision API, round robin. The routes are 8081's four, in its order:
//
//   public              /pep-app/public      public
//   pep-app-api-admin   /pep-app/api/admin   simple, read: pep-demo-admins
//   pep-app-api         /pep-app/api         simple, read: pep-demo-users
//   pep-app             /pep-app             simple, read: pep-demo-users,
//                                            several accounts
//
// each by prefix, GET and HEAD, each non-public one naming the application
// `pep-demo-app` and forwarding the X-Remote-User / X-Iya-* headers. ONE
// DIFFERENCE, for the credential the request asks for: the two API routes
// take `basic` as well as `session`, so a simple route is driven with a
// credential the way sts_xacml_remote_pep.js section 10j drives one, as well
// as with a browser's sign-in.
//
// ---------------------------------------------------------------------------
// THE LAUNCHER PROVIDES THE TOPOLOGY, AND THAT IS THE POINT OF THIS FILE.
//
// sts_xacml_remote_pep.js section 11 starts two PEPs with docker itself, so
// under ./run-tests.sh — whose runner is a container with no docker in it —
// it asserts nothing at all. Here the stack does it: docker-compose-run-
// tests.yml's `pep-cluster` profile brings up `pep-cluster-1`,
// `pep-cluster-2` and `pep-cluster-lb` (tests/cluster/pep-haproxy.cfg),
// ./run-tests.sh generates each member's key and certificate request in the
// first PEP's way (mintThePepClusterCredentials) and turns the profile on
// in the modes STS_TEST_PEP_CLUSTER_MODES names — every mode but `fuzz`,
// which runs its own jobs only — and hands this job four variables:
//
//   XACML_PEP_CLUSTER_REALM          the realm the members poll
//   XACML_PEP_CLUSTER_MEMBERS        their names, each also its host name
//   XACML_PEP_CLUSTER_LB             the balancer's host name
//   XACML_PEP_CLUSTER_CERT_DIR_HERE  the members' credential directories
//
// and XACML_PEP_UPSTREAM_URL, the companion. This job drives everything over
// HTTP and shells out to nothing. Without the four it DECLINES TO RUN
// (expectation.js), saying why: a coverage run or an AWS target has no such
// stack, and that is a fact about the run rather than a defect.
//
// ---------------------------------------------------------------------------
// A NEW JOB RATHER THAN A SECTION OF sts_xacml_remote_pep.js, for three
// reasons. That job's PEP is not these: it reconfigures its proxy section by
// section, and section 9 takes its PDP away and leaves it so; a cluster
// sharing it would write this job's needs into that job's order. Its realm
// is fixed by its launcher-owned PEP, and these members poll another. And
// its 5800 lines are already the longest job in the suite; this one reuses
// its helpers' shapes (the proxy request, the cookie jars, the sign-in walk)
// rather than its sections.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED, in the order it runs, and IN TWO SCOPES (rcbj, the same
// day: "Add a test for a single Remote PEP with the same configuration at
// that scope (not cluster) and the same tests"):
//
//   0. EACH MEMBER ON ITS KEY ALONE: registered, authenticated, GET /'s
//      credential from PEP_ASSERTION_KEY with no client certificate, and a
//      service account on the PDP's row.
//
//   THE STANDALONE PEP — `pep-cluster-1` holding the document as its OWN
//   (set-pep-proxy), dialled directly — and then THE CLUSTER BEHIND THE
//   BALANCER, each through the SAME assertion functions, which take a
//   "scope" (where requests go, every address it serves on, the PEPs whose
//   records it makes, a tag in every path, how a route edit is made) and
//   nothing else:
//
//   1. PUBLIC: /pep-app/public answers an anonymous caller at every address
//      of the scope (for the cluster: the balancer and each member), and the
//      companion counts each one.
//   2. A PERSON WITH THE ROLE: signed in by the session route, the
//      protected page with the identity headers; the simple API route on a
//      Basic credential; the admin route admitting the administrator and
//      refusing the plain role holder, by Basic and by session.
//   3. A PERSON WITHOUT IT: refused on the session route (the HTML refusal
//      page) and the simple route (403), with nothing reaching the
//      application; and nobody at all is 401 or sent to sign in.
//   4. ONE ROUTE EDIT (set-pep-route on the PEP, set-pep-cluster-route on
//      the cluster) reaches every running proxy of the scope.
//   5. THE AUDIT: every PEP of the scope's xacml.remote.proxy rows, its
//      refusal of the person without the role among them.
//
//   and for the cluster alone: both members serve the routes and decide
//   alike, and the balancer's 9443 reaches both while its 9543 keeps a
//   source on one (the session made through it is honoured by exactly one
//   member when each is dialled direct).
//
// ONE CONTAINER IS BOTH SCOPES, ONE AFTER THE OTHER, rather than a third PEP
// in the stack: the standalone document is CLEARED and the PEP then joins
// the cluster holding nothing of its own, so the cluster starts from an
// empty PEP joining an empty cluster (standaloneScope() argues it). ONE JOB
// RATHER THAN TWO SHARING A MODULE: the two scopes share the realm, the
// people, the application and the members' keys and listener pairs, which
// two jobs would each have to make — and the second could not, since the
// launcher fixes the realm the members poll.
//
// ---------------------------------------------------------------------------
// FROM A KNOWN STATE: the realm is this job's own and is created here — the
// three people, the two roles, the application, the members' entries and the
// cluster with it — in DEVELOPMENT mode whatever the process runs in, as
// sts_xacml_remote_pep.js section 10 does, because the session sign-in and
// the Basic door then take any password but `invalid`; the product half is
// the PEP's own test and the service's validation doors'. **The realm is
// LEFT STANDING**, by this suite's rule, so a red run can be read; the id is
// fixed by the launcher, so a second run against the same stack is refused
// at its creation — restart the stack.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const http = require("http");
const https = require("https");
const nodeCrypto = require("crypto");
const path = require("path");
const { URL } = require("url");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin");
const expectation = require("./expectation.js");
const credentials = require("../tools/pep-credential.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_xacml_pep_proxy_cluster",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// ---------------------------------------------------------------------------
// WHAT THE LAUNCHER STARTED. All four arrive together or the job declines.
// ---------------------------------------------------------------------------
const REALM = String(process.env.XACML_PEP_CLUSTER_REALM || "").trim();
const MEMBERS = String(process.env.XACML_PEP_CLUSTER_MEMBERS || "")
  .split(/[\s,]+/).filter(Boolean);
const LB = String(process.env.XACML_PEP_CLUSTER_LB || "").trim();
const CERT_DIR = String(process.env.XACML_PEP_CLUSTER_CERT_DIR_HERE || "")
  .trim();
const UPSTREAM = String(process.env.XACML_PEP_UPSTREAM_URL || "")
  .replace(/\/+$/, "");

// 8081's names, in a realm of this job's own.
const CLUSTER = "pep-demo";
const APP = "pep-demo-app";
const USERS_ROLE = "pep-demo-users";
const ADMINS_ROLE = "pep-demo-admins";
// THE THREE PEOPLE: one holding pep-demo-users, one holding both roles, and
// one holding neither.
const READER = "pep-cluster-reader";
const ADMIN = "pep-cluster-admin";
const OUTSIDER = "pep-cluster-outsider";
// Paths this run alone asks for, so the companion's counter, shared with
// sts_xacml_remote_pep.js, reads this job's requests and nobody else's.
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 16);
const LB_PROXY = "https://" + LB + ":9543";
const LB_API = "https://" + LB + ":9443";
const CALLBACK = LB_PROXY + "/.iya-pep/callback";
// How long a member may take to find what the service now holds: its poll
// (5 s in this stack), a nudge, a backoff of up to 15 s while its realm did
// not exist, and the balancer's two health checks.
const CONVERGE_MS = 90000;
const IDENTITY = {
  mode: "headers", separator: ",",
  headers: [{ name: "X-Remote-User", claim: "username" },
            { name: "X-Iya-User", claim: "sub" },
            { name: "X-Iya-Email", claim: "email" },
            { name: "X-Iya-Name", claim: "name" },
            { name: "X-Iya-Groups", claim: "groups" },
            { name: "X-Iya-Auth", claim: "mechanism" },
            { name: "X-Iya-Amr", claim: "amr" }]
};

// The anchor every member's listener chains to: the service Root, which
// issue-pep-certificate hands back with each pair.
let listenerAnchorPem = "";
// The application's client secret: never logged.
let appSecret = "";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("check passed: " + what);
  log.debug("Leaving check().");
}

function realmUrl(p) {
  log.debug("Entering realmUrl().");
  log.debug("Leaving realmUrl().");
  return base + "/realm/" + REALM + p;
}

function api(p) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return realmUrl("/admin-api" + p);
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, options || {});
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in fetchJson(): " + ((e && e.message) || e));
    // Not JSON. The caller reports the status and the raw text, which says
    // more than a parse error would.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

function get(url) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return fetchJson(url);
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload || {}) });
}

// A realm /admin-api action that must have worked, its refusal quoted whole.
async function act(p, payload, what) {
  log.debug("Entering act(). " + p);
  const r = await postJson(api(p), payload || {});
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST /admin-api" + p + " should have " + what + "; it answered " +
    r.status + " " + withoutSecret(JSON.stringify(
      (r.body && (r.body.why || r.body.error_description)) || r.body ||
      r.text)).slice(0, 400));
  log.debug("Leaving act().");
  return r.body;
}

async function setSetting(key, value) {
  log.debug("Entering setSetting(). " + key);
  await act("/config/set", { key: key, value: value },
            "set " + key + " in " + REALM);
  log.debug("Leaving setSetting().");
}

function withoutSecret(text) {
  log.debug("Entering withoutSecret().");
  const out = appSecret ? String(text || "").split(appSecret)
    .join("<client secret>") : String(text || "");
  log.debug("Leaving withoutSecret().");
  return out;
}

// ---------------------------------------------------------------------------
// WAITING, with a budget and the last thing seen, for the reason
// sts_xacml_remote_pep.js's until() gives: a wait that cannot fail is worse
// than a sleep, and a timeout that does not say what it saw is no help.
// ---------------------------------------------------------------------------
async function until(what, probe, budgetMs) {
  log.debug("Entering until(). what=" + what);
  const budget = budgetMs || CONVERGE_MS;
  const started = Date.now();
  let last = "nothing was seen at all";
  while (Date.now() - started < budget) {
    let seen;
    try {
      /* eslint-disable no-await-in-loop */
      seen = await probe();
      /* eslint-enable no-await-in-loop */
    } catch (e) {
      // A refused connection is an ordinary poll result here: this is what
      // waits for a listener to come up. Kept as the last thing seen.
      log.debug("Caught in until(): " + ((e && e.message) || e));
      seen = { ok: false, note: "the probe threw: " + e.message };
    }
    if (seen.ok) {
      seen.ms = Date.now() - started;
      log.debug("Leaving until(). " + what + " after " + seen.ms + "ms.");
      return seen;
    }
    last = seen.note;
    /* eslint-disable no-await-in-loop */
    await sleep(250);
    /* eslint-enable no-await-in-loop */
  }
  log.debug("Leaving until(). Gave up.");
  throw new Error("Gave up after " + budget + "ms waiting for " + what +
                  ". Last seen: " + last);
}

// ---------------------------------------------------------------------------
// ONE REQUEST TO A MEMBER, THE BALANCER OR THE APPLICATION, sent with
// `http.request` so the path goes as written, and over https trusting ONLY
// the service Root with the host name checked — every member's pair names
// the member and the balancer, so a verified handshake by either name is
// itself part of what is asserted. `agent: false`, so every request is a new
// connection and the balancer's choice is made afresh each time.
// ---------------------------------------------------------------------------
//
// A 502 `bad_gateway` IS SENT ONCE MORE, and counted (`badGateways`, logged
// at the end). On the hand runs of 2026-11-16 a member's call to the
// service — POST /xacml/pep/basic or /xacml/pep/session — sometimes timed
// out after an idle spell (STS-XPEP-0075, "the PDP did not answer in time")
// and the very next call took tens of milliseconds. Nothing is forwarded
// before that validation, so the retry cannot double a hit; it keeps that
// PEP-side defect from deciding every assertion of this job, and the count
// says how often it happened.
let badGateways = 0;
async function request(method, url, options) {
  log.debug("Entering request(). " + method + " " + url);
  const first = await requestOnce(method, url, options);
  if (first.status === 502 && first.json &&
      first.json.error === "bad_gateway") {
    badGateways += 1;
    log.warn("A 502 bad_gateway from " + url + " (the PEP could not ask " +
             "the service in time); sending it once more. " + told(first));
    const again = await requestOnce(method, url, options);
    log.debug("Leaving request(). Sent twice.");
    return again;
  }
  log.debug("Leaving request().");
  return first;
}

function requestOnce(method, url, options) {
  log.debug("Entering requestOnce(). " + method + " " + url);
  const o = options || {};
  const m = /^(https?):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/.exec(String(url));
  assert.ok(m, "request() was handed " + url + ", which it cannot send");
  const secure = m[1] === "https";
  const headers = Object.assign({}, o.headers || {});
  log.debug("Leaving requestOnce().");
  return new Promise(function (resolve) {
    const started = Date.now();
    const sent = (secure ? https : http).request({
      host: m[2], port: m[3] || (secure ? 443 : 80), path: m[4] || "/",
      method: method, headers: headers, agent: false,
      ca: secure && listenerAnchorPem ? [listenerAnchorPem] : undefined,
      servername: secure ? m[2] : undefined
    }, function (response) {
      const chunks = [];
      response.on("data", function (chunk) {
        chunks.push(chunk);
      });
      response.on("end", function () {
        const text = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in a callback in requestOnce(): " +
                    ((e && e.message) || e));
          json = null;
        }
        resolve({ status: response.statusCode, headers: response.headers,
                  text: text, json: json, ms: Date.now() - started });
      });
    });
    sent.setTimeout(o.timeoutMs || 20000, function () {
      sent.destroy(new Error("no answer within " +
                             (o.timeoutMs || 20000) + "ms"));
    });
    sent.on("error", function (e) {
      resolve({ status: 0, headers: {}, text: "", json: null,
                error: e.message, ms: Date.now() - started });
    });
    sent.end();
  });
}

function memberPlain(name) {
  log.debug("Entering memberPlain().");
  log.debug("Leaving memberPlain().");
  return "http://" + name + ":9090";
}

function memberProxy(name) {
  log.debug("Entering memberProxy().");
  log.debug("Leaving memberProxy().");
  return "https://" + name + ":9543";
}

function told(r) {
  log.debug("Entering told().");
  log.debug("Leaving told().");
  return r.status + " " + (r.error || withoutSecret(String(r.text || ""))
    .slice(0, 300)) + " (www-authenticate: " +
    JSON.stringify((r.headers || {})["www-authenticate"] || null) +
    ", location: " + JSON.stringify((r.headers || {}).location || null) + ")";
}

function echoed(r, header) {
  log.debug("Entering echoed().");
  log.debug("Leaving echoed().");
  return String(((r.json || {}).headers || {})[header] || "");
}

function basic(username) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  // ANY PASSWORD BUT `invalid` in this development realm.
  return "Basic " + Buffer.from(username + ":pep-cluster-" + username)
    .toString("base64");
}

// What reached the application, by path, read off the companion DIRECTLY.
async function upstreamHits() {
  log.debug("Entering upstreamHits().");
  const r = await request("GET", UPSTREAM + "/pep-app/_hits");
  assert.strictEqual(r.status, 200,
    "GET " + UPSTREAM + "/pep-app/_hits should answer the companion's hit " +
    "counter; it answered " + told(r));
  log.debug("Leaving upstreamHits().");
  return (r.json && r.json.byPath) || {};
}

function hitsOn(byPath, p) {
  log.debug("Entering hitsOn().");
  log.debug("Leaving hitsOn().");
  return Number(byPath[p] || 0);
}

// A member's own GET /, over its plain 9090.
async function overview(name) {
  log.debug("Entering overview(). " + name);
  const r = await get(memberPlain(name) + "/");
  assert.strictEqual(r.status, 200,
    "GET / on " + name + " answered " + r.status + " " +
    String(r.text).slice(0, 200) + ". `docker logs` on that member says " +
    "why; ./run-tests.sh captures it as 00-" + name + ".log.");
  log.debug("Leaving overview().");
  return r.body;
}

async function pepRow(name) {
  log.debug("Entering pepRow(). " + name);
  const r = await get(api("/xacml/peps"));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/xacml/peps answered " + r.status);
  const found = ((r.body && r.body.peps) || []).filter(function (one) {
    return one.name === name;
  });
  log.debug("Leaving pepRow().");
  return found.length ? found[0] : null;
}

// ---------------------------------------------------------------------------
// THE BROWSER: one jar per origin; a member or the balancer reached with
// request(), the service with fetch (the run's trust bundle), every redirect
// followed, and the service's sign-in and consent screens answered over
// /authn-api as their pages do — sts_xacml_remote_pep.js section 10's walk.
// ---------------------------------------------------------------------------
function originOf(url) {
  log.debug("Entering originOf().");
  const m = /^(https?:\/\/[^/]+)/.exec(String(url));
  log.debug("Leaving originOf().");
  return m ? m[1].toLowerCase() : "";
}

function jarHeader(jars, url) {
  log.debug("Entering jarHeader().");
  const jar = jars[originOf(url)] || {};
  log.debug("Leaving jarHeader().");
  return Object.keys(jar).map(function (name) {
    return name + "=" + jar[name];
  }).join("; ");
}

function jarTake(jars, url, lines) {
  log.debug("Entering jarTake().");
  const origin = originOf(url);
  jars[origin] = jars[origin] || {};
  [].concat(lines || []).forEach(function (line) {
    const pair = String(line).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const name = pair.slice(0, at).trim();
    const value = pair.slice(at + 1).trim();
    if (value === "" || /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(line)) {
      delete jars[origin][name];
    } else {
      jars[origin][name] = value;
    }
  });
  log.debug("Leaving jarTake().");
}

function isProxyUrl(url) {
  log.debug("Entering isProxyUrl().");
  const origin = originOf(url);
  log.debug("Leaving isProxyUrl().");
  return origin === originOf(LB_PROXY) || MEMBERS.some(function (name) {
    return origin === originOf(memberProxy(name));
  });
}

async function browserGet(jars, url) {
  log.debug("Entering browserGet(). " + url);
  const cookie = jarHeader(jars, url);
  const headers = { accept: "text/html,application/xhtml+xml" };
  if (cookie) {
    headers.cookie = cookie;
  }
  if (isProxyUrl(url)) {
    const r = await request("GET", url, { headers: headers });
    jarTake(jars, url, r.headers["set-cookie"]);
    log.debug("Leaving browserGet(). The proxy: " + r.status);
    return { status: r.status, location: r.headers.location || "",
             text: r.text, json: r.json, headers: r.headers, url: url };
  }
  const r = await fetch(url, { redirect: "manual", headers: headers });
  jarTake(jars, url, r.headers.getSetCookie ? r.headers.getSetCookie() : []);
  const text = r.status >= 300 && r.status < 400 ? "" : await r.text();
  log.debug("Leaving browserGet(). The service: " + r.status);
  return { status: r.status, location: r.headers.get("location") || "",
           text: text, json: null,
           headers: { "content-type": r.headers.get("content-type") || "" },
           url: url };
}

// From `url`, through every redirect and screen, until an answer that is
// neither. Answers the last response and every address it passed.
async function browse(jars, url, username) {
  log.debug("Entering browse(). " + url);
  const passed = [];
  let at = url;
  let r = await browserGet(jars, at);
  for (let n = 0; n < 25; n += 1) {
    passed.push(r.status + " " + at.replace(/([?&](code|state)=)[^&]+/g,
                                             "$1…"));
    if (r.status >= 300 && r.status < 400 && r.location) {
      at = new URL(r.location, at).toString();
      /* eslint-disable no-await-in-loop */
      r = await browserGet(jars, at);
      /* eslint-enable no-await-in-loop */
      continue;
    }
    if (r.status === 200 && /\/authn\/signin\.js/.test(r.text || "")) {
      /* eslint-disable no-await-in-loop */
      const answer = await authnSignin.submit(realmUrl(""), at,
        { action: "login", username: username,
          password: "pep-cluster-" + username },
        { cookie: jarHeader(jars, at) });
      /* eslint-enable no-await-in-loop */
      jarTake(jars, at, answer.headers.getSetCookie());
      assert.strictEqual(answer.next, "redirect",
        "signing " + username + " in at the service's screen should send " +
        "the browser on; it answered " + answer.status + " " +
        JSON.stringify(answer.json).slice(0, 300));
      at = answer.location;
      /* eslint-disable no-await-in-loop */
      r = await browserGet(jars, at);
      /* eslint-enable no-await-in-loop */
      continue;
    }
    if (r.status === 200 && authnSignin.isConsent(at)) {
      /* eslint-disable no-await-in-loop */
      const answer = await authnSignin.consentFor(at, jarHeader(jars, at));
      /* eslint-enable no-await-in-loop */
      jarTake(jars, at, answer.headers.getSetCookie());
      assert.strictEqual(answer.next, "redirect",
        "the consent screen should send the browser on; it answered " +
        answer.status);
      at = answer.location;
      /* eslint-disable no-await-in-loop */
      r = await browserGet(jars, at);
      /* eslint-enable no-await-in-loop */
      continue;
    }
    break;
  }
  log.debug("Leaving browse(). " + r.status);
  return { r: r, url: at, passed: passed };
}

// One person signed in through `page` with a fresh browser.
async function signInAt(page, username) {
  log.debug("Entering signInAt(). " + page + " " + username);
  const jars = {};
  const walked = await browse(jars, page, username);
  log.debug("Leaving signInAt(). " + walked.r.status);
  return { jars: jars, walked: walked };
}

function wentThroughTheCallback(walked) {
  log.debug("Entering wentThroughTheCallback().");
  log.debug("Leaving wentThroughTheCallback().");
  return walked.passed.some(function (one) {
    return one.indexOf("/.iya-pep/callback") >= 0;
  });
}

// The proxy's refusal page (rust/bins/xacml-pep/src/proxy_page.rs).
function isRefusalPage(r) {
  log.debug("Entering isRefusalPage().");
  const type = String((r.headers || {})["content-type"] || "");
  log.debug("Leaving isRefusalPage().");
  return /text\/html/i.test(type) &&
         /You do not have access to this page/.test(String(r.text || "")) &&
         /Incident ID/.test(String(r.text || ""));
}

// ===========================================================================
// THE REALM, THE MEMBERS' ENTRIES AND THEIR KEYS.
// ===========================================================================
async function createTheRealm() {
  log.debug("Entering createTheRealm().");
  const r = await postJson(base + "/admin-api/realms/create", {
    id: REALM, domain: REALM + ".example.net",
    name: "Remote PEP cluster end-to-end realm",
    description: "Created by tests/protocol/sts_xacml_pep_proxy_cluster.js; " +
                 "LEFT IN PLACE on purpose, so a failed run can be read."
  });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "creating the realm " + REALM + " answered " + r.status + " " +
    String(r.text).slice(0, 300) + ". IF IT SAYS THE REALM IS ALREADY " +
    "DEFINED, this job already ran against this stack: the realm is left " +
    "standing so it can be read, and the launcher fixes its id. Restart the " +
    "stack.");
  // DEVELOPMENT, whatever the process runs in (the header says why); the
  // members on their tokens alone; the nudge on, so a cluster edit is
  // delivered as well as polled; and no sign-in risk scoring, whose verdict
  // on a scripted browser is not this job's subject.
  await setSetting("global.mode", "development");
  await setSetting("xacml.pepAuthentication", "token");
  await setSetting("xacml.pepNotify", true);
  await setSetting("risk.assessSignIns", false);
  // ITS CERTIFICATE AUTHORITY, which a new realm does not have the moment it
  // is created: issue-pep-credential asked at once was refused STS-PKI-0008
  // ("no certificate authority yet") on the first hand run, and the realm
  // reported its chain on GET /admin-api/pki once asked.
  await until(REALM + "'s certificate authority", async function () {
    const r = await get(api("/pki"));
    const tiers = (r.body && r.body.chain && r.body.chain.tiers) || [];
    return { ok: r.status === 200 && tiers.length >= 2,
             note: "GET /admin-api/pki answered " + r.status + " with " +
                   tiers.length + " tier(s)" };
  }, 60000);
  log.info("Created " + REALM + " (development, xacml.pepAuthentication " +
           "token).");
  log.debug("Leaving createTheRealm().");
}

// Each member's entry, as `register-remote-pep.js` makes one: a person with
// no password, in `remote-peps` (which makes it a service account), and its
// key certified from the request the launcher wrote beside it.
async function provisionTheMembers() {
  log.debug("Entering provisionTheMembers().");
  for (const name of MEMBERS) {
    /* eslint-disable no-await-in-loop */
    const made = await postJson(api("/users/create"), {
      username: name, invent: false,
      attributes: { cn: name, givenName: "Remote", sn: "PEP cluster member",
                    mail: name + "@pep-cluster.test", displayName: name,
                    description: "a member of the remote PEP cluster " +
                                 CLUSTER + " this job drives" } });
    assert.ok(made.status === 200,
      "POST /admin-api/users/create for " + name + " answered " +
      made.status + " " + String(made.text).slice(0, 300));
    await act("/groups/add-member", { group: "remote-peps", member: name },
              "put " + name + " in remote-peps");
    const file = path.join(CERT_DIR, name, "pep-assertion.csr");
    let csr = "";
    try {
      csr = fs.readFileSync(file, "utf8");
    } catch (e) {
      log.debug("Caught in provisionTheMembers(): " + ((e && e.message) || e));
      csr = "";
    }
    assert.ok(csr.indexOf("CERTIFICATE REQUEST") >= 0,
      "the launcher should have written " + name + "'s certificate request " +
      "at " + file + " (mintThePepClusterCredentials, `pep-credential.js " +
      "--assertion --csr-only`); it is not there, so that member has no " +
      "key the service could certify and can never authenticate.");
    const issued = await credentials.issueAssertionCredential(
      { post: postJson }, base, "/realm/" + REALM, name, csr);
    /* eslint-enable no-await-in-loop */
    assert.ok(!/PRIVATE KEY-----/.test(JSON.stringify(issued)),
      "issue-pep-credential's answer for " + name + " carries a private " +
      "key; the service never had one");
    log.info("Certified " + name + "'s assertion key: " + issued.urn +
             ", kid " + issued.kid + ".");
  }
  log.debug("Leaving provisionTheMembers().");
}

// ===========================================================================
// 1. EACH MEMBER REGISTERS ON A DPoP TOKEN FROM ITS KEY ALONE.
// ===========================================================================
async function theMembersRegisterOnTheirKeys() {
  log.debug("Entering theMembersRegisterOnTheirKeys().");
  log.info("=== 1. Each member registers on its own key ===");
  for (const name of MEMBERS) {
    let seen = null;
    /* eslint-disable no-await-in-loop */
    await until(name + " to register in " + REALM + " and hold a token",
                async function () {
      seen = await overview(name);
      const token = ((seen.credential || {}).tokens || {})["xacml-pep"] || {};
      return { ok: seen.registration && seen.registration.registered &&
                   token.held === true,
               note: "registration=" + JSON.stringify(seen.registration)
                 .slice(0, 300) + " credential=" +
                 JSON.stringify(seen.credential || null).slice(0, 300) };
    });
    const row = await pepRow(name);
    /* eslint-enable no-await-in-loop */
    check(name + " registered, authenticated, as itself", function () {
      assert.strictEqual(seen.registration.name, name,
        "it registered as " + seen.registration.name);
      assert.strictEqual(seen.registration.authenticated, true,
        "its registration carried no credential the PDP accepted: " +
        JSON.stringify(seen.registration));
      assert.ok(String(seen.pdp || "").replace(/\/+$/, "")
        .endsWith("/realm/" + REALM),
        "it is dialling " + seen.pdp + ", not " + REALM);
    });
    check(name + "'s calls carry a DPoP-bound token from PEP_ASSERTION_KEY " +
          "and no client certificate", function () {
      assert.strictEqual(seen.credential.keySource, "PEP_ASSERTION_KEY",
        "GET /'s credential.keySource is " + seen.credential.keySource);
      assert.strictEqual(seen.credential.clientCertificate, false,
        "GET /'s credential.clientCertificate is " +
        JSON.stringify(seen.credential.clientCertificate));
    });
    check("the PDP's row for " + name + " is authenticated, a service " +
          "account", function () {
      assert.ok(row, "GET /admin-api/xacml/peps does not list " + name);
      assert.strictEqual(row.authenticated, true,
        "the row says authenticated=" + row.authenticated);
      assert.ok(row.identityAccount &&
                row.identityAccount.serviceAccount === true,
        "its identity entry should be a service account; the row says " +
        JSON.stringify(row.identityAccount));
    });
  }
  log.debug("Leaving theMembersRegisterOnTheirKeys().");
}

// Each member's listener pair, issued by the realm and naming the balancer
// as well as the member, written where it reads it.
async function theMembersServeHttps() {
  log.debug("Entering theMembersServeHttps().");
  for (const name of MEMBERS) {
    /* eslint-disable no-await-in-loop */
    const issued = await postJson(api("/xacml/issue-pep-certificate"),
                                  { name: name, dnsNames: [LB] });
    /* eslint-enable no-await-in-loop */
    const got = issued.body || {};
    check(name + "'s listener certificate names it and the balancer",
          function () {
      assert.strictEqual(issued.status, 200,
        "POST /admin-api/xacml/issue-pep-certificate for " + name +
        " answered " + issued.status + " " + String(issued.text)
          .slice(0, 300));
      assert.ok(got.dnsNames.indexOf(name) >= 0 &&
                got.dnsNames.indexOf(LB) >= 0,
        "it names " + JSON.stringify(got.dnsNames));
    });
    listenerAnchorPem = String(got.anchorPem || "");
    const dir = path.join(CERT_DIR, name, "server");
    fs.writeFileSync(path.join(dir, "pep-server.crt"), got.fullChainPem,
                     { mode: 0o644 });
    fs.writeFileSync(path.join(dir, "pep-server.key"), got.privateKeyPem,
                     { mode: 0o644 });
    /* eslint-disable no-await-in-loop */
    await until(name + " to start its HTTPS listeners", async function () {
      const seen = await overview(name);
      const h = seen.https || {};
      return { ok: h.listening === true,
               note: "listening=" + h.listening + ", problem=" + h.problem };
    });
    /* eslint-enable no-await-in-loop */
  }
  log.info("Both members serve the realm's listener certificates.");
  log.debug("Leaving theMembersServeHttps().");
}

// ===========================================================================
// THE PEOPLE, THE ROLES, THE APPLICATION AND THE CLUSTER.
// ===========================================================================
async function createThePeople() {
  log.debug("Entering createThePeople().");
  for (const one of [[READER, "Reader"], [ADMIN, "Admin"],
                     [OUTSIDER, "Outsider"]]) {
    /* eslint-disable no-await-in-loop */
    const r = await postJson(api("/users/create"), {
      username: one[0], invent: false,
      attributes: { cn: "PEP cluster " + one[1], givenName: "PEP cluster",
                    sn: one[1], displayName: "PEP cluster " + one[1],
                    mail: one[0] + "@pep-cluster.test" } });
    /* eslint-enable no-await-in-loop */
    assert.ok(r.status === 200 && r.body && r.body.ok,
      "POST /admin-api/users/create for " + one[0] + " answered " +
      r.status + " " + String(r.text).slice(0, 300));
  }
  const holders = [[USERS_ROLE, [READER, ADMIN]], [ADMINS_ROLE, [ADMIN]]];
  for (const one of holders) {
    /* eslint-disable no-await-in-loop */
    await act("/roles/create-role", { role: one[0],
      description: "The remote PEP cluster's " + one[0] },
      "created the role " + one[0]);
    for (const member of one[1]) {
      await act("/roles/add-member", { role: one[0], kind: "user",
                                       member: member },
                "given " + member + " the role " + one[0]);
    }
    /* eslint-enable no-await-in-loop */
  }
  log.info(READER + " holds " + USERS_ROLE + "; " + ADMIN + " holds it and " +
           ADMINS_ROLE + "; " + OUTSIDER + " holds neither.");
  log.debug("Leaving createThePeople().");
}

// The application behind the proxy: a confidential OpenID Connect client
// with the callback of each place a browser reaches the proxy at — the
// standalone PEP's own origin, and the balancer every cluster member's
// publicBaseUrl names.
async function registerTheApplication() {
  log.debug("Entering registerTheApplication().");
  appSecret = nodeCrypto.randomBytes(24).toString("base64url");
  await act("/applications/create", {
    identifier: APP, name: APP, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [APP], oauthClientSecret: appSecret,
              oauthRedirectUri: [CALLBACK, memberProxy(SOLO) +
                                 "/.iya-pep/callback"],
              oauthResponseType: ["code"],
              oauthGrantType: ["authorization_code", "refresh_token"],
              oauthAllowedScope: ["openid", "profile", "email"],
              oauthTokenEndpointAuthMethod: "client_secret_basic",
              oauthIdTokenSignedResponseAlg: "RS256" } },
    "registered " + APP);
  log.debug("Leaving registerTheApplication().");
}

function aRoute(id, routePath, mechanisms, role, multiple) {
  log.debug("Entering aRoute(). " + id);
  log.debug("Leaving aRoute().");
  return { id: id, path: routePath, match: "prefix",
           methods: ["GET", "HEAD"], mechanisms: mechanisms,
           application: APP,
           authorization: { kind: "simple", actionModel: "read-write",
                            roles: { read: [role] } },
           identity: IDENTITY, forwardCredentials: false, signals: false,
           multipleAccounts: multiple };
}

// THE ONE DOCUMENT BOTH SCOPES HOLD: 8081's upstream and four routes, at the
// publicBaseUrl the scope is reached at.
function theDocument(publicBaseUrl) {
  log.debug("Entering theDocument().");
  log.debug("Leaving theDocument().");
  return {
    enabled: true, upstream: UPSTREAM, publicBaseUrl: publicBaseUrl,
    upstreamTimeoutMs: 10000, maxBodyBytes: 1048576,
    routes: [
      { id: "public", path: "/pep-app/public", match: "prefix",
        methods: ["GET", "HEAD"], authorization: { kind: "public" } },
      aRoute("pep-app-api-admin", "/pep-app/api/admin", ["session", "basic"],
             ADMINS_ROLE, false),
      aRoute("pep-app-api", "/pep-app/api", ["session", "basic"],
             USERS_ROLE, false),
      aRoute("pep-app", "/pep-app", ["session"], USERS_ROLE, true)
    ]
  };
}

// Every address in `targets` serving the scope's public route.
async function untilServed(scope) {
  log.debug("Entering untilServed(). " + scope.label);
  for (const one of scope.targets) {
    /* eslint-disable no-await-in-loop */
    const served = await until(one[0] + " to serve " + scope.label +
                               "'s public route", async function () {
      const got = await request("GET", one[1] + "/pep-app/public/ready-" +
                                scope.tag);
      return { ok: got.status === 200,
               note: "GET /pep-app/public/ready-" + scope.tag +
                     " answered " + told(got) };
    });
    /* eslint-enable no-await-in-loop */
    log.info(one[0] + " serves " + scope.label + "'s routes (" + served.ms +
             "ms).");
    // AND ITS FIRST BASIC VALIDATION ANSWERED. On the first hand run a
    // member's first POST /xacml/pep/basic timed out at the PEP (502,
    // STS-XPEP-0075) and the next took 60 ms; the wait is for that warm-up
    // and asserts nothing, so a 502 that persists still fails below.
    /* eslint-disable no-await-in-loop */
    const warm = await until(one[0] + " to answer a Basic credential",
                             async function () {
      const got = await request("GET", one[1] + "/pep-app/api/items", {
        headers: { authorization: basic(READER),
                   accept: "application/json" } });
      return { ok: got.status !== 502 && got.status !== 0,
               note: "GET /pep-app/api/items answered " + told(got) };
    }, 60000);
    /* eslint-enable no-await-in-loop */
    log.info(one[0] + " answered its first Basic credential after " +
             warm.ms + "ms.");
  }
  log.debug("Leaving untilServed().");
}

// ===========================================================================
// THE TWO SCOPES. Each is the place its requests go (`proxy`), every address
// it serves on (`targets`), the PEPs whose records it makes (`peps`), a tag
// in every path it asks for, and how an edit to one of its routes is made.
// The assertion groups below take a scope and nothing else, so the
// standalone PEP and the cluster are held to literally the same code.
//
// **ONE CONTAINER IS BOTH SCOPES, ONE AFTER THE OTHER**: `pep-cluster-1` is
// the standalone PEP first, holding the document as its OWN (set-pep-proxy),
// and then its proxy is CLEARED and it joins the cluster with no
// configuration of its own — so the cluster starts from what an empty PEP
// joining an empty cluster gives, no `discard` needed, which the join itself
// proves (it refuses a PEP still holding one, STS-XACML-0272). A third
// container would buy nothing the clear does not: what the standalone half
// asserts is the PEP's own document, and the member's in-memory proxy
// sessions from it are in browsers (jars) the cluster half never uses. What
// the clear leaves is the standalone routes' generated `pep-<pep>-<route>`
// policies, which no cluster route names (each is `pepc-<cluster>-<route>`).
// ===========================================================================
const SOLO = MEMBERS[0];

function standaloneScope() {
  log.debug("Entering standaloneScope().");
  log.debug("Leaving standaloneScope().");
  return {
    label: "the standalone PEP " + SOLO, tag: STAMP + "-solo",
    proxy: memberProxy(SOLO), peps: [SOLO],
    targets: [[SOLO, memberProxy(SOLO)]],
    editTargets: [SOLO],
    edit: function (route) {
      log.debug("Entering edit(). standalone");
      log.debug("Leaving edit().");
      return act("/xacml/set-pep-route", { name: SOLO, position: 0,
                                           route: route },
                 "added a public route at the head of " + SOLO + "'s table");
    }
  };
}

function clusterScope() {
  log.debug("Entering clusterScope().");
  log.debug("Leaving clusterScope().");
  return {
    label: "the cluster " + CLUSTER + " behind " + LB, tag: STAMP + "-clu",
    proxy: LB_PROXY, peps: MEMBERS.slice(),
    targets: [["the balancer", LB_PROXY]].concat(MEMBERS.map(
      function (name) {
        return [name, memberProxy(name)];
      })),
    editTargets: MEMBERS.slice(),
    edit: function (route) {
      log.debug("Entering edit(). cluster");
      log.debug("Leaving edit().");
      return act("/xacml/set-pep-cluster-route", { cluster: CLUSTER,
                                                   position: 0,
                                                   route: route },
                 "added a public route at the head of " + CLUSTER +
                 "'s table");
    }
  };
}

async function theStandalonePepIsConfigured(scope) {
  log.debug("Entering theStandalonePepIsConfigured().");
  log.info("=== Standalone: " + SOLO + " holds the document as its own ===");
  await act("/xacml/set-pep-proxy", { name: SOLO,
    proxy: theDocument(memberProxy(SOLO)) },
    "saved " + SOLO + "'s own reverse proxy");
  const row = await pepRow(SOLO);
  check(SOLO + "'s row holds the four routes and no secret", function () {
    const routes = ((row && row.proxy && row.proxy.routes) || [])
      .map(function (one) {
        return one.id;
      });
    ["public", "pep-app-api-admin", "pep-app-api", "pep-app"]
      .forEach(function (id) {
        assert.ok(routes.indexOf(id) >= 0,
          "the row's proxy holds " + JSON.stringify(routes));
      });
    assert.ok(!appSecret || JSON.stringify(row).indexOf(appSecret) < 0,
      "the application's client secret is on the PEP's row");
  });
  await untilServed(scope);
  log.debug("Leaving theStandalonePepIsConfigured().");
}

// The standalone document cleared: its member must answer 404 before it
// joins, so the cluster never starts from anything it held.
async function theStandaloneDocumentIsCleared() {
  log.debug("Entering theStandaloneDocumentIsCleared().");
  await act("/xacml/clear-pep-proxy", { name: SOLO },
            "cleared " + SOLO + "'s own reverse proxy");
  const gone = await until(SOLO + " to drop its own proxy configuration",
                           async function () {
    const r = await request("GET", memberProxy(SOLO) + "/pep-app/public/x",
                            { headers: { accept: "application/json" } });
    return { ok: r.status === 404, note: "it answered " + told(r) };
  });
  check(SOLO + " holds no proxy before it joins the cluster", function () {
    assert.ok(gone.ok);
  });
  log.debug("Leaving theStandaloneDocumentIsCleared().");
}

async function theClusterIsConfigured(scope) {
  log.debug("Entering theClusterIsConfigured().");
  log.info("=== Cluster: " + CLUSTER + " holds the same document ===");
  await act("/xacml/create-pep-cluster", { cluster: CLUSTER,
    description: "8081's pep-demo, in the suite" }, "created " + CLUSTER);
  for (const name of MEMBERS) {
    /* eslint-disable no-await-in-loop */
    await act("/xacml/add-pep-cluster-member", { cluster: CLUSTER,
      pep: name, publicBaseUrl: LB_PROXY },
      "added " + name + " to " + CLUSTER + " (with no `discard`: a PEP " +
      "holding no configuration of its own needs none)");
    /* eslint-enable no-await-in-loop */
  }
  await act("/xacml/set-pep-cluster-proxy", { cluster: CLUSTER,
    proxy: theDocument(LB_PROXY) }, "saved the cluster's reverse proxy");
  const r = await get(api("/xacml/pep-clusters?cluster=" + CLUSTER));
  check("the cluster holds both members and no secret", function () {
    assert.strictEqual(r.status, 200,
      "GET /admin-api/xacml/pep-clusters?cluster= answered " + r.status);
    MEMBERS.forEach(function (name) {
      assert.ok(r.text.indexOf('"' + name + '"') >= 0,
        "the cluster's answer names no member " + name + ": " +
        withoutSecret(r.text).slice(0, 400));
    });
    assert.ok(!appSecret || r.text.indexOf(appSecret) < 0,
      "the application's client secret is in the cluster's answer");
  });
  await untilServed(scope);
  log.debug("Leaving theClusterIsConfigured().");
}

// ===========================================================================
// THE SHARED ASSERTION GROUPS, each over one scope.
// ===========================================================================

// PUBLIC ACCESS, at every address the scope serves on.
async function publicAccess(scope) {
  log.debug("Entering publicAccess(). " + scope.label);
  log.info("=== " + scope.label + ": public access ===");
  for (const one of scope.targets) {
    const p = "/pep-app/public/open-" + scope.tag;
    /* eslint-disable no-await-in-loop */
    const before = await upstreamHits();
    const r = await request("GET", one[1] + p + "?x=1",
                            { headers: { accept: "application/json" } });
    const after = await upstreamHits();
    /* eslint-enable no-await-in-loop */
    check(scope.label + ": an anonymous GET of the public route through " +
          one[0] + " is forwarded and answered", function () {
      assert.strictEqual(r.status, 200, "GET " + p + " through " + one[0] +
                         " answered " + told(r));
      assert.ok(r.json && r.json.page === "public" && r.json.query &&
                r.json.query.x === "1",
        "the echo should be the public page with its query; it is " +
        String(r.text).slice(0, 300));
      assert.ok(!echoed(r, "x-remote-user"),
        "a public route names nobody; X-Remote-User arrived as " +
        echoed(r, "x-remote-user"));
      assert.strictEqual(hitsOn(after, p), hitsOn(before, p) + 1,
        "and the companion counted exactly that request");
    });
  }
  log.debug("Leaving publicAccess().");
}

// A PERSON WITH THE ROLE, AND THE ADMINISTRATOR. Answers the reader's
// session, which the cluster's stickiness check reuses.
async function aRoleHolderIsAdmitted(scope) {
  log.debug("Entering aRoleHolderIsAdmitted(). " + scope.label);
  log.info("=== " + scope.label + ": a person with the role ===");
  const page = scope.proxy + "/pep-app/protected/report-" + scope.tag;
  const p = new URL(page).pathname;
  const before = await upstreamHits();
  const session = await signInAt(page, READER);
  const after = await upstreamHits();
  const r = session.walked.r;
  check(scope.label + ": signed in by the session route, " + READER +
        " reaches the protected page with the identity headers",
        function () {
    assert.strictEqual(r.status, 200,
      "the sign-in should end on " + page + "; it ended " + r.status +
      " at " + session.walked.url + " after " +
      JSON.stringify(session.walked.passed) + " " +
      withoutSecret(String(r.text)).slice(0, 300));
    assert.ok(wentThroughTheCallback(session.walked),
      "through the proxy's callback; it passed " +
      JSON.stringify(session.walked.passed));
    assert.strictEqual((r.json || {}).page, "protected",
      "the application's protected page answered");
    assert.strictEqual(echoed(r, "x-remote-user"), READER,
      "X-Remote-User names the person");
    assert.ok(echoed(r, "x-iya-user"), "X-Iya-User carries their subject");
    assert.ok(/session/i.test(echoed(r, "x-iya-auth")),
      "X-Iya-Auth says how; it arrived as " + echoed(r, "x-iya-auth"));
    // Present, not equal to the entry's mail: a development realm answers
    // the email claim with an address of its own domain.
    assert.ok(/@/.test(echoed(r, "x-iya-email")),
      "X-Iya-Email carries an address; it arrived as " +
      JSON.stringify(echoed(r, "x-iya-email")));
    assert.strictEqual(hitsOn(after, p), hitsOn(before, p) + 1,
      "and the application saw the one admitted request");
  });

  const items = await request("GET", scope.proxy + "/pep-app/api/items", {
    headers: { authorization: basic(READER), accept: "application/json",
               "x-remote-user": "mallory" } });
  check(scope.label + ": the simple API route admits " + READER + " on a " +
        "Basic credential, named to the application as themself",
        function () {
    assert.strictEqual(items.status, 200,
      "GET /pep-app/api/items with Basic answered " + told(items));
    assert.strictEqual((items.json || {}).page, "items",
      "the application's items page answered");
    assert.strictEqual(echoed(items, "x-remote-user"), READER,
      "X-Remote-User is the person, never the client's mallory");
    assert.ok(!("authorization" in ((items.json || {}).headers || {})),
      "forwardCredentials is false, so the credential must not reach the " +
      "application");
  });

  const adminPath = "/pep-app/api/admin/console-" + scope.tag;
  const beforeAdmin = await upstreamHits();
  const asAdmin = await request("GET", scope.proxy + adminPath, {
    headers: { authorization: basic(ADMIN), accept: "application/json" } });
  const asReader = await request("GET", scope.proxy + adminPath, {
    headers: { authorization: basic(READER), accept: "application/json" } });
  const afterAdmin = await upstreamHits();
  check(scope.label + ": the admin route admits " + ADMIN + " and refuses " +
        READER + " on Basic", function () {
    assert.strictEqual(asAdmin.status, 200,
      ADMIN + " holds " + ADMINS_ROLE + "; GET " + adminPath + " answered " +
      told(asAdmin));
    assert.strictEqual(echoed(asAdmin, "x-remote-user"), ADMIN,
      "naming the administrator");
    assert.strictEqual(asReader.status, 403,
      READER + " holds " + USERS_ROLE + " only, which the admin route does " +
      "not grant; it answered " + told(asReader));
    assert.strictEqual(hitsOn(afterAdmin, adminPath),
                       hitsOn(beforeAdmin, adminPath) + 1,
      "and only the administrator's request reached the application");
  });

  const adminPage = scope.proxy + "/pep-app/api/admin/report-" + scope.tag;
  const adminPagePath = new URL(adminPage).pathname;
  const beforeSessions = await upstreamHits();
  const adminWalk = await signInAt(adminPage, ADMIN);
  const readerWalk = await signInAt(adminPage, READER);
  const afterSessions = await upstreamHits();
  check(scope.label + ": signed in by session, the admin route admits " +
        ADMIN + " and shows " + READER + " the refusal page", function () {
    assert.strictEqual(adminWalk.walked.r.status, 200,
      ADMIN + "'s sign-in at " + adminPage + " ended " +
      adminWalk.walked.r.status + " after " +
      JSON.stringify(adminWalk.walked.passed));
    assert.strictEqual(echoed(adminWalk.walked.r, "x-remote-user"), ADMIN,
      "naming the administrator");
    assert.ok(wentThroughTheCallback(readerWalk.walked),
      READER + " signed in through the callback before being refused; " +
      "they passed " + JSON.stringify(readerWalk.walked.passed));
    assert.strictEqual(readerWalk.walked.r.status, 403,
      READER + " signed in and should be refused the admin route; it " +
      "ended " + readerWalk.walked.r.status);
    assert.ok(isRefusalPage(readerWalk.walked.r),
      "a browser is refused with the proxy's HTML refusal page; it got " +
      JSON.stringify(readerWalk.walked.r.headers["content-type"]) + " " +
      String(readerWalk.walked.r.text).slice(0, 300));
    assert.strictEqual(hitsOn(afterSessions, adminPagePath),
                       hitsOn(beforeSessions, adminPagePath) + 1,
      "and only the administrator's access reached the application");
  });
  log.debug("Leaving aRoleHolderIsAdmitted().");
  return session;
}

// A PERSON WITHOUT THE ROLE, AND NOBODY AT ALL.
async function aPersonWithoutTheRoleIsRefused(scope) {
  log.debug("Entering aPersonWithoutTheRoleIsRefused(). " + scope.label);
  log.info("=== " + scope.label + ": a person without the role ===");
  const page = scope.proxy + "/pep-app/protected/report-" + scope.tag +
               "-out";
  const p = new URL(page).pathname;
  const itemsPath = "/pep-app/api/denied-" + scope.tag;
  const before = await upstreamHits();
  const walked = (await signInAt(page, OUTSIDER)).walked;
  const items = await request("GET", scope.proxy + itemsPath, {
    headers: { authorization: basic(OUTSIDER), accept: "application/json" } });
  const after = await upstreamHits();
  check(scope.label + ": " + OUTSIDER + " signs in and is refused the " +
        "session route with the refusal page", function () {
    assert.ok(wentThroughTheCallback(walked),
      "the sign-in itself works; it passed " + JSON.stringify(walked.passed));
    assert.strictEqual(walked.r.status, 403,
      OUTSIDER + " holds no " + USERS_ROLE + "; " + page + " answered " +
      walked.r.status + " " + String(walked.r.text).slice(0, 200));
    assert.ok(isRefusalPage(walked.r),
      "the refusal is the proxy's HTML page: " +
      String(walked.r.text).slice(0, 300));
  });
  check(scope.label + ": " + OUTSIDER + " is refused the simple route on " +
        "Basic", function () {
    assert.strictEqual(items.status, 403,
      "GET " + itemsPath + " with " + OUTSIDER + "'s Basic answered " +
      told(items));
    assert.ok(!/text\/html/i.test(String(items.headers["content-type"] ||
                                         "")),
      "an API client that does not accept HTML gets the JSON refusal");
  });
  check(scope.label + ": nothing of " + OUTSIDER + "'s reached the " +
        "application", function () {
    assert.strictEqual(hitsOn(after, p), hitsOn(before, p),
      "the refused session access was forwarded");
    assert.strictEqual(hitsOn(after, itemsPath), hitsOn(before, itemsPath),
      "the refused Basic request was forwarded");
  });

  const anonPath = "/pep-app/protected/anon-" + scope.tag;
  const anonItems = "/pep-app/api/items";
  const beforeAnon = await upstreamHits();
  const machine = await request("GET", scope.proxy + anonPath,
                                { headers: { accept: "application/json" } });
  const browser = await request("GET", scope.proxy + anonPath,
    { headers: { accept: "text/html,application/xhtml+xml" } });
  const api401 = await request("GET", scope.proxy + anonItems,
                               { headers: { accept: "application/json" } });
  const afterAnon = await upstreamHits();
  check(scope.label + ": nobody is 401 to a machine and sent to sign in " +
        "as a browser", function () {
    assert.strictEqual(machine.status, 401,
      "GET " + anonPath + " with no session and no browser Accept answered " +
      told(machine));
    assert.strictEqual(browser.status, 302,
      "as a browser it should be a redirect to sign in; it answered " +
      told(browser));
    const to = new URL(browser.headers.location, scope.proxy);
    assert.ok(/\/oauth2\/authorize$/.test(to.pathname) &&
              to.pathname.indexOf("/realm/" + REALM + "/") >= 0,
      "to this realm's authorization endpoint; it is " + to.pathname);
    assert.strictEqual(to.searchParams.get("client_id"), APP,
      "as the route's application");
    // PUSHED (RFC 9126): the relying party sends its redirect URI in the
    // pushed request, so the browser's address carries a request_uri; one
    // sent in the address must be the scope's callback.
    assert.ok(/^urn:ietf:params:oauth:request_uri:/.test(
                String(to.searchParams.get("request_uri") || "")) ||
              to.searchParams.get("redirect_uri") ===
                scope.proxy + "/.iya-pep/callback",
      "returning to the callback at the scope's publicBaseUrl, pushed or " +
      "in the address; it is " + to.search);
    assert.strictEqual(api401.status, 401,
      "GET " + anonItems + " with nothing answered " + told(api401));
    assert.ok(/Basic/i.test(String(api401.headers["www-authenticate"] || "")),
      "with a Basic challenge, a mechanism the route takes");
    assert.strictEqual(hitsOn(afterAnon, anonPath), hitsOn(beforeAnon,
                                                           anonPath),
      "and the application saw none of it");
    assert.strictEqual(hitsOn(afterAnon, anonItems),
                       hitsOn(beforeAnon, anonItems),
      "nor the unauthenticated API request");
  });
  log.debug("Leaving aPersonWithoutTheRoleIsRefused().");
}

// ONE EDIT TO THE SCOPE'S ROUTE TABLE REACHES EVERY RUNNING PROXY IN IT.
async function oneEditReaches(scope) {
  log.debug("Entering oneEditReaches(). " + scope.label);
  log.info("=== " + scope.label + ": one route edit reaches every proxy ===");
  const editPath = "/pep-app/edited-" + scope.tag;
  const probe = editPath + "/page";
  const before = {};
  for (const name of scope.editTargets) {
    /* eslint-disable no-await-in-loop */
    before[name] = await request("GET", memberProxy(name) + probe,
                                 { headers: { accept: "application/json" } });
    /* eslint-enable no-await-in-loop */
  }
  check(scope.label + ": before the edit, " + editPath + " is the session " +
        "route's", function () {
    scope.editTargets.forEach(function (name) {
      assert.strictEqual(before[name].status, 401,
        name + " answered " + told(before[name]) + " for " + probe);
    });
  });
  const saved = Date.now();
  await scope.edit({ id: "edited", path: editPath, match: "prefix",
                     methods: ["GET", "HEAD"],
                     authorization: { kind: "public" } });
  const took = {};
  for (const name of scope.editTargets) {
    /* eslint-disable no-await-in-loop */
    await until(name + " to serve the route the edit added",
                async function () {
      const r = await request("GET", memberProxy(name) + probe,
                              { headers: { accept: "application/json" } });
      return { ok: r.status === 200 && !!r.json && r.json.page === "other",
               note: "GET " + probe + " answered " + told(r) };
    }, 60000);
    /* eslint-enable no-await-in-loop */
    took[name] = Date.now() - saved;
  }
  const hitsBefore = await upstreamHits();
  const via = await request("GET", scope.proxy + probe,
                            { headers: { accept: "application/json" } });
  const hitsAfter = await upstreamHits();
  check(scope.label + ": the edit reached every running proxy, and the " +
        "scope's address serves it", function () {
    assert.strictEqual(via.status, 200,
      "GET " + probe + " at " + scope.proxy + " answered " + told(via));
    assert.ok(!echoed(via, "x-remote-user"), "a public route names nobody");
    assert.strictEqual(hitsOn(hitsAfter, probe), hitsOn(hitsBefore, probe) +
                       1, "and the companion counted it");
  });
  log.info(scope.label + ": the edit reached " + JSON.stringify(took) +
           " ms after it was saved.");
  log.debug("Leaving oneEditReaches().");
}

// The realm's audit, asked of the service and of every node a cluster mode
// names: a row is the node's that received the push, and the store
// replicates it to the others' next read.
async function proxyAuditRows() {
  log.debug("Entering proxyAuditRows().");
  const bases = [base].concat(String(process.env.STS_TEST_NODE_URLS || "")
    .split(",").map(function (one) {
      return one.trim().replace(/\/+$/, "");
    }).filter(Boolean));
  const rows = [];
  for (const one of bases) {
    /* eslint-disable no-await-in-loop */
    const r = await get(one + "/realm/" + REALM +
                        "/admin-api/audit?per=500&action=xacml.remote.proxy");
    /* eslint-enable no-await-in-loop */
    if (r.status === 200 && r.body) {
      [].concat(r.body.events || r.body.rows || r.body.entries || [])
        .forEach(function (row) {
          rows.push(row);
        });
    }
  }
  log.debug("Leaving proxyAuditRows(). " + rows.length);
  return rows;
}

// EVERY PEP OF THE SCOPE'S DECISIONS IN THE AUDIT LOG, its refusal of the
// person without the role (a path carrying the scope's tag) among them.
async function theScopeIsAudited(scope) {
  log.debug("Entering theScopeIsAudited(). " + scope.label);
  log.info("=== " + scope.label + ": decision records in the audit log ===");
  let rows = [];
  const of = function (name) {
    log.debug("Entering of().");
    log.debug("Leaving of().");
    return rows.filter(function (row) {
      return row.detail && row.detail.pep === name;
    });
  };
  const refusedOutsider = function (name) {
    log.debug("Entering refusedOutsider().");
    log.debug("Leaving refusedOutsider().");
    return of(name).filter(function (row) {
      const text = JSON.stringify(row);
      return row.outcome === "refused" && text.indexOf(OUTSIDER) >= 0 &&
             text.indexOf(scope.tag) >= 0;
    });
  };
  await until(scope.label + "'s xacml.remote.proxy rows in " + REALM +
              "'s audit", async function () {
    rows = await proxyAuditRows();
    return { ok: scope.peps.every(function (name) {
      return refusedOutsider(name).length > 0;
    }), note: rows.length + " row(s): " + JSON.stringify(scope.peps.map(
      function (name) {
        return [name, of(name).length, refusedOutsider(name).length];
      })) };
  }, 60000);
  check(scope.label + ": each PEP's decisions are xacml.remote.proxy rows " +
        "naming it, its refusal of " + OUTSIDER + " among them", function () {
    scope.peps.forEach(function (name) {
      assert.ok(refusedOutsider(name).length > 0,
        "no refused row of " + name + "'s names " + OUTSIDER + " on a " +
        scope.tag + " path");
      assert.ok(of(name).every(function (row) {
        return row.action === "xacml.remote.proxy";
      }), "every row is xacml.remote.proxy");
      // The three people's Basic credentials as sent, a PEM and the
      // proxy's session cookie: none may be in a row. (A pattern for "a
      // Basic credential" matched the PEP's own "Basic validation could
      // not be asked" reason on the first hand run.)
      const text = JSON.stringify(of(name));
      [READER, ADMIN, OUTSIDER].forEach(function (who) {
        assert.ok(text.indexOf(basic(who).slice(6)) < 0,
          "a row carries " + who + "'s Basic credential");
      });
      assert.ok(!/BEGIN [A-Z ]+-----|iya_pep_session=/.test(text),
        "no PEM or proxy cookie in a row");
    });
  });
  log.debug("Leaving theScopeIsAudited().");
}

// ===========================================================================
// THE CLUSTER'S OWN: the members alike, and the balancer.
// ===========================================================================
async function theMembersDecideAlike(scope) {
  log.debug("Entering theMembersDecideAlike().");
  log.info("=== " + scope.label + ": each member serves the routes and " +
           "decides alike ===");
  const cases = [
    ["/pep-app/api/items", READER, 200],
    ["/pep-app/api/denied-" + scope.tag, OUTSIDER, 403],
    ["/pep-app/api/admin/console-" + scope.tag, ADMIN, 200],
    ["/pep-app/api/admin/console-" + scope.tag, READER, 403]
  ];
  const answers = {};
  for (const name of MEMBERS) {
    answers[name] = [];
    for (const one of cases) {
      /* eslint-disable no-await-in-loop */
      const r = await request("GET", memberProxy(name) + one[0], {
        headers: { authorization: basic(one[1]),
                   accept: "application/json" } });
      /* eslint-enable no-await-in-loop */
      answers[name].push(r.status);
      check(name + " answers " + one[1] + "'s GET " + one[0] + " with " +
            one[2], function () {
        assert.strictEqual(r.status, one[2], name + " answered " + told(r));
        if (one[2] === 200) {
          assert.strictEqual(echoed(r, "x-remote-user"), one[1],
            "naming " + one[1]);
        }
      });
    }
  }
  check("the members' answers are the same, case for case", function () {
    const first = JSON.stringify(answers[MEMBERS[0]]);
    MEMBERS.forEach(function (name) {
      assert.strictEqual(JSON.stringify(answers[name]), first,
        "the members disagree: " + JSON.stringify(answers));
    });
  });
  log.debug("Leaving theMembersDecideAlike().");
}

async function theBalancerSpreadsAndSticks(scope, readerSession) {
  log.debug("Entering theBalancerSpreadsAndSticks().");
  log.info("=== " + scope.label + ": round robin on 9443, sticky on " +
           "9543 ===");
  // 9443: a new connection per request, round robin, so both members
  // answer GET / behind it. Polled, because a member is DOWN at the
  // balancer until two health checks after its listener started.
  const seen = {};
  await until("both members to answer GET / behind the balancer's 9443",
              async function () {
    const r = await request("GET", LB_API + "/",
                            { headers: { accept: "application/json" } });
    const name = r.json && r.json.registration && r.json.registration.name;
    if (name) {
      seen[name] = (seen[name] || 0) + 1;
    }
    return { ok: MEMBERS.every(function (one) {
      return seen[one] > 0;
    }), note: "answered by " + JSON.stringify(seen) + "; last " + told(r) };
  }, 60000);
  check("the balancer's decision API reaches both members", function () {
    MEMBERS.forEach(function (name) {
      assert.ok(seen[name] > 0, name + " never answered: " +
                JSON.stringify(seen));
    });
  });

  // 9543: the reader's session was made through the balancer. Ten more
  // accesses through it on ten new connections all land on the member that
  // holds it, and dialled direct, exactly one member honours it.
  const page = LB_PROXY + "/pep-app/protected/sticky-" + scope.tag;
  const statuses = [];
  for (let n = 0; n < 10; n += 1) {
    /* eslint-disable no-await-in-loop */
    const r = await browserGet(readerSession.jars, page);
    /* eslint-enable no-await-in-loop */
    statuses.push(r.status + ":" + echoed(r, "x-remote-user"));
  }
  check("a session made through the balancer's 9543 is carried on every " +
        "new connection through it", function () {
    statuses.forEach(function (one) {
      assert.strictEqual(one, "200:" + READER,
        "ten GETs with the proxy session answered " +
        JSON.stringify(statuses) + ": a round-robin listener would have " +
        "sent some to the member that does not hold it");
    });
  });
  const cookie = jarHeader(readerSession.jars, LB_PROXY);
  const holders = [];
  const direct = {};
  for (const name of MEMBERS) {
    /* eslint-disable no-await-in-loop */
    const r = await request("GET", memberProxy(name) +
                            "/pep-app/protected/direct-" + scope.tag, {
      headers: { cookie: cookie, accept: "application/json" } });
    /* eslint-enable no-await-in-loop */
    direct[name] = r.status;
    if (r.status === 200 && echoed(r, "x-remote-user") === READER) {
      holders.push(name);
    }
  }
  check("exactly one member holds that session, which is why the proxy " +
        "listener must stick", function () {
    assert.strictEqual(holders.length, 1,
      "the session cookie dialled direct at each member answered " +
      JSON.stringify(direct) + "; a proxy session is in one member's " +
      "memory, so one member should honour it and the other refuse it");
    MEMBERS.filter(function (name) {
      return holders.indexOf(name) < 0;
    }).forEach(function (name) {
      assert.strictEqual(direct[name], 401,
        name + " does not hold the session and should answer a machine " +
        "401; it answered " + direct[name]);
    });
  });
  log.info("The balancer's 9443 answered from " + JSON.stringify(seen) +
           "; its 9543 kept the reader on " + holders.join(", ") + ".");
  log.debug("Leaving theBalancerSpreadsAndSticks().");
}

// ===========================================================================
// THE TWO SECTIONS: the same groups, a different target.
// ===========================================================================
async function theStandalonePep() {
  log.debug("Entering theStandalonePep().");
  const scope = standaloneScope();
  await theStandalonePepIsConfigured(scope);
  await publicAccess(scope);
  await aRoleHolderIsAdmitted(scope);
  await aPersonWithoutTheRoleIsRefused(scope);
  await oneEditReaches(scope);
  await theScopeIsAudited(scope);
  await theStandaloneDocumentIsCleared();
  log.debug("Leaving theStandalonePep().");
}

async function theClusterBehindABalancer() {
  log.debug("Entering theClusterBehindABalancer().");
  const scope = clusterScope();
  await theClusterIsConfigured(scope);
  await publicAccess(scope);
  const readerSession = await aRoleHolderIsAdmitted(scope);
  await aPersonWithoutTheRoleIsRefused(scope);
  await theMembersDecideAlike(scope);
  await theBalancerSpreadsAndSticks(scope, readerSession);
  await oneEditReaches(scope);
  await theScopeIsAudited(scope);
  log.debug("Leaving theClusterBehindABalancer().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
function whyItCannotRun() {
  log.debug("Entering whyItCannotRun().");
  const missing = [];
  if (!REALM) {
    missing.push("XACML_PEP_CLUSTER_REALM");
  }
  if (MEMBERS.length < 2) {
    missing.push("XACML_PEP_CLUSTER_MEMBERS (two names)");
  }
  if (!LB) {
    missing.push("XACML_PEP_CLUSTER_LB");
  }
  if (!CERT_DIR) {
    missing.push("XACML_PEP_CLUSTER_CERT_DIR_HERE");
  }
  if (!UPSTREAM) {
    missing.push("XACML_PEP_UPSTREAM_URL");
  }
  log.debug("Leaving whyItCannotRun().");
  return missing.length
    ? "this run brought up no remote PEP cluster (" + missing.join(", ") +
      " not set). ./run-tests.sh does, behind the `pep-cluster` compose " +
      "profile, in the modes STS_TEST_PEP_CLUSTER_MODES names (every mode " +
      "but fuzz by default); a coverage run or an AWS target has none, so " +
      "here the remote PEP cluster, its balancer and its reverse proxy are " +
      "unchecked end to end, and what stands is tests/xacml_pep_clusters.js " +
      "and sts_xacml_remote_pep.js's single PEP."
    : "";
}

async function test() {
  log.debug("Entering test().");
  const why = whyItCannotRun();
  if (why) {
    expectation.declineToRun(log, why);
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("Driving the remote PEP cluster " + MEMBERS.join(" + ") +
           " behind " + LB + ", in " + REALM + ", against " + base + ".");
  const status = await get(base + "/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base);
  await until("the companion's /pep-app to answer", async function () {
    const r = await request("GET", UPSTREAM + "/pep-app/_hits");
    return { ok: r.status === 200, note: told(r) };
  }, 60000);

  await createTheRealm();
  await provisionTheMembers();
  await theMembersRegisterOnTheirKeys();
  await theMembersServeHttps();
  await createThePeople();
  await registerTheApplication();
  await theStandalonePep();
  await theClusterBehindABalancer();

  // A FLOOR ON THE COUNT: a section that stops being called takes its
  // assertions with it, and the run would still say "passed".
  assert.ok(checks >= 45,
    "only " + checks + " checks ran, and this file makes more than 45 " +
    "against a healthy stack: a SECTION STOPPED BEING CALLED.");
  log.info("The realm " + REALM + " is LEFT IN PLACE on purpose, with the " +
           "cluster " + CLUSTER + ", its members' rows and the people; " +
           "restart the stack before running this job against it again.");
  if (badGateways) {
    log.warn(badGateways + " request(s) were answered 502 bad_gateway " +
             "(STS-XPEP-0075) and sent again; see request().");
  }
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_xacml_pep_proxy_cluster")
  .description("Drive the two-member remote PEP cluster and its load " +
      "balancer that ./run-tests.sh brings up: each member on its own RFC " +
      "7523 key, one cluster's reverse proxy in front of the companion's " +
      "/pep-app, public, role-holding, administrator and role-less people " +
      "through the balancer and on each member, one cluster edit reaching " +
      "both, and both members' decisions in the audit log.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exitCode = 1;
});
