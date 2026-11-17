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
// A 502 `bad_gateway` IS SENT AGAIN, up to twice, and counted
// (`badGateways`, logged at the end). On the hand runs of 2026-11-16 a
// member's call to the service — POST /xacml/pep/basic or
// /xacml/pep/session — sometimes timed out after an idle spell
// (STS-XPEP-0075, "the PDP did not answer in time"), once twice in a row,
// and the next call took tens of milliseconds. Nothing is forwarded before
// that validation, so a retry cannot double a hit; it keeps that PEP-side
// defect from deciding every assertion of this job, and the count says how
// often it happened.
let badGateways = 0;
async function request(method, url, options) {
  log.debug("Entering request(). " + method + " " + url);
  let answer = await requestOnce(method, url, options);
  for (let n = 1; n < 3 && answer.status === 502 && answer.json &&
                  answer.json.error === "bad_gateway"; n += 1) {
    badGateways += 1;
    log.warn("A 502 bad_gateway from " + url + " (the PEP could not ask " +
             "the service in time); sending it again. " + told(answer));
    /* eslint-disable no-await-in-loop */
    answer = await requestOnce(method, url, options);
    /* eslint-enable no-await-in-loop */
  }
  log.debug("Leaving request().");
  return answer;
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

// ===========================================================================
// LISTENERS (2026-11-16, rcbj: "Add a test that updates each listener's
// configuration settings one at a time. Then, confirm that setting took
// effect. Include the thread pool settings. Then, create a custom listener
// for the reverse proxy. Add a new route to pep-app on the companion
// container. Make sure calls work as expected.").
//
// ON THE STANDALONE PEP AGAIN, AFTER THE CLUSTER'S SECTION: `pep-cluster-1`
// leaves the cluster with remove-pep-cluster-member's default — it keeps a
// copy of the cluster's document as its own and goes on enforcing it, which
// is asserted — so the cluster's assertions all ran against an untouched
// cluster, and a member's listener definitions, refused while it pulls a
// cluster's (STS-XACML-0276), are its own again.
//
// A) EVERY LISTENER SETTING, ONE AT A TIME, from LISTENER_ROWS below: the
//    PEP's four environment listeners that listen in this stack (api-http,
//    api-https, proxy-https; proxy-http is off, PEP_PROXY_HTTP=false) and
//    the custom one B makes. For each row: the setting changed through
//    /admin-api (set-pep-environment-tuning, or set-pep-listener for the
//    custom one), the PEP's own report that it holds what would be sent
//    now (the PDP's row `settingsCurrent`, from a heartbeat after the
//    change, and GET /'s settings token the same), the effect OBSERVED on
//    the wire, then the setting restored and the restore observed too. A
//    TLS row is a plain-HTTP listener's too, and is not run there: the PEP
//    forces HTTP/2 and the client-certificate questions off for HTTP and
//    has no handshake for the others to change. HOW EACH IS OBSERVED:
//
//      disableTls12         a TLS 1.2 client completes the handshake once
//                           it is off with minVersion TLSv1.2, and is
//                           refused again restored
//      minVersion           with disableTls12 off: TLSv1.2 admits that
//                           client, TLSv1.3 refuses it
//      ciphers              with TLS 1.2 on: a client offering only the
//                           AES-256 suites is admitted and one offering only
//                           AES-128 refused
//      tls13CipherSuites    the suite the handshake chose: CHACHA20 alone
//                           admits a default client on it and refuses an
//                           AES-128-only one; restored, AES-128-only again
//                           admitted
//      pqcOnly              a client offering only X25519 is refused, and
//                           admitted restored; a default client is admitted
//                           over a post-quantum group
//      groups               "P-256" alone: an X25519-only client refused, a
//                           P-256 one admitted
//      signatureAlgorithms  only an algorithm the listener's key cannot
//                           make: every handshake refused; restored,
//                           admitted
//      requireClientCertificate  with a trust anchors file set first, a
//                           client with no certificate is refused (the PEP
//                           asks nobody on the API listener without one)
//      keepAliveTimeoutS    an idle keep-alive connection is closed by the
//                           PEP within the new bound, and held past it
//                           restored
//      headersTimeoutS      a request whose headers never finish should be
//                           closed within the new bound: A KNOWN PEP DEFECT
//                           (the row's `knownDefect`) — held and not applied
//      maxRequestsPerSocket 1: the second request on one connection is not
//                           answered; restored, both are
//      maxConnections       1: a second connection beside one held open is
//                           refused; restored, both answered
//      http2                an h2 client by prior knowledge gets the PEP's
//                           SETTINGS on, and fails off (ALPN never selects
//                           h2: a PEP defect, logged by the row)
//      http2MaxConcurrentStreams  the SETTINGS frame's
//                           MAX_CONCURRENT_STREAMS the PEP sends
//      threadPoolMin, threadPoolMax  the listener's pool, as the PEP itself
//                           reports it on its heartbeat (`stats.pool`)
//      port                 the new port answers, the old one refuses
//      address              bound to 127.0.0.1 it refuses this job, which
//                           dials from another container; 0.0.0.0 admits it
//      dnsNames, ipAddresses  the names in the certificate the listener
//                           serves, which the PEP requested anew
//      keyAlg               the served certificate's key type
//      protocol             http: the port answers plain HTTP, and no TLS
//      purpose              api: the port answers GET / as the PEP's own
//                           API; proxy: the proxy's routes
//
//    OBSERVED ONLY AS PULLED (the PEP reports holding it, and nothing on
//    the wire this job can see changes): trustAnchorsFile,
//    trustIssuedClientCertificates and askClientCertificate (which
//    authorities a CertificateRequest names; a Node client cannot read
//    them), sessionCacheSize (TLS 1.3 resumes from a stateless ticket
//    whatever the server's cache holds), and sessionTimeoutS — which the
//    PEP does NOT APPLY: its TLS library has no session-lifetime call, and
//    it logs STS-XPEP-0119 for any value but 300.
//
//    THE TABLE IS CHECKED AGAINST THE MODEL: every tuning key the service's
//    listener catalogue declares (`tuningDefaults`) and every member of a
//    defined listener but its id, `renew` and `tuning` must have a row, so
//    a knob added later without one fails this job.
//
// B) A CUSTOM LISTENER FOR THE REVERSE PROXY: an HTTPS proxy listener on
//    9643 (exposed by the stack on the member's network), its certificate
//    requested by the PEP over its own key and issued by the realm, bound
//    without a restart and answering the proxy's routes.
// C) A NEW pep-app ROUTE: `/pep-app/whoami` on the companion, which names
//    the identity the proxy forwarded and the listener it came through,
//    behind a simple route for pep-demo-users, asked on the custom listener
//    by the role holder (admitted, named, via 9643) and the person without
//    the role (refused, nothing forwarded), while the environment listener
//    still serves the other routes; then the custom listener is removed and
//    its port stops answering.
// ===========================================================================
const net = require("net");
const tls = require("tls");
const http2 = require("http2");
const dns = require("dns");

const CUSTOM = { id: "proxy-custom", protocol: "https", purpose: "proxy",
                 address: "0.0.0.0", port: 9643, keyAlg: "ec-p256" };
const CUSTOM_MOVED_PORT = 9644;
const LISTENER_CONVERGE_MS = 60000;

function socketTarget(listener) {
  log.debug("Entering socketTarget(). " + listener.id);
  log.debug("Leaving socketTarget().");
  return { host: SOLO, port: listener.port, https: listener.https,
           path: listener.purpose === "proxy"
             ? "/pep-app/public/probe-" + STAMP : "/healthcheck" };
}

// ONE CONNECTION, plain or TLS, under the options a row asks for, that
// writes `requests` HTTP/1.1 requests one after another on it and says what
// came back: the handshake (protocol, suite, group, ALPN, the certificate),
// each status line, and whether and when the PEP closed it. Never throws.
function probe(target, options) {
  log.debug("Entering probe(). " + target.host + ":" + target.port);
  const o = options || {};
  log.debug("Leaving probe().");
  return new Promise(function (resolve) {
    const started = Date.now();
    const out = { handshake: false, statuses: [], closedAfterMs: null,
                  error: null, protocol: null, cipher: null, group: null,
                  alpn: null, certificate: null };
    let socket = null;
    let buffered = "";
    let sent = 0;
    let finished = false;
    let idleTimer = null;
    const finish = function () {
      log.debug("Entering finish().");
      if (finished) {
        log.debug("Leaving finish(). Already.");
        return;
      }
      finished = true;
      clearTimeout(idleTimer);
      if (socket) {
        socket.destroy();
      }
      log.debug("Leaving finish().");
      resolve(out);
    };
    const sendOne = function () {
      log.debug("Entering sendOne().");
      sent += 1;
      const last = sent >= (o.requests === undefined ? 1 : o.requests);
      socket.write(o.partial
        ? "GET " + target.path + " HTTP/1.1\r\nHost: " + target.host + "\r\n"
        : "GET " + target.path + " HTTP/1.1\r\nHost: " + target.host + ":" +
          target.port + "\r\nAccept: application/json\r\n" +
          (last && !o.holdMs ? "Connection: close\r\n" : "") + "\r\n");
      log.debug("Leaving sendOne().");
    };
    const ready = function () {
      log.debug("Entering ready().");
      out.handshake = true;
      if (target.https) {
        out.protocol = socket.getProtocol();
        out.cipher = (socket.getCipher() || {}).name || null;
        const key = socket.getEphemeralKeyInfo();
        out.group = key ? key.name || key.type : null;
        out.alpn = socket.alpnProtocol || null;
        const peer = socket.getPeerX509Certificate();
        out.certificate = peer ? { subjectAltName: peer.subjectAltName,
          keyType: peer.publicKey.asymmetricKeyType } : null;
      }
      if (o.handshakeOnly) {
        finish();
        log.debug("Leaving ready(). Handshake only.");
        return;
      }
      if ((o.requests === undefined ? 1 : o.requests) > 0 || o.partial) {
        sendOne();
      }
      if (o.holdMs) {
        idleTimer = setTimeout(finish, o.holdMs);
      }
      log.debug("Leaving ready().");
    };
    const connect = Object.assign({ host: target.host, port: target.port },
                                  o.connect || {});
    if (target.https) {
      Object.assign(connect, { servername: target.host,
                               ca: listenerAnchorPem ? [listenerAnchorPem]
                                                     : undefined,
                               rejectUnauthorized: !o.insecure });
      socket = tls.connect(connect, ready);
    } else {
      socket = net.connect(connect, ready);
    }
    socket.setEncoding("utf8");
    socket.on("data", function (chunk) {
      buffered += chunk;
      const lines = buffered.match(/HTTP\/1\.1 \d{3}/g) || [];
      out.statuses = lines.map(function (one) {
        return Number(one.slice(9));
      });
      if (out.statuses.length >= sent && sent <
          (o.requests === undefined ? 1 : o.requests) &&
          /\r\n\r\n/.test(buffered)) {
        sendOne();
      }
    });
    socket.on("error", function (e) {
      out.error = e.code || e.message;
      finish();
    });
    socket.on("close", function () {
      out.closedAfterMs = Date.now() - started;
      finish();
    });
    setTimeout(finish, o.timeoutMs || 8000);
  });
}

// The SETTINGS frame an HTTP/2 connection to the listener gets first.
function http2Settings(target) {
  log.debug("Entering http2Settings().");
  log.debug("Leaving http2Settings().");
  return new Promise(function (resolve) {
    let done = false;
    const session = http2.connect("https://" + target.host + ":" +
                                  target.port,
      { ca: listenerAnchorPem ? [listenerAnchorPem] : undefined,
        servername: target.host });
    const end = function (value) {
      log.debug("Entering end().");
      if (!done) {
        done = true;
        session.destroy();
        resolve(value);
      }
      log.debug("Leaving end().");
    };
    session.on("remoteSettings", function (settings) {
      end({ ok: true, settings: settings });
    });
    session.on("error", function (e) {
      end({ ok: false, error: e.code || e.message });
    });
    setTimeout(function () {
      end({ ok: false, error: "no SETTINGS within 5s" });
    }, 5000);
  });
}

// What the PEP reported last about one of its listeners, on the PDP's row.
async function reported(id) {
  log.debug("Entering reported(). " + id);
  const row = await pepRow(SOLO);
  const found = (((row || {}).listenersInUse || {}).listeners || [])
    .filter(function (one) {
      return one.id === id;
    })[0] || null;
  log.debug("Leaving reported().");
  return { row: row, listener: found };
}

const TLS12 = { maxVersion: "TLSv1.2" };
const CLASSIC_AES128 = "ECDHE-ECDSA-AES128-GCM-SHA256:" +
                       "ECDHE-RSA-AES128-GCM-SHA256";
const CLASSIC_AES256 = "ECDHE-ECDSA-AES256-GCM-SHA384:" +
                       "ECDHE-RSA-AES256-GCM-SHA384";
const answered = function (p) {
  log.debug("Entering answered().");
  log.debug("Leaving answered().");
  return p.handshake && p.statuses.length > 0 && p.statuses[0] < 500;
};

// ---------------------------------------------------------------------------
// THE TABLE. `tls` rows apply to an HTTPS listener only; `definition` rows
// to the custom one only. `change` is laid over the listener's defaults (or
// over `from`, set and observed first); `changed` and `restored` observe.
// A row with `pulledOnly` is asserted only as held by the PEP, and says why.
// ---------------------------------------------------------------------------
const LISTENER_ROWS = [
  { key: "disableTls12", tls: true,
    change: { disableTls12: false, minVersion: "TLSv1.2" },
    changed: async function (t) {
      const p = await probe(t, { connect: TLS12 });
      return { ok: answered(p) && p.protocol === "TLSv1.2",
               note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, { connect: TLS12 });
      return { ok: !p.handshake, note: JSON.stringify(p) };
    } },
  { key: "minVersion", tls: true,
    from: { disableTls12: false, minVersion: "TLSv1.2" },
    fromObserved: async function (t) {
      const p = await probe(t, { connect: TLS12 });
      return { ok: answered(p), note: JSON.stringify(p) };
    },
    change: { disableTls12: false, minVersion: "TLSv1.3" },
    changed: async function (t) {
      const p = await probe(t, { connect: TLS12 });
      const q = await probe(t, {});
      return { ok: !p.handshake && answered(q) && q.protocol === "TLSv1.3",
               note: JSON.stringify([p, q]) };
    },
    restored: async function (t) {
      const p = await probe(t, { connect: TLS12 });
      return { ok: !p.handshake, note: JSON.stringify(p) };
    } },
  { key: "ciphers", tls: true,
    change: { disableTls12: false, minVersion: "TLSv1.2",
              ciphers: CLASSIC_AES256 },
    changed: async function (t) {
      const p = await probe(t, { connect: Object.assign(
        { ciphers: CLASSIC_AES128 }, TLS12) });
      const q = await probe(t, { connect: Object.assign(
        { ciphers: CLASSIC_AES256 }, TLS12) });
      return { ok: !p.handshake && answered(q) && /AES256/.test(q.cipher),
               note: JSON.stringify([p, q]) };
    },
    restored: async function (t) {
      const p = await probe(t, { connect: TLS12 });
      return { ok: !p.handshake, note: JSON.stringify(p) };
    } },
  { key: "tls13CipherSuites", tls: true,
    change: { tls13CipherSuites: "TLS_CHACHA20_POLY1305_SHA256" },
    changed: async function (t) {
      const p = await probe(t, {});
      const q = await probe(t, { connect:
        { ciphers: "TLS_AES_128_GCM_SHA256" } });
      return { ok: answered(p) && p.cipher === "TLS_CHACHA20_POLY1305_SHA256" &&
                   !q.handshake, note: JSON.stringify([p, q]) };
    },
    restored: async function (t) {
      const q = await probe(t, { connect:
        { ciphers: "TLS_AES_128_GCM_SHA256" } });
      return { ok: answered(q) && q.cipher === "TLS_AES_128_GCM_SHA256",
               note: JSON.stringify(q) };
    } },
  { key: "pqcOnly", tls: true, change: { pqcOnly: true },
    changed: async function (t) {
      const p = await probe(t, { connect: { ecdhCurve: "X25519" } });
      const q = await probe(t, {});
      return { ok: !p.handshake && answered(q) && /MLKEM/i.test(q.group),
               note: JSON.stringify([p, q]) };
    },
    restored: async function (t) {
      const p = await probe(t, { connect: { ecdhCurve: "X25519" } });
      return { ok: answered(p), note: JSON.stringify(p) };
    } },
  { key: "groups", tls: true, change: { groups: "P-256" },
    changed: async function (t) {
      const p = await probe(t, { connect: { ecdhCurve: "X25519" } });
      const q = await probe(t, { connect: { ecdhCurve: "P-256" } });
      return { ok: !p.handshake && answered(q), note: JSON.stringify([p, q]) };
    },
    restored: async function (t) {
      const p = await probe(t, { connect: { ecdhCurve: "X25519" } });
      return { ok: answered(p), note: JSON.stringify(p) };
    } },
  { key: "signatureAlgorithms", tls: true,
    // Set when the row runs: an algorithm the served key cannot make.
    change: null,
    changed: async function (t) {
      const p = await probe(t, {});
      return { ok: !p.handshake, note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p), note: JSON.stringify(p) };
    } },
  { key: "trustAnchorsFile", tls: true,
    change: { trustAnchorsFile: "/certs/server/pep-server.crt" },
    pulledOnly: "the authorities a CertificateRequest names, which a Node " +
                "client cannot read" },
  { key: "trustIssuedClientCertificates", tls: true, flip: true,
    pulledOnly: "the authorities a CertificateRequest names" },
  { key: "askClientCertificate", tls: true, flip: true,
    pulledOnly: "whether a CertificateRequest is sent, which a Node " +
                "client cannot see when it has no certificate to give" },
  // WITH A TRUST SOURCE: on the API listener the PEP asks nobody for a
  // certificate unless it has authorities to verify one against
  // (`apply_client_auth`, PEP_AUTHZEN_CLIENT_CA unset here), so `true`
  // alone was held and changed nothing on the first hand run. A trust
  // anchors file first, observed as harmless, then the requirement.
  { key: "requireClientCertificate", tls: true,
    from: { trustAnchorsFile: "/certs/server/pep-server.crt" },
    fromObserved: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p), note: JSON.stringify(p) };
    },
    change: { trustAnchorsFile: "/certs/server/pep-server.crt",
              requireClientCertificate: true },
    changed: async function (t) {
      const p = await probe(t, {});
      return { ok: !answered(p), note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p), note: JSON.stringify(p) };
    } },
  { key: "sessionTimeoutS", tls: true, change: { sessionTimeoutS: 120 },
    pulledOnly: "NOT APPLIED by the PEP: its TLS library has no " +
                "session-lifetime call, and it logs STS-XPEP-0119" },
  { key: "sessionCacheSize", tls: true, change: { sessionCacheSize: 16 },
    pulledOnly: "TLS 1.3 resumes from a stateless ticket whatever the " +
                "server's session cache holds" },
  // HTTP/2 BY PRIOR KNOWLEDGE, NOT BY ALPN, and the difference is a PEP
  // defect these rows found on 2026-11-16: the PEP calls `set_alpn_protos`
  // (the CLIENT's offer) on its acceptor and no `set_alpn_select_callback`,
  // so no handshake ever selects h2 — a browser never uses HTTP/2 against
  // it — while hyper still answers an h2 connection preface when `http2`
  // is on. So the knob is observed by a client that speaks h2 without
  // asking (Node's http2.connect): on, its SETTINGS arrive; off
  // (`http1_only`), the connection fails. The ALPN half is logged.
  { key: "http2", tls: true, change: { http2: false },
    changed: async function (t) {
      const s = await http2Settings(t);
      return { ok: !s.ok, note: JSON.stringify(s) };
    },
    restored: async function (t) {
      const s = await http2Settings(t);
      const p = await probe(t, { handshakeOnly: true,
                                 connect: { ALPNProtocols: ["h2",
                                                            "http/1.1"] } });
      if (s.ok && p.alpn !== "h2") {
        log.warn("KNOWN PEP DEFECT, " + t.id + ".http2: HTTP/2 answers a " +
                 "preface but ALPN never selects h2 (alpn " +
                 JSON.stringify(p.alpn) + ").");
      }
      return { ok: s.ok, note: JSON.stringify([s, p]) };
    } },
  { key: "http2MaxConcurrentStreams", tls: true,
    change: { http2MaxConcurrentStreams: 7 },
    changed: async function (t) {
      const s = await http2Settings(t);
      return { ok: s.ok && s.settings.maxConcurrentStreams === 7,
               note: JSON.stringify(s) };
    },
    restored: async function (t) {
      const s = await http2Settings(t);
      return { ok: s.ok && s.settings.maxConcurrentStreams === 100,
               note: JSON.stringify(s) };
    } },
  { key: "keepAliveTimeoutS", change: { keepAliveTimeoutS: 2 },
    changed: async function (t) {
      const p = await probe(t, { holdMs: 6000 });
      return { ok: answered(p) && p.closedAfterMs !== null &&
                   p.closedAfterMs < 5500, note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, { holdMs: 4500 });
      return { ok: answered(p) && p.closedAfterMs === null,
               note: JSON.stringify(p) };
    } },
  { key: "headersTimeoutS", change: { headersTimeoutS: 2 },
    // FOUND BY THIS ROW ON 2026-11-16: with 2 held (settingsCurrent), a
    // request whose headers never finished was still open 20 s later on
    // api-http; only the keep-alive watchdog closed it, at 60 s.
    knownDefect: "the PEP holds the value and does not apply it: hyper's " +
                 "header_read_timeout never closed a request whose headers " +
                 "did not finish (keep-alive closed it, at 60 s)",
    changed: async function (t) {
      const p = await probe(t, { partial: true, holdMs: 6000 });
      return { ok: p.handshake && p.closedAfterMs !== null &&
                   p.closedAfterMs < 5500, note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, { partial: true, holdMs: 4500 });
      return { ok: p.handshake && p.closedAfterMs === null,
               note: JSON.stringify(p) };
    } },
  { key: "maxRequestsPerSocket", change: { maxRequestsPerSocket: 1 },
    changed: async function (t) {
      const p = await probe(t, { requests: 2, holdMs: 3000 });
      return { ok: p.statuses.length === 1, note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, { requests: 2, holdMs: 3000 });
      return { ok: p.statuses.length === 2, note: JSON.stringify(p) };
    } },
  { key: "maxConnections", change: { maxConnections: 1 },
    changed: async function (t) {
      const held = probe(t, { requests: 0, holdMs: 4000 });
      await sleep(500);
      const second = await probe(t, { timeoutMs: 3000 });
      await held;
      return { ok: !answered(second), note: JSON.stringify(second) };
    },
    restored: async function (t) {
      const held = probe(t, { requests: 0, holdMs: 3000 });
      await sleep(500);
      const second = await probe(t, { timeoutMs: 3000 });
      await held;
      return { ok: answered(second), note: JSON.stringify(second) };
    } },
  { key: "threadPoolMin", pool: true,
    change: function (d) {
      return { threadPoolMin: d.threadPoolMin + 1 };
    },
    changed: async function (t, d) {
      const r = await reported(t.id);
      const pool = (((r.listener || {}).stats) || {}).pool || {};
      return { ok: pool.min === d.threadPoolMin + 1,
               note: JSON.stringify(pool) };
    },
    restored: async function (t, d) {
      const r = await reported(t.id);
      const pool = (((r.listener || {}).stats) || {}).pool || {};
      return { ok: pool.min === d.threadPoolMin, note: JSON.stringify(pool) };
    } },
  { key: "threadPoolMax", pool: true,
    change: function (d) {
      return { threadPoolMax: d.threadPoolMax + 3 };
    },
    changed: async function (t, d) {
      const r = await reported(t.id);
      const pool = (((r.listener || {}).stats) || {}).pool || {};
      return { ok: pool.max === d.threadPoolMax + 3,
               note: JSON.stringify(pool) };
    },
    restored: async function (t, d) {
      const r = await reported(t.id);
      const pool = (((r.listener || {}).stats) || {}).pool || {};
      return { ok: pool.max === d.threadPoolMax, note: JSON.stringify(pool) };
    } },
  // THE DEFINITION'S OWN MEMBERS, the custom listener only.
  { key: "port", definition: { port: CUSTOM_MOVED_PORT },
    changed: async function (t) {
      const moved = await probe(Object.assign({}, t,
                                              { port: CUSTOM_MOVED_PORT }), {});
      const old = await probe(t, { timeoutMs: 2000 });
      return { ok: answered(moved) && !old.handshake,
               note: JSON.stringify([moved, old]) };
    },
    restored: async function (t) {
      const back = await probe(t, {});
      const moved = await probe(Object.assign({}, t,
        { port: CUSTOM_MOVED_PORT }), { timeoutMs: 2000 });
      return { ok: answered(back) && !moved.handshake,
               note: JSON.stringify([back, moved]) };
    } },
  { key: "address", definition: { address: "127.0.0.1" },
    changed: async function (t) {
      const p = await probe(t, { timeoutMs: 2000 });
      return { ok: !p.handshake, note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p), note: JSON.stringify(p) };
    } },
  { key: "dnsNames", definition: { dnsNames: [SOLO, "pep-custom.example"] },
    changed: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p) && /DNS:pep-custom\.example/.test(
                 String((p.certificate || {}).subjectAltName)),
               note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p) && !/pep-custom\.example/.test(
                 String((p.certificate || {}).subjectAltName)),
               note: JSON.stringify(p) };
    } },
  { key: "ipAddresses", definition: { ipAddresses: ["127.0.0.2"] },
    changed: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p) && /IP Address:127\.0\.0\.2/.test(
                 String((p.certificate || {}).subjectAltName)),
               note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p) && !/127\.0\.0\.2/.test(
                 String((p.certificate || {}).subjectAltName)),
               note: JSON.stringify(p) };
    } },
  { key: "keyAlg", definition: { keyAlg: "rsa-2048" },
    changed: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p) && (p.certificate || {}).keyType === "rsa",
               note: JSON.stringify(p) };
    },
    restored: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p) && (p.certificate || {}).keyType === "ec",
               note: JSON.stringify(p) };
    } },
  { key: "protocol", definition: { protocol: "http" },
    changed: async function (t) {
      const p = await probe(Object.assign({}, t, { https: false }), {});
      const q = await probe(t, { timeoutMs: 2000 });
      return { ok: answered(p) && !q.handshake,
               note: JSON.stringify([p, q]) };
    },
    restored: async function (t) {
      const p = await probe(t, {});
      return { ok: answered(p) && p.protocol === "TLSv1.3",
               note: JSON.stringify(p) };
    } },
  { key: "purpose", definition: { purpose: "api" },
    changed: async function (t) {
      const r = await request("GET", "https://" + SOLO + ":" + t.port + "/",
                              { headers: { accept: "application/json" } });
      return { ok: r.status === 200 && !!r.json && !!r.json.registration,
               note: told(r) };
    },
    restored: async function (t) {
      const r = await request("GET", "https://" + SOLO + ":" + t.port +
                              "/pep-app/public/purpose-" + STAMP,
                              { headers: { accept: "application/json" } });
      return { ok: r.status === 200 && !!r.json && r.json.page === "public",
               note: told(r) };
    } }
];

// The rows whose effect a known PEP defect keeps from the wire, listed at
// the end of the run.
const knownDefects = [];

// The members of a defined listener that are not settings.
const NOT_SETTINGS = ["id", "renew", "tuning"];

async function theCatalogue() {
  log.debug("Entering theCatalogue().");
  const r = await get(api("/xacml/peps?pep=" + SOLO));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/xacml/peps?pep= answered " + r.status);
  log.debug("Leaving theCatalogue().");
  return r.body.listenersCatalogue || {};
}

// Waits for the PEP's own report that it holds what would be sent now, from
// a heartbeat after `since`; and GET / carrying the same settings token.
async function untilHeld(since, what) {
  log.debug("Entering untilHeld(). " + what);
  const held = await until(SOLO + " to hold " + what, async function () {
    const row = await pepRow(SOLO);
    const inUse = (row && row.settingsInUse) || {};
    const own = await overview(SOLO);
    return { ok: !!row && row.settingsCurrent === true &&
                 Date.parse(inUse.at || 0) > since &&
                 ((own.settings || {}).token === inUse.token),
             note: "settingsCurrent=" + (row && row.settingsCurrent) +
                   " at " + inUse.at + ", GET /'s token " +
                   ((own.settings || {}).token) + " against " + inUse.token };
  }, LISTENER_CONVERGE_MS);
  log.debug("Leaving untilHeld().");
  return held;
}

async function saveTuning(listener, tuning) {
  log.debug("Entering saveTuning(). " + listener.id);
  if (listener.source === "environment") {
    await act("/xacml/set-pep-environment-tuning", { name: SOLO,
      listener: listener.id, tuning: tuning },
      "set the tuning of " + SOLO + "'s " + listener.id);
  } else {
    await act("/xacml/set-pep-listener", { name: SOLO,
      listener: Object.assign({}, listener.definition, { tuning: tuning }) },
      "set " + SOLO + "'s listener " + listener.id);
  }
  log.debug("Leaving saveTuning().");
}

async function saveDefinition(listener, definition) {
  log.debug("Entering saveDefinition(). " + listener.id);
  const sent = Object.assign({}, definition, { tuning: listener.defaults });
  if (sent.protocol === "http") {
    // A plain listener names no certificate (STS-XACML refuses its names
    // and key), so the `protocol` row sends it without them.
    delete sent.dnsNames;
    delete sent.ipAddresses;
    delete sent.keyAlg;
  }
  await act("/xacml/set-pep-listener", { name: SOLO, listener: sent },
    "set " + SOLO + "'s listener " + listener.id);
  log.debug("Leaving saveDefinition().");
}

// ONE ROW ON ONE LISTENER: from, change, restore, each held and observed.
async function oneSetting(listener, row) {
  log.debug("Entering oneSetting(). " + listener.id + " " + row.key);
  const t = Object.assign(socketTarget(listener), { id: listener.id });
  const d = listener.defaults;
  const label = listener.id + "." + row.key;
  const save = async function (overlay) {
    log.debug("Entering save(). " + label);
    if (row.definition) {
      await saveDefinition(listener, Object.assign({}, listener.definition,
                                                   overlay || {}));
    } else {
      await saveTuning(listener, Object.assign({}, d, overlay || {}));
    }
    log.debug("Leaving save().");
  };
  let change = typeof row.change === "function" ? row.change(d) : row.change;
  if (row.flip) {
    change = {};
    change[row.key] = !d[row.key];
  }
  if (row.key === "signatureAlgorithms") {
    const seen = await probe(t, {});
    change = { signatureAlgorithms:
      (seen.certificate || {}).keyType === "rsa" ? "ecdsa_secp256r1_sha256"
                                                 : "rsa_pss_rsae_sha256" };
  }
  if (row.definition) {
    change = row.definition;
  }
  if (row.from) {
    const sinceFrom = Date.now();
    await save(row.from);
    await untilHeld(sinceFrom, label + "'s starting point");
    await until(label + "'s starting point on the wire", function () {
      return row.fromObserved(t, d);
    }, LISTENER_CONVERGE_MS);
  }
  const since = Date.now();
  await save(Object.assign({}, row.from || {}, change));
  await untilHeld(since, label + " changed");
  let changed = { ok: true, ms: 0 };
  // A KNOWN PEP DEFECT: both states are looked at once each, and a wrong
  // one is a warning rather than this job's failure; BOTH RIGHT is the
  // failure, because then the row's knownDefect is stale.
  let defectSeen = null;
  if (row.knownDefect) {
    defectSeen = { changed: await row.changed(t, d) };
  } else if (!row.pulledOnly) {
    changed = await until(label + " to take effect on the wire",
                          function () {
      return row.changed(t, d);
    }, LISTENER_CONVERGE_MS);
  }
  const sinceBack = Date.now();
  await save(row.definition ? {} : null);
  await untilHeld(sinceBack, label + " restored");
  let restored = { ok: true, ms: 0 };
  if (row.knownDefect) {
    defectSeen.restored = await row.restored(t, d);
    assert.ok(!(defectSeen.changed.ok && defectSeen.restored.ok),
      label + " TOOK EFFECT both ways, so its knownDefect (" +
      row.knownDefect + ") is fixed: remove it from LISTENER_ROWS so the " +
      "row is asserted again.");
    log.warn("KNOWN PEP DEFECT, " + label + ": " + row.knownDefect +
             ". Seen: " + JSON.stringify(defectSeen).slice(0, 600));
    knownDefects.push(label);
  } else if (!row.pulledOnly) {
    restored = await until(label + " restored on the wire", function () {
      return row.restored(t, d);
    }, LISTENER_CONVERGE_MS);
  }
  check(label + (row.knownDefect ? " is held by the PEP, changed and " +
        "restored, and does NOT take effect (a known PEP defect: " +
        row.knownDefect + ")"
        : row.pulledOnly ? " is held by the PEP, changed and " +
        "restored (observed as pulled only: " + row.pulledOnly + ")"
        : " took effect (" + changed.ms + "ms) and its restore did (" +
          restored.ms + "ms)"), function () {
    assert.ok(changed.ok && restored.ok);
  });
  log.debug("Leaving oneSetting().");
}

// The table against the model: every knob and member has a row.
function theTableCoversTheModel(catalogue, definition) {
  log.debug("Entering theTableCoversTheModel().");
  const keys = LISTENER_ROWS.map(function (row) {
    return row.key;
  });
  const tuningKeys = Object.keys((catalogue.tuningDefaults || {}).proxy ||
                                 {});
  const memberKeys = Object.keys(definition || {}).filter(function (k) {
    return NOT_SETTINGS.indexOf(k) < 0;
  });
  check("every listener setting the model declares has a row in " +
        "LISTENER_ROWS (" + tuningKeys.length + " tuning knobs, " +
        memberKeys.length + " definition members)", function () {
    assert.ok(tuningKeys.length >= 21,
      "the catalogue's tuningDefaults lists " + tuningKeys.length +
      " knobs: " + JSON.stringify(tuningKeys));
    const missing = tuningKeys.concat(memberKeys).filter(function (k) {
      return keys.indexOf(k) < 0;
    });
    assert.deepStrictEqual(missing, [],
      "a listener setting with no row, so nothing asserts it takes effect: " +
      JSON.stringify(missing) + ". Add a row to LISTENER_ROWS.");
  });
  log.debug("Leaving theTableCoversTheModel().");
}

async function theStandalonePepLeavesTheCluster() {
  log.debug("Entering theStandalonePepLeavesTheCluster().");
  log.info("=== Listeners: " + SOLO + " leaves the cluster, keeping a " +
           "copy ===");
  const left = await act("/xacml/remove-pep-cluster-member",
                         { cluster: CLUSTER, pep: SOLO },
                         "taken " + SOLO + " out of " + CLUSTER);
  const row = await pepRow(SOLO);
  check(SOLO + " left " + CLUSTER + " holding a copy of its document as " +
        "its own", function () {
    assert.strictEqual(left.kept, true, JSON.stringify(left));
    assert.ok(row && !row.cluster && row.proxy &&
              (row.proxy.routes || []).length >= 4,
      "its row: cluster " + JSON.stringify(row && row.cluster) + ", " +
      ((row && row.proxy && row.proxy.routes) || []).length + " route(s)");
  });
  await until(SOLO + " to go on enforcing its copy", async function () {
    const r = await request("GET", memberProxy(SOLO) + "/pep-app/api/items",
      { headers: { authorization: basic(READER),
                   accept: "application/json" } });
    return { ok: r.status === 200, note: told(r) };
  });
  log.debug("Leaving theStandalonePepLeavesTheCluster().");
}

async function theCustomListenerIsBound() {
  log.debug("Entering theCustomListenerIsBound().");
  log.info("=== Listeners: a custom HTTPS proxy listener on " + CUSTOM.port +
           " ===");
  const catalogue = await theCatalogue();
  const defaults = catalogue.tuningDefaults.proxy;
  await act("/xacml/set-pep-listener", { name: SOLO, listener: Object.assign(
    { dnsNames: [SOLO], ipAddresses: [] }, CUSTOM, { tuning: defaults }) },
    "defined " + SOLO + "'s listener " + CUSTOM.id);
  const bound = await until(SOLO + " to bind " + CUSTOM.id + " with a " +
                            "certificate from the realm", async function () {
    const r = await reported(CUSTOM.id);
    const l = r.listener || {};
    return { ok: l.state === "listening" && !!l.certificate,
             note: JSON.stringify(l).slice(0, 400) };
  }, LISTENER_CONVERGE_MS);
  const served = await request("GET", "https://" + SOLO + ":" + CUSTOM.port +
                               "/pep-app/public/custom-" + STAMP,
                               { headers: { accept: "application/json" } });
  const listed = (await pepRow(SOLO)).listeners || [];
  check(CUSTOM.id + " is bound without a restart, serves the realm's " +
        "certificate and the proxy's routes", function () {
    const l = bound;
    assert.ok(l.ok);
    assert.strictEqual(served.status, 200,
      "GET /pep-app/public on " + CUSTOM.port + " answered " + told(served));
    assert.strictEqual((served.json || {}).page, "public");
    assert.ok(listed.some(function (one) {
      return one.id === CUSTOM.id;
    }), "the row lists the definition: " + JSON.stringify(listed));
  });
  log.debug("Leaving theCustomListenerIsBound().");
  return listed.filter(function (one) {
    return one.id === CUSTOM.id;
  })[0];
}

async function everyListenerSetting(definition) {
  log.debug("Entering everyListenerSetting().");
  log.info("=== Listeners: every setting, one at a time ===");
  const catalogue = await theCatalogue();
  theTableCoversTheModel(catalogue, definition);
  const defaultsOf = function (purpose) {
    log.debug("Entering defaultsOf().");
    log.debug("Leaving defaultsOf().");
    return Object.assign({}, catalogue.tuningDefaults[purpose]);
  };
  const plainDefaults = Object.assign(defaultsOf("api"), { http2: false,
    askClientCertificate: false, requireClientCertificate: false,
    trustIssuedClientCertificates: false });
  const listeners = [
    { id: "api-http", source: "environment", purpose: "api", https: false,
      port: 9090, defaults: plainDefaults },
    { id: "api-https", source: "environment", purpose: "api", https: true,
      port: 9443, defaults: defaultsOf("api") },
    { id: "proxy-https", source: "environment", purpose: "proxy",
      https: true, port: 9543, defaults: defaultsOf("proxy") },
    { id: CUSTOM.id, source: "service", purpose: "proxy", https: true,
      port: CUSTOM.port, defaults: defaultsOf("proxy"),
      definition: Object.assign({ dnsNames: [SOLO], ipAddresses: [] },
                                CUSTOM) }
  ];
  let ran = 0;
  for (const listener of listeners) {
    for (const row of LISTENER_ROWS) {
      if ((row.tls && !listener.https) ||
          (row.definition && listener.source !== "service")) {
        continue;
      }
      /* eslint-disable no-await-in-loop */
      await oneSetting(listener, row);
      /* eslint-enable no-await-in-loop */
      ran += 1;
    }
  }
  log.info(ran + " listener settings were changed, observed and restored.");
  log.debug("Leaving everyListenerSetting().");
}

async function aRouteOnTheCustomListener() {
  log.debug("Entering aRouteOnTheCustomListener().");
  log.info("=== Listeners: /pep-app/whoami behind a route, on " + CUSTOM.port +
           " ===");
  await act("/xacml/set-pep-route", { name: SOLO, position: 0, route: {
    id: "whoami", path: "/pep-app/whoami", match: "prefix",
    methods: ["GET", "HEAD"], mechanisms: ["basic"], application: APP,
    authorization: { kind: "simple", actionModel: "read-write",
                     roles: { read: [USERS_ROLE] } },
    identity: IDENTITY, forwardCredentials: false, signals: false } },
    "added the whoami route to " + SOLO);
  const custom = "https://" + SOLO + ":" + CUSTOM.port;
  const p = "/pep-app/whoami/" + STAMP;
  await until("the whoami route on " + CUSTOM.port, async function () {
    const r = await request("GET", custom + p, { headers: {
      authorization: basic(READER), accept: "application/json" } });
    return { ok: r.status === 200 && (r.json || {}).page === "whoami",
             note: told(r) };
  });
  const before = await upstreamHits();
  const asReader = await request("GET", custom + p, { headers: {
    authorization: basic(READER), accept: "application/json",
    "x-remote-user": "mallory" } });
  const asOutsider = await request("GET", custom + p, { headers: {
    authorization: basic(OUTSIDER), accept: "application/json" } });
  const anonymous = await request("GET", custom + p,
                                  { headers: { accept: "application/json" } });
  const after = await upstreamHits();
  const who = (asReader.json || {}).whoami || {};
  check("on the custom listener the whoami route names " + READER + " and " +
        "the listener it came through", function () {
    assert.strictEqual(asReader.status, 200, told(asReader));
    assert.strictEqual(who.user, READER,
      "whoami.user is the person, never the client's mallory: " +
      JSON.stringify(who));
    assert.ok(who.subject && /basic/i.test(who.mechanism),
      "with their subject and the mechanism: " + JSON.stringify(who));
    assert.strictEqual(who.via.port, CUSTOM.port,
      "through " + CUSTOM.port + ": " + JSON.stringify(who.via));
    assert.strictEqual(who.via.proto, "https", JSON.stringify(who.via));
  });
  check("and refuses " + OUTSIDER + " (403) and nobody (401), forwarding " +
        "neither", function () {
    assert.strictEqual(asOutsider.status, 403, told(asOutsider));
    assert.strictEqual(anonymous.status, 401, told(anonymous));
    assert.strictEqual(hitsOn(after, p), hitsOn(before, p) + 1,
      "only the role holder's request reached the application");
  });
  const onDefault = await request("GET", memberProxy(SOLO) +
    "/pep-app/api/items", { headers: { authorization: basic(READER),
                                       accept: "application/json" } });
  const whoDefault = await request("GET", memberProxy(SOLO) + p,
    { headers: { authorization: basic(READER), accept: "application/json" } });
  check("the environment's proxy listener still serves the other routes, " +
        "and the new one through 9543", function () {
    assert.strictEqual(onDefault.status, 200, told(onDefault));
    assert.strictEqual((onDefault.json || {}).page, "items");
    assert.strictEqual(whoDefault.status, 200, told(whoDefault));
    assert.strictEqual((((whoDefault.json || {}).whoami || {}).via || {})
      .port, 9543, "via 9543: " + told(whoDefault));
  });
  log.debug("Leaving aRouteOnTheCustomListener().");
}

async function theCustomListenerIsRemoved() {
  log.debug("Entering theCustomListenerIsRemoved().");
  await act("/xacml/remove-pep-listener", { name: SOLO,
                                            listener: CUSTOM.id },
            "removed " + SOLO + "'s listener " + CUSTOM.id);
  const gone = await until(CUSTOM.port + " to stop answering",
                           async function () {
    const p = await probe({ host: SOLO, port: CUSTOM.port, https: true,
                            path: "/" }, { timeoutMs: 2000 });
    return { ok: !p.handshake && p.error === "ECONNREFUSED",
             note: JSON.stringify(p) };
  }, LISTENER_CONVERGE_MS);
  check("the custom listener removed, its port refuses connections",
        function () {
    assert.ok(gone.ok);
  });
  log.debug("Leaving theCustomListenerIsRemoved().");
}

async function theListeners() {
  log.debug("Entering theListeners().");
  await theStandalonePepLeavesTheCluster();
  const definition = await theCustomListenerIsBound();
  await everyListenerSetting(definition);
  await aRouteOnTheCustomListener();
  await theCustomListenerIsRemoved();
  log.debug("Leaving theListeners().");
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
  await theListeners();

  // A FLOOR ON THE COUNT: a section that stops being called takes its
  // assertions with it, and the run would still say "passed".
  assert.ok(checks >= 100,
    "only " + checks + " checks ran, and this file makes more than 100 " +
    "against a healthy stack: a SECTION STOPPED BEING CALLED.");
  log.info("The realm " + REALM + " is LEFT IN PLACE on purpose, with the " +
           "cluster " + CLUSTER + ", its members' rows and the people; " +
           "restart the stack before running this job against it again.");
  if (knownDefects.length) {
    log.warn("KNOWN PEP DEFECTS (held, not applied): " +
             knownDefects.join(", ") + ".");
  }
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
