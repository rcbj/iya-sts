// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_launch.js
//
// ---------------------------------------------------------------------------
// THE TARGET A LAUNCH LINK PASSES ON, OVER THE WIRE (#426, #713, #714).
//
// D12 (#444): carries over the part of `tests/launch.js` that
// `sts_idp_initiated_launch.js` does not hold — section e3's target rules.
// `GET /launch/{app}?target=` for an OpenID Connect client passes the target
// on as `target_link_uri` only when it is EXACTLY one of the client's
// registered https redirect URIs, matched after URL parsing and sent as
// registered; anything else is refused 400 with no Location and recorded
// STS-LAUNCH-0007 (read off the realm's `/admin-api/audit`). In a
// DEVELOPMENT realm of its own, because the observed-address case needs a
// sighting, which only development records:
//
//   e3a. a registered redirect URI as target is passed on;
//   e3b. the same address in another case is matched after parsing and
//        sent as registered;
//   e3c. refused, each 400 STS-LAUNCH-0007: an unregistered https address,
//        an address the client was only OBSERVED using (an authorization
//        request in development, read back as `appRedirectUriObserved`), an
//        extension, a prefix, a query added, another scheme, another host,
//        and a bare path.
//
// NOT carried, and why: launch.js's sections a–d, f and g are
// `sts_idp_initiated_launch.js`'s already; e4 (the launch recorded on the
// session) has no wire form but its effect, which that job's f1 asserts;
// the "redirect URI a sighting MARKED observed" case needs a sighting that
// writes `oauthRedirectUri` itself, which only `applications.seen()` in
// process can produce (class (d)).
//
// OWNED HERE (local: true): this repository's own door and registry.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_launch",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
// A password this process made: product checks it.
const PASSWORD = "Launch-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-9a!";
// A desktop browser's User-Agent with this job's name on the end: risk
// scoring reads a bare job name as an automated client, and product refuses
// a first sign-in from one (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 sts_launch/1.0 (" +
  STAMP + ")";

let checks = 0;
const failures = [];

// ONE CHECK. A failure is recorded and the run carries on; setup that later
// sections depend on uses `must()`, which throws.
async function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    await fn();
    checks += 1;
    log.info("  [ok] " + what);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    failures.push(what + " — " + ((e && e.message) || e));
    log.error("  [FAILED] " + what + "  — " + ((e && e.message) || e));
  }
  log.debug("Leaving check().");
}

function must(condition, message) {
  log.debug("Entering must().");
  if (!condition) {
    log.debug("Leaving must(). Refused.");
    throw new Error("SETUP: " + message);
  }
  log.debug("Leaving must().");
}

function expect(condition, message) {
  log.debug("Entering expect().");
  if (!condition) {
    log.debug("Leaving expect(). Refused.");
    throw new Error(String(message));
  }
  log.debug("Leaving expect().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + realm;
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "", headers: r.headers };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

// The management API of a realm (`realm` null: the root's). The run's admin
// token is attached by the preload (`tools/attach-admin-token.js`).
function api(realm, method, p, payload) {
  log.debug("Entering api(). " + method + " " + p);
  const url = (realm ? realmBase(realm) : base) + "/admin-api" + p;
  log.debug("Leaving api().");
  if (method === "GET") {
    return send(url);
  }
  return postJson(url, payload);
}

async function apiOk(realm, p, payload, what) {
  log.debug("Entering apiOk(). " + p);
  const r = await api(realm, "POST", p, payload);
  must(r.status === 200 && r.body && r.body.ok !== false,
       (what || p) + " answered " + r.status + " " + r.raw.slice(0, 400));
  log.debug("Leaving apiOk().");
  return r.body;
}

const MADE = [];
async function makeRealm(stem, mode) {
  log.debug("Entering makeRealm(). " + stem);
  const id = (stem + "-" + STAMP).slice(0, 31);
  await apiOk(null, "/realms/create", { id: id, domain: id + ".example.net",
    name: stem + " " + STAMP }, "created the realm " + id);
  MADE.push(id);
  await apiOk(null, "/realms/set", { id: id, key: "global.mode",
    value: mode }, "set " + id + " to " + mode);
  log.debug("Leaving makeRealm(). " + id);
  return id;
}

function setting(realm, key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  log.debug("Leaving setting().");
  return apiOk(null, "/realms/set", { id: realm, key: key,
    value: String(value) }, "set " + key + " on " + realm);
}

async function createPerson(realm, username, extra) {
  log.debug("Entering createPerson(). " + username);
  const body = await apiOk(realm, "/users/create", Object.assign({
    username: username, invent: false,
    attributes: { cn: "Probe " + username, givenName: "Probe",
                  sn: username, mail: username + "@" + realm + ".example" },
    credential: "password", password: PASSWORD }, extra || {}),
  "created " + username);
  log.debug("Leaving createPerson().");
  return body;
}

// How many of a realm's audit rows carry `code`.
async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await api(realm, "GET", "/audit?per=500&code=" +
                      encodeURIComponent(code));
  const b = r.body && typeof r.body === "object" ? r.body : {};
  const rows = b.rows || b.events || [];
  const n = typeof b.matched === "number" ? b.matched : rows.length;
  log.debug("Leaving codeCount(). " + n);
  return n;
}

// Whether a new row with `code` arrived since `before`: the row is written
// as the response finishes, so the read after it may need a moment.
async function newRowWith(realm, code, before) {
  log.debug("Entering newRowWith(). " + code);
  let after = await codeCount(realm, code);
  for (let i = 0; i < 30 && after <= before; i += 1) {
    await sleep(200);
    after = await codeCount(realm, code);
  }
  log.debug("Leaving newRowWith(). " + before + " -> " + after);
  return after > before;
}

// A browser: a cookie jar (a plain object, which `authn_signin.js` writes
// back into) and redirects left to the caller.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    cookie: function cookieOf() {
      log.debug("Entering cookieOf().");
      log.debug("Leaving cookieOf().");
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    go: async function go(method, url, body, extra) {
      log.debug("Entering go(). " + method + " " + url);
      const headers = Object.assign({ "User-Agent": AGENT }, extra || {});
      const cookie = self.cookie();
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const absolute = /^https?:\/\//i.test(url) ? url : base + url;
      const r = await fetch(absolute, { method: method, redirect: "manual",
                                        headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text, url: absolute };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function sentToSignIn(r) {
  log.debug("Entering sentToSignIn().");
  log.debug("Leaving sentToSignIn().");
  return (r.status === 302 || r.status === 303) &&
    /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location);
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token || "").split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1] || "", "base64url")
    .toString("utf8") || "{}");
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made is removed
// at the end, pass or fail. A suite run leaves them standing
// (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of MADE) {
    const r = await postJson(base + "/admin-api/realms/remove", { id: id });
    log.info("removed the realm " + id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // A failed removal leaves a realm on a private probe; it is not the
    // job's verdict.
    log.warn("removing the realms failed: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("Test failed: " + ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  if (failures.length) {
    log.error(failures.length + " check(s) FAILED:\n  " +
              failures.join("\n  "));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}


const HOST = "https://rp-" + STAMP + ".launch.example";
const REDIRECT = HOST + "/cb";
const OBSERVED = HOST + "/observed-cb";
const INITIATE = HOST + "/login";
const HOME = HOST + "/home";
let REALM = "";
const USER = names.usernameFor("lt");
const RP = "launch-target-" + STAMP;
// A client with NO registered redirect URI, which development lets use any
// address and records what it used as OBSERVED (`appRedirectUriObserved`).
const RP_SEEN = "launch-seen-" + STAMP;

function link(query, client) {
  log.debug("Entering link().");
  const q = new URLSearchParams(query || {}).toString();
  log.debug("Leaving link().");
  return realmBase(REALM) + "/launch/" + encodeURIComponent(client || RP) +
    (q ? "?" + q : "");
}

function targetOf(r) {
  log.debug("Entering targetOf().");
  let at = null;
  try {
    at = new URL(String(r.location || ""));
  } catch (e) {
    log.debug("Caught in targetOf(): " + ((e && e.message) || e));
    // Not an absolute URL, so not the client's initiate_login_uri.
    at = null;
  }
  log.debug("Leaving targetOf().");
  return at && at.origin + at.pathname === INITIATE
    ? at.searchParams.get("target_link_uri") : null;
}

async function test() {
  log.debug("Entering test().");
  REALM = await makeRealm("lt", "development");
  await createPerson(REALM, USER);
  await apiOk(REALM, "/applications/create", { identifier: RP,
    name: "launch target " + RP, kind: "oauth2-client",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [RP], oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code"],
              oauthResponseType: ["code"], oauthAllowedScope: ["openid"],
              oauthTokenEndpointAuthMethod: "none",
              appHomePageUrl: HOME, oauthInitiateLoginUri: INITIATE,
              oauthThirdPartyInitiatedLogin: "TRUE" } },
  "registered the client");
  await apiOk(REALM, "/applications/create", { identifier: RP_SEEN,
    name: "launch seen " + RP_SEEN, kind: "oauth2-client",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [RP_SEEN],
              oauthGrantType: ["authorization_code"],
              oauthResponseType: ["code"], oauthAllowedScope: ["openid"],
              oauthTokenEndpointAuthMethod: "none",
              appHomePageUrl: HOME, oauthInitiateLoginUri: INITIATE,
              oauthThirdPartyInitiatedLogin: "TRUE" } },
  "registered the client with no redirect URI");
  for (const client of [RP, RP_SEEN]) {
    await apiOk(REALM, "/consent/grant-global-consent",
                { client: client, scope: "openid" }, "consented openid");
  }

  log.info("=== a sign-in through the link ===");
  const alice = browser();
  const first = await alice.go("GET", link());
  must(sentToSignIn(first), "the launch did not reach the sign-in screen: " +
       first.status + " " + first.location);
  const screen = new URL(first.location, realmBase(REALM) + "/").toString();
  const sent = await authnSignin.signInWithJar(realmBase(REALM), screen,
    { action: "login", username: USER, password: PASSWORD }, alice.jar,
    { ignoreOffer: true, headers: { "User-Agent": AGENT } });
  must(sent.status === 303 && sent.location, "the sign-in did not finish: " +
       sent.status + " " + String(sent.text || "").slice(0, 300));
  const home = await alice.go("GET", new URL(sent.location,
    realmBase(REALM) + "/").toString());
  await check("e3 (precondition). with a session the link sends the browser " +
              "to initiate_login_uri with the home page as target",
              async function () {
    expect(home.status === 303 && targetOf(home) === HOME,
           home.status + " " + home.location);
  });

  log.info("=== e3a, e3b. a registered address ===");
  let r = await alice.go("GET", link({ target: REDIRECT }));
  await check("e3a. a registered redirect URI as target is passed on as " +
              "target_link_uri", async function () {
    expect(r.status === 303 && targetOf(r) === REDIRECT,
           r.status + " " + r.location);
  });
  r = await alice.go("GET", link({ target: REDIRECT.replace(
    "https://rp-", "HTTPS://RP-") }));
  await check("e3b. the same address in another case is matched after URL " +
              "parsing, and sent as registered", async function () {
    expect(r.status === 303 && targetOf(r) === REDIRECT,
           r.status + " " + r.location);
  });

  log.info("=== an address the client was only observed using ===");
  const p = pkce();
  const seen = await alice.go("GET", realmBase(REALM) + "/oauth2/authorize?" +
    form({ client_id: RP_SEEN, response_type: "code", redirect_uri: OBSERVED,
           scope: "openid", state: "s", nonce: "n" + STAMP,
           code_challenge: p.challenge, code_challenge_method: "S256" }));
  const app = await api(REALM, "GET", "/applications?application=" +
                        encodeURIComponent(RP_SEEN));
  const observedOnEntry = urls.namesAddress(JSON.stringify(app.body || {}),
                                            OBSERVED);
  await check("e3c (precondition). in development the authorization request " +
              "is answered and the address is OBSERVED on the entry, not " +
              "registered", async function () {
    expect((seen.status === 302 || seen.status === 303) &&
           urls.isAt(seen.location, OBSERVED),
           seen.status + " " + seen.location);
    expect(observedOnEntry, JSON.stringify(app.body).slice(0, 600));
  });

  log.info("=== e3c. everything else is refused ===");
  const refusals = [
    ["an unregistered https address", "https://evil-" + STAMP +
                                      ".launch.example/x"],
    ["an extension of a registered address", REDIRECT + "/more"],
    ["a prefix of a registered address", HOST + "/c"],
    ["a registered address with a query added", REDIRECT + "?x=1"],
    ["another scheme", REDIRECT.replace("https:", "http:")],
    ["another host", "https://rp2-" + STAMP + ".launch.example/cb"],
    ["not a URL", "/cb"]
  ];
  refusals.push(["an address the client was only OBSERVED using " +
                 "(appRedirectUriObserved)", OBSERVED, RP_SEEN]);
  for (const [what, target, client] of refusals) {
    const before = await codeCount(REALM, "STS-LAUNCH-0007");
    const got = await alice.go("GET", link({ target: target }, client));
    const recorded = await newRowWith(REALM, "STS-LAUNCH-0007", before);
    await check("e3c. " + what + " as target is refused 400 with no " +
                "Location, STS-LAUNCH-0007 recorded and no code sent",
                async function () {
      expect(got.status === 400 && !got.location,
             got.status + " " + got.location);
      expect(/not registered/i.test(got.text), got.text.slice(0, 300));
      expect(!/STS-[A-Z]+-\d{4}/.test(got.text), "a code was sent");
      expect(recorded, "no STS-LAUNCH-0007 row");
    });
  }
  log.debug("Leaving test().");
}

main();
