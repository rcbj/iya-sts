"use strict";
//
// File: sts_step_up.js
//
// ===========================================================================
// RFC 9470 — STEP-UP AUTHENTICATION, OVER HTTP, IN A THROWAWAY TRUST REALM
// (2026-09-13).
//
// `tests/rfc9470_step_up.js` holds the library, the registry and the
// endpoints in a child process on a plain-HTTP loopback port with consent
// switched off and TOTP enrolled by calling `credentials` directly. What is
// here is the same feature as a client and an operator meet it on a real
// stack: HTTPS, the consent screen ON, a person enrolled through
// `/portal/mfa` with a code this file computes itself, and every requirement
// written through `/admin-api`. Mostly NEGATIVES, for `sts_dpop.js`'s reason:
// an authorization server that hands a stepped-up token to a stepped-up
// person looks finished and can be worth nothing — what matters is that a
// session which does NOT meet a request is not an answer to it.
//
//   a. discovery — `acr_values_supported` is ["0","1","mfa"] in both
//      documents of the realm;
//   b. a client and a resource application through `/admin-api`, the
//      resource declaring `oauthStepUpAcrValues=mfa` and
//      `oauthStepUpMaxAge=600`, and the two attribute refusals (a quote in
//      an acr value, a negative age) with the stored values read back
//      unchanged;
//   c. a password sign-in with `resource=<API>` gives a token with acr "1",
//      the stand-in resource answers it 401 with section 3's challenge and
//      both auth-params, and client-authenticated introspection carries acr
//      and auth_time (section 6.2);
//   d. what the stand-in resource refuses BEFORE any step-up question: a
//      token for the default audience, no token (both 401 invalid_token),
//      an application the realm has no entry for (404);
//   e. STEP-UP TO mfa END TO END — an authenticator enrolled at
//      `/portal/mfa`, `acr_values=mfa` on the one-factor session sent to
//      the sign-in screen rather than answered, the screen demanding the
//      second factor, the code step, `step_up_honoured=1` on the return, a
//      token carrying acr "mfa", and the resource that challenged answering
//      200 met:true;
//   f. the hierarchy — the mfa session answers `acr_values=1` with no
//      sign-in and the token carries the REQUESTED "1";
//   g. `prompt=none` with an unmet requirement is `login_required`, a URN no
//      sign-in here produces gets ONE sign-in and then
//      `unmet_authentication_requirements`, and `acr_values=mfa a"b` is
//      `invalid_request`;
//   h. this service's own resource server: `oauth2.stepUpAcrValues=mfa` set
//      IN THE REALM makes UserInfo challenge a one-factor token and answer
//      an mfa one, and `/admin-api/config/reset` takes it away again;
//   i. the monitor — `GET <realm>/admin-api/oauth2/monitor`'s `stepup`
//      section with this client's counters moved, `clientsParam` and
//      `ownResourceRequirement` following the setting — and the console's
//      `?format=json` of the same page carrying the same row.
//
// ---------------------------------------------------------------------------
// WHY IT IS THIS REPOSITORY'S OWN (`local: true`).
//
// `tests/CLAUDE.md`'s third reason: A CONSOLE CONTROL WITH A PROTOCOL
// CONSEQUENCE. The requirement a resource application makes is an attribute
// written through `/admin-api/applications`, the own resource server's
// requirement is a setting written through `/admin-api/config`, and the
// counters are read on `/admin-api/oauth2/monitor` and `/admin/oauth2/monitor`
// — while every assertion that matters is made at `/oauth2/authorize`,
// `/oauth2/token`, `/oauth2/introspect`, `/oauth2/userinfo` and the stand-in
// resource. A repository holding one of those two doors could not make it.
//
// ---------------------------------------------------------------------------
// THE CONSOLE HALF, AND WHY IT IS DRIVEN THE WAY IT IS.
//
// The console's session lives in the DEFAULT realm's partition wherever it is
// reached (`common/CLAUDE.md`, the realm split), and a session signed in
// through the default realm is asked the service roster, which reads every
// realm (`admin-ui/CLAUDE.md`, 8d) — so the operator signs in to the console
// at the default realm through `console_signin.js` and reads the realm's page
// under its prefix with that cookie. No browser: the page is JSON under
// `?format=json`.
//
// ---------------------------------------------------------------------------
// WHAT IT LEAVES BEHIND.
//
// Its realm, left STANDING (`tests/CLAUDE.md`, *NO JOB REMOVES A REALM*), with
// the two applications, the two people, an authenticator app enrolled on one
// of them and the global consent for `openid` on the client. The one setting
// it changes in that realm is put back with `/admin-api/config/reset`, in a
// `finally`, because a setting left overridden is another job's starting
// state. The console operator it signs in with is a person in the default
// realm, like every console job's. It does NOT touch `oauth2.consentRequired`:
// the client is given a global consent for the one scope it asks for.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_step_up",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

const STAMP = names.runStamp();
const REALM = ("stepup-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";

const CLIENT = "su-client-" + STAMP;
const RESOURCE = "su-api-" + STAMP;
const API = "https://api-" + STAMP + ".stepup.example.test/";
const REDIRECT = "https://rp.stepup.example.test/cb";
const SECRET = "su-client-secret-" + STAMP + "-0123456789abcdef";
const PASSWORD = "step-up-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("su-alice");
const BOB = names.usernameFor("su-bob");
const OPERATOR = names.usernameFor("su-operator");
const UNMEETABLE = "urn:example:stepup:gold";

// A section that stops being called takes its assertions with it and the run
// still says "passed"; this is the floor that notices.
const FLOOR = 50;

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE JOB'S OWN RFC 6238 GENERATOR — `sts_portal_totp.js`'s, for its reason:
// a code computed by the service's own module would prove that a function
// agrees with itself. It is held to RFC 6238 Appendix B before it is used.
// ---------------------------------------------------------------------------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32ToBytes(text) {
  log.debug("Entering base32ToBytes().");
  const cleaned = String(text).toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < cleaned.length; i++) {
    const index = B32.indexOf(cleaned[i]);
    assert.ok(index >= 0,
      "the secret this service showed is not base32: " + cleaned[i]);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  log.debug("Leaving base32ToBytes().");
  return Buffer.from(out);
}

function bytesToBase32(bytes) {
  log.debug("Entering bytesToBase32().");
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += B32[(value << (5 - bits)) & 31];
  }
  log.debug("Leaving bytesToBase32().");
  return out;
}

// RFC 4226 section 5.3 over RFC 6238 section 4.2.
function codeFor(secret, atMs, opts) {
  log.debug("Entering codeFor().");
  const options = opts || {};
  const digits = Number(options.digits || 6);
  const alg = String(options.algorithm || "SHA1").toLowerCase();
  const counter = Math.floor(Number(atMs || Date.now()) / 1000 / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = nodeCrypto.createHmac(alg, base32ToBytes(secret))
                           .update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  log.debug("Leaving codeFor().");
  return String(binary % Math.pow(10, digits)).padStart(digits, "0");
}

// ---------------------------------------------------------------------------
// THE VERBS. Manual redirects everywhere: which redirect comes back IS the
// assertion in most sections, and a fetch that followed it would hide it.
// ---------------------------------------------------------------------------
function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
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
    // Not JSON — a page. The caller reads `raw`, which says more than a
    // parse failure would.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "",
           challenge: r.headers.get("www-authenticate") || "",
           headers: r.headers };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// One browser: a cookie jar kept BY NAME, because a browser signed in to the
// portal holds the sign-on cookie and the portal's own.
function browser(name) {
  log.debug("Entering browser(). " + name);
  const jar = {};
  const self = {
    name: name,
    jar: jar,
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers, body: body });
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
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  try {
    const claims = JSON.parse(Buffer.from(String(jwt).split(".")[1],
                                          "base64url").toString("utf8"));
    log.debug("Leaving claimsOf().");
    return claims;
  } catch (e) {
    log.debug("Caught in claimsOf(): " + ((e && e.message) || e));
    // Not a JWT. The assertion that reads it reports the empty object with
    // the token beside it.
    log.debug("Leaving claimsOf(). Not a JWT.");
    return {};
  }
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const challenge = nodeCrypto.createHash("sha256").update(verifier)
    .digest("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier, challenge: challenge };
}

function basic() {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(encodeURIComponent(CLIENT) + ":" +
                                encodeURIComponent(SECRET)).toString("base64");
}

// An authorization request in the realm, and the PKCE verifier it needs.
function authorizeRequest(extra) {
  log.debug("Entering authorizeRequest().");
  const p = pkce();
  const path = R + "/oauth2/authorize?" + form(Object.assign({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid", state: "st-" + STAMP,
    nonce: "n-" + nodeCrypto.randomBytes(4).toString("hex"),
    code_challenge: p.challenge, code_challenge_method: "S256"
  }, extra || {}));
  log.debug("Leaving authorizeRequest().");
  return { path: path, verifier: p.verifier };
}

function toSignIn(r) {
  log.debug("Entering toSignIn().");
  log.debug("Leaving toSignIn().");
  return (r.status === 302 || r.status === 303) &&
         /\/authn\/login\?authn=/.test(r.location);
}

// The redirect to the client's registered address, as its parameters, or
// null when the answer went anywhere else.
function atClient(r) {
  log.debug("Entering atClient().");
  if (!(r.status === 302 || r.status === 303) ||
      String(r.location).indexOf(REDIRECT) !== 0) {
    log.debug("Leaving atClient(). Not at the client.");
    return null;
  }
  log.debug("Leaving atClient().");
  return new URL(r.location).searchParams;
}

// The sign-in screen the last answer pointed at, a name and a password, and
// — when `code` is given and the screen asks for one — the one-time code
// step. Answers every hop, so a section can look at each screen.
async function signInScreen(b, location, who, code) {
  log.debug("Entering signInScreen(). who=" + who);
  const page = await b.go("GET", location);
  assert.strictEqual(page.status, 200,
    "the sign-in screen should be drawn; it answered " + page.status + " " +
    page.text.slice(0, 300));
  const fields = hiddenFields(page.text);
  assert.ok(fields.authn_id,
    "the sign-in screen carries no authn_id: " + page.text.slice(0, 300));
  fields.username = who;
  fields.password = PASSWORD;
  fields.action = "login";
  let posted = await b.go("POST", R + "/authn/login", form(fields));
  let totpPage = null;
  if (posted.status === 200 && /name="mfa_id"/.test(posted.text)) {
    totpPage = posted;
    if (code) {
      const mfaId = (posted.text.match(/name="mfa_id" value="([^"]+)"/) ||
                     [])[1];
      posted = await b.go("POST", R + "/authn/totp",
                          form({ mfa_id: mfaId, code: code }));
    }
  }
  log.debug("Leaving signInScreen(). " + posted.status + " " +
            posted.location);
  return { page: page, posted: posted, totpPage: totpPage,
           back: posted.location };
}

async function redeem(code, verifier) {
  log.debug("Entering redeem().");
  const r = await send(base + R + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basic() },
    body: form({ grant_type: "authorization_code", code: code,
                 redirect_uri: REDIRECT, code_verifier: verifier }) });
  assert.strictEqual(r.status, 200,
    "the token endpoint should redeem a code it issued; it answered " +
    r.status + " " + r.raw.slice(0, 400));
  log.debug("Leaving redeem().");
  return r.body;
}

// A request answered from the session with a code, redeemed.
async function tokenFromSession(b, extra) {
  log.debug("Entering tokenFromSession().");
  const asked = authorizeRequest(extra);
  const r = await b.go("GET", asked.path);
  const params = atClient(r);
  assert.ok(params && params.get("code"),
    "the session should answer " + JSON.stringify(extra || {}) + " with a " +
    "code and no sign-in; it answered " + r.status + " " + r.location);
  const tokens = await redeem(params.get("code"), asked.verifier);
  log.debug("Leaving tokenFromSession().");
  return tokens;
}

function stepUpResource(token, application) {
  log.debug("Entering stepUpResource().");
  log.debug("Leaving stepUpResource().");
  return send(base + R + "/oauth2/step-up/resource/" +
              encodeURIComponent(application || RESOURCE),
              { headers: token ? { Authorization: "Bearer " + token } : {} });
}

function userinfo(token) {
  log.debug("Entering userinfo().");
  log.debug("Leaving userinfo().");
  return send(base + R + "/oauth2/userinfo",
              { headers: { Authorization: "Bearer " + token } });
}

async function applicationEntry(identifier) {
  log.debug("Entering applicationEntry().");
  const r = await send(realmApi + "/applications?application=" +
                       encodeURIComponent(identifier));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/applications?application= answered " + r.status + " " +
    r.raw.slice(0, 200));
  const entry = (r.body && (r.body.application || r.body)) || {};
  log.debug("Leaving applicationEntry().");
  return entry;
}

function attributeOf(entry, attribute) {
  log.debug("Entering attributeOf().");
  const held = ((entry.fields || {})[attribute] !== undefined)
    ? entry.fields[attribute] : (entry.attributes || {})[attribute];
  const values = held === undefined || held === null ? [] : [].concat(held);
  log.debug("Leaving attributeOf().");
  return values.length ? String(values[0]) : null;
}

// The step-up section of the realm's monitor, and one client's row in it
// walked across the section's own paging parameter.
async function stepUpSection(query) {
  log.debug("Entering stepUpSection().");
  const r = await send(realmApi + "/oauth2/monitor" +
                       (query ? "?" + query : ""));
  assert.strictEqual(r.status, 200,
    "GET <realm>/admin-api/oauth2/monitor answered " + r.status + " " +
    r.raw.slice(0, 300));
  const section = (r.body.sections || []).filter(function (one) {
    return one.id === "stepup";
  })[0];
  assert.ok(section, "the reply carries no `stepup` section: " +
    r.raw.slice(0, 300));
  log.debug("Leaving stepUpSection().");
  return section;
}

async function clientRow(client) {
  log.debug("Entering clientRow(). client=" + client);
  let page = 1;
  for (;;) {
    const section = await stepUpSection("stepUpClientsPage=" + page);
    const row = section.clients.filter(function (one) {
      return one.client_id === client;
    })[0];
    if (row) {
      log.debug("Leaving clientRow(). Found on page " + page + ".");
      return row;
    }
    if (page >= ((section.clientsPaging || {}).pages || 1)) {
      log.debug("Leaving clientRow(). Not found.");
      return null;
    }
    page += 1;
  }
}

// One setting's row out of `/admin-api/config`'s groups, or null.
function settingRow(body, key) {
  log.debug("Entering settingRow(). key=" + key);
  const rows = [];
  ((body && body.groups) || []).forEach(function (group) {
    (group.settings || []).forEach(function (one) {
      rows.push(one);
    });
  });
  ((body && body.settings) || []).forEach(function (one) {
    rows.push(one);
  });
  const row = rows.filter(function (one) {
    return one.key === key;
  })[0] || null;
  log.debug("Leaving settingRow(). found=" + !!row);
  return row;
}

// ===========================================================================
// 0. THE GENERATOR, THE REALM, THE PEOPLE.
// ===========================================================================
function theGeneratorIsRight() {
  log.debug("Entering theGeneratorIsRight().");
  log.info("=== 0. the job's own RFC 6238 implementation ===");
  // RFC 6238 Appendix B with errata 2866's digest-length seeds.
  const seed = function (bytes) {
    log.debug("Entering seed().");
    let s = "";
    while (s.length < bytes) {
      s += "1234567890";
    }
    log.debug("Leaving seed().");
    return Buffer.from(s.slice(0, bytes), "utf8");
  };
  [[59, "SHA1", 20, "94287082"], [1111111109, "SHA1", 20, "07081804"],
   [1234567890, "SHA256", 32, "91819424"],
   [2000000000, "SHA512", 64, "38618901"]].forEach(function (row) {
    const got = codeFor(bytesToBase32(seed(row[2])), row[0] * 1000,
                        { digits: 8, algorithm: row[1] });
    assert.strictEqual(got, row[3],
      "this job's TOTP generator disagrees with RFC 6238 Appendix B at t=" +
      row[0] + " " + row[1] + ": " + got);
  });
  check("the generator this job checks the service with agrees with RFC " +
        "6238 Appendix B", function () {
    assert.ok(true);
  });
  log.debug("Leaving theGeneratorIsRight().");
}

async function ensurePerson(who) {
  log.debug("Entering ensurePerson(). who=" + who);
  await ok(realmApi + "/users/create", {
    username: who, invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: "Step-up " + who, givenName: "Step-up", sn: who,
                  displayName: "Step-up " + who,
                  mail: who + "@stepup.test" } },
    "created " + who + " in the realm with a password");
  log.debug("Leaving ensurePerson().");
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(api + "/realms/create", { id: REALM,
                                     domain: REALM + ".example.net",
                                     name: "RFC 9470 " + STAMP },
           "created the realm");
  await ensurePerson(ALICE);
  await ensurePerson(BOB);
  log.debug("Leaving setUp().");
}

// ===========================================================================
// a. DISCOVERY.
// ===========================================================================
async function discovery() {
  log.debug("Entering discovery().");
  log.info("=== a. acr_values_supported in both discovery documents ===");
  for (const doc of ["/.well-known/oauth-authorization-server",
                     "/.well-known/openid-configuration"]) {
    const r = await send(base + R + doc);
    check(doc + " in the realm publishes acr_values_supported 0, 1, mfa — " +
          "ordered weakest first, and no RFC 8176 method name among them",
          function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
      assert.deepStrictEqual(r.body.acr_values_supported, ["0", "1", "mfa"],
        JSON.stringify(r.body.acr_values_supported));
      assert.ok(String(r.body.issuer || "").indexOf(R) >= 0,
        "the document is the realm's own: " + r.body.issuer);
    });
  }
  log.debug("Leaving discovery().");
}

// ===========================================================================
// b. THE TWO APPLICATIONS, AND THE TWO ATTRIBUTE REFUSALS.
// ===========================================================================
async function theApplications() {
  log.debug("Entering theApplications().");
  log.info("=== b. a client, a resource declaring a requirement ===");
  await ok(realmApi + "/applications/create", {
    identifier: CLIENT, name: "Step-up client " + STAMP,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: CLIENT, oauthRedirectUri: [REDIRECT],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_basic" }
  }, "created the client application");
  // THE CONSENT SCREEN STAYS ON. The client's one scope is consented for
  // everybody on its own entry, which is what an application that must not
  // interrupt anybody is configured with — `oauth2.consentRequired` is left
  // alone, because turning it off would be testing a different service.
  await ok(realmApi + "/consent/grant-global-consent",
           { client: CLIENT, scope: "openid" },
           "consented openid for everybody on the client");
  await ok(realmApi + "/applications/create", {
    identifier: RESOURCE, name: "Step-up API " + STAMP,
    protocols: ["oauth2"],
    fields: { oauthAudience: [API], oauthStepUpAcrValues: "mfa",
              oauthStepUpMaxAge: "600" }
  }, "created the resource application with a step-up requirement");

  let entry = await applicationEntry(RESOURCE);
  check("the resource's requirement is on its entry as written: " +
        "oauthStepUpAcrValues mfa, oauthStepUpMaxAge 600", function () {
    assert.strictEqual(attributeOf(entry, "oauthStepUpAcrValues"), "mfa",
      JSON.stringify(entry).slice(0, 400));
    assert.strictEqual(attributeOf(entry, "oauthStepUpMaxAge"), "600",
      JSON.stringify(entry).slice(0, 400));
  });

  const quote = await postJson(realmApi + "/applications/set",
    { application: RESOURCE, attribute: "oauthStepUpAcrValues",
      value: "mfa a\"b" });
  check("an acr value holding a double quote is REFUSED by the generic " +
        "set (STS-REG-0140) — it could not be repeated in section 3's " +
        "quoted-string", function () {
    assert.strictEqual(quote.status, 400, quote.status + " " + quote.raw);
    assert.strictEqual(quote.body.ok, false, quote.raw);
    assert.ok((quote.body.errors || []).join(" ").length > 0, quote.raw);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(quote.raw),
      "an error code reached the caller: " + quote.raw);
  });
  const negative = await postJson(realmApi + "/applications/set",
    { application: RESOURCE, attribute: "oauthStepUpMaxAge", value: "-5" });
  check("a negative age is REFUSED (STS-REG-0141)", function () {
    assert.strictEqual(negative.status, 400,
                       negative.status + " " + negative.raw);
    assert.strictEqual(negative.body.ok, false, negative.raw);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(negative.raw), negative.raw);
  });
  // THE CODE IS AN OPERATOR'S NAME, RECORDED AND NEVER SENT (root
  // CLAUDE.md), so it is read where it is recorded: the call-log row the
  // refused request left on the realm's audit log.
  const audit = await send(realmApi + "/audit?action=protocol.call&per=200");
  check("the two refusals are on the realm's audit log under their codes, " +
        "STS-REG-0140 and STS-REG-0141", function () {
    assert.strictEqual(audit.status, 200, audit.raw.slice(0, 200));
    const codes = (audit.body.events || []).filter(function (row) {
      return /\/applications\/set/.test(JSON.stringify(row));
    }).map(function (row) {
      return row.errorCode;
    });
    assert.ok(codes.indexOf("STS-REG-0140") >= 0, JSON.stringify(codes));
    assert.ok(codes.indexOf("STS-REG-0141") >= 0, JSON.stringify(codes));
  });
  entry = await applicationEntry(RESOURCE);
  check("AND NEITHER LANDED:the entry still requires mfa within 600 " +
        "seconds — a refusal that wrote anyway reads the same to the caller",
        function () {
    assert.strictEqual(attributeOf(entry, "oauthStepUpAcrValues"), "mfa");
    assert.strictEqual(attributeOf(entry, "oauthStepUpMaxAge"), "600");
  });
  log.debug("Leaving theApplications().");
}

// ===========================================================================
// c. A ONE-FACTOR TOKEN FOR THE API, CHALLENGED; INTROSPECTION.
// ===========================================================================
async function aOneFactorTokenIsChallenged() {
  log.debug("Entering aOneFactorTokenIsChallenged().");
  log.info("=== c. a password sign-in for the API, and the challenge ===");
  const alice = browser(ALICE);
  const asked = authorizeRequest({ resource: API });
  let r = await alice.go("GET", asked.path);
  check("with no session, the authorization request goes to the sign-in " +
        "screen", function () {
    assert.ok(toSignIn(r), r.status + " " + r.location);
  });
  const done = await signInScreen(alice, r.location, ALICE);
  check("a password is enough when nothing more was asked for — no " +
        "one-time code screen", function () {
    assert.strictEqual(done.totpPage, null);
    assert.ok(done.posted.status === 302 || done.posted.status === 303,
      done.posted.status + " " + done.posted.text.slice(0, 200));
    assert.ok(!/step_up_honoured/.test(done.back),
      "a request carrying no requirement gets no marker: " + done.back);
  });
  r = await alice.go("GET", done.back);
  const params = atClient(r);
  check("and the authorization endpoint issues a code", function () {
    assert.ok(params && params.get("code"), r.status + " " + r.location);
  });
  const tokens = await redeem(params.get("code"), asked.verifier);
  const at = claimsOf(tokens.access_token);
  check("RFC 9470 section 6.1: the access token carries acr \"1\" and an " +
        "auth_time, and is addressed to the API", function () {
    assert.strictEqual(at.acr, "1", JSON.stringify(at));
    assert.strictEqual(typeof at.auth_time, "number", JSON.stringify(at));
    assert.ok([].concat(at.aud).indexOf(API) >= 0, JSON.stringify(at.aud));
  });

  r = await stepUpResource(tokens.access_token);
  check("SECTION 3: the stand-in resource answers the one-factor token 401 " +
        "with error=\"insufficient_user_authentication\" under Bearer",
        function () {
    assert.strictEqual(r.status, 401, r.status + " " + r.raw.slice(0, 300));
    assert.ok(/^Bearer error="insufficient_user_authentication"/.test(
      r.challenge), r.challenge);
    assert.strictEqual(r.body.error, "insufficient_user_authentication",
                       r.raw.slice(0, 300));
    assert.ok(String(r.body.error_description || "").length > 0);
  });
  check("and the challenge carries BOTH auth-params the application " +
        "declared, exactly: acr_values=\"mfa\" and max_age=\"600\"",
        function () {
    assert.ok(/, acr_values="mfa"(,|$)/.test(r.challenge), r.challenge);
    assert.ok(/, max_age="600"$/.test(r.challenge), r.challenge);
    assert.ok(/error_description="[^"]+"/.test(r.challenge), r.challenge);
  });

  const intro = await send(base + R + "/oauth2/introspect", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basic(), Accept: "application/json" },
    body: form({ token: tokens.access_token }) });
  check("SECTION 6.2: introspection by the authenticated client carries acr " +
        "and the same auth_time", function () {
    assert.strictEqual(intro.status, 200, intro.raw.slice(0, 300));
    assert.strictEqual(intro.body.active, true, intro.raw.slice(0, 300));
    assert.strictEqual(intro.body.acr, "1", intro.raw.slice(0, 300));
    assert.strictEqual(intro.body.auth_time, at.auth_time,
                       intro.raw.slice(0, 300));
  });
  log.debug("Leaving aOneFactorTokenIsChallenged().");
  return { alice: alice, oneFactor: tokens.access_token };
}

// ===========================================================================
// d. WHAT THE STAND-IN RESOURCE REFUSES BEFORE ASKING ANYTHING ABOUT STEP-UP.
// ===========================================================================
async function theResourceRefusesFirst(held) {
  log.debug("Entering theResourceRefusesFirst().");
  log.info("=== d. refused before any step-up question ===");
  const own = await tokenFromSession(held.alice);
  check("(a second request is answered from the session: a token for the " +
        "default audience, still acr \"1\")", function () {
    assert.strictEqual(claimsOf(own.access_token).acr, "1");
  });
  let r = await stepUpResource(own.access_token);
  check("a token addressed to ANOTHER audience is 401 invalid_token, not a " +
        "step-up challenge — stepping up would not make it this API's",
        function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_token", r.raw.slice(0, 300));
    assert.ok(!/insufficient_user_authentication/.test(r.challenge),
      r.challenge);
    assert.ok(r.raw.indexOf(RESOURCE) >= 0,
      "the refusal names the application it answers for: " +
      r.raw.slice(0, 300));
  });
  r = await stepUpResource(null);
  check("no token at all is 401 invalid_token, not a step-up challenge",
        function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_token", r.raw.slice(0, 300));
    assert.ok(!/acr_values=/.test(r.challenge), r.challenge);
  });
  r = await stepUpResource(held.oneFactor, "su-nobody-" + STAMP);
  check("an application the realm has no entry for is 404", function () {
    assert.strictEqual(r.status, 404, r.raw.slice(0, 300));
  });
  r = await send(base + "/oauth2/step-up/resource/" +
                 encodeURIComponent(RESOURCE),
                 { headers: { Authorization: "Bearer " + held.oneFactor } });
  check("and the application is the REALM's: the default realm has no " +
        "such entry and answers 404", function () {
    assert.strictEqual(r.status, 404, r.status + " " + r.raw.slice(0, 300));
  });
  log.debug("Leaving theResourceRefusesFirst().");
}

// ===========================================================================
// e. STEP-UP TO mfa, END TO END.
// ===========================================================================
async function enrolAnAuthenticator(alice) {
  log.debug("Entering enrolAnAuthenticator().");
  // `/portal` is a relying party of the realm's own authorization server,
  // so a browser holding a sign-on session goes round the code flow with no
  // sign-in screen and lands on the page.
  let r = await alice.go("GET", R + "/portal/mfa");
  for (let i = 0; i < 6 && (r.status === 302 || r.status === 303); i++) {
    assert.ok(!/\/authn\/login/.test(r.location),
      "the portal should be answered out of the sign-on session; it sent " +
      "the browser to sign in: " + r.location);
    r = await alice.go("GET", r.location);
  }
  assert.strictEqual(r.status, 200,
    "/portal/mfa should be drawn; it answered " + r.status + " " +
    r.text.slice(0, 300));
  const csrf = (r.text.match(/name="csrf_token" value="([^"]+)"/) || [])[1];
  r = await alice.go("POST", R + "/portal/mfa",
                     form({ action: "start", csrf_token: csrf }));
  assert.ok(r.status === 303 || r.status === 302,
    "starting the setup answered " + r.status);
  const page = await alice.go("GET", R + "/portal/mfa");
  const cell = page.text.match(/<th>Secret<\/th><td><code>([^<]+)<\/code>/);
  const secret = cell ? cell[1].replace(/\s+/g, "") : "";
  assert.ok(secret.length >= 32,
    "no secret on the setup page: " + page.text.slice(0, 400));
  r = await alice.go("POST", R + "/portal/mfa",
    form({ action: "confirm", code: codeFor(secret),
           csrf_token: (page.text.match(
             /name="csrf_token" value="([^"]+)"/) || [])[1] }));
  check("(" + ALICE + " enrols an authenticator app at the realm's " +
        "/portal/mfa, confirmed with a code this job computed)", function () {
    assert.ok(r.status === 200 || r.status === 302 || r.status === 303,
      r.status + " " + r.text.slice(0, 300));
    assert.ok(!/class="err"/.test(r.text), r.text.slice(0, 300));
  });
  log.debug("Leaving enrolAnAuthenticator().");
  return secret;
}

async function stepUpToMfa(held) {
  log.debug("Entering stepUpToMfa().");
  log.info("=== e. step-up to mfa, end to end ===");
  const alice = held.alice;
  const secret = await enrolAnAuthenticator(alice);

  const cold = browser("no-session");
  const coldAsk = await cold.go("GET",
    authorizeRequest({ acr_values: "mfa" }).path);
  check("(with no session, acr_values=mfa goes to the sign-in screen, as " +
        "any request does)", function () {
    assert.ok(toSignIn(coldAsk), coldAsk.status + " " + coldAsk.location);
  });

  const asked = authorizeRequest({ resource: API, acr_values: "mfa" });
  const first = await alice.go("GET", asked.path);
  check("A ONE-FACTOR SESSION IS SENT TO SIGN IN AGAIN for acr_values=mfa, " +
        "rather than answered with a code — the whole of what RFC 9470 asks " +
        "of an authorization server", function () {
    assert.ok(toSignIn(first),
      "expected the sign-in screen; it answered " + first.status + " " +
      first.location);
    assert.ok(!/[?&]code=/.test(first.location), first.location);
  });
  // Thirty seconds ahead: the window forgives one step either side, and the
  // step the enrolment's confirmation code spent is refused as a replay.
  const done = await signInScreen(alice, first.location, ALICE,
                                  codeFor(secret, Date.now() + 30000));
  check("the sign-in screen DEMANDS the second factor: the checkbox drawn " +
        "checked and disabled", function () {
    assert.ok(/id="use_webauthn"[^>]*checked disabled/.test(done.page.text),
      done.page.text.slice(0, 600));
  });
  check("and the password is answered with the one-time code screen, not " +
        "a redirect", function () {
    assert.ok(done.totpPage !== null,
      "no code screen: " + done.posted.status + " " + done.posted.location);
  });
  check("the code is accepted and the return address carries " +
        "step_up_honoured=1", function () {
    assert.ok(done.posted.status === 302 || done.posted.status === 303,
      done.posted.status + " " + done.posted.text.slice(0, 300));
    assert.ok(/[?&]step_up_honoured=1(&|$)/.test(done.back), done.back);
    assert.ok(/\/oauth2\/authorize\?/.test(done.back), done.back);
  });
  const back = await alice.go("GET", done.back);
  const params = atClient(back);
  check("and the stepped-up session is issued a code", function () {
    assert.ok(params && params.get("code"),
              back.status + " " + back.location);
  });
  const tokens = await redeem(params.get("code"), asked.verifier);
  const at = claimsOf(tokens.access_token);
  const idt = claimsOf(tokens.id_token);
  check("the access token and the ID Token carry acr \"mfa\", and amr " +
        "names the one-time code", function () {
    assert.strictEqual(at.acr, "mfa", JSON.stringify(at));
    assert.strictEqual(idt.acr, "mfa", JSON.stringify(idt));
    assert.ok([].concat(at.amr || idt.amr || []).indexOf("otp") >= 0,
      JSON.stringify([at.amr, idt.amr]));
  });
  const r = await stepUpResource(tokens.access_token);
  check("THE RESOURCE THAT CHALLENGED ANSWERS THE STEPPED-UP TOKEN 200, " +
        "met:true, naming the requirement and the token's acr", function () {
    assert.strictEqual(r.status, 200, r.status + " " + r.raw.slice(0, 300));
    assert.strictEqual(r.body.met, true);
    assert.strictEqual(r.body.resource, RESOURCE);
    assert.deepStrictEqual(r.body.requirement,
                           { acr_values: "mfa", max_age: 600 });
    assert.strictEqual(r.body.token.acr, "mfa");
    assert.strictEqual(r.body.token.client_id, CLIENT);
    // An auth-scheme is case-insensitive (RFC 9110 section 11.1), and the
    // resource reports it the way `presentedAccessToken()` normalised it.
    assert.ok(/^bearer$/i.test(r.body.token.scheme), r.body.token.scheme);
    assert.ok(r.body.token.authenticated_seconds_ago <= 600,
              String(r.body.token.authenticated_seconds_ago));
  });
  log.debug("Leaving stepUpToMfa().");
}

// ===========================================================================
// f. THE HIERARCHY.
// ===========================================================================
async function theHierarchy(held) {
  log.debug("Entering theHierarchy().");
  log.info("=== f. an mfa session answers acr_values=1 ===");
  const tokens = await tokenFromSession(held.alice, { acr_values: "1" });
  check("THE mfa SESSION ANSWERS acr_values=1 WITH NO SIGN-IN, and the " +
        "tokens carry the REQUESTED \"1\", not the session's \"mfa\"",
        function () {
    assert.strictEqual(claimsOf(tokens.access_token).acr, "1");
    assert.strictEqual(claimsOf(tokens.id_token).acr, "1");
  });
  const preferred = await tokenFromSession(held.alice,
                                           { acr_values: "mfa 1" });
  check("and `mfa 1` is answered with the most preferred value it meets, " +
        "\"mfa\"", function () {
    assert.strictEqual(claimsOf(preferred.access_token).acr, "mfa");
  });
  log.debug("Leaving theHierarchy().");
}

// ===========================================================================
// g. THE AUTHORIZATION ENDPOINT'S THREE REFUSALS.
// ===========================================================================
async function theRefusals() {
  log.debug("Entering theRefusals().");
  log.info("=== g. login_required, unmet_authentication_requirements, " +
           "invalid_request ===");
  const bob = browser(BOB);
  const plain = authorizeRequest();
  let r = await bob.go("GET", plain.path);
  const done = await signInScreen(bob, r.location, BOB);
  r = await bob.go("GET", done.back);
  check("(" + BOB + " signs in with a password: a one-factor session)",
        function () {
    assert.ok(atClient(r) && atClient(r).get("code"),
              r.status + " " + r.location);
  });

  r = await bob.go("GET",
                   authorizeRequest({ acr_values: "mfa",
                                      prompt: "none" }).path);
  let params = atClient(r);
  check("PROMPT=NONE WITH A REQUIREMENT THE SESSION DOES NOT MEET IS " +
        "login_required, returned to the client — not a code, and not the " +
        "sign-in screen prompt=none forbids", function () {
    assert.ok(params, r.status + " " + r.location);
    assert.strictEqual(params.get("error"), "login_required", r.location);
    assert.strictEqual(params.get("code"), null, r.location);
  });

  r = await bob.go("GET", authorizeRequest({ acr_values: UNMEETABLE }).path);
  check("a URN no sign-in here produces still gets ONE sign-in — a " +
        "federation partner's sign-in might produce it", function () {
    assert.ok(toSignIn(r), r.status + " " + r.location);
  });
  const again = await signInScreen(bob, r.location, BOB);
  check("(the sign-in completes and returns with the marker)", function () {
    assert.ok(/[?&]step_up_honoured=1(&|$)/.test(again.back), again.back);
  });
  r = await bob.go("GET", again.back);
  params = atClient(r);
  check("SECTION 5: ON THE RETURN THE REQUEST IS REFUSED " +
        "unmet_authentication_requirements, not sent round again", function () {
    assert.ok(params, r.status + " " + r.location);
    assert.strictEqual(params.get("error"),
                       "unmet_authentication_requirements", r.location);
    assert.strictEqual(params.get("code"), null, r.location);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.location), r.location);
  });

  r = await bob.go("GET",
                   authorizeRequest({ acr_values: "mfa a\"b" }).path);
  params = atClient(r);
  check("an acr value holding a double quote is invalid_request, naming " +
        "acr_values", function () {
    assert.ok(params, r.status + " " + r.location);
    assert.strictEqual(params.get("error"), "invalid_request", r.location);
    assert.ok(/acr_values/.test(params.get("error_description") || ""),
      params.get("error_description"));
  });
  log.debug("Leaving theRefusals().");
  return bob;
}

// ===========================================================================
// h. THIS SERVICE'S OWN RESOURCE SERVER, IN THE REALM.
// ===========================================================================
async function resetQuietly(key) {
  log.debug("Entering resetQuietly(). key=" + key);
  try {
    const r = await postJson(realmApi + "/config/reset", { key: key });
    if (r.status !== 200) {
      log.warn("resetting " + key + " in " + REALM + " answered " + r.status +
               " " + r.raw.slice(0, 200));
    }
  } catch (e) {
    // A `finally` that throws replaces the failure that got there
    // (tests/CLAUDE.md), so the reset reports and does not throw.
    log.debug("Caught in resetQuietly(): " + ((e && e.message) || e));
    log.warn("resetting " + key + " in " + REALM + " failed: " +
             ((e && e.message) || e));
  }
  log.debug("Leaving resetQuietly().");
}

async function theOwnResourceServer(held, bob) {
  log.debug("Entering theOwnResourceServer().");
  log.info("=== h. UserInfo under oauth2.stepUpAcrValues in the realm ===");
  const oneFactor = (await tokenFromSession(bob)).access_token;
  const mfa = (await tokenFromSession(held.alice,
                                      { acr_values: "mfa" })).access_token;
  let r = await userinfo(oneFactor);
  check("(UserInfo answers the one-factor token while nothing is required)",
        function () {
    assert.strictEqual(r.status, 200, r.status + " " + r.raw.slice(0, 200));
  });
  const before = await stepUpSection("");
  check("the monitor reports no requirement on the realm's own resource " +
        "server", function () {
    assert.deepStrictEqual(before.ownResourceRequirement,
                           { acr_values: null, max_age: null });
  });
  try {
    await ok(realmApi + "/config/set",
             { key: "oauth2.stepUpAcrValues", value: "mfa" },
             "required mfa at the realm's own resource server");
    r = await userinfo(oneFactor);
    check("WITH oauth2.stepUpAcrValues=mfa IN THE REALM, UserInfo answers " +
          "the one-factor token 401 insufficient_user_authentication with " +
          "acr_values=\"mfa\"", function () {
      assert.strictEqual(r.status, 401, r.status + " " + r.raw.slice(0, 200));
      assert.ok(/^Bearer error="insufficient_user_authentication"/.test(
        r.challenge), r.challenge);
      assert.ok(/acr_values="mfa"/.test(r.challenge), r.challenge);
      assert.ok(!/max_age=/.test(r.challenge),
        "no age was required, so none is named: " + r.challenge);
    });
    r = await userinfo(mfa);
    check("and answers the mfa token 200", function () {
      assert.strictEqual(r.status, 200, r.status + " " + r.raw.slice(0, 200));
    });
    const during = await stepUpSection("");
    check("the monitor's ownResourceRequirement follows the setting",
          function () {
      assert.deepStrictEqual(during.ownResourceRequirement,
                             { acr_values: "mfa", max_age: null });
    });
    const overriding = settingRow((await send(realmApi + "/config")).body,
                                  "oauth2.stepUpAcrValues");
    check("(the realm's settings report the value as the REALM's while it " +
          "is set)", function () {
      assert.ok(overriding, "the realm's settings do not list the key");
      assert.strictEqual(overriding.source, "realm",
                         JSON.stringify(overriding));
    });
  } finally {
    await resetQuietly("oauth2.stepUpAcrValues");
  }
  r = await userinfo(oneFactor);
  check("RESET, the one-factor token is answered again", function () {
    assert.strictEqual(r.status, 200, r.status + " " + r.raw.slice(0, 200));
  });
  const setting = settingRow((await send(realmApi + "/config")).body,
                             "oauth2.stepUpAcrValues");
  check("and the setting is no longer the realm's own value — put back with " +
        "reset, not by writing the old value over it", function () {
    assert.ok(setting, "the realm's settings do not list the key");
    assert.notStrictEqual(setting.source, "realm", JSON.stringify(setting));
    assert.notStrictEqual(setting.source, "override",
                          JSON.stringify(setting));
  });
  log.debug("Leaving theOwnResourceServer().");
}

// ===========================================================================
// i. THE MONITOR, THROUGH THE API AND THE CONSOLE.
// ===========================================================================
async function theMonitor() {
  log.debug("Entering theMonitor().");
  log.info("=== i. the step-up section of the realm's monitor ===");
  const section = await stepUpSection("");
  check("the section is RFC 9470's, with its eight events, paged under its " +
        "own parameter and publishing what this realm supports", function () {
    assert.strictEqual(section.title, "Step-up authentication (RFC 9470)");
    assert.strictEqual(section.events.length, 8,
                       JSON.stringify(section.events));
    assert.strictEqual(section.clientsParam, "stepUpClientsPage");
    assert.deepStrictEqual(section.acrValuesSupported, ["0", "1", "mfa"]);
    assert.deepStrictEqual(section.ownResourceRequirement,
                           { acr_values: null, max_age: null });
  });
  const row = await clientRow(CLIENT);
  const c = (row && row.counters) || {};
  check("THIS CLIENT'S ROW MOVED FOR EVERY EVENT THIS JOB CAUSED: sent to " +
        "sign in again for acr, met after signing in, met by the session, " +
        "unmet, login_required, sent to sign in with no session, and the " +
        "challenges its tokens met", function () {
    assert.ok(row, "no row for " + CLIENT);
    assert.ok(c.stepUpReauthAcr >= 2, JSON.stringify(c));
    assert.ok(c.stepUpMetAfterSignIn >= 1, JSON.stringify(c));
    assert.ok(c.stepUpMetBySession >= 3, JSON.stringify(c));
    assert.ok(c.stepUpUnmet >= 1, JSON.stringify(c));
    assert.ok(c.stepUpLoginRequired >= 1, JSON.stringify(c));
    assert.ok(c.stepUpSignIn >= 1, JSON.stringify(c));
    assert.ok(c.stepUpChallenged >= 2, JSON.stringify(c));
    assert.strictEqual(c.stepUpReauthMaxAge, 0, JSON.stringify(c));
  });
  check("the section's totals are at least this client's", function () {
    Object.keys(c).forEach(function (counter) {
      assert.ok(section.totals[counter] >= c[counter],
                counter + ": " + JSON.stringify(section.totals));
    });
  });

  const anonymous = await send(base + R + "/admin/oauth2/monitor");
  check("the console page is behind the console's gate", function () {
    assert.ok(anonymous.status === 302 || anonymous.status === 303,
              "status " + anonymous.status);
  });
  const cookie = await consoleSignIn.signInToTheConsole(base, OPERATOR, log,
                                                        { grant: "read" });
  const page = await send(base + R + "/admin/oauth2/monitor?format=json", {
    headers: cookie ? { cookie: cookie } : {} });
  check("?format=json of the realm's console page carries the same step-up " +
        "row the API does (rule 7)", function () {
    assert.strictEqual(page.status, 200,
                       page.status + " " + page.raw.slice(0, 300));
    const s = (page.body.sections || []).filter(function (one) {
      return one.id === "stepup";
    })[0];
    assert.ok(s, page.raw.slice(0, 300));
    assert.strictEqual(s.clientsParam, "stepUpClientsPage");
    const mine = s.clients.filter(function (one) {
      return one.client_id === CLIENT;
    })[0];
    assert.ok(mine, "the console's JSON has no row for " + CLIENT);
    assert.deepStrictEqual(mine.counters, c);
  });
  log.debug("Leaving theMonitor().");
}

async function test() {
  log.debug("Entering test().");
  log.info("RFC 9470 step-up against " + base + " in the realm " + REALM +
           ", client " + CLIENT + ", resource " + RESOURCE);
  theGeneratorIsRight();
  await setUp();
  await discovery();
  await theApplications();
  const held = await aOneFactorTokenIsChallenged();
  await theResourceRefusesFirst(held);
  await stepUpToMfa(held);
  await theHierarchy(held);
  const bob = await theRefusals();
  await theOwnResourceServer(held, bob);
  await theMonitor();
  assert.ok(checks >= FLOOR,
    "only " + checks + " checks ran, against a floor of " + FLOOR + ". A " +
    "section that stops being called takes its assertions with it.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_step_up")
  .description("RFC 9470 step-up authentication over HTTP in a throwaway " +
      "realm: acr_values_supported, a resource application's requirement " +
      "and its two refusals, the stand-in resource's challenge and what it " +
      "refuses first, acr and auth_time in introspection, a one-factor " +
      "session sent to sign in again and stepped up to mfa with a TOTP " +
      "code, the hierarchy, login_required, " +
      "unmet_authentication_requirements and invalid_request, UserInfo " +
      "under oauth2.stepUpAcrValues, and the monitor's step-up section.")
  // Accepted and ignored: the parent project's run-report.js passes --url to
  // every job; this repository's (tests/tools/run-report.js) passes none.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
