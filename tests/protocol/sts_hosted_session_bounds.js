// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_hosted_session_bounds.js
//
// ---------------------------------------------------------------------------
// THE CONSOLE, THE PORTAL AND THE REPORTS APPLICATION KEEP A SESSION BOUND
// OF THEIR OWN, OVER THE WIRE (#825).
//
// D12 (#444): carries over `tests/hosted_session_bounds.js`. In a realm of
// its own, through `/admin-api/applications/set` and `update-fields` on the
// realm's seeded `sts-admin-console`, `sts-user-portal` and `sts-report`:
//
//   1. the shipped bounds as the registry holds them: the console's and
//      reports' hour, the portal's eight hours, fifteen minutes idle;
//   7. a confirmed different number is stored and read back;
//   8. an unconfirmed change is refused (STS-REG-0368) and the stored value
//      kept; a confirmed clear, a 0 and a value that will not parse are
//      refused (STS-REG-0369); removing the bound with `applications/remove`
//      is refused at the request schema (it is not a multi-valued
//      attribute: STS-API-0009 on the wire, where the in-process call says
//      STS-REG-0369);
//   9. a mixed `update-fields` save without confirm writes NOTHING
//      (STS-REG-0368), and with confirm writes both;
//  10. a confirmed bound change is audited `application.update` with
//      `hostedSessionBound`;
//   2/3. THE BOUND ENFORCED: the portal's bound set to 30 seconds (the
//      row's step); a fresh sign-on session is answered a code for the
//      portal at once, and once
//      it is older than 30 seconds the portal's authorization request is sent
//      to the sign-in screen even with `max_age` 99999 asked (a longer
//      request is capped), while an ordinary client in the same browser is
//      still answered from the session (5: realm max age 0 changes nothing).
//
// NOT carried, and why: 4, 5c–5e, 6 and 11 are the in-process helpers'
// arithmetic (`hostedEffective()`, the debugger's realm-only bound) and the
// start-up fill of an absent attribute, which needs an ldapmodify past the
// registry and a restart (class (d)); the refresh-lifetime halves (6, 6c)
// have no wire form short of a token's own expiry, which no answer states.
//
// OWNED HERE (local: true): this repository's own registry and hosted
// applications.
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
var log = bunyan.createLogger({ name: "sts_hosted_session_bounds",
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
const PASSWORD = "Bounds-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-9a!";
// A desktop browser's User-Agent with this job's name on the end: risk
// scoring reads a bare job name as an automated client, and product refuses
// a first sign-in from one (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_hosted_session_bounds/1.0 (" + STAMP + ")";

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


const CONSOLE = "sts-admin-console";
const PORTAL = "sts-user-portal";
const REPORT = "sts-report";
const USER = names.usernameFor("hsb");
const ORDINARY = "hsb-ordinary-" + STAMP;
const ORDINARY_REDIRECT = "https://rp-" + STAMP + ".hsb.example/cb";
let REALM = "";

function first(v) {
  log.debug("Entering first().");
  log.debug("Leaving first().");
  return Array.isArray(v) ? String(v[0] === undefined ? "" : v[0])
    : String(v === undefined || v === null ? "" : v);
}

async function fieldsOf(identifier) {
  log.debug("Entering fieldsOf(). " + identifier);
  const r = await api(REALM, "GET", "/applications?application=" +
                      encodeURIComponent(identifier));
  must(r.status === 200 && r.body, "reading " + identifier + ": " +
       r.status + " " + r.raw.slice(0, 300));
  const app = r.body.application || (r.body.page &&
    r.body.page.application) || r.body;
  log.debug("Leaving fieldsOf().");
  return (app && (app.fields || app)) || {};
}

function setAttr(identifier, attribute, value, confirm) {
  log.debug("Entering setAttr(). " + identifier + " " + attribute);
  const body = { application: identifier, attribute: attribute,
                 value: value };
  if (confirm !== undefined) {
    body.confirm = confirm;
  }
  log.debug("Leaving setAttr().");
  return api(REALM, "POST", "/applications/set", body);
}

async function authorize(b, client, redirect, extra) {
  log.debug("Entering authorize(). " + client);
  const p = pkce();
  const r = await b.go("GET", realmBase(REALM) + "/oauth2/authorize?" +
    form(Object.assign({ client_id: client, response_type: "code",
      redirect_uri: redirect, scope: "openid", state: "s",
      nonce: "n" + Date.now(), code_challenge: p.challenge,
      code_challenge_method: "S256" }, extra || {})));
  log.debug("Leaving authorize(). " + r.status);
  return r;
}

function answeredWithCode(r, redirect) {
  log.debug("Entering answeredWithCode().");
  log.debug("Leaving answeredWithCode().");
  return (r.status === 302 || r.status === 303) &&
    urls.isAt(r.location, redirect) && /[?&]code=/.test(r.location);
}

async function test() {
  log.debug("Entering test().");
  REALM = await makeRealm("hsb", "development");

  log.info("=== 1. the shipped bounds ===");
  const consoleFields = await fieldsOf(CONSOLE);
  const portalFields = await fieldsOf(PORTAL);
  const reportFields = await fieldsOf(REPORT);
  await check("1. the console keeps an hour, the portal eight hours and " +
              "reports the console's hour", async function () {
    expect(first(consoleFields.oauthMaxAuthAgeS) === "3600",
           JSON.stringify(consoleFields.oauthMaxAuthAgeS));
    expect(first(portalFields.oauthMaxAuthAgeS) === "28800",
           JSON.stringify(portalFields.oauthMaxAuthAgeS));
    expect(first(reportFields.oauthMaxAuthAgeS) === "3600",
           JSON.stringify(reportFields.oauthMaxAuthAgeS));
  });
  await check("1. reports' and the console's refresh idle is 15 minutes",
              async function () {
    expect(first(reportFields.oauthRefreshIdleSeconds) === "900",
           JSON.stringify(reportFields.oauthRefreshIdleSeconds));
    expect(first(consoleFields.oauthRefreshIdleSeconds) === "900",
           JSON.stringify(consoleFields.oauthRefreshIdleSeconds));
  });
  const ttl = first(consoleFields.oauthRefreshTokenTtlS);

  log.info("=== 7. a confirmed different number ===");
  let r = await setAttr(CONSOLE, "oauthMaxAuthAgeS", "7200", "1");
  let now = await fieldsOf(CONSOLE);
  await check("7. a confirmed different number is stored and read back",
              async function () {
    expect(r.status === 200, r.status + " " + r.raw.slice(0, 300));
    expect(first(now.oauthMaxAuthAgeS) === "7200",
           JSON.stringify(now.oauthMaxAuthAgeS));
  });
  r = await setAttr(CONSOLE, "oauthMaxAuthAgeS", "7200");
  await check("7. an unchanged value needs no confirm", async function () {
    expect(r.status === 200, r.status + " " + r.raw.slice(0, 300));
  });

  log.info("=== 8. the refusals ===");
  const cases = [
    ["8. an unconfirmed change", CONSOLE, "oauthRefreshTokenTtlS", "1800",
     undefined, "STS-REG-0368", "oauthRefreshTokenTtlS", ttl],
    ["8d. a confirmed clear", CONSOLE, "oauthRefreshIdleSeconds", "", "1",
     "STS-REG-0369", "oauthRefreshIdleSeconds", "900"],
    ["8e. 0 on reports", REPORT, "oauthMaxAuthAgeS", "0", "on",
     "STS-REG-0369", "oauthMaxAuthAgeS", "3600"],
    ["8f. a value the setting will not parse", PORTAL,
     "oauthRefreshIdleSeconds", "nope", "true", "STS-REG-0369",
     "oauthRefreshIdleSeconds", first(portalFields.oauthRefreshIdleSeconds)]
  ];
  for (const [what, app, attr, value, confirm, code, readBack, kept] of
       cases) {
    const before = await codeCount(REALM, code);
    const got = await setAttr(app, attr, value, confirm);
    const recorded = await newRowWith(REALM, code, before);
    const after = await fieldsOf(app);
    await check(what + " is refused 400, " + code + " recorded, the stored " +
                "value kept and no code sent", async function () {
      expect(got.status === 400, got.status + " " + got.raw.slice(0, 300));
      expect(recorded, "no " + code + " row");
      expect(first(after[readBack]) === kept,
             readBack + "=" + JSON.stringify(after[readBack]) + " not " +
             kept);
      expect(!/STS-[A-Z]+-\d{4}/.test(got.raw), "a code was sent");
    });
  }
  const removeBefore = await codeCount(REALM, "STS-API-0009");
  const removed = await api(REALM, "POST", "/applications/remove",
    { application: CONSOLE, attribute: "oauthRefreshTokenTtlS",
      value: ttl, confirm: "1" });
  const removeRecorded = await newRowWith(REALM, "STS-API-0009",
                                          removeBefore);
  const afterRemove = await fieldsOf(CONSOLE);
  await check("8g. removing the bound is refused — at the request schema, " +
              "since it is no multi-valued attribute (STS-API-0009) — and " +
              "the stored value kept", async function () {
    expect(removed.status === 400, removed.status + " " +
           removed.raw.slice(0, 300));
    expect(removeRecorded, "no STS-API-0009 row");
    expect(first(afterRemove.oauthRefreshTokenTtlS) === ttl,
           JSON.stringify(afterRemove.oauthRefreshTokenTtlS));
  });

  log.info("=== 9. a mixed save ===");
  const oldDesc = first(afterRemove.description);
  const before9 = await codeCount(REALM, "STS-REG-0368");
  const partial = await api(REALM, "POST", "/applications/update-fields",
    { application: CONSOLE, fields: { oauthMaxAuthAgeS: "1800",
      description: "hosted bound partial " + STAMP } });
  const recorded9 = await newRowWith(REALM, "STS-REG-0368", before9);
  const afterPartial = await fieldsOf(CONSOLE);
  await check("9. a mixed save without confirm is refused (STS-REG-0368) " +
              "and writes NOTHING — neither the description nor the bound",
              async function () {
    expect(partial.status === 400, partial.status + " " +
           partial.raw.slice(0, 300));
    expect(recorded9, "no STS-REG-0368 row");
    expect(first(afterPartial.description) === oldDesc,
           JSON.stringify(afterPartial.description));
    expect(first(afterPartial.oauthMaxAuthAgeS) === "7200",
           JSON.stringify(afterPartial.oauthMaxAuthAgeS));
  });
  const both = await api(REALM, "POST", "/applications/update-fields",
    { application: CONSOLE, confirm: "1", fields: {
      oauthMaxAuthAgeS: "1800", description: "hosted bound " + STAMP } });
  const afterBoth = await fieldsOf(CONSOLE);
  await check("9e. the same save with confirm writes both", async function () {
    expect(both.status === 200, both.status + " " + both.raw.slice(0, 300));
    expect(first(afterBoth.description) === "hosted bound " + STAMP,
           JSON.stringify(afterBoth.description));
    expect(first(afterBoth.oauthMaxAuthAgeS) === "1800",
           JSON.stringify(afterBoth.oauthMaxAuthAgeS));
  });

  log.info("=== 10. the audit row ===");
  const audit = await api(REALM, "GET", "/audit?per=500");
  const rows = ((audit.body && (audit.body.rows || audit.body.events)) ||
    []).filter(function (one) {
    return one.action === "application.update" && one.target === CONSOLE &&
      one.detail && one.detail.hostedSessionBound === true;
  });
  await check("10. a confirmed bound change is audited application.update " +
              "with hostedSessionBound", async function () {
    expect(rows.length > 0, JSON.stringify(audit.body).slice(0, 400));
  });

  log.info("=== 2, 3, 5. the portal's bound, enforced ===");
  await createPerson(REALM, USER);
  await apiOk(REALM, "/applications/create", { identifier: ORDINARY,
    name: ORDINARY, kind: "oauth2-client", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [ORDINARY], oauthRedirectUri: [ORDINARY_REDIRECT],
              oauthGrantType: ["authorization_code"],
              oauthResponseType: ["code"], oauthAllowedScope: ["openid"],
              oauthTokenEndpointAuthMethod: "none" } }, "an ordinary client");
  for (const client of [ORDINARY, PORTAL]) {
    await apiOk(REALM, "/consent/grant-global-consent",
                { client: client, scope: "openid" }, "consented openid");
  }
  r = await setAttr(PORTAL, "oauthMaxAuthAgeS", "30", "1");
  must(r.status === 200, "the portal's bound of 30s: " + r.status + " " +
       r.raw.slice(0, 300));
  const portalRedirect = realmBase(REALM) + "/portal/callback";
  const b = browser();
  // The shell registers the realm's /portal/callback on the seeded client.
  await b.go("GET", realmBase(REALM) + "/portal");
  let start = await authorize(b, ORDINARY, ORDINARY_REDIRECT);
  must(sentToSignIn(start), "no sign-in screen: " + start.status + " " +
       start.location);
  const signed = await authnSignin.signInWithJar(realmBase(REALM),
    new URL(start.location, realmBase(REALM) + "/").toString(),
    { action: "login", username: USER, password: PASSWORD }, b.jar,
    { ignoreOffer: true, headers: { "User-Agent": AGENT } });
  must(signed.status === 303, "the sign-in: " + signed.status + " " +
       String(signed.text || "").slice(0, 300));
  const fresh = await authorize(b, PORTAL, portalRedirect);
  await check("2c. a fresh sign-on session is answered a code for the " +
              "portal at once", async function () {
    expect(answeredWithCode(fresh, portalRedirect),
           fresh.status + " " + fresh.location);
  });
  await sleep(31500);
  const stale = await authorize(b, PORTAL, portalRedirect,
                                { max_age: "99999" });
  await check("2, 3b. once the session is older than the portal's 30 " +
              "seconds its authorization request is sent to the sign-in " +
              "screen, even with max_age 99999 asked (a longer request is " +
              "capped)", async function () {
    expect(sentToSignIn(stale), stale.status + " " + stale.location);
  });
  const ordinary = await authorize(b, ORDINARY, ORDINARY_REDIRECT);
  await check("5. an ordinary client in the same browser is still answered " +
              "from the session: realm max age 0 holds it to nothing",
              async function () {
    expect(answeredWithCode(ordinary, ORDINARY_REDIRECT),
           ordinary.status + " " + ordinary.location);
  });
  const shortAsk = await authorize(b, ORDINARY, ORDINARY_REDIRECT,
                                   { max_age: "5" });
  await check("3. a request max_age shorter than the session's age is " +
              "honoured for an ordinary client too", async function () {
    expect(sentToSignIn(shortAsk), shortAsk.status + " " + shortAsk.location);
  });
  log.debug("Leaving test().");
}

main();
