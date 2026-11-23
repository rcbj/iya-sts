// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authn_policy.js
//
// ---------------------------------------------------------------------------
// THE AUTHENTICATION POLICY, AND A GROUP NAMING ONE, OVER THE WIRE (#64,
// #1237, rule 3cx).
//
// D12 (#444): carries over `tests/authn_policy.js` and
// `tests/authn_policy_by_group.js`, in a PRODUCT realm of its own (A–F) and
// a DEVELOPMENT one (G, H: a product realm asks everybody for a second
// factor before the mechanism rule is the question), through
// `/admin-api/policies`, `/admin-api/groups/set-policy`,
// `/admin-api/applications/set` and the sign-in screen:
//
//   A. the profile in force with nothing stored in the realm (the default
//      realm's, or the built-in one, whichever the default realm holds),
//      with both email mechanisms off, no first-factor row for a TOTP or a
//      recovery code, and no "never";
//   B. a save that leaves a field out is refused BY NAME; an enum outside
//      its values, an emailed code valid for more than ten minutes, a
//      profile with no first factor (STS-AUTHN-0243), a second factor
//      required with none allowed, and another profile name
//      (STS-AUTHN-0242) are refused;
//   C. the realm's own save is in force there (`from: realm`); `reset` puts
//      it back to inheriting;
//   D. an email row cannot be saved on where the realm cannot send mail
//      (STS-AUTHN-0244);
//   E. the retired settings (`totp.enabled`, `backupCodes.enabled`,
//      `authn.mfaRequired`) are not in `/admin-api/config`;
//   F. the page holds every policy kind, and the actions are the kinds';
//   G. A GROUP NAMES ITS POLICY: `policyReferences` on the group; a name the
//      realm does not hold refused (STS-LDAP-0195); a precedence outside 1
//      to 1000 refused (STS-AUTHN-0541); at the sign-in screen the policy of
//      lower precedence wins — a member of a group naming a policy with no
//      password is refused a password sign-in the application's policy
//      would allow, somebody outside the group is not, raising the group's
//      precedence lets the member in, and an equal precedence goes by name;
//   H. a named policy a group names is not deleted (STS-AUTHN-0534, the
//      refusal naming the group), and is once nothing names it; the view's
//      named policies carry their precedence and the groups naming them.
//
// NOT carried, and why: B2 (an unticked box on the console's own form),
// F3–F6 (a kind registered later, in process), G1 (the risk engine's
// step-up table) and H1–H3 (the issuance policy's email rule, a
// `role-issuance` decision asked of the PDP in process) are library
// questions (class (d)); C1, C2 and C6 write the DEFAULT realm's profile,
// which every concurrent job's realm inherits, so they stay in process
// (class (d) for a suite run); a group naming a policy the realm does not
// hold (fail closed, STS-AUTHN-0536) cannot be produced through any door,
// which all refuse it (class (d)); the report source's `authMechanisms`
// rows are G09's `/report-api` family.
//
// OWNED HERE (local: true): this repository's own policies and sign-in.
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
var log = bunyan.createLogger({ name: "sts_authn_policy",
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
const PASSWORD = "AuthnPol-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-9a!";
// A desktop browser's User-Agent with this job's name on the end: risk
// scoring reads a bare job name as an automated client, and product refuses
// a first sign-in from one (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_authn_policy/1.0 (" + STAMP + ")";

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


const APP = "authn-pol-" + STAMP;
const REDIRECT = "https://rp-" + STAMP + ".authn-pol.example/cb";
const GROUP = "authn-pol-g-" + STAMP;
const ALICE = names.usernameFor("apa");
const BOB = names.usernameFor("apb");
// "no-pwd" sorts before "pwd-ok", so a tie goes to the group's.
const NO_PWD = "no-pwd";
const PWD_OK = "pwd-ok";
let REALM = "";

async function view(realm) {
  log.debug("Entering view().");
  const r = await api(realm, "GET", "/policies");
  must(r.status === 200 && r.body && r.body.authn,
       "GET /admin-api/policies: " + r.status + " " + r.raw.slice(0, 300));
  log.debug("Leaving view().");
  return r.body;
}

// Every field of the profile, as the view says it is now.
function fullProfile(v, changes) {
  log.debug("Entering fullProfile().");
  const out = {};
  v.authn.fields.forEach(function (f) {
    out[f.key] = f.value;
  });
  log.debug("Leaving fullProfile().");
  return Object.assign(out, changes || {});
}

async function refusedWith(path, body, code) {
  log.debug("Entering refusedWith(). " + path);
  const before = code ? await codeCount(REALM, code) : 0;
  const r = await api(REALM, "POST", path, body);
  const recorded = code ? await newRowWith(REALM, code, before) : true;
  log.debug("Leaving refusedWith(). " + r.status);
  return { r: r, recorded: recorded };
}

function sentence(r) {
  log.debug("Entering sentence().");
  log.debug("Leaving sentence().");
  return JSON.stringify((r.body && (r.body.errors || r.body.error)) ||
                        r.raw).slice(0, 600);
}

async function passwordSignIn(who) {
  log.debug("Entering passwordSignIn(). " + who);
  const b = browser();
  const p = pkce();
  const start = await b.go("GET", realmBase(REALM) + "/oauth2/authorize?" +
    form({ client_id: APP, response_type: "code", redirect_uri: REDIRECT,
           scope: "openid", state: "s", nonce: "n" + Date.now(),
           code_challenge: p.challenge, code_challenge_method: "S256" }));
  must(sentToSignIn(start), "no sign-in screen: " + start.status + " " +
       start.location);
  const sent = await authnSignin.signInWithJar(realmBase(REALM),
    new URL(start.location, realmBase(REALM) + "/").toString(),
    { action: "login", username: who, password: PASSWORD }, b.jar,
    { headers: { "User-Agent": AGENT } });
  let landed = null;
  if (sent.status === 303 && sent.location) {
    landed = await b.go("GET", new URL(sent.location,
                                       realmBase(REALM) + "/").toString());
  }
  const out = { next: sent.answer.next, errors: sent.answer.errors || [],
    code: !!landed && urls.isAt(landed.location, REDIRECT) &&
          /[?&]code=/.test(landed.location),
    shown: sent.status + " " + sent.answer.next + " " +
           JSON.stringify(sent.answer.errors || []) + " " +
           (landed ? landed.status + " " + landed.location : "") };
  log.debug("Leaving passwordSignIn(). " + out.shown);
  return out;
}

function named(name, mechanisms, precedence) {
  log.debug("Entering named(). " + name);
  log.debug("Leaving named().");
  return api(REALM, "POST", "/policies/save-named-authn-policy", {
    name: name, description: "sts_authn_policy " + STAMP,
    mechanisms: mechanisms,
    secondFactors: ["password", "securityKey", "totp", "recoveryCode"],
    precedence: precedence });
}

async function profileSections() {
  log.debug("Entering profileSections().");
  const root = await view(null);
  const v = await view(REALM);
  const p = v.authn.profile;
  log.info("=== A. the profile in force with nothing stored ===");
  await check("A1. with nothing stored in the realm it follows the default " +
              "realm's profile, or the built-in one", async function () {
    expect(!p.stored, JSON.stringify({ from: p.from, stored: p.stored }));
    expect(p.from === (root.authn.profile.stored ? "default-realm"
                                                 : "built-in"),
           p.from + " (default realm stored: " +
           root.authn.profile.stored + ")");
  });
  if (!root.authn.profile.stored) {
    await check("A2. both email mechanisms are OFF by default (NIST SP " +
                "800-63B-4 section 3.1.3.1), a password is a first factor " +
                "and the second is asked of those who hold one",
                async function () {
      expect(p.emailCodePrimary === false && p.emailCodeSecondFactor ===
             false && p.emailLinkPrimary === false &&
             p.emailLinkSecondFactor === false, JSON.stringify(p));
      expect(p.passwordPrimary === true &&
             p.requireSecondFactor === "if-held", JSON.stringify(p));
      expect(p.hotpSecondFactor === false &&
             p.yubicoOtpSecondFactor === false,
             "HOTP and YubiKey OTP are listed and off by default: " +
             JSON.stringify({ hotp: p.hotpSecondFactor,
                              yubiotp: p.yubicoOtpSecondFactor }));
    });
  }
  const keys = v.authn.fields.map(function (f) {
    return f.key;
  });
  await check("A4. a TOTP and a recovery code have no first-factor row, so " +
              "no save can make either one", async function () {
    expect(keys.indexOf("totpPrimary") < 0 &&
           keys.indexOf("recoveryCodePrimary") < 0, keys.join(","));
    expect(keys.indexOf("totpSecondFactor") >= 0, keys.join(","));
  });
  const rsf = v.authn.fields.filter(function (f) {
    return f.key === "requireSecondFactor";
  })[0];
  await check("A5. there is no \"never\": the values are if-held and always",
              async function () {
    expect(rsf && rsf.values.join(",") === "if-held,always",
           JSON.stringify(rsf && rsf.values));
  });

  log.info("=== B. what a save refuses ===");
  const whole = fullProfile(v);
  const partial = Object.assign({}, whole);
  delete partial.totpSecondFactor;
  let got = await refusedWith("/policies/save-authn-policy", partial);
  await check("B1. a save that leaves a field out is refused BY NAME",
              async function () {
    expect(got.r.status === 400 && /totpSecondFactor|Authenticator app/i
      .test(sentence(got.r)), got.r.status + " " + sentence(got.r));
  });
  got = await refusedWith("/policies/save-authn-policy",
                          fullProfile(v, { requireSecondFactor: "never" }));
  await check("B3. an enum value that is not one of its values is refused",
              async function () {
    expect(got.r.status === 400, got.r.status + " " + sentence(got.r));
  });
  got = await refusedWith("/policies/save-authn-policy",
                          fullProfile(v, { emailCodeTtlS: 900 }));
  await check("B4. an emailed code valid for more than ten minutes is " +
              "refused", async function () {
    expect(got.r.status === 400, got.r.status + " " + sentence(got.r));
  });
  const noFirst = {};
  v.authn.fields.forEach(function (f) {
    if (/Primary$/.test(f.key)) {
      noFirst[f.key] = false;
    }
  });
  got = await refusedWith("/policies/save-authn-policy",
                          fullProfile(v, noFirst), "STS-AUTHN-0243");
  await check("B5. a profile with no first factor is refused " +
              "(STS-AUTHN-0243)", async function () {
    expect(got.r.status === 400 && got.recorded,
           got.r.status + " " + sentence(got.r));
  });
  const noSecond = { requireSecondFactor: "always" };
  v.authn.fields.forEach(function (f) {
    if (/SecondFactor$/.test(f.key) && f.type !== "enum" &&
        f.key !== "rememberedBrowserSkipsSecondFactor") {
      noSecond[f.key] = false;
    }
  });
  got = await refusedWith("/policies/save-authn-policy",
                          fullProfile(v, noSecond));
  await check("B6. a second factor required of everybody with none allowed " +
              "is refused: nobody could finish", async function () {
    expect(got.r.status === 400 && /nobody could finish/i
      .test(sentence(got.r)), got.r.status + " " + sentence(got.r));
  });
  got = await refusedWith("/policies/save-authn-policy",
    Object.assign({}, whole, { profile: "other" }), "STS-AUTHN-0242");
  await check("B7. there is one profile, \"default\" (another refused, " +
              "STS-AUTHN-0242 or the request schema)", async function () {
    expect(got.r.status === 400, got.r.status + " " + sentence(got.r));
  });

  log.info("=== C. the realm's own profile, and reset ===");
  got = await refusedWith("/policies/save-authn-policy",
    fullProfile(v, { totpSecondFactor: false,
                     description: "sts_authn_policy " + STAMP }));
  const own = await view(REALM);
  await check("C4. the realm's own save is in force there, from: realm, " +
              "stored", async function () {
    expect(got.r.status === 200, got.r.status + " " + sentence(got.r));
    expect(own.authn.profile.from === "realm" && own.authn.profile.stored &&
           own.authn.profile.totpSecondFactor === false,
           JSON.stringify(own.authn.profile).slice(0, 300));
  });
  await check("E2. the authenticator app's switch is the policy's row: the " +
              "view's totpSecondFactor field reads false", async function () {
    const f = own.authn.fields.filter(function (one) {
      return one.key === "totpSecondFactor";
    })[0];
    expect(f && f.value === false && f.source !== "built-in",
           JSON.stringify(f));
  });
  const otherView = await view(null);
  await check("C4. and nowhere else: the default realm's profile did not " +
              "change", async function () {
    expect(otherView.authn.profile.from === root.authn.profile.from &&
           otherView.authn.profile.totpSecondFactor ===
           root.authn.profile.totpSecondFactor,
           JSON.stringify(otherView.authn.profile).slice(0, 300));
  });
  got = await refusedWith("/policies/reset-authn-policy", {});
  const back = await view(REALM);
  await check("C5. reset removes the realm's entry and it INHERITS again",
              async function () {
    expect(got.r.status === 200, got.r.status + " " + sentence(got.r));
    expect(!back.authn.profile.stored &&
           back.authn.profile.from === p.from,
           JSON.stringify(back.authn.profile).slice(0, 300));
  });

  log.info("=== D. the mail guard ===");
  got = await refusedWith("/policies/save-authn-policy",
    fullProfile(back, { emailCodePrimary: true }), "STS-AUTHN-0244");
  await check("D1. an email row cannot be SAVED on in a realm that cannot " +
              "send mail (STS-AUTHN-0244)", async function () {
    expect(got.r.status === 400 && got.recorded &&
           /cannot send mail/i.test(sentence(got.r)),
           got.r.status + " " + sentence(got.r));
  });

  log.info("=== E3, F. the retired settings and the kinds ===");
  const cfg = await api(REALM, "GET", "/config");
  await check("E3. totp.enabled, backupCodes.enabled and authn.mfaRequired " +
              "are gone from the configuration", async function () {
    expect(cfg.status === 200, cfg.status);
    ["totp.enabled", "backupCodes.enabled", "authn.mfaRequired"]
      .forEach(function (key) {
        expect(cfg.raw.indexOf("\"" + key + "\"") < 0, key + " is listed");
      });
  });
  await check("F1, F2. the page holds every policy kind, and its actions are " +
              "the kinds' actions", async function () {
    const ids = v.kinds.map(function (k) {
      return k.id;
    });
    ["password", "authn", "serviceAccount", "passkey"].forEach(function (k) {
      expect(ids.indexOf(k) >= 0, ids.join(","));
    });
    const union = [];
    v.kinds.forEach(function (k) {
      (k.actions || []).forEach(function (a) {
        union.push(a);
      });
    });
    expect(union.join(",") === v.actions.join(","),
           union.join(",") + " / " + v.actions.join(","));
  });
  log.debug("Leaving profileSections().");
}

async function groupSections() {
  log.debug("Entering groupSections().");
  log.info("=== G. a group names its policy ===");
  await createPerson(REALM, ALICE);
  await createPerson(REALM, BOB);
  await apiOk(REALM, "/applications/create", { identifier: APP, name: APP,
    kind: "oauth2-client", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [APP], oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code"],
              oauthResponseType: ["code"], oauthAllowedScope: ["openid"],
              oauthTokenEndpointAuthMethod: "none" } }, "the client");
  await apiOk(REALM, "/consent/grant-global-consent",
              { client: APP, scope: "openid" }, "consented openid");
  await apiOk(REALM, "/groups/create", { group: GROUP, members: [ALICE] },
              "the group");
  let r = await named(PWD_OK, ["password", "webauthn"], 100);
  must(r.status === 200, "the named policy " + PWD_OK + ": " + r.status +
       " " + r.raw.slice(0, 300));
  r = await named(NO_PWD, ["webauthn"], 10);
  must(r.status === 200, "the named policy " + NO_PWD + ": " + r.status +
       " " + r.raw.slice(0, 300));
  await apiOk(REALM, "/applications/set", { application: APP,
    attribute: "appAuthnPolicy", value: PWD_OK }, "the app names pwd-ok");

  const listedGroups = await api(REALM, "GET", "/groups");
  const groupDn = "cn=" + GROUP + "," + String((listedGroups.body &&
    listedGroups.body.groupsDn) || "");
  const g = await api(REALM, "GET", "/groups?group=" +
                      encodeURIComponent(groupDn));
  await check("G-A1. the group lists stsAuthnPolicy among its policy " +
              "references, offering default and the realm's named policies",
              async function () {
    const text = JSON.stringify(g.body || {});
    expect(g.status === 200 && text.indexOf("stsAuthnPolicy") >= 0 &&
           text.indexOf(NO_PWD) >= 0, g.status + " " + text.slice(0, 500));
  });
  let got = await refusedWith("/groups/set-policy", { group: GROUP,
    attribute: "stsAuthnPolicy", policy: "nobody-" + STAMP },
  "STS-LDAP-0195");
  await check("G-A2. a name the realm does not hold is refused " +
              "(STS-LDAP-0195)", async function () {
    expect(got.r.status === 400 && got.recorded,
           got.r.status + " " + sentence(got.r));
  });
  // As strings: the request schema refuses a NUMBER out of range first
  // (STS-API-0009), and the policy's own refusal is the one held here.
  for (const bad of ["0", "1001"]) {
    got = await refusedWith("/policies/save-named-authn-policy",
      { name: "bad-prec", mechanisms: ["password"], precedence: bad },
      "STS-AUTHN-0541");
    await check("G-B6. a precedence of " + bad + " (outside 1 to 1000) is " +
                "refused (STS-AUTHN-0541)", async function () {
      expect(got.r.status === 400 && got.recorded,
             got.r.status + " " + sentence(got.r));
    });
  }
  await apiOk(REALM, "/groups/set-policy", { group: GROUP,
    attribute: "stsAuthnPolicy", policy: NO_PWD }, "the group names no-pwd");

  let a = await passwordSignIn(ALICE);
  await check("G-B2. a member of the group, whose policy (precedence 10) " +
              "beats the application's (100), is refused a password " +
              "sign-in", async function () {
    expect(!a.code && a.next === "refused", a.shown);
  });
  const bo = await passwordSignIn(BOB);
  await check("G-B3. somebody outside the group signs in with the " +
              "password the application's policy allows", async function () {
    expect(bo.code, bo.shown);
  });
  r = await named(NO_PWD, ["webauthn"], 500);
  must(r.status === 200, "raising the precedence: " + r.raw.slice(0, 300));
  a = await passwordSignIn(ALICE);
  await check("G-B4. once the group's precedence is raised above the " +
              "application's, the member signs in with the password",
              async function () {
    expect(a.code, a.shown);
  });
  r = await named(NO_PWD, ["webauthn"], 100);
  must(r.status === 200, "an equal precedence: " + r.raw.slice(0, 300));
  a = await passwordSignIn(ALICE);
  await check("G-B5. an equal precedence goes by name: no-pwd before " +
              "pwd-ok, so the member is refused again", async function () {
    expect(!a.code && a.next === "refused", a.shown);
  });

  log.info("=== H. the delete, and the view ===");
  const v = await view(REALM);
  const listed = (v.authn.named || []).filter(function (one) {
    return one.name === NO_PWD;
  })[0];
  await check("H-F. the view's named policies carry their precedence and " +
              "the groups naming them", async function () {
    const text = JSON.stringify(listed || {});
    expect(listed && Number(listed.precedence) === 100 &&
           text.indexOf(GROUP) >= 0, JSON.stringify(v.authn.named)
      .slice(0, 600));
  });
  got = await refusedWith("/policies/delete-named-authn-policy",
                          { name: NO_PWD }, "STS-AUTHN-0534");
  await check("H-E1. a named policy a group names is not deleted " +
              "(STS-AUTHN-0534), and the refusal names the group",
              async function () {
    expect(got.r.status === 400 && got.recorded &&
           sentence(got.r).indexOf(GROUP) >= 0,
           got.r.status + " " + sentence(got.r));
  });
  await apiOk(REALM, "/groups/set-policy", { group: GROUP,
    attribute: "stsAuthnPolicy", policy: "" }, "the group names nothing");
  got = await refusedWith("/policies/delete-named-authn-policy",
                          { name: NO_PWD });
  const after = await view(REALM);
  await check("H-E2. once nothing names it, it is deleted", async function () {
    expect(got.r.status === 200, got.r.status + " " + sentence(got.r));
    expect(!(after.authn.named || []).some(function (one) {
      return one.name === NO_PWD;
    }), JSON.stringify(after.authn.named).slice(0, 300));
  });
  log.debug("Leaving groupSections().");
}

async function test() {
  log.debug("Entering test().");
  REALM = await makeRealm("apol", "product");
  await profileSections();
  // DEVELOPMENT for the sign-ins: a product realm asks every person for a
  // second factor (they would stop at `mfa`, before the mechanism rule is
  // the question), and the mechanism rule is the same in both modes.
  REALM = await makeRealm("apolg", "development");
  await groupSections();
  log.debug("Leaving test().");
}

main();
