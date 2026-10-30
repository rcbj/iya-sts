// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: sts_post_login_activity.js
//
// ===========================================================================
// POST-LOGIN ACTIVITIES, OVER HTTP (#1096).
//
// In a throwaway realm it leaves behind, in every mode:
//
//   0. The post-login activity policy is a kind on GET /admin-api/policies,
//      and off by default: a password sign-in goes straight to the client.
//   1. On, with `noPasskey: invite`: a person holding no passkey is held at
//      /authn/post-login — no session — with Register and Skip offered.
//   2. Skip starts the held session: the code reaches the client.
//   3. While it is put off, the next sign-in is not asked.
//   4. A named profile a group names (#1239) is read back with the group,
//      is not deleted while named, and is reset once the group lets go.
//
// The ML-DSA registration, the required case and the doors that cannot ask
// are `tests/post_login.js`'s, in process, with a software authenticator.
//
// OWNED HERE (local: true): this repository's own /authn and /admin-api.
// ===========================================================================

// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_post_login_activity",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("pla1096-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const CLIENT = "pla1096-rp-" + STAMP.toLowerCase();
const SECRET = "pla-1096-" + String(Date.now()).slice(-8);
const REDIRECT = "https://rp.pla1096.example.test/cb";
const PASSWORD = "Pla-1096-Passw0rd!-" + String(Date.now()).slice(-6);
const BOB = names.usernameFor("pla-bob");
const GROUP = "pla-group-" + STAMP.toLowerCase();
// A desktop Chrome string with this job's name on the end: product mode
// refuses a first sign-in from a client isbot reads as automated (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_post_login_activity/1.0 (" + STAMP + ")";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "" };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// A browser: a cookie jar, and GET with it.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    cookie: function () {
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    keep: function (setCookies) {
      (setCookies || []).forEach(function (one) {
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
    },
    async go(path) {
      log.debug("Entering go(). " + path);
      const headers = { "User-Agent": AGENT };
      const cookie = self.cookie();
      if (cookie) {
        headers.cookie = cookie;
      }
      const r = await fetch(absolute(path), { redirect: "manual",
                                              headers: headers });
      self.keep(r.headers.getSetCookie ? r.headers.getSetCookie() : []);
      await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "" };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

// An authorization request, and the sign-in screen's answer to Bob's
// password: `redirect`, or `mfa` with the step's location.
async function signIn(b) {
  log.debug("Entering signIn().");
  const r = await b.go(R + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid", state: "st", nonce: "n-" + STAMP,
    code_challenge: nodeCrypto.createHash("sha256").update("v".repeat(43))
      .digest("base64url"), code_challenge_method: "S256" }).toString());
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
            "the authorization request goes to the sign-in screen: " +
            r.status + " " + r.location);
  const answer = await authnSignin.submit(base + R, absolute(r.location),
    { action: "login", username: BOB, password: PASSWORD },
    { cookie: b.cookie(), headers: { "User-Agent": AGENT } });
  b.keep(answer.headers.getSetCookie());
  log.debug("Leaving signIn(). " + answer.next);
  return answer;
}

// Follows an answer's redirect through the authorization endpoint to the
// client's redirect URI, and answers the code there.
async function codeAfter(b, location) {
  log.debug("Entering codeAfter().");
  let r = await b.go(location);
  for (let hops = 0; hops < 5 && r.location &&
       r.location.indexOf(REDIRECT) !== 0; hops += 1) {
    r = await b.go(r.location);
  }
  const code = r.location.indexOf(REDIRECT) === 0
    ? new URL(r.location).searchParams.get("code") : "";
  log.debug("Leaving codeAfter(). " + (code ? "A code." : "None."));
  return code || "";
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + ", off by default ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Post-login 1096 " + STAMP },
    "created the realm");
  await ok(realmApi + "/applications/create", { identifier: CLIENT,
    kind: "oauth2-client", name: CLIENT, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["openid"],
              oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code"],
              oauthResponseType: ["code"] } },
    "created the client");
  await ok(realmApi + "/consent/grant-global-consent",
           { client: CLIENT, scope: "openid" }, "consented openid");
  await ok(realmApi + "/policies/save-attributes-policy",
    { profile: "default", requiredAttributes: ["givenName"] },
    "this realm's attribute policy requires no address");
  await ok(realmApi + "/users/create", { username: BOB, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Post " + BOB, givenName: "Post", sn: "Login" } },
    "created " + BOB);
  const read = await send(realmApi + "/policies");
  check("the post-login activity policy is a kind, off by default",
    function () {
      assert.strictEqual(read.status, 200, read.raw.slice(0, 300));
      const kind = read.body.postLogin;
      assert.ok(kind, Object.keys(read.body).join(","));
      const json = JSON.stringify(kind);
      assert.ok(/"enabled":false/.test(json), json.slice(0, 600));
    });
  let b = browser();
  let answer = await signIn(b);
  check("off, the sign-in goes straight on", function () {
    assert.strictEqual(answer.next, "redirect", JSON.stringify(answer.json));
  });

  log.info("=== 1. on: a person with no passkey is held ===");
  await ok(realmApi + "/policies/save-postLogin-policy", {
    profile: "default", enabled: true, activity: "pqc-passkey-migration",
    snoozeDays: 2, graceDays: 0, noPasskey: "invite",
    method: "automatic", attestation: "any",
    noPasskeyFallback: "none" },
    "switched the policy on");
  b = browser();
  answer = await signIn(b);
  check("the sign-in is held at /authn/post-login",
    function () {
      assert.strictEqual(answer.next, "mfa", JSON.stringify(answer.json));
      assert.ok(/\/authn\/post-login\?mfa=/.test(answer.location),
                answer.location);
    });
  const opened = await authnSignin.step(absolute(answer.location),
    { cookie: b.cookie(), headers: { "User-Agent": AGENT } });
  check("its view offers Register and Skip, for a passkey that carries no " +
        "role (#1135)",
    function () {
      const v = (opened.view || {}).postLogin || {};
      assert.strictEqual(opened.status, 200, opened.text.slice(0, 300));
      assert.ok(v.role === undefined && v.reason === "none" &&
                v.canSkip === true && v.snoozeDays === 2,
                JSON.stringify(opened.view));
    });

  // NO SESSION WHILE IT IS HELD: the browser's cookie is the arrival one
  // the surface mints (so not evidence either way), and a new authorization
  // request from the same browser still goes to the sign-in screen.
  const probe = await b.go(R + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid", state: "probe", nonce: "p-" + STAMP,
    code_challenge: nodeCrypto.createHash("sha256").update("v".repeat(43))
      .digest("base64url"), code_challenge_method: "S256" }).toString());
  check("while it is held there is no session: the application is sent " +
        "to the sign-in screen again", function () {
    assert.ok(/\/authn\/login\?authn=/.test(probe.location),
              probe.status + " " + probe.location);
  });

  log.info("=== 2. Skip starts the held session ===");
  const skipped = await authnSignin.stepAct(opened, "post-login/skip", {},
    { headers: { "User-Agent": AGENT } });
  b.keep(skipped.headers.getSetCookie());
  check("Skip answers a redirect", function () {
    assert.strictEqual(skipped.next, "redirect",
                       JSON.stringify(skipped.json));
  });
  const code = await codeAfter(b, skipped.location);
  check("and the code reaches the client", function () {
    assert.ok(code, "no code at " + REDIRECT);
  });

  log.info("=== 3. put off: the next sign-in is not asked ===");
  b = browser();
  answer = await signIn(b);
  check("the next sign-in goes straight on", function () {
    assert.strictEqual(answer.next, "redirect", JSON.stringify(answer.json));
  });

  log.info("=== 4. a named profile a group names (#1239) ===");
  await ok(realmApi + "/groups/create", { group: GROUP },
           "created the group");
  await ok(realmApi + "/policies/save-postLogin-policy", {
    profile: "pilot", precedence: 10,
    enabled: false, activity: "pqc-passkey-migration", snoozeDays: 7,
    graceDays: 30, noPasskey: "require",
    method: "upgrade", attestation: "post-quantum",
    noPasskeyFallback: "classical" },
    "saved a named profile");
  await ok(realmApi + "/groups/set-policy", { group: GROUP,
    attribute: "stsPostLoginPolicy", policy: "pilot" },
    "named it from the group");
  const named = await send(realmApi + "/policies");
  check("the named profile is read back with its precedence, and the group " +
    "naming it", function () {
      const member = named.body.postLogin || {};
      const row = (member.named || []).filter(function (one) {
        return one.name === "pilot";
      })[0] || {};
      assert.ok(row.precedence === 10 &&
                ((row.namedBy || {}).groups || []).indexOf(GROUP) >= 0 &&
                (member.references || {}).group === "stsPostLoginPolicy" &&
                (member.references || {}).application ===
                  "appPostLoginPolicy",
                JSON.stringify(member).slice(0, 800));
    });
  const refused = await send(realmApi + "/policies/reset-postLogin-policy", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ profile: "pilot" }) });
  check("a profile a group names is not deleted (STS-AUTHN-0540)",
    function () {
      assert.ok(refused.status === 400 ||
                (refused.body && refused.body.ok === false),
                refused.status + " " + String(refused.raw).slice(0, 400));
    });
  await ok(realmApi + "/groups/set-policy", { group: GROUP,
    attribute: "stsPostLoginPolicy", policy: "" },
    "cleared the group's reference");
  await ok(realmApi + "/policies/reset-postLogin-policy",
           { profile: "pilot" }, "removed the named profile");
  await ok(realmApi + "/policies/reset-postLogin-policy",
           { profile: "default" }, "put the default back");
  log.info("sts_post_login_activity: " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_post_login_activity FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
