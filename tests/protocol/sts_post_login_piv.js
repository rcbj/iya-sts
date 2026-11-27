// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: sts_post_login_piv.js
//
// ===========================================================================
// THE POST-LOGIN PIV RE-ISSUE, OVER HTTP (#2009 P3).
//
// In a throwaway realm whose EST family may issue `piv-auth`, for a person
// holding a 9a certificate enrolled through POST
// /admin-api/hardware-tokens/enrol-piv (a request made here with openssl;
// no card in the suite, and no attestation, which the realm does not
// require):
//
//   0. The policy's PIV block is on the saved profile, off; a save naming
//      none of it is accepted, and the sign-in goes straight on.
//   1. On, with `pivTrigger` expiring and `pivRenewDays` 365 (so the fresh
//      certificate is due), the sign-in is held at /authn/post-login, and
//      its view names the activity, the 9a slot and its certificate.
//   2. A slot the step does not ask for is refused (STS-AUTHN-0620), the
//      mail act at this step (STS-AUTHN-0602), and Continue before the
//      enrolment (STS-AUTHN-0622), each 400 with no code in the answer.
//   3. A new request for 9a is enrolled: the view shows the new
//      certificate and the `ykman piv certificates import` command, and
//      Continue starts the held session: the code reaches the client.
//   4. With `pivRenewDays` back at 30 the next sign-in is not asked.
//
// D5 (the old certificate revoked at the new one's first use) needs a
// sign-in WITH the new certificate's key over TLS, which this job does not
// make; it is `tests/post_login_piv.js`'s, in process, as is the
// classical-issuer trigger, which needs a post-quantum EST Issuing CA.
//
// OWNED HERE (local: true): this repository's own /authn and /admin-api.
// ===========================================================================

const urls = require("./url_match.js");
const authnSignin = require("./authn_signin");
const ownPassword = require("./own_password");
const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
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
var log = bunyan.createLogger({ name: "sts_post_login_piv",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("plp2009-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const DOMAIN = REALM + ".example.net";
const CLIENT = "plp2009-rp-" + STAMP.toLowerCase();
const SECRET = "plp-2009-" + String(Date.now()).slice(-8);
const REDIRECT = "https://rp.plp2009.example.test/cb";
const PASSWORD = "Plp-2009-Passw0rd!-" + String(Date.now()).slice(-6);
const BOB = names.usernameFor("plp-bob");
const MAIL = BOB + "@" + DOMAIN;
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_post_login_piv/1.0 (" + STAMP + ")";
const PASSKEY_BLOCK = { enabled: false, activity: "pqc-passkey-migration",
  snoozeDays: 7, graceDays: 0, noPasskey: "leave", method: "automatic",
  attestation: "any", noPasskeyFallback: "none" };

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
    // Not JSON: the caller reads `raw`.
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

// Two S/MIME certificates for the address, made by openssl under a CA of
// this run: an RSA one and an ML-KEM-768 one (RFC 9935).
// A certificate request over a fresh P-256 key, as `ykman piv certificates
// request` hands one over: the key stays here (no card in the suite).
function request() {
  log.debug("Entering request().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plp2009-"));
  try {
    childProcess.execFileSync("openssl", ["req", "-new", "-newkey", "ec",
      "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "k.pem",
      "-out", "r.csr", "-subj", "/CN=" + BOB], { cwd: dir,
      stdio: ["ignore", "pipe", "pipe"] });
    const out = fs.readFileSync(path.join(dir, "r.csr"), "utf8");
    log.debug("Leaving request().");
    return out;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
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
    async go(p) {
      log.debug("Entering go(). " + p);
      const headers = { "User-Agent": AGENT };
      const cookie = self.cookie();
      if (cookie) {
        headers.cookie = cookie;
      }
      const r = await fetch(absolute(p), { redirect: "manual",
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

async function signIn(b) {
  log.debug("Entering signIn().");
  const r = await b.go(R + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid", state: "st", nonce: "n-" + STAMP,
    code_challenge: nodeCrypto.createHash("sha256").update("v".repeat(43))
      .digest("base64url"), code_challenge_method: "S256" }).toString());
  assert.ok(/\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location),
            "the authorization request goes to the sign-in screen: " +
            r.status + " " + r.location);
  const answer = await authnSignin.submit(base + R, absolute(r.location),
    { action: "login", username: BOB, password: PASSWORD },
    { cookie: b.cookie(), headers: { "User-Agent": AGENT } });
  b.keep(answer.headers.getSetCookie());
  log.debug("Leaving signIn(). " + answer.next);
  return answer;
}

async function codeAfter(b, location) {
  log.debug("Entering codeAfter().");
  let r = await b.go(location);
  for (let hops = 0; hops < 5 && r.location &&
       !urls.isAt(r.location, REDIRECT); hops += 1) {
    r = await b.go(r.location);
  }
  const code = urls.isAt(r.location, REDIRECT)
    ? new URL(r.location).searchParams.get("code") : "";
  log.debug("Leaving codeAfter(). " + (code ? "A code." : "None."));
  return code || "";
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "Post-login PIV 2009 " + STAMP }, "created the realm");
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
  await ok(realmApi + "/users/create", { username: BOB, invent: false,
    credential: "password", password: ownPassword.temporaryFor(PASSWORD),
    attributes: { cn: "PIV " + BOB, givenName: "PIV", sn: "Bob",
                  mail: MAIL } },
    "created " + BOB);
  // THE PASSWORD IS THE PERSON'S OWN (#2160): a typed one is temporary in
  // product, so they choose PASSWORD at the sign-in screen
  // (`own_password.js`; in development it is simply set).
  await ownPassword.ownPassword(base + R, BOB, PASSWORD, function (who, value) {
    return send(realmApi + "/users/set-password", { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user: who, password: value }) });
  });
  await ok(realmApi + "/config/set", { key: "est.allowedProfiles",
    value: "tls-client,piv-auth" }, "let EST issue piv-auth");
  const first = await ok(realmApi + "/hardware-tokens/enrol-piv", {
    username: BOB, profile: "piv-auth", csr: request() },
    "enrolled a piv-auth certificate");
  const oldSerial = String(first.serialHex || "");
  const saved = await ok(realmApi + "/policies/save-postLogin-policy",
    Object.assign({ profile: "default" }, PASSKEY_BLOCK),
    "saved a profile naming no PIV field");
  check("the PIV block is on the profile, off, with its defaults",
    function () {
      const p = saved.profile || {};
      assert.ok(p.pivEnabled === false && p.pivSlots === "9a,9c,9d,9e" &&
                p.pivTrigger === "both" && p.pivRenewDays === 30 &&
                oldSerial, JSON.stringify(p) + " " + JSON.stringify(first));
    });
  let b = browser();
  let answer = await signIn(b);
  check("off, the sign-in goes straight on", function () {
    assert.strictEqual(answer.next, "redirect", JSON.stringify(answer.json));
  });

  log.info("=== 1. on: the sign-in is held for the PIV re-issue ===");
  await ok(realmApi + "/policies/save-postLogin-policy",
    Object.assign({ profile: "default", pivEnabled: true,
                    pivTrigger: "expiring", pivRenewDays: 365 },
                  PASSKEY_BLOCK),
    "switched the PIV block on");
  b = browser();
  answer = await signIn(b);
  check("the sign-in is held at /authn/post-login", function () {
    assert.strictEqual(answer.next, "mfa", JSON.stringify(answer.json));
    assert.ok(/\/authn\/post-login/.test(answer.location), answer.location);
  });
  let opened = await authnSignin.step(absolute(answer.location),
    { cookie: b.cookie(), headers: { "User-Agent": AGENT } });
  check("its view names the activity, the 9a slot and its certificate",
    function () {
      const v = (opened.view || {}).postLogin || {};
      const slots = (v.piv || {}).slots || [];
      assert.ok(v.activity === "piv-reissue" && v.reason === "expiring" &&
                slots.length === 1 && slots[0].slot === "9a" &&
                slots[0].serialHex === oldSerial &&
                (v.piv.issued || []).length === 0,
                JSON.stringify(opened.view));
    });

  log.info("=== 2. the step's refusals ===");
  const refusedOf = async function (op, payload, what) {
    const r = await authnSignin.stepAct(opened, op, payload,
      { headers: { "User-Agent": AGENT } });
    check(what + " (400), with no code in the answer", function () {
      assert.strictEqual(r.status, 400, JSON.stringify(r.json));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(JSON.stringify(r.json)),
                JSON.stringify(r.json));
    });
  };
  await refusedOf("post-login/piv", { act: "piv-enrol", slot: "9d",
    csr: request() }, "a slot the step does not ask for is refused");
  await refusedOf("post-login/mail", { act: "smime-register",
    certificate: "x" }, "the mail act at this step is refused");
  await refusedOf("post-login/piv", { act: "piv-continue" },
    "Continue before the enrolment is refused");

  log.info("=== 3. a new 9a certificate, then Continue ===");
  const enrolled = await authnSignin.stepAct(opened, "post-login/piv",
    { act: "piv-enrol", slot: "9a", csr: request() },
    { headers: { "User-Agent": AGENT } });
  opened = await authnSignin.step(absolute(answer.location),
    { cookie: b.cookie(), headers: { "User-Agent": AGENT } });
  check("the new certificate and the import command are on the step",
    function () {
      assert.strictEqual(enrolled.next, "mfa", JSON.stringify(enrolled.json));
      const issued = (((opened.view || {}).postLogin || {}).piv || {})
        .issued || [];
      assert.ok(issued.length === 1 && issued[0].slot === "9a" &&
                issued[0].serialHex && issued[0].serialHex !== oldSerial &&
                /BEGIN CERTIFICATE/.test(issued[0].certificatePem) &&
                /ykman piv certificates import 9a/.test(issued[0].command),
                JSON.stringify(opened.view));
    });
  const done = await authnSignin.stepAct(opened, "post-login/piv",
    { act: "piv-continue" }, { headers: { "User-Agent": AGENT } });
  b.keep(done.headers.getSetCookie());
  check("Continue starts the held session", function () {
    assert.strictEqual(done.next, "redirect", JSON.stringify(done.json));
  });
  const code = await codeAfter(b, done.location);
  check("the code reaches the client", function () {
    assert.ok(code, "no code at " + REDIRECT);
  });

  log.info("=== 4. not due, not asked ===");
  await ok(realmApi + "/policies/save-postLogin-policy",
    Object.assign({ profile: "default", pivRenewDays: 30 }, PASSKEY_BLOCK),
    "renewal back to 30 days");
  b = browser();
  answer = await signIn(b);
  check("the next sign-in is not asked", function () {
    assert.strictEqual(answer.next, "redirect", JSON.stringify(answer.json));
  });
  await ok(realmApi + "/policies/reset-postLogin-policy",
           { profile: "default" }, "put the default back");
  log.info("sts_post_login_piv: " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_post_login_piv FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
