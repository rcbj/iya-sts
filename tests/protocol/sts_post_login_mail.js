// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: sts_post_login_mail.js
//
// ===========================================================================
// THE POST-LOGIN MAIL-ENCRYPTION ACTIVITY, OVER HTTP (#2009 P2).
//
// In a throwaway realm, for a person whose mail is S/MIME to an RSA
// certificate (made here with openssl, as is the ML-KEM one):
//
//   0. The policy's mail block is on GET /admin-api/policies, off; a save
//      naming none of it is accepted.
//   1. On (`mailEnabled`), the sign-in is held at /authn/post-login, and its
//      view names the activity, the classical certificate and what it
//      offers.
//   2. The passkey `register` act at this step is refused (STS-AUTHN-0602);
//      an RSA certificate is refused (STS-AUTHN-0600); an OpenPGP challenge
//      is issued and drawn on the step.
//   3. An uploaded ML-KEM certificate finishes it: the code reaches the
//      client, mail is S/MIME to the ML-KEM certificate, and the next
//      sign-in is not asked.
//
// The OpenPGP registration needs an RFC 9980 key, which no tool in the
// suite can make, and D3's kept key with it; both are
// `tests/post_login_mail.js`'s, in process.
//
// OWNED HERE (local: true): this repository's own /authn and /admin-api.
// ===========================================================================

const urls = require("./url_match.js");
const authnSignin = require("./authn_signin");
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
var log = bunyan.createLogger({ name: "sts_post_login_mail",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("plm2009-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const R = "/realm/" + REALM;
const realmApi = base + R + "/admin-api";
const DOMAIN = REALM + ".example.net";
const CLIENT = "plm2009-rp-" + STAMP.toLowerCase();
const SECRET = "plm-2009-" + String(Date.now()).slice(-8);
const REDIRECT = "https://rp.plm2009.example.test/cb";
const PASSWORD = "Plm-2009-Passw0rd!-" + String(Date.now()).slice(-6);
const BOB = names.usernameFor("plm-bob");
const MAIL = BOB + "@" + DOMAIN;
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_post_login_mail/1.0 (" + STAMP + ")";
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
function certificates() {
  log.debug("Entering certificates().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plm2009-"));
  const sh = function (args) {
    return childProcess.execFileSync("openssl", args, { cwd: dir,
      stdio: ["ignore", "pipe", "pipe"] }).toString();
  };
  try {
    fs.writeFileSync(path.join(dir, "ext"), "subjectAltName=email:" + MAIL +
      "\nkeyUsage=critical,keyEncipherment\n" +
      "extendedKeyUsage=emailProtection\n");
    sh(["req", "-x509", "-newkey", "ec", "-pkeyopt",
        "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key",
        "-out", "ca.pem", "-subj", "/CN=plm2009 test CA", "-days", "2"]);
    sh(["req", "-newkey", "rsa:3072", "-nodes", "-keyout", "rsa.key",
        "-out", "rsa.csr", "-subj", "/CN=" + BOB]);
    sh(["x509", "-req", "-in", "rsa.csr", "-CA", "ca.pem", "-CAkey",
        "ca.key", "-days", "2", "-extfile", "ext", "-out", "rsa.pem"]);
    sh(["genpkey", "-algorithm", "ML-KEM-768", "-out", "kem.key"]);
    sh(["pkey", "-in", "kem.key", "-pubout", "-out", "kem.pub"]);
    sh(["x509", "-new", "-force_pubkey", "kem.pub", "-subj", "/CN=" + BOB,
        "-CA", "ca.pem", "-CAkey", "ca.key", "-days", "2", "-extfile",
        "ext", "-out", "kem.pem"]);
    const out = { rsa: fs.readFileSync(path.join(dir, "rsa.pem"), "utf8"),
                  kem: fs.readFileSync(path.join(dir, "kem.pem"), "utf8") };
    log.debug("Leaving certificates().");
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
  const certs = certificates();
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "Post-login mail 2009 " + STAMP }, "created the realm");
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
    credential: "password", password: PASSWORD,
    attributes: { cn: "Mail " + BOB, givenName: "Mail", sn: "Bob",
                  mail: MAIL } },
    "created " + BOB);
  await ok(realmApi + "/openpgp/smime", { user: BOB, certificate: certs.rsa },
           "set an RSA S/MIME certificate");
  await ok(realmApi + "/openpgp/mail-encryption",
           { user: BOB, choice: "smime" }, "chose S/MIME");
  const saved = await ok(realmApi + "/policies/save-postLogin-policy",
    Object.assign({ profile: "default" }, PASSKEY_BLOCK),
    "saved a profile naming no mail field");
  check("the mail block is on the profile, off, with its defaults",
    function () {
      const p = saved.profile || {};
      assert.ok(p.mailEnabled === false && p.mailKeepClassical === 90 &&
                p.mailPrefer === "either", JSON.stringify(p));
    });
  let b = browser();
  let answer = await signIn(b);
  check("off, the sign-in goes straight on", function () {
    assert.strictEqual(answer.next, "redirect", JSON.stringify(answer.json));
  });

  log.info("=== 1. on: the sign-in is held for the mail encryption ===");
  await ok(realmApi + "/policies/save-postLogin-policy",
    Object.assign({ profile: "default", mailEnabled: true,
                    mailSnoozeDays: 2 }, PASSKEY_BLOCK),
    "switched the mail block on");
  b = browser();
  answer = await signIn(b);
  check("the sign-in is held at /authn/post-login", function () {
    assert.strictEqual(answer.next, "mfa", JSON.stringify(answer.json));
    assert.ok(/\/authn\/post-login/.test(answer.location), answer.location);
  });
  let opened = await authnSignin.step(absolute(answer.location),
    { cookie: b.cookie(), headers: { "User-Agent": AGENT } });
  check("its view names the activity, the classical certificate and what " +
        "it offers, S/MIME first", function () {
    const v = (opened.view || {}).postLogin || {};
    const m = v.mail || {};
    assert.ok(v.activity === "pqc-mail-encryption" &&
              v.reason === "smime-classical" && v.canSkip === true &&
              (m.offers || [])[0] === "smime" &&
              (m.current || {}).kind === "smime" && m.challenge === null,
              JSON.stringify(opened.view));
  });

  log.info("=== 2. the step's refusals, and the challenge ===");
  const passkey = await authnSignin.stepAct(opened, "post-login/register",
    {}, { headers: { "User-Agent": AGENT } });
  check("the passkey register act is refused at this step (400)",
    function () {
      assert.strictEqual(passkey.status, 400, JSON.stringify(passkey.json));
    });
  const rsa = await authnSignin.stepAct(opened, "post-login/mail",
    { act: "smime-register", certificate: certs.rsa },
    { headers: { "User-Agent": AGENT } });
  check("an RSA certificate is refused (400), with no code in the answer",
    function () {
      assert.strictEqual(rsa.status, 400, JSON.stringify(rsa.json));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(JSON.stringify(rsa.json)),
                JSON.stringify(rsa.json));
    });
  const offers = ((opened.view.postLogin || {}).mail || {}).offers || [];
  if (offers.indexOf("openpgp") >= 0) {
    const asked = await authnSignin.stepAct(opened, "post-login/mail",
      { act: "openpgp-challenge" }, { headers: { "User-Agent": AGENT } });
    opened = await authnSignin.step(absolute(answer.location),
      { cookie: b.cookie(), headers: { "User-Agent": AGENT } });
    check("an OpenPGP challenge is issued and drawn on the step", function () {
      const c = ((opened.view.postLogin || {}).mail || {}).challenge || {};
      assert.strictEqual(asked.next, "mfa", JSON.stringify(asked.json));
      assert.ok(/Account: /.test(String(c.text || "")) &&
                String(c.text).indexOf(BOB) >= 0, JSON.stringify(c));
    });
  }

  log.info("=== 3. an ML-KEM certificate finishes it ===");
  const done = await authnSignin.stepAct(opened, "post-login/mail",
    { act: "smime-register", certificate: certs.kem },
    { headers: { "User-Agent": AGENT } });
  b.keep(done.headers.getSetCookie());
  check("the ML-KEM certificate is taken and the held session starts",
    function () {
      assert.strictEqual(done.next, "redirect", JSON.stringify(done.json));
    });
  const code = await codeAfter(b, done.location);
  check("the code reaches the client", function () {
    assert.ok(code, "no code at " + REDIRECT);
  });
  const view = await send(realmApi + "/openpgp?user=" +
                          encodeURIComponent(BOB));
  check("mail to the person is S/MIME, to a certificate that can receive",
    function () {
      const m = ((view.body || {}).person || {}).mailEncryption || {};
      assert.ok(m.choice === "smime" && m.smimeUsable === true,
                String(view.raw).slice(0, 600));
    });
  b = browser();
  answer = await signIn(b);
  check("the next sign-in is not asked", function () {
    assert.strictEqual(answer.next, "redirect", JSON.stringify(answer.json));
  });
  await ok(realmApi + "/policies/reset-postLogin-policy",
           { profile: "default" }, "put the default back");
  log.info("sts_post_login_mail: " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_post_login_mail FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
