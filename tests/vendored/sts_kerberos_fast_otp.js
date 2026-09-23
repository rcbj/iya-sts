"use strict";
//
// File: sts_kerberos_fast_otp.js
//
// ---------------------------------------------------------------------------
// A PASSWORD ALONE IS NO KERBEROS TICKET FOR A TWO-FACTOR ACCOUNT, AND FAST
// WITH OTP PRE-AUTHENTICATION IS — OVER TCP 88, AGAINST THE SERVICE (#173,
// 2026-09-22).
//
// In product a person's Kerberos keys come from their own password, and until
// #173 an AS-REQ proving that password alone got a ticket-granting ticket — and
// through SPNEGO a browser session — for a person the sign-in screen would have
// asked for an authenticator code. This job is a Kerberos client at the
// service's published address, and asserts, in order:
//
//   0. its own RFC 6238 generator against RFC 6238 Appendix B;
//   1. a HOST principal made through /admin-api (its keytab handed over once,
//      read here) gets a TGT with its key — the armor ticket RFC 6113 section
//      5.4.1.1 asks for; a person P enrols an authenticator app on the portal
//      (the code that confirms it is computed here); a person Q holds nothing;
//   2. P's right password alone over PA-ENC-TIMESTAMP: KDC_ERR_POLICY in
//      product, a TGT in development; P's WRONG password:
//      KDC_ERR_PREAUTH_FAILED
//      in both — the refusal says nothing to somebody without the password; Q's
//      password: a TGT in both;
//   3. the bare AS-REQ advertises PA-FX-FAST; an armored bare AS-REQ is
//      KDC_ERR_PREAUTH_REQUIRED INSIDE the armor, offering PA-OTP-CHALLENGE
//      first, PA-ENCRYPTED-CHALLENGE and a cookie;
//   4. the password alone inside FAST (the encrypted challenge): KDC_ERR_POLICY
//      in product, and a TGT for Q in both, with the KDC's own challenge and a
//      KrbFastFinished that verifies over the ticket;
//   5. OTP inside FAST, the password as the PIN: the code the PORTAL spent is
//      refused at the KDC (one once-only counter for both doors), the next code
//      gets a TGT, and the same code again is refused;
//   6. the TGT carries the RFC 8129 indicator `otp`: a service ticket it buys
//      for the host principal holds it in an AD-CAMMAC whose svc-verifier
//      checks under the host key read from the keytab, and Q's holds none;
//   7. with the SPNEGO door open, that indicator makes `/authn/spnego` a
//      two-factor sign-in: `amr` pwd and otp;
//   8. and, where MIT Kerberos is installed on the machine running the job,
//      the same with REAL `kinit`: `kinit -k` for the host, and
//      `kinit -T <armor ccache>` for P answering the OTP and PIN prompts.
//      Without MIT Kerberos that section says so and is skipped.
//
// THE CLIENT is `krb5_wire.js` beside this file: the vendored codec for RFC
// 4120's encodings, and FAST, OTP, the PRF and KRB-FX-CF2 written out there
// apart from the service's `krb5_fast.ts` (its header says why).
//
// WHAT IT CHANGES: two people, one host principal. Nothing is loosened; no
// setting is read-and-changed. KEY MATERIAL is made at run time — the host's
// keytab comes from the service in the reply that creates it and lives in a
// temporary directory for the MIT section — and nothing is read from disk.
//
// WHERE IT DIALS: the KDC at the service URL's host and `krb5.kdcPort`, or
// STS_KDC_HOST / STS_KDC_PORT (sts_kerberos_spnego.js's convention).
//
// OWNED HERE (local: true): this repository's KDC, portal and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const facts = require("./service_facts.js");
const wire = require("./krb5_wire.js");
const { declineToRun } = require("./expectation.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_fast_otp",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const apiBase = base + "/admin-api";

const P = usernameFor("krb5-otp");
const Q = usernameFor("krb5-plain");
const PASSWORD = "Krb5-Fast-Otp-Passw0rd!-" + String(Date.now()).slice(-6);
const HOST_NAME = "fast-" + String(Date.now()).slice(-8);

const K = { product: false, realm: "", domain: "", kdcHost: "", kdcPort: 88,
            servicePrincipal: "", password: "", spnegoOn: true };

// How long a product person's keys may take to appear after the password is
// set (sts_kerberos_spnego.js argues the number).
const KEYS_WAIT_MS = 20000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// ---------------------------------------------------------------------------
// RFC 6238, written here (sts_portal_totp.js's arrangement: two
// implementations written apart, each checked against the specification).
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
    assert.ok(index >= 0, "not base32: " + cleaned[i]);
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

function codeAtStep(secret, step, opts) {
  log.debug("Entering codeAtStep().");
  const options = opts || {};
  const digits = Number(options.digits || 6);
  const alg = String(options.algorithm || "SHA1").toLowerCase();
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(step));
  const digest = nodeCrypto.createHmac(alg, base32ToBytes(secret))
                           .update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  log.debug("Leaving codeAtStep().");
  return String(binary % Math.pow(10, digits)).padStart(digits, "0");
}

function stepNow() {
  log.debug("Entering stepNow().");
  log.debug("Leaving stepNow().");
  return Math.floor(Date.now() / 30000);
}

// A code for a step AFTER `used`: the next one if it is inside the verifier's
// window already, else waiting for the clock to reach it.
async function codeAfter(secret, used) {
  log.debug("Entering codeAfter(). used=" + used);
  while (stepNow() + 1 <= used) {
    await pause(1000);
  }
  const step = Math.max(used + 1, stepNow());
  log.debug("Leaving codeAfter(). step=" + step);
  return { step: step, code: codeAtStep(secret, step) };
}

function theGeneratorIsRight() {
  log.debug("Entering theGeneratorIsRight().");
  log.info("=== 0. the job's own RFC 6238 generator ===");
  // RFC 6238 Appendix B, SHA-1, the twenty-byte ASCII seed, eight digits.
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  check("RFC 6238 Appendix B: T=59 is 94287082 and T=1111111109 is 07081804",
        function () {
          assert.strictEqual(codeAtStep(secret, 1, { digits: 8 }), "94287082");
          assert.strictEqual(codeAtStep(secret, 37037036, { digits: 8 }),
                             "07081804");
        });
  log.debug("Leaving theGeneratorIsRight().");
}

// ---------------------------------------------------------------------------
// THE ADMIN API, AND A BROWSER FOR THE PORTAL (sts_portal_totp.js's).
// ---------------------------------------------------------------------------
async function apiPost(pathName, body) {
  log.debug("Entering apiPost(). " + pathName);
  const r = await fetch(apiBase + pathName, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body) });
  const raw = await r.text();
  let parsed = null;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiPost(): " + ((e && e.message) || e));
    parsed = raw;
  }
  log.debug("Leaving apiPost(). " + r.status);
  return { status: r.status, body: parsed, raw: raw };
}

async function ensurePerson(who) {
  log.debug("Entering ensurePerson(). " + who);
  const r = await apiPost("/users/create", {
    username: who, invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: "FAST " + who, givenName: "FAST", sn: who,
                  displayName: "FAST " + who, mail: who + "@fast.test" } });
  assert.ok(r.status === 200 && r.body && r.body.ok,
            "POST /admin-api/users/create " + who + ": " + r.status + " " +
            String(r.raw).slice(0, 300));
  log.debug("Leaving ensurePerson().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function browser() {
  log.debug("Entering browser().");
  const self = {
    jar: {},
    cookieHeader: function () {
      log.debug("Entering cookieHeader().");
      log.debug("Leaving cookieHeader().");
      return Object.keys(self.jar).map(function (k) {
        return k + "=" + self.jar[k];
      }).join("; ");
    },
    async go(method, where, body) {
      log.debug("Entering go(). " + method + " " + where);
      const headers = { cookie: self.cookieHeader() };
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const url = /^https?:\/\//i.test(where) ? where : base + where;
      const r = await fetch(url, { method: method, redirect: "manual",
                                   headers: headers, body: body });
      (r.headers.getSetCookie ? r.headers.getSetCookie() : [])
        .forEach(function (one) {
          const pair = String(one).split(";")[0];
          const name = pair.split("=")[0];
          const value = pair.slice(name.length + 1);
          if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(one)) {
            delete self.jar[name];
          } else {
            self.jar[name] = value;
          }
        });
      log.debug("Leaving go(). " + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text() };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

// Sign in to the portal (an OIDC relying party of this service) as `who`.
async function portalSignIn(who) {
  log.debug("Entering portalSignIn(). " + who);
  const b = browser();
  let r = await b.go("GET", "/portal/mfa?realm=default");
  r = await b.go("GET", r.location);
  r = await b.go("GET", r.location);
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id: " +
            String(r.text).slice(0, 300));
  r = await b.go("POST", "/authn/login", form({
    authn_id: authnId, username: who, password: PASSWORD, action: "login",
    csrf_token: csrfOf(r.text) }));
  assert.ok(r.status === 303 || r.status === 302,
            "the password sign-in for " + who + " answered " + r.status +
            ": " + String(r.text).slice(0, 300));
  r = await b.go("GET", r.location);
  r = await b.go("GET", r.location);
  log.debug("Leaving portalSignIn().");
  return b;
}

// Enrol an authenticator app for `who` at /portal/mfa, confirmed with a code
// computed here. Answers the secret and the step the confirmation spent.
async function enrolAuthenticator(who) {
  log.debug("Entering enrolAuthenticator(). " + who);
  const b = await portalSignIn(who);
  let page = await b.go("GET", "/portal/mfa");
  let r = await b.go("POST", "/portal/mfa",
                     form({ action: "start", csrf_token: csrfOf(page.text) }));
  page = await b.go("GET", "/portal/mfa");
  const cell = String(page.text)
    .match(/<th>Secret<\/th><td><code>([^<]+)<\/code>/);
  const secret = cell ? cell[1].replace(/\s+/g, "") : "";
  assert.ok(secret.length >= 32, "no secret on /portal/mfa: " +
            String(page.text).slice(0, 400));
  const step = stepNow();
  r = await b.go("POST", "/portal/mfa",
                 form({ action: "confirm", code: codeAtStep(secret, step),
                        csrf_token: csrfOf(page.text) }));
  assert.ok((r.status === 303 || r.status === 302 || r.status === 200) &&
            !/class="err"/.test(r.text),
            "the confirmation answered " + r.status + ": " +
            String(r.text).slice(0, 300));
  log.debug("Leaving enrolAuthenticator().");
  return { secret: secret, step: step };
}

// ---------------------------------------------------------------------------
// WHAT THE SERVICE IS.
// ---------------------------------------------------------------------------
async function learnTheService() {
  log.debug("Entering learnTheService().");
  K.product = await facts.isProduct(apiBase);
  K.realm = String(process.env.KRB5_REALM ||
                   await facts.setting(apiBase, "krb5.realm") || "");
  K.domain = K.realm.toLowerCase();
  K.kdcHost = process.env.STS_KDC_HOST || new URL(base).hostname;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(apiBase, "krb5.kdcPort") || 88);
  K.servicePrincipal = String(
    await facts.setting(apiBase, "krb5.servicePrincipal") || "");
  const spnego = await facts.setting(apiBase, "krb5.spnegoAuthentication");
  K.spnegoOn = spnego !== false && String(spnego) !== "false";
  // Product keys a person from their own password; development keys every
  // user account from one shared password (kerberos/CLAUDE.md).
  K.password = K.product ? PASSWORD
    : String(await facts.setting(apiBase, "krb5.userPassword") ||
             "password!");
  log.info("mode " + (K.product ? "product" : "development") + ", realm " +
           K.realm + ", KDC " + K.kdcHost + ":" + K.kdcPort);
  log.debug("Leaving learnTheService().");
}

// The AS exchange for a person, waiting out product mode's derivation window
// (only the refusals that window produces are retried).
async function asForPerson(tcp, who, password) {
  log.debug("Entering asForPerson(). " + who);
  const started = Date.now();
  for (;;) {
    const r = await wire.asExchange(tcp, K.realm, who,
                                    { password: password });
    const e = (r.second && r.second.error) || (r.first && r.first.error);
    if (!(K.product && !r.tgt && e &&
          /no Kerberos keys yet|sign in once|nobody by that name/i
            .test(e.eText) && Date.now() - started < KEYS_WAIT_MS)) {
      log.debug("Leaving asForPerson().");
      return r;
    }
    await pause(500);
  }
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------
async function setUp(tcp) {
  log.debug("Entering setUp().");
  log.info("=== 1. a host principal and its armor TGT; P with an " +
           "authenticator app; Q with nothing ===");
  const spn = "host/" + HOST_NAME + "." + K.domain;
  const created = await apiPost("/kerberos/principals/create-service",
                                { spn: spn });
  check("POST /admin-api/kerberos/principals/create-service makes " + spn +
        " and hands over its keytab once", function () {
          assert.ok(created.status === 200 && created.body.ok &&
                    created.body.keytab,
                    created.status + " " + String(created.raw).slice(0, 300));
        });
  const keytabBytes = Buffer.from(created.body.keytab, "base64");
  const entries = wire.readKeytab(keytabBytes);
  const aes = entries.filter(function (one) {
    return one.etype === 18;
  })[0];
  check("the keytab (read here) holds an aes256 key for the SPN",
        function () {
          assert.ok(aes, "no aes256 entry: " + JSON.stringify(entries.map(
            function (one) {
              return one.etype;
            })));
          assert.deepStrictEqual(aes.name, spn.split("/"));
        });
  const armor = await wire.asExchange(tcp, K.realm, spn,
                                      { key: aes.key });
  check("the host gets a TGT with its keytab key — the ARMOR ticket " +
        "(RFC 6113 section 5.4.1.1)", function () {
          assert.ok(armor.tgt, "no TGT for " + spn + ": " +
                    JSON.stringify(armor.second || armor.first).slice(0,
                                                                      300));
        });
  await ensurePerson(P);
  await ensurePerson(Q);
  const enrolment = await enrolAuthenticator(P);
  check(P + " enrolled an authenticator app on the portal, with a code " +
        "computed here", function () {
          assert.ok(enrolment.secret);
        });
  log.debug("Leaving setUp().");
  return { spn: spn, hostKey: aes.key, keytab: keytabBytes,
           armor: armor.tgt, enrolment: enrolment };
}

async function passwordAlone(tcp) {
  log.debug("Entering passwordAlone().");
  log.info("=== 2. a password alone, over PA-ENC-TIMESTAMP ===");
  const right = await asForPerson(tcp, P, K.password);
  check("the bare AS-REQ offers PA-ENC-TIMESTAMP AND PA-FX-FAST", function () {
    assert.ok(right.offered.indexOf(2) !== -1 &&
              right.offered.indexOf(wire.FAST.PA_FX_FAST) !== -1,
              "offered " + right.offered);
  });
  if (K.product) {
    check("PRODUCT: " + P + "'s right password alone is KDC_ERR_POLICY " +
          "(12), naming FAST and OTP", function () {
            assert.ok(!right.tgt, "a TGT was issued on a password alone");
            assert.strictEqual(right.second.error.code, 12,
                               right.second.error.toString());
            assert.ok(/password alone is not enough/.test(
              right.second.error.eText), right.second.error.eText);
          });
  } else {
    check("DEVELOPMENT: " + P + "'s password alone gets a TGT, as every " +
          "password does", function () {
            assert.ok(right.tgt, JSON.stringify(right.second).slice(0, 300));
          });
  }
  const wrong = await wire.asExchange(tcp, K.realm, P,
                                      { password: K.password + "-wrong" });
  check("a WRONG password is KDC_ERR_PREAUTH_FAILED (24) — the refusal of a " +
        "right one tells nobody without it anything", function () {
          assert.ok(!wrong.tgt);
          assert.strictEqual(wrong.second.error.code, 24,
                             wrong.second.error.toString());
        });
  const q = await asForPerson(tcp, Q, K.password);
  check(Q + ", with no second factor, gets a TGT on the password",
        function () {
          assert.ok(q.tgt, JSON.stringify(q.second || q.first).slice(0, 300));
          assert.ok(q.tgt.flagNames.indexOf("pre-authent") !== -1);
        });
  log.debug("Leaving passwordAlone().");
  return q.tgt;
}

async function fastMethods(tcp, ctx) {
  log.debug("Entering fastMethods().");
  log.info("=== 3/4. FAST: the method list and the encrypted challenge ===");
  const first = await wire.fastAsExchange(tcp, K.realm, P, ctx.armor,
    async function () {
      return [];
    });
  const offered = first.padata.map(function (pa) {
    return pa.type;
  }).filter(function (type) {
    return type !== wire.FAST.PA_FX_ERROR;
  });
  check("an armored bare AS-REQ is KDC_ERR_PREAUTH_REQUIRED INSIDE the " +
        "armor, bound to its nonce", function () {
          assert.ok(!first.ok && first.armored, JSON.stringify(first));
          assert.strictEqual(first.code, 25);
          assert.ok(first.nonceOk, "the KrbFastResponse nonce");
        });
  check("inside FAST the methods are PA-OTP-CHALLENGE FIRST, then " +
        "PA-ENCRYPTED-CHALLENGE, with a PA-FX-COOKIE", function () {
          assert.strictEqual(offered[0], wire.FAST.PA_OTP_CHALLENGE,
                             "offered " + offered);
          assert.ok(offered.indexOf(wire.FAST.PA_ENCRYPTED_CHALLENGE) !== -1 &&
                    offered.indexOf(wire.FAST.PA_FX_COOKIE) !== -1,
                    "offered " + offered);
        });
  const challenge = wire.readOtpChallenge(first.padata.filter(function (pa) {
    return pa.type === wire.FAST.PA_OTP_CHALLENGE;
  })[0].value);
  check("the OTP challenge asks for the PIN separately (collect-pin, " +
        "separate-pin-required) and carries a nonce of 32 random bytes or " +
        "more", function () {
          assert.deepStrictEqual(challenge.tokenInfo[0].flags, [3, 6]);
          assert.ok(challenge.nonce.length >= 36, challenge.nonce.length);
        });
  const cookie = first.padata.filter(function (pa) {
    return pa.type === wire.FAST.PA_FX_COOKIE;
  })[0];

  const ltk = async function () {
    return { etype: 18, key: await wire.stringToKey(
      K.password, K.realm + P) };
  };
  const pw = await wire.fastAsExchange(tcp, K.realm, P, ctx.armor,
    async function (armorKey) {
      return wire.encryptedChallenge(await ltk())(armorKey);
    }, { replyKey: ltk });
  if (K.product) {
    check("PRODUCT: the password alone INSIDE FAST (encrypted challenge) " +
          "is KDC_ERR_POLICY too, armored", function () {
            assert.ok(!pw.ok && pw.armored, JSON.stringify(pw).slice(0, 300));
            assert.strictEqual(pw.code, 12);
          });
  } else {
    check("DEVELOPMENT: the encrypted challenge alone gets " + P + " a TGT",
          function () {
            assert.ok(pw.ok, JSON.stringify(pw).slice(0, 300));
          });
  }
  const qKey = async function () {
    return { etype: 18, key: await wire.stringToKey(
      K.password, K.realm + Q) };
  };
  const q = await wire.fastAsExchange(tcp, K.realm, Q, ctx.armor,
    async function (armorKey) {
      return wire.encryptedChallenge(await qKey())(armorKey);
    }, { replyKey: qKey });
  check(Q + " gets a TGT through FAST: the KrbFastFinished checksum " +
        "verifies over the ticket, the reply key is strengthened, and the " +
        "KDC answers with its own PA-ENCRYPTED-CHALLENGE", function () {
          assert.ok(q.ok, JSON.stringify(q).slice(0, 300));
          assert.ok(q.finishedOk && q.nonceOk && q.strengthened);
          assert.ok(q.padata.some(function (pa) {
            return pa.type === wire.FAST.PA_ENCRYPTED_CHALLENGE;
          }));
        });
  log.debug("Leaving fastMethods().");
  return { challenge: challenge, cookie: cookie, qTgt: q.ok ? q.tgt : null };
}

async function otpExchange(tcp, ctx, fast) {
  log.debug("Entering otpExchange().");
  log.info("=== 5. OTP inside FAST: the password as the PIN, and the code ===");
  const spent = codeAtStep(ctx.enrolment.secret, ctx.enrolment.step);
  const again = await wire.fastAsExchange(tcp, K.realm, P, ctx.armor,
    wire.otpRequest(fast.challenge, fast.cookie, K.password, spent));
  check("THE CODE THE PORTAL SPENT IS REFUSED AT THE KDC — one once-only " +
        "step for both doors", function () {
          assert.ok(!again.ok && again.armored, JSON.stringify(again));
          assert.strictEqual(again.code, 24);
          assert.ok(/already been used/.test(again.eText), again.eText);
        });
  const next = await codeAfter(ctx.enrolment.secret, ctx.enrolment.step);
  const good = await wire.fastAsExchange(tcp, K.realm, P, ctx.armor,
    wire.otpRequest(fast.challenge, fast.cookie, K.password, next.code));
  check("PASSWORD AND CODE: a TGT, sealed under the strengthened armor key, " +
        "with a KrbFastFinished that verifies", function () {
          assert.ok(good.ok, JSON.stringify(good).slice(0, 400));
          assert.ok(good.finishedOk && good.nonceOk && good.strengthened);
          assert.ok(good.tgt.flagNames.indexOf("pre-authent") !== -1,
                    good.tgt.flagNames);
        });
  const replay = await wire.fastAsExchange(tcp, K.realm, P, ctx.armor,
    wire.otpRequest(fast.challenge, fast.cookie, K.password, next.code));
  check("the SAME code a second time is refused", function () {
    assert.ok(!replay.ok && replay.code === 24, JSON.stringify(replay));
  });
  log.debug("Leaving otpExchange().");
  return { tgt: good.tgt, step: next.step };
}

async function theIndicator(tcp, ctx, otpTgt, qTgt) {
  log.debug("Entering theIndicator().");
  log.info("=== 6. the RFC 8129 indicator ===");
  const sname = { type: 3, name: ctx.spn.split("/") };
  const svc = await wire.tgsExchange(tcp, otpTgt, sname);
  const read = svc.ok ? await wire.ticketIndicators(svc.ticket, ctx.hostKey)
                      : null;
  check("a service ticket bought with the OTP TGT carries \"otp\" in an " +
        "AD-CAMMAC whose svc-verifier checks under the host key from the " +
        "keytab", function () {
          assert.ok(svc.ok, svc.error ? svc.error.toString() : "?");
          assert.deepStrictEqual(read.indicators, ["otp"],
                                 JSON.stringify(read));
          assert.strictEqual(read.verified, 1);
        });
  if (qTgt) {
    const plain = await wire.tgsExchange(tcp, qTgt, sname);
    const none = plain.ok ? await wire.ticketIndicators(plain.ticket,
                                                        ctx.hostKey)
                          : null;
    check("one bought with a password-only TGT carries none", function () {
      assert.ok(plain.ok, plain.error ? plain.error.toString() : "?");
      assert.deepStrictEqual(none.indicators, []);
    });
  }
  log.debug("Leaving theIndicator().");
}

async function spnegoCountsIt(tcp, otpTgt) {
  log.debug("Entering spnegoCountsIt().");
  log.info("=== 7. /authn/spnego counts the indicator ===");
  if (!K.spnegoOn || !K.servicePrincipal) {
    log.info("  krb5.spnegoAuthentication is off here; the SPNEGO half is " +
             "tests/kerberos_fast_otp.js's in-process acceptor check.");
    log.debug("Leaving spnegoCountsIt(). Off.");
    return;
  }
  const ticket = await wire.tgsExchange(tcp, otpTgt, {
    type: 3, name: K.servicePrincipal.split("/") });
  check("a ticket for " + K.servicePrincipal + " from the OTP TGT",
        function () {
          assert.ok(ticket.ok, ticket.error ? ticket.error.toString() : "?");
        });
  const built = await wire.apRequest(ticket);
  const token = await wire.negTokenInit(built, { mic: true });
  const r = await fetch(base + "/authn/spnego", {
    headers: { Authorization: "Negotiate " +
                              Buffer.from(token).toString("base64") },
    redirect: "manual" });
  const body = await r.text();
  const cookie = ((r.headers.getSetCookie ? r.headers.getSetCookie() : [])
    .filter(function (one) {
      return /^sts_session=/.test(one);
    })[0] || "").replace(/^sts_session=([^;.]*).*$/, "$1");
  check("the SPNEGO sign-in succeeds and the page says two factors: amr " +
        "pwd and otp, acr mfa", function () {
          assert.strictEqual(r.status, 200, body.slice(0, 300));
          assert.ok(cookie, "no session cookie");
          assert.ok(/pwd, otp/.test(body) && /<code>mfa<\/code>/.test(body),
                    "the page does not show amr pwd, otp and acr mfa: " +
                    body.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ")
                      .slice(0, 600));
        });
  let listed = null;
  for (let i = 0; i < 20 && !listed; i++) {
    const s = await fetch(apiBase + "/sessions?per=500&q=" +
                          encodeURIComponent(P),
                          { headers: { Accept: "application/json" } });
    const rows = ((await s.json()).sessions || []);
    listed = rows.filter(function (row) {
      return row.family === "session" && row.sessionId === cookie;
    })[0] || null;
    if (!listed) {
      await pause(500);
    }
  }
  check("and /admin-api/sessions lists that session with amr [pwd, otp]",
        function () {
          assert.ok(listed, "session " + cookie + " not listed");
          assert.deepStrictEqual(listed.amr, ["pwd", "otp"],
                                 JSON.stringify(listed.amr));
        });
  log.debug("Leaving spnegoCountsIt().");
}

// ---------------------------------------------------------------------------
// 8. REAL MIT KERBEROS, WHERE IT IS INSTALLED.
// ---------------------------------------------------------------------------
function hasMit() {
  log.debug("Entering hasMit().");
  const r = childProcess.spawnSync("sh", ["-c", "command -v kinit"],
                                   { encoding: "utf8" });
  log.debug("Leaving hasMit().");
  return r.status === 0 && /kinit/.test(r.stdout || "");
}

async function withMitKinit(ctx, used) {
  log.debug("Entering withMitKinit().");
  log.info("=== 8. MIT kinit with FAST and OTP ===");
  if (!hasMit() || process.env.STS_KRB5_MIT === "off") {
    log.info("  MIT Kerberos (kinit) is not installed on this machine, so " +
             "this section is SKIPPED; sections 3 to 6 drove FAST and OTP " +
             "with this job's own client.");
    log.debug("Leaving withMitKinit(). Skipped.");
    return;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "krb5-fast-otp-"));
  try {
    const conf = path.join(dir, "krb5.conf");
    fs.writeFileSync(conf, "[libdefaults]\n default_realm = " + K.realm +
      "\n dns_lookup_kdc = false\n dns_lookup_realm = false\n" +
      " udp_preference_limit = 1\n rdns = false\n\n[realms]\n " + K.realm +
      " = {\n  kdc = " + K.kdcHost + ":" + K.kdcPort + "\n }\n");
    // THE KEYTAB, WRITTEN AT RUN TIME into this temporary directory and
    // removed with it: the host's keys are the service's answer to this
    // run's create-service, never a file in the repository.
    const keytab = path.join(dir, "host.keytab");
    fs.writeFileSync(keytab, ctx.keytab, { mode: 0o600 });
    const env = Object.assign({}, process.env, { KRB5_CONFIG: conf,
                                                 KRB5CCNAME: "FILE:" +
                                                   path.join(dir, "cc") });
    const run = function (args, input) {
      log.debug("Entering run(). kinit " + args.join(" "));
      const r = childProcess.spawnSync("kinit", args, {
        env: env, input: input || "", encoding: "utf8", timeout: 60000 });
      log.debug("Leaving run(). exit " + r.status);
      return { status: r.status,
               out: String(r.stdout || "") + String(r.stderr || "") };
    };
    const armorCc = "FILE:" + path.join(dir, "armor");
    const host = run(["-k", "-t", keytab, "-c", armorCc,
                      ctx.spn + "@" + K.realm]);
    check("MIT: kinit -k -t <keytab> " + ctx.spn + " — the armor ccache",
          function () {
            assert.strictEqual(host.status, 0, host.out);
          });
    const plain = run([P + "@" + K.realm], K.password + "\n");
    if (K.product) {
      check("MIT: kinit " + P + " with the password alone is refused " +
            "(KDC policy)", function () {
              assert.notStrictEqual(plain.status, 0, plain.out);
              assert.ok(/policy|password alone/i.test(plain.out), plain.out);
            });
    } else {
      check("MIT (development): kinit " + P + " with the password alone " +
            "succeeds", function () {
              assert.strictEqual(plain.status, 0, plain.out);
            });
    }
    const next = await codeAfter(ctx.enrolment.secret, used);
    // MIT's OTP client asks for the token value, then the PIN
    // (separate-pin-required) — src/lib/krb5/krb/preauth_otp.c.
    const fast = run(["-T", armorCc, P + "@" + K.realm],
                     next.code + "\n" + K.password + "\n");
    check("MIT: kinit -T <armor ccache> " + P + " answering the OTP value " +
          "and the PIN gets a TGT", function () {
            assert.strictEqual(fast.status, 0, fast.out);
          });
    // THE TGS WITH MIT: its client puts FAST (implicit armor) in every
    // TGS-REQ; this KDC answers it unarmored, which MIT accepts — the
    // documented gap, asserted as working rather than assumed.
    if (K.servicePrincipal) {
      const kvno = childProcess.spawnSync("kvno",
        [K.servicePrincipal + "@" + K.realm],
        { env: env, encoding: "utf8", timeout: 60000 });
      check("MIT: kvno " + K.servicePrincipal + " with that TGT gets a " +
            "service ticket", function () {
              assert.strictEqual(kvno.status, 0, String(kvno.stdout || "") +
                                 String(kvno.stderr || ""));
            });
    }
    const again = run(["-T", armorCc, P + "@" + K.realm],
                      next.code + "\n" + K.password + "\n");
    check("MIT: the same code again is refused", function () {
      assert.notStrictEqual(again.status, 0, again.out);
    });
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in withMitKinit(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving withMitKinit().");
}

async function test() {
  log.debug("Entering test().");
  if (String(process.env.STS_TEST_UNPUBLISHED || "").split(",")
        .indexOf("kerberos") >= 0) {
    declineToRun(log, "this environment does not publish the KDC's TCP 88 " +
                      "(STS_TEST_UNPUBLISHED names kerberos).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("Driving Kerberos FAST and OTP at " + base);
  theGeneratorIsRight();
  await learnTheService();
  const tcp = wire.tcpTransport(K.kdcHost, K.kdcPort);
  const ctx = await setUp(tcp);
  const qTgt = await passwordAlone(tcp);
  const fast = await fastMethods(tcp, ctx);
  const otp = await otpExchange(tcp, ctx, fast);
  await theIndicator(tcp, ctx, otp.tgt, fast.qTgt || qTgt);
  await spnegoCountsIt(tcp, otp.tgt);
  await withMitKinit(ctx, otp.step);
  const floor = 20;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_fast_otp")
  .description("Kerberos FAST (RFC 6113) with OTP pre-authentication (RFC " +
    "6560) over TCP 88: a password alone refused for a two-factor account " +
    "in product, password and authenticator code accepted, and the RFC " +
    "8129 indicator in the tickets.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
