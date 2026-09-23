"use strict";
//
// File: sts_kerberos_keytab.js
//
// ---------------------------------------------------------------------------
// A PERSON'S KEYTAB, DOWNLOADED AND USED (#59, 2026-09-22).
//
// A keytab is only worth anything if a Kerberos client signs in with it, so
// this job gets one from each door that hands one out and then SIGNS IN WITH
// IT — with MIT's own `kinit -k -t`, against the KDC at the address the
// service is published at, and with this suite's own client
// (`krb5_wire.js`) using the keytab's key in place of a password:
//
//   1. THE ADMINISTRATOR'S DOOR: `POST /admin-api/kerberos/principals/
//      reset-person-keytab` with a typed password — a password RESET, so the
//      reply is a keytab at the NEXT kvno, served no-store — then `klist -k`
//      reads it and `kinit -k -t` gets a TGT with it. In product mode the
//      old password is then refused (KDC_ERR_PREAUTH_FAILED) and the new one
//      works; in development every user is keyed from `krb5.userPassword`,
//      so the keytab holds that key and says `source: development`.
//   2. A GENERATED PASSWORD (`random: true`): no password in the reply, and
//      the keytab signs in; in product the keytab from step 1 no longer does.
//   3. THE PERSON'S OWN DOOR, `/portal/kerberos`, signed in as them: the page
//      names their principal; their password on the form gives a keytab on a
//      no-store 200, and `kinit -k -t` signs in with it; in product a wrong
//      password is refused with no keytab on the page.
//   4. THE CONSOLE'S FORM on the person's `/admin/users` page, posted by an
//      administrator signed in to `/admin` with Admin Write: the section
//      names the principal, the form answers the shown-once keytab page
//      (no-store, saying the password was changed), and `kinit -k -t` signs in
//      with the keytab on it.
//   5. THE REFUSALS THAT CHANGE NOTHING: neither or both of `password` and
//      `random`, and a person who does not exist — 400 with no keytab.
//
// WHAT IT CHANGES ON THE SERVICE: one person, created here, whose password it
// resets, and an administrator granted Admin Write for section 4 and revoked
// again after it. No setting is touched.
//
// OWNED HERE (local: true): this repository's own KDC, console API and
// portal, against the published address.
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const facts = require("./service_facts.js");
const registry = require("./sts_applications.js");
const wire = require("./krb5_wire.js");
const consoleSignIn = require("./console_signin.js");
const { declineToRun } = require("./expectation.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads,
  // for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_kerberos_keytab",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

const USER = usernameFor("krb5-keytab");
const ADMIN = usernameFor("krb5-keytab-admin");
const FIRST_PASSWORD = "Keytab-First-Passw0rd!-" + String(Date.now()).slice(-6);
const RESET_PASSWORD = "Keytab-Reset-Passw0rd!-" + String(Date.now()).slice(-6);

// How long a product person's keys may take to reach the node that answers
// (sts_kerberos_spnego.js's KEYS_WAIT_MS, for its reason).
const KEYS_WAIT_MS = 20000;

const K = { product: false, realm: "", kdcHost: "", kdcPort: 88 };

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

async function apiGet(where) {
  log.debug("Entering apiGet(). " + where);
  const r = await fetch(api + where);
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiGet(): " + ((e && e.message) || e));
    // Not JSON — the raw text says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving apiGet(). HTTP " + r.status);
  return { status: r.status, body: parsed };
}

async function apiPost(where, body) {
  log.debug("Entering apiPost(). " + where);
  const r = await fetch(api + where, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiPost(): " + ((e && e.message) || e));
    // Not JSON — the raw text says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving apiPost(). HTTP " + r.status);
  return { status: r.status, body: parsed,
           cacheControl: r.headers.get("cache-control") || "" };
}

// ---------------------------------------------------------------------------
// A KEYTAB READER of this job's own (MIT's 0x0502 layout), so the file is
// read by something other than the writer that made it.
// ---------------------------------------------------------------------------
function readKeytab(b64) {
  log.debug("Entering readKeytab().");
  const buf = Buffer.from(String(b64 || ""), "base64");
  assert.ok(buf.length > 2 && buf.readUInt16BE(0) === 0x0502,
            "not an MIT 0x0502 keytab");
  const out = [];
  let i = 2;
  const str = function () {
    log.debug("Entering str().");
    const n = buf.readUInt16BE(i);
    const s = buf.subarray(i + 2, i + 2 + n);
    i += 2 + n;
    log.debug("Leaving str().");
    return s;
  };
  while (i < buf.length) {
    const size = buf.readInt32BE(i);
    i += 4;
    if (size < 0) {
      i += -size;
      continue;
    }
    const end = i + size;
    const count = buf.readUInt16BE(i);
    i += 2;
    const realm = str().toString("latin1");
    const name = [];
    for (let k = 0; k < count; k++) {
      name.push(str().toString("latin1"));
    }
    i += 8;
    let kvno = buf[i];
    i += 1;
    const etype = buf.readUInt16BE(i);
    i += 2;
    const key = Buffer.from(str());
    if (end - i >= 4) {
      kvno = buf.readUInt32BE(i);
    }
    i = end;
    out.push({ realm: realm, name: name.join("/"), kvno: kvno, etype: etype,
               key: key });
  }
  log.debug("Leaving readKeytab(). " + out.length + " entries.");
  return out;
}

// ---------------------------------------------------------------------------
// MIT KERBEROS, driven from a per-run krb5.conf and a credential cache of its
// own (no root, nothing of the host's). TCP only (`udp_preference_limit`),
// the KDC named directly (no DNS), and a trace written to a FILE — MIT writes
// nothing to a pipe (the parent project's krb5_mit_client.js learned that).
// ---------------------------------------------------------------------------
const MIT = { dir: "", conf: "", ok: false };

function mitAvailable() {
  log.debug("Entering mitAvailable().");
  const probe = childProcess.spawnSync("kinit", ["--version"],
                                       { encoding: "utf8" });
  log.debug("Leaving mitAvailable().");
  return !probe.error;
}

function mitSetUp() {
  log.debug("Entering mitSetUp().");
  MIT.dir = fs.mkdtempSync(path.join(os.tmpdir(), "sts-keytab-"));
  MIT.conf = path.join(MIT.dir, "krb5.conf");
  fs.writeFileSync(MIT.conf,
    "[libdefaults]\n" +
    "  default_realm = " + K.realm + "\n" +
    "  dns_lookup_kdc = false\n" +
    "  dns_lookup_realm = false\n" +
    "  udp_preference_limit = 1\n" +
    "  rdns = false\n" +
    "[realms]\n" +
    "  " + K.realm + " = {\n" +
    "    kdc = " + K.kdcHost + ":" + K.kdcPort + "\n" +
    "  }\n");
  log.debug("Leaving mitSetUp().");
}

function mit(command, args, label) {
  log.debug("Entering mit(). " + command + " " + label);
  const cache = path.join(MIT.dir, "ccache-" + label);
  const trace = path.join(MIT.dir, "trace-" + label);
  const run = childProcess.spawnSync(command, args, {
    encoding: "utf8", timeout: 30000,
    env: Object.assign({}, process.env, {
      KRB5_CONFIG: MIT.conf, KRB5CCNAME: "FILE:" + cache,
      KRB5_TRACE: trace })
  });
  let traced = "";
  try {
    traced = fs.readFileSync(trace, "utf8");
  } catch (e) {
    log.debug("Caught in mit(): " + ((e && e.message) || e));
    // No trace written: the command never reached the library.
    traced = "";
  }
  log.debug("Leaving mit(). exit " + run.status);
  return { status: run.status, stdout: run.stdout || "",
           stderr: run.stderr || "", trace: traced, cache: cache };
}

function saveKeytab(b64, label) {
  log.debug("Entering saveKeytab(). " + label);
  const file = path.join(MIT.dir, label + ".keytab");
  fs.writeFileSync(file, Buffer.from(String(b64 || ""), "base64"),
                   { mode: 0o600 });
  log.debug("Leaving saveKeytab().");
  return file;
}

// `kinit -k -t` with a keytab, retried through product mode's window (the
// keys reaching the node that answers) and only through it.
async function kinitWithKeytab(file, label, expectOk) {
  log.debug("Entering kinitWithKeytab(). " + label);
  const started = Date.now();
  let run = mit("kinit", ["-k", "-t", file, USER + "@" + K.realm], label);
  while (expectOk && run.status !== 0 && K.product &&
         Date.now() - started < KEYS_WAIT_MS) {
    await pause(500);
    run = mit("kinit", ["-k", "-t", file, USER + "@" + K.realm], label);
  }
  log.debug("Leaving kinitWithKeytab(). exit " + run.status);
  return run;
}

function keysByEtype(entries) {
  log.debug("Entering keysByEtype().");
  const keys = {};
  entries.forEach(function (one) {
    keys[one.etype] = one.key;
  });
  log.debug("Leaving keysByEtype().");
  return keys;
}

// The keytab's own key, not a password, pre-authenticating an AS-REQ over TCP
// 88 with this suite's client — retried through the same window.
async function asWithKeytab(entries, expectOk) {
  log.debug("Entering asWithKeytab().");
  const transport = wire.tcpTransport(K.kdcHost, K.kdcPort);
  const started = Date.now();
  let result = await wire.asExchange(transport, K.realm, USER,
                                     { keys: keysByEtype(entries) });
  while (expectOk && !result.tgt && K.product &&
         Date.now() - started < KEYS_WAIT_MS) {
    await pause(500);
    result = await wire.asExchange(transport, K.realm, USER,
                                   { keys: keysByEtype(entries) });
  }
  log.debug("Leaving asWithKeytab(). " + (result.tgt ? "a TGT" : "none"));
  return result;
}

async function asWithPassword(password) {
  log.debug("Entering asWithPassword().");
  const transport = wire.tcpTransport(K.kdcHost, K.kdcPort);
  const result = await wire.asExchange(transport, K.realm, USER,
                                       { password: password });
  log.debug("Leaving asWithPassword().");
  return result;
}

function refusalCode(result) {
  log.debug("Entering refusalCode().");
  const e = (result.second && result.second.error) ||
            (result.first && result.first.error);
  log.debug("Leaving refusalCode().");
  return e ? e.code : null;
}

// ---------------------------------------------------------------------------
// A BROWSER SIGNED IN TO THE PORTAL — sts_portal_certificates.js's.
// ---------------------------------------------------------------------------
function formBody(o) {
  log.debug("Entering formBody().");
  log.debug("Leaving formBody().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

function browser() {
  log.debug("Entering browser().");
  const self = {
    jar: {},
    async go(method, where, body) {
      log.debug("Entering go().");
      const headers = {};
      const cookie = Object.keys(self.jar).map(function (k) {
        return k + "=" + self.jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(where), { method: method,
                                               redirect: "manual",
                                               headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const key = pair.split("=")[0];
        const value = pair.slice(key.length + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete self.jar[key];
        } else {
          self.jar[key] = value;
        }
      });
      log.debug("Leaving go(). HTTP " + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text(), headers: r.headers };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

async function signIn(password) {
  log.debug("Entering signIn().");
  const b = browser();
  let r = await b.go("GET", "/portal/kerberos");
  assert.ok(/\/oauth2\/authorize\?/.test(r.location),
    "an unauthenticated browser should be sent to the authorization " +
    "endpoint; it answered " + r.status + " -> " + r.location);
  r = await b.go("GET", r.location);
  r = await b.go("GET", r.location);
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id.");
  r = await b.go("POST", "/authn/login",
                 formBody({ authn_id: authnId, username: USER,
                            password: password, action: "login",
                            csrf_token: csrfOf(r.text) }));
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in should end in a redirect; got " + r.status);
  r = await b.go("GET", r.location);
  r = await b.go("GET", r.location);
  assert.ok(Object.keys(b.jar).length, "no session was established.");
  log.debug("Leaving signIn().");
  return b;
}

function keytabOnPage(text) {
  log.debug("Entering keytabOnPage().");
  log.debug("Leaving keytabOnPage().");
  return (String(text).match(
    /<textarea readonly rows="6" name="keytab-base64">([A-Za-z0-9+/=]+)</) ||
    [])[1] || "";
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------
async function learnTheService() {
  log.debug("Entering learnTheService().");
  K.product = await facts.isProduct(api);
  K.realm = String(process.env.KRB5_REALM ||
                   await facts.setting(api, "krb5.realm") || "");
  K.kdcHost = process.env.STS_KDC_HOST || new URL(base).hostname;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(api, "krb5.kdcPort") || 88);
  const enabled = await facts.setting(api, "krb5.enabled");
  log.info("mode " + (K.product ? "product" : "development") + ", realm " +
           K.realm + ", KDC " + K.kdcHost + ":" + K.kdcPort);
  check("the service has Kerberos on and names a realm", function () {
    assert.ok(enabled === true || String(enabled) === "true",
              "krb5.enabled is " + JSON.stringify(enabled));
    assert.ok(K.realm, "krb5.realm is empty");
  });
  log.debug("Leaving learnTheService().");
}

function checkKeytab(what, reply, expectKvno) {
  log.debug("Entering checkKeytab(). " + what);
  let entries = [];
  check(what + ": the reply is 200, no-store, and carries a keytab for " +
        USER + "@" + K.realm + " at one kvno", function () {
    assert.strictEqual(reply.status, 200,
                       JSON.stringify(reply.body).slice(0, 400));
    assert.ok(/no-store/.test(reply.cacheControl),
              "Cache-Control is " + JSON.stringify(reply.cacheControl));
    entries = readKeytab(reply.body.keytab);
    assert.ok(entries.length > 0, "the keytab is empty");
    entries.forEach(function (one) {
      assert.strictEqual(one.name, USER, "an entry names " + one.name);
      assert.strictEqual(one.realm, K.realm, "an entry is in " + one.realm);
      assert.strictEqual(one.kvno, reply.body.kvno,
                         "an entry is at kvno " + one.kvno);
    });
    assert.deepStrictEqual(reply.body.keytabKvnos, [reply.body.kvno],
                           "the keytab carries more than the current kvno");
    if (expectKvno !== undefined) {
      assert.strictEqual(reply.body.kvno, expectKvno, "the kvno");
    }
    assert.strictEqual(reply.body.source,
                       K.product ? "password" : "development", "source");
  });
  log.debug("Leaving checkKeytab().");
  return entries;
}

async function mitSignsIn(what, keytabB64, label) {
  log.debug("Entering mitSignsIn(). " + label);
  const file = saveKeytab(keytabB64, label);
  const listed = mit("klist", ["-k", "-e", file], label + "-list");
  check(what + ": MIT klist -k reads the keytab and lists the principal",
        function () {
    assert.strictEqual(listed.status, 0, listed.stderr);
    assert.ok(listed.stdout.indexOf(USER + "@" + K.realm) >= 0,
              "klist -k did not list " + USER + "@" + K.realm + ": " +
              listed.stdout);
  });
  const run = await kinitWithKeytab(file, label, true);
  check(what + ": MIT kinit -k -t signs in with it, and the cache holds a " +
        "TGT for " + USER + "@" + K.realm, function () {
    assert.strictEqual(run.status, 0, "kinit exited " + run.status + ": " +
                       run.stderr + "\n" + run.trace.slice(-1500));
    const cached = mit("klist", ["-c", "FILE:" + run.cache], label + "-c");
    assert.strictEqual(cached.status, 0, cached.stderr);
    assert.ok(cached.stdout.indexOf(USER + "@" + K.realm) >= 0 &&
              cached.stdout.indexOf("krbtgt/" + K.realm + "@" + K.realm) >=
                0, "no TGT in the cache: " + cached.stdout);
  });
  log.debug("Leaving mitSignsIn().");
  return file;
}

async function theAdministratorsDoor() {
  log.debug("Entering theAdministratorsDoor().");
  log.info("=== 1. the administrator's reset, with a typed password ===");
  const reply = await apiPost("/kerberos/principals/reset-person-keytab",
                              { username: USER, password: RESET_PASSWORD });
  const entries = checkKeytab("reset-person-keytab", reply);
  check("the reply says the password was set, typed, and names no password",
        function () {
    assert.strictEqual(reply.body.passwordSet, true);
    assert.strictEqual(reply.body.generated, false);
    assert.ok(!Object.prototype.hasOwnProperty.call(reply.body, "password"),
              "a password member is in the reply");
  });
  const file = await mitSignsIn("the reset's keytab", reply.body.keytab,
                                "reset");
  const own = await asWithKeytab(entries, true);
  check("the keytab's KEY pre-authenticates an AS-REQ over TCP 88 with this " +
        "suite's client, and the AS-REP opens under it", function () {
    assert.ok(own.tgt, "no TGT: " + JSON.stringify(own.second || own.first));
    assert.ok(own.tgt.nonceEchoed, "the AS-REP's nonce is not ours");
  });
  if (K.product) {
    const oldPassword = await asWithPassword(FIRST_PASSWORD);
    const newPassword = await asWithPassword(RESET_PASSWORD);
    check("PRODUCT: the old password is refused KDC_ERR_PREAUTH_FAILED and " +
          "the reset one signs in", function () {
      assert.strictEqual(refusalCode(oldPassword), 24,
                         JSON.stringify(oldPassword.second));
      assert.ok(newPassword.tgt, JSON.stringify(newPassword.second));
    });
  }
  log.debug("Leaving theAdministratorsDoor().");
  return { reply: reply, file: file };
}

async function aGeneratedPassword(first) {
  log.debug("Entering aGeneratedPassword().");
  log.info("=== 2. a generated password, never returned ===");
  const reply = await apiPost("/kerberos/principals/reset-person-keytab",
                              { username: USER, random: true });
  checkKeytab("reset-person-keytab with random", reply,
              K.product ? first.reply.body.kvno + 1 : undefined);
  check("the generated password is not in the reply", function () {
    assert.strictEqual(reply.body.generated, true);
    assert.ok(!Object.prototype.hasOwnProperty.call(reply.body, "password"),
              "a password member is in the reply");
    assert.ok(JSON.stringify(reply.body).indexOf(RESET_PASSWORD) < 0,
              "the previous password is in the reply");
  });
  await mitSignsIn("the generated password's keytab", reply.body.keytab,
                   "random");
  if (K.product) {
    const stale = await kinitWithKeytab(first.file, "stale", false);
    check("PRODUCT: the keytab from the password before it no longer signs " +
          "in", function () {
      assert.notStrictEqual(stale.status, 0, "kinit with the old keytab " +
                            "succeeded");
    });
  }
  // A PASSWORD BACK, so the portal section can sign in as them.
  const again = await apiPost("/kerberos/principals/reset-person-keytab",
                              { username: USER, password: FIRST_PASSWORD +
                                                          "-again" });
  check("a typed password is set again for the portal section", function () {
    assert.strictEqual(again.status, 200,
                       JSON.stringify(again.body).slice(0, 300));
  });
  log.debug("Leaving aGeneratedPassword().");
  return FIRST_PASSWORD + "-again";
}

async function thePersonsDoor(password) {
  log.debug("Entering thePersonsDoor().");
  log.info("=== 3. the person's own keytab, on /portal/kerberos ===");
  const b = await signIn(password);
  const page = await b.go("GET", "/portal/kerberos");
  check("the page names their principal and carries a real form",
        function () {
    assert.strictEqual(page.status, 200, "answered " + page.status);
    assert.ok(page.text.indexOf(USER + "@" + K.realm) >= 0,
              "the principal is not on the page");
    assert.ok(/name="current"/.test(page.text) &&
              /<button type="submit">Make and download a keytab<\/button>/
                .test(page.text), "no password field and submit button");
    assert.ok(page.text.indexOf('name="username"') < 0,
              "a form on this page names a person");
  });
  if (K.product) {
    const wrong = await b.go("POST", "/portal/kerberos",
      formBody({ action: "keytab", current: "Not-Their-Passw0rd!-1",
                 csrf_token: csrfOf(page.text) }));
    check("PRODUCT: a wrong password is refused, with no keytab on the page",
          function () {
      assert.strictEqual(wrong.status, 400, "answered " + wrong.status);
      assert.strictEqual(keytabOnPage(wrong.text), "",
                         "a keytab is on the refusal");
    });
  }
  const fresh = await b.go("GET", "/portal/kerberos");
  const made = await b.go("POST", "/portal/kerberos",
    formBody({ action: "keytab", current: password,
               csrf_token: csrfOf(fresh.text) }));
  const b64 = keytabOnPage(made.text);
  check("their password gives a keytab on a no-store 200", function () {
    assert.strictEqual(made.status, 200, "answered " + made.status);
    assert.ok(/no-store/.test(made.headers.get("cache-control") || ""),
              "the page carrying the keytab is cacheable");
    assert.ok(b64, "no keytab on the page");
    readKeytab(b64).forEach(function (one) {
      assert.strictEqual(one.name, USER, "an entry names " + one.name);
    });
    assert.ok(/download="[^"]+\.keytab"/.test(made.text),
              "no download link");
  });
  await mitSignsIn("the portal's keytab", b64, "portal");
  const again = await b.go("GET", "/portal/kerberos");
  check("and it is not on the page again", function () {
    assert.strictEqual(keytabOnPage(again.text), "",
                       "the keytab is shown a second time");
  });
  log.debug("Leaving thePersonsDoor().");
}

async function theConsolesForm() {
  log.debug("Entering theConsolesForm().");
  log.info("=== 4. the console's form on the person's page ===");
  const rbac = await apiGet("/rbac");
  const open = !!(rbac.body && rbac.body.openToAnyone);
  let granted = false;
  try {
    if (!open) {
      const grant = await apiPost("/rbac/grant",
                                  { username: ADMIN, role: "write" });
      assert.strictEqual(grant.status, 200, "granting Admin Write answered " +
                         grant.status + " " +
                         JSON.stringify(grant.body).slice(0, 200));
      granted = true;
    }
    const cookie = await consoleSignIn.signInToTheConsole(base, ADMIN, log);
    const userPage = await fetch(base + "/admin/users?user=" +
                                 encodeURIComponent(USER),
                                 { headers: { Cookie: cookie },
                                   redirect: "manual" });
    const drawn = await userPage.text();
    check("the person's page has a Kerberos section naming their principal " +
          "and the reset form", function () {
      assert.strictEqual(userPage.status, 200, "answered " + userPage.status);
      assert.ok(/<h2 id="kerberos"[^>]*>Kerberos<\/h2>/.test(drawn),
                "no Kerberos section");
      assert.ok(drawn.indexOf(USER + "@" + K.realm) >= 0,
                "the principal is not in the section");
      assert.ok(/name="action" value="reset-person-keytab"/.test(drawn) &&
                /Reset password and download keytab<\/button>/.test(drawn),
                "no reset form with a real submit button");
    });
    const csrf = (drawn.match(/name="csrf_token" value="([^"]+)"/) ||
                  [])[1] || "";
    const posted = await fetch(base + "/admin/kerberos/principals", {
      method: "POST", redirect: "manual",
      headers: { Cookie: cookie,
                 "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf_token: csrf,
                                  action: "reset-person-keytab",
                                  username: USER, from: "user",
                                  password: RESET_PASSWORD + "-console" })
        .toString() });
    const shown = await posted.text();
    const b64 = keytabOnPage(shown);
    check("the form answers the shown-once keytab page, no-store, saying " +
          "the password was changed", function () {
      assert.strictEqual(posted.status, 200, "answered " + posted.status +
                         " " + shown.replace(/<[^>]+>/g, " ").slice(0, 300));
      assert.ok(/no-store/.test(posted.headers.get("cache-control") || ""),
                "the keytab page is cacheable");
      assert.ok(b64, "no keytab on the page");
      assert.ok(/password was changed/.test(shown),
                "the page does not say the password was changed");
      readKeytab(b64).forEach(function (one) {
        assert.strictEqual(one.name, USER, "an entry names " + one.name);
      });
    });
    await mitSignsIn("the console's keytab", b64, "console");
  } finally {
    if (granted) {
      const revoked = await apiPost("/rbac/revoke",
                                    { username: ADMIN, role: "write" });
      log.info("revoked the Admin Write granted for this section: " +
               revoked.status);
    }
  }
  log.debug("Leaving theConsolesForm().");
}

async function theRefusals() {
  log.debug("Entering theRefusals().");
  log.info("=== 5. refusals that change nothing ===");
  const neither = await apiPost("/kerberos/principals/reset-person-keytab",
                                { username: USER });
  const both = await apiPost("/kerberos/principals/reset-person-keytab",
                             { username: USER, password: RESET_PASSWORD,
                               random: true });
  const nobody = await apiPost("/kerberos/principals/reset-person-keytab",
                               { username: usernameFor("krb5-nobody"),
                                 password: RESET_PASSWORD });
  check("neither or both of password and random, and nobody, are 400 with " +
        "no keytab", function () {
    [neither, both, nobody].forEach(function (one) {
      assert.strictEqual(one.status, 400, JSON.stringify(one.body));
      assert.ok(!one.body.keytab, "a refusal carries a keytab");
    });
  });
  log.debug("Leaving theRefusals().");
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
  assert.ok(mitAvailable(), "MIT Kerberos (kinit) is not installed; the " +
            "tests image installs krb5-user (tests/Dockerfile).");
  log.info("Downloading and using a person's keytab at " + base);
  await learnTheService();
  mitSetUp();
  log.info("=== 0. the person, created with a password of their own ===");
  await registry.ensurePerson(base, USER, FIRST_PASSWORD);
  const first = await theAdministratorsDoor();
  const password = await aGeneratedPassword(first);
  await thePersonsDoor(password);
  await theConsolesForm();
  await theRefusals();
  try {
    fs.rmSync(MIT.dir, { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in test(): " + ((e && e.message) || e));
    // A temporary directory left behind is not what this job tests.
  }
  const floor = K.product ? 23 : 20;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_keytab")
  .description("A person's keytab from /admin-api and /portal/kerberos, " +
    "used with MIT kinit -k -t and this suite's own client against the " +
    "KDC at the service's published address.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
