// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_password_policy_rules.js
//
// ---------------------------------------------------------------------------
// THE PASSWORD POLICY AND ITS NAMED PROFILES, AS A CLIENT MEETS THEM.
//
// D12 (#444): carries over `tests/password_policy.js` and
// `tests/password_named_policies.js` (#1236). In realms of this job's own,
// through `/admin-api` (`users/set-password`, `users/create`,
// `policies/save-password-policy`, `policies/reset-password-policy`,
// `groups/set-policy`, `applications/set`), the sign-in screen's forced
// change and the LDAPS socket, codes read off `/admin-api/audit`:
//
//   A. THE DEFAULT PROFILE IN A PRODUCT REALM: built in until saved and
//      enforced; a short password refused with the one rule it breaks, a
//      sentence naming `/admin/policies` and the profile; twelve characters
//      with no symbol, letters of one case, a passphrase with spaces,
//      Greek capitals as uppercase and emoji counted as code points; a
//      password on the breach list refused as `breached`;
//   B. THE HISTORY: the current password and the five before it refused,
//      the oldest accepted again once it has left the history; a
//      GENERATED password meets the profile, carries neither `"` nor a
//      backtick, and is answered once;
//   C. THE PROFILE AS AN ENTRY: a save that leaves fields out refused by
//      NAME for each (STS-AUTHN-0108), a profile name outside the pattern
//      refused by the request schema, the rules ASVS 5.0.0 6.2.5 forbids
//      (a symbol count, a required uppercase letter or digit) and a
//      generated length under the minimum refused (STS-AUTHN-0108); a whole
//      profile saved, read back as `cn=default,ou=passwordPolicies`, and
//      ENFORCED with its own minimum and history; a reset putting the
//      built-in defaults back;
//   D. DEVELOPMENT sets a one-character password, and the same again;
//   E. THE LDAP DOOR in product: a person may not write their own
//      `userPassword` over LDAP (50); an operator's write (Admin Write,
//      bound with an LDAP app password) that breaks the profile is a
//      constraint violation and nothing is written (the old password still
//      binds); one that meets it is taken; the current password sent in the
//      clear again, a value in this service's own hashed form and an ADD of
//      a second value are refused (19); `users/create` with `credential:
//      generate` answers a password that meets the profile and must be
//      changed first (an LDAPS bind with it is refused, as one with an
//      administrator's generated password is), and `credential: none`
//      creates a person holding nothing;
//   F. NAMED PROFILES: saved with a precedence, a precedence outside
//      1..1000 refused (STS-AUTHN-0108); named by a group
//      (`stsPasswordPolicy`) and an application (`appPasswordPolicy`),
//      a name the realm does not hold refused at both doors; in product a
//      group member's password is refused by the group's profile and the
//      same password set for a person nothing names; the forced change at
//      the sign-in screen for an application decided by the application's
//      profile; the lower precedence winning where both name one; a named
//      profile something names not removed (STS-AUTHN-0540), and removed
//      once nothing does; another realm holding only `default`.
//
// NOT carried, and why (class (d)): what a hash was WRITTEN under (the
// scrypt or argon2id parameters, `security.passwordHash*`, the worker-pool
// door) and what `pwdHistory` holds — both are stored values no answer
// carries, and none should; a stored CLEAR `userPassword` an older build
// wrote, which no door can produce; `selectionFor()` and the ranking as a
// library call (the doors above are its observable); a reference to a
// profile the realm does not hold (STS-AUTHN-0539), which every door
// refuses to write, so only a delete made past the console produces it;
// the console's tab markup.
//
// The realms turn `risk.assessSignIns` off and the product one turns
// `authn.allowOptionalSecondFactor` on, for sts_second_factor_codes.js's
// reasons.
//
// OWNED HERE (local: true): this repository's own API and doors.
// ---------------------------------------------------------------------------

const assert = require("assert");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin");
const passkeys = require("./passkey_wire_kit.js");
const fixtures = require("./oauth_fixtures.js");

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
var log = bunyan.createLogger({ name: "sts_password_policy_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
// Letters only, from the run's stamp: a password the breach list cannot
// hold, so a refusal below is the policy's and never "breached".
const LETTERS = STAMP.replace(/[0-9]/g, function (d) {
  return "qwrtypsdfg"[Number(d)];
});
const FIELDS = ["minLength", "history", "minSymbols", "requireUppercase",
                "requireDigit", "generatedLength", "hashAlgorithm",
                "argon2Memory", "argon2Iterations", "argon2Parallelism",
                "scryptLogN", "scryptBlockSize", "scryptParallelism"];

function realmOf(id) {
  log.debug("Entering realmOf(). " + id);
  const r = { id: id, domain: id + ".example.net" };
  r.base = base + "/realm/" + id;
  r.api = r.base + "/admin-api";
  log.debug("Leaving realmOf().");
  return r;
}
const PROD = realmOf("pwp-p-" + STAMP);
const DEV = realmOf("pwp-d-" + STAMP);
const NAMED = realmOf("pwp-n-" + STAMP);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const sent = Object.assign({ redirect: "manual" }, options || {});
  sent.headers = Object.assign({ "User-Agent": AGENT }, sent.headers || {});
  const r = await fetch(url, sent);
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — an empty answer or a page; `raw` holds it.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
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

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(realm.api + "/audit?per=1&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function gained(realm, code, before) {
  log.debug("Entering gained(). " + code);
  let n = (await codeCount(realm, code)) - before;
  for (let i = 0; i < 20 && n < 1; i += 1) {
    await sleep(150);
    n = (await codeCount(realm, code)) - before;
  }
  log.debug("Leaving gained(). " + n);
  return n;
}

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return ((r.body && r.body.errors) || []).join(" ");
}

async function makeRealm(realm, mode) {
  log.debug("Entering makeRealm(). " + realm.id);
  // allowOptionalSecondFactor in every realm: NAMED is switched to product
  // after its fixtures are in, and the setting means nothing in development.
  const overrides = { "global.mode": mode, "risk.assessSignIns": "false",
                      "authn.allowOptionalSecondFactor": "true" };
  await ok(base + "/admin-api/realms/create", { id: realm.id,
    domain: realm.domain, name: "Password policy " + realm.id,
    overrides: overrides }, "created the realm " + realm.id);
  log.debug("Leaving makeRealm().");
}

async function person(realm, who, password) {
  log.debug("Entering person(). " + who);
  await ok(realm.api + "/users/create", { username: who, invent: false,
    credential: "password", password: password,
    attributes: { cn: "PWP " + who, givenName: "PWP", sn: who,
                  mail: who + "@" + realm.domain } },
    "created " + who + " in " + realm.id);
  log.debug("Leaving person().");
}

function setPassword(realm, who, password) {
  log.debug("Entering setPassword(). " + who);
  log.debug("Leaving setPassword().");
  return postJson(realm.api + "/users/set-password",
                  { user: who, password: password });
}

async function passwordView(realm) {
  log.debug("Entering passwordView().");
  const r = await send(realm.api + "/policies");
  assert.ok(r.status === 200 && r.body && r.body.password,
            "GET /admin-api/policies: " + r.status + " " +
            r.raw.slice(0, 300));
  log.debug("Leaving passwordView().");
  return r.body;
}

function profileOf(view, changes) {
  log.debug("Entering profileOf().");
  const out = {};
  FIELDS.forEach(function (k) {
    out[k] = view.password.profile[k];
  });
  log.debug("Leaving profileOf().");
  return Object.assign(out, changes || {});
}

// A save expected refused, recorded with `code` where one is named.
async function saveRefused(realm, body, code) {
  log.debug("Entering saveRefused().");
  const before = code ? await codeCount(realm, code) : 0;
  const r = await postJson(realm.api + "/policies/save-password-policy",
                           body);
  const got = code ? await gained(realm, code, before) : 1;
  log.debug("Leaving saveRefused(). " + r.status);
  return { r: r, got: got };
}

// ---------------------------------------------------------------------------
// THE LDAP DOOR: a person bound as themselves, modifying their own
// userPassword over LDAPS.
// ---------------------------------------------------------------------------
function personDn(realm, who) {
  log.debug("Entering personDn().");
  log.debug("Leaving personDn().");
  return "uid=" + who + ",ou=users," + realm.domain.split(".").map(
    function (one) {
      return "dc=" + one;
    }).join(",");
}

function ldapClient() {
  log.debug("Entering ldapClient().");
  const url = process.env.STS_LDAPS_URL ||
    ("ldaps://" + new URL(base).hostname + ":" +
     (process.env.STS_LDAPS_PORT || 636));
  const client = ldapjs.createClient({
    url: url, reconnect: false, timeout: 20000, connectTimeout: 15000,
    tlsOptions: { servername: new URL(url).hostname,
                  rejectUnauthorized:
                    process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0" }
  });
  client.on("error", function (e) {
    // ldapjs also emits on the client; each operation's callback reports it.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving ldapClient().");
  return client;
}

function close(client) {
  log.debug("Entering close().");
  try {
    client.unbind(function () {
      client.destroy();
    });
  } catch (x) {
    // An unbind on a connection the server already closed.
    log.debug("Caught in close(): " + ((x && x.message) || x));
  }
  log.debug("Leaving close().");
}

function bind(realm, who, password) {
  log.debug("Entering bind(). " + who);
  return new Promise(function (resolve) {
    const client = ldapClient();
    client.bind(personDn(realm, who), password, function (e) {
      close(client);
      log.debug("Leaving bind(). " + (e ? e.code : 0));
      resolve(e ? e.code : 0);
    });
  });
}

// Bound as the realm's operator (Admin Write, with an app password scoped
// to LDAP: a person's own password is refused at a password-only door in
// product once they hold a console role), a replace of `who`'s
// userPassword: the LDAP result code, 0 for success. A person may not
// write their own userPassword over LDAP in product (50).
function modifyAs(realm, operator, who, value) {
  log.debug("Entering modifyAs(). " + who);
  return new Promise(function (resolve) {
    const client = ldapClient();
    client.bind(personDn(realm, operator.who), operator.password,
                function (e) {
      if (e) {
        close(client);
        log.debug("Leaving modifyAs(). Bind refused " + e.code);
        resolve({ bound: false, code: e.code, message: String(e.message) });
        return;
      }
      const change = new ldapjs.Change({ operation: "replace",
        modification: new ldapjs.Attribute({ type: "userPassword",
                                             values: [value] }) });
      client.modify(personDn(realm, who), change, function (m) {
        close(client);
        log.debug("Leaving modifyAs(). " + (m ? m.code : 0));
        resolve({ bound: true, code: m ? m.code : 0,
                  message: m ? String(m.message) : "" });
      });
    });
  });
}

// ---------------------------------------------------------------------------
// A. AND B. THE DEFAULT PROFILE AND ITS HISTORY, IN PRODUCT.
// ---------------------------------------------------------------------------
async function defaults() {
  log.debug("Entering defaults().");
  log.info("=== A. the default profile, enforced in product ===");
  const who = names.usernameFor("pwp-a");
  await person(PROD, who, "Seed-" + STAMP + "-Passw0rd");
  const view = await passwordView(PROD);
  check("A. nothing is stored: the built-in profile is in force, and " +
        "enforced", function () {
    assert.strictEqual(view.password.profile.stored, false);
    assert.strictEqual(view.password.profile.enforced, true);
    assert.strictEqual(view.password.profile.minLength, 12);
    assert.strictEqual(view.password.profile.history, 5);
  });
  const short = await setPassword(PROD, who, "x");
  check("A. a one-character password is refused for the one rule it " +
        "breaks, with a sentence naming /admin/policies and the profile",
        function () {
    assert.strictEqual(short.status, 400, short.raw.slice(0, 300));
    assert.strictEqual(short.body.reason, "password-policy");
    assert.strictEqual(short.body.problems.length, 1,
                       JSON.stringify(short.body.problems));
    assert.ok(/\/admin\/policies/.test(errorsOf(short)) &&
              /profile "default"/.test(errorsOf(short)), errorsOf(short));
  });
  const eleven = await setPassword(PROD, who, "Abcdefghij1");
  check("A. eleven characters are refused", function () {
    assert.strictEqual(eleven.status, 400, eleven.raw.slice(0, 300));
  });
  const accepted = ["Kq" + LETTERS, "zz" + LETTERS + "zzzzzzz",
                    "a plain " + LETTERS + " passphrase",
                    "Αβγδεζηθ" +
                    "ικΛ1!",
                    "😀".repeat(10) + "A1"];
  const answers = [];
  for (const pw of accepted) {
    answers.push(await setPassword(PROD, who, pw));
  }
  const fewEmoji = await setPassword(PROD, who,
                                     "😀".repeat(5) + "A1");
  check("A. twelve with no symbol, letters of one case, a passphrase with " +
        "spaces, Greek capitals and ten emoji (counted as code points) are " +
        "each accepted (ASVS 5.0.0 6.2.5)", function () {
    answers.forEach(function (r, i) {
      assert.strictEqual(r.status, 200, "#" + i + ": " + r.raw.slice(0, 300));
    });
  });
  check("A. five emoji and two characters are seven code points, and " +
        "refused", function () {
    assert.strictEqual(fewEmoji.status, 400, fewEmoji.raw.slice(0, 300));
    assert.strictEqual(fewEmoji.body.reason, "password-policy");
  });
  const breached = await setPassword(PROD, who, "Abcdefghijk1");
  check("A. a password long enough but on the breach list is refused as " +
        "breached, not as a policy failure", function () {
    assert.strictEqual(breached.status, 400, breached.raw.slice(0, 300));
    assert.strictEqual(breached.body.reason, "breached");
  });

  log.info("=== B. the history, and a generated password ===");
  const hist = names.usernameFor("pwp-b");
  const H = [0, 1, 2, 3, 4, 5, 6].map(function (i) {
    return "History-" + STAMP + "-number-" + i;
  });
  await person(PROD, hist, H[0]);
  const current = await setPassword(PROD, hist, H[0]);
  check("B. the CURRENT password is refused as a new one", function () {
    assert.strictEqual(current.status, 400, current.raw.slice(0, 300));
    assert.strictEqual(current.body.reason, "password-history");
    assert.ok(/the 5 before it/.test(errorsOf(current)), errorsOf(current));
  });
  for (let i = 1; i <= 5; i += 1) {
    const r = await setPassword(PROD, hist, H[i]);
    assert.strictEqual(r.status, 200, "H" + i + ": " + r.raw.slice(0, 300));
  }
  const oldest = await setPassword(PROD, hist, H[0]);
  const middle = await setPassword(PROD, hist, H[3]);
  check("B. five back and two back are both still in the history",
        function () {
    assert.strictEqual(oldest.body.reason, "password-history",
                       oldest.raw.slice(0, 300));
    assert.strictEqual(middle.body.reason, "password-history",
                       middle.raw.slice(0, 300));
  });
  await ok(PROD.api + "/users/set-password", { user: hist, password: H[6] },
           "set the seventh");
  const back = await setPassword(PROD, hist, H[0]);
  check("B. six back, the first has left the history and is accepted",
        function () {
    assert.strictEqual(back.status, 200, back.raw.slice(0, 300));
  });
  const generated = await ok(PROD.api + "/users/set-password",
                             { user: hist, generate: true },
                             "generated one");
  const generatedAgain = await ok(PROD.api + "/users/set-password",
                                  { user: hist, generate: true },
                                  "generated another");
  check("B. a GENERATED password meets the profile (twenty characters), " +
        "carries neither `\"` nor a backtick, and is answered once",
        function () {
    [generated, generatedAgain].forEach(function (g) {
      assert.strictEqual(g.generated, true);
      assert.strictEqual([...g.password].length, 20, g.password);
      assert.ok(!/["`]/.test(g.password), g.password);
    });
    assert.notStrictEqual(generated.password, generatedAgain.password);
  });
  const signs = await bind(PROD, hist, generatedAgain.password);
  const wrongBind = await bind(PROD, hist, generatedAgain.password + "x");
  check("B. an administrator's generated password must be changed first: " +
        "in product an LDAPS bind with it is refused (49), as a wrong one " +
        "is", function () {
    assert.ok(/changed at the next sign-in/.test(generatedAgain.message),
              generatedAgain.message);
    assert.strictEqual(signs, 49, "bind result " + signs);
    assert.strictEqual(wrongBind, 49, "bind result " + wrongBind);
  });
  log.debug("Leaving defaults().");
}

// ---------------------------------------------------------------------------
// C. THE PROFILE AS AN ENTRY.
// ---------------------------------------------------------------------------
async function asEntry() {
  log.debug("Entering asEntry().");
  log.info("=== C. the profile as a directory entry ===");
  const view = await passwordView(PROD);
  const partial = await saveRefused(PROD, { profile: "default",
                                            minLength: 8 },
                                    "STS-AUTHN-0108");
  check("C. a save that leaves fields out is refused BY NAME for each " +
        "(STS-AUTHN-0108)", function () {
    assert.strictEqual(partial.r.status, 400, partial.r.raw.slice(0, 300));
    ["history", "minSymbols", "requireUppercase", "requireDigit",
     "generatedLength"].forEach(function (name) {
      assert.ok(errorsOf(partial.r).indexOf("`" + name + "`") >= 0,
                name + ": " + errorsOf(partial.r));
    });
    assert.ok(partial.got >= 1, "STS-AUTHN-0108 rows: " + partial.got);
  });
  const badName = await postJson(PROD.api + "/policies/save-password-policy",
    profileOf(view, { profile: "Strict!" }));
  check("C. a profile name outside the pattern is refused by the request " +
        "schema", function () {
    assert.strictEqual(badName.status, 400, badName.raw.slice(0, 300));
    assert.ok(/must match pattern/.test(errorsOf(badName)),
              errorsOf(badName));
  });
  const asks = [{ minSymbols: 1 }, { requireUppercase: true },
                { requireDigit: true },
                { minLength: 24, generatedLength: 20 }];
  for (const ask of asks) {
    const r = await saveRefused(PROD, profileOf(view,
      Object.assign({ profile: "default" }, ask)), "STS-AUTHN-0108");
    check("C. a profile asking " + JSON.stringify(ask) + " is refused " +
          "(STS-AUTHN-0108)", function () {
      assert.strictEqual(r.r.status, 400, r.r.raw.slice(0, 300));
      assert.ok(r.got >= 1, "STS-AUTHN-0108 rows: " + r.got);
    });
  }
  const saved = await ok(PROD.api + "/policies/save-password-policy",
    profileOf(view, { profile: "default", minLength: "8", history: 2 }),
    "saved a whole profile, from a form string and JSON alike");
  const after = await passwordView(PROD);
  check("C. the profile is stored as cn=default,ou=passwordPolicies and " +
        "read back as the directory's", function () {
    assert.ok(saved.profile && saved.profile.stored, JSON.stringify(saved)
      .slice(0, 300));
    assert.ok(/^cn=default,ou=passwordPolicies,/.test(after.password
      .profile.dn), after.password.profile.dn);
    assert.strictEqual(after.password.profile.minLength, 8);
    assert.strictEqual(after.password.profile.history, 2);
    assert.strictEqual(after.password.profile.sources.minLength,
                       "directory");
  });
  const who = names.usernameFor("pwp-c");
  await person(PROD, who, "Seed-" + STAMP + "-Passw0rd");
  const e = ["a", "b", "c", "d"].map(function (one) {
    return one + LETTERS.slice(0, 7);
  });
  const first = await setPassword(PROD, who, e[0]);
  await setPassword(PROD, who, e[1]);
  await setPassword(PROD, who, e[2]);
  const reused = await setPassword(PROD, who, e[0]);
  await setPassword(PROD, who, e[3]);
  const free = await setPassword(PROD, who, e[0]);
  check("C. the stored profile is what is ENFORCED: eight characters, and " +
        "a history of two", function () {
    assert.strictEqual(first.status, 200, first.raw.slice(0, 300));
    assert.strictEqual(reused.body.reason, "password-history",
                       reused.raw.slice(0, 300));
    assert.strictEqual(free.status, 200, free.raw.slice(0, 300));
  });
  const reset = await ok(PROD.api + "/policies/reset-password-policy",
                         { profile: "default" }, "reset the profile");
  const builtIn = await passwordView(PROD);
  const shortAgain = await setPassword(PROD, who, "e" + LETTERS.slice(0, 7));
  check("C. a reset removes the entry and the built-in defaults are back",
        function () {
    assert.strictEqual(reset.removed, true, JSON.stringify(reset));
    assert.strictEqual(builtIn.password.profile.stored, false);
    assert.strictEqual(builtIn.password.profile.minLength, 12);
    assert.strictEqual(shortAgain.body.reason, "password-policy");
  });
  log.debug("Leaving asEntry().");
}

// ---------------------------------------------------------------------------
// D. DEVELOPMENT, AND E. THE LDAP DOOR.
// ---------------------------------------------------------------------------
async function developmentAndLdap() {
  log.debug("Entering developmentAndLdap().");
  log.info("=== D. development ===");
  const dev = names.usernameFor("pwp-d");
  await person(DEV, dev, "Seed-" + STAMP + "-Passw0rd");
  const one = await setPassword(DEV, dev, "x");
  const same = await setPassword(DEV, dev, "x");
  check("D. DEVELOPMENT sets a one-character password, and the same again " +
        "(nothing is enforced there)", function () {
    assert.strictEqual(one.status, 200, one.raw.slice(0, 300));
    assert.strictEqual(same.status, 200, same.raw.slice(0, 300));
  });

  log.info("=== E. the LDAP door, in product ===");
  const who = names.usernameFor("pwp-e");
  const start = "Ldap-" + STAMP + "-Start-Passw0rd";
  const strong = "Ldap-" + STAMP + "-Strong-Passw0rd";
  await person(PROD, who, start);
  const self = await modifyAs(PROD, { who: who, password: start }, who,
                              strong);
  check("E. in product a person may not write their own userPassword over " +
        "LDAP (50)", function () {
    assert.ok(self.bound, "the person's own bind was refused " + self.code);
    assert.strictEqual(self.code, 50, self.message);
  });
  const opName = names.usernameFor("pwp-op");
  await person(PROD, opName, "Operator-" + STAMP + "-Passw0rd");
  await ok(PROD.api + "/rbac/grant", { username: opName, role: "write" },
           "granted Admin Write");
  const opApp = await ok(PROD.api + "/users/create-app-password",
    { user: opName, name: "ldap tool", doors: ["ldap"] },
    "made the operator's LDAP app password");
  const operator = { who: opName, password: opApp.appPassword };
  const weak = await modifyAs(PROD, operator, who, "short");
  const stillOld = await bind(PROD, who, start);
  check("E. an operator's ldapmodify of userPassword that breaks the " +
        "profile is a constraint violation (19), and nothing is written",
        function () {
    assert.ok(weak.bound, "the operator's bind was refused " + weak.code +
              " " + weak.message);
    assert.strictEqual(weak.code, 19, weak.message);
    assert.strictEqual(stillOld, 0, "the old password no longer binds");
  });
  const good = await modifyAs(PROD, operator, who, strong);
  const binds = await bind(PROD, who, strong);
  log.info("after an operator's LDAP write the password binds with " +
           "result " + binds);
  check("E. one that meets it is accepted", function () {
    assert.strictEqual(good.code, 0, good.message);
  });
  const reuse = await modifyAs(PROD, operator, who, strong);
  check("E. the current password sent in the CLEAR again meets its own " +
        "history (19)", function () {
    assert.strictEqual(reuse.code, 19, reuse.message);
  });
  // A value in this service's own stored form ($scrypt$…): a hash cannot be
  // checked against a policy. (An `{SSHA}` string is not a form this service
  // knows, so it would be taken as a clear password and judged as one.)
  const prehashed = await modifyAs(PROD, operator, who,
    "$scrypt$32768$8$1$" + Buffer.from("salt-" + STAMP).toString("base64") +
    "$" + Buffer.from("not-a-real-hash-" + STAMP).toString("base64"));
  check("E. a PRE-HASHED value is refused in product (19)", function () {
    assert.strictEqual(prehashed.code, 19, prehashed.message);
  });
  const twoValues = await new Promise(function (resolve) {
    const client = ldapClient();
    client.bind(personDn(PROD, operator.who), operator.password,
                function (e) {
      if (e) {
        close(client);
        resolve(e.code);
        return;
      }
      client.modify(personDn(PROD, who), new ldapjs.Change({
        operation: "add", modification: new ldapjs.Attribute({
          type: "userPassword",
          values: ["Another-" + STAMP + "-Passw0rd"] }) }), function (m) {
        close(client);
        resolve(m ? m.code : 0);
      });
    });
  });
  check("E. an ADD of a second userPassword is refused (19): two values " +
        "would leave the old password working", function () {
    assert.strictEqual(twoValues, 19, "result " + twoValues);
  });
  const made = await ok(PROD.api + "/users/create", {
    username: names.usernameFor("pwp-gen"), invent: false,
    credential: "generate",
    attributes: { cn: "PWP gen", givenName: "PWP", sn: "gen",
                  mail: "gen-" + STAMP + "@" + PROD.domain } },
    "created a person with a generated password");
  const madeBinds = await bind(PROD, made.username || made.user ||
                               names.usernameFor("pwp-gen"), made.password);
  const none = await ok(PROD.api + "/users/create", {
    username: names.usernameFor("pwp-none"), invent: false,
    credential: "none",
    attributes: { cn: "PWP none", givenName: "PWP", sn: "none",
                  mail: "none-" + STAMP + "@" + PROD.domain } },
    "created a person holding nothing");
  check("E. a create naming `credential: generate` answers a password that " +
        "meets the profile, to be changed first (an LDAPS bind with it is " +
        "49); `none` creates a person holding nothing", function () {
    assert.strictEqual(madeBinds, 49, "bind result " + madeBinds);
    assert.strictEqual(made.generated, true, JSON.stringify(made)
      .slice(0, 300));
    assert.ok([...String(made.password)].length >= 12, made.password);
    assert.strictEqual(none.password, undefined);
    assert.ok(!none.passwordSet, JSON.stringify(none).slice(0, 300));
  });
  log.debug("Leaving developmentAndLdap().");
}

// ---------------------------------------------------------------------------
// F. NAMED PROFILES.
// ---------------------------------------------------------------------------
async function named() {
  log.debug("Entering named().");
  log.info("=== F. named password policies ===");
  const STRICT = "strict-" + STAMP;
  const APPP = "appl-" + STAMP;
  const GROUP = "pwp-group-" + STAMP;
  const OTHER = "pwp-other-" + STAMP;
  const APP = "pwp-app-" + STAMP;
  const REDIRECT = passkeys.kit("sts_password_policy_rules").REDIRECT;
  const MEMBER = names.usernameFor("pwp-member");
  const LONE = names.usernameFor("pwp-lone");
  const SEED = "Seed-" + STAMP + "-Passw0rd";
  const view = await passwordView(NAMED);
  await ok(NAMED.api + "/policies/save-password-policy", profileOf(view,
    { profile: STRICT, precedence: 10, minLength: 24, history: 0,
      generatedLength: 32 }),
    "saved the strict profile");
  await ok(NAMED.api + "/policies/save-password-policy", profileOf(view,
    { profile: APPP, precedence: 50, minLength: 18, history: 0,
      generatedLength: 24 }),
    "saved the application's profile");
  const rank = await saveRefused(NAMED, profileOf(view,
    { profile: "rank-" + STAMP, precedence: "0" }), "STS-AUTHN-0108");
  const rank2 = await saveRefused(NAMED, profileOf(view,
    { profile: "rank-" + STAMP, precedence: "1001" }), "STS-AUTHN-0108");
  check("F. a precedence outside 1..1000 is refused (STS-AUTHN-0108)",
        function () {
    [rank, rank2].forEach(function (one) {
      assert.strictEqual(one.r.status, 400, one.r.raw.slice(0, 300));
      assert.ok(/precedence/.test(errorsOf(one.r)), errorsOf(one.r));
      assert.ok(one.got >= 1, "STS-AUTHN-0108 rows: " + one.got);
    });
  });
  await person(NAMED, MEMBER, SEED);
  await person(NAMED, LONE, SEED);
  await ok(NAMED.api + "/groups/create", { group: GROUP, members: [MEMBER] },
           "made the group");
  await ok(NAMED.api + "/groups/create", { group: OTHER, members: [MEMBER] },
           "made the other group");
  await ok(NAMED.api + "/groups/set-policy", { group: GROUP,
    attribute: "stsPasswordPolicy", policy: STRICT },
    "the group names the strict profile");
  await fixtures.publicClient(NAMED.api, APP, [REDIRECT]);
  await ok(NAMED.api + "/applications/set", { application: APP,
    attribute: "appPasswordPolicy", value: APPP },
    "the application names its profile");
  const wrongGroup = await postJson(NAMED.api + "/groups/set-policy",
    { group: OTHER, attribute: "stsPasswordPolicy", policy: "nope" });
  const wrongApp = await postJson(NAMED.api + "/applications/set",
    { application: APP, attribute: "appPasswordPolicy", value: "nope" });
  check("F. a name the realm does not hold is refused at both doors",
        function () {
    assert.strictEqual(wrongGroup.status, 400, wrongGroup.raw.slice(0, 300));
    assert.ok(/neither/.test(errorsOf(wrongGroup)), errorsOf(wrongGroup));
    assert.strictEqual(wrongApp.status, 400, wrongApp.raw.slice(0, 300));
  });
  const listed = await passwordView(NAMED);
  check("F. the view lists the named profiles and says what names each",
        function () {
    const text = JSON.stringify(listed.password.named || []) +
                 JSON.stringify(listed.password.references || []);
    assert.ok(text.indexOf(STRICT) >= 0 && text.indexOf(GROUP) >= 0,
              text.slice(0, 600));
    assert.ok(text.indexOf(APPP) >= 0 && text.indexOf(APP) >= 0,
              text.slice(0, 600));
  });
  await ok(base + "/admin-api/realms/set", { id: NAMED.id,
    key: "global.mode", value: "product" }, "switched to product");

  const twenty = "Twenty-" + STAMP + "-pass";
  const memberShort = await setPassword(NAMED, MEMBER, twenty);
  const loneSame = await setPassword(NAMED, LONE, twenty);
  const memberLong = await setPassword(NAMED, MEMBER,
                                       "Long-enough-" + STAMP + "-for-it");
  check("F. in product a group member's password is refused by the " +
        "group's profile, naming it, and the same password is set for a " +
        "person nothing names", function () {
    assert.strictEqual(memberShort.status, 400,
                       memberShort.raw.slice(0, 300));
    assert.ok(errorsOf(memberShort).indexOf('"' + STRICT + '"') >= 0,
              errorsOf(memberShort));
    assert.strictEqual(loneSame.status, 200, loneSame.raw.slice(0, 300));
    assert.strictEqual(memberLong.status, 200, memberLong.raw.slice(0, 300));
  });
  const generated = await ok(NAMED.api + "/users/set-password",
                             { user: MEMBER, generate: true }, "generated");
  const generatedLone = await ok(NAMED.api + "/users/set-password",
                                 { user: LONE, generate: true },
                                 "generated another");
  check("F. the generator is the person's profile's: 32 characters for the " +
        "group's member, the default 20 for a person nothing names",
        function () {
    assert.strictEqual([...generated.password].length, 32);
    assert.strictEqual([...generatedLone.password].length, 20);
  });

  // The forced change at the screen, for the application.
  const forced = await ok(NAMED.api + "/users/reset-password",
                          { user: LONE }, "reset LONE's password");
  const k = passkeys.kit("sts_password_policy_rules");
  const screen = await k.screen(NAMED, undefined, APP);
  const login = await authnSignin.submit(NAMED.base, screen.location,
    { action: "login", username: LONE, password: forced.password },
    { cookie: screen.cookie, screen: screen.opened,
      headers: { "User-Agent": AGENT } });
  check("F. the reset password signs in to the forced change", function () {
    assert.strictEqual(login.next, "password-change",
                       login.next + " " + JSON.stringify(login.json)
                         .slice(0, 300));
  });
  const cookie = authnSignin.foldCookies(screen.cookie, login.setCookies);
  const sixteen = "Sixteen-" + LETTERS.slice(0, 8);
  const tooShort = await authnSignin.changePassword(NAMED.base,
    login.location, { new_password: sixteen, confirm_password: sixteen },
    { cookie: cookie });
  check("F. the change for the application is decided by the " +
        "application's profile: " + [...sixteen].length + " characters " +
        "are refused, naming it", function () {
    assert.ok(tooShort.next !== "redirect" && tooShort.next !== "mfa",
              tooShort.next + " " + JSON.stringify(tooShort.json)
                .slice(0, 300));
    assert.ok(JSON.stringify(tooShort.json || {}).indexOf(APPP) >= 0,
              JSON.stringify(tooShort.json).slice(0, 400));
  });
  const longer = "Long-enough-for-the-app-" + STAMP;
  const changed = await authnSignin.changePassword(NAMED.base,
    login.location, { new_password: longer, confirm_password: longer },
    { cookie: cookie });
  check("F. and a password that meets it is taken", function () {
    assert.ok(changed.next === "redirect" || changed.next === "mfa" ||
              changed.next === "consent" || changed.status === 200,
              changed.next + " " + JSON.stringify(changed.json)
                .slice(0, 300));
    assert.ok(!changed.json || changed.json.ok !== false,
              JSON.stringify(changed.json).slice(0, 300));
  });

  // Both name one: at the same application's forced change, a member of
  // the strict group (precedence 10) is held to the group's profile over
  // the application's (precedence 50).
  await ok(NAMED.api + "/groups/add-member", { group: GROUP, member: LONE },
           "LONE joins the strict group");
  const again = await ok(NAMED.api + "/users/reset-password", { user: LONE },
                         "reset LONE's password again");
  const screen2 = await k.screen(NAMED, undefined, APP);
  const login2 = await authnSignin.submit(NAMED.base, screen2.location,
    { action: "login", username: LONE, password: again.password },
    { cookie: screen2.cookie, screen: screen2.opened,
      headers: { "User-Agent": AGENT } });
  const nineteen = "Twenty-chars-" + LETTERS.slice(0, 7);
  const both = await authnSignin.changePassword(NAMED.base,
    login2.location, { new_password: nineteen, confirm_password: nineteen },
    { cookie: authnSignin.foldCookies(screen2.cookie, login2.setCookies) });
  check("F. where a group and the application both name one, the lower " +
        "precedence applies: " + [...nineteen].length + " characters meet " +
        "the application's 18 and are refused by the group's 24",
        function () {
    assert.strictEqual(login2.next, "password-change", login2.next);
    assert.ok(both.next !== "redirect" && both.next !== "mfa",
              both.next + " " + JSON.stringify(both.json).slice(0, 300));
    assert.ok(JSON.stringify(both.json || {}).indexOf(STRICT) >= 0,
              JSON.stringify(both.json).slice(0, 400));
  });

  const before40 = await codeCount(NAMED, "STS-AUTHN-0540");
  const held = await postJson(NAMED.api + "/policies/reset-password-policy",
                              { profile: STRICT });
  const heldApp = await postJson(NAMED.api +
    "/policies/reset-password-policy", { profile: APPP });
  const got40 = await gained(NAMED, "STS-AUTHN-0540", before40);
  check("F. a named profile something names is not removed " +
        "(STS-AUTHN-0540), for a group and for an application",
        function () {
    assert.strictEqual(held.status, 400, held.raw.slice(0, 300));
    assert.ok(errorsOf(held).indexOf(GROUP) >= 0, errorsOf(held));
    assert.strictEqual(heldApp.status, 400, heldApp.raw.slice(0, 300));
    assert.ok(got40 >= 2, "STS-AUTHN-0540 rows: " + got40);
  });
  await ok(NAMED.api + "/groups/set-policy", { group: GROUP,
    attribute: "stsPasswordPolicy", policy: "" }, "unnamed it");
  const gone = await ok(NAMED.api + "/policies/reset-password-policy",
                        { profile: STRICT }, "removed the strict profile");
  check("F. once nothing names it, it is removed", function () {
    assert.strictEqual(gone.removed, true, JSON.stringify(gone));
  });
  const elsewhere = await passwordView(DEV);
  check("F. another realm does not inherit a named profile", function () {
    const there = (elsewhere.profiles || []).filter(function (p) {
      return p.kind === "password";
    }).map(function (p) {
      return p.name;
    });
    assert.deepStrictEqual(there, ["default"]);
  });
  log.debug("Leaving named().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " in realms of this job's own (" + STAMP +
           ").");
  await makeRealm(PROD, "product");
  await makeRealm(DEV, "development");
  await makeRealm(NAMED, "development");
  await defaults();
  await asEntry();
  await developmentAndLdap();
  await named();
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
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
  for (const realm of [PROD, DEV, NAMED]) {
    const r = await postJson(base + "/admin-api/realms/remove",
                             { id: realm.id });
    log.info("removed the realm " + realm.id + " (" + r.status + ")");
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
    log.warn("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("sts_password_policy_rules FAILED: " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
