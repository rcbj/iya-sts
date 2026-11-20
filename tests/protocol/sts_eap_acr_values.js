// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_eap_acr_values.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT EAP ACR VALUES 1.0 — `phr` AND `phrh` — REQUESTED, EARNED
// AND ASSERTED, OVER THE WIRE (#723, #739).
//
// D12 (#444): carries over section E of `tests/eap_acr_values.js` and the
// parts of B and C a relying party sees. In a development realm of its own,
// passkeys registered at the portal (`/account-api/keys`) by this job's
// software authenticator (`passkey_wire_kit.js`), sign-ins at the screen
// and the passkey step, and the ID Token's `acr` read at the token endpoint:
//
//   E1. discovery publishes `phr` and `phrh` in `acr_values_supported`;
//   E2. a passkey sign-in that asks for nothing carries `acr` "1";
//   E3a. `acr_values=phr`: the screen demands a key, and the passkey
//        sign-in's ID Token carries `acr` "phr";
//   E3c. `acr_values=phrh` with only an UNATTESTED device-bound key: refused
//        before the ceremony, no code issued (STS-AUTHN-0459) — an
//        unattested key earns `phr` only;
//   E4. a password with the person's security key as the step, under `phr`,
//       carries `acr` "phr" and `amr` with `pwd`;
//   E5a. a synced passkey carries `phr`; E5b. under `phrh` it is refused
//        before the ceremony (STS-AUTHN-0459);
//   E6a. a password-only person under `phr` is not let through on the
//        password: the screen demands a key and no code is issued;
//   E6b. that person's password session returning under the round-trip
//        marker is refused `unmet_authentication_requirements`
//        (STS-OAUTH-0970), naming a phishing-resistant authentication.
//
// NOT carried, and why: E3b (`phrh` EARNED) needs a key whose attestation
// chains to an anchor the realm trusts; the in-process file writes that
// record as a fixture, and a chain this job could present is the passkey
// attestation family's (owed with `sts_webauthn_attestation`); E7 (the
// issuance policy's `requirePhishingResistant`) is a template option no
// `/admin-api` operation sets (owed with the XACML family, phase 8); A, B,
// C1–C7 and D (the evidence table, what meets what, the PDP's requests) and
// C8 (allowCredentials narrowed for `phrh`, read off the step's own view
// with trusted attestation records) are library questions or need the same
// trusted record (class (d) / owed as above); STS-OAUTH-0971 (`phrh` asked
// of a `phr` sign-in) needs a `phr` session returning under `phrh`, which
// the screen refuses earlier (STS-AUTHN-0459) for every key this job can
// make.
//
// OWNED HERE (local: true): this repository's own sign-in and provider.
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
var log = bunyan.createLogger({ name: "sts_eap_acr_values",
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
const PASSWORD = "Eap-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-9a!";
// A desktop browser's User-Agent with this job's name on the end: risk
// scoring reads a bare job name as an automated client, and product refuses
// a first sign-in from one (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_eap_acr_values/1.0 (" + STAMP + ")";

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


const wire = require("./passkey_wire_kit.js");
const portalSignin = require("./portal_signin.js");

const k = wire.kit("sts_eap_acr_values", { log: log });
const RP = "eap-rp-" + STAMP;
const REDIRECT = "https://rp-" + STAMP + ".eap.example/cb";
const HEADERS = { "User-Agent": AGENT };
let REALM = "";

function jarFrom(b, cookieHeader) {
  log.debug("Entering jarFrom().");
  String(cookieHeader || "").split(/;\s*/).forEach(function (pair) {
    const at = pair.indexOf("=");
    if (at > 0) {
      b.jar[pair.slice(0, at)] = pair.slice(at + 1);
    }
  });
  log.debug("Leaving jarFrom().");
}

// One sign-in: the request (with `extra`), the screen, a password or
// `webauthn_only`, the passkey step where one follows (`key`), and the way
// back. `{ page, answer, final, params, claims, b }`.
async function signIn(who, how, key, extra, given) {
  log.debug("Entering signIn(). " + who + " " + how);
  const b = given || browser();
  const p = pkce();
  const first = await b.go("GET", realmBase(REALM) + "/oauth2/authorize?" +
    form(Object.assign({ client_id: RP, response_type: "code",
      redirect_uri: REDIRECT, scope: "openid", state: "s",
      nonce: "n" + nodeCrypto.randomBytes(8).toString("hex"),
      code_challenge: p.challenge, code_challenge_method: "S256" },
    extra || {})));
  const out = { b: b, first: first, page: null, answer: null,
                final: first, params: null, claims: null };
  if (sentToSignIn(first)) {
    const at = new URL(first.location, realmBase(REALM) + "/").toString();
    const page = await authnSignin.screen(realmBase(REALM), at,
      { cookie: b.cookie(), headers: HEADERS });
    out.page = page;
    let answer = await authnSignin.submit(realmBase(REALM), at,
      { action: "login", username: who,
        password: how === "passkey" ? "" : PASSWORD,
        webauthn_only: how === "passkey" ? "1" : "" },
      { screen: page, cookie: page.cookie, headers: HEADERS });
    if (key && answer.next === "mfa" && answer.location) {
      const st = await authnSignin.step(answer.location,
        { cookie: answer.cookie, headers: HEADERS });
      answer = await authnSignin.passkeyStep(st, function (c) {
        return key.assert(c.challenge);
      }, { headers: HEADERS });
    }
    out.answer = answer;
    jarFrom(b, answer.cookie);
    if (answer.next === "redirect" && answer.location) {
      out.final = await b.go("GET", answer.location);
      if (/\/oauth2\/authorize\?/.test(out.final.location)) {
        out.final = await b.go("GET", new URL(out.final.location,
          realmBase(REALM) + "/").toString());
      }
    } else {
      out.final = { status: answer.status, location: "",
                    text: JSON.stringify(answer.json || {}) };
    }
  }
  if (urls.isAt(out.final.location, REDIRECT)) {
    out.params = new URL(out.final.location).searchParams;
    if (out.params.get("code")) {
      const t = await send(realmBase(REALM) + "/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ grant_type: "authorization_code",
          code: out.params.get("code"), redirect_uri: REDIRECT,
          client_id: RP, code_verifier: p.verifier }) });
      out.claims = t.body && t.body.id_token ? decode(t.body.id_token)
        : null;
    }
  }
  out.shown = (out.answer ? out.answer.status + " " + out.answer.next +
    " " + JSON.stringify(out.answer.errors || []).slice(0, 200) + " " : "") +
    out.final.status + " " + out.final.location.slice(0, 200) + " " +
    JSON.stringify(out.claims || {}).slice(0, 200);
  log.debug("Leaving signIn(). " + out.shown);
  return out;
}

function demandsKey(r) {
  log.debug("Entering demandsKey().");
  const v = (r.page && r.page.view) || {};
  log.debug("Leaving demandsKey().");
  return !!(v.demands && v.demands.key === true);
}

async function enrolled(who, options) {
  log.debug("Entering enrolled(). " + who);
  await createPerson(REALM, who);
  const portal = await portalSignin.signInToThePortal(realmBase(REALM), who,
    null, { password: PASSWORD });
  const key = k.authenticator(options || {});
  const e = await k.enrol(portal, key, {});
  must(e.done && e.done.status === 200, "enrolling " + who + ": " +
       JSON.stringify(e.done && e.done.json).slice(0, 300));
  log.debug("Leaving enrolled().");
  return key;
}

async function test() {
  log.debug("Entering test().");
  REALM = await makeRealm("eap", "development");
  await apiOk(REALM, "/applications/create", { identifier: RP, name: RP,
    kind: "oauth2-client", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [RP], oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code"],
              oauthResponseType: ["code"], oauthAllowedScope: ["openid"],
              oauthTokenEndpointAuthMethod: "none" } }, "the client");
  await apiOk(REALM, "/consent/grant-global-consent",
              { client: RP, scope: "openid" }, "consented openid");
  const erin = names.usernameFor("eape");
  const carol = names.usernameFor("eapc");
  const dave = names.usernameFor("eapd");
  const bob = names.usernameFor("eapb");
  const erinKey = await enrolled(erin, {});
  const carolKey = await enrolled(carol, { synced: true });
  const daveKey = await enrolled(dave, {});
  await createPerson(REALM, bob);

  log.info("=== E1. discovery ===");
  const doc = await send(realmBase(REALM) +
                         "/.well-known/openid-configuration");
  await check("E1. discovery publishes phr and phrh in acr_values_supported",
              async function () {
    const s = (doc.body && doc.body.acr_values_supported) || [];
    expect(s.indexOf("phr") >= 0 && s.indexOf("phrh") >= 0,
           JSON.stringify(s));
  });

  log.info("=== E2, E3. a device-bound passkey ===");
  let r = await signIn(erin, "passkey", erinKey);
  await check("E2. a passkey sign-in that asks for nothing carries acr " +
              "\"1\"", async function () {
    expect(r.claims && r.claims.acr === "1", r.shown);
  });
  r = await signIn(erin, "passkey", erinKey, { acr_values: "phr" });
  await check("E3a. acr_values=phr: the screen demands a key, and the " +
              "passkey sign-in's ID Token carries acr \"phr\"",
              async function () {
    expect(demandsKey(r), JSON.stringify((r.page && r.page.view &&
      r.page.view.demands) || {}));
    expect(r.claims && r.claims.acr === "phr", r.shown);
  });
  let before = await codeCount(REALM, "STS-AUTHN-0459");
  r = await signIn(erin, "passkey", erinKey, { acr_values: "phrh" });
  let coded = await newRowWith(REALM, "STS-AUTHN-0459", before);
  await check("E3c. acr_values=phrh with only an unattested device-bound " +
              "key is refused before the ceremony, saying why, and no code " +
              "is issued (STS-AUTHN-0459)", async function () {
    expect(!(r.params && r.params.get("code")), r.shown);
    expect(/hardware-protected/.test(r.shown), r.shown);
    expect(coded, "no STS-AUTHN-0459 row");
  });

  log.info("=== E4. a password and a security key ===");
  r = await signIn(dave, "password", daveKey, { acr_values: "phr" });
  await check("E4. a password with the person's security key as the step " +
              "carries acr \"phr\", and amr names the password",
              async function () {
    expect(r.claims && r.claims.acr === "phr" &&
           (r.claims.amr || []).indexOf("pwd") >= 0, r.shown);
  });

  log.info("=== E5. a synced passkey ===");
  r = await signIn(carol, "passkey", carolKey, { acr_values: "phr" });
  await check("E5a. a synced passkey carries acr \"phr\"", async function () {
    expect(r.claims && r.claims.acr === "phr", r.shown);
  });
  before = await codeCount(REALM, "STS-AUTHN-0459");
  r = await signIn(carol, "passkey", carolKey, { acr_values: "phrh" });
  coded = await newRowWith(REALM, "STS-AUTHN-0459", before);
  await check("E5b. under phrh a synced passkey is refused before the " +
              "ceremony, and no code is issued (STS-AUTHN-0459)",
              async function () {
    expect(!(r.params && r.params.get("code")) &&
           /hardware-protected/.test(r.shown), r.shown);
    expect(coded, "no STS-AUTHN-0459 row");
  });

  log.info("=== E6. a password-only person ===");
  r = await signIn(bob, "password", null, { acr_values: "phr" });
  await check("E6a. under phr a password alone is not let through: the " +
              "screen demands a key, and no code is issued",
              async function () {
    expect(demandsKey(r), JSON.stringify((r.page && r.page.view &&
      r.page.view.demands) || {}));
    expect(!(r.params && r.params.get("code")), r.shown);
  });
  const plain = await signIn(bob, "password", null);
  must(plain.claims && plain.claims.acr === "1", "a password session for " +
       "bob: " + plain.shown);
  before = await codeCount(REALM, "STS-OAUTH-0970");
  const again = await signIn(bob, "password", null,
    { acr_values: "phr", step_up_honoured: "1" }, plain.b);
  coded = await newRowWith(REALM, "STS-OAUTH-0970", before);
  await check("E6b. that session returning under the round-trip marker is " +
              "refused unmet_authentication_requirements, naming a " +
              "phishing-resistant authentication (STS-OAUTH-0970)",
              async function () {
    expect(again.params && again.params.get("error") ===
           "unmet_authentication_requirements" &&
           /phishing-resistant/.test(String(again.params
             .get("error_description"))), again.shown);
    expect(coded, "no STS-OAUTH-0970 row");
  });
  log.debug("Leaving test().");
}

main();
