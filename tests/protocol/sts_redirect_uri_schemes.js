// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_redirect_uri_schemes.js
//
// ---------------------------------------------------------------------------
// WHICH ADDRESSES AN OAUTH REDIRECT MAY BE, IN EVERY MODE, OVER THE WIRE.
//
// D12 (#444): carries over `tests/redirect_uri_schemes.js`. The rule is
// `common/validation.js`'s allowlist — http(s) with a host, or a private-use
// scheme (RFC 8252 section 7.1) containing a period — and it is asked here of
// the doors a client and an administrator reach, in a development realm and
// a product realm of its own:
//
//   A. RFC 7591 REGISTRATION (dynamic registration opened in the realm):
//      seven usable addresses registered, ten refused
//      invalid_redirect_uri (STS-REG-0070 off the audit log) — among them
//      the two typing mistakes `localhost:3000/cb` and `https:/cb`, an
//      executable scheme, a protocol handler on no blocklist and a
//      fragment; a private-use frontchannel_logout_uri refused
//      invalid_client_metadata while a private-use
//      post_logout_redirect_uri is taken.
//   B. THE MANAGEMENT API'S WRITES: a create naming `myapp:/cb` refused
//      (STS-REG-0071); on an entry holding a LEGACY unusable address (put
//      there over LDAP, the one way past the write checks), an add of
//      `ms-msdt:/x` refused, an add of a usable address taken, and the
//      legacy value still removable; a private-use front-channel URI
//      refused.
//   C. THE FRONT-CHANNEL URI'S ORIGIN: one on no redirect URI's origin
//      refused (STS-REG-0171, Front-Channel Logout section 2); a usable one
//      written; and a set of the value already on the entry (a `javascript:`
//      planted over LDAP) not refused, since nothing is being added.
//
// NOT carried, and why: the zod type and isPrivateUseRedirect() as
// functions (class (d)); the front-channel page declining to frame a stored
// unusable URI is `sts_frontchannel_logout.js`'s section f, over the wire
// already.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

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
var log = bunyan.createLogger({ name: "sts_redirect_uri_schemes",
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

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
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
  return { status: r.status, body: body, raw: raw, headers: r.headers,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

function postForm(url, fields, headers) {
  log.debug("Entering postForm().");
  log.debug("Leaving postForm().");
  return send(url, { method: "POST",
    headers: Object.assign({ "Content-Type":
                               "application/x-www-form-urlencoded" },
                           headers || {}),
    body: form(fields) });
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

// How many rows of a realm's audit log carry `code`, waited for until there
// are more than `above` (default 0): the row is written as the refusal is
// sent, and a code is recorded, never sent.
async function codeCount(realm, code, above) {
  log.debug("Entering codeCount(). " + code);
  const floor = Number(above || 0);
  let n = 0;
  for (let i = 0; i < 20; i += 1) {
    const r = await send(base + "/realm/" + realm + "/admin-api/audit" +
                         "?per=500&code=" + encodeURIComponent(code));
    n = Number((r.body && r.body.matched) || 0);
    if (n > floor) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving codeCount(). " + n);
  return n;
}

async function createRealm(id, mode, what) {
  log.debug("Entering createRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: what + " " + STAMP },
    "created the realm " + id);
  if (mode) {
    await ok(base + "/admin-api/realms/set", { id: id, key: "global.mode",
                                               value: mode },
             "put " + id + " in " + mode + " mode");
  }
  log.debug("Leaving createRealm().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made — each id
// carries the run's STAMP — is removed at the end, pass or fail. A suite run
// leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const listed = await send(base + "/admin-api/realms?per=500");
  const mine = ((listed.body && listed.body.realms) || []).filter(
    function (one) {
      return one.id !== "default" && one.id.indexOf(STAMP) >= 0;
    });
  for (const one of mine) {
    const r = await postJson(base + "/admin-api/realms/remove",
                             { id: one.id });
    log.info("removed the realm " + one.id + " (" + r.status + ")");
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
    // A failed removal is not the job's verdict.
    log.info("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

const DEV = "rus-" + STAMP;
const PROD = "rusp-" + STAMP;
const ACCEPTED = [
  "https://client.example/cb",
  "http://127.0.0.1:51004/oauth2redirect",
  "http://[::1]:61023/cb",
  "http://localhost:3000/cb",
  "com.example.app:/oauth2redirect/example-provider",
  "com.example.app://callback",
  "net.example-client.app+beta:/cb"
];
const REFUSED = [
  ["localhost:3000/cb", "typed without http:// — parses as scheme localhost"],
  ["myapp:/cb", "a private-use scheme with no period"],
  ["javascript:alert(1)", "an executable scheme"],
  ["data:text/html,<script>", "an executable scheme"],
  ["ms-msdt:/id", "a protocol handler on no blocklist"],
  ["intent://x#Intent;end", "a protocol handler, and a fragment"],
  ["https:/cb", "https with one slash — a parser invents a host"],
  ["https:///cb", "https with no host"],
  ["https://client.example/cb#frag", "a fragment"],
  ["not a uri", "not an absolute URI"]
];

function register(realm, metadata) {
  log.debug("Entering register().");
  log.debug("Leaving register().");
  return postJson(base + "/realm/" + realm + "/oauth2/register",
                  Object.assign({ token_endpoint_auth_method: "none",
                                  grant_types: ["authorization_code"],
                                  response_types: ["code"] }, metadata));
}

// One LDAP operation in `realm`'s tree, bound as a person of that realm (a
// development realm authorizes no write, so a person may write any entry —
// the way an `ldapmodify` puts a value past every door that checks).
function ldapModify(realm, filter, change) {
  log.debug("Entering ldapModify().");
  const ldap = require("ldapjs");
  const suffix = (realm + ".example.net").split(".").map(function (label) {
    return "dc=" + label;
  }).join(",");
  return new Promise(function (resolve, reject) {
    const client = ldap.createClient({ url: "ldap://" +
      new URL(base).hostname + ":" + (process.env.STS_LDAP_PORT || "389"),
      reconnect: false });
    // An error handler is not optional: a socket the server closes would
    // otherwise throw out of the client and take the job down.
    client.on("error", function (e) {
      log.debug("ldap client error: " + ((e && e.message) || e));
    });
    const fail = function (e) {
      client.unbind();
      log.debug("Leaving ldapModify(). Failed.");
      reject(e);
    };
    client.bind("uid=rus-binder," + "ou=users," + suffix, "x-" + STAMP,
                function (err) {
      if (err) {
        fail(err);
        return;
      }
      const found = [];
      client.search("ou=applications," + suffix,
                    { scope: "sub", filter: filter, attributes: ["dn"] },
                    function (e2, res) {
        if (e2) {
          fail(e2);
          return;
        }
        res.on("searchEntry", function (entry) {
          found.push(String(entry.objectName || entry.dn));
        });
        res.on("error", fail);
        res.on("end", function () {
          if (found.length !== 1) {
            fail(new Error("the filter " + filter + " found " +
                           found.length + " entries"));
            return;
          }
          client.modify(found[0], new ldap.Change(change), function (e3) {
            if (e3) {
              fail(e3);
              return;
            }
            client.unbind();
            log.debug("Leaving ldapModify().");
            resolve(found[0]);
          });
        });
      });
    });
  });
}

async function registration(realm) {
  log.debug("Entering registration(). " + realm);
  log.info("=== A. RFC 7591 registration in " + realm + " ===");
  const before = await codeCount(realm, "STS-REG-0070");
  for (const uri of ACCEPTED) {
    const r = await register(realm, { redirect_uris: [uri] });
    check("A. " + realm + ": registered with the redirect URI " + uri,
          function () {
      assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
    });
  }
  for (const pair of REFUSED) {
    const r = await register(realm, { redirect_uris: [pair[0]] });
    check("A. " + realm + ": refused invalid_redirect_uri: " +
          JSON.stringify(pair[0]) + " (" + pair[1] + ")", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.strictEqual(r.body.error, "invalid_redirect_uri",
                         r.raw.slice(0, 300));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), r.raw.slice(0, 300));
    });
  }
  // NODE DEFECT, PINNED: the allowlist refuses the empty string, but in a
  // DEVELOPMENT realm the registration endpoint takes `redirect_uris: [""]`,
  // answering 201 and echoing [""] back; a product realm refuses it through
  // RFC 9700 mode's absolute-URI check. The wire is asserted; the defect is
  // listed in the D12 notes.
  const empty = await register(realm, { redirect_uris: [""] });
  const product = realm === PROD;
  check("A. " + realm + ": " + (product
    ? "an empty redirect URI is refused invalid_redirect_uri"
    : "PINNED DEFECT — an empty redirect URI is registered (201, echoed " +
      "back), where the allowlist refuses it"), function () {
    if (product) {
      assert.strictEqual(empty.status, 400, empty.raw.slice(0, 300));
      assert.strictEqual(empty.body.error, "invalid_redirect_uri");
    } else {
      assert.strictEqual(empty.status, 201, empty.raw.slice(0, 300));
      assert.deepStrictEqual(empty.body.redirect_uris, [""]);
    }
  });
  const mixed = await register(realm, { redirect_uris:
    ["https://ok.example/cb", "javascript:alert(1)"] });
  check("A. " + realm + ": one unusable address among usable ones refuses " +
        "the registration", function () {
    assert.strictEqual(mixed.status, 400, mixed.raw.slice(0, 300));
    assert.strictEqual(mixed.body.error, "invalid_redirect_uri");
  });
  const after = await codeCount(realm, "STS-REG-0070",
                                before + REFUSED.length);
  check("A. " + realm + ": each refusal is recorded STS-REG-0070",
        function () {
    assert.ok(after >= before + REFUSED.length + 1, before + " -> " + after);
  });
  const front = await register(realm, {
    redirect_uris: ["com.example.app:/cb"],
    frontchannel_logout_uri: "com.example.app:/fc" });
  check("A. " + realm + ": a private-use frontchannel_logout_uri is refused " +
        "invalid_client_metadata — a browser frames it", function () {
    assert.strictEqual(front.status, 400, front.raw.slice(0, 300));
    assert.strictEqual(front.body.error, "invalid_client_metadata",
                       front.raw.slice(0, 300));
  });
  const native = await register(realm, {
    redirect_uris: ["com.example.app:/cb"],
    post_logout_redirect_uris: ["com.example.app:/bye"] });
  check("A. " + realm + ": a native application registers private-use " +
        "redirect and sign-out addresses", function () {
    assert.strictEqual(native.status, 201, native.raw.slice(0, 300));
  });
  log.debug("Leaving registration().");
}

async function registerWrites(realm) {
  log.debug("Entering registerWrites(). " + realm);
  log.info("=== B, C. the management API's writes in " + realm + " ===");
  const API = base + "/realm/" + realm + "/admin-api";
  const bad = await postJson(API + "/applications/create", {
    identifier: "rus-bad-" + STAMP, protocols: ["oauth2"],
    fields: { oauthClientId: "rus-bad-" + STAMP,
              oauthRedirectUri: ["myapp:/cb"] } });
  const c71 = await codeCount(realm, "STS-REG-0071");
  check("B. a create with an unusable redirect URI is refused STS-REG-0071",
        function () {
    assert.strictEqual(bad.status, 400, bad.raw.slice(0, 300));
    assert.ok(c71 >= 1, String(c71));
  });
  const id = "rus-app-" + STAMP;
  await ok(API + "/applications/create", { identifier: id,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: id,
              oauthRedirectUri: ["https://rp.example/cb"] } },
    "created " + id);
  await ok(API + "/users/create", { username: "rus-binder", invent: false,
    credential: "password", password: "x-" + STAMP,
    attributes: { cn: "rus binder", sn: "binder" } }, "created a binder");
  await ldapModify(realm, "(oauthClientId=" + id + ")",
    { operation: "add", modification: { type: "oauthRedirectUri",
                                        values: ["myapp:/legacy"] } });
  const held = await send(API + "/applications?application=" + id);
  const entry = (held.body && (held.body.application || held.body)) || {};
  check("B. fixture: a legacy unusable address sits on the entry, put " +
        "there over LDAP", function () {
    assert.ok([].concat((entry.fields || {}).oauthRedirectUri || [])
      .indexOf("myapp:/legacy") >= 0, JSON.stringify(entry.fields || {})
      .slice(0, 300));
  });
  const addBad = await postJson(API + "/applications/add",
    { application: id, attribute: "oauthRedirectUri", value: "ms-msdt:/x" });
  const c71b = await codeCount(realm, "STS-REG-0071", c71);
  check("B. an ADD of an unusable address is refused STS-REG-0071",
        function () {
    assert.strictEqual(addBad.status, 400, addBad.raw.slice(0, 300));
    assert.ok(c71b > c71, c71 + " -> " + c71b);
  });
  const addGood = await postJson(API + "/applications/add",
    { application: id, attribute: "oauthRedirectUri",
      value: "com.example.rus:/cb" });
  check("B. an add of a usable address succeeds beside the legacy value — " +
        "only what is added is checked", function () {
    assert.strictEqual(addGood.status, 200, addGood.raw.slice(0, 300));
  });
  const removed = await postJson(API + "/applications/remove",
    { application: id, attribute: "oauthRedirectUri",
      value: "myapp:/legacy" });
  check("B. and the legacy value can still be REMOVED", function () {
    assert.strictEqual(removed.status, 200, removed.raw.slice(0, 300));
  });
  const frontBad = await postJson(API + "/applications/set",
    { application: id, attribute: "oauthFrontchannelLogoutUri",
      value: "com.example.rus:/fc" });
  check("B. a private-use front-channel logout URI is refused", function () {
    assert.strictEqual(frontBad.status, 400, frontBad.raw.slice(0, 300));
  });
  const offOrigin = await postJson(API + "/applications/set",
    { application: id, attribute: "oauthFrontchannelLogoutUri",
      value: "https://elsewhere.example/fc" });
  const c171 = await codeCount(realm, "STS-REG-0171");
  check("C. a front-channel URI on no redirect URI's origin is refused " +
        "STS-REG-0171 (section 2)", function () {
    assert.strictEqual(offOrigin.status, 400, offOrigin.raw.slice(0, 300));
    assert.ok(c171 >= 1, String(c171));
  });
  const goodSet = await postJson(API + "/applications/set",
    { application: id, attribute: "oauthFrontchannelLogoutUri",
      value: "https://rp.example/fc" });
  check("C. one on a redirect URI's origin is written", function () {
    assert.strictEqual(goodSet.status, 200, goodSet.raw.slice(0, 300));
  });
  await ldapModify(realm, "(oauthClientId=" + id + ")",
    { operation: "replace", modification: {
      type: "oauthFrontchannelLogoutUri", values: ["javascript:alert(1)"] } });
  const resaved = await postJson(API + "/applications/set",
    { application: id, attribute: "oauthFrontchannelLogoutUri",
      value: "javascript:alert(1)" });
  check("C. a set of the value already on the entry is not refused — a " +
        "form posting its whole state back adds nothing", function () {
    assert.strictEqual(resaved.status, 200, resaved.raw.slice(0, 300));
  });
  log.debug("Leaving registerWrites().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Redirect URI schemes at " + base);
  await createRealm(DEV, "development", "Redirect URI schemes");
  await createRealm(PROD, "product", "Redirect URI schemes (product)");
  for (const realm of [DEV, PROD]) {
    await ok(base + "/admin-api/realms/set", { id: realm,
      key: "oauth2.openRegistration", value: "true" },
      "opened dynamic registration in " + realm);
    await registration(realm);
  }
  await registerWrites(DEV);
  assert.ok(checks >= 50, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.debug("Leaving test().");
}

main();
