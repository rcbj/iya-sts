// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_public_clients_product.js
//
// ---------------------------------------------------------------------------
// PUBLIC CLIENTS IN A PRODUCT REALM, OVER THE WIRE.
//
// D12 (#444): carries over `tests/public_clients_product.js`. Product mode
// allows a client that cannot keep a secret because it IMPLIES RFC 9700
// mode, so what a confidential client proves with a credential a public
// client proves with PKCE, an exactly matched redirect URI and a refresh
// token that rotates. In a realm of its own, made in development (for 8c's
// one LDAP write) and switched to product through the root API before any
// flow (`oauth2.rfc9700` and `oauth2.oauth21` left off):
//
//   0. /oauth2/rfc9700 reports the mode on, by the implication;
//   1. a PUBLIC client created by hand (no secret, so the create writes
//      `none`) completes the code flow and redeems its code presenting no
//      credential;
//   6. the code-flow ID Token carries no profile or email claim (OIDC Core
//      5.4) and its sub is the person's urn:uuid:<entryUUID>; UserInfo
//      answers family_name and email from the directory, email_verified
//      true for the address the administrator's create verified (#64; the
//      units file's unverified person read false); a second person gets
//      none of them in the ID Token either;
//   7. the refresh token rotates and the spent one is refused invalid_grant;
//   2. without PKCE, and with plain PKCE, the same client is refused;
//   3. the client credentials grant is refused to it unauthorized_client,
//      and registering that combination is refused;
//   4. a CONFIDENTIAL client presenting no credential is still 401
//      invalid_client, and with its secret is issued tokens;
//   8. the create's method: none with no credential, client_secret_basic
//      with a secret, an explicit one kept; and an entry that declares NO
//      method (its method removed over LDAP) is not called public — 401,
//      STS-OAUTH-0553 off the audit log.
//
// NOT carried (class (d)): `declaredPublic()` and `isConfidential()` as
// functions (0b, 0c) — their difference is what 8 observes on the wire.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

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
var log = bunyan.createLogger({ name: "sts_public_clients_product",
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

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

// One browser, with a cookie jar, following nothing by itself.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers, body: body });
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
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

// Follows redirects inside this service, signing `who` in on the screen
// over `/authn-api` and allowing a consent screen, until the answer leaves
// the service or is a page.
async function follow(realm, b, first, who, password) {
  log.debug("Entering follow().");
  let r = first;
  for (let i = 0; i < 12; i++) {
    if (!(r.status === 302 || r.status === 303)) {
      break;
    }
    const where = absolute(r.location);
    if (where.indexOf(base) !== 0) {
      break;
    }
    if (/\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(where) && who) {
      const posted = await authnSignin.signInWithJar(base + "/realm/" +
        realm, where, { action: "login", username: who,
                        password: password }, b.jar);
      assert.ok(posted.answer.view, "the sign-in screen: " +
                posted.answer.status + " " +
                JSON.stringify(posted.answer.json));
      r = posted;
      continue;
    }
    if (authnSignin.isConsent(where)) {
      r = await authnSignin.consentWithJar(where, "allow", b.jar);
      continue;
    }
    r = await b.go("GET", where);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
                      .toString("utf8"));
}

const REALM = "pcp-" + STAMP;
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const REDIRECT = "https://rp.pcp.example.test/cb";
const PASSWORD = "Pcp-Passw0rd!-" + String(Date.now()).slice(-6);
const SECRET = "pcp-secret-" + nodeCrypto.randomBytes(12).toString("hex");
const ALICE = names.usernameFor("pcp-alice");
const BARE = names.usernameFor("pcp-bare");

async function codeFlow(clientId, who, extra) {
  log.debug("Entering codeFlow(). " + clientId);
  const b = browser();
  const p = pkce();
  const first = await b.go("GET", RB + "/oauth2/authorize?" + form(
    Object.assign({ client_id: clientId, response_type: "code",
      redirect_uri: REDIRECT, scope: "openid profile email",
      state: "st-" + nodeCrypto.randomBytes(6).toString("hex"),
      nonce: "n-" + nodeCrypto.randomBytes(8).toString("hex"),
      code_challenge: p.challenge, code_challenge_method: "S256" },
                  extra || {})));
  const done = await follow(REALM, b, first, who, PASSWORD);
  let code = null;
  if ((done.status === 302 || done.status === 303) &&
      String(done.location).indexOf(REDIRECT) === 0) {
    code = new URL(done.location).searchParams.get("code");
  }
  log.debug("Leaving codeFlow().");
  return { first: first, final: done, code: code, verifier: p.verifier,
           browser: b };
}

function token(fields, headers) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return postForm(RB + "/oauth2/token", fields, headers);
}

async function methodOf(id) {
  log.debug("Entering methodOf(). " + id);
  const r = await send(API + "/applications?application=" + id);
  const entry = (r.body && (r.body.application || r.body)) || {};
  const value = (entry.fields || {}).oauthTokenEndpointAuthMethod;
  log.debug("Leaving methodOf().");
  return String([].concat(value === undefined ? [] : value)[0] || "");
}

// One LDAP modify of an application entry in the realm, bound as a person
// of it while the realm is still in development (which authorizes no
// write) — the way an `ldapmodify` takes a value off past every door.
function ldapModifyApplication(clientId, change) {
  log.debug("Entering ldapModifyApplication().");
  const ldap = require("ldapjs");
  const suffix = (REALM + ".example.net").split(".").map(function (label) {
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
      log.debug("Leaving ldapModifyApplication(). Failed.");
      reject(e);
    };
    client.bind("uid=" + LDAP_ADMIN + ",ou=users," + suffix, PASSWORD,
                function (err) {
      if (err) {
        fail(err);
        return;
      }
      const found = [];
      client.search("ou=applications," + suffix, { scope: "sub",
        filter: "(oauthClientId=" + clientId + ")", attributes: ["dn"] },
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
              fail(new Error(found.length + " entries for " + clientId));
              return;
            }
            client.modify(found[0], new ldap.Change(change), function (e3) {
              if (e3) {
                fail(e3);
                return;
              }
              client.unbind();
              log.debug("Leaving ldapModifyApplication().");
              resolve(found[0]);
            });
          });
        });
    });
  });
}

const LDAP_ADMIN = names.usernameFor("pcp-dirwriter");

async function test() {
  log.debug("Entering test().");
  log.info("Public clients in a product realm at " + RB);
  // THE REALM STARTS IN DEVELOPMENT, so the one LDAP write below (8c's
  // method taken off an entry, past every door that checks) needs no
  // directory administrator, and is switched to product before any flow.
  await createRealm(REALM, "development", "Public clients");
  await ok(base + "/admin-api/realms/set", { id: REALM,
    key: "authn.allowOptionalSecondFactor", value: "true" },
    "let a password alone sign people in");
  await ok(base + "/admin-api/realms/set", { id: REALM,
    key: "oauth2.openRegistration", value: "true" },
    "opened dynamic registration");
  await ok(API + "/users/create", { username: ALICE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Alice Public", givenName: "Alice", sn: "Public",
                  mail: "alice@pcp.example" } }, "created " + ALICE);
  await ok(API + "/users/create", { username: BARE, invent: false,
    credential: "password", password: PASSWORD,
    // A product realm's attribute policy requires givenName and mail of
    // everybody, so the in-process file's person with none cannot exist
    // here; the ID Token's claims are still asked of a second person.
    attributes: { cn: BARE, sn: BARE, givenName: "Bare",
                  mail: BARE + "@pcp.example" } }, "created " + BARE);
  await ok(API + "/applications/create", { identifier: "pcp-public",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: "pcp-public", oauthRedirectUri: [REDIRECT] } },
    "created a public client by hand");
  await ok(API + "/applications/create", { identifier: "pcp-confidential",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: "pcp-confidential", oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthRedirectUri: [REDIRECT] } },
    "created a confidential client");
  await ok(API + "/applications/create", { identifier: "pcp-secret",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: "pcp-secret", oauthClientSecret: SECRET,
              oauthRedirectUri: [REDIRECT] } },
    "created a client with a secret and no method");

  await ok(API + "/users/create", { username: LDAP_ADMIN, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: LDAP_ADMIN, sn: LDAP_ADMIN, givenName: "Dir",
                  mail: LDAP_ADMIN + "@pcp.example" } },
    "created a person to bind as");
  await ok(API + "/applications/create", { identifier: "pcp-undeclared",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: "pcp-undeclared",
              oauthRedirectUri: [REDIRECT] } },
    "created another public client");
  await ldapModifyApplication("pcp-undeclared", { operation: "delete",
    modification: { type: "oauthTokenEndpointAuthMethod", values: [] } });
  await ok(base + "/admin-api/realms/set", { id: REALM, key: "global.mode",
                                             value: "product" },
           "switched the realm to product mode");

  log.info("=== 0. the premise ===");
  const bcp = await send(RB + "/oauth2/rfc9700");
  const config = await send(API + "/config");
  const values = {};
  const walk = function (o) {
    if (Array.isArray(o)) {
      o.forEach(walk);
    } else if (o && typeof o === "object") {
      if ((o.key === "oauth2.rfc9700" || o.key === "oauth2.oauth21") &&
          "value" in o) {
        values[o.key] = o.value;
      }
      Object.keys(o).forEach(function (k) {
        walk(o[k]);
      });
    }
  };
  walk(config.body);
  check("0. the product realm is in RFC 9700 mode with oauth2.rfc9700 and " +
        "oauth2.oauth21 both off — the implication everything below rests " +
        "on", function () {
    assert.strictEqual(bcp.body.enabled, true, bcp.raw.slice(0, 300));
    assert.deepStrictEqual(values, { "oauth2.rfc9700": false,
                                     "oauth2.oauth21": false });
  });

  log.info("=== 1, 6. a public client is issued tokens ===");
  let flow = await codeFlow("pcp-public", ALICE);
  let r = await token({ grant_type: "authorization_code",
    code: flow.code || "", redirect_uri: REDIRECT, client_id: "pcp-public",
    code_verifier: flow.verifier });
  check("1. a PUBLIC client reaches a code and redeems it presenting no " +
        "credential", function () {
    assert.ok(flow.code, flow.first.status + " " + flow.final.status + " " +
              String(flow.final.location).slice(0, 200) + " " +
              JSON.stringify(flow.final.answer || flow.final.text || "")
                .slice(0, 400));
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.ok(r.body.access_token && r.body.id_token, r.raw.slice(0, 200));
  });
  const issued = r.body || {};
  const idt = claimsOf(issued.id_token);
  check("6a. the code-flow ID Token carries none of the profile or email " +
        "claims, nor email_verified (OIDC Core 5.4)", function () {
    ["name", "given_name", "family_name", "email", "email_verified"]
      .forEach(function (one) {
        assert.ok(!(one in idt), one + " in " + JSON.stringify(idt));
      });
  });
  check("6c. and sub is the person's urn:uuid:<entryUUID>", function () {
    assert.ok(/^urn:uuid:[0-9a-f-]{36}$/.test(idt.sub), idt.sub);
  });
  const info = await send(RB + "/oauth2/userinfo",
    { headers: { authorization: "Bearer " + issued.access_token } });
  // email_verified IS THE MAIL CHANNEL'S VERIFICATION (#63), and an
  // address an administrator writes through /admin-api is VERIFIED by that
  // write (#64's trusted sources), so here it is true — where the units
  // file's person, made with no verification, read false. What is held is
  // that the claim follows the entry's stsMailVerified.
  const person = await send(API + "/users?user=" + ALICE);
  const marked = JSON.stringify(person.body || {})
    .indexOf("alice@pcp.example") >= 0 &&
    /"stsMailVerified"/.test(person.raw);
  check("6d. UserInfo answers family_name and email from the directory, " +
        "and email_verified true for the address the administrator's " +
        "create verified", function () {
    assert.strictEqual(info.status, 200, info.raw.slice(0, 300));
    assert.strictEqual(info.body.family_name, "Public");
    assert.strictEqual(info.body.email, "alice@pcp.example");
    assert.ok(marked, person.raw.slice(0, 300));
    assert.strictEqual(info.body.email_verified, true);
    assert.strictEqual(info.body.sub, idt.sub);
  });
  flow = await codeFlow("pcp-public", BARE);
  r = await token({ grant_type: "authorization_code", code: flow.code || "",
    redirect_uri: REDIRECT, client_id: "pcp-public",
    code_verifier: flow.verifier });
  check("6e. a second person's ID Token invents none of them either",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    const bare = claimsOf(r.body.id_token);
    ["name", "given_name", "family_name", "email", "email_verified"]
      .forEach(function (one) {
        assert.ok(!(one in bare), one + " in " + JSON.stringify(bare));
      });
  });

  log.info("=== 7. the refresh token rotates ===");
  const once = await token({ grant_type: "refresh_token",
    refresh_token: issued.refresh_token, client_id: "pcp-public" });
  const twice = await token({ grant_type: "refresh_token",
    refresh_token: issued.refresh_token, client_id: "pcp-public" });
  check("7a. a public client's refresh returns a NEW refresh token",
        function () {
    assert.ok(issued.refresh_token, "no refresh token was issued");
    assert.strictEqual(once.status, 200, once.raw.slice(0, 300));
    assert.ok(once.body.refresh_token &&
              once.body.refresh_token !== issued.refresh_token);
  });
  check("7b. and the spent one is refused invalid_grant", function () {
    assert.strictEqual(twice.status, 400, twice.raw.slice(0, 300));
    assert.strictEqual(twice.body.error, "invalid_grant");
  });

  log.info("=== 2. PKCE ===");
  let b = browser();
  r = await b.go("GET", RB + "/oauth2/authorize?" + form({
    client_id: "pcp-public", response_type: "code", redirect_uri: REDIRECT,
    scope: "openid", state: "np-" + STAMP }));
  check("2a. with NO code_challenge the public client is refused " +
        "(RFC 9700 section 2.1.1, oauth2.rfc9700 off)", function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
    assert.ok(/PKCE|code_challenge/.test(r.text), r.text.slice(0, 300));
  });
  b = browser();
  r = await b.go("GET", RB + "/oauth2/authorize?" + form({
    client_id: "pcp-public", response_type: "code", redirect_uri: REDIRECT,
    scope: "openid", state: "pl-" + STAMP,
    code_challenge: pkce().verifier, code_challenge_method: "plain" }));
  check("2b. and code_challenge_method=plain is refused: S256 only",
        function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.location);
    assert.ok(/S256/.test(r.text), r.text.slice(0, 300));
  });

  log.info("=== 3. client credentials ===");
  r = await token({ grant_type: "client_credentials",
                    client_id: "pcp-public", scope: "openid" });
  check("3a. the client credentials grant is refused to a public client " +
        "unauthorized_client (RFC 6749 section 4.4)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "unauthorized_client");
    assert.ok(/4\.4|public/i.test(r.body.error_description || ""),
              r.raw.slice(0, 300));
  });
  r = await postJson(RB + "/oauth2/register", {
    token_endpoint_auth_method: "none", grant_types: ["client_credentials"],
    redirect_uris: [REDIRECT] });
  check("3b. and registering that combination is refused too", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
  });

  log.info("=== 4. a confidential client is unchanged ===");
  flow = await codeFlow("pcp-confidential", ALICE);
  r = await token({ grant_type: "authorization_code", code: flow.code || "",
    redirect_uri: REDIRECT, client_id: "pcp-confidential",
    code_verifier: flow.verifier });
  check("4a. a confidential client presenting no credential is refused " +
        "401 invalid_client", function () {
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_client");
  });
  flow = await codeFlow("pcp-confidential", ALICE);
  r = await token({ grant_type: "authorization_code", code: flow.code || "",
    redirect_uri: REDIRECT, client_id: "pcp-confidential",
    client_secret: SECRET, code_verifier: flow.verifier });
  check("4b. and presenting its secret is issued tokens", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.ok(r.body.access_token);
  });

  log.info("=== 8. the method a create writes ===");
  const methods = { bare: await methodOf("pcp-public"),
                    secret: await methodOf("pcp-secret"),
                    explicit: await methodOf("pcp-confidential") };
  check("8a. a create declared for OAuth is given a method: none with no " +
        "credential, client_secret_basic with a secret, an explicit one " +
        "kept", function () {
    assert.deepStrictEqual(methods, { bare: "none",
      secret: "client_secret_basic", explicit: "client_secret_post" });
  });
  const undeclaredMethod = await methodOf("pcp-undeclared");
  const c553 = await codeCount(REALM, "STS-OAUTH-0553");
  flow = await codeFlow("pcp-undeclared", ALICE);
  r = await token({ grant_type: "authorization_code", code: flow.code || "",
    redirect_uri: REDIRECT, client_id: "pcp-undeclared",
    code_verifier: flow.verifier });
  const c553after = await codeCount(REALM, "STS-OAUTH-0553", c553);
  check("8c. an entry that declares NO method is not public: no credential " +
        "is 401 invalid_client, recorded STS-OAUTH-0553", function () {
    assert.strictEqual(undeclaredMethod, "", undeclaredMethod);
    assert.strictEqual(r.status, 401, r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, "invalid_client");
    assert.ok(c553after > c553, c553 + " -> " + c553after);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), r.raw.slice(0, 300));
  });
  assert.ok(checks >= 16, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.debug("Leaving test().");
}

main();
