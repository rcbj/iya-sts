// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// sts_realm_administrators.js — A TRUST REALM'S OWN ADMINISTRATORS, OVER HTTP.
//
// Since 2026-09-14 (#32) every trust realm has two console role groups of its
// own, whose members administer THAT realm and nothing outside it, while the
// default realm's two groups stay the service administrators over every realm.
// `admin-ui/CLAUDE.md` 8d is the design; `tests/realm_administrators.js` holds
// the half no request can reach (the roster views, the bootstrap window, the
// scope table as a table, the chooser's decision). This is the half that is
// only true of a running service:
//
//   1. THE CHOOSER. A bare `/portal` with realms defined asks which realm;
//      `?realm=<id>` redirects under that realm's prefix, an unknown id is
//      refused, `?realm=default` and a prefixed path sign in where they are.
//      The console has no chooser since the #446 cutover: every `/admin`
//      address answers the static console's document, which signs in at the
//      realm its own prefix names and switches realms in place.
//   2. A REALM ADMINISTRATOR IS CONFINED. Signed in through a realm they read
//      that realm's pages, do not see or reach the service pages, cannot write
//      a per-process setting, create a realm or replace the service Root, and
//      are refused the default realm's console and any other realm's. Since
//      the #446 cutover each of those is the console's `/admin-api` call made
//      with the token the realm's console holds (`console_signin.js`), and the
//      navigation is `GET /admin-api/console`'s sections.
//   3. THE SERVICE ADMINISTRATOR IS NOT. Signed in through the default realm
//      they reach the service pages under a realm's prefix as well as at the
//      root.
//   4. A NAME IS NOT AN AUTHORITY. The service administrator's own username,
//      signed in through the realm, is that realm's person and is confined.
//   5. A REALM'S OWN TOKEN. Minted at the realm's token endpoint by its
//      `sts-management-api` client it reaches the realm's operations, is
//      refused everywhere else and refused the service-wide operations, and
//      the same scopes are not issued to any other client in the realm unless
//      an administrator declares them on it (#110) — and withdrawing that
//      declaration cuts off the token it already holds.
//
// **IT IS `local: true` FOR THE OWNERSHIP REASON.** Everything here is
// asserted over HTTP and could run from the parent's suite; the tree that GAVE
// a realm its administrators is the tree that should go red when one stops
// being confined, and that tree is this one.
//
// **ITS REALMS ARE LEFT STANDING**, by tests/CLAUDE.md's rule. It touches the
// default realm's roster only when that realm's bootstrap window is already
// closed — and then grants one name and revokes it in a `finally`, because a
// member left in `admin-write` is a service administrator nobody meant.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor, runStamp } = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_realm_administrators",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = runStamp();
const REALM = "ra-" + STAMP;
const OTHER = "rb-" + STAMP;
const REALM_PERSON = usernameFor("realm-admin");
const SERVICE_PERSON = usernameFor("service-admin");

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// One request, with no redirect followed and the body read both ways.
async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const opts = Object.assign({ method: method, redirect: "manual" },
                             options || {});
  const r = await fetch(url, opts);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page, a redirect or an empty body. The text is kept.
    body = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, body: body, text: text,
           location: r.headers.get("location") || "" };
}

// The management API with the run's token, which the preload attaches.
async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = payload === undefined ? {}
    : { headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload) };
  const reply = await call(method, base + path, options);
  log.debug("Leaving api().");
  return reply;
}

// The management API with a token this file chose, so the preload leaves it.
async function apiAs(token, method, path, payload) {
  log.debug("Entering apiAs(). " + method + " " + path);
  const headers = { Authorization: "Bearer " + token };
  const options = { headers: headers };
  if (payload !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const reply = await call(method, base + path, options);
  log.debug("Leaving apiAs().");
  return reply;
}

async function ensureRealm(id, name) {
  log.debug("Entering ensureRealm(). " + id);
  const made = await api("POST", "/admin-api/realms/create",
                         { id: id, domain: id + ".example.net", name: name });
  assert.ok(made.status === 200 ||
            /already/i.test(JSON.stringify(made.body || made.text)),
    "creating the realm " + id + " answered " + made.status + " " +
    made.text.slice(0, 300));
  log.debug("Leaving ensureRealm().");
}

// THE CONSOLE'S DOCUMENT FIRST, as a browser opening it loads it: serving it
// under a realm's prefix is what registers that realm's console callback
// (#446), so the sign-in that follows has a redirect URI to come back to.
async function consoleIn(prefix, username) {
  log.debug("Entering consoleIn(). " + prefix);
  const shell = await call("GET", base + prefix + "/admin");
  assert.strictEqual(shell.status, 200, "GET " + prefix + "/admin answered " +
                     shell.status);
  const consoleClient = await consoleSignIn.signInToTheConsole(base + prefix,
    username, log);
  log.debug("Leaving consoleIn().");
  return consoleClient;
}

// A CONSOLE READ AS THE STATIC CONSOLE MAKES IT (#446): the operation a page
// is drawn from, with the console's token. `prefix` is the realm whose
// operation is asked — the token's own realm, or another one, which is the
// point of half the checks below — and `consolePath` the page,
// `/admin/tokens`, whose operation is the `/admin-api` path of the same name.
async function page(consoleClient, prefix, consolePath) {
  log.debug("Entering page(). " + prefix + consolePath);
  const reply = await consoleClient.api("GET", base + prefix + "/admin-api" +
                                        consolePath.slice("/admin".length));
  log.debug("Leaving page().");
  return { status: reply.status, body: reply.json || {},
           text: reply.text || "" };
}

// The frame's answer, `GET /admin-api/console`, for the realm `prefix` names:
// the sections the navigation is drawn from, the account link, the footer's
// facts.
async function shellOf(consoleClient, prefix) {
  log.debug("Entering shellOf(). " + prefix);
  const reply = await consoleClient.api("GET", base + prefix +
                                        "/admin-api/console");
  assert.strictEqual(reply.status, 200, "GET " + prefix +
    "/admin-api/console answered " + reply.status + " " +
    String(reply.text).slice(0, 200));
  log.debug("Leaving shellOf().");
  return reply.json || {};
}

// The console paths a shell answer's sections name.
function navPaths(shell) {
  log.debug("Entering navPaths().");
  const out = [];
  const re = /"path":"(\/admin[^"]*)"/g;
  const text = JSON.stringify(shell.sections || []);
  let m = re.exec(text);
  while (m) {
    out.push(m[1]);
    m = re.exec(text);
  }
  log.debug("Leaving navPaths(). " + out.length);
  return out;
}

// A console form, as the static console sends it: the operation it is
// (`console_signin.js`'s `act()`), in the realm the client signed in to.
async function consolePost(consoleClient, path, form) {
  log.debug("Entering consolePost(). " + path);
  const reply = await consoleClient.act(path, form);
  log.debug("Leaving consolePost().");
  return reply;
}

// ---------------------------------------------------------------------------
// 1. THE CHOOSER.
// ---------------------------------------------------------------------------
async function theChooserAsksWhichRealm() {
  log.debug("Entering theChooserAsksWhichRealm().");
  log.info("=== the plain /admin and /portal ask which realm ===");
  for (const surface of ["/admin", "/portal"]) {
    const bare = await call("GET", base + surface);
    check("a bare " + surface + " with realms defined draws the chooser " +
          "rather than starting a sign-in", function () {
      assert.strictEqual(bare.status, 200,
        surface + " answered " + bare.status + " -> " + bare.location);
      assert.ok(/name="realm"/.test(bare.text),
        "the page has no realm control: " + bare.text.slice(0, 200));
    });
    check("its control is a list naming the realm in development, or a " +
          "text box in product — never a list in product", function () {
      const listed = /<select[^>]*name="realm"/.test(bare.text);
      if (listed) {
        assert.ok(bare.text.indexOf('value="' + REALM + '"') >= 0,
          "the list does not offer " + REALM);
      } else {
        assert.ok(/<input[^>]+name="realm"/.test(bare.text),
          "neither a list nor a text box");
        assert.ok(bare.text.indexOf(REALM) < 0,
          "a text box page must not name the realms");
      }
    });
    const chosen = await call("GET", base + surface + "?realm=" + REALM);
    check("choosing " + REALM + " redirects under that realm's prefix",
      function () {
        assert.ok(chosen.status === 303 || chosen.status === 302,
          "it answered " + chosen.status);
        assert.ok(new RegExp("/realm/" + REALM + surface + "$")
                    .test(chosen.location),
          "it went to " + chosen.location);
      });
    const unknown = await call("GET", base + surface +
                               "?realm=no-such-realm-" + STAMP);
    check("an unknown realm is refused on the chooser, not redirected",
      function () {
        assert.strictEqual(unknown.status, 400, "it answered " +
                           unknown.status + " -> " + unknown.location);
        assert.ok(!unknown.location, "it redirected to " + unknown.location);
      });
    const here = await call("GET", base + surface + "?realm=default");
    // THE CONSOLE SIGNS IN IN THE BROWSER since the #446 cutover: past the
    // chooser `/admin` answers the static console's document, whose script
    // starts the authorization request; the portal still redirects to it.
    check("?realm=default signs in where it is: an authorization request" +
          (surface === "/admin" ? ", started by the console's document" : ""),
      function () {
        if (surface === "/admin") {
          assert.ok(here.status === 200 &&
                    /<script src="\/admin\/console\.js"/.test(here.text),
            "it answered " + here.status + " " + here.text.slice(0, 200));
          return;
        }
        assert.ok(/\/oauth2\/authorize\?/.test(here.location),
          "it answered " + here.status + " -> " + here.location);
      });
  }
  const deep = await call("GET", base + "/admin/tokens");
  check("a deep link is never asked: /admin/tokens is the console's " +
        "document, which signs in where it is",
    function () {
      assert.ok(deep.status === 200 &&
                /<script src="\/admin\/console\.js"/.test(deep.text),
        "it answered " + deep.status + " " + deep.text.slice(0, 200));
    });
  const prefixed = await call("GET", base + "/realm/" + REALM + "/portal");
  check("a surface already under a realm prefix is never asked",
    function () {
      assert.ok(/\/oauth2\/authorize\?/.test(prefixed.location),
        "it answered " + prefixed.status + " -> " + prefixed.location);
    });
  log.debug("Leaving theChooserAsksWhichRealm().");
}

// ---------------------------------------------------------------------------
// 2. A REALM ADMINISTRATOR IS CONFINED.
// ---------------------------------------------------------------------------
async function aRealmAdministratorIsConfined() {
  log.debug("Entering aRealmAdministratorIsConfined().");
  log.info("=== a realm administrator reaches their realm and no more ===");
  const R = "/realm/" + REALM;
  const roster = await api("GET", R + "/admin-api/rbac");
  assert.ok(roster.body && roster.body.bootstrap &&
            !roster.body.bootstrap.claimedAt,
    "precondition: a realm this run created has its bootstrap window " +
    "unclaimed; it reads " +
    JSON.stringify(roster.body && roster.body.bootstrap));
  // IN DEVELOPMENT THE WINDOW MAKES THEM AN ADMINISTRATOR; IN PRODUCT IT NEVER
  // OPENS (#103, 2026-09-22), so the realm's roster is given them — through
  // the realm's own API, which is a grant in that realm and nowhere else.
  if (!roster.body.openToAnyone) {
    const grant = await api("POST", R + "/admin-api/rbac/grant",
                            { username: REALM_PERSON, role: "write" });
    assert.strictEqual(grant.status, 200, "granting " + REALM_PERSON +
                       " Admin Write in " + REALM + " answered " +
                       grant.status + " " + grant.text.slice(0, 200));
  }
  const consoleClient = await consoleIn(R, REALM_PERSON);

  const own = await page(consoleClient, R, "/admin/tokens?per=1");
  check("their own realm's pages answer", function () {
    assert.strictEqual(own.status, 200, "it answered " + own.status);
  });
  const shell = await shellOf(consoleClient, R);
  const nav = navPaths(shell);
  check("the navigation does not offer a service page", function () {
    assert.ok(nav.indexOf("/admin/users") >= 0,
      "precondition: the sections name no /admin/users: " + nav.join(" "));
    assert.ok(nav.indexOf("/admin/persistence") < 0,
      "the navigation names /admin/persistence");
    assert.ok(nav.indexOf("/admin/secrets") < 0,
      "the navigation names /admin/secrets");
  });
  // THE ACCOUNT LINK GOES WHERE THEIR ACCOUNT IS. It named the default
  // realm's portal for everybody until 2026-09-16, which for a realm
  // administrator is a portal where they are nobody.
  check("their My account link is their own realm's portal", function () {
    assert.ok(new RegExp(R + "/portal$").test(String(shell.portalHref || "")),
      "the link is " + JSON.stringify(shell.portalHref));
  });
  // NOR ARE THEY HANDED the database host and the secret-store paths the
  // footer draws for a service administrator: since the #446 cutover the
  // frame is drawn in their browser from this answer, so what is not drawn
  // must not be in it either.
  check("nor the runtime footer's database host and secret-store paths",
    function () {
      const facts = shell.runtime || {};
      assert.ok(!facts.database && !facts.keyEncryptionKey &&
                !facts.databasePassword,
        "the console's answer carries the runtime facts: " +
        JSON.stringify(facts).slice(0, 200));
    });
  for (const service of ["/admin/persistence", "/admin/secrets",
                         "/admin/api-explorer"]) {
    const refused = await page(consoleClient, R, service);
    check("a service page is refused under their own prefix: " + service,
      function () {
        assert.strictEqual(refused.status, 403,
          "it answered " + refused.status);
      });
  }
  // THEIR TOKEN IS THEIR REALM'S: the default realm's API is not its
  // audience, and neither is any other realm's.
  const root = await page(consoleClient, "", "/admin/tokens?per=1");
  check("the default realm's console is refused — they administer another " +
        "realm", function () {
    assert.ok(root.status === 401 || root.status === 403,
      "it answered " + root.status + " " + root.text.slice(0, 200));
  });
  const other = await page(consoleClient, "/realm/" + OTHER,
                           "/admin/tokens?per=1");
  check("so is any other realm's console", function () {
    assert.ok(other.status === 401 || other.status === 403,
      "it answered " + other.status);
  });

  const perProcess = await consolePost(consoleClient, "/admin/config",
    { action: "set-many", "scheduler.runHistoryCount": "3" });
  check("a per-process setting is refused, because a realm write of one " +
        "lands process-wide", function () {
    assert.strictEqual(perProcess.status, 403,
      "it answered " + perProcess.status + " " + perProcess.text.slice(0, 200));
  });
  const created = await consolePost(consoleClient, "/admin/realms",
    { action: "create", id: "rc-" + STAMP, name: "Should not exist" });
  check("creating a realm is refused", function () {
    assert.strictEqual(created.status, 403, "it answered " + created.status);
  });
  const rootCa = await consolePost(consoleClient, "/admin/pki",
    { action: "build-root" });
  check("replacing the service Root is refused", function () {
    assert.strictEqual(rootCa.status, 403, "it answered " + rootCa.status);
  });
  const listed = await api("GET", "/admin-api/realms");
  check("and the refused create really created nothing", function () {
    const ids = ((listed.body && listed.body.realms) || [])
      .map(function (one) { return one.id; });
    assert.ok(ids.indexOf("rc-" + STAMP) < 0, "the realm exists: " + ids);
  });
  log.debug("Leaving aRealmAdministratorIsConfined().");
}

// ---------------------------------------------------------------------------
// 3 AND 4. THE SERVICE ADMINISTRATOR, AND THE SAME NAME THROUGH THE REALM.
// ---------------------------------------------------------------------------
async function theServiceAdministratorIsNot() {
  log.debug("Entering theServiceAdministratorIsNot().");
  log.info("=== the service administrator reaches every realm ===");
  const service = await api("GET", "/admin-api/rbac");
  // `openToAnyone` and not "seeded and unclaimed": product never opens the
  // window (#103), so an unclaimed default realm there admits nobody.
  const open = !!(service.body && service.body.openToAnyone);
  let granted = false;
  try {
    if (!open) {
      const grant = await api("POST", "/admin-api/rbac/grant",
                              { username: SERVICE_PERSON, role: "write" });
      assert.strictEqual(grant.status, 200, "granting Admin Write answered " +
                         grant.status + " " + grant.text.slice(0, 200));
      granted = true;
    }
    const consoleClient = await consoleIn("", SERVICE_PERSON);
    for (const where of [["", "/admin/persistence"],
                         ["/realm/" + REALM, "/admin/persistence"],
                         ["/realm/" + OTHER, "/admin/tokens?per=1"]]) {
      const reply = await page(consoleClient, where[0], where[1]);
      check("the service administrator reads " + where[0] + where[1],
        function () {
          assert.strictEqual(reply.status, 200, "it answered " +
                             reply.status + " " + reply.text.slice(0, 200));
        });
    }
    const shell = await shellOf(consoleClient, "/realm/" + REALM);
    check("and, reading a realm, is linked to the DEFAULT realm's portal, " +
          "where a service administrator's account is", function () {
      assert.ok(/:\/\/[^/]+\/portal$/.test(String(shell.portalHref || "")),
        "the link is " + JSON.stringify(shell.portalHref));
    });
    check("and is offered the service pages in a realm's navigation",
      function () {
        assert.ok(navPaths(shell).indexOf("/admin/persistence") >= 0,
          "the navigation does not name /admin/persistence");
      });

    log.info("=== the same username, signed in through the realm ===");
    const R = "/realm/" + REALM;
    const same = await consoleIn(R, SERVICE_PERSON);
    const collided = await page(same, R, "/admin/persistence");
    check("A NAME IS NOT AN AUTHORITY: the service administrator's username " +
          "signed in through the realm is that realm's person, and is " +
          "refused a service page", function () {
      assert.strictEqual(collided.status, 403,
        "it answered " + collided.status);
    });
  } finally {
    if (granted) {
      const revoked = await api("POST", "/admin-api/rbac/revoke",
                                { username: SERVICE_PERSON, role: "write" });
      log.info("revoked the Admin Write granted for this section: " +
               revoked.status);
    }
  }
  log.debug("Leaving theServiceAdministratorIsNot().");
}

// ---------------------------------------------------------------------------
// 5. A REALM'S OWN TOKEN.
// ---------------------------------------------------------------------------
async function tokenFor(realmId, clientId, secret) {
  log.debug("Entering tokenFor(). " + clientId);
  const R = "/realm/" + realmId;
  const reply = await call("POST", base + R + "/oauth2/token", {
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: "Basic " +
                 Buffer.from(clientId + ":" + secret).toString("base64") },
    body: new URLSearchParams({ grant_type: "client_credentials",
                                scope: "admin:read admin:write",
                                resource: base + R + "/admin-api" })
      .toString()
  });
  log.debug("Leaving tokenFor(). status=" + reply.status);
  return reply;
}

async function aRealmTokenStaysInItsRealm() {
  log.debug("Entering aRealmTokenStaysInItsRealm().");
  log.info("=== a realm's own management API token ===");
  const R = "/realm/" + REALM;
  const regenerated = await api("POST", R +
    "/admin-api/applications/regenerate-secret",
    { application: "sts-management-api" });
  const secret = regenerated.body && regenerated.body.clientSecret;
  assert.ok(secret, "precondition: regenerating the realm's " +
    "sts-management-api secret answered " + regenerated.status + " " +
    regenerated.text.slice(0, 200));
  const minted = await tokenFor(REALM, "sts-management-api", secret);
  const token = minted.body && minted.body.access_token;
  assert.ok(token, "precondition: the realm's token endpoint answered " +
            minted.status + " " + minted.text.slice(0, 200));

  const own = await apiAs(token, "GET", R + "/admin-api/users?per=1");
  check("it reads its own realm", function () {
    assert.strictEqual(own.status, 200, "it answered " + own.status);
  });
  const root = await apiAs(token, "GET", "/admin-api/users?per=1");
  check("it is not a credential at /admin-api itself", function () {
    assert.strictEqual(root.status, 401, "it answered " + root.status);
  });
  const other = await apiAs(token, "GET", "/realm/" + OTHER +
                            "/admin-api/users?per=1");
  check("nor under another realm's prefix", function () {
    assert.strictEqual(other.status, 401, "it answered " + other.status);
  });
  const persistence = await apiAs(token, "GET", R + "/admin-api/persistence");
  check("a service operation is refused 403", function () {
    assert.strictEqual(persistence.status, 403,
                       "it answered " + persistence.status);
  });
  const createRealm = await apiAs(token, "POST", R + "/admin-api/realms/create",
    { id: "rt-" + STAMP,
      domain: ("rt-" + STAMP) + ".example.net",
      name: "Should not exist" });
  check("creating a realm is refused 403", function () {
    assert.strictEqual(createRealm.status, 403,
                       "it answered " + createRealm.status);
  });
  const buildRoot = await apiAs(token, "POST", R + "/admin-api/pki/build-root",
                                {});
  check("replacing the service Root is refused 403", function () {
    assert.strictEqual(buildRoot.status, 403,
                       "it answered " + buildRoot.status);
  });
  const workers = await apiAs(token, "POST", R + "/admin-api/config/set",
                              { key: "scheduler.runHistoryCount", value: "2" });
  check("a per-process setting is refused 403", function () {
    assert.strictEqual(workers.status, 403, "it answered " + workers.status);
  });
  const allowed = await apiAs(token, "POST", R + "/admin-api/config/set",
                              { key: "groups.claim", value: "true" });
  check("a setting the realm may carry is written", function () {
    assert.strictEqual(allowed.status, 200,
      "it answered " + allowed.status + " " + allowed.text.slice(0, 200));
  });
  await apiAs(token, "POST", R + "/admin-api/config/reset",
              { key: "groups.claim" });
  const serviceHere = await api("GET", R + "/admin-api/persistence");
  check("the SERVICE token still reaches a service operation under the " +
        "realm's prefix", function () {
    assert.strictEqual(serviceHere.status, 200,
                       "it answered " + serviceHere.status);
  });

  const rogueId = "ra-rogue-" + STAMP;
  const made = await api("POST", R + "/admin-api/applications/create",
    { identifier: rogueId, name: "Another client", protocols: ["oauth2"],
      // CONFIDENTIAL, said at the create (2026-09-18). A create declaring
      // OAuth with no credential is recorded PUBLIC (`none`), and the secret
      // regenerated below does not change the method — so in product mode
      // the client_credentials request was refused as a public client's
      // before the gate this section is about was ever asked.
      fields: { oauthTokenEndpointAuthMethod: "client_secret_basic" } });
  assert.ok(made.status === 200, "precondition: creating " + rogueId +
            " answered " + made.status + " " + made.text.slice(0, 200));
  const rogueSecret = await api("POST", R +
    "/admin-api/applications/regenerate-secret", { application: rogueId });
  const secretOfRogue = rogueSecret.body && rogueSecret.body.clientSecret;
  const refusedAtIssuance = await tokenFor(REALM, rogueId, secretOfRogue);
  check("THE SAME SCOPES FROM ANY OTHER CLIENT IN THE REALM ARE NOT ISSUED " +
        "(#110) — invalid_scope, because it does not declare them",
        function () {
    assert.strictEqual(refusedAtIssuance.status, 400,
      "it answered " + refusedAtIssuance.status + " " +
      refusedAtIssuance.text.slice(0, 200));
    assert.strictEqual(refusedAtIssuance.body &&
                       refusedAtIssuance.body.error, "invalid_scope");
  });
  // DECLARED BY AN ADMINISTRATOR, the other client is a door too: ONE RULE
  // for every realm since #110 — the client declares the scope — where it was
  // "only the realm's sts-management-api" (STS-API-0111, retired).
  for (const scope of ["admin:read", "admin:write"]) {
    const declared = await api("POST", R + "/admin-api/applications/add",
      { application: rogueId, attribute: "oauthAllowedScope",
        value: scope });
    assert.ok(declared.status === 200, "precondition: declaring " + scope +
              " answered " + declared.status + " " +
              declared.text.slice(0, 200));
  }
  // DECLARING IS NO LONGER ENOUGH (#303): admin:read and admin:write are
  // authorized by the realm's ADMIN_READ and ADMIN_WRITE roles, and a client
  // is issued them only while it is a member. Declared and holding neither,
  // the request asked for nothing it may have.
  const declaredOnly = await tokenFor(REALM, rogueId, secretOfRogue);
  check("DECLARED BUT HOLDING NO ROLE, IT IS STILL REFUSED (#303) — " +
        "invalid_scope, because the role authorizes the scope",
        function () {
    assert.strictEqual(declaredOnly.status, 400,
      "it answered " + declaredOnly.status + " " +
      declaredOnly.text.slice(0, 200));
    assert.strictEqual(declaredOnly.body && declaredOnly.body.error,
                       "invalid_scope");
  });
  for (const role of ["ADMIN_READ", "ADMIN_WRITE"]) {
    const added = await api("POST", R + "/admin-api/roles/add-member",
      { role: role, kind: "application", member: rogueId });
    assert.ok(added.status === 200, "precondition: adding " + rogueId +
              " to the realm's " + role + " answered " + added.status + " " +
              added.text.slice(0, 200));
  }
  const rogue = await tokenFor(REALM, rogueId, secretOfRogue);
  const rogueToken = rogue.body && rogue.body.access_token;
  assert.ok(rogueToken, "precondition: a client declaring admin:* and " +
            "holding both roles is issued them; it answered " + rogue.status +
            " " + rogue.text.slice(0, 200));
  const rogueRead = await apiAs(rogueToken, "GET",
                                R + "/admin-api/users?per=1");
  check("a client an administrator declared admin:* for, and put in the " +
        "realm's two console roles, reaches the realm's operations",
        function () {
    assert.strictEqual(rogueRead.status, 200,
                       "it answered " + rogueRead.status + " " +
                       rogueRead.text.slice(0, 200));
  });
  const withdrawn = await api("POST", R + "/admin-api/applications/remove",
    { application: rogueId, attribute: "oauthAllowedScope",
      value: "admin:read" });
  assert.ok(withdrawn.status === 200, "precondition: withdrawing admin:read " +
            "answered " + withdrawn.status);
  const afterWithdrawal = await apiAs(rogueToken, "GET",
                                      R + "/admin-api/users?per=1");
  check("and withdrawing the declaration cuts off the token it already " +
        "holds: 403", function () {
    assert.strictEqual(afterWithdrawal.status, 403,
                       "it answered " + afterWithdrawal.status + " " +
                       afterWithdrawal.text.slice(0, 200));
  });
  log.debug("Leaving aRealmTokenStaysInItsRealm().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving trust realm administrators at " + base + ".");
  await ensureRealm(REALM, "Realm administrators " + STAMP);
  await ensureRealm(OTHER, "Another realm " + STAMP);

  await theChooserAsksWhichRealm();
  await aRealmAdministratorIsConfined();
  await theServiceAdministratorIsNot();
  await aRealmTokenStaysInItsRealm();

  // A FLOOR ON THE COUNT, for the reason sts_roles.js gives: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed".
  assert.ok(checks >= 40,
    "only " + checks + " checks ran. This file makes at least forty against " +
    "a healthy service, so a count this low means a SECTION STOPPED BEING " +
    "CALLED.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_realm_administrators")
  .description("Drive a trust realm's own administrators: the realm " +
      "chooser, a realm administrator confined to their realm, the service " +
      "administrator over every realm, a name signed in through two realms, " +
      "and a realm's own management API token.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
