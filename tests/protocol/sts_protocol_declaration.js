// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_protocol_declaration.js
//
// ---------------------------------------------------------------------------
// WHAT AN APPLICATION IS DECLARED FOR, AND WHAT EVERY PROTOCOLS PAGE SAYS
// ANSWERS IN ITS REALM, OVER THE WIRE (D12, #444).
//
//   P. NOTHING THROUGH A PROTOCOL AN APPLICATION IS NOT DECLARED FOR, IN
//      PRODUCT (D12: carries over tests/protocol_declaration.js B and C's
//      consequence). In a product realm a client_credentials token for an
//      application declared for SAML 2.0 alone is refused (400
//      access_denied; STS-XACML-0084 and STS-OAUTH-0191 on the audit rows,
//      the first naming the declaration); one declared for OAuth, and one
//      declared for nothing, are issued; in a development realm the SAML
//      2.0 one is issued too.
//   E. EVERY PROTOCOLS PAGE'S ENDPOINTS ARE ITS REALM'S (D12: carries over
//      tests/protocol_endpoints.js B, C and E). Every operation mirroring a
//      Protocols page answers `protocolEndpoints`, every URL in it carries
//      the realm's prefix, every concrete GET row answers something other
//      than an unrouted path (Express's "Cannot GET", which
//      `sts_metadata.js` also reads), and every row names a method; a named
//      authorization server is listed once per route by its id with both
//      of its discovery documents at their own addresses; an operation
//      mirroring a page outside Protocols (`/admin-api/users`) carries none.
//
// NOT CARRIED, and why: protocol_declaration.js A (the rule's place in the
// built-in document and `decideProtocols: no`) is the template's own
// structure, and B's requests are built by hand against the PDP;
// protocol_endpoints.js A (every Protocols page has a row) compares the
// table with the console's SECTIONS in one process, and F is the
// browser-drawn section.
//
// ITS REALMS ARE REMOVED AT THE END ONLY WHEN ASKED
// (`STS_TEST_REMOVE_REALMS=1`, which a hand run against a long-lived probe
// sets so that its directory does not fill): tests/CLAUDE.md's *No job
// removes a realm* is the rule for a shared run, so by default they stay.
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_protocol_declaration",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
    .slice(0, 31);
}
const PRODUCT = realmId("pdecl-");
const DEVELOPMENT = realmId("pdecd-");
const SECRET = "pdecl-" + STAMP + "-secret-value";

// The operations mirroring a Protocols page, each by the page it mirrors.
const MIRRORS = ["saml2", "kerberos", "credential-claims", "federation",
                 "xacml", "ssf", "scim", "webauthn", "oauth2", "wsfed",
                 "wstrust", "oidfed", "ldap", "tls", "totp",
                 "backup-codes"];

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
  return { status: r.status, body: body, raw: raw };
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

function apiOf(realm) {
  log.debug("Entering apiOf().");
  log.debug("Leaving apiOf().");
  return base + "/realm/" + realm + "/admin-api";
}

async function newestAt(realm) {
  log.debug("Entering newestAt().");
  const r = await send(apiOf(realm) + "/audit?per=1");
  log.debug("Leaving newestAt().");
  // BY TIME (#465): `seq` is unique across processes and rises within
  // each, but it is not one order across them, so a row a request worker
  // numbered from a lower block than the newest row here would be missed.
  // A reader resumes by `at`, as the audit API says.
  const newest = (r.body && r.body.events && r.body.events[0]) || {};
  return newest.at || 0;
}

// The rows recorded in a realm after `since` that carry a code.
async function codedSince(realm, since, wanted) {
  log.debug("Entering codedSince().");
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await send(apiOf(realm) + "/audit?per=200");
    found = ((r.body && r.body.events) || []).filter(function (row) {
      return row.at > since && row.errorCode;
    });
    if (!wanted || found.some(function (row) {
      return row.errorCode === wanted;
    })) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving codedSince(). " + found.length);
  return found;
}

// A client_credentials client declared for `declared` (empty: nothing).
async function client(realm, identifier, declared) {
  log.debug("Entering client().");
  const api = apiOf(realm);
  await ok(api + "/applications/create", { identifier: identifier,
    protocols: ["oauth2"], fields: { oauthClientId: [identifier],
      oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthGrantType: ["client_credentials"] } }, "created " + identifier);
  if (declared.indexOf("oauth2") < 0) {
    for (const family of declared) {
      await ok(api + "/applications/add", { application: identifier,
        attribute: "appAllowedProtocol", value: family },
        "declared " + identifier + " for " + family);
    }
    await ok(api + "/applications/remove", { application: identifier,
      attribute: "appAllowedProtocol", value: "oauth2" },
      "took oauth2 off " + identifier);
  }
  const view = await send(api + "/applications?application=" + identifier);
  const app = view.body.application || view.body;
  log.debug("Leaving client().");
  return [].concat((app.fields || {}).appAllowedProtocol || []);
}

function token(realm, identifier) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return send(base + "/realm/" + realm + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
      client_id: identifier, client_secret: SECRET }).toString() });
}

async function declarations() {
  log.debug("Entering declarations().");
  log.info("=== P. the declaration, in product and development ===");
  const declared = {
    saml: await client(PRODUCT, "pd-saml2", ["saml2"]),
    oauth: await client(PRODUCT, "pd-oauth2", ["oauth2"]),
    none: await client(PRODUCT, "pd-none", [])
  };
  check("the three are declared for SAML 2.0 alone, for OAuth, and for " +
        "nothing", function () {
    assert.deepStrictEqual(declared, { saml: ["saml2"], oauth: ["oauth2"],
                                       none: [] });
  });
  const since = await newestAt(PRODUCT);
  const saml = await token(PRODUCT, "pd-saml2");
  const rows = await codedSince(PRODUCT, since, "STS-OAUTH-0191");
  const policyRow = rows.filter(function (row) {
    return row.errorCode === "STS-XACML-0084";
  })[0];
  check("in product an access token for an application declared for SAML " +
        "2.0 alone is refused, the issuance policy's protocol rule on the " +
        "audit row (STS-XACML-0084, then STS-OAUTH-0191)", function () {
    assert.strictEqual(saml.status, 400, saml.raw.slice(0, 300));
    assert.strictEqual(saml.body.error, "access_denied");
    assert.ok(policyRow, JSON.stringify(rows.map(function (row) {
      return row.errorCode;
    })));
    assert.ok(/declared for saml2/.test(policyRow.summary),
              policyRow.summary);
    assert.ok(rows.some(function (row) {
      return row.errorCode === "STS-OAUTH-0191";
    }));
    assert.ok(saml.raw.indexOf("STS-") < 0, "a code was sent");
  });
  const oauth = await token(PRODUCT, "pd-oauth2");
  const none = await token(PRODUCT, "pd-none");
  check("one declared for OAuth and one declared for nothing are issued",
        function () {
    assert.strictEqual(oauth.status, 200, oauth.raw.slice(0, 300));
    assert.ok(oauth.body.access_token);
    assert.strictEqual(none.status, 200, none.raw.slice(0, 300));
  });
  await client(DEVELOPMENT, "pd-saml2", ["saml2"]);
  const dev = await token(DEVELOPMENT, "pd-saml2");
  check("in development the SAML 2.0 one is issued", function () {
    assert.strictEqual(dev.status, 200, dev.raw.slice(0, 300));
  });
  log.debug("Leaving declarations().");
}

async function endpoints() {
  log.debug("Entering endpoints().");
  log.info("=== E. every Protocols page's endpoints are its realm's ===");
  const api = apiOf(DEVELOPMENT);
  const prefix = base + "/realm/" + DEVELOPMENT + "/";
  await ok(api + "/authorization-servers/create", { id: "tenantpe",
    label: "Endpoints test" }, "created a named authorization server");
  const all = [];
  for (const page of MIRRORS) {
    const r = await send(api + "/" + page);
    check("GET /admin-api/" + page + " answers its page's endpoints",
          function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
      assert.ok(Array.isArray(r.body.protocolEndpoints) &&
                r.body.protocolEndpoints.length > 0, page);
    });
    r.body.protocolEndpoints.forEach(function (row) {
      all.push(Object.assign({ page: page }, row));
    });
  }
  check("every HTTP row of every page carries the realm's prefix and names " +
        "a method", function () {
    const outside = all.filter(function (row) {
      return row.route && row.url.indexOf(prefix) !== 0;
    });
    assert.deepStrictEqual(outside.map(function (row) {
      return row.page + " " + row.url;
    }), []);
    all.filter(function (row) {
      return row.route;
    }).forEach(function (row) {
      assert.ok(Array.isArray(row.methods) && row.methods.length > 0,
                JSON.stringify(row));
    });
  });
  const concrete = all.filter(function (row) {
    return row.route && row.methods.indexOf("GET") >= 0 &&
           row.url.indexOf("{") < 0;
  });
  const unrouted = [];
  for (const row of concrete) {
    const r = await send(row.url);
    // Express's own 404 body, whole: a report that QUOTES the phrase (the
    // RFC 9700 one does) is not an unrouted path.
    if (r.status === 404 && /<pre>Cannot GET [^<]*<\/pre>/.test(r.raw)) {
      unrouted.push(row.page + " " + row.url);
    }
  }
  check("every concrete GET row (" + concrete.length + ") reaches a route " +
        "rather than Express's unrouted answer", function () {
    assert.ok(concrete.length > 20, String(concrete.length));
    assert.deepStrictEqual(unrouted, []);
  });
  const oauth = await send(api + "/oauth2");
  const named = oauth.body.protocolEndpoints.filter(function (row) {
    return /tenantpe/.test(row.url);
  });
  check("a named authorization server's twelve routes are each listed " +
        "once by its id, and both its discovery documents at their own " +
        "addresses", function () {
    assert.strictEqual(named.length, 12, JSON.stringify(named.map(
      function (row) {
        return row.url;
      })));
    named.forEach(function (row) {
      assert.ok(/tenantpe$/.test(row.name), row.name);
    });
    const urls = named.map(function (row) {
      return row.url;
    });
    assert.ok(urls.indexOf(prefix +
      ".well-known/oauth-authorization-server/tenantpe") >= 0);
    assert.ok(urls.indexOf(prefix +
      "tenantpe/.well-known/openid-configuration") >= 0);
    assert.strictEqual(new Set(urls).size, urls.length);
  });
  const users = await send(api + "/users");
  check("an operation mirroring a page outside Protocols carries none",
        function () {
    assert.strictEqual(users.status, 200);
    assert.ok(!("protocolEndpoints" in users.body));
  });
  log.debug("Leaving endpoints().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. the throwaway realms " + PRODUCT + " (product) and " +
           DEVELOPMENT + " ===");
  for (const id of [PRODUCT, DEVELOPMENT]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Protocol declaration " + STAMP },
      "created the realm " + id);
  }
  await ok(apiOf(PRODUCT) + "/config/set", { key: "global.mode",
                                             value: "product" },
           "switched " + PRODUCT + " to product");
  await declarations();
  await endpoints();
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// The realms this job made, removed from the default realm only when
// STS_TEST_REMOVE_REALMS is "1" (the header says why).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Kept.");
    return;
  }
  for (const id of [PRODUCT, DEVELOPMENT]) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A removal that fails leaves a realm behind, which is what a run
      // without the switch does anyway; the job's verdict stands.
      log.info("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

test().then(function () {
  return true;
}, function (e) {
  log.error("sts_protocol_declaration FAILED: " + ((e && e.stack) || e));
  return false;
}).then(async function (passed) {
  await removeRealms();
  if (!passed) {
    process.exit(1);
  }
});
