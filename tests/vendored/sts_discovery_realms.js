"use strict";
//
// File: sts_discovery_realms.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT DISCOVERY AND WEBFINGER ON THE REALM MODEL (#119,
// 2026-09-22).
//
// Discovery follows the realm model on the common listener (rcbj's decision):
// an issuer is https://host[/realm/<id>][/<server>], and both discovery shapes
// read that path.
//
//   a. RFC 8414's INSERTED form for a realm and for a server in a realm
//      answers inside the realm: its issuer, its JWKS.
//   b. OIDC Discovery's APPENDED form for the same issuers agrees.
//   c. A path naming nothing — an unknown realm, two server segments — is a
//      404, and creates no authorization server.
//   d. WEBFINGER at the host root: an acct: at the realm's domain, a bare
//      e-mail address, an acct: at the default realm's domain, an https URL
//      with /realm/<id>; a missing or unreadable resource (400), an unknown
//      domain (404), rel filtering, the JRD and its CORS header.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
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
var log = bunyan.createLogger({ name: "sts_discovery_realms",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("disco-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const DOMAIN = REALM + ".example.net";
const SERVER = "t1";
const ISSUER_REL = "http://openid.net/specs/connect/1.0/issuer";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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
    // Not JSON — a 404 page, a text refusal; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers };
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

function webfinger(query) {
  log.debug("Entering webfinger().");
  log.debug("Leaving webfinger().");
  return send(base + "/.well-known/webfinger?" +
              new URLSearchParams(query).toString());
}

async function serverIds(api) {
  log.debug("Entering serverIds().");
  const reply = await send(api + "/authorization-servers");
  log.debug("Leaving serverIds().");
  return ((reply.body && reply.body.authorizationServers) || [])
    .map(function (row) {
      return row && row.id;
    });
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving discovery on the realm model at " + base);
  const realmIssuer = base + "/realm/" + REALM;
  const serverIssuer = realmIssuer + "/" + SERVER;

  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "Discovery " + STAMP }, "created the realm");
  await ok(base + "/realm/" + REALM + "/admin-api/authorization-servers/" +
           "create", { id: SERVER, label: "Discovery server" },
           "created a named server in the realm");
  const realms = await send(base + "/admin-api/realms");
  const defaultRealm = ((realms.body && realms.body.realms) || [])
    .filter(function (one) {
      return one && (one.id === "" || one.id === "default" ||
                     one.isDefault);
    })[0] || {};
  const defaultDomain = String(defaultRealm.domain || "");
  const defaultIssuer = (await send(base +
    "/.well-known/openid-configuration")).body.issuer;

  log.info("=== a. the RFC 8414 inserted form ===");
  let r = await send(base + "/.well-known/oauth-authorization-server/realm/" +
                     REALM);
  check("/.well-known/oauth-authorization-server/realm/<id> is the realm's " +
        "own document", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.strictEqual(r.body.issuer, realmIssuer);
    assert.strictEqual(r.body.jwks_uri, realmIssuer + "/oauth2/jwks");
  });
  r = await send(base + "/.well-known/openid-configuration/realm/" + REALM +
                 "/" + SERVER);
  check("/.well-known/openid-configuration/realm/<id>/<server> is that " +
        "server's, inside the realm", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.strictEqual(r.body.issuer, serverIssuer);
  });

  log.info("=== b. the appended form agrees ===");
  r = await send(realmIssuer + "/.well-known/openid-configuration");
  check("/realm/<id>/.well-known/openid-configuration names the same issuer",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.strictEqual(r.body.issuer, realmIssuer);
  });
  r = await send(serverIssuer + "/.well-known/openid-configuration");
  check("and /realm/<id>/<server>/.well-known/openid-configuration the " +
        "server's", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.strictEqual(r.body.issuer, serverIssuer);
  });

  log.info("=== c. paths that name nothing ===");
  const before = await serverIds(base + "/admin-api");
  for (const path of ["/.well-known/oauth-authorization-server/realm/no-" +
                        STAMP.toLowerCase(),
                      "/.well-known/openid-configuration/t1/x",
                      "/t1/x/.well-known/openid-configuration",
                      "/.well-known/openid-configuration/realm/" + REALM +
                        "/" + SERVER + "/extra"]) {
    r = await send(base + path);
    check(path + " is a 404", function () {
      assert.strictEqual(r.status, 404, r.status + " " + r.raw.slice(0, 200));
    });
  }
  const after = await serverIds(base + "/admin-api");
  check("and no authorization server was created by any of them",
        function () {
    ["realm", "x"].forEach(function (id) {
      assert.ok(before.indexOf(id) >= 0 || after.indexOf(id) < 0,
                "a server called " + id + " appeared");
    });
  });

  log.info("=== d. WebFinger ===");
  r = await webfinger({ resource: "acct:alice@" + DOMAIN, rel: ISSUER_REL });
  check("acct: at the realm's domain answers the realm's issuer, as a JRD " +
        "any origin may read", function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.ok(/application\/jrd\+json/.test(
      r.headers.get("content-type") || ""), r.headers.get("content-type"));
    assert.strictEqual(r.headers.get("access-control-allow-origin"), "*");
    assert.strictEqual(r.body.subject, "acct:alice@" + DOMAIN);
    assert.deepStrictEqual(r.body.links, [{ rel: ISSUER_REL,
                                            href: realmIssuer }]);
  });
  r = await webfinger({ resource: "nobody-at-all@" + DOMAIN });
  check("a bare e-mail address is the same, and nobody is looked up",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.strictEqual(r.body.links[0].href, realmIssuer);
  });
  if (defaultDomain) {
    r = await webfinger({ resource: "acct:bob@" + defaultDomain });
    check("acct: at the default realm's domain answers its issuer",
          function () {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
      assert.strictEqual(r.body.links[0].href, defaultIssuer);
    });
  }
  r = await webfinger({ resource: realmIssuer });
  check("an https URL on this service resolves by its /realm/<id> path",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.strictEqual(r.body.links[0].href, realmIssuer);
  });
  r = await webfinger({ resource: "acct:alice@" + DOMAIN,
                        rel: "http://webfinger.net/rel/avatar" });
  check("a rel filter that names another relation leaves no link",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
    assert.deepStrictEqual(r.body.links, []);
  });
  r = await webfinger({});
  check("no resource is a 400 (RFC 7033 section 4.2)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 200));
  });
  r = await webfinger({ resource: "mailto:x" });
  check("an unreadable resource is a 400", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 200));
  });
  r = await webfinger({ resource: "acct:alice@unknown-" + STAMP.toLowerCase() +
                                  ".example.org" });
  check("an unknown domain is a 404", function () {
    assert.strictEqual(r.status, 404, r.raw.slice(0, 200));
  });

  assert.ok(checks >= 15, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_discovery_realms")
  .description("Discovery and WebFinger on the realm model (#119).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
