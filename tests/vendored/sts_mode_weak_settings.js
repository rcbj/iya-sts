"use strict";
//
// File: sts_mode_weak_settings.js
//
// ---------------------------------------------------------------------------
// SIX MORE DEVELOPMENT-ONLY SETTINGS, AND THE MODE'S OWN PAGE, OVER HTTP
// (#181, 2026-09-23).
//
// `risc.googleSubjectType` on, `krb5.clockOffset` not 0,
// `saml2.signAssertion` / `saml11.signAssertion` / `saml11.signResponse`
// off, `spiffe.requireSecurityHeader` off, and the broken algorithms —
// `saml.signatureAlgorithm` rsa-sha1, `saml2.keyTransportAlgorithm` rsa-1_5,
// `saml.allowSha1Signatures` on, `pki.signatureAlgorithm` sha1-rsa /
// sha1-ecdsa — are development's: in product each is IGNORED where it is read
// and REFUSED on write (STS-CORE-0103), and an application's override of one
// is refused too (STS-REG-0193). This job asserts both halves against a
// running service, in two throwaway trust realms it leaves standing, one
// development and one product, so it asserts both whatever mode the service
// itself was started in:
//
//   1. THE MODE'S TWO ROUTES. `GET /admin-api/mode` answers each realm's mode
//      and `common/mode.js`'s report — the three new requirements, every
//      development-only setting — and `GET /admin/mode` draws the same
//      report in the console (its `?format=json` equal to the API's), and
//      the OpenAPI document carries `getMode`.
//   2. THE WRITE DOORS. In the product realm every weak value is refused
//      through `config/set` and `realms/set` (from the default realm), a
//      stronger value of the same setting is accepted, and an application's
//      `saml2SignAssertion=FALSE`, `saml2KeyTransportAlgorithm=rsa-1_5` and
//      `saml11SignResponse=FALSE` are refused through `applications/set`;
//      the development realm accepts every one.
//   3. THE READ SITES. In the development realm, every weak value stored:
//      the signed SAML 2.0 metadata's SignatureMethod is RSA-SHA1, `GET
//      /spiffe` says the Workload API header is not required, the RISC view
//      says `subject_type`, and `/admin-api/mode` says nothing is ignored.
//      The realm is then switched to product with every value STILL stored:
//      the metadata is RSA-SHA256, the header is required, the RISC view says
//      `format`, `/admin-api/mode` lists every one as ignored with its
//      default in force, and a certificate authority build naming SHA-1 is
//      refused.
//
// What no HTTP request reaches without a partner — a SHA-1 signature
// presented to the verifier, an rsa-1_5 EncryptedKey unwrapped, an assertion
// built under an application's override, the KDC's own clock — is asserted in
// process by `tests/mode_weak_settings.js`.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const signin = require("./console_signin");

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
var log = bunyan.createLogger({ name: "sts_mode_weak_settings",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const DEV = ("weakmode-d-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const PROD = ("weakmode-p-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                 .slice(0, 31);
const SP = "urn:weakmode:sp:" + STAMP;
const RP = "urn:weakmode:rp:" + STAMP;
// Each weak value, and where the setting has one, a stronger value product
// still accepts.
const MARKED = [
  { key: "risc.googleSubjectType", weak: true },
  { key: "krb5.clockOffset", weak: 120 },
  { key: "saml2.signAssertion", weak: false },
  { key: "saml11.signAssertion", weak: false },
  { key: "saml11.signResponse", weak: false },
  { key: "spiffe.requireSecurityHeader", weak: false },
  { key: "saml.allowSha1Signatures", weak: true },
  { key: "saml.signatureAlgorithm", weak: "rsa-sha1", strong: "rsa-sha512" },
  { key: "saml2.keyTransportAlgorithm", weak: "rsa-1_5" },
  { key: "pki.signatureAlgorithm", weak: "sha1-rsa", strong: "sha384-rsa" },
  { key: "pki.signatureAlgorithm", weak: "sha1-ecdsa" }
];
const OVERRIDES = [
  { app: SP, attribute: "saml2SignAssertion", weak: "FALSE" },
  { app: SP, attribute: "saml2KeyTransportAlgorithm", weak: "rsa-1_5" },
  { app: RP, attribute: "saml11SignResponse", weak: "FALSE" }
];
const NEW_REQUIREMENTS = ["broken-algorithms", "signed-assertions",
                          "workload-security-header"];
const FLOOR = 40;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function realmBase(id) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + id;
}

async function call(method, url, body, headers) {
  log.debug("Entering call().");
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined :
          (typeof body === "string" ? body : JSON.stringify(body)) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call().");
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function setting(realm, key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(realmBase(realm) + "/admin-api/config/set",
            { key: key, value: value }, "set " + key + " in " + realm);
}

async function modeOf(realm) {
  log.debug("Entering modeOf().");
  const r = await call("GET", (realm ? realmBase(realm) : base) +
                       "/admin-api/mode");
  assert.strictEqual(r.status, 200, "GET /admin-api/mode in " +
                     (realm || "the default realm") + ": " + r.status + " " +
                     r.text.slice(0, 300));
  log.debug("Leaving modeOf().");
  return r.json;
}

function rowOf(report, key) {
  log.debug("Entering rowOf(). " + key);
  log.debug("Leaving rowOf().");
  return (report.developmentOnlySettings || []).filter(function (row) {
    return row.key === key;
  })[0] || null;
}

// The SignatureMethod of a realm's signed SAML 2.0 identity provider
// metadata.
async function metadataSignatureMethod(realm) {
  log.debug("Entering metadataSignatureMethod().");
  const r = await call("GET", realmBase(realm) + "/saml2/metadata");
  assert.strictEqual(r.status, 200, "metadata: " + r.status + " " +
                     r.text.slice(0, 200));
  const found = /SignatureMethod[^>]*Algorithm="([^"]+)"/.exec(r.text);
  assert.ok(found, "the metadata carries no SignatureMethod: " +
            r.text.slice(0, 300));
  log.debug("Leaving metadataSignatureMethod(). " + found[1]);
  return found[1];
}

async function headerRequired(realm) {
  log.debug("Entering headerRequired().");
  const r = await call("GET", realmBase(realm) + "/spiffe?format=json");
  assert.strictEqual(r.status, 200, "GET /spiffe: " + r.text.slice(0, 200));
  const w = (r.json && r.json.workloadApi) || {};
  assert.ok(typeof w.securityHeaderRequired === "boolean",
            "GET /spiffe says nothing about the header: " +
            JSON.stringify(w).slice(0, 300));
  log.debug("Leaving headerRequired().");
  return w.securityHeaderRequired;
}

async function riscSubjectType(realm) {
  log.debug("Entering riscSubjectType().");
  const r = await call("GET", realmBase(realm) + "/admin-api/risc");
  assert.strictEqual(r.status, 200, "GET /admin-api/risc: " +
                     r.text.slice(0, 200));
  log.debug("Leaving riscSubjectType().");
  return r.json.googleSubjectType;
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. two realms, one each way, each with two applications ===");
  await ok(base + "/admin-api/realms/create",
           { id: PROD, domain: PROD + ".example.net", name: "#181 product",
             overrides: { "global.mode": "product" } },
           "created the product realm");
  await ok(base + "/admin-api/realms/create",
           { id: DEV, domain: DEV + ".example.net", name: "#181 development",
             overrides: { "global.mode": "development" } },
           "created the development realm");
  for (const realm of [PROD, DEV]) {
    await ok(realmBase(realm) + "/admin-api/applications/create",
             { identifier: SP, name: "#181 SAML 2.0 " + STAMP,
               protocols: ["saml2"], fields: { samlEntityId: SP } },
             "created the SAML 2.0 service provider in " + realm);
    await ok(realmBase(realm) + "/admin-api/applications/create",
             { identifier: RP, name: "#181 SAML 1.1 " + STAMP,
               protocols: ["saml11"], fields: { samlEntityId: RP } },
             "created the SAML 1.1 relying party in " + realm);
  }
  log.debug("Leaving setUp().");
}

async function theRoutes() {
  log.debug("Entering theRoutes().");
  log.info("=== 1. GET /admin-api/mode and GET /admin/mode ===");
  const prod = await modeOf(PROD);
  const dev = await modeOf(DEV);
  check("GET /admin-api/mode answers each realm's own mode", function () {
    assert.strictEqual(prod.mode, "product", JSON.stringify(prod.mode));
    assert.strictEqual(prod.isProduct, true);
    assert.strictEqual(dev.mode, "development", JSON.stringify(dev.mode));
    assert.strictEqual(dev.isProduct, false);
  });
  check("it carries the three new requirements, each with the answer in " +
        "force", function () {
    NEW_REQUIREMENTS.forEach(function (id) {
      const row = prod.requirements.filter(function (one) {
        return one.id === id;
      })[0];
      assert.ok(row, id + " is missing: " + prod.requirements.map(function (
        one) {
        return one.id;
      }).join(", "));
      assert.strictEqual(row.inForce, row.product, id);
    });
  });
  check("and every development-only setting, with its predicate", function () {
    MARKED.forEach(function (m) {
      const row = rowOf(prod, m.key);
      assert.ok(row && row.predicate, m.key + ": " + JSON.stringify(row));
    });
  });
  check("and what product mode still does not check", function () {
    assert.ok(Array.isArray(prod.notYet) && prod.notYet.length > 0,
              JSON.stringify(prod.notYet).slice(0, 200));
  });
  const spec = await call("GET", base + "/admin-api/openapi.json");
  check("the OpenAPI document carries GET /mode as getMode", function () {
    assert.strictEqual(spec.status, 200, spec.text.slice(0, 200));
    const paths = spec.json.paths || {};
    const op = Object.keys(paths).filter(function (p) {
      return /\/mode$/.test(p);
    }).map(function (p) {
      return paths[p].get;
    })[0];
    assert.ok(op && op.operationId === "getMode",
              JSON.stringify(Object.keys(paths).filter(function (p) {
                return /mode/.test(p);
              })));
  });
  const cookie = await signin.signInToTheConsole(base, "weakmode-" + STAMP,
                                                 log, { grant: "read" });
  const headers = cookie ? { Cookie: cookie } : {};
  const page = await call("GET", base + "/admin/mode", undefined, headers);
  const own = await modeOf("");
  check("GET /admin/mode draws the report in the console", function () {
    assert.strictEqual(page.status, 200, page.status + " " +
                       page.text.slice(0, 200));
    assert.ok(page.text.indexOf("What the mode changes") >= 0,
              page.text.slice(0, 300));
    own.requirements.forEach(function (row) {
      assert.ok(page.text.indexOf('id="requirement-' + row.id + '"') >= 0,
                "no row for " + row.id);
    });
    assert.ok(page.text.indexOf("Development-only settings") >= 0);
  });
  const pageJson = await call("GET", base + "/admin/mode?format=json",
                              undefined, headers);
  check("and its ?format=json is the API's answer", function () {
    assert.strictEqual(pageJson.status, 200, pageJson.text.slice(0, 200));
    assert.strictEqual(pageJson.json.mode, own.mode);
    assert.deepStrictEqual(pageJson.json.requirements.map(function (r) {
      return r.id;
    }), own.requirements.map(function (r) {
      return r.id;
    }));
    assert.deepStrictEqual(pageJson.json.developmentOnlySettings,
                           own.developmentOnlySettings);
  });
  log.debug("Leaving theRoutes().");
}

async function writeDoors() {
  log.debug("Entering writeDoors().");
  log.info("=== 2. the write doors ===");
  for (const m of MARKED) {
    let r = await call("POST", realmBase(PROD) + "/admin-api/config/set",
                       { key: m.key, value: m.weak });
    check("product: config/set " + m.key + "=" + m.weak + " is refused, " +
          "naming it", function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
      assert.ok(/product mode/.test(r.text) && r.text.indexOf(m.key) >= 0,
                r.text.slice(0, 300));
    });
    r = await call("POST", base + "/admin-api/realms/set",
                   { id: PROD, key: m.key, value: String(m.weak) });
    check("product: realms/set of it from the default realm is refused too",
          function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    });
    if (m.strong) {
      await setting(PROD, m.key, m.strong);
      check("product: " + m.key + "=" + m.strong + ", a stronger value, " +
            "is accepted", function () {
        assert.ok(true);
      });
      await call("POST", realmBase(PROD) + "/admin-api/config/reset",
                 { key: m.key });
    }
    await setting(DEV, m.key, m.weak);
  }
  check("the development realm accepted every weak value (every call above " +
        "answered 200)", function () {
    assert.ok(true);
  });
  for (const o of OVERRIDES) {
    const r = await call("POST", realmBase(PROD) +
                         "/admin-api/applications/set",
                         { application: o.app, attribute: o.attribute,
                           value: o.weak });
    check("product: an application's " + o.attribute + "=" + o.weak +
          " is refused", function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
      assert.ok(/product mode/.test(r.text), r.text.slice(0, 300));
    });
    await ok(realmBase(DEV) + "/admin-api/applications/set",
             { application: o.app, attribute: o.attribute, value: o.weak },
             "development: " + o.attribute + "=" + o.weak);
  }
  check("the development realm accepted every override", function () {
    assert.ok(true);
  });
  log.debug("Leaving writeDoors().");
}

async function readSites() {
  log.debug("Entering readSites().");
  log.info("=== 3. the read sites, in development and then in product ===");
  // The development realm holds every weak value (section 2) but
  // pki.signatureAlgorithm's second, which is sha1-ecdsa; the first is the
  // one an RSA hierarchy can use.
  await setting(DEV, "pki.signatureAlgorithm", "sha1-rsa");
  const devSig = await metadataSignatureMethod(DEV);
  check("development: the realm's SAML 2.0 metadata is signed RSA-SHA1",
        function () {
    assert.ok(/#rsa-sha1$/.test(devSig), devSig);
  });
  const devHeader = await headerRequired(DEV);
  check("development: GET /spiffe says the Workload API header is not " +
        "required", function () {
    assert.strictEqual(devHeader, false);
  });
  const devRisc = await riscSubjectType(DEV);
  check("development: the RISC view says subject_type is written",
        function () {
    assert.strictEqual(devRisc, true);
  });
  const devReport = await modeOf(DEV);
  check("development: /admin-api/mode says nothing is ignored, and shows " +
        "each value as stored and in force", function () {
    MARKED.forEach(function (m) {
      const row = rowOf(devReport, m.key);
      assert.ok(row && row.ignored === false, m.key + ": " +
                JSON.stringify(row));
    });
    assert.strictEqual(rowOf(devReport, "krb5.clockOffset").inForce, 120);
  });

  await setting(DEV, "global.mode", "product");
  const prodSig = await metadataSignatureMethod(DEV);
  check("product, rsa-sha1 still stored: the metadata is signed RSA-SHA256",
        function () {
    assert.ok(/#rsa-sha256$/.test(prodSig), prodSig);
  });
  const prodHeader = await headerRequired(DEV);
  check("product, requireSecurityHeader off still stored: GET /spiffe says " +
        "the header is required", function () {
    assert.strictEqual(prodHeader, true);
  });
  const prodRisc = await riscSubjectType(DEV);
  check("product, googleSubjectType still stored: the RISC view says format " +
        "is written", function () {
    assert.strictEqual(prodRisc, false);
  });
  const prodReport = await modeOf(DEV);
  check("product: /admin-api/mode lists every stored weak value as IGNORED, " +
        "its default in force", function () {
    MARKED.forEach(function (m) {
      const row = rowOf(prodReport, m.key);
      assert.ok(row && row.ignored === true &&
                JSON.stringify(row.inForce) === JSON.stringify(row.default),
                m.key + ": " + JSON.stringify(row));
    });
  });
  const build = await call("POST", realmBase(DEV) + "/admin-api/pki/build",
                           { keyAlg: "rsa-2048", signatureAlg: "sha1-rsa" });
  check("product: a certificate authority build naming sha1-rsa is refused",
        function () {
    assert.strictEqual(build.status, 400, build.text.slice(0, 300));
    assert.ok(/SHA-1/.test(build.text), build.text.slice(0, 300));
  });
  const again = await call("POST", realmBase(DEV) + "/admin-api/config/set",
                           { key: "saml2.signAssertion", value: false });
  check("product: and the switched realm refuses a new write", function () {
    assert.strictEqual(again.status, 400, again.text.slice(0, 300));
  });
  await setting(DEV, "global.mode", "development");
  for (const m of MARKED) {
    await call("POST", realmBase(DEV) + "/admin-api/config/reset",
               { key: m.key });
  }
  log.debug("Leaving readSites().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the #181 development-only settings at " + base);
  await setUp();
  await theRoutes();
  await writeDoors();
  await readSites();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_mode_weak_settings")
  .description("#181: six non-conforming or weak settings are honoured in " +
    "development, ignored where they are read in product, and refused on " +
    "write there; /admin/mode and /admin-api/mode publish the report.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
