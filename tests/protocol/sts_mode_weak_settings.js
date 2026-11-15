// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   4. THE CODES BEHIND TWO OF THEM (D12, #444: carries over the
//      over-the-wire half of tests/mode_weak_settings.js B). A SHA-1 XML
//      signature presented to the RFC 7522 token endpoint — an assertion a
//      person signed with RSA-SHA1 over a SHA-1 digest — is refused before
//      any cryptography with saml.allowSha1Signatures off, its sentence
//      saying so (the door records its own STS-OAUTH-0067; the verifier's
//      STS-KEYS-0062 reaches no audit row), accepted in development with it
//      on, and refused again in product with it still on; a certificate
//      authority build naming sha1-rsa is accepted in development and
//      refused in product (STS-PKI-0191 on the audit row).
//
// What no HTTP request reaches without a partner — an rsa-1_5 EncryptedKey
// unwrapped (STS-KEYS-0070, a LogoutRequest's EncryptedID: the SAML
// encryption family's to carry), an assertion built under an application's
// override, the KDC's own clock — is asserted in process by
// `tests/mode_weak_settings.js`.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const nodeCrypto = require("crypto");
const signer = require("./saml_xmldsig.js");
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
  const consoleClient = await signin.signInToTheConsole(base,
    "weakmode-" + STAMP, log, { grant: "read" });
  const page = await consoleClient.get("/admin/mode");
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
  const pageJson = await consoleClient.get("/admin/mode?format=json");
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

// The newest audit sequence number of a realm, and the codes recorded after
// one; a response carries no code.
async function newestSeq(realm) {
  log.debug("Entering newestSeq().");
  const r = await call("GET", realmBase(realm) + "/admin-api/audit?per=1");
  log.debug("Leaving newestSeq().");
  return (r.json && r.json.newestSeq) || 0;
}

async function codesSince(realm, since, wanted) {
  log.debug("Entering codesSince().");
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await call("GET", realmBase(realm) +
                         "/admin-api/audit?per=200");
    found = ((r.json && r.json.events) || []).filter(function (row) {
      return row.seq > since && row.errorCode;
    }).map(function (row) {
      return row.errorCode;
    });
    if (found.indexOf(wanted) >= 0) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 150);
    });
  }
  log.debug("Leaving codesSince(). " + found.join(","));
  return found;
}

// An assertion signed RSA-SHA1 over a SHA-1 digest: `saml_xmldsig.js`'s
// signature with the two algorithms SHA-1's, by hand, so the signature is
// real and only the algorithm is at issue.
function signSha1(built, privateKeyPem, certPem) {
  log.debug("Entering signSha1().");
  const DS = "http://www.w3.org/2000/09/xmldsig#";
  const EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
  const digest = nodeCrypto.createHash("sha1")
    .update(Buffer.from(built.xml, "utf8")).digest("base64");
  const signedInfo = "<ds:SignedInfo xmlns:ds=\"" + DS + "\">" +
    "<ds:CanonicalizationMethod Algorithm=\"" + EXC + "\"></ds:" +
    "CanonicalizationMethod><ds:SignatureMethod Algorithm=\"" + DS +
    "rsa-sha1\"></ds:SignatureMethod><ds:Reference URI=\"#" + built.id +
    "\"><ds:Transforms><ds:Transform Algorithm=\"" + DS +
    "enveloped-signature\"></ds:Transform><ds:Transform Algorithm=\"" +
    EXC + "\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=" +
    "\"" + DS + "sha1\"></ds:DigestMethod><ds:DigestValue>" + digest +
    "</ds:DigestValue></ds:Reference></ds:SignedInfo>";
  const value = nodeCrypto.sign("sha1", Buffer.from(signedInfo, "utf8"),
                                privateKeyPem).toString("base64");
  const keyInfo = "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" +
    String(certPem).replace(/-----[^-]+-----/g, "").replace(/\s+/g, "") +
    "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";
  const signature = "<ds:Signature xmlns:ds=\"" + DS + "\">" + signedInfo +
    "<ds:SignatureValue>" + value + "</ds:SignatureValue>" + keyInfo +
    "</ds:Signature>";
  const marker = "</saml:Issuer>";
  const at = built.xml.indexOf(marker) + marker.length;
  log.debug("Leaving signSha1().");
  return built.xml.slice(0, at) + signature + built.xml.slice(at);
}

async function sha1Grant(realm, person, issued) {
  log.debug("Entering sha1Grant().");
  const endpoint = realmBase(realm) + "/oauth2/token";
  const built = signer.buildAssertion({ issuer: person, subject: person,
                                        audience: endpoint,
                                        recipient: endpoint });
  const r = await call("POST", endpoint, new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:saml2-bearer",
    assertion: signer.b64u(signSha1(built, issued.privateKeyPem,
                                    issued.certificatePem)) }).toString(),
    { "Content-Type": "application/x-www-form-urlencoded" });
  log.debug("Leaving sha1Grant().");
  return r;
}

async function theCodes() {
  log.debug("Entering theCodes().");
  log.info("=== 4. the codes behind a SHA-1 signature and a SHA-1 CA ===");
  const SHA = ("weakmode-s-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
    .slice(0, 31);
  const CA = ("weakmode-c-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
    .slice(0, 31);
  // BOTH START IN DEVELOPMENT, SAID SO (run #300): each half asserts the
  // development answer first and then puts its realm in product, so in a
  // product process a realm made without the override would be product
  // from the start and refuse saml.allowSha1Signatures — setUp()'s DEV
  // realm says it the same way.
  for (const id of [SHA, CA]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Weak settings " + STAMP,
      overrides: { "global.mode": "development" } },
      "created the realm " + id);
  }
  try {
    await sha1Codes(SHA, CA);
  } finally {
    // REMOVED ONLY WHEN ASKED (STS_TEST_REMOVE_REALMS=1, a hand run against
    // a long-lived probe): tests/CLAUDE.md's *No job removes a realm* is the
    // rule for a shared run.
    if (process.env.STS_TEST_REMOVE_REALMS === "1") {
      for (const id of [SHA, CA]) {
        await call("POST", base + "/admin-api/realms/remove", { id: id });
      }
    }
  }
  log.debug("Leaving theCodes().");
}

async function sha1Codes(SHA, CA) {
  log.debug("Entering sha1Codes().");
  const PERSON = "weak-sha1-signer";
  await ok(realmBase(SHA) + "/admin-api/pki/build",
           { organisation: "Weak settings", country: "US" },
           "built a certificate authority");
  await ok(realmBase(SHA) + "/admin-api/users/create", { username: PERSON,
    invent: false, credential: "none", attributes: { cn: PERSON,
      sn: "Signer", givenName: "Weak", mail: PERSON + "@" + SHA +
      ".example.net" } }, "created the signer");
  const issued = await ok(realmBase(SHA) + "/admin-api/pki/issue",
    { identifier: PERSON, target: "person", purpose: "saml",
      keyAlg: "rsa-2048" }, "issued an RFC 7522 key pair");
  let since = await newestSeq(SHA);
  const off = await sha1Grant(SHA, PERSON, issued);
  // OBSERVED: the grant records its own code, STS-OAUTH-0067 (no
  // signature verified), and the sentence carries the verifier's reason;
  // STS-KEYS-0062 itself is not on an audit row of this door.
  const offCodes = await codesSince(SHA, since, "STS-OAUTH-0067");
  check("development, saml.allowSha1Signatures off: a SHA-1 signature is " +
        "refused before it is verified, saying why (STS-OAUTH-0067 on the " +
        "audit row)", function () {
    assert.strictEqual(off.status, 400, off.text.slice(0, 300));
    assert.strictEqual(off.json.error, "invalid_grant");
    assert.ok(/uses SHA-1/.test(off.json.error_description) &&
              /saml\.allowSha1Signatures is off/
                .test(off.json.error_description), off.text.slice(0, 400));
    assert.ok(offCodes.indexOf("STS-OAUTH-0067") >= 0, offCodes.join(","));
  });
  await setting(SHA, "saml.allowSha1Signatures", true);
  const on = await sha1Grant(SHA, PERSON, issued);
  check("development, with it on: the same assertion is accepted",
        function () {
    assert.strictEqual(on.status, 200, on.text.slice(0, 300));
    assert.ok(on.json.access_token);
  });
  await setting(SHA, "global.mode", "product");
  since = await newestSeq(SHA);
  const product = await sha1Grant(SHA, PERSON, issued);
  const productCodes = await codesSince(SHA, since, "STS-OAUTH-0067");
  check("product, saml.allowSha1Signatures still on: refused again for " +
        "SHA-1 (STS-OAUTH-0067)", function () {
    assert.strictEqual(product.status, 400, product.text.slice(0, 300));
    assert.ok(/uses SHA-1/.test(product.json.error_description),
              product.text.slice(0, 400));
    assert.ok(productCodes.indexOf("STS-OAUTH-0067") >= 0,
              productCodes.join(","));
  });

  const devBuild = await call("POST", realmBase(CA) + "/admin-api/pki/build",
    { keyAlg: "rsa-2048", signatureAlg: "sha1-rsa" });
  check("development: a certificate authority may be built naming sha1-rsa",
        function () {
    assert.strictEqual(devBuild.status, 200, devBuild.text.slice(0, 300));
  });
  await setting(CA, "global.mode", "product");
  since = await newestSeq(CA);
  const prodBuild = await call("POST", realmBase(CA) +
    "/admin-api/pki/build", { keyAlg: "rsa-2048", signatureAlg: "sha1-rsa" });
  const buildCodes = await codesSince(CA, since, "STS-PKI-0191");
  check("product: a build naming sha1-rsa is refused (STS-PKI-0191 on the " +
        "audit row)", function () {
    assert.strictEqual(prodBuild.status, 400, prodBuild.text.slice(0, 300));
    assert.ok(buildCodes.indexOf("STS-PKI-0191") >= 0, buildCodes.join(","));
    assert.ok(prodBuild.text.indexOf("STS-") < 0, "a code was sent");
  });
  log.debug("Leaving sha1Codes().");
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
  await theCodes();
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
