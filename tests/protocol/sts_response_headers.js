// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_response_headers.js
//
// ---------------------------------------------------------------------------
// THE RULES EVERY RESPONSE FOLLOWS, ASKED OF A RUNNING SERVICE.
//
// D12 (#444): carries over, in a development and a product realm this job
// creates and leaves behind,
//
//   * `tests/asvs_response_rules.js` (#1438, #1439, #1442): HSTS in product
//     over TLS on a route and on the framework's 404, never in development;
//     a charset named on text and XML answers and left off a JOSE type; a
//     cookie write from another site refused (`POST /authn/language`, the
//     JSON `POST /logout`) and this service's own and a program's taken;
//     no refusal naming an error code;
//   * `tests/cookie_wire.js` (#1441): in product over TLS a cookie leaves
//     as `__Host-`, a request's `__Host-` cookie arrives under its inside
//     name and an unprefixed one is dropped; in development neither;
//   * `tests/qualys_hardening.js` (2026-11-10): Permissions-Policy on every
//     answer, a narrowed policy on a JSON answer and the base one on a page,
//     COOP and CORP on the three static applications and on nothing else,
//     the branding preview's form, the four sentences that refuse without
//     repeating the probe (SAML's in product), and the switched-off VC
//     API's 501 audited `refused`;
//   * `tests/parse_body_non_object.js` (#1346): a JSON body of `null` or a
//     primitive is refused at `/admin-api` as `{}` is, never a 500, and no
//     STS-HTTP-0003 is recorded;
//   * `tests/healthcheck.js`: `/healthcheck` answers on the main port and
//     through the plain-HTTP revocation listener, whose filter refuses any
//     other path, and a successful probe moves `calls.healthProbes`.
//
// The revocation listener is `PKI_DISTRIBUTION_BASE_URL` (the launcher's
// `http://sts:8082`), or port 8082 of the service's host.
//
// OWNED HERE (local: true): this repository's own HTTP spine.
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
var log = bunyan.createLogger({ name: "sts_response_headers",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
var plainBase = String(process.env.PKI_DISTRIBUTION_BASE_URL ||
                       "http://" + new URL(base).hostname + ":8082")
  .replace(/\/+$/, "");
const STAMP = names.runStamp();
function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                       .slice(0, 31);
}
const DEV = realmId("hdrd-");
const PROD = realmId("hdrp-");
const HSTS = "max-age=31536000; includeSubDomains";
const CODE = /STS-[A-Z0-9]+-\d{4}/;

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
    // Not JSON — a page or a document; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, headers: r.headers, body: body, raw: raw };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof payload === "string" ? payload
                                      : JSON.stringify(payload || {}) });
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

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function auditRows(realm, query) {
  log.debug("Entering auditRows().");
  const r = await send(base + "/realm/" + realm + "/admin-api/audit?per=500" +
                       (query || ""));
  log.debug("Leaving auditRows().");
  return (r.body && (r.body.events || r.body.rows)) || [];
}

function header(r, name) {
  log.debug("Entering header().");
  log.debug("Leaving header().");
  return String(r.headers.get(name) || "");
}

async function sectionHsts() {
  log.debug("Entering sectionHsts().");
  log.info("=== 1. HSTS ===");
  const route = await send(base + "/realm/" + PROD + "/healthcheck");
  const unrouted = await send(base + "/realm/" + PROD + "/no/such/path");
  check("product over TLS sends HSTS on a route and on the framework's 404",
        function () {
    assert.strictEqual(route.status, 200);
    assert.strictEqual(header(route, "strict-transport-security"), HSTS);
    assert.strictEqual(unrouted.status, 404);
    assert.strictEqual(header(unrouted, "strict-transport-security"), HSTS);
  });
  const dev = await send(base + "/realm/" + DEV + "/healthcheck");
  check("never in development", function () {
    assert.strictEqual(dev.status, 200);
    assert.strictEqual(dev.headers.get("strict-transport-security"), null);
  });
  log.debug("Leaving sectionHsts().");
}

async function sectionCharset() {
  log.debug("Entering sectionCharset().");
  log.info("=== 2. the charset ===");
  const named = [
    ["/saml2/metadata", "application/samlmetadata+xml"],
    ["/saml11/metadata", "application/samlmetadata+xml"],
    ["/FederationMetadata/2007-06/FederationMetadata.xml", "application/xml"],
    ["/web/card.css", "text/css"],
    ["/no/such/path", "text/html"]
  ];
  for (const one of named) {
    const r = await send(base + "/realm/" + DEV + one[0]);
    check(one[0] + " names utf-8 on " + one[1], function () {
      assert.strictEqual(header(r, "content-type"),
                         one[1] + "; charset=utf-8");
    });
  }
  const jose = await send(base + "/realm/" + DEV +
                          "/.well-known/openid-federation");
  check("a JOSE type is left alone", function () {
    assert.strictEqual(jose.status, 200);
    assert.strictEqual(header(jose, "content-type"),
                       "application/entity-statement+jwt");
  });
  log.debug("Leaving sectionCharset().");
}

function language(realm, headers) {
  log.debug("Entering language().");
  log.debug("Leaving language().");
  return send(base + "/realm/" + realm + "/authn/language", {
    method: "POST",
    headers: Object.assign({ "Content-Type":
                             "application/x-www-form-urlencoded" }, headers),
    body: "lang=fr&return=/" });
}

function signOut(realm, headers) {
  log.debug("Entering signOut().");
  log.debug("Leaving signOut().");
  return send(base + "/realm/" + realm + "/logout", {
    method: "POST",
    headers: Object.assign({ "Content-Type": "application/json",
                             Accept: "application/json" }, headers),
    body: "{}" });
}

async function sectionCrossSite() {
  log.debug("Entering sectionCrossSite().");
  log.info("=== 3. a cookie write from another site ===");
  const own = new URL(base).origin;
  const refusals = [];
  let r = await language(DEV, { Origin: "https://evil.example" });
  refusals.push(r);
  check("the language chooser refuses another Origin, saying why",
        function () {
    assert.strictEqual(r.status, 403);
    assert.strictEqual(r.raw,
                       "The language is chosen from a page of this service.");
    assert.strictEqual(r.headers.get("set-cookie"), null);
  });
  r = await language(DEV, { Origin: "null", "Sec-Fetch-Site": "cross-site" });
  refusals.push(r);
  check("and a null Origin from another site", function () {
    assert.strictEqual(r.status, 403);
  });
  r = await language(DEV, { Origin: "null" });
  refusals.push(r);
  check("and a null Origin nothing vouches for", function () {
    assert.strictEqual(r.status, 403);
  });
  r = await language(DEV, { Origin: "null", "Sec-Fetch-Site": "same-origin" });
  check("it takes this service's own form under no-referrer", function () {
    assert.strictEqual(r.status, 303);
  });
  r = await language(DEV, { Origin: own });
  check("its own Origin", function () {
    assert.strictEqual(r.status, 303);
    assert.strictEqual(header(r, "location"), "/realm/" + DEV + "/");
  });
  r = await language(DEV, {});
  check("and a program with neither header", function () {
    assert.strictEqual(r.status, 303);
  });
  r = await signOut(DEV, { Origin: "https://evil.example" });
  refusals.push(r);
  check("the JSON sign-out refuses another Origin", function () {
    assert.strictEqual(r.status, 403);
  });
  r = await signOut(DEV, { "Sec-Fetch-Site": "cross-site" });
  refusals.push(r);
  check("and a cross-site fetch", function () {
    assert.strictEqual(r.status, 403);
  });
  r = await signOut(DEV, { Origin: own });
  const program = await signOut(DEV, {});
  check("it answers its own Origin and a program", function () {
    assert.notStrictEqual(r.status, 403, r.raw.slice(0, 200));
    assert.notStrictEqual(program.status, 403, program.raw.slice(0, 200));
  });
  check("no refusal carries an error code", function () {
    refusals.forEach(function (one) {
      assert.ok(!CODE.test(one.raw), one.raw.slice(0, 200));
    });
  });
  log.debug("Leaving sectionCrossSite().");
}

function langOf(raw) {
  log.debug("Entering langOf().");
  log.debug("Leaving langOf().");
  return (String(raw).match(/data-sts-lang="([a-z-]*)"/) || ["", ""])[1];
}

async function sectionCookies() {
  log.debug("Entering sectionCookies().");
  log.info("=== 4. cookies on the wire ===");
  const prod = await language(PROD, {});
  const dev = await language(DEV, {});
  check("in product over TLS a cookie leaves as __Host-, its attributes kept",
        function () {
    assert.strictEqual(header(prod, "set-cookie"), "__Host-sts_lang=fr; " +
      "Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax; Secure");
  });
  check("in development it leaves under its own name", function () {
    assert.strictEqual(header(dev, "set-cookie"), "sts_lang=fr; Path=/; " +
      "Max-Age=31536000; HttpOnly; SameSite=Lax; Secure");
  });
  const session = await send(base + "/realm/" + PROD + "/admin");
  check("the session cookie is __Host- in product too", function () {
    assert.ok(/^__Host-sts_session=[^;]+; Path=\/; HttpOnly; SameSite=Lax; Secure$/
      .test(header(session, "set-cookie")), header(session, "set-cookie"));
  });
  const asked = async function (realm, cookie) {
    const r = await send(base + "/realm/" + realm + "/", {
      headers: { Cookie: cookie } });
    return langOf(r.raw);
  };
  const prodHost = await asked(PROD, "__Host-sts_lang=fr");
  const prodBare = await asked(PROD, "sts_lang=fr");
  const prodSecure = await asked(PROD, "__Secure-sts_lang=fr");
  check("in product a request's __Host- cookie arrives under its inside " +
        "name, and an unprefixed or __Secure- one is dropped", function () {
    assert.strictEqual(prodHost, "fr");
    assert.strictEqual(prodBare, "");
    assert.strictEqual(prodSecure, "");
  });
  const devBare = await asked(DEV, "sts_lang=fr");
  const devHost = await asked(DEV, "__Host-sts_lang=fr");
  check("in development the bare name is read and the prefixed one is not",
        function () {
    assert.strictEqual(devBare, "fr");
    assert.strictEqual(devHost, "");
  });
  log.debug("Leaving sectionCookies().");
}

async function sectionQualys() {
  log.debug("Entering sectionQualys().");
  log.info("=== 5. what the Qualys scan asked for ===");
  const discovery = await send(base + "/realm/" + DEV +
                               "/.well-known/openid-configuration",
                               { headers: { Accept: "application/json" } });
  const pp = header(discovery, "permissions-policy");
  check("Permissions-Policy allows WebAuthn, the Digital Credentials API, " +
        "the clipboard and full screen for this origin, and the camera, " +
        "microphone, geolocation and payment for nobody", function () {
    ["publickey-credentials-get=(self)", "publickey-credentials-create=(self)",
     "digital-credentials-get=(self)", "clipboard-write=(self)",
     "fullscreen=(self)"].forEach(function (one) {
      assert.ok(pp.indexOf(one) >= 0, one + " in " + pp);
    });
    ["camera", "microphone", "geolocation", "payment"].forEach(function (one) {
      assert.ok(new RegExp("(^|, )" + one + "=\\(\\)").test(pp), one);
    });
  });
  const missing = await send(base + "/realm/" + DEV + "/qualys-no-such-path");
  check("an unrouted path carries the same Permissions-Policy", function () {
    assert.strictEqual(header(missing, "permissions-policy"), pp);
  });
  const json = header(discovery, "content-security-policy");
  check("a JSON answer carries no style-src and no img-src, and keeps " +
        "frame-ancestors and base-uri", function () {
    assert.ok(/^application\/json/.test(header(discovery, "content-type")));
    assert.ok(json.indexOf("style-src") < 0 && json.indexOf("img-src") < 0,
              json);
    assert.ok(json.indexOf("default-src 'none'") >= 0 &&
              json.indexOf("frame-ancestors 'none'") >= 0 &&
              json.indexOf("base-uri 'none'") >= 0, json);
  });
  const health = await send(base + "/realm/" + DEV + "/healthcheck");
  check("so does /healthcheck, which the scan named", function () {
    const csp = header(health, "content-security-policy");
    assert.ok(csp.indexOf("style-src") < 0 &&
              csp.indexOf("frame-ancestors") >= 0, csp);
  });
  check("an HTML page (the framework's 404) keeps the base policy",
        function () {
    const csp = header(missing, "content-security-policy");
    assert.ok(/^text\/html/.test(header(missing, "content-type")));
    assert.ok(csp.indexOf("style-src 'unsafe-inline'") >= 0 &&
              csp.indexOf("frame-ancestors 'none'") >= 0, csp);
  });
  for (const p of ["/admin", "/portal", "/report"]) {
    const r = await send(base + "/realm/" + DEV + p);
    check(p + " answers COOP same-origin-allow-popups and CORP same-origin",
          function () {
      assert.strictEqual(r.status, 200);
      assert.strictEqual(header(r, "cross-origin-opener-policy"),
                         "same-origin-allow-popups");
      assert.strictEqual(header(r, "cross-origin-resource-policy"),
                         "same-origin");
    });
  }
  const front = await send(base + "/realm/" + DEV + "/");
  check("a surface not asked to be isolated (the front door) answers neither",
        function () {
    assert.strictEqual(front.status, 200);
    assert.strictEqual(front.headers.get("cross-origin-opener-policy"), null);
    assert.strictEqual(front.headers.get("cross-origin-resource-policy"),
                       null);
  });
  const probes = [
    [DEV, "/account-api/locale?%22%3E%3Cscript%3Ealert(81)%3C/script%3E=",
     "<script>", 400],
    [PROD, "/saml2/metadata/z--%3E%3Cqss%3E", "<qss>", 404],
    [PROD, "/saml11/metadata/z--%3E%3Cqss%3E", "<qss>", 404],
    [DEV, "/.well-known/jwt-vc-issuer/z--%3E%3Cqss%3E", "<qss>", 404]
  ];
  for (const one of probes) {
    const r = await send(base + "/realm/" + one[0] + one[1],
                         { headers: { Accept: "application/json" } });
    check(one[1].split("?")[0] + " refuses without repeating the probe",
          function () {
      assert.strictEqual(r.status, one[3], r.raw.slice(0, 300));
      assert.ok(r.raw.indexOf(one[2]) < 0 && /%3C/i.test(r.raw),
                r.raw.slice(0, 300));
    });
  }
  const devSaml = await send(base + "/realm/" + DEV +
                             "/saml2/metadata/z--%3E%3Cqss%3E");
  check("in development SAML describes itself to anybody", function () {
    assert.strictEqual(devSaml.status, 200);
    assert.ok(/<md:EntityDescriptor/.test(devSaml.raw));
  });
  const vc = await send(base + "/realm/" + DEV + "/vc-api/issuers",
                        { headers: { Accept: "application/json" } });
  let row = null;
  for (let i = 0; i < 20 && !row; i += 1) {
    row = (await auditRows(DEV, "&category=protocol")).filter(function (e) {
      return String(e.target || "").indexOf("/vc-api/issuers") >= 0;
    })[0] || null;
    if (!row) {
      await sleep(150);
    }
  }
  check("the switched-off VC API's 501 is audited as refused", function () {
    assert.strictEqual(vc.status, 501);
    assert.ok(row && row.outcome === "refused", JSON.stringify(row));
  });
  log.debug("Leaving sectionQualys().");
}

async function sectionBodies() {
  log.debug("Entering sectionBodies().");
  log.info("=== 6. a JSON body that is not an object ===");
  const before = (await auditRows(DEV, "&code=STS-HTTP-0003")).length;
  const api = base + "/realm/" + DEV + "/admin-api";
  for (const p of ["/applications/create", "/claims/add",
                   "/credential-claims/add", "/kerberos/claims/add"]) {
    const empty = await postJson(api + p, "{}");
    for (const body of ["null", "123", "\"x\"", "true", "[1,2]"]) {
      const r = await postJson(api + p, body);
      check("POST " + p + " with " + body + " is refused as {} is (" +
            empty.status + "), never a 500", function () {
        assert.strictEqual(r.status, empty.status, r.raw.slice(0, 300));
        assert.ok(r.status >= 400 && r.status < 500);
      });
    }
  }
  await sleep(300);
  const after = (await auditRows(DEV, "&code=STS-HTTP-0003")).length;
  check("and no uncaught failure (STS-HTTP-0003) was recorded", function () {
    assert.strictEqual(after, before);
  });
  log.debug("Leaving sectionBodies().");
}

function probesOf(metrics) {
  log.debug("Entering probesOf().");
  log.debug("Leaving probesOf().");
  return Number(((metrics || {}).calls || {}).healthProbes || 0);
}

async function sectionHealth() {
  log.debug("Entering sectionHealth().");
  log.info("=== 7. /healthcheck on both listeners ===");
  const before = probesOf((await send(base + "/admin-api/metrics")).body);
  const main = await send(base + "/healthcheck");
  const plain = await send(plainBase + "/healthcheck");
  check("/healthcheck answers 200 on the main port and through the " +
        "revocation listener", function () {
    assert.strictEqual(main.status, 200);
    assert.deepStrictEqual(main.body, { message: "Success" });
    assert.strictEqual(plain.status, 200);
    assert.deepStrictEqual(plain.body, { message: "Success" });
  });
  const other = await send(plainBase + "/oauth2/jwks");
  const ca = await send(plainBase + "/pki/ca/" + DEV + "/intermediate.cer");
  check("the revocation listener still refuses a path that is neither it " +
        "nor /pki/..., and serves /pki/...", function () {
    assert.strictEqual(other.status, 404);
    assert.strictEqual(ca.status, 200);
    assert.strictEqual(header(ca, "content-type"), "application/pkix-cert");
  });
  let after = before;
  for (let i = 0; i < 30 && after < before + 2; i += 1) {
    await sleep(200);
    after = probesOf((await send(base + "/admin-api/metrics")).body);
  }
  check("both successful probes move calls.healthProbes", function () {
    assert.ok(after >= before + 2, before + " -> " + after);
  });
  log.debug("Leaving sectionHealth().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. two throwaway realms " + DEV + " and " + PROD + " ===");
  for (const id of [DEV, PROD]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Response headers " + STAMP },
      "created the realm " + id);
  }
  await ok(base + "/realm/" + PROD + "/admin-api/config/set",
           { key: "global.mode", value: "product" }, "made it product");
  await sectionHsts();
  await sectionCharset();
  await sectionCrossSite();
  await sectionCookies();
  await sectionQualys();
  await sectionBodies();
  await sectionHealth();
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

async function main() {
  log.debug("Entering main().");
  try {
    await test();
    log.info("Test completed successfully.");
    log.debug("Leaving main().");
    process.exit(0);
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.error("Test failed: " + ((e && e.stack) || e));
    log.debug("Leaving main().");
    process.exit(1);
  }
}

main();
