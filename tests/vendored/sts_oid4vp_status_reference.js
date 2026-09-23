"use strict";
//
// File: sts_oid4vp_status_reference.js
//
// ---------------------------------------------------------------------------
// A PRESENTED CREDENTIAL MUST NAME ITS STATUS, OVER HTTP (#165, 2026-09-23).
//
// The OpenID4VP Verifier accepted a credential from a trusted foreign issuer
// that carried no status reference at all, and an `ldp_vc` whose presentation
// simply did not disclose its `credentialStatus` — so a revoked credential
// passed the bar door by withholding its status entry. Since #165
// `oid4vp.requireStatusReference` (all | own-only | off, `all` by default in
// BOTH modes) says what a missing reference means, and
// `oid4vp.statusOptionalIssuers` exempts one trusted issuer by the thumbprint
// of its certificate. This job asserts, against a running service, in two
// throwaway trust realms it leaves standing — one development and one
// product, so both are covered whatever mode the service started in:
//
//   0. SETTING UP each realm: a certificate of this job's own, made at run
//      time (`outbound_test_ca.js`, no key material committed), is written
//      into `oid4vp.trustedIssuerCertificates`, and the Verifier's request
//      asks for no claim (`/admin-api/verifier-request/select`), so a
//      credential that discloses nothing answers it.
//   1. THE SETTING: `/admin-api/config` reports it with the default `all`;
//      in the product realm writing `off` is refused (HTTP 400, naming
//      product mode, STS-CORE-0103) while `own-only` and `all` are
//      accepted; the development realm accepts `off`.
//   2. THE ldp_vc QUERY: the bar door's DCQL query for `ldp_vc` asks for
//      `credentialStatus`, so a conforming wallet discloses it.
//   3. A FOREIGN CREDENTIAL WITH NO STATUS, as an SD-JWT VC and as a
//      `jwt_vc_json`, in each realm: refused `invalid_request` under `all`,
//      the refusal naming the missing status reference; accepted once the
//      issuer's certificate thumbprint is in `oid4vp.statusOptionalIssuers`,
//      and refused again when the exemption names another certificate;
//      accepted under `own-only`.
//   4. `off` IS IGNORED IN PRODUCT: stored in the development realm it
//      accepts the foreign credential with no status; the realm is switched
//      to product with `off` still stored, and the same credential is
//      refused.
//
// WHAT IS ASSERTED IN PROCESS INSTEAD (`tests/vc_status_list.js`): this
// realm's own `ldp_vc` presented with and without its `credentialStatus`,
// valid and revoked — its presentation is a bbs-2023 derived proof, and the
// only BBS implementation in this tree is the service's own, which an
// independent wallet may not borrow (`sts_oid4vp_wallet.js` says the same);
// and a foreign credential whose status list resolves, which needs a list
// the service can fetch from this job. The `STS-VC-*` codes are an
// operator's names and never sent, so they are asserted there too.
//
// OWNED HERE (local: true): the Verifier is this repository's own.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const testCa = require("./outbound_test_ca.js");

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
var log = bunyan.createLogger({ name: "sts_oid4vp_status_reference",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const DEV = ("vcstat-d-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const PROD = ("vcstat-p-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const KEY = "oid4vp.requireStatusReference";
const EXEMPT = "oid4vp.statusOptionalIssuers";
// What this Verifier asks an SD-JWT VC and a W3C credential to be, as the
// issuer here mints them (`oid4vc/vc_configs.ts`).
const VCT = "urn:idptools:sd-jwt-vc:identity";
const W3C_TYPES = ["VerifiableCredential", "IdentityCredential"];
const FLOOR = 30;

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
  return { status: r.status, json: json, text: text,
           location: r.headers.get("location") || "" };
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

// One setting's row out of `/admin-api/config`'s groups, or null.
function settingRow(body, key) {
  log.debug("Entering settingRow(). key=" + key);
  const rows = [];
  ((body && body.groups) || []).forEach(function (group) {
    (group.settings || []).forEach(function (one) {
      rows.push(one);
    });
  });
  ((body && body.settings) || []).forEach(function (one) {
    rows.push(one);
  });
  const row = rows.filter(function (one) {
    return one.key === key;
  })[0] || null;
  log.debug("Leaving settingRow(). found=" + !!row);
  return row;
}

function b64u(input) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(input).toString("base64url");
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
    .toString("utf8"));
}

// A compact JWS with node's crypto: RS256 for the issuer, ES256 for the
// holder.
function signJws(header, payload, privateKey) {
  log.debug("Entering signJws(). " + header.alg);
  const input = b64u(JSON.stringify(header)) + "." +
                b64u(JSON.stringify(payload));
  const signature = header.alg === "ES256"
    ? nodeCrypto.sign("sha256", Buffer.from(input, "ascii"),
                      { key: privateKey, dsaEncoding: "ieee-p1363" })
    : nodeCrypto.sign("sha256", Buffer.from(input, "ascii"), privateKey);
  log.debug("Leaving signJws().");
  return input + "." + signature.toString("base64url");
}

function holderKey() {
  log.debug("Entering holderKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  log.debug("Leaving holderKey().");
  return { privateKey: pair.privateKey,
           jwk: pair.publicKey.export({ format: "jwk" }) };
}

// THE FOREIGN ISSUER: a certificate of this job's own and the credentials
// it signs, none of them naming a status.
function sdJwtVc(issuer, holder) {
  log.debug("Entering sdJwtVc().");
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving sdJwtVc().");
  return signJws({ alg: "RS256", typ: "dc+sd-jwt" }, {
    iss: "https://status-partner.example", vct: VCT,
    sub: "urn:uuid:status-partner-person", cnf: { jwk: holder.jwk },
    nbf: now - 5, exp: now + 600, _sd_alg: "sha-256", _sd: [] },
    issuer.privateKey) + "~";
}

function jwtVcJson(issuer, holder) {
  log.debug("Entering jwtVcJson().");
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving jwtVcJson().");
  return signJws({ alg: "RS256", typ: "JWT" }, {
    iss: "https://status-partner.example",
    sub: "urn:uuid:status-partner-person", cnf: { jwk: holder.jwk },
    nbf: now - 5, exp: now + 600,
    vc: { "@context": ["https://www.w3.org/2018/credentials/v1"],
          type: W3C_TYPES,
          credentialSubject: { id: "urn:uuid:status-partner-person" } } },
    issuer.privateKey);
}

// The holder's presentation of either: an SD-JWT VC with a Key Binding JWT
// (no Disclosures — the credential has none), or a VP JWT around the
// jwt_vc_json.
function presentationOf(format, credential, holder, ro) {
  log.debug("Entering presentationOf(). " + format);
  const iat = Math.floor(Date.now() / 1000);
  if (format === "jwt_vc_json") {
    log.debug("Leaving presentationOf(). A VP JWT.");
    return signJws({ alg: "ES256", typ: "JWT", jwk: holder.jwk }, {
      iss: "urn:ietf:params:oauth:jwk-thumbprint:holder",
      aud: ro.client_id, nonce: ro.nonce, iat: iat,
      vp: { "@context": ["https://www.w3.org/2018/credentials/v1"],
            type: ["VerifiablePresentation"],
            verifiableCredential: [credential] } }, holder.privateKey);
  }
  const sdHash = nodeCrypto.createHash("sha256")
    .update(credential, "ascii").digest("base64url");
  log.debug("Leaving presentationOf(). An SD-JWT VC.");
  return credential + signJws({ alg: "ES256", typ: "kb+jwt" },
    { iat: iat, nonce: ro.nonce, aud: ro.client_id, sd_hash: sdHash },
    holder.privateKey);
}

// The bar door in `realm`: a request by reference for `format`, and its
// request object.
async function begin(realm, format) {
  log.debug("Entering begin(). " + realm + " " + format);
  const started = await call("GET", realmBase(realm) +
    "/oid4vp/start?by=reference&format=" + encodeURIComponent(format));
  assert.strictEqual(started.status, 302,
                     "the bar door should hand the wallet a request: " +
                     started.status + " " + started.text.slice(0, 300));
  const requestUri = new URL(started.location).searchParams
    .get("request_uri");
  const got = await call("GET", requestUri);
  assert.strictEqual(got.status, 200, "the request object: " +
                     got.text.slice(0, 200));
  log.debug("Leaving begin().");
  return payloadOf(got.text);
}

async function present(realm, format, credential, holder) {
  log.debug("Entering present(). " + realm + " " + format);
  const ro = await begin(realm, format);
  const id = (((ro.dcql_query || {}).credentials || [])[0] || {}).id;
  const vpToken = {};
  vpToken[id] = [presentationOf(format, credential, holder, ro)];
  const r = await call("POST", ro.response_uri,
    new URLSearchParams({ state: ro.state,
                          vp_token: JSON.stringify(vpToken) }).toString(),
    { "Content-Type": "application/x-www-form-urlencoded" });
  log.debug("Leaving present(). " + r.status);
  return r;
}

function refusedForNoStatus(r) {
  log.debug("Entering refusedForNoStatus().");
  assert.strictEqual(r.status, 400, r.text.slice(0, 400));
  assert.strictEqual(r.json && r.json.error, "invalid_request",
                     r.text.slice(0, 400));
  assert.ok(/Credential status/.test(r.json.error_description) &&
            /no status reference/.test(r.json.error_description),
            r.json.error_description);
  log.debug("Leaving refusedForNoStatus().");
}

function accepted(r) {
  log.debug("Entering accepted().");
  assert.strictEqual(r.status, 200, r.text.slice(0, 400));
  assert.ok(/\/oid4vp\/done\?/.test((r.json || {}).redirect_uri || ""),
            r.text.slice(0, 300));
  log.debug("Leaving accepted().");
}

async function setUp(issuer) {
  log.debug("Entering setUp().");
  log.info("=== 0. two realms, one each way ===");
  await ok(base + "/admin-api/realms/create",
           { id: PROD, domain: PROD + ".example.net", name: "#165 product",
             overrides: { "global.mode": "product" } },
           "created the product realm");
  await ok(base + "/admin-api/realms/create",
           { id: DEV, domain: DEV + ".example.net", name: "#165 development",
             overrides: { "global.mode": "development" } },
           "created the development realm");
  for (const realm of [DEV, PROD]) {
    await setting(realm, "oid4vp.trustedIssuerCertificates", issuer.certPem);
    await ok(realmBase(realm) + "/admin-api/verifier-request/select",
             { claims: [] }, "the Verifier in " + realm + " asks for no claim");
  }
  check("each realm trusts this job's issuer certificate and asks for no " +
        "claim", function () {
    assert.ok(true);
  });
  log.debug("Leaving setUp().");
}

async function theSetting() {
  log.debug("Entering theSetting().");
  log.info("=== 1. the setting ===");
  for (const realm of [DEV, PROD]) {
    const config = await call("GET", realmBase(realm) + "/admin-api/config");
    check(realm + ": /admin-api/config reports " + KEY + " with the default " +
          "all, in both modes, and " + EXEMPT + " empty", function () {
      assert.strictEqual(config.status, 200, config.text.slice(0, 200));
      const row = settingRow(config.json, KEY);
      assert.ok(row && row.value === "all", JSON.stringify(row));
      const exempt = settingRow(config.json, EXEMPT);
      assert.ok(exempt && (exempt.value === "" ||
                           (Array.isArray(exempt.value) &&
                            !exempt.value.length)), JSON.stringify(exempt));
    });
  }
  const refused = await call("POST", realmBase(PROD) +
                             "/admin-api/config/set",
                             { key: KEY, value: "off" });
  check("product: writing " + KEY + "=off is refused, naming product mode " +
        "(STS-CORE-0103)", function () {
    assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
    assert.ok(/product mode/.test(refused.text) &&
              refused.text.indexOf(KEY) >= 0, refused.text.slice(0, 300));
  });
  const fromDefault = await call("POST", base + "/admin-api/realms/set",
                                 { id: PROD, key: KEY, value: "off" });
  check("product: and so is realms/set of it from the default realm",
        function () {
    assert.strictEqual(fromDefault.status, 400,
                       fromDefault.text.slice(0, 300));
  });
  await setting(PROD, KEY, "own-only");
  await setting(PROD, KEY, "all");
  await setting(DEV, KEY, "off");
  await setting(DEV, KEY, "all");
  check("product accepts own-only and all; development accepts off (every " +
        "call above answered 200)", function () {
    assert.ok(true);
  });
  log.debug("Leaving theSetting().");
}

async function theLdpQuery() {
  log.debug("Entering theLdpQuery().");
  log.info("=== 2. the ldp_vc query asks for credentialStatus ===");
  for (const realm of [DEV, PROD]) {
    const ro = await begin(realm, "ldp_vc");
    const query = ((ro.dcql_query || {}).credentials || [])[0] || {};
    check(realm + ": the bar door's ldp_vc DCQL query asks for " +
          "credentialStatus, though no claim is configured", function () {
      assert.strictEqual(query.format, "ldp_vc", JSON.stringify(query));
      assert.ok((query.claims || []).some(function (c) {
        return JSON.stringify(c.path) === "[\"credentialStatus\"]";
      }), JSON.stringify(query));
    });
  }
  log.debug("Leaving theLdpQuery().");
}

async function foreignCredentials(issuer, holder) {
  log.debug("Entering foreignCredentials().");
  log.info("=== 3. a foreign credential with no status reference ===");
  const hex = issuer.x509.fingerprint256.replace(/:/g, "").toLowerCase();
  const other = new nodeCrypto.X509Certificate(
    (await testCa.selfSignedCertificate("other-issuer.example")).cert)
    .fingerprint256;
  const made = { "dc+sd-jwt": sdJwtVc(issuer, holder),
                 "jwt_vc_json": jwtVcJson(issuer, holder) };
  for (const realm of [DEV, PROD]) {
    for (const format of Object.keys(made)) {
      let r = await present(realm, format, made[format], holder);
      check(realm + ": a foreign " + format + " naming no status is " +
            "refused under all, invalid_request, the refusal naming the " +
            "missing status reference", function () {
        refusedForNoStatus(r);
      });
      await setting(realm, EXEMPT, "0000," + issuer.x509.fingerprint256);
      r = await present(realm, format, made[format], holder);
      check(realm + ": accepted once its issuer certificate's thumbprint " +
            "(colon-hex) is in " + EXEMPT, function () {
        accepted(r);
      });
      await setting(realm, EXEMPT, hex);
      r = await present(realm, format, made[format], holder);
      check(realm + ": and by the same thumbprint in hex", function () {
        accepted(r);
      });
      await setting(realm, EXEMPT, other);
      r = await present(realm, format, made[format], holder);
      check(realm + ": refused again when the exemption names another " +
            "certificate", function () {
        refusedForNoStatus(r);
      });
      await setting(realm, EXEMPT, "");
      await setting(realm, KEY, "own-only");
      r = await present(realm, format, made[format], holder);
      check(realm + ": accepted under own-only — the relaxation its " +
            "description warns about", function () {
        accepted(r);
      });
      await setting(realm, KEY, "all");
    }
  }
  log.debug("Leaving foreignCredentials().");
}

async function offInProduct(issuer, holder) {
  log.debug("Entering offInProduct().");
  log.info("=== 4. off, stored in development, is ignored in product ===");
  const credential = sdJwtVc(issuer, holder);
  await setting(DEV, KEY, "off");
  let r = await present(DEV, "dc+sd-jwt", credential, holder);
  check("development, off: the foreign credential with no status is " +
        "accepted", function () {
    accepted(r);
  });
  await setting(DEV, "global.mode", "product");
  const config = await call("GET", realmBase(DEV) + "/admin-api/config");
  check("switched to product, off is still STORED", function () {
    const row = settingRow(config.json, KEY);
    assert.ok(row && row.value === "off", JSON.stringify(row));
  });
  r = await present(DEV, "dc+sd-jwt", credential, holder);
  check("and IGNORED: the same credential is refused, as under all",
        function () {
    refusedForNoStatus(r);
  });
  await setting(DEV, KEY, "all");
  await setting(DEV, "global.mode", "development");
  log.debug("Leaving offInProduct().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving oid4vp.requireStatusReference at " + base);
  const made = await testCa.selfSignedCertificate("status-partner.example");
  const issuer = { certPem: made.cert,
                   privateKey: nodeCrypto.createPrivateKey(made.key),
                   x509: new nodeCrypto.X509Certificate(made.cert) };
  const holder = holderKey();
  await setUp(issuer);
  await theSetting();
  await theLdpQuery();
  await foreignCredentials(issuer, holder);
  await offInProduct(issuer, holder);
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_oid4vp_status_reference")
  .description("#165: a credential presented to the OpenID4VP Verifier must " +
    "name its status — a foreign one with none is refused unless its " +
    "issuer is exempted by certificate thumbprint or the rule is own-only, " +
    "the ldp_vc query asks for credentialStatus, and off is development " +
    "only.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
