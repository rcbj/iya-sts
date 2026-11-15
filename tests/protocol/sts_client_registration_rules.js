// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_client_registration_rules.js
//
// ---------------------------------------------------------------------------
// HOW A CLIENT COMES TO EXIST, AND WHAT IT IS TOLD ABOUT AUTHENTICATING,
// OVER THE WIRE.
//
// D12 (#444): carries over the part a client or an administrator can see of
//
//   * `tests/software_statement.js` — RFC 7591 section 2.3 at a realm's
//     `POST /oauth2/register` and RFC 7592's read, PUT and DELETE: a trusted
//     statement's members beating the JSON and the statement echoed
//     unmodified; every invalid document refused (`none`, HMAC, a foreign
//     key, expiry, a foreign `aud`, not a JWS, one of the realm's own JWTs
//     untyped) and an undeclared issuer `unapproved_software_statement`;
//     the issuer refusal off; a statement this realm issues through
//     `/admin-api/applications/issue-software-statement`, its refusals and
//     STS-ADMIN-0915; PRODUCT with registration closed (only a trusted
//     statement opens it, an unverified one does not, a client let in that
//     way cannot PUT its metadata away, `softwareStatementOpensRegistration`
//     off); `softwareStatementRequired`; the application view's
//     `softwareStatements`;
//   * `tests/oauth_confidential.js` — `oauthConfidential` follows the token
//     endpoint authentication method, through `/admin-api/applications`'
//     create, set, add, remove, update-fields, add-secret and
//     revoke-registration (STS-REG-0363, STS-REG-0008);
//   * `tests/client_auth_declared_methods.js` — a client that presented no
//     credential is told every method it declares, STS-OAUTH-0019, and the
//     RFC 9700 sentence names them too.
//
// NOT carried, and why: the oauth_confidential cases that PLANT a stale
// flag past the registry (an LDAP write the registry does not see — no door
// over the wire writes one, class (d)), the field grid's attribute lists
// (module tables), `declaredMethodsOf()` as a function, and the issue
// action refusing with no request address (a console caller always has
// one, class (d)).
//
// OWNED HERE (local: true). Its realms are left standing unless
// STS_TEST_REMOVE_REALMS=1.
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
var log = bunyan.createLogger({ name: "sts_client_registration_rules",
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
// One realm for the software statements (switched to product half way),
// one in development for the confidential flag, one product and one
// development + RFC 9700 for the declared methods.
const SS = "crs-ss-" + STAMP;
const CONF = "crs-conf-" + STAMP;
const PROD = "crs-prod-" + STAMP;
const BCP = "crs-bcp-" + STAMP;
const PUBLISHER = "crs-publisher";
const ISS = "https://publisher-" + STAMP + ".crs.example";

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

function rb(realm) {
  log.debug("Entering rb().");
  log.debug("Leaving rb().");
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
  return { status: r.status, body: body || {}, raw: raw };
}

function postJson(url, payload, headers) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: JSON.stringify(payload || {}) });
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

async function realm(id, mode, extra) {
  log.debug("Entering realm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Client registration " + id },
    "created the realm " + id);
  await setting(id, "global.mode", mode);
  for (const key of Object.keys(extra || {})) {
    await setting(id, key, extra[key]);
  }
  log.debug("Leaving realm().");
}

function setting(id, key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: id, key: key,
    value: String(value) }, "set " + key + " on " + id);
}

function resetting(id, key) {
  log.debug("Entering resetting(). " + key);
  log.debug("Leaving resetting().");
  return ok(base + "/admin-api/realms/unset", { id: id, key: key },
            "reset " + key + " on " + id);
}

async function codeCount(id, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(rb(id) + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codeRose(id, code, before) {
  log.debug("Entering codeRose(). " + code);
  let n = await codeCount(id, code);
  for (let i = 0; i < 20 && n <= before; i += 1) {
    await sleep(100);
    n = await codeCount(id, code);
  }
  log.debug("Leaving codeRose(). " + n);
  return n > before;
}

function b64uJson(o) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return Buffer.from(JSON.stringify(o), "utf8").toString("base64url");
}

function partOf(jwt, i) {
  log.debug("Entering partOf().");
  log.debug("Leaving partOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[i], "base64url")
    .toString("utf8"));
}

function signRs256(header, claims, key) {
  log.debug("Entering signRs256().");
  const input = b64uJson(header) + "." + b64uJson(claims);
  log.debug("Leaving signRs256().");
  return input + "." + nodeCrypto.sign("sha256", Buffer.from(input), key)
    .toString("base64url");
}

function now() {
  log.debug("Entering now().");
  log.debug("Leaving now().");
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// 1-7. SOFTWARE STATEMENTS.
// ---------------------------------------------------------------------------
async function statements() {
  log.debug("Entering statements().");
  log.info("=== S. software statements (RFC 7591 section 2.3) ===");
  await realm(SS, "development");
  const R = rb(SS);
  const REG = R + "/oauth2/register";
  const pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const other = nodeCrypto.generateKeyPairSync("rsa",
                                               { modulusLength: 2048 });
  const jwk = Object.assign(pair.publicKey.export({ format: "jwk" }),
                            { kid: "crs-kid", use: "sig", alg: "RS256" });
  await ok(R + "/admin-api/applications/create", { identifier: PUBLISHER,
    protocols: ["oauth2"],
    fields: { oauthClientId: [PUBLISHER],
              oauthJwks: JSON.stringify({ keys: [jwk] }),
              oauthSoftwareStatementIssuer: [ISS] } },
    "registered the publisher, its JWKS and its declared issuer");
  const statementFrom = function (claims, opts) {
    log.debug("Entering statementFrom().");
    const o = opts || {};
    log.debug("Leaving statementFrom().");
    return signRs256(Object.assign({ alg: "RS256", kid: "crs-kid",
                                     typ: "JWT" }, o.header || {}),
                     Object.assign({ iss: ISS, iat: now(),
                                     software_id: "crs-app" }, claims),
                     o.key || pair.privateKey);
  };
  const register = function (json, headers) {
    log.debug("Entering register().");
    log.debug("Leaving register().");
    return postJson(REG, json, headers);
  };

  let r = await register({ redirect_uris: ["https://control.crs.example/cb"] });
  check("S1a. development: a registration with no statement registers — " +
        "the control", function () {
          assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
        });
  const trusted = statementFrom({
    redirect_uris: ["https://app.crs.example/cb"],
    grant_types: ["authorization_code"] });
  r = await register({ software_statement: trusted,
    redirect_uris: ["https://attacker.crs.example/cb"],
    grant_types: ["client_credentials"], client_name: "From the JSON" });
  const fromStatement = r.body;
  check("S1b. a trusted statement's redirect_uris and grant_types beat the " +
        "JSON (section 3.1.1), a member only the JSON carries is kept, the " +
        "statement's software_id is registered", function () {
          assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
          assert.deepStrictEqual(fromStatement.redirect_uris,
                                 ["https://app.crs.example/cb"]);
          assert.deepStrictEqual(fromStatement.grant_types,
                                 ["authorization_code"]);
          assert.strictEqual(fromStatement.client_name, "From the JSON");
          assert.strictEqual(fromStatement.software_id, "crs-app");
        });
  check("S1c. the statement comes back unmodified (section 3.2.1) and its " +
        "JWT claims are not registered as metadata", function () {
          assert.strictEqual(fromStatement.software_statement, trusted);
          assert.ok(!("iss" in fromStatement) && !("iat" in fromStatement),
                    Object.keys(fromStatement).join(","));
        });
  const read = await send(REG + "/" +
    encodeURIComponent(fromStatement.client_id), { headers: {
      Authorization: "Bearer " + fromStatement.registration_access_token } });
  check("S1d. an RFC 7592 read hands the statement back too", function () {
    assert.strictEqual(read.status, 200, read.raw.slice(0, 300));
    assert.strictEqual(read.body.software_statement, trusted);
  });
  const view = await send(R + "/admin-api/applications?application=" +
                          encodeURIComponent(fromStatement.client_id));
  const facts = ((view.body.application || view.body).softwareStatements ||
                 view.body.softwareStatements || {}).registeredWith || {};
  check("S1e. the application view records the issuer, that it was " +
        "trusted, and the publisher it was trusted through", function () {
          assert.strictEqual(facts.issuer, ISS, view.raw.slice(0, 600));
          assert.strictEqual(facts.trusted, true, JSON.stringify(facts));
          assert.strictEqual(facts.publisher, PUBLISHER,
                             JSON.stringify(facts));
        });

  const refusals = [];
  const refusedAs = async function (label, statement, error) {
    log.debug("Entering refusedAs().");
    const answer = await register({ software_statement: statement,
      redirect_uris: ["https://refused.crs.example/cb"] });
    if (answer.status !== 400 || answer.body.error !== error) {
      refusals.push(label + ": " + answer.status + " " +
                    answer.raw.slice(0, 200));
    }
    log.debug("Leaving refusedAs().");
    return answer;
  };
  await refusedAs("undeclared issuer", statementFrom(
    { iss: "https://nobody.crs.example" }), "unapproved_software_statement");
  await refusedAs("alg none", b64uJson({ alg: "none" }) + "." +
    b64uJson({ iss: ISS, software_id: "x" }) + ".",
  "invalid_software_statement");
  const hsInput = b64uJson({ alg: "HS256", typ: "JWT" }) + "." +
                  b64uJson({ iss: ISS, software_id: "x" });
  await refusedAs("HMAC", hsInput + "." + nodeCrypto.createHmac("sha256", "k")
    .update(hsInput).digest("base64url"), "invalid_software_statement");
  await refusedAs("a foreign key", statementFrom({}, { key: other.privateKey }),
                  "invalid_software_statement");
  await refusedAs("expired", statementFrom({ iat: now() - 7200,
    exp: now() - 3600 }), "invalid_software_statement");
  await refusedAs("aud elsewhere", statementFrom(
    { aud: "https://other-as.example" }), "invalid_software_statement");
  await refusedAs("not a JWS", "not-a-jwt", "invalid_software_statement");
  // One of this realm's own JWTs, signed with its key and naming its
  // issuer: an ID Token from the password grant, which is no statement.
  await ok(R + "/admin-api/applications/create", { identifier: "crs-pw",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: ["crs-pw"],
              oauthClientSecret: "crs-pw-secret-0123456789abcdef",
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["password"] } },
    "registered a password-grant client");
  const pw = await send(R + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", username: "crs-alice",
      password: "anything", scope: "openid", client_id: "crs-pw",
      client_secret: "crs-pw-secret-0123456789abcdef" }).toString() });
  assert.ok(pw.body.id_token, "no ID Token to present: " + pw.raw);
  const confused = await refusedAs("this realm's own untyped JWT",
                                   pw.body.id_token,
                                   "invalid_software_statement");
  r = await register({ software_statement: statementFrom({ aud: REG }),
                       redirect_uris: ["https://aud.crs.example/cb"] });
  check("S2a. every invalid document is refused invalid_software_statement " +
        "and an undeclared issuer unapproved_software_statement — none, " +
        "HMAC, a foreign key, expiry, a foreign aud, not a JWS, this " +
        "realm's own ID Token", function () {
          assert.deepStrictEqual(refusals, []);
        });
  check("S2b. the own-JWT refusal is the missing software-statement+jwt " +
        "type, and a statement addressed to this registration endpoint " +
        "registers", function () {
          assert.ok(/software-statement\+jwt/.test(
            confused.body.error_description), confused.raw.slice(0, 300));
          assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
        });

  await setting(SS, "oauth2.softwareStatementRequireTrustedIssuer", false);
  r = await register({ software_statement: statementFrom(
    { iss: "https://nobody.crs.example",
      redirect_uris: ["https://unverified.crs.example/cb"] }),
  redirect_uris: ["https://json.crs.example/cb"] });
  const untrustedView = await send(R + "/admin-api/applications?" +
    "application=" + encodeURIComponent(r.body.client_id || "x"));
  const untrusted = ((untrustedView.body.application ||
                      untrustedView.body).softwareStatements ||
                     untrustedView.body.softwareStatements ||
                     {}).registeredWith || {};
  const stillBad = await register({ software_statement: statementFrom({},
    { key: other.privateKey }), redirect_uris: ["https://x.crs.example/cb"] });
  check("S3. with the issuer refusal off an undeclared statement is " +
        "accepted UNVERIFIED — the JSON wins and the entry says untrusted — " +
        "and a bad signature from a declared issuer is still invalid",
        function () {
          assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
          assert.deepStrictEqual(r.body.redirect_uris,
                                 ["https://json.crs.example/cb"]);
          assert.strictEqual(untrusted.trusted, false,
                             untrustedView.raw.slice(0, 400));
          assert.strictEqual(stillBad.status, 400);
          assert.strictEqual(stillBad.body.error,
                             "invalid_software_statement");
        });
  await resetting(SS, "oauth2.softwareStatementRequireTrustedIssuer");

  const issue = function (body) {
    log.debug("Entering issue().");
    log.debug("Leaving issue().");
    return postJson(R + "/admin-api/applications/issue-software-statement",
                    Object.assign({ application: PUBLISHER }, body));
  };
  const issued = await issue({ metadata: JSON.stringify({
    redirect_uris: ["https://realm.crs.example/cb"],
    grant_types: ["authorization_code"] }) });
  const realmStatement = String(issued.body.softwareStatement || "");
  check("S4a. the issue action signs a typed statement naming this realm's " +
        "issuer, the publisher and an exp", function () {
          assert.strictEqual(issued.status, 200, issued.raw.slice(0, 300));
          assert.strictEqual(partOf(realmStatement, 0).typ,
                             "software-statement+jwt");
          const p = partOf(realmStatement, 1);
          assert.strictEqual(p.iss, R);
          assert.strictEqual(p.sub, PUBLISHER);
          assert.strictEqual(p.software_id, PUBLISHER);
          assert.ok(p.exp > now(), String(p.exp));
        });
  r = await register({ software_statement: realmStatement,
                       redirect_uris: ["https://elsewhere.crs.example/cb"] });
  const realmClient = r.body;
  check("S4b. a client presenting it registers with the members it fixes",
        function () {
          assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
          assert.deepStrictEqual(realmClient.redirect_uris,
                                 ["https://realm.crs.example/cb"]);
        });
  const noExpiry = await issue({ metadata: {}, lifetimeSeconds: 0 });
  check("S4c. a lifetime of 0 issues a statement with no exp", function () {
    assert.strictEqual(noExpiry.status, 200, noExpiry.raw.slice(0, 300));
    assert.ok(!("exp" in partOf(noExpiry.body.softwareStatement, 1)));
  });
  const before0915 = await codeCount(SS, "STS-ADMIN-0915");
  const tooLong = [];
  for (const life of [1e300, "1e300", "Infinity", 8.64e12]) {
    tooLong.push(await issue({ metadata: {}, lifetimeSeconds: life }));
  }
  const rows0915 = (await codeCount(SS, "STS-ADMIN-0915")) - before0915;
  check("S4d. a lifetime past the last date a Date can hold is refused, " +
        "recorded STS-ADMIN-0915 (where the request schema lets it reach " +
        "the action)", function () {
          tooLong.forEach(function (one) {
            assert.ok(one.status >= 400 && one.body.ok !== true,
                      one.raw.slice(0, 200));
          });
          assert.ok(rows0915 >= 1, "STS-ADMIN-0915 rows: " + rows0915);
        });
  const reserved = await issue({ metadata: { client_id: "chosen" } });
  const notJson = await issue({ metadata: "{nope" });
  const nobody = await postJson(R + "/admin-api/applications/" +
    "issue-software-statement", { application: "crs-nobody" });
  const badUri = await issue({ metadata: {
    redirect_uris: ["javascript:alert(1)"] } });
  check("S4e. it refuses a server-assigned member, JSON that is not JSON, an " +
        "application that does not exist and an address a registration " +
        "would refuse", function () {
          [reserved, notJson, nobody, badUri].forEach(function (one) {
            assert.ok(one.status >= 400 && one.body.ok !== true,
                      one.raw.slice(0, 200));
          });
        });

  log.info("=== S5. product, registration closed ===");
  await setting(SS, "global.mode", "product");
  r = await register({ redirect_uris: ["https://closed.crs.example/cb"],
                       token_endpoint_auth_method: "client_secret_basic" });
  let meta = await send(R + "/.well-known/oauth-authorization-server");
  check("S5a. PRODUCT: a registration with no statement is refused " +
        "access_denied 403, and registration_endpoint is still advertised " +
        "because a trusted statement opens it", function () {
          assert.strictEqual(r.status, 403, r.raw.slice(0, 300));
          assert.strictEqual(r.body.error, "access_denied");
          assert.ok(meta.body.registration_endpoint, meta.raw.slice(0, 300));
        });
  r = await register({ software_statement: trusted,
                       token_endpoint_auth_method: "client_secret_basic" });
  const admitted = r.body;
  const invalid = await register({ software_statement: statementFrom({},
    { key: other.privateKey }), redirect_uris: ["https://x.crs.example/cb"] });
  check("S5b. PRODUCT: a trusted statement opens the closed endpoint, and an " +
        "invalid one is refused with its own error rather than " +
        "access_denied", function () {
          assert.strictEqual(r.status, 201, r.raw.slice(0, 300));
          assert.ok(admitted.client_id);
          assert.strictEqual(invalid.status, 400);
          assert.strictEqual(invalid.body.error,
                             "invalid_software_statement");
        });
  await setting(SS, "oauth2.softwareStatementRequireTrustedIssuer", false);
  r = await register({ software_statement: statementFrom(
    { iss: "https://nobody.crs.example" }),
  redirect_uris: ["https://unverified.crs.example/cb"] });
  check("S5c. PRODUCT: an UNVERIFIED statement does not open it",
        function () {
          assert.strictEqual(r.status, 403, r.raw.slice(0, 300));
        });
  await resetting(SS, "oauth2.softwareStatementRequireTrustedIssuer");
  const clientUri = REG + "/" + encodeURIComponent(admitted.client_id);
  const auth = { Authorization: "Bearer " +
                 admitted.registration_access_token };
  const put = function (json) {
    log.debug("Entering put().");
    log.debug("Leaving put().");
    return send(clientUri, { method: "PUT",
      headers: Object.assign({ "Content-Type": "application/json" }, auth),
      body: JSON.stringify(Object.assign({ client_id: admitted.client_id,
        token_endpoint_auth_method: "client_secret_basic" }, json)) });
  };
  const away = await put({ redirect_uris: ["https://attacker.crs.example/cb"] });
  const otherIssuer = await put({ software_statement: realmStatement });
  const same = await put({ software_statement: trusted,
                           client_name: "Renamed" });
  check("S5d. PRODUCT: a client let in by a statement cannot PUT its " +
        "metadata away without one, nor with a trusted statement from " +
        "ANOTHER issuer; an update carrying the same issuer's statement is " +
        "accepted and keeps the statement's members", function () {
          assert.strictEqual(away.status, 400, away.raw.slice(0, 300));
          assert.strictEqual(away.body.error, "unapproved_software_statement");
          assert.strictEqual(otherIssuer.status, 400,
                             otherIssuer.raw.slice(0, 300));
          assert.strictEqual(otherIssuer.body.error,
                             "unapproved_software_statement");
          assert.strictEqual(same.status, 200, same.raw.slice(0, 300));
          assert.strictEqual(same.body.client_name, "Renamed");
          assert.deepStrictEqual(same.body.redirect_uris,
                                 ["https://app.crs.example/cb"]);
        });
  await setting(SS, "oauth2.softwareStatementOpensRegistration", false);
  r = await register({ software_statement: trusted,
                       token_endpoint_auth_method: "client_secret_basic" });
  meta = await send(R + "/.well-known/oauth-authorization-server");
  check("S5e. PRODUCT with softwareStatementOpensRegistration off: even a " +
        "trusted statement is refused and the endpoint is not advertised",
        function () {
          assert.strictEqual(r.status, 403, r.raw.slice(0, 300));
          assert.ok(!("registration_endpoint" in meta.body),
                    String(meta.body.registration_endpoint));
        });
  await resetting(SS, "oauth2.softwareStatementOpensRegistration");
  await setting(SS, "global.mode", "development");

  await setting(SS, "oauth2.softwareStatementRequired", true);
  r = await register({ redirect_uris: ["https://none.crs.example/cb"] });
  const carried = await register({ software_statement: trusted });
  check("S6a. softwareStatementRequired refuses a registration with none " +
        "and accepts one that carries a statement", function () {
          assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
          assert.strictEqual(r.body.error, "invalid_software_statement");
          assert.strictEqual(carried.status, 201, carried.raw.slice(0, 300));
        });
  await resetting(SS, "oauth2.softwareStatementRequired");
  const gone = await send(REG + "/" +
    encodeURIComponent(fromStatement.client_id), { method: "DELETE",
    headers: { Authorization: "Bearer " +
               fromStatement.registration_access_token } });
  const after = await send(R + "/admin-api/applications?application=" +
                           encodeURIComponent(fromStatement.client_id));
  const afterFacts = ((after.body.application || after.body)
    .softwareStatements || after.body.softwareStatements || {})
    .registeredWith;
  check("S6b. an RFC 7592 delete takes the statement facts with the " +
        "registration", function () {
          assert.strictEqual(gone.status, 204, gone.raw.slice(0, 200));
          assert.ok(!afterFacts || !afterFacts.issuer,
                    JSON.stringify(afterFacts));
        });

  const pubView = await send(R + "/admin-api/applications?application=" +
                             PUBLISHER);
  const section = (pubView.body.application || pubView.body)
    .softwareStatements || pubView.body.softwareStatements || {};
  const clientView = await send(R + "/admin-api/applications?application=" +
                                encodeURIComponent(realmClient.client_id));
  const clientSection = (clientView.body.application || clientView.body)
    .softwareStatements || clientView.body.softwareStatements || {};
  check("S7. the publisher's view reports its declared issuer, its usable " +
        "key and the issued statement verifying now; a client's view " +
        "reports how a statement let it in", function () {
          assert.ok((section.declaredIssuers || []).indexOf(ISS) >= 0,
                    pubView.raw.slice(0, 600));
          assert.strictEqual(section.usableKeys, 1, JSON.stringify(section));
          assert.ok(section.issued && section.issued.verifies === true,
                    JSON.stringify(section.issued));
          assert.strictEqual((clientSection.registeredWith || {}).issuer, R,
                             JSON.stringify(clientSection));
        });
  log.debug("Leaving statements().");
}

// ---------------------------------------------------------------------------
// C. oauthConfidential FOLLOWS THE METHOD.
// ---------------------------------------------------------------------------
async function confidential() {
  log.debug("Entering confidential().");
  log.info("=== C. oauthConfidential follows the method ===");
  await realm(CONF, "development");
  const R = rb(CONF);
  const A = R + "/admin-api/applications/";
  const held = async function (id) {
    log.debug("Entering held().");
    const r = await send(R + "/admin-api/applications?application=" +
                         encodeURIComponent(id));
    const entry = r.body.application || r.body;
    const fields = entry && entry.fields ? entry.fields : null;
    log.debug("Leaving held().");
    if (r.status !== 200 || !fields) {
      return { present: false };
    }
    const flag = fields.oauthConfidential;
    return { present: true,
             flag: flag === undefined ? "" : String([].concat(flag)[0]),
             methods: [].concat(fields.oauthTokenEndpointAuthMethod ===
               undefined ? [] : fields.oauthTokenEndpointAuthMethod)
               .map(String),
             description: String(entry.description || "") };
  };
  const create = function (id, protocols, fields) {
    log.debug("Entering create().");
    log.debug("Leaving create().");
    return postJson(A + "create", { identifier: id, protocols: protocols,
                                    fields: fields || {} });
  };
  const act = function (action, body) {
    log.debug("Entering act(). " + action);
    log.debug("Leaving act().");
    return postJson(A + action, body);
  };
  // A refusal: 4xx, the sentence, the code off the audit log, and nothing
  // written (`id` absent, or `still` what it was).
  const refusal = async function (label, attempt, code, says, absent) {
    log.debug("Entering refusal().");
    const before = await codeCount(CONF, code);
    const r = await attempt();
    const rose = await codeRose(CONF, code, before);
    const text = JSON.stringify(r.body);
    let gone = true;
    if (absent) {
      gone = !(await held(absent)).present;
    }
    log.debug("Leaving refusal().");
    return r.status >= 400 && r.body.ok !== true && rose &&
           (!says || says.test(text)) && gone ? "" : label + ": " +
           r.status + " " + text.slice(0, 200) + " rose=" + rose +
           " gone=" + gone;
  };
  const P = "crs-c-";
  const problems = [];

  await create(P + "plain", ["oauth2"], {});
  await create(P + "secret", ["oauth2"],
               { oauthClientSecret: "crs-secret-0123456789abcdef" });
  await create(P + "jwks", ["oauth2"], { oauthJwks: '{"keys":[]}' });
  const plain = await held(P + "plain");
  const secret = await held(P + "secret");
  const jwks = await held(P + "jwks");
  check("C1. a create infers the method and writes its flag: nothing is " +
        "none and FALSE, a secret client_secret_basic and TRUE, a JWK Set " +
        "private_key_jwt and TRUE", function () {
          assert.deepStrictEqual([plain.methods, plain.flag],
                                 [["none"], "FALSE"]);
          assert.deepStrictEqual([secret.methods, secret.flag],
                                 [["client_secret_basic"], "TRUE"]);
          assert.deepStrictEqual([jwks.methods, jwks.flag],
                                 [["private_key_jwt"], "TRUE"]);
        });

  problems.push(await refusal("2a none+TRUE", function () {
    return create(P + "lied", ["oauth2"], {
      oauthTokenEndpointAuthMethod: "none", oauthConfidential: "TRUE" });
  }, "STS-REG-0363", /does not match/, P + "lied"));
  await create(P + "pub", ["oauth2"], { oauthTokenEndpointAuthMethod: "none",
                                        oauthConfidential: "FALSE" });
  await create(P + "basic", ["oauth2"], {
    oauthTokenEndpointAuthMethod: "client_secret_basic",
    oauthClientSecret: "crs-secret-0123456789abcdef",
    oauthConfidential: "true" });
  problems.push(await refusal("2d basic+FALSE", function () {
    return create(P + "basic-lie", ["oauth2"], {
      oauthTokenEndpointAuthMethod: "client_secret_basic",
      oauthConfidential: "FALSE" });
  }, "STS-REG-0363", null, P + "basic-lie"));
  problems.push(await refusal("2f secret+FALSE", function () {
    return create(P + "secret-lie", ["oauth2"], {
      oauthClientSecret: "crs-secret-0123456789abcdef",
      oauthConfidential: "FALSE" });
  }, "STS-REG-0363", null, P + "secret-lie"));
  problems.push(await refusal("2g maybe", function () {
    return create(P + "maybe", ["oauth2"], {
      oauthTokenEndpointAuthMethod: "none", oauthConfidential: "maybe" });
  }, "STS-REG-0363", /neither/, P + "maybe"));
  problems.push(await refusal("2h two values", function () {
    return create(P + "two", ["oauth2"],
                  { oauthConfidential: ["TRUE", "FALSE"] });
  }, "STS-REG-0008", null, P + "two"));
  const pub = await held(P + "pub");
  const basic = await held(P + "basic");
  check("C2. a stated value is kept when it is the determination (any " +
        "case) and refused STS-REG-0363 when it is not or is neither " +
        "TRUE nor FALSE, before anything is created; two values are " +
        "STS-REG-0008", function () {
          assert.deepStrictEqual(problems.filter(Boolean), []);
          assert.strictEqual(pub.flag, "FALSE");
          assert.strictEqual(basic.flag, "TRUE");
        });

  problems.length = 0;
  const moved = await act("update-fields", { application: P + "plain",
    fields: { oauthTokenEndpointAuthMethod: "client_secret_basic" } });
  const plainMoved = await held(P + "plain");
  problems.push(await refusal("3b set TRUE on none", function () {
    return act("set", { application: P + "pub",
                        attribute: "oauthConfidential", value: "TRUE" });
  }, "STS-API-0009", /not one of the \d+ values it accepts/));
  problems.push(await refusal("3e clear", function () {
    return act("set", { application: P + "pub",
                        attribute: "oauthConfidential", value: "" });
  }, "STS-API-0009", /not one of the \d+ values it accepts/));
  problems.push(await refusal("3f add", function () {
    return act("add", { application: P + "pub",
                        attribute: "oauthConfidential", value: "TRUE" });
  }, "STS-API-0009", /not one of the \d+ values it accepts/));
  problems.push(await refusal("3f remove", function () {
    return act("remove", { application: P + "pub",
                           attribute: "oauthConfidential", value: "FALSE" });
  }, "STS-API-0009", /not one of the \d+ values it accepts/));
  const pubAfter = await held(P + "pub");
  // OVER THE WIRE the single-attribute doors never reach the registry's
  // own rule (STS-REG-0363, "cannot be cleared", "not added to or
  // removed"): `/admin-api`'s closed request schema does not list
  // oauthConfidential among the attributes `set`, `add` and `remove` take,
  // so each is refused STS-API-0009 first — the wire's answer, asserted.
  check("C3. changing the method rewrites the flag; the flag alone cannot " +
        "be set, cleared, added or removed (the request schema refuses " +
        "the attribute, STS-API-0009) and stays what the method makes",
        function () {
          assert.strictEqual(moved.status, 200, moved.raw.slice(0, 300));
          assert.deepStrictEqual([plainMoved.methods, plainMoved.flag],
                                 [["client_secret_basic"], "TRUE"]);
          assert.deepStrictEqual(problems.filter(Boolean), []);
          assert.strictEqual(pubAfter.flag, "FALSE");
        });

  const descBefore = (await held(P + "plain")).description;
  problems.length = 0;
  problems.push(await refusal("4d disagreeing body", function () {
    return act("update-fields", { application: P + "plain",
      fields: { description: "must-not-land", oauthConfidential: "FALSE" } });
  }, "STS-REG-0363", /does not match/));
  const plainKept = await held(P + "plain");
  const together = await act("update-fields", { application: P + "pub",
    fields: { oauthTokenEndpointAuthMethod: "client_secret_basic",
              oauthConfidential: "TRUE" } });
  const pubTogether = await held(P + "pub");
  problems.push(await refusal("4f none+TRUE body", function () {
    return act("update-fields", { application: P + "pub",
      fields: { oauthTokenEndpointAuthMethod: "none",
                oauthConfidential: "TRUE" } });
  }, "STS-REG-0363"));
  const pubStuck = await held(P + "pub");
  check("C4. update-fields judges the flag against the methods the body " +
        "leaves: a disagreement writes nothing else in the body, a method " +
        "change with its own flag is saved", function () {
          assert.deepStrictEqual(problems.filter(Boolean), []);
          assert.strictEqual(plainKept.description, descBefore);
          assert.notStrictEqual(plainKept.description, "must-not-land");
          assert.strictEqual(plainKept.flag, "TRUE");
          assert.strictEqual(together.status, 200,
                             together.raw.slice(0, 300));
          assert.deepStrictEqual([pubTogether.methods, pubTogether.flag],
                                 [["client_secret_basic"], "TRUE"]);
          assert.deepStrictEqual([pubStuck.methods, pubStuck.flag],
                                 [["client_secret_basic"], "TRUE"]);
        });

  await create(P + "secret-public", ["oauth2"],
               { oauthTokenEndpointAuthMethod: "none" });
  const minted = await act("add-secret", { application: P + "secret-public" });
  const sp = await held(P + "secret-public");
  check("C5. adding a secret to a public client replaces none with " +
        "client_secret_basic, records TRUE and says so", function () {
          assert.strictEqual(minted.status, 200, minted.raw.slice(0, 300));
          assert.deepStrictEqual([sp.methods, sp.flag],
                                 [["client_secret_basic"], "TRUE"]);
          assert.ok(/was none and is now client_secret_basic/.test(
            minted.raw), minted.raw.slice(0, 300));
        });

  const REG = R + "/oauth2/register";
  const regBasic = await postJson(REG, { redirect_uris:
    ["https://reg-basic.crs.example/cb"],
  token_endpoint_auth_method: "client_secret_basic" });
  const regNone = await postJson(REG, { redirect_uris:
    ["https://reg-none.crs.example/cb"], token_endpoint_auth_method: "none" });
  const regOmit = await postJson(REG, { redirect_uris:
    ["https://reg-omit.crs.example/cb"] });
  const rb1 = await held(regBasic.body.client_id);
  const ro = await held(regOmit.body.client_id);
  await act("revoke-registration", { application: regBasic.body.client_id });
  await act("revoke-registration", { application: regNone.body.client_id });
  const rb2 = await held(regBasic.body.client_id);
  const rn2 = await held(regNone.body.client_id);
  check("C6. a registration of client_secret_basic records TRUE and keeps " +
        "it when the registration is revoked; a public one keeps none and " +
        "FALSE; an omitted registration method is client_secret_basic and " +
        "TRUE", function () {
          assert.deepStrictEqual([rb1.methods, rb1.flag],
                                 [["client_secret_basic"], "TRUE"]);
          assert.deepStrictEqual([rb2.methods, rb2.flag],
                                 [["client_secret_basic"], "TRUE"]);
          assert.deepStrictEqual([rn2.methods, rn2.flag], [["none"], "FALSE"]);
          assert.deepStrictEqual([ro.methods, ro.flag],
                                 [["client_secret_basic"], "TRUE"]);
        });

  await create(P + "saml", ["saml2"], {});
  const samlTrue = await refusal("7b saml TRUE", function () {
    return create(P + "saml-true", ["saml2"], { oauthConfidential: "TRUE" });
  }, "STS-REG-0363", null, P + "saml-true");
  await create(P + "saml-false", ["saml2"], { oauthConfidential: "FALSE" });
  await create(P + "wallet", ["oid4vci"], {});
  const saml = await held(P + "saml");
  const samlFalse = await held(P + "saml-false");
  const wallet = await held(P + "wallet");
  check("C7. a SAML application gains the attribute only when the caller " +
        "stated a value that agrees; OpenID4VCI alone is FALSE with no " +
        "inferred method", function () {
          assert.deepStrictEqual([saml.flag, saml.methods], ["", []]);
          assert.strictEqual(samlTrue, "");
          assert.strictEqual(samlFalse.flag, "FALSE");
          assert.deepStrictEqual([wallet.flag, wallet.methods],
                                 ["FALSE", []]);
        });
  log.debug("Leaving confidential().");
}

// ---------------------------------------------------------------------------
// M. A CLIENT THAT SENT NO CREDENTIAL IS TOLD EVERY METHOD IT DECLARES.
// ---------------------------------------------------------------------------
async function declaredMethods() {
  log.debug("Entering declaredMethods().");
  log.info("=== M. every declared method, named ===");
  await realm(PROD, "product");
  await realm(BCP, "development", { "oauth2.rfc9700": true });
  const make = async function (id, methods) {
    log.debug("Entering make().");
    for (const one of [PROD, BCP]) {
      await ok(rb(one) + "/admin-api/applications/create", { identifier: id,
        protocols: ["oauth2"],
        fields: { oauthClientId: [id],
                  oauthClientSecret: id + "-secret-0123456789abcdef",
                  oauthTokenEndpointAuthMethod: methods,
                  oauthJwks: methods.indexOf("private_key_jwt") >= 0
                    ? '{"keys":[]}' : undefined,
                  oauthGrantType: ["client_credentials"] } },
        "registered " + id + " in " + one);
    }
    log.debug("Leaving make().");
  };
  await make("crs-one", ["client_secret_basic"]);
  await make("crs-two", ["client_secret_basic", "client_secret_post"]);
  await make("crs-three", ["client_secret_post", "private_key_jwt",
                           "tls_client_auth"]);
  const bare = function (realmId, id) {
    log.debug("Entering bare().");
    log.debug("Leaving bare().");
    return send(rb(realmId) + "/oauth2/token", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials",
                                  client_id: id }).toString() });
  };
  const before = await codeCount(PROD, "STS-OAUTH-0019");
  const one = await bare(PROD, "crs-one");
  const two = await bare(PROD, "crs-two");
  const three = await bare(PROD, "crs-three");
  const rose = (await codeCount(PROD, "STS-OAUTH-0019")) - before;
  check("M1. PRODUCT: a single-method client that sent no secret is told " +
        "that method alone, recorded STS-OAUTH-0019", function () {
          assert.strictEqual(one.status, 401, one.raw.slice(0, 300));
          assert.ok(/client_secret_basic \(an Authorization: Basic header\)/
            .test(one.body.error_description) &&
            !/client_secret_post/.test(one.body.error_description),
          one.body.error_description);
          assert.ok(rose >= 1, "STS-OAUTH-0019 rows: " + rose);
          assert.ok(!/STS-[A-Z]+-\d{4}/.test(one.raw), one.raw);
        });
  check("M2. a two-method client is told both and how each is sent, and " +
        "three are listed in order, the last after \"or\"", function () {
          const d2 = String(two.body.error_description);
          assert.ok(/client_secret_basic \(an Authorization: Basic header\)/
            .test(d2) &&
            /client_secret_post \(a client_secret form parameter\)/.test(d2),
          d2);
          const d3 = String(three.body.error_description);
          assert.ok(/client_secret_post \(a client_secret form parameter\), private_key_jwt \(a client_assertion signed with a registered key\) or tls_client_auth \(a client certificate\)/
            .test(d3), d3);
        });
  const bcp = await bare(BCP, "crs-two");
  check("M3. in a development realm in RFC 9700 mode the refusal names both " +
        "declared methods too", function () {
          assert.strictEqual(bcp.status, 401, bcp.raw.slice(0, 300));
          const d = String(bcp.body.error_description);
          assert.ok(/declares token_endpoint_auth_methods client_secret_basic, client_secret_post/
            .test(d) &&
            /client_secret_post \(a client_secret form parameter\)/.test(d),
          d);
        });
  log.debug("Leaving declaredMethods().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " (realms ending " + STAMP + ")");
  await statements();
  await confidential();
  await declaredMethods();
  assert.ok(checks >= 29, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
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
    log.warn("could not remove this run's realms: " + e.message);
  }
  if (failure) {
    log.error("Test failed: " + (failure.stack || failure));
    log.debug("Leaving main().");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
