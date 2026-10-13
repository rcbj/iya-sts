// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_token_exchange_assertions.js
//
// ===========================================================================
// AN ASSERTION FROM A DECLARED ISSUER, EXCHANGED AT A REAL TOKEN ENDPOINT
// (#114, 2026-10-03).
//
// RFC 8693 section 3 names `jwt`, `saml2` and `saml1` as token types; this
// service accepts an RFC 7523 JWT, an RFC 7522 SAML 2.0 assertion or a SAML
// 1.1 assertion signed by an issuer the realm DECLARED as a subject_token or
// an actor_token, verified by the assertion grant's own code and spent in
// its one history.
//
// `tests/token_exchange_assertions.js` asserts the same rules in process.
// This job asserts them through the doors an operator uses — the issuer
// declared and the key pair issued through `/admin-api`, the audience rule
// set through `/admin-api/config/set` — and runs in either mode: what
// development refuses as well is asserted in both, and what only product
// refuses is asserted where the stack is product.
//
// `local: true`: the feature is this repository's. It works in a throwaway
// realm, so the certificate authority is one it built, and leaves the realm
// standing (*No job removes a realm*, `tests/CLAUDE.md`).
// ===========================================================================

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const saml = require("./saml_xmldsig.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_token_exchange_assertions",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("txassert").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const SECRET = "tx-assertions-" + crypto.randomBytes(8).toString("hex");
const ALICE = usernameFor("txalice");
const DAVE = usernameFor("txdave");
const CLIENT = "txa-client";
const FRONT = "txa-front";
const BACK = "txa-back";
const OTHER = "txa-other";
const JWT_IDP = "txa-jwt-idp";
const SAML_IDP = "txa-saml-idp";
const url = function (identifier) {
  log.debug("Entering url().");
  log.debug("Leaving url().");
  return "https://" + identifier + ".example";
};
const FRONT_ACS = url(FRONT) + "/saml/acs";
const JWT_ISS = url(JWT_IDP);
const SAML_ISS = url(SAML_IDP);
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const T = { jwt: "urn:ietf:params:oauth:token-type:jwt",
            saml2: "urn:ietf:params:oauth:token-type:saml2",
            saml1: "urn:ietf:params:oauth:token-type:saml1" };
let PRODUCT = false;
let TOKEN = "";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function call(method, target, body, form) {
  log.debug("Entering call().");
  const r = await fetch(target, { method: method, redirect: "manual",
    headers: { "Content-Type": form ? "application/x-www-form-urlencoded"
                                    : "application/json" },
    body: body === undefined ? undefined :
          (form ? new URLSearchParams(body).toString()
                : JSON.stringify(body)) });
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

async function ok(target, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", target, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function b64u(o) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(JSON.stringify(o), "utf8").toString("base64url");
}

function claimsOf(token) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url")
    .toString("utf8"));
}

function now() {
  log.debug("Entering now().");
  log.debug("Leaving now().");
  return Math.floor(Date.now() / 1000);
}

function jti() {
  log.debug("Entering jti().");
  log.debug("Leaving jti().");
  return "txa-" + crypto.randomBytes(8).toString("hex");
}

function signJwt(claims, key, kid) {
  log.debug("Entering signJwt().");
  const input = b64u({ alg: "RS256", typ: "JWT", kid: kid }) + "." +
                b64u(claims);
  log.debug("Leaving signJwt().");
  return input + "." + crypto.sign("sha256", Buffer.from(input), key)
    .toString("base64url");
}

async function exchange(client, token, type, extra) {
  log.debug("Entering exchange().");
  const r = await call("POST", TOKEN, Object.assign({
    grant_type: EXCHANGE, subject_token: token, subject_token_type: type,
    client_id: client, client_secret: SECRET }, extra || {}), true);
  log.debug("Leaving exchange().");
  return r;
}

// A refusal, read as the OAuth error code and never as the status alone.
function refused(r, what) {
  log.debug("Entering refused().");
  assert.ok(r.status === 400 && r.json && r.json.error === "invalid_request" &&
            !r.json.access_token,
            what + " should be refused invalid_request; it answered " +
            r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving refused().");
  return String(r.json.error_description || "");
}

function issued(r, what) {
  log.debug("Entering issued().");
  assert.ok(r.status === 200 && r.json && r.json.access_token,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving issued().");
  return claimsOf(r.json.access_token);
}

async function subjectOf(username) {
  log.debug("Entering subjectOf().");
  // `urn:uuid:<entryUUID>` since 2026-09-14, so asked rather than built.
  const r = await call("GET", realmApi + "/users?user=" +
                       encodeURIComponent(username));
  const sub = String((r.json && r.json.subject) || "");
  assert.ok(/^urn:uuid:/.test(sub), "the subject of " + username + ": " +
            r.text.slice(0, 200));
  log.debug("Leaving subjectOf().");
  return sub;
}

async function setup() {
  log.debug("Entering setup().");
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: REALM + ".example.net",
             name: "Token exchange assertions" }, "created the realm");
  await ok(realmApi + "/pki/build", { organisation: "Exchange Assertion " +
                                      "Test", country: "US" },
           "built a certificate authority");
  for (const who of [ALICE, DAVE]) {
    await ok(realmApi + "/users/create",
             { username: who, invent: false,
               attributes: { cn: who, sn: who } }, "created " + who);
  }
  const app = async function (identifier, fields) {
    log.debug("Entering app().");
    await ok(realmApi + "/applications/create",
             { identifier: identifier, protocols: ["oauth2", "oidc"],
               fields: Object.assign({ oauthClientId: [identifier],
                 oauthClientSecret: SECRET,
                 oauthTokenEndpointAuthMethod: "client_secret_post",
                 oauthGrantType: ["client_credentials", EXCHANGE,
                                  JWT_BEARER],
                 oauthAllowedScope: ["api", "openid"],
                 oauthAudience: [url(identifier)] }, fields || {}) },
             "the application " + identifier);
    log.debug("Leaving app().");
  };
  // S for an assertion addressed to this server; it delegates to R.
  await app(CLIENT, { appAllowedToDelegateTo: [BACK] });
  // A relying party an assertion is FORWARDED from, with its ACS.
  await app(FRONT, { samlAssertionConsumerService: [FRONT_ACS] });
  // R, accepting DAVE (who holds the actor role) as an actor.
  await app(BACK, { appAllowedToActOnBehalfOf: [DAVE] });
  await app(OTHER);
  await ok(realmApi + "/roles/create-role", { role: "DELEGATION_ACTOR" },
           "created DELEGATION_ACTOR");
  await ok(realmApi + "/roles/add-member",
           { role: "DELEGATION_ACTOR", kind: "user", member: DAVE },
           "gave " + DAVE + " DELEGATION_ACTOR");

  // The declared JWT issuer, with a key this job made.
  const jwtKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = Object.assign(jwtKey.publicKey.export({ format: "jwk" }),
                            { kid: "txa-jwt-1", alg: "RS256", use: "sig" });
  await app(JWT_IDP, { oauthAssertionIssuer: [JWT_ISS],
                       oauthAssertionJwks: JSON.stringify({ keys: [jwk] }) });
  // The declared SAML issuer, with a key pair this realm issued; and another
  // application holding one too, which chains to the same CA.
  await app(SAML_IDP, { oauthSamlAssertionIssuer: [SAML_ISS] });
  await ok(realmApi + "/pki/issue", { identifier: SAML_IDP, purpose: "saml" },
           "issued the declared issuer's RFC 7522 key pair");
  await ok(realmApi + "/pki/issue", { identifier: OTHER, purpose: "saml" },
           "issued another application an RFC 7522 key pair");
  const fieldsOf = async function (identifier) {
    log.debug("Entering fieldsOf().");
    const view = await call("GET", realmApi + "/applications?application=" +
                            encodeURIComponent(identifier));
    log.debug("Leaving fieldsOf().");
    return ((view.json.application || view.json).fields) || {};
  };
  const idp = await fieldsOf(SAML_IDP);
  const other = await fieldsOf(OTHER);
  // NO GET CARRIES A CREDENTIAL (#446): an issued private key is read with
  // reveal-secret, the one door a sealed key comes out of.
  const revealedKey = async function (identifier) {
    log.debug("Entering revealedKey().");
    const answer = await ok(realmApi + "/applications/reveal-secret",
      { application: identifier, secret: "oauthSamlAssertionPrivateKey" },
      "revealed " + identifier + "'s RFC 7522 private key");
    log.debug("Leaving revealedKey().");
    return answer.value;
  };
  idp.oauthSamlAssertionPrivateKey = await revealedKey(SAML_IDP);
  other.oauthSamlAssertionPrivateKey = await revealedKey(OTHER);
  const md = await call("GET", realmBase +
                        "/.well-known/oauth-authorization-server");
  TOKEN = String(md.json.token_endpoint || realmBase + "/oauth2/token");
  log.debug("Leaving setup().");
  return {
    jwtKey: jwtKey.privateKey,
    saml: { key: idp.oauthSamlAssertionPrivateKey,
            cert: idp.oauthSamlAssertionCertificate },
    other: { key: other.oauthSamlAssertionPrivateKey,
             cert: other.oauthSamlAssertionCertificate }
  };
}

async function test() {
  log.debug("Entering test().");
  PRODUCT = await registry.isProduct(base);
  log.info("Driving " + realmBase + (PRODUCT ? " (product)" :
                                     " (development)"));
  const keys = await setup();
  const aliceSub = await subjectOf(ALICE);
  const daveSub = await subjectOf(DAVE);
  const jwtAbout = function (sub, extra) {
    log.debug("Entering jwtAbout().");
    log.debug("Leaving jwtAbout().");
    return signJwt(Object.assign({ iss: JWT_ISS, sub: sub, aud: TOKEN,
      iat: now(), exp: now() + 120, jti: jti() }, extra || {}),
    keys.jwtKey, "txa-jwt-1");
  };
  const saml2About = function (subject, o, pair) {
    log.debug("Entering saml2About().");
    const built = saml.buildAssertion(Object.assign({ issuer: SAML_ISS,
      subject: subject, audience: TOKEN, recipient: TOKEN }, o || {}));
    const p = pair || keys.saml;
    log.debug("Leaving saml2About().");
    return saml.b64u(saml.sign(built, p.key, p.cert));
  };
  const saml1About = function (subject, o) {
    log.debug("Entering saml1About().");
    const built = saml.buildAssertion11(Object.assign({ issuer: SAML_ISS,
      subject: subject, audience: TOKEN }, o || {}));
    log.debug("Leaving saml1About().");
    return saml.b64u(saml.sign(built, keys.saml.key, keys.saml.cert,
                               { at: "end" }));
  };
  const stranger = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

  log.info("=== A. the three types, from declared issuers ===");
  let r = await exchange(CLIENT, jwtAbout(ALICE), T.jwt);
  check("A1. a JWT from a DECLARED issuer is exchanged, about the person " +
        "it names", function () {
          assert.strictEqual(issued(r, "A1").sub, aliceSub);
        });
  r = await exchange(CLIENT, saml2About(ALICE), T.saml2);
  check("A2. a SAML 2.0 assertion from the declared issuer is exchanged",
        function () {
          assert.strictEqual(issued(r, "A2").sub, aliceSub);
        });
  r = await exchange(CLIENT, saml1About(ALICE), T.saml1);
  check("A3. a SAML 1.1 assertion is exchanged as saml1", function () {
    assert.strictEqual(issued(r, "A3").sub, aliceSub);
  });

  log.info("=== B. what is refused in every mode ===");
  r = await exchange(CLIENT, saml2About(ALICE, {}, keys.other), T.saml2);
  check("B1. a SAML assertion signed with a certificate this realm's CA " +
        "issued to SOMEBODY ELSE — it chains — is refused", function () {
          assert.ok(/KeyInfo/.test(refused(r, "B1")), r.text.slice(0, 300));
        });
  r = await exchange(CLIENT, saml2About(ALICE), T.saml1);
  check("B2. a SAML 2.0 assertion declared as saml1 is refused", function () {
    assert.ok(/declared/.test(refused(r, "B2")), r.text.slice(0, 300));
  });
  r = await exchange(CLIENT, jwtAbout(ALICE, { aud: url(FRONT) }), T.jwt);
  check("B3. under authorization-server (the default) an assertion " +
        "addressed to a relying party registered here is refused" +
        (PRODUCT ? "" : " (development: read unverified instead)"),
        function () {
          if (PRODUCT) {
            assert.ok(/tokenExchangeAudience/.test(refused(r, "B3")),
                      r.text.slice(0, 300));
          } else {
            // Development falls back to its unverified read of a JWT that
            // does not verify, as it always has (F1).
            issued(r, "B3 development");
          }
        });
  const twice = saml2About(ALICE);
  r = await exchange(CLIENT, twice, T.saml2);
  const again = await exchange(CLIENT, twice, T.saml2);
  check("B4. a SAML assertion is spent once: the second exchange is refused",
        function () {
          issued(r, "B4 first");
          assert.ok(/used already/.test(refused(again, "B4 second")));
        });

  log.info("=== C. ONE HISTORY with the jwt-bearer grant ===");
  const once = jwtAbout(ALICE);
  r = await call("POST", TOKEN, { grant_type: JWT_BEARER, assertion: once,
                                  client_id: CLIENT, client_secret: SECRET },
                 true);
  const spent = await exchange(CLIENT, once, T.jwt);
  check("C1. a JWT spent at the grant is refused at the exchange" +
        (PRODUCT ? "" : " (development: read unverified instead)"),
        function () {
          issued(r, "C1 grant");
          if (PRODUCT) {
            assert.ok(/used already/.test(refused(spent, "C1")),
                      spent.text.slice(0, 300));
          } else {
            // The unverified read again: the spend still refuses it as a
            // VERIFIED assertion, and development exchanges what it says.
            issued(spent, "C1 development");
          }
        });

  log.info("=== D. forwarding, under any-declared-relying-party ===");
  await ok(realmApi + "/config/set",
           { key: "oauth2.tokenExchangeAudience",
             value: "any-declared-relying-party" },
           "set oauth2.tokenExchangeAudience");
  r = await exchange(FRONT, jwtAbout(ALICE, { aud: url(FRONT) }), T.jwt);
  check("D1. the relying party an assertion was addressed to exchanges it, " +
        "for its own audience", function () {
          const claims = issued(r, "D1");
          assert.strictEqual(claims.sub, aliceSub);
          assert.ok([].concat(claims.aud).indexOf(url(FRONT)) >= 0,
                    JSON.stringify(claims.aud));
        });
  const acts = await call("GET", realmApi + "/delegation?per=50");
  check("D2. and the act on /admin-api/delegation says it was FORWARDED",
        function () {
          assert.ok(/FORWARDED/.test(JSON.stringify(acts.json)),
                    acts.text.slice(0, 400));
        });
  r = await exchange(FRONT, saml2About(ALICE, { audience: url(FRONT),
                                                recipient: FRONT_ACS }),
                     T.saml2);
  check("D3. a forwarded SAML assertion whose Recipient is the exchanging " +
        "client's registered ACS is exchanged", function () {
          assert.strictEqual(issued(r, "D3").sub, aliceSub);
        });
  r = await exchange(FRONT, saml2About(ALICE, { audience: url(FRONT),
    recipient: "https://elsewhere.example/acs" }), T.saml2);
  check("D4. and one whose Recipient is somebody else's is refused",
        function () {
          assert.ok(/Recipient/.test(refused(r, "D4")), r.text.slice(0, 300));
        });
  r = await exchange(FRONT, saml2About(ALICE,
    { audience: "https://unregistered.example" }), T.saml2);
  check("D5. an audience nobody registered is refused under forwarding too",
        function () {
          refused(r, "D5");
        });
  await ok(realmApi + "/config/set",
           { key: "oauth2.tokenExchangeAudience",
             value: "authorization-server" },
           "restored oauth2.tokenExchangeAudience");

  log.info("=== E. an assertion as the actor_token ===");
  r = await exchange(CLIENT, saml2About(ALICE), T.saml2, {
    audience: url(BACK), actor_token: jwtAbout(DAVE),
    actor_token_type: T.jwt });
  check("E1. act.sub is the person the actor's assertion names", function () {
    const claims = issued(r, "E1");
    assert.strictEqual(claims.sub, aliceSub);
    assert.strictEqual(claims.act && claims.act.sub, daveSub,
                       JSON.stringify(claims.act));
  });

  log.info("=== F. product only ===");
  if (PRODUCT) {
    r = await exchange(CLIENT, signJwt({ iss: "https://nobody.example",
      sub: ALICE, aud: TOKEN, iat: now(), exp: now() + 120, jti: jti() },
    stranger.privateKey, "x"), T.jwt);
    check("F1. a JWT from an issuer nobody declared is refused", function () {
      refused(r, "F1");
    });
    r = await exchange(CLIENT, jwtAbout("txa-nobody-" + jti()), T.jwt);
    check("F2. an assertion naming nobody the directory holds is refused",
          function () {
            refused(r, "F2");
          });
  } else {
    const forged = b64u({ alg: "none", typ: "JWT" }) + "." + b64u({
      iss: "https://nobody.example", sub: ALICE, username: ALICE,
      iat: now(), exp: now() + 120, jti: jti() }) + ".";
    r = await exchange(CLIENT, forged, T.jwt);
    check("F1. DEVELOPMENT: an undeclared, unsigned JWT is still exchanged " +
          "unverified, as it always was", function () {
            issued(r, "F1");
          });
  }

  const expected = PRODUCT ? 16 : 15;
  assert.ok(checks >= expected, "only " + checks + " of " + expected +
            " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_token_exchange_assertions")
  .description("RFC 8693 token exchange of RFC 7523 JWT, RFC 7522 SAML 2.0 " +
      "and SAML 1.1 assertions from issuers declared through /admin-api: " +
      "the three types, a chaining certificate refused, one replay history " +
      "with the jwt-bearer grant, oauth2.tokenExchangeAudience's two rules " +
      "and the SAML Recipient under forwarding, and an assertion as the " +
      "actor_token (#114).")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
